# observer

一个基于 eBPF 的按进程网络流量观测器, 使用 [Aya](https://aya-rs.dev) 构建. 它以 kprobe/kretprobe 挂到内核的 TCP 与 UDP 函数上, 把入口与返回配对以测量内核在每次调用上花了多长时间, 并把每个事件写成磁盘上的一行. 终端只显示一行自行覆盖的状态行, 每秒刷新一次.

## 探针

共十二个钩子, 全部都在真实流量上验证过(见[实测结果](#实测结果)). 下表中的标签与日志里出现的完全一致.

| 标签                          | 配置键                              | 内核函数                          | 一行日志的含义                                            |
| :---------------------------- | :---------------------------------- | :-------------------------------- | :-------------------------------------------------------- |
| `[SEND]`                      | `target_func`                       | `tcp_sendmsg`                     | 应用交给 TCP 去发送的字节数                               |
| `[RECV]`                      | `recv_func`                         | `tcp_recvmsg`                     | 应用从 TCP 接收缓冲区里取走的字节数                       |
| `[NEW CONN]`                  | `accept_func`                       | `inet_csk_accept`                 | 一个服务端 socket 取出了一条已完成的连接                  |
| `[TCP RETRANSMIT]`            | `retransmit_func`                   | `tcp_retransmit_skb`              | 内核重发了一份未被确认的报文                              |
| `[TCP CONNECT]`               | `connect_func`                      | `tcp_connect`                     | 一个客户端发起了连接; 带返回码(超时为 `err=-110`)         |
| `[TCP STATE]`                 | `state_func`                        | `tcp_set_state`                   | 一次 TCP 状态机迁移(`-> ESTABLISHED`, `-> CLOSE_WAIT`, …) |
| `[BACKPRESSURE]`              | `backpressure_func`                 | `sk_stream_wait_memory`           | 发送缓冲区已满, 应用被内核按住; `Blocked:` 是按住的时长   |
| `[RST]`                       | `reset_func`                        | `tcp_send_active_reset`           | 本端主动中止了一条连接                                    |
| `[UDP4 SEND]` / `[UDP4 RECV]` | `udp_send_func` / `udp_recv_func`   | `udp_sendmsg` / `udp_recvmsg`     | 写出 / 读入的 IPv4 数据报                                 |
| `[UDP6 SEND]` / `[UDP6 RECV]` | `udp6_send_func` / `udp6_recv_func` | `udpv6_sendmsg` / `udpv6_recvmsg` | 写出 / 读入的 IPv6 数据报                                 |

IPv4 和 IPv6 的 UDP 是**两个独立的内核函数**; 只挂 v4 那一对会静默丢掉全部 IPv6 的 DNS 与 QUIC 流量. TCP 没有这种拆分 — `tcp_sendmsg` / `tcp_recvmsg` 同时服务两个协议族, 这就是 TCP 行里目前不带 `4`/`6` 标记的原因.

> **为什么是 `tcp_recvmsg` 而不是 `sock_recvmsg`:** `sock_recvmsg` 是通用的 socket 入口, 所以它连 X server、输入法与 D-Bus 之间的本地 IPC 也一并计数. 在一个桌面会话上实测, 120 秒产生 53,085 个事件, 其中**零个 TCP socket** 的三个进程贡献了 40.7 %(仅 Xwayland 就 17,879 个). 把钩子移到 `tcp_recvmsg` 后这些归零, 事件速率从 442/s 降到 39/s.

## 前置条件

- 支持 eBPF/BTF 的 Linux, 以及 root(加载探针需要 `CAP_BPF`/`CAP_SYS_ADMIN`)
- Rust stable 工具链
- 带 `rust-src` 组件的 Rust nightly 工具链
- `bpf-linker`
- `cc` / build-essential

`build.sh` 会在缺失时安装上述全部内容, 因此通常不需要手动装任何东西.

> **注意:** 优先用 `cargo binstall bpf-linker`, 而不是 `cargo install bpf-linker`. 从源码构建 `bpf-linker` 需要一套匹配的 LLVM 开发环境, 并且常见地以 `could not find llvm-config` 失败. 完整报错与解释见 [docs/CN.md](CN.md).

## 构建

```shell
./build.sh
```

这个脚本是幂等的 — 每装一个依赖前先检查它是否存在 — 并在第一个失败处停止(`set -e`). 它产出两个构件:

| 构件                                         | 说明                     |
| :------------------------------------------- | :----------------------- |
| `target/bpfel-unknown-none/release/observer` | eBPF 内核侧对象          |
| `target/release/observer`                    | 用户态加载器与事件消费者 |

eBPF 对象在编译时被内嵌进用户态二进制, 所以两者都必须在运行前构建好. 手动构建内核侧对象:

```shell
cargo +nightly build --release -p observer-ebpf \
  --target bpfel-unknown-none \
  -Z build-std=core,alloc \
  -Z build-std-features=compiler-builtins-mem
```

## 运行

```shell
sudo ./run.sh
```

`run.sh` 必须从仓库根目录执行: 程序从当前工作目录读取相对路径下的 `config.toml`, 文件缺失就中止.

要控制观测对象, 请编辑 `config.toml` — **不要**改 `run.sh`. `run.sh` 里仍然存在的带注释的 `--pid ...` 行是历史遗留; 程序不接受任何命令行参数.

## 输出

每次运行创建一个带时间戳的目录并写入其中:

```
results/<YYYY-MM>/<DD_HH-MM-SS_run>/
├── config.toml      # 本次运行所用配置的快照
├── traffic.log      # 捕获到的事件
├── traffic.2.log    # 仅在达到 max_log_mb 时才有
└── traffic.3.log    # ……
```

启动时会打印该路径(`📂 Logging to: ...`). 日志里每一行都以毫秒级时钟作前缀(`[14:44:43.573] ...`), 这样一次运行之后可以切成区间, 并与另一个工具的时间线做对照. `results/` 已被 gitignore.

逐事件的行**只写入文件**; 终端显示一行, 每秒原地刷新(实测约 2,900 事件/s 时它仍保持一行, 从不滚动):

```
⏱ 24s  176.6 KB/s ↓1295.2 KB/s ↑0.0 KB/s 重传 0 次
```

`↓` / `↑` 是那一秒内应用读出 / 写入的字节数, `条/s` 是全部十二个钩子的合计事件速率, `重传` 是落在这一秒内的重传次数. 同一行内容每秒追加进日志一次, 所以文件里保留了完整的时间序列.

当某个分片写满达到 `max_log_mb`, 写入器转到 `traffic.2.log`, 并把这个切换**记录在文件里**(不显示在屏幕上, 否则会打断那行实时状态):

```
---- 上一片写满, 分片从这里开始: "results/2026-09/28_14-22-31_run/traffic.2.log" ----
```

事件行与退出汇总都由同一张表生成(`observer/src/report.rs` 里的 `LOG_SPECS`), 所以汇总里的标签与日志行里的标签逐字节一致:

```
[TCP STATE] PID: 22918  Comm: Chrome_ChildIOT  -> SYN_SENT
[TCP CONNECT] PID: 22918  Comm: Chrome_ChildIOT  SYN-sent | Latency: 35722  ns
[UDP4 SEND] PID: 22918  Comm: Chrome_ChildIOT  Size: 34     bytes | Latency: 40689  ns
[SEND] PID: 22918  Comm: Chrome_ChildIOT  Size: 527    bytes | Latency: 33457  ns
[RECV] PID: 1660   Comm: Socket Thread    Size: 8216   bytes | Latency: 4951   ns
🚨 [TCP RETRANSMIT] PID: 2363   Comm: qoder            | Packet Lost!
🚧 [BACKPRESSURE] PID: 2318   Comm: WorkerThread     | Blocked: 2352   ns
```

退出时, 程序先等待各 per-CPU 读取任务排空, 然后打印派生指标与各钩子触发次数, 终端与日志都输出. 下面是一次 928.6 秒全局模式、当时正推着约 3.2 MB/s 的真实输出:

```
📈 ===== 指标 =====
   运行时长          928.6 s
   事件速率         2983.1 条/s
   下行(应用字节) 2947.89 MB (3250.9 KB/s)
   上行(应用字节) 194.99 MB (215.0 KB/s)
   重传事件            0.5 次/s 449 次里 326 次落在软中断/网卡中断(72.6 %), 这部分拿不到真正的进程
   发起连接            0.4 次/s
   发不出去       28.8 µs (19 次) —— 要写的数据内核暂时收不下, 等了一会儿
📊 ===== 钩子触发次数汇总 =====
   RECV           2752393
   SEND           14790
   NEW CONN       6
   TCP RETRANSMIT 449
   TCP CONNECT    366
   TCP STATE      1315
   BACKPRESSURE   19
   RST            7
   UDP4 RECV      266
   UDP4 SEND      340
   UDP6 RECV      0
   UDP6 SEND      0
   TOTAL          2769951
```

如何读那些*不是*不言自明的标签:

- `下行/上行(应用字节)` 统计的是应用从 socket 读出 / 写入的字节. 它不含 TCP/IP 头部(在网卡上大约多 7 %)也不含重传数据, 所以它永远低于任何网络计数器显示的值.
- `重传事件` 是 `tcp_retransmit_skb` 的**调用**次数, 不是丢失报文数, 而且这里没有可用的分母(一次调用可以重发若干段)— 请把它当成一个强度指标, 永远不要当成丢包率.
- `发不出去` 是内核因为发送缓冲区已满而按住发送方的时长. 亚毫秒值属于常规噪声; 本机实测出的有效判读阈值是**单次事件 >1 ms, 一秒内累计 >50 ms**.
- `发起连接` 统计客户端侧的 `tcp_connect`; 服务端侧的视角是 `NEW CONN`(`inet_csk_accept` 返回). 这两者在客户端机器上极不对称 — 上面那次运行是 366 对 6 — 这是预期, 不是 bug.

### 界面模式

`config.toml` 里写 `ui_mode = "tui"` 会把每秒活行换成三块面板: 顶部速率, 中间**按 PID**
的明细表(按字节排序, 按 q 退出并照旧输出退出汇总), 底部最近 200 行事件. 下面是一次 46 秒、
期间下载 93 MB 并上传 20 MB 的会话录屏重建出来的样子:

```
+-------------------------------------------------------------+
| observer  (q 退出, p 暂停刷新)                               |
| 跑了 46 s   这一秒 15.8 条/s  ↓4.5 KB/s  ↑0.0 KB/s           |
| 累计 ↓93.75 MB  ↑20.19 MB  重传 46 次(其中 36 次在中断里)  发不出去 18.4 µs |
+-------------------------------------------------------------+
| PID     进程            事件数   下行      上行      重传 RST 按住    |
| 89241   curl          96250   93.67 MB  1.1 KB     0    0   -       |
| 89251   curl           1244    4.6 KB  19.10 MB    0    0   -       |
| 3109    WorkerThread    271    69.8 KB   1.08 MB   1    0   18.4 µs |
| …另有 6 个进程没显示                                                |
+-------------------------------------------------------------+
| 最近事件 (最新在上面)                                                |
| [RECV] PID: 3908  Comm: WorkerThread  Size: 392 bytes | Latency: …  |
+-------------------------------------------------------------+
```

在 100 列的终端下头部两行仍放得下, 再窄就会被切. 按 PID 的记账只在这个模式下打开,
纯文本模式不会多一次加锁.

## 实测结果

一次 60 秒的全局模式抓取, 期间在 Firefox 里播放 B 站视频、循环跑 curl、并有一个编辑器在运行, 十二个钩子全部挂上且无挂载失败, 产出 **8,100 行日志**.

- **按进程归因是有效的.** Firefox 的网络线程(`Socket Thread`)一个就占了 4,910 行 `[RECV]` 中的 **4,729 行(96 %)**, 另外还有 917 行 `[SEND]`、100 行 `[TCP CONNECT]`、169 行 `[TCP STATE]`. 下行占主导的形态(`RECV:SEND ≈ 4:1`)正是视频流媒体应有的样子.
- **B 站走的是 TCP 而不是 QUIC** — UDP6 一直是 0, 全部 862 行 UDP(431 发 + 431 收)都来自 DNS 解析线程和一个名为 `ping` 的线程. (我此前推测浏览器那些约 1,357 字节的 UDP 包是 QUIC 视频流, 这个推测是错的.)
- **重传与背压确实会触发.** 抓到 48 行 `[TCP RETRANSMIT]`, 另一次独立运行里抓到 7 行 `[BACKPRESSURE]`. `[RST]` 用一个合成测试验证: 强制 16 次 `SO_LINGER(1,0)` 中止, 恰好产出 16 行.
- 观测到的最大单次读取: 16,401 字节.

### 与 curl 对照的字节计数

长时运行与 curl 自身的计数器做了对比, 数字在字节级别吻合, 双向都吻合:

| curl 做了什么                          | curl 报告                             | observer 报告                                          |
| :------------------------------------- | :------------------------------------ | :----------------------------------------------------- |
| `head -c 100000000 \| curl POST /__up` | 上传 100,000,000 B, 1.44 MB/s, 69.3 s | 上行 **95.37 MiB = 100,000,000 B**                     |
| Python 里 20,000 次 `send(64 KiB)`     | 20,000 次调用, 1,310,720,000 B        | **20,000 行, 1,310,720,000 B**                         |
| ISO 下载, 928.6 s 全局模式运行         | 约 3.2 MB/s                           | 下行 **2947.89 MB**, 用 `awk` 重算日志得到完全相同的值 |

那个 20,000 次调用的测试是在四个 curl 下载把机器打满(5,201 事件/s)的情况下跑的, 这也是 kretprobe 实例池并没有静默丢弃返回的证据: 本内核上 `/sys/kernel/debug/kprobes/list` 不暴露 `nmissed` 计数器, 所以改用经验方式验证计数.

### 端到端实测的背压

`test/block_probe.py` 让内核真的按住一个发送方: 服务端 accept 之后每 0.3 秒只取走 4 KiB, 而客户端在写 100 MB.

```
observer: [14:28:09.689] 🚧 [BACKPRESSURE] PID: 47684  Comm: python3  | Blocked: 30015456233 ns
python:   send() 卡住(>1ms) 1 次, 合计 30.02s
```

内核侧测得 30.0155 秒, 应用侧测得 30.02 秒: 相差 0.02 %. 同时运行的两个独立 observer 实例记录了同一个数值.

反面同样有用: 在一次真实的 1.44 MB/s 上传中, 同一个钩子**触发 0 次**, 因为 curl 被管道和 HTTP 分帧节拍了流, 它总能把自己的字节交给 socket. 所以 `发不出去` 是一个判别器 — "卡顿在 socket 缓冲区里" 对比 "卡顿在 socket 之上或之下" — 而不是一个吞吐仪表. 在本桌面环境, 覆盖 928 秒的真实浏览加下载, 出现 19 个事件, 最长的是 2.9 µs.

## 已知局限

八条全部是实测出来的, 不是理论推导, 统一维护在一个双语文件里, 免得两种语言互相跑偏:
**[docs/LIMITS.md](LIMITS.md)**. 摘要: 没有对端地址与端口; 软中断上下文无法归因到进程;
`Latency:` 是内核时间不是网络时延; `[RECV]` 记的是读取时刻而不是到达时刻; 解码侧不在
范围内; 聚合按 `comm` 而非 PID; `max_log_mb` 限制的是分片不是整次运行. (曾经在这里的
"退出汇总少计"已经修好, 验证过程写在那个文件里.)

## 测试

格式测试在 `observer/tests/report.rs`(4 个, 不需要权限), 其余都是对着真实流量跑的手工
工装. 完整步骤、实测基线、"看着像 bug 其实不是"的那些坑, 以及怎么加第十三个钩子, 都在
**[docs/TESTING.md](TESTING.md)**. 简版:

```shell
cargo test --release -p observer --test report --no-run
./target/release/deps/report-<hash>     # 预期: 4 passed; 0 failed
```

不要直接跑 `cargo test`: `.cargo/config.toml` 设了 `runner = "sudo -E"`, cargo 会去要
密码.路径用 cargo 自己打印的那个, 不要用 shell 通配符.

## 配置

仓库根目录的 `config.toml` 控制探针挂载、目标选择和过滤.

| 段          | 键                                  | 含义                                                                |
| :---------- | :---------------------------------- | :------------------------------------------------------------------ |
| `probes`    | `target_func`                       | 出向要挂的内核符号(默认 `tcp_sendmsg`)                              |
|             | `recv_func`                         | 入向要挂的内核符号(默认 `tcp_recvmsg`; 不要用 `sock_recvmsg`)       |
|             | `accept_func`                       | 新建连接的符号(默认 `inet_csk_accept`)                              |
|             | `retransmit_func`                   | 重传的符号(默认 `tcp_retransmit_skb`)                               |
|             | `connect_func`                      | 客户端侧连接尝试的符号(默认 `tcp_connect`)                          |
|             | `state_func`                        | TCP 状态迁移的符号(默认 `tcp_set_state`)                            |
|             | `reset_func`                        | 本端发出 RST 的符号(默认 `tcp_send_active_reset`)                   |
|             | `backpressure_func`                 | 发送缓冲区按住应用时命中的符号(默认 `sk_stream_wait_memory`)        |
|             | `udp_send_func` / `udp_recv_func`   | IPv4 UDP(默认 `udp_sendmsg` / `udp_recvmsg`)                        |
|             | `udp6_send_func` / `udp6_recv_func` | IPv6 UDP(默认 `udpv6_sendmsg` / `udpv6_recvmsg`)                    |
| `discovery` | `force_pid`                         | 只观测这个 PID; 优先级高于自动探测                                  |
|             | `auto_detect_name`                  | 对进程名做子串匹配; 空字符串表示全局模式                            |
| `filters`   | `include_names`                     | 对 `comm` 的白名单; 空表示全部放行                                  |
|             | `exclude_names`                     | 对 `comm` 的黑名单; 先于白名单应用                                  |
| `settings`  | `perf_pages`                        | per-CPU perf 缓冲区大小, 以页计, 必须是 2 的幂                      |
|             | `max_log_mb`                        | 单个 `traffic*.log` 分片的大小, 以 MB 计. `0` 或不写该键 = 永不切分 |
|             | `ui_mode`                           | `"tui"` = 三块面板的实时界面; 填别的或不写 = 纯文本(默认)           |

`discovery.auto_detect_name = ""`(全局模式)配合 `filters.exclude_names` 是推荐配置, 用于观测全系统流量而不至于被编辑器、浏览器和内核工作线程的噪声淹没.

列出可用的内核符号:

```shell
grep -wE 'tcp_sendmsg|tcp_recvmsg|tcp_connect|tcp_set_state|tcp_send_active_reset|sk_stream_wait_memory|tcp_retransmit_skb|inet_csk_accept|udp_sendmsg|udp_recvmsg|udpv6_sendmsg|udpv6_recvmsg' /proc/kallsyms
```

`T` 表示全局符号, `t` 表示局部符号 — 两者都可挂载, 前提是该函数没有被内联掉. 仓库根目录的 `hooks_candidates.txt` 列出了更多候选钩子, 每个都标注了其事件能否归因到进程(`P`)还是会落到软中断/定时器上下文(`S`).

## 文档

- [CHANGELOG.md](../CHANGELOG.md) - 按提交日期排的更新日志.
- [docs/TESTING.md](TESTING.md) - 每个钩子怎么验证, 附实测基线.
- [docs/LIMITS.md](LIMITS.md) - 八条实测局限, 英文与中文放在同一文件里维护.
- [docs/CN.md](CN.md) — 中文版 `bpf-linker` 安装失败说明与解决方案.
- [docs/EN.md](EN.md) — 同一份排错说明的英文版.

## 许可

除 eBPF 代码之外, observer 遵循 [MIT 许可证] 或 [Apache 许可证] (2.0 版)的条款分发, 由你自行选择.

除非你明确另行声明, 你有意提交给本 crate 收录的任何贡献, 按 Apache-2.0 许可证的定义, 均如上双许可, 不附加任何额外条款或条件.

### eBPF

所有 eBPF 代码遵循 [GNU 通用公共许可证第 2 版] 或 [MIT 许可证]的条款分发, 由你自行选择.

除非你明确另行声明, 你有意提交给本项目收录的任何贡献, 按 GPL-2 许可证的定义, 均如上双许可, 不附加任何额外条款或条件.

[Apache 许可证]: ../LICENSE-APACHE
[MIT 许可证]: ../LICENSE-MIT
[GNU 通用公共许可证第 2 版]: ../LICENSE-GPL2
