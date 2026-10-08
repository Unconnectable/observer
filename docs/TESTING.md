# Testing / 测试

How this project is verified. Two layers: automated tests that need no
privileges, and manual harnesses that need root plus real traffic. Every number
below is a measured baseline from this machine (Debian, kernel
`6.1.0-29-amd64`, 4 CPUs, desktop session), not an expectation.

Contents / 目录: [English](#english) | [中文](#中文)

---

## English

### Layer 1: automated format tests

`observer/tests/report.rs`, 4 tests, no privileges needed:

| Test                           | What it pins                                                                                                                 | If it fails                                                     |
| :----------------------------- | :--------------------------------------------------------------------------------------------------------------------------- | :-------------------------------------------------------------- |
| `shapes_with_size_and_latency` | the `[SEND]` / `[RECV]` line: `Size: N bytes                                                                                 | Latency: N ns`, column widths                                   | someone changed `LOG_SPECS` padding |
| `shapes_with_tail`             | a 16-byte full-width process name (`HAJIMINABEILUDUO`) still fits the `Comm:` column without shifting the tail               | `comm` handling or the `%-16s` field broke                      |
| `shapes_with_head`             | the leading extras: `err=-110` on `[TCP CONNECT]`, `-> ESTABLISHED` on `[TCP STATE]`, round-tripped through `TcpEvent.value` | the `value` field or `state_name()` mapping drifted             |
| `table_index_matches_enum`     | all twelve `TrafficDirection` discriminants equal their row index in `LOG_SPECS`, and no row has an empty tag                | someone inserted an enum value or a spec row in the wrong place |

```shell
cargo test --release -p observer --test report --no-run
./target/release/deps/report-<hash>     # expected: 4 passed; 0 failed
```

Two traps, both hit in practice:

1. Do **not** run `cargo test` directly. `.cargo/config.toml` sets
   `runner = "sudo -E"`, so cargo tries to run the test binary through sudo and
   asks for a password. Build with `--no-run` and execute the binary it prints.
2. Take the path from cargo's own `Executable ...` line. A shell glob like
   `./target/release/deps/report-*` can pick a stale binary and print
   `0 passed; 4 filtered out`, which looks like a pass and is not one.

### Layer 2: manual verification

Run each one against a live capture and compare with the baseline. The generic
setup is: start `sudo ./run.sh`, wait for the `🪝 Hooks Active: ...` banner
(timestamped), only then generate traffic.

| #    | What it proves                                 | Command                                                                                                                                                                                                                     | Baseline on this machine                                                                                                                                                                                  |
| :--- | :--------------------------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | all twelve symbols exist                       | `grep -wE 'tcp_sendmsg\|tcp_recvmsg\|tcp_connect\|tcp_set_state\|tcp_send_active_reset\|sk_stream_wait_memory\|tcp_retransmit_skb\|inet_csk_accept\|udp_sendmsg\|udp_recvmsg\|udpv6_sendmsg\|udpv6_recvmsg' /proc/kallsyms` | all present; `T` global, `t` local, both attachable unless inlined                                                                                                                                        |
| 2    | probes are really registered                   | `sudo cat /sys/kernel/debug/kprobes/list` while observer runs                                                                                                                                                               | 21 rows: 12 `k` + 9 `r`; the three entry-only hooks (`tcp_set_state`, `tcp_send_active_reset`, `tcp_retransmit_skb`) correctly have no `r` row                                                            |
| 3    | byte accounting matches an independent counter | `curl -L -o /dev/null <big ISO>`; and `head -c 100000000 /dev/zero \| curl -X POST --data-binary @- https://speed.cloudflare.com/__up`                                                                                      | 100 MB upload: uplink row `95.37 MiB` = 100,000,000 B, i.e. byte-for-byte; a 928.6 s run printed `2947.89 MB` and an `awk` re-sum over the log gave the same value                                        |
| 4    | nothing is dropped at high load                | 20,000 x `send(64 KiB)` while four curl downloads saturate the box                                                                                                                                                          | observer recorded exactly **20,000 lines / 1,310,720,000 bytes** at 5,201 events/s. This is also the kretprobe-pool check: `kprobes/list` exposes no `nmissed` here, so the count is verified empirically |
| 5    | the exit summary is exact                      | compare `TOTAL` with `grep -c` on event lines across all shards                                                                                                                                                             | gap **0** at 84,844 / 444,987 / 1,480,008 / 2,769,951 events, spanning several log shards                                                                                                                 |
| 6    | `[RST]` fires on an active reset               | 16 forced aborts: `SO_LINGER {on_off=1, time=0}` then `close()`, or unread data discarded on close                                                                                                                          | exactly **16** `[RST]` lines. Real traffic also produces them: 7 in a 928 s run, all from one Chrome IO thread, three inside the same millisecond                                                         |
| 7    | `sk_stream_wait_memory` can report a real hold | `test/block_probe.py` (see below)                                                                                                                                                                                           | `Blocked: 30015456233 ns` vs the application's own `30.02s`: 0.02 % apart                                                                                                                                 |
| 8    | the live row does not flood the terminal       | count newlines vs `\r` in captured stdout                                                                                                                                                                                   | 16.4 s run: 15 refreshes, 25 newlines, of which 0 come from the status row; 928 s run: 926 rows in the log, still one row on screen                                                                       |
| 9    | log sharding works                             | set `max_log_mb = 1` and capture ~3,000 events/s                                                                                                                                                                            | shards of 1,059,5xx bytes, boundary honoured to the line, and the switch marker written as the first line of the new shard, not printed to the terminal                                                   |

### UDP6 is only half verified

`[UDP6 SEND]` / `[UDP6 RECV]` stay at 0 on this machine, which is consistent with
there being no global IPv6 address at all (`ip -6 addr show scope global`
returns nothing, only `fe80::` link-local routes exist). But **the hook itself
has no reproducible test recorded yet**: 0 could mean "no IPv6 traffic" or "never
fired". Before claiming it works, run a v6 sender on the loopback (`::1`) and
check that `[UDP6 ...]` lines appear. Until then treat it as "symbol exists,
attachable, no data emitted".

### The traps that look like bugs but are not

- **Traffic before attachment.** If the flow starts before the `Hooks Active`
  line, every counter for it stays 0. This burned twice while testing
  backpressure. Use the banner timestamp on the log line to check ordering.
- **`curl` finishes too fast to measure.** A 50 MB loopback transfer completed in
  0.01 s and produced nothing; pace it (`time.sleep(0.01)` between sends) or make
  it long enough.
- **Backgrounded `sudo` cannot read a password.** `sudo` needs a tty; either run
  it in the foreground with `sudo -S ... < pass.txt`, or refresh the timestamp
  first with `sudo -v`.
- **`results/` written by root stays root-owned.** A later non-root run then
  aborts inside `TrafficLogger::init()`. Fix ownership with
  `sudo chown -R "$USER": results`.
- **Never kill an observer by name.** `pkill -f target/release/observer` also hits
  instances the user started interactively from `run.sh`. Track the PID of the
  instance you launched and signal that one only.
- **`grep -c RETRANSMIT` over-counts.** The banner line `🪝 Hooks Active: ...`
  contains every label. Match the bracketed event tag at line start, e.g.
  `grep -cE '^\[[0-9:.]+\] 🚨 \[TCP RETRANSMIT\]'`.

### `test/block_probe.py`

A manual harness, not a `cargo test`, and it touches nothing in the build:

```bash
cd ~/code/observer && sudo ./run.sh          # wait for the "Hooks Active" line
python3 test/block_probe.py                  # in another terminal
```

One process, two threads, one loopback connection. The server accepts and then
reads only 4 KiB every 0.3 s (~13 KB/s); the client writes 100 MB in 64 KiB
pushes. The receive window closes, the send buffer hits `tcp_wmem` (4 MB here),
and the next `send()` sleeps inside `sk_stream_wait_memory` until the peer closes
and a RST wakes it. The script times every `send()` itself, so its `>1ms` total is
an application-side witness that can be compared against the kernel-side
`Blocked:` value.

Measured: the expectation written into the first version ("many events of a few
milliseconds") was wrong. Reality is **one 30-second hold**, because once the
buffer is full a single `send()` sleeps until it is woken. To get many short
holds instead, shrink the 0.3 s drain interval to about 0.02 s so the buffer
hovers near the limit.

Knobs: `TOTAL`, `CHUNK`, `DRAIN_ROUNDS`, the `0.3` sleep, and `PORT = 0` (let the
kernel pick a free port; a fixed port produced `Address already in use` on the
second run).

### Adding a thirteenth hook

The order of three things is coupled, and the automated tests catch two of the
three mistakes:

1. `observer-common/src/lib.rs`: append the new `TrafficDirection` variant **after**
   the existing ones (indices are the wire format; inserting shifts everything).
2. `observer-ebpf/src/main.rs`: add the kprobe/kretprobe program, and give
   `value: 0` in every existing `TcpEvent { .. }` literal that now needs the field.
3. `observer/src/report.rs`: add one row to `LOG_SPECS` at the same index, and the
   matching label. `table_index_matches_enum` fails if the index and the variant
   disagree.
4. `observer/src/stats.rs`: extend `DIRECTIONS` (same order) and, if the event
   carries bytes, add it to the direction match in `record()`.
5. `observer/src/config.rs` + `config.toml`: one key for the kernel symbol, and a
   row in `observer/src/hooks.rs::plan()`.
6. `observer/tests/report.rs`: pin the new line's exact rendering before trusting it.

---

## 中文

这个项目分两层验证: 不需要权限的自动测试, 和需要 root + 真实流量的手工验证.
下面每个数字都是本机实测基线(Debian, 内核 `6.1.0-29-amd64`, 4 核, 普通桌面会话),
不是"期望值".

### 第一层: 格式自动测试

`observer/tests/report.rs`, 4 个测试, 不需要权限:

| 测试                           | 钉住什么                                                                                                   | 失败说明什么                             |
| :----------------------------- | :--------------------------------------------------------------------------------------------------------- | :--------------------------------------- |
| `shapes_with_size_and_latency` | `[SEND]` / `[RECV]` 那一行的 `Size: N bytes \| Latency: N ns` 与列宽                                       | 有人改了 `LOG_SPECS` 的对齐              |
| `shapes_with_tail`             | 16 字节全宽进程名(`HAJIMINABEILUDUO`)仍不把后半行挤走                                                      | `comm` 处理或 `%-16s` 字段坏了           |
| `shapes_with_head`             | 行首附加信息: `[TCP CONNECT]` 的 `err=-110`、`[TCP STATE]` 的 `-> ESTABLISHED`, 且经 `TcpEvent.value` 往返 | `value` 字段或 `state_name()` 映射漂移了 |
| `table_index_matches_enum`     | 十二个 `TrafficDirection` 判别值 == `LOG_SPECS` 里的行号, 且每行标签非空                                   | 有人在中间插了枚举值或表行               |

```shell
cargo test --release -p observer --test report --no-run
./target/release/deps/report-<hash>     # 预期: 4 passed; 0 failed
```

两个坑都是真踩过的:

1. **不要直接 `cargo test`**.`.cargo/config.toml` 里设了 `runner = "sudo -E"`,
   cargo 会用 sudo 去跑测试二进制并向你要密码.用 `--no-run` 构建, 然后执行它打印
   出来的那个路径.
2. 路径要取 cargo 自己那行 `Executable ...`.像 `./target/release/deps/report-*`
   这种 glob 会选中过期二进制, 打印 `0 passed; 4 filtered out`, 看着像通过, 其实没跑.

### 第二层: 手工验证

通用做法: 先 `sudo ./run.sh`, 等日志里出现带时间戳的 `🪝 Hooks Active: ...` 那行,
**然后**再造流量.

| #    | 证明什么                                     | 命令                                                                                                   | 本机基线                                                                                                                                                    |
| :--- | :------------------------------------------- | :----------------------------------------------------------------------------------------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | 十二个符号都存在                             | `grep -wE '…\|udpv6_recvmsg' /proc/kallsyms`                                                           | 全在; `T` 全局, `t` 局部, 只要没被内联都能挂                                                                                                                |
| 2    | 探针真的注册上了                             | 运行时 `sudo cat /sys/kernel/debug/kprobes/list`                                                       | 21 行: 12 个 `k` + 9 个 `r`; 三个只挂入口的钩子(`tcp_set_state`、`tcp_send_active_reset`、`tcp_retransmit_skb`)没有 `r` 行, 符合预期                        |
| 3    | 字节记账与独立计数器一致                     | `curl -L -o /dev/null <大 ISO>`; `head -c 100000000 /dev/zero \| curl -X POST --data-binary @- …/__up` | 100 MB 上传: 上行那一行 `95.37 MiB` = 100,000,000 B, 逐字节相等; 928.6 s 那次印 `2947.89 MB`, 用 `awk` 重算日志得到同一个值                                 |
| 4    | 高负载下不丢事件                             | 四个 curl 打满机器的同时跑 20,000 次 `send(64 KiB)`                                                    | observer 记下 **20,000 行 / 1,310,720,000 字节**, 当时 5,201 事件/s.这也是 kretprobe 实例池的检查: 本机 `kprobes/list` 不暴露 `nmissed`, 所以用计数实测代替 |
| 5    | 退出汇总是精确的                             | 拿 `TOTAL` 跟跨分片的事件行数 `grep -c` 比                                                             | 84,844 / 444,987 / 1,480,008 / 2,769,951 四种规模下差都是 **0**                                                                                             |
| 6    | `[RST]` 会在主动中止时触发                   | 强制 16 次 `SO_LINGER {on_off=1, time=0}` 后 `close()`, 或关闭时有未读数据                             | 恰好 **16** 行.真实流量里也有: 928 s 那次 7 行, 全来自同一个 Chrome IO 线程, 其中 3 行在同一毫秒                                                            |
| 7    | `sk_stream_wait_memory` 能报出真实的挂起时长 | `test/block_probe.py`(见下)                                                                            | `Blocked: 30015456233 ns` 对上应用自己量的 `30.02s`, 相差 0.02 %                                                                                            |
| 8    | 每秒活行不刷屏                               | 数捕获到的 stdout 里换行与 `\r` 的个数                                                                 | 16.4 s: 15 次刷新、25 个换行, 其中 0 个来自活行; 928 s: 文件里 926 行, 屏幕上仍只占一行                                                                     |
| 9    | 日志分片可用                                 | 设 `max_log_mb = 1`, 以约 3,000 事件/s 抓                                                              | 每片 1,059,5xx 字节, 边界精确到行; 切换标记写在新分片第一行, **不**上屏                                                                                     |

### UDP6 只验证了一半

`[UDP6 SEND]` / `[UDP6 RECV]` 在本机一直是 0, 这与"这台机器根本没有 global IPv6
地址"一致(`ip -6 addr show scope global` 什么都没输出, 只有 `fe80::` 链路本地路由).
但**钩子本身还没有可复现的测试记录**: 0 可能意味着"没有 v6 流量", 也可能意味着
"从来没响".在下结论之前, 先在回环 `::1` 上发一次 v6 UDP 看有没有 `[UDP6 ...]` 行.
在那之前它只能算"符号存在、能挂、没出过数据".

### 看着像 bug 其实不是的几件事

- **流量早于挂载.** 如果数据在 `Hooks Active` 之前就发完了, 相关计数全是 0.
  测背压时踩过两次.用日志行上的 banner 时间戳判断先后.
- **curl 跑得太快来不及测.** 一次 50 MB 回环传输 0.01 秒结束, 什么都没记到;
  要么加节流(每次 send 之间 `time.sleep(0.01)`), 要么把量做大.
- **后台起的 sudo 读不到密码.** sudo 需要 tty; 要么前台跑并用
  `sudo -S ... < pass.txt`, 要么先 `sudo -v` 把时间戳刷新.
- **root 写过的 `results/` 属主是 root.** 之后非 root 运行会在
  `TrafficLogger::init()` 里中止.用 `sudo chown -R "$USER": results` 修.
- **绝不按名字杀 observer.** `pkill -f target/release/observer` 会连带杀掉用户在
  终端里用 `run.sh` 起的实例.只给自己启动的那个 PID 发信号.
- **`grep -c RETRANSMIT` 会多计.** banner 行 `🪝 Hooks Active: ...` 里包含所有标签.
  要匹配行首的方括号事件标签, 例如
  `grep -cE '^\[[0-9:.]+\] 🚨 \[TCP RETRANSMIT\]'`.

### `test/block_probe.py`

它是手工工具, 不是 `cargo test`, 也不参与构建:

```bash
cd ~/code/observer && sudo ./run.sh          # 等 "Hooks Active" 那行出现
python3 test/block_probe.py                  # 另开一个终端
```

一个进程、两个线程、一条回环连接.服务端 accept 之后每 0.3 秒只读 4 KiB
(约 13 KB/s), 客户端以 64 KiB 一次猛写 100 MB.接收窗收到 0, 发送缓冲顶到
`tcp_wmem`(本机 4 MB), 下一次 `send()` 就睡进 `sk_stream_wait_memory`, 直到对端
关闭、RST 把它叫醒.脚本自己给每次 `send()` 计时, 所以它那个"超过 1 ms 的合计"
是一份**应用侧的独立证词**, 可以和内核侧的 `Blocked:` 对表.

实测结论: 第一版脚本里写的预期("会看到很多条几毫秒的")是错的.真实情况是
**一条 30 秒的挂起** —— 缓冲顶满之后一次 `send()` 会一路睡到被唤醒.想要很多条
短挂起, 把 0.3 秒缩到约 0.02 秒, 让缓冲维持在临界附近.

可调量: `TOTAL`、`CHUNK`、`DRAIN_ROUNDS`、那个 `0.3` 睡眠, 以及 `PORT = 0`
(让内核挑空闲端口; 固定端口第二次跑就 `Address already in use`).

### 要加第十三个钩子时

这三处的顺序是耦合的, 自动测试能抓住其中两个错误:

1. `observer-common/src/lib.rs`: 新的 `TrafficDirection` 变体**加在末尾**(下标就是
   线上格式, 中间插一个会把后面全挪位).
2. `observer-ebpf/src/main.rs`: 写 kprobe/kretprobe 程序, 并给每个已有的
   `TcpEvent { .. }` 字面量补上 `value: 0`.
3. `observer/src/report.rs`: 在**同一个下标**处给 `LOG_SPECS` 加一行和对应标签;
   下标和变体不一致时 `table_index_matches_enum` 会失败.
4. `observer/src/stats.rs`: 扩 `DIRECTIONS`(顺序要一致); 如果新事件带字节, 还要加进
   `record()` 里的方向 match.
5. `observer/src/config.rs` + `config.toml`: 一个内核符号的配置键, 再在
   `observer/src/hooks.rs::plan()` 里加一行.
6. `observer/tests/report.rs`: 先把新那一行的渲染钉住, 再相信它.
