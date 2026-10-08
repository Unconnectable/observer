# 更新日志

按 commit 哈希倒序排列. 数字都是本机实测(Debian, 内核 `6.1.0-29-amd64`, 4 核),
完整口径见 `README.md` 与 `docs/LIMITS.md`、`docs/TESTING.md`.

---

- **工作区(未提交)** `feature/more-tui` · 2026-10-08 · `ui_mode = "tui"` 实时界面
  - 新增 `observer/src/tui.rs`(224 行): 顶部两行速率 / 按 PID 明细表(以 `tgid` 为键,
    按字节排序, 一屏 14 行 + 溢出计数, "按住"非零染黄) / 最近 200 行事件;
    `q`·`Esc` 退出并走同一套收尾, `p`·空格 冻结刷新但事件继续收
  - `stats.rs` 加 `PidRow` 与按 PID 累加器, **只在界面模式开启**, 纯文本每条事件不多一次加锁
  - 实测: 界面那次 98,106 事件 `TOTAL` 与日志行数差 **0**(每秒行 45 条只在文件里, 屏幕 `⏱` 0 次);
    上传 20,000,000 B = 19.07 MiB 对表里 **19.10 MB**; 下载 92.47 MiB 对累计 **93.75 MB**;
    100 列(`stty rows 30 cols 100`)头部两行仍放得下; 纯文本回归 `TOTAL 595` == 595
  - 依赖 `ratatui 0.30.2` + `crossterm 0.29.0(events)`(0.30 不再再导出 crossterm)
  - 文件: `M` `Cargo.lock` `README.md` `config.toml` `docs/README_CN.md` `docs/TESTING.md`
    `observer/Cargo.toml` `observer/src/{config,lib,main,stats}.rs`; `??` `CHANGELOG.md` `observer/src/tui.rs`

- **`1e13927`** · 2026-09-28 · 每秒活行 + 毫秒时间戳 + 日志分片, 文档拆分双语化(18 文件 +1291/−170)
  - 活行靠 `\r` + `ESC[K` 原地刷新, 同一行每秒另写文件一份; 逐事件行不再上屏(那行 `println!` 是注释掉的)
  - 每行日志加 `[HH:MM:SS.mmm]`; `max_log_mb` 写满切 `traffic.2.log`(0 或不写 = 永不切分)
  - 收尾改成 stop 标志 → 300 ms 排空 → 取消; 统计任务 `await` 不再 `abort`
  - 修正: 汇总少计(四种规模差 **0**: 2,769,951 / 1,480,008 / 444,987 / 84,844);
    `s📈` 那个杂字符; 写死的"约六成"改成每次现算(实测 38.6 % ~ 100 %); 亚毫秒改显 µs;
    `新建连接速率`→`发起连接`; "按住"→`发不出去`; 清掉 18 处改动标记
  - 实测: 20,000 次 `send(64 KiB)` 在 5,201 事件/s 满载下 → **20,000 行 / 1,310,720,000 字节**;
    背压 `Blocked: 30015456233 ns` 对应用自报 `30.02s`(差 0.02 %); 上传 100 MB → `95.37 MiB`
    = 100,000,000 B; 928.6 s 那次 `2947.89 MB` 用 `awk` 重算得同一值; `max_log_mb = 1` 每片 1,059,5xx B
  - 归因的坑: 一次 960 s 里 `curl` 有 **107 个 PID**; 软中断占比 `TCP STATE` 663/1,315 = 50.4 %,
    `TCP RETRANSMIT` 326/449 = 72.6 %; 日志体积 **16.6 MB/min**
  - 新增 `docs/LIMITS.md`、`docs/TESTING.md`、`docs/README_CN.md`、`test/block_probe.py`;
    `.gitignore` 忽略 `pass.txt`

- **`0c1ca1e`** · 2026-09-27 · 拆成 lib + bin, 按职责分文件, 测试移到 tests/(7 文件 +581/−549)
  - `observer/src/main.rs` **683 行 → 156 行**, 只剩装配与收事件; 新模块
    `config.rs` 89 / `hooks.rs` 115 / `lib.rs` 12 / `report.rs` 185 / `stats.rs` 50 / `tests/report.rs` 108
  - 输出改由一张 `LOG_SPECS` 表驱动(逐行与退出汇总共用同一份 tag); 挂载改遍历 `hooks::plan()`
  - 4 个测试: 每个标签的确切渲染行、16 字节全宽名钉住 `Comm:` 列、`err=-110` 往返、
    枚举值 == 表下标

- **`db008ad`** · 2026-09-26 · 钩子扩到 12 个, 表驱动输出 + 退出汇总(8 文件 +971/−48)
  - 新增 `tcp_connect` / `tcp_set_state` / `tcp_send_active_reset` / `sk_stream_wait_memory`
    + 四个 UDP 入口; **IPv4 与 IPv6 是两个不同内核函数**, 只挂 v4 会静默丢掉全部 IPv6
  - `TcpEvent` 末尾追加 `value`(错误码 / 新状态), 不动原有字段顺序
  - `recv_func` 从 `sock_recvmsg` 换 `tcp_recvmsg`: 实测 120 s 53,085 事件里 40.7 % 来自
    零个 TCP socket 的进程(仅 Xwayland 17,879), 换后速率 **442/s → 39/s**
  - 新增 `hooks_candidates.txt`(候选钩子, 标注能否归因到进程 `P` / 落软中断 `S`)

- **`e2b968c`** · 2026-09-26 · 新增 `hooks.txt`(1534 行): `/proc/kallsyms` 导出,
  用来确认符号存在以及它是 `T` 还是 `t`

- **`81f03c5`** · 2026-09-16 · 文档: 改 `README.md`、`docs/CN.md`, 新增 `docs/EN.md`

- **`672d8d7`** · 2026-09-16 · 文档: 更新 `README.md`

- **`7bdd3eb`** · 2026-09-08 · `build.sh` 取消注释并修好(逐项查依赖 → `set -e` → 产出两个构件);
  新增 `docs/CN.md`: `cargo install bpf-linker` 为什么必然失败
  (`could not find llvm-config`), 改用 `cargo binstall`

- **`17ac37e`** · 2025-12-25 · 新增 TCP 重传探针 `tcp_retransmit_skb` 及其配置键

- **`947ed70`** · 2025-12-25 · 修一处**挂错位置**(入向探针被挂到 `tcp_send` 上); 修好后能检测到
  `git` / `node` / `Relay` / `kworker` / `GnsPortTracker`; 加连接检测; 首次加入 `test/curl-script.sh`

- **`db30239`** · 2025-12-25 · 新增 `tcp_recvmsg` 探针, 开始有入向数据

- **`f62dd93`** · 2025-12-15 · 启动过程(过滤规则 / 目标 PID / 挂载清单)也写进日志文件

- **`dafd46c`** · 2025-12-15 · 日志落盘结构定型: 新增 `observer/src/logger.rs`, 写进
  `results/<YYYY-MM>/<DD_HH-MM-SS_run>/` 并在同目录存一份本次 `config.toml`;
  `.gitignore` 新增忽略 `results/`

- **`1104377`** · 2025-12-14 · 首次出现 `config.toml`: 要观测的 PID 从 `run.sh` 的参数挪进配置文件
  —— "程序不接受命令行参数"这条规矩的起点

- **`baa25ec`** · 2025-12-01 · 补注释 + 修中文符号(改了 `build.sh`、`run.sh`、`observer/build.rs`、
  `observer-common/src/lib.rs`、`observer-ebpf/src/main.rs`、`observer/src/main.rs`)

- **`6b6697c`** · 2025-12-01 · 用户态与内核态成型, 全局采集能跑; 修 `.gitignore` 取消跟踪日志;
  新增 `build.sh` 与 `run.sh`. 当时**还识别不到 `websocket` / `press_test` 那个进程的流量**

- **`f1df56d`** · 2025-11-28 · 初始提交(18 文件 1667 行): `observer` / `observer-ebpf` /
  `observer-common` 三个 crate + workspace + `rustfmt.toml` + `.cargo/config.toml`
  (`runner = "sudo -E"`) + 三份 LICENSE + README
