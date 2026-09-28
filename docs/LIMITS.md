# Known limits / 已知局限

The eight items below are maintained here for both languages, in one place, so
the numbers cannot drift apart. Everything in this file was measured on this
machine (Debian, kernel `6.1.0-29-amd64`, 4 CPUs, a normal desktop session with
Firefox, Chrome, VS Code and a WiFi interface running); nothing here is
theoretical.

Contents / 目录: [English](#english) | [中文](#中文)

## English

1. **No peer address and no port.** An event carries process, direction, size
   and kernel time, and nothing about who is on the other end. This is the
   largest single gap: a video segment and a DNS reply differ only by size. Two
   ways out: read `skc_family` / `skc_dport` out of `struct sock` with
   `bpf_probe_read_kernel`, which costs a struct offset that changes with the
   kernel version; or move those hooks to tracepoints, for example
   `tcp:tcp_retransmit_skb`, which hand over family, both addresses and both
   ports as ready-made fields. Note that `ss` / `inet_diag` already give the
   same five-tuple plus RTT, RTO, cwnd and retransmit counters without root
   privileges, so a second tool, not a second probe, is the cheaper fix.

2. **Softirq and timer context cannot be attributed to a process.** Share of
   lines stamped to `swapper/N`, `irq/15x-iwlwifi` or `ksoftirqd`, counted from
   real logs: TCP state transitions **663 of 1,315 = 50.4 %** in one run and 522
   of 924 (56 %) in another; retransmits **326 of 449 = 72.6 %** in one run and
   30 of 47 (64 %) in another. The share swings that much, which is exactly why
   the exit block recalculates it every run instead of quoting a fixed figure.
   Anything a kernel timer or a received packet can drive belongs to this class.
   Practical rule: use `[TCP STATE]` and `[TCP RETRANSMIT]` as global counters,
   never as a per-process ranking.

3. **`Latency:` is kernel function duration, not network delay.** It contains no
   RTT at all. On a blocking read it also includes the time spent waiting for
   data to arrive, so a large value may mean "slow copy" or "the application
   waited", and today the two are indistinguishable. The `inet_csk_accept` value
   is dequeue time, not handshake time.

4. **`[RECV]` marks when the application read the bytes, not when they
   arrived.** Queue depth, dwell time and UDP drops are invisible, so a burst
   that sat in the receive buffer for two seconds and then read instantly looks
   identical to one that arrived instantly.

5. **The exit summary is exact, and that is measured.** It used to under-count:
   8,100 log lines against `TOTAL 8072`. Reader tasks are now told to stop, get
   300 ms to drain whatever already reached the perf buffer, and are then
   cancelled; the stats task is awaited rather than killed mid-print, which is
   what used to leave a stray character in front of the summary. Across
   2,769,951 events in one 928 s run and 1,480,008 in another, spanning several
   log shards, the number of event lines in the files equals `TOTAL` exactly
   (gap 0). What this does **not** prove is that the kernel handed over
   everything it saw: see the kretprobe note in the README, where the count was
   verified separately with a known 20,000-call workload.

6. **The decoder side is out of scope.** Stutter caused by software decoding is
   invisible to socket-level hooks: on this machine Firefox runs with VA-API off
   and logs `iHD_drv_video.so init failed`, and once bytes reach the application
   buffer these probes stop knowing or caring what happens to them.

7. **Aggregation is by `comm`, not by PID.** Every filter and every statistic
   keys on the 16-byte process name, so processes sharing a name collapse into
   one number. Measured: one 960 s run contained **107 distinct PIDs named
   `curl`**; in another, three live curls carried 2,305 / 541 / 90 MB
   respectively while the summary could only state `curl = 2,936 MB`. Per-event
   lines do carry `PID:`, so the split is available in the log; the exit summary
   just does not perform it yet. This is the reason "watch one process" needs a
   PID rather than a name.

8. **`max_log_mb` caps one shard, not the whole run.** Reaching it opens
   `traffic.2.log` instead of stopping, so total volume stays unbounded: 15.5
   minutes at about 2,900 events/s produced 4 shards and 257 MB
   (**16.6 MB/min**, roughly 24 GB per day). A `max_log_files` bound that recycles
   the oldest shard is not implemented.

## 中文

以下八条全部是实测出来的, 不是理论推导. 实测环境: Debian, 内核 `6.1.0-29-amd64`,
4 核, 普通桌面会话(Firefox、Chrome、VS Code 和一块无线网卡在跑).

1. **没有对端地址和端口.** 一个事件携带进程、方向、大小和内核耗时, 关于对端是谁
   什么也没有. 这是最大的单项缺口: 一段视频和一个 DNS 响应除了大小之外看起来完全
   一样. 两条出路: 用 `bpf_probe_read_kernel` 从 `struct sock` 里读 `skc_family` /
   `skc_dport`, 代价是要一个随内核版本变化的结构体偏移; 或者把相关钩子改挂
   tracepoint, 例如 `tcp:tcp_retransmit_skb`, 它把协议族、两侧地址和两侧端口作为
   现成字段直接给你. 另外注意 `ss` / `inet_diag` 本来就免 root 地给出同样的五元组
   加上 RTT、RTO、cwnd 和重传计数, 所以更便宜的做法是再接一个工具, 而不是再挂一个
   探针.

2. **软中断 / 定时器上下文的事件无法归因到进程.** 实测打在 `swapper/N`、
   `irq/15x-iwlwifi` 或 `ksoftirqd` 上的行占比(直接从真实日志里数): TCP 状态迁移
   **1,315 中 663 = 50.4 %**, 另一次 924 中 522(56 %); 重传 **449 中 326 = 72.6 %**,
   另一次 47 中 30(64 %). 这个比例能波动这么大, 正是退出块每次运行现算、而不在文档
   里引用固定值的原因. 凡是内核定时器或收包能驱动的都属于这一类. 实用结论: 把
   `[TCP STATE]` 和 `[TCP RETRANSMIT]` 当全局计数器用, 不要当按进程的排行用.

3. **`Latency:` 是内核函数持续时间, 不是网络时延.** 它完全不含 RTT. 对一次阻塞读,
   它还包含等待数据到达的时间, 所以一个大值可能意味着"拷贝慢", 也可能意味着"应用在
   等", 这两者目前无法区分. `inet_csk_accept` 的值是出队时间, 不是握手时间.

4. **`[RECV]` 标记的是应用读取字节的时刻, 不是字节到达的时刻.** 队列深度、驻留时间
   和 UDP 丢弃都不可见, 所以一批数据在接收缓冲区里躺了两秒才被瞬间读走, 和它一到就被
   读走, 看起来一模一样.

5. **退出汇总是精确的, 这一点经过实测.** 它曾经少计: 8,100 行日志对 `TOTAL 8072`.
   现在会通知读取任务停止, 给它们 300 ms 排空已经到达 perf 缓冲的内容, 然后再取消;
   统计任务是被 await 而不是在打印中途被杀掉 — 后者正是以前在汇总前面留下一个杂字符
   的原因. 在一次 928 秒运行的 2,769,951 个事件和另一次 1,480,008 个事件中, 跨若干
   日志分片, 文件里事件行的数量与 `TOTAL` 完全相等(差 0). 但这**不**证明内核把看到
   的都交出来了: 见 README 里的 kretprobe 说明, 那里用一个已知 20,000 次调用的负载
   单独验过计数.

6. **解码侧不在范围内.** 软件解码造成的卡顿对 socket 层钩子是不可见的: 本机 Firefox
   关掉了 VA-API 并且日志里出现 `iHD_drv_video.so init failed`, 而一旦字节到达应用
   缓冲区, 这些探针就不再关心它们后来怎么样了.

7. **聚合按 `comm` 而非 PID.** 过滤器和每一项统计都以那 16 字节的进程名为键, 所以
   同名的多个进程会塌成一个数字. 实测: 一次 960 秒的运行里包含 **107 个不同的名叫
   `curl` 的 PID**; 另一次里存活的三个分别承载了 2,305 / 541 / 90 MB, 而汇总只能说
   `curl = 2,936 MB`. 逐事件的行确实带 `PID:`, 所以从日志里做拆分是可行的, 只是退出
   汇总还没做. 这就是"盯住一个进程"必须用 PID 而不是用进程名的原因.

8. **`max_log_mb` 限制的是单个分片, 不是整次运行.** 达到它不会停止, 而是开始写
   `traffic.2.log`, 所以总量没有上界: 以约 2,900 事件/s 跑 15.5 分钟产生了 4 个分片、
   257 MB(**16.6 MB/min**, 约合每天 24 GB). 像 `max_log_files` 那样回头覆盖最旧分片
   的上界尚未实现.
