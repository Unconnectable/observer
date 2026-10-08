# observer

[English](README.md) | [Chinese](docs/wREADME_CN.md)

An eBPF-based per-process network traffic observer built with
[Aya](https://aya-rs.dev). It attaches kprobes/kretprobes to kernel TCP and UDP
functions, pairs entry and return to measure how long the kernel spent on each
call, and writes one line per event to disk. The terminal shows a single
self-overwriting status line that refreshes every second.

## Probes

Twelve hooks, all of them verified against live traffic (see
[Measured results](#measured-results)). Labels below are exactly what appears in
the log.

| Label                         | Config key                          | Kernel function                   | What one line means                                                                         |
| :---------------------------- | :---------------------------------- | :-------------------------------- | :------------------------------------------------------------------------------------------ |
| `[SEND]`                      | `target_func`                       | `tcp_sendmsg`                     | bytes an application handed to TCP for sending                                              |
| `[RECV]`                      | `recv_func`                         | `tcp_recvmsg`                     | bytes an application took out of the TCP receive buffer                                     |
| `[NEW CONN]`                  | `accept_func`                       | `inet_csk_accept`                 | a server socket dequeued a completed connection                                             |
| `[TCP RETRANSMIT]`            | `retransmit_func`                   | `tcp_retransmit_skb`              | the kernel re-sent a packet that was not acknowledged                                       |
| `[TCP CONNECT]`               | `connect_func`                      | `tcp_connect`                     | a client started a connection; carries the return code (`err=-110` on timeout)              |
| `[TCP STATE]`                 | `state_func`                        | `tcp_set_state`                   | one TCP state-machine transition (`-> ESTABLISHED`, `-> CLOSE_WAIT`, etc.)                  |
| `[BACKPRESSURE]`              | `backpressure_func`                 | `sk_stream_wait_memory`           | the send buffer was full and the application was held by the kernel; `Blocked:` is how long |
| `[RST]`                       | `reset_func`                        | `tcp_send_active_reset`           | this end actively aborted a connection                                                      |
| `[UDP4 SEND]` / `[UDP4 RECV]` | `udp_send_func` / `udp_recv_func`   | `udp_sendmsg` / `udp_recvmsg`     | IPv4 datagram written / read                                                                |
| `[UDP6 SEND]` / `[UDP6 RECV]` | `udp6_send_func` / `udp6_recv_func` | `udpv6_sendmsg` / `udpv6_recvmsg` | IPv6 datagram written / read                                                                |

IPv4 and IPv6 UDP are **two separate kernel functions**; hooking only the v4
pair silently drops all IPv6 DNS and QUIC traffic. TCP has no such split:
`tcp_sendmsg` / `tcp_recvmsg` serve both families, which is why TCP lines carry
no `4`/`6` marker yet.

> **Why `tcp_recvmsg` and not `sock_recvmsg`:** `sock_recvmsg` is the generic
> socket entry point, so it also counts local IPC between the X server, the
> input method and D-Bus. Measured on a desktop session that produced 53,085
> events in 120 s, three processes with **zero TCP sockets** contributed 40.7 %
> of them (Xwayland alone: 17,879). Moving the hook to `tcp_recvmsg` dropped
> those to 0 and cut the event rate from 442/s to 39/s.

## Prerequisites

- Linux with eBPF/BTF support, and root (loading probes requires `CAP_BPF`/`CAP_SYS_ADMIN`)
- Rust stable toolchain
- Rust nightly toolchain with the `rust-src` component
- `bpf-linker`
- `cc` / build-essential

`build.sh` installs all of the above if they are missing, so you normally do not
need to install anything by hand.

> **Note:** prefer `cargo binstall bpf-linker` over `cargo install bpf-linker`.
> Building `bpf-linker` from source requires a matching LLVM development
> environment and commonly fails with `could not find llvm-config`. See
> [docs/EN.md](docs/EN.md) for the full error and explanation.

## Build

```shell
./build.sh
```

The script is idempotent: it checks each dependency before installing it, and
stops at the first failure (`set -e`). It produces two artifacts:

| Artifact                                     | Description                          |
| :------------------------------------------- | :----------------------------------- |
| `target/bpfel-unknown-none/release/observer` | eBPF kernel-side object              |
| `target/release/observer`                    | User-space loader and event consumer |

The eBPF object is embedded into the user-space binary at compile time, so both
must be built before running. Building the kernel-side object by hand:

```shell
cargo +nightly build --release -p observer-ebpf \
  --target bpfel-unknown-none \
  -Z build-std=core,alloc \
  -Z build-std-features=compiler-builtins-mem
```

## Run

```shell
sudo ./run.sh
```

`run.sh` must be executed from the repository root: the program reads
`config.toml` relative to the current working directory and aborts if it is
missing.

To control what is observed, edit `config.toml`, **not** `run.sh`. The commented
`--pid ...` lines still present in `run.sh` are historical; the program takes no
command-line arguments.

## Output

Every run creates a timestamped directory and writes to it:

```sh
results/<YYYY-MM>/<DD_HH-MM-SS_run>/
├── config.toml      # snapshot of the config used for this run
├── traffic.log      # captured events
├── traffic.2.log    # only if max_log_mb was reached
└── traffic.3.log    # etc.
```

The path is printed on startup (`📂 Logging to: ...`). Every line in the log is
prefixed with a millisecond clock (`[14:44:43.573] ...`) so a run can later be
cut into intervals and compared against another tool's timeline. `results/` is
gitignored.

Per-event lines go to the **file only**; the terminal shows one row that
refreshes in place every second (measured at ~2,900 events/s it stays a single
row and never scrolls). The row is real output from a 42 s capture:

```sh
⏱ 23s   1068.1 条/s ↓1232.7 KB/s ↑8.8 KB/s 重传 0 次
```

Field by field: elapsed seconds since startup, event rate across all twelve
hooks, application bytes read per second, application bytes written per second,
and how many retransmits fell in that second. The same row is appended to the
log once per second, so the file keeps the whole time series.

When a shard reaches `max_log_mb`, the writer moves on to `traffic.2.log` and
records the switch **in the file** (not on screen, because it would chop the
live row). That marker line is:

```sh
---- 上一片写满, 分片从这里开始: "results/2026-09/28_14-22-31_run/traffic.2.log" ----
```

Event lines and the exit summary are produced from a single table (`LOG_SPECS` in
`observer/src/report.rs`), so the label in the summary is byte-for-byte the label
in the log lines:

```sh
[TCP STATE] PID: 22918  Comm: Chrome_ChildIOT  -> SYN_SENT
[TCP CONNECT] PID: 22918  Comm: Chrome_ChildIOT  SYN-sent | Latency: 35722  ns
[UDP4 SEND] PID: 22918  Comm: Chrome_ChildIOT  Size: 34     bytes | Latency: 40689  ns
[SEND] PID: 22918  Comm: Chrome_ChildIOT  Size: 527    bytes | Latency: 33457  ns
[RECV] PID: 1660   Comm: Socket Thread    Size: 8216   bytes | Latency: 4951   ns
🚨 [TCP RETRANSMIT] PID: 2363   Comm: qoder            | Packet Lost!
🚧 [BACKPRESSURE] PID: 2318   Comm: WorkerThread     | Blocked: 2352   ns
```

On exit the program first waits for the per-CPU reader tasks to drain, then
prints derived metrics and the per-hook hit counts, to both terminal and log.
This is real output from a 928.6 s global-mode run that was pushing ~3.2 MB/s:

```sh
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

The metrics block has seven rows, in this order:

```sh
1  运行时长        run duration
2  事件速率        events per second, all twelve hooks summed
3  下行(应用字节)  downlink, application bytes read + rate
4  上行(应用字节)  uplink, application bytes written + rate
5  重传事件        retransmit rate + how many of them are unattributable
6  发起连接        client-side connect rate
7  发不出去        total time the kernel held a sender, and how often
```

How to read the rows that are *not* self-evident:

- **Downlink / uplink (rows 3 and 4)** count bytes the application read from or
  wrote to the socket. They exclude TCP/IP headers (~7 % more at the NIC) and
  retransmitted data, so they are always below what a network counter shows.
- **Retransmits (row 5)** is the number of `tcp_retransmit_skb` **calls**, not
  the number of packets lost, and there is no denominator available (one call
  can re-send several segments). Treat it as an intensity, never as a loss
  percentage. The parenthetical is computed at exit from the current run because
  that share swings widely: measured 38.6 %, 56.1 %, 66.7 %, 72.6 % and 93.2 %
  across five separate runs on this machine.
- **Held by the kernel (row 7)** is how long the kernel held a sender because its
  send buffer was full. Sub-millisecond values are routine noise; the useful
  reading threshold measured here is **more than 1 ms for one event, or more
  than 50 ms accumulated within one second**. Below 1 ms it is printed in
  microseconds, and if nothing happened the row says so instead of printing
  `0.0 ms`.
- **Connect rate (row 6)** counts client-side `tcp_connect`; the server-side view
  is the `NEW CONN` counter in the summary block. These two are wildly
  asymmetric on a client machine (366 vs 6 in the run above), which is expected:
  `inet_csk_accept` sleeps inside the kernel until a connection is actually
  dequeued, so its return probe fires far less often than `tcp_connect`'s.

### Terminal UI

Setting `ui_mode = "tui"` in `config.toml` replaces the live row with a
three-pane dashboard: rates on top, a **per-PID** table in the middle (sorted by
bytes, `q` quits and runs the same exit summary), and the last 200 event lines at
the bottom. Reconstructed from a captured 46 s session that downloaded 93 MB and
uploaded 20 MB:

Measured on a 100-column terminal the header still fits; below that the long
second row starts to clip. Per-PID accounting is only switched on in this mode, so
the text mode pays no extra lock cost.

## Measured results

A 60 s global-mode capture while playing a Bilibili video in Firefox, curl in a
loop, and an editor running produced **8,100 log lines** with all twelve hooks
attached and no attach failures.

- **Per-process attribution works.** Firefox's network thread (`Socket Thread`)
  alone accounted for **4,729 of the 4,910 `[RECV]` lines (96 %)**, plus 917
  `[SEND]`, 100 `[TCP CONNECT]`, 169 `[TCP STATE]`. Download-heavy shape
  (`RECV:SEND ≈ 4:1`) is exactly what video streaming should look like.
- **Bilibili streamed over TCP, not QUIC.** UDP6 stayed at 0, and all 862 UDP
  lines (431 sent + 431 received) came from DNS resolver threads and a thread
  named `ping`. (An earlier guess of mine that the browser's ~1,357-byte UDP
  packets were QUIC video was wrong.)
- **Retransmission and backpressure fire.** 48 `[TCP RETRANSMIT]` and, in a
  separate run, 7 `[BACKPRESSURE]` were captured. `[RST]` was verified with a
  synthetic test: 16 forced `SO_LINGER(1,0)` aborts produced exactly 16 lines.
  In a 928 s real-world run 7 `[RST]` appeared, all of them from the same Chrome
  IO thread, three of them inside the same millisecond.
- Largest single read observed: 16,401 bytes.

### Byte accounting checked against curl

Long runs were compared against curl's own counters, and the numbers agree to
the byte, in both directions:

| What curl did                       | curl reported                             | observer reported                                                           |
| :---------------------------------- | :---------------------------------------- | :-------------------------------------------------------------------------- |
| 100 MB upload via `curl POST /__up` | 100,000,000 B uploaded, 1.44 MB/s, 69.3 s | uplink **95.37 MiB = 100,000,000 B**                                        |
| 20,000 x `send(64 KiB)` in Python   | 20,000 calls, 1,310,720,000 B             | **20,000 lines, 1,310,720,000 B**                                           |
| ISO download, 928.6 s global run    | ~3.2 MB/s                                 | downlink **2947.89 MB**, recomputed by `awk` over the log to the same value |

That 20,000-call test was run while four curl downloads were saturating the
machine (5,201 events/s), which is also the evidence that the kretprobe instance
pool is not silently dropping returns: `/sys/kernel/debug/kprobes/list` on this
kernel exposes no `nmissed` counter (it lists the 21 registered probes, and the
three entry-only hooks correctly have no `r` row), so the count was verified
empirically instead.

### Backpressure measured end to end

`test/block_probe.py` makes the kernel actually hold a sender: the server accepts
and then drains only 4 KiB every 0.3 s while the client writes 100 MB.

```sh
observer: [14:28:09.689] 🚧 [BACKPRESSURE] PID: 47684  Comm: python3  | Blocked: 30015456233 ns
python:   send() 卡住(>1ms) 1 次, 合计 30.02s
```

30.0155 s measured in kernel vs 30.02 s measured by the application: 0.02 %
apart. Two independent observer instances running at the same time recorded the
same figure.

The flip side is just as useful: the same hook fired **0 times** during a real
1.44 MB/s upload, because curl was paced by the pipe and by HTTP framing and
could always hand its bytes to the socket. So this row is a discriminator: "the
stall is in the socket buffer" versus "the stall is above or below the socket".
It is not a throughput gauge. On this desktop, across 928 s of real browsing
plus downloads, 19 events appeared and the longest was 2.9 µs.

## Known limits

All eight limits are measured on a real desktop rather than reasoned about, and
they are maintained in one bilingual file so the two languages cannot drift:
**[docs/LIMITS.md](docs/LIMITS.md)**. In short: no peer address or port, softirq
context is unattributable, `Latency:` is kernel time not network delay, `[RECV]`
timestamps the read rather than the arrival, the decoder side is out of scope,
aggregation keys on `comm` instead of PID, and `max_log_mb` caps one shard
instead of the run. (One limit that used to be here, the under-counting exit
summary, has been fixed and is verified in that file.)

## Tests

Format tests are `observer/tests/report.rs` (4 tests, no privileges); everything
else is a manual harness run against live traffic. The full procedure, the
measured baselines, the traps that look like bugs, and how to add a thirteenth
hook live in **[docs/TESTING.md](docs/TESTING.md)**. Quick version:

```shell
cargo test --release -p observer --test report --no-run
./target/release/deps/report-<hash>     # expected: 4 passed; 0 failed
```

Do not run plain `cargo test`: `.cargo/config.toml` sets `runner = "sudo -E"`, so
cargo asks for a password. Use the exact path cargo prints, not a shell glob.

## Configuration

`config.toml` in the repository root controls probe attachment, target selection
and filtering.

| Section     | Key                                 | Meaning                                                                              |
| :---------- | :---------------------------------- | :----------------------------------------------------------------------------------- |
| `probes`    | `target_func`                       | Kernel symbol to hook for egress (default `tcp_sendmsg`)                             |
|             | `recv_func`                         | Kernel symbol to hook for ingress (default `tcp_recvmsg`; do not use `sock_recvmsg`) |
|             | `accept_func`                       | Symbol for new connections (default `inet_csk_accept`)                               |
|             | `retransmit_func`                   | Symbol for retransmissions (default `tcp_retransmit_skb`)                            |
|             | `connect_func`                      | Symbol for client-side connection attempts (default `tcp_connect`)                   |
|             | `state_func`                        | Symbol for TCP state transitions (default `tcp_set_state`)                           |
|             | `reset_func`                        | Symbol for locally sent RST (default `tcp_send_active_reset`)                        |
|             | `backpressure_func`                 | Symbol hit when the send buffer holds the app (default `sk_stream_wait_memory`)      |
|             | `udp_send_func` / `udp_recv_func`   | IPv4 UDP (default `udp_sendmsg` / `udp_recvmsg`)                                     |
|             | `udp6_send_func` / `udp6_recv_func` | IPv6 UDP (default `udpv6_sendmsg` / `udpv6_recvmsg`)                                 |
| `discovery` | `force_pid`                         | Monitor only this PID; takes precedence over auto-detection                          |
|             | `auto_detect_name`                  | Substring match on process name; empty string means global mode                      |
| `filters`   | `include_names`                     | Allowlist on `comm`; empty means allow all                                           |
|             | `exclude_names`                     | Denylist on `comm`; applied before the allowlist                                     |
| `settings`  | `perf_pages`                        | Per-CPU perf buffer size, in pages, must be a power of two                           |
|             | `max_log_mb`                        | Size of one `traffic*.log` shard, in MB. `0` or the key absent = never split         |
|             | `ui_mode`                           | `"tui"` = live three-pane dashboard; any other value or the key absent = plain text  |

`discovery.auto_detect_name = ""` (global mode) combined with
`filters.exclude_names` is the recommended setup for observing system-wide
traffic without drowning in noise from editors, browsers and kernel workers.

Available kernel symbols can be listed with:

```shell
grep -wE 'tcp_sendmsg|tcp_recvmsg|tcp_connect|tcp_set_state|tcp_send_active_reset|sk_stream_wait_memory|tcp_retransmit_skb|inet_csk_accept|udp_sendmsg|udp_recvmsg|udpv6_sendmsg|udpv6_recvmsg' /proc/kallsyms
```

A `T` means a global symbol, `t` a local one; both are attachable, but only if
the function was not inlined away. `hooks_candidates.txt` in the repository root
lists further candidate hooks, each marked with whether the resulting events can
be attributed to a process (`P`) or land in softirq/timer context (`S`).

## Documentation

- [CHANGELOG.md](CHANGELOG.md) - release history, dated by commit.
- [docs/TESTING.md](docs/TESTING.md) - how each hook is verified, with measured baselines.
- [docs/LIMITS.md](docs/LIMITS.md) - the eight measured limits, English and Chinese in one file.
- [docs/README_CN.md](docs/README_CN.md) - full Chinese version of this README.
- [docs/EN.md](docs/EN.md) - `bpf-linker` installation failure: the raw error and how to fix it.
- [docs/CN.md](docs/CN.md) - the same troubleshooting note in Chinese.

## License

With the exception of eBPF code, observer is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
