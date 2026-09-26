# observer

An eBPF-based per-process network traffic observer built with
[Aya](https://aya-rs.dev). It attaches kprobes/kretprobes to kernel TCP and UDP
functions, pairs entry and return to measure how long the kernel spent on each
call, and reports one line per event to the terminal and to disk.

## Probes

Twelve hooks, all of them verified against live traffic (see
[Measured results](#measured-results)). Labels below are exactly what appears in
the log.

| Label | Config key | Kernel function | What one line means |
| :------------------- | :---------------------- | :------------------------- | :-------------------------------------------- |
| `[SEND]` | `target_func` | `tcp_sendmsg` | bytes an application handed to TCP for sending |
| `[RECV]` | `recv_func` | `tcp_recvmsg` | bytes an application took out of the TCP receive buffer |
| `[NEW CONN]` | `accept_func` | `inet_csk_accept` | a server socket dequeued a completed connection |
| `[TCP RETRANSMIT]` | `retransmit_func` | `tcp_retransmit_skb` | the kernel re-sent a packet that was not acknowledged |
| `[TCP CONNECT]` | `connect_func` | `tcp_connect` | a client started a connection; carries the return code (`err=-110` on timeout) |
| `[TCP STATE]` | `state_func` | `tcp_set_state` | one TCP state-machine transition (`-> ESTABLISHED`, `-> CLOSE_WAIT`, …) |
| `[BACKPRESSURE]` | `backpressure_func` | `sk_stream_wait_memory` | the send buffer was full and the application was held by the kernel; `Blocked:` is how long |
| `[RST]` | `reset_func` | `tcp_send_active_reset` | this end actively aborted a connection |
| `[UDP4 SEND]` / `[UDP4 RECV]` | `udp_send_func` / `udp_recv_func` | `udp_sendmsg` / `udp_recvmsg` | IPv4 datagram written / read |
| `[UDP6 SEND]` / `[UDP6 RECV]` | `udp6_send_func` / `udp6_recv_func` | `udpv6_sendmsg` / `udpv6_recvmsg` | IPv6 datagram written / read |

IPv4 and IPv6 UDP are **two separate kernel functions**; hooking only the v4
pair silently drops all IPv6 DNS and QUIC traffic. TCP has no such split —
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
> [docs/CN.md](docs/CN.md) for the full error and explanation.

## Build

```shell
./build.sh
```

The script is idempotent — it checks for each dependency before installing it —
and stops at the first failure (`set -e`). It produces two artifacts:

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

To control what is observed, edit `config.toml` — **not** `run.sh`. The
commented `--pid ...` lines still present in `run.sh` are historical; the
program takes no command-line arguments.

## Output

Every run creates a timestamped directory and writes to it:

```
results/<YYYY-MM>/<DD_HH-MM-SS_run>/
├── config.toml    # snapshot of the config used for this run
└── traffic.log    # captured events
```

The path is printed on startup (`📂 Logging to: ...`). Events are written both
to the terminal and to `traffic.log`. `results/` is gitignored.

Event lines and the exit summary are produced from a single table (`LOG_SPECS` in
`observer/src/main.rs`), so the label in the summary is byte-for-byte the label in
the log lines:

```
[TCP STATE] PID: 22918  Comm: Chrome_ChildIOT  -> SYN_SENT
[TCP CONNECT] PID: 22918  Comm: Chrome_ChildIOT  SYN-sent | Latency: 35722  ns
[UDP4 SEND] PID: 22918  Comm: Chrome_ChildIOT  Size: 34     bytes | Latency: 40689  ns
[SEND] PID: 22918  Comm: Chrome_ChildIOT  Size: 527    bytes | Latency: 33457  ns
[RECV] PID: 1660   Comm: Socket Thread    Size: 8216   bytes | Latency: 4951   ns
🚨 [TCP RETRANSMIT] PID: 2363   Comm: qoder            | Packet Lost!
🚧 [BACKPRESSURE] PID: 2318   Comm: WorkerThread     | Blocked: 2352   ns
```

On exit the program prints the per-hook hit counts, again to both places:

```
📊 ===== 钩子触发次数汇总 =====
   RECV         4910
   SEND         1118
   NEW CONN     0
   TCP RETRANSMIT 48
   TCP CONNECT  212
   TCP STATE    924
   BACKPRESSURE 0
   RST          0
   UDP4 RECV    430
   UDP4 SEND    430
   UDP6 RECV    0
   UDP6 SEND    0
   TOTAL        8072
```

## Measured results

A 60 s global-mode capture while playing a Bilibili video in Firefox, curl in a
loop, and an editor running produced **8,100 log lines** with all twelve hooks
attached and no attach failures.

- **Per-process attribution works.** Firefox's network thread (`Socket Thread`)
  alone accounted for **4,729 of the 4,910 `[RECV]` lines (96 %)**, plus 917
  `[SEND]`, 100 `[TCP CONNECT]`, 169 `[TCP STATE]`. Download-heavy shape
  (`RECV:SEND ≈ 4:1`) is exactly what video streaming should look like.
- **Bilibili streamed over TCP, not QUIC** — UDP6 stayed at 0, and all 862 UDP
  lines (431 sent + 431 received) came from DNS resolver threads and a thread
  named `ping`. (An earlier guess of mine that the browser's ~1,357-byte UDP
  packets were QUIC video was wrong.)
- **Retransmission and backpressure fire.** 48 `[TCP RETRANSMIT]` and, in a
  separate run, 7 `[BACKPRESSURE]` were captured. `[RST]` was verified with a
  synthetic test: 16 forced `SO_LINGER(1,0)` aborts produced exactly 16 lines.
- Largest single read observed: 16,401 bytes.

## Known limits

These are measured, not theoretical:

1. **No peer address or port.** The event carries process, direction, size and
   kernel time — nothing about *who* is on the other end. This is the single
   biggest gap: a video segment and a DNS reply look the same apart from size.
   Adding it means reading `skc_family` / `skc_dport` out of `struct sock` via
   `bpf_probe_read_kernel` (needs a struct offset, which is kernel-version
   specific), or switching to tracepoints such as `tcp:tcp_retransmit_skb`,
   which hand you family, both addresses and both ports as ready-made fields.
2. **Events from softirq / timer context cannot be attributed to a process.**
   In the run above, **522 of 924 `[TCP STATE]` lines were stamped to WiFi
   interrupt threads** (`irq/155-iwlwifi` and friends), and in another run 30 of
   47 retransmits were stamped to `swapper/N` (the idle task). Anything that can
   be driven by a kernel timer or by packet receive falls in this class: use it
   as a global counter, not as a per-process ranking.
3. **`Latency` is kernel function duration, not network delay.** It contains no
   RTT. For a blocking read it also includes the time spent waiting for data to
   arrive, so a large value can mean "slow copy" or "the app waited" — the two
   are indistinguishable today. `inet_csk_accept`'s value is dequeue time, not
   handshake time.
4. **`[RECV]` marks the moment the application read the bytes**, not the moment
   they arrived. Queue depth, dwell time and UDP drops are invisible.
5. **The exit summary under-counts.** Per-CPU reader tasks never stop, so events
   processed after the summary is printed still reach the log (8,100 lines vs
   `TOTAL 8072`). The log is complete; the summary is a snapshot. Fixing it
   needs a shutdown flag.
6. **The decoder side is out of scope.** Stutter caused by software decoding
   (this machine's Firefox has VA-API off and `iHD_drv_video.so init failed`)
   is invisible to socket-level hooks, which stop caring once the bytes reach
   the application buffer.

## Tests

`observer/src/main.rs` has a `#[cfg(test)]` module that pins the exact output
string of every label (including emoji spacing and column padding) and asserts
that each `TrafficDirection` discriminant still lines up with its row in
`LOG_SPECS`.

```shell
cargo test --release -p observer --no-run
./target/release/deps/observer-<hash>
```

Run the binary directly rather than `cargo test` because `.cargo/config.toml`
sets `runner = "sudo -E"`, which would make cargo ask for a password — these
tests only format strings and need no privileges.

## Configuration

`config.toml` in the repository root controls probe attachment, target
selection and filtering.

| Section     | Key                | Meaning                                                        |
| :---------- | :----------------- | :------------------------------------------------------------- |
| `probes`    | `target_func`      | Kernel symbol to hook for egress (default `tcp_sendmsg`)        |
|             | `recv_func`        | Kernel symbol to hook for ingress (default `tcp_recvmsg`; do not use `sock_recvmsg`) |
|             | `accept_func`      | Symbol for new connections (default `inet_csk_accept`)          |
|             | `retransmit_func`  | Symbol for retransmissions (default `tcp_retransmit_skb`)       |
|             | `connect_func`     | Symbol for client-side connection attempts (default `tcp_connect`) |
|             | `state_func`       | Symbol for TCP state transitions (default `tcp_set_state`)      |
|             | `reset_func`       | Symbol for locally sent RST (default `tcp_send_active_reset`)   |
|             | `backpressure_func` | Symbol hit when the send buffer holds the app (default `sk_stream_wait_memory`) |
|             | `udp_send_func` / `udp_recv_func` | IPv4 UDP (default `udp_sendmsg` / `udp_recvmsg`) |
|             | `udp6_send_func` / `udp6_recv_func` | IPv6 UDP (default `udpv6_sendmsg` / `udpv6_recvmsg`) |
| `discovery` | `force_pid`        | Monitor only this PID; takes precedence over auto-detection     |
|             | `auto_detect_name` | Substring match on process name; empty string means global mode |
| `filters`   | `include_names`    | Allowlist on `comm`; empty means allow all                      |
|             | `exclude_names`    | Denylist on `comm`; applied before the allowlist                |
| `settings`  | `perf_pages`       | Per-CPU perf buffer size, in pages, must be a power of two      |

`discovery.auto_detect_name = ""` (global mode) combined with
`filters.exclude_names` is the recommended setup for observing system-wide
traffic without drowning in noise from editors, browsers and kernel workers.

Available kernel symbols can be listed with:

```shell
grep -wE 'tcp_sendmsg|tcp_recvmsg|tcp_connect|tcp_set_state|tcp_send_active_reset|sk_stream_wait_memory|tcp_retransmit_skb|inet_csk_accept|udp_sendmsg|udp_recvmsg|udpv6_sendmsg|udpv6_recvmsg' /proc/kallsyms
```

A `T` means a global symbol, `t` a local one — both are attachable, but only if
the function was not inlined away. `hooks_candidates.txt` in the repository root
lists further candidate hooks, each marked with whether the resulting events can
be attributed to a process (`P`) or land in softirq/timer context (`S`).

## Documentation

- [docs/CN.md](docs/CN.md) — 中文版 `bpf-linker` 安装失败说明与解决方案.
- [docs/EN.md](docs/EN.md) — English version of the same troubleshooting note.

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
