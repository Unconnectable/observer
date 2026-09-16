# observer

An eBPF-based TCP traffic observer built with [Aya](https://aya-rs.dev).
It attaches kprobes to kernel TCP functions, correlates entry/return to measure
latency, and reports per-event traffic lines to the terminal and to disk.

Probes currently attached:

| Probe                        | Config key        | Reports                   |
| :--------------------------- | :---------------- | :------------------------ |
| `tcp_sendmsg`                | `target_func`     | `[SEND]`                  |
| `sock_recvmsg`               | `recv_func`       | `[RECV]`                  |
| `inet_csk_accept`            | `accept_func`     | `[NEW CONN]`              |
| `tcp_retransmit_skb`         | `retransmit_func` | `[RETRANSMIT]`            |

Each line carries PID, process name (`comm`), byte count and latency in ns.

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

## Configuration

`config.toml` in the repository root controls probe attachment, target
selection and filtering.

| Section     | Key                | Meaning                                                        |
| :---------- | :----------------- | :------------------------------------------------------------- |
| `probes`    | `target_func`      | Kernel symbol to hook for egress (default `tcp_sendmsg`)        |
|             | `recv_func`        | Kernel symbol to hook for ingress (default `sock_recvmsg`)      |
|             | `accept_func`      | Symbol for new connections (default `inet_csk_accept`)          |
|             | `retransmit_func`  | Symbol for retransmissions (default `tcp_retransmit_skb`)       |
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
sudo grep -E 'tcp_sendmsg|tcp_recvmsg|sock_recvmsg|tcp_retransmit' /proc/kallsyms
```

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
