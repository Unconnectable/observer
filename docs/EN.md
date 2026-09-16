# bpf-linker installation issue

When building `observer`, installing `bpf-linker` by hand with
`cargo install bpf-linker` commonly fails like this:

```
warning: bpf-linker@0.11.1: Installing bpf-linker through `cargo install` is NOT recommended for regular users due to dependency on specific LLVM version, system libraries and overall complexity of getting the setup right. See https://github.com/aya-rs/bpf-linker#installation for easier installation methods.
error: failed to run custom build command for `bpf-linker v0.11.1`

Caused by:
  process didn't exit successfully: `/tmp/cargo-install3LysUH/release/build/bpf-linker-73f35fc69af93d62/build-script-build` (exit status: 1)
  --- stdout
  cargo:warning=Installing bpf-linker through `cargo install` is NOT recommended for regular users due to dependency on specific LLVM version, system libraries and overall complexity of getting the setup right. See https://github.com/aya-rs/
  bpf-linker#installation for easier installation methods.
  cargo:rerun-if-env-changed=LLVM_PREFIX
  cargo:rerun-if-env-changed=PATH

  --- stderr
  Error: could not find llvm-config in directories specified by environment
  variable `PATH` /home/filament/.local/bin:/home/filament/.cargo/bin:/home/filament/.local/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
warning: build failed, waiting for other jobs to finish...
error: failed to compile `bpf-linker v0.11.1`, intermediate artifacts can be found at `/tmp/cargo-install3LysUH`.
To reuse those artifacts with a future compilation, set the environment variable `CARGO_BUILD_BUILD_DIR` to that path.
```

## Cause

`bpf-linker` depends on LLVM, but not every machine ships an LLVM development
environment, so building it from source via `cargo install` fails.

## Solution

Per the [official bpf-linker installation docs](https://github.com/aya-rs/bpf-linker#installation),
install a prebuilt binary instead:

```sh
# 1. install the cargo-binstall helper
cargo install cargo-binstall

# 2. fetch the prebuilt bpf-linker binary
cargo binstall bpf-linker
```

`build.sh` already does this for you: if `bpf-linker` is missing it installs
`cargo-binstall` first and then pulls the prebuilt binary, so there is no need
to run the commands above manually or to have LLVM installed system-wide.
