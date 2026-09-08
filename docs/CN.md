# 构建与运行说明

本文档说明 `build.sh` 和 `run.sh` 两个脚本的作用及使用方法.

------

## 🔧 依赖说明:bpf-linker 安装问题

在编译 `observer` 项目时,`build.sh` 中的 `cargo install bpf-linker` 可能会遇到以下错误(大概是更新后无法直接安装):

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



### 原因

`bpf-linker` 依赖于 LLVM 设施,但并不是所有电脑都预装了 LLVM 开发环境,导致 `cargo install` 从源码编译失败.

### 解决方案

根据 [bpf-linker 官方安装文档](https://github.com/aya-rs/bpf-linker#installation),推荐使用预编译版本安装:

```sh
# 1. 安装 cargo-binstall 工具
cargo install cargo-binstall

# 2. 使用 binstall 下载预编译的 bpf-linker 二进制文件
cargo binstall bpf-linker
```



修改后的 `build.sh` 已自动集成此方案,无需手动执行上述命令.

------

## 📦 build.sh - 构建脚本

`build.sh` 负责从源码编译整个 `observer` 项目,包括 eBPF 内核态程序和用户态程序.

### 功能说明

1. **安装依赖**
   - `build-essential`:C 编译器工具链(如果系统缺少 `cc` 命令)
   - `bpf-linker`:eBPF 程序链接器,通过 `cargo-binstall` 安装预编译版本(无需系统预装 LLVM)
   - `nightly` Rust 工具链及 `rust-src` 组件
2. **编译 eBPF 程序**
   - 使用 `cargo +nightly` 编译 `observer-ebpf` 模块
   - 目标平台:`bpfel-unknown-none`
   - 输出文件:`target/bpfel-unknown-none/release/observer`
3. **编译用户态程序**
   - 使用 `cargo build --release` 编译 `observer` 模块
   - 输出文件:`target/release/observer`

### 使用方法



```sh
# 首次运行或更新依赖后
./build.sh
```



### 注意事项

- 脚本开头有 `set -e`,任何步骤失败都会立即退出
- `bpf-linker` 通过 `cargo binstall` 安装预编译版本,无需系统安装 LLVM
- 编译需要网络连接以下载 Rust 依赖

------

## ▶️ run.sh - 运行脚本

`run.sh` 负责以 root 权限运行编译好的 `observer` 程序,并自动保存日志.

### 功能说明

1. **权限检查**:确保以 root 权限运行(eBPF 程序加载需要)
2. **创建日志目录**:自动创建 `results/` 文件夹
3. **运行并记录日志**:
   - 执行 `target/release/observer`
   - 将标准输出和标准错误同时显示在终端并保存到日志文件
   - 日志文件命名格式:`results/observer_YYYY-MM-DD_HH-MM-SS.log`

### 使用方法


```sh
# 以 root 权限运行
sudo ./run.sh
```



### 日志输出

日志文件保存在 `results/` 目录下,例如:

```sh
results/observer_2026-09-08_15-30-45.log
```



------

## 🔧 配置说明

### 修改运行参数

如需修改运行参数(如监控特定 PID),可以直接编辑 `run.sh`,修改最后一行:

```sh
# 监控所有进程(默认)
sudo RUST_LOG=info ./target/release/observer

# 监控特定 PID
sudo RUST_LOG=info ./target/release/observer --pid 12345

# 自动检测特定进程
sudo RUST_LOG=info ./target/release/observer --pid $(pgrep -n websocket)
```



### 配置文件

项目根目录下的 `config.toml` 用于控制 eBPF 探针的开关和行为,运行前可按需修改.

------

## 📂 相关文件

| 文件          | 说明              |
| :------------ | :---------------- |
| `build.sh`    | 编译脚本          |
| `run.sh`      | 运行脚本          |
| `config.toml` | eBPF 探针配置文件 |
| `results/`    | 日志输出目录      |
| `target/`     | 编译输出目录      |