#!/bin/bash

set -e  # 遇到任何错误立即退出

echo "start building user and kernel"

# if all done before, could skip  update and install again

# 1. install all dependencies
echo "📦 installing dependencies ..."

# === install cc and build-essential ===
if ! command -v cc &> /dev/null; then
    echo "missing cc ! build-essential..."
    sudo apt update && sudo apt install -y build-essential
fi

# === install bpf-linker ===
if ! command -v bpf-linker &> /dev/null; then
    echo "installing bpf-linker..."
    # 确保 cargo-binstall 已安装
    if ! command -v cargo-binstall &> /dev/null; then
        echo "cargo-binstall not found, installing..."
        cargo install cargo-binstall
    fi
    # 使用 binstall 下载预编译版本,-y 自动确认
    cargo binstall bpf-linker -y
else
    echo "✅ bpf-linker installed: $(which bpf-linker)"
fi

# === install nightly toolchain and rust-src components ===
echo "🔧 Rust nightly tool-chain ..."
rustup toolchain install nightly --profile minimal --force-non-host || true

echo "📥 rust-src componet ..."
rustup component add rust-src --toolchain nightly

# build steps

# === build eBPF program ===
echo "🔨 building eBPF kernel mode (observer-ebpf)..."
cargo +nightly build \
    --release \
    -p observer-ebpf \
    --target bpfel-unknown-none \
    -Z build-std=core,alloc \
    -Z build-std-features=compiler-builtins-mem

# show BPF object file location
BPF_BIN="target/bpfel-unknown-none/release/observer"
if [ -f "$BPF_BIN" ]; then
    echo "✅ eBPF success: $BPF_BIN"
    ls -l "$BPF_BIN"
else
    echo "❌ build fail $BPF_BIN"
    exit 1
fi

# === build user mode program ===
echo "👤 build user mode (observer)..."
cargo build --release -p observer

USER_BIN="target/release/observer"
if [ -f "$USER_BIN" ]; then
    echo "✅ build user mode success: $USER_BIN"
else
    echo "❌ build user mode failed"
    exit 1
fi

# === 6. run observer ===
echo "💡 run as below :"
echo "    sudo RUST_LOG=info $USER_BIN"