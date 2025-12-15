#!/bin/bash

set -e  # 遇到任何错误立即退出

echo "start building user and kernel"

# # === 1. 确保必要依赖已安装 ===
# if ! command -v cc &> /dev/null; then
#     echo "missing cc ! build-essential..."
#     sudo apt update && sudo apt install -y build-essential
# fi

# # === 2. 安装 bpf-linker(如果未安装)===
# if ! command -v bpf-linker &> /dev/null; then
#     echo "installing bpf-linker..."
#     cargo install bpf-linker
# else
#     echo "✅ bpf-linker installed: $(which bpf-linker)"
# fi

# # === 3. 确保 nightly 工具链及 rust-src 组件 ===
# echo "🔧 Rust nightly tool-chain ..."
# rustup toolchain install nightly --profile minimal --force-non-host || true

# echo "📥 rust-src componet ..."
# rustup component add rust-src --toolchain nightly

# === 4. 构建 eBPF 程序 ===
echo "🔨 building eBPF  (observer-ebpf)..."
cargo +nightly build \
    --release \
    -p observer-ebpf \
    --target bpfel-unknown-none \
    -Z build-std=core,alloc \
    -Z build-std-features=compiler-builtins-mem

# 输出 BPF 对象文件位置
BPF_BIN="target/bpfel-unknown-none/release/observer"
if [ -f "$BPF_BIN" ]; then
    echo "✅ eBPF success: $BPF_BIN"
    ls -l "$BPF_BIN"
else
    echo "❌ build fail $BPF_BIN"
    exit 1
fi

# === 5. 构建用户态程序 ===
echo "👤 build user mode (observer)..."
cargo build --release -p observer

USER_BIN="target/release/observer"
if [ -f "$USER_BIN" ]; then
    echo "✅ build user mode success: $USER_BIN"
else
    echo "❌ build user mode failed"
    exit 1
fi

# === 6. 运行观测器(可选)===
echo "💡 run as below :"
echo "    sudo RUST_LOG=info $USER_BIN"