#!/bin/bash

# 找到监听 8080 端口的 TCP 进程 PID (需要安装 lsof)
# -t: 仅输出 PID
# -i:8080: 端口
# -sTCP:LISTEN: 仅 TCP 监听状态
# TARGET_PID=$(lsof -t -i:8080 -sTCP:LISTEN)

# if [ -z "$TARGET_PID" ]; then
#     echo "❌ 没找到监听 8080 端口的进程,服务启动了吗?"
#     exit 1
# fi

# echo "🎯 自动检测到 Server PID: $TARGET_PID"
# sudo RUST_LOG=info ./target/release/observer --pid $TARGET_PID

#sudo RUST_LOG=info ./target/release/observer --pid $(pgrep -n websocket)
#sudo RUST_LOG=info ./target/release/observer #观测所有


#sudo RUST_LOG=info ./target/release/observer --pid 62727
#sudo RUST_LOG=info ./target/release/observer --pid $(pgrep -n websocket)
#sudo RUST_LOG=info ./target/release/observer --pid 67418

# 修复后的参数须在config.toml中修改
sudo RUST_LOG=info target/release/observer