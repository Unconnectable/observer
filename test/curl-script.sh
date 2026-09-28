#!/bin/bash

# 设置循环次数
COUNT=100

echo "开始执行 $COUNT 次 curl -I www.baidu.com 循环..."

# 循环从 1 到 $COUNT
for i in $(seq 1 $COUNT); do
    echo "--- 第 $i 次执行 ---"
    curl -I www.baidu.com
    
    # 添加休眠
    sleep 0.1 
done

echo "loop done"

# bash 赋值号两边不能有空格
site1="https://www.bilibili.com/video/BV1bZhQ6VEQK/"
site2="https://www.bilibili.com/video/BV1gthU6TExk/"

# UDP 视频流量
#
# 本机 curl 7.88.1 编译时没带 HTTP/3(见 curl --version 里没有 HTTP3 特性),
# 所以 curl 造不出 QUIC 流量, 必须用浏览器播放才会有 UDP.
# 用途: 一边跑 observer, 一边跑这个脚本, 看 [UDP SEND]/[UDP RECV] 是否随播放上升.

# 播多少秒
# PLAY_SECONDS=20

# echo "先用 xdg-open 打开默认浏览器播放, 制造真实 UDP/QUIC 流量"
# for url in "$site1" "$site2"; do
#     echo "--- 打开: ${url:0:60}..."
#     xdg-open "$url"
#     sleep "$PLAY_SECONDS"
# done

# # 播放期间是否有 UDP:443 的流(有 = QUIC 生效; 为 0 = 这次走的还是 TCP)
# echo "UDP 443 连接数(QUIC 判据): $(ss -u 2>/dev/null | grep -c ':443')"
# echo "TCP 443 连接数: $(ss -t 2>/dev/null | grep -c ':443')"



# 测试upload

head -c 100000000 /dev/zero | curl -o /dev/null -s -w "上传速度: %{speed_upload} B/s\n耗时: %{time_total}s\n" \
  -X POST --data-binary @- https://speed.cloudflare.com/__up



# 测试下载
curl -o /dev/null https://mirrors.shanghaitech.edu.cn/ubuntu-cdimage/xubuntu/releases/resolute/release/xubuntu-26.04-desktop-amd64.iso
