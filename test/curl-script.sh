#!/bin/bash

# 设置循环次数
COUNT=500

echo "开始执行 $COUNT 次 curl -I www.baidu.com 循环..."

# 循环从 1 到 $COUNT
for i in $(seq 1 $COUNT); do
    echo "--- 第 $i 次执行 ---"
    curl -I www.baidu.com
    
    # 添加休眠
    sleep 0.1 
done

echo "loop done"