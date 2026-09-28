#!/usr/bin/env python3
"""验证 sk_stream_wait_memory 这条钩子能不能出数.

服务端 accept 之后只极慢地读(每 0.3 秒读 4 KB, 约 13 KB/s), 客户端猛写 100 MB.
发送缓冲很快就顶满, 之后那一次 send() 会一直睡在 sk_stream_wait_memory 里,
直到服务端关闭连接被 RST 唤醒. 本机实测: 不是很多条毫秒级, 而是**一条 30 秒**,
脚本自己量的 30.02s 和 observer 量的 30.0155s 相差 0.02 %.

用法: 先把 observer 跑起来, 等日志里出现 Hooks Active 那行, 再跑这个脚本.
顺序反过来阻塞就发生在钩子存在之前, 所有计数都会停在 0.
"""
import socket
import threading
import time

HOST = "127.0.0.1"
PORT = 0  # 让内核挑空闲端口, 免得重复跑时撞 Address already in use
TOTAL = 100 * 1024 * 1024
CHUNK = 64 * 1024
DRAIN_ROUNDS = 100  # 100 次 * 0.3s = 服务端总共只读走约 400 KB
BOUND = []


def server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(1)
    BOUND.append(srv.getsockname()[1])
    conn, _ = srv.accept()
    conn.settimeout(1)
    drained = 0
    for _ in range(DRAIN_ROUNDS):
        time.sleep(0.3)
        try:
            drained += len(conn.recv(4096))
        except OSError:
            break
    print("[server] 只读走了 {} KB, 收工".format(drained // 1024))
    conn.close()
    srv.close()


def client():
    for _ in range(100):
        if BOUND:
            break
        time.sleep(0.05)
    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    c.connect((HOST, BOUND[0]))
    buf = b"\0" * CHUNK
    sent = stalls = 0
    stalled_ns = 0.0
    t0 = time.perf_counter()
    try:
        while sent < TOTAL:
            s = time.perf_counter()
            n = c.send(buf)
            cost = time.perf_counter() - s
            sent += n
            if cost > 0.001:  # 1 ms 以上算一次"被挂起"
                stalls += 1
                stalled_ns += cost
    except OSError as e:
        print("[client] 服务端关了: {}".format(e))
    print(
        "[client] 送出 {:.1f} MB 用了 {:.1f}s; send() 卡住(>1ms) {} 次, 合计 {:.2f}s".format(
            sent / 1048576.0,
            time.perf_counter() - t0,
            stalls,
            stalled_ns,
        )
    )
    c.close()


if __name__ == "__main__":
    t = threading.Thread(target=server)
    t.start()
    time.sleep(0.5)
    client()
    t.join()
