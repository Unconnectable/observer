//! 用测试锁住输出格式.改表或改 render 时如果输出变了, cargo test 就会红.
//! 这是集成测试, 走 observer 这个 lib 的公开 API, 所以 main.rs 里不再有 #[cfg(test)].
use observer::report::{render_event, HOOK_KINDS, LOG_SPECS};
use observer::{TcpEvent, TrafficDirection};

fn evt(
    direction: TrafficDirection,
    pid: u32,
    name: &str,
    len: usize,
    ns: u64,
    value: u32,
) -> TcpEvent {
    let mut comm = [0u8; 16];
    comm[..name.len()].copy_from_slice(name.as_bytes());
    TcpEvent {
        pid,
        tgid: pid,
        len,
        direction,
        duration_ns: ns,
        comm,
        value,
    }
}

fn line(direction: TrafficDirection, name: &str, len: usize, ns: u64, value: u32) -> String {
    render_event(&evt(direction, 1660, name, len, ns, value), name)
}

#[test]
fn shapes_with_size_and_latency() {
    assert_eq!(
        line(TrafficDirection::Ingress, "Socket Thread", 8216, 4951, 0),
        "[RECV] PID: 1660   Comm: Socket Thread    Size: 8216   bytes | Latency: 4951   ns"
    );
    assert_eq!(
        line(TrafficDirection::Egress, "curl", 517, 73663, 0),
        "[SEND] PID: 1660   Comm: curl             Size: 517    bytes | Latency: 73663  ns"
    );
    assert_eq!(
        line(TrafficDirection::UdpIngress, "ping", 131, 8025, 0),
        "[UDP4 RECV] PID: 1660   Comm: ping             Size: 131    bytes | Latency: 8025   ns"
    );
    assert_eq!(
        line(TrafficDirection::Udp6Egress, "firefox", 204, 32176, 0),
        "[UDP6 SEND] PID: 1660   Comm: firefox          Size: 204    bytes | Latency: 32176  ns"
    );
    assert_eq!(
        line(TrafficDirection::Accept, "python3", 0, 2735, 0),
        "[NEW CONN] PID: 1660   Comm: python3          Size: 0      bytes | Latency: 2735   ns"
    );
}

#[test]
fn shapes_with_tail() {
    // 16 字节正好占满 comm, 用来确认对齐宽度不会被撑坏
    assert_eq!(
        line(TrafficDirection::Retransmit, "HAJIMINABEILUDUO", 0, 0, 0),
        "🚨 [TCP RETRANSMIT] PID: 1660   Comm: HAJIMINABEILUDUO | Packet Lost!"
    );
    assert_eq!(
        line(TrafficDirection::Backpressure, "WorkerThread", 0, 2352, 0),
        "🚧 [BACKPRESSURE] PID: 1660   Comm: WorkerThread     | Blocked: 2352   ns"
    );
    assert_eq!(
        line(TrafficDirection::Reset, "python3", 0, 0, 0),
        "🚨 [RST] PID: 1660   Comm: python3          | Active Reset Sent!"
    );
}

#[test]
fn shapes_with_head() {
    assert_eq!(
        line(TrafficDirection::Connect, "curl", 0, 50714, 0),
        "[TCP CONNECT] PID: 1660   Comm: curl             SYN-sent | Latency: 50714  ns"
    );
    // -110 存进 u32 再取回来仍是 -110
    assert_eq!(
        line(TrafficDirection::Connect, "curl", 0, 30, (-110i32) as u32),
        "[TCP CONNECT] PID: 1660   Comm: curl             err=-110 | Latency: 30     ns"
    );
    assert_eq!(
        line(TrafficDirection::StateChange, "Socket Thread", 0, 0, 1),
        "[TCP STATE] PID: 1660   Comm: Socket Thread    -> ESTABLISHED"
    );
}

#[test]
fn table_index_matches_enum() {
    for (i, spec) in LOG_SPECS.iter().enumerate() {
        assert!(!spec.tag.is_empty(), "第 {} 行没有标签", i);
    }
    // 抽查: 枚举值 == 表里的位置.中间插入或改动顺序都会在这里红掉
    assert_eq!(TrafficDirection::Ingress as usize, 0);
    assert_eq!(TrafficDirection::Egress as usize, 1);
    assert_eq!(TrafficDirection::Accept as usize, 2);
    assert_eq!(TrafficDirection::Retransmit as usize, 3);
    assert_eq!(TrafficDirection::Connect as usize, 4);
    assert_eq!(TrafficDirection::StateChange as usize, 5);
    assert_eq!(TrafficDirection::Backpressure as usize, 6);
    assert_eq!(TrafficDirection::Reset as usize, 7);
    assert_eq!(TrafficDirection::UdpIngress as usize, 8);
    assert_eq!(TrafficDirection::UdpEgress as usize, 9);
    assert_eq!(TrafficDirection::Udp6Ingress as usize, 10);
    assert_eq!(TrafficDirection::Udp6Egress as usize, 11);
    assert_eq!(LOG_SPECS.len(), HOOK_KINDS);
}
