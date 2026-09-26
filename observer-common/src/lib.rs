#![no_std]

/// 用于区分是发送还是接收
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u32)]
// 保证通信双方对数据大小的认知绝对一致
pub enum TrafficDirection {
    Ingress = 0,    // recv
    Egress = 1,     // send
    Accept = 2,     // accept connection
    Retransmit = 3, // retransmit

    // ↓ 以下 6 个是本次在后面追加的, 你原有四个的顺序和取值都没动
    Connect = 4,      // tcp_connect 返回, value = 错误码 (0 只代表 SYN 已交出)
    StateChange = 5,  // tcp_set_state, value = 新状态 (内核 tcp_states_t)
    Backpressure = 6, // sk_stream_wait_memory, 发送缓冲满导致应用被内核按住
    Reset = 7,        // tcp_send_active_reset, 本端主动发 RST
    UdpIngress = 8,   // udp_recvmsg / udpv6_recvmsg
    UdpEgress = 9,    // udp_sendmsg / udpv6_sendmsg

    // ↓ IPv6 单独给值, 因为"是谁走的"在程序里本来就已知, 不需要读内核结构体
    Udp6Ingress = 10, // udpv6_recvmsg
    Udp6Egress = 11,  // udpv6_sendmsg
}

/// TCP 状态值, 与内核 include/net/tcp_states.h 一致, 给 StateChange 事件的 value 用
pub mod tcp_state {
    pub const ESTABLISHED: u32 = 1;
    pub const SYN_SENT: u32 = 2;
    pub const SYN_RECV: u32 = 3;
    pub const FIN_WAIT1: u32 = 4;
    pub const FIN_WAIT2: u32 = 5;
    pub const TIME_WAIT: u32 = 6;
    pub const CLOSE: u32 = 7;
    pub const CLOSE_WAIT: u32 = 8;
    pub const LAST_ACK: u32 = 9;
    pub const LISTEN: u32 = 10;
    pub const CLOSING: u32 = 11;
    pub const NEW_SYN_RECV: u32 = 12;
}

/// send to user mode event structure
#[derive(Clone, Copy)]
#[repr(C)]
pub struct TcpEvent {
    pub pid: u32,                    // thread ID
    pub tgid: u32,                   // main process ID
    pub len: usize,                  // data packet size (bytes)
    pub direction: TrafficDirection, // send or receive
    pub duration_ns: u64,            // function execution time (nanoseconds)
    pub comm: [u8; 16],              // process name ("chat-server", "tokio-runtime")

    // ↓ 本次追加: 上面的字段一个没动, 新字段加在最末尾以保持你原有布局顺序
    pub value: u32, // 附加语义: Connect 的错误码 / StateChange 的新状态; 其余填 0
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for TcpEvent {} // user mode use Trait aya:Pod to parse TcpEvent structure data
