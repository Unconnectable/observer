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
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for TcpEvent {} // user mode use Trait aya:Pod to parse TcpEvent structure data
