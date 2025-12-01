#![no_std]

/// 用于区分是发送还是接收
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum TrafficDirection {
    Ingress = 0, // 接收 (recv)
    Egress = 1,  // 发送 (send)
}

/// 发送给用户态的事件结构体
#[derive(Clone, Copy)]
#[repr(C)]
pub struct TcpEvent {
    pub pid: u32,   // 进程 ID
    pub tgid: u32,  // 线程组 ID (通常就是主进程ID)
    pub len: usize, // 数据包大小 (字节)
    pub direction: TrafficDirection,
    pub duration_ns: u64, // 函数执行耗时 (纳秒)
    pub comm: [u8; 16],   // 进程名称 (例如 "chat-server")
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for TcpEvent {} // 用户态需要这个 Trait 来解析数据
