// net-observer-common/src/lib.rs
#![no_std]

#[derive(Clone, Copy)]
#[repr(C)]
pub struct TcpEvent {
    pub pid: u32,           // 进程 ID
    pub len: usize,         // 数据包大小
    pub direction: u8,      // 0: Recv, 1: Send
    pub comm: [u8; 16],     // 进程名 (例如 "server")
    pub duration_ns: u64,   // 操作耗时 (纳秒)
}