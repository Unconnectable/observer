#![no_std]
#![no_main]

use core::time::Duration;

use aya_ebpf::{
    cty::c_void,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_trace_vprintk,
    },
    macros::{kprobe, kretprobe, map},
    maps::{HashMap, PerfEventArray},
    programs::{ProbeContext, RetProbeContext},
};
use observer_common::{TcpEvent, TrafficDirection};

#[map]
static EVENTS: PerfEventArray<TcpEvent> = PerfEventArray::new(0);

// tcp_sendmsg 存储时间的map
#[map]
static SEND_START: HashMap<u64, u64> = HashMap::with_max_entries(10240, 0);

// tcp_recvmsg map
#[map]
static RECV_START: HashMap<u64, u64> = HashMap::with_max_entries(10240, 0);

// inet_csk_accept
#[map]
static ACCEPT_START: HashMap<u64, u64> = HashMap::with_max_entries(10240, 0);
// --- debug func ---
/*
unsafe fn debug_print(msg: &[u8]) {
    bpf_trace_vprintk(
        msg.as_ptr() as *const i8,
        msg.len() as u32,
        core::ptr::null() as *const c_void,
        0,
    );
}
*/
// ------------------

#[kprobe]
pub fn tcp_retransmit_skb_entry(_ctx: ProbeContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let pid = pid_tgid as u32;

    let comm = match bpf_get_current_comm() {
        Ok(c) => c,
        Err(_) => [0; 16],
    };

    // 重传事件, 实际从 skb 读取,暂时为0
    let event = TcpEvent {
        pid,
        tgid,
        len: 0,
        direction: TrafficDirection::Retransmit,
        duration_ns: 0,
        comm,
    };

    EVENTS.output(&_ctx, &event, 0);
    0
}

#[kprobe]
pub fn inet_csk_accept_entry(_ctx: ProbeContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let start_time = unsafe { bpf_ktime_get_ns() };

    if let Err(_e) = ACCEPT_START.insert(&pid_tgid, &start_time, 0u64) {}
    0
}

#[kretprobe]
pub fn inet_csk_accept_return(_ctx: RetProbeContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();

    if let Some(start_time) = unsafe { ACCEPT_START.get(&pid_tgid) } {
        let end_time = unsafe { bpf_ktime_get_ns() };
        let duration_ns = end_time - *start_time;

        let ret: u64 = _ctx.ret::<u64>();
        if ret != 0 {
            let tgid = (pid_tgid >> 32) as u32;
            let pid = pid_tgid as u32;
            let comm = match bpf_get_current_comm() {
                Ok(c) => c,
                Err(_) => [0; 16],
            };

            let event = TcpEvent {
                pid,
                tgid,
                len: 0,                              // Accept 事件没有“数据长度”的概念,填 0
                direction: TrafficDirection::Accept, // 标记为 Accept
                duration_ns,
                comm,
            };
            EVENTS.output(&_ctx, &event, 0);
        }
    }

    let _ = ACCEPT_START.remove(&pid_tgid);
    0
}

#[kprobe]
pub fn tcp_sendmsg_entry(_ctx: ProbeContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let start_time = unsafe { bpf_ktime_get_ns() };

    if let Err(_e) = SEND_START.insert(&pid_tgid, &start_time, 0u64) {
        // map 满了
        // 目前什么也不做
    }
    0
}

#[kretprobe]
pub fn tcp_sendmsg_return(_ctx: RetProbeContext) -> u32 {
    handle_return(_ctx, &SEND_START, TrafficDirection::Egress)
}

#[kprobe]
pub fn tcp_recvmsg_entry(_ctx: ProbeContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let start_time = unsafe { bpf_ktime_get_ns() };

    if let Err(_e) = RECV_START.insert(&pid_tgid, &start_time, 0) {}

    0
}

#[kretprobe]
pub fn tcp_recvmsg_return(_ctx: RetProbeContext) -> u32 {
    handle_return(_ctx, &RECV_START, TrafficDirection::Ingress)
}
#[inline(always)]

pub fn handle_return(
    ctx: RetProbeContext,
    map: &HashMap<u64, u64>,
    direction: TrafficDirection,
) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();

    if let Some(start_time) = unsafe { map.get(&pid_tgid) } {
        let end_time = unsafe { bpf_ktime_get_ns() };
        let duration_ns = end_time - *start_time;
        let ret: i32 = ctx.ret::<i32>();

        if ret > 0 {
            // 高 32 位是 TGID (主进程ID),低 32 位是 PID (线程ID)
            let tgid = (pid_tgid >> 32) as u32; // 主进程 ID (TGID)
            let pid = pid_tgid as u32; // 线程 ID (PID)

            let comm = match bpf_get_current_comm() {
                Ok(c) => c,
                Err(_) => [0; 16],
            };

            let event = TcpEvent {
                pid,
                tgid,
                len: ret as usize,
                direction, // send or recv
                duration_ns,
                comm,
            };

            EVENTS.output(&ctx, &event, 0);
        }
        let _ = map.remove(&pid_tgid);
    }
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
