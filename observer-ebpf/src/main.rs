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

// tcp_connect map
#[map]
static CONNECT_START: HashMap<u64, u64> = HashMap::with_max_entries(10240, 0);

// sk_stream_wait_memory map
#[map]
static WAIT_START: HashMap<u64, u64> = HashMap::with_max_entries(10240, 0);

// udp_sendmsg(v4) 与 udpv6_sendmsg(v6) 共用一张, 同一线程不会同时身处两者
#[map]
static UDP_SEND_START: HashMap<u64, u64> = HashMap::with_max_entries(10240, 0);

// udp_recvmsg(v4) 与 udpv6_recvmsg(v6) 共用
#[map]
static UDP_RECV_START: HashMap<u64, u64> = HashMap::with_max_entries(10240, 0);

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
        value: 0, //  重传暂无附加语义
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
                value: 0,
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
                value: 0,
            };

            EVENTS.output(&ctx, &event, 0);
        }
        let _ = map.remove(&pid_tgid);
    }
    0
}

// tcp_connect: 客户端发起连接.返回 0 只代表 SYN 已交出, 不代表三次握手完成
#[kprobe]
pub fn tcp_connect_entry(_ctx: ProbeContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let start_time = unsafe { bpf_ktime_get_ns() };

    if let Err(_e) = CONNECT_START.insert(&pid_tgid, &start_time, 0u64) {
        // map 满了
        // 目前什么也不做
    }
    0
}

#[kretprobe]
pub fn tcp_connect_return(_ctx: RetProbeContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();

    if let Some(start_time) = unsafe { CONNECT_START.get(&pid_tgid) } {
        let end_time = unsafe { bpf_ktime_get_ns() };
        let duration_ns = end_time - *start_time;

        // 成功(0)和失败(<0)都上报, 失败次数本身就是诊断信息; value 放返回码, 负数即 -errno
        let ret: i32 = _ctx.ret::<i32>();
        let tgid = (pid_tgid >> 32) as u32; // 主进程 ID (TGID)
        let pid = pid_tgid as u32; // 线程 ID (PID)
        let comm = match bpf_get_current_comm() {
            Ok(c) => c,
            Err(_) => [0; 16],
        };

        let event = TcpEvent {
            pid,
            tgid,
            len: 0,
            direction: TrafficDirection::Connect,
            duration_ns,
            comm,
            value: (ret as i64) as u32,
        };
        EVENTS.output(&_ctx, &event, 0);

        let _ = CONNECT_START.remove(&pid_tgid);
    }
    0
}

// tcp_set_state(struct sock *sk, int state): kprobe 的第 2 个参数就是新状态
#[kprobe]
pub fn tcp_set_state_entry(ctx: ProbeContext) -> u32 {
    let state: u32 = match ctx.arg::<i32>(1) {
        Some(s) => s as u32,
        None => return 0,
    };

    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let pid = pid_tgid as u32;
    let comm = match bpf_get_current_comm() {
        Ok(c) => c,
        Err(_) => [0; 16],
    };

    let event = TcpEvent {
        pid,
        tgid,
        len: 0,
        direction: TrafficDirection::StateChange,
        duration_ns: 0,
        comm,
        value: state,
    };
    EVENTS.output(&ctx, &event, 0);
    0
}

// tcp_send_active_reset: 本端主动发 RST(SO_LINGER 0 关闭, 或 close 时还有未读数据)
#[kprobe]
pub fn tcp_send_active_reset_entry(_ctx: ProbeContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let pid = pid_tgid as u32;
    let comm = match bpf_get_current_comm() {
        Ok(c) => c,
        Err(_) => [0; 16],
    };

    let event = TcpEvent {
        pid,
        tgid,
        len: 0,
        direction: TrafficDirection::Reset,
        duration_ns: 0,
        comm,
        value: 0,
    };
    EVENTS.output(&_ctx, &event, 0);
    0
}

// sk_stream_wait_memory: 只有发送缓冲不足, 应用被内核按住时才会被调用
// 出现即"上行被 TCP 层限住", duration_ns 就是应用等了多久
#[kprobe]
pub fn sk_stream_wait_memory_entry(_ctx: ProbeContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let start_time = unsafe { bpf_ktime_get_ns() };

    if let Err(_e) = WAIT_START.insert(&pid_tgid, &start_time, 0u64) {
        // map 满了
        // 目前什么也不做
    }
    0
}

#[kretprobe]
pub fn sk_stream_wait_memory_return(_ctx: RetProbeContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();

    if let Some(start_time) = unsafe { WAIT_START.get(&pid_tgid) } {
        let end_time = unsafe { bpf_ktime_get_ns() };
        let duration_ns = end_time - *start_time;

        // 该函数返回 void, 所以不读返回值; 读了拿到的是 rax 里的残留值
        let tgid = (pid_tgid >> 32) as u32;
        let pid = pid_tgid as u32;
        let comm = match bpf_get_current_comm() {
            Ok(c) => c,
            Err(_) => [0; 16],
        };

        let event = TcpEvent {
            pid,
            tgid,
            len: 0,
            direction: TrafficDirection::Backpressure,
            duration_ns,
            comm,
            value: 0,
        };
        EVENTS.output(&_ctx, &event, 0);

        let _ = WAIT_START.remove(&pid_tgid);
    }
    0
}

// udp: IPv4 和 IPv6 是两套入口, 只挂 v4 会静默漏掉 IPv6 的 DNS 和 QUIC.
// 四个 udp 钩子都复用 handle_return, 只是方向换成 UdpEgress / UdpIngress.

#[kprobe]
pub fn udp_sendmsg_entry(_ctx: ProbeContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let start_time = unsafe { bpf_ktime_get_ns() };

    if let Err(_e) = UDP_SEND_START.insert(&pid_tgid, &start_time, 0u64) {
        // map 满了
        // 目前什么也不做
    }
    0
}

#[kretprobe]
pub fn udp_sendmsg_return(_ctx: RetProbeContext) -> u32 {
    handle_return(_ctx, &UDP_SEND_START, TrafficDirection::UdpEgress)
}

#[kprobe]
pub fn udp_recvmsg_entry(_ctx: ProbeContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let start_time = unsafe { bpf_ktime_get_ns() };

    if let Err(_e) = UDP_RECV_START.insert(&pid_tgid, &start_time, 0u64) {
        // map 满了
        // 目前什么也不做
    }
    0
}

#[kretprobe]
pub fn udp_recvmsg_return(_ctx: RetProbeContext) -> u32 {
    handle_return(_ctx, &UDP_RECV_START, TrafficDirection::UdpIngress)
}

#[kprobe]
pub fn udpv6_sendmsg_entry(_ctx: ProbeContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let start_time = unsafe { bpf_ktime_get_ns() };

    if let Err(_e) = UDP_SEND_START.insert(&pid_tgid, &start_time, 0u64) {
        // map 满了
        // 目前什么也不做
    }
    0
}

#[kretprobe]
pub fn udpv6_sendmsg_return(_ctx: RetProbeContext) -> u32 {
    handle_return(_ctx, &UDP_SEND_START, TrafficDirection::Udp6Egress)
}

#[kprobe]
pub fn udpv6_recvmsg_entry(_ctx: ProbeContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let start_time = unsafe { bpf_ktime_get_ns() };

    if let Err(_e) = UDP_RECV_START.insert(&pid_tgid, &start_time, 0u64) {
        // map 满了
        // 目前什么也不做
    }
    0
}

#[kretprobe]
pub fn udpv6_recvmsg_return(_ctx: RetProbeContext) -> u32 {
    handle_return(_ctx, &UDP_RECV_START, TrafficDirection::Udp6Ingress)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
