mod logger; //  自定义如何输出日志

use aya::{
    include_bytes_aligned, maps::perf::AsyncPerfEventArray, programs::KProbe, util::online_cpus,
    Bpf,
};
use bytes::BytesMut;
use chrono::format::format;
use log::{error, info, warn};
use logger::TrafficLogger;
use observer_common::{tcp_state, TcpEvent, TrafficDirection};
use serde::Deserialize;
use std::fs; // fs 模块拷贝 config.toml
use std::sync::atomic::{AtomicU64, Ordering}; // 统计每个钩子的触发次数, 退出时汇总
use std::sync::Arc;
use sysinfo::{PidExt, ProcessExt, System, SystemExt};
use tokio::signal;

#[derive(Debug, Deserialize)]
struct AppConfig {
    probes: ProbesConfig,
    discovery: DiscoveryConfig,
    filters: FiltersConfig,
    settings: SettingsConfig,
}

#[derive(Debug, Deserialize)]
struct ProbesConfig {
    target_func: String,
    recv_func: String,
    accept_func: String,
    retransmit_func: String,

    // 追加挂载点
    connect_func: String,
    state_func: String,
    reset_func: String,
    backpressure_func: String,
    udp_send_func: String,
    udp_recv_func: String,
    udp6_send_func: String,
    udp6_recv_func: String,
}

#[derive(Debug, Deserialize)]
struct DiscoveryConfig {
    force_pid: Option<u32>,
    auto_detect_name: String,
}

#[derive(Debug, Deserialize)]
struct FiltersConfig {
    include_names: Vec<String>,
    exclude_names: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SettingsConfig {
    perf_pages: usize,
}

// 找指定的pid
fn find_target_tgid(config: &DiscoveryConfig) -> Option<u32> {
    if let Some(pid) = config.force_pid {
        info!("🎯 Target force-set to PID: {}", pid);
        return Some(pid);
    }

    if config.auto_detect_name.is_empty() {
        return None;
    }

    info!("🔍 Scanning system for: '{}'...", config.auto_detect_name);
    let mut sys = System::new_all();
    sys.refresh_all();

    let pids: Vec<u32> = sys
        .processes()
        .iter()
        .filter(|(_, p)| p.name().contains(&config.auto_detect_name))
        .map(|(pid, _)| pid.as_u32())
        .collect();

    if let Some(pid) = pids.last() {
        info!("✅ Found match: PID {}", pid);
        return Some(*pid);
    }

    warn!(
        "❌ No process matching '{}' found.",
        config.auto_detect_name
    );
    None
}

// tcp_set_state 上报的数值翻译成状态名
fn state_name(value: u32) -> &'static str {
    match value {
        tcp_state::ESTABLISHED => "ESTABLISHED",
        tcp_state::SYN_SENT => "SYN_SENT",
        tcp_state::SYN_RECV => "SYN_RECV",
        tcp_state::FIN_WAIT1 => "FIN_WAIT1",
        tcp_state::FIN_WAIT2 => "FIN_WAIT2",
        tcp_state::TIME_WAIT => "TIME_WAIT",
        tcp_state::CLOSE => "CLOSE",
        tcp_state::CLOSE_WAIT => "CLOSE_WAIT",
        tcp_state::LAST_ACK => "LAST_ACK",
        tcp_state::LISTEN => "LISTEN",
        tcp_state::CLOSING => "CLOSING",
        tcp_state::NEW_SYN_RECV => "NEW_SYN_RECV",
        _ => "UNKNOWN",
    }
}

//   日志由这张表决定 (下标 = TrafficDirection 的取值)
const HOOK_KINDS: usize = 12;

struct LogSpec {
    emoji: &'static str,
    tag: &'static str,
    show_size: bool,
    show_latency: bool,
}

// 不同的traffic log 标识
const LOG_SPECS: [LogSpec; HOOK_KINDS] = [
    // 0
    LogSpec { emoji: "", tag: "RECV", show_size: true, show_latency: true },
    // 1
    LogSpec { emoji: "", tag: "SEND", show_size: true, show_latency: true },
    // 2
    LogSpec { emoji: "", tag: "NEW CONN", show_size: true, show_latency: true },
    // 3
    LogSpec { emoji: "🚨", tag: "TCP RETRANSMIT", show_size: false, show_latency: false },
    // 4
    LogSpec { emoji: "", tag: "TCP CONNECT", show_size: false, show_latency: true },
    // 5
    LogSpec { emoji: "", tag: "TCP STATE", show_size: false, show_latency: false },
    // 6
    LogSpec { emoji: "🚧", tag: "BACKPRESSURE", show_size: false, show_latency: false },
    // 7
    LogSpec { emoji: "🚨", tag: "RST", show_size: false, show_latency: false },
    // 8
    LogSpec { emoji: "", tag: "UDP4 RECV", show_size: true, show_latency: true },
    // 9
    LogSpec { emoji: "", tag: "UDP4 SEND", show_size: true, show_latency: true },
    // 10
    LogSpec { emoji: "", tag: "UDP6 RECV", show_size: true, show_latency: true },
    // 11
    LogSpec { emoji: "", tag: "UDP6 SEND", show_size: true, show_latency: true },
];

/// 表里装不下的那点差异: 写在 Comm 后面(Head)还是写在整行末尾(Tail)
enum Detail {
    None,
    Head(String),
    Tail(String),
}

fn detail_of(event: &TcpEvent) -> Detail {
    match event.direction {
        TrafficDirection::Retransmit => Detail::Tail("Packet Lost!".to_string()),
        TrafficDirection::Connect => {
            let ret = event.value as i32;
            if ret == 0 {
                Detail::Head("SYN-sent".to_string())
            } else {
                Detail::Head(format!("err={}", ret))
            }
        }
        TrafficDirection::StateChange => Detail::Head(format!("-> {}", state_name(event.value))),
        TrafficDirection::Backpressure => {
            Detail::Tail(format!("Blocked: {:<6} ns", event.duration_ns))
        }
        TrafficDirection::Reset => Detail::Tail("Active Reset Sent!".to_string()),
        _ => Detail::None,
    }
}

/// 唯一的拼行函数 吧之前的match合并到现在的一个
fn render_event(event: &TcpEvent, comm: &str) -> String {
    let spec = match LOG_SPECS.get(event.direction as usize) {
        Some(s) => s,
        None => return format!("[UNKOWN] PID: {:<6} Comm: {:<16}", event.pid, comm),
    };

    let mut s = format!(
        "{}{}[{}] PID: {:<6} Comm: {:<16}",
        spec.emoji,
        if spec.emoji.is_empty() { "" } else { " " },
        spec.tag,
        event.pid,
        comm
    );
    let mut has_clause = false;
    let detail = detail_of(event);

    if let Detail::Head(text) = &detail {
        s.push_str(&format!(" {}", text));
        has_clause = true;
    }
    if spec.show_size {
        s.push_str(&format!(" Size: {:<6} bytes", event.len));
        has_clause = true;
    }
    if spec.show_latency {
        if has_clause {
            s.push_str(" |");
        }
        s.push_str(&format!(" Latency: {:<6} ns", event.duration_ns));
    }
    if let Detail::Tail(text) = &detail {
        s.push_str(&format!(" | {}", text));
    }
    s
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    // 1. 初始化文件日志系统 (按月/日分类)
    let logger = TrafficLogger::init()?;

    // 2. 备份配置文件到当次运行目录
    if let Err(e) = fs::copy("config.toml", logger.run_dir.join("config.toml")) {
        warn!("⚠️ Config backup failed: {}", e);
    }

    // 3. 加载并解析配置 config.toml
    let settings = config::Config::builder()
        .add_source(config::File::with_name("config"))
        .build()?;
    let config: AppConfig = settings.try_deserialize()?;

    // 将过滤规则同时也写入日志文件
    let config_msg = format!(
        "📋 Filter Rules: Include {:?}, Exclude {:?}",
        config.filters.include_names, config.filters.exclude_names
    );
    info!("{}", config_msg);
    logger.log(&config_msg);

    // 4. 寻找要监测的pid
    let target_tgid = find_target_tgid(&config.discovery);

    // 将 PID 锁定状态写入日志文件
    if let Some(tgid) = target_tgid {
        let msg = format!("✅ Target PID Locked: {}", tgid);
        // info! 已经在 find_target_tgid 里打印过了,这里只写文件
        logger.log(&msg);
    } else {
        let msg = "🌐 Running in GLOBAL mode (Filtered by names only)";
        warn!("{}", msg);
        logger.log(msg);
    }

    // 5. 加载 eBPF 字节码
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/observer"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/observer"
    ))?;

    //  TCP Send 挂载探针
    let send_func = &config.probes.target_func;
    info!("🪝 Hooking Send: tcp_sendmsg_entry/return -> {}", send_func);

    let send_entry: &mut KProbe = bpf.program_mut("tcp_sendmsg_entry").unwrap().try_into()?;
    send_entry.load()?;
    send_entry.attach(send_func, 0)?;

    let send_return: &mut KProbe = bpf.program_mut("tcp_sendmsg_return").unwrap().try_into()?;
    send_return.load()?;
    send_return.attach(send_func, 0)?;

    // TCP Recv
    let recv_func = &config.probes.recv_func;
    info!("🪝 Hooking Recv: tcp_recvmsg_entry/return -> {}", recv_func);

    let recv_entry: &mut KProbe = bpf.program_mut("tcp_recvmsg_entry").unwrap().try_into()?;
    recv_entry.load()?;
    recv_entry.attach(recv_func, 0)?;

    let recv_return: &mut KProbe = bpf.program_mut("tcp_recvmsg_return").unwrap().try_into()?;
    recv_return.load()?;
    recv_return.attach(recv_func, 0)?;

    //  TCP Accept
    let accept_func = &config.probes.accept_func;
    info!(
        "🪝 Hooking Accept: inet_csk_accept_entry/return -> {}",
        accept_func
    );

    let accept_entry: &mut KProbe = bpf
        .program_mut("inet_csk_accept_entry")
        .unwrap()
        .try_into()?;
    accept_entry.load()?;
    accept_entry.attach(accept_func, 0)?;

    let accept_return: &mut KProbe = bpf
        .program_mut("inet_csk_accept_return")
        .unwrap()
        .try_into()?;
    accept_return.load()?;
    accept_return.attach(accept_func, 0)?;

    //  TCP Retransmit
    let retrans_func = &config.probes.retransmit_func;
    info!(
        "🪝 Hooking Retransmit: tcp_retransmit_skb_entry -> {}",
        retrans_func
    );

    let retrans_entry: &mut KProbe = bpf
        .program_mut("tcp_retransmit_skb_entry")
        .unwrap()
        .try_into()?;
    retrans_entry.load()?;
    retrans_entry.attach(retrans_func, 0)?;

    //  TCP Connect
    let connect_func = &config.probes.connect_func;
    info!(
        "🪝 Hooking Connect: tcp_connect_entry/return -> {}",
        connect_func
    );

    let connect_entry: &mut KProbe = bpf.program_mut("tcp_connect_entry").unwrap().try_into()?;
    connect_entry.load()?;
    connect_entry.attach(connect_func, 0)?;

    let connect_return: &mut KProbe = bpf.program_mut("tcp_connect_return").unwrap().try_into()?;
    connect_return.load()?;
    connect_return.attach(connect_func, 0)?;

    //  TCP State
    let state_func = &config.probes.state_func;
    info!("🪝 Hooking State: tcp_set_state_entry -> {}", state_func);

    let state_entry: &mut KProbe = bpf.program_mut("tcp_set_state_entry").unwrap().try_into()?;
    state_entry.load()?;
    state_entry.attach(state_func, 0)?;

    //  TCP Reset
    let reset_func = &config.probes.reset_func;
    info!(
        "🪝 Hooking Reset: tcp_send_active_reset_entry -> {}",
        reset_func
    );

    let reset_entry: &mut KProbe = bpf
        .program_mut("tcp_send_active_reset_entry")
        .unwrap()
        .try_into()?;
    reset_entry.load()?;
    reset_entry.attach(reset_func, 0)?;

    //  TCP Backpressure
    let backpressure_func = &config.probes.backpressure_func;
    info!(
        "🪝 Hooking Backpressure: sk_stream_wait_memory_entry/return -> {}",
        backpressure_func
    );

    let bp_entry: &mut KProbe = bpf
        .program_mut("sk_stream_wait_memory_entry")
        .unwrap()
        .try_into()?;
    bp_entry.load()?;
    bp_entry.attach(backpressure_func, 0)?;

    let bp_return: &mut KProbe = bpf
        .program_mut("sk_stream_wait_memory_return")
        .unwrap()
        .try_into()?;
    bp_return.load()?;
    bp_return.attach(backpressure_func, 0)?;

    //  UDP Send (v4)
    let udp_send_func = &config.probes.udp_send_func;
    info!(
        "🪝 Hooking UdpSend: udp_sendmsg_entry/return -> {}",
        udp_send_func
    );

    let udp_send_entry: &mut KProbe = bpf.program_mut("udp_sendmsg_entry").unwrap().try_into()?;
    udp_send_entry.load()?;
    udp_send_entry.attach(udp_send_func, 0)?;

    let udp_send_return: &mut KProbe = bpf.program_mut("udp_sendmsg_return").unwrap().try_into()?;
    udp_send_return.load()?;
    udp_send_return.attach(udp_send_func, 0)?;

    //  UDP Recv (v4)
    let udp_recv_func = &config.probes.udp_recv_func;
    info!(
        "🪝 Hooking UdpRecv: udp_recvmsg_entry/return -> {}",
        udp_recv_func
    );

    let udp_recv_entry: &mut KProbe = bpf.program_mut("udp_recvmsg_entry").unwrap().try_into()?;
    udp_recv_entry.load()?;
    udp_recv_entry.attach(udp_recv_func, 0)?;

    let udp_recv_return: &mut KProbe = bpf.program_mut("udp_recvmsg_return").unwrap().try_into()?;
    udp_recv_return.load()?;
    udp_recv_return.attach(udp_recv_func, 0)?;

    //  UDP6 Send (v6) —— 与 v4 是两个不同的内核函数, 少挂一组会静默漏掉 IPv6 流量
    let udp6_send_func = &config.probes.udp6_send_func;
    info!(
        "🪝 Hooking Udp6Send: udpv6_sendmsg_entry/return -> {}",
        udp6_send_func
    );

    let udp6_send_entry: &mut KProbe =
        bpf.program_mut("udpv6_sendmsg_entry").unwrap().try_into()?;
    udp6_send_entry.load()?;
    udp6_send_entry.attach(udp6_send_func, 0)?;

    let udp6_send_return: &mut KProbe = bpf
        .program_mut("udpv6_sendmsg_return")
        .unwrap()
        .try_into()?;
    udp6_send_return.load()?;
    udp6_send_return.attach(udp6_send_func, 0)?;

    //  UDP6 Recv (v6)
    let udp6_recv_func = &config.probes.udp6_recv_func;
    info!(
        "🪝 Hooking Udp6Recv: udpv6_recvmsg_entry/return -> {}",
        udp6_recv_func
    );

    let udp6_recv_entry: &mut KProbe =
        bpf.program_mut("udpv6_recvmsg_entry").unwrap().try_into()?;
    udp6_recv_entry.load()?;
    udp6_recv_entry.attach(udp6_recv_func, 0)?;

    let udp6_recv_return: &mut KProbe = bpf
        .program_mut("udpv6_recvmsg_return")
        .unwrap()
        .try_into()?;
    udp6_recv_return.load()?;
    udp6_recv_return.attach(udp6_recv_func, 0)?;

    // ============================================================ 追加的挂载代码结束

    //  汇总日志

    let hook_msg = format!(
        "🪝 Hooks Active: Send({}), Recv({}), Accept({}), Retrans({})",
        send_func, recv_func, accept_func, retrans_func
    );
    info!("{}", hook_msg);
    logger.log(&hook_msg);

    // 钩子的汇总日志
    let hook_msg2 = format!(
        "🪝 Hooks Active2: Connect({}), State({}), Reset({}), Backpressure({}), UdpSend({}), UdpRecv({}), Udp6Send({}), Udp6Recv({})",
        connect_func, state_func, reset_func, backpressure_func, udp_send_func, udp_recv_func,
        udp6_send_func, udp6_recv_func
    );
    info!("{}", hook_msg2);
    logger.log(&hook_msg2);

    // 读取 Perf Buffer
    let mut perf_array = AsyncPerfEventArray::try_from(bpf.take_map("EVENTS").unwrap())?;

    //   统计每个钩子的触发次数, 下标 = TrafficDirection 的取值
    //   标签和数量都由文件上方的 LOG_SPECS 决定, 这里不再单独维护一份名字
    let hook_counts: Arc<Vec<AtomicU64>> =
        Arc::new((0..HOOK_KINDS).map(|_| AtomicU64::new(0)).collect());

    // start logging loop
    let start_msg = "🚀 Observer is running. Capturing events...";
    logger.log(start_msg);

    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, Some(config.settings.perf_pages))?;

        let t_tgid = target_tgid;
        let includes = config.filters.include_names.clone();
        let excludes = config.filters.exclude_names.clone();

        // 克隆 logger 传给异步任务
        let file_logger = logger.clone();
        let counts = hook_counts.clone(); // 每个 CPU 的任务共用同一份计数器

        tokio::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();
            loop {
                // 系统里所有的 TCP 发送事件
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    // 把字节数组强转为结构体
                    let event: TcpEvent =
                        unsafe { (buffers[i].as_ptr() as *const TcpEvent).read_unaligned() };

                    // 解析 command 字段
                    let comm = std::str::from_utf8(&event.comm)
                        .unwrap_or("?")
                        .trim_end_matches('\0');

                    // 过滤规则

                    // 只看 指定 PID
                    if let Some(target) = t_tgid {
                        if event.tgid != target {
                            continue;
                        }
                    }

                    if !excludes.is_empty() && excludes.iter().any(|name| comm.contains(name)) {
                        continue;
                    }

                    if !includes.is_empty() && !includes.iter().any(|name| comm.contains(name)) {
                        continue;
                    }

                    // 吧原来的
                    let log_line = render_event(&event, comm);

                    // 双写:屏幕一份,日志文件文件一份
                    println!("{}", log_line);
                    file_logger.log(&log_line);

                    // 计数, 供退出时汇总
                    if let Some(counter) = counts.get(event.direction as usize) {
                        counter.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        });
    }

    signal::ctrl_c().await?;

    // 退出
    let exit_msg = "👋 Exiting...";
    info!("{}", exit_msg);
    logger.log(exit_msg);

    // 退出时把每个钩子的触发次数汇总, 同样双写(屏幕一份, 日志文件一份)
    let mut total: u64 = 0;
    println!("📊 ===== 钩子触发次数汇总 =====");
    logger.log("📊 ===== 钩子触发次数汇总 =====");
    // 标签直接取自 LOG_SPECS, 和每行日志用的字符串是同一份定义
    for (i, spec) in LOG_SPECS.iter().enumerate() {
        let hits = hook_counts
            .get(i)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0);
        total += hits;
        let line = format!("   {:<12} {}", spec.tag, hits);
        println!("{}", line);
        logger.log(&line);
    }
    let sum_line = format!("   {:<12} {}", "TOTAL", total);
    println!("{}", sum_line);
    logger.log(&sum_line);
    if total == 0 {
        let warn_line = "   (全是 0: 要么没有流量, 要么挂载点没被触发)";
        println!("{}", warn_line);
        logger.log(warn_line);
    }

    Ok(())
}

// ↓ 本次追加: 用测试锁住输出格式。改表或改 render 时如果输出变了, cargo test 就会红
#[cfg(test)]
mod tests {
    use super::*;

    fn evt(direction: TrafficDirection, pid: u32, name: &str, len: usize, ns: u64, value: u32) -> TcpEvent {
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
        assert_eq!(LOG_SPECS.len(), HOOK_KINDS);
        for (i, spec) in LOG_SPECS.iter().enumerate() {
            let direction = i as u32;
            // 每个取值都能落到表里一行
            assert!(direction < HOOK_KINDS as u32, "下标 {} 越界", i);
            assert!(!spec.tag.is_empty(), "第 {} 行没有标签", i);
        }
        // 抽查: 枚举值 == 表里的位置
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
    }
}
