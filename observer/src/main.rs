mod logger; //  自定义如何输出日志

use aya::{
    include_bytes_aligned, maps::perf::AsyncPerfEventArray, programs::KProbe, util::online_cpus,
    Bpf,
};
use bytes::BytesMut;
use chrono::format::format;
use log::{error, info, warn};
use logger::TrafficLogger;
use observer_common::{TcpEvent, TrafficDirection};
use serde::Deserialize;
use std::fs; // fs 模块拷贝 config.toml
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

    //  汇总日志

    let hook_msg = format!(
        "🪝 Hooks Active: Send({}), Recv({}), Accept({}), Retrans({})",
        send_func, recv_func, accept_func, retrans_func
    );
    info!("{}", hook_msg);
    logger.log(&hook_msg);

    // 读取 Perf Buffer
    let mut perf_array = AsyncPerfEventArray::try_from(bpf.take_map("EVENTS").unwrap())?;

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

                    let log_line = match event.direction {
                        TrafficDirection::Retransmit => {
                            format!(
                                "🚨 [RETRANSMIT] PID: {:<6} Comm: {:<16} | Packet Lost!",
                                event.pid, comm
                            )
                        }
                        TrafficDirection::Accept => {
                            format!(
                                "[NEW CONN] PID: {:<6} Comm: {:<16} Size: {:<6} bytes | Latency: {:<6} ns",
                                event.pid, comm, event.len, event.duration_ns
                            )
                        }
                        _ => {
                            let dir_str = match event.direction {
                                TrafficDirection::Egress => "SEND",
                                TrafficDirection::Ingress => "RECV",
                                _ => "UNKOWN",
                            };
                            format!(
                                "[{}] PID: {:<6} Comm: {:<16} Size: {:<6} bytes | Latency: {:<6} ns",
                                dir_str, event.pid, comm, event.len, event.duration_ns
                            )
                        }
                    };

                    // 双写:屏幕一份,日志文件文件一份
                    println!("{}", log_line);
                    file_logger.log(&log_line);
                }
            }
        });
    }

    signal::ctrl_c().await?;

    // 退出
    let exit_msg = "👋 Exiting...";
    info!("{}", exit_msg);
    logger.log(exit_msg);

    Ok(())
}
