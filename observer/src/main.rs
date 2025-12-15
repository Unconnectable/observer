mod logger; // +++ 引入新模块

use aya::{
    include_bytes_aligned, maps::perf::AsyncPerfEventArray, programs::KProbe, util::online_cpus,
    Bpf,
};
use bytes::BytesMut;
use log::{error, info, warn};
use logger::TrafficLogger;
use observer_common::TcpEvent;
use serde::Deserialize;
use std::fs; // fs 模块拷贝 config.toml
use sysinfo::{PidExt, ProcessExt, System, SystemExt};
use tokio::signal; // +++ 使用 Logger

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

    // 初始化文件日志系统 (按月/日分类)
    let logger = TrafficLogger::init()?;

    // 2. +++ 备份配置文件到当次运行目录
    if let Err(e) = fs::copy("config.toml", logger.run_dir.join("config.toml")) {
        warn!("⚠️ Config backup failed: {}", e);
    }

    // 3. 加载并解析配置 config.toml
    let settings = config::Config::builder()
        .add_source(config::File::with_name("config"))
        .build()?;
    let config: AppConfig = settings.try_deserialize()?;
    info!(
        "📋 Filter Rules: Include {:?}, Exclude {:?}",
        config.filters.include_names, config.filters.exclude_names
    );

    // 4. 寻找要监测的pid
    let target_tgid = find_target_tgid(&config.discovery);
    if target_tgid.is_none() {
        warn!("🌐 Running in GLOBAL mode (Filtered by names only)");
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

    // 6. 挂载探针
    let func = &config.probes.target_func;
    info!("🪝 Hooking into: {}", func);
    let p_entry: &mut KProbe = bpf.program_mut("tcp_sendmsg_entry").unwrap().try_into()?;
    p_entry.load()?;
    p_entry.attach(func, 0)?;

    let p_return: &mut KProbe = bpf.program_mut("tcp_sendmsg_return").unwrap().try_into()?;
    p_return.load()?;
    p_return.attach(func, 0)?;

    // 7. 读取 Perf Buffer
    let mut perf_array = AsyncPerfEventArray::try_from(bpf.take_map("EVENTS").unwrap())?;

    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, Some(config.settings.perf_pages))?;

        let t_tgid = target_tgid;
        let includes = config.filters.include_names.clone();
        let excludes = config.filters.exclude_names.clone();

        // +++ 克隆 logger 指针传给异步任务
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

                    // --- 过滤规则 ---

                    // 规则 1: 只看 指定 PID
                    if let Some(target) = t_tgid {
                        if event.tgid != target {
                            continue;
                        }
                    }

                    // 规则 2: 黑名单过滤 (Exclude)
                    if !excludes.is_empty() && excludes.iter().any(|name| comm.contains(name)) {
                        continue;
                    }

                    // 规则 3: 白名单过滤 (Include)
                    if !includes.is_empty() && !includes.iter().any(|name| comm.contains(name)) {
                        continue;
                    }

                    let log_line = format!(
                        "[SEND] PID: {:<6} Comm: {:<16} Size: {:<6} bytes | Latency: {:<6} ns",
                        event.pid, comm, event.len, event.duration_ns
                    );

                    // +++ 双写：屏幕一份，文件一份 +++
                    println!("{}", log_line);
                    file_logger.log(&log_line);
                }
            }
        });
    }

    signal::ctrl_c().await?;
    info!("👋 Exiting...");
    Ok(())
}
