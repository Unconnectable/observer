//! 配置: 结构定义、读取 config.toml、以及要监控哪个进程
use log::{info, warn};
use serde::Deserialize;
use sysinfo::{PidExt, ProcessExt, System, SystemExt};

#[derive(Debug, Deserialize)]
pub struct AppConfig {
    pub probes: ProbesConfig,
    pub discovery: DiscoveryConfig,
    pub filters: FiltersConfig,
    pub settings: SettingsConfig,
}

#[derive(Debug, Deserialize)]
pub struct ProbesConfig {
    pub target_func: String,
    pub recv_func: String,
    pub accept_func: String,
    pub retransmit_func: String,

    // 追加挂载点
    pub connect_func: String,
    pub state_func: String,
    pub reset_func: String,
    pub backpressure_func: String,
    pub udp_send_func: String,
    pub udp_recv_func: String,
    pub udp6_send_func: String,
    pub udp6_recv_func: String,
}

#[derive(Debug, Deserialize)]
pub struct DiscoveryConfig {
    pub force_pid: Option<u32>,
    pub auto_detect_name: String,
}

#[derive(Debug, Deserialize)]
pub struct FiltersConfig {
    pub include_names: Vec<String>,
    pub exclude_names: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct SettingsConfig {
    pub perf_pages: usize,
}

/// 加载并解析 config.toml(相对当前工作目录)
pub fn load() -> Result<AppConfig, anyhow::Error> {
    let settings = config::Config::builder()
        .add_source(config::File::with_name("config"))
        .build()?;
    Ok(settings.try_deserialize()?)
}

// 找指定的pid
pub fn find_target_tgid(config: &DiscoveryConfig) -> Option<u32> {
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
