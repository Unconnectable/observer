use aya::{include_bytes_aligned, maps::perf::AsyncPerfEventArray, util::online_cpus, Bpf};
use bytes::BytesMut;
use chrono::format::format;
use log::{error, info, warn};
use observer::config::{find_target_tgid, load};
use observer::hooks;
use observer::logger::TrafficLogger;
use observer::report::render_event;
use observer::stats::HookCounts;
use observer::TcpEvent;
use std::fs; // fs 模块拷贝 config.toml
use std::sync::Arc; // 统计每个钩子的触发次数, 退出时汇总
use tokio::signal;

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
    let config = load()?;

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

    // 6. 按清单挂载
    let plan = hooks::plan(&config.probes);
    let mut active: Vec<String> = Vec::new();
    for hook in plan.iter() {
        hook.attach(&mut bpf)?;
        active.push(hook.summary());
    }

    //  汇总日志: 一次打印全部挂载结果
    let hook_msg = format!("🪝 Hooks Active: {}", active.join(", "));
    info!("{}", hook_msg);
    logger.log(&hook_msg);

    // 读取 Perf Buffer
    let mut perf_array = AsyncPerfEventArray::try_from(bpf.take_map("EVENTS").unwrap())?;

    let counts = Arc::new(HookCounts::new());

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
        let counts = counts.clone(); // 每个 CPU 的任务共用同一份计数器

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

                    let log_line = render_event(&event, comm);

                    // 双写:屏幕一份,日志文件文件一份
                    println!("{}", log_line);
                    file_logger.log(&log_line);

                    // 计数, 供退出时汇总
                    counts.record(event.direction);
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
    for line in counts.summary() {
        println!("{}", line);
        logger.log(&line);
    }

    Ok(())
}
