use aya::{include_bytes_aligned, maps::perf::AsyncPerfEventArray, util::online_cpus, Bpf};
use bytes::BytesMut;
use chrono::format::format;
use log::{error, info, warn};
use observer::config::{find_target_tgid, load};
use observer::hooks;
use observer::logger::TrafficLogger;
use observer::report::render_event;
use observer::stats::Metrics;
use observer::TcpEvent;
use std::fs; // fs 模块拷贝 config.toml
use std::io::Write; // 每秒刷新的那一行要手动 flush, print! 不像 println! 会自动换行触发
use std::sync::atomic::{AtomicBool, Ordering}; // 退出标志: 让各 CPU 的读取任务停下来
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

    // 配置一读出来就把日志上限交给 logger (0 = 不限)
    logger.set_max_log_mb(config.settings.max_log_mb);

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

    let counts = Arc::new(Metrics::new());
    let stop = Arc::new(AtomicBool::new(false)); // 置为 true 后各任务收尾退出
    let mut readers: Vec<tokio::task::JoinHandle<()>> = Vec::new();

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
        let stop = stop.clone(); // 共用同一个退出标志

        readers.push(tokio::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();
            // 收到退出信号后停止读取, 这样最后的统计不会再漏事件
            while !stop.load(Ordering::Relaxed) {
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
                    // 屏幕这一路先关掉: 一分钟八千行没人看得了, 逐行只留在文件里
                    // println!("{}", log_line);
                    file_logger.log(&log_line);

                    // 计数, 供退出时汇总
                    counts.record(&event);
                }
            }
        }));
    }

    // 运行中每 1 秒刷新同一行: 屏幕只占一行不刷屏, 文件里仍按秒留一行历史
    let stats_handle = {
        let counts = counts.clone();
        let file_logger = logger.clone();
        let stop = stop.clone();
        tokio::spawn(async move {
            const STATS_MS: u64 = 1000;
            let mut prev = counts.snapshot();
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(STATS_MS)).await;
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                let cur = counts.snapshot();
                let line = Metrics::interval_line(&prev, &cur);
                // \r 回到行首 + \x1b[K 擦掉右边残留, 所以屏幕上永远是同一行在换数字
                print!("\r\x1b[K{}", line);
                let _ = std::io::stdout().flush();
                file_logger.log(&line);
                prev = cur;
            }
        })
    };

    signal::ctrl_c().await?;

    // 先让各 CPU 的读取任务收尾, 再统计, 否则汇总会漏掉最后一批
    stop.store(true, Ordering::Relaxed);
    // 不能用 abort(): 掐的那一刻任务可能正处在一次 print! 中间, 退出块前面就会多个
    // 半行的尾巴(你那次就印出了 "s📈 ===== 指标 ====="). 改成等它自己跳出循环 ——
    // 它每 1 秒醒一次并检查 stop, 所以最多等 1.2 秒就一定能干净退出
    if tokio::time::timeout(std::time::Duration::from_millis(1200), stats_handle)
        .await
        .is_err()
    {
        warn!("⚠️ 统计任务 1.2 秒没退出, 强制掐掉");
    }
    println!(); // 那行结尾没有换行, 这里补一个, 让它正式占一行

    // 退出
    let exit_msg = "👋 Exiting...";
    info!("{}", exit_msg);
    logger.log(exit_msg);

    // 各 CPU 的读取任务卡在 read_events 上不会自己醒, 等一小会儿让它们把
    // 已到-buffer 的事件收完, 再直接把任务掐掉.掐在 await 点上, 不会撕碎半批事件,
    // 汇总数字和日志文件的条数因此能对上 (旧写法是固定睡 3 秒, 每次差 0~2 条)
    const DRAIN_MS: u64 = 300;
    let drain_msg = format!("⏳ 再等 {} 毫秒收尾统计...", DRAIN_MS);
    println!("{}", drain_msg);
    logger.log(&drain_msg);
    tokio::time::sleep(std::time::Duration::from_millis(DRAIN_MS)).await;
    for handle in readers.iter() {
        handle.abort();
    }
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // 退出时先给派生指标(速率/字节量/重传比例/被按住总时长), 再给每个钩子的次数汇总
    for line in counts.report() {
        println!("{}", line);
        logger.log(&line);
    }

    // 退出时把每个钩子的触发次数汇总, 同样双写(屏幕一份, 日志文件一份)
    for line in counts.summary() {
        println!("{}", line);
        logger.log(&line);
    }

    Ok(())
}
