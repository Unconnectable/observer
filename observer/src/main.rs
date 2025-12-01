use aya::{
    include_bytes_aligned, maps::perf::AsyncPerfEventArray, programs::KProbe, util::online_cpus,
    Bpf,
};
use bytes::BytesMut;
use clap::Parser;
use log::info;
use observer_common::TcpEvent;
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    /// 要监控的目标 TGID (主进程 ID)
    #[clap(short, long)]
    pid: Option<u32>,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    let opt = Opt::parse();

    // 1. 加载 eBPF 字节码
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/observer"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/observer"
    ))?;

    // 2. 加载并挂载 KProbe (Entry)
    let program: &mut KProbe = bpf.program_mut("tcp_sendmsg_entry").unwrap().try_into()?;
    program.load()?;
    program.attach("tcp_sendmsg", 0)?;
    info!("Attached tcp_sendmsg entry probe");

    // 3. 加载并挂载 KRetProbe (Return)
    let program: &mut KProbe = bpf.program_mut("tcp_sendmsg_return").unwrap().try_into()?;
    program.load()?;
    program.attach("tcp_sendmsg", 0)?;
    info!("Attached tcp_sendmsg return probe");

    // 4. 读取 Perf Buffer
    let mut perf_array = AsyncPerfEventArray::try_from(bpf.take_map("EVENTS").unwrap())?;

    info!("Waiting for events...");
    if let Some(p) = opt.pid {
        info!("Filtering for TGID (Main Process ID): {}", p);
    } else {
        info!("No PID filter (showing all TCP traffic)");
    }

    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;
        let target_pid = opt.pid;

        tokio::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                // 读取事件
                let events = buf.read_events(&mut buffers).await.unwrap();

                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let ptr = buf.as_ptr() as *const TcpEvent;
                    let event = unsafe { ptr.read_unaligned() };

                    // 解析进程名
                    let comm = std::str::from_utf8(&event.comm)
                        .unwrap_or("<unknown>")
                        .trim_end_matches('\0');

                    // 过滤与打印逻辑
                    if let Some(target) = target_pid {
                        // 使用 event.tgid (主进程ID) 进行过滤
                        if event.tgid != target {
                            // 保持调试输出来确认我们捕获到了正确的 TGID
                            // if comm.contains("tokio-runtime") || comm.contains("websocket") {
                            //     // 打印 Mismatch 只是调试,真正的目标是打印 SEND
                            // }
                            if comm.contains("tokio")
                                || comm.contains("websocket")
                                || comm.contains("press")
                            {
                                println!(
                                    "[DEBUG] PID Mismatch! Event TGID: {}, Target: {}, Comm: {}",
                                    event.tgid, target, comm
                                );
                            }
                            continue;
                        }
                    }

                    // 只有 TGID 匹配时才会到达这里
                    println!(
                        "[SEND] PID: {:<6} Comm: {:<12} Size: {:<6} bytes | Latency: {:<6} ns",
                        event.pid, comm, event.len, event.duration_ns
                    );
                }
            }
        });
    }

    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
