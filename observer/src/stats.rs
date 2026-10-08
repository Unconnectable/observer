//! 从事件流里算指标: 每个钩子触发次数 + 字节量/速率/重传率/反压总时长.
//! 标签取自 report::LOG_SPECS, 与每行日志同一份定义.
use crate::report::{LogSpec, HOOK_KINDS, LOG_SPECS};
use crate::{TcpEvent, TrafficDirection};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

/// 下标 = TrafficDirection 的取值, 与 report::LOG_SPECS 的行序一一对应
const DIRECTIONS: [TrafficDirection; HOOK_KINDS] = [
    TrafficDirection::Ingress,
    TrafficDirection::Egress,
    TrafficDirection::Accept,
    TrafficDirection::Retransmit,
    TrafficDirection::Connect,
    TrafficDirection::StateChange,
    TrafficDirection::Backpressure,
    TrafficDirection::Reset,
    TrafficDirection::UdpIngress,
    TrafficDirection::UdpEgress,
    TrafficDirection::Udp6Ingress,
    TrafficDirection::Udp6Egress,
];

/// Metrics 的一次快照, 存的全是累计值
pub struct Sample {
    pub secs: f64,
    pub hits: Vec<u64>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub blocked_ms: f64,
}

/// 一个进程(PID 维度)累计到的量, 只在界面模式下才记账
#[derive(Clone)]
pub struct PidRow {
    pub pid: u32,
    pub comm: String,
    pub events: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_n: u64,
    pub tx_n: u64,
    pub retrans: u64,
    pub rst: u64,
    pub blocked_ns: u64,
}

impl PidRow {
    pub fn bytes_total(&self) -> u64 {
        self.rx_bytes + self.tx_bytes
    }
}

pub struct Metrics {
    hits: Vec<AtomicU64>,
    bytes_tx: AtomicU64,
    bytes_rx: AtomicU64,
    blocked_ns: AtomicU64,
    // 重传事件里有多少条的 comm 是软中断/网卡中断(kprobe 拿不到真正的进程)
    retrans_irq: AtomicU64,
    // 按 PID 的明细, 默认关闭: 纯文本模式不需要它, 免得每条事件多一次加锁
    track_pids: AtomicBool,
    pids: Mutex<HashMap<u32, PidRow>>,
    started: Instant,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub fn new() -> Self {
        Metrics {
            hits: (0..HOOK_KINDS).map(|_| AtomicU64::new(0)).collect(),
            bytes_tx: AtomicU64::new(0),
            bytes_rx: AtomicU64::new(0),
            blocked_ns: AtomicU64::new(0),
            retrans_irq: AtomicU64::new(0),
            track_pids: AtomicBool::new(false),
            pids: Mutex::new(HashMap::new()),
            started: Instant::now(),
        }
    }

    /// 打开按 PID 的明细记账(界面模式用)
    pub fn set_track_pids(&self, on: bool) {
        self.track_pids.store(on, Ordering::Relaxed);
    }

    /// 当前按 PID 的明细, 按总字节从多到少排
    pub fn pid_rows(&self) -> Vec<PidRow> {
        let mut rows: Vec<PidRow> = match self.pids.lock() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => return Vec::new(),
        };
        rows.sort_by(|a, b| b.bytes_total().cmp(&a.bytes_total()));
        rows
    }

    /// 累计被按住的毫秒总数
    pub fn blocked_ms_total(&self) -> f64 {
        self.blocked_ns.load(Ordering::Relaxed) as f64 / 1_000_000.0
    }

    /// 重传里落在软中断/网卡中断的条数(这部分拿不到真正的进程)
    pub fn retrans_irq_total(&self) -> u64 {
        self.retrans_irq.load(Ordering::Relaxed)
    }

    fn add(&self, which: TrafficDirection) -> u64 {
        self.hits
            .get(which as usize)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    // 重传是在软中断里补发的, kprobe 看到的就是中断线程本身, 不是发起流量的进程
    fn is_irq_comm(comm: &[u8; 16]) -> bool {
        comm.starts_with(b"swapper") || comm.starts_with(b"irq/") || comm.starts_with(b"ksoftirqd")
    }

    /// 记一条事件: 计数 + 按方向累加字节 + 累加被按住时长.下标越界时静默忽略
    pub fn record(&self, event: &TcpEvent) {
        if let Some(counter) = self.hits.get(event.direction as usize) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
        match event.direction {
            TrafficDirection::Egress
            | TrafficDirection::UdpEgress
            | TrafficDirection::Udp6Egress => {
                self.bytes_tx.fetch_add(event.len as u64, Ordering::Relaxed);
            }
            TrafficDirection::Ingress
            | TrafficDirection::UdpIngress
            | TrafficDirection::Udp6Ingress => {
                self.bytes_rx.fetch_add(event.len as u64, Ordering::Relaxed);
            }
            TrafficDirection::Backpressure => {
                self.blocked_ns
                    .fetch_add(event.duration_ns, Ordering::Relaxed);
            }
            _ => {}
        }
        if event.direction == TrafficDirection::Retransmit && Self::is_irq_comm(&event.comm) {
            self.retrans_irq.fetch_add(1, Ordering::Relaxed);
        }

        // 按 PID 的明细: 键用 tgid(进程), 不用 pid(线程), 否则一个浏览器会铺成几十个条目
        if self.track_pids.load(Ordering::Relaxed) {
            let comm = String::from_utf8_lossy(&event.comm)
                .trim_end_matches('\0')
                .to_string();
            if let Ok(mut g) = self.pids.lock() {
                let row = g.entry(event.tgid).or_insert_with(|| PidRow {
                    pid: event.tgid,
                    comm: String::new(),
                    events: 0,
                    rx_bytes: 0,
                    tx_bytes: 0,
                    rx_n: 0,
                    tx_n: 0,
                    retrans: 0,
                    rst: 0,
                    blocked_ns: 0,
                });
                if row.comm.is_empty() {
                    row.comm = comm;
                }
                row.events += 1;
                match event.direction {
                    TrafficDirection::Egress
                    | TrafficDirection::UdpEgress
                    | TrafficDirection::Udp6Egress => {
                        row.tx_bytes += event.len as u64;
                        row.tx_n += 1;
                    }
                    TrafficDirection::Ingress
                    | TrafficDirection::UdpIngress
                    | TrafficDirection::Udp6Ingress => {
                        row.rx_bytes += event.len as u64;
                        row.rx_n += 1;
                    }
                    TrafficDirection::Retransmit => row.retrans += 1,
                    TrafficDirection::Reset => row.rst += 1,
                    TrafficDirection::Backpressure => row.blocked_ns += event.duration_ns,
                    _ => {}
                }
            }
        }
    }

    fn secs(&self) -> f64 {
        self.started.elapsed().as_secs_f64().max(0.001)
    }

    pub fn human(bytes: f64) -> String {
        if bytes >= 1_048_576.0 {
            format!("{:.2} MB", bytes / 1_048_576.0)
        } else if bytes >= 1024.0 {
            format!("{:.1} KB", bytes / 1024.0)
        } else {
            format!("{:.0} B", bytes)
        }
    }

    /// 某一时刻的累计量快照, 供周期性汇总算区间增量用
    pub fn snapshot(&self) -> Sample {
        Sample {
            secs: self.secs(),
            hits: self
                .hits
                .iter()
                .map(|c| c.load(Ordering::Relaxed))
                .collect(),
            rx_bytes: self.bytes_rx.load(Ordering::Relaxed),
            tx_bytes: self.bytes_tx.load(Ordering::Relaxed),
            blocked_ms: self.blocked_ns.load(Ordering::Relaxed) as f64 / 1_000_000.0,
        }
    }

    /// 一个区间一行: 传入上一次快照和当前快照
    pub fn interval_line(prev: &Sample, cur: &Sample) -> String {
        let dt = (cur.secs - prev.secs).max(0.001);
        let d =
            |a: &[u64], b: &[u64], i: usize| -> u64 { (b[i] as i64 - a[i] as i64).max(0) as u64 };
        let events: u64 = cur
            .hits
            .iter()
            .zip(prev.hits.iter())
            .map(|(c, p)| (*c as i64 - *p as i64).max(0) as u64)
            .sum();
        let retrans = d(&prev.hits, &cur.hits, TrafficDirection::Retransmit as usize);

        format!(
            "⏱ {:.0}s {:>6.1} 条/s ↓{:.1} KB/s ↑{:.1} KB/s 重传 {} 次",
            cur.secs,
            events as f64 / dt,
            (cur.rx_bytes - prev.rx_bytes) as f64 / 1024.0 / dt,
            (cur.tx_bytes - prev.tx_bytes) as f64 / 1024.0 / dt,
            retrans,
        )
    }

    /// 每个钩子触发了多少次
    pub fn summary(&self) -> Vec<String> {
        let specs: &[LogSpec] = &LOG_SPECS;
        let mut out = vec!["📊 ===== 钩子触发次数汇总 =====".to_string()];
        let mut total: u64 = 0;
        for (i, spec) in specs.iter().enumerate() {
            let hits = self.add(DIRECTIONS[i]);
            total += hits;
            out.push(format!("   {:<14} {}", spec.tag, hits));
        }
        out.push(format!("   {:<14} {}", "TOTAL", total));
        if total == 0 {
            out.push("   (全是 0: 要么没有流量, 要么挂载点没被触发)".to_string());
        }
        out
    }

    /// 派生指标.分母口径写在每一行后面, 免得被当成精确值
    pub fn report(&self) -> Vec<String> {
        let s = self.secs();
        let tx = self.bytes_tx.load(Ordering::Relaxed) as f64;
        let rx = self.bytes_rx.load(Ordering::Relaxed) as f64;
        let events: u64 = DIRECTIONS.iter().map(|d| self.add(*d)).sum();
        let retrans = self.add(TrafficDirection::Retransmit);
        let connects = self.add(TrafficDirection::Connect);
        let blocked_n = self.add(TrafficDirection::Backpressure);
        let blocked_ms = self.blocked_ns.load(Ordering::Relaxed) as f64 / 1_000_000.0;

        let mut out = vec!["📈 ===== 指标 =====".to_string()];
        out.push(format!("   运行时长       {:>8.1} s", s));
        out.push(format!("   事件速率       {:>8.1} 条/s", events as f64 / s));
        out.push(format!(
            "   下行(应用字节) {:>8} ({:.1} KB/s)",
            Self::human(rx),
            rx / 1024.0 / s
        ));
        out.push(format!(
            "   上行(应用字节) {:>8} ({:.1} KB/s)",
            Self::human(tx),
            tx / 1024.0 / s
        ));
        // 注意: 一次 tcp_sendmsg 会被拆成很多包, 所以"重传 ÷ sendmsg 调用数"不是丢包率,
        // 那样印百分比会算出 59 % 这种离谱值.这里只给可核实的量:次数和速率.
        // 归属比例也不能写死 —— 同一台机器上实测过 38.6 % 和 72.6 % 两个值.
        let retrans_irq = self.retrans_irq.load(Ordering::Relaxed);
        let irq_note = if retrans == 0 {
            "(没有重传)".to_string()
        } else {
            format!(
                "{} 次里 {} 次落在软中断/网卡中断({:.1} %), 这部分拿不到真正的进程",
                retrans,
                retrans_irq,
                retrans_irq as f64 * 100.0 / retrans as f64
            )
        };
        out.push(format!(
            "   重传事件       {:>8.1} 次/s {}",
            retrans as f64 / s,
            irq_note
        ));
        // 这一栏数的是客户端侧 connect(); 服务端 accept 是 NEW CONN 那一行
        out.push(format!(
            "   发起连接       {:>8.1} 次/s",
            connects as f64 / s
        ));
        // 这一栏是"进程要写出去的数据内核暂时收不下, 让它多等了一会儿"的总时长
        let blocked_text = if blocked_n == 0 {
            "没发生".to_string()
        } else {
            format!("{} ({} 次)", Self::human_ms(blocked_ms), blocked_n)
        };
        out.push(format!(
            "   发不出去       {} —— 要写的数据内核暂时收不下, 等了一会儿",
            blocked_text
        ));
        out
    }

    pub fn human_ms(ms: f64) -> String {
        if ms >= 1000.0 {
            format!("{:.2} s", ms / 1000.0)
        } else if ms >= 1.0 {
            format!("{:.1} ms", ms)
        } else {
            // 亚毫秒时印 0.0 ms 等于没印, 改显微秒
            format!("{:.1} µs", ms * 1000.0)
        }
    }
}
