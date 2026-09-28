use anyhow::{Context, Result};
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

// 线程安全的日志写入器
#[derive(Clone)]
pub struct TrafficLogger {
    writer: Arc<Mutex<Inner>>,
    pub run_dir: PathBuf, // 暴露给 main 用来存 config.toml
}

// 一个写入器背后可以是好几个分片文件: traffic.log 写满上限就切到 traffic.2.log
struct Inner {
    w: BufWriter<File>,
    run_dir: PathBuf,
    written: u64,
    cap: u64, // 单片字节上限, 0 = 不限
    part: usize,
}

impl Inner {
    fn part_path(run_dir: &Path, part: usize) -> PathBuf {
        if part == 0 {
            run_dir.join("traffic.log")
        } else {
            run_dir.join(format!("traffic.{}.log", part + 1))
        }
    }
}

impl TrafficLogger {
    pub fn init() -> Result<Self> {
        let now = chrono::Local::now();

        // 1. 年-月 (YYYY-MM)
        let month_str = now.format("%Y-%m").to_string();

        // 2. 日_时-分-秒_run (DD_HH-MM-SS_run)
        let run_id = now.format("%d_%H-%M-%S_run").to_string();

        // 路径拼接: results/2025-12/15_09-30-00_run/
        let run_dir = Path::new("results").join(month_str).join(run_id);

        // 创建目录 (递归创建)
        fs::create_dir_all(&run_dir)
            .context(format!("Failed to create directory: {:?}", run_dir))?;

        // 创建日志文件
        let file_path = run_dir.join("traffic.log");
        let file = File::create(&file_path).context("Failed to create log file")?;

        //  println! 显示日志存放路径 而不是 log::info! 确保这一行一定能看到
        println!("📂 Logging to: {:?}", run_dir);

        Ok(Self {
            writer: Arc::new(Mutex::new(Inner {
                w: BufWriter::new(file),
                run_dir: run_dir.clone(),
                written: 0,
                cap: 0,
                part: 0,
            })),
            run_dir,
        })
    }

    /// 设置单个日志分片的上限(MB).0 = 不限, 与不填这个配置键等效
    pub fn set_max_log_mb(&self, mb: u64) {
        if let Ok(mut w) = self.writer.lock() {
            w.cap = mb.saturating_mul(1_048_576);
        }
    }

    pub fn log(&self, line: &str) {
        if let Ok(mut g) = self.writer.lock() {
            // 每行前面盖一个毫秒时刻: 没这个就没法把日志切成区间去和 curl/ss 对时
            let stamp = chrono::Local::now().format("%H:%M:%S%.3f");
            let _ = write!(g.w, "[{}] {}\n", stamp, line);
            // 14 = "[HH:MM:SS.mmm]" 的定宽长度, 免得每行再分配一次字符串
            g.written += 14 + line.len() as u64 + 1;
            if g.cap > 0 && g.written >= g.cap {
                let next = g.part + 1;
                let path = Inner::part_path(&g.run_dir, next);
                // 开新分片失败就继续写原来那个, 不因为磁盘问题把日志整段丢掉
                if let Ok(f) = File::create(&path) {
                    let _ = g.w.flush();
                    g.w = BufWriter::new(f);
                    g.written = 0;
                    g.part = next;
                    // 提示只写进文件, 不往屏幕印: 屏幕那一行是每秒刷新的活行,
                    // println 会把它的尾巴切掉
                    let _ = writeln!(g.w, "---- 上一片写满, 分片从这里开始: {:?} ----", path);
                }
            }
        }
    }
}
