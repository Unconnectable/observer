use anyhow::{Context, Result};
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

// 线程安全的日志写入器
#[derive(Clone)]
pub struct TrafficLogger {
    writer: Arc<Mutex<BufWriter<File>>>,
    pub run_dir: PathBuf, // 暴露给 main 用来存 config.toml
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
            writer: Arc::new(Mutex::new(BufWriter::new(file))),
            run_dir,
        })
    }

    pub fn log(&self, line: &str) {
        if let Ok(mut w) = self.writer.lock() {
            let _ = writeln!(w, "{}", line);
        }
    }
}
