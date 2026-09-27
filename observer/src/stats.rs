//! 每个钩子触发了多少次。标签取自 report::LOG_SPECS, 与每行日志同一份定义。
use crate::report::{LogSpec, HOOK_KINDS, LOG_SPECS};
use observer_common::TrafficDirection;
use std::sync::atomic::{AtomicU64, Ordering};

pub struct HookCounts {
    hits: Vec<AtomicU64>,
}

impl Default for HookCounts {
    fn default() -> Self {
        Self::new()
    }
}

impl HookCounts {
    pub fn new() -> Self {
        HookCounts {
            hits: (0..HOOK_KINDS).map(|_| AtomicU64::new(0)).collect(),
        }
    }

    /// 记一次触发。下标越界(结构体错位之类的脏数据)时静默忽略, 不影响主循环
    pub fn record(&self, direction: TrafficDirection) {
        if let Some(counter) = self.hits.get(direction as usize) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// 汇总文本, 一行一条; 打印和落盘由调用方负责(双写)
    pub fn summary(&self) -> Vec<String> {
        let spec: &[LogSpec] = &LOG_SPECS;
        let mut out = vec!["📊 ===== 钩子触发次数汇总 =====".to_string()];
        let mut total: u64 = 0;
        for (i, spec) in spec.iter().enumerate() {
            let hits = self
                .hits
                .get(i)
                .map(|c| c.load(Ordering::Relaxed))
                .unwrap_or(0);
            total += hits;
            out.push(format!("   {:<12} {}", spec.tag, hits));
        }
        out.push(format!("   {:<12} {}", "TOTAL", total));
        if total == 0 {
            out.push("   (全是 0: 要么没有流量, 要么挂载点没被触发)".to_string());
        }
        out
    }
}
