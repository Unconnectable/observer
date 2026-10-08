//! observer 的用户态部分.
//! 拆成模块是为了让 main.rs 只管"装配 + 收事件", 也让测试能从外部访问
//! (见 tests/ 目录, 集成测试只能用 crate 的公开 API).

pub mod config;
pub mod hooks;
pub mod logger;
pub mod report;
pub mod stats;
pub mod tui;

// 让外部测试只需要 use observer::..., 不必再单独引入 observer-common
pub use observer_common::{TcpEvent, TrafficDirection};
