//! 一行日志怎么拼.所有差异都收在 LOG_SPECS 这张表里,
//! 退出汇总也取同一份 tag, 所以日志里的标签和统计里的标签不会分成两套.
use observer_common::{tcp_state, TcpEvent, TrafficDirection};

// tcp_set_state 上报的数值翻译成状态名
pub fn state_name(value: u32) -> &'static str {
    match value {
        tcp_state::ESTABLISHED => "ESTABLISHED",
        tcp_state::SYN_SENT => "SYN_SENT",
        tcp_state::SYN_RECV => "SYN_RECV",
        tcp_state::FIN_WAIT1 => "FIN_WAIT1",
        tcp_state::FIN_WAIT2 => "FIN_WAIT2",
        tcp_state::TIME_WAIT => "TIME_WAIT",
        tcp_state::CLOSE => "CLOSE",
        tcp_state::CLOSE_WAIT => "CLOSE_WAIT",
        tcp_state::LAST_ACK => "LAST_ACK",
        tcp_state::LISTEN => "LISTEN",
        tcp_state::CLOSING => "CLOSING",
        tcp_state::NEW_SYN_RECV => "NEW_SYN_RECV",
        _ => "UNKNOWN",
    }
}

//   日志由这张表决定 (下标 = TrafficDirection 的取值)
pub const HOOK_KINDS: usize = 12;

pub struct LogSpec {
    pub emoji: &'static str,
    pub tag: &'static str,
    pub show_size: bool,
    pub show_latency: bool,
}

// 不同的traffic log 标识
pub const LOG_SPECS: [LogSpec; HOOK_KINDS] = [
    // 0
    LogSpec {
        emoji: "",
        tag: "RECV",
        show_size: true,
        show_latency: true,
    },
    // 1
    LogSpec {
        emoji: "",
        tag: "SEND",
        show_size: true,
        show_latency: true,
    },
    // 2
    LogSpec {
        emoji: "",
        tag: "NEW CONN",
        show_size: true,
        show_latency: true,
    },
    // 3
    LogSpec {
        emoji: "🚨",
        tag: "TCP RETRANSMIT",
        show_size: false,
        show_latency: false,
    },
    // 4
    LogSpec {
        emoji: "",
        tag: "TCP CONNECT",
        show_size: false,
        show_latency: true,
    },
    // 5
    LogSpec {
        emoji: "",
        tag: "TCP STATE",
        show_size: false,
        show_latency: false,
    },
    // 6
    LogSpec {
        emoji: "🚧",
        tag: "BACKPRESSURE",
        show_size: false,
        show_latency: false,
    },
    // 7
    LogSpec {
        emoji: "🚨",
        tag: "RST",
        show_size: false,
        show_latency: false,
    },
    // 8
    LogSpec {
        emoji: "",
        tag: "UDP4 RECV",
        show_size: true,
        show_latency: true,
    },
    // 9
    LogSpec {
        emoji: "",
        tag: "UDP4 SEND",
        show_size: true,
        show_latency: true,
    },
    // 10
    LogSpec {
        emoji: "",
        tag: "UDP6 RECV",
        show_size: true,
        show_latency: true,
    },
    // 11
    LogSpec {
        emoji: "",
        tag: "UDP6 SEND",
        show_size: true,
        show_latency: true,
    },
];

/// 表里装不下的那点差异: 写在 Comm 后面(Head)还是写在整行末尾(Tail)
enum Detail {
    None,
    Head(String),
    Tail(String),
}

fn detail_of(event: &TcpEvent) -> Detail {
    match event.direction {
        TrafficDirection::Retransmit => Detail::Tail("Packet Lost!".to_string()),
        TrafficDirection::Connect => {
            let ret = event.value as i32;
            if ret == 0 {
                Detail::Head("SYN-sent".to_string())
            } else {
                Detail::Head(format!("err={}", ret))
            }
        }
        TrafficDirection::StateChange => Detail::Head(format!("-> {}", state_name(event.value))),
        TrafficDirection::Backpressure => {
            Detail::Tail(format!("Blocked: {:<6} ns", event.duration_ns))
        }
        TrafficDirection::Reset => Detail::Tail("Active Reset Sent!".to_string()),
        _ => Detail::None,
    }
}

/// 唯一的拼行函数 吧之前的match合并到现在的一个
pub fn render_event(event: &TcpEvent, comm: &str) -> String {
    let spec = match LOG_SPECS.get(event.direction as usize) {
        Some(s) => s,
        None => return format!("[UNKOWN] PID: {:<6} Comm: {:<16}", event.pid, comm),
    };

    let mut s = format!(
        "{}{}[{}] PID: {:<6} Comm: {:<16}",
        spec.emoji,
        if spec.emoji.is_empty() { "" } else { " " },
        spec.tag,
        event.pid,
        comm
    );
    let mut has_clause = false;
    let detail = detail_of(event);

    if let Detail::Head(text) = &detail {
        s.push_str(&format!(" {}", text));
        has_clause = true;
    }
    if spec.show_size {
        s.push_str(&format!(" Size: {:<6} bytes", event.len));
        has_clause = true;
    }
    if spec.show_latency {
        if has_clause {
            s.push_str(" |");
        }
        s.push_str(&format!(" Latency: {:<6} ns", event.duration_ns));
    }
    if let Detail::Tail(text) = &detail {
        s.push_str(&format!(" | {}", text));
    }
    s
}
