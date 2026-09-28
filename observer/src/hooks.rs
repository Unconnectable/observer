//! 挂载点: 每个钩子 = 一个内核函数 + 它在内核态对应的 entry/return 程序名
use crate::config::ProbesConfig;
use aya::{programs::KProbe, Bpf};

/// 一个挂载点: 日志标签 + 内核函数名(来自 config) + 对应的 entry/return BPF 程序名
pub struct Hook<'a> {
    pub label: &'static str,
    pub func: &'a str,
    pub entry: &'static str,
    pub ret: Option<&'static str>,
}

impl<'a> Hook<'a> {
    /// 把某个 BPF 程序挂到内核函数上, entry 和 return 共用这一份
    fn attach_one(bpf: &mut Bpf, prog_name: &str, func: &str) -> Result<(), anyhow::Error> {
        let kprobe: &mut KProbe = bpf.program_mut(prog_name).unwrap().try_into()?;
        kprobe.load()?;
        kprobe.attach(func, 0)?;
        Ok(())
    }

    /// 挂上这个钩子.语义和原来手写的三段式一致: 程序名写错照样 panic,
    /// load/attach 失败原样向上返回错误
    pub fn attach(&self, bpf: &mut Bpf) -> Result<(), anyhow::Error> {
        Self::attach_one(bpf, self.entry, self.func)?;
        if let Some(ret) = self.ret {
            Self::attach_one(bpf, ret, self.func)?;
        }
        Ok(())
    }

    /// 汇总日志
    pub fn summary(&self) -> String {
        format!("{}({})", self.label, self.func)
    }
}

/// 挂载点清单.加新钩子: 内核态写出同名程序 + config 加一个键 + 这里加一条
pub fn plan(probes: &ProbesConfig) -> Vec<Hook<'_>> {
    vec![
        Hook {
            label: "SEND",
            func: probes.target_func.as_str(),
            entry: "tcp_sendmsg_entry",
            ret: Some("tcp_sendmsg_return"),
        },
        Hook {
            label: "RECV",
            func: probes.recv_func.as_str(),
            entry: "tcp_recvmsg_entry",
            ret: Some("tcp_recvmsg_return"),
        },
        Hook {
            label: "ACCEPT",
            func: probes.accept_func.as_str(),
            entry: "inet_csk_accept_entry",
            ret: Some("inet_csk_accept_return"),
        },
        Hook {
            label: "RETRANSMIT",
            func: probes.retransmit_func.as_str(),
            entry: "tcp_retransmit_skb_entry",
            ret: None,
        },
        Hook {
            label: "CONNECT",
            func: probes.connect_func.as_str(),
            entry: "tcp_connect_entry",
            ret: Some("tcp_connect_return"),
        },
        Hook {
            label: "STATE",
            func: probes.state_func.as_str(),
            entry: "tcp_set_state_entry",
            ret: None,
        },
        Hook {
            label: "RST",
            func: probes.reset_func.as_str(),
            entry: "tcp_send_active_reset_entry",
            ret: None,
        },
        Hook {
            label: "BACKPRESSURE",
            func: probes.backpressure_func.as_str(),
            entry: "sk_stream_wait_memory_entry",
            ret: Some("sk_stream_wait_memory_return"),
        },
        Hook {
            label: "UDP4 SEND",
            func: probes.udp_send_func.as_str(),
            entry: "udp_sendmsg_entry",
            ret: Some("udp_sendmsg_return"),
        },
        Hook {
            label: "UDP4 RECV",
            func: probes.udp_recv_func.as_str(),
            entry: "udp_recvmsg_entry",
            ret: Some("udp_recvmsg_return"),
        },
        Hook {
            // IPv6 的 UDP 是另一个内核函数, 少挂一组会静默漏掉 IPv6 的 DNS 和 QUIC
            label: "UDP6 SEND",
            func: probes.udp6_send_func.as_str(),
            entry: "udpv6_sendmsg_entry",
            ret: Some("udpv6_sendmsg_return"),
        },
        Hook {
            label: "UDP6 RECV",
            func: probes.udp6_recv_func.as_str(),
            entry: "udpv6_recvmsg_entry",
            ret: Some("udpv6_recvmsg_return"),
        },
    ]
}
