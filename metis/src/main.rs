pub mod modules;
pub mod probes;
pub mod util;

use crate::modules::mysql::dependencies::MysqlModule;
use aya::programs::{KProbe, TracePoint};
#[rustfmt::skip]
use log::{debug, warn};
use crate::modules::Module;
use crate::modules::http::HttpModule;
use crate::modules::tcp::tcp::TcpModule;
use crate::probes::kprobes::tcp_sendmsg::TCPSendMsgProbe;
use crate::probes::tracepoints::tcp_probe::TcpProbe;
use crate::probes::tracepoints::tcp_retransmit_skb::TcpRetransmitSkb;
use crate::probes::{Probe, ProbeEvent, ProbeRequirement};
use crate::util::TelegrafMetricsPusher;
use aya::maps::RingBuf;
use log::info;
use metis_common::TCPProbeEvent;
use std::env;
use std::sync::Arc;
use tokio::io::unix::AsyncFd;
use tokio::signal;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let metrics_pusher = Arc::new(TelegrafMetricsPusher::new("127.0.0.1:8125").await?);

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/metis"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    let enabled_modules: Vec<Box<dyn Module>> = vec![
        // Box::new(MysqlModule),
        // Box::new(HttpModule),
        Box::new(TcpModule),
    ];

    let mut required_probes: Vec<ProbeRequirement> = vec![];
    let mut tcp_sendmsg_ports: Vec<u16> = Vec::new();
    let mut tcp_retransmit_skb_ports: Vec<u16> = Vec::new();

    for module in &enabled_modules {
        required_probes.extend(module.required_probes())
    }

    for probe in required_probes {
        match probe {
            ProbeRequirement::TcpSendMsg { dest_ports } => {
                tcp_sendmsg_ports.extend(dest_ports);
            }
            ProbeRequirement::TcpProbe => {
                let p = TcpProbe {};
                p.load(&mut ebpf).expect("Unable to load tcp probe");

                let pusher = metrics_pusher.clone();
                p.get_event_stream(&mut ebpf, move |event| {
                    if let ProbeEvent::TcpProbe(event) = event {
                        pusher.push_tcp_probe(event);
                    }
                })
            }
            ProbeRequirement::TcpRetransmitSkb { dest_ports } => {
                tcp_retransmit_skb_ports.extend(dest_ports);
            }
            _ => {}
        }
    }

    let final_tcp_sendmsg_probe = TCPSendMsgProbe::new(tcp_sendmsg_ports);

    final_tcp_sendmsg_probe.load(&mut ebpf);

    let final_tcp_retransmit_skb_probe = TcpRetransmitSkb::new(tcp_retransmit_skb_ports);
    final_tcp_retransmit_skb_probe.load(&mut ebpf);

    let pusher = metrics_pusher.clone();
    final_tcp_retransmit_skb_probe.get_event_stream(&mut ebpf, move |event| {
        if let ProbeEvent::TcpRetransmitSkb(event) = event {
            pusher.push_tcp_retransmit_skb(event);
        }
    });

    let ctrl_c = signal::ctrl_c();
    info!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    info!("Exiting...");

    Ok(())
}
