pub mod util;
pub mod modules;
pub mod probes;

use crate::modules::mysql::dependencies::MysqlModule;
use aya::programs::{KProbe, TracePoint};
#[rustfmt::skip]
use log::{debug, warn};
use aya::maps::RingBuf;
use log::info;
use metis_common::TCPEvent;
use std::env;
use std::sync::Arc;
use tokio::io::unix::AsyncFd;
use tokio::signal;
use crate::modules::http::HttpModule;
use crate::modules::Module;
use crate::probes::kprobes::tcp_sendmsg::TCPSendMsgProbe;
use crate::probes::{Probe, ProbeRequirement};
use crate::util::{ReadableTCPProbeEvent, TelegrafMetricsPusher};

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
        Box::new(MysqlModule), Box::new(HttpModule)
    ];


    let mut required_probes: Vec<ProbeRequirement> = vec![];
    let mut tcp_sendmsg_ports: Vec<u16> = Vec::new();

    for module in &enabled_modules {
        required_probes.extend(module.required_probes())
    }

    for probe in required_probes {
        match probe {
            ProbeRequirement::TcpSendMsg {dest_ports} => {
                tcp_sendmsg_ports.extend(dest_ports);
            },
            _ => {}

        }
    }



    let final_tcp_sendmsg_probe = TCPSendMsgProbe::new(tcp_sendmsg_ports);

    final_tcp_sendmsg_probe.load(&mut ebpf);


    // match ebpf.program_mut("tcp_sendmsg") {
    //     Some(program) => {
    //         let program: & mut KProbe = program.try_into()?;
    //         program.load()?;
    //         program.attach("tcp_sendmsg", 0)?;
    //     }
    //     _ => {}
    // }
    //
    // // Attach all tracepoints
    // let tp_names = vec![
    //     "tcp_retransmit_skb",
    //     "tcp_retransmit_synack",
    //     "tcp_receive_reset",
    //     "tcp_send_reset",
    //     "tcp_probe",
    // ];
    //
    // for name in tp_names {
    //     match ebpf.program_mut(name) {
    //         Some(program_optional) => {
    //             let program: &mut TracePoint = program_optional.try_into()?;
    //             program.load()?;
    //             program.attach("tcp", name)?;
    //         }
    //         None => {
    //             warn!("program not found: {name}");
    //         }
    //     }
    // }
    //
    // tokio::spawn(async move {
    //     let ringbuf = RingBuf::try_from(ebpf.map_mut("EVENTS").unwrap()).unwrap();
    //     let mut events = AsyncFd::with_interest(ringbuf, Interest::READABLE).unwrap();
    //
    //     loop {
    //         let mut guard = events.readable_mut().await.unwrap();
    //         let ring_buf = guard.get_inner_mut();
    //
    //         while let Some(item) = ring_buf.next() {
    //
    //             let raw_event: TCPEvent =
    //             unsafe { std::ptr::read_unaligned(item.as_ptr() as *const TCPEvent) };
    //
    //             let event = ReadableTCPProbeEvent::try_from_raw_ctx(&raw_event).unwrap();
    //             println!("Received: {:?}", &event);
    //
    //             let pusher = metrics_pusher.clone();
    //             tokio::spawn(async move {
    //                 pusher.push_tcp_probe(&event).await;
    //             });
    //         }
    //
    //         guard.clear_ready();
    //     }
    // });

    let ctrl_c = signal::ctrl_c();
    info!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    info!("Exiting...");

    Ok(())
}
