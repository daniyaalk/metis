pub mod assembler;
pub mod modules;
pub mod orchestrator;
pub mod probes;
pub mod router;
pub mod sink;

use crate::modules::Module;
use crate::modules::http::HttpModule;
use crate::modules::mysql::MysqlModule;
use crate::modules::tcp::TcpModule;
use crate::orchestrator::Orchestrator;
use crate::sink::telegraf::TelegrafMetricsPusher;
use log::{info, warn};
use std::sync::{Arc, Mutex};
use tokio::signal;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Needed on older kernels that use memlock accounting instead of memcg.
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/metis"
    )))?;

    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => warn!("eBPF logger init failed: {e}"),
        Ok(logger) => {
            let mut fd =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::spawn(async move {
                loop {
                    let mut guard = fd.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    let sink = Arc::new(TelegrafMetricsPusher::new("127.0.0.1:8125").await?);

    let modules: Vec<Arc<Mutex<dyn Module>>> = vec![
        Arc::new(Mutex::new(TcpModule::new(sink.clone()))),
        Arc::new(Mutex::new(MysqlModule)),
        // Arc::new(Mutex::new(HttpModule)),
    ];

    Orchestrator::new(modules).run(&mut ebpf).await?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
