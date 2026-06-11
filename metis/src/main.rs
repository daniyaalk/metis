pub mod assembler;
pub mod config;
pub mod modules;
pub mod orchestrator;
pub mod probes;
pub mod router;
pub mod sink;

use crate::config::Config;
use crate::modules::Module;
use crate::modules::http::HttpModule;
use crate::modules::mysql::MysqlModule;
use crate::modules::tcp::TcpModule;
use crate::orchestrator::Orchestrator;
use crate::sink::telegraf::TelegrafMetricsPusher;
use clap::Parser;
use log::{info, warn};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::signal;

#[derive(Parser)]
#[command(about = "eBPF TCP observability agent")]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(short, long, default_value = "metis.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let cli = Cli::parse();
    let cfg: Config = match std::fs::read_to_string(&cli.config) {
        Ok(s) => toml::from_str(&s)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            warn!("config file {:?} not found, using defaults", cli.config);
            Config::default()
        }
        Err(e) => return Err(e.into()),
    };
    info!("loaded config: {cfg:?}");

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

    let sink = Arc::new(TelegrafMetricsPusher::new(&cfg.telegraf.address).await?);

    let mut modules: Vec<Arc<Mutex<dyn Module>>> = Vec::new();
    if cfg.modules.tcp.enabled {
        modules.push(Arc::new(Mutex::new(TcpModule::new(sink.clone(), cfg.modules.tcp.ports))));
    }
    if cfg.modules.mysql.enabled {
        modules.push(Arc::new(Mutex::new(MysqlModule::new(sink.clone(), cfg.modules.mysql.ports))));
    }
    if cfg.modules.http.enabled {
        modules.push(Arc::new(Mutex::new(HttpModule::new(cfg.modules.http.ports))));
    }

    Orchestrator::new(modules, cfg.tcp_sendmsg_sample_rate.clamp(0.0, 100.0))
        .run(&mut ebpf)
        .await?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
