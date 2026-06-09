use aya::programs::TracePoint;
#[rustfmt::skip]
use log::{debug, warn};
use log::info;
use tokio::signal;
use std::env;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();


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
    match aya_log::EbpfLogger::init(&mut ebpf)
    {
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


    // Attach all tracepoints
    let tp_names = vec![
        "tcp_bad_csum",
        "tcp_retransmit_skb",
        "tcp_retransmit_synack",
        "tcp_hash_md5_mismatch",
        "tcp_hash_md5_required",
        "tcp_hash_md5_unexpected",
        "tcp_receive_reset",
        "tcp_send_reset",
        "tcp_sendmsg_locked",
        "tcp_cong_state_set",
        "tcp_rcvbuf_grow",
        "tcp_probe",
    ];

    for name in tp_names {

        if let Some(program_optional) = ebpf.program_mut(name) {
            let program: &mut TracePoint = program_optional.try_into()?;
            program.load()?;
            program.attach("tcp", name)?;
        }
    }


    let ctrl_c = signal::ctrl_c();
    info!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    info!("Exiting...");

    Ok(())
}
