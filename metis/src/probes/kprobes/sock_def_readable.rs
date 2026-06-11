use crate::probes::ProbeEvent;
use anyhow::Context;
use aya::maps::RingBuf;
use aya::programs::KProbe;
use aya::Ebpf;
use metis_common::TcpResponseEvent;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

pub struct SockDefReadableProbe;

impl SockDefReadableProbe {
    pub fn attach<F>(self, ebpf: &mut Ebpf, on_event: F) -> anyhow::Result<()>
    where
        F: Fn(ProbeEvent) + Send + 'static,
    {
        let program: &mut KProbe = ebpf
            .program_mut("sock_def_readable")
            .context("sock_def_readable program not found")?
            .try_into()?;
        program.load()?;
        program.attach("sock_def_readable", 0)?;

        let ringbuf = RingBuf::try_from(
            ebpf.take_map("LATENCY_RINGBUF")
                .context("LATENCY_RINGBUF map not found")?,
        )?;

        tokio::spawn(async move {
            let mut fd = AsyncFd::with_interest(ringbuf, Interest::READABLE).unwrap();
            loop {
                let mut guard = fd.readable_mut().await.unwrap();
                let buf = guard.get_inner_mut();
                while let Some(item) = buf.next() {
                    let event: TcpResponseEvent = unsafe {
                        std::ptr::read_unaligned(item.as_ptr() as *const TcpResponseEvent)
                    };
                    on_event(ProbeEvent::SockDefReadable {
                        socket_ptr: event.socket_ptr,
                        timestamp_ns: event.timestamp_ns,
                    });
                }
                guard.clear_ready();
            }
        });

        Ok(())
    }
}
