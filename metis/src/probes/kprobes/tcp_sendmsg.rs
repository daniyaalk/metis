use crate::assembler::KProbeAssembler;
use crate::probes::ProbeEvent;
use anyhow::Context;
use aya::maps::RingBuf;
use aya::programs::KProbe;
use aya::Ebpf;
use metis_common::KProbeChunk;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

pub struct TcpSendMsgProbe {
    ports: Vec<u16>,
}

impl TcpSendMsgProbe {
    pub fn new(ports: Vec<u16>) -> Self {
        Self { ports }
    }

    /// Inserts port filters, attaches the `tcp_sendmsg` kprobe, and spawns
    /// a task that reassembles chunked payloads before calling `on_event`.
    pub fn attach<F>(self, ebpf: &mut Ebpf, on_event: F) -> anyhow::Result<()>
    where
        F: Fn(ProbeEvent) + Send + 'static,
    {
        let mut map = aya::maps::HashMap::<_, u16, u8>::try_from(
            ebpf.map_mut("TCP_SENDMSG_PORTS")
                .context("TCP_SENDMSG_PORTS map not found")?,
        )?;
        for port in &self.ports {
            map.insert(*port, 1, 0)?;
        }

        let program: &mut KProbe = ebpf
            .program_mut("tcp_sendmsg")
            .context("tcp_sendmsg program not found")?
            .try_into()?;
        program.load()?;
        program.attach("tcp_sendmsg", 0)?;

        let ringbuf = RingBuf::try_from(
            ebpf.take_map("TCP_SENDMSG_RINGBUF")
                .context("TCP_SENDMSG_RINGBUF map not found")?,
        )?;

        tokio::spawn(async move {
            let mut fd = AsyncFd::with_interest(ringbuf, Interest::READABLE).unwrap();
            let mut assembler = KProbeAssembler::new();
            loop {
                let mut guard = fd.readable_mut().await.unwrap();
                let buf = guard.get_inner_mut();
                while let Some(item) = buf.next() {
                    let chunk: KProbeChunk =
                        unsafe { std::ptr::read_unaligned(item.as_ptr() as *const KProbeChunk) };
                    if let Some(event) = assembler.ingest(&chunk) {
                        on_event(event);
                    }
                }
                guard.clear_ready();
            }
        });

        Ok(())
    }
}
