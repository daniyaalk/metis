use crate::assembler::KProbeAssembler;
use crate::probes::kprobes::btf_layout::detect_iov_layout;
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
    /// Sampling rate as a percentage (0.0–100.0). Supports fractional values like 0.01.
    sample_rate: f32,
}

impl TcpSendMsgProbe {
    pub fn new(ports: Vec<u16>, sample_rate: f32) -> Self {
        Self { ports, sample_rate }
    }

    /// Inserts port filters and sample rate, attaches the `tcp_sendmsg` kprobe,
    /// and spawns a task that reassembles chunked payloads before calling `on_event`.
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

        // Scale percentage to [0, u32::MAX] threshold. BPF passes when random <= threshold.
        let rate_fraction = (self.sample_rate as f64 / 100.0).clamp(0.0, 1.0);
        let threshold = if rate_fraction >= 1.0 {
            u32::MAX
        } else {
            (rate_fraction * u32::MAX as f64) as u32
        };
        let mut rate_map = aya::maps::Array::<_, u32>::try_from(
            ebpf.map_mut("TCP_SENDMSG_SAMPLE_RATE")
                .context("TCP_SENDMSG_SAMPLE_RATE map not found")?,
        )?;
        rate_map.set(0, threshold, 0)?;

        let layout = detect_iov_layout();
        let mut layout_map = aya::maps::Array::<_, metis_common::IovLayout>::try_from(
            ebpf.map_mut("IOV_LAYOUT").context("IOV_LAYOUT map not found")?,
        )?;
        layout_map.set(0, layout, 0)?;

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
