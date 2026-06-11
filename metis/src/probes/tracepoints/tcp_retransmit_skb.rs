use crate::probes::ProbeEvent;
use anyhow::Context;
use aya::maps::RingBuf;
use aya::programs::TracePoint;
use aya::Ebpf;
use metis_common::TCPProbeEvent;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::{mem, ptr};
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

pub struct TcpRetransmitSkb {
    ports: Vec<u16>,
}

impl TcpRetransmitSkb {
    pub fn new(ports: Vec<u16>) -> Self {
        Self { ports }
    }

    /// Inserts port filters, loads the `tcp_retransmit_skb` tracepoint, and
    /// spawns a task delivering parsed events to `on_event`.
    pub fn attach<F>(self, ebpf: &mut Ebpf, on_event: F) -> anyhow::Result<()>
    where
        F: Fn(ProbeEvent) + Send + 'static,
    {
        let mut map = aya::maps::HashMap::<_, u16, u8>::try_from(
            ebpf.map_mut("TCP_RETRANSMIT_SKB_PORTS")
                .context("TCP_RETRANSMIT_SKB_PORTS map not found")?,
        )?;
        for port in &self.ports {
            map.insert(*port, 1, 0)?;
        }

        let program: &mut TracePoint = ebpf
            .program_mut("tcp_retransmit_skb")
            .context("tcp_retransmit_skb program not found")?
            .try_into()?;
        program.load()?;
        program.attach("tcp", "tcp_retransmit_skb")?;

        let ringbuf = RingBuf::try_from(
            ebpf.take_map("TCP_RETRANSMIT_SKB_RINGBUF")
                .context("TCP_RETRANSMIT_SKB_RINGBUF map not found")?,
        )?;

        tokio::spawn(async move {
            let mut fd = AsyncFd::with_interest(ringbuf, Interest::READABLE).unwrap();
            loop {
                let mut guard = fd.readable_mut().await.unwrap();
                let buf = guard.get_inner_mut();
                while let Some(item) = buf.next() {
                    let raw: TCPProbeEvent =
                        unsafe { std::ptr::read_unaligned(item.as_ptr() as *const TCPProbeEvent) };
                    if let Some(inner) = RawTcpRetransmitSkb::from_bytes(&raw.ctx_buf) {
                        let event: ReadableTCPRetransmitSkbEvent = inner.into();
                        on_event(ProbeEvent::TcpRetransmitSkb(event));
                    }
                }
                guard.clear_ready();
            }
        });

        Ok(())
    }
}

// ── Parsed event ─────────────────────────────────────────────────────────────

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct RawTcpRetransmitSkb {
    common_type: u16,
    common_flags: u8,
    common_preempt_count: u8,
    common_pid: i32,
    skbaddr: u64,
    skaddr: u64,
    state: i32,
    sport: u16,
    dport: u16,
    family: u16,
    saddr: [u8; 4],
    daddr: [u8; 4],
    saddr_v6: [u8; 16],
    daddr_v6: [u8; 16],
    err: i32,
}

impl RawTcpRetransmitSkb {
    fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < mem::size_of::<Self>() {
            return None;
        }
        Some(unsafe { ptr::read_unaligned(buf.as_ptr() as *const Self) })
    }
}

#[derive(Debug, Clone)]
pub struct ReadableTCPRetransmitSkbEvent {
    pub pid: i32,
    pub skbaddr: u64,
    pub skaddr: u64,
    pub state: i32,
    pub err: i32,
    pub family: u16,
    pub source_ip: IpAddr,
    pub destination_ip: IpAddr,
    pub source_port: u16,
    pub destination_port: u16,
}

impl From<RawTcpRetransmitSkb> for ReadableTCPRetransmitSkbEvent {
    fn from(r: RawTcpRetransmitSkb) -> Self {
        let (source_ip, destination_ip) = match r.family {
            2 => (
                IpAddr::V4(Ipv4Addr::from(r.saddr)),
                IpAddr::V4(Ipv4Addr::from(r.daddr)),
            ),
            10 => (
                IpAddr::V6(Ipv6Addr::from(r.saddr_v6)),
                IpAddr::V6(Ipv6Addr::from(r.daddr_v6)),
            ),
            _ => (
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            ),
        };
        Self {
            pid: r.common_pid,
            skbaddr: r.skbaddr,
            skaddr: r.skaddr,
            state: r.state,
            err: r.err,
            family: r.family,
            source_ip,
            destination_ip,
            source_port: r.sport,
            destination_port: r.dport,
        }
    }
}
