use crate::probes::ProbeEvent;
use anyhow::Context;
use aya::maps::RingBuf;
use aya::programs::TracePoint;
use aya::Ebpf;
use metis_common::TCPProbeEvent;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::mem;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

pub struct TcpReceiveReset {
    ports: Vec<u16>,
}

impl TcpReceiveReset {
    pub fn new(ports: Vec<u16>) -> Self {
        Self { ports }
    }

    /// Inserts port filters, loads the `tcp_receive_reset` tracepoint, and
    /// spawns a task delivering parsed events to `on_event`.
    pub fn attach<F>(self, ebpf: &mut Ebpf, on_event: F) -> anyhow::Result<()>
    where
        F: Fn(ProbeEvent) + Send + 'static,
    {
        let mut map = aya::maps::HashMap::<_, u16, u8>::try_from(
            ebpf.map_mut("TCP_RECEIVE_RESET_PORTS")
                .context("TCP_RECEIVE_RESET_PORTS map not found")?,
        )?;
        for port in &self.ports {
            map.insert(*port, 1, 0)?;
        }

        let program: &mut TracePoint = ebpf
            .program_mut("tcp_receive_reset")
            .context("tcp_receive_reset program not found")?
            .try_into()?;
        program.load()?;
        program.attach("tcp", "tcp_receive_reset")?;

        let ringbuf = RingBuf::try_from(
            ebpf.take_map("TCP_RECEIVE_RESET_RINGBUF")
                .context("TCP_RECEIVE_RESET_RINGBUF map not found")?,
        )?;

        tokio::spawn(async move {
            let mut fd = AsyncFd::with_interest(ringbuf, Interest::READABLE).unwrap();
            loop {
                let mut guard = fd.readable_mut().await.unwrap();
                let buf = guard.get_inner_mut();
                while let Some(item) = buf.next() {
                    let raw: TCPProbeEvent =
                        unsafe { std::ptr::read_unaligned(item.as_ptr() as *const TCPProbeEvent) };
                    if let Some(inner) = RawTcpReceiveReset::from_bytes(&raw.ctx_buf) {
                        let event: ReadableTcpReceiveResetEvent = inner.into();
                        on_event(ProbeEvent::TcpReceiveReset(event));
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
#[derive(Copy, Clone)]
struct RawTcpReceiveReset {
    common_type: u16,
    common_flags: u8,
    common_preempt_count: u8,
    common_pid: i32,
    skaddr: u64,
    sport: u16,
    dport: u16,
    family: u16,
    saddr_v4: [u8; 4],
    daddr_v4: [u8; 4],
    saddr_v6: [u8; 16],
    daddr_v6: [u8; 16],
    sock_cookie: u64,
}

impl RawTcpReceiveReset {
    fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < mem::size_of::<Self>() {
            return None;
        }
        Some(unsafe { std::ptr::read_unaligned(data.as_ptr() as *const Self) })
    }
}

#[derive(Debug, Clone)]
pub struct ReadableTcpReceiveResetEvent {
    pub pid: i32,
    pub skaddr: u64,
    pub sport: u16,
    pub dport: u16,
    pub family: u16,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub sock_cookie: u64,
}

impl From<RawTcpReceiveReset> for ReadableTcpReceiveResetEvent {
    fn from(r: RawTcpReceiveReset) -> Self {
        let src_ip = parse_ip(r.family, &r.saddr_v4, &r.saddr_v6);
        let dst_ip = parse_ip(r.family, &r.daddr_v4, &r.daddr_v6);
        Self {
            pid: r.common_pid,
            skaddr: r.skaddr,
            sport: r.sport,
            dport: r.dport,
            family: r.family,
            src_ip,
            dst_ip,
            sock_cookie: r.sock_cookie,
        }
    }
}

fn parse_ip(family: u16, v4: &[u8; 4], v6: &[u8; 16]) -> IpAddr {
    match family {
        2 => IpAddr::V4(Ipv4Addr::new(v4[0], v4[1], v4[2], v4[3])),
        10 => {
            let mut ip = [0u8; 16];
            ip.copy_from_slice(v6);
            IpAddr::V6(Ipv6Addr::from(ip))
        }
        _ => {
            if v6.iter().all(|&b| b == 0) {
                IpAddr::V4(Ipv4Addr::new(v4[0], v4[1], v4[2], v4[3]))
            } else {
                let mut ip = [0u8; 16];
                ip.copy_from_slice(v6);
                IpAddr::V6(Ipv6Addr::from(ip))
            }
        }
    }
}
