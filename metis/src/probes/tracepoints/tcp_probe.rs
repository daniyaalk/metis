use crate::probes::ProbeEvent;
use anyhow::Context;
use aya::maps::RingBuf;
use aya::programs::TracePoint;
use aya::Ebpf;
use metis_common::TCPProbeEvent;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

pub struct TcpProbe;

impl TcpProbe {
    /// Loads the `tcp_probe` tracepoint and spawns a task that feeds parsed
    /// events into `on_event` for every TCP segment observed by the kernel.
    pub fn attach<F>(self, ebpf: &mut Ebpf, on_event: F) -> anyhow::Result<()>
    where
        F: Fn(ProbeEvent) + Send + 'static,
    {
        let program: &mut TracePoint = ebpf
            .program_mut("tcp_probe")
            .context("tcp_probe program not found")?
            .try_into()?;
        program.load()?;
        program.attach("tcp", "tcp_probe")?;

        let ringbuf =
            RingBuf::try_from(ebpf.take_map("TCP_PROBE_RINGBUF").context("TCP_PROBE_RINGBUF map not found")?)?;

        tokio::spawn(async move {
            let mut fd = AsyncFd::with_interest(ringbuf, Interest::READABLE).unwrap();
            loop {
                let mut guard = fd.readable_mut().await.unwrap();
                let buf = guard.get_inner_mut();
                while let Some(item) = buf.next() {
                    let raw: TCPProbeEvent =
                        unsafe { std::ptr::read_unaligned(item.as_ptr() as *const TCPProbeEvent) };
                    if let Some(event) = ReadableTCPProbeEvent::try_from_raw(&raw) {
                        on_event(ProbeEvent::TcpProbe(event));
                    }
                }
                guard.clear_ready();
            }
        });

        Ok(())
    }
}

// ── Parsed event ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ReadableTCPProbeEvent {
    pub pid: u32,
    pub tgid: u32,
    pub common_pid: i32,
    pub src_addr: IpAddr,
    pub dest_addr: IpAddr,
    pub src_port: u16,
    pub dest_port: u16,
    pub family: u16,
    pub mark: u32,
    pub data_len: u16,
    pub snd_nxt: u32,
    pub snd_una: u32,
    pub snd_cwnd: u32,
    pub ssthresh: u32,
    pub snd_wnd: u32,
    pub srtt_us: u32,
    pub rcv_wnd: u32,
    pub sock_cookie: u64,
    pub skbaddr: u64,
    pub skaddr: u64,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct RawTcpProbe {
    common_type: u16,
    common_flags: u8,
    common_preempt_count: u8,
    common_pid: i32,
    saddr: [u8; 28],
    daddr: [u8; 28],
    sport: u16,
    dport: u16,
    family: u16,
    _pad1: [u8; 2],
    mark: u32,
    data_len: u16,
    _pad2: [u8; 2],
    snd_nxt: u32,
    snd_una: u32,
    snd_cwnd: u32,
    ssthresh: u32,
    snd_wnd: u32,
    srtt: u32,
    rcv_wnd: u32,
    _pad3: [u8; 4],
    sock_cookie: u64,
    skbaddr: u64,
    skaddr: u64,
}

impl ReadableTCPProbeEvent {
    pub fn try_from_raw(event: &TCPProbeEvent) -> Option<Self> {
        if event.ctx_buf.len() < std::mem::size_of::<RawTcpProbe>() {
            return None;
        }
        let raw: RawTcpProbe =
            unsafe { std::ptr::read_unaligned(event.ctx_buf.as_ptr() as *const RawTcpProbe) };

        const AF_INET: u16 = 2;
        const AF_INET6: u16 = 10;

        let (src_addr, dest_addr) = match raw.family {
            AF_INET => (
                IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&raw.saddr[4..8]).unwrap())),
                IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&raw.daddr[4..8]).unwrap())),
            ),
            AF_INET6 => (
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&raw.saddr[8..24]).unwrap())),
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&raw.daddr[8..24]).unwrap())),
            ),
            _ => (
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            ),
        };

        Some(Self {
            pid: event.pid,
            tgid: event.tgid,
            common_pid: raw.common_pid,
            src_addr,
            dest_addr,
            src_port: raw.sport,
            dest_port: raw.dport,
            family: raw.family,
            mark: raw.mark,
            data_len: raw.data_len,
            snd_nxt: raw.snd_nxt,
            snd_una: raw.snd_una,
            snd_cwnd: raw.snd_cwnd,
            ssthresh: raw.ssthresh,
            snd_wnd: raw.snd_wnd,
            srtt_us: raw.srtt,
            rcv_wnd: raw.rcv_wnd,
            sock_cookie: raw.sock_cookie,
            skbaddr: raw.skbaddr,
            skaddr: raw.skaddr,
        })
    }
}
