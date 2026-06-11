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

pub struct TcpSendReset;

impl TcpSendReset {
    /// Loads the `tcp_send_reset` tracepoint and spawns a task delivering
    /// parsed events to `on_event`.
    pub fn attach<F>(self, ebpf: &mut Ebpf, on_event: F) -> anyhow::Result<()>
    where
        F: Fn(ProbeEvent) + Send + 'static,
    {
        let program: &mut TracePoint = ebpf
            .program_mut("tcp_send_reset")
            .context("tcp_send_reset program not found")?
            .try_into()?;
        program.load()?;
        program.attach("tcp", "tcp_send_reset")?;

        let ringbuf = RingBuf::try_from(
            ebpf.take_map("TCP_SEND_RESET_RINGBUF")
                .context("TCP_SEND_RESET_RINGBUF map not found")?,
        )?;

        tokio::spawn(async move {
            let mut fd = AsyncFd::with_interest(ringbuf, Interest::READABLE).unwrap();
            loop {
                let mut guard = fd.readable_mut().await.unwrap();
                let buf = guard.get_inner_mut();
                while let Some(item) = buf.next() {
                    let raw: TCPProbeEvent =
                        unsafe { std::ptr::read_unaligned(item.as_ptr() as *const TCPProbeEvent) };
                    if let Some(inner) = RawTcpSendReset::from_bytes(&raw.ctx_buf) {
                        let event: ReadableTcpSendResetEvent = inner.into();
                        on_event(ProbeEvent::TcpSendReset(event));
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
struct RawTcpSendReset {
    common_type: u16,
    common_flags: u8,
    common_preempt_count: u8,
    common_pid: i32,
    skbaddr: u64,
    skaddr: u64,
    state: i32,
    reason: i32,
    saddr: [u8; 28],
    daddr: [u8; 28],
}

impl RawTcpSendReset {
    fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < mem::size_of::<Self>() {
            return None;
        }
        Some(unsafe { std::ptr::read_unaligned(data.as_ptr() as *const Self) })
    }
}

#[derive(Debug, Clone)]
pub struct ReadableTcpSendResetEvent {
    pub pid: i32,
    pub state: &'static str,
    pub reason: &'static str,
    pub skbaddr: u64,
    pub skaddr: u64,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
}

impl From<RawTcpSendReset> for ReadableTcpSendResetEvent {
    fn from(r: RawTcpSendReset) -> Self {
        Self {
            pid: r.common_pid,
            state: decode_tcp_state(r.state),
            reason: decode_reset_reason(r.reason),
            skbaddr: r.skbaddr,
            skaddr: r.skaddr,
            src_ip: parse_ip(&r.saddr),
            dst_ip: parse_ip(&r.daddr),
            src_port: parse_port(&r.saddr),
            dst_port: parse_port(&r.daddr),
        }
    }
}

fn parse_ip(buf: &[u8; 28]) -> IpAddr {
    let family = u16::from_le_bytes([buf[0], buf[1]]);
    match family {
        2 => IpAddr::V4(Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7])),
        10 => {
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&buf[8..24]);
            if addr[..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff] {
                IpAddr::V4(Ipv4Addr::new(addr[12], addr[13], addr[14], addr[15]))
            } else {
                IpAddr::V6(Ipv6Addr::from(addr))
            }
        }
        _ => IpAddr::V4(Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3])),
    }
}

fn parse_port(buf: &[u8; 28]) -> u16 {
    u16::from_be_bytes([buf[2], buf[3]])
}

fn decode_tcp_state(state: i32) -> &'static str {
    match state {
        1 => "ESTABLISHED",
        2 => "SYN_SENT",
        3 => "SYN_RECV",
        4 => "FIN_WAIT1",
        5 => "FIN_WAIT2",
        6 => "TIME_WAIT",
        7 => "CLOSE",
        8 => "CLOSE_WAIT",
        9 => "LAST_ACK",
        10 => "LISTEN",
        11 => "CLOSING",
        12 => "NEW_SYN_RECV",
        _ => "UNKNOWN",
    }
}

fn decode_reset_reason(reason: i32) -> &'static str {
    match reason {
        0 => "NOT_SPECIFIED",
        1 => "NO_SOCKET",
        2 => "INVALID_ACK_SEQUENCE",
        3 => "RFC7323_PAWS",
        4 => "TOO_OLD_ACK",
        5 => "ACK_UNSENT_DATA",
        6 => "FLAGS",
        7 => "OLD_ACK",
        8 => "ABORT_ON_DATA",
        9 => "TIMEWAIT_SOCKET",
        10 => "INVALID_SYN",
        11 => "ABORT_ON_CLOSE",
        12 => "ABORT_ON_LINGER",
        13 => "ABORT_ON_MEMORY",
        14 => "STATE",
        15 => "KEEPALIVE_TIMEOUT",
        16 => "DISCONNECT_WITH_DATA",
        _ => "UNKNOWN",
    }
}
