use crate::probes::{Probe, ProbeEvent};
use aya::Ebpf;
use aya::maps::RingBuf;
use aya::programs::TracePoint;
use log::debug;
use metis_common::TCPProbeEvent;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::{mem, ptr};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

pub struct TcpSendReset {}

impl Probe for TcpSendReset {
    fn load(&self, ebpf: &mut Ebpf) -> Result<(), ()> {
        let program = ebpf.program_mut("tcp_send_reset").unwrap();
        let program: &mut TracePoint = program.try_into().unwrap();
        program.load().or(Err(()))?;
        program.attach("tcp", "tcp_send_reset");

        Ok(())
    }

    fn get_event_stream<F>(&self, ebpf: &mut Ebpf, callback: F)
    where
        F: Fn(&ProbeEvent) + Send + Sync + 'static,
    {
        let ringbuf = RingBuf::try_from(ebpf.take_map("TCP_SEND_RESET_RINGBUF").unwrap()).unwrap();
        tokio::spawn(async move {
            let mut events = AsyncFd::with_interest(ringbuf, Interest::READABLE).unwrap();

            loop {
                let mut guard = events.readable_mut().await.unwrap();
                let ring_buf = guard.get_inner_mut();

                while let Some(item) = ring_buf.next() {
                    let raw_event: TCPProbeEvent =
                        unsafe { std::ptr::read_unaligned(item.as_ptr() as *const TCPProbeEvent) };

                    let event = TcpSendResetEvent::from_bytes(&raw_event.ctx_buf).unwrap();
                    let event: ReadableTcpSendResetEvent = event.into();
                    debug!("event: {:?}", event);
                    callback(&ProbeEvent::TcpSendReset(event));
                }

                guard.clear_ready();
            }
        });
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct TcpSendResetEvent {
    // common trace fields
    pub common_type: u16,
    pub common_flags: u8,
    pub common_preempt_count: u8,
    pub common_pid: i32,

    // pointers from kernel (never dereference in userspace)
    pub skbaddr: u64,
    pub skaddr: u64,

    pub state: i32,
    pub reason: i32, // enum sk_rst_reason

    // network addresses (fixed 28-byte buffers)
    pub saddr: [u8; 28],
    pub daddr: [u8; 28],
}

impl TcpSendResetEvent {
    /// Safe conversion from raw byte slice (e.g. ringbuf)
    pub fn from_bytes(data: &[u8]) -> Option<&Self> {
        if data.len() < mem::size_of::<Self>() {
            return None;
        }

        let ptr = data.as_ptr() as *const Self;
        unsafe { Some(&*ptr) }
    }
}

#[derive(Debug, Clone)]
pub struct ReadableTcpSendResetEvent {
    pub pid: i32,

    pub state: String,
    pub reason: String,

    pub skbaddr: u64,
    pub skaddr: u64,

    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,

    pub src_port: u16,
    pub dst_port: u16,
}

impl From<&TcpSendResetEvent> for ReadableTcpSendResetEvent {
    fn from(raw: &TcpSendResetEvent) -> Self {
        Self {
            pid: raw.common_pid,

            state: decode_tcp_state(raw.state).to_string(),
            reason: decode_tcp_send_reset_reason(raw.reason).to_string(),

            skbaddr: raw.skbaddr,
            skaddr: raw.skaddr,

            src_ip: parse_ip(&raw.saddr),
            dst_ip: parse_ip(&raw.daddr),

            src_port: parse_port(&raw.saddr),
            dst_port: parse_port(&raw.daddr),
        }
    }
}


fn parse_ip(buf: &[u8; 28]) -> IpAddr {
    let family = u16::from_le_bytes([buf[0], buf[1]]);

    match family {
        2 => {
            // AF_INET: address at bytes 4..8
            let addr = &buf[4..8];
            IpAddr::V4(Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]))
        }
        10 => {
            // AF_INET6: address at bytes 8..24
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&buf[8..24]);

            // Unwrap IPv4-mapped addresses (::ffff:x.x.x.x)
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
        1 => "TCP_ESTABLISHED",
        2 => "TCP_SYN_SENT",
        3 => "TCP_SYN_RECV",
        4 => "TCP_FIN_WAIT1",
        5 => "TCP_FIN_WAIT2",
        6 => "TCP_TIME_WAIT",
        7 => "TCP_CLOSE",
        8 => "TCP_CLOSE_WAIT",
        9 => "TCP_LAST_ACK",
        10 => "TCP_LISTEN",
        11 => "TCP_CLOSING",
        12 => "TCP_NEW_SYN_RECV",
        _ => "UNKNOWN",
    }
}

fn decode_tcp_send_reset_reason(reason: i32) -> &'static str {
    match reason {
        0 => "NOT_SPECIFIED",
        1 => "NO_SOCKET",
        2 => "TCP_INVALID_ACK_SEQUENCE",
        3 => "TCP_RFC7323_PAWS",
        4 => "TCP_TOO_OLD_ACK",
        5 => "TCP_ACK_UNSENT_DATA",
        6 => "TCP_FLAGS",
        7 => "TCP_OLD_ACK",
        8 => "TCP_ABORT_ON_DATA",
        9 => "TCP_TIMEWAIT_SOCKET",
        10 => "INVALID_SYN",
        11 => "TCP_ABORT_ON_CLOSE",
        12 => "TCP_ABORT_ON_LINGER",
        13 => "TCP_ABORT_ON_MEMORY",
        14 => "TCP_STATE",
        15 => "TCP_KEEPALIVE_TIMEOUT",
        16 => "TCP_DISCONNECT_WITH_DATA",
        17 => "MPTCP_RST_EUNSPEC",
        18 => "MPTCP_RST_EMPTCP",
        19 => "MPTCP_RST_ERESOURCE",
        20 => "MPTCP_RST_EPROHIBIT",
        21 => "MPTCP_RST_EWQ2BIG",
        22 => "MPTCP_RST_EBADPERF",
        23 => "MPTCP_RST_EMIDDLEBOX",
        24 => "ERROR",
        25 => "MAX",
        _ => "UNKNOWN",
    }
}
