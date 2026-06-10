use crate::probes::{Probe, ProbeEvent};
use aya::Ebpf;
use aya::maps::RingBuf;
use aya::programs::TracePoint;
use log::{debug, error};
use metis_common::TCPProbeEvent;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::net::UdpSocket;

pub struct TcpProbe {}

impl Probe for TcpProbe {
    fn load(&self, ebpf: &mut Ebpf) -> Result<(), ()> {
        let program = ebpf.program_mut("tcp_probe").unwrap();
        let program: &mut TracePoint = program.try_into().unwrap();
        program.load();
        program.attach("tcp", "tcp_probe");

        Ok(())
    }

    fn get_event_stream<F>(&self, ebpf: &mut Ebpf, callback: F)
    where
        F: Fn(&ProbeEvent) + Send + Sync + 'static,
    {
        let ringbuf = RingBuf::try_from(ebpf.take_map("TCP_PROBE_RINGBUF").unwrap()).unwrap();
        tokio::spawn(async move {
            let mut events = AsyncFd::with_interest(ringbuf, Interest::READABLE).unwrap();

            loop {
                let mut guard = events.readable_mut().await.unwrap();
                let ring_buf = guard.get_inner_mut();

                while let Some(item) = ring_buf.next() {
                    let raw_event: TCPProbeEvent =
                        unsafe { std::ptr::read_unaligned(item.as_ptr() as *const TCPProbeEvent) };

                    let event = ReadableTCPProbeEvent::try_from_raw_ctx(&raw_event).unwrap();
                    callback(&ProbeEvent::TcpProbe(event));
                }

                guard.clear_ready();
            }
        });
    }
}

// Clean, application-facing readable format
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

// Hidden internal structural representation matching the tracepoint byte format
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct RawTcpProbe {
    common_type: u16,         // offset: 0, size: 2
    common_flags: u8,         // offset: 2, size: 1
    common_preempt_count: u8, // offset: 3, size: 1
    common_pid: i32,          // offset: 4, size: 4
    saddr: [u8; 28],          // offset: 8, size: 28
    daddr: [u8; 28],          // offset: 36, size: 28
    sport: u16,               // offset: 64, size: 2
    dport: u16,               // offset: 66, size: 2
    family: u16,              // offset: 68, size: 2
    _pad1: [u8; 2],           // padding to offset 72
    mark: u32,                // offset: 72, size: 4
    data_len: u16,            // offset: 76, size: 2
    _pad2: [u8; 2],           // padding to offset 80
    snd_nxt: u32,             // offset: 80, size: 4
    snd_una: u32,             // offset: 84, size: 4
    snd_cwnd: u32,            // offset: 88, size: 4
    ssthresh: u32,            // offset: 92, size: 4
    snd_wnd: u32,             // offset: 96, size: 4
    srtt: u32,                // offset: 100, size: 4
    rcv_wnd: u32,             // offset: 104, size: 4
    _pad3: [u8; 4],           // padding to offset 112
    sock_cookie: u64,         // offset: 112, size: 8
    skbaddr: u64,             // offset: 120, size: 8
    skaddr: u64,              // offset: 128, size: 8
}

impl ReadableTCPProbeEvent {
    /// Attempts to parse raw tracepoint data context directly into a clean `ReadableTCPProbeEvent`
    pub fn try_from_raw_ctx(event: &TCPProbeEvent) -> Option<Self> {
        // Enforce safe buffer boundaries
        if event.ctx_buf.len() < std::mem::size_of::<RawTcpProbe>() {
            return None;
        }

        // Safely extract the raw trace structure using unaligned parsing rules
        let raw: RawTcpProbe =
            unsafe { std::ptr::read_unaligned(event.ctx_buf.as_ptr() as *const RawTcpProbe) };

        const AF_INET: u16 = 2;
        const AF_INET6: u16 = 10;

        let (src_addr, dest_addr) = match raw.family {
            AF_INET => {
                let src_bytes: [u8; 4] = raw.saddr[4..8].try_into().unwrap();
                let dest_bytes: [u8; 4] = raw.daddr[4..8].try_into().unwrap();
                (
                    IpAddr::V4(Ipv4Addr::from(src_bytes)),
                    IpAddr::V4(Ipv4Addr::from(dest_bytes)),
                )
            }
            AF_INET6 => {
                let src_bytes: [u8; 16] = raw.saddr[8..24].try_into().unwrap();
                let dest_bytes: [u8; 16] = raw.daddr[8..24].try_into().unwrap();
                (
                    IpAddr::V6(Ipv6Addr::from(src_bytes)),
                    IpAddr::V6(Ipv6Addr::from(dest_bytes)),
                )
            }
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
            // Convert networking network-byte-order integers back to host CPU endianness
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
