use crate::probes::{Probe, ProbeEvent};
use aya::Ebpf;
use aya::maps::RingBuf;
use aya::programs::TracePoint;
use log::{debug};
use metis_common::TCPProbeEvent;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::{mem, ptr};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

pub struct TcpRetransmitSkb {
    dest_port: Vec<u16>,
}

impl TcpRetransmitSkb {
    pub fn new(dest_port: Vec<u16>) -> Self {
        Self { dest_port }
    }
}

impl Probe for TcpRetransmitSkb {
    fn load(&self, ebpf: &mut Ebpf) -> Result<(), ()> {
        let mut map = aya::maps::HashMap::<_, u16, u8>::try_from(
            ebpf.map_mut("TCP_RETRANSMIT_SKB_PORTS").unwrap(),
        )
        .or(Err(()))?;

        for port in &self.dest_port {
            map.insert(*port, 1, 0).or(Err(()))?;
        }

        let program = ebpf.program_mut("tcp_retransmit_skb").unwrap();
        let program: &mut TracePoint = program.try_into().unwrap();
        program.load().or(Err(()))?;
        program.attach("tcp", "tcp_retransmit_skb");

        Ok(())
    }

    fn get_event_stream<F>(&self, ebpf: &mut Ebpf, callback: F)
    where
        F: Fn(&ProbeEvent) + Send + Sync + 'static,
    {
        let ringbuf =
            RingBuf::try_from(ebpf.take_map("TCP_RETRANSMIT_SKB_RINGBUF").unwrap()).unwrap();
        tokio::spawn(async move {
            let mut events = AsyncFd::with_interest(ringbuf, Interest::READABLE).unwrap();

            loop {
                let mut guard = events.readable_mut().await.unwrap();
                let ring_buf = guard.get_inner_mut();

                while let Some(item) = ring_buf.next() {
                    let raw_event: TCPProbeEvent =
                        unsafe { std::ptr::read_unaligned(item.as_ptr() as *const TCPProbeEvent) };

                    let event = TCPRetransmitSkbEvent::from_bytes(&raw_event.ctx_buf).unwrap();
                    let event: ReadableTCPRetransmitSkbEvent = event.into();
                    debug!("event: {:?}", event);
                    callback(&ProbeEvent::TcpRetransmitSkb(event));
                }

                guard.clear_ready();
            }
        });
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct TCPRetransmitSkbEvent {
    pub common_type: u16,
    pub common_flags: u8,
    pub common_preempt_count: u8,
    pub common_pid: i32,

    pub skbaddr: u64,
    pub skaddr: u64,

    pub state: i32,

    pub sport: u16,
    pub dport: u16,
    pub family: u16,

    pub saddr: [u8; 4],
    pub daddr: [u8; 4],

    pub saddr_v6: [u8; 16],
    pub daddr_v6: [u8; 16],

    pub err: i32,
}

impl TCPRetransmitSkbEvent {
    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < mem::size_of::<Self>() {
            return None;
        }

        Some(unsafe { ptr::read_unaligned(buf.as_ptr() as *const TCPRetransmitSkbEvent) })
    }
}

#[derive(Debug)]
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

impl From<TCPRetransmitSkbEvent> for ReadableTCPRetransmitSkbEvent {
    fn from(event: TCPRetransmitSkbEvent) -> Self {
        let (source_ip, destination_ip) = match event.family {
            2 => (
                IpAddr::V4(Ipv4Addr::from(event.saddr)),
                IpAddr::V4(Ipv4Addr::from(event.daddr)),
            ),

            10 => (
                IpAddr::V6(Ipv6Addr::from(event.saddr_v6)),
                IpAddr::V6(Ipv6Addr::from(event.daddr_v6)),
            ),

            _ => (
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            ),
        };

        Self {
            pid: event.common_pid,

            skbaddr: event.skbaddr,
            skaddr: event.skaddr,

            state: event.state,
            err: event.err,

            family: event.family,

            source_ip,
            destination_ip,

            source_port: event.sport,
            destination_port: event.dport,
        }
    }
}
