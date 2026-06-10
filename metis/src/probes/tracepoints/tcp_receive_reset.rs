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

pub struct TcpReceiveReset {
    dest_port: Vec<u16>,
}

impl TcpReceiveReset {
    pub fn new(dest_port: Vec<u16>) -> Self {
        Self { dest_port }
    }
}

impl Probe for TcpReceiveReset {
    fn load(&self, ebpf: &mut Ebpf) -> Result<(), ()> {
        let mut map = aya::maps::HashMap::<_, u16, u8>::try_from(
            ebpf.map_mut("TCP_RECEIVE_RESET_PORTS").unwrap(),
        )
        .or(Err(()))?;

        for port in &self.dest_port {
            map.insert(*port, 1, 0).or(Err(()))?;
        }

        let program = ebpf.program_mut("tcp_receive_reset").unwrap();
        let program: &mut TracePoint = program.try_into().unwrap();
        program.load().or(Err(()))?;
        program.attach("tcp", "tcp_receive_reset");

        Ok(())
    }

    fn get_event_stream<F>(&self, ebpf: &mut Ebpf, callback: F)
    where
        F: Fn(&ProbeEvent) + Send + Sync + 'static,
    {
        let ringbuf =
            RingBuf::try_from(ebpf.take_map("TCP_RECEIVE_RESET_RINGBUF").unwrap()).unwrap();
        tokio::spawn(async move {
            let mut events = AsyncFd::with_interest(ringbuf, Interest::READABLE).unwrap();

            loop {
                let mut guard = events.readable_mut().await.unwrap();
                let ring_buf = guard.get_inner_mut();

                while let Some(item) = ring_buf.next() {
                    let raw_event: TCPProbeEvent =
                        unsafe { std::ptr::read_unaligned(item.as_ptr() as *const TCPProbeEvent) };

                    let event = TcpReceiveResetEvent::from_bytes(&raw_event.ctx_buf).unwrap();
                    let event: ReadableTcpReceiveResetEvent = event.into();
                    debug!("event: {:?}", event);
                    callback(&ProbeEvent::TcpReceiveReset(event));
                }

                guard.clear_ready();
            }
        });
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct TcpReceiveResetEvent {
    pub common_type: u16,
    pub common_flags: u8,
    pub common_preempt_count: u8,
    pub common_pid: i32,

    pub skaddr: u64,

    pub sport: u16,
    pub dport: u16,
    pub family: u16,

    pub saddr_v4: [u8; 4],
    pub daddr_v4: [u8; 4],

    pub saddr_v6: [u8; 16],
    pub daddr_v6: [u8; 16],

    pub sock_cookie: u64,
}

impl TcpReceiveResetEvent {
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

impl From<&TcpReceiveResetEvent> for ReadableTcpReceiveResetEvent {
    fn from(raw: &TcpReceiveResetEvent) -> Self {
        let src_ip = parse_ip(raw.family, &raw.saddr_v4, &raw.saddr_v6);
        let dst_ip = parse_ip(raw.family, &raw.daddr_v4, &raw.daddr_v6);

        Self {
            pid: raw.common_pid,
            skaddr: raw.skaddr,
            sport: raw.sport,
            dport: raw.dport,
            family: raw.family,
            src_ip,
            dst_ip,
            sock_cookie: raw.sock_cookie,
        }
    }
}

fn parse_ip(family: u16, v4: &[u8; 4], v6: &[u8; 16]) -> IpAddr {
    match family as i32 {
        2 => {
            // AF_INET
            IpAddr::V4(Ipv4Addr::new(v4[0], v4[1], v4[2], v4[3]))
        }
        10 => {
            // AF_INET6
            let mut ip = [0u8; 16];
            ip.copy_from_slice(v6);
            IpAddr::V6(Ipv6Addr::from(ip))
        }
        _ => {
            // fallback heuristic (rare)
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
