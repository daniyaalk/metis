use crate::probes::kprobes::btf_layout::detect_udp_layout;
use crate::probes::ProbeEvent;
use anyhow::Context;
use aya::maps::RingBuf;
use aya::programs::KProbe;
use aya::Ebpf;
use metis_common::UdpPacketEvent;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

pub struct UdpRecvMsgProbe {
    /// Source ports to capture; empty = use wildcard (key 0 in the BPF map).
    src_ports: Vec<u16>,
}

impl UdpRecvMsgProbe {
    pub fn new(src_ports: Vec<u16>) -> Self {
        Self { src_ports }
    }

    /// Populates the port filter and UDP layout maps, attaches kprobes on both
    /// `udp_recvmsg` (IPv4) and `udpv6_recvmsg` (IPv6 / dual-stack), and
    /// spawns a single ring-buffer reader that calls `on_event` for each packet.
    pub fn attach<F>(self, ebpf: &mut Ebpf, on_event: F) -> anyhow::Result<()>
    where
        F: Fn(ProbeEvent) + Send + 'static,
    {
        let mut port_map = aya::maps::HashMap::<_, u16, u8>::try_from(
            ebpf.map_mut("UDP_RECVMSG_PORTS")
                .context("UDP_RECVMSG_PORTS map not found")?,
        )?;
        for port in &self.src_ports {
            port_map.insert(*port, 1u8, 0)?;
        }

        let udp_layout = detect_udp_layout();
        log::info!(
            "[udp_recvmsg] layout: sk_receive_queue_off={} skb_data_off={}",
            udp_layout.sk_receive_queue_off,
            udp_layout.skb_data_off,
        );
        let mut layout_map = aya::maps::Array::<_, metis_common::UdpLayout>::try_from(
            ebpf.map_mut("UDP_LAYOUT").context("UDP_LAYOUT map not found")?,
        )?;
        layout_map.set(0, udp_layout, 0)?;

        let v4: &mut KProbe = ebpf
            .program_mut("udp_recvmsg")
            .context("udp_recvmsg program not found")?
            .try_into()?;
        v4.load()?;
        v4.attach("udp_recvmsg", 0)?;

        let v6: &mut KProbe = ebpf
            .program_mut("udpv6_recvmsg")
            .context("udpv6_recvmsg program not found")?
            .try_into()?;
        v6.load()?;
        v6.attach("udpv6_recvmsg", 0)?;

        let ringbuf = RingBuf::try_from(
            ebpf.take_map("UDP_RECVMSG_RINGBUF")
                .context("UDP_RECVMSG_RINGBUF map not found")?,
        )?;

        tokio::spawn(async move {
            let mut fd = AsyncFd::with_interest(ringbuf, Interest::READABLE).unwrap();
            loop {
                let mut guard = fd.readable_mut().await.unwrap();
                let buf = guard.get_inner_mut();
                while let Some(item) = buf.next() {
                    let raw: UdpPacketEvent = unsafe {
                        std::ptr::read_unaligned(item.as_ptr() as *const UdpPacketEvent)
                    };
                    let len = raw.len as usize;
                    if len == 0 || len > raw.data.len() {
                        log::warn!(
                            "[udp_recvmsg] dropped event: invalid len={} src_port={}",
                            len, raw.src_port
                        );
                        continue;
                    }
                    let src_ip = match raw.ip_family {
                        4 => IpAddr::V4(Ipv4Addr::new(
                            raw.src_ip[0], raw.src_ip[1], raw.src_ip[2], raw.src_ip[3],
                        )),
                        _ => {
                            let v6 = Ipv6Addr::from(raw.src_ip);
                            match v6.to_ipv4_mapped() {
                                Some(v4) => IpAddr::V4(v4),
                                None => IpAddr::V6(v6),
                            }
                        }
                    };
                    log::debug!(
                        "[udp_recvmsg] ring-buf event: src_port={} src_ip={} payload_len={}",
                        raw.src_port, src_ip, len
                    );
                    let payload = raw.data[..len].to_vec();
                    on_event(ProbeEvent::UdpRecvMsg {
                        src_port: raw.src_port,
                        src_ip,
                        payload,
                    });
                }
                guard.clear_ready();
            }
        });

        Ok(())
    }
}
