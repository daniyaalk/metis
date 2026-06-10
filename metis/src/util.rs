use crate::probes::tracepoints::tcp_probe::ReadableTCPProbeEvent;
use crate::probes::tracepoints::tcp_retransmit_skb::ReadableTCPRetransmitSkbEvent;
use log::{debug, error};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

pub struct TelegrafMetricsPusher {
    socket: Arc<UdpSocket>,
    telegraf_addr: SocketAddr,
}

impl TelegrafMetricsPusher {
    /// Creates a new UDP metrics pusher targeted at a local Telegraf daemon
    pub async fn new(telegraf_target: &str) -> anyhow::Result<Self> {
        // Bind to an ephemeral local port
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let telegraf_addr: SocketAddr = telegraf_target.parse()?;

        Ok(Self {
            socket: Arc::new(socket),
            telegraf_addr,
        })
    }

    /// Formats and pushes a TCP Probe event using InfluxDB line protocol over UDP
    pub fn push_tcp_probe(&self, event: &ReadableTCPProbeEvent) {
        // Format: measurement,tag_key=tag_val field_key=field_val
        // Note: Strings in tags must not have unescaped spaces.

        let event = event.clone();
        let socket = self.socket.clone();
        let addr = self.telegraf_addr;

        let line_protocol = format!(
            "bpf_tcp_probe,src_ip={},dest_ip={},family={} \
            pid={},tgid={},src_port={},dest_port={},data_len={}u,\
            snd_cwnd={}u,ssthresh={}u,snd_wnd={}u,srtt_us={}u,rcv_wnd={}u,value=1u",
            event.src_addr,
            event.dest_addr,
            event.family,
            event.pid,
            event.tgid,
            event.src_port,
            event.dest_port,
            event.data_len,
            event.snd_cwnd,
            event.ssthresh,
            event.snd_wnd,
            event.srtt_us,
            event.rcv_wnd
        );

        // Send non-blocking over UDP. If Telegraf is down or dropping packets,
        // your eBPF agent won't stall or back up.

        tokio::spawn(async move {
            if let Err(e) = socket.send_to(line_protocol.as_bytes(), addr).await {
                error!("Failed to ship telemetry packet to Telegraf: {}", e);
            } else {
                debug!("Telemetry metrics pushed successfully.");
            }
        });
    }

    pub fn push_tcp_retransmit_skb(&self, event: &ReadableTCPRetransmitSkbEvent) {
        let socket = self.socket.clone();
        let addr = self.telegraf_addr;

        let line_protocol = format!(
            "bpf_tcp_retransmit_skb,\
            src_ip={},dest_ip={},family={},state={} \
            pid={},src_port={},dest_port={},\
            err={},skbaddr={},skaddr={},value=1u",
            event.source_ip,
            event.destination_ip,
            event.family,
            event.state,
            event.pid,
            event.source_port,
            event.destination_port,
            event.err,
            event.skbaddr,
            event.skaddr,
        );

        tokio::spawn(async move {
            if let Err(e) = socket.send_to(line_protocol.as_bytes(), addr).await {
                error!("Failed to ship TCP retransmit telemetry packet: {}", e);
            } else {
                debug!("TCP retransmit telemetry pushed successfully.");
            }
        });
    }
}
