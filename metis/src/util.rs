use std::net::SocketAddr;
use std::sync::Arc;
use log::{debug, error};
use tokio::net::UdpSocket;
use crate::probes::tracepoints::tcp_probe::ReadableTCPProbeEvent;

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
            pid={}u,tgid={}u,src_port={}u,dest_port={}u,data_len={}u,\
            snd_cwnd={}u,ssthresh={}u,snd_wnd={}u,srtt_us={}u,rcv_wnd={}u",
            event.src_addr, event.dest_addr, event.family,
            event.pid, event.tgid, event.src_port, event.dest_port, event.data_len,
            event.snd_cwnd, event.ssthresh, event.snd_wnd, event.srtt_us, event.rcv_wnd
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
}