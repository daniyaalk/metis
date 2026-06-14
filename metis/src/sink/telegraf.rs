use crate::probes::tracepoints::tcp_probe::ReadableTCPProbeEvent;

/// Escapes a string for use as an InfluxDB line-protocol tag value.
fn escape_tag(s: &str) -> String {
    s.replace(',', "\\,")
        .replace('=', "\\=")
        .replace(' ', "\\ ")
}

fn domain_tag(domain: Option<&str>) -> String {
    match domain {
        Some(d) if !d.is_empty() => format!(",domain={}", escape_tag(d)),
        _ => String::new(),
    }
}

use crate::probes::tracepoints::tcp_receive_reset::ReadableTcpReceiveResetEvent;
use crate::probes::tracepoints::tcp_retransmit_skb::ReadableTCPRetransmitSkbEvent;
use crate::probes::tracepoints::tcp_send_reset::ReadableTcpSendResetEvent;
use log::error;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

/// Pushes metrics to a local Telegraf agent using InfluxDB line protocol over UDP.
///
/// All sends are fire-and-forget: a slow or unavailable Telegraf won't stall
/// the eBPF event loops.
pub struct TelegrafMetricsPusher {
    socket: Arc<UdpSocket>,
    addr: SocketAddr,
}

impl TelegrafMetricsPusher {
    pub async fn new(target: &str) -> anyhow::Result<Self> {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        Ok(Self {
            socket: Arc::new(socket),
            addr: target.parse()?,
        })
    }

    pub fn push_tcp_probe(&self, e: &ReadableTCPProbeEvent, domain: Option<&str>) {
        let line = format!(
            "bpf_tcp_probe,src_ip={},dest_ip={}{},family={},\
             pid={},tgid={},src_port={},dest_port={} \
             data_len={}u,snd_cwnd={}u,ssthresh={}u,snd_wnd={}u,\
             srtt_us={}u,rcv_wnd={}u,value=1u",
            e.src_addr,
            e.dest_addr,
            domain_tag(domain),
            e.family,
            e.pid,
            e.tgid,
            e.src_port,
            e.dest_port,
            e.data_len,
            e.snd_cwnd,
            e.ssthresh,
            e.snd_wnd,
            e.srtt_us,
            e.rcv_wnd,
        );
        self.send(line);
    }

    pub fn push_tcp_retransmit_skb(&self, e: &ReadableTCPRetransmitSkbEvent, domain: Option<&str>) {
        let line = format!(
            "bpf_tcp_retransmit_skb,src_ip={},dest_ip={}{},family={},\
             state={},pid={},src_port={},dest_port={},err={} value=1u",
            e.source_ip,
            e.destination_ip,
            domain_tag(domain),
            e.family,
            e.state,
            e.pid,
            e.source_port,
            e.destination_port,
            e.err,
        );
        self.send(line);
    }

    pub fn push_tcp_send_reset(&self, e: &ReadableTcpSendResetEvent, domain: Option<&str>) {
        let line = format!(
            "bpf_tcp_send_reset,src_ip={},dest_ip={}{},state={},reason={},\
             pid={},src_port={},dst_port={} value=1u",
            e.src_ip,
            e.dst_ip,
            domain_tag(domain),
            e.state,
            e.reason,
            e.pid,
            e.src_port,
            e.dst_port,
        );
        self.send(line);
    }

    pub fn push_tcp_receive_reset(&self, e: &ReadableTcpReceiveResetEvent, domain: Option<&str>) {
        let line = format!(
            "bpf_tcp_receive_reset,src_ip={},dest_ip={}{},family={},\
             pid={},src_port={},dest_port={},skaddr={},sock_cookie={} value=1u",
            e.src_ip,
            e.dst_ip,
            domain_tag(domain),
            e.family,
            e.pid,
            e.sport,
            e.dport,
            e.skaddr,
            e.sock_cookie,
        );
        self.send(line);
    }

    pub fn push_mysql_query_latency(
        &self,
        dest_ip: [u8; 16],
        ip_family: u8,
        port: u16,
        db: &str,
        query: &str,
        latency_ms: f64,
        domain: Option<&str>,
    ) {
        let ip_tag = match ip_family {
            4 => format!(",db_ip={}", std::net::Ipv4Addr::new(dest_ip[0], dest_ip[1], dest_ip[2], dest_ip[3])),
            6 => {
                let v6 = std::net::Ipv6Addr::from(dest_ip);
                match v6.to_ipv4_mapped() {
                    Some(v4) => format!(",db_ip={}", v4),
                    None => format!(",db_ip={}", v6),
                }
            }
            _ => String::new(),
        };
        let db_tag = if db.is_empty() {
            String::new()
        } else {
            format!(",db={}", escape_tag(db))
        };
        let line = format!(
            "mysql_query_latency,port={}{}{}{},query={} latency_ms={}",
            port,
            ip_tag,
            db_tag,
            domain_tag(domain),
            escape_tag(query),
            latency_ms,
        );
        self.send(line);
    }

    pub fn push_dns_query(
        &self,
        domain: &str,
        rcode: u8,
        querier_ip: std::net::IpAddr,
        resolved_ips: &[std::net::IpAddr],
    ) {
        let rcode_name = match rcode {
            0 => "NOERROR",
            1 => "FORMERR",
            2 => "SERVFAIL",
            3 => "NXDOMAIN",
            4 => "NOTIMP",
            5 => "REFUSED",
            _ => "UNKNOWN",
        };
        // All resolved IPs joined with '&' as a single tag so one line is emitted
        // per DNS response. Caller must pre-sort and dedup the slice so that
        // round-robin responses returning the same IPs in different orders always
        // produce the same tag value and don't create duplicate series.
        let mut line = format!(
            "dns_query,domain={},rcode={},querier_ip={}",
            escape_tag(domain),
            rcode_name,
            querier_ip,
        );
        if !resolved_ips.is_empty() {
            let joined = resolved_ips
                .iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>()
                .join("&");
            line.push_str(&format!(",resolved_ip={}", joined));
        }
        line.push_str(" value=1u");
        self.send(line);
    }

    fn send(&self, line: String) {
        let socket = self.socket.clone();
        let addr = self.addr;
        tokio::spawn(async move {
            if let Err(e) = socket.send_to(line.as_bytes(), addr).await {
                error!("telegraf send failed: {e}");
            }
        });
    }
}
