use crate::config::MetricProtocol;
use crate::probes::tracepoints::tcp_probe::ReadableTCPProbeEvent;
use crate::probes::tracepoints::tcp_receive_reset::ReadableTcpReceiveResetEvent;
use crate::probes::tracepoints::tcp_retransmit_skb::ReadableTCPRetransmitSkbEvent;
use crate::probes::tracepoints::tcp_send_reset::ReadableTcpSendResetEvent;
use log::error;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

// ── InfluxDB helpers ──────────────────────────────────────────────────────────

/// Escapes a string for use as an InfluxDB line-protocol tag value.
fn influx_tag(s: &str) -> String {
    s.replace(',', "\\,")
        .replace('=', "\\=")
        .replace(' ', "\\ ")
}

fn influx_domain_tag(domain: Option<&str>) -> String {
    match domain {
        Some(d) if !d.is_empty() => format!(",domain={}", influx_tag(d)),
        _ => String::new(),
    }
}

fn influx_db_ip(dest_ip: [u8; 16], ip_family: u8) -> String {
    match ip_family {
        4 => format!(
            ",db_ip={}",
            std::net::Ipv4Addr::new(dest_ip[0], dest_ip[1], dest_ip[2], dest_ip[3])
        ),
        6 => {
            let v6 = std::net::Ipv6Addr::from(dest_ip);
            match v6.to_ipv4_mapped() {
                Some(v4) => format!(",db_ip={}", v4),
                None => format!(",db_ip={}", v6),
            }
        }
        _ => String::new(),
    }
}

// ── StatsD (DogStatsD) helpers ────────────────────────────────────────────────

/// Escapes a value for use in a DogStatsD tag (`|#key:value`).
/// `:` is the key/value separator and `,` is the tag separator — both must be
/// replaced. IPv6 addresses contain `:` so they become `_`-separated here.
fn statsd_val(s: &str) -> String {
    s.replace(':', "_").replace(',', "_")
}

/// Builds the `|#tag1:val1,tag2:val2` suffix for a DogStatsD metric.
struct StatsdTags(String);

impl StatsdTags {
    fn new() -> Self {
        Self(String::new())
    }

    fn add(&mut self, key: &str, val: &str) -> &mut Self {
        if !self.0.is_empty() {
            self.0.push(',');
        }
        self.0.push_str(key);
        self.0.push(':');
        self.0.push_str(&statsd_val(val));
        self
    }

    fn add_opt(&mut self, key: &str, val: Option<&str>) -> &mut Self {
        if let Some(v) = val {
            if !v.is_empty() {
                self.add(key, v);
            }
        }
        self
    }

    /// Returns the formatted suffix, empty string if no tags were added.
    fn suffix(&self) -> String {
        if self.0.is_empty() {
            String::new()
        } else {
            format!("|#{}", self.0)
        }
    }
}

fn statsd_db_ip(dest_ip: [u8; 16], ip_family: u8) -> String {
    match ip_family {
        4 => std::net::Ipv4Addr::new(dest_ip[0], dest_ip[1], dest_ip[2], dest_ip[3])
            .to_string(),
        6 => {
            let v6 = std::net::Ipv6Addr::from(dest_ip);
            match v6.to_ipv4_mapped() {
                Some(v4) => v4.to_string(),
                None => v6.to_string(),
            }
        }
        _ => String::new(),
    }
}

// ── Pusher ────────────────────────────────────────────────────────────────────

pub struct TelegrafMetricsPusher {
    socket: Arc<UdpSocket>,
    addr: SocketAddr,
    protocol: MetricProtocol,
}

impl TelegrafMetricsPusher {
    pub async fn new(target: &str, protocol: MetricProtocol) -> anyhow::Result<Self> {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        Ok(Self {
            socket: Arc::new(socket),
            addr: target.parse()?,
            protocol,
        })
    }

    pub fn push_tcp_probe(&self, e: &ReadableTCPProbeEvent, domain: Option<&str>) {
        match self.protocol {
            MetricProtocol::Influx => {
                self.send(format!(
                    "bpf_tcp_probe,src_ip={},dest_ip={}{},family={},\
                     pid={},tgid={},src_port={},dest_port={} \
                     data_len={}u,snd_cwnd={}u,ssthresh={}u,snd_wnd={}u,\
                     srtt_us={}u,rcv_wnd={}u",
                    e.src_addr,
                    e.dest_addr,
                    influx_domain_tag(domain),
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
                ));
            }
            MetricProtocol::Statsd => {
                // InfluxDB can hold multiple fields in one line; StatsD is one
                // value per datagram, so each numeric field becomes its own metric.
                let mut tags = StatsdTags::new();
                tags.add("src_ip", &e.src_addr.to_string())
                    .add("dest_ip", &e.dest_addr.to_string())
                    .add_opt("domain", domain)
                    .add("family", &e.family.to_string())
                    .add("pid", &e.pid.to_string())
                    .add("tgid", &e.tgid.to_string())
                    .add("src_port", &e.src_port.to_string())
                    .add("dest_port", &e.dest_port.to_string());
                let sfx = tags.suffix();
                let gauges = [
                    ("bpf_tcp_probe.data_len",  e.data_len  as u64),
                    ("bpf_tcp_probe.snd_cwnd",  e.snd_cwnd  as u64),
                    ("bpf_tcp_probe.ssthresh",  e.ssthresh  as u64),
                    ("bpf_tcp_probe.snd_wnd",   e.snd_wnd   as u64),
                    ("bpf_tcp_probe.srtt_us",   e.srtt_us   as u64),
                    ("bpf_tcp_probe.rcv_wnd",   e.rcv_wnd   as u64),
                ];
                for (name, val) in gauges {
                    self.send(format!("{}:{}|g{}", name, val, sfx));
                }
                self.send(format!("bpf_tcp_probe:1|c{}", sfx));
            }
        }
    }

    pub fn push_tcp_retransmit_skb(
        &self,
        e: &ReadableTCPRetransmitSkbEvent,
        domain: Option<&str>,
    ) {
        match self.protocol {
            MetricProtocol::Influx => {
                self.send(format!(
                    "bpf_tcp_retransmit_skb,src_ip={},dest_ip={}{},family={},\
                     state={},pid={},src_port={},dest_port={},err={} count=1i",
                    e.source_ip,
                    e.destination_ip,
                    influx_domain_tag(domain),
                    e.family,
                    e.state,
                    e.pid,
                    e.source_port,
                    e.destination_port,
                    e.err,
                ));
            }
            MetricProtocol::Statsd => {
                let mut tags = StatsdTags::new();
                tags.add("src_ip", &e.source_ip.to_string())
                    .add("dest_ip", &e.destination_ip.to_string())
                    .add_opt("domain", domain)
                    .add("family", &e.family.to_string())
                    .add("state", &e.state.to_string())
                    .add("pid", &e.pid.to_string())
                    .add("src_port", &e.source_port.to_string())
                    .add("dest_port", &e.destination_port.to_string())
                    .add("err", &e.err.to_string());
                self.send(format!("bpf_tcp_retransmit_skb:1|c{}", tags.suffix()));
            }
        }
    }

    pub fn push_tcp_send_reset(&self, e: &ReadableTcpSendResetEvent, domain: Option<&str>) {
        match self.protocol {
            MetricProtocol::Influx => {
                self.send(format!(
                    "bpf_tcp_send_reset,src_ip={},dest_ip={}{},state={},reason={},\
                     pid={},src_port={},dst_port={} count=1i",
                    e.src_ip,
                    e.dst_ip,
                    influx_domain_tag(domain),
                    e.state,
                    e.reason,
                    e.pid,
                    e.src_port,
                    e.dst_port,
                ));
            }
            MetricProtocol::Statsd => {
                let mut tags = StatsdTags::new();
                tags.add("src_ip", &e.src_ip.to_string())
                    .add("dest_ip", &e.dst_ip.to_string())
                    .add_opt("domain", domain)
                    .add("state", &e.state.to_string())
                    .add("reason", &e.reason.to_string())
                    .add("pid", &e.pid.to_string())
                    .add("src_port", &e.src_port.to_string())
                    .add("dst_port", &e.dst_port.to_string());
                self.send(format!("bpf_tcp_send_reset:1|c{}", tags.suffix()));
            }
        }
    }

    pub fn push_tcp_receive_reset(
        &self,
        e: &ReadableTcpReceiveResetEvent,
        domain: Option<&str>,
    ) {
        match self.protocol {
            MetricProtocol::Influx => {
                self.send(format!(
                    "bpf_tcp_receive_reset,src_ip={},dest_ip={}{},family={},\
                     pid={},src_port={},dest_port={},skaddr={},sock_cookie={} count=1i",
                    e.src_ip,
                    e.dst_ip,
                    influx_domain_tag(domain),
                    e.family,
                    e.pid,
                    e.sport,
                    e.dport,
                    e.skaddr,
                    e.sock_cookie,
                ));
            }
            MetricProtocol::Statsd => {
                let mut tags = StatsdTags::new();
                tags.add("src_ip", &e.src_ip.to_string())
                    .add("dest_ip", &e.dst_ip.to_string())
                    .add_opt("domain", domain)
                    .add("family", &e.family.to_string())
                    .add("pid", &e.pid.to_string())
                    .add("src_port", &e.sport.to_string())
                    .add("dest_port", &e.dport.to_string())
                    .add("skaddr", &e.skaddr.to_string())
                    .add("sock_cookie", &e.sock_cookie.to_string());
                self.send(format!("bpf_tcp_receive_reset:1|c{}", tags.suffix()));
            }
        }
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
        match self.protocol {
            MetricProtocol::Influx => {
                let db_tag = if db.is_empty() {
                    String::new()
                } else {
                    format!(",db={}", influx_tag(db))
                };
                self.send(format!(
                    "mysql_query_latency,port={}{}{}{},query={} latency_ms={}",
                    port,
                    influx_db_ip(dest_ip, ip_family),
                    db_tag,
                    influx_domain_tag(domain),
                    influx_tag(query),
                    latency_ms,
                ));
            }
            MetricProtocol::Statsd => {
                // latency maps naturally to StatsD's `ms` timing type.
                let mut tags = StatsdTags::new();
                tags.add("port", &port.to_string());
                let ip_str = statsd_db_ip(dest_ip, ip_family);
                if !ip_str.is_empty() {
                    tags.add("db_ip", &ip_str);
                }
                if !db.is_empty() {
                    tags.add("db", db);
                }
                tags.add_opt("domain", domain)
                    .add("query", query);
                self.send(format!("mysql_query_latency:{}|ms{}", latency_ms, tags.suffix()));
            }
        }
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
        let resolved_tag_val = resolved_ips
            .iter()
            .map(|ip| ip.to_string())
            .collect::<Vec<_>>()
            .join("&");

        match self.protocol {
            MetricProtocol::Influx => {
                let mut line = format!(
                    "dns_query,domain={},rcode={},querier_ip={}",
                    influx_tag(domain),
                    rcode_name,
                    querier_ip,
                );
                if !resolved_tag_val.is_empty() {
                    line.push_str(&format!(",resolved_ips={}", resolved_tag_val));
                }
                line.push_str(" count=1i");
                self.send(line);
            }
            MetricProtocol::Statsd => {
                let mut tags = StatsdTags::new();
                tags.add("domain", domain)
                    .add("rcode", rcode_name)
                    .add("querier_ip", &querier_ip.to_string());
                if !resolved_tag_val.is_empty() {
                    tags.add("resolved_ips", &resolved_tag_val);
                }
                self.send(format!("dns_query:1|c{}", tags.suffix()));
            }
        }
    }

    fn send(&self, line: String) {
        let socket = self.socket.clone();
        let addr = self.addr;
        tokio::spawn(async move {
            if let Err(e) = socket.send_to(line.as_bytes(), addr).await {
                error!("metric send failed: {e}");
            }
        });
    }
}
