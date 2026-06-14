use crate::dns_cache::{DnsCache, SharedDnsCache};
use crate::modules::Module;
use crate::probes::{ProbeEvent, ProbeRequirement};
use crate::sink::telegraf::TelegrafMetricsPusher;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

pub struct DnsModule {
    cache: SharedDnsCache,
    sink: Arc<TelegrafMetricsPusher>,
}

impl DnsModule {
    pub fn new(cache: SharedDnsCache, sink: Arc<TelegrafMetricsPusher>) -> Self {
        Self { cache, sink }
    }
}

impl Module for DnsModule {
    fn name(&self) -> &'static str {
        "dns"
    }

    fn required_probes(&self) -> Vec<ProbeRequirement> {
        vec![ProbeRequirement::UdpRecvMsg {
            src_ports: Some(vec![53]),
        }]
    }

    fn on_event(&mut self, event: &ProbeEvent) {
        // dest_ip in the probe event is the packet's destination — for DNS responses
        // that is the host which issued the query, so we surface it as querier_ip.
        if let ProbeEvent::UdpRecvMsg { src_port, dest_ip: querier_ip, payload } = event {
            log::trace!("[dns] on_event: src_port={} querier_ip={} payload_len={}", src_port, querier_ip, payload.len());
            if let Ok(mut cache) = self.cache.lock() {
                if let Some((queries, rcode)) = try_parse(payload, &mut cache) {
                    for q in &queries {
                        log::debug!("[dns] query metric: domain={} rcode={} querier_ip={}", q, rcode, querier_ip);
                        self.sink.push_dns_query(q, rcode, *querier_ip);
                    }
                }
            }
        }
    }
}

/// Parses a DNS response message. Updates the cache for A/AAAA records on RCODE=0.
/// Returns `(queries, rcode)` where `queries` are the question QNAMEs (for metrics).
/// Returns None for DNS queries (QR=0) or malformed messages.
fn try_parse(msg: &[u8], cache: &mut DnsCache) -> Option<(Vec<String>, u8)> {
    if msg.len() < 12 {
        return None;
    }

    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    if flags & 0x8000 == 0 {
        return None; // QR=0 — this is a query, not a response
    }

    let rcode = (flags & 0x000F) as u8;
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let ancount = u16::from_be_bytes([msg[6], msg[7]]) as usize;

    let mut pos = 12;
    let mut queries = Vec::new();

    // Parse question section and collect all QNAMEs for metrics.
    for _ in 0..qdcount {
        let (qname, next) = parse_name(msg, pos)?;
        pos = next;
        if pos + 4 > msg.len() {
            return None;
        }
        pos += 4; // skip QTYPE + QCLASS
        queries.push(qname);
    }

    // Only process answer records for successful (RCODE=0) responses.
    if rcode == 0 && ancount > 0 {
        for _ in 0..ancount {
            // Parse the record's own NAME — for CNAME chains this is the canonical
            // name at that point in the chain (e.g. the CNAME target for A records).
            let (rec_name, next) = parse_name(msg, pos)?;
            pos = next;
            if pos + 10 > msg.len() {
                return None;
            }

            let rtype    = u16::from_be_bytes([msg[pos],     msg[pos + 1]]);
            // CLASS at pos+2..pos+4; TTL at pos+4..pos+8
            let rdlength = u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]) as usize;
            pos += 10;

            if pos + rdlength > msg.len() {
                return None;
            }

            match rtype {
                1 if rdlength == 4 => {
                    let ip = IpAddr::V4(Ipv4Addr::new(
                        msg[pos], msg[pos + 1], msg[pos + 2], msg[pos + 3],
                    ));
                    log::debug!("[dns] A {} → {}", ip, rec_name);
                    cache.insert(ip, rec_name);
                }
                28 if rdlength == 16 => {
                    let mut bytes = [0u8; 16];
                    bytes.copy_from_slice(&msg[pos..pos + 16]);
                    let v6 = Ipv6Addr::from(bytes);
                    let ip = match v6.to_ipv4_mapped() {
                        Some(v4) => IpAddr::V4(v4),
                        None => IpAddr::V6(v6),
                    };
                    log::debug!("[dns] AAAA {} → {}", ip, rec_name);
                    cache.insert(ip, rec_name);
                }
                5 => {
                    if let Some((cname_target, _)) = parse_name(msg, pos) {
                        log::trace!("[dns] CNAME {} → {}", rec_name, cname_target);
                    }
                }
                _ => {}
            }

            pos += rdlength;
        }
    }

    Some((queries, rcode))
}

/// Parses a DNS name (with pointer compression) starting at `pos` in `msg`.
/// Returns `(name, end_pos)` where `end_pos` is the byte after the name in
/// the *original* message (not after a followed pointer).
fn parse_name(msg: &[u8], pos: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut cur = pos;
    let mut jumped = false;
    let mut end_pos = pos;
    let mut depth = 0usize;

    loop {
        if depth > 128 || cur >= msg.len() {
            return None;
        }
        depth += 1;

        let byte = msg[cur];

        if byte == 0 {
            if !jumped {
                end_pos = cur + 1;
            }
            break;
        }

        if byte & 0xC0 == 0xC0 {
            if cur + 1 >= msg.len() {
                return None;
            }
            let target = (((byte & 0x3F) as usize) << 8) | msg[cur + 1] as usize;
            if target >= msg.len() {
                return None;
            }
            if !jumped {
                end_pos = cur + 2;
            }
            jumped = true;
            cur = target;
        } else {
            let label_end = cur + 1 + byte as usize;
            if label_end > msg.len() {
                return None;
            }
            if !name.is_empty() {
                name.push('.');
            }
            name.push_str(std::str::from_utf8(&msg[cur + 1..label_end]).ok()?);
            cur = label_end;
        }
    }

    if !jumped {
        end_pos = cur + 1;
    }

    Some((name, end_pos))
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn make_dns_response(domain: &str, ip: Ipv4Addr) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&[0x00, 0x01]); // ID
        msg.extend_from_slice(&[0x81, 0x80]); // QR=1, RCODE=0
        msg.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
        msg.extend_from_slice(&[0x00, 0x01]); // ANCOUNT = 1
        msg.extend_from_slice(&[0x00, 0x00]); // NSCOUNT = 0
        msg.extend_from_slice(&[0x00, 0x00]); // ARCOUNT = 0

        for label in domain.split('.') {
            msg.push(label.len() as u8);
            msg.extend_from_slice(label.as_bytes());
        }
        msg.push(0x00);
        msg.extend_from_slice(&[0x00, 0x01]); // QTYPE = A
        msg.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN

        // Answer: pointer back to QNAME at offset 12
        msg.extend_from_slice(&[0xC0, 0x0C]);
        msg.extend_from_slice(&[0x00, 0x01]); // TYPE = A
        msg.extend_from_slice(&[0x00, 0x01]); // CLASS = IN
        msg.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL = 60
        msg.extend_from_slice(&[0x00, 0x04]); // RDLENGTH = 4
        msg.extend_from_slice(&ip.octets());

        msg
    }

    fn make_cname_response(query: &str, cname: &str, ip: Ipv4Addr) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&[0x00, 0x02]); // ID
        msg.extend_from_slice(&[0x81, 0x80]); // QR=1, RCODE=0
        msg.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
        msg.extend_from_slice(&[0x00, 0x02]); // ANCOUNT = 2
        msg.extend_from_slice(&[0x00, 0x00]);
        msg.extend_from_slice(&[0x00, 0x00]);

        let qname_off = 12usize;

        // Question
        for label in query.split('.') {
            msg.push(label.len() as u8);
            msg.extend_from_slice(label.as_bytes());
        }
        msg.push(0x00);
        msg.extend_from_slice(&[0x00, 0x01]); // QTYPE = A
        msg.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN

        // Answer 1: CNAME record — NAME = pointer to QNAME, RDATA = cname target
        let cname_off = msg.len();
        msg.push(0xC0);
        msg.push(qname_off as u8); // pointer to question name
        msg.extend_from_slice(&[0x00, 0x05]); // TYPE = CNAME
        msg.extend_from_slice(&[0x00, 0x01]); // CLASS = IN
        msg.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL

        // Encode CNAME target as DNS labels
        let mut cname_rdata = Vec::new();
        for label in cname.split('.') {
            cname_rdata.push(label.len() as u8);
            cname_rdata.extend_from_slice(label.as_bytes());
        }
        cname_rdata.push(0x00);
        let _ = cname_off; // suppress unused warning
        msg.extend_from_slice(&(cname_rdata.len() as u16).to_be_bytes()); // RDLENGTH
        let cname_rdata_off = msg.len();
        msg.extend_from_slice(&cname_rdata);

        // Answer 2: A record — NAME = pointer to CNAME target in RDATA
        msg.push(0xC0);
        msg.push(cname_rdata_off as u8); // pointer to CNAME target
        msg.extend_from_slice(&[0x00, 0x01]); // TYPE = A
        msg.extend_from_slice(&[0x00, 0x01]); // CLASS = IN
        msg.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL
        msg.extend_from_slice(&[0x00, 0x04]); // RDLENGTH = 4
        msg.extend_from_slice(&ip.octets());

        msg
    }

    #[test]
    fn parses_a_record() {
        let ip = Ipv4Addr::new(93, 184, 216, 34);
        let msg = make_dns_response("example.com", ip);
        let mut cache = DnsCache::new();
        let _ = try_parse(&msg, &mut cache);
        assert_eq!(
            cache.lookup(&IpAddr::V4(ip)).unwrap(),
            "example.com"
        );
    }

    #[test]
    fn ignores_query_packets() {
        let mut msg = make_dns_response("example.com", Ipv4Addr::new(1, 2, 3, 4));
        msg[2] = 0x01; // clear QR bit
        msg[3] = 0x00;
        let mut cache = DnsCache::new();
        let result = try_parse(&msg, &mut cache);
        assert!(result.is_none());
        assert!(cache.lookup(&IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))).is_none());
    }

    #[test]
    fn ignores_error_responses() {
        let mut msg = make_dns_response("example.com", Ipv4Addr::new(1, 2, 3, 4));
        msg[3] = 0x03; // RCODE = NXDOMAIN
        let mut cache = DnsCache::new();
        let result = try_parse(&msg, &mut cache);
        // Should still return the query name and rcode for metrics
        assert!(result.is_some());
        let (queries, rcode) = result.unwrap();
        assert_eq!(rcode, 3);
        assert_eq!(queries, ["example.com"]);
        // But cache must NOT be updated
        assert!(cache.lookup(&IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))).is_none());
    }

    #[test]
    fn cname_uses_canonical_name() {
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        let msg = make_cname_response("www.example.com", "cdn.example.net", ip);
        let mut cache = DnsCache::new();
        let result = try_parse(&msg, &mut cache);
        assert!(result.is_some());
        let (queries, rcode) = result.unwrap();
        assert_eq!(rcode, 0);
        assert_eq!(queries, ["www.example.com"]);
        // The A record's NAME is "cdn.example.net" (the CNAME target), not the QNAME
        assert_eq!(
            cache.lookup(&IpAddr::V4(ip)).unwrap(),
            "cdn.example.net"
        );
    }
}
