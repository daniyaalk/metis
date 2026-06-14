use crate::dns_cache::SharedDnsCache;
use crate::modules::Module;
use crate::probes::{ProbeEvent, ProbeRequirement};
use crate::sink::telegraf::TelegrafMetricsPusher;
use lru::LruCache;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

const MAX_CONNECTIONS: usize = 4096;
const PENDING_TTL: Duration = Duration::from_secs(30);

pub struct MysqlModule {
    sink: Arc<TelegrafMetricsPusher>,
    ports: Vec<u16>,
    dns_cache: SharedDnsCache,
    // socket_ptr → current database (set by COM_INIT_DB); LRU-bounded to MAX_CONNECTIONS
    connections: LruCache<u64, String>,
    // socket_ptr → (dest_ip, ip_family, dest_port, send_timestamp_ns, query, db_at_send, inserted_at)
    pending: HashMap<u64, ([u8; 16], u8, u16, u64, String, String, Instant)>,
    // insertion-ordered expiry queue; drained from the front on each insert
    expiry: VecDeque<(Instant, u64)>,
}

impl MysqlModule {
    pub fn new(
        sink: Arc<TelegrafMetricsPusher>,
        ports: Vec<u16>,
        dns_cache: SharedDnsCache,
    ) -> Self {
        Self {
            sink,
            ports,
            dns_cache,
            connections: LruCache::new(NonZeroUsize::new(MAX_CONNECTIONS).unwrap()),
            pending: HashMap::new(),
            expiry: VecDeque::new(),
        }
    }
}

impl Module for MysqlModule {
    fn name(&self) -> &'static str {
        "mysql"
    }

    fn required_probes(&self) -> Vec<ProbeRequirement> {
        vec![
            ProbeRequirement::TcpSendMsg {
                dest_ports: Some(self.ports.clone()),
            },
            ProbeRequirement::SockDefReadable {
                dest_ports: None,
            },
        ]
    }

    fn on_event(&mut self, event: &ProbeEvent) {
        match event {
            ProbeEvent::TcpSendMsg { dest_ip, ip_family, dest_port, socket_ptr, timestamp_ns, payload } => {
                if payload.get(3) != Some(&0x00) { return; }

                match payload.get(4) {
                    Some(&0x02) => {
                        // COM_INIT_DB — payload[5..] is the database name
                        let db = String::from_utf8_lossy(&payload[5..]).into_owned();
                        self.connections.put(*socket_ptr, db);
                    }
                    Some(&0x03) => {
                        // COM_QUERY — capture the query with the current db for this connection
                        let now = Instant::now();

                        while let Some((ts, _ptr)) = self.expiry.front() {
                            if now.duration_since(*ts) < PENDING_TTL { break; }
                            let (ts, ptr) = self.expiry.pop_front().unwrap();
                            if self.pending.get(&ptr).map_or(false, |e| e.6 == ts) {
                                self.pending.remove(&ptr);
                            }
                        }

                        let query = String::from_utf8_lossy(&payload[5..]).into_owned();
                        let db = self.connections.get(socket_ptr).cloned().unwrap_or_default();
                        self.pending.insert(*socket_ptr, (*dest_ip, *ip_family, *dest_port, *timestamp_ns, query, db, now));
                        self.expiry.push_back((now, *socket_ptr));
                    }
                    _ => {}
                }
            }
            ProbeEvent::SockDefReadable { socket_ptr, timestamp_ns } => {
                if let Some((dest_ip, ip_family, dest_port, send_ns, query, db, _)) = self.pending.remove(socket_ptr) {
                    if !query.is_empty() {
                        let latency_ms = timestamp_ns.saturating_sub(send_ns) as f64 / 1_000_000.0;
                        let normalized = normalize_query(&query);
                        let ip = fmt_ip(dest_ip, ip_family);
                        let domain = self.dns_cache.lock().ok()
                            .and_then(|mut c| c.lookup(&ip).map(str::to_string));
                        log::debug!(
                            "[mysql] ip={} port={} db={:?} latency={:.3}ms query={:?}",
                            ip, dest_port, db, latency_ms, normalized,
                        );
                        self.sink.push_mysql_query_latency(
                            dest_ip, ip_family, dest_port, &db, &normalized, latency_ms,
                            domain.as_deref(),
                        );
                    }
                }
            }
            _ => {}
        }
    }
}

fn fmt_ip(ip: [u8; 16], family: u8) -> IpAddr {
    match family {
        4 => IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])),
        6 => {
            let v6 = Ipv6Addr::from(ip);
            match v6.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => IpAddr::V6(v6),
            }
        }
        _ => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    }
}

/// Replaces string literals and numeric literals with `?`.
fn normalize_query(query: &str) -> String {
    let chars: Vec<char> = query.chars().collect();
    let mut out = String::with_capacity(query.len());
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];

        if c == '\'' || c == '"' {
            out.push('?');
            let quote = c;
            i += 1;
            while i < chars.len() {
                if chars[i] == '\\' && i + 1 < chars.len() {
                    i += 2;
                } else if chars[i] == quote {
                    i += 1;
                    if i < chars.len() && chars[i] == quote {
                        i += 1;
                    } else {
                        break;
                    }
                } else {
                    i += 1;
                }
            }
        } else if c.is_ascii_digit() && (i == 0 || !is_ident_char(chars[i - 1])) {
            out.push('?');
            i += 1;
            while i < chars.len() && chars[i].is_ascii_digit() {
                i += 1;
            }
            if i + 1 < chars.len() && chars[i] == '.' && chars[i + 1].is_ascii_digit() {
                i += 1;
                while i < chars.len() && chars[i].is_ascii_digit() {
                    i += 1;
                }
            }
        } else {
            out.push(c);
            i += 1;
        }
    }

    out
}

fn is_ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

#[cfg(test)]
mod tests {
    use super::normalize_query;

    #[test]
    fn plain_string_literal() {
        assert_eq!(normalize_query("SELECT 'foo'"), "SELECT ?");
    }

    #[test]
    fn double_quoted() {
        assert_eq!(normalize_query(r#"WHERE name = "bar""#), "WHERE name = ?");
    }

    #[test]
    fn backslash_escape() {
        assert_eq!(normalize_query(r"WHERE x = 'it\'s'"), "WHERE x = ?");
    }

    #[test]
    fn doubled_quote_escape() {
        assert_eq!(normalize_query("WHERE x = 'it''s'"), "WHERE x = ?");
    }

    #[test]
    fn multiple_literals() {
        assert_eq!(
            normalize_query("INSERT INTO t VALUES ('a', 'b', 'c')"),
            "INSERT INTO t VALUES (?, ?, ?)"
        );
    }

    #[test]
    fn no_literals() {
        assert_eq!(normalize_query("SELECT id FROM users"), "SELECT id FROM users");
    }

    #[test]
    fn bare_integer() {
        assert_eq!(
            normalize_query("select * from txn_info where id=2388219"),
            "select * from txn_info where id=?"
        );
    }

    #[test]
    fn decimal_number() {
        assert_eq!(normalize_query("WHERE price > 9.99"), "WHERE price > ?");
    }

    #[test]
    fn digit_in_identifier_untouched() {
        assert_eq!(
            normalize_query("SELECT col1, table2.col FROM t"),
            "SELECT col1, table2.col FROM t"
        );
    }

    #[test]
    fn mixed_string_and_numeric() {
        assert_eq!(
            normalize_query("WHERE name='alice' AND age=30"),
            "WHERE name=? AND age=?"
        );
    }
}
