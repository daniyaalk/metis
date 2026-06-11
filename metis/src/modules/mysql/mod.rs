use crate::modules::Module;
use crate::probes::{ProbeEvent, ProbeRequirement};
use crate::sink::telegraf::TelegrafMetricsPusher;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

const PENDING_TTL: Duration = Duration::from_secs(30);

pub struct MysqlModule {
    sink: Arc<TelegrafMetricsPusher>,
    ports: Vec<u16>,
    // socket_ptr → (dest_port, send_timestamp_ns, query, inserted_at)
    pending: HashMap<u64, (u16, u64, String, Instant)>,
    // insertion-ordered expiry queue; drained from the front on each insert
    expiry: VecDeque<(Instant, u64)>,
}

impl MysqlModule {
    pub fn new(sink: Arc<TelegrafMetricsPusher>, ports: Vec<u16>) -> Self {
        Self {
            sink,
            ports,
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
            ProbeEvent::TcpSendMsg { dest_port, socket_ptr, timestamp_ns, payload } => {
                if payload.get(4) != Some(&0x03) {
                    return;
                }

                // Drain expired entries from the front of the expiry queue.
                let now = Instant::now();
                while let Some((ts, _ptr)) = self.expiry.front() {
                    if now.duration_since(*ts) < PENDING_TTL {
                        break;
                    }
                    let (ts, ptr) = self.expiry.pop_front().unwrap();
                    // Guard against socket ptr reuse: only evict if the stored
                    // Instant matches the one we're expiring.
                    if self.pending.get(&ptr).map_or(false, |e| e.3 == ts) {
                        self.pending.remove(&ptr);
                    }
                }

                let query = String::from_utf8_lossy(&payload[5..]).into_owned();
                self.pending.insert(*socket_ptr, (*dest_port, *timestamp_ns, query, now));
                self.expiry.push_back((now, *socket_ptr));
            }
            ProbeEvent::SockDefReadable { socket_ptr, timestamp_ns } => {
                if let Some((dest_port, send_ns, query, _)) = self.pending.remove(socket_ptr) {
                    let latency_ms = timestamp_ns.saturating_sub(send_ns) as f64 / 1_000_000.0;
                    let normalized = normalize_query(&query);
                    log::info!(
                        "[mysql] port={} latency={:.3}ms query={:?}",
                        dest_port, latency_ms, normalized,
                    );
                    self.sink.push_mysql_query_latency(dest_port, &normalized, latency_ms);
                }
            }
            _ => {}
        }
    }
}

/// Replaces string literals and numeric literals with `?`.
///
/// String literals: single- or double-quoted, with backslash escapes
/// (`\'`, `\"`) and doubled-quote escapes (`''`, `""`).
///
/// Numeric literals: integer or decimal sequences (`42`, `3.14`) that are
/// not part of an identifier (i.e. not preceded by a letter, digit, or `_`).
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
                    i += 2; // skip backslash-escaped char
                } else if chars[i] == quote {
                    i += 1;
                    if i < chars.len() && chars[i] == quote {
                        i += 1; // doubled quote — stay inside string
                    } else {
                        break; // closing delimiter
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
            // consume optional decimal part — only if dot is followed by a digit
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
