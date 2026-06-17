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

const CLIENT_PROTOCOL_41:                u32 = 0x0000_0200;
const CLIENT_CONNECT_WITH_DB:            u32 = 0x0000_0008;
const CLIENT_SECURE_CONNECTION:          u32 = 0x0000_8000;
const CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA: u32 = 0x0020_0000;

#[derive(Default, Clone)]
struct ConnectionState {
    username: String,
    db: String,
}

struct PendingQuery {
    dest_ip: [u8; 16],
    ip_family: u8,
    dest_port: u16,
    send_ns: u64,
    query: String,
    db: String,
    username: String,
    inserted_at: Instant,
}

pub struct MysqlModule {
    sink: Arc<TelegrafMetricsPusher>,
    ports: Vec<u16>,
    dns_cache: SharedDnsCache,
    /// socket_ptr → connection state (username + current db); LRU-bounded
    connections: LruCache<u64, ConnectionState>,
    /// socket_ptr → query waiting for the response timestamp
    pending: HashMap<u64, PendingQuery>,
    /// insertion-ordered expiry queue; drained from the front on each insert
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
            ProbeEvent::TcpSendMsg {
                dest_ip, ip_family, dest_port, socket_ptr, timestamp_ns, payload,
            } => {
                match payload.get(3) {
                    Some(&0x01) => {
                        // HandshakeResponse41: the first client→server packet after the
                        // server's initial handshake always carries sequence number 1.
                        if let Some((username, db)) =
                            parse_handshake_response(payload)
                        {
                            if !self.connections.contains(socket_ptr) {
                                self.connections.put(*socket_ptr, ConnectionState::default());
                            }
                            if let Some(state) = self.connections.get_mut(socket_ptr) {
                                state.username = username;
                                if !db.is_empty() {
                                    state.db = db;
                                }
                                log::debug!(
                                    "[mysql] handshake: socket={:x} user={:?} db={:?}",
                                    socket_ptr, state.username, state.db
                                );
                            }
                        }
                    }
                    Some(&0x00) => {
                        // Regular command packet (new command sequence, seq=0).
                        match payload.get(4) {
                            Some(&0x02) => {
                                // COM_INIT_DB — payload[5..] is the new database name.
                                let db = String::from_utf8_lossy(
                                    payload.get(5..).unwrap_or_default(),
                                )
                                .into_owned();
                                if !self.connections.contains(socket_ptr) {
                                    self.connections.put(*socket_ptr, ConnectionState::default());
                                }
                                if let Some(state) = self.connections.get_mut(socket_ptr) {
                                    state.db = db;
                                }
                            }
                            Some(&0x03) => {
                                // COM_QUERY — snapshot current connection state at send time.
                                let now = Instant::now();

                                while let Some((ts, _)) = self.expiry.front() {
                                    if now.duration_since(*ts) < PENDING_TTL {
                                        break;
                                    }
                                    let (ts, ptr) = self.expiry.pop_front().unwrap();
                                    if self
                                        .pending
                                        .get(&ptr)
                                        .map_or(false, |e| e.inserted_at == ts)
                                    {
                                        self.pending.remove(&ptr);
                                    }
                                }

                                let query = String::from_utf8_lossy(
                                    payload.get(5..).unwrap_or_default(),
                                )
                                .into_owned();
                                let (db, username) = self
                                    .connections
                                    .get(socket_ptr)
                                    .map(|s| (s.db.clone(), s.username.clone()))
                                    .unwrap_or_default();

                                self.pending.insert(
                                    *socket_ptr,
                                    PendingQuery {
                                        dest_ip: *dest_ip,
                                        ip_family: *ip_family,
                                        dest_port: *dest_port,
                                        send_ns: *timestamp_ns,
                                        query,
                                        db,
                                        username,
                                        inserted_at: now,
                                    },
                                );
                                self.expiry.push_back((now, *socket_ptr));
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
            ProbeEvent::SockDefReadable { socket_ptr, timestamp_ns } => {
                if let Some(pq) = self.pending.remove(socket_ptr) {
                    if !pq.query.is_empty() {
                        let latency_ms =
                            timestamp_ns.saturating_sub(pq.send_ns) as f64 / 1_000_000.0;
                        let normalized = normalize_query(&pq.query);
                        let ip = fmt_ip(pq.dest_ip, pq.ip_family);
                        let domain = self
                            .dns_cache
                            .lock()
                            .ok()
                            .and_then(|mut c| c.lookup(&ip).map(str::to_string));
                        log::debug!(
                            "[mysql] ip={} port={} user={:?} db={:?} latency={:.3}ms query={:?}",
                            ip, pq.dest_port, pq.username, pq.db, latency_ms, normalized,
                        );
                        self.sink.push_mysql_query_latency(
                            pq.dest_ip,
                            pq.ip_family,
                            pq.dest_port,
                            &pq.db,
                            &pq.username,
                            &normalized,
                            latency_ms,
                            domain.as_deref(),
                        );
                    }
                }
            }
            _ => {}
        }
    }
}

/// Parses a `HandshakeResponse41` packet and returns `(username, database)`.
/// The database is only populated when `CLIENT_CONNECT_WITH_DB` is set in the
/// capability flags; otherwise it is an empty string.
///
/// Packet layout (MySQL framing header + payload):
///   [0..3]  payload length (3-byte LE, ignored here)
///   [3]     sequence number — must be 1
///   [4..8]  capability flags (4-byte LE)
///   [8..12] max packet size
///   [12]    character set
///   [13..36] reserved (23 zero bytes)
///   [36..]  username (null-terminated)
///           auth response (length varies by capability flags)
///           database name (null-terminated, only if CLIENT_CONNECT_WITH_DB)
fn parse_handshake_response(payload: &[u8]) -> Option<(String, String)> {
    if payload.len() < 36 {
        return None;
    }
    if payload[3] != 0x01 {
        return None;
    }

    let caps =
        u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);

    // Require CLIENT_PROTOCOL_41 so we know the packet layout above is valid.
    if caps & CLIENT_PROTOCOL_41 == 0 {
        return None;
    }

    let mut pos = 36;

    let username = read_null_str(payload, &mut pos)?;

    // Skip the auth response — its encoding depends on capability flags.
    if caps & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA != 0 {
        let len = read_lenenc_int(payload, &mut pos)? as usize;
        pos = pos.checked_add(len).filter(|&p| p <= payload.len())?;
    } else if caps & CLIENT_SECURE_CONNECTION != 0 {
        let len = *payload.get(pos)? as usize;
        pos = pos.checked_add(1 + len).filter(|&p| p <= payload.len())?;
    } else {
        skip_null_str(payload, &mut pos)?;
    }

    let db = if caps & CLIENT_CONNECT_WITH_DB != 0 {
        read_null_str(payload, &mut pos).unwrap_or_default()
    } else {
        String::new()
    };

    Some((username, db))
}

fn read_null_str(data: &[u8], pos: &mut usize) -> Option<String> {
    let start = *pos;
    loop {
        match data.get(*pos) {
            Some(&0) => {
                let s = String::from_utf8_lossy(&data[start..*pos]).into_owned();
                *pos += 1;
                return Some(s);
            }
            Some(_) => *pos += 1,
            None => return None,
        }
    }
}

fn skip_null_str(data: &[u8], pos: &mut usize) -> Option<()> {
    loop {
        match data.get(*pos) {
            Some(&0) => { *pos += 1; return Some(()); }
            Some(_) => *pos += 1,
            None => return None,
        }
    }
}

fn read_lenenc_int(data: &[u8], pos: &mut usize) -> Option<u64> {
    let first = *data.get(*pos)?;
    *pos += 1;
    match first {
        0..=250 => Some(first as u64),
        252 => {
            let v = u16::from_le_bytes([*data.get(*pos)?, *data.get(*pos + 1)?]) as u64;
            *pos += 2;
            Some(v)
        }
        253 => {
            let v = u32::from_le_bytes([
                *data.get(*pos)?,
                *data.get(*pos + 1)?,
                *data.get(*pos + 2)?,
                0,
            ]) as u64;
            *pos += 3;
            Some(v)
        }
        254 => {
            let bytes = [
                *data.get(*pos)?,     *data.get(*pos + 1)?,
                *data.get(*pos + 2)?, *data.get(*pos + 3)?,
                *data.get(*pos + 4)?, *data.get(*pos + 5)?,
                *data.get(*pos + 6)?, *data.get(*pos + 7)?,
            ];
            *pos += 8;
            Some(u64::from_le_bytes(bytes))
        }
        _ => None,
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
    use super::*;

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

    fn make_handshake_response(username: &str, db: Option<&str>) -> Vec<u8> {
        let mut caps: u32 = CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION;
        if db.is_some() {
            caps |= CLIENT_CONNECT_WITH_DB;
        }

        let mut payload = Vec::new();
        // MySQL framing header (length placeholder + seq=1)
        payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        // Capability flags
        payload.extend_from_slice(&caps.to_le_bytes());
        // Max packet size
        payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        // Charset
        payload.push(0x21);
        // Reserved (23 bytes)
        payload.extend_from_slice(&[0u8; 23]);
        // Username (null-terminated)
        payload.extend_from_slice(username.as_bytes());
        payload.push(0x00);
        // Auth response (CLIENT_SECURE_CONNECTION: 1-byte length + data)
        payload.push(0x14); // 20 bytes
        payload.extend_from_slice(&[0u8; 20]);
        // Database (null-terminated), if CLIENT_CONNECT_WITH_DB
        if let Some(d) = db {
            payload.extend_from_slice(d.as_bytes());
            payload.push(0x00);
        }
        payload
    }

    #[test]
    fn handshake_extracts_username() {
        let pkt = make_handshake_response("alice", None);
        let (user, db) = parse_handshake_response(&pkt).unwrap();
        assert_eq!(user, "alice");
        assert_eq!(db, "");
    }

    #[test]
    fn handshake_extracts_username_and_db() {
        let pkt = make_handshake_response("bob", Some("myapp"));
        let (user, db) = parse_handshake_response(&pkt).unwrap();
        assert_eq!(user, "bob");
        assert_eq!(db, "myapp");
    }

    #[test]
    fn handshake_rejects_wrong_sequence() {
        let mut pkt = make_handshake_response("alice", None);
        pkt[3] = 0x00; // wrong sequence
        assert!(parse_handshake_response(&pkt).is_none());
    }
}
