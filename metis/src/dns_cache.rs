use lru::LruCache;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

const CACHE_CAPACITY: usize = 4096;

/// Reverse DNS cache: IP address → canonical domain name.
/// Populated by the DNS module from observed A/AAAA responses.
pub struct DnsCache {
    map: LruCache<IpAddr, String>,
}

impl DnsCache {
    pub fn new() -> Self {
        Self {
            map: LruCache::new(NonZeroUsize::new(CACHE_CAPACITY).unwrap()),
        }
    }

    pub fn insert(&mut self, ip: IpAddr, domain: String) {
        self.map.put(ip, domain);
    }

    /// Returns the domain for `ip` and promotes it to MRU position.
    pub fn lookup(&mut self, ip: &IpAddr) -> Option<&str> {
        self.map.get(ip).map(|s| s.as_str())
    }
}

pub type SharedDnsCache = Arc<Mutex<DnsCache>>;

pub fn new_shared() -> SharedDnsCache {
    Arc::new(Mutex::new(DnsCache::new()))
}
