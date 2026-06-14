use crate::dns_cache::SharedDnsCache;
use crate::modules::Module;
use crate::probes::{ProbeEvent, ProbeRequirement};
use crate::sink::telegraf::TelegrafMetricsPusher;
use std::sync::Arc;

pub struct TcpModule {
    sink: Arc<TelegrafMetricsPusher>,
    ports: Option<Vec<u16>>,
    dns_cache: SharedDnsCache,
}

impl TcpModule {
    pub fn new(
        sink: Arc<TelegrafMetricsPusher>,
        ports: Option<Vec<u16>>,
        dns_cache: SharedDnsCache,
    ) -> Self {
        Self { sink, ports, dns_cache }
    }
}

impl Module for TcpModule {
    fn name(&self) -> &'static str {
        "tcp"
    }

    fn required_probes(&self) -> Vec<ProbeRequirement> {
        let p = self.ports.clone();
        vec![
            ProbeRequirement::TcpProbe { dest_ports: p.clone() },
            ProbeRequirement::TcpRetransmitSkb { dest_ports: p.clone() },
            ProbeRequirement::TcpSendReset { dest_ports: p.clone() },
            ProbeRequirement::TcpReceiveReset { dest_ports: p },
        ]
    }

    fn on_event(&mut self, event: &ProbeEvent) {
        match event {
            ProbeEvent::TcpProbe(e) => {
                let domain = self.dns_cache.lock().ok()
                    .and_then(|mut c| c.lookup(&e.dest_addr).map(str::to_string));
                self.sink.push_tcp_probe(e, domain.as_deref());
            }
            ProbeEvent::TcpRetransmitSkb(e) => {
                let domain = self.dns_cache.lock().ok()
                    .and_then(|mut c| c.lookup(&e.destination_ip).map(str::to_string));
                self.sink.push_tcp_retransmit_skb(e, domain.as_deref());
            }
            ProbeEvent::TcpSendReset(e) => {
                let domain = self.dns_cache.lock().ok()
                    .and_then(|mut c| c.lookup(&e.dst_ip).map(str::to_string));
                self.sink.push_tcp_send_reset(e, domain.as_deref());
            }
            ProbeEvent::TcpReceiveReset(e) => {
                let domain = self.dns_cache.lock().ok()
                    .and_then(|mut c| c.lookup(&e.dst_ip).map(str::to_string));
                self.sink.push_tcp_receive_reset(e, domain.as_deref());
            }
            _ => {}
        }
    }
}
