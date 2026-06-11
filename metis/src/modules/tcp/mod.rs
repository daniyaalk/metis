use crate::modules::Module;
use crate::probes::{ProbeEvent, ProbeRequirement};
use crate::sink::telegraf::TelegrafMetricsPusher;
use std::sync::Arc;

pub struct TcpModule {
    sink: Arc<TelegrafMetricsPusher>,
    ports: Option<Vec<u16>>,
}

impl TcpModule {
    pub fn new(sink: Arc<TelegrafMetricsPusher>, ports: Option<Vec<u16>>) -> Self {
        Self { sink, ports }
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
            ProbeEvent::TcpProbe(e) => self.sink.push_tcp_probe(e),
            ProbeEvent::TcpRetransmitSkb(e) => self.sink.push_tcp_retransmit_skb(e),
            ProbeEvent::TcpSendReset(e) => self.sink.push_tcp_send_reset(e),
            ProbeEvent::TcpReceiveReset(e) => self.sink.push_tcp_receive_reset(e),
            _ => {}
        }
    }
}
