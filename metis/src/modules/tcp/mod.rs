use crate::modules::Module;
use crate::probes::{ProbeEvent, ProbeRequirement};
use crate::sink::telegraf::TelegrafMetricsPusher;
use std::sync::Arc;

pub struct TcpModule {
    sink: Arc<TelegrafMetricsPusher>,
}

impl TcpModule {
    pub fn new(sink: Arc<TelegrafMetricsPusher>) -> Self {
        Self { sink }
    }
}

impl Module for TcpModule {
    fn name(&self) -> &'static str {
        "tcp"
    }

    fn required_probes(&self) -> Vec<ProbeRequirement> {
        vec![
            ProbeRequirement::TcpProbe { dest_ports: None },
            ProbeRequirement::TcpRetransmitSkb { dest_ports: None },
            ProbeRequirement::TcpSendReset { dest_ports: None },
            ProbeRequirement::TcpReceiveReset { dest_ports: None },
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
