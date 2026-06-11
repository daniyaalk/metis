use crate::modules::Module;
use crate::probes::{ProbeEvent, ProbeRequirement};

pub struct HttpModule;

impl Module for HttpModule {
    fn name(&self) -> &'static str {
        "http"
    }

    fn required_probes(&self) -> Vec<ProbeRequirement> {
        vec![ProbeRequirement::TcpSendMsg {
            dest_ports: Some(vec![80]),
        }]
    }

    fn on_event(&mut self, event: &ProbeEvent) {
        if let ProbeEvent::TcpSendMsg { dest_port, payload, .. } = event {
            let text = String::from_utf8_lossy(payload);
            log::info!(
                "[http] port={} len={} data={:?}",
                dest_port,
                payload.len(),
                &text,
            );
        }
    }
}

