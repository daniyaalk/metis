use crate::modules::Module;
use crate::probes::{ProbeEvent, ProbeRequirement};

pub struct MysqlModule;

impl Module for MysqlModule {
    fn name(&self) -> &'static str {
        "mysql"
    }

    fn required_probes(&self) -> Vec<ProbeRequirement> {
        vec![ProbeRequirement::TcpSendMsg {
            dest_ports: Some(vec![3306]),
        }]
    }

    fn on_event(&mut self, event: &ProbeEvent) {
        if let ProbeEvent::TcpSendMsg { dest_port, payload } = event {
            let text = String::from_utf8_lossy(payload);
            log::info!(
                "[mysql] port={} len={} data={:?}",
                dest_port,
                payload.len(),
                &text
            );
        }
    }
}

