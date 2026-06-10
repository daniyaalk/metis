use crate::modules::Module;
use crate::probes::ProbeRequirement;

pub struct HttpModule;

impl Module for HttpModule {
    fn name(&self) -> String {
        "mysql".to_string()
    }

    fn required_probes(&self) -> Vec<ProbeRequirement> {
        vec![ProbeRequirement::TcpSendMsg{dest_ports: vec![80]}]
    }
}