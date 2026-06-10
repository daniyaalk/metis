use crate::modules::Module;
use crate::probes::ProbeRequirement;

pub struct HttpModule;

impl Module for HttpModule {
    fn name(&self) -> String {
        "mysql".to_string()
    }

    fn required_probes(&self) -> Vec<ProbeRequirement> {
        vec![ProbeRequirement::TcpRetransmitSkb {
            dest_ports: vec![80, 443],
        }]
    }
}
