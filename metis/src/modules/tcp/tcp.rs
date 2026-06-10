use crate::modules::Module;
use crate::probes::ProbeRequirement;

pub struct TcpModule;

impl Module for TcpModule {
    fn name(&self) -> String {
        todo!()
    }

    fn required_probes(&self) -> Vec<ProbeRequirement> {
        vec![
            ProbeRequirement::TcpProbe,
            ProbeRequirement::TcpRetransmitSkb {
                dest_ports: vec![0], // Port 0 is a sentinel key to disable port filtering.
            },
            ProbeRequirement::TcpSendReset {
                dest_ports: vec![0],
            },
            ProbeRequirement::TcpReceiveReset {
                dest_ports: vec![0],
            }
        ]
    }
}
