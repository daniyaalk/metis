use crate::modules::Module;
use crate::probes::ProbeRequirement;

pub struct MysqlModule;

impl Module for MysqlModule {
    fn name(&self) -> String {
        "mysql".to_string()
    }

    fn required_probes(&self) -> Vec<ProbeRequirement> {
        vec![ProbeRequirement::TcpSendMsg {
            dest_ports: vec![3306, 6033],
        }]
    }
}
