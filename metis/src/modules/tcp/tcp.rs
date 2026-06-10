use crate::modules::Module;
use crate::probes::ProbeRequirement;

pub struct TcpModule;


impl Module for TcpModule {
    fn name(&self) -> String { todo!() }

    fn required_probes(&self) -> Vec<ProbeRequirement> {
        vec![ProbeRequirement::TcpProbe]
    }
}