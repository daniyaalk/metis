use crate::probes::ProbeRequirement;

pub mod mysql;
pub mod http;


pub trait Module {
    fn name(&self) -> String;
    fn required_probes(&self) -> Vec<ProbeRequirement>;
}