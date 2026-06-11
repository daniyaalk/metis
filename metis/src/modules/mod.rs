use crate::probes::{ProbeEvent, ProbeRequirement};

pub mod http;
pub mod mysql;
pub mod tcp;

pub trait Module: Send {
    fn name(&self) -> &'static str;
    fn required_probes(&self) -> Vec<ProbeRequirement>;
    fn on_event(&mut self, event: &ProbeEvent);
}
