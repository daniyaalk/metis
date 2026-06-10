use aya::Ebpf;
use metis_common::TCPProbeEvent;
use crate::probes::tracepoints::tcp_probe::ReadableTCPProbeEvent;

pub mod kprobes;
pub mod tracepoints;

#[derive(Hash, Eq, PartialEq, Clone)]
pub enum ProbeRequirement {
    TcpSendMsg {
        dest_ports: Vec<u16>,
    },

    TcpProbe,

    TcpRetransmitSkb,

    TcpRecvMsg,

    MysqlQuery,


}

pub enum ProbeEvent {
    TcpProbe(ReadableTCPProbeEvent)
}


pub trait Probe {
    fn load(&self, ebpf: &mut Ebpf) -> Result<(), ()>;

    fn get_event_stream<F>(&self, _ebpf: &mut Ebpf, _callback: F)
    where F : Fn(&ProbeEvent)  + Send + Sync + 'static,
    {}

}