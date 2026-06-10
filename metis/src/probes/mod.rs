use crate::probes::tracepoints::tcp_probe::ReadableTCPProbeEvent;
use aya::Ebpf;
use metis_common::TCPProbeEvent;
use crate::probes::tracepoints::tcp_retransmit_skb::ReadableTCPRetransmitSkbEvent;

pub mod kprobes;
pub mod tracepoints;

pub enum ProbeRequirement {
    TcpSendMsg { dest_ports: Vec<u16> },

    TcpProbe,

    TcpRetransmitSkb { dest_ports: Vec<u16> },

    TcpReceiveReset  { dest_ports: Vec<u16> },

    TcpSendReset  { dest_ports: Vec<u16> },

    TcpRecvMsg,

    MysqlQuery,
}

pub enum ProbeEvent {
    TcpProbe(ReadableTCPProbeEvent),
    TcpRetransmitSkb(ReadableTCPRetransmitSkbEvent),
}

pub trait Probe {
    fn load(&self, ebpf: &mut Ebpf) -> Result<(), ()>;

    fn get_event_stream<F>(&self, _ebpf: &mut Ebpf, _callback: F)
    where
        F: Fn(&ProbeEvent) + Send + Sync + 'static,
    {
    }
}
