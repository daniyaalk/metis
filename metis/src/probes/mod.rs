use crate::probes::tracepoints::tcp_probe::ReadableTCPProbeEvent;
use crate::probes::tracepoints::tcp_receive_reset::ReadableTcpReceiveResetEvent;
use crate::probes::tracepoints::tcp_retransmit_skb::ReadableTCPRetransmitSkbEvent;
use crate::probes::tracepoints::tcp_send_reset::ReadableTcpSendResetEvent;
use aya::Ebpf;
use metis_common::TCPProbeEvent;

pub mod kprobes;
pub mod tracepoints;

pub enum ProbeRequirement {
    TcpSendMsg { dest_ports: Vec<u16> },

    TcpProbe,

    TcpRetransmitSkb { dest_ports: Vec<u16> },

    TcpReceiveReset { dest_ports: Vec<u16> },

    TcpSendReset,

    TcpRecvMsg,

    MysqlQuery,
}

pub enum ProbeEvent {
    TcpProbe(ReadableTCPProbeEvent),
    TcpRetransmitSkb(ReadableTCPRetransmitSkbEvent),
    TcpSendReset(ReadableTcpSendResetEvent),
    TcpReceiveReset(ReadableTcpReceiveResetEvent),
}

pub trait Probe {
    fn load(&self, ebpf: &mut Ebpf) -> Result<(), ()>;

    fn get_event_stream<F>(&self, _ebpf: &mut Ebpf, _callback: F)
    where
        F: Fn(&ProbeEvent) + Send + Sync + 'static,
    {
    }
}
