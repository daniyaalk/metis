use crate::probes::tracepoints::tcp_probe::ReadableTCPProbeEvent;
use crate::probes::tracepoints::tcp_receive_reset::ReadableTcpReceiveResetEvent;
use crate::probes::tracepoints::tcp_retransmit_skb::ReadableTCPRetransmitSkbEvent;
use crate::probes::tracepoints::tcp_send_reset::ReadableTcpSendResetEvent;

pub mod kprobes;
pub mod tracepoints;

/// What a module needs from the probe layer.
/// `dest_ports: None` means receive events for all ports (no port filter).
#[derive(Clone)]
pub enum ProbeRequirement {
    TcpSendMsg { dest_ports: Option<Vec<u16>> },
    TcpProbe { dest_ports: Option<Vec<u16>> },
    TcpRetransmitSkb { dest_ports: Option<Vec<u16>> },
    TcpSendReset { dest_ports: Option<Vec<u16>> },
    TcpReceiveReset { dest_ports: Option<Vec<u16>> },
    /// Fires when the first response packet arrives on a tracked socket.
    /// Filtering is implicit via QUERY_START_TIMES (populated by TcpSendMsg).
    SockDefReadable { dest_ports: Option<Vec<u16>> },
}

/// Probe identity without payload — used as the routing table key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProbeType {
    TcpSendMsg,
    TcpProbe,
    TcpRetransmitSkb,
    TcpSendReset,
    TcpReceiveReset,
    SockDefReadable,
}

/// A fully-decoded, module-ready event.
#[derive(Clone, Debug)]
pub enum ProbeEvent {
    TcpProbe(ReadableTCPProbeEvent),
    TcpRetransmitSkb(ReadableTCPRetransmitSkbEvent),
    TcpSendReset(ReadableTcpSendResetEvent),
    TcpReceiveReset(ReadableTcpReceiveResetEvent),
    /// Reassembled payload from one or more `KProbeChunk`s.
    TcpSendMsg { dest_ip: [u8; 16], ip_family: u8, dest_port: u16, socket_ptr: u64, timestamp_ns: u64, payload: Vec<u8> },
    /// First inbound packet on a tracked socket; correlate with TcpSendMsg via socket_ptr.
    SockDefReadable { socket_ptr: u64, timestamp_ns: u64 },
}

impl ProbeEvent {
    pub fn probe_type(&self) -> ProbeType {
        match self {
            ProbeEvent::TcpProbe(_) => ProbeType::TcpProbe,
            ProbeEvent::TcpRetransmitSkb(_) => ProbeType::TcpRetransmitSkb,
            ProbeEvent::TcpSendReset(_) => ProbeType::TcpSendReset,
            ProbeEvent::TcpReceiveReset(_) => ProbeType::TcpReceiveReset,
            ProbeEvent::TcpSendMsg { .. } => ProbeType::TcpSendMsg,
            ProbeEvent::SockDefReadable { .. } => ProbeType::SockDefReadable,
        }
    }

    pub fn dest_port(&self) -> Option<u16> {
        match self {
            ProbeEvent::TcpProbe(e) => Some(e.dest_port),
            ProbeEvent::TcpRetransmitSkb(e) => Some(e.destination_port),
            ProbeEvent::TcpSendReset(e) => Some(e.dst_port),
            ProbeEvent::TcpReceiveReset(e) => Some(e.dport),
            ProbeEvent::TcpSendMsg { dest_port, .. } => Some(*dest_port),
            ProbeEvent::SockDefReadable { .. } => None,
        }
    }
}
