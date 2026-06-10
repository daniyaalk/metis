#![no_std]

// pub enum TCPTracePoint {
//     Probe(),
//     RetransmitSyn(),
//     RetransmitSynAck(),
//     ReceiveReset(),
//     SendReset(),
// }


#[repr(C)]
pub enum EventType {
    TcpProbe(Event),
    MysqlProbe(Event),

}


#[repr(C)]
pub struct Event {
    pub complete: bool,
    pub data: [u8; 100],
}

#[repr(C)]
#[derive(Debug)]
pub struct TCPEvent {
    pub pid: u32,
    pub tgid: u32,
    pub ctx_buf: [u8; 150],
}
