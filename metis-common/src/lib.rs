#![no_std]

// pub enum TCPTracePoint {
//     Probe(),
//     RetransmitSyn(),
//     RetransmitSynAck(),
//     ReceiveReset(),
//     SendReset(),
// }

#[repr(C)]
#[derive(Debug)]
pub struct TCPEvent {
    pub pid: u32,
    pub tgid: u32,
    pub ctx_buf: [u8; 150],
}
