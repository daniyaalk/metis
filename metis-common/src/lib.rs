#![no_std]

/// Emitted by tracepoints — always one self-contained event per kernel firing.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TCPProbeEvent {
    pub pid: u32,
    pub tgid: u32,
    pub ctx_buf: [u8; 150],
}

/// Emitted by kprobes. Due to the 512-byte eBPF stack limit, large payloads
/// are split across multiple chunks sharing the same `session_id`. The final
/// (or only) chunk carries `complete == true`. Userspace must concatenate all
/// chunks for a session before dispatching the completed event.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KProbeChunk {
    /// Links chunks belonging to the same logical event (e.g. `pid_tgid`).
    pub session_id: u64,
    /// Destination port — present on every chunk so routing can start early.
    pub dest_port: u16,
    /// True when this is the last (or only) chunk for this session.
    pub complete: bool,
    /// Number of valid bytes in `data`.
    pub len: u16,
    pub data: [u8; 1024],
}
