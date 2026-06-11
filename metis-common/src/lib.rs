#![no_std]

/// Emitted by tracepoints — always one self-contained event per kernel firing.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TCPProbeEvent {
    pub pid: u32,
    pub tgid: u32,
    // 152 bytes makes sizeof = 4+4+152 = 160, exactly divisible by 4 with no
    // trailing padding. Uninitialized padding bytes would fail the BPF verifier
    // when ringbuf.output reads the full sizeof(TCPProbeEvent) off the stack.
    pub ctx_buf: [u8; 152],
}

/// Emitted by sock_def_readable when the first inbound packet arrives on a
/// tracked socket. Userspace correlates with KProbeChunk via socket_ptr.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TcpResponseEvent {
    pub socket_ptr: u64,
    pub timestamp_ns: u64,
}

/// Emitted by kprobes. Due to the 512-byte eBPF stack limit, large payloads
/// are split across multiple chunks sharing the same `socket_ptr`. The final
/// (or only) chunk carries `complete == true`. Userspace must concatenate all
/// chunks for a session before dispatching the completed event.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KProbeChunk {
    /// Socket pointer — stable connection identifier, used for reassembly and
    /// for correlating with TcpResponseEvent in userspace.
    pub socket_ptr: u64,
    /// Kernel timestamp (bpf_ktime_get_ns) at the moment of the send.
    pub timestamp_ns: u64,
    /// Destination port — present on every chunk so routing can start early.
    pub dest_port: u16,
    /// True when this is the last (or only) chunk for this session.
    pub complete: bool,
    /// Number of valid bytes in `data`.
    pub len: u16,
    pub data: [u8; 1024],
}
