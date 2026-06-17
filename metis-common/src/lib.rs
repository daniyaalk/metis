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
    /// Number of valid bytes in `data`. 0 = receive-queue peek failed.
    pub data_len: u16,
    pub _pad: [u8; 6],
    /// First bytes of the TCP payload peeked from sk->sk_receive_queue.
    /// For MySQL, this is the raw MySQL packet (4-byte framing header + payload).
    pub data: [u8; 128],
}

/// Kernel field offsets for `iov_iter`, detected at startup from BTF.
/// Stored in the `IOV_LAYOUT` BPF map; all offsets are in bytes from `msghdr` base.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct IovLayout {
    pub iter_type_off:  u32,
    pub iov_offset_off: u32,
    pub count_off:      u32,
    pub ptr_off:        u32,
    pub iter_iovec:     u8,
    pub iter_ubuf:      u8,
    pub _pad:           u16,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for IovLayout {}

/// Kernel field offsets for `struct sock_common`, detected at startup from BTF.
/// Stored in the `SOCK_LAYOUT` BPF map.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SockLayout {
    /// Byte offset of `skc_v6_daddr` (`struct in6_addr`) from the start of `struct sock`.
    pub v6_daddr_off: u32,
    pub _pad: [u8; 4],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SockLayout {}

/// Kernel field offsets for the UDP receive path, detected at startup from BTF.
/// Stored in the `UDP_LAYOUT` BPF map.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct UdpLayout {
    /// Byte offset of `sk_receive_queue` (struct sk_buff_head) within `struct sock`.
    pub sk_receive_queue_off: u32,
    /// Byte offset of `data` (unsigned char *) within `struct sk_buff`.
    pub skb_data_off: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for UdpLayout {}

/// Emitted by the udp_recvmsg / udpv6_recvmsg kprobes for every inbound UDP
/// packet whose source port is in the configured filter.
/// `data[..len]` holds the UDP payload (UDP header already stripped).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UdpPacketEvent {
    /// Source port of the received packet (e.g. 53 for a DNS response).
    pub src_port: u16,
    /// Number of valid bytes in `data`.
    pub len: u16,
    /// 4 = IPv4, 6 = IPv6.
    pub ip_family: u8,
    pub _pad: [u8; 3],
    /// Destination IP of the received packet. IPv4 address in bytes [0..4]; IPv6 uses all 16.
    pub dest_ip: [u8; 16],
    pub data: [u8; 512],
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
    /// Destination IP address in network byte order.
    /// For IPv4 the first 4 bytes hold the address; remaining bytes are zero.
    /// For IPv6 all 16 bytes are used.
    pub dest_ip: [u8; 16],
    /// Destination port — present on every chunk so routing can start early.
    pub dest_port: u16,
    /// 4 = IPv4, 6 = IPv6, 0 = unknown/unread.
    pub ip_family: u8,
    /// True when this is the last (or only) chunk for this session.
    pub complete: bool,
    /// Number of valid bytes in `data`.
    pub len: u16,
    pub data: [u8; 1024],
}
