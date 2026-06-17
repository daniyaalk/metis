use aya_ebpf::helpers::{bpf_ktime_get_ns, bpf_probe_read_kernel, bpf_probe_read_kernel_buf};
use aya_ebpf::macros::map;
use aya_ebpf::maps::{Array, RingBuf};
use aya_ebpf::programs::ProbeContext;
use aya_log_ebpf::{debug, trace};
use metis_common::{TcpResponseEvent, UdpLayout};

use crate::kprobes::tcp_sendmsg::TRACKED_SOCKETS;

#[map(name = "LATENCY_RINGBUF")]
pub static mut LATENCY_RINGBUF: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Populated by userspace with sk_receive_queue and sk_buff.data byte offsets.
/// We reuse UdpLayout since the layout of struct sock and struct sk_buff is
/// identical for both TCP and UDP sockets.
#[map(name = "TCP_RESPONSE_LAYOUT")]
static mut TCP_RESPONSE_LAYOUT: Array<UdpLayout> = Array::with_max_entries(1, 0);

pub fn sock_def_readable(ctx: ProbeContext) -> Result<u32, u32> {
    let sk: *const u8 = ctx.arg(0).ok_or(0u32)?;
    let sk_ptr = sk as u64;

    // Only emit for sockets where we saw an outbound sampled query.
    #[allow(static_mut_refs)]
    if unsafe { TRACKED_SOCKETS.get(&sk_ptr).is_none() } {
        trace!(&ctx, "sock_def_readable: skipping untracked socket {:x}", sk_ptr);
        return Ok(0);
    }

    // Remove first so a burst of readable events for the same response doesn't
    // emit duplicates — we only need the first packet's timestamp.
    #[allow(static_mut_refs)]
    unsafe { let _ = TRACKED_SOCKETS.remove(&sk_ptr); }

    let mut event = TcpResponseEvent {
        socket_ptr: sk_ptr,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        data_len: 0,
        _pad: [0; 6],
        data: [0u8; 128],
    };

    // Peek the leading bytes of the TCP payload from the receive queue.
    // After tcp_rcv_established strips the TCP header (via __skb_pull),
    // skb->data in sk->sk_receive_queue points directly to application data.
    #[allow(static_mut_refs)]
    if let Some(layout) = unsafe { TCP_RESPONSE_LAYOUT.get(0) }.copied() {
        let sq_addr = sk_ptr + layout.sk_receive_queue_off as u64;
        if let Ok(skb_ptr) = unsafe { bpf_probe_read_kernel::<u64>(sq_addr as *const u64) } {
            // sq_addr itself is the sk_buff_head sentinel; a matching value means empty.
            if skb_ptr != 0 && skb_ptr != sq_addr {
                let data_field = skb_ptr + layout.skb_data_off as u64;
                if let Ok(data_ptr) =
                    unsafe { bpf_probe_read_kernel::<u64>(data_field as *const u64) }
                {
                    if data_ptr != 0 {
                        if unsafe {
                            bpf_probe_read_kernel_buf(data_ptr as *const u8, &mut event.data)
                        }
                        .is_ok()
                        {
                            event.data_len = event.data.len() as u16;
                        }
                    }
                }
            }
        }
    }

    debug!(
        &ctx,
        "sock_def_readable: socket={:x} data_len={}", sk_ptr, event.data_len as u32
    );

    #[allow(static_mut_refs)]
    unsafe {
        let _ = LATENCY_RINGBUF.output::<TcpResponseEvent>(&event, 0);
    }

    Ok(0)
}
