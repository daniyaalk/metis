use aya_ebpf::helpers::bpf_ktime_get_ns;
use aya_ebpf::macros::map;
use aya_ebpf::maps::RingBuf;
use aya_ebpf::programs::ProbeContext;
use metis_common::TcpResponseEvent;

use crate::kprobes::tcp_sendmsg::TRACKED_SOCKETS;

#[map(name = "LATENCY_RINGBUF")]
pub static mut LATENCY_RINGBUF: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

pub fn sock_def_readable(ctx: ProbeContext) -> Result<u32, u32> {
    let sk: *const u8 = ctx.arg(0).ok_or(0u32)?;
    let sk_ptr = sk as u64;

    // Only emit for sockets where we saw an outbound sampled query.
    #[allow(static_mut_refs)]
    if unsafe { TRACKED_SOCKETS.get(&sk_ptr).is_none() } {
        // trace!(&ctx, "sock_def_readable: skipping untracked socket {}", sk_ptr);
        return Ok(0);
    }

    // Remove first so a burst of readable events for the same response doesn't
    // emit duplicates — we only need the first packet's timestamp.
    #[allow(static_mut_refs)]
    unsafe { let _ = TRACKED_SOCKETS.remove(&sk_ptr); }

    #[allow(static_mut_refs)]
    unsafe {
        let _ = LATENCY_RINGBUF.output::<TcpResponseEvent>(
            &TcpResponseEvent { socket_ptr: sk_ptr, timestamp_ns: bpf_ktime_get_ns() },
            0,
        );
    }

    Ok(0)
}
