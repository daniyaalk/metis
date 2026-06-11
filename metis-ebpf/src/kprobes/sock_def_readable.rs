use aya_ebpf::helpers::bpf_ktime_get_ns;
use aya_ebpf::macros::map;
use aya_ebpf::maps::RingBuf;
use aya_ebpf::programs::ProbeContext;
use metis_common::TcpResponseEvent;

#[map(name = "LATENCY_RINGBUF")]
pub static mut LATENCY_RINGBUF: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

pub fn sock_def_readable(ctx: ProbeContext) -> Result<u32, u32> {
    let sk: *const u8 = ctx.arg(0).ok_or(0u32)?;

    #[allow(static_mut_refs)]
    unsafe {
        let _ = LATENCY_RINGBUF.output::<TcpResponseEvent>(
            &TcpResponseEvent {
                socket_ptr: sk as u64,
                timestamp_ns: bpf_ktime_get_ns(),
            },
            0,
        );
    }

    Ok(0)
}
