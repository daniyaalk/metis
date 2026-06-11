use aya_ebpf::macros::map;
use aya_ebpf::maps::RingBuf;
use aya_ebpf::programs::TracePointContext;
use metis_common::TCPProbeEvent;

#[map(name = "TCP_PROBE_RINGBUF")]
pub static mut TCP_PROBE_RINGBUF: RingBuf = RingBuf::with_byte_size(1024 * 64, 0);

pub fn tcp_probe(ctx: TracePointContext) -> Result<u32, u32> {
    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();

    if let Ok(buf) = unsafe { ctx.read_at::<[u8; 152]>(0) } {
        unsafe {
            #[allow(static_mut_refs)]
            let _ = TCP_PROBE_RINGBUF.output::<TCPProbeEvent>(
                &TCPProbeEvent {
                    pid: (pid_tgid >> 32) as u32,
                    tgid: pid_tgid as u32,
                    ctx_buf: buf,
                },
                0,
            );
        }
    }

    Ok(0)
}
