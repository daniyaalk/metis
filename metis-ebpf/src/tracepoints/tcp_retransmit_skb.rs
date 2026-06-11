use aya_ebpf::macros::map;
use aya_ebpf::maps::{HashMap, RingBuf};
use aya_ebpf::programs::TracePointContext;
use metis_common::TCPProbeEvent;

#[map(name = "TCP_RETRANSMIT_SKB_PORTS")]
static mut PORTS: HashMap<u16, u8> =
    HashMap::with_max_entries(100, aya_ebpf::bindings::BPF_F_RDONLY_PROG);

#[map(name = "TCP_RETRANSMIT_SKB_RINGBUF")]
pub static mut TCP_RETRANSMIT_SKB_RINGBUF: RingBuf = RingBuf::with_byte_size(1024 * 64, 0);

pub fn tcp_retransmit_skb(ctx: TracePointContext) -> Result<u32, u32> {
    if let Ok(buf) = unsafe { ctx.read_at::<[u8; 150]>(0) } {
        let port: u16 = u16::from_ne_bytes(buf[30..32].try_into().unwrap());

        #[allow(static_mut_refs)]
        if unsafe { PORTS.get(0).is_none() && PORTS.get(&port).is_none() } {
            return Ok(0);
        }

        let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();

        unsafe {
            #[allow(static_mut_refs)]
            let _ = TCP_RETRANSMIT_SKB_RINGBUF.output::<TCPProbeEvent>(
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
