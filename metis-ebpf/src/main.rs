#![no_std]
#![no_main]

mod kprobes;

use aya_ebpf::macros::{kprobe, map};
use aya_ebpf::maps::RingBuf;
use aya_ebpf::{macros::tracepoint, programs::TracePointContext};
use aya_log_ebpf::info;
use aya_ebpf::programs::ProbeContext;
use metis_common::TCPEvent;

enum RetransmitMode {
    SKB,
    SYNACK,
}

#[map(name = "EVENTS")]
pub static mut EVENTS: RingBuf = RingBuf::with_byte_size(1024 * 256, 0);

// #[tracepoint]
// pub fn tcp_retransmit_synack(ctx: TracePointContext) -> u32 {
//     try_metis(ctx, RetransmitMode::SYNACK).unwrap_or_else(|ret| ret)
// }
//
// #[tracepoint]
// pub fn tcp_retransmit_skb(ctx: TracePointContext) -> u32 {
//     try_metis(ctx, RetransmitMode::SKB).unwrap_or_else(|ret| ret)
// }
// fn try_metis(ctx: TracePointContext, mode: RetransmitMode) -> Result<u32, u32> {
//     match mode {
//         RetransmitMode::SKB => info!(&ctx, "tcp_retransmit_skb"),
//         RetransmitMode::SYNACK => info!(&ctx, "tcp_retransmit_synack"),
//     }
//     Ok(0)
// }
//
// #[tracepoint]
// pub fn tcp_probe(ctx: TracePointContext) -> u32 {
//     let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
//
//     if let Ok(buf) = unsafe { ctx.read_at(0) } {
//         unsafe {
//             #[allow(static_mut_refs)]
//             let _ = EVENTS.output::<TCPEvent>(
//                 &TCPEvent {
//                     pid: (pid_tgid >> 32) as u32,
//                     tgid: pid_tgid as u32,
//                     ctx_buf: buf,
//                 },
//                 0,
//             );
//         }
//     } else {
//         info!(&ctx, "Unable to send event");
//     }
//
//     0
// }


#[kprobe]
pub fn tcp_sendmsg(ctx: ProbeContext) -> u32 {
    match kprobes::tcp_sendmsg::tcp_sendmsg(ctx) {
        Ok(ret) => 0,
        Err(ret) => 0,
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
