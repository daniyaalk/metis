#![no_std]
#![no_main]

use aya_ebpf::{macros::tracepoint, programs::TracePointContext};
use aya_log_ebpf::info;

enum RetransmitMode { SKB, SYNACK }

#[tracepoint]
pub fn tcp_retransmit_synack(ctx: TracePointContext) -> u32 {
    try_metis(ctx, RetransmitMode::SYNACK).unwrap_or_else(|ret| ret)
}

#[tracepoint]
pub fn tcp_retransmit_skb(ctx: TracePointContext) -> u32 {
    try_metis(ctx, RetransmitMode::SKB).unwrap_or_else(|ret| ret)
}
fn try_metis(ctx: TracePointContext, mode: RetransmitMode) -> Result<u32, u32> {
    match mode {
        RetransmitMode::SKB => info!(&ctx, "tcp_retransmit_skb"),
        RetransmitMode::SYNACK => info!(&ctx, "tcp_retransmit_synack"),
    }
    Ok(0)
}


#[tracepoint]
pub fn tcp_probe(ctx: TracePointContext) -> u32 {
    info!(&ctx, "tcp_probe");
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
