use aya_ebpf::helpers::{bpf_probe_read_kernel, bpf_probe_read_kernel_buf};
use aya_ebpf::macros::map;
use aya_ebpf::maps::{Array, HashMap, PerCpuArray, RingBuf};
use aya_ebpf::programs::ProbeContext;
use aya_log_ebpf::{debug, info, warn};
use metis_common::{UdpLayout, UdpPacketEvent};

const MAX_DNS_PAYLOAD: usize = 512;

/// Port filter keyed by UDP source port.
/// Insert key 0 as a wildcard sentinel to capture all ports.
#[map(name = "UDP_RECVMSG_PORTS")]
static mut PORTS: HashMap<u16, u8> =
    HashMap::with_max_entries(64, aya_ebpf::bindings::BPF_F_RDONLY_PROG);

#[map(name = "UDP_LAYOUT")]
static mut UDP_LAYOUT: Array<UdpLayout> = Array::with_max_entries(1, 0);

#[map(name = "UDP_RECVMSG_SCRATCH")]
static mut SCRATCH: PerCpuArray<UdpPacketEvent> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "UDP_RECVMSG_RINGBUF")]
pub static mut UDP_RECVMSG_RINGBUF: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Shared handler for udp_recvmsg and udpv6_recvmsg kprobes.
pub fn handle(ctx: ProbeContext) -> Result<u32, u32> {
    let sk: *const u8 = ctx.arg(0).ok_or(0u32)?;

    #[allow(static_mut_refs)]
    let layout: UdpLayout = match unsafe { UDP_LAYOUT.get(0) }.copied() {
        Some(l) => l,
        None => {
            warn!(&ctx, "udp_recvmsg: UDP_LAYOUT not populated");
            return Ok(0);
        }
    };

    // debug!(
    //     &ctx,
    //     "udp_recvmsg: sk={:x} sq_off={} data_off={}",
    //     sk as u64,
    //     layout.sk_receive_queue_off as u64,
    //     layout.skb_data_off as u64,
    // );

    // sk->sk_receive_queue is a struct sk_buff_head embedded in struct sock.
    // Its first field (next) is a *sk_buff pointing to the first queued packet,
    // or back to itself (the head) when the queue is empty.
    let sq_addr = sk as u64 + layout.sk_receive_queue_off as u64;
    let skb_ptr: u64 = match unsafe { bpf_probe_read_kernel(sq_addr as *const u64) } {
        Ok(v) => v,
        Err(_) => {
            warn!(&ctx, "udp_recvmsg: failed to read sk_receive_queue at {:x}", sq_addr);
            return Ok(0);
        }
    };

    // debug!(&ctx, "udp_recvmsg: sq_addr={:x} skb_ptr={:x}", sq_addr, skb_ptr);

    if skb_ptr == 0 || skb_ptr == sq_addr {
        // debug!(&ctx, "udp_recvmsg: receive queue empty (sentinel={:x})", sq_addr);
        return Ok(0);
    }

    // skb->data points to the start of the UDP header for received packets.
    let data_ptr: u64 = match unsafe {
        bpf_probe_read_kernel((skb_ptr + layout.skb_data_off as u64) as *const u64)
    } {
        Ok(v) => v,
        Err(_) => {
            warn!(&ctx, "udp_recvmsg: failed to read skb->data from skb={:x}", skb_ptr);
            return Ok(0);
        }
    };

    debug!(&ctx, "udp_recvmsg: skb={:x} data={:x}", skb_ptr, data_ptr);

    if data_ptr == 0 {
        warn!(&ctx, "udp_recvmsg: skb->data is NULL");
        return Ok(0);
    }

    // udp_csum_pull_header() calls __skb_pull(skb, sizeof(udphdr)) before queuing,
    // so skb->data already points to the UDP payload (DNS message). The 8-byte
    // UDP header still lives in the headroom at [data_ptr - 8 .. data_ptr).
    let udp_hdr_ptr = data_ptr - 8;
    let src_port_be: u16 = match unsafe { bpf_probe_read_kernel(udp_hdr_ptr as *const u16) } {
        Ok(v) => v,
        Err(_) => {
            warn!(&ctx, "udp_recvmsg: failed to read UDP src_port from udp_hdr={:x}", udp_hdr_ptr);
            return Ok(0);
        }
    };
    let src_port = u16::from_be(src_port_be);

    let dst_port_be: u16 =
        unsafe { bpf_probe_read_kernel((udp_hdr_ptr + 2) as *const u16) }.unwrap_or(0);
    let dst_port = u16::from_be(dst_port_be);

    debug!(
        &ctx,
        "udp_recvmsg: src_port={} dst_port={}",
        src_port as u32,
        dst_port as u32,
    );

    // Apply port filter; key 0 = wildcard (all ports pass).
    #[allow(static_mut_refs)]
    if unsafe { PORTS.get(0).is_none() && PORTS.get(&src_port).is_none() } {
        debug!(&ctx, "udp_recvmsg: src_port={} not in filter, skipping", src_port as u32);
        return Ok(0);
    }

    info!(
        &ctx,
        "udp_recvmsg: matched src_port={} dst_port={} data={:x}",
        src_port as u32,
        dst_port as u32,
        data_ptr,
    );

    #[allow(static_mut_refs)]
    let scratch = unsafe { SCRATCH.get_ptr_mut(0) }.ok_or(0u32)?;

    // skb->data already points to the DNS payload (UDP header was pulled off).
    let payload_ptr = data_ptr as *const u8;

    let read_ok;
    unsafe {
        (*scratch).src_port = src_port;
        (*scratch)._pad = [0; 4];
        read_ok = bpf_probe_read_kernel_buf(
            payload_ptr,
            &mut (&mut (*scratch).data)[..MAX_DNS_PAYLOAD],
        )
        .is_ok();
        (*scratch).len = if read_ok { MAX_DNS_PAYLOAD as u16 } else { 0 };
    }

    if read_ok {
        // Log the first 8 bytes of the DNS message: transaction ID, flags,
        // question count, answer count — enough to confirm real DNS traffic.
        unsafe {
            let b0 = (*scratch).data[0] as u32;
            let b1 = (*scratch).data[1] as u32;
            let b2 = (*scratch).data[2] as u32;
            let b3 = (*scratch).data[3] as u32;
            let b4 = (*scratch).data[4] as u32;
            let b5 = (*scratch).data[5] as u32;
            let b6 = (*scratch).data[6] as u32;
            let b7 = (*scratch).data[7] as u32;
            let txid  = (b0 << 8) | b1;
            let flags = (b2 << 8) | b3;
            let qdcnt = (b4 << 8) | b5;
            let ancnt = (b6 << 8) | b7;
            info!(
                &ctx,
                "udp_recvmsg: DNS txid={:x} flags={:x} qd={} an={}",
                txid, flags, qdcnt, ancnt,
            );
        }

        #[allow(static_mut_refs)]
        unsafe {
            let _ = UDP_RECVMSG_RINGBUF.output::<UdpPacketEvent>(&*scratch, 0);
        }
    } else {
        warn!(&ctx, "udp_recvmsg: payload read failed for src_port={}", src_port as u32);
    }

    Ok(0)
}
