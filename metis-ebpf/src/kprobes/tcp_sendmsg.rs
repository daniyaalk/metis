use aya_ebpf::helpers::{
    bpf_get_prandom_u32, bpf_ktime_get_ns, bpf_probe_read_kernel, bpf_probe_read_kernel_buf,
    bpf_probe_read_user_buf,
};
use aya_ebpf::macros::map;
use aya_ebpf::maps::{Array, HashMap, LruHashMap, PerCpuArray, RingBuf};
use aya_ebpf::programs::ProbeContext;
use aya_log_ebpf::debug;
use metis_common::{IovLayout, KProbeChunk, SockLayout};

const SOCK_DPORT_OFFSET: usize = 6; // sock.add(6) = byte offset 12 = skc_dport
const SOCK_FAMILY_OFFSET: usize = 8; // sock.add(8) = byte offset 16 = skc_family

const AF_INET:  u16 = 2;
const AF_INET6: u16 = 10;

const IOVEC_BASE_OFF: usize = 0;
const MAX_PAYLOAD: usize = 1024;

const KERNEL_ADDR_THRESHOLD: u64 = 0xffff_0000_0000_0000;

#[map(name = "TCP_SENDMSG_PORTS")]
static mut PORTS: HashMap<u16, u8> =
    HashMap::with_max_entries(100, aya_ebpf::bindings::BPF_F_RDONLY_PROG);

#[map(name = "TCP_SENDMSG_SCRATCH")]
static mut SCRATCH: PerCpuArray<KProbeChunk> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "TCP_SENDMSG_RINGBUF")]
pub static mut TCP_SENDMSG_RINGBUF: RingBuf = RingBuf::with_byte_size(512 * 1024, 0);

#[map(name = "TRACKED_SOCKETS")]
pub static mut TRACKED_SOCKETS: LruHashMap<u64, u8> = LruHashMap::with_max_entries(8192, 0);

#[map(name = "TCP_SENDMSG_SAMPLE_RATE")]
static mut SAMPLE_RATE: Array<u32> = Array::with_max_entries(1, 0);

/// iov_iter field offsets (bytes from msghdr base), populated by userspace from BTF at startup.
#[map(name = "IOV_LAYOUT")]
static mut IOV_LAYOUT: Array<IovLayout> = Array::with_max_entries(1, 0);

/// sock_common field offsets, populated by userspace from BTF at startup.
#[map(name = "SOCK_LAYOUT")]
static mut SOCK_LAYOUT: Array<SockLayout> = Array::with_max_entries(1, 0);

pub fn tcp_sendmsg(ctx: ProbeContext) -> Result<u32, u32> {
    let sock: *const u16 = ctx.arg(0).ok_or(1u32)?;
    let msg: *const u8 = ctx.arg(1).ok_or(1u32)?;

    // ── Port filter ───────────────────────────────────────────────────────────
    let port_raw =
        unsafe { bpf_probe_read_kernel(sock.add(SOCK_DPORT_OFFSET)) }.map_err(|_| 1u32)?;
    let port = u16::from_be(port_raw);

    #[allow(static_mut_refs)]
    if unsafe { PORTS.get(0).is_none() && PORTS.get(&port).is_none() } {
        return Ok(0);
    }

    // ── Sampling ──────────────────────────────────────────────────────────────
    #[allow(static_mut_refs)]
    let threshold = unsafe { SAMPLE_RATE.get(0).copied().unwrap_or(u32::MAX) };
    if threshold < u32::MAX && unsafe { bpf_get_prandom_u32() } > threshold {
        return Ok(0);
    }

    // ── Read destination IP from sock_common ──────────────────────────────────
    let family: u16 =
        unsafe { bpf_probe_read_kernel(sock.add(SOCK_FAMILY_OFFSET)) }.unwrap_or(0);

    let (dest_ip, ip_family) = if family == AF_INET {
        // skc_daddr is __be32 at byte offset 0; read as raw bytes to preserve network order.
        let v4: [u8; 4] =
            unsafe { bpf_probe_read_kernel(sock as *const [u8; 4]) }.unwrap_or([0u8; 4]);
        let mut ip = [0u8; 16];
        ip[0] = v4[0]; ip[1] = v4[1]; ip[2] = v4[2]; ip[3] = v4[3];
        (ip, 4u8)
    } else if family == AF_INET6 {
        #[allow(static_mut_refs)]
        let sock_layout: SockLayout = unsafe { SOCK_LAYOUT.get(0) }.copied().ok_or(1u32)?;
        let v6_off = sock_layout.v6_daddr_off as usize;
        let v6: [u8; 16] = unsafe {
            bpf_probe_read_kernel((sock as *const u8).add(v6_off) as *const [u8; 16])
        }.unwrap_or([0u8; 16]);
        (v6, 6u8)
    } else {
        ([0u8; 16], 0u8)
    };

    // ── Load iov_iter layout (populated by userspace from BTF at startup) ─────
    #[allow(static_mut_refs)]
    let layout: IovLayout = unsafe { IOV_LAYOUT.get(0) }.copied().ok_or(1u32)?;
    let iter_type_off  = layout.iter_type_off  as usize;
    let iov_offset_off = layout.iov_offset_off as usize;
    let count_off      = layout.count_off      as usize;
    let ptr_off        = layout.ptr_off        as usize;
    let iter_iovec     = layout.iter_iovec;
    let iter_ubuf      = layout.iter_ubuf;

    // ── Read iov_iter fields ──────────────────────────────────────────────────
    let iter_type: u8 = unsafe {
        bpf_probe_read_kernel(msg.add(iter_type_off) as *const u8)
    }
    .map_err(|_| 1u32)?;

    let iov_offset: usize = unsafe {
        bpf_probe_read_kernel(msg.add(iov_offset_off) as *const usize)
    }
    .map_err(|_| 1u32)?;

    let count: usize = unsafe {
        bpf_probe_read_kernel(msg.add(count_off) as *const usize)
    }
    .map_err(|_| 1u32)?;

    if count == 0 {
        return Ok(0);
    }

    // ── Resolve the data pointer ──────────────────────────────────────────────
    let raw_ptr: u64 = unsafe {
        bpf_probe_read_kernel(msg.add(ptr_off) as *const u64)
    }
    .map_err(|_| 1u32)?;

    if raw_ptr == 0 {
        return Ok(0);
    }

    let data_ptr: *const u8 = if iter_type == iter_ubuf {
        (raw_ptr as usize + iov_offset) as *const u8
    } else if iter_type == iter_iovec {
        let iov_base: u64 = unsafe {
            bpf_probe_read_kernel((raw_ptr as usize + IOVEC_BASE_OFF) as *const u64)
        }
        .map_err(|_| 1u32)?;
        if iov_base == 0 {
            return Ok(0);
        }
        (iov_base as usize + iov_offset) as *const u8
    } else {
        return Ok(0);
    };

    // ── Read payload into per-CPU scratch (no stack allocation) ───────────────
    #[allow(static_mut_refs)]
    let scratch = unsafe { SCRATCH.get_ptr_mut(0) }.ok_or(1u32)?;

    let read_len = count.min(MAX_PAYLOAD);

    let read_ok: bool;
    let data_addr = data_ptr as u64;
    unsafe {
        (*scratch).socket_ptr = sock as u64;
        (*scratch).timestamp_ns = bpf_ktime_get_ns();
        (*scratch).dest_ip = dest_ip;
        (*scratch).dest_port = port;
        (*scratch).ip_family = ip_family;
        (*scratch).complete = true;
        read_ok = if data_addr >= KERNEL_ADDR_THRESHOLD {
            bpf_probe_read_kernel_buf(data_ptr, &mut (&mut (*scratch).data)[..read_len]).is_ok()
        } else {
            bpf_probe_read_user_buf(data_ptr, &mut (&mut (*scratch).data)[..read_len]).is_ok()
        };
        (*scratch).len = if read_ok { read_len as u16 } else { 0 };
    }

    debug!(
        &ctx,
        "tcp_sendmsg: family={} iter={} cnt={} off={} ptr={:x} ok={}",
        family,
        iter_type,
        count as u64,
        iov_offset as u64,
        data_addr,
        read_ok as u8,
    );

    unsafe {
        #[allow(static_mut_refs)]
        let _ = TCP_SENDMSG_RINGBUF.output::<KProbeChunk>(&*scratch, 0);
        #[allow(static_mut_refs)]
        let _ = TRACKED_SOCKETS.insert(&(sock as u64), &1u8, 0);
    }

    Ok(0)
}
