use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_probe_read_kernel, bpf_probe_read_user_buf};
use aya_ebpf::macros::map;
use aya_ebpf::maps::{HashMap, PerCpuArray, RingBuf};
use aya_ebpf::programs::ProbeContext;
use metis_common::KProbeChunk;

const SOCK_DPORT_OFFSET: usize = 6;

// struct msghdr offsets (x86_64, Linux 6.x)
const MSG_ITER: usize = 16;

// struct iov_iter offsets (relative to msghdr base)
const ITER_TYPE_OFF: usize       = MSG_ITER;      // u8  iter_type   @ 16
const ITER_IOV_OFFSET_OFF: usize = MSG_ITER + 8;  // usize iov_offset @ 24
const ITER_PTR_OFF: usize        = MSG_ITER + 16; // ptr               @ 32
const ITER_COUNT_OFF: usize      = MSG_ITER + 24; // size_t count      @ 40

// iter_type enum values (Linux 6.x)
const ITER_UBUF:  u8 = 0;
const ITER_IOVEC: u8 = 1;

const IOVEC_BASE_OFF: usize = 0;

const MAX_PAYLOAD: usize = 1024;

#[map(name = "TCP_SENDMSG_PORTS")]
static mut PORTS: HashMap<u16, u8> =
    HashMap::with_max_entries(100, aya_ebpf::bindings::BPF_F_RDONLY_PROG);

// Per-CPU scratch avoids putting MAX_PAYLOAD bytes on the 512-byte BPF stack.
#[map(name = "TCP_SENDMSG_SCRATCH")]
static mut SCRATCH: PerCpuArray<KProbeChunk> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "TCP_SENDMSG_RINGBUF")]
pub static mut TCP_SENDMSG_RINGBUF: RingBuf = RingBuf::with_byte_size(512 * 1024, 0);

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

    // ── Read iov_iter fields ──────────────────────────────────────────────────
    let iter_type: u8 = unsafe {
        bpf_probe_read_kernel(msg.add(ITER_TYPE_OFF) as *const u8)
    }
    .map_err(|_| 1u32)?;

    let iov_offset: usize = unsafe {
        bpf_probe_read_kernel(msg.add(ITER_IOV_OFFSET_OFF) as *const usize)
    }
    .map_err(|_| 1u32)?;

    let count: usize = unsafe {
        bpf_probe_read_kernel(msg.add(ITER_COUNT_OFF) as *const usize)
    }
    .map_err(|_| 1u32)?;

    if count == 0 {
        return Ok(0);
    }

    // ── Resolve the user-space data pointer ───────────────────────────────────
    let raw_ptr: u64 = unsafe {
        bpf_probe_read_kernel(msg.add(ITER_PTR_OFF) as *const u64)
    }
    .map_err(|_| 1u32)?;

    if raw_ptr == 0 {
        return Ok(0);
    }

    let data_ptr: *const u8 = match iter_type {
        ITER_UBUF => (raw_ptr as usize + iov_offset) as *const u8,
        ITER_IOVEC => {
            let iov_base: u64 = unsafe {
                bpf_probe_read_kernel((raw_ptr as usize + IOVEC_BASE_OFF) as *const u64)
            }
            .map_err(|_| 1u32)?;
            if iov_base == 0 {
                return Ok(0);
            }
            (iov_base as usize + iov_offset) as *const u8
        }
        _ => return Ok(0),
    };

    // ── Read payload into per-CPU scratch (no stack allocation) ───────────────
    #[allow(static_mut_refs)]
    let scratch = unsafe { SCRATCH.get_ptr_mut(0) }.ok_or(1u32)?;

    let read_len = count.min(MAX_PAYLOAD);

    unsafe {
        (*scratch).session_id = bpf_get_current_pid_tgid();
        (*scratch).dest_port = port;
        (*scratch).complete = true;
        (*scratch).len = read_len as u16;
        // bpf_probe_read_user_buf writes directly into map memory.
        let _ = bpf_probe_read_user_buf(data_ptr, &mut (&mut (*scratch).data)[..read_len]);
    }

    unsafe {
        #[allow(static_mut_refs)]
        let _ = TCP_SENDMSG_RINGBUF.output::<KProbeChunk>(&*scratch, 0);
    }

    Ok(0)
}
