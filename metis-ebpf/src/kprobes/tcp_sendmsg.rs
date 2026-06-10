use aya_ebpf::helpers::bpf_probe_read_kernel;
use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;
use aya_ebpf::programs::ProbeContext;
use aya_log_ebpf::info;

const DPORT_OFFSET: usize = 6;

#[map(name = "TCP_SENDMSG_PORTS")]
static mut PORTS: HashMap<u16, u8> =
    HashMap::with_max_entries(100, aya_ebpf::bindings::BPF_F_RDONLY_PROG);

pub fn tcp_sendmsg(ctx: ProbeContext) -> Result<u32, u32> {
    let sock: *const u16 = ctx.arg(0).ok_or(1u32)?;

    let val = unsafe { bpf_probe_read_kernel(sock.add(DPORT_OFFSET)) };

    if val.is_err() {
        info!(&ctx, "out of bounds");
        return Err(0);
    }

    let val = u16::from_be(val.unwrap());

    #[allow(static_mut_refs)]
    if unsafe { PORTS.get(val) }.is_none() {
        return Ok(0);
    }

    info!(&ctx, "mysql probe: {}", val);

    // if val == 3306 {
    //     info!(&ctx, "Saw mysql packet!");
    // }

    Ok(0)
}
