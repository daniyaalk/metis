use metis_common::IovLayout;

/// Detect `iov_iter` field offsets from the kernel's BTF type information.
/// Falls back to Linux 6.4+ defaults if BTF is unavailable or parsing fails.
pub fn detect_iov_layout() -> IovLayout {
    match try_detect() {
        Some(layout) => {
            log::info!(
                "iov_iter layout: iter_type@{} iov_offset@{} count@{} ptr@{} ITER_IOVEC={} ITER_UBUF={}",
                layout.iter_type_off, layout.iov_offset_off,
                layout.count_off, layout.ptr_off,
                layout.iter_iovec, layout.iter_ubuf,
            );
            layout
        }
        None => {
            log::warn!("BTF iov_iter detection failed; using Linux 6.4+ layout defaults");
            IovLayout {
                iter_type_off:  16,
                iov_offset_off: 24,
                count_off:      32,
                ptr_off:        40,
                iter_iovec:     0,
                iter_ubuf:      1,
                _pad:           0,
            }
        }
    }
}

fn try_detect() -> Option<IovLayout> {
    let data = std::fs::read("/sys/kernel/btf/vmlinux").ok()?;
    if data.len() < 24 { return None; }
    if u16::from_le_bytes([data[0], data[1]]) != 0xEB9F { return None; }

    let hdr_len  = u32_le(&data, 4)  as usize;
    let type_off = u32_le(&data, 8)  as usize;
    let type_len = u32_le(&data, 12) as usize;
    let str_off  = u32_le(&data, 16) as usize;
    let str_len  = u32_le(&data, 20) as usize;

    let ts = hdr_len + type_off;
    let ss = hdr_len + str_off;
    if ts + type_len > data.len() || ss + str_len > data.len() { return None; }

    let tb = &data[ts..ts + type_len];
    let sb = &data[ss..ss + str_len];

    let idx = build_index(tb);

    let msghdr_off   = find_struct(tb, sb, &idx, "msghdr")?;
    let iov_iter_off = find_struct(tb, sb, &idx, "iov_iter")?;

    let msg_iter_bits   = member_bit_off(tb, sb, &idx, msghdr_off,   "msg_iter",   0)?;
    let msg_iter_bytes  = (msg_iter_bits / 8) as u32;

    let iter_type_bits  = member_bit_off(tb, sb, &idx, iov_iter_off, "iter_type",  0)?;
    let iov_offset_bits = member_bit_off(tb, sb, &idx, iov_iter_off, "iov_offset", 0)?;
    let count_bits      = member_bit_off(tb, sb, &idx, iov_iter_off, "count",      0)?;

    // Try multiple historical names for the data pointer field
    let ptr_bits = member_bit_off(tb, sb, &idx, iov_iter_off, "ubuf",  0)
        .or_else(|| member_bit_off(tb, sb, &idx, iov_iter_off, "__iov", 0))
        .or_else(|| member_bit_off(tb, sb, &idx, iov_iter_off, "iov",   0))?;

    let (iter_iovec, iter_ubuf) = find_iter_enum_vals(tb, sb, &idx).unwrap_or_else(|| {
        // Infer from layout: new kernels have count before ptr
        if count_bits < ptr_bits { (0, 1) } else { (1, 0) }
    });

    Some(IovLayout {
        iter_type_off:  msg_iter_bytes + (iter_type_bits  / 8) as u32,
        iov_offset_off: msg_iter_bytes + (iov_offset_bits / 8) as u32,
        count_off:      msg_iter_bytes + (count_bits      / 8) as u32,
        ptr_off:        msg_iter_bytes + (ptr_bits        / 8) as u32,
        iter_iovec,
        iter_ubuf,
        _pad: 0,
    })
}

fn u32_le(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(data[off..off + 4].try_into().unwrap())
}

fn btf_str<'a>(sb: &'a [u8], off: usize) -> &'a str {
    if off >= sb.len() { return ""; }
    let end = sb[off..].iter().position(|&b| b == 0).map_or(sb.len(), |i| off + i);
    std::str::from_utf8(&sb[off..end]).unwrap_or("")
}

fn btf_kind(tb: &[u8], off: usize) -> u8 {
    ((u32_le(tb, off + 4) >> 24) & 0x1f) as u8
}

fn btf_vlen(tb: &[u8], off: usize) -> usize {
    (u32_le(tb, off + 4) & 0xffff) as usize
}

fn type_record_size(tb: &[u8], off: usize) -> usize {
    if off + 12 > tb.len() { return 0; }
    let kind = btf_kind(tb, off);
    let vlen = btf_vlen(tb, off);
    12 + match kind {
        1 => 4,              // int
        3 => 12,             // array
        4 | 5 => vlen * 12, // struct, union
        6 => vlen * 8,       // enum
        13 => vlen * 8,      // func_proto
        14 => 4,             // var
        15 => vlen * 12,     // datasec
        17 => 4,             // declTag
        19 => vlen * 12,     // enum64
        _ => 0,
    }
}

fn build_index(tb: &[u8]) -> Vec<usize> {
    let mut idx = vec![usize::MAX]; // slot 0 unused; type IDs start at 1
    let mut off = 0;
    while off + 12 <= tb.len() {
        idx.push(off);
        let sz = type_record_size(tb, off);
        if sz == 0 { break; }
        off += sz;
    }
    idx
}

/// Follow typedef / const / volatile / restrict chains to reach the underlying type.
fn resolve(tb: &[u8], idx: &[usize], type_id: u32) -> usize {
    let mut tid = type_id as usize;
    for _ in 0..8 {
        let Some(&off) = idx.get(tid) else { break };
        if off == usize::MAX || off + 12 > tb.len() { break; }
        match btf_kind(tb, off) {
            8 | 9 | 10 | 11 => tid = u32_le(tb, off + 8) as usize,
            _ => return off,
        }
    }
    usize::MAX
}

fn find_struct(tb: &[u8], sb: &[u8], idx: &[usize], name: &str) -> Option<usize> {
    for &off in idx.iter().skip(1) {
        if off == usize::MAX || off + 12 > tb.len() { continue; }
        if btf_kind(tb, off) == 4 {
            if btf_str(sb, u32_le(tb, off) as usize) == name { return Some(off); }
        }
    }
    None
}

/// Recursively search for `field` in a struct/union type, following anonymous members.
/// Returns the bit offset of the field from the start of the enclosing struct.
fn member_bit_off(tb: &[u8], sb: &[u8], idx: &[usize], type_off: usize, field: &str, depth: u32) -> Option<u32> {
    if depth > 6 || type_off == usize::MAX || type_off + 12 > tb.len() { return None; }
    let kind = btf_kind(tb, type_off);
    if kind != 4 && kind != 5 { return None; }

    let vlen  = btf_vlen(tb, type_off);
    let kflag = (u32_le(tb, type_off + 4) >> 31) != 0;

    for i in 0..vlen {
        let m = type_off + 12 + i * 12;
        if m + 12 > tb.len() { break; }

        let m_name_off = u32_le(tb, m) as usize;
        let m_type_id  = u32_le(tb, m + 4);
        let m_raw_off  = u32_le(tb, m + 8);
        // When kflag is set, upper 8 bits hold bitfield_size; lower 24 bits are the bit offset.
        let m_bit_off  = if kflag { m_raw_off & 0x00FF_FFFF } else { m_raw_off };
        let m_name     = btf_str(sb, m_name_off);

        if m_name == field {
            return Some(m_bit_off);
        }

        // Anonymous member — recurse into the inner struct/union
        if m_name.is_empty() {
            let inner = resolve(tb, idx, m_type_id);
            if let Some(inner_bits) = member_bit_off(tb, sb, idx, inner, field, depth + 1) {
                return Some(m_bit_off + inner_bits);
            }
        }
    }
    None
}

/// Find ITER_IOVEC and ITER_UBUF values in `enum iter_type` from BTF.
fn find_iter_enum_vals(tb: &[u8], sb: &[u8], idx: &[usize]) -> Option<(u8, u8)> {
    for &off in idx.iter().skip(1) {
        if off == usize::MAX || off + 12 > tb.len() { continue; }
        if btf_kind(tb, off) != 6 { continue; }
        if btf_str(sb, u32_le(tb, off) as usize) != "iter_type" { continue; }

        let vlen = btf_vlen(tb, off);
        let mut iter_iovec: Option<i32> = None;
        let mut iter_ubuf:  Option<i32> = None;

        for i in 0..vlen {
            let e = off + 12 + i * 8;
            if e + 8 > tb.len() { break; }
            let e_name = btf_str(sb, u32_le(tb, e) as usize);
            let e_val  = i32::from_le_bytes(tb[e + 4..e + 8].try_into().ok()?);
            match e_name {
                "ITER_IOVEC" => iter_iovec = Some(e_val),
                "ITER_UBUF"  => iter_ubuf  = Some(e_val),
                _ => {}
            }
        }

        if let (Some(iv), Some(ub)) = (iter_iovec, iter_ubuf) {
            return Some((iv as u8, ub as u8));
        }
    }
    None
}
