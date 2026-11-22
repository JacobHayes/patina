//! Naming a containment stop (`HE_CONTAINMENT`): program code reached into the runtime. The
//! runtime reports what happened and where; this says which part of the runtime's region the
//! address is, down to the control region's field or the boundary log's record.

use proto::ctl::*;
use proto::layout::*;
use proto::rec::REC_SIZE;
use std::mem::{offset_of, size_of};

/// The sentence of the verdict for `[kind, addr, _, rip, store]`.
pub fn describe(kind: u64, addr: u64, rip: u64, store: bool) -> String {
    match kind {
        CONTAIN_ACCESS => format!(
            "the program {} {} at {addr:#x} (instruction at {rip:#x})",
            if store { "wrote" } else { "read" },
            place(addr)
        ),
        CONTAIN_STUB => format!(
            "the program jumped to the runtime's system call stub (stopped at {addr:#x}): at most \
             one call reached the kernel untrapped, and the run ended before the program saw its result"
        ),
        CONTAIN_SYSCALL => format!(
            "the program jumped to a system call instruction in the runtime's text at {addr:#x} (trapped, not made)"
        ),
        CONTAIN_EXEC => format!("the program jumped into {} at {addr:#x}", place(addr)),
        _ => format!("unknown containment report {kind} at {addr:#x}"),
    }
}

/// Which part of the runtime's region `a` is.
fn place(a: u64) -> String {
    let ctl_end = CTL_ADDR + CTL_SIZE as u64;
    if (CTL_ADDR..ctl_end).contains(&a) {
        return format!(
            "the control region's {}",
            ctl_field((a - CTL_ADDR) as usize)
        );
    }
    if (LOG_ADDR..LOG_ADDR + LOG_GUARD).contains(&a) {
        return format!(
            "the boundary log (record {})",
            (a - LOG_ADDR) / REC_SIZE as u64
        );
    }
    if a < RT_PRIV {
        return "the runtime's image".into();
    }
    "the runtime's memory".into()
}

/// The control region field at offset `off` (`proto::ctl` and the tables after the slots).
fn ctl_field(off: usize) -> String {
    let slots = CTL_HEADER_SIZE..CTL_HEADER_SIZE + MAX_THREADS * size_of::<Slot>();
    if slots.contains(&off) {
        let i = (off - CTL_HEADER_SIZE) / size_of::<Slot>();
        let o = (off - CTL_HEADER_SIZE) % size_of::<Slot>();
        return format!("slot {i} ({})", field(SLOT_FIELDS, o, "padding"));
    }
    if off < CTL_HEADER_SIZE {
        return field(CTL_FIELDS, off, "header padding").into();
    }
    let tables = [
        (
            proto::vfs::VFS_OFFSET,
            proto::vfs::VFS_SIZE,
            "filesystem table",
        ),
        (
            proto::oplog::DUR_OFFSET,
            proto::oplog::DUR_SIZE,
            "durability state",
        ),
        (
            proto::wire::WIRE_OFFSET,
            proto::wire::WIRE_SIZE,
            "network wire table",
        ),
        (
            proto::sdk::SDK_OFFSET,
            proto::sdk::SDK_SIZE,
            "SDK site table",
        ),
        (
            COMPUTE_TAB_OFFSET,
            COMPUTE_TAB_SIZE,
            "compute-point image table",
        ),
        (SCAN_TAB_OFFSET, SCAN_TAB_SIZE, "instruction scan table"),
        (
            proto::node::NODE_TAB_OFFSET,
            proto::node::NODE_TAB_SIZE,
            "node table",
        ),
    ];
    for (start, len, name) in tables {
        if (start..start + len).contains(&off) {
            return name.into();
        }
    }
    "padding".into()
}

/// The last field of `fields` (sorted by offset) that starts at or before `off`, if `off` is
/// inside it.
fn field(fields: &[(usize, usize, &'static str)], off: usize, gap: &'static str) -> &'static str {
    fields
        .iter()
        .rev()
        .find(|(o, len, _)| (*o..*o + *len).contains(&off))
        .map(|f| f.2)
        .unwrap_or(gap)
}

macro_rules! fields {
    ($t:ty: $($f:ident),* $(,)?) => {
        &[$((offset_of!($t, $f), size_of_field(|x: &$t| &x.$f), stringify!($f))),*]
    };
}

const fn size_of_field<T, F>(_: fn(&T) -> &F) -> usize {
    size_of::<F>()
}

const CTL_FIELDS: &[(usize, usize, &str)] = fields!(Ctl:
    magic, layout_version, config, seq, vclock_ns, next_deadline_ns, log_len, log_hash,
    log_cap, oplog_len, opdata_len, sup_word, pending_slot, stats, filter_installed, log_exempt, maps_table, view,
    denied, stop_nr, io, faults, insn, timing, sched, compute, debug, phases,
);

const SLOT_FIELDS: &[(usize, usize, &str)] = fields!(Slot: go, state, tid, pid, req, rep, vmask, sigpend, siginfo, sched, node, clock_flags, nofile_hard, probe_pc);

#[cfg(test)]
mod tests {
    use super::*;

    /// The listed fields tile the struct: no overlap, and no gap wider than alignment padding,
    /// so a field added to `Ctl` or `Slot` but not listed fails here.
    fn tiles(fields: &[(usize, usize, &str)], size: usize) {
        let mut covered = 0;
        for (o, len, name) in fields {
            assert!(*o >= covered && *o - covered < 8, "{name}: gap before it");
            covered = o + len;
        }
        assert!(covered <= size && size - covered < 8);
    }

    #[test]
    fn every_byte_names_one_field() {
        tiles(CTL_FIELDS, size_of::<Ctl>());
        tiles(SLOT_FIELDS, size_of::<Slot>());
        let vclock = offset_of!(Ctl, vclock_ns);
        assert_eq!(ctl_field(vclock + 3), "vclock_ns");
        let slot = CTL_HEADER_SIZE + 5 * size_of::<Slot>() + offset_of!(Slot, sigpend);
        assert_eq!(ctl_field(slot), "slot 5 (sigpend)");
    }
}
