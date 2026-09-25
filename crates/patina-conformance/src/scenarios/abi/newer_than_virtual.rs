//! abi/newer_than_virtual — rows the vendored table lists past the virtual
//! ABI level (their registry rows are `Absent`) answer ENOSYS, exactly as a
//! kernel of the declared level does — never a trap, never the host's newer
//! semantics: `mseal` (Linux 6.10), `uretprobe` (6.11, x86_64), the
//! `*xattrat` rows (6.13), `open_tree_attr` (6.15), `file_getattr`/
//! `file_setattr` (6.17), `uprobe` (6.18, x86_64), `listns` (6.19),
//! `rseq_slice_yield` (7.0) and `fchroot` (7.3). The number is judged before
//! its arguments, so each row that takes arguments is issued with ones a
//! kernel implementing it would refuse, and still answers ENOSYS. The probe
//! trampoline entries (`uretprobe`, `uprobe`) take none: a kernel that has
//! them kills a caller outside its trampoline with SIGILL, and
//! `rseq_slice_yield` takes none either (at most it yields the CPU). glibc
//! wraps none of the rows, so the scenario runs through the kernel vehicles.
//! Natively the host kernel must lack the rows too; on a kernel that
//! implements one, the native run answers it with the declared ENOSYS
//! (`asserts_absent`) and never issues it.

use crate::catalog::{DEFAULTS, Scenario};
use crate::probe::{Probe, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

/// A closed directory descriptor and a NULL path: `EBADF` or `EFAULT` on a
/// kernel implementing the row.
const CLOSED_AT: &[(&str, i64)] = &[("dirfd", 4000), ("path", 0), ("flags", 0)];

/// Each row past the level, with arguments a kernel implementing it refuses.
const ROWS: &[(Syscall, &[(&str, i64)])] = &[
    // An unknown flag and a misaligned address: `EINVAL`.
    (
        Syscall::N_mseal,
        &[("addr", 1), ("len", 4096), ("flags", 1)],
    ),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_uretprobe, &[]),
    (Syscall::N_setxattrat, CLOSED_AT),
    (Syscall::N_getxattrat, CLOSED_AT),
    (Syscall::N_listxattrat, CLOSED_AT),
    (Syscall::N_removexattrat, CLOSED_AT),
    (Syscall::N_open_tree_attr, CLOSED_AT),
    (Syscall::N_file_getattr, CLOSED_AT),
    (Syscall::N_file_setattr, CLOSED_AT),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_uprobe, &[]),
    // A NULL request: `EFAULT`.
    (
        Syscall::N_listns,
        &[("req", 0), ("ns_ids", 0), ("nr_ns_ids", 1), ("flags", 0)],
    ),
    (Syscall::N_rseq_slice_yield, &[]),
    // No descriptor: `EBADF`.
    (Syscall::N_fchroot, &[("fd", -1), ("flags", 0)]),
];

/// The rows of [`ROWS`], which the scenario asserts absent.
const ABSENT: [Syscall; ROWS.len()] = {
    let mut rows = [Syscall::N_mseal; ROWS.len()];
    let mut index = 0;
    while index < ROWS.len() {
        rows[index] = ROWS[index].0;
        index += 1;
    }
    rows
};

pub fn run(p: &Probe) {
    for (row, args) in ROWS {
        let r = p.absent(*row, args);
        p.check(
            &format!("{} past the virtual ABI level is ENOSYS", row.name()),
            r == neg(ENOSYS),
        );
    }
}

pub const SCENARIO: Scenario = Scenario {
    name: "abi/newer_than_virtual",
    run,
    vehicles: Vehicle::KERNEL,
    asserts_absent: &ABSENT,
    ..DEFAULTS
};
