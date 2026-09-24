//! mem/membarrier — process-wide memory barriers (man 2 membarrier;
//! kernel/sched/membarrier.c): `MEMBARRIER_CMD_QUERY` answers the supported
//! commands (compared within the private and global expedited commands every
//! kernel with the row offers; the rest follow the architecture and config);
//! the query takes no flag and an unknown command is `EINVAL`; the private
//! expedited barrier is `EPERM` until the process registers for it, then
//! succeeds, and it too takes no flag.

use crate::catalog::{DEFAULTS, KernelFloor, Need, Scenario};
use crate::probe::{Probe, neg};
use libc::*;
use patina_dst_syscalls::Syscall;

/// `enum membarrier_cmd` (uapi/linux/membarrier.h).
const QUERY: i32 = 0;
const GLOBAL_EXPEDITED: u64 = 1 << 1;
const REGISTER_GLOBAL_EXPEDITED: u64 = 1 << 2;
const PRIVATE_EXPEDITED: i32 = 1 << 3;
const REGISTER_PRIVATE_EXPEDITED: i32 = 1 << 4;
/// A command no kernel defines (the commands are single bits up to
/// `MEMBARRIER_CMD_GET_REGISTRATIONS`, 1 << 9, in 6.3).
const UNKNOWN_CMD: i32 = 1 << 20;
/// The commands a kernel with the row always offers.
const PORTABLE: u64 = GLOBAL_EXPEDITED
    | REGISTER_GLOBAL_EXPEDITED
    | PRIVATE_EXPEDITED as u64
    | REGISTER_PRIVATE_EXPEDITED as u64;

pub fn run(p: &Probe) {
    let supported = p.membarrier(QUERY, 0, Some(PORTABLE));
    p.check(
        "the query offers the private and global expedited commands",
        supported >= 0 && supported as u64 & PORTABLE == PORTABLE,
    );
    p.check(
        "the query with a flag is EINVAL",
        p.membarrier(QUERY, 1, None) == neg(EINVAL),
    );
    p.check(
        "an unknown command is EINVAL",
        p.membarrier(UNKNOWN_CMD, 0, None) == neg(EINVAL),
    );
    p.check(
        "the private expedited barrier before registering is EPERM",
        p.membarrier(PRIVATE_EXPEDITED, 0, None) == neg(EPERM),
    );
    p.check(
        "registering for it succeeds",
        p.membarrier(REGISTER_PRIVATE_EXPEDITED, 0, None) == 0,
    );
    p.check(
        "then the barrier succeeds",
        p.membarrier(PRIVATE_EXPEDITED, 0, None) == 0,
    );
    p.check(
        "registering again succeeds",
        p.membarrier(REGISTER_PRIVATE_EXPEDITED, 0, None) == 0,
    );
    p.check(
        "the barrier with a flag is EINVAL",
        p.membarrier(PRIVATE_EXPEDITED, 1, None) == neg(EINVAL),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "mem/membarrier",
    run,
    covers: &[Syscall::N_membarrier],
    symbols: &["syscall"],
    needs: &[Need::Membarrier],
    kernel_floor: Some(KernelFloor {
        release: "4.16",
        why: "MEMBARRIER_CMD_GLOBAL_EXPEDITED and its registration first appear in Linux 4.16",
    }),
    ..DEFAULTS
};
