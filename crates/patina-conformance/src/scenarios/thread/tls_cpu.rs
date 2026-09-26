//! thread/tls_cpu — the `arch_prctl` answers that are the CPU's as much as
//! the kernel's (arch/x86/kernel/process_64.c `do_arch_prctl_64`,
//! arch/x86/kernel/process.c `set_cpuid_mode`), as 6.8 gives them on the
//! virtual machine's CPU, which has 4-level paging and no CPUID faulting:
//!
//! * a GS or FS base at or past `TASK_SIZE_MAX` is `EPERM`. That limit is
//!   the paging depth's: 4-level paging ends the user address space at
//!   `0x7fff_ffff_f000`, but a CPU with 5-level paging (`la57`, enabled by
//!   the kernel wherever the CPU has it) ends it at `0xff_ffff_ffff_f000`,
//!   where the same base is an ordinary unmapped user address:
//!   `ARCH_SET_FS` there answers 0 and moves the thread pointer, and the
//!   probe's next thread-local access faults. The GS row runs first, so a
//!   host the need detection misjudged fails that check by name (nothing in
//!   user space reads the GS base) before the FS row could move anything;
//! * enabling `cpuid` (`ARCH_SET_CPUID` 1) is `ENODEV` on a CPU that cannot
//!   make it fault, and 0 on one that can.
//!
//! So the native run is an oracle only on such a CPU ([`Need::FourLevelPaging`],
//! [`Need::NoCpuidFaulting`]); on another it is reported not run, and
//! `thread/tls` judges the rest of the rows on any x86_64 CPU.

use super::tls::{ARCH_SET_FS, arch_prctl};
use crate::catalog::{DEFAULTS, Need, Scenario};
use crate::probe::{Probe, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

/// `ARCH_*` codes (arch/x86/include/uapi/asm/prctl.h).
const ARCH_SET_GS: i64 = 0x1001;
const ARCH_SET_CPUID: i64 = 0x1012;
/// `TASK_SIZE_MAX` with 4-level paging: the first base past the user
/// address space.
const TASK_SIZE_MAX: i64 = 0x7fff_ffff_f000;

pub fn run(p: &Probe) {
    for (what, code, arg, arg_what, errno) in [
        (
            "a GS base past the user address space is EPERM",
            ARCH_SET_GS,
            TASK_SIZE_MAX,
            "task-size-max",
            EPERM,
        ),
        (
            "an FS base past the user address space is EPERM",
            ARCH_SET_FS,
            TASK_SIZE_MAX,
            "task-size-max",
            EPERM,
        ),
        (
            "enabling cpuid is ENODEV: the CPU has no CPUID faulting",
            ARCH_SET_CPUID,
            1,
            "enable",
            ENODEV,
        ),
    ] {
        p.check(what, arch_prctl(p, code, arg, arg_what) == neg(errno));
    }
}

pub const SCENARIO: Scenario = Scenario {
    name: "thread/tls_cpu",
    run,
    vehicles: Vehicle::ALL,
    covers: &[Syscall::N_arch_prctl],
    symbols: &["arch_prctl"],
    needs: &[Need::FourLevelPaging, Need::NoCpuidFaulting],
    ..DEFAULTS
};
