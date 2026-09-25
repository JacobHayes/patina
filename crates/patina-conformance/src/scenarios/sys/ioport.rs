//! sys/ioport — x86 I/O port permissions (arch/x86/kernel/ioport.c):
//!
//! * `iopl` refuses a level past 3 (`EINVAL`), answers 0 for the current
//!   level (0) without a privilege, and needs `CAP_SYS_RAWIO` to raise it
//!   (`EPERM`);
//! * `ioperm` refuses a range past the 65536 ports or one that wraps
//!   (`EINVAL`), turns permissions off without a privilege (0: there is
//!   nothing to clear), and needs `CAP_SYS_RAWIO` to turn them on (`EPERM`).
//!
//! What root would be granted is harmless: `iopl(1)` grants no port (only
//! level 3 does), and `ioperm` port 0x80 (the POST diagnostic port) is never
//! touched by the probe. The libc vehicle goes through glibc's `iopl` and
//! `ioperm`, which the shim defines.

use crate::catalog::{DEFAULTS, Need, Scenario};
use crate::probe::{Probe, neg};
use libc::*;
use patina_dst_syscalls::Syscall;

/// The POST diagnostic port.
const PORT: i64 = 0x80;

pub fn run(p: &Probe) {
    p.require_unprivileged();
    let iopl = |level: i64| p.call_observed(Syscall::N_iopl, [level, 0, 0, 0, 0, 0]);
    p.check("iopl 4 is EINVAL", iopl(4) == neg(EINVAL));
    p.check(
        "iopl of the current level 0 needs no privilege",
        iopl(0) == 0,
    );
    p.check(
        "raising the level is EPERM (no CAP_SYS_RAWIO)",
        iopl(1) == neg(EPERM),
    );
    let ioperm =
        |from: i64, num: i64, on: i64| p.call_observed(Syscall::N_ioperm, [from, num, on, 0, 0, 0]);
    p.check(
        "a range past the last port is EINVAL",
        ioperm(0xffff, 2, 1) == neg(EINVAL),
    );
    p.check(
        "an empty range is EINVAL",
        ioperm(PORT, 0, 1) == neg(EINVAL),
    );
    p.check(
        "turning a port off needs no privilege",
        ioperm(PORT, 1, 0) == 0,
    );
    p.check(
        "turning a port on is EPERM (no CAP_SYS_RAWIO)",
        ioperm(PORT, 1, 1) == neg(EPERM),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "sys/ioport",
    run,
    covers: &[Syscall::N_iopl, Syscall::N_ioperm],
    symbols: &["iopl", "ioperm"],
    needs: &[Need::Unprivileged],
    ..DEFAULTS
};
