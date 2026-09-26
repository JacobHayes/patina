//! proc/seccomp — the `seccomp` row (kernel/seccomp.c `do_seccomp`), probed
//! only where it restricts nothing:
//!
//! * an unknown operation is `EINVAL`; strict mode with a flag or an
//!   argument is `EINVAL` (strict mode itself is never entered: it would
//!   kill the probe at its next call);
//! * `SECCOMP_GET_ACTION_AVAIL` refuses a flag (`EINVAL`) and an unreadable
//!   action (`EFAULT`), answers 0 for every action the kernel knows and
//!   `EOPNOTSUPP` for another;
//! * `SECCOMP_GET_NOTIF_SIZES` refuses a flag (`EINVAL`) and answers the
//!   kernel's structure sizes: 80, 24 and 64 bytes;
//! * `SECCOMP_SET_MODE_FILTER` refuses an unknown flag and two flag
//!   combinations (`TSYNC` with `NEW_LISTENER` but no `TSYNC_ESRCH`;
//!   `WAIT_KILLABLE_RECV` without `NEW_LISTENER`) as `EINVAL`, an
//!   unreadable program (`EFAULT`), and a program of no or more than
//!   `BPF_MAXINSNS` instructions (`EINVAL`); then a caller without
//!   `no_new_privs` needs `CAP_SYS_ADMIN` (`seccomp_prepare_filter`:
//!   `EACCES`) before the program is checked.
//!
//! * prctl's `PR_SET_SECCOMP` refuses a mode it does not know (`EINVAL`)
//!   and runs a filter through the same checks (an unreadable program:
//!   `EFAULT`).
//!
//! The one program offered is a single invalid instruction: without the
//! capability it is refused as `EACCES`, with it (or with `no_new_privs`)
//! as `EINVAL`, so no filter is ever installed. The scenario requires the
//! caller to start without `no_new_privs` (proc/prctl asserts it).

use crate::catalog::{DEFAULTS, Need, Scenario};
use crate::probe::{Probe, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

const SECCOMP_SET_MODE_STRICT: i64 = 0;
const SECCOMP_SET_MODE_FILTER: i64 = 1;
const SECCOMP_GET_ACTION_AVAIL: i64 = 2;
const SECCOMP_GET_NOTIF_SIZES: i64 = 3;
/// No `SECCOMP_SET_MODE_*`/`SECCOMP_GET_*` operation.
const UNKNOWN_OPERATION: i64 = 99;
/// No `SECCOMP_FILTER_FLAG_*`.
const UNKNOWN_FILTER_FLAG: i64 = 1 << 31;
/// `SECCOMP_FILTER_FLAG_TSYNC`, `_NEW_LISTENER` and `_WAIT_KILLABLE_RECV`.
const TSYNC: i64 = 1;
const NEW_LISTENER: i64 = 1 << 3;
const WAIT_KILLABLE_RECV: i64 = 1 << 5;
/// No `SECCOMP_RET_*` action.
const UNKNOWN_ACTION: u32 = 0x1234_0000;
/// No `SECCOMP_MODE_*`.
const UNKNOWN_MODE: u64 = 99;
/// One past `BPF_MAXINSNS`.
const TOO_LONG: u16 = 4097;

/// `struct sock_filter`.
#[repr(C)]
struct Instruction {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

/// `struct sock_fprog`.
#[repr(C)]
struct Program {
    len: u16,
    filter: *const Instruction,
}

pub fn run(p: &Probe) {
    p.require_unprivileged();
    p.require(
        "the caller starts without no_new_privs (proc/prctl asserts it)",
        p.rec.quiet(|| p.prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)) == 0,
    );
    let seccomp = |op: i64, flags: i64, args: i64| {
        p.call_observed(Syscall::N_seccomp, [op, flags, args, 0, 0, 0])
    };
    p.check(
        "an unknown operation is EINVAL",
        seccomp(UNKNOWN_OPERATION, 0, 0) == neg(EINVAL),
    );
    let action = 0u32;
    p.check(
        "strict mode with a flag is EINVAL",
        seccomp(SECCOMP_SET_MODE_STRICT, 1, 0) == neg(EINVAL),
    );
    p.check(
        "strict mode with an argument is EINVAL",
        seccomp(SECCOMP_SET_MODE_STRICT, 0, &action as *const u32 as i64) == neg(EINVAL),
    );

    let avail = |action: u32, flags: i64| {
        seccomp(
            SECCOMP_GET_ACTION_AVAIL,
            flags,
            &action as *const u32 as i64,
        )
    };
    p.check(
        "SECCOMP_GET_ACTION_AVAIL with a flag is EINVAL",
        avail(SECCOMP_RET_ALLOW, 1) == neg(EINVAL),
    );
    p.check(
        "an unreadable action is EFAULT",
        seccomp(SECCOMP_GET_ACTION_AVAIL, 0, 0) == neg(EFAULT),
    );
    p.check(
        "every action the kernel knows is available",
        [
            SECCOMP_RET_KILL_PROCESS,
            SECCOMP_RET_KILL_THREAD,
            SECCOMP_RET_TRAP,
            SECCOMP_RET_ERRNO,
            SECCOMP_RET_USER_NOTIF,
            SECCOMP_RET_TRACE,
            SECCOMP_RET_LOG,
            SECCOMP_RET_ALLOW,
        ]
        .into_iter()
        .all(|action| avail(action, 0) == 0),
    );
    p.check(
        "another action is EOPNOTSUPP",
        avail(UNKNOWN_ACTION, 0) == neg(EOPNOTSUPP),
    );

    let mut sizes = [0u16; 3];
    p.check(
        "SECCOMP_GET_NOTIF_SIZES with a flag is EINVAL",
        seccomp(SECCOMP_GET_NOTIF_SIZES, 1, sizes.as_mut_ptr() as i64) == neg(EINVAL),
    );
    p.check(
        "SECCOMP_GET_NOTIF_SIZES answers the notification, response and data sizes",
        seccomp(SECCOMP_GET_NOTIF_SIZES, 0, sizes.as_mut_ptr() as i64) == 0
            && sizes == [80, 24, 64],
    );

    let invalid = [Instruction {
        code: 0xffff,
        jt: 0,
        jf: 0,
        k: 0,
    }];
    let program = |len: u16| Program {
        len,
        filter: invalid.as_ptr(),
    };
    let filter = |flags: i64, program: Option<&Program>| {
        let program = program.map_or(0, |program| program as *const Program as i64);
        seccomp(SECCOMP_SET_MODE_FILTER, flags, program)
    };
    p.check(
        "a filter with an unknown flag is EINVAL",
        filter(UNKNOWN_FILTER_FLAG, Some(&program(1))) == neg(EINVAL),
    );
    p.check(
        "TSYNC with NEW_LISTENER is EINVAL without TSYNC_ESRCH, before the program is read",
        filter(TSYNC | NEW_LISTENER, None) == neg(EINVAL),
    );
    p.check(
        "WAIT_KILLABLE_RECV is EINVAL without NEW_LISTENER, before the program is read",
        filter(WAIT_KILLABLE_RECV, None) == neg(EINVAL),
    );
    p.check(
        "an unreadable program is EFAULT",
        filter(0, None) == neg(EFAULT),
    );
    p.check(
        "a program of no instructions is EINVAL",
        filter(0, Some(&program(0))) == neg(EINVAL),
    );
    p.check(
        "a program past BPF_MAXINSNS is EINVAL",
        filter(0, Some(&program(TOO_LONG))) == neg(EINVAL),
    );
    p.check(
        "without no_new_privs a filter is EACCES (no CAP_SYS_ADMIN) before its program is checked",
        filter(0, Some(&program(1))) == neg(EACCES),
    );

    p.check(
        "PR_SET_SECCOMP with a mode no kernel has is EINVAL",
        p.prctl(PR_SET_SECCOMP, UNKNOWN_MODE, 0, 0, 0) == neg(EINVAL),
    );
    p.check(
        "PR_SET_SECCOMP's filter meets the same checks: an unreadable program is EFAULT",
        p.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER as u64, 0, 0, 0) == neg(EFAULT),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "proc/seccomp",
    run,
    // glibc has no wrapper for the row: the libc spelling would be
    // `syscall(2)` again.
    vehicles: Vehicle::KERNEL,
    covers: &[Syscall::N_seccomp, Syscall::N_prctl],
    needs: &[Need::Unprivileged],
    ..DEFAULTS
};
