//! proc/ptrace — tracing (kernel/ptrace.c), probed only on the caller
//! itself, which no caller may trace:
//!
//! * the pid is looked up first: one no process has is `ESRCH`, whatever
//!   the request;
//! * a request other than `PTRACE_ATTACH`/`PTRACE_SEIZE` wants a tracee the
//!   caller already traces and stopped (`ptrace_check_attach`), so asking
//!   it of itself is `ESRCH`;
//! * `PTRACE_SEIZE` refuses a nonzero address or an unknown option (`EIO`)
//!   first; `PTRACE_O_SUSPEND_SECCOMP` needs `CAP_SYS_ADMIN`
//!   (`check_ptrace_options`: `EPERM`);
//! * attaching to a thread of the caller's own thread group is `EPERM`
//!   (`ptrace_attach`), for any caller;
//! * seizing init, root's, is `EPERM`: its ids are not the caller's and the
//!   caller has no `CAP_SYS_PTRACE` (`__ptrace_may_access`, before Yama or
//!   dumpability are consulted). `PTRACE_SEIZE` stops no one, so even a
//!   privileged run past both guards would not stop pid 1.
//!
//! Whether an unprivileged caller may attach to another process of its own
//! user is the host's policy (a dumpable target, Yama's
//! `kernel.yama.ptrace_scope`, `CAP_SYS_PTRACE`), so no such process is
//! ever named, and `PTRACE_TRACEME` is never asked: it would hand the probe
//! to the harness as a tracee.
//!
//! The libc vehicle goes through glibc's `ptrace`, which the shim defines.

use crate::catalog::{DEFAULTS, Need, Scenario};
use crate::probe::{Probe, neg};
use libc::*;
use patina_dst_syscalls::Syscall;

/// Past every `pid_max`.
const NO_PID: i64 = 0x3fff_ffff;
/// No `PTRACE_*` request.
const UNKNOWN_REQUEST: i64 = 0x7fff;
/// No `PTRACE_O_*` option.
const UNKNOWN_OPTION: i64 = 1 << 30;
const PTRACE_O_SUSPEND_SECCOMP: i64 = 1 << 21;

pub fn run(p: &Probe) {
    p.require_unprivileged();
    let ptrace = |request: c_uint, pid: i64, addr: i64, data: i64| {
        p.call_observed(Syscall::N_ptrace, [request as i64, pid, addr, data, 0, 0])
    };
    p.check(
        "a pid no process has is ESRCH",
        ptrace(PTRACE_PEEKDATA, NO_PID, 0, 0) == neg(ESRCH),
    );
    p.check(
        "before an unknown request is looked at",
        p.call_observed(Syscall::N_ptrace, [UNKNOWN_REQUEST, NO_PID, 0, 0, 0, 0]) == neg(ESRCH),
    );
    let pid = p.getpid();
    p.check(
        "PTRACE_PEEKDATA of an untraced process (itself) is ESRCH",
        ptrace(PTRACE_PEEKDATA, pid, 0, 0) == neg(ESRCH),
    );
    p.check(
        "PTRACE_SEIZE with an address is EIO",
        ptrace(PTRACE_SEIZE, pid, 1, 0) == neg(EIO),
    );
    p.check(
        "PTRACE_SEIZE with an unknown option is EIO",
        ptrace(PTRACE_SEIZE, pid, 0, UNKNOWN_OPTION) == neg(EIO),
    );
    p.check(
        "PTRACE_O_SUSPEND_SECCOMP is EPERM (no CAP_SYS_ADMIN)",
        ptrace(PTRACE_SEIZE, pid, 0, PTRACE_O_SUSPEND_SECCOMP) == neg(EPERM),
    );
    p.check(
        "seizing its own thread group is EPERM",
        ptrace(PTRACE_SEIZE, pid, 0, 0) == neg(EPERM),
    );
    p.check(
        "attaching to it is EPERM",
        ptrace(PTRACE_ATTACH, pid, 0, 0) == neg(EPERM),
    );
    p.check(
        "seizing init, root's process, is EPERM",
        ptrace(PTRACE_SEIZE, 1, 0, 0) == neg(EPERM),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "proc/ptrace",
    run,
    covers: &[Syscall::N_ptrace, Syscall::N_getpid],
    symbols: &["ptrace", "getpid"],
    needs: &[Need::Unprivileged, Need::RootInit],
    ..DEFAULTS
};
