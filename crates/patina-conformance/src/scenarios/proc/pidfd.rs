//! proc/pidfd — a descriptor for the caller's own process (kernel/pid.c
//! `pidfd_open`, `pidfd_getfd`; kernel/signal.c `pidfd_send_signal`;
//! mm/oom_kill.c `process_mrelease`), as 6.8 answers them:
//!
//! * `pidfd_open` refuses an undefined flag and 6.9's `PIDFD_THREAD`, and a
//!   pid that is no process (`EINVAL` for 0 and -1), answers `ESRCH` for a
//!   pid past `PID_MAX_LIMIT`,
//!   and opens the caller's own process: always close-on-exec, read-write,
//!   non-blocking when asked, and not readable while the process runs;
//! * `pidfd_getfd` duplicates one of the caller's descriptors through its
//!   own pidfd (a ptrace-mode check the caller always passes on itself):
//!   the copy shares the open file and is close-on-exec; a flag is `EINVAL`,
//!   and a target descriptor not open, or a descriptor that is no pidfd,
//!   `EBADF`;
//! * `pidfd_send_signal` probes with signal 0 (0), refuses an undefined
//!   flag, 6.9's `PIDFD_SIGNAL_THREAD` and an invalid signal (`EINVAL`) and a descriptor that is no pidfd (`EBADF`),
//!   and sends a blocked SIGUSR1 to the caller as a process-directed signal
//!   from itself (`SI_USER`), which `rt_sigtimedwait` then takes;
//! * `process_mrelease` refuses a flag before looking at the descriptor
//!   (`EINVAL`) and a descriptor that is no pidfd (`EBADF`). It is only ever
//!   given invalid arguments: reaping a process's memory is never asked for.
//!
//! glibc 2.39 wraps `pidfd_open`, `pidfd_getfd` and `pidfd_send_signal`, but
//! the registry has no symbol row for them (the shim defines none), so the
//! probe binary cannot import them — the pre-run audit would refuse it — and
//! the scenario runs through the kernel vehicles.

use crate::catalog::{Arc, DEFAULTS, Gap, Scenario, Status};
use crate::compare::{Ending, Failure};
use crate::observe::Norm;
use crate::probe::{AT_FDCWD, CLOSED_FD, NO_SUCH_PID, Probe, SIGSET_BYTES, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

/// A flag no kernel defines for `pidfd_open` or `pidfd_send_signal`.
const UNDEFINED_FLAG: i64 = 1 << 30;
/// `PIDFD_THREAD` (`O_EXCL`) and `PIDFD_SIGNAL_THREAD` (1): Linux 6.9's
/// thread pidfds, which 6.8 refuses.
const PIDFD_THREAD: u32 = O_EXCL as u32;
const PIDFD_SIGNAL_THREAD: i64 = 1;

/// `pidfd_getfd(pidfd, target, flags)`: the copy is an allocated
/// descriptor, and an open target one of the scenario's (both compared as
/// identities); `CLOSED_FD` is recorded as `closed`.
fn getfd(p: &Probe, pidfd: i32, what: &str, target: i32, flags: i64) -> i64 {
    let result = p.call_unrecorded(
        Syscall::N_pidfd_getfd,
        [pidfd as i64, target as i64, flags, 0, 0, 0],
    );
    let builder = p
        .rec
        .event(Syscall::N_pidfd_getfd.name(), result)
        .arg("pidfd", what)
        .arg("flags", flags)
        .norm("ret", Norm::Relative("fd"));
    let builder = if target == CLOSED_FD {
        builder.arg("targetfd", "closed")
    } else {
        builder
            .arg("targetfd", target)
            .norm("args.targetfd", Norm::Relative("fd"))
    };
    builder.emit();
    result
}

fn send_signal(p: &Probe, pidfd: i32, what: &str, sig: i32, flags: i64) -> i64 {
    p.observed(
        Syscall::N_pidfd_send_signal,
        [pidfd as i64, sig as i64, 0, flags, 0, 0],
        &[
            ("pidfd", what.into()),
            ("sig", sig.into()),
            ("flags", flags.into()),
        ],
    )
}

fn mrelease(p: &Probe, pidfd: i32, what: &str, flags: i64) -> i64 {
    p.observed(
        Syscall::N_process_mrelease,
        [pidfd as i64, flags, 0, 0, 0, 0],
        &[("pidfd", what.into()), ("flags", flags.into())],
    )
}

pub fn run(p: &Probe) {
    let pid = p.getpid() as i32;
    let pidfd = p.pidfd_open(pid, 0);
    p.require("open the caller's pidfd", pidfd >= 0);
    p.check(
        "a pidfd is always close-on-exec",
        p.fcntl(pidfd, F_GETFD, 0) == i64::from(FD_CLOEXEC),
    );
    p.check(
        "a pidfd is read-write and blocking by default",
        p.fcntl(pidfd, F_GETFL, 0) == i64::from(O_RDWR),
    );
    let (r, revents) = p.ppoll(&[(pidfd, POLLIN)], Some(0));
    p.check(
        "the pidfd of a running process is not readable",
        r == 0 && revents == [0],
    );
    let nonblocking = p.pidfd_open(pid, O_NONBLOCK as u32);
    p.check(
        "O_NONBLOCK opens a non-blocking pidfd",
        nonblocking >= 0 && p.fcntl(nonblocking, F_GETFL, 0) == i64::from(O_RDWR | O_NONBLOCK),
    );
    p.check(
        "an undefined pidfd_open flag is EINVAL",
        p.pidfd_open(pid, UNDEFINED_FLAG as u32) == neg(EINVAL) as i32,
    );
    p.check(
        "PIDFD_THREAD (Linux 6.9) is EINVAL on 6.8",
        p.pidfd_open(pid, PIDFD_THREAD) == neg(EINVAL) as i32,
    );
    for (target, label) in [(0, "pid 0 is EINVAL"), (-1, "pid -1 is EINVAL")] {
        p.check(label, p.pidfd_open(target, 0) == neg(EINVAL) as i32);
    }
    p.check(
        "a pid no process has is ESRCH",
        p.pidfd_open(NO_SUCH_PID, 0) == neg(ESRCH) as i32,
    );

    let path = format!("{}/shared", p.dir());
    let file = p.openat(AT_FDCWD, &path, O_RDWR | O_CREAT | O_EXCL, 0o644);
    p.require("create a file", file >= 0);
    let copy = getfd(p, pidfd, "self", file, 0) as i32;
    p.check("pidfd_getfd copies the caller's descriptor", copy >= 0);
    p.check(
        "the copy is close-on-exec",
        p.fcntl(copy, F_GETFD, 0) == i64::from(FD_CLOEXEC),
    );
    p.check(
        "the copy shares the open file: a seek through one moves the other",
        p.lseek(file, 5, SEEK_SET) == 5 && p.lseek(copy, 0, SEEK_CUR) == 5,
    );
    p.check(
        "a pidfd_getfd flag is EINVAL",
        getfd(p, pidfd, "self", file, 1) == neg(EINVAL),
    );
    p.check(
        "a target descriptor not open is EBADF",
        getfd(p, pidfd, "self", CLOSED_FD, 0) == neg(EBADF),
    );
    p.check(
        "a descriptor that is no pidfd is EBADF",
        getfd(p, file, "file", file, 0) == neg(EBADF),
    );

    p.check(
        "signal 0 through the pidfd probes the process",
        send_signal(p, pidfd, "self", 0, 0) == 0,
    );
    p.check(
        "an undefined pidfd_send_signal flag is EINVAL",
        send_signal(p, pidfd, "self", 0, UNDEFINED_FLAG) == neg(EINVAL),
    );
    p.check(
        "PIDFD_SIGNAL_THREAD (Linux 6.9) is EINVAL on 6.8",
        send_signal(p, pidfd, "self", 0, PIDFD_SIGNAL_THREAD) == neg(EINVAL),
    );
    p.check(
        "an invalid signal is EINVAL",
        send_signal(p, pidfd, "self", 999, 0) == neg(EINVAL),
    );
    p.check(
        "pidfd_send_signal on a descriptor that is no pidfd is EBADF",
        send_signal(p, file, "file", 0, 0) == neg(EBADF),
    );
    // SAFETY: plain sigset_t manipulation on a local.
    let usr1 = unsafe {
        let mut set: sigset_t = std::mem::zeroed();
        sigemptyset(&mut set);
        sigaddset(&mut set, SIGUSR1);
        set
    };
    p.require(
        "block SIGUSR1",
        p.rt_sigprocmask(SIG_BLOCK, Some(&usr1), None, SIGSET_BYTES as usize) == 0,
    );
    p.check(
        "SIGUSR1 through the pidfd is sent",
        send_signal(p, pidfd, "self", SIGUSR1, 0) == 0,
    );
    // SAFETY: an all-zero siginfo is a valid out-parameter.
    let mut info: siginfo_t = unsafe { std::mem::zeroed() };
    let taken = p.rt_sigtimedwait(&usr1, Some(&mut info), Some(0), SIGSET_BYTES as usize);
    p.check(
        "the signal is pending for the process and taken, sent by the caller (SI_USER)",
        taken == i64::from(SIGUSR1) && info.si_code == SI_USER,
    );
    p.require(
        "unblock SIGUSR1",
        p.rt_sigprocmask(SIG_UNBLOCK, Some(&usr1), None, SIGSET_BYTES as usize) == 0,
    );

    p.check(
        "a process_mrelease flag is EINVAL, judged before the descriptor",
        mrelease(p, -1, "none", 1) == neg(EINVAL),
    );
    p.check(
        "process_mrelease of a descriptor that is no pidfd is EBADF",
        mrelease(p, file, "file", 0) == neg(EBADF),
    );
    p.check(
        "process_mrelease of a descriptor not open is EBADF",
        mrelease(p, CLOSED_FD, "closed", 0) == neg(EBADF),
    );
    for fd in [copy, file, nonblocking, pidfd] {
        p.close(fd);
    }
}

pub const SCENARIO: Scenario = Scenario {
    name: "proc/pidfd",
    run,
    vehicles: Vehicle::KERNEL,
    covers: &[
        Syscall::N_pidfd_open,
        Syscall::N_pidfd_getfd,
        Syscall::N_pidfd_send_signal,
        Syscall::N_process_mrelease,
    ],
    gaps: &[Gap {
        status: Status::Pending(Arc::SignalsThreadsProcess),
        vehicles: Vehicle::KERNEL,
        what: "pidfd_open is Trap(unmodeled) in the registry: the descriptor table has no pidfd kind, which the signals arc adds for the process itself (pidfd_send_signal is a by-design process trap behind it, pidfd_getfd and process_mrelease unmodeled traps), so the SUD dispatcher aborts at the first pidfd_open",
        failure: Failure::Stops {
            events: 1,
            ending: Ending::Signal(libc::SIGABRT),
            diagnostic: "patina: SUD trapped unsupported syscall pidfd_open (nr",
        },
    }],
    ..DEFAULTS
};
