//! proc/pidfd — a descriptor for the caller's own process, and for init
//! (kernel/pid.c `pidfd_open`, `pidfd_getfd`; kernel/signal.c
//! `pidfd_send_signal`; mm/oom_kill.c `process_mrelease`), as 6.8 answers
//! them:
//!
//! * `pidfd_open` refuses an undefined flag and 6.9's `PIDFD_THREAD`, a pid
//!   that is no process (`EINVAL` for 0 and -1) and a thread that leads no
//!   thread group (`EINVAL`: 6.8 has no thread pidfds), answers `ESRCH` for a
//!   pid past `PID_MAX_LIMIT`, and opens the caller's own process (and
//!   init): always close-on-exec, read-write, non-blocking when asked, and
//!   not readable while the process runs;
//! * `pidfd_getfd` duplicates one of the caller's descriptors through its
//!   own pidfd (a ptrace-mode check the caller always passes on itself):
//!   the copy shares the open file and is close-on-exec; a flag is `EINVAL`,
//!   a target descriptor not open, or a descriptor that is no pidfd,
//!   `EBADF`, and one of init's descriptors `EPERM` (the ptrace-mode check
//!   init does not pass);
//! * `setns` through a pidfd refuses the caller's own user namespace
//!   (`EINVAL`) and joining another namespace of its own without
//!   `CAP_SYS_ADMIN` (`EPERM`), and init's namespaces at the ptrace-mode check
//!   (`EPERM`);
//! * `pidfd_send_signal` probes with signal 0 (0) and refuses it to init,
//!   root's process (`EPERM`), refuses an undefined
//!   flag, 6.9's `PIDFD_SIGNAL_THREAD` and an invalid signal (`EINVAL`) and
//!   a descriptor that is no pidfd (`EBADF`), and sends a blocked SIGUSR1 to
//!   the caller as a process-directed signal from itself (`SI_USER`), which
//!   `rt_sigtimedwait` then takes; with a siginfo, one naming another signal
//!   is `EINVAL` and an unreadable one `EFAULT`, and one the caller queues to
//!   itself (`SI_QUEUE`) arrives as sent;
//! * `process_mrelease` refuses a flag before looking at the descriptor
//!   (`EINVAL`) and a descriptor that is no pidfd (`EBADF`), and a live
//!   process, the caller's or init's, whose memory is not being freed
//!   (`EINVAL`): nothing is ever reaped.
//!
//! The libc vehicle goes through glibc 2.36's `pidfd_open`, `pidfd_getfd`,
//! `pidfd_send_signal` and `process_mrelease`, and its `setns`.

use super::ids::INIT_SHARES_THE_CREDENTIAL;
use crate::catalog::{DEFAULTS, Gap, Scenario, Status};
use crate::compare::{Difference, Failure, Observed};
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

/// `pidfd_send_signal` with a siginfo, recorded by what it holds.
fn send_info(p: &Probe, pidfd: i32, sig: i32, info: *const siginfo_t, what: &str) -> i64 {
    p.observed(
        Syscall::N_pidfd_send_signal,
        [pidfd as i64, sig as i64, info as i64, 0, 0, 0],
        &[
            ("pidfd", "self".into()),
            ("sig", sig.into()),
            ("info", what.into()),
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
    let (tid_sender, tid) = std::sync::mpsc::channel();
    let (release, parked) = std::sync::mpsc::channel::<()>();
    let other = std::thread::spawn(move || {
        // SAFETY: gettid has no preconditions.
        tid_sender.send(unsafe { gettid() }).unwrap();
        let _ = parked.recv();
    });
    let tid = tid.recv().unwrap();
    p.check(
        "a thread that leads no thread group is EINVAL",
        p.observed(
            Syscall::N_pidfd_open,
            [tid as i64, 0, 0, 0, 0, 0],
            &[("pid", "another-thread".into()), ("flags", 0.into())],
        ) == neg(EINVAL),
    );
    release.send(()).unwrap();
    other.join().unwrap();
    let init = p.pidfd_open(1, 0);
    p.require("open init's pidfd", init >= 0);

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
        "taking one of init's descriptors is EPERM (a ptrace attach init refuses)",
        getfd(p, init, "init", 0, 0) == neg(EPERM),
    );
    for (fd, what, nstype, errno, label) in [
        (
            pidfd,
            "self",
            CLONE_NEWUSER,
            EINVAL,
            "setns into the caller's own user namespace is EINVAL",
        ),
        (
            pidfd,
            "self",
            CLONE_NEWUTS,
            EPERM,
            "setns into a namespace through the caller's pidfd is EPERM (no CAP_SYS_ADMIN)",
        ),
        (
            init,
            "init",
            CLONE_NEWUTS,
            EPERM,
            "setns into init's namespaces is EPERM (the ptrace-mode check)",
        ),
    ] {
        let r = p.observed(
            Syscall::N_setns,
            [fd as i64, nstype as i64, 0, 0, 0, 0],
            &[("pidfd", what.into()), ("nstype", nstype.into())],
        );
        p.check(label, r == neg(errno));
    }

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
    p.check(
        "signal 0 through init's pidfd is EPERM: init is root's",
        send_signal(p, init, "init", 0, 0) == neg(EPERM),
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
    // SAFETY: an all-zero siginfo is a valid record to fill.
    let mut queued: siginfo_t = unsafe { std::mem::zeroed() };
    queued.si_signo = SIGUSR2;
    queued.si_code = SI_QUEUE;
    p.check(
        "a siginfo naming another signal is EINVAL",
        send_info(p, pidfd, SIGUSR1, &queued, "other-signal") == neg(EINVAL),
    );
    p.check(
        "an unreadable siginfo is EFAULT",
        send_info(p, pidfd, SIGUSR1, std::ptr::dangling(), "unmapped") == neg(EFAULT),
    );
    queued.si_signo = SIGUSR1;
    p.check(
        "the caller may queue its own siginfo to itself",
        send_info(p, pidfd, SIGUSR1, &queued, "queued") == 0,
    );
    // SAFETY: as above.
    let mut arrived: siginfo_t = unsafe { std::mem::zeroed() };
    let taken = p.rt_sigtimedwait(&usr1, Some(&mut arrived), Some(0), SIGSET_BYTES as usize);
    p.check(
        "and it arrives as sent (SI_QUEUE)",
        taken == i64::from(SIGUSR1) && arrived.si_code == SI_QUEUE,
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
    for (fd, what) in [(pidfd, "self"), (init, "init")] {
        p.check(
            &format!("process_mrelease of a live process ({what}) is EINVAL"),
            mrelease(p, fd, what, 0) == neg(EINVAL),
        );
    }
    for fd in [copy, file, nonblocking, init, pidfd] {
        p.close(fd);
    }
}

pub const SCENARIO: Scenario = Scenario {
    name: "proc/pidfd",
    run,
    vehicles: Vehicle::ALL,
    covers: &[
        Syscall::N_pidfd_open,
        Syscall::N_pidfd_getfd,
        Syscall::N_pidfd_send_signal,
        Syscall::N_process_mrelease,
    ],
    symbols: &[
        "pidfd_open",
        "pidfd_getfd",
        "pidfd_send_signal",
        "process_mrelease",
        "setns",
    ],
    gaps: &[Gap {
        status: Status::ByDesign,
        vehicles: Vehicle::ALL,
        what: INIT_SHARES_THE_CREDENTIAL,
        failure: Failure::Differs(&[
            Difference::field(56, "pidfd_send_signal", "errno", Observed::Null),
            Difference::field(56, "pidfd_send_signal", "ret", Observed::Int(0)),
            Difference::check(57, "signal 0 through init's pidfd is EPERM: init is root's"),
        ]),
    }],
    ..DEFAULTS
};
