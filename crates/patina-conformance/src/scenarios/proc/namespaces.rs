//! proc/namespaces — leaving and joining namespaces (kernel/fork.c
//! `ksys_unshare`, kernel/nsproxy.c `setns`), for the unprivileged caller
//! the virtual kernel models:
//!
//! * `unshare` of nothing, or of what only the caller holds (its descriptor
//!   table, `CLONE_FILES`; its root, cwd and umask, `CLONE_FS`; its System V
//!   semaphore undo list, `CLONE_SYSVSEM`) needs no privilege and answers 0;
//! * `unshare` refuses a flag it does not take (`EINVAL`) and, while another
//!   thread lives, anything that would split the thread group
//!   (`check_unshare_flags`: `CLONE_THREAD`, `CLONE_SIGHAND`, `CLONE_VM`, and
//!   `CLONE_NEWUSER`, which implies `CLONE_THREAD`: `EINVAL`); every other
//!   new namespace needs `CAP_SYS_ADMIN` (`unshare_nsproxy_namespaces`:
//!   `EPERM`). A new user namespace needs no capability, so it is only ever
//!   asked for while a second thread makes it `EINVAL`: whether a
//!   single-threaded caller gets one is the host's user-namespace policy
//!   (`user.max_user_namespaces`, Ubuntu's AppArmor restriction), and it
//!   would move the probe.
//! * `setns` of a descriptor not open is `EBADF`, of one that is neither a
//!   namespace nor a pidfd `EINVAL`; of the caller's own UTS namespace
//!   (`/proc/self/ns/uts`) with another namespace type `EINVAL`, and
//!   otherwise `EPERM` (`CAP_SYS_ADMIN` over the namespace: `validate_ns`).
//!
//! The libc vehicle goes through glibc's `unshare` and `setns`, which the
//! shim defines.
//!
//! Were the capability checks to pass, the namespaces asked for would be the
//! probe's own (new UTS, IPC, mount, network, pid, cgroup and time
//! namespaces, or its current UTS namespace joined again): nothing outside
//! the probe changes. The harness runs the scenario only for an unprivileged
//! caller, and the probe stops before any call unless it is one.

use crate::catalog::{Arc, DEFAULTS, Gap, Need, Scenario, Status};
use crate::compare::{Difference, Ending, Failure, Observed};
use crate::probe::{AT_FDCWD, Probe, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

/// `CSIGNAL`'s low bit: no namespace or sharing flag.
const UNKNOWN_FLAG: i64 = 0x1;

pub fn run(p: &Probe) {
    p.require_unprivileged();
    let unshare = |flags: c_int| p.call_observed(Syscall::N_unshare, [flags as i64, 0, 0, 0, 0, 0]);
    for (flag, label) in [
        (0, "unshare of nothing needs no privilege"),
        (
            CLONE_FILES,
            "unsharing its descriptor table needs no privilege",
        ),
        (
            CLONE_FS,
            "unsharing its root, cwd and umask needs no privilege",
        ),
        (
            CLONE_SYSVSEM,
            "unsharing its semaphore undo list needs no privilege",
        ),
    ] {
        p.check(label, unshare(flag) == 0);
    }
    p.check(
        "unshare of a flag it does not take is EINVAL",
        p.call_observed(Syscall::N_unshare, [UNKNOWN_FLAG, 0, 0, 0, 0, 0]) == neg(EINVAL),
    );
    for (flag, label) in [
        (
            CLONE_NEWUTS,
            "a new UTS namespace is EPERM (no CAP_SYS_ADMIN)",
        ),
        (CLONE_NEWIPC, "a new IPC namespace is EPERM"),
        (CLONE_NEWNS, "a new mount namespace is EPERM"),
        (CLONE_NEWNET, "a new network namespace is EPERM"),
        (CLONE_NEWPID, "a new pid namespace is EPERM"),
        (CLONE_NEWCGROUP, "a new cgroup namespace is EPERM"),
        (CLONE_NEWTIME, "a new time namespace is EPERM"),
    ] {
        p.check(label, unshare(flag) == neg(EPERM));
    }

    let (release, parked) = std::sync::mpsc::channel::<()>();
    let other = std::thread::spawn(move || {
        let _ = parked.recv();
    });
    for (flag, label) in [
        (
            CLONE_NEWUSER,
            "a new user namespace with another thread alive is EINVAL",
        ),
        (
            CLONE_THREAD,
            "unsharing the thread group with another thread alive is EINVAL",
        ),
        (
            CLONE_SIGHAND,
            "unsharing the signal handlers with another thread alive is EINVAL",
        ),
        (
            CLONE_VM,
            "unsharing the address space with another thread alive is EINVAL",
        ),
    ] {
        p.check(label, unshare(flag) == neg(EINVAL));
    }
    release.send(()).unwrap();
    other.join().unwrap();

    let setns = |fd: i32, kind: c_int| {
        p.call_observed(Syscall::N_setns, [fd as i64, kind as i64, 0, 0, 0, 0])
    };
    p.check(
        "setns of a descriptor not open is EBADF",
        setns(-1, 0) == neg(EBADF),
    );
    let dir = p.openat(AT_FDCWD, &p.dir(), O_RDONLY | O_DIRECTORY, 0);
    p.require("open the run directory", dir >= 0);
    p.check(
        "setns of a descriptor that is no namespace is EINVAL",
        setns(dir, 0) == neg(EINVAL),
    );
    p.close(dir);
    let uts = p.openat(AT_FDCWD, "/proc/self/ns/uts", O_RDONLY | O_CLOEXEC, 0);
    p.require("open the caller's UTS namespace", uts >= 0);
    p.check(
        "setns naming another namespace type is EINVAL",
        setns(uts, CLONE_NEWNET) == neg(EINVAL),
    );
    p.check(
        "joining a UTS namespace is EPERM (no CAP_SYS_ADMIN)",
        setns(uts, CLONE_NEWUTS) == neg(EPERM),
    );
    p.check("with any type too", setns(uts, 0) == neg(EPERM));
    p.close(uts);
}

pub const SCENARIO: Scenario = Scenario {
    name: "proc/namespaces",
    run,
    covers: &[
        Syscall::N_unshare,
        Syscall::N_setns,
        Syscall::N_openat,
        Syscall::N_close,
    ],
    symbols: &["unshare", "setns", "openat", "close"],
    needs: &[Need::Unprivileged],
    gaps: &[
        Gap {
            status: Status::Pending(Arc::Privileged),
            vehicles: Vehicle::ALL,
            what: "the virtual filesystem has no namespace files: /proc/self/ns/uts is ENOENT where the kernel opens the caller's UTS namespace",
            failure: Failure::Differs(&[
                Difference::field(38, "openat", "errno", Observed::Str("ENOENT")),
                Difference::field(38, "openat", "ret", Observed::Int(-1)),
            ]),
        },
        Gap {
            status: Status::Pending(Arc::Privileged),
            vehicles: Vehicle::ALL,
            what: "without a namespace file the scenario cannot continue, so setns's namespace-type and CAP_SYS_ADMIN checks are never reached (patina-native-shim sud/privileged/process.rs setns refuses every descriptor the model holds)",
            failure: Failure::Stops {
                events: 39,
                ending: Ending::Exit(101),
                diagnostic: "proc/namespaces: cannot continue: open the caller's UTS namespace",
            },
        },
    ],
    ..DEFAULTS
};
