//! proc/kcmp — comparing kernel objects of the caller with themselves
//! (kernel/kcmp.c, `CONFIG_KCMP`), as 6.8 answers it:
//!
//! * two descriptors of one open file are the same object (0), and a second
//!   open of the same path is another one — answered 1 or 2, an order of
//!   the objects' obfuscated addresses, which the stream records only as
//!   "distinct" (their order is the host's business), though swapping the
//!   pair must swap the answer;
//! * the caller shares its address space, descriptor table, filesystem
//!   state, signal handlers, I/O context and semaphore undo list with
//!   itself (0 for `KCMP_VM`, `KCMP_FILES`, `KCMP_FS`, `KCMP_SIGHAND`,
//!   `KCMP_IO`, `KCMP_SYSVSEM`);
//! * an epoll instance's registered target is the file it names
//!   (`KCMP_EPOLL_TFD`: 0), and a descriptor it does not watch is `ENOENT`;
//! * an unknown type is `EINVAL`, a descriptor not open `EBADF`, and a pid
//!   no process has `ESRCH`.
//!
//! The ptrace-mode check kcmp makes passes for the caller's own process;
//! another process is never named. glibc wraps no kcmp, so the scenario
//! runs through the kernel vehicles.

use crate::catalog::{Arc, DEFAULTS, Gap, Scenario, Status};
use crate::compare::{Ending, Failure};
use crate::observe::{Id, Norm};
use crate::probe::{AT_FDCWD, CLOSED_FD, NO_SUCH_PID, Probe, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

/// `enum kcmp_type` (include/uapi/linux/kcmp.h).
const KCMP_FILE: i64 = 0;
const KCMP_VM: i64 = 1;
const KCMP_FILES: i64 = 2;
const KCMP_FS: i64 = 3;
const KCMP_SIGHAND: i64 = 4;
const KCMP_IO: i64 = 5;
const KCMP_SYSVSEM: i64 = 6;
const KCMP_EPOLL_TFD: i64 = 7;
/// `KCMP_TYPES`: one past the last type.
const KCMP_TYPES: i64 = 8;

/// `struct kcmp_epoll_slot`.
#[repr(C)]
struct EpollSlot {
    efd: u32,
    tfd: u32,
    toff: u32,
}

/// `kcmp(pid, pid, kind, idx1, idx2)` of the caller's own `pid` (or `pid1`
/// when given). A distinct pair's 1 or 2 is recorded as 1 with the field
/// `distinct`: which of two objects orders first is the host's business.
fn kcmp(
    p: &Probe,
    pid: i32,
    pid1: Option<i32>,
    kind: i64,
    idx1: i64,
    idx2: i64,
    what: &str,
) -> i64 {
    let first = pid1.unwrap_or(pid);
    let result = p.call_unrecorded(
        Syscall::N_kcmp,
        [first as i64, pid as i64, kind, idx1, idx2, 0],
    );
    let distinct = result == 1 || result == 2;
    p.rec
        .event(Syscall::N_kcmp.name(), if distinct { 1 } else { result })
        .arg("pid1", first)
        .norm("args.pid1", Norm::Identity(Id::Process))
        .arg("pid2", pid)
        .norm("args.pid2", Norm::Identity(Id::Process))
        .arg("type", kind)
        .arg("objects", what)
        .field("distinct", distinct)
        .emit();
    result
}

pub fn run(p: &Probe) {
    let pid = p.getpid() as i32;
    let path = format!("{}/object", p.dir());
    let file = p.openat(AT_FDCWD, &path, O_RDWR | O_CREAT | O_EXCL, 0o644);
    p.require("create a file", file >= 0);
    let dup = p.dup(file);
    p.require("duplicate it", dup >= 0);
    let reopened = p.openat(AT_FDCWD, &path, O_RDONLY, 0);
    p.require("open it again", reopened >= 0);
    let (file, reopened) = (i64::from(file), i64::from(reopened));

    p.check(
        "two descriptors of one open file are the same object",
        kcmp(p, pid, None, KCMP_FILE, file, dup, "dup") == 0,
    );
    let forward = kcmp(p, pid, None, KCMP_FILE, file, reopened, "reopened");
    let backward = kcmp(p, pid, None, KCMP_FILE, reopened, file, "reopened-swapped");
    p.check(
        "a second open is another object, and swapping the pair swaps the order",
        matches!((forward, backward), (1, 2) | (2, 1)),
    );
    for (kind, label) in [
        (KCMP_VM, "the caller shares its address space with itself"),
        (
            KCMP_FILES,
            "the caller shares its descriptor table with itself",
        ),
        (
            KCMP_FS,
            "the caller shares its filesystem state with itself",
        ),
        (
            KCMP_SIGHAND,
            "the caller shares its signal handlers with itself",
        ),
        (KCMP_IO, "the caller shares its I/O context with itself"),
        (
            KCMP_SYSVSEM,
            "the caller shares its semaphore undo list with itself",
        ),
    ] {
        p.check(label, kcmp(p, pid, None, kind, 0, 0, "self") == 0);
    }

    let epfd = p.epoll_create1(EPOLL_CLOEXEC);
    p.require("create an epoll instance", epfd >= 0);
    let (r, [rd, wr]) = p.pipe2(O_CLOEXEC);
    p.require("create a pipe", r == 0);
    p.require(
        "watch the pipe's read end",
        p.epoll_ctl(epfd, EPOLL_CTL_ADD, rd, EPOLLIN as u32, 7) == 0,
    );
    let watched = EpollSlot {
        efd: epfd as u32,
        tfd: rd as u32,
        toff: 0,
    };
    p.check(
        "an epoll target is the file it names",
        kcmp(
            p,
            pid,
            None,
            KCMP_EPOLL_TFD,
            i64::from(rd),
            &watched as *const EpollSlot as i64,
            "epoll-target",
        ) == 0,
    );
    let unwatched = EpollSlot {
        tfd: wr as u32,
        ..watched
    };
    p.check(
        "a target the epoll instance does not watch is ENOENT",
        kcmp(
            p,
            pid,
            None,
            KCMP_EPOLL_TFD,
            i64::from(wr),
            &unwatched as *const EpollSlot as i64,
            "epoll-unwatched",
        ) == neg(ENOENT),
    );

    p.check(
        "an unknown type is EINVAL",
        kcmp(p, pid, None, KCMP_TYPES, 0, 0, "self") == neg(EINVAL),
    );
    p.check(
        "a descriptor not open is EBADF",
        kcmp(
            p,
            pid,
            None,
            KCMP_FILE,
            file,
            i64::from(CLOSED_FD),
            "closed",
        ) == neg(EBADF),
    );
    p.check(
        "a pid no process has is ESRCH",
        kcmp(p, pid, Some(NO_SUCH_PID), KCMP_VM, 0, 0, "no-such-pid") == neg(ESRCH),
    );
    for fd in [
        i64::from(rd),
        i64::from(wr),
        i64::from(epfd),
        reopened,
        dup,
        file,
    ] {
        p.close(fd as i32);
    }
}

pub const SCENARIO: Scenario = Scenario {
    name: "proc/kcmp",
    run,
    vehicles: Vehicle::KERNEL,
    covers: &[Syscall::N_kcmp],
    gaps: &[Gap {
        status: Status::Pending(Arc::SignalsThreadsProcess),
        vehicles: Vehicle::KERNEL,
        what: "kcmp is Trap(unmodeled) in the registry (the signals arc answers it for the process itself over the unified descriptor table), so the SUD dispatcher aborts at the first kcmp",
        failure: Failure::Stops {
            events: 4,
            ending: Ending::Signal(libc::SIGABRT),
            diagnostic: "patina: SUD trapped unsupported syscall kcmp (nr",
        },
    }],
    ..DEFAULTS
};
