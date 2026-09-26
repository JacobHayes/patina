//! proc/kcmp — comparing kernel objects of the caller with themselves
//! (kernel/kcmp.c, `CONFIG_KCMP`), as 6.8 answers it:
//!
//! * two descriptors of one open file are the same object (0), and a second
//!   open of the same path is another one — answered 1 or 2, an order of
//!   the objects' obfuscated addresses, which the stream records only as
//!   "distinct" (their order is the host's business), though swapping the
//!   pair must swap the answer; an `O_PATH` descriptor names an object too,
//!   and a descriptor index is an `unsigned int` (`get_file_raw_ptr`), its
//!   high bits ignored;
//! * the caller shares its address space, descriptor table, filesystem
//!   state, signal handlers, I/O context and semaphore undo list with
//!   itself (0 for `KCMP_VM`, `KCMP_FILES`, `KCMP_FS`, `KCMP_SIGHAND`,
//!   `KCMP_IO`, `KCMP_SYSVSEM`);
//! * an epoll instance's registered target is the file it names
//!   (`KCMP_EPOLL_TFD`: 0), and a descriptor it does not watch is `ENOENT`;
//!   `kcmp_epoll_target` copies the slot in (`EFAULT`), then checks the
//!   first descriptor (`EBADF`), looks up the slot's epoll descriptor
//!   (`EBADF`, and `EINVAL` for one that is not an epoll instance), then the
//!   target at its offset (`ENOENT` past the one interest);
//! * an unknown type is `EINVAL`, a descriptor not open `EBADF`, and a pid
//!   no process has `ESRCH`;
//! * a thread shares its creator's address space, descriptor table,
//!   filesystem state, signal handlers and semaphore undo list, but not its
//!   I/O context: glibc passes no `CLONE_IO`, so a thread that sets an I/O
//!   priority gets a context of its own (`set_task_ioprio`), and a thread it
//!   then creates gets another (`copy_io`, for a valid priority).
//!
//! The ptrace-mode check kcmp makes passes for the caller's own process;
//! another process is never named. glibc wraps no kcmp, so the scenario
//! runs through the kernel vehicles.

use crate::catalog::{DEFAULTS, Scenario};
use crate::observe::{Id, Norm};
use crate::probe::{AT_FDCWD, CLOSED_FD, NO_SUCH_PID, Probe, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;
use std::sync::{Barrier, mpsc};

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
/// An address no mapping covers.
const UNMAPPED: i64 = 8;
/// `ioprio_set(IOPRIO_WHO_PROCESS, 0, IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, 4))`:
/// the calling thread's best-effort I/O priority, which needs no privilege.
const WHO_PROCESS: i64 = 1;
const BEST_EFFORT_4: i64 = (2 << 13) | 4;

/// `struct kcmp_epoll_slot`.
#[repr(C)]
struct EpollSlot {
    efd: u32,
    tfd: u32,
    toff: u32,
}

/// `kcmp(pid1, pid2, kind, idx1, idx2)`. A distinct pair's 1 or 2 is
/// recorded as 1 with the field `distinct`: which of two objects orders
/// first is the host's business.
fn kcmp(p: &Probe, [first, second]: [i32; 2], kind: i64, idx1: i64, idx2: i64, what: &str) -> i64 {
    let result = p.call_unrecorded(
        Syscall::N_kcmp,
        [first as i64, second as i64, kind, idx1, idx2, 0],
    );
    let distinct = result == 1 || result == 2;
    p.rec
        .event(Syscall::N_kcmp.name(), if distinct { 1 } else { result })
        .arg("pid1", first)
        .norm("args.pid1", Norm::Identity(Id::Process))
        .arg("pid2", second)
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
        kcmp(p, [pid, pid], KCMP_FILE, file, dup, "dup") == 0,
    );
    let forward = kcmp(p, [pid, pid], KCMP_FILE, file, reopened, "reopened");
    let backward = kcmp(p, [pid, pid], KCMP_FILE, reopened, file, "reopened-swapped");
    p.check(
        "a second open is another object, and swapping the pair swaps the order",
        matches!((forward, backward), (1, 2) | (2, 1)),
    );
    let located = p.openat(AT_FDCWD, &path, O_PATH, 0);
    p.require("open it O_PATH", located >= 0);
    let located = i64::from(located);
    p.check(
        "an O_PATH descriptor names an object too",
        kcmp(p, [pid, pid], KCMP_FILE, located, located, "o-path") == 0,
    );
    p.check(
        "a descriptor index is an unsigned int: its high bits are ignored",
        kcmp(
            p,
            [pid, pid],
            KCMP_FILE,
            file | 1 << 32,
            dup,
            "index-high-bits",
        ) == 0,
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
        p.check(label, kcmp(p, [pid, pid], kind, 0, 0, "self") == 0);
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
            [pid, pid],
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
            [pid, pid],
            KCMP_EPOLL_TFD,
            i64::from(wr),
            &unwatched as *const EpollSlot as i64,
            "epoll-unwatched",
        ) == neg(ENOENT),
    );
    let slot = |efd: i32, toff: u32| EpollSlot {
        efd: efd as u32,
        tfd: rd as u32,
        toff,
    };
    let (closed, not_epoll, past) = (slot(CLOSED_FD, 0), slot(rd, 0), slot(epfd, 1));
    let at = |slot: &EpollSlot| slot as *const EpollSlot as i64;
    for (first, slot, errno, what, label) in [
        (
            CLOSED_FD,
            UNMAPPED,
            EFAULT,
            "epoll-unmapped-slot",
            "the slot is copied in first: one that cannot be read is EFAULT",
        ),
        (
            CLOSED_FD,
            at(&watched),
            EBADF,
            "epoll-closed-first",
            "then a first descriptor not open is EBADF",
        ),
        (
            rd,
            at(&closed),
            EBADF,
            "epoll-closed-efd",
            "a slot naming no open descriptor is EBADF",
        ),
        (
            rd,
            at(&not_epoll),
            EINVAL,
            "epoll-not-epoll",
            "a slot naming a descriptor that is not an epoll instance is EINVAL",
        ),
        (
            rd,
            at(&past),
            ENOENT,
            "epoll-second-offset",
            "an offset past the target's one interest is ENOENT",
        ),
    ] {
        p.check(
            label,
            kcmp(p, [pid, pid], KCMP_EPOLL_TFD, i64::from(first), slot, what) == neg(errno),
        );
    }

    p.check(
        "an unknown type is EINVAL",
        kcmp(p, [pid, pid], KCMP_TYPES, 0, 0, "self") == neg(EINVAL),
    );
    p.check(
        "a descriptor not open is EBADF",
        kcmp(
            p,
            [pid, pid],
            KCMP_FILE,
            file,
            i64::from(CLOSED_FD),
            "closed",
        ) == neg(EBADF),
    );
    p.check(
        "a pid no process has is ESRCH",
        kcmp(p, [NO_SUCH_PID, pid], KCMP_VM, 0, 0, "no-such-pid") == neg(ESRCH),
    );
    threads(p, pid);
    for fd in [
        located,
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

/// A thread sets its I/O priority and creates a second; while both wait,
/// the main thread compares its objects with theirs.
fn threads(p: &Probe, pid: i32) {
    let release = Barrier::new(3);
    let (report, reports) = mpsc::channel();
    std::thread::scope(|scope| {
        let (report, release) = (&report, &release);
        scope.spawn(move || {
            let tid = p.call_unrecorded(Syscall::N_gettid, [0; 6]) as i32;
            let set = p.call_unrecorded(
                Syscall::N_ioprio_set,
                [WHO_PROCESS, 0, BEST_EFFORT_4, 0, 0, 0],
            );
            std::thread::scope(|scope| {
                scope.spawn(move || {
                    let tid = p.call_unrecorded(Syscall::N_gettid, [0; 6]) as i32;
                    report.send(("created", tid, 0)).unwrap();
                    release.wait();
                });
                report.send(("prioritized", tid, set)).unwrap();
                release.wait();
            });
        });
        let mut tids = [0; 2];
        for _ in 0..2 {
            let (role, tid, set) = reports.recv().unwrap();
            if role == "prioritized" {
                p.require("a thread sets its own best-effort I/O priority", set == 0);
                tids[0] = tid;
            } else {
                tids[1] = tid;
            }
        }
        let [prioritized, created] = tids;
        for (kind, label) in [
            (KCMP_VM, "a thread shares its creator's address space"),
            (KCMP_FILES, "a thread shares its creator's descriptor table"),
            (KCMP_FS, "a thread shares its creator's filesystem state"),
            (
                KCMP_SIGHAND,
                "a thread shares its creator's signal handlers",
            ),
            (
                KCMP_SYSVSEM,
                "a thread shares its creator's semaphore undo list",
            ),
        ] {
            p.check(
                label,
                kcmp(p, [pid, prioritized], kind, 0, 0, "threads") == 0,
            );
        }
        let distinct = |pair, what| matches!(kcmp(p, pair, KCMP_IO, 0, 0, what), 1 | 2);
        p.check(
            "a thread that sets an I/O priority has an I/O context of its own",
            distinct([pid, prioritized], "prioritized-thread"),
        );
        p.check(
            "a thread it then creates gets another",
            distinct([prioritized, created], "created-thread"),
        );
        release.wait();
    });
}

pub const SCENARIO: Scenario = Scenario {
    name: "proc/kcmp",
    run,
    vehicles: Vehicle::KERNEL,
    covers: &[Syscall::N_kcmp],
    ..DEFAULTS
};
