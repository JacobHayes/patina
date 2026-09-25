//! readiness/fanotify — an unprivileged fanotify group on the run directory
//! (fanotify(7), fanotify_init(2), fanotify_mark(2);
//! fs/notify/fanotify/fanotify_user.c):
//!
//! * an unprivileged group must report file handles (`FAN_REPORT_FID`) and
//!   be a notification class: a content class, or no file handles, is
//!   `EPERM`; so is a mount mark (`CAP_SYS_ADMIN`);
//! * an inode mark on the directory with `FAN_CREATE` reports a file
//!   created in it: one event of metadata version 3, mask `FAN_CREATE`, no
//!   descriptor (`FAN_NOFD`), this process's pid, carrying a file-handle
//!   record (`FAN_EVENT_INFO_TYPE_FID`); the group polls readable while it
//!   is queued, and a read with nothing queued is `EAGAIN`;
//! * unknown mark flags are `EINVAL`.
//!
//! The file handle's bytes are the host filesystem's business and are not
//! recorded. Under patina fanotify is a named trap by design
//! (docs/arcs/syscall-conformance.md §6, network + readiness), so the
//! scenario runs through the kernel vehicles only: glibc's spelling of the
//! fanotify rows is `syscall(2)` again, and its other wrappers would only
//! ever be observed natively.

use crate::catalog::{DEFAULTS, Gap, KernelFloor, Need, Scenario, Status};
use crate::compare::{Ending, Failure};
use crate::observe::{Id, Norm};
use crate::probe::{AT_FDCWD, Probe, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

/// `FANOTIFY_METADATA_VERSION`.
const METADATA_VERSION: u8 = 3;
/// `FAN_EVENT_INFO_TYPE_FID`.
const INFO_FID: u8 = 1;
/// `FAN_NOFD`: an event with no descriptor.
const NOFD: i32 = -1;
/// The fixed part of `struct fanotify_event_metadata`.
const METADATA: usize = 24;

fn init(p: &Probe, flags: u32) -> i32 {
    let result = p.call_unrecorded(
        Syscall::N_fanotify_init,
        [i64::from(flags), i64::from(O_RDONLY), 0, 0, 0, 0],
    );
    p.rec
        .event("fanotify_init", result)
        .arg("flags", flags)
        .norm("ret", Norm::Relative("fd"))
        .emit();
    result as i32
}

fn mark(p: &Probe, fd: i32, flags: u32, mask: u64, path: &str) -> i64 {
    let c = std::ffi::CString::new(path).expect("no NUL in the path");
    let result = p.call_unrecorded(
        Syscall::N_fanotify_mark,
        [
            i64::from(fd),
            i64::from(flags),
            mask as i64,
            i64::from(AT_FDCWD),
            c.as_ptr() as i64,
            0,
        ],
    );
    p.rec
        .event("fanotify_mark", result)
        .arg("fd", fd)
        .norm("args.fd", Norm::Relative("fd"))
        .arg("flags", flags)
        .arg("mask", mask)
        .arg("path", path)
        .emit();
    result
}

pub fn run(p: &Probe) {
    let root = p.dir();
    let base = FAN_CLOEXEC | FAN_NONBLOCK;
    p.check(
        "an unprivileged content-class group is EPERM",
        i64::from(init(p, FAN_CLASS_CONTENT | FAN_REPORT_FID | base)) == neg(EPERM),
    );
    p.check(
        "an unprivileged group without file handles is EPERM",
        i64::from(init(p, FAN_CLASS_NOTIF | base)) == neg(EPERM),
    );
    let fd = init(p, FAN_CLASS_NOTIF | FAN_REPORT_FID | base);
    p.require("an unprivileged notification group", fd >= 0);
    p.check(
        "a mount mark is EPERM",
        mark(p, fd, FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_CREATE, &root) == neg(EPERM),
    );
    p.check(
        "unknown mark flags are EINVAL",
        mark(p, fd, FAN_MARK_ADD | 0x8000_0000, FAN_CREATE, &root) == neg(EINVAL),
    );
    p.check(
        "an inode mark on the directory",
        mark(p, fd, FAN_MARK_ADD, FAN_CREATE, &root) == 0,
    );
    p.check("nothing queued: EAGAIN", p.read(fd, 256).0 == neg(EAGAIN));
    let (n, _) = p.ppoll(&[(fd, POLLIN)], Some(0));
    p.check("nothing queued: not readable", n == 0);
    let created = p.openat(
        AT_FDCWD,
        &format!("{root}/created"),
        O_WRONLY | O_CREAT,
        0o600,
    );
    p.require("create a file", created >= 0);
    p.close(created);
    let (n, revents) = p.ppoll(&[(fd, POLLIN)], Some(0));
    p.check(
        "an event queued: readable",
        n == 1 && revents == vec![POLLIN],
    );
    let mut buf = [0u8; 256];
    let got = p.call_unrecorded(
        Syscall::N_read,
        [
            i64::from(fd),
            buf.as_mut_ptr() as i64,
            buf.len() as i64,
            0,
            0,
            0,
        ],
    );
    let len = u32::from_ne_bytes(buf[0..4].try_into().unwrap()) as i64;
    let version = buf[4];
    let mask = u64::from_ne_bytes(buf[8..16].try_into().unwrap());
    let event_fd = i32::from_ne_bytes(buf[16..20].try_into().unwrap());
    let pid = i32::from_ne_bytes(buf[20..24].try_into().unwrap());
    let info = buf[METADATA];
    p.rec
        .event("read", got)
        .arg("fd", fd)
        .norm("args.fd", Norm::Relative("fd"))
        .field("whole", got == len)
        .field("version", version)
        .field("mask", mask)
        .field("event_fd", event_fd)
        .field("pid", pid)
        .norm("fields.pid", Norm::Identity(Id::Process))
        .field("info_type", info)
        .emit();
    let me = p.getpid();
    p.check(
        "one FAN_CREATE event: version 3, no descriptor, this process, a file-handle record",
        got > 0
            && got == len
            && version == METADATA_VERSION
            && mask == FAN_CREATE
            && event_fd == NOFD
            && i64::from(pid) == me
            && info == INFO_FID,
    );
    p.check("drained: EAGAIN", p.read(fd, 256).0 == neg(EAGAIN));
    p.close(fd);
}

pub const SCENARIO: Scenario = Scenario {
    name: "readiness/fanotify",
    run,
    covers: &[
        Syscall::N_fanotify_init,
        Syscall::N_fanotify_mark,
        Syscall::N_read,
        Syscall::N_ppoll,
        Syscall::N_openat,
        Syscall::N_getpid,
        Syscall::N_close,
    ],
    vehicles: Vehicle::KERNEL,
    needs: &[Need::Fanotify, Need::Unprivileged],
    kernel_floor: Some(KernelFloor {
        release: "5.13",
        why: "unprivileged fanotify groups (fs/notify/fanotify/fanotify_user.c)",
    }),
    gaps: &[Gap {
        status: Status::ByDesign,
        vehicles: Vehicle::KERNEL,
        what: "fanotify is a named trap (docs/arcs/syscall-conformance.md §6: fanotify → named trap); the native oracle alone observes the group",
        failure: Failure::Stops {
            events: 0,
            ending: Ending::Signal(libc::SIGABRT),
            diagnostic: "patina: SUD trapped unsupported syscall fanotify_init",
        },
    }],
    ..DEFAULTS
};
