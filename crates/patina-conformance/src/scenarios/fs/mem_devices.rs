//! fs/mem_devices — the memory devices as nodes and as files
//! (drivers/char/mem.c's `null`, `zero` and `full`, drivers/char/random.c's
//! `random` and `urandom`, devtmpfs nodes), by path and by descriptor:
//!
//! * each is a root-owned `0666` character device (major 1) with one link and
//!   no size, on a mount other than the root's, and a descriptor of it names
//!   the same node;
//! * the caller may read and write it but not execute it (`access`); changing
//!   its mode is `EPERM` (not the owner), truncating it `EINVAL` (no regular
//!   file), removing it `EACCES` (`/dev` is root's), making a directory over
//!   it `EEXIST`, and reading it as a link `EINVAL`;
//! * an open refuses `O_CREAT|O_EXCL` (`EEXIST`) and `O_DIRECTORY`
//!   (`ENOTDIR`); a read-only one opens it, `O_CREAT`, `O_TRUNC` and
//!   `O_APPEND` included, and `null`, `zero` and `full` open for writing too;
//!   a descriptor seeks nowhere (`null_lseek`, `noop_llseek`: 0);
//! * `null` reads end of file, `zero` and `full` read zeros, `random` and
//!   `urandom` read as many bytes as asked; `null` and `zero` take every
//!   write and `full` refuses it (`ENOSPC`); a read of a write-only
//!   descriptor and a write to a read-only one are `EBADF`;
//! * only `random` has a poll method, so epoll takes it and refuses the rest,
//!   and it polls readable alone where the rest poll readable and writable
//!   (`EPERM`); `FIONREAD` goes to the device's ioctl: `random_ioctl`
//!   refuses it (`EINVAL`), and `mem.c`'s devices have none (`ENOTTY`).
//!
//! Nothing here writes to an entropy device (which feeds the input pool), and
//! the entropy devices' bytes are not recorded: they are the host's own.

use crate::catalog::{DEFAULTS, Scenario};
use crate::probe::{AT_FDCWD, IoctlArg, Probe, neg};
use libc::*;
use patina_dst_syscalls::Syscall;
use std::ffi::CStr;

/// What a read of a device answers.
#[derive(Clone, Copy, PartialEq)]
enum Reads {
    EndOfFile,
    Zeros,
    Entropy,
}

/// A device: its path, minor number, what it reads, and what a write to it
/// answers (`None`: never opened for writing here).
struct Device {
    path: &'static str,
    name: &'static CStr,
    minor: u32,
    reads: Reads,
    write: Option<c_int>,
}

const DEVICES: [Device; 5] = [
    Device {
        path: "/dev/null",
        name: c"/dev/null",
        minor: 3,
        reads: Reads::EndOfFile,
        write: Some(0),
    },
    Device {
        path: "/dev/zero",
        name: c"/dev/zero",
        minor: 5,
        reads: Reads::Zeros,
        write: Some(0),
    },
    Device {
        path: "/dev/full",
        name: c"/dev/full",
        minor: 7,
        reads: Reads::Zeros,
        write: Some(ENOSPC),
    },
    Device {
        path: "/dev/random",
        name: c"/dev/random",
        minor: 8,
        reads: Reads::Entropy,
        write: None,
    },
    Device {
        path: "/dev/urandom",
        name: c"/dev/urandom",
        minor: 9,
        reads: Reads::Entropy,
        write: None,
    },
];

/// Opens of a device and their answers (0: a descriptor).
const OPENS: [(c_int, c_int); 6] = [
    (O_RDONLY, 0),
    (O_RDONLY | O_TRUNC, 0),
    (O_RDONLY | O_CREAT, 0),
    (O_RDONLY | O_APPEND, 0),
    (O_RDONLY | O_CREAT | O_EXCL, EEXIST),
    (O_RDONLY | O_DIRECTORY, ENOTDIR),
];

/// Writing opens of the devices that take writes.
const WRITING_OPENS: [c_int; 4] = [O_WRONLY, O_RDWR, O_WRONLY | O_TRUNC, O_WRONLY | O_APPEND];

/// `STATX_MNT_ID_UNIQUE` (6.8 `uapi/linux/stat.h`).
const STATX_MNT_ID_UNIQUE: u32 = 0x4000;

/// How many bytes each read asks for.
const ASK: usize = 16;

/// `statx` of `name` for its unique mount id, or `None`.
fn mount_of(p: &Probe, name: &CStr) -> Option<u64> {
    // SAFETY: plain data.
    let mut buf: statx = unsafe { std::mem::zeroed() };
    let r = p.call_observed(
        Syscall::N_statx,
        [
            AT_FDCWD as i64,
            name.as_ptr() as i64,
            0,
            STATX_MNT_ID_UNIQUE as i64,
            &mut buf as *mut statx as i64,
            0,
        ],
    );
    (r == 0 && buf.stx_mask & STATX_MNT_ID_UNIQUE != 0).then_some(buf.stx_mnt_id)
}

pub fn run(p: &Probe) {
    let root = mount_of(p, c"/");
    p.require("statx of the root names its mount", root.is_some());
    let epfd = p.epoll_create1(EPOLL_CLOEXEC);
    p.require("epoll_create1", epfd >= 0);
    for device in &DEVICES {
        node(p, device, root);
        io(p, device, epfd);
        paths(p, device);
    }
    p.close(epfd);
}

/// The node, by path and by descriptor.
fn node(p: &Probe, device: &Device, root: Option<u64>) {
    let path = device.path;
    let (r, node) = p.newfstatat(AT_FDCWD, path, 0);
    p.check(
        &format!("{path} is a root-owned 0666 character device with one link and no size"),
        r == 0
            && node.as_ref().is_some_and(|node| {
                node.kind == "chr"
                    && node.perm == 0o666
                    && node.uid == 0
                    && node.nlink == 1
                    && node.size == 0
            }),
    );
    // SAFETY: plain data.
    let mut raw: stat = unsafe { std::mem::zeroed() };
    let r = p.call_observed(
        Syscall::N_newfstatat,
        [
            AT_FDCWD as i64,
            device.name.as_ptr() as i64,
            &mut raw as *mut stat as i64,
            0,
            0,
            0,
        ],
    );
    p.check(
        &format!("{path}'s device is 1:{}", device.minor),
        r == 0 && major(raw.st_rdev) == 1 && minor(raw.st_rdev) == device.minor,
    );
    p.check(
        &format!("{path} is on a mount other than the root's"),
        mount_of(p, device.name).is_some_and(|mount| Some(mount) != root),
    );
    let fd = p.openat(AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
    p.require(&format!("open {path}"), fd >= 0);
    let (_, opened) = p.fstat(fd);
    p.check(
        &format!("a descriptor of {path} names the same node"),
        opened
            .zip(node)
            .is_some_and(|(opened, node)| opened.ino == node.ino && opened.kind == "chr"),
    );
    p.check(
        &format!("{path} seeks nowhere"),
        p.lseek(fd, 5, SEEK_SET) == 0,
    );
    p.check(
        &format!("fchmod of {path} is EPERM (not the owner)"),
        p.fchmod(fd, 0o600) == neg(EPERM),
    );
    p.close(fd);
}

/// Reads, writes, readiness and the device's own ioctl.
fn io(p: &Probe, device: &Device, epfd: i32) {
    let path = device.path;
    let fd = p.openat(AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
    p.require(&format!("open {path}"), fd >= 0);
    match device.reads {
        Reads::EndOfFile => {
            let (r, _) = p.read(fd, ASK);
            p.check(&format!("a read of {path} is end of file"), r == 0);
        }
        Reads::Zeros => {
            let (r, data) = p.read(fd, ASK);
            p.check(
                &format!("a read of {path} is zeros"),
                r == ASK as i64 && data.iter().all(|&byte| byte == 0),
            );
        }
        Reads::Entropy => {
            let mut buf = [0u8; ASK];
            let r = p.call_observed(
                Syscall::N_read,
                [fd as i64, buf.as_mut_ptr() as i64, ASK as i64, 0, 0, 0],
            );
            p.check(
                &format!("a read of {path} fills the buffer"),
                r == ASK as i64,
            );
        }
    }
    p.check(
        &format!("a write to read-only {path} is EBADF"),
        p.write(fd, b"bytes") == neg(EBADF),
    );
    let polls = device.minor == 8;
    p.check(
        &format!(
            "epoll {} {path}",
            if polls { "takes" } else { "refuses (EPERM)" }
        ),
        p.epoll_ctl(epfd, EPOLL_CTL_ADD, fd, EPOLLIN as u32, 0)
            == if polls { 0 } else { neg(EPERM) },
    );
    // `random_poll` answers readable alone; a device without a poll method
    // answers `DEFAULT_POLLMASK`, readable and writable.
    let (_, revents) = p.ppoll(&[(fd, POLLIN | POLLOUT)], Some(0));
    p.check(
        &format!("{path} polls as its poll method answers"),
        revents.first().copied() == Some(if polls { POLLIN } else { POLLIN | POLLOUT }),
    );
    let own = if device.reads == Reads::Entropy {
        EINVAL
    } else {
        ENOTTY
    };
    p.check(
        &format!("FIONREAD on {path} is the device's own ioctl's answer"),
        p.ioctl(fd, FIONREAD, "FIONREAD", IoctlArg::Out).0 == neg(own),
    );
    p.close(fd);

    let Some(answer) = device.write else {
        return;
    };
    for flags in WRITING_OPENS {
        let fd = p.openat(AT_FDCWD, path, flags | O_CLOEXEC, 0);
        p.check(&format!("{path} opens with flags {flags:#o}"), fd >= 0);
        if fd < 0 {
            continue;
        }
        p.check(
            &format!("a write to {path} opened {flags:#o} answers {answer}"),
            p.write(fd, b"bytes") == if answer == 0 { 5 } else { neg(answer) },
        );
        if flags & O_ACCMODE == O_WRONLY {
            p.check(
                &format!("a read of write-only {path} is EBADF"),
                p.read(fd, ASK).0 == neg(EBADF),
            );
        }
        p.close(fd);
    }
}

/// What the path answers to calls that would change or look through it.
fn paths(p: &Probe, device: &Device) {
    let path = device.path;
    for (mode, answer, label) in [
        (F_OK, 0, "exists"),
        (R_OK | W_OK, 0, "may be read and written"),
        (X_OK, EACCES, "may not be executed"),
    ] {
        p.check(
            &format!("{path} {label}"),
            p.faccessat(AT_FDCWD, path, mode, 0, false)
                == if answer == 0 { 0 } else { neg(answer) },
        );
    }
    p.check(
        &format!("changing {path}'s mode is EPERM"),
        p.fchmodat(AT_FDCWD, path, 0o666) == neg(EPERM),
    );
    p.check(
        &format!("truncating {path} is EINVAL"),
        p.truncate(path, 0) == neg(EINVAL),
    );
    p.check(
        &format!("removing {path} is EACCES"),
        p.unlinkat(AT_FDCWD, path, 0) == neg(EACCES),
    );
    p.check(
        &format!("a directory over {path} is EEXIST"),
        p.mkdirat(AT_FDCWD, path, 0o755) == neg(EEXIST),
    );
    p.check(
        &format!("reading {path} as a link is EINVAL"),
        p.readlinkat(AT_FDCWD, path, 64).0 == neg(EINVAL),
    );
    for (flags, answer) in OPENS {
        let fd = p.openat(AT_FDCWD, path, flags | O_CLOEXEC, 0o600);
        p.check(
            &format!("an open of {path} with flags {flags:#o} answers {answer}"),
            if answer == 0 {
                fd >= 0
            } else {
                fd == neg(answer) as i32
            },
        );
        if fd >= 0 {
            p.close(fd);
        }
    }
}

pub const SCENARIO: Scenario = Scenario {
    name: "fs/mem_devices",
    run,
    covers: &[
        Syscall::N_newfstatat,
        Syscall::N_statx,
        Syscall::N_openat,
        Syscall::N_fstat,
        Syscall::N_lseek,
        Syscall::N_fchmod,
        Syscall::N_read,
        Syscall::N_write,
        Syscall::N_epoll_create1,
        Syscall::N_epoll_ctl,
        Syscall::N_ppoll,
        Syscall::N_ioctl,
        Syscall::N_close,
        Syscall::N_faccessat,
        Syscall::N_fchmodat,
        Syscall::N_truncate,
        Syscall::N_unlinkat,
        Syscall::N_mkdirat,
        Syscall::N_readlinkat,
    ],
    symbols: &[
        "fstatat",
        "statx",
        "openat",
        "fstat",
        "lseek",
        "fchmod",
        "read",
        "write",
        "epoll_create1",
        "epoll_ctl",
        "ppoll",
        "ioctl",
        "close",
        "faccessat",
        "fchmodat",
        "truncate",
        "unlinkat",
        "mkdirat",
        "readlinkat",
    ],
    ..DEFAULTS
};
