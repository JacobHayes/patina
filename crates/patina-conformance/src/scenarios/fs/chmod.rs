//! fs/chmod — fchmod / fchmodat / fchmodat2: the permission bits by
//! descriptor, by path and by flagged path. chmod(2): only the 07777 bits
//! change (fs/attr.c via chmod_common keeps the type), ctime moves and mtime
//! does not, the owner keeps setuid and — in one of its own groups — setgid; fchmod needs no write access (an O_RDONLY descriptor works) but
//! an O_PATH descriptor is EBADF (fdget, not fdget_raw); a pipe's descriptor
//! reaches the pipe's own pipefs inode. fchmodat follows symlinks and ignores
//! the dirfd for an absolute path; fchmodat2 (Linux 6.6, fs/open.c
//! do_fchmodat) takes AT_SYMLINK_NOFOLLOW (EOPNOTSUPP on a symlink itself,
//! harmless on anything else) and AT_EMPTY_PATH, and any other flag is EINVAL.

use crate::catalog::{Arc, DEFAULTS, Gap, KernelFloor, Scenario, Status};
use crate::compare::{Difference, Failure, Observed};
use crate::vehicle::Vehicle;

use patina_dst_syscalls::Syscall;

use crate::probe::{AT_FDCWD, Probe, neg};
use libc::*;

fn pause(p: &Probe) {
    p.nanosleep(0, 20_000_000);
}

/// A descriptor's `(kind, permission bits)`, if fstat answers.
fn mode_of(p: &Probe, fd: i32) -> Option<(&'static str, u32)> {
    p.fstat(fd).1.map(|s| (s.kind, s.perm))
}

fn perm(p: &Probe, path: &str, flags: i32) -> Option<u32> {
    p.newfstatat(AT_FDCWD, path, flags).1.map(|s| s.perm)
}

pub fn run(p: &Probe) {
    let root = p.dir();
    let file = format!("{root}/f");
    let link = format!("{root}/l");
    let dir = format!("{root}/d");

    // ---- fchmod ------------------------------------------------------------
    let fd = p.openat(AT_FDCWD, &file, O_RDWR | O_CREAT | O_EXCL, 0o644);
    p.require("create f", fd >= 0);
    p.write(fd, b"data");
    let before = p.fstat(fd).1;
    pause(p);
    p.check("fchmod 0600", p.fchmod(fd, 0o600) == 0);
    let after = p.fstat(fd).1;
    p.check(
        "fchmod sets the bits",
        after.as_ref().is_some_and(|s| s.perm == 0o600),
    );
    p.check(
        "fchmod moves ctime forward and leaves mtime alone",
        matches!((&before, &after), (Some(b), Some(a))
            if a.ctime_ns > b.ctime_ns && a.mtime_ns == b.mtime_ns),
    );
    p.check(
        "fchmod keeps only the 07777 bits",
        p.fchmod(fd, S_IFDIR | 0o640) == 0,
    );
    p.check(
        "the file type survives fchmod's type bits",
        mode_of(p, fd) == Some(("reg", 0o640)),
    );
    // The kernel strips S_ISGID when the file's group is not one of the
    // caller's (mode_strip_sgid): a setgid run directory of a foreign group
    // would hand the file that group, so it is made the caller's own first.
    let gid = p.getgid() as u32;
    p.check(
        "fchown to the caller's own group",
        p.fchown(fd, u32::MAX, gid) == 0,
    );
    p.check(
        "fchmod stores setuid and setgid for the owner",
        p.fchmod(fd, 0o6750) == 0,
    );
    p.check(
        "the special bits are stored",
        mode_of(p, fd) == Some(("reg", 0o6750)),
    );
    let reader = p.openat(AT_FDCWD, &file, O_RDONLY, 0);
    p.require("open f read-only", reader >= 0);
    p.check(
        "fchmod through an O_RDONLY descriptor",
        p.fchmod(reader, 0o644) == 0,
    );
    p.check(
        "the change is visible through the other descriptor",
        mode_of(p, fd) == Some(("reg", 0o644)),
    );
    let location = p.openat(AT_FDCWD, &file, O_PATH, 0);
    p.require("open f O_PATH", location >= 0);
    p.check(
        "fchmod on an O_PATH descriptor is EBADF",
        p.fchmod(location, 0o600) == neg(EBADF),
    );
    p.check(
        "fchmod on a closed descriptor is EBADF",
        p.fchmod(4000, 0o600) == neg(EBADF),
    );
    p.check("mkdirat d", p.mkdirat(AT_FDCWD, &dir, 0o755) == 0);
    let dirfd = p.openat(AT_FDCWD, &dir, O_RDONLY | O_DIRECTORY, 0);
    p.require("open d", dirfd >= 0);
    p.check(
        "fchmod on a directory descriptor",
        p.fchmod(dirfd, 0o700) == 0,
    );
    p.check(
        "the directory's bits changed",
        mode_of(p, dirfd) == Some(("dir", 0o700)),
    );
    let (r, pipe) = p.pipe2(0);
    p.require("pipe2", r == 0);
    p.check(
        "a pipe starts at 0600",
        mode_of(p, pipe[0]) == Some(("fifo", 0o600)),
    );
    p.check(
        "fchmod on a pipe reaches its inode",
        p.fchmod(pipe[1], 0o640) == 0,
    );
    p.check(
        "both ends see the pipe inode's new mode",
        mode_of(p, pipe[0]) == Some(("fifo", 0o640)),
    );

    // ---- fchmodat ----------------------------------------------------------
    p.check("symlinkat l -> f", p.symlinkat("f", AT_FDCWD, &link) == 0);
    p.check(
        "fchmodat by absolute path",
        p.fchmodat(AT_FDCWD, &file, 0o640) == 0,
    );
    p.check("the bits changed", perm(p, &file, 0) == Some(0o640));
    p.check(
        "fchmodat relative to a dirfd",
        p.fchmodat(dirfd, "..", 0o750) == 0,
    );
    p.check(
        "the dirfd-relative `..` named the run directory",
        perm(p, &root, 0) == Some(0o750),
    );
    p.check(
        "fchmodat follows a symlink",
        p.fchmodat(AT_FDCWD, &link, 0o600) == 0,
    );
    p.check(
        "the target's bits changed",
        perm(p, &file, 0) == Some(0o600),
    );
    p.check(
        "the link's own mode is untouched",
        perm(p, &link, AT_SYMLINK_NOFOLLOW) == Some(0o777),
    );
    p.check(
        "fchmodat of a missing name is ENOENT",
        p.fchmodat(AT_FDCWD, &format!("{root}/missing"), 0o600) == neg(ENOENT),
    );
    p.check(
        "fchmodat through a file is ENOTDIR",
        p.fchmodat(AT_FDCWD, &format!("{file}/x"), 0o600) == neg(ENOTDIR),
    );
    p.check(
        "fchmodat relative to a file descriptor is ENOTDIR",
        p.fchmodat(fd, "x", 0o600) == neg(ENOTDIR),
    );
    p.check(
        "fchmodat relative to a closed descriptor is EBADF",
        p.fchmodat(4000, "f", 0o600) == neg(EBADF),
    );
    p.check(
        "fchmodat ignores the dirfd for an absolute path",
        p.fchmodat(4000, &file, 0o644) == 0,
    );
    p.check(
        "fchmodat of an empty path is ENOENT",
        p.fchmodat(fd, "", 0o644) == neg(ENOENT),
    );

    // ---- fchmodat2 ---------------------------------------------------------
    p.check(
        "fchmodat2 without flags",
        p.fchmodat2(AT_FDCWD, &file, 0o600, 0) == 0,
    );
    p.check("the bits changed", perm(p, &file, 0) == Some(0o600));
    p.check(
        "fchmodat2 AT_SYMLINK_NOFOLLOW on a regular file",
        p.fchmodat2(AT_FDCWD, &file, 0o640, AT_SYMLINK_NOFOLLOW) == 0,
    );
    p.check("the bits changed", perm(p, &file, 0) == Some(0o640));
    p.check(
        "fchmodat2 AT_SYMLINK_NOFOLLOW on a symlink is EOPNOTSUPP",
        p.fchmodat2(AT_FDCWD, &link, 0o600, AT_SYMLINK_NOFOLLOW) == neg(EOPNOTSUPP),
    );
    p.check(
        "the refused change left the link alone",
        perm(p, &link, AT_SYMLINK_NOFOLLOW) == Some(0o777),
    );
    p.check("and its target", perm(p, &file, 0) == Some(0o640));
    p.check(
        "fchmodat2 follows a symlink without the flag",
        p.fchmodat2(AT_FDCWD, &link, 0o604, 0) == 0,
    );
    p.check(
        "the target's bits changed",
        perm(p, &file, 0) == Some(0o604),
    );
    p.check(
        "fchmodat2 AT_EMPTY_PATH names the descriptor",
        p.fchmodat2(fd, "", 0o644, AT_EMPTY_PATH) == 0,
    );
    p.check("the bits changed", perm(p, &file, 0) == Some(0o644));
    p.check(
        "fchmodat2 AT_EMPTY_PATH works through an O_PATH descriptor",
        p.fchmodat2(location, "", 0o640, AT_EMPTY_PATH) == 0,
    );
    p.check("the bits changed", perm(p, &file, 0) == Some(0o640));
    p.check(
        "fchmodat2 of an empty path without AT_EMPTY_PATH is ENOENT",
        p.fchmodat2(fd, "", 0o600, 0) == neg(ENOENT),
    );
    p.check(
        "fchmodat2 with an unknown flag is EINVAL",
        p.fchmodat2(AT_FDCWD, &file, 0o600, AT_REMOVEDIR) == neg(EINVAL),
    );
    p.check(
        "fchmodat2 judges its flags before the path",
        p.fchmodat2(AT_FDCWD, &format!("{root}/missing"), 0o600, AT_REMOVEDIR) == neg(EINVAL),
    );

    for f in [fd, reader, location, dirfd, pipe[0], pipe[1]] {
        p.close(f);
    }
}

pub const SCENARIO: Scenario = Scenario {
    name: "fs/chmod",
    run,
    covers: &[
        Syscall::N_fchmod,
        Syscall::N_fchmodat,
        Syscall::N_fchmodat2,
        Syscall::N_openat,
        Syscall::N_write,
        Syscall::N_fstat,
        Syscall::N_newfstatat,
        Syscall::N_mkdirat,
        Syscall::N_symlinkat,
        Syscall::N_pipe2,
        Syscall::N_nanosleep,
        Syscall::N_fchown,
        Syscall::N_getgid,
        Syscall::N_close,
    ],
    symbols: &[
        "fchmod",
        "fchmodat",
        "syscall",
        "openat",
        "write",
        "fstat",
        "fstatat",
        "mkdirat",
        "symlinkat",
        "pipe2",
        "nanosleep",
        "fchown",
        "getgid",
        "close",
    ],
    kernel_floor: Some(KernelFloor {
        release: "6.6",
        why: "fchmodat2",
    }),
    gaps: &[
        Gap {
            status: Status::Pending(Arc::Fs),
            vehicles: Vehicle::ALL,
            what: "anonymous pipes have no inode: fstat and fchmod on a pipe descriptor are EBADF, where the kernel answers from the pipe's own pipefs inode (S_IFIFO 0600, owned by the caller, chmod-able); patina_fd_metadata_full / patina_fchmod refuse a pipe kind",
            failure: Failure::Differs(&[
                Difference::field(38, "fstat", "errno", Observed::Str("EBADF")),
                Difference::field(38, "fstat", "fields.gid", Observed::Null),
                Difference::field(38, "fstat", "fields.ino", Observed::Null),
                Difference::field(38, "fstat", "fields.kind", Observed::Null),
                Difference::field(38, "fstat", "fields.nlink", Observed::Null),
                Difference::field(38, "fstat", "fields.perm", Observed::Null),
                Difference::field(38, "fstat", "fields.size", Observed::Null),
                Difference::field(38, "fstat", "fields.uid", Observed::Null),
                Difference::field(38, "fstat", "ret", Observed::Int(-1)),
                Difference::check(39, "a pipe starts at 0600"),
                Difference::field(40, "fchmod", "errno", Observed::Str("EBADF")),
                Difference::field(40, "fchmod", "ret", Observed::Int(-1)),
                Difference::check(41, "fchmod on a pipe reaches its inode"),
                Difference::field(42, "fstat", "errno", Observed::Str("EBADF")),
                Difference::field(42, "fstat", "fields.gid", Observed::Null),
                Difference::field(42, "fstat", "fields.ino", Observed::Null),
                Difference::field(42, "fstat", "fields.kind", Observed::Null),
                Difference::field(42, "fstat", "fields.nlink", Observed::Null),
                Difference::field(42, "fstat", "fields.perm", Observed::Null),
                Difference::field(42, "fstat", "fields.size", Observed::Null),
                Difference::field(42, "fstat", "fields.uid", Observed::Null),
                Difference::field(42, "fstat", "ret", Observed::Int(-1)),
                Difference::check(43, "both ends see the pipe inode's new mode"),
            ]),
        },
        Gap {
            status: Status::Pending(Arc::Fs),
            vehicles: Vehicle::ALL,
            what: "path resolution order: an empty path relative to a file descriptor is ENOTDIR, where the kernel refuses the empty name first (getname: ENOENT) unless AT_EMPTY_PATH (crates/patina-native-shim/src/paths.rs judges the dirfd's kind before the path)",
            failure: Failure::Differs(&[
                Difference::field(70, "fchmodat", "errno", Observed::Str("ENOTDIR")),
                Difference::check(71, "fchmodat of an empty path is ENOENT"),
                Difference::field(98, "fchmodat2", "errno", Observed::Str("ENOTDIR")),
                Difference::check(
                    99,
                    "fchmodat2 of an empty path without AT_EMPTY_PATH is ENOENT",
                ),
            ]),
        },
        Gap {
            status: Status::Pending(Arc::Fs),
            vehicles: Vehicle::ALL,
            what: "fchmodat2 AT_EMPTY_PATH is EINVAL (only AT_SYMLINK_NOFOLLOW is accepted), where Linux 6.6+ changes the descriptor's own inode, O_PATH included (fs/open.c do_fchmodat); the SUD fchmodat2 row and the C fchmodat flag decode",
            failure: Failure::Differs(&[
                Difference::field(90, "fchmodat2", "errno", Observed::Str("EINVAL")),
                Difference::field(90, "fchmodat2", "ret", Observed::Int(-1)),
                Difference::check(91, "fchmodat2 AT_EMPTY_PATH names the descriptor"),
                Difference::field(92, "newfstatat", "fields.perm", Observed::Int(0o604)),
                Difference::check(93, "the bits changed"),
                Difference::field(94, "fchmodat2", "errno", Observed::Str("EINVAL")),
                Difference::field(94, "fchmodat2", "ret", Observed::Int(-1)),
                Difference::check(
                    95,
                    "fchmodat2 AT_EMPTY_PATH works through an O_PATH descriptor",
                ),
                Difference::field(96, "newfstatat", "fields.perm", Observed::Int(0o604)),
                Difference::check(97, "the bits changed"),
            ]),
        },
    ],
    ..DEFAULTS
};
