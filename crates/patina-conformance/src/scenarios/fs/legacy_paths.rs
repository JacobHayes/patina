//! fs/legacy_paths — the x86_64 pre-`*at` path rows: open, creat, stat, lstat,
//! mkdir, rmdir, rename, link, unlink, symlink, readlink, chmod, mknod. Each
//! resolves relative to the working directory — its `*at` twin with
//! `AT_FDCWD`, which is how the generic table spells it on arm64 — and carries
//! the twin's errno vocabulary: open(2) (EEXIST, ENOENT, ENOTDIR on a trailing
//! slash, EISDIR for a write-open of a directory), creat(2) (O_WRONLY|O_TRUNC,
//! an existing file keeps its mode), stat(2)/lstat(2), mkdir(2), rmdir(2)
//! (ENOTEMPTY, ENOTDIR, EINVAL for a final `.`, ENOTEMPTY for a final `..`, a
//! symlink is ENOTDIR), rename(2) (EISDIR, ENOTDIR, EINVAL into itself, the
//! EEXIST/ENOTEMPTY pair onto a nonempty directory), link(2) (EPERM for a
//! directory; a symlink is linked, not followed), unlink(2) (EISDIR; ENOTDIR
//! on a trailing slash: fs/namei.c do_unlinkat), symlink(2), readlink(2)
//! (EINVAL for a zero buffer and a non-link, truncation), chmod(2) (only the
//! 07777 bits change; a symlink is followed) and mknod(2) (a zero type is a
//! regular file, S_IFSOCK needs no privilege, S_IFDIR is EPERM and an unknown
//! type EINVAL before the path is looked at — fs/namei.c may_mknod — while
//! S_IFCHR is EPERM for an unprivileged caller after it: vfs_mknod).

use crate::catalog::{Arc, DEFAULTS, Gap, Need, Scenario, Status};
use crate::compare::{Difference, Failure, Observed};
use crate::vehicle::Vehicle;

use patina_dst_syscalls::Syscall;

use crate::probe::{Probe, neg};
use libc::*;

/// An `S_IFMT` value naming no file type.
const UNKNOWN_TYPE: u32 = 0o030000;

pub fn run(p: &Probe) {
    let root = p.dir();
    p.require("chdir into the run directory", p.chdir(&root) == 0);

    // ---- open and creat ----------------------------------------------------
    let fd = p.open("f", O_RDWR | O_CREAT | O_EXCL, 0o640);
    p.require("open creates f", fd >= 0);
    p.check("write through open's descriptor", p.write(fd, b"abc") == 3);
    p.check(
        "open O_CREAT|O_EXCL on an existing name is EEXIST",
        i64::from(p.open("f", O_RDWR | O_CREAT | O_EXCL, 0o640)) == neg(EEXIST),
    );
    p.check(
        "open of a missing name is ENOENT",
        i64::from(p.open("missing", O_RDONLY, 0)) == neg(ENOENT),
    );
    p.check(
        "open with a trailing slash on a file is ENOTDIR",
        i64::from(p.open("f/", O_RDONLY, 0)) == neg(ENOTDIR),
    );
    p.check(
        "open of an empty path is ENOENT",
        i64::from(p.open("", O_RDONLY, 0)) == neg(ENOENT),
    );
    p.check("mkdir d", p.mkdir("d", 0o750) == 0);
    p.check(
        "a write-open of a directory is EISDIR",
        i64::from(p.open("d", O_WRONLY, 0)) == neg(EISDIR),
    );
    let dir = p.open("d", O_RDONLY, 0);
    p.check("a read-open of a directory succeeds", dir >= 0);

    let c = p.creat("c", 0o600);
    p.require("creat makes c", c >= 0);
    p.check("creat's descriptor writes", p.write(c, b"xy") == 2);
    p.check(
        "creat's descriptor is O_WRONLY: read is EBADF",
        p.read(c, 1).0 == neg(EBADF),
    );
    let again = p.creat("f", 0o777);
    p.require("creat of an existing file", again >= 0);
    let (r, st) = p.fstat(again);
    p.check(
        "creat truncates an existing file and keeps its mode",
        r == 0 && st.is_some_and(|s| s.size == 0 && s.perm == 0o640),
    );
    p.check(
        "creat of a directory is EISDIR",
        i64::from(p.creat("d", 0o600)) == neg(EISDIR),
    );
    p.check(
        "creat under a missing parent is ENOENT",
        i64::from(p.creat("missing/x", 0o600)) == neg(ENOENT),
    );

    // ---- stat and lstat ------------------------------------------------------
    let (r, f) = p.stat("f", true);
    p.check(
        "stat: a regular file, mode 0640, one link, emptied",
        r == 0
            && f.as_ref()
                .is_some_and(|s| s.kind == "reg" && s.perm == 0o640 && s.nlink == 1 && s.size == 0),
    );
    let f_ino = f.map_or(0, |s| s.ino);
    p.check(
        "stat of an empty path is ENOENT",
        p.stat("", true).0 == neg(ENOENT),
    );
    p.check(
        "stat with a trailing slash on a file is ENOTDIR",
        p.stat("f/", true).0 == neg(ENOTDIR),
    );
    p.check(
        "stat of a missing name is ENOENT",
        p.stat("missing", true).0 == neg(ENOENT),
    );

    // ---- symlink, readlink, and the follow rule --------------------------------
    p.check("symlink l -> f", p.symlink("f", "l") == 0);
    p.check(
        "symlink onto an existing name is EEXIST",
        p.symlink("f", "l") == neg(EEXIST),
    );
    p.check(
        "symlink with an empty target is ENOENT",
        p.symlink("", "empty") == neg(ENOENT),
    );
    let (r, l) = p.stat("l", false);
    p.check(
        "lstat names the link: kind lnk, size = target length",
        r == 0 && l.is_some_and(|s| s.kind == "lnk" && s.size == 1),
    );
    let (r, via) = p.stat("l", true);
    p.check(
        "stat follows the link to f",
        r == 0 && via.is_some_and(|s| s.kind == "reg" && s.ino == f_ino),
    );
    p.check(
        "symlink dangling -> missing",
        p.symlink("missing", "dangling") == 0,
    );
    p.check(
        "stat through a dangling link is ENOENT",
        p.stat("dangling", true).0 == neg(ENOENT),
    );
    let (r, target) = p.readlink("l", 64);
    p.check("readlink returns the target", r == 1 && target == "f");
    let (r, truncated) = p.readlink("dangling", 3);
    p.check(
        "readlink truncates to the buffer",
        r == 3 && truncated == "mis",
    );
    p.check(
        "readlink with a zero buffer is EINVAL",
        p.readlink("l", 0).0 == neg(EINVAL),
    );
    p.check(
        "readlink of a regular file is EINVAL",
        p.readlink("f", 64).0 == neg(EINVAL),
    );
    p.check(
        "readlink of a missing name is ENOENT",
        p.readlink("missing", 64).0 == neg(ENOENT),
    );

    // ---- mkdir and rmdir ---------------------------------------------------------
    let (r, d) = p.stat("d", true);
    p.check(
        "mkdir: a directory, mode 0750, two links",
        r == 0 && d.is_some_and(|s| s.kind == "dir" && s.perm == 0o750 && s.nlink == 2),
    );
    p.check(
        "mkdir of an existing directory is EEXIST",
        p.mkdir("d", 0o750) == neg(EEXIST),
    );
    p.check(
        "mkdir onto a symlink's name is EEXIST",
        p.mkdir("l", 0o750) == neg(EEXIST),
    );
    p.check(
        "mkdir under a missing parent is ENOENT",
        p.mkdir("missing/x", 0o750) == neg(ENOENT),
    );
    p.check(
        "mkdir under a file is ENOTDIR",
        p.mkdir("f/x", 0o750) == neg(ENOTDIR),
    );
    p.check("mkdir d/sub", p.mkdir("d/sub", 0o700) == 0);
    p.check(
        "rmdir of a nonempty directory is ENOTEMPTY",
        p.rmdir("d") == neg(ENOTEMPTY),
    );
    p.check("rmdir of a file is ENOTDIR", p.rmdir("f") == neg(ENOTDIR));
    p.check(
        "rmdir of a symlink is ENOTDIR (the link is not followed)",
        p.rmdir("l") == neg(ENOTDIR),
    );
    p.check(
        "rmdir with a final `.` is EINVAL",
        p.rmdir("d/sub/.") == neg(EINVAL),
    );
    p.check(
        "rmdir with a final `..` is ENOTEMPTY",
        p.rmdir("d/sub/..") == neg(ENOTEMPTY),
    );
    p.check(
        "rmdir of a missing name is ENOENT",
        p.rmdir("missing") == neg(ENOENT),
    );
    p.check("rmdir of an empty directory", p.rmdir("d/sub") == 0);
    p.check(
        "the removed directory is gone",
        p.stat("d/sub", false).0 == neg(ENOENT),
    );

    // ---- rename ----------------------------------------------------------------
    p.check("rename f -> g", p.rename("f", "g") == 0);
    p.check("the old name is gone", p.stat("f", false).0 == neg(ENOENT));
    p.check(
        "rename of a missing name is ENOENT",
        p.rename("missing", "x") == neg(ENOENT),
    );
    p.check(
        "rename of a file onto a directory is EISDIR",
        p.rename("g", "d") == neg(EISDIR),
    );
    p.check("mkdir e", p.mkdir("e", 0o750) == 0);
    p.check(
        "rename of a directory onto a file is ENOTDIR",
        p.rename("e", "g") == neg(ENOTDIR),
    );
    p.check("mkdir d/inner", p.mkdir("d/inner", 0o750) == 0);
    let onto_nonempty = p.rename("e", "d");
    p.check(
        "rename of a directory onto a nonempty one is ENOTEMPTY or EEXIST",
        onto_nonempty == neg(ENOTEMPTY) || onto_nonempty == neg(EEXIST),
    );
    p.check(
        "rename of a directory into itself is EINVAL",
        p.rename("d", "d/inner/x") == neg(EINVAL),
    );
    p.check(
        "rename onto the same name succeeds",
        p.rename("g", "g") == 0,
    );
    p.check(
        "rename of a directory onto an empty one replaces it",
        p.rename("e", "d/inner") == 0,
    );
    p.check(
        "the source directory is gone",
        p.stat("e", false).0 == neg(ENOENT),
    );

    // ---- link and unlink ----------------------------------------------------------
    p.check("link g -> h", p.link("g", "h") == 0);
    let (r, g) = p.stat("g", true);
    p.check(
        "a hard link bumps nlink to 2 on the same inode",
        r == 0 && g.is_some_and(|s| s.nlink == 2 && s.ino == f_ino),
    );
    p.check(
        "link onto an existing name is EEXIST",
        p.link("g", "h") == neg(EEXIST),
    );
    p.check(
        "link of a missing name is ENOENT",
        p.link("missing", "m") == neg(ENOENT),
    );
    p.check(
        "link of a directory is EPERM",
        p.link("d", "d2") == neg(EPERM),
    );
    p.check("symlink lg -> g", p.symlink("g", "lg") == 0);
    p.check(
        "link of a symlink links the link itself",
        p.link("lg", "lg2") == 0,
    );
    let (r, lg2) = p.stat("lg2", false);
    p.check(
        "the new name is a symlink sharing the link's inode (nlink 2)",
        r == 0 && lg2.is_some_and(|s| s.kind == "lnk" && s.nlink == 2),
    );
    p.check("unlink h", p.unlink("h") == 0);
    let (r, g) = p.stat("g", true);
    p.check(
        "unlinking one name drops nlink to 1",
        r == 0 && g.is_some_and(|s| s.nlink == 1),
    );
    p.check(
        "unlink of a directory is EISDIR",
        p.unlink("d") == neg(EISDIR),
    );
    p.check(
        "unlink of a missing name is ENOENT",
        p.unlink("missing") == neg(ENOENT),
    );
    p.check(
        "unlink with a trailing slash on a file is ENOTDIR",
        p.unlink("g/") == neg(ENOTDIR),
    );
    p.check("unlink of a symlink", p.unlink("lg2") == 0);
    p.check("removes the link, not its target", p.stat("g", true).0 == 0);

    // ---- chmod ----------------------------------------------------------------------
    p.check("chmod g 0600", p.chmod("g", 0o600) == 0);
    let (r, g) = p.stat("g", true);
    p.check(
        "chmod sets the permission bits",
        r == 0 && g.is_some_and(|s| s.perm == 0o600),
    );
    p.check(
        "chmod keeps only the 07777 bits",
        p.chmod("g", S_IFDIR | 0o644) == 0,
    );
    let (r, g) = p.stat("g", true);
    p.check(
        "the file type is untouched by chmod's type bits",
        r == 0 && g.is_some_and(|s| s.kind == "reg" && s.perm == 0o644),
    );
    p.check(
        "chmod keeps setuid for the owner",
        p.chmod("g", 0o4755) == 0,
    );
    p.check(
        "the setuid bit is stored",
        p.stat("g", true).1.is_some_and(|s| s.perm == 0o4755),
    );
    p.check("chmod through a symlink", p.chmod("lg", 0o640) == 0);
    p.check(
        "chmod follows the link to its target",
        p.stat("g", true).1.is_some_and(|s| s.perm == 0o640),
    );
    p.check(
        "the link's own mode is untouched",
        p.stat("lg", false).1.is_some_and(|s| s.perm == 0o777),
    );
    p.check(
        "chmod of a missing name is ENOENT",
        p.chmod("missing", 0o600) == neg(ENOENT),
    );

    // ---- mknod ---------------------------------------------------------------------
    p.check("mknod a FIFO", p.mknod("p", S_IFIFO | 0o640, 0) == 0);
    p.check(
        "the FIFO stats as fifo with its mode",
        p.stat("p", false)
            .1
            .is_some_and(|s| s.kind == "fifo" && s.perm == 0o640),
    );
    p.check(
        "mknod with a zero type makes a regular file",
        p.mknod("r", 0o640, 0) == 0,
    );
    p.check(
        "the zero-type node is a regular file",
        p.stat("r", false)
            .1
            .is_some_and(|s| s.kind == "reg" && s.perm == 0o640 && s.size == 0),
    );
    p.check(
        "mknod S_IFREG makes a regular file",
        p.mknod("r2", S_IFREG | 0o600, 0) == 0,
    );
    p.check(
        "mknod S_IFSOCK needs no privilege",
        p.mknod("s", S_IFSOCK | 0o600, 0) == 0,
    );
    p.check(
        "the socket node stats as sock",
        p.stat("s", false).1.is_some_and(|s| s.kind == "sock"),
    );
    p.check(
        "mknod of an existing name is EEXIST",
        p.mknod("p", S_IFIFO | 0o640, 0) == neg(EEXIST),
    );
    p.check(
        "mknod S_IFDIR is EPERM, judged before the path exists",
        p.mknod("missing/dir", S_IFDIR | 0o700, 0) == neg(EPERM),
    );
    p.check(
        "mknod of an unknown type is EINVAL, judged before the path exists",
        p.mknod("missing/odd", UNKNOWN_TYPE | 0o600, 0) == neg(EINVAL),
    );
    p.check(
        "mknod S_IFCHR of a real device is EPERM without CAP_MKNOD",
        p.mknod("chr", S_IFCHR | 0o600, makedev(1, 3)) == neg(EPERM),
    );
    p.check(
        "mknod S_IFCHR under a missing parent is ENOENT (the path first)",
        p.mknod("missing/chr", S_IFCHR | 0o600, makedev(1, 3)) == neg(ENOENT),
    );

    for fd in [fd, dir, c, again] {
        p.close(fd);
    }
}

pub const SCENARIO: Scenario = Scenario {
    name: "fs/legacy_paths",
    run,
    covers: &[
        #[cfg(target_arch = "x86_64")]
        Syscall::N_open,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_creat,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_stat,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_lstat,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_mkdir,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_rmdir,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_rename,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_link,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_unlink,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_symlink,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_readlink,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_chmod,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_mknod,
        #[cfg(not(target_arch = "x86_64"))]
        Syscall::N_openat,
        #[cfg(not(target_arch = "x86_64"))]
        Syscall::N_newfstatat,
        #[cfg(not(target_arch = "x86_64"))]
        Syscall::N_mkdirat,
        #[cfg(not(target_arch = "x86_64"))]
        Syscall::N_unlinkat,
        #[cfg(not(target_arch = "x86_64"))]
        Syscall::N_renameat,
        #[cfg(not(target_arch = "x86_64"))]
        Syscall::N_linkat,
        #[cfg(not(target_arch = "x86_64"))]
        Syscall::N_symlinkat,
        #[cfg(not(target_arch = "x86_64"))]
        Syscall::N_readlinkat,
        #[cfg(not(target_arch = "x86_64"))]
        Syscall::N_fchmodat,
        #[cfg(not(target_arch = "x86_64"))]
        Syscall::N_mknodat,
        Syscall::N_chdir,
        Syscall::N_read,
        Syscall::N_write,
        Syscall::N_fstat,
        Syscall::N_close,
    ],
    symbols: &[
        "open", "creat", "stat", "lstat", "mkdir", "rmdir", "rename", "link", "unlink", "symlink",
        "readlink", "chmod", "mknod", "chdir", "read", "write", "fstat", "close",
    ],
    needs: &[Need::Unprivileged],
    gaps: &[
        Gap {
            status: Status::Pending(Arc::Fs),
            vehicles: Vehicle::ALL,
            what: "rmdir (unlinkat AT_REMOVEDIR) resolves a final `.` or `..` instead of refusing it: `d/sub/.` removes d/sub (kernel: EINVAL for LAST_DOT) and `d/sub/..` is ENOENT (kernel: ENOTEMPTY for LAST_DOTDOT, fs/namei.c do_rmdir); the later rmdir of d/sub then finds nothing",
            failure: Failure::Differs(&[
                Difference::field(80, "rmdir", "errno", Observed::Null),
                Difference::field(80, "rmdir", "ret", Observed::Int(0)),
                Difference::check(81, "rmdir with a final `.` is EINVAL"),
                Difference::field(82, "rmdir", "errno", Observed::Str("ENOENT")),
                Difference::check(83, "rmdir with a final `..` is ENOTEMPTY"),
                Difference::field(86, "rmdir", "errno", Observed::Str("ENOENT")),
                Difference::field(86, "rmdir", "ret", Observed::Int(-1)),
                Difference::check(87, "rmdir of an empty directory"),
            ]),
        },
        Gap {
            status: Status::Pending(Arc::Fs),
            vehicles: Vehicle::ALL,
            what: "rename of a directory onto an EMPTY directory is EEXIST, where the kernel replaces it (the target's emptiness is the only condition); patina-fs-mem rename refuses any existing directory target, so the source stays",
            failure: Failure::Differs(&[
                Difference::field(110, "rename", "errno", Observed::Str("EEXIST")),
                Difference::field(110, "rename", "ret", Observed::Int(-1)),
                Difference::check(111, "rename of a directory onto an empty one replaces it"),
                Difference::field(112, "lstat", "errno", Observed::Null),
                Difference::field(112, "lstat", "fields.gid", Observed::Str("gid@24")),
                Difference::field(112, "lstat", "fields.ino", Observed::Str("ino@112")),
                Difference::field(112, "lstat", "fields.kind", Observed::Str("dir")),
                Difference::field(112, "lstat", "fields.nlink", Observed::Int(2)),
                Difference::field(112, "lstat", "fields.perm", Observed::Int(0o750)),
                Difference::field(112, "lstat", "fields.uid", Observed::Str("uid@24")),
                Difference::field(112, "lstat", "ret", Observed::Int(0)),
                Difference::check(113, "the source directory is gone"),
            ]),
        },
        Gap {
            status: Status::Pending(Arc::Fs),
            vehicles: Vehicle::ALL,
            what: "link of a symlink copies the link instead of hard-linking it: the new name has nlink 1 and its own inode (patina-fs-mem link: a symlink is a path-keyed entry, not an inode; the same gap as fs/links)",
            failure: Failure::Differs(&[
                Difference::field(128, "lstat", "fields.nlink", Observed::Int(1)),
                Difference::check(
                    129,
                    "the new name is a symlink sharing the link's inode (nlink 2)",
                ),
                Difference::field(160, "lstat", "fields.ino", Observed::Str("ino@160")),
            ]),
        },
        Gap {
            status: Status::Pending(Arc::Fs),
            vehicles: Vehicle::ALL,
            what: "mknod models only S_IFIFO: a zero type or S_IFREG (a regular file), S_IFSOCK (a socket inode) answer ENOSYS, and so do S_IFDIR and an unknown type, which the kernel refuses before the path (EPERM, EINVAL: fs/namei.c may_mknod); S_IFCHR under a missing parent is EPERM where the kernel looks the path up first (ENOENT; vfs_mknod checks CAP_MKNOD after); patina_mknodat's type switch",
            failure: Failure::Differs(&[
                Difference::field(168, "mknod", "errno", Observed::Str("ENOSYS")),
                Difference::field(168, "mknod", "ret", Observed::Int(-1)),
                Difference::check(169, "mknod with a zero type makes a regular file"),
                Difference::field(170, "lstat", "errno", Observed::Str("ENOENT")),
                Difference::field(170, "lstat", "fields.gid", Observed::Null),
                Difference::field(170, "lstat", "fields.ino", Observed::Null),
                Difference::field(170, "lstat", "fields.kind", Observed::Null),
                Difference::field(170, "lstat", "fields.nlink", Observed::Null),
                Difference::field(170, "lstat", "fields.perm", Observed::Null),
                Difference::field(170, "lstat", "fields.size", Observed::Null),
                Difference::field(170, "lstat", "fields.uid", Observed::Null),
                Difference::field(170, "lstat", "ret", Observed::Int(-1)),
                Difference::check(171, "the zero-type node is a regular file"),
                Difference::field(172, "mknod", "errno", Observed::Str("ENOSYS")),
                Difference::field(172, "mknod", "ret", Observed::Int(-1)),
                Difference::check(173, "mknod S_IFREG makes a regular file"),
                Difference::field(174, "mknod", "errno", Observed::Str("ENOSYS")),
                Difference::field(174, "mknod", "ret", Observed::Int(-1)),
                Difference::check(175, "mknod S_IFSOCK needs no privilege"),
                Difference::field(176, "lstat", "errno", Observed::Str("ENOENT")),
                Difference::field(176, "lstat", "fields.gid", Observed::Null),
                Difference::field(176, "lstat", "fields.ino", Observed::Null),
                Difference::field(176, "lstat", "fields.kind", Observed::Null),
                Difference::field(176, "lstat", "fields.nlink", Observed::Null),
                Difference::field(176, "lstat", "fields.perm", Observed::Null),
                Difference::field(176, "lstat", "fields.size", Observed::Null),
                Difference::field(176, "lstat", "fields.uid", Observed::Null),
                Difference::field(176, "lstat", "ret", Observed::Int(-1)),
                Difference::check(177, "the socket node stats as sock"),
                Difference::field(180, "mknod", "errno", Observed::Str("ENOSYS")),
                Difference::check(181, "mknod S_IFDIR is EPERM, judged before the path exists"),
                Difference::field(182, "mknod", "errno", Observed::Str("ENOSYS")),
                Difference::check(
                    183,
                    "mknod of an unknown type is EINVAL, judged before the path exists",
                ),
                Difference::field(186, "mknod", "errno", Observed::Str("EPERM")),
                Difference::check(
                    187,
                    "mknod S_IFCHR under a missing parent is ENOENT (the path first)",
                ),
            ]),
        },
    ],
    ..DEFAULTS
};
