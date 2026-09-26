//! fs/dirent — glibc's directory streams (opendir(3), fdopendir(3),
//! readdir(3), readdir_r(3), rewinddir(3), dirfd(3), closedir(3); glibc
//! sysdeps/unix/sysv/linux/opendir.c, readdir.c, rewinddir.c):
//!
//! * `opendir` opens the directory `O_RDONLY|O_NONBLOCK|O_DIRECTORY|
//!   O_CLOEXEC` and `dirfd` answers that descriptor; `closedir` closes it;
//! * a read lists every entry once — `.` and `..` included — with its
//!   `d_type`, and `d_ino` is the inode `fstatat` reports for the name;
//!   `readdir`, `readdir64` and `readdir_r` list the same entries
//!   (`readdir_r` into the caller's own entry); at the end a read answers
//!   NULL (`readdir_r`: 0 and a NULL result) and leaves errno alone, and
//!   keeps answering it;
//! * the stream reads the directory through its descriptor, not a copy
//!   taken at `opendir` (glibc's `opendir` reads nothing): an entry created
//!   after `opendir` and before the first read is listed, one removed is
//!   not; `rewinddir` restarts the stream at the directory's current state;
//! * a read that fails answers NULL with errno set (`readdir_r`: the error
//!   number): with the stream's descriptor closed underneath it every
//!   spelling is getdents64's `EBADF`, and `closedir` answers close's;
//! * `fdopendir` adopts the caller's descriptor, setting its `FD_CLOEXEC`
//!   (glibc `__alloc_dir`), and `closedir` closes it; an `O_PATH` descriptor is
//!   `EBADF`; a plain `O_DIRECTORY` open reports `O_DIRECTORY` in `F_GETFL`;
//! * `opendir` of a missing name is `ENOENT` (an empty name too), of a file
//!   or through one `ENOTDIR`, of a directory without `r` `EACCES`; it follows
//!   a symlink; `fdopendir` of a file or a pipe is `ENOTDIR`, of a closed
//!   number `EBADF`.
//!
//! libc only: the stream API has no row of its own (it reads through
//! getdents64).

use crate::catalog::{Arc, DEFAULTS, Gap, Need, Scenario, Status};
use crate::compare::{Difference, Failure, Observed};
use crate::probe::{AT_FDCWD, DirEntry, KERNEL_O_LARGEFILE, Probe, ReadSpelling, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

/// Every entry's `d_ino` is the inode `fstatat` reports for its name in
/// `root` (without following a symlink). `.` and `..` are left out: their
/// inodes are this directory's and its parent's, which a stacked or
/// subvolume filesystem lists differently from what `stat` reports
/// (overlayfs without `xino`, a btrfs subvolume root's `..`).
fn inodes_match(p: &Probe, root: &str, entries: &[DirEntry]) -> bool {
    entries
        .iter()
        .filter(|entry| entry.name != "." && entry.name != "..")
        .all(|entry| {
            let (r, st) = p.rec.quiet(|| {
                p.newfstatat(
                    AT_FDCWD,
                    &format!("{root}/{}", entry.name),
                    AT_SYMLINK_NOFOLLOW,
                )
            });
            r == 0 && st.is_some_and(|st| st.ino == entry.ino)
        })
}

pub fn run(p: &Probe) {
    let root = p.dir();
    for name in ["a", "b"] {
        p.create(&format!("{root}/{name}"), 0o644);
    }
    p.check(
        "mkdirat sub",
        p.mkdirat(AT_FDCWD, &format!("{root}/sub"), 0o755) == 0,
    );
    p.check(
        "symlinkat l -> sub",
        p.symlinkat("sub", AT_FDCWD, &format!("{root}/l")) == 0,
    );
    p.check(
        "mknodat p",
        p.mknodat(AT_FDCWD, &format!("{root}/p"), S_IFIFO | 0o644, 0) == 0,
    );
    let everything = ["..:4", ".:4", "a:8", "b:8", "l:10", "p:1", "sub:4"];
    let listed = |entries: &[DirEntry]| {
        let mut names: Vec<String> = entries
            .iter()
            .map(|entry| format!("{}:{}", entry.name, entry.kind))
            .collect();
        names.sort();
        names
    };

    // ---- opendir, dirfd, the reads -----------------------------------------
    let (r, dir) = p.opendir(&root);
    p.require("opendir the run directory", r == 0);
    let dir = dir.unwrap();
    let fd = p.dirfd(&dir);
    p.check(
        "opendir's descriptor is FD_CLOEXEC",
        p.fcntl(fd, F_GETFD, 0) == i64::from(FD_CLOEXEC),
    );
    p.check(
        "and O_RDONLY|O_NONBLOCK|O_DIRECTORY",
        p.fcntl(fd, F_GETFL, 0)
            == i64::from(O_RDONLY | O_NONBLOCK | O_DIRECTORY) | KERNEL_O_LARGEFILE,
    );
    let (n, entries) = p.readdir_all(&dir, ReadSpelling::Readdir);
    p.check(
        "readdir lists every entry once, with its d_type",
        n == 7 && listed(&entries) == everything,
    );
    p.check(
        "each d_ino is the entry's inode",
        inodes_match(p, &root, &entries),
    );
    p.check(
        "at the end readdir answers NULL without an errno",
        p.readdir_step(&dir, ReadSpelling::Readdir).0 == 0,
    );
    p.check(
        "and keeps answering it",
        p.readdir_step(&dir, ReadSpelling::Readdir64).0 == 0,
    );
    p.create(&format!("{root}/c"), 0o644);
    p.rewinddir(&dir);
    let (n, entries) = p.readdir_all(&dir, ReadSpelling::Readdir64);
    p.check(
        "after rewinddir readdir64 lists the directory as it is now",
        n == 8
            && entries
                .iter()
                .any(|entry| entry.name == "c" && entry.kind == DT_REG),
    );
    p.check(
        "readdir64's d_ino is the entry's inode",
        inodes_match(p, &root, &entries),
    );
    p.rewinddir(&dir);
    let (n, again) = p.readdir_all(&dir, ReadSpelling::ReaddirR);
    p.check(
        "readdir_r lists the same entries",
        n == 8 && listed(&again) == listed(&entries),
    );
    p.check(
        "each into the caller's own entry",
        again.iter().all(|entry| entry.result_is_entry),
    );
    p.check(
        "at the end readdir_r answers 0 and a NULL result",
        p.readdir_step(&dir, ReadSpelling::ReaddirR).0 == 0,
    );
    p.check("closedir", p.closedir(dir) == 0);
    p.check(
        "closedir closed the stream's descriptor",
        p.fcntl(fd, F_GETFD, 0) == neg(EBADF),
    );

    // ---- fdopendir -----------------------------------------------------------
    let sub = format!("{root}/sub");
    let fd = p.openat(AT_FDCWD, &sub, O_RDONLY | O_DIRECTORY, 0);
    p.require("open sub", fd >= 0);
    p.check(
        "an O_DIRECTORY open reports O_RDONLY|O_DIRECTORY",
        p.fcntl(fd, F_GETFL, 0) == i64::from(O_RDONLY | O_DIRECTORY) | KERNEL_O_LARGEFILE,
    );
    let (r, dir) = p.fdopendir(fd);
    p.require("fdopendir sub", r == 0);
    let dir = dir.unwrap();
    p.check("dirfd answers the adopted descriptor", p.dirfd(&dir) == fd);
    p.check(
        "fdopendir sets FD_CLOEXEC on the adopted descriptor",
        p.fcntl(fd, F_GETFD, 0) == i64::from(FD_CLOEXEC),
    );
    let (n, entries) = p.readdir_all(&dir, ReadSpelling::Readdir);
    p.check(
        "an empty directory lists . and ..",
        n == 2 && listed(&entries) == ["..:4", ".:4"],
    );
    p.check("closedir", p.closedir(dir) == 0);
    p.check(
        "closedir closed the adopted descriptor",
        p.fcntl(fd, F_GETFD, 0) == neg(EBADF),
    );
    let location = p.openat(AT_FDCWD, &sub, O_PATH | O_DIRECTORY, 0);
    p.require("open sub O_PATH", location >= 0);
    // glibc's own refusal (fstat + F_GETFL in fdopendir), verified on glibc
    // 2.39; an older glibc adopts it and fails the first read EBADF instead.
    p.check(
        "fdopendir of an O_PATH descriptor is EBADF",
        p.fdopendir(location).0 == neg(EBADF),
    );
    p.close(location);

    // ---- refusals ------------------------------------------------------------
    p.check(
        "opendir of a missing name is ENOENT",
        p.opendir(&format!("{root}/missing")).0 == neg(ENOENT),
    );
    p.check(
        "opendir of an empty name is ENOENT",
        p.opendir("").0 == neg(ENOENT),
    );
    p.check(
        "opendir of a file is ENOTDIR",
        p.opendir(&format!("{root}/a")).0 == neg(ENOTDIR),
    );
    p.check(
        "opendir through a file is ENOTDIR",
        p.opendir(&format!("{root}/a/x")).0 == neg(ENOTDIR),
    );
    let (r, dir) = p.opendir(&format!("{root}/l"));
    p.check("opendir follows a symlink", r == 0);
    if let Some(dir) = dir {
        let (n, entries) = p.readdir_all(&dir, ReadSpelling::Readdir);
        p.check(
            "to the directory it names",
            n == 2 && listed(&entries) == ["..:4", ".:4"],
        );
        p.closedir(dir);
    }
    let locked = format!("{root}/locked");
    p.check("mkdirat locked 0", p.mkdirat(AT_FDCWD, &locked, 0) == 0);
    p.check(
        "opendir of a directory without r is EACCES",
        p.opendir(&locked).0 == neg(EACCES),
    );
    let file = p.openat(AT_FDCWD, &format!("{root}/a"), O_RDONLY, 0);
    p.require("open a", file >= 0);
    p.check(
        "fdopendir of a file is ENOTDIR",
        p.fdopendir(file).0 == neg(ENOTDIR),
    );
    p.close(file);
    let (r, [rd, wr]) = p.pipe2(0);
    p.require("pipe2", r == 0);
    p.check(
        "fdopendir of a pipe is ENOTDIR",
        p.fdopendir(rd).0 == neg(ENOTDIR),
    );
    p.close(rd);
    p.close(wr);
    p.check(
        "fdopendir of a closed number is EBADF",
        p.fdopendir(4000).0 == neg(EBADF),
    );
    p.check(
        "chmod locked back to 0755",
        p.fchmodat(AT_FDCWD, &locked, 0o755) == 0,
    );

    // ---- the listing is read, not copied at opendir ------------------------------
    let snap = format!("{root}/snap");
    p.check("mkdirat snap", p.mkdirat(AT_FDCWD, &snap, 0o755) == 0);
    p.create(&format!("{snap}/x"), 0o644);
    let (r, dir) = p.opendir(&snap);
    p.require("opendir snap", r == 0);
    let dir = dir.unwrap();
    p.create(&format!("{snap}/y"), 0o644);
    let (n, entries) = p.readdir_all(&dir, ReadSpelling::Readdir);
    p.check(
        "an entry created after opendir, before the first read, is listed",
        n == 4 && listed(&entries) == ["..:4", ".:4", "x:8", "y:8"],
    );
    p.check("closedir", p.closedir(dir) == 0);
    let (r, dir) = p.opendir(&snap);
    p.require("opendir snap again", r == 0);
    let dir = dir.unwrap();
    p.check(
        "unlinkat snap/x",
        p.unlinkat(AT_FDCWD, &format!("{snap}/x"), 0) == 0,
    );
    let (n, entries) = p.readdir_all(&dir, ReadSpelling::Readdir);
    p.check(
        "one removed after opendir, before the first read, is not",
        n == 3 && listed(&entries) == ["..:4", ".:4", "y:8"],
    );
    p.check("closedir", p.closedir(dir) == 0);

    // ---- a failing read ------------------------------------------------------------
    let (r, dir) = p.opendir(&snap);
    p.require("opendir snap a third time", r == 0);
    let dir = dir.unwrap();
    let fd = p.dirfd(&dir);
    p.check(
        "close the stream's descriptor underneath it",
        p.close(fd) == 0,
    );
    p.check(
        "readdir then answers NULL and getdents64's EBADF",
        p.readdir_step(&dir, ReadSpelling::Readdir).0 == neg(EBADF),
    );
    p.check(
        "readdir64 too",
        p.readdir_step(&dir, ReadSpelling::Readdir64).0 == neg(EBADF),
    );
    p.check(
        "readdir_r returns it",
        p.readdir_step(&dir, ReadSpelling::ReaddirR).0 == neg(EBADF),
    );
    p.check(
        "and closedir answers close's EBADF",
        p.closedir(dir) == neg(EBADF),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "fs/dirent",
    run,
    vehicles: &[Vehicle::Libc],
    covers: &[
        Syscall::N_getdents64,
        Syscall::N_openat,
        Syscall::N_close,
        Syscall::N_fcntl,
        Syscall::N_mkdirat,
        Syscall::N_symlinkat,
        Syscall::N_mknodat,
        Syscall::N_pipe2,
        Syscall::N_newfstatat,
        Syscall::N_unlinkat,
        Syscall::N_fchmodat,
    ],
    symbols: &[
        "opendir",
        "fdopendir",
        "readdir",
        "readdir64",
        "readdir_r",
        "rewinddir",
        "dirfd",
        "closedir",
        "openat",
        "close",
        "fcntl",
        "mkdirat",
        "symlinkat",
        "mknodat",
        "pipe2",
        "fstatat",
        "unlinkat",
        "fchmodat",
    ],
    needs: &[Need::Unprivileged],
    gaps: &[
        Gap {
            status: Status::Pending(Arc::Fs),
            vehicles: &[Vehicle::Libc],
            what: "F_GETFL on opendir's descriptor answers O_LARGEFILE alone: the shim's opendir (c/posix/fs.c) opens without glibc's O_NONBLOCK (the missing O_DIRECTORY is the virtual descriptor's, pinned on its own below)",
            failure: Failure::Differs(&[
                Difference::field(14, "fcntl", "ret", Observed::Int(KERNEL_O_LARGEFILE)),
                Difference::check(15, "and O_RDONLY|O_NONBLOCK|O_DIRECTORY"),
            ]),
        },
        Gap {
            status: Status::Pending(Arc::Fs),
            vehicles: &[Vehicle::Libc],
            what: "F_GETFL on an O_DIRECTORY descriptor never reports O_DIRECTORY: the shim's F_GETFL translation (c/posix/fd_io.c) carries only the access mode, O_APPEND, O_NONBLOCK, O_PATH and O_LARGEFILE",
            failure: Failure::Differs(&[
                Difference::field(40, "fcntl", "ret", Observed::Int(KERNEL_O_LARGEFILE)),
                Difference::check(41, "an O_DIRECTORY open reports O_RDONLY|O_DIRECTORY"),
            ]),
        },
        Gap {
            status: Status::Pending(Arc::Fs),
            vehicles: &[Vehicle::Libc],
            what: "the shim's fdopendir (c/posix/fs.c) adopts the descriptor without setting FD_CLOEXEC, which glibc's __alloc_dir sets",
            failure: Failure::Differs(&[
                Difference::field(45, "fcntl", "ret", Observed::Int(0)),
                Difference::check(46, "fdopendir sets FD_CLOEXEC on the adopted descriptor"),
            ]),
        },
        Gap {
            status: Status::Pending(Arc::Fs),
            vehicles: &[Vehicle::Libc],
            what: "fdopendir of a pipe answers patina_read_dir's EBADF, where glibc's fstat check refuses a non-directory with ENOTDIR first (c/posix/fs.c fdopendir)",
            failure: Failure::Differs(&[
                Difference::field(79, "fdopendir", "errno", Observed::Str("EBADF")),
                Difference::check(80, "fdopendir of a pipe is ENOTDIR"),
            ]),
        },
        Gap {
            status: Status::Pending(Arc::Fs),
            vehicles: &[Vehicle::Libc],
            what: "the shim's opendir copies the listing when it opens (c/posix/fs.c opendir/fdopendir through patina_read_dir): a name created or removed between opendir and the first read is missed, where glibc's first readdir reads the directory",
            failure: Failure::Differs(&[
                Difference::field(94, "readdir", "ret", Observed::Int(3)),
                Difference::field(
                    94,
                    "readdir",
                    "fields.entries",
                    Observed::Json(r#"["..:4",".:4","x:8"]"#),
                ),
                Difference::check(
                    95,
                    "an entry created after opendir, before the first read, is listed",
                ),
                Difference::field(101, "readdir", "ret", Observed::Int(4)),
                Difference::field(
                    101,
                    "readdir",
                    "fields.entries",
                    Observed::Json(r#"["..:4",".:4","x:8","y:8"]"#),
                ),
                Difference::check(
                    102,
                    "one removed after opendir, before the first read, is not",
                ),
            ]),
        },
        Gap {
            status: Status::Pending(Arc::Fs),
            vehicles: &[Vehicle::Libc],
            what: "the shim's reads answer the copied listing and never fail, and its closedir answers 0 whatever close says (c/posix/fs.c readdir, readdir64, readdir_r, closedir): a stream whose descriptor is closed underneath it keeps listing",
            failure: Failure::Differs(&[
                Difference::field(109, "readdir", "ret", Observed::Int(1)),
                Difference::field(109, "readdir", "errno", Observed::Null),
                Difference::check(110, "readdir then answers NULL and getdents64's EBADF"),
                Difference::field(111, "readdir64", "ret", Observed::Int(1)),
                Difference::field(111, "readdir64", "errno", Observed::Null),
                Difference::check(112, "readdir64 too"),
                Difference::field(113, "readdir_r", "ret", Observed::Int(1)),
                Difference::field(113, "readdir_r", "errno", Observed::Null),
                Difference::field(
                    113,
                    "readdir_r",
                    "fields.result_is_entry",
                    Observed::Bool(true),
                ),
                Difference::check(114, "readdir_r returns it"),
                Difference::field(115, "closedir", "ret", Observed::Int(0)),
                Difference::field(115, "closedir", "errno", Observed::Null),
                Difference::check(116, "and closedir answers close's EBADF"),
            ]),
        },
    ],
    ..DEFAULTS
};
