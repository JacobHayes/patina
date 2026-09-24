//! fs/openat2 — openat2 (openat2(2); fs/open.c build_open_flags,
//! fs/namei.c): openat with an extensible `struct open_how` and path
//! resolution restrictions. The struct is judged first: smaller than
//! OPEN_HOW_SIZE_VER0 is EINVAL, larger than a page E2BIG, and bytes past the
//! known fields must be zero (E2BIG). Then strictly, unlike openat: an unknown
//! flag bit (the upper 32 included), a mode without O_CREAT/O_TMPFILE or with
//! bits past 07777, an unknown RESOLVE_* bit, or RESOLVE_BENEATH with
//! RESOLVE_IN_ROOT, are EINVAL; RESOLVE_CACHED with O_CREAT is EAGAIN. The
//! restrictions: RESOLVE_BENEATH refuses `..` past the dirfd and an absolute
//! path (EXDEV) but follows a symlink that stays beneath; RESOLVE_IN_ROOT
//! treats the dirfd as `/` (an absolute path and `..` stay inside);
//! RESOLVE_NO_SYMLINKS refuses any symlink (ELOOP); RESOLVE_NO_XDEV and
//! RESOLVE_NO_MAGICLINKS allow an ordinary path and symlink. Otherwise the
//! openat vocabulary (EEXIST, ENOENT, ENOTDIR). A descriptor's identity is
//! checked by inode; openat2 results are closed unobserved.

use crate::catalog::{DEFAULTS, KernelFloor, Scenario};

use patina_dst_syscalls::Syscall;

use crate::probe::{AT_FDCWD, Probe, neg, page_size};
use libc::*;

/// linux/openat2.h OPEN_HOW_SIZE_VER0: `flags`, `mode`, `resolve`.
const HOW: usize = 24;
/// A RESOLVE_* bit the kernel does not define.
const UNKNOWN_RESOLVE: u64 = 0x80;
/// An open flag in the upper 32 bits, which openat2 refuses.
const UPPER_FLAG: u64 = 1 << 40;

pub fn run(p: &Probe) {
    let root = p.dir();
    let file = format!("{root}/f");
    let fd = p.openat(AT_FDCWD, &file, O_WRONLY | O_CREAT | O_EXCL, 0o644);
    p.require("create f", fd >= 0);
    p.close(fd);
    p.check(
        "mkdirat d",
        p.mkdirat(AT_FDCWD, &format!("{root}/d"), 0o755) == 0,
    );
    let inner = p.openat(
        AT_FDCWD,
        &format!("{root}/d/inner"),
        O_WRONLY | O_CREAT | O_EXCL,
        0o644,
    );
    p.require("create d/inner", inner >= 0);
    p.close(inner);
    p.check(
        "symlinkat l -> f",
        p.symlinkat("f", AT_FDCWD, &format!("{root}/l")) == 0,
    );
    p.check(
        "symlinkat d/esc -> ../f",
        p.symlinkat("../f", AT_FDCWD, &format!("{root}/d/esc")) == 0,
    );
    let inode = |path: &str| p.newfstatat(AT_FDCWD, path, 0).1.map(|s| s.ino);
    let f_ino = inode(&file);
    let inner_ino = inode(&format!("{root}/d/inner"));
    let rootfd = p.openat(AT_FDCWD, &root, O_RDONLY | O_DIRECTORY, 0);
    let dfd = p.openat(AT_FDCWD, &format!("{root}/d"), O_RDONLY | O_DIRECTORY, 0);
    p.require("open the directories", rootfd >= 0 && dfd >= 0);

    // An opened descriptor's inode, read and closed unobserved: patina's
    // answer to openat2 must not shift the rest of the stream.
    let opened = |fd: i32| -> Option<u64> {
        if fd < 0 {
            return None;
        }
        p.rec.quiet(|| {
            let ino = p.fstat(fd).1.map(|s| s.ino);
            p.close(fd);
            ino
        })
    };
    let read_only = (O_RDONLY as u64, 0, 0);

    // ---- the struct ----------------------------------------------------------
    p.check(
        "openat2 opens by path",
        opened(p.openat2(AT_FDCWD, &file, read_only, HOW, 0)) == f_ino,
    );
    p.check(
        "a struct smaller than OPEN_HOW_SIZE_VER0 is EINVAL",
        i64::from(p.openat2(AT_FDCWD, &file, read_only, HOW - 1, 0)) == neg(EINVAL),
    );
    p.check(
        "a struct larger than a page is E2BIG",
        i64::from(p.openat2(AT_FDCWD, &file, read_only, page_size() + 1, 0)) == neg(E2BIG),
    );
    p.check(
        "a larger struct with zero trailing bytes is accepted",
        opened(p.openat2(AT_FDCWD, &file, read_only, HOW + 8, 0)) == f_ino,
    );
    p.check(
        "nonzero trailing bytes are E2BIG",
        i64::from(p.openat2(AT_FDCWD, &file, read_only, HOW + 8, 1)) == neg(E2BIG),
    );

    // ---- strict flags and mode -------------------------------------------------
    p.check(
        "an upper-32-bit flag is EINVAL",
        i64::from(p.openat2(AT_FDCWD, &file, (UPPER_FLAG, 0, 0), HOW, 0)) == neg(EINVAL),
    );
    p.check(
        "a mode without O_CREAT is EINVAL",
        i64::from(p.openat2(AT_FDCWD, &file, (O_RDONLY as u64, 0o644, 0), HOW, 0)) == neg(EINVAL),
    );
    p.check(
        "a mode past 07777 is EINVAL",
        i64::from(p.openat2(
            AT_FDCWD,
            &format!("{root}/new"),
            ((O_WRONLY | O_CREAT) as u64, 0o10644, 0),
            HOW,
            0,
        )) == neg(EINVAL),
    );
    p.check(
        "an unknown RESOLVE_* bit is EINVAL",
        i64::from(p.openat2(
            AT_FDCWD,
            &file,
            (O_RDONLY as u64, 0, UNKNOWN_RESOLVE),
            HOW,
            0,
        )) == neg(EINVAL),
    );
    p.check(
        "RESOLVE_BENEATH with RESOLVE_IN_ROOT is EINVAL",
        i64::from(p.openat2(
            rootfd,
            "f",
            (O_RDONLY as u64, 0, RESOLVE_BENEATH | RESOLVE_IN_ROOT),
            HOW,
            0,
        )) == neg(EINVAL),
    );
    p.check(
        "RESOLVE_CACHED with O_CREAT is EAGAIN",
        i64::from(p.openat2(
            rootfd,
            "cached",
            ((O_WRONLY | O_CREAT) as u64, 0o644, RESOLVE_CACHED),
            HOW,
            0,
        )) == neg(EAGAIN),
    );
    let created = p.openat2(
        rootfd,
        "new",
        ((O_WRONLY | O_CREAT | O_EXCL) as u64, 0o600, 0),
        HOW,
        0,
    );
    p.check("O_CREAT with a mode creates", opened(created).is_some());
    p.check(
        "the created file carries the mode",
        p.newfstatat(AT_FDCWD, &format!("{root}/new"), 0)
            .1
            .is_some_and(|s| s.kind == "reg" && s.perm == 0o600),
    );
    p.check(
        "O_CREAT|O_EXCL on an existing name is EEXIST",
        i64::from(p.openat2(
            rootfd,
            "f",
            ((O_WRONLY | O_CREAT | O_EXCL) as u64, 0o600, 0),
            HOW,
            0,
        )) == neg(EEXIST),
    );
    p.check(
        "a missing name is ENOENT",
        i64::from(p.openat2(rootfd, "missing", read_only, HOW, 0)) == neg(ENOENT),
    );
    p.check(
        "O_DIRECTORY on a file is ENOTDIR",
        i64::from(p.openat2(rootfd, "f", ((O_RDONLY | O_DIRECTORY) as u64, 0, 0), HOW, 0))
            == neg(ENOTDIR),
    );

    // ---- resolution restrictions ---------------------------------------------
    let beneath = (O_RDONLY as u64, 0, RESOLVE_BENEATH);
    p.check(
        "RESOLVE_BENEATH allows a path beneath the dirfd",
        opened(p.openat2(rootfd, "d/inner", beneath, HOW, 0)) == inner_ino,
    );
    p.check(
        "RESOLVE_BENEATH follows a symlink that stays beneath",
        opened(p.openat2(rootfd, "d/esc", beneath, HOW, 0)) == f_ino,
    );
    p.check(
        "RESOLVE_BENEATH refuses `..` past the dirfd",
        i64::from(p.openat2(dfd, "../f", beneath, HOW, 0)) == neg(EXDEV),
    );
    p.check(
        "RESOLVE_BENEATH refuses a symlink out of the dirfd",
        i64::from(p.openat2(dfd, "esc", beneath, HOW, 0)) == neg(EXDEV),
    );
    p.check(
        "RESOLVE_BENEATH refuses an absolute path",
        i64::from(p.openat2(dfd, &file, beneath, HOW, 0)) == neg(EXDEV),
    );
    let in_root = (O_RDONLY as u64, 0, RESOLVE_IN_ROOT);
    p.check(
        "RESOLVE_IN_ROOT resolves an absolute path inside the dirfd",
        opened(p.openat2(dfd, "/inner", in_root, HOW, 0)) == inner_ino,
    );
    p.check(
        "RESOLVE_IN_ROOT clamps `..` at the dirfd",
        opened(p.openat2(dfd, "../../inner", in_root, HOW, 0)) == inner_ino,
    );
    p.check(
        "RESOLVE_NO_SYMLINKS refuses a symlink",
        i64::from(p.openat2(
            rootfd,
            "l",
            (O_RDONLY as u64, 0, RESOLVE_NO_SYMLINKS),
            HOW,
            0,
        )) == neg(ELOOP),
    );
    p.check(
        "RESOLVE_NO_SYMLINKS allows a plain path",
        opened(p.openat2(
            rootfd,
            "d/inner",
            (O_RDONLY as u64, 0, RESOLVE_NO_SYMLINKS),
            HOW,
            0,
        )) == inner_ino,
    );
    p.check(
        "RESOLVE_NO_MAGICLINKS allows an ordinary symlink",
        opened(p.openat2(
            rootfd,
            "l",
            (O_RDONLY as u64, 0, RESOLVE_NO_MAGICLINKS),
            HOW,
            0,
        )) == f_ino,
    );
    p.check(
        "RESOLVE_NO_XDEV allows a path on one mount",
        opened(p.openat2(
            rootfd,
            "d/inner",
            (O_RDONLY as u64, 0, RESOLVE_NO_XDEV),
            HOW,
            0,
        )) == inner_ino,
    );
    p.check(
        "openat2 relative to a closed descriptor is EBADF",
        i64::from(p.openat2(4000, "f", read_only, HOW, 0)) == neg(EBADF),
    );
    p.close(rootfd);
    p.close(dfd);
}

pub const SCENARIO: Scenario = Scenario {
    name: "fs/openat2",
    run,
    covers: &[
        Syscall::N_openat2,
        Syscall::N_openat,
        Syscall::N_newfstatat,
        Syscall::N_fstat,
        Syscall::N_mkdirat,
        Syscall::N_symlinkat,
        Syscall::N_close,
    ],
    symbols: &[
        "syscall",
        "openat",
        "fstatat",
        "fstat",
        "mkdirat",
        "symlinkat",
        "close",
    ],
    kernel_floor: Some(KernelFloor {
        release: "5.12",
        why: "RESOLVE_CACHED",
    }),
    ..DEFAULTS
};
