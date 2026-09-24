//! fs/renameat2 — renameat2's flags (rename(2), fs/namei.c do_renameat2):
//! flags 0 is renameat; RENAME_NOREPLACE refuses an existing destination with
//! EEXIST (a file, a directory, even an empty one) and otherwise renames;
//! RENAME_EXCHANGE swaps two existing names atomically, of any two kinds, and
//! is ENOENT when either is missing and EINVAL when one contains the other;
//! NOREPLACE or WHITEOUT with EXCHANGE, and any unknown bit, are EINVAL before
//! the paths are looked at; RENAME_WHITEOUT needs no privilege since Linux 5.8
//! and leaves a whiteout (a 0/0 character device) at the old name.

use crate::catalog::{DEFAULTS, KernelFloor, Need, Scenario};

use patina_dst_syscalls::Syscall;

use crate::probe::{AT_FDCWD, Probe, neg};
use libc::*;

/// A flag bit renameat2 does not define.
const UNKNOWN_FLAG: u32 = 1 << 3;

/// A file's bytes (nothing when it cannot be opened).
fn contents(p: &Probe, path: &str) -> Vec<u8> {
    // Read and close whatever open answered, so a refused open records the
    // same calls (EBADF) and the stream stays aligned.
    let fd = p.openat(AT_FDCWD, path, O_RDONLY, 0);
    let (_, data) = p.read(fd, 16);
    p.close(fd);
    data
}

fn kind(p: &Probe, path: &str) -> Option<&'static str> {
    p.newfstatat(AT_FDCWD, path, AT_SYMLINK_NOFOLLOW)
        .1
        .map(|s| s.kind)
}

pub fn run(p: &Probe) {
    let root = p.dir();
    for (name, data) in [("a", b"A"), ("b", b"B")] {
        let fd = p.openat(
            AT_FDCWD,
            &format!("{root}/{name}"),
            O_WRONLY | O_CREAT | O_EXCL,
            0o644,
        );
        p.require("create a file", fd >= 0);
        p.write(fd, data);
        p.close(fd);
    }
    for dir in ["d", "d/inner", "e"] {
        p.check(
            "mkdirat",
            p.mkdirat(AT_FDCWD, &format!("{root}/{dir}"), 0o755) == 0,
        );
    }
    let dirfd = p.openat(AT_FDCWD, &root, O_RDONLY | O_DIRECTORY, 0);
    p.require("open the run directory", dirfd >= 0);

    // ---- flags 0 -----------------------------------------------------------
    p.check(
        "renameat2 with no flags renames",
        p.renameat2(dirfd, "a", dirfd, "c", 0) == 0,
    );
    p.check(
        "the old name is gone",
        kind(p, &format!("{root}/a")).is_none(),
    );
    let onto_nonempty = p.renameat2(dirfd, "e", dirfd, "d", 0);
    p.check(
        "no flags: a directory onto a nonempty one is ENOTEMPTY or EEXIST",
        onto_nonempty == neg(ENOTEMPTY) || onto_nonempty == neg(EEXIST),
    );

    // ---- RENAME_NOREPLACE --------------------------------------------------
    p.check(
        "RENAME_NOREPLACE onto an existing file is EEXIST",
        p.renameat2(dirfd, "c", dirfd, "b", RENAME_NOREPLACE) == neg(EEXIST),
    );
    let (b, c) = (
        contents(p, &format!("{root}/b")),
        contents(p, &format!("{root}/c")),
    );
    p.check("the refused rename left both files", b == b"B" && c == b"A");
    p.check(
        "RENAME_NOREPLACE onto an empty directory is EEXIST",
        p.renameat2(dirfd, "e", dirfd, "d/inner", RENAME_NOREPLACE) == neg(EEXIST),
    );
    p.check(
        "RENAME_NOREPLACE onto a missing name renames",
        p.renameat2(dirfd, "c", dirfd, "a", RENAME_NOREPLACE) == 0,
    );
    p.check(
        "RENAME_NOREPLACE of a missing source is ENOENT",
        p.renameat2(dirfd, "missing", dirfd, "x", RENAME_NOREPLACE) == neg(ENOENT),
    );

    // ---- RENAME_EXCHANGE ---------------------------------------------------
    p.check(
        "RENAME_EXCHANGE swaps two files",
        p.renameat2(dirfd, "a", dirfd, "b", RENAME_EXCHANGE) == 0,
    );
    let (a, b) = (
        contents(p, &format!("{root}/a")),
        contents(p, &format!("{root}/b")),
    );
    p.check("the contents moved with the names", a == b"B" && b == b"A");
    p.check(
        "RENAME_EXCHANGE swaps a file and a directory",
        p.renameat2(dirfd, "a", dirfd, "e", RENAME_EXCHANGE) == 0,
    );
    p.check(
        "the kinds moved with the names",
        (kind(p, &format!("{root}/a")), kind(p, &format!("{root}/e")))
            == (Some("dir"), Some("reg")),
    );
    p.check(
        "RENAME_EXCHANGE with a missing destination is ENOENT",
        p.renameat2(dirfd, "b", dirfd, "missing", RENAME_EXCHANGE) == neg(ENOENT),
    );
    p.check(
        "RENAME_EXCHANGE of a directory with its own child is EINVAL",
        p.renameat2(dirfd, "d", dirfd, "d/inner", RENAME_EXCHANGE) == neg(EINVAL),
    );
    p.check(
        "RENAME_EXCHANGE of a name with itself succeeds",
        p.renameat2(dirfd, "b", dirfd, "b", RENAME_EXCHANGE) == 0,
    );

    // ---- refused flag sets, judged before the paths -----------------------------
    p.check(
        "RENAME_NOREPLACE|RENAME_EXCHANGE is EINVAL",
        p.renameat2(
            dirfd,
            "missing",
            dirfd,
            "x",
            RENAME_NOREPLACE | RENAME_EXCHANGE,
        ) == neg(EINVAL),
    );
    p.check(
        "an unknown flag is EINVAL",
        p.renameat2(dirfd, "missing", dirfd, "x", UNKNOWN_FLAG) == neg(EINVAL),
    );
    p.check(
        "RENAME_WHITEOUT needs no privilege: a missing source is ENOENT",
        p.renameat2(dirfd, "missing", dirfd, "x", RENAME_WHITEOUT) == neg(ENOENT),
    );
    p.check(
        "RENAME_WHITEOUT|RENAME_EXCHANGE is EINVAL",
        p.renameat2(dirfd, "b", dirfd, "e", RENAME_WHITEOUT | RENAME_EXCHANGE) == neg(EINVAL),
    );
    p.check(
        "renameat2 relative to a closed descriptor is EBADF",
        p.renameat2(4000, "b", dirfd, "x", 0) == neg(EBADF),
    );
    p.check(
        "renameat2 with absolute paths ignores the dirfds",
        p.renameat2(
            4000,
            &format!("{root}/b"),
            4000,
            &format!("{root}/f"),
            RENAME_NOREPLACE,
        ) == 0,
    );
    p.check(
        "RENAME_WHITEOUT renames",
        p.renameat2(dirfd, "f", dirfd, "g", RENAME_WHITEOUT) == 0,
    );
    let (r, whiteout) = p.newfstatat(dirfd, "f", AT_SYMLINK_NOFOLLOW);
    p.check(
        "and leaves a whiteout, a character device, at the old name",
        r == 0 && whiteout.is_some_and(|s| s.kind == "chr"),
    );
    p.close(dirfd);
}

pub const SCENARIO: Scenario = Scenario {
    name: "fs/renameat2",
    run,
    covers: &[
        Syscall::N_renameat2,
        Syscall::N_openat,
        Syscall::N_read,
        Syscall::N_write,
        Syscall::N_close,
        Syscall::N_mkdirat,
        Syscall::N_newfstatat,
    ],
    symbols: &[
        "renameat2",
        "openat",
        "read",
        "write",
        "close",
        "mkdirat",
        "fstatat",
    ],
    needs: &[Need::Whiteouts],
    kernel_floor: Some(KernelFloor {
        release: "5.8",
        why: "RENAME_WHITEOUT without CAP_MKNOD",
    }),
    ..DEFAULTS
};
