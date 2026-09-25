//! fs/getdents — listing a directory through getdents64 and x86_64's legacy
//! getdents (`struct linux_dirent`: the type in each record's last byte, after
//! the name's padding; fs/readdir.c filldir). Through each row: the entry set,
//! `.` and `..`, d_type per kind, 0 at the end, a rewind through lseek, EINVAL
//! for a buffer too small for one record, ENOTDIR for a file, EBADF for a
//! closed descriptor. Through getdents64: an unlinked entry drops out, and the
//! cursor (the position after a call is its last record's d_off, and seeking
//! to a d_off resumes after that record; SEEK_END is filesystem-specific —
//! refused, or a position whose listing is a suffix of the whole). The libc
//! door of getdents64 is glibc's `getdents64`; glibc has no getdents wrapper,
//! so that row's libc spelling is `syscall(2)`.

use crate::catalog::{DEFAULTS, Scenario};

use patina_dst_syscalls::Syscall;

use crate::probe::{AT_FDCWD, Probe, neg};
use libc::*;

/// The listing rows this architecture has: the generic (arm64) table has no
/// legacy getdents.
const ROWS: &[Syscall] = &[
    Syscall::N_getdents64,
    #[cfg(target_arch = "x86_64")]
    Syscall::N_getdents,
];

pub fn run(p: &Probe) {
    let root = p.dir();
    for name in ["a", "b"] {
        let fd = p.openat(
            AT_FDCWD,
            &format!("{root}/{name}"),
            O_WRONLY | O_CREAT | O_EXCL,
            0o640,
        );
        p.require("create file", fd >= 0);
        p.close(fd);
    }
    p.check(
        "mkdirat sub",
        p.mkdirat(AT_FDCWD, &format!("{root}/sub"), 0o750) == 0,
    );
    p.check(
        "symlinkat l -> a",
        p.symlinkat("a", AT_FDCWD, &format!("{root}/l")) == 0,
    );
    p.check(
        "mknodat a FIFO",
        p.mknodat(AT_FDCWD, &format!("{root}/p"), S_IFIFO | 0o640, 0) == 0,
    );
    let file = p.openat(AT_FDCWD, &format!("{root}/a"), O_RDONLY, 0);
    p.require("open a", file >= 0);

    for &row in ROWS {
        let name = row.name();
        let dirfd = p.openat(AT_FDCWD, &root, O_RDONLY | O_DIRECTORY, 0);
        p.require("open the directory", dirfd >= 0);
        let (r, entries) = p.getdents(row, dirfd, 4096);
        p.check(&format!("{name} returns bytes"), r > 0);
        let has = |entry: &str, kind: u8| entries.iter().any(|(n, k)| n == entry && *k == kind);
        p.check(
            &format!("{name}: regular files are DT_REG"),
            has("a", DT_REG) && has("b", DT_REG),
        );
        p.check(
            &format!("{name}: the subdirectory is DT_DIR"),
            has("sub", DT_DIR),
        );
        p.check(&format!("{name}: the symlink is DT_LNK"), has("l", DT_LNK));
        p.check(&format!("{name}: the FIFO is DT_FIFO"), has("p", DT_FIFO));
        p.check(
            &format!("{name}: '.' and '..' are listed as DT_DIR"),
            has(".", DT_DIR) && has("..", DT_DIR),
        );
        p.check(
            &format!("{name}: every entry exactly once"),
            entries.len() == 7,
        );
        p.check(
            &format!("{name}: a second call at the end returns 0"),
            p.getdents(row, dirfd, 4096).0 == 0,
        );
        p.check(
            &format!("{name}: lseek to 0 rewinds the directory"),
            p.lseek(dirfd, 0, SEEK_SET) == 0,
        );
        let (r, again) = p.getdents(row, dirfd, 4096);
        p.check(
            &format!("{name}: after the rewind the same entries come back"),
            r > 0 && again == entries,
        );
        p.lseek(dirfd, 0, SEEK_SET);
        p.check(
            &format!("{name}: a buffer too small for one record is EINVAL"),
            p.getdents(row, dirfd, 16).0 == neg(EINVAL),
        );
        p.check(
            &format!("{name} on a file is ENOTDIR"),
            p.getdents(row, file, 4096).0 == neg(ENOTDIR),
        );
        p.check(
            &format!("{name} on a closed descriptor is EBADF"),
            p.getdents(row, 4000, 4096).0 == neg(EBADF),
        );
        p.close(dirfd);
    }

    p.check(
        "unlinkat a",
        p.unlinkat(AT_FDCWD, &format!("{root}/a"), 0) == 0,
    );
    let dirfd = p.openat(AT_FDCWD, &root, O_RDONLY | O_DIRECTORY, 0);
    p.require("open the directory", dirfd >= 0);
    let (r, after) = p.getdents(Syscall::N_getdents64, dirfd, 4096);
    p.check(
        "an unlinked entry is no longer listed",
        r > 0 && !after.iter().any(|(n, _)| n == "a") && after.len() == 6,
    );
    p.close(file);
    p.close(dirfd);

    // ---- the directory cursor ----------------------------------------------
    // A directory's positions are cookies its filesystem chooses (lseek(2):
    // directory offsets are filesystem-specific), so they are never recorded,
    // only related: a fresh descriptor is at 0; after a call the cursor is
    // the last record's d_off (fs/readdir.c getdents64 stores ctx.pos there);
    // seeking to a record's d_off resumes right after that record; SEEK_END
    // is refused (EINVAL: tmpfs's dcache_dir_lseek) or lands at a position
    // whose listing is a suffix of the whole one, in order (ext4: 2^63-1,
    // past every hash, so nothing follows; XFS: generic_file_llseek at the
    // directory's VFS size, 0 here, so the whole listing follows).
    let lseek_raw = |fd: i32, offset: i64, whence: i32| {
        p.call_unrecorded(
            Syscall::N_lseek,
            [fd as i64, offset, whence as i64, 0, 0, 0],
        )
    };
    let fresh = p.openat(AT_FDCWD, &root, O_RDONLY | O_DIRECTORY, 0);
    p.require("reopen the directory", fresh >= 0);
    p.check(
        "a fresh directory descriptor is at 0",
        p.lseek(fresh, 0, SEEK_CUR) == 0,
    );
    let (r, all) = p.getdents64_cookies(fresh, 4096);
    p.check("the whole listing in one call", r > 0 && all.len() == 6);
    p.check(
        "after a call the cursor is the last record's d_off",
        all.last()
            .is_some_and(|last| last.off == lseek_raw(fresh, 0, SEEK_CUR)),
    );
    p.check("rewind", p.lseek(fresh, 0, SEEK_SET) == 0);
    // Every name here is at most four bytes (19 + len + 1 rounds to 24), so
    // every record is 24 bytes and this buffer holds exactly two.
    let (r, first) = p.getdents64_cookies(fresh, 48);
    p.check(
        "a two-record buffer gets two records",
        r == 48 && first.len() == 2,
    );
    p.check(
        "a partial call leaves the cursor at its last record's d_off",
        first.len() == 2 && first[1].off == lseek_raw(fresh, 0, SEEK_CUR),
    );
    let resumed = first
        .first()
        .map_or(-1, |entry| lseek_raw(fresh, entry.off, SEEK_SET));
    p.check(
        "seeking to a record's d_off lands there",
        first.first().is_some_and(|entry| resumed == entry.off),
    );
    let (r, rest) = p.getdents64_cookies(fresh, 4096);
    let names = |entries: &[crate::probe::Dirent]| -> Vec<String> {
        entries.iter().map(|entry| entry.name.clone()).collect()
    };
    p.check(
        "and resumes right after that record",
        r > 0 && all.len() == 6 && names(&rest) == names(&all[1..]),
    );
    let end = lseek_raw(fresh, 0, SEEK_END);
    let after_end = if end >= 0 {
        p.rec.quiet(|| p.getdents64_cookies(fresh, 4096))
    } else {
        (end, Vec::new())
    };
    let listed = names(&all);
    p.check(
        "SEEK_END is refused, or lands where what follows is a suffix of the listing",
        end == neg(EINVAL)
            || (end >= 0 && after_end.0 >= 0 && listed.ends_with(&names(&after_end.1))),
    );
    p.close(fresh);
}

pub const SCENARIO: Scenario = Scenario {
    name: "fs/getdents",
    run,
    covers: &[
        Syscall::N_getdents64,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_getdents,
        Syscall::N_openat,
        Syscall::N_close,
        Syscall::N_lseek,
        Syscall::N_mkdirat,
        Syscall::N_symlinkat,
        Syscall::N_mknodat,
        Syscall::N_unlinkat,
    ],
    symbols: &[
        "getdents64",
        #[cfg(target_arch = "x86_64")]
        "syscall",
        "openat",
        "close",
        "lseek",
        "mkdirat",
        "symlinkat",
        "mknodat",
        "unlinkat",
    ],
    ..DEFAULTS
};
