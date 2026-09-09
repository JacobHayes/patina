//! fs/getdents — getdents64 over a directory descriptor: the entry set, `.`
//! and `..`, d_type per kind, the cursor (EOF and rewind through lseek), and
//! the errno vocabulary. Its own probe because the libc symbol `getdents64` is
//! not interposed today, which makes the whole binary an audit refusal under
//! patina; keeping it apart leaves fs/dirs runnable.

#[cfg(target_os = "linux")]
mod scenario {
    use libc::*;
    use syscall_conformance::calls::{neg, Probe, AT_FDCWD};
    use syscall_conformance::vehicle::{fold_errno, Args, Sys};

    // glibc exports `getdents64` (2.30+) but the libc crate does not declare it
    // for gnu targets. Declared HERE, not in the shared vehicle table, so only
    // this probe binary imports the (uninterposed) symbol.
    extern "C" {
        fn getdents64(fd: c_int, dirp: *mut c_void, count: size_t) -> ssize_t;
    }

    fn libc_getdents64(a: Args) -> i64 {
        fold_errno(unsafe { getdents64(a[0] as c_int, a[1] as *mut c_void, a[2] as size_t) } as i64)
    }

    pub fn run(p: &Probe) {
        p.register_libc(Sys::Getdents64, libc_getdents64);
        let root = p.scratch();
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

        let dirfd = p.openat(AT_FDCWD, &root, O_RDONLY | O_DIRECTORY, 0);
        p.require("open the directory", dirfd >= 0);
        let (r, entries) = p.getdents64(dirfd, 4096);
        p.check("getdents64 returns bytes", r > 0);
        let has = |name: &str, kind: u8| entries.iter().any(|(n, k)| n == name && *k == kind);
        p.check(
            "regular files are DT_REG",
            has("a", DT_REG) && has("b", DT_REG),
        );
        p.check("the subdirectory is DT_DIR", has("sub", DT_DIR));
        p.check("the symlink is DT_LNK", has("l", DT_LNK));
        p.check(
            "'.' and '..' are listed as DT_DIR",
            has(".", DT_DIR) && has("..", DT_DIR),
        );
        p.check("every entry exactly once", entries.len() == 6);
        let (r, _) = p.getdents64(dirfd, 4096);
        p.check("a second call at the end returns 0", r == 0);
        p.check(
            "lseek to 0 rewinds the directory",
            p.lseek(dirfd, 0, SEEK_SET) == 0,
        );
        let (r, again) = p.getdents64(dirfd, 4096);
        p.check(
            "after the rewind the same entries come back",
            r > 0 && again == entries,
        );
        p.lseek(dirfd, 0, SEEK_SET);
        let (r, _) = p.getdents64(dirfd, 16);
        p.check(
            "a buffer too small for one entry is EINVAL",
            r == neg(EINVAL),
        );

        let file = p.openat(AT_FDCWD, &format!("{root}/a"), O_RDONLY, 0);
        p.require("open a", file >= 0);
        let (r, _) = p.getdents64(file, 4096);
        p.check("getdents64 on a file is ENOTDIR", r == neg(ENOTDIR));
        let (r, _) = p.getdents64(4000, 4096);
        p.check(
            "getdents64 on a closed descriptor is EBADF",
            r == neg(EBADF),
        );

        p.check(
            "unlinkat a",
            p.unlinkat(AT_FDCWD, &format!("{root}/a"), 0) == 0,
        );
        p.lseek(dirfd, 0, SEEK_SET);
        let (r, after) = p.getdents64(dirfd, 4096);
        p.check(
            "an unlinked entry is no longer listed",
            r > 0 && !after.iter().any(|(n, _)| n == "a") && after.len() == 5,
        );
        p.close(file);
        p.close(dirfd);
    }
}

syscall_conformance::probe_main!("fs/getdents", scenario::run);
