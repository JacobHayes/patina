//! fs/metadata — fstat / newfstatat / statx (plus the identity constants they
//! report): kinds, permission bits, link counts, sizes, inode identity, the
//! AT_* flag vocabulary, and timestamp ordering.

#[cfg(target_os = "linux")]
mod scenario {
    use libc::*;
    use syscall_conformance::calls::{neg, Probe, AT_FDCWD};

    pub fn run(p: &Probe) {
        let root = p.scratch();
        let file = format!("{root}/f");
        let dir = format!("{root}/d");
        let link = format!("{root}/l");

        let uid = p.getuid();
        let gid = p.getgid();
        let pid = p.getpid();
        p.check("pid is positive", pid > 0);

        let fd = p.openat(AT_FDCWD, &file, O_RDWR | O_CREAT | O_EXCL, 0o640);
        p.require("create f", fd >= 0);
        let (r, st) = p.fstat(fd);
        p.require("fstat f", r == 0 && st.is_some());
        let st = st.unwrap();
        p.check("fstat: regular file", st.kind == "reg");
        p.check(
            "fstat: creation mode 0640 survives the umask",
            st.perm == 0o640,
        );
        p.check("fstat: empty", st.size == 0);
        p.check("fstat: one link", st.nlink == 1);
        p.check(
            "fstat: owned by the caller",
            i64::from(st.uid) == uid && i64::from(st.gid) == gid,
        );

        p.write(fd, b"12345");
        let (_, after) = p.fstat(fd);
        let after = after.expect("fstat after write");
        p.check("size follows the write", after.size == 5);
        p.check(
            "mtime does not go backwards on write",
            after.mtime_ns >= st.mtime_ns,
        );
        p.check("inode identity is stable", after.ino == st.ino);

        let (r, by_path) = p.newfstatat(AT_FDCWD, &file, 0);
        p.check(
            "newfstatat by path sees the same inode",
            r == 0
                && by_path
                    .as_ref()
                    .is_some_and(|s| s.ino == st.ino && s.size == 5),
        );
        let (r, empty_path) = p.newfstatat(fd, "", AT_EMPTY_PATH);
        p.check(
            "AT_EMPTY_PATH stats the descriptor",
            r == 0 && empty_path.as_ref().is_some_and(|s| s.ino == st.ino),
        );
        let (r, _) = p.newfstatat(AT_FDCWD, &format!("{root}/missing"), 0);
        p.check("a missing path is ENOENT", r == neg(ENOENT));
        let (r, _) = p.newfstatat(AT_FDCWD, &file, 0x1);
        p.check("an unknown flag is EINVAL", r == neg(EINVAL));
        let (r, _) = p.fstat(4000);
        p.check("fstat on a closed descriptor is EBADF", r == neg(EBADF));

        p.check("mkdirat 0750", p.mkdirat(AT_FDCWD, &dir, 0o750) == 0);
        let (r, d) = p.newfstatat(AT_FDCWD, &dir, 0);
        p.check(
            "a directory: kind dir, mode 0750, two links",
            r == 0
                && d.as_ref()
                    .is_some_and(|s| s.kind == "dir" && s.perm == 0o750 && s.nlink == 2),
        );
        let dirfd = p.openat(AT_FDCWD, &dir, O_RDONLY | O_DIRECTORY, 0);
        p.require("open d", dirfd >= 0);
        let (r, via_fd) = p.fstat(dirfd);
        p.check(
            "fstat on a directory descriptor",
            r == 0 && via_fd.as_ref().is_some_and(|s| s.kind == "dir"),
        );
        p.check(
            "mkdirat relative to a dirfd",
            p.mkdirat(dirfd, "sub", 0o750) == 0,
        );
        let (r, d2) = p.newfstatat(AT_FDCWD, &dir, 0);
        p.check(
            "a subdirectory bumps the parent link count to 3",
            r == 0 && d2.as_ref().is_some_and(|s| s.nlink == 3),
        );
        let (r, sub) = p.newfstatat(dirfd, "sub", 0);
        p.check("newfstatat relative to a dirfd", r == 0 && sub.is_some());

        p.check("symlinkat l -> f", p.symlinkat("f", AT_FDCWD, &link) == 0);
        let (r, nofollow) = p.newfstatat(AT_FDCWD, &link, AT_SYMLINK_NOFOLLOW);
        p.check(
            "AT_SYMLINK_NOFOLLOW: kind lnk, size = target length",
            r == 0
                && nofollow
                    .as_ref()
                    .is_some_and(|s| s.kind == "lnk" && s.size == 1),
        );
        let (r, follow) = p.newfstatat(AT_FDCWD, &link, 0);
        p.check(
            "following the link reaches f",
            r == 0
                && follow
                    .as_ref()
                    .is_some_and(|s| s.kind == "reg" && s.ino == st.ino),
        );

        p.check(
            "linkat f -> h",
            p.linkat(AT_FDCWD, &file, AT_FDCWD, &format!("{root}/h"), 0) == 0,
        );
        let (_, linked) = p.fstat(fd);
        let linked = linked.expect("fstat after link");
        p.check("a hard link bumps nlink to 2", linked.nlink == 2);
        p.check(
            "ctime does not go backwards on link",
            linked.ctime_ns >= after.ctime_ns,
        );

        let (r, sx, mask) = p.statx(AT_FDCWD, &file, 0, STATX_BASIC_STATS);
        p.check(
            "statx basic stats",
            r == 0
                && sx.as_ref().is_some_and(|s| {
                    s.kind == "reg" && s.size == 5 && s.nlink == 2 && s.ino == st.ino
                }),
        );
        p.check(
            "statx fills every basic field",
            mask & STATX_BASIC_STATS == STATX_BASIC_STATS,
        );
        let (r, _, mask) = p.statx(AT_FDCWD, &file, 0, STATX_BTIME);
        p.check(
            "statx can report a birth time",
            r == 0 && mask & STATX_BTIME != 0,
        );
        let (r, sx, _) = p.statx(fd, "", AT_EMPTY_PATH, STATX_ALL);
        p.check(
            "statx AT_EMPTY_PATH on the descriptor",
            r == 0 && sx.as_ref().is_some_and(|s| s.ino == st.ino),
        );
        let (r, sx, _) = p.statx(AT_FDCWD, &link, AT_SYMLINK_NOFOLLOW, STATX_BASIC_STATS);
        p.check(
            "statx AT_SYMLINK_NOFOLLOW sees the link",
            r == 0 && sx.as_ref().is_some_and(|s| s.kind == "lnk"),
        );
        let (r, _, _) = p.statx(AT_FDCWD, &format!("{root}/missing"), 0, STATX_BASIC_STATS);
        p.check("statx on a missing path is ENOENT", r == neg(ENOENT));
        let (r, _, _) = p.statx(AT_FDCWD, &file, 0x1, STATX_BASIC_STATS);
        p.check("statx with an unknown flag is EINVAL", r == neg(EINVAL));
        let (r, _, _) = p.statx(dirfd, "sub", 0, STATX_TYPE | STATX_MODE);
        p.check("statx relative to a dirfd with a narrow mask", r == 0);

        p.close(fd);
        p.close(dirfd);
    }
}

syscall_conformance::probe_main!("fs/metadata", scenario::run);
