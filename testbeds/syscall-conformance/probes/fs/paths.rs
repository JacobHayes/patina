//! fs/paths — the working directory, path resolution, and the umask: relative
//! paths from a changed cwd, `..` applied after symlink expansion, the 40-hop
//! ELOOP limit, ENAMETOOLONG, ENOTDIR through a file and on a trailing slash,
//! getcwd ERANGE/ENOENT, chdir/fchdir errno, umask applied to open/mkdir/mknod.

#[cfg(target_os = "linux")]
mod scenario {
    use libc::*;
    use syscall_conformance::calls::{neg, Probe, AT_FDCWD};

    fn stat_kind(p: &Probe, dirfd: i32, path: &str, flags: i32) -> Option<&'static str> {
        p.newfstatat(dirfd, path, flags).1.map(|s| s.kind)
    }

    pub fn run(p: &Probe) {
        let root = p.scratch();

        // ---- the working directory -----------------------------------------
        p.check("chdir into the scratch root", p.chdir(&root) == 0);
        let (r, cwd) = p.getcwd(4096);
        p.check(
            "getcwd reports the directory chdir set",
            r == 0 && cwd == root,
        );
        let (r, _) = p.getcwd(4);
        p.check("getcwd into a short buffer is ERANGE", r == neg(ERANGE));

        // Relative paths resolve against the changed directory.
        let fd = p.openat(AT_FDCWD, "rel.txt", O_RDWR | O_CREAT | O_EXCL, 0o644);
        p.require("create rel.txt relative to the cwd", fd >= 0);
        p.close(fd);
        p.check(
            "the relative name is visible by absolute path",
            stat_kind(p, AT_FDCWD, &format!("{root}/rel.txt"), 0) == Some("reg"),
        );
        p.check(
            "mkdirat relative to the cwd",
            p.mkdirat(AT_FDCWD, "sub", 0o755) == 0,
        );
        p.check("chdir into a relative subdirectory", p.chdir("sub") == 0);
        let (r, cwd) = p.getcwd(4096);
        p.check(
            "getcwd follows the relative chdir",
            r == 0 && cwd == format!("{root}/sub"),
        );
        let fd = p.openat(AT_FDCWD, "../rel.txt", O_RDONLY, 0);
        p.check("`..` from the cwd reaches the parent's file", fd >= 0);
        p.close(fd);
        p.check("chdir `..`", p.chdir("..") == 0);
        let (r, cwd) = p.getcwd(4096);
        p.check("getcwd after `..` is the root again", r == 0 && cwd == root);

        // AT_EMPTY_PATH on AT_FDCWD names the working directory itself.
        let (r, root_stat) = p.newfstatat(AT_FDCWD, &root, 0);
        p.require("stat the root", r == 0);
        let root_ino = root_stat.expect("root stat").ino;
        let (r, empty) = p.newfstatat(AT_FDCWD, "", AT_EMPTY_PATH);
        p.check(
            "AT_EMPTY_PATH on AT_FDCWD is the working directory",
            r == 0
                && empty
                    .as_ref()
                    .is_some_and(|s| s.kind == "dir" && s.ino == root_ino),
        );

        // A directory opened without O_DIRECTORY is still a directory
        // descriptor: `.` names the cwd, fstat says so, and fchdir accepts it.
        let dot = p.openat(AT_FDCWD, ".", O_RDONLY, 0);
        p.require("open `.`", dot >= 0);
        let (r, dot_stat) = p.fstat(dot);
        p.check(
            "`.` opened read-only is the cwd's directory node",
            r == 0
                && dot_stat
                    .as_ref()
                    .is_some_and(|s| s.kind == "dir" && s.ino == root_ino),
        );

        // chdir errno: a file, a missing name, a symlink to a directory.
        p.check(
            "chdir into a file is ENOTDIR",
            p.chdir("rel.txt") == neg(ENOTDIR),
        );
        p.check(
            "chdir into a missing name is ENOENT",
            p.chdir("missing") == neg(ENOENT),
        );
        p.check("mkdirat a", p.mkdirat(AT_FDCWD, "a", 0o755) == 0);
        p.check("mkdirat a/b", p.mkdirat(AT_FDCWD, "a/b", 0o755) == 0);
        p.check(
            "symlinkat link -> a/b",
            p.symlinkat("a/b", AT_FDCWD, "link") == 0,
        );
        p.check("chdir through a symlink", p.chdir("link") == 0);
        let (r, cwd) = p.getcwd(4096);
        p.check(
            "getcwd is the physical directory behind the symlink",
            r == 0 && cwd == format!("{root}/a/b"),
        );
        p.check("chdir back to the root", p.chdir(&root) == 0);

        // fchdir: an O_PATH directory descriptor works, a file fd is ENOTDIR, a
        // closed number is EBADF.
        let a_path = p.openat(AT_FDCWD, "a", O_PATH | O_DIRECTORY | O_CLOEXEC, 0);
        p.require("open a as O_PATH", a_path >= 0);
        p.check("fchdir on an O_PATH directory fd", p.fchdir(a_path) == 0);
        let (r, cwd) = p.getcwd(4096);
        p.check("getcwd after fchdir", r == 0 && cwd == format!("{root}/a"));
        p.check("fchdir on `.` (opened read-only)", p.fchdir(dot) == 0);
        let (r, cwd) = p.getcwd(4096);
        p.check(
            "getcwd after fchdir to the root descriptor",
            r == 0 && cwd == root,
        );
        let file_fd = p.openat(AT_FDCWD, "rel.txt", O_RDONLY, 0);
        p.require("open rel.txt", file_fd >= 0);
        p.check(
            "fchdir on a file descriptor is ENOTDIR",
            p.fchdir(file_fd) == neg(ENOTDIR),
        );
        p.check(
            "fchdir on a closed number is EBADF",
            p.fchdir(4000) == neg(EBADF),
        );
        p.close(a_path);
        p.close(dot);

        // ---- `..` is applied after symlink expansion ------------------------
        let fd = p.openat(AT_FDCWD, "a/x", O_WRONLY | O_CREAT | O_EXCL, 0o644);
        p.require("create a/x", fd >= 0);
        p.close(fd);
        p.check(
            "link/../x resolves through the link's target, not the link's name",
            stat_kind(p, AT_FDCWD, "link/../x", 0) == Some("reg"),
        );
        p.check(
            "the lexical reading of link/../x names nothing",
            stat_kind(p, AT_FDCWD, "x", 0).is_none(),
        );
        p.check(
            "openat with a bogus dirfd and an absolute path ignores the dirfd",
            {
                let fd = p.openat(4000, &format!("{root}/rel.txt"), O_RDONLY, 0);
                let ok = fd >= 0;
                if ok {
                    p.close(fd);
                }
                ok
            },
        );

        // ---- symlink hops ----------------------------------------------------
        // A chain of 40 links resolves; a 41st is ELOOP; a self-loop is ELOOP.
        let fd = p.openat(AT_FDCWD, "t", O_WRONLY | O_CREAT | O_EXCL, 0o644);
        p.require("create t", fd >= 0);
        p.close(fd);
        p.rec.quiet(|| {
            p.symlinkat("t", AT_FDCWD, "c40");
            for i in (1..40).rev() {
                p.symlinkat(&format!("c{}", i + 1), AT_FDCWD, &format!("c{i}"));
            }
            p.symlinkat("c1", AT_FDCWD, "c0");
            p.symlinkat("loop", AT_FDCWD, "loop");
        });
        let fd = p.openat(AT_FDCWD, "c1", O_RDONLY, 0);
        p.check("a chain of 40 symlinks resolves", fd >= 0);
        if fd >= 0 {
            p.close(fd);
        }
        let fd = p.openat(AT_FDCWD, "c0", O_RDONLY, 0);
        p.check(
            "a chain of 41 symlinks is ELOOP",
            i64::from(fd) == neg(ELOOP),
        );
        let fd = p.openat(AT_FDCWD, "loop", O_RDONLY, 0);
        p.check(
            "a self-referential symlink is ELOOP",
            i64::from(fd) == neg(ELOOP),
        );
        p.check(
            "newfstatat through the 41-hop chain is ELOOP",
            p.newfstatat(AT_FDCWD, "c0", 0).0 == neg(ELOOP),
        );
        p.check(
            "AT_SYMLINK_NOFOLLOW names the first link itself",
            stat_kind(p, AT_FDCWD, "c0", AT_SYMLINK_NOFOLLOW) == Some("lnk"),
        );

        // ---- name and path length -------------------------------------------
        let long_component = "n".repeat(256);
        let fd = p.openat(AT_FDCWD, &long_component, O_RDONLY, 0);
        p.check(
            "a 256-byte component is ENAMETOOLONG",
            i64::from(fd) == neg(ENAMETOOLONG),
        );
        let max_component = "m".repeat(255);
        let fd = p.openat(AT_FDCWD, &max_component, O_RDONLY, 0);
        p.check(
            "a 255-byte component is a legal (missing) name",
            i64::from(fd) == neg(ENOENT),
        );
        let long_path = "d/".repeat(2048);
        let fd = p.openat(AT_FDCWD, &long_path, O_RDONLY, 0);
        p.check(
            "a 4096-byte path is ENAMETOOLONG",
            i64::from(fd) == neg(ENAMETOOLONG),
        );
        p.check(
            "mkdirat of a 4096-byte path is ENAMETOOLONG",
            p.mkdirat(AT_FDCWD, &long_path, 0o755) == neg(ENAMETOOLONG),
        );

        // ---- ENOTDIR --------------------------------------------------------
        let fd = p.openat(AT_FDCWD, "rel.txt/x", O_RDONLY, 0);
        p.check(
            "a component through a file is ENOTDIR",
            i64::from(fd) == neg(ENOTDIR),
        );
        p.check(
            "newfstatat through a file is ENOTDIR",
            p.newfstatat(AT_FDCWD, "rel.txt/x", 0).0 == neg(ENOTDIR),
        );
        p.check(
            "mkdirat under a file is ENOTDIR",
            p.mkdirat(AT_FDCWD, "rel.txt/x", 0o755) == neg(ENOTDIR),
        );
        let fd = p.openat(AT_FDCWD, "rel.txt/", O_RDONLY, 0);
        p.check(
            "a trailing slash on a file is ENOTDIR",
            i64::from(fd) == neg(ENOTDIR),
        );
        p.check(
            "newfstatat with a trailing slash on a file is ENOTDIR",
            p.newfstatat(AT_FDCWD, "rel.txt/", 0).0 == neg(ENOTDIR),
        );
        p.check(
            "a trailing slash on a directory resolves",
            stat_kind(p, AT_FDCWD, "a/", 0) == Some("dir"),
        );
        p.check(
            "a trailing slash on a symlink to a directory follows it",
            stat_kind(p, AT_FDCWD, "link/", AT_SYMLINK_NOFOLLOW) == Some("dir"),
        );
        let fd = p.openat(AT_FDCWD, "a", O_RDONLY | O_CREAT | O_TRUNC, 0o644);
        p.check(
            "a creating open of a directory is EISDIR",
            i64::from(fd) == neg(EISDIR),
        );
        let fd = p.openat(AT_FDCWD, "rel.txt", O_RDONLY | O_DIRECTORY, 0);
        p.check(
            "O_DIRECTORY on a file is ENOTDIR",
            i64::from(fd) == neg(ENOTDIR),
        );
        let fd = p.openat(AT_FDCWD, "missing", O_RDONLY | O_DIRECTORY, 0);
        p.check(
            "O_DIRECTORY on a missing name is ENOENT",
            i64::from(fd) == neg(ENOENT),
        );
        let fd = p.openat(AT_FDCWD, "link", O_RDONLY | O_NOFOLLOW, 0);
        p.check(
            "O_NOFOLLOW on a symlink is ELOOP",
            i64::from(fd) == neg(ELOOP),
        );
        let fd = p.openat(AT_FDCWD, "", O_RDONLY, 0);
        p.check("an empty path is ENOENT", i64::from(fd) == neg(ENOENT));

        // ---- the umask --------------------------------------------------------
        p.check("the initial umask is 022", p.umask(0o077) == 0o022);
        let fd = p.openat(AT_FDCWD, "masked", O_WRONLY | O_CREAT | O_EXCL, 0o666);
        p.require("create masked under umask 077", fd >= 0);
        let (r, st) = p.fstat(fd);
        p.check(
            "open applies the umask: 0666 & ~077 is 0600",
            r == 0 && st.as_ref().is_some_and(|s| s.perm == 0o600),
        );
        p.close(fd);
        p.check(
            "mkdirat under umask 077",
            p.mkdirat(AT_FDCWD, "maskdir", 0o777) == 0,
        );
        p.check(
            "mkdir applies the umask: 0777 & ~077 is 0700",
            p.newfstatat(AT_FDCWD, "maskdir", 0)
                .1
                .is_some_and(|s| s.kind == "dir" && s.perm == 0o700),
        );
        p.check(
            "mknodat a FIFO under umask 077",
            p.mknodat(AT_FDCWD, "maskfifo", S_IFIFO | 0o666, 0) == 0,
        );
        p.check(
            "mknod applies the umask: the FIFO is 0600",
            p.newfstatat(AT_FDCWD, "maskfifo", 0)
                .1
                .is_some_and(|s| s.kind == "fifo" && s.perm == 0o600),
        );
        p.check("umask returns the previous mask", p.umask(0o022) == 0o077);
        let fd = p.openat(AT_FDCWD, "unmasked", O_WRONLY | O_CREAT | O_EXCL, 0o666);
        p.require("create unmasked under umask 022", fd >= 0);
        let (r, st) = p.fstat(fd);
        p.check(
            "the restored umask applies: 0666 & ~022 is 0644",
            r == 0 && st.as_ref().is_some_and(|s| s.perm == 0o644),
        );
        p.close(fd);

        // ---- an unlinked working directory ----------------------------------
        p.check("mkdirat gone", p.mkdirat(AT_FDCWD, "gone", 0o755) == 0);
        p.check("chdir into gone", p.chdir("gone") == 0);
        p.check(
            "unlinkat the working directory by absolute path",
            p.unlinkat(AT_FDCWD, &format!("{root}/gone"), AT_REMOVEDIR) == 0,
        );
        let (r, _) = p.getcwd(4096);
        p.check(
            "getcwd in an unlinked directory is ENOENT",
            r == neg(ENOENT),
        );
        let fd = p.openat(AT_FDCWD, "anything", O_RDONLY | O_CREAT, 0o644);
        p.check(
            "a relative create in an unlinked directory is ENOENT",
            i64::from(fd) == neg(ENOENT),
        );
        p.check("chdir out by absolute path", p.chdir(&root) == 0);
        let (r, cwd) = p.getcwd(4096);
        p.check("getcwd recovers", r == 0 && cwd == root);

        p.close(file_fd);

        // Creation permissions are enforced on the NEXT open, not merely
        // reported by stat (native_raw::creation_modes_are_enforced_on_later_open pairs the
        // modern spelling with x86's legacy open/creat/mkdir aliases).
        let fd = p.openat(AT_FDCWD, "strict", O_WRONLY | O_CREAT, 0o400);
        p.require("create strict file", fd >= 0);
        let (rc, st) = p.fstat(fd);
        p.check(
            "requested 0400 is stored",
            rc == 0 && st.is_some_and(|s| s.perm == 0o400),
        );
        p.close(fd);
        p.check(
            "0400 refuses a later write-open",
            i64::from(p.openat(AT_FDCWD, "strict", O_WRONLY, 0)) == neg(EACCES),
        );
        p.check("mkdir 0500", p.mkdirat(AT_FDCWD, "locked", 0o500) == 0);
        p.check(
            "0500 directory refuses a new name",
            i64::from(p.openat(AT_FDCWD, "locked/nope", O_WRONLY | O_CREAT, 0o600)) == neg(EACCES),
        );

        // A FIFO's descriptor uses the pipe channel while its metadata stays
        // filesystem-backed. No blocking host rendezvous is needed here.
        let rd = p.openat(AT_FDCWD, "maskfifo", O_RDONLY | O_NONBLOCK, 0);
        p.require("FIFO read-open without a writer", rd >= 0);
        let (rc, st) = p.fstat(rd);
        p.check(
            "FIFO fd reports FIFO",
            rc == 0 && st.is_some_and(|s| s.kind == "fifo" && s.perm == 0o600),
        );
        let wr = p.openat(AT_FDCWD, "maskfifo", O_WRONLY, 0);
        p.require("FIFO write-open with reader", wr >= 0);
        p.check("FIFO transfer write", p.write(wr, b"raw-fifo") == 8);
        let (n, bytes) = p.read(rd, 16);
        p.check("FIFO transfer read", n == 8 && bytes == b"raw-fifo");
        p.check("close FIFO writer", p.close(wr) == 0);
        p.check("FIFO EOF after last writer", p.read(rd, 1).0 == 0);
        p.close(rd);
        p.check(
            "FIFO writer without reader is ENXIO",
            i64::from(p.openat(AT_FDCWD, "maskfifo", O_WRONLY | O_NONBLOCK, 0)) == neg(ENXIO),
        );
    }
}

syscall_conformance::probe_main!("fs/paths", scenario::run);
