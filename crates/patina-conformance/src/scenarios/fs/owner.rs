//! fs/owner — ownership under the one identity, and the permission probe:
//! st_uid/st_gid are the caller's; the chown family accepts the caller's own
//! ids and -1 (killing the setuid bit, and the setgid bit of a group-executable
//! file, on a non-directory; moving ctime) and answers EPERM for any other id;
//! lchown names a link itself; fchownat's flag vocabulary; fchown on O_PATH is
//! EBADF; access/faccessat/faccessat2 answer from the mode bits, X_OK included.

use crate::catalog::{DEFAULTS, Need, Scenario};

use patina_dst_syscalls::Syscall;

use crate::probe::{AT_FDCWD, Probe, StatView, neg};
use libc::*;

const UNCHANGED: u32 = u32::MAX;

fn pause(p: &Probe) {
    p.nanosleep(0, 20_000_000);
}

fn stat(p: &Probe, path: &str, flags: i32) -> StatView {
    let (r, st) = p.newfstatat(AT_FDCWD, path, flags);
    p.require("newfstatat", r == 0 && st.is_some());
    st.unwrap()
}

pub fn run(p: &Probe) {
    let root = p.dir();
    let uid = p.getuid() as u32;
    let gid = p.getgid() as u32;
    // Ids nobody on the host has: an id past every real account, so the
    // oracle's EPERM is the unprivileged one and not a group membership.
    let other_uid = uid + 100_000;
    let other_gid = gid + 100_000;

    // ---- ownership is the identity ---------------------------------------
    let setuid = format!("{root}/setuid");
    let fd = p.openat(AT_FDCWD, &setuid, O_RDWR | O_CREAT | O_EXCL, 0o4755);
    p.require("create setuid", fd >= 0);
    let created = stat(p, &setuid, 0);
    p.check(
        "the creation mode kept the setuid bit",
        created.perm == 0o4755,
    );
    p.check(
        "a new file is owned by the caller",
        created.uid == uid && created.gid == gid,
    );

    pause(p);
    p.check(
        "chown(-1, -1) succeeds",
        p.chown(&setuid, UNCHANGED, UNCHANGED, true) == 0,
    );
    let killed = stat(p, &setuid, 0);
    p.check(
        "chown kills the setuid bit even when nothing changes",
        killed.perm == 0o755,
    );
    p.check(
        "chown moves ctime forward",
        killed.ctime_ns > created.ctime_ns,
    );
    p.check(
        "chown leaves mtime alone",
        killed.mtime_ns == created.mtime_ns,
    );
    p.check(
        "chown(own, own) succeeds",
        p.chown(&setuid, uid, gid, true) == 0,
    );
    p.check(
        "chown to another user is EPERM",
        p.chown(&setuid, other_uid, UNCHANGED, true) == neg(EPERM),
    );
    p.check(
        "chown to another group is EPERM",
        p.chown(&setuid, UNCHANGED, other_gid, true) == neg(EPERM),
    );
    p.check(
        "chown of a missing path is ENOENT",
        p.chown(&format!("{root}/missing"), uid, gid, true) == neg(ENOENT),
    );
    p.close(fd);

    // setgid: killed only when the group may execute.
    let setgid_exec = format!("{root}/setgid-exec");
    let fd = p.openat(AT_FDCWD, &setgid_exec, O_RDWR | O_CREAT | O_EXCL, 0o2775);
    p.require("create setgid-exec", fd >= 0);
    p.check(
        "the creation mode kept setgid with group exec",
        stat(p, &setgid_exec, 0).perm == 0o2755,
    );
    p.check("fchown(own, own)", p.fchown(fd, uid, gid) == 0);
    p.check(
        "fchown kills the setgid bit of a group-executable file",
        stat(p, &setgid_exec, 0).perm == 0o755,
    );
    p.check(
        "fchown to another user is EPERM",
        p.fchown(fd, other_uid, gid) == neg(EPERM),
    );
    p.close(fd);
    let setgid_noexec = format!("{root}/setgid-noexec");
    let fd = p.openat(AT_FDCWD, &setgid_noexec, O_RDWR | O_CREAT | O_EXCL, 0o2745);
    p.require("create setgid-noexec", fd >= 0);
    p.check("fchown(-1, -1)", p.fchown(fd, UNCHANGED, UNCHANGED) == 0);
    p.check(
        "fchown keeps the setgid bit of a file its group cannot execute",
        stat(p, &setgid_noexec, 0).perm == 0o2745,
    );
    p.close(fd);

    // A directory: mkdir itself drops setuid/setgid from the request
    // (vfs_mkdir keeps the triads and the sticky bit), and chown moves
    // ctime without touching the bits.
    let dir = format!("{root}/d");
    p.check("mkdirat d 3755", p.mkdirat(AT_FDCWD, &dir, 0o3755) == 0);
    let before = stat(p, &dir, 0);
    p.check(
        "mkdir keeps the sticky bit and drops setgid",
        before.perm == 0o1755,
    );
    p.check(
        "a new directory is owned by the caller",
        before.uid == uid && before.gid == gid,
    );
    pause(p);
    p.check("chown on a directory", p.chown(&dir, uid, gid, true) == 0);
    let after = stat(p, &dir, 0);
    p.check(
        "chown leaves a directory's bits alone",
        after.perm == 0o1755,
    );
    p.check(
        "chown on a directory moves ctime forward",
        after.ctime_ns > before.ctime_ns,
    );

    // fchownat and its flags; fchown on O_PATH.
    let dirfd = p.openat(AT_FDCWD, &dir, O_RDONLY | O_DIRECTORY, 0);
    p.require("open d", dirfd >= 0);
    let inner = p.openat(dirfd, "inner", O_WRONLY | O_CREAT | O_EXCL, 0o644);
    p.require("create d/inner", inner >= 0);
    p.close(inner);
    p.check(
        "fchownat relative to a dirfd",
        p.fchownat(dirfd, "inner", uid, gid, 0) == 0,
    );
    p.check(
        "fchownat AT_EMPTY_PATH names the descriptor",
        p.fchownat(dirfd, "", uid, gid, AT_EMPTY_PATH) == 0,
    );
    p.check(
        "fchownat with an unknown flag is EINVAL",
        p.fchownat(dirfd, "inner", uid, gid, 0x1) == neg(EINVAL),
    );
    p.check(
        "fchownat to another user is EPERM",
        p.fchownat(dirfd, "inner", other_uid, gid, 0) == neg(EPERM),
    );
    let location = p.openat(dirfd, "inner", O_PATH, 0);
    p.require("open d/inner O_PATH", location >= 0);
    p.check(
        "fchown on an O_PATH descriptor is EBADF",
        p.fchown(location, uid, gid) == neg(EBADF),
    );
    p.check(
        "fchownat AT_EMPTY_PATH on an O_PATH descriptor works",
        p.fchownat(location, "", uid, gid, AT_EMPTY_PATH) == 0,
    );
    p.close(location);
    p.check(
        "fchown on a closed descriptor is EBADF",
        p.fchown(4000, uid, gid) == neg(EBADF),
    );

    // lchown names the link itself; chown follows it.
    let link = format!("{root}/l");
    p.check(
        "symlinkat l -> setuid",
        p.symlinkat("setuid", AT_FDCWD, &link) == 0,
    );
    let link_stat = stat(p, &link, AT_SYMLINK_NOFOLLOW);
    p.check(
        "a symlink is owned by the caller",
        link_stat.uid == uid && link_stat.gid == gid,
    );
    pause(p);
    p.check(
        "lchown(own, own) on a symlink",
        p.chown(&link, uid, gid, false) == 0,
    );
    let changed_link = stat(p, &link, AT_SYMLINK_NOFOLLOW);
    p.check(
        "lchown moves the symlink ctime only",
        changed_link.ctime_ns > link_stat.ctime_ns
            && changed_link.atime_ns == link_stat.atime_ns
            && changed_link.mtime_ns == link_stat.mtime_ns,
    );
    let fifo = format!("{root}/owner-fifo");
    p.require(
        "create owner FIFO",
        p.mknodat(AT_FDCWD, &fifo, S_IFIFO | 0o600, 0) == 0,
    );
    let fifo_fd = p.openat(AT_FDCWD, &fifo, O_RDWR, 0);
    p.require("open owner FIFO", fifo_fd >= 0);
    for unlinked in [false, true] {
        if unlinked {
            p.unlinkat(AT_FDCWD, &fifo, 0);
        }
        let before = p.fstat(fifo_fd).1.unwrap();
        pause(p);
        p.check(
            "fchown reaches retained FIFO",
            p.fchown(fifo_fd, uid, gid) == 0,
        );
        let after = p.fstat(fifo_fd).1.unwrap();
        p.check(
            "FIFO ownership moves ctime only",
            after.ctime_ns > before.ctime_ns
                && after.mtime_ns == before.mtime_ns
                && after.atime_ns == before.atime_ns,
        );
    }
    p.close(fifo_fd);
    p.check(
        "lchown to another user is EPERM",
        p.chown(&link, other_uid, gid, false) == neg(EPERM),
    );
    p.check(
        "the link's mode is untouched",
        stat(p, &link, AT_SYMLINK_NOFOLLOW).perm == 0o777,
    );
    p.check(
        "chown through the link reaches the target",
        p.chown(&link, uid, gid, true) == 0,
    );
    p.check(
        "fchownat AT_SYMLINK_NOFOLLOW names the link",
        p.fchownat(AT_FDCWD, &link, uid, gid, AT_SYMLINK_NOFOLLOW) == 0,
    );

    // ---- the permission probe --------------------------------------------
    let plain = format!("{root}/plain");
    let fd = p.openat(AT_FDCWD, &plain, O_RDWR | O_CREAT | O_EXCL, 0o644);
    p.require("create plain", fd >= 0);
    p.close(fd);
    p.check("F_OK on a file", p.access(&plain, F_OK) == 0);
    p.check("R_OK|W_OK on 0644", p.access(&plain, R_OK | W_OK) == 0);
    p.check(
        "X_OK on 0644 is EACCES",
        p.access(&plain, X_OK) == neg(EACCES),
    );
    p.check("X_OK on 0755", p.access(&setuid, X_OK) == 0);
    p.check("X_OK on a directory", p.access(&dir, X_OK) == 0);
    p.check(
        "F_OK on a missing path is ENOENT",
        p.access(&format!("{root}/missing"), F_OK) == neg(ENOENT),
    );
    let unreadable = format!("{root}/unreadable");
    let fd = p.openat(AT_FDCWD, &unreadable, O_WRONLY | O_CREAT | O_EXCL, 0o200);
    p.require("create unreadable", fd >= 0);
    p.close(fd);
    p.check(
        "R_OK on 0200 is EACCES",
        p.access(&unreadable, R_OK) == neg(EACCES),
    );
    p.check("W_OK on 0200", p.access(&unreadable, W_OK) == 0);
    p.check(
        "faccessat X_OK relative to a dirfd is EACCES on 0644",
        p.faccessat(dirfd, "inner", X_OK, 0, false) == neg(EACCES),
    );
    p.check(
        "faccessat R_OK relative to a dirfd",
        p.faccessat(dirfd, "inner", R_OK, 0, false) == 0,
    );
    p.check(
        "faccessat2 X_OK on 0755",
        p.faccessat(AT_FDCWD, &setuid, X_OK, 0, true) == 0,
    );
    p.check(
        "faccessat2 X_OK on 0644 is EACCES",
        p.faccessat(AT_FDCWD, &plain, X_OK, 0, true) == neg(EACCES),
    );
    p.check(
        "faccessat2 AT_EACCESS reads the same identity",
        p.faccessat(AT_FDCWD, &plain, R_OK, AT_EACCESS, true) == 0,
    );
    p.check(
        "faccessat2 with an unknown flag is EINVAL",
        p.faccessat(AT_FDCWD, &plain, R_OK, 0x1, true) == neg(EINVAL),
    );
    p.close(dirfd);
}

pub const SCENARIO: Scenario = Scenario {
    name: "fs/owner",
    run,
    covers: &[
        #[cfg(target_arch = "x86_64")]
        Syscall::N_chown,
        Syscall::N_fchown,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_lchown,
        Syscall::N_fchownat,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_access,
        Syscall::N_faccessat,
        Syscall::N_faccessat2,
        Syscall::N_fstat,
        Syscall::N_newfstatat,
        Syscall::N_openat,
        Syscall::N_close,
        Syscall::N_mkdirat,
        Syscall::N_symlinkat,
        Syscall::N_nanosleep,
        Syscall::N_getuid,
        Syscall::N_getgid,
    ],
    symbols: &[
        "chown",
        "fchown",
        "lchown",
        "fchownat",
        "access",
        "faccessat",
        "syscall",
        "fstat",
        "fstatat",
        "openat",
        "close",
        "mkdirat",
        "symlinkat",
        "nanosleep",
        "getuid",
        "getgid",
    ],
    needs: &[Need::Unprivileged],
    ..DEFAULTS
};
