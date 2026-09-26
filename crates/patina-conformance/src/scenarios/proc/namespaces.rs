//! proc/namespaces — leaving and joining namespaces (kernel/fork.c
//! `ksys_unshare`, kernel/nsproxy.c `setns`), for the unprivileged caller
//! the virtual kernel models:
//!
//! * `unshare` of nothing, or of what only the caller holds (its descriptor
//!   table, `CLONE_FILES`; its root, cwd and umask, `CLONE_FS`; its System V
//!   semaphore undo list, `CLONE_SYSVSEM`) needs no privilege and answers 0;
//! * `unshare` refuses a flag it does not take (`EINVAL`) and, while another
//!   thread lives, anything that would split the thread group
//!   (`check_unshare_flags`: `CLONE_THREAD`, `CLONE_SIGHAND`, `CLONE_VM`, and
//!   `CLONE_NEWUSER`, which implies `CLONE_THREAD`: `EINVAL`); every other
//!   new namespace needs `CAP_SYS_ADMIN` (`unshare_nsproxy_namespaces`:
//!   `EPERM`). A new user namespace needs no capability, so it is only ever
//!   asked for while a second thread makes it `EINVAL`: whether a
//!   single-threaded caller gets one is the host's user-namespace policy
//!   (`user.max_user_namespaces`, Ubuntu's AppArmor restriction), and it
//!   would move the probe.
//! * the caller's namespace files (`/proc/self/ns/*`) are links that read
//!   `<type>:[<inode>]` and open the namespace's nsfs inode: a root-owned,
//!   read-only regular file of that inode number, immutable (opening it for
//!   writing or `fchmod` of it is `EPERM`; the open flags are judged in
//!   `do_open`'s order), which an `O_PATH` open names too; an `O_PATH`
//!   descriptor opened nothing, so every operation that takes an opened file
//!   refuses it (`EBADF`); by path, every change to it is `EPERM`, as is
//!   asking for write access, execute access `EACCES`, it has no extended
//!   attributes, and removing it is `EACCES`;
//! * `setns` of a descriptor not open is `EBADF` (an `O_PATH` one too), of
//!   one that is neither a namespace nor a pidfd `EINVAL`; of the caller's
//!   own UTS namespace (`/proc/self/ns/uts`) with another namespace type
//!   `EINVAL`, and otherwise `EPERM` (`CAP_SYS_ADMIN` over the namespace:
//!   `validate_ns`); of its own user namespace `EINVAL` (`userns_install`
//!   refuses the namespace the caller is in, before any capability).
//!
//! The libc vehicle goes through glibc's `unshare` and `setns`, which the
//! shim defines.
//!
//! Were the capability checks to pass, the namespaces asked for would be the
//! probe's own (new UTS, IPC, mount, network, pid, cgroup and time
//! namespaces, or its current UTS namespace joined again): nothing outside
//! the probe changes. The harness runs the scenario only for an unprivileged
//! caller, and the probe stops before any call unless it is one.

use crate::catalog::{DEFAULTS, Need, Scenario};
use crate::probe::{AT_FDCWD, Probe, XattrTarget, neg};
use libc::*;
use patina_dst_syscalls::Syscall;

/// `CSIGNAL`'s low bit: no namespace or sharing flag.
const UNKNOWN_FLAG: i64 = 0x1;

pub fn run(p: &Probe) {
    p.require_unprivileged();
    let unshare = |flags: c_int| p.call_observed(Syscall::N_unshare, [flags as i64, 0, 0, 0, 0, 0]);
    for (flag, label) in [
        (0, "unshare of nothing needs no privilege"),
        (
            CLONE_FILES,
            "unsharing its descriptor table needs no privilege",
        ),
        (
            CLONE_FS,
            "unsharing its root, cwd and umask needs no privilege",
        ),
        (
            CLONE_SYSVSEM,
            "unsharing its semaphore undo list needs no privilege",
        ),
    ] {
        p.check(label, unshare(flag) == 0);
    }
    p.check(
        "unshare of a flag it does not take is EINVAL",
        p.call_observed(Syscall::N_unshare, [UNKNOWN_FLAG, 0, 0, 0, 0, 0]) == neg(EINVAL),
    );
    for (flag, label) in [
        (
            CLONE_NEWUTS,
            "a new UTS namespace is EPERM (no CAP_SYS_ADMIN)",
        ),
        (CLONE_NEWIPC, "a new IPC namespace is EPERM"),
        (CLONE_NEWNS, "a new mount namespace is EPERM"),
        (CLONE_NEWNET, "a new network namespace is EPERM"),
        (CLONE_NEWPID, "a new pid namespace is EPERM"),
        (CLONE_NEWCGROUP, "a new cgroup namespace is EPERM"),
        (CLONE_NEWTIME, "a new time namespace is EPERM"),
    ] {
        p.check(label, unshare(flag) == neg(EPERM));
    }

    let (release, parked) = std::sync::mpsc::channel::<()>();
    let other = std::thread::spawn(move || {
        let _ = parked.recv();
    });
    for (flag, label) in [
        (
            CLONE_NEWUSER,
            "a new user namespace with another thread alive is EINVAL",
        ),
        (
            CLONE_THREAD,
            "unsharing the thread group with another thread alive is EINVAL",
        ),
        (
            CLONE_SIGHAND,
            "unsharing the signal handlers with another thread alive is EINVAL",
        ),
        (
            CLONE_VM,
            "unsharing the address space with another thread alive is EINVAL",
        ),
    ] {
        p.check(label, unshare(flag) == neg(EINVAL));
    }
    release.send(()).unwrap();
    other.join().unwrap();

    let setns = |fd: i32, kind: c_int| {
        p.call_observed(Syscall::N_setns, [fd as i64, kind as i64, 0, 0, 0, 0])
    };
    p.check(
        "setns of a descriptor not open is EBADF",
        setns(-1, 0) == neg(EBADF),
    );
    let dir = p.openat(AT_FDCWD, &p.dir(), O_RDONLY | O_DIRECTORY, 0);
    p.require("open the run directory", dir >= 0);
    p.check(
        "setns of a descriptor that is no namespace is EINVAL",
        setns(dir, 0) == neg(EINVAL),
    );
    p.close(dir);
    let uts = p.openat(AT_FDCWD, "/proc/self/ns/uts", O_RDONLY | O_CLOEXEC, 0);
    p.require("open the caller's UTS namespace", uts >= 0);
    p.check(
        "setns naming another namespace type is EINVAL",
        setns(uts, CLONE_NEWNET) == neg(EINVAL),
    );
    p.check(
        "joining a UTS namespace is EPERM (no CAP_SYS_ADMIN)",
        setns(uts, CLONE_NEWUTS) == neg(EPERM),
    );
    p.check("with any type too", setns(uts, 0) == neg(EPERM));
    let (read, target) = p.readlinkat(AT_FDCWD, "/proc/self/ns/uts", 64);
    let (_, file) = p.fstat(uts);
    p.check(
        "the link reads uts:[inode], the inode the open file has",
        read > 0
            && file
                .as_ref()
                .is_some_and(|file| target == format!("uts:[{}]", file.ino)),
    );
    p.check(
        "a namespace file is a root-owned, read-only regular file",
        file.as_ref()
            .is_some_and(|file| file.kind == "reg" && file.perm == 0o444 && file.uid == 0),
    );
    p.check(
        "its immutable inode refuses fchmod (EPERM)",
        p.fchmod(uts, 0o400) == neg(EPERM),
    );
    p.close(uts);
    // Path operations on the namespace file: its inode is immutable (every
    // change `EPERM`, write access `EPERM` before the mode bits), root's and
    // `0444` (no execute), without extended attributes; its directory is
    // not the caller's to remove from.
    let uts_path = "/proc/self/ns/uts";
    for (label, answer, errno) in [
        (
            "it exists",
            p.faccessat(AT_FDCWD, uts_path, F_OK, 0, false),
            0,
        ),
        (
            "it may be read",
            p.faccessat(AT_FDCWD, uts_path, R_OK, 0, false),
            0,
        ),
        (
            "write access is EPERM",
            p.faccessat(AT_FDCWD, uts_path, W_OK, 0, false),
            EPERM,
        ),
        (
            "execute access is EACCES",
            p.faccessat(AT_FDCWD, uts_path, X_OK, 0, false),
            EACCES,
        ),
        (
            "changing its mode is EPERM",
            p.fchmodat(AT_FDCWD, uts_path, 0o400),
            EPERM,
        ),
        (
            "setting its times is EPERM",
            p.utimensat(AT_FDCWD, Some(uts_path), None, 0),
            EPERM,
        ),
        ("truncating it is EPERM", p.truncate(uts_path, 0), EPERM),
        (
            "an attribute is EOPNOTSUPP",
            p.getxattr(XattrTarget::Path(uts_path), "user.patina", 0).0,
            EOPNOTSUPP,
        ),
        (
            "it lists no attribute",
            p.listxattr(XattrTarget::Path(uts_path), 0).0,
            0,
        ),
        (
            "removing it is EACCES",
            p.unlinkat(AT_FDCWD, uts_path, 0),
            EACCES,
        ),
    ] {
        p.check(label, answer == if errno == 0 { 0 } else { neg(errno) });
    }
    for (flags, answer) in OPENS {
        let fd = p.openat(AT_FDCWD, "/proc/self/ns/uts", flags | O_CLOEXEC, 0o600);
        p.check(
            &format!("an open with flags {flags:#o} answers {answer}"),
            if answer == 0 {
                fd >= 0
            } else {
                fd == neg(answer) as i32
            },
        );
        if fd >= 0 {
            p.close(fd);
        }
    }
    let path_only = p.openat(AT_FDCWD, "/proc/self/ns/uts", O_PATH | O_CLOEXEC, 0);
    p.require("open the caller's UTS namespace O_PATH", path_only >= 0);
    let (_, named) = p.fstat(path_only);
    p.check(
        "an O_PATH descriptor names the same file",
        named
            .zip(file)
            .is_some_and(|(named, file)| named.ino == file.ino),
    );
    p.check(
        "setns of an O_PATH descriptor is EBADF",
        setns(path_only, 0) == neg(EBADF),
    );
    // An `O_PATH` descriptor opened nothing: every operation that takes an
    // opened file (`fdget`) refuses it.
    let epoll = p.epoll_create1(EPOLL_CLOEXEC);
    p.require("epoll_create1", epoll >= 0);
    for (what, answer) in [
        ("fsync", p.fsync(path_only)),
        ("ftruncate", p.ftruncate(path_only, 0)),
        (
            "getdents64",
            p.getdents(Syscall::N_getdents64, path_only, 256).0,
        ),
        ("fchown", p.fchown(path_only, u32::MAX, u32::MAX)),
        ("fchmod", p.fchmod(path_only, 0o400)),
        ("flock", p.flock(path_only, LOCK_SH)),
        (
            "epoll_ctl",
            p.epoll_ctl(epoll, EPOLL_CTL_ADD, path_only, EPOLLIN as u32, 0),
        ),
    ] {
        p.check(
            &format!("{what} of an O_PATH descriptor is EBADF"),
            answer == neg(EBADF),
        );
    }
    p.close(epoll);
    p.close(path_only);
    let user = p.openat(AT_FDCWD, "/proc/self/ns/user", O_RDONLY | O_CLOEXEC, 0);
    p.require("open the caller's user namespace", user >= 0);
    p.check(
        "joining the user namespace the caller is in is EINVAL",
        setns(user, 0) == neg(EINVAL),
    );
    p.close(user);
}

/// Opens of `/proc/self/ns/uts` and their answers (0: a descriptor), in the
/// kernel's order: `O_CREAT|O_EXCL` (`EEXIST`), then `O_DIRECTORY`
/// (`ENOTDIR`, before the link a trailing `O_NOFOLLOW` names is judged),
/// then `O_NOFOLLOW` (`ELOOP`), then write access or `O_TRUNC` on the
/// immutable inode (`EPERM`); `O_PATH` takes only `O_DIRECTORY`.
const OPENS: [(c_int, c_int); 16] = [
    (O_RDONLY, 0),
    (O_WRONLY, EPERM),
    (O_RDWR, EPERM),
    (O_RDONLY | O_TRUNC, EPERM),
    (O_CREAT, 0),
    (O_CREAT | O_WRONLY, EPERM),
    (O_CREAT | O_EXCL, EEXIST),
    (O_CREAT | O_EXCL | O_NOFOLLOW, EEXIST),
    (O_NOFOLLOW, ELOOP),
    (O_WRONLY | O_NOFOLLOW, ELOOP),
    (O_DIRECTORY, ENOTDIR),
    (O_NOFOLLOW | O_DIRECTORY, ENOTDIR),
    (O_WRONLY | O_DIRECTORY, ENOTDIR),
    (O_PATH | O_DIRECTORY, ENOTDIR),
    (O_PATH | O_NOFOLLOW | O_DIRECTORY, ENOTDIR),
    (O_APPEND | O_NONBLOCK, 0),
];

pub const SCENARIO: Scenario = Scenario {
    name: "proc/namespaces",
    run,
    covers: &[
        Syscall::N_unshare,
        Syscall::N_setns,
        Syscall::N_openat,
        Syscall::N_close,
        Syscall::N_readlinkat,
        Syscall::N_fstat,
        Syscall::N_fchmod,
        Syscall::N_fsync,
        Syscall::N_ftruncate,
        Syscall::N_getdents64,
        Syscall::N_fchown,
        Syscall::N_flock,
        Syscall::N_epoll_ctl,
        Syscall::N_faccessat,
        Syscall::N_fchmodat,
        Syscall::N_utimensat,
        Syscall::N_truncate,
        Syscall::N_getxattr,
        Syscall::N_listxattr,
        Syscall::N_unlinkat,
    ],
    symbols: &[
        "unshare",
        "setns",
        "openat",
        "close",
        "readlinkat",
        "fstat",
        "fchmod",
        "fsync",
        "ftruncate",
        "getdents64",
        "fchown",
        "flock",
        "epoll_ctl",
        "faccessat",
        "fchmodat",
        "utimensat",
        "truncate",
        "getxattr",
        "listxattr",
        "unlinkat",
    ],
    needs: &[Need::Unprivileged],
    ..DEFAULTS
};
