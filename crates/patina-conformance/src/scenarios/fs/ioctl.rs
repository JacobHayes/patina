//! fs/ioctl — the generic descriptor ioctls (ioctl(2), ioctl_list; fs/ioctl.c
//! do_vfs_ioctl): FIONREAD on a regular file is the size minus the position
//! as an int (negative past EOF), on a pipe the bytes queued, and ENOTTY on a
//! directory; FIOCLEX/FIONCLEX set and clear the descriptor's FD_CLOEXEC and
//! FIONBIO the description's O_NONBLOCK (read back through fcntl); a NULL
//! argument is EFAULT; a terminal request on a file or a pipe, and an unknown
//! request, are ENOTTY; an O_PATH descriptor is EBADF (fdget), as is a closed
//! number. The rest of do_vfs_ioctl's requests are answered before the
//! file's own ioctl: FIOASYNC off is 0 and on needs the file's fasync
//! (ENOTTY without), FIOQSIZE the bytes a regular file or directory holds,
//! FIGETBSZ the superblock's block size, FIFREEZE/FITHAW EPERM without
//! CAP_SYS_ADMIN, FS_IOC_FIEMAP EOPNOTSUPP on a pseudo-filesystem, FIBMAP
//! EPERM on a regular file without CAP_SYS_RAWIO; what a file does not take
//! goes to its own ioctl (the entropy device's refuses what it does not
//! know, EINVAL). The request is read as an unsigned int.

use crate::catalog::{DEFAULTS, Scenario};

use patina_dst_syscalls::Syscall;

use crate::probe::{AT_FDCWD, IoctlArg, Probe, neg};
use libc::*;

/// A request number no driver answers: `_IOC(_IOC_NONE, 0x7f, 0xee, 0)`,
/// type 0x7f and number 0xee, which Documentation/userspace-api/ioctl/
/// ioctl-number.rst assigns to no one (the generic FIO*/TC* requests are type
/// 'T', 0x54).
const UNKNOWN_REQUEST: u64 = 0x0000_7fee;

pub fn run(p: &Probe) {
    let root = p.dir();
    let file = format!("{root}/f");
    let fd = p.openat(AT_FDCWD, &file, O_RDWR | O_CREAT | O_EXCL, 0o644);
    p.require("create f", fd >= 0);
    p.check("write five bytes", p.write(fd, b"hello") == 5);
    let fionread = |fd| p.ioctl(fd, FIONREAD, "FIONREAD", IoctlArg::Out);

    // ---- FIONREAD ----------------------------------------------------------
    p.lseek(fd, 0, SEEK_SET);
    let (r, n) = fionread(fd);
    p.check(
        "FIONREAD on a file is the size minus the position",
        r == 0 && n == Some(5),
    );
    p.read(fd, 2);
    let (r, n) = fionread(fd);
    p.check("FIONREAD follows the cursor", r == 0 && n == Some(3));
    p.lseek(fd, 0, SEEK_END);
    let (r, n) = fionread(fd);
    p.check("FIONREAD at EOF is 0", r == 0 && n == Some(0));
    p.lseek(fd, 9, SEEK_SET);
    let (r, n) = fionread(fd);
    p.check("FIONREAD past EOF is negative", r == 0 && n == Some(-4));
    p.check(
        "FIONREAD with a NULL argument is EFAULT",
        p.ioctl(fd, FIONREAD, "FIONREAD", IoctlArg::Null).0 == neg(EFAULT),
    );
    let (r, pipe) = p.pipe2(0);
    p.require("pipe2", r == 0);
    let (r, n) = fionread(pipe[0]);
    p.check("FIONREAD on an empty pipe is 0", r == 0 && n == Some(0));
    p.check("fill the pipe", p.write(pipe[1], b"abc") == 3);
    let (r, n) = fionread(pipe[0]);
    p.check(
        "FIONREAD on a pipe is the bytes queued",
        r == 0 && n == Some(3),
    );
    let dirfd = p.openat(AT_FDCWD, &root, O_RDONLY | O_DIRECTORY, 0);
    p.require("open the run directory", dirfd >= 0);
    p.check(
        "FIONREAD on a directory is ENOTTY",
        fionread(dirfd).0 == neg(ENOTTY),
    );

    // ---- FIOCLEX / FIONCLEX / FIONBIO ---------------------------------------
    p.check(
        "FIOCLEX",
        p.ioctl(fd, FIOCLEX, "FIOCLEX", IoctlArg::None).0 == 0,
    );
    p.check(
        "FIOCLEX sets FD_CLOEXEC",
        p.fcntl(fd, F_GETFD, 0) == i64::from(FD_CLOEXEC),
    );
    p.check(
        "FIONCLEX",
        p.ioctl(fd, FIONCLEX, "FIONCLEX", IoctlArg::None).0 == 0,
    );
    p.check("FIONCLEX clears FD_CLOEXEC", p.fcntl(fd, F_GETFD, 0) == 0);
    p.check(
        "FIONBIO on",
        p.ioctl(pipe[0], FIONBIO, "FIONBIO", IoctlArg::In(1)).0 == 0,
    );
    p.check(
        "FIONBIO sets O_NONBLOCK",
        p.fcntl(pipe[0], F_GETFL, 0) & i64::from(O_NONBLOCK) != 0,
    );
    p.check(
        "FIONBIO off",
        p.ioctl(pipe[0], FIONBIO, "FIONBIO", IoctlArg::In(0)).0 == 0,
    );
    p.check(
        "FIONBIO clears O_NONBLOCK",
        p.fcntl(pipe[0], F_GETFL, 0) & i64::from(O_NONBLOCK) == 0,
    );
    p.check(
        "FIONBIO with a NULL argument is EFAULT",
        p.ioctl(fd, FIONBIO, "FIONBIO", IoctlArg::Null).0 == neg(EFAULT),
    );

    // ---- refusals ----------------------------------------------------------
    p.check(
        "TCGETS on a regular file is ENOTTY",
        p.ioctl(fd, TCGETS, "TCGETS", IoctlArg::Out).0 == neg(ENOTTY),
    );
    p.check(
        "TCGETS on a pipe is ENOTTY",
        p.ioctl(pipe[0], TCGETS, "TCGETS", IoctlArg::Out).0 == neg(ENOTTY),
    );
    p.check(
        "an unknown request on a file is ENOTTY",
        p.ioctl(fd, UNKNOWN_REQUEST, "unknown", IoctlArg::Out).0 == neg(ENOTTY),
    );
    let location = p.openat(AT_FDCWD, &file, O_PATH, 0);
    p.require("open f O_PATH", location >= 0);
    p.check(
        "FIOCLEX on an O_PATH descriptor is EBADF",
        p.ioctl(location, FIOCLEX, "FIOCLEX", IoctlArg::None).0 == neg(EBADF),
    );
    p.check(
        "FIONREAD on an O_PATH descriptor is EBADF",
        fionread(location).0 == neg(EBADF),
    );
    p.check(
        "ioctl on a closed descriptor is EBADF",
        fionread(4000).0 == neg(EBADF),
    );

    // ---- do_vfs_ioctl's requests, answered before the file's own ----------
    let event = p.eventfd2(0, EFD_CLOEXEC);
    p.require("eventfd2", event >= 0);
    let ns = p.openat(AT_FDCWD, "/proc/self/ns/uts", O_RDONLY | O_CLOEXEC, 0);
    p.require("open the caller's UTS namespace file", ns >= 0);
    let urandom = p.openat(AT_FDCWD, "/dev/urandom", O_RDONLY | O_CLOEXEC, 0);
    p.require("open the entropy device", urandom >= 0);
    use IoctlArg::{In, Out};
    #[rustfmt::skip]
    let generic = [
        // Turning async notification off is no change: 0 whatever the file.
        ("a file", fd, "FIOASYNC", FIOASYNC, In(0), 0, None),
        ("a pipe", pipe[0], "FIOASYNC", FIOASYNC, In(0), 0, None),
        // Turning it on needs the file's `fasync`, which few have.
        ("a file", fd, "FIOASYNC", FIOASYNC, In(1), ENOTTY, None),
        ("an eventfd", event, "FIOASYNC", FIOASYNC, In(1), ENOTTY, None),
        ("a namespace file", ns, "FIOASYNC", FIOASYNC, In(1), ENOTTY, None),
        // The bytes a regular file or directory holds; nothing else has any.
        ("a namespace file", ns, "FIOQSIZE", FIOQSIZE, Out, 0, Some(0)),
        ("a pipe", pipe[0], "FIOQSIZE", FIOQSIZE, Out, ENOTTY, None),
        ("an eventfd", event, "FIOQSIZE", FIOQSIZE, Out, ENOTTY, None),
        // The superblock's block size: a page on the pseudo-filesystems.
        ("a pipe", pipe[0], "FIGETBSZ", FIGETBSZ, Out, 0, Some(4096)),
        ("an eventfd", event, "FIGETBSZ", FIGETBSZ, Out, 0, Some(4096)),
        ("a namespace file", ns, "FIGETBSZ", FIGETBSZ, Out, 0, Some(4096)),
        // Freezing needs CAP_SYS_ADMIN, checked first.
        ("a file", fd, "FIFREEZE", FIFREEZE, Out, EPERM, None),
        ("a pipe", pipe[0], "FITHAW", FITHAW, Out, EPERM, None),
        ("a namespace file", ns, "FIFREEZE", FIFREEZE, Out, EPERM, None),
        // No pseudo-filesystem maps extents.
        ("a pipe", pipe[0], "FS_IOC_FIEMAP", FS_IOC_FIEMAP, Out, EOPNOTSUPP, None),
        ("an eventfd", event, "FS_IOC_FIEMAP", FS_IOC_FIEMAP, Out, EOPNOTSUPP, None),
        // FIBMAP is a regular file's (CAP_SYS_RAWIO first); anything else
        // hands it, like the file-attribute requests of a file without
        // attributes, to the file's own ioctl.
        ("a file", fd, "FIBMAP", FIBMAP, Out, EPERM, None),
        ("a namespace file", ns, "FIBMAP", FIBMAP, Out, EPERM, None),
        ("a pipe", pipe[0], "FIBMAP", FIBMAP, Out, ENOTTY, None),
        ("a namespace file", ns, "FS_IOC_GETFLAGS", FS_IOC_GETFLAGS, Out, ENOTTY, None),
        ("a pipe", pipe[0], "FS_IOC_GETFLAGS", FS_IOC_GETFLAGS, Out, ENOTTY, None),
        // The entropy device's own ioctl refuses what it does not know.
        ("the entropy device", urandom, "FS_IOC_GETFLAGS", FS_IOC_GETFLAGS, Out, EINVAL, None),
        ("the entropy device", urandom, "unknown", UNKNOWN_REQUEST, Out, EINVAL, None),
    ];
    for (what, f, name, request, arg, errno, value) in generic {
        let (r, got) = p.ioctl(f, request, name, arg);
        p.check(
            &format!("{name} on {what}"),
            if errno == 0 {
                r == 0 && got == value
            } else {
                r == neg(errno)
            },
        );
    }
    // The request is an `unsigned int`: the upper half of the word is not read.
    p.check(
        "FIOCLEX with the upper half of the word set",
        p.ioctl(
            fd,
            FIOCLEX | 0xffff_ffff_0000_0000,
            "FIOCLEX",
            IoctlArg::None,
        )
        .0 == 0
            && p.fcntl(fd, F_GETFD, 0) == i64::from(FD_CLOEXEC),
    );

    for f in [fd, pipe[0], pipe[1], dirfd, location, event, ns, urandom] {
        p.close(f);
    }
}

/// The generic requests past the four above (`fs.h`, `ioctls.h`).
const FIOASYNC: u64 = 0x5452;
const FIOQSIZE: u64 = 0x5460;
const FIBMAP: u64 = 0x1;
const FIGETBSZ: u64 = 0x2;
const FIFREEZE: u64 = 0xc004_5877;
const FITHAW: u64 = 0xc004_5878;
const FS_IOC_FIEMAP: u64 = 0xc020_660b;
const FS_IOC_GETFLAGS: u64 = 0x8008_6601;

pub const SCENARIO: Scenario = Scenario {
    name: "fs/ioctl",
    run,
    covers: &[
        Syscall::N_ioctl,
        Syscall::N_fcntl,
        Syscall::N_openat,
        Syscall::N_read,
        Syscall::N_write,
        Syscall::N_lseek,
        Syscall::N_pipe2,
        Syscall::N_close,
        Syscall::N_eventfd2,
    ],
    symbols: &[
        "ioctl", "fcntl", "openat", "read", "write", "lseek", "pipe2", "close", "eventfd",
    ],
    ..DEFAULTS
};
