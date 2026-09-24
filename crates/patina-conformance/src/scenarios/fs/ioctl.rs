//! fs/ioctl — the generic descriptor ioctls (ioctl(2), ioctl_list; fs/ioctl.c
//! do_vfs_ioctl): FIONREAD on a regular file is the size minus the position
//! as an int (negative past EOF), on a pipe the bytes queued, and ENOTTY on a
//! directory; FIOCLEX/FIONCLEX set and clear the descriptor's FD_CLOEXEC and
//! FIONBIO the description's O_NONBLOCK (read back through fcntl); a NULL
//! argument is EFAULT; a terminal request on a file or a pipe, and an unknown
//! request, are ENOTTY; an O_PATH descriptor is EBADF (fdget), as is a closed
//! number.

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

    for f in [fd, pipe[0], pipe[1], dirfd, location] {
        p.close(f);
    }
}

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
    ],
    symbols: &[
        "ioctl", "fcntl", "openat", "read", "write", "lseek", "pipe2", "close",
    ],
    ..DEFAULTS
};
