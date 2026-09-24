//! fs/positional_io — pread64 / pwrite64 (pread(2)): I/O at an explicit
//! position that never moves the descriptor's cursor; a short read at EOF and
//! 0 past it; a write past EOF leaves a zero-filled hole; on an O_APPEND
//! descriptor Linux appends whatever the position (pwrite(2) BUGS); a
//! negative position is EINVAL even for a zero length (fs/read_write.c
//! ksys_pread64 judges it first); ESPIPE on a pipe, EISDIR on a directory,
//! EBADF for the wrong access mode or a closed descriptor.

use crate::catalog::{Arc, DEFAULTS, Gap, Scenario, Status};
use crate::compare::{Difference, Failure, Observed};
use crate::vehicle::Vehicle;

use patina_dst_syscalls::Syscall;

use crate::probe::{AT_FDCWD, Probe, neg};
use libc::*;

pub fn run(p: &Probe) {
    let root = p.dir();
    let file = format!("{root}/f");
    let fd = p.openat(AT_FDCWD, &file, O_RDWR | O_CREAT | O_EXCL, 0o644);
    p.require("create f", fd >= 0);
    p.check("write the contents", p.write(fd, b"hello world") == 11);

    // ---- pread64 -------------------------------------------------------------
    let (r, data) = p.pread64(fd, 5, 0);
    p.check("pread64 at 0", r == 5 && data == b"hello");
    let (r, data) = p.pread64(fd, 5, 6);
    p.check("pread64 at 6", r == 5 && data == b"world");
    p.check(
        "pread64 leaves the cursor where write put it",
        p.lseek(fd, 0, SEEK_CUR) == 11,
    );
    let (r, data) = p.pread64(fd, 10, 8);
    p.check("pread64 across EOF is short", r == 3 && data == b"rld");
    p.check("pread64 at EOF is 0", p.pread64(fd, 4, 11).0 == 0);
    p.check("pread64 past EOF is 0", p.pread64(fd, 4, 100).0 == 0);
    p.check("a zero-length pread64 is 0", p.pread64(fd, 0, 0).0 == 0);
    p.check(
        "pread64 at a negative position is EINVAL",
        p.pread64(fd, 4, -1).0 == neg(EINVAL),
    );
    p.check(
        "the position is judged before the length",
        p.pread64(fd, 0, -1).0 == neg(EINVAL),
    );

    // ---- pwrite64 ------------------------------------------------------------
    p.check("pwrite64 at 0", p.pwrite64(fd, b"HELLO", 0) == 5);
    p.check(
        "pwrite64 leaves the cursor alone",
        p.lseek(fd, 0, SEEK_CUR) == 11,
    );
    let (r, data) = p.pread64(fd, 11, 0);
    p.check(
        "the positional write landed",
        r == 11 && data == b"HELLO world",
    );
    p.check("pwrite64 past EOF", p.pwrite64(fd, b"!", 20) == 1);
    p.check(
        "the file grew to the write's end",
        p.lseek(fd, 0, SEEK_END) == 21,
    );
    let (r, data) = p.pread64(fd, 16, 8);
    p.check(
        "the gap reads as zeros",
        r == 13 && data == b"rld\0\0\0\0\0\0\0\0\0!",
    );
    p.check("a zero-length pwrite64 is 0", p.pwrite64(fd, b"", 0) == 0);
    p.check(
        "pwrite64 at a negative position is EINVAL",
        p.pwrite64(fd, b"x", -1) == neg(EINVAL),
    );
    p.check(
        "the position is judged before the length",
        p.pwrite64(fd, b"", -1) == neg(EINVAL),
    );

    let append = p.openat(AT_FDCWD, &file, O_WRONLY | O_APPEND, 0);
    p.require("open f O_APPEND", append >= 0);
    p.check(
        "pwrite64 on an O_APPEND descriptor",
        p.pwrite64(append, b"++", 0) == 2,
    );
    p.check(
        "Linux appends whatever the position",
        p.pread64(fd, 64, 0).1 == b"HELLO world\0\0\0\0\0\0\0\0\0!++",
    );

    // ---- refusals ------------------------------------------------------------
    let reader = p.openat(AT_FDCWD, &file, O_RDONLY, 0);
    p.require("open f read-only", reader >= 0);
    p.check(
        "pwrite64 on a read-only descriptor is EBADF",
        p.pwrite64(reader, b"x", 0) == neg(EBADF),
    );
    p.check(
        "pread64 on a write-only descriptor is EBADF",
        p.pread64(append, 1, 0).0 == neg(EBADF),
    );
    let (r, pipe) = p.pipe2(0);
    p.require("pipe2", r == 0);
    p.check("fill the pipe", p.write(pipe[1], b"pipe") == 4);
    p.check(
        "pread64 on a pipe is ESPIPE",
        p.pread64(pipe[0], 4, 0).0 == neg(ESPIPE),
    );
    p.check(
        "pwrite64 on a pipe is ESPIPE",
        p.pwrite64(pipe[1], b"x", 0) == neg(ESPIPE),
    );
    let dirfd = p.openat(AT_FDCWD, &root, O_RDONLY | O_DIRECTORY, 0);
    p.require("open the run directory", dirfd >= 0);
    p.check(
        "pread64 on a directory is EISDIR",
        p.pread64(dirfd, 4, 0).0 == neg(EISDIR),
    );
    let location = p.openat(AT_FDCWD, &file, O_PATH, 0);
    p.require("open f O_PATH", location >= 0);
    p.check(
        "pread64 on an O_PATH descriptor is EBADF",
        p.pread64(location, 4, 0).0 == neg(EBADF),
    );
    p.check(
        "pread64 on a closed descriptor is EBADF",
        p.pread64(4000, 4, 0).0 == neg(EBADF),
    );
    p.check(
        "pwrite64 on a closed descriptor is EBADF",
        p.pwrite64(4000, b"x", 0) == neg(EBADF),
    );
    p.check(
        "the position is judged before the descriptor",
        p.pread64(4000, 4, -1).0 == neg(EINVAL),
    );

    for f in [fd, append, reader, pipe[0], pipe[1], dirfd, location] {
        p.close(f);
    }
}

pub const SCENARIO: Scenario = Scenario {
    name: "fs/positional_io",
    run,
    covers: &[
        Syscall::N_pread64,
        Syscall::N_pwrite64,
        Syscall::N_openat,
        Syscall::N_write,
        Syscall::N_lseek,
        Syscall::N_pipe2,
        Syscall::N_close,
    ],
    symbols: &[
        "pread64", "pwrite64", "openat", "write", "lseek", "pipe2", "close",
    ],
    gaps: &[
        Gap {
            status: Status::Pending(Arc::Fs),
            vehicles: Vehicle::ALL,
            what: "pwrite64 on an O_APPEND descriptor writes at the given position, where Linux appends whatever the position (pwrite(2) BUGS; generic_write_checks sets the position to i_size under IOCB_APPEND); patina_pwrite",
            failure: Failure::Differs(&[
                Difference::field(
                    42,
                    "pread64",
                    "fields.data",
                    Observed::Str("++LLO world\0\0\0\0\0\0\0\0\0!"),
                ),
                Difference::field(42, "pread64", "ret", Observed::Int(21)),
                Difference::check(43, "Linux appends whatever the position"),
            ]),
        },
        Gap {
            status: Status::Pending(Arc::Fs),
            vehicles: Vehicle::ALL,
            what: "pread64 refuses a directory and an O_PATH descriptor with EINVAL, where the kernel answers EISDIR (vfs_read on a directory) and EBADF (fdget refuses O_PATH); patina_pread's descriptor-kind dispatch",
            failure: Failure::Differs(&[
                Difference::field(57, "pread64", "errno", Observed::Str("EINVAL")),
                Difference::check(58, "pread64 on a directory is EISDIR"),
                Difference::field(60, "pread64", "errno", Observed::Str("EINVAL")),
                Difference::check(61, "pread64 on an O_PATH descriptor is EBADF"),
            ]),
        },
        Gap {
            status: Status::Pending(Arc::Fs),
            vehicles: Vehicle::ALL,
            what: "pread64 judges the descriptor before the position: a closed descriptor with position -1 is EBADF, where ksys_pread64 refuses the negative position first (EINVAL); patina_pread",
            failure: Failure::Differs(&[
                Difference::field(66, "pread64", "errno", Observed::Str("EBADF")),
                Difference::check(67, "the position is judged before the descriptor"),
            ]),
        },
    ],
    ..DEFAULTS
};
