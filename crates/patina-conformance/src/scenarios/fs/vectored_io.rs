//! fs/vectored_io — readv / writev / preadv / pwritev / preadv2 / pwritev2
//! (readv(2)): segments filled and drained in order, zero-length segments
//! skipped, a short read spread over the segments; the vector itself judged
//! by lib/iov_iter.c (a count of 0 is 0 without touching the pointer, past
//! UIO_MAXIOV or negative is EINVAL, a segment length negative as ssize_t is
//! EINVAL, a NULL vector is EFAULT); the positional rows never move the
//! cursor, refuse a negative position with EINVAL and a pipe with ESPIPE, and
//! append on an O_APPEND descriptor whatever the position; the `*v2` rows take
//! position -1 as "the cursor, advanced" (so a pipe works), RWF_APPEND per
//! call, RWF_NOWAIT (EAGAIN on an empty pipe), and refuse an unknown RWF_*
//! bit with EOPNOTSUPP (fs/read_write.c, kiocb_set_rw_flags).

use crate::catalog::{DEFAULTS, KernelFloor, Scenario};

use patina_dst_syscalls::Syscall;

use crate::probe::{AT_FDCWD, IovShape, Probe, neg};
use libc::*;

/// An RWF_* bit the kernel does not define.
const UNKNOWN_RWF: i32 = 1 << 30;

/// The `*v2` rows' "use and advance the file position" offset.
const CURSOR: i64 = -1;

pub fn run(p: &Probe) {
    let root = p.dir();
    let file = format!("{root}/f");
    let fd = p.openat(AT_FDCWD, &file, O_RDWR | O_CREAT | O_EXCL, 0o644);
    p.require("create f", fd >= 0);

    // ---- readv / writev ------------------------------------------------------
    p.check(
        "writev gathers the segments in order, skipping an empty one",
        p.writev_row(Syscall::N_writev, fd, &[b"ab", b"", b"cde"], None, None) == 5,
    );
    p.check("writev advanced the cursor", p.lseek(fd, 0, SEEK_CUR) == 5);
    p.lseek(fd, 0, SEEK_SET);
    let (r, segments) = p.readv_row(Syscall::N_readv, fd, &[2, 0, 10], None, None);
    p.check(
        "readv scatters in order; a short read leaves the tail unfilled",
        r == 5 && segments == [b"ab".to_vec(), vec![], b"cde".to_vec()],
    );
    p.check("readv advanced the cursor", p.lseek(fd, 0, SEEK_CUR) == 5);
    let (r, segments) = p.readv_row(Syscall::N_readv, fd, &[4, 4], None, None);
    p.check(
        "readv at EOF is 0",
        r == 0 && segments.iter().all(Vec::is_empty),
    );
    p.check(
        "a zero count is 0 even with a NULL vector",
        (
            p.iov_shape(Syscall::N_readv, fd, IovShape::Null(0), None, None),
            p.iov_shape(Syscall::N_writev, fd, IovShape::Null(0), None, None),
        ) == (0, 0),
    );
    p.check(
        "UIO_MAXIOV empty segments are accepted",
        p.iov_shape(
            Syscall::N_writev,
            fd,
            IovShape::Empty(UIO_MAXIOV as i64),
            None,
            None,
        ) == 0,
    );
    p.check(
        "one segment past UIO_MAXIOV is EINVAL",
        p.iov_shape(
            Syscall::N_writev,
            fd,
            IovShape::Empty(UIO_MAXIOV as i64 + 1),
            None,
            None,
        ) == neg(EINVAL),
    );
    p.check(
        "a negative count is EINVAL",
        p.iov_shape(Syscall::N_readv, fd, IovShape::Empty(-1), None, None) == neg(EINVAL),
    );
    p.check(
        "a segment length negative as ssize_t is EINVAL",
        p.iov_shape(Syscall::N_readv, fd, IovShape::NegativeLength, None, None) == neg(EINVAL),
    );
    p.check(
        "a NULL vector with a count is EFAULT",
        p.iov_shape(Syscall::N_writev, fd, IovShape::Null(1), None, None) == neg(EFAULT),
    );

    let (r, pipe) = p.pipe2(0);
    p.require("pipe2", r == 0);
    p.check(
        "writev into a pipe",
        p.writev_row(Syscall::N_writev, pipe[1], &[b"xy", b"z"], None, None) == 3,
    );
    let (r, segments) = p.readv_row(Syscall::N_readv, pipe[0], &[2, 5], None, None);
    p.check(
        "readv from a pipe spreads what is there",
        r == 3 && segments == [b"xy".to_vec(), b"z".to_vec()],
    );
    let reader = p.openat(AT_FDCWD, &file, O_RDONLY, 0);
    let writer = p.openat(AT_FDCWD, &file, O_WRONLY | O_APPEND, 0);
    p.require(
        "open f read-only and append-only",
        reader >= 0 && writer >= 0,
    );
    p.check(
        "writev on a read-only descriptor is EBADF",
        p.writev_row(Syscall::N_writev, reader, &[b"x"], None, None) == neg(EBADF),
    );
    p.check(
        "readv on a write-only descriptor is EBADF",
        p.readv_row(Syscall::N_readv, writer, &[1], None, None).0 == neg(EBADF),
    );
    let dirfd = p.openat(AT_FDCWD, &root, O_RDONLY | O_DIRECTORY, 0);
    p.require("open the run directory", dirfd >= 0);
    p.check(
        "readv on a directory is EISDIR",
        p.readv_row(Syscall::N_readv, dirfd, &[4], None, None).0 == neg(EISDIR),
    );
    p.check(
        "writev on a closed descriptor is EBADF",
        p.writev_row(Syscall::N_writev, 4000, &[b"x"], None, None) == neg(EBADF),
    );
    p.check(
        "writev on an O_APPEND descriptor lands at the end",
        (
            p.writev_row(Syscall::N_writev, writer, &[b"f", b"g"], None, None),
            p.lseek(fd, 0, SEEK_END),
        ) == (2, 7),
    );

    // ---- preadv / pwritev ----------------------------------------------------
    p.lseek(fd, 1, SEEK_SET);
    let (r, segments) = p.readv_row(Syscall::N_preadv, fd, &[3, 3], Some(2), None);
    p.check(
        "preadv reads at the position",
        r == 5 && segments == [b"cde".to_vec(), b"fg".to_vec()],
    );
    p.check(
        "preadv leaves the cursor alone",
        p.lseek(fd, 0, SEEK_CUR) == 1,
    );
    p.check(
        "pwritev writes at the position",
        p.writev_row(Syscall::N_pwritev, fd, &[b"A", b"B"], Some(0), None) == 2,
    );
    p.check(
        "pwritev leaves the cursor alone",
        p.lseek(fd, 0, SEEK_CUR) == 1,
    );
    let (_, segments) = p.readv_row(Syscall::N_preadv, fd, &[16], Some(0), None);
    p.check(
        "the positional write landed",
        segments == [b"ABcdefg".to_vec()],
    );
    let wrote = p.writev_row(Syscall::N_pwritev, fd, &[b"!"], Some(9), None);
    let (_, gap) = p.readv_row(Syscall::N_preadv, fd, &[16], Some(6), None);
    p.check(
        "pwritev past EOF leaves a zero-filled gap",
        wrote == 1 && gap == [b"g\0\0!".to_vec()],
    );
    p.check(
        "preadv past EOF is 0",
        p.readv_row(Syscall::N_preadv, fd, &[4], Some(100), None).0 == 0,
    );
    p.check(
        "preadv at a negative position is EINVAL",
        p.readv_row(Syscall::N_preadv, fd, &[4], Some(-1), None).0 == neg(EINVAL),
    );
    p.check(
        "pwritev at a negative position is EINVAL",
        p.writev_row(Syscall::N_pwritev, fd, &[b"x"], Some(-1), None) == neg(EINVAL),
    );
    p.check(
        "preadv on a pipe is ESPIPE",
        p.readv_row(Syscall::N_preadv, pipe[0], &[4], Some(0), None)
            .0
            == neg(ESPIPE),
    );
    let wrote = p.writev_row(Syscall::N_pwritev, writer, &[b"+"], Some(0), None);
    let (_, all) = p.readv_row(Syscall::N_preadv, fd, &[16], Some(0), None);
    p.check(
        "pwritev on an O_APPEND descriptor appends whatever the position",
        wrote == 1 && all == [b"ABcdefg\0\0!+".to_vec()],
    );
    p.check(
        "preadv past UIO_MAXIOV is EINVAL",
        p.iov_shape(
            Syscall::N_preadv,
            fd,
            IovShape::Empty(UIO_MAXIOV as i64 + 1),
            Some(0),
            None,
        ) == neg(EINVAL),
    );

    // ---- preadv2 / pwritev2 --------------------------------------------------
    p.lseek(fd, 2, SEEK_SET);
    let (r, segments) = p.readv_row(Syscall::N_preadv2, fd, &[2, 1], Some(CURSOR), Some(0));
    p.check(
        "preadv2 at -1 reads at the cursor",
        r == 3 && segments == [b"cd".to_vec(), b"e".to_vec()],
    );
    p.check("and advances it", p.lseek(fd, 0, SEEK_CUR) == 5);
    let (r, segments) = p.readv_row(Syscall::N_preadv2, fd, &[2], Some(0), Some(0));
    p.check(
        "preadv2 at a position reads there",
        r == 2 && segments == [b"AB".to_vec()],
    );
    p.check("and leaves the cursor alone", p.lseek(fd, 0, SEEK_CUR) == 5);
    p.check(
        "pwritev2 at -1 writes at the cursor",
        p.writev_row(Syscall::N_pwritev2, fd, &[b"E"], Some(CURSOR), Some(0)) == 1,
    );
    p.check("and advances it", p.lseek(fd, 0, SEEK_CUR) == 6);
    let wrote = p.writev_row(Syscall::N_pwritev2, fd, &[b"$"], Some(0), Some(RWF_APPEND));
    let (_, all) = p.readv_row(Syscall::N_preadv2, fd, &[16], Some(0), Some(0));
    p.check(
        "pwritev2 RWF_APPEND appends whatever the position",
        wrote == 1 && all == [b"ABcdeEg\0\0!+$".to_vec()],
    );
    p.check(
        "pwritev2 RWF_DSYNC writes",
        p.writev_row(Syscall::N_pwritev2, fd, &[b"a"], Some(0), Some(RWF_DSYNC)) == 1,
    );
    p.check(
        "an unknown RWF_* bit is EOPNOTSUPP",
        p.readv_row(Syscall::N_preadv2, fd, &[1], Some(0), Some(UNKNOWN_RWF))
            .0
            == neg(EOPNOTSUPP),
    );
    p.check(
        "pwritev2 with an unknown RWF_* bit is EOPNOTSUPP",
        p.writev_row(Syscall::N_pwritev2, fd, &[b"x"], Some(0), Some(UNKNOWN_RWF))
            == neg(EOPNOTSUPP),
    );
    p.check(
        "preadv2 below -1 is EINVAL",
        p.readv_row(Syscall::N_preadv2, fd, &[1], Some(-2), Some(0))
            .0
            == neg(EINVAL),
    );
    let wrote = p.write(pipe[1], b"pq");
    let (_, piped) = p.readv_row(Syscall::N_preadv2, pipe[0], &[4], Some(CURSOR), Some(0));
    p.check(
        "preadv2 at -1 reads a pipe",
        wrote == 2 && piped == [b"pq".to_vec()],
    );
    p.check(
        "preadv2 at a position on a pipe is ESPIPE",
        p.readv_row(Syscall::N_preadv2, pipe[0], &[4], Some(0), Some(0))
            .0
            == neg(ESPIPE),
    );
    p.check(
        "preadv2 RWF_NOWAIT on an empty pipe is EAGAIN",
        p.readv_row(
            Syscall::N_preadv2,
            pipe[0],
            &[4],
            Some(CURSOR),
            Some(RWF_NOWAIT),
        )
        .0 == neg(EAGAIN),
    );
    p.check(
        "pwritev2 on a closed descriptor is EBADF",
        p.writev_row(Syscall::N_pwritev2, 4000, &[b"x"], Some(0), Some(0)) == neg(EBADF),
    );

    for f in [fd, reader, writer, dirfd, pipe[0], pipe[1]] {
        p.close(f);
    }
}

pub const SCENARIO: Scenario = Scenario {
    name: "fs/vectored_io",
    run,
    covers: &[
        Syscall::N_readv,
        Syscall::N_writev,
        Syscall::N_preadv,
        Syscall::N_pwritev,
        Syscall::N_preadv2,
        Syscall::N_pwritev2,
        Syscall::N_openat,
        Syscall::N_write,
        Syscall::N_lseek,
        Syscall::N_pipe2,
        Syscall::N_close,
    ],
    symbols: &[
        "readv", "writev", "preadv", "pwritev", "syscall", "openat", "write", "lseek", "pipe2",
        "close",
    ],
    kernel_floor: Some(KernelFloor {
        release: "6.4",
        why: "RWF_NOWAIT on a pipe (pipes gained FMODE_NOWAIT)",
    }),
    ..DEFAULTS
};
