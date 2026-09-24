//! fs/splice — splice / tee / vmsplice: moving bytes through pipes without a
//! user copy (splice(2), tee(2), vmsplice(2); fs/splice.c). splice needs a
//! pipe on at least one side (EINVAL otherwise) and refuses an offset for the
//! pipe side (ESPIPE); a file side reads or writes at its cursor or at the
//! offset (written back, the cursor untouched); pipe to pipe moves; an empty
//! pipe with SPLICE_F_NONBLOCK is EAGAIN; one pipe as both ends, or an
//! unknown flag, is EINVAL; a zero length is 0. tee duplicates a pipe's
//! contents into another without consuming them; both ends must be distinct
//! pipes (EINVAL). vmsplice gathers user segments into a pipe's write end
//! (and, from a read end, copies out); a descriptor that is not a pipe is
//! EBADF, past UIO_MAXIOV EINVAL, an unknown flag EINVAL.

use crate::catalog::{Arc, DEFAULTS, Gap, Scenario, Status};
use crate::compare::{Ending, Failure};
use crate::vehicle::Vehicle;

use patina_dst_syscalls::Syscall;

use crate::probe::{AT_FDCWD, IovShape, Probe, neg};
use libc::*;

/// A flag bit the splice family does not define.
const UNKNOWN_SPLICE_FLAG: u32 = 1 << 8;

fn pipe(p: &Probe) -> [i32; 2] {
    let (r, ends) = p.pipe2(0);
    p.require("pipe2", r == 0);
    ends
}

pub fn run(p: &Probe) {
    let root = p.dir();
    let src = p.openat(
        AT_FDCWD,
        &format!("{root}/src"),
        O_RDWR | O_CREAT | O_EXCL,
        0o644,
    );
    let dst = p.openat(
        AT_FDCWD,
        &format!("{root}/dst"),
        O_RDWR | O_CREAT | O_EXCL,
        0o644,
    );
    p.require("create src and dst", src >= 0 && dst >= 0);
    p.check("write the source", p.write(src, b"0123456789") == 10);
    p.lseek(src, 0, SEEK_SET);
    let a = pipe(p);
    let b = pipe(p);

    // ---- splice ------------------------------------------------------------
    let (r, off_in, _) = p.splice(src, Some(2), a[1], None, 4, 0);
    p.check(
        "splice from a file at an offset into a pipe",
        r == 4 && off_in == Some(6),
    );
    p.check(
        "the file's cursor is untouched",
        p.lseek(src, 0, SEEK_CUR) == 0,
    );
    let (r, _, _) = p.splice(src, None, a[1], None, 2, 0);
    p.check("splice from a file at its cursor", r == 2);
    p.check("the file's cursor advanced", p.lseek(src, 0, SEEK_CUR) == 2);
    let (r, _, off_out) = p.splice(a[0], None, dst, Some(0), 64, 0);
    p.check(
        "splice drains the pipe into a file at an offset",
        r == 6 && off_out == Some(6),
    );
    p.check(
        "the file holds the bytes in order",
        p.pread64(dst, 16, 0).1 == b"234501",
    );
    p.check(
        "the destination's cursor is untouched",
        p.lseek(dst, 0, SEEK_CUR) == 0,
    );
    p.check(
        "splice between two files is EINVAL",
        p.splice(src, None, dst, None, 4, 0).0 == neg(EINVAL),
    );
    p.check(
        "an offset for the pipe side is ESPIPE",
        p.splice(src, None, a[1], Some(0), 4, 0).0 == neg(ESPIPE),
    );
    p.check(
        "an empty pipe with SPLICE_F_NONBLOCK is EAGAIN",
        p.splice(a[0], None, dst, None, 4, SPLICE_F_NONBLOCK).0 == neg(EAGAIN),
    );
    p.check(
        "a zero length is 0",
        p.splice(src, None, a[1], None, 0, 0).0 == 0,
    );
    p.check(
        "an unknown flag is EINVAL",
        p.splice(src, None, a[1], None, 4, UNKNOWN_SPLICE_FLAG).0 == neg(EINVAL),
    );
    p.check("fill pipe a", p.write(a[1], b"xyz") == 3);
    p.check(
        "one pipe as both ends is EINVAL",
        p.splice(a[0], None, a[1], None, 4, 0).0 == neg(EINVAL),
    );
    p.check(
        "splice moves between two pipes",
        p.splice(a[0], None, b[1], None, 2, 0).0 == 2,
    );
    p.check("the bytes moved", p.read(b[0], 8).1 == b"xy");
    p.check("the rest stayed behind", p.read(a[0], 8).1 == b"z");
    let writer = p.openat(AT_FDCWD, &format!("{root}/src"), O_WRONLY, 0);
    p.require("open src write-only", writer >= 0);
    p.check(
        "splice from a write-only file is EBADF",
        p.splice(writer, None, a[1], None, 4, 0).0 == neg(EBADF),
    );
    p.check(
        "splice from a closed descriptor is EBADF",
        p.splice(4000, None, a[1], None, 4, 0).0 == neg(EBADF),
    );

    // ---- tee ---------------------------------------------------------------
    p.check("fill pipe a", p.write(a[1], b"tee!") == 4);
    p.check(
        "tee duplicates a pipe's contents",
        p.tee(a[0], b[1], 64, 0) == 4,
    );
    p.check("the copy arrived", p.read(b[0], 8).1 == b"tee!");
    p.check("the source was not consumed", p.read(a[0], 8).1 == b"tee!");
    p.check(
        "tee from an empty pipe with SPLICE_F_NONBLOCK is EAGAIN",
        p.tee(a[0], b[1], 4, SPLICE_F_NONBLOCK) == neg(EAGAIN),
    );
    p.check("a zero-length tee is 0", p.tee(a[0], b[1], 0, 0) == 0);
    p.check(
        "tee with a file end is EINVAL",
        p.tee(src, b[1], 4, 0) == neg(EINVAL),
    );
    p.check(
        "tee within one pipe is EINVAL",
        p.tee(a[0], a[1], 4, 0) == neg(EINVAL),
    );
    p.check(
        "tee with an unknown flag is EINVAL",
        p.tee(a[0], b[1], 4, UNKNOWN_SPLICE_FLAG) == neg(EINVAL),
    );

    // ---- vmsplice ----------------------------------------------------------
    p.check(
        "vmsplice gathers segments into a pipe",
        p.vmsplice(a[1], &[b"ab", b"cd"], 0) == 4,
    );
    p.check("the pipe holds them in order", p.read(a[0], 8).1 == b"abcd");
    p.check("fill pipe a", p.write(a[1], b"wxyz") == 4);
    let (r, segments) = p.vmsplice_read(a[0], &[2, 3], 0);
    p.check(
        "vmsplice from a read end copies out",
        r == 4 && segments == [b"wx".to_vec(), b"yz".to_vec()],
    );
    p.check(
        "a zero count is 0",
        p.iov_shape(Syscall::N_vmsplice, a[1], IovShape::Empty(0), None, Some(0)) == 0,
    );
    p.check(
        "past UIO_MAXIOV is EINVAL",
        p.iov_shape(
            Syscall::N_vmsplice,
            a[1],
            IovShape::Empty(UIO_MAXIOV as i64 + 1),
            None,
            Some(0),
        ) == neg(EINVAL),
    );
    p.check(
        "vmsplice with an unknown flag is EINVAL",
        p.vmsplice(a[1], &[b"x"], UNKNOWN_SPLICE_FLAG) == neg(EINVAL),
    );
    p.check(
        "vmsplice into a file is EBADF",
        p.vmsplice(dst, &[b"x"], 0) == neg(EBADF),
    );
    p.check(
        "vmsplice into a closed descriptor is EBADF",
        p.vmsplice(4000, &[b"x"], 0) == neg(EBADF),
    );

    for f in [src, dst, writer, a[0], a[1], b[0], b[1]] {
        p.close(f);
    }
}

pub const SCENARIO: Scenario = Scenario {
    name: "fs/splice",
    run,
    covers: &[
        Syscall::N_splice,
        Syscall::N_tee,
        Syscall::N_vmsplice,
        Syscall::N_openat,
        Syscall::N_read,
        Syscall::N_write,
        Syscall::N_pread64,
        Syscall::N_lseek,
        Syscall::N_pipe2,
        Syscall::N_close,
    ],
    symbols: &[
        "syscall", "openat", "read", "write", "pread64", "lseek", "pipe2", "close",
    ],
    gaps: &[Gap {
        status: Status::Pending(Arc::Fs),
        vehicles: Vehicle::ALL,
        what: "splice, tee and vmsplice are unmodeled Trap rows: the first splice aborts",
        failure: Failure::Stops {
            events: 7,
            ending: Ending::Signal(6),
            diagnostic: "unsupported syscall splice",
        },
    }],
    ..DEFAULTS
};
