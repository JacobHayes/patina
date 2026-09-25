//! fs/copy — copy_file_range / sendfile: in-kernel copies between
//! descriptors. copy_file_range(2): NULL offsets use and advance both
//! cursors, offset pointers are read and advanced instead and leave the
//! cursors alone; a copy is short at the source's EOF and 0 past it; flags
//! must be 0 (EINVAL); both ends regular files (EISDIR for a directory,
//! EINVAL for a pipe), the source readable and the destination writable and
//! not O_APPEND (EBADF: fs/read_write.c generic_file_rw_checks); within one
//! file the ranges must not overlap (EINVAL). sendfile(2): the input is a
//! file read at its cursor or at `*offset` (then written back, the cursor
//! untouched); the output may be a file or a pipe, but not O_APPEND (EINVAL);
//! a pipe as input is EINVAL; EBADF for the wrong access mode or a closed
//! descriptor at either end; a negative offset is EINVAL.
//!
//! The libc vehicle goes through glibc's `copy_file_range` and `sendfile`,
//! imported (the shim defines them); every vehicle also calls glibc's LFS
//! spelling `sendfile64`.

use crate::catalog::{DEFAULTS, Scenario};

use patina_dst_syscalls::Syscall;

use crate::probe::{Probe, neg};
use libc::*;

pub fn run(p: &Probe) {
    let root = p.dir();
    let src_path = format!("{root}/src");
    let dst_path = format!("{root}/dst");
    let src = p.open_or_stop(&src_path, O_RDWR | O_CREAT | O_EXCL);
    p.check("write the source", p.write(src, b"0123456789") == 10);
    p.lseek(src, 0, SEEK_SET);
    let dst = p.open_or_stop(&dst_path, O_RDWR | O_CREAT | O_EXCL);

    // ---- copy_file_range ---------------------------------------------------
    let (r, _, _) = p.copy_file_range(src, None, dst, None, 4, 0);
    p.check("copy_file_range at the cursors", r == 4);
    p.check(
        "both cursors advanced",
        (p.lseek(src, 0, SEEK_CUR), p.lseek(dst, 0, SEEK_CUR)) == (4, 4),
    );
    let (r, off_in, off_out) = p.copy_file_range(src, Some(6), dst, Some(0), 10, 0);
    p.check(
        "a copy at offsets is short at the source's EOF",
        r == 4 && off_in == Some(10) && off_out == Some(4),
    );
    p.check(
        "the offsets moved, the cursors did not",
        (p.lseek(src, 0, SEEK_CUR), p.lseek(dst, 0, SEEK_CUR)) == (4, 4),
    );
    p.check(
        "the destination holds both copies",
        p.pread64(dst, 16, 0).1 == b"6789",
    );
    p.check(
        "a copy from the source's EOF is 0",
        p.copy_file_range(src, Some(10), dst, Some(0), 4, 0).0 == 0,
    );
    p.check(
        "a zero-length copy is 0",
        p.copy_file_range(src, None, dst, None, 0, 0).0 == 0,
    );
    p.check(
        "nonzero flags are EINVAL",
        p.copy_file_range(src, None, dst, None, 4, 1).0 == neg(EINVAL),
    );
    p.check(
        "overlapping ranges within one file are EINVAL",
        p.copy_file_range(src, Some(0), src, Some(2), 4, 0).0 == neg(EINVAL),
    );
    let (r, _, off_out) = p.copy_file_range(src, Some(0), src, Some(12), 4, 0);
    p.check(
        "disjoint ranges within one file copy",
        r == 4 && off_out == Some(16),
    );
    p.check(
        "the file grew by the copy past its end",
        p.pread64(src, 32, 0).1 == b"0123456789\0\x000123",
    );
    let append = p.open_or_stop(&dst_path, O_WRONLY | O_APPEND);
    p.check(
        "an O_APPEND destination is EBADF",
        p.copy_file_range(src, None, append, None, 4, 0).0 == neg(EBADF),
    );
    let reader = p.open_or_stop(&dst_path, O_RDONLY);
    p.check(
        "a read-only destination is EBADF",
        p.copy_file_range(src, None, reader, None, 4, 0).0 == neg(EBADF),
    );
    let writer = p.open_or_stop(&src_path, O_WRONLY);
    p.check(
        "a write-only source is EBADF",
        p.copy_file_range(writer, None, dst, None, 4, 0).0 == neg(EBADF),
    );
    let dirfd = p.open_or_stop(&root, O_RDONLY | O_DIRECTORY);
    p.check(
        "a directory source is EISDIR",
        p.copy_file_range(dirfd, None, dst, None, 4, 0).0 == neg(EISDIR),
    );
    let (r, pipe) = p.pipe2(0);
    p.require("pipe2", r == 0);
    p.check("fill the pipe", p.write(pipe[1], b"pipe") == 4);
    p.check(
        "a pipe source is EINVAL",
        p.copy_file_range(pipe[0], None, dst, None, 4, 0).0 == neg(EINVAL),
    );
    p.check(
        "a pipe destination is EINVAL",
        p.copy_file_range(src, None, pipe[1], None, 4, 0).0 == neg(EINVAL),
    );
    p.check(
        "a closed source is EBADF",
        p.copy_file_range(4000, None, dst, None, 4, 0).0 == neg(EBADF),
    );
    p.check(
        "the descriptors are judged before the flags",
        p.copy_file_range(4000, None, dst, None, 4, 1).0 == neg(EBADF),
    );

    // ---- sendfile ----------------------------------------------------------
    let out = p.open_or_stop(&format!("{root}/out"), O_RDWR | O_CREAT | O_EXCL);
    p.lseek(src, 0, SEEK_SET);
    let (r, _) = p.sendfile(out, src, None, 4);
    p.check("sendfile at the input's cursor", r == 4);
    p.check(
        "the input's and output's cursors advanced",
        (p.lseek(src, 0, SEEK_CUR), p.lseek(out, 0, SEEK_CUR)) == (4, 4),
    );
    let (r, after) = p.sendfile(out, src, Some(14), 10);
    p.check(
        "sendfile at an offset is short at EOF and writes the offset back",
        r == 2 && after == Some(16),
    );
    p.check(
        "the input's cursor is untouched",
        p.lseek(src, 0, SEEK_CUR) == 4,
    );
    p.check(
        "the output holds both copies",
        p.pread64(out, 16, 0).1 == b"012323",
    );
    p.check(
        "a zero-count sendfile is 0",
        p.sendfile(out, src, None, 0).0 == 0,
    );
    p.check(
        "sendfile at EOF is 0",
        p.sendfile(out, src, Some(16), 4).0 == 0,
    );
    let (r, pipe2) = p.pipe2(0);
    p.require("pipe2", r == 0);
    p.check(
        "sendfile into a pipe",
        p.sendfile(pipe2[1], src, Some(0), 3).0 == 3,
    );
    p.check("the pipe holds the bytes", p.read(pipe2[0], 8).1 == b"012");
    p.check(
        "sendfile from a pipe is EINVAL",
        p.sendfile(out, pipe[0], None, 4).0 == neg(EINVAL),
    );
    p.check(
        "sendfile to an O_APPEND output is EINVAL",
        p.sendfile(append, src, Some(0), 4).0 == neg(EINVAL),
    );
    p.check(
        "sendfile from a write-only input is EBADF",
        p.sendfile(out, writer, Some(0), 4).0 == neg(EBADF),
    );
    p.check(
        "sendfile to a read-only output is EBADF",
        p.sendfile(reader, src, Some(0), 4).0 == neg(EBADF),
    );
    p.check(
        "sendfile at a negative offset is EINVAL",
        p.sendfile(out, src, Some(-1), 4).0 == neg(EINVAL),
    );
    p.check(
        "sendfile from a closed descriptor is EBADF",
        p.sendfile(out, 4000, None, 4).0 == neg(EBADF),
    );
    p.check(
        "sendfile to a closed descriptor is EBADF",
        p.sendfile(4000, src, Some(0), 4).0 == neg(EBADF),
    );

    // glibc's LFS spelling, which `<sys/sendfile.h>` binds `sendfile` to
    // under `_FILE_OFFSET_BITS=64`: the same call on every vehicle.
    let sendfile64 = |out_fd: i32, in_fd: i32, offset: i64, count: usize| {
        let mut pos = offset;
        // SAFETY: two descriptor numbers and a live offset.
        let r =
            crate::vehicle::fold_errno(
                unsafe { libc::sendfile64(out_fd, in_fd, &mut pos, count) } as i64
            );
        p.rec
            .event("sendfile64", r)
            .arg("out_fd", out_fd)
            .norm("args.out_fd", crate::observe::Norm::Relative("fd"))
            .arg("in_fd", in_fd)
            .norm("args.in_fd", crate::observe::Norm::Relative("fd"))
            .arg("offset", offset)
            .arg("count", count)
            .field("offset_after", pos)
            .emit();
        (r, pos)
    };
    p.check(
        "sendfile64 at an offset writes the offset back",
        sendfile64(pipe2[1], src, 4, 3) == (3, 7),
    );
    p.check(
        "the pipe holds those bytes",
        p.read(pipe2[0], 8).1 == b"456",
    );
    p.check(
        "sendfile64 at a negative offset is EINVAL",
        sendfile64(out, src, -1, 4).0 == neg(EINVAL),
    );

    for f in [
        src, dst, append, reader, writer, dirfd, pipe[0], pipe[1], out, pipe2[0], pipe2[1],
    ] {
        p.close(f);
    }
}

pub const SCENARIO: Scenario = Scenario {
    name: "fs/copy",
    run,
    covers: &[
        Syscall::N_copy_file_range,
        Syscall::N_sendfile,
        Syscall::N_openat,
        Syscall::N_read,
        Syscall::N_write,
        Syscall::N_pread64,
        Syscall::N_lseek,
        Syscall::N_pipe2,
        Syscall::N_close,
    ],
    symbols: &[
        "copy_file_range",
        "sendfile",
        "sendfile64",
        "openat",
        "read",
        "write",
        "pread64",
        "lseek",
        "pipe2",
        "close",
    ],
    ..DEFAULTS
};
