//! fs/rw — file I/O at the descriptor's cursor and at an explicit position.
//! openat / read / write / lseek / close: the cursor, access modes, creation
//! flags, and the errno vocabulary around them. pread64 / pwrite64 (pread(2)):
//! I/O at a position that never moves the cursor; a short read at EOF and 0
//! past it; a write past EOF leaves a zero-filled hole; on an O_APPEND
//! descriptor Linux appends whatever the position (pwrite(2) BUGS); a negative
//! position is EINVAL even for a zero length (fs/read_write.c ksys_pread64
//! judges it first); ESPIPE on a pipe, EISDIR on a directory, EBADF for the
//! wrong access mode or a closed descriptor.

use crate::catalog::{DEFAULTS, Scenario};

use patina_dst_syscalls::Syscall;

use crate::probe::{AT_FDCWD, Probe, neg};
use libc::*;

pub fn run(p: &Probe) {
    let root = p.dir();
    at_the_cursor(p, &root);
    at_a_position(p, &root);
}

fn at_the_cursor(p: &Probe, root: &str) {
    let file = format!("{root}/data");

    let fd = p.openat(
        AT_FDCWD,
        &file,
        O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC,
        0o644,
    );
    p.require("create the data file", fd >= 0);
    p.check(
        "write returns the full length",
        p.write(fd, b"hello world") == 11,
    );
    p.check(
        "SEEK_CUR after the write is at the end",
        p.lseek(fd, 0, SEEK_CUR) == 11,
    );
    p.check("read at EOF returns 0", p.read(fd, 8).0 == 0);
    p.check("SEEK_SET rewinds", p.lseek(fd, 0, SEEK_SET) == 0);
    let (n, data) = p.read(fd, 5);
    p.check(
        "a partial read returns the prefix",
        n == 5 && data == b"hello",
    );
    p.check(
        "SEEK_CUR advanced by the read",
        p.lseek(fd, 0, SEEK_CUR) == 5,
    );
    p.check("SEEK_END reports the size", p.lseek(fd, 0, SEEK_END) == 11);
    p.check(
        "seeking past EOF succeeds",
        p.lseek(fd, 100, SEEK_SET) == 100,
    );
    p.check("a write past EOF extends the file", p.write(fd, b"!") == 1);
    p.check("size after the hole write", p.lseek(fd, 0, SEEK_END) == 101);
    p.lseek(fd, 50, SEEK_SET);
    let (n, data) = p.read(fd, 4);
    p.check("the hole reads as zeros", n == 4 && data == [0, 0, 0, 0]);
    p.check(
        "a negative offset is EINVAL",
        p.lseek(fd, -1, SEEK_SET) == neg(EINVAL),
    );
    p.check("a bad whence is EINVAL", p.lseek(fd, 0, 99) == neg(EINVAL));
    p.check("a zero-length read returns 0", p.read(fd, 0).0 == 0);
    p.check("a zero-length write returns 0", p.write(fd, b"") == 0);

    let again = p.openat(AT_FDCWD, &file, O_RDWR | O_CREAT | O_EXCL, 0o644);
    p.check(
        "O_EXCL on an existing file is EEXIST",
        i64::from(again) == neg(EEXIST),
    );
    let missing = p.openat(AT_FDCWD, &format!("{root}/missing"), O_RDONLY, 0);
    p.check(
        "a missing file is ENOENT",
        i64::from(missing) == neg(ENOENT),
    );

    let ro = p.openat(AT_FDCWD, &file, O_RDONLY, 0);
    p.require("read-only open", ro >= 0);
    p.check(
        "write on O_RDONLY is EBADF",
        p.write(ro, b"x") == neg(EBADF),
    );
    let (n, data) = p.read(ro, 5);
    p.check(
        "a second open has its own cursor",
        n == 5 && data == b"hello",
    );
    let wo = p.openat(AT_FDCWD, &file, O_WRONLY, 0);
    p.require("write-only open", wo >= 0);
    p.check("read on O_WRONLY is EBADF", p.read(wo, 1).0 == neg(EBADF));
    let ap = p.openat(AT_FDCWD, &file, O_WRONLY | O_APPEND, 0);
    p.require("append open", ap >= 0);
    p.check(
        "O_APPEND write lands at the end",
        p.write(ap, b"++") == 2 && p.lseek(ap, 0, SEEK_CUR) == 103,
    );
    let tr = p.openat(AT_FDCWD, &file, O_RDWR | O_TRUNC, 0);
    p.require("truncating open", tr >= 0);
    p.check("O_TRUNC empties the file", p.lseek(tr, 0, SEEK_END) == 0);
    p.check(
        "the truncation is visible through the older descriptor",
        p.lseek(fd, 0, SEEK_END) == 0,
    );

    let dir = p.openat(AT_FDCWD, root, O_RDONLY | O_DIRECTORY, 0);
    p.require("directory open", dir >= 0);
    p.check(
        "read on a directory is EISDIR",
        p.read(dir, 8).0 == neg(EISDIR),
    );
    p.check(
        "write on a directory is EBADF",
        p.write(dir, b"x") == neg(EBADF),
    );
    let rel = p.openat(dir, "relative", O_WRONLY | O_CREAT, 0o600);
    p.check(
        "openat creates relative to a directory descriptor",
        rel >= 0,
    );
    let via_path = p.openat(AT_FDCWD, &format!("{root}/relative"), O_RDONLY, 0);
    p.check(
        "the relative name is visible by absolute path",
        via_path >= 0,
    );
    let bad_dirfd = p.openat(fd, "x", O_RDONLY | O_CREAT, 0o600);
    p.check(
        "a dirfd that is a file is ENOTDIR",
        i64::from(bad_dirfd) == neg(ENOTDIR),
    );
    let closed_dirfd = p.openat(4000, "x", O_RDONLY, 0);
    p.check(
        "a dirfd that is not open is EBADF",
        i64::from(closed_dirfd) == neg(EBADF),
    );

    p.check("close succeeds", p.close(fd) == 0);
    p.check("a second close is EBADF", p.close(fd) == neg(EBADF));
    p.check(
        "read on a closed descriptor is EBADF",
        p.read(fd, 1).0 == neg(EBADF),
    );
    p.check(
        "lseek on a closed descriptor is EBADF",
        p.lseek(fd, 0, SEEK_SET) == neg(EBADF),
    );
    let reused = p.openat(AT_FDCWD, &file, O_RDONLY, 0);
    p.check("the lowest free descriptor number is reused", reused == fd);

    for f in [ro, wo, ap, tr, dir, rel, via_path, reused] {
        p.close(f);
    }
}

fn at_a_position(p: &Probe, root: &str) {
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
    let dirfd = p.openat(AT_FDCWD, root, O_RDONLY | O_DIRECTORY, 0);
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
    name: "fs/rw",
    run,
    covers: &[
        Syscall::N_openat,
        Syscall::N_read,
        Syscall::N_write,
        Syscall::N_lseek,
        Syscall::N_pread64,
        Syscall::N_pwrite64,
        Syscall::N_pipe2,
        Syscall::N_close,
    ],
    symbols: &[
        "openat", "read", "write", "lseek", "pread64", "pwrite64", "pipe2", "close",
    ],
    ..DEFAULTS
};
