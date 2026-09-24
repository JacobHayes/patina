//! fs/size — sizes by name and by descriptor: truncate (grow zero-filled,
//! shrink, EINVAL/EISDIR/ENOENT/EACCES, through a symlink, on a FIFO),
//! ftruncate (EISDIR, EINVAL for a read-only or non-file descriptor, EBADF for
//! O_PATH), and fallocate (reserve, KEEP_SIZE, PUNCH_HOLE|KEEP_SIZE, ZERO_RANGE,
//! the kernel's order of refusals: EINVAL, EOPNOTSUPP, EBADF, ESPIPE).

use crate::catalog::{DEFAULTS, Scenario};

use patina_dst_syscalls::Syscall;

use crate::probe::{AT_FDCWD, Probe, StatView, neg};
use libc::*;

fn pause(p: &Probe) {
    p.nanosleep(0, 20_000_000);
}

fn fstat(p: &Probe, fd: i32) -> StatView {
    let (r, st) = p.fstat(fd);
    p.require("fstat", r == 0 && st.is_some());
    st.unwrap()
}

fn size(p: &Probe, path: &str) -> i64 {
    let (r, st) = p.newfstatat(AT_FDCWD, path, 0);
    p.require("newfstatat", r == 0 && st.is_some());
    st.unwrap().size
}

fn contents(p: &Probe, fd: i32, len: usize) -> Vec<u8> {
    p.lseek(fd, 0, SEEK_SET);
    let (r, bytes) = p.read(fd, len);
    p.require("read back", r >= 0);
    bytes
}

pub fn run(p: &Probe) {
    let root = p.dir();
    let file = format!("{root}/f");
    let dir = format!("{root}/d");

    // ---- truncate by name ------------------------------------------------
    let fd = p.openat(AT_FDCWD, &file, O_RDWR | O_CREAT | O_EXCL, 0o644);
    p.require("create f", fd >= 0);
    p.write(fd, b"abcdef");
    let before = fstat(p, fd);
    pause(p);
    p.check("truncate shrinks", p.truncate(&file, 3) == 0);
    p.check("the size is 3", size(p, &file) == 3);
    p.check("the bytes are the prefix", contents(p, fd, 8) == b"abc");
    let shrunk = fstat(p, fd);
    p.check(
        "truncate moves mtime and ctime forward",
        shrunk.mtime_ns > before.mtime_ns && shrunk.ctime_ns > before.ctime_ns,
    );
    p.check("truncate grows", p.truncate(&file, 8) == 0);
    p.check("the size is 8", size(p, &file) == 8);
    p.check(
        "growth is zero-filled",
        contents(p, fd, 16) == b"abc\0\0\0\0\0",
    );
    p.check(
        "a negative length is EINVAL",
        p.truncate(&file, -1) == neg(EINVAL),
    );
    p.check("mkdirat d", p.mkdirat(AT_FDCWD, &dir, 0o755) == 0);
    p.check(
        "truncate on a directory is EISDIR",
        p.truncate(&dir, 0) == neg(EISDIR),
    );
    p.check(
        "truncate on a missing path is ENOENT",
        p.truncate(&format!("{root}/missing"), 0) == neg(ENOENT),
    );
    let link = format!("{root}/l");
    p.check("symlinkat l -> f", p.symlinkat("f", AT_FDCWD, &link) == 0);
    p.check("truncate follows a symlink", p.truncate(&link, 2) == 0);
    p.check("the target shrank", size(p, &file) == 2);
    let fifo = format!("{root}/p");
    p.check(
        "mknodat a FIFO",
        p.mknodat(AT_FDCWD, &fifo, S_IFIFO | 0o644, 0) == 0,
    );
    p.check(
        "truncate on a FIFO is EINVAL",
        p.truncate(&fifo, 0) == neg(EINVAL),
    );
    let readonly = format!("{root}/ro");
    let ro = p.openat(AT_FDCWD, &readonly, O_RDWR | O_CREAT | O_EXCL, 0o444);
    p.require("create ro", ro >= 0);
    p.check(
        "truncate without w is EACCES",
        p.truncate(&readonly, 0) == neg(EACCES),
    );

    // ---- ftruncate -------------------------------------------------------
    p.check("ftruncate grows", p.ftruncate(fd, 4) == 0);
    p.check("the size is 4", fstat(p, fd).size == 4);
    p.check(
        "ftruncate negative is EINVAL",
        p.ftruncate(fd, -1) == neg(EINVAL),
    );
    let reader = p.openat(AT_FDCWD, &file, O_RDONLY, 0);
    p.require("open f read-only", reader >= 0);
    p.check(
        "ftruncate on a read-only descriptor is EINVAL",
        p.ftruncate(reader, 0) == neg(EINVAL),
    );
    let dirfd = p.openat(AT_FDCWD, &dir, O_RDONLY | O_DIRECTORY, 0);
    p.require("open d", dirfd >= 0);
    p.check(
        "ftruncate on a directory is EINVAL (EISDIR is the by-name answer)",
        p.ftruncate(dirfd, 0) == neg(EINVAL),
    );
    let location = p.openat(AT_FDCWD, &file, O_PATH, 0);
    p.require("open f O_PATH", location >= 0);
    p.check(
        "ftruncate on an O_PATH descriptor is EBADF",
        p.ftruncate(location, 0) == neg(EBADF),
    );
    p.check(
        "ftruncate on a closed descriptor is EBADF",
        p.ftruncate(4000, 0) == neg(EBADF),
    );
    let (r, pipe) = p.pipe2(0);
    p.require("pipe2", r == 0);
    p.check(
        "ftruncate on a pipe is EINVAL",
        p.ftruncate(pipe[1], 0) == neg(EINVAL),
    );

    // ---- fallocate -------------------------------------------------------
    p.check("ftruncate to 6", p.ftruncate(fd, 6) == 0);
    p.lseek(fd, 0, SEEK_SET);
    p.write(fd, b"abcdef");
    let before = fstat(p, fd);
    pause(p);
    p.check(
        "fallocate mode 0 past the end grows the file",
        p.fallocate(fd, 0, 4, 4) == 0,
    );
    p.check("the size is 8", fstat(p, fd).size == 8);
    p.check(
        "the growth is zero-filled",
        contents(p, fd, 16) == b"abcdef\0\0",
    );
    let grown = fstat(p, fd);
    p.check(
        "growing moves mtime and ctime forward",
        grown.mtime_ns > before.mtime_ns && grown.ctime_ns > before.ctime_ns,
    );
    p.check(
        "fallocate mode 0 inside the file",
        p.fallocate(fd, 0, 0, 2) == 0,
    );
    p.check("the size is unchanged", fstat(p, fd).size == 8);
    p.check(
        "FALLOC_FL_KEEP_SIZE reserves without growing",
        p.fallocate(fd, FALLOC_FL_KEEP_SIZE, 0, 4096) == 0,
    );
    p.check("the size is still 8", fstat(p, fd).size == 8);
    p.check(
        "FALLOC_FL_PUNCH_HOLE|FALLOC_FL_KEEP_SIZE zeroes the range",
        p.fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 1, 2) == 0,
    );
    p.check(
        "the hole reads as zeros",
        contents(p, fd, 16) == b"a\0\0def\0\0",
    );
    p.check("the size is still 8 after the hole", fstat(p, fd).size == 8);
    p.check(
        "a hole past the end changes nothing",
        p.fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 8, 100) == 0
            && fstat(p, fd).size == 8,
    );
    p.check(
        "FALLOC_FL_PUNCH_HOLE without KEEP_SIZE is EOPNOTSUPP",
        p.fallocate(fd, FALLOC_FL_PUNCH_HOLE, 0, 1) == neg(EOPNOTSUPP),
    );
    p.check(
        "FALLOC_FL_ZERO_RANGE zeroes and grows",
        p.fallocate(fd, FALLOC_FL_ZERO_RANGE, 6, 4) == 0,
    );
    p.check("the size is 10", fstat(p, fd).size == 10);
    p.check(
        "the zeroed range reads as zeros",
        contents(p, fd, 16) == b"a\0\0def\0\0\0\0",
    );
    p.check(
        "FALLOC_FL_ZERO_RANGE|FALLOC_FL_KEEP_SIZE never grows",
        p.fallocate(fd, FALLOC_FL_ZERO_RANGE | FALLOC_FL_KEEP_SIZE, 8, 100) == 0
            && fstat(p, fd).size == 10,
    );
    p.check(
        "an unknown mode bit is EOPNOTSUPP",
        p.fallocate(fd, 0x80, 0, 1) == neg(EOPNOTSUPP),
    );
    p.check(
        "FALLOC_FL_COLLAPSE_RANGE with KEEP_SIZE is EOPNOTSUPP",
        p.fallocate(fd, FALLOC_FL_COLLAPSE_RANGE | FALLOC_FL_KEEP_SIZE, 0, 4096) == neg(EOPNOTSUPP),
    );
    p.check(
        "two operation bits at once are EOPNOTSUPP",
        p.fallocate(
            fd,
            FALLOC_FL_PUNCH_HOLE | FALLOC_FL_ZERO_RANGE | FALLOC_FL_KEEP_SIZE,
            0,
            1,
        ) == neg(EOPNOTSUPP),
    );
    p.check(
        "a zero length is EINVAL",
        p.fallocate(fd, 0, 0, 0) == neg(EINVAL),
    );
    p.check(
        "a negative offset is EINVAL",
        p.fallocate(fd, 0, -1, 1) == neg(EINVAL),
    );
    p.check(
        "a read-only descriptor is EBADF",
        p.fallocate(reader, 0, 0, 1) == neg(EBADF),
    );
    p.check(
        "an O_PATH descriptor is EBADF",
        p.fallocate(location, 0, 0, 1) == neg(EBADF),
    );
    p.check(
        "a directory descriptor is EBADF",
        p.fallocate(dirfd, 0, 0, 1) == neg(EBADF),
    );
    p.check(
        "a pipe's write end is ESPIPE",
        p.fallocate(pipe[1], 0, 0, 1) == neg(ESPIPE),
    );
    p.check(
        "a pipe's read end is EBADF",
        p.fallocate(pipe[0], 0, 0, 1) == neg(EBADF),
    );
    p.check(
        "a closed descriptor is EBADF",
        p.fallocate(4000, 0, 0, 1) == neg(EBADF),
    );

    p.check(
        "fallocate overflow is EFBIG",
        p.fallocate(fd, FALLOC_FL_KEEP_SIZE, i64::MAX, 1) == neg(EFBIG),
    );
    let reserved = p.openat(
        AT_FDCWD,
        &format!("{root}/reserved"),
        O_RDWR | O_CREAT | O_EXCL,
        0o600,
    );
    p.require("open allocation inventory", reserved >= 0);
    p.check(
        "reserve without size growth",
        p.fallocate(reserved, FALLOC_FL_KEEP_SIZE, 0, 4096) == 0,
    );
    // A claimed BLOCKS field must reflect allocation, not logical length.
    let mut sx: libc::statx = unsafe { std::mem::zeroed() };
    let empty = b"\0";
    let r = p.vehicle.call(
        Syscall::N_statx,
        [
            reserved as i64,
            empty.as_ptr() as i64,
            AT_EMPTY_PATH as i64,
            STATX_BASIC_STATS as i64,
            &mut sx as *mut _ as i64,
            0,
        ],
    );
    p.check(
        "statx either models reservations or omits BLOCKS",
        r == 0 && (sx.stx_mask & STATX_BLOCKS == 0 || sx.stx_blocks > 0),
    );
    p.close(reserved);
    p.close(pipe[0]);
    p.close(pipe[1]);
    p.close(location);
    p.close(dirfd);
    p.close(reader);
    p.close(ro);
    p.close(fd);
}

pub const SCENARIO: Scenario = Scenario {
    name: "fs/size",
    run,
    covers: &[
        Syscall::N_truncate,
        Syscall::N_ftruncate,
        Syscall::N_fallocate,
        Syscall::N_fstat,
        Syscall::N_newfstatat,
        Syscall::N_openat,
        Syscall::N_read,
        Syscall::N_write,
        Syscall::N_lseek,
        Syscall::N_close,
        Syscall::N_mkdirat,
        Syscall::N_mknodat,
        Syscall::N_symlinkat,
        Syscall::N_pipe2,
        Syscall::N_nanosleep,
    ],
    symbols: &[
        "truncate",
        "ftruncate",
        "fallocate",
        "fstat",
        "fstatat",
        "openat",
        "read",
        "write",
        "lseek",
        "close",
        "mkdirat",
        "mknodat",
        "symlinkat",
        "pipe2",
        "nanosleep",
    ],
    ..DEFAULTS
};
