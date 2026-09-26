//! fs/lfs64 — glibc's large-file spellings of the file calls: `open64`,
//! `openat64`, the `stat64` family, `statfs64`/`fstatfs64`, `preadv64`/
//! `pwritev64`, `lseek64`, `ftruncate64`/`truncate64`, `fallocate64`,
//! `posix_fallocate64` and `fcntl64` (glibc io/, misc/, posix/; a 64-bit
//! target's `*64` symbol is its plain one). What a program built with
//! `_FILE_OFFSET_BITS=64`, or Rust's std and rustix on 64-bit Linux, imports:
//!
//! * `open64`/`openat64` create and open (EEXIST, ENOENT, ENOTDIR through a
//!   file descriptor, EBADF for a closed one);
//! * `pwritev64` writes past the end (a hole reads as zeros) and `preadv64`
//!   scatters the file back; on a pipe both are ESPIPE, a negative offset
//!   EINVAL;
//! * `lseek64` finds the end (EINVAL for a negative position or an unknown
//!   whence, ESPIPE on a pipe); in a file written without gaps `SEEK_DATA`
//!   answers the offset and `SEEK_HOLE` the end, and at the end both are
//!   ENXIO;
//! * offsets past 4 GiB pass whole: `lseek64` there reads back, `preadv64`
//!   there is past the end (not the file's first bytes), `SEEK_DATA` from
//!   there is ENXIO, `fallocate64(FALLOC_FL_KEEP_SIZE)` past 8 GiB allocates
//!   without growing, and a lock past 8 GiB keeps its range. Nothing is
//!   written that far: the offsets are what the 64-bit spellings carry, and
//!   a sparse multi-gigabyte file costs its whole size on a volume that holds
//!   files densely;
//! * `ftruncate64`/`truncate64` set the size (EINVAL negative or through a
//!   read-only descriptor, EISDIR for a directory, ENOENT);
//! * `fallocate64` allocates (`FALLOC_FL_KEEP_SIZE` without growing; EINVAL
//!   for a zero length, EBADF read-only, ESPIPE on a pipe) and
//!   `posix_fallocate64` grows the file, returning its error number (EINVAL
//!   for a negative offset, EBADF read-only, ESPIPE on a pipe);
//! * the `stat64` family reports the kind, size and links (`stat64` follows
//!   a symlink, `lstat64` and `fstatat64(AT_SYMLINK_NOFOLLOW)` do not,
//!   `fstatat64(AT_EMPTY_PATH)` names the descriptor): ENOENT, EFAULT for a
//!   NULL buffer, EBADF;
//! * `statfs64` and `fstatfs64` describe the run directory's filesystem
//!   alike (ENOENT, EBADF);
//! * `fcntl64` reads and sets descriptor flags and takes write locks through
//!   its 64-bit `flock64`: `F_GETLK` never reports the caller's own lock,
//!   while `F_OFD_GETLK` through a second open file description reports it
//!   (range and owner pid) and `F_OFD_SETLK` there is EAGAIN (EBADF for a
//!   write lock through a read-only descriptor or a closed number, EINVAL
//!   for an unknown command); an unlock splits a lock and a relock merges it
//!   back, any close of the file but an `O_PATH` one releases the process's
//!   POSIX locks and the last close of a description its OFD locks,
//!   `F_OFD_SETLKW` waits for a POSIX lock, and `F_GETLK` reports an OFD lock
//!   with pid -1.
//!
//! libc only: the plain names are the libc vehicle of the row scenarios.

use crate::catalog::{DEFAULTS, Gap, Scenario, Status};
use crate::compare::{Difference, Failure, Observed};
use crate::probe::{AT_FDCWD, Probe, StatBy, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

/// A `fcntl` command no kernel defines.
const UNKNOWN_FCNTL: i32 = 9999;
/// An offset past 4 GiB, which a 32-bit `off_t` would truncate to 5.
const PAST_4GIB: i64 = (1 << 32) + 5;
/// An offset past 8 GiB.
const PAST_8GIB: i64 = 1 << 33;

pub fn run(p: &Probe) {
    let root = p.dir();
    let file = format!("{root}/f");

    // ---- open64 / openat64 ---------------------------------------------------
    let fd = p.open64(&file, O_RDWR | O_CREAT | O_EXCL, 0o640);
    p.require("open64 creates f", fd >= 0);
    p.check(
        "open64 O_EXCL on an existing name is EEXIST",
        i64::from(p.open64(&file, O_RDWR | O_CREAT | O_EXCL, 0o640)) == neg(EEXIST),
    );
    p.check(
        "open64 of a missing name is ENOENT",
        i64::from(p.open64(&format!("{root}/missing"), O_RDONLY, 0)) == neg(ENOENT),
    );
    let dir = p.open64(&root, O_RDONLY | O_DIRECTORY, 0);
    p.require("open64 the run directory", dir >= 0);
    let g = p.openat64(dir, "g", O_WRONLY | O_CREAT | O_EXCL, 0o600);
    p.check("openat64 creates g under the directory", g >= 0);
    p.close(g);
    p.check(
        "openat64 of a missing name is ENOENT",
        i64::from(p.openat64(dir, "missing", O_RDONLY, 0)) == neg(ENOENT),
    );
    p.check(
        "openat64 relative to a file is ENOTDIR",
        i64::from(p.openat64(fd, "x", O_RDONLY, 0)) == neg(ENOTDIR),
    );
    p.check(
        "openat64 relative to a closed number is EBADF",
        i64::from(p.openat64(4000, "x", O_RDONLY, 0)) == neg(EBADF),
    );
    let (r, [rd, wr]) = p.pipe2(0);
    p.require("pipe2", r == 0);

    // ---- pwritev64 / preadv64 / lseek64 ---------------------------------------
    p.check(
        "pwritev64 gathers at an offset past the end",
        p.pwritev64(fd, &[b"abc", b"def"], 2) == 6,
    );
    let (n, segments) = p.preadv64(fd, &[3, 5], 0);
    p.check(
        "preadv64 scatters the file back, the hole as zeros",
        n == 8 && segments == [b"\0\0a".to_vec(), b"bcdef".to_vec()],
    );
    p.check(
        "preadv64 at the end reads nothing",
        p.preadv64(fd, &[4], 8).0 == 0,
    );
    p.check(
        "preadv64 at a negative offset is EINVAL",
        p.preadv64(fd, &[4], -1).0 == neg(EINVAL),
    );
    p.check(
        "pwritev64 on a pipe is ESPIPE",
        p.pwritev64(wr, &[b"x"], 0) == neg(ESPIPE),
    );
    p.check(
        "preadv64 on a pipe is ESPIPE",
        p.preadv64(rd, &[1], 0).0 == neg(ESPIPE),
    );
    p.check("lseek64 finds the end", p.lseek64(fd, 0, SEEK_END) == 8);
    p.check(
        "SEEK_DATA inside the file answers the offset: it is data",
        p.lseek64(fd, 3, SEEK_DATA) == 3,
    );
    p.check(
        "SEEK_HOLE inside a file written without gaps answers its end",
        p.lseek64(fd, 1, SEEK_HOLE) == 8,
    );
    p.check(
        "SEEK_HOLE at the end is ENXIO",
        p.lseek64(fd, 8, SEEK_HOLE) == neg(ENXIO),
    );
    p.check(
        "lseek64 to a negative position is EINVAL",
        p.lseek64(fd, -1, SEEK_SET) == neg(EINVAL),
    );
    p.check(
        "lseek64 with an unknown whence is EINVAL",
        p.lseek64(fd, 0, 7) == neg(EINVAL),
    );
    p.check(
        "lseek64 on a pipe is ESPIPE",
        p.lseek64(rd, 0, SEEK_SET) == neg(ESPIPE),
    );
    p.check(
        "pwritev64 at a negative offset is EINVAL",
        p.pwritev64(fd, &[b"x"], -1) == neg(EINVAL),
    );

    // ---- offsets past 4 GiB ------------------------------------------------------
    p.check(
        "lseek64 moves the offset past 4 GiB",
        p.lseek64(fd, PAST_4GIB, SEEK_SET) == PAST_4GIB,
    );
    p.check(
        "and reads it back whole",
        p.lseek64(fd, 0, SEEK_CUR) == PAST_4GIB,
    );
    p.check(
        "preadv64 past 4 GiB is past the end, not the file's first bytes",
        p.preadv64(fd, &[4], PAST_4GIB).0 == 0,
    );
    p.check(
        "SEEK_DATA from past 4 GiB is past the end: ENXIO",
        p.lseek64(fd, PAST_4GIB, SEEK_DATA) == neg(ENXIO),
    );
    p.check("lseek64 back to the start", p.lseek64(fd, 0, SEEK_SET) == 0);

    // ---- sizes -------------------------------------------------------------
    p.check("ftruncate64 shrinks f", p.ftruncate64(fd, 4) == 0);
    let (r, st) = p.stat64(StatBy::Fd(fd), false);
    p.check(
        "fstat64 reports the new size",
        r == 0 && st.is_some_and(|st| st.kind == "reg" && st.size == 4 && st.perm == 0o640),
    );
    p.check(
        "ftruncate64 to a negative length is EINVAL",
        p.ftruncate64(fd, -1) == neg(EINVAL),
    );
    let reader = p.open64(&file, O_RDONLY, 0);
    p.require("open64 f read-only", reader >= 0);
    p.check(
        "ftruncate64 through a read-only descriptor is EINVAL",
        p.ftruncate64(reader, 0) == neg(EINVAL),
    );
    p.check("truncate64 grows f", p.truncate64(&file, 10) == 0);
    let (r, st) = p.stat64(StatBy::Path(&file), false);
    p.check(
        "stat64 reports it",
        r == 0 && st.is_some_and(|st| st.size == 10),
    );
    p.check(
        "truncate64 of a missing name is ENOENT",
        p.truncate64(&format!("{root}/missing"), 0) == neg(ENOENT),
    );
    p.check(
        "truncate64 of a directory is EISDIR",
        p.truncate64(&root, 0) == neg(EISDIR),
    );
    p.check(
        "truncate64 to a negative length is EINVAL",
        p.truncate64(&file, -1) == neg(EINVAL),
    );
    p.check(
        "fallocate64 allocates and grows",
        p.fallocate64(fd, 0, 0, 4096) == 0,
    );
    p.check(
        "FALLOC_FL_KEEP_SIZE allocates without growing",
        p.fallocate64(fd, FALLOC_FL_KEEP_SIZE, 4096, 4096) == 0,
    );
    p.check(
        "past 8 GiB too",
        p.fallocate64(fd, FALLOC_FL_KEEP_SIZE, PAST_8GIB, 4096) == 0,
    );
    let (r, st) = p.stat64(StatBy::Fd(fd), false);
    p.check(
        "the size is fallocate64's first extent",
        r == 0 && st.is_some_and(|st| st.size == 4096),
    );
    p.check(
        "fallocate64 of a zero length is EINVAL",
        p.fallocate64(fd, 0, 0, 0) == neg(EINVAL),
    );
    p.check(
        "fallocate64 through a read-only descriptor is EBADF",
        p.fallocate64(reader, 0, 0, 4096) == neg(EBADF),
    );
    p.check(
        "fallocate64 on a pipe is ESPIPE",
        p.fallocate64(wr, 0, 0, 4096) == neg(ESPIPE),
    );
    p.check(
        "posix_fallocate64 grows f",
        p.posix_fallocate64(fd, 4096, 4096) == 0,
    );
    let (r, st) = p.stat64(StatBy::Fd(fd), false);
    p.check(
        "to the end of the range",
        r == 0 && st.is_some_and(|st| st.size == 8192),
    );
    p.check(
        "posix_fallocate64 at a negative offset returns EINVAL",
        p.posix_fallocate64(fd, -1, 4096) == neg(EINVAL),
    );
    p.check(
        "posix_fallocate64 through a read-only descriptor returns EBADF",
        p.posix_fallocate64(reader, 0, 4096) == neg(EBADF),
    );
    p.check(
        "posix_fallocate64 on a pipe returns ESPIPE",
        p.posix_fallocate64(wr, 0, 4096) == neg(ESPIPE),
    );

    // A file that is all hole: the volume tracks no allocation (ByDesign).
    let sparse = p.open64(&format!("{root}/sparse"), O_RDWR | O_CREAT | O_EXCL, 0o600);
    p.require("open64 creates sparse", sparse >= 0);
    p.check(
        "ftruncate64 grows sparse to 1 MiB without writing",
        p.ftruncate64(sparse, 1 << 20) == 0,
    );
    p.check(
        "SEEK_DATA in a file that is all hole is ENXIO",
        p.lseek64(sparse, 0, SEEK_DATA) == neg(ENXIO),
    );
    p.close(sparse);

    // ---- the stat64 family -------------------------------------------------
    let link = format!("{root}/l");
    p.check("symlinkat l -> f", p.symlinkat("f", AT_FDCWD, &link) == 0);
    let (r, st) = p.stat64(StatBy::Path(&link), false);
    p.check(
        "stat64 follows a symlink",
        r == 0 && st.is_some_and(|st| st.kind == "reg" && st.size == 8192),
    );
    let (r, st) = p.stat64(StatBy::Link(&link), false);
    p.check(
        "lstat64 does not",
        r == 0 && st.is_some_and(|st| st.kind == "lnk" && st.size == 1),
    );
    let (r, st) = p.stat64(StatBy::At(dir, "l", AT_SYMLINK_NOFOLLOW), false);
    p.check(
        "fstatat64 AT_SYMLINK_NOFOLLOW neither",
        r == 0 && st.is_some_and(|st| st.kind == "lnk"),
    );
    let (r, st) = p.stat64(StatBy::At(dir, "l", 0), false);
    p.check(
        "fstatat64 relative to the directory follows it",
        r == 0 && st.is_some_and(|st| st.kind == "reg"),
    );
    let (r, st) = p.stat64(StatBy::At(fd, "", AT_EMPTY_PATH), false);
    p.check(
        "fstatat64 AT_EMPTY_PATH names the descriptor",
        r == 0 && st.is_some_and(|st| st.kind == "reg" && st.size == 8192),
    );
    let (r, st) = p.stat64(StatBy::At(AT_FDCWD, &root, 0), false);
    p.check(
        "fstatat64 of the directory",
        r == 0 && st.is_some_and(|st| st.kind == "dir"),
    );
    p.check(
        "stat64 of a missing name is ENOENT",
        p.stat64(StatBy::Path(&format!("{root}/missing")), false).0 == neg(ENOENT),
    );
    p.check(
        "lstat64 through a file is ENOTDIR",
        p.stat64(StatBy::Link(&format!("{file}/x")), false).0 == neg(ENOTDIR),
    );
    p.check(
        "stat64 into a NULL buffer is EFAULT",
        p.stat64(StatBy::Path(&file), true).0 == neg(EFAULT),
    );
    p.check(
        "fstat64 of a closed number is EBADF",
        p.stat64(StatBy::Fd(4000), false).0 == neg(EBADF),
    );
    p.check(
        "fstatat64 relative to a file is ENOTDIR",
        p.stat64(StatBy::At(fd, "x", 0), false).0 == neg(ENOTDIR),
    );

    // ---- statfs64 / fstatfs64 --------------------------------------------------
    let (r, by_path) = p.statfs64(&root);
    let (s, by_fd) = p.fstatfs64(dir);
    p.check(
        "statfs64 and fstatfs64 describe one filesystem alike",
        r == 0
            && s == 0
            && by_path.is_some_and(|a| {
                by_fd.is_some_and(|b| {
                    (a.f_type, a.f_bsize, a.f_fsid, a.f_namelen, a.f_blocks)
                        == (b.f_type, b.f_bsize, b.f_fsid, b.f_namelen, b.f_blocks)
                })
            }),
    );
    p.check(
        "statfs64 of a missing name is ENOENT",
        p.statfs64(&format!("{root}/missing")).0 == neg(ENOENT),
    );
    p.check(
        "fstatfs64 of a closed number is EBADF",
        p.fstatfs64(4000).0 == neg(EBADF),
    );

    // ---- fcntl64 -------------------------------------------------------------
    p.check(
        "fcntl64 F_GETFL answers the access mode",
        p.fcntl64(fd, F_GETFL, 0) & i64::from(O_ACCMODE) == i64::from(O_RDWR),
    );
    p.check(
        "fcntl64 F_GETFD starts clear",
        p.fcntl64(fd, F_GETFD, 0) == 0,
    );
    p.check(
        "fcntl64 F_SETFD sets FD_CLOEXEC",
        p.fcntl64(fd, F_SETFD, i64::from(FD_CLOEXEC)) == 0
            && p.fcntl64(fd, F_GETFD, 0) == i64::from(FD_CLOEXEC),
    );
    let dup = p.fcntl64(fd, F_DUPFD_CLOEXEC, 0);
    p.check("fcntl64 F_DUPFD_CLOEXEC duplicates", dup >= 0);
    p.close(dup as i32);
    let pid = p.getpid();
    let other = p.open64(&file, O_RDWR, 0);
    p.require("open64 f again: a second open file description", other >= 0);
    let (wr_lock, rd_lock, unlocked) = (F_WRLCK as i16, F_RDLCK as i16, F_UNLCK as i16);
    p.check(
        "fcntl64 F_SETLK takes a write lock on 10 bytes past 8 GiB",
        p.fcntl64_lock(fd, F_SETLK, wr_lock, PAST_8GIB, 10).0 == 0,
    );
    let (r, lock) = p.fcntl64_lock(other, F_OFD_GETLK, wr_lock, PAST_8GIB + 5, 1);
    p.check(
        "F_OFD_GETLK through the other description finds it, its range whole",
        r == 0
            && lock.l_type == wr_lock
            && (lock.l_start, lock.l_len) == (PAST_8GIB, 10)
            && i64::from(lock.l_pid) == pid,
    );
    let (r, lock) = p.fcntl64_lock(other, F_OFD_GETLK, wr_lock, 0, 10);
    p.check("and no lock below it", r == 0 && lock.l_type == unlocked);
    p.check(
        "fcntl64 F_SETLK takes a whole-file write lock",
        p.fcntl64_lock(fd, F_SETLK, wr_lock, 0, 0).0 == 0,
    );
    let (r, lock) = p.fcntl64_lock(fd, F_GETLK, wr_lock, 0, 0);
    p.check(
        "F_GETLK never reports the caller's own lock",
        r == 0 && lock.l_type == unlocked,
    );
    let (r, lock) = p.fcntl64_lock(other, F_OFD_GETLK, rd_lock, 0, 0);
    p.check(
        "F_OFD_GETLK through the other description reports it: the whole file, the caller's pid",
        r == 0
            && lock.l_type == wr_lock
            && (lock.l_start, lock.l_len) == (0, 0)
            && i64::from(lock.l_pid) == pid,
    );
    p.check(
        "F_OFD_SETLK a write lock through the other description is EAGAIN",
        p.fcntl64_lock(other, F_OFD_SETLK, wr_lock, 0, 0).0 == neg(EAGAIN),
    );
    p.check(
        "fcntl64 F_SETLK a write lock through a read-only descriptor is EBADF",
        p.fcntl64_lock(reader, F_SETLK, wr_lock, 0, 0).0 == neg(EBADF),
    );
    // An unlock cuts the whole-file lock in two, reported piece by piece in
    // list order; relocking the gap merges the pieces back into one.
    p.fcntl64_lock(fd, F_SETLK, unlocked, 100, 50);
    let (r, lock) = p.fcntl64_lock(other, F_OFD_GETLK, wr_lock, 120, 1);
    p.check(
        "F_SETLK F_UNLCK frees the range it names",
        r == 0 && lock.l_type == unlocked,
    );
    let (r, lock) = p.fcntl64_lock(other, F_OFD_GETLK, wr_lock, 0, 200);
    p.check(
        "the lock is split in two, the lower piece reported first",
        r == 0 && lock.l_type == wr_lock && (lock.l_start, lock.l_len) == (0, 100),
    );
    let (r, lock) = p.fcntl64_lock(other, F_OFD_GETLK, wr_lock, 150, 1);
    p.check(
        "the upper piece runs to the end of the file",
        r == 0 && (lock.l_start, lock.l_len) == (150, 0),
    );
    p.fcntl64_lock(fd, F_SETLK, wr_lock, 100, 50);
    let (r, lock) = p.fcntl64_lock(other, F_OFD_GETLK, wr_lock, 120, 1);
    p.check(
        "relocking the gap merges the pieces back into one",
        r == 0 && lock.l_type == wr_lock && (lock.l_start, lock.l_len) == (0, 0),
    );
    let path_only = p.open64(&file, O_PATH, 0);
    p.require("open64 f O_PATH", path_only >= 0);
    p.close(path_only);
    let (r, lock) = p.fcntl64_lock(other, F_OFD_GETLK, wr_lock, 0, 0);
    p.check(
        "closing an O_PATH descriptor of the file keeps the process's POSIX locks",
        r == 0 && lock.l_type == wr_lock,
    );
    p.close(reader);
    let (r, lock) = p.fcntl64_lock(other, F_OFD_GETLK, wr_lock, 0, 0);
    p.check(
        "closing another descriptor of the file releases the process's POSIX locks",
        r == 0 && lock.l_type == unlocked,
    );
    // F_OFD_SETLKW waits while the process holds the range: the main thread
    // sleeps holding it (so a helper that has not yet asked still meets it)
    // and then lets go. An OFD lock belongs to its description, and F_GETLK
    // reports it with pid -1.
    p.fcntl64_lock(fd, F_SETLK, wr_lock, 0, 10);
    let waited = std::thread::scope(|scope| {
        let helper = scope.spawn(|| {
            p.rec
                .quiet(|| p.fcntl64_lock(other, F_OFD_SETLKW, wr_lock, 0, 10).0)
        });
        p.rec.quiet(|| p.nanosleep(0, 10_000_000));
        p.fcntl64_lock(fd, F_SETLK, unlocked, 0, 10);
        helper.join().expect("the helper")
    });
    p.check(
        "F_OFD_SETLKW takes the range once the POSIX lock is released",
        waited == 0,
    );
    let (r, lock) = p.fcntl64_lock(fd, F_GETLK, wr_lock, 0, 10);
    p.check(
        "F_GETLK reports another description's OFD lock with pid -1",
        r == 0
            && lock.l_type == wr_lock
            && (lock.l_start, lock.l_len) == (0, 10)
            && lock.l_pid == -1,
    );
    let fourth = p.open64(&file, O_RDWR, 0);
    p.require("open64 f a fourth time", fourth >= 0);
    p.fcntl64_lock(fourth, F_OFD_SETLK, wr_lock, 20, 5);
    p.close(fourth);
    let (r, lock) = p.fcntl64_lock(other, F_OFD_GETLK, wr_lock, 0, 0);
    p.check(
        "the last close of a description releases its OFD locks",
        r == 0 && lock.l_type == unlocked,
    );
    p.check(
        "fcntl64 of a closed number is EBADF",
        p.fcntl64(4000, F_GETFD, 0) == neg(EBADF),
    );
    p.check(
        "fcntl64 with an unknown command is EINVAL",
        p.fcntl64(fd, UNKNOWN_FCNTL, 0) == neg(EINVAL),
    );

    for fd in [fd, other, dir, rd, wr] {
        p.close(fd);
    }
}

pub const SCENARIO: Scenario = Scenario {
    name: "fs/lfs64",
    run,
    vehicles: &[Vehicle::Libc],
    covers: &[
        Syscall::N_openat,
        Syscall::N_newfstatat,
        Syscall::N_fstat,
        Syscall::N_statfs,
        Syscall::N_fstatfs,
        Syscall::N_preadv,
        Syscall::N_pwritev,
        Syscall::N_lseek,
        Syscall::N_ftruncate,
        Syscall::N_truncate,
        Syscall::N_fallocate,
        Syscall::N_fcntl,
        Syscall::N_symlinkat,
        Syscall::N_pipe2,
        Syscall::N_close,
        Syscall::N_getpid,
    ],
    symbols: &[
        "open64",
        "openat64",
        "stat64",
        "lstat64",
        "fstat64",
        "fstatat64",
        "statfs64",
        "fstatfs64",
        "preadv64",
        "pwritev64",
        "lseek64",
        "ftruncate64",
        "truncate64",
        "fallocate64",
        "posix_fallocate64",
        "fcntl64",
        "symlinkat",
        "pipe2",
        "close",
        "getpid",
    ],
    gaps: &[Gap {
        status: Status::ByDesign,
        vehicles: &[Vehicle::Libc],
        what: "allocation is not tracked: the volume holds a regular file's bytes densely (patina-fs-mem Inode.contents) and neither the crash model nor the restart snapshot carries which blocks a file has allocated, so sparse files, FALLOC_FL_KEEP_SIZE, FALLOC_FL_PUNCH_HOLE and the holes an extending write or truncate leaves are not modeled: SEEK_DATA/SEEK_HOLE answer as for a file without holes, and st_blocks/stx_blocks count the length",
        failure: Failure::Differs(&[
            Difference::field(100, "lseek64", "ret", Observed::Int(0)),
            Difference::field(100, "lseek64", "errno", Observed::Null),
            Difference::check(101, "SEEK_DATA in a file that is all hole is ENXIO"),
        ]),
    }],
    ..DEFAULTS
};
