//! fs/sync — fsync / fdatasync / sync / syncfs / sync_file_range: which
//! descriptors each accepts. fsync(2): any file or directory descriptor,
//! whatever its access mode; EINVAL for a pipe (no `fsync` file operation:
//! fs/sync.c vfs_fsync_range); EBADF for O_PATH or a closed number. sync(2)
//! never fails (issued once). syncfs(2) resolves the descriptor's
//! superblock, so a pipe (pipefs) is fine and O_PATH is EBADF (fdget).
//! sync_file_range(2): EINVAL for an unknown flag or a negative offset or
//! length (judged after the descriptor itself — fdget first — but before its
//! kind), ESPIPE for anything but a
//! regular file, directory, block device or symlink, and no access mode
//! needed.

use crate::catalog::{Arc, DEFAULTS, Gap, Scenario, Status};
use crate::compare::{Ending, Failure};
use crate::vehicle::Vehicle;

use patina_dst_syscalls::Syscall;

use crate::probe::{AT_FDCWD, Probe, neg};
use libc::*;

/// A flag bit sync_file_range does not define.
const UNKNOWN_SYNC_FLAG: u32 = 8;

pub fn run(p: &Probe) {
    let root = p.dir();
    let file = format!("{root}/f");
    let fd = p.openat(AT_FDCWD, &file, O_RDWR | O_CREAT | O_EXCL, 0o644);
    p.require("create f", fd >= 0);
    p.check("write the contents", p.write(fd, b"durable") == 7);
    let reader = p.openat(AT_FDCWD, &file, O_RDONLY, 0);
    let writer = p.openat(AT_FDCWD, &file, O_WRONLY, 0);
    let location = p.openat(AT_FDCWD, &file, O_PATH, 0);
    let dirfd = p.openat(AT_FDCWD, &root, O_RDONLY | O_DIRECTORY, 0);
    p.require(
        "the descriptors",
        reader >= 0 && writer >= 0 && location >= 0 && dirfd >= 0,
    );
    let (r, pipe) = p.pipe2(0);
    p.require("pipe2", r == 0);

    // ---- fsync / fdatasync -------------------------------------------------
    p.check("fsync a written file", p.fsync(fd) == 0);
    p.check("fsync through a read-only descriptor", p.fsync(reader) == 0);
    p.check("fsync a directory", p.fsync(dirfd) == 0);
    p.check("fsync a pipe is EINVAL", p.fsync(pipe[0]) == neg(EINVAL));
    p.check(
        "fsync an O_PATH descriptor is EBADF",
        p.fsync(location) == neg(EBADF),
    );
    p.check(
        "fsync a closed descriptor is EBADF",
        p.fsync(4000) == neg(EBADF),
    );
    p.check("fdatasync a written file", p.fdatasync(fd) == 0);
    p.check(
        "fdatasync through a read-only descriptor",
        p.fdatasync(reader) == 0,
    );
    p.check("fdatasync a directory", p.fdatasync(dirfd) == 0);
    p.check(
        "fdatasync a pipe's write end is EINVAL",
        p.fdatasync(pipe[1]) == neg(EINVAL),
    );
    p.check(
        "fdatasync an O_PATH descriptor is EBADF",
        p.fdatasync(location) == neg(EBADF),
    );
    p.check(
        "fdatasync a closed descriptor is EBADF",
        p.fdatasync(4000) == neg(EBADF),
    );

    // ---- sync / syncfs -----------------------------------------------------
    p.check("sync answers 0", p.sync() == 0);
    p.check("syncfs through a file", p.syncfs(fd) == 0);
    p.check("syncfs through a directory", p.syncfs(dirfd) == 0);
    p.check("syncfs through a pipe (pipefs)", p.syncfs(pipe[0]) == 0);
    p.check(
        "syncfs through an O_PATH descriptor is EBADF",
        p.syncfs(location) == neg(EBADF),
    );
    p.check(
        "syncfs of a closed descriptor is EBADF",
        p.syncfs(4000) == neg(EBADF),
    );

    // ---- sync_file_range ---------------------------------------------------
    let all = SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_AFTER;
    p.check(
        "sync_file_range writes and waits on the whole file",
        p.sync_file_range(fd, 0, 0, all) == 0,
    );
    p.check(
        "sync_file_range with no flags is a no-op",
        p.sync_file_range(fd, 0, 7, 0) == 0,
    );
    p.check(
        "sync_file_range needs no write access",
        p.sync_file_range(reader, 0, 0, SYNC_FILE_RANGE_WRITE) == 0,
    );
    p.check(
        "sync_file_range through a write-only descriptor",
        p.sync_file_range(writer, 0, 0, SYNC_FILE_RANGE_WRITE) == 0,
    );
    p.check(
        "sync_file_range on a directory",
        p.sync_file_range(dirfd, 0, 0, 0) == 0,
    );
    p.check(
        "sync_file_range on a pipe is ESPIPE",
        p.sync_file_range(pipe[0], 0, 0, 0) == neg(ESPIPE),
    );
    p.check(
        "an unknown flag is EINVAL",
        p.sync_file_range(fd, 0, 0, UNKNOWN_SYNC_FLAG) == neg(EINVAL),
    );
    p.check(
        "a negative offset is EINVAL",
        p.sync_file_range(fd, -1, 0, SYNC_FILE_RANGE_WRITE) == neg(EINVAL),
    );
    p.check(
        "a negative length is EINVAL",
        p.sync_file_range(fd, 0, -1, SYNC_FILE_RANGE_WRITE) == neg(EINVAL),
    );
    p.check(
        "the range is judged before the descriptor's kind",
        p.sync_file_range(pipe[0], -1, 0, 0) == neg(EINVAL),
    );
    p.check(
        "sync_file_range through an O_PATH descriptor is EBADF",
        p.sync_file_range(location, 0, 0, 0) == neg(EBADF),
    );
    p.check(
        "the descriptor is judged before the range: closed",
        p.sync_file_range(4000, -1, 0, 0) == neg(EBADF),
    );
    p.check(
        "the descriptor is judged before the range: O_PATH",
        p.sync_file_range(location, -1, 0, 0) == neg(EBADF),
    );
    p.check(
        "sync_file_range of a closed descriptor is EBADF",
        p.sync_file_range(4000, 0, 0, 0) == neg(EBADF),
    );

    for f in [fd, reader, writer, location, dirfd, pipe[0], pipe[1]] {
        p.close(f);
    }
}

pub const SCENARIO: Scenario = Scenario {
    name: "fs/sync",
    run,
    covers: &[
        Syscall::N_fsync,
        Syscall::N_fdatasync,
        Syscall::N_sync,
        Syscall::N_syncfs,
        Syscall::N_sync_file_range,
        Syscall::N_openat,
        Syscall::N_write,
        Syscall::N_pipe2,
        Syscall::N_close,
    ],
    symbols: &[
        "fsync",
        "fdatasync",
        "syscall",
        "openat",
        "write",
        "pipe2",
        "close",
    ],
    gaps: &[Gap {
        status: Status::Pending(Arc::Fs),
        vehicles: Vehicle::ALL,
        what: "sync, syncfs and sync_file_range are unmodeled Trap rows: the first sync aborts (fsync/fdatasync before it conform)",
        failure: Failure::Stops {
            events: 32,
            ending: Ending::Signal(6),
            diagnostic: "unsupported syscall sync",
        },
    }],
    ..DEFAULTS
};
