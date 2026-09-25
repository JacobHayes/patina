//! fs/cache — readahead / fadvise64 / cachestat: page-cache advice and
//! accounting. readahead(2) needs a readable descriptor (EBADF otherwise,
//! O_PATH included) of a regular file (EINVAL for a pipe or a directory);
//! beyond EOF it is a no-op. posix_fadvise(2) (fadvise64): every POSIX_FADV_*
//! advice is 0 on a file, whatever its access mode, and on a directory; an
//! unknown advice is EINVAL; a pipe is ESPIPE, judged before the advice
//! (mm/fadvise.c generic_fadvise); O_PATH is EBADF. cachestat(2) (Linux
//! 6.5, mm/filemap.c): flags must be 0 (EINVAL, after the descriptor), NULL
//! range or result is EFAULT, O_PATH or a closed number EBADF; the counters
//! are the host page cache's business except right after a write: the two
//! pages just written are cached (on ext4, XFS and tmpfs alike), dirty and
//! writeback pages are cached pages, recently evicted pages are evicted
//! pages, and a range past EOF (or a pipe) has none.

use crate::catalog::{Arc, DEFAULTS, Gap, KernelFloor, Scenario, Status};
use crate::compare::{Ending, Failure};
use crate::vehicle::Vehicle;

use patina_dst_syscalls::Syscall;

use crate::probe::{AT_FDCWD, Cachestat, Probe, neg, page_size};
use libc::*;

/// The pages the scenario's file holds.
const PAGES: usize = 2;

/// An advice value POSIX_FADV_* does not define.
const UNKNOWN_ADVICE: i32 = 99;

fn empty(stat: &Cachestat) -> bool {
    *stat == Cachestat::default()
}

pub fn run(p: &Probe) {
    let root = p.dir();
    let file = format!("{root}/f");
    let page = page_size();
    let fd = p.openat(AT_FDCWD, &file, O_RDWR | O_CREAT | O_EXCL, 0o644);
    p.require("create f", fd >= 0);
    p.check(
        "write two pages",
        p.write(fd, &vec![b'x'; PAGES * page]) == (PAGES * page) as i64,
    );
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

    // ---- the pages just written --------------------------------------------
    // Before any advice: POSIX_FADV_DONTNEED below may evict clean pages.
    let (r, stat) = p.cachestat(fd, Some((0, 0)), true, 0);
    p.check("cachestat of the whole file", r == 0);
    p.check(
        "dirty and writeback pages are cached pages",
        stat.nr_dirty <= stat.nr_cache && stat.nr_writeback <= stat.nr_cache,
    );
    p.check(
        "recently evicted pages are evicted pages",
        stat.nr_recently_evicted <= stat.nr_evicted,
    );
    p.check(
        "the two pages just written are cached",
        stat.nr_cache == PAGES as u64,
    );

    // ---- readahead ---------------------------------------------------------
    p.check(
        "readahead a file",
        p.readahead(reader, 0, PAGES * page) == 0,
    );
    p.check(
        "readahead past EOF is a no-op",
        p.readahead(reader, 1 << 20, page) == 0,
    );
    p.check("a zero-count readahead", p.readahead(reader, 0, 0) == 0);
    p.check(
        "readahead through a write-only descriptor is EBADF",
        p.readahead(writer, 0, page) == neg(EBADF),
    );
    p.check(
        "readahead through O_PATH is EBADF",
        p.readahead(location, 0, page) == neg(EBADF),
    );
    p.check(
        "readahead of a pipe is EINVAL",
        p.readahead(pipe[0], 0, page) == neg(EINVAL),
    );
    p.check(
        "readahead of a directory is EINVAL",
        p.readahead(dirfd, 0, page) == neg(EINVAL),
    );
    p.check(
        "readahead of a closed descriptor is EBADF",
        p.readahead(4000, 0, page) == neg(EBADF),
    );

    // ---- fadvise64 ---------------------------------------------------------
    for advice in [
        POSIX_FADV_NORMAL,
        POSIX_FADV_RANDOM,
        POSIX_FADV_SEQUENTIAL,
        POSIX_FADV_WILLNEED,
        POSIX_FADV_DONTNEED,
        POSIX_FADV_NOREUSE,
    ] {
        p.check(
            "every POSIX_FADV_* advice is accepted",
            p.fadvise64(reader, 0, 0, advice) == 0,
        );
    }
    p.check(
        "advice needs no read access",
        p.fadvise64(writer, 0, page as i64, POSIX_FADV_DONTNEED) == 0,
    );
    p.check(
        "advice on a directory",
        p.fadvise64(dirfd, 0, 0, POSIX_FADV_WILLNEED) == 0,
    );
    p.check(
        "an unknown advice is EINVAL",
        p.fadvise64(reader, 0, 0, UNKNOWN_ADVICE) == neg(EINVAL),
    );
    p.check(
        "advice on a pipe is ESPIPE",
        p.fadvise64(pipe[0], 0, 0, POSIX_FADV_NORMAL) == neg(ESPIPE),
    );
    p.check(
        "a pipe is judged before the advice",
        p.fadvise64(pipe[0], 0, 0, UNKNOWN_ADVICE) == neg(ESPIPE),
    );
    p.check(
        "advice through O_PATH is EBADF",
        p.fadvise64(location, 0, 0, POSIX_FADV_NORMAL) == neg(EBADF),
    );
    p.check(
        "advice on a closed descriptor is EBADF",
        p.fadvise64(4000, 0, 0, POSIX_FADV_NORMAL) == neg(EBADF),
    );

    // ---- cachestat ---------------------------------------------------------
    let (r, past) = p.cachestat(fd, Some((1 << 20, page as u64)), true, 0);
    p.check("a range past EOF has no pages", r == 0 && empty(&past));
    let (r, piped) = p.cachestat(pipe[0], Some((0, 0)), true, 0);
    p.check("a pipe has no page cache", r == 0 && empty(&piped));
    p.check(
        "cachestat of a directory",
        p.cachestat(dirfd, Some((0, 0)), true, 0).0 == 0,
    );
    p.check(
        "nonzero flags are EINVAL",
        p.cachestat(fd, Some((0, 0)), true, 1).0 == neg(EINVAL),
    );
    p.check(
        "a NULL range is EFAULT",
        p.cachestat(fd, None, true, 0).0 == neg(EFAULT),
    );
    p.check(
        "a NULL result is EFAULT",
        p.cachestat(fd, Some((0, 0)), false, 0).0 == neg(EFAULT),
    );
    p.check(
        "cachestat through O_PATH is EBADF",
        p.cachestat(location, Some((0, 0)), true, 0).0 == neg(EBADF),
    );
    p.check(
        "cachestat of a closed descriptor is EBADF",
        p.cachestat(4000, Some((0, 0)), true, 0).0 == neg(EBADF),
    );
    p.check(
        "the descriptor is judged before the flags",
        p.cachestat(4000, Some((0, 0)), true, 1).0 == neg(EBADF),
    );

    for f in [fd, reader, writer, location, dirfd, pipe[0], pipe[1]] {
        p.close(f);
    }
}

pub const SCENARIO: Scenario = Scenario {
    name: "fs/cache",
    run,
    // glibc has no cachestat wrapper and the shim defines neither readahead
    // nor posix_fadvise (fs/posix_fadvise), so the libc spelling would be
    // `syscall(2)` again.
    vehicles: Vehicle::KERNEL,
    covers: &[
        Syscall::N_readahead,
        Syscall::N_fadvise64,
        Syscall::N_cachestat,
        Syscall::N_openat,
        Syscall::N_write,
        Syscall::N_pipe2,
        Syscall::N_close,
    ],
    kernel_floor: Some(KernelFloor {
        release: "6.5",
        why: "cachestat",
    }),
    gaps: &[Gap {
        status: Status::Pending(Arc::Fs),
        vehicles: Vehicle::KERNEL,
        what: "cachestat, readahead and fadvise64 are unmodeled Trap rows: the first cachestat aborts",
        failure: Failure::Stops {
            events: 8,
            ending: Ending::Signal(6),
            diagnostic: "unsupported syscall cachestat",
        },
    }],
    ..DEFAULTS
};
