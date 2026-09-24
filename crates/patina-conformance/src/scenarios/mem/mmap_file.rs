//! mem/mmap_file — mappings of a regular file (man 2 mmap, man 2 msync;
//! mm/mmap.c `do_mmap`, mm/filemap.c, mm/msync.c):
//!
//! * a `MAP_SHARED` mapping IS the file's page cache: a store through it is
//!   what `read` returns next, a `write` is what the mapping shows next, no
//!   `msync` needed; two shared mappings of different shapes over the same
//!   pages see each other's stores; truncating the file zeroes the mapped
//!   bytes past its new end within the last page;
//! * a `MAP_PRIVATE` mapping's stores stay private;
//! * `msync` of a file mapping: `MS_SYNC`, `MS_ASYNC`, `MS_INVALIDATE`
//!   succeed; `MS_SYNC|MS_ASYNC` is `EINVAL`;
//! * refusals: `MAP_SHARED` + `PROT_WRITE` of a read-only descriptor and any
//!   mapping of a write-only one (`EACCES`), a misaligned offset
//!   (`EINVAL`), a pipe or a directory (`ENODEV`), a closed descriptor
//!   (`EBADF`), an unknown flag under `MAP_SHARED_VALIDATE` (`EOPNOTSUPP`,
//!   where plain `MAP_SHARED` ignores it).
//!
//! The first mapping goes through `mmap64`, glibc's LFS spelling of the row.

use crate::catalog::{DEFAULTS, KernelFloor, Scenario};
use crate::probe::{AT_FDCWD, At, Probe, Region, neg, page_size};
use libc::*;
use patina_dst_syscalls::Syscall;

const RW: i32 = PROT_READ | PROT_WRITE;
/// A flag bit no architecture defines: bit 21, between `MAP_FIXED_NOREPLACE`
/// (bit 20) and the huge-page size field (`MAP_HUGE_SHIFT`, 26); the newest
/// flag, `MAP_DROPPABLE` (6.11), is 0x08.
const UNKNOWN_MAP_FLAG: i32 = 0x0020_0000;

/// An anonymous page a mapping that may fail under patina falls back to
/// (`Region::or_spare`), so a failure differs in its checks only. Unmapping
/// the stand-in consumes the spare; a spare no failure needed stays mapped
/// (process-local memory the exit releases), because unmapping it again
/// could hit whatever reused its address.
fn spare(p: &Probe, name: &'static str) -> Region {
    let (r, spare) = p.mmap(
        name,
        &At::null(),
        page_size(),
        RW,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    p.require("map a spare page", r >= 0);
    spare.unwrap()
}

pub fn run(p: &Probe) {
    let page = page_size();
    let null = At::null();
    let root = p.dir();
    let path = format!("{root}/mapped");
    let fd = p.openat(AT_FDCWD, &path, O_RDWR | O_CREAT | O_CLOEXEC, 0o600);
    p.require("create the file", fd >= 0);
    let mut contents = vec![b'A'; page];
    contents.extend(std::iter::repeat_n(b'B', page));
    p.check("fill two pages", p.write(fd, &contents) == 2 * page as i64);

    let (r, m) = p.mmap64("m", &null, 2 * page, RW, MAP_SHARED, fd, 0);
    p.require("map the file shared", r >= 0);
    let m = m.unwrap();
    p.check(
        "the mapping shows the file",
        m.load(0) == b'A' && m.load(page) == b'B' && m.load(2 * page - 1) == b'B',
    );

    // ---- one page cache ----
    m.store(0, b'x');
    p.check("rewind", p.lseek(fd, 0, SEEK_SET) == 0);
    p.check(
        "a store through a shared mapping is what read returns",
        p.read(fd, 1).1 == b"x",
    );
    p.check(
        "seek to the second page",
        p.lseek(fd, page as i64, SEEK_SET) == page as i64,
    );
    p.check("write through the descriptor", p.write(fd, b"y") == 1);
    p.check(
        "a write is what the shared mapping shows",
        m.load(page) == b'y',
    );
    let stand_in = spare(p, "spare-n");
    let (r, second) = p.mmap("n", &null, page, RW, MAP_SHARED, fd, page as i64);
    let second = Region::or_spare(second, stand_in, "n");
    p.check(
        "a second shared mapping of the second page",
        r >= 0 && second.load(0) == b'y',
    );
    second.store(1, b'z');
    p.check(
        "its stores show through the first mapping",
        m.load(page + 1) == b'z',
    );
    m.store(page + 2, b'w');
    p.check("and the first mapping's through it", second.load(2) == b'w');
    p.check(
        "unmap the second mapping",
        p.munmap(&second.at(0), page) == 0,
    );

    // ---- private stores ----
    let stand_in = spare(p, "spare-p");
    let (r, private) = p.mmap("p", &null, page, RW, MAP_PRIVATE, fd, 0);
    let private = Region::or_spare(private, stand_in, "p");
    p.check(
        "a private mapping shows the file",
        r >= 0 && private.load(0) == b'x',
    );
    private.store(0, b'q');
    p.check(
        "a private store reaches neither the file nor the shared mapping",
        p.lseek(fd, 0, SEEK_SET) == 0 && p.read(fd, 1).1 == b"x" && m.load(0) == b'x',
    );
    p.check(
        "unmap the private mapping",
        p.munmap(&private.at(0), page) == 0,
    );

    // ---- msync ----
    p.check(
        "MS_SYNC of a file mapping succeeds",
        p.msync(&m.at(0), 2 * page, MS_SYNC) == 0,
    );
    p.check("MS_ASYNC succeeds", p.msync(&m.at(0), page, MS_ASYNC) == 0);
    p.check(
        "MS_INVALIDATE succeeds",
        p.msync(&m.at(0), 2 * page, MS_INVALIDATE) == 0,
    );
    p.check(
        "MS_SYNC with MS_ASYNC is EINVAL",
        p.msync(&m.at(0), page, MS_SYNC | MS_ASYNC) == neg(EINVAL),
    );

    // ---- truncation ----
    let tail = page as i64 + 10;
    p.check("truncate into the second page", p.ftruncate(fd, tail) == 0);
    p.check(
        "the mapped bytes past the new end read zero",
        m.bytes(page, 3) == b"yzw" && m.zeroed(page + 10, page - 10),
    );
    p.check("unmap the file", p.munmap(&m.at(0), 2 * page) == 0);

    // ---- refusals ----
    let reader = p.openat(AT_FDCWD, &path, O_RDONLY | O_CLOEXEC, 0);
    let writer = p.openat(AT_FDCWD, &path, O_WRONLY | O_CLOEXEC, 0);
    p.require(
        "open it read-only and write-only",
        reader >= 0 && writer >= 0,
    );
    p.check(
        "MAP_SHARED with PROT_WRITE of a read-only descriptor is EACCES",
        p.mmap("-", &null, page, RW, MAP_SHARED, reader, 0).0 == neg(EACCES),
    );
    let stand_in = spare(p, "spare-c");
    let (r, copy) = p.mmap("c", &null, page, RW, MAP_PRIVATE, reader, 0);
    let copy = Region::or_spare(copy, stand_in, "c");
    p.check(
        "MAP_PRIVATE with PROT_WRITE of a read-only descriptor is allowed",
        r >= 0 && copy.load(0) == b'x',
    );
    p.check("unmap it", p.munmap(&copy.at(0), page) == 0);
    p.check(
        "any mapping of a write-only descriptor is EACCES",
        p.mmap("-", &null, page, PROT_READ, MAP_SHARED, writer, 0).0 == neg(EACCES),
    );
    p.check(
        "a misaligned offset is EINVAL",
        p.mmap("-", &null, page, PROT_READ, MAP_SHARED, fd, 1).0 == neg(EINVAL),
    );
    p.check(
        "an unknown flag under MAP_SHARED_VALIDATE is EOPNOTSUPP",
        p.mmap(
            "-",
            &null,
            page,
            PROT_READ,
            MAP_SHARED_VALIDATE | UNKNOWN_MAP_FLAG,
            fd,
            0,
        )
        .0 == neg(EOPNOTSUPP),
    );
    let stand_in = spare(p, "spare-l");
    let (r, lax) = p.mmap(
        "l",
        &null,
        page,
        PROT_READ,
        MAP_SHARED | UNKNOWN_MAP_FLAG,
        fd,
        0,
    );
    let lax = Region::or_spare(lax, stand_in, "l");
    p.check("plain MAP_SHARED ignores it", r >= 0);
    p.check("unmap it", p.munmap(&lax.at(0), page) == 0);
    let (r, [rd, wr]) = p.pipe2(O_CLOEXEC);
    p.require("pipe2", r == 0);
    p.check(
        "a pipe is ENODEV",
        p.mmap("-", &null, page, PROT_READ, MAP_SHARED, rd, 0).0 == neg(ENODEV),
    );
    let dir = p.openat(AT_FDCWD, &root, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    p.require("open the directory", dir >= 0);
    p.check(
        "a directory is ENODEV",
        p.mmap("-", &null, page, PROT_READ, MAP_SHARED, dir, 0).0 == neg(ENODEV),
    );
    for fd in [rd, wr, dir, reader, writer, fd] {
        p.close(fd);
    }
    p.check(
        "a closed descriptor is EBADF",
        p.mmap("-", &null, page, PROT_READ, MAP_SHARED, 4000, 0).0 == neg(EBADF),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "mem/mmap_file",
    run,
    covers: &[Syscall::N_mmap, Syscall::N_msync, Syscall::N_munmap],
    symbols: &[
        "mmap",
        "mmap64",
        "munmap",
        "msync",
        "openat",
        "write",
        "read",
        "lseek",
        "ftruncate",
        "pipe2",
        "close",
    ],
    kernel_floor: Some(KernelFloor {
        release: "4.15",
        why: "MAP_SHARED_VALIDATE and its EOPNOTSUPP for an unknown flag first appear in Linux 4.15",
    }),
    ..DEFAULTS
};
