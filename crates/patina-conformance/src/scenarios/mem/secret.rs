//! mem/secret — `memfd_secret` (man 2 memfd_secret; mm/secretmem.c): the
//! only flag is `O_CLOEXEC` (`FD_CLOEXEC` on the descriptor; anything else
//! is `EINVAL`); the file starts empty, is sized with `ftruncate` once (a
//! sized one cannot be resized, `EINVAL`), and its bytes are reachable only
//! through a `MAP_SHARED` mapping — `read` and `write` are `EINVAL`, and so
//! is a `MAP_PRIVATE` mapping. It is a filesystem of its own with no copy
//! operation: `copy_file_range` with another is `EXDEV`, empty or not. It
//! has no file position (`pread`, `lseek`: `ESPIPE`, after `lseek`'s
//! `EINVAL` for an unknown whence), nothing to write back (`fsync`, and
//! `msync(MS_SYNC)` of its
//! mapping, `EINVAL`), no `fallocate` (`EOPNOTSUPP`) and no seals
//! (`EINVAL`), and lives on a `noexec` mount: an executable mapping is
//! `EPERM`, and a mapping cannot become executable (`EACCES`). No page walk
//! reaches its pages, so `mlock`'s populate of them fails (`ENOMEM`). Its
//! mapping's pages are locked against `RLIMIT_MEMLOCK`, judged after a
//! `MAP_FIXED` mapping unmapped what it replaces: a secret page mapped over
//! itself fits a limit of one page.
//!
//! Secret memory can be disabled on a host (`secretmem.enable=0`, or no
//! direct-map support) and its pages are locked memory, so the scenario
//! needs one page of it to map.

use crate::catalog::{DEFAULTS, Need, Scenario};
use crate::probe::{At, Probe, RW, Shown, neg, page_size};
use libc::*;
use patina_dst_syscalls::Syscall;

pub fn run(p: &Probe) {
    let page = page_size();
    let null = At::null();
    p.check(
        "a flag other than O_CLOEXEC is EINVAL",
        i64::from(p.memfd_secret(O_NONBLOCK as u32)) == neg(EINVAL),
    );
    let fd = p.memfd_secret(O_CLOEXEC as u32);
    p.require("memfd_secret", fd >= 0);
    p.check(
        "O_CLOEXEC sets FD_CLOEXEC",
        p.fcntl(fd, F_GETFD, 0) == i64::from(FD_CLOEXEC),
    );
    let file = p.open_or_stop(&format!("{}/file", p.dir()), O_RDWR | O_CREAT | O_EXCL);
    p.check(
        "copying it, empty, to another filesystem is EXDEV",
        p.copy_file_range(fd, None, file, None, 1, 0).0 == neg(EXDEV),
    );
    let (r, st) = p.fstat_masked(fd, 0o777);
    p.check(
        "it starts as an empty regular file",
        r == 0 && st.is_some_and(|st| st.st_mode & S_IFMT == S_IFREG && st.st_size == 0),
    );
    p.check("size it to a page", p.ftruncate(fd, page as i64) == 0);
    let (r, secret) = p.mmap("s", &null, page, RW, MAP_SHARED, fd, 0);
    p.require("map it shared", r >= 0);
    let secret = secret.unwrap();
    p.check("its page reads zero", secret.zeroed(0, page));
    secret.fill(0, b"hidden");
    p.check("and holds a store", secret.bytes(0, 6) == b"hidden");
    p.check("read is EINVAL", p.read(fd, 6).0 == neg(EINVAL));
    p.check("write is EINVAL", p.write(fd, b"x") == neg(EINVAL));
    p.check(
        "a private mapping is EINVAL",
        p.mmap("-", &null, page, RW, MAP_PRIVATE, fd, 0).0 == neg(EINVAL),
    );
    p.check(
        "a sized file cannot be resized",
        p.ftruncate(fd, 2 * page as i64) == neg(EINVAL),
    );
    p.check(
        "pread has no position",
        p.pread64(fd, 6, 0).0 == neg(ESPIPE),
    );
    p.check("lseek has none", p.lseek(fd, 0, SEEK_SET) == neg(ESPIPE));
    p.check(
        "an unknown whence is EINVAL first",
        p.lseek(fd, 0, SEEK_HOLE + 1) == neg(EINVAL),
    );
    p.check("fsync is EINVAL", p.fsync(fd) == neg(EINVAL));
    p.check(
        "fallocate is EOPNOTSUPP",
        p.fallocate(fd, 0, 0, page as i64) == neg(EOPNOTSUPP),
    );
    p.check(
        "it has no seals",
        p.fcntl(fd, F_GET_SEALS, 0) == neg(EINVAL),
    );
    p.check(
        "mlock of its mapping is ENOMEM",
        p.mlock(&secret.at(0), page) == neg(ENOMEM),
    );
    p.check(
        "msync(MS_SYNC) of its mapping is EINVAL",
        p.msync(&secret.at(0), page, MS_SYNC) == neg(EINVAL),
    );
    p.check(
        "an executable mapping is EPERM",
        p.mmap("-", &null, page, PROT_READ | PROT_EXEC, MAP_SHARED, fd, 0)
            .0
            == neg(EPERM),
    );
    p.check(
        "the mapping cannot become executable",
        p.mprotect(&secret.at(0), page, PROT_READ | PROT_EXEC) == neg(EACCES),
    );
    let (r, soft, hard) = p.getrlimit(RLIMIT_MEMLOCK as i32, Shown::Relation);
    p.require("getrlimit(RLIMIT_MEMLOCK)", r == 0);
    p.check(
        "lock no more than the page it maps",
        p.setrlimit_kept(RLIMIT_MEMLOCK as i32, page as u64, hard) == 0,
    );
    p.check(
        "a fixed mapping over its page fits that limit",
        p.mmap("s", &secret.at(0), page, RW, MAP_SHARED | MAP_FIXED, fd, 0)
            .0
            >= 0,
    );
    p.rec
        .quiet(|| p.setrlimit_kept(RLIMIT_MEMLOCK as i32, soft, hard));
    p.check("unmap it", p.munmap(&secret.at(0), page) == 0);
    p.check("close the other file", p.close(file) == 0);
    p.check("close it", p.close(fd) == 0);
}

pub const SCENARIO: Scenario = Scenario {
    name: "mem/secret",
    run,
    covers: &[Syscall::N_memfd_secret],
    symbols: &[
        "syscall",
        "copy_file_range",
        "getrlimit",
        "setrlimit",
        "fcntl",
        "fstat",
        "ftruncate",
        "mmap",
        "munmap",
        "read",
        "write",
        "pread64",
        "lseek",
        "fsync",
        "fallocate",
        "msync",
        "mprotect",
        "mlock",
        "close",
    ],
    needs: &[Need::SecretMemory],
    ..DEFAULTS
};
