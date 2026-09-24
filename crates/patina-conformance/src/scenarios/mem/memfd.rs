//! mem/memfd — anonymous files and their seals (man 2 memfd_create, man 2
//! fcntl "File Sealing"; mm/memfd.c, mm/shmem.c):
//!
//! * a memfd is an empty regular file that reads, writes, seeks and resizes
//!   like one; `MFD_CLOEXEC` sets `FD_CLOEXEC`; an unknown flag and a name
//!   past 249 bytes are `EINVAL`;
//! * without `MFD_ALLOW_SEALING` it carries `F_SEAL_SEAL` and refuses new
//!   seals (`EPERM`); with it, seals start empty;
//! * `F_SEAL_WRITE` cannot be added while a shared writable mapping is live
//!   (`EBUSY`); once added, `write` and a new shared writable mapping are
//!   `EPERM` while a private writable mapping is still allowed;
//!   `F_SEAL_SHRINK`/`F_SEAL_GROW` refuse the resize they name (`EPERM`) and
//!   allow the same size; `F_SEAL_SEAL` refuses every later seal, but an
//!   unknown seal bit is `EINVAL` first;
//! * `F_SEAL_FUTURE_WRITE` may be added under a live writable mapping, which
//!   keeps working, while `write` and new shared writable mappings are
//!   `EPERM`;
//! * `F_GET_SEALS` on a pipe is `EINVAL` (a regular file on tmpfs is shmem
//!   and answers its seals, so the probe is a pipe, not the run directory).
//!
//! The execute bits of a memfd's mode follow the `vm.memfd_noexec` sysctl (a
//! host setting), so its mode is compared within `0o666`.

use crate::catalog::{DEFAULTS, KernelFloor, Scenario};
use crate::probe::{At, Probe, neg, page_size};
use libc::*;
use patina_dst_syscalls::Syscall;

/// A `memfd_create` flag no kernel defines (`MFD_CLOEXEC` 1,
/// `MFD_ALLOW_SEALING` 2, `MFD_HUGETLB` 4, `MFD_NOEXEC_SEAL` 8, `MFD_EXEC`
/// 0x10).
const UNKNOWN_MFD: u32 = 0x20;
/// A seal bit no kernel defines (`F_SEAL_SEAL` 0x1 through `F_SEAL_EXEC`
/// 0x20, 6.3, are all there are).
const UNKNOWN_SEAL: i64 = 0x100;
/// `MFD_NAME_MAX_LEN`: `NAME_MAX` less the `memfd:` prefix.
const NAME_MAX_LEN: usize = 249;

pub fn run(p: &Probe) {
    let page = page_size();
    let null = At::null();

    // ---- an anonymous file ----
    let fd = p.memfd_create("plain", MFD_CLOEXEC);
    p.require("memfd_create", fd >= 0);
    p.check(
        "MFD_CLOEXEC sets FD_CLOEXEC",
        p.fcntl(fd, F_GETFD, 0) == i64::from(FD_CLOEXEC),
    );
    let (r, st) = p.fstat_masked(fd, 0o666);
    p.check(
        "a memfd is an empty regular file",
        r == 0 && st.is_some_and(|st| st.st_mode & S_IFMT == S_IFREG && st.st_size == 0),
    );
    p.check("it takes writes", p.write(fd, b"hello") == 5);
    p.check("and seeks", p.lseek(fd, 0, SEEK_SET) == 0);
    p.check("and reads them back", p.read(fd, 16).1 == b"hello");
    p.check("reading at its end is EOF", p.read(fd, 16).0 == 0);
    p.check("ftruncate grows it", p.ftruncate(fd, 2 * page as i64) == 0);
    let (r, st) = p.fstat_masked(fd, 0o666);
    p.check(
        "fstat reports the new size",
        r == 0 && st.is_some_and(|st| st.st_size == 2 * page as i64),
    );
    p.check(
        "without MFD_ALLOW_SEALING it carries F_SEAL_SEAL",
        p.fcntl(fd, F_GET_SEALS, 0) == i64::from(F_SEAL_SEAL),
    );
    p.check(
        "and takes no new seal",
        p.fcntl(fd, F_ADD_SEALS, i64::from(F_SEAL_WRITE)) == neg(EPERM),
    );
    p.check("close it", p.close(fd) == 0);
    p.check(
        "an unknown flag is EINVAL",
        i64::from(p.memfd_create("bad", MFD_CLOEXEC | UNKNOWN_MFD)) == neg(EINVAL),
    );
    let long = "n".repeat(NAME_MAX_LEN + 1);
    p.check(
        "a name past 249 bytes is EINVAL",
        i64::from(p.memfd_create(&long, MFD_CLOEXEC)) == neg(EINVAL),
    );
    let longest = p.memfd_create(&"n".repeat(NAME_MAX_LEN), MFD_CLOEXEC);
    p.check("a name of 249 bytes is accepted", longest >= 0);
    if longest >= 0 {
        p.close(longest);
    }

    // ---- seals ----
    let fd = p.memfd_create("sealed", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    p.require("memfd_create with MFD_ALLOW_SEALING", fd >= 0);
    p.check("its seals start empty", p.fcntl(fd, F_GET_SEALS, 0) == 0);
    p.check("size it to a page", p.ftruncate(fd, page as i64) == 0);
    let (r, shared) = p.mmap("m", &null, page, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    p.require("map it shared and writable", r >= 0);
    let shared = shared.unwrap();
    shared.fill(0, b"mapped");
    p.check(
        "F_SEAL_WRITE under a live shared writable mapping is EBUSY",
        p.fcntl(fd, F_ADD_SEALS, i64::from(F_SEAL_WRITE)) == neg(EBUSY),
    );
    p.check("unmap it", p.munmap(&shared.at(0), page) == 0);
    p.check(
        "F_SEAL_WRITE is added once no such mapping is live",
        p.fcntl(fd, F_ADD_SEALS, i64::from(F_SEAL_WRITE)) == 0,
    );
    p.check("a write is EPERM", p.write(fd, b"x") == neg(EPERM));
    p.check(
        "a new shared writable mapping is EPERM",
        p.mmap("-", &null, page, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)
            .0
            == neg(EPERM),
    );
    let (r, reader) = p.mmap("r", &null, page, PROT_READ, MAP_SHARED, fd, 0);
    p.check(
        "a shared read-only mapping shows the bytes",
        r >= 0 && reader.is_some_and(|reader| reader.bytes(0, 6) == b"mapped"),
    );
    if let Some(reader) = reader {
        p.munmap(&reader.at(0), page);
    }
    let (r, private) = p.mmap("p", &null, page, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    p.check("a private writable mapping is allowed", r >= 0);
    if let Some(private) = private {
        private.store(0, b'P');
        p.munmap(&private.at(0), page);
    }
    p.check(
        "growing is allowed before F_SEAL_GROW",
        p.ftruncate(fd, 2 * page as i64) == 0,
    );
    p.check(
        "add F_SEAL_SHRINK",
        p.fcntl(fd, F_ADD_SEALS, i64::from(F_SEAL_SHRINK)) == 0,
    );
    p.check(
        "shrinking is EPERM",
        p.ftruncate(fd, page as i64) == neg(EPERM),
    );
    p.check(
        "add F_SEAL_GROW",
        p.fcntl(fd, F_ADD_SEALS, i64::from(F_SEAL_GROW)) == 0,
    );
    p.check(
        "growing is EPERM",
        p.ftruncate(fd, 3 * page as i64) == neg(EPERM),
    );
    p.check(
        "the same size is allowed",
        p.ftruncate(fd, 2 * page as i64) == 0,
    );
    p.check(
        "F_GET_SEALS reports every seal added",
        p.fcntl(fd, F_GET_SEALS, 0) == i64::from(F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW),
    );
    p.check(
        "add F_SEAL_SEAL",
        p.fcntl(fd, F_ADD_SEALS, i64::from(F_SEAL_SEAL)) == 0,
    );
    p.check(
        "no seal can be added after F_SEAL_SEAL",
        p.fcntl(fd, F_ADD_SEALS, i64::from(F_SEAL_FUTURE_WRITE)) == neg(EPERM),
    );
    p.check(
        "an unknown seal bit is EINVAL, judged before F_SEAL_SEAL",
        p.fcntl(fd, F_ADD_SEALS, UNKNOWN_SEAL) == neg(EINVAL),
    );
    p.check("close it", p.close(fd) == 0);

    // ---- F_SEAL_FUTURE_WRITE ----
    let fd = p.memfd_create("future", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    p.require("another sealable memfd", fd >= 0);
    p.check("size it to a page", p.ftruncate(fd, page as i64) == 0);
    let (r, live) = p.mmap("w", &null, page, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    p.require("map it shared and writable", r >= 0);
    let live = live.unwrap();
    p.check(
        "F_SEAL_FUTURE_WRITE is added under a live writable mapping",
        p.fcntl(fd, F_ADD_SEALS, i64::from(F_SEAL_FUTURE_WRITE)) == 0,
    );
    live.fill(0, b"still");
    p.check("a write is EPERM", p.write(fd, b"x") == neg(EPERM));
    p.check(
        "the live mapping still writes the file",
        p.lseek(fd, 0, SEEK_SET) == 0 && p.read(fd, 5).1 == b"still",
    );
    p.check(
        "a new shared writable mapping is EPERM",
        p.mmap("-", &null, page, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)
            .0
            == neg(EPERM),
    );
    p.check("unmap it", p.munmap(&live.at(0), page) == 0);
    p.check("close it", p.close(fd) == 0);

    // ---- not a memfd ----
    // A pipe: every shmem file (a regular file on tmpfs too) answers seals,
    // and the run directory's filesystem is the host's business; a pipe has
    // none on every kernel.
    let (r, [rd, wr]) = p.pipe2(O_CLOEXEC);
    p.require("pipe2", r == 0);
    p.check(
        "F_GET_SEALS on a pipe is EINVAL",
        p.fcntl(rd, F_GET_SEALS, 0) == neg(EINVAL),
    );
    p.close(rd);
    p.close(wr);
}

pub const SCENARIO: Scenario = Scenario {
    name: "mem/memfd",
    run,
    covers: &[
        Syscall::N_memfd_create,
        Syscall::N_fcntl,
        Syscall::N_ftruncate,
        Syscall::N_mmap,
    ],
    symbols: &[
        "memfd_create",
        "fcntl",
        "fstat",
        "write",
        "read",
        "lseek",
        "ftruncate",
        "close",
        "mmap",
        "munmap",
        "pipe2",
    ],
    kernel_floor: Some(KernelFloor {
        release: "5.1",
        why: "F_SEAL_FUTURE_WRITE first appears in Linux 5.1",
    }),
    ..DEFAULTS
};
