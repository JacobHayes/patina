//! mem/secret — `memfd_secret` (man 2 memfd_secret; mm/secretmem.c): the
//! only flag is `O_CLOEXEC` (`FD_CLOEXEC` on the descriptor; anything else
//! is `EINVAL`); the file starts empty, is sized with `ftruncate`, and its
//! bytes are reachable only through a `MAP_SHARED` mapping — `read` and
//! `write` are `EINVAL`, and so is a `MAP_PRIVATE` mapping.
//!
//! Secret memory can be disabled on a host (`secretmem.enable=0`, or no
//! direct-map support) and its pages are locked memory, so the scenario
//! needs one page of it to map.

use crate::catalog::{Arc, DEFAULTS, Gap, Need, Scenario, Status};
use crate::compare::{Ending, Failure};
use crate::probe::{At, Probe, neg, page_size};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

const RW: i32 = PROT_READ | PROT_WRITE;

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
    p.check("unmap it", p.munmap(&secret.at(0), page) == 0);
    p.check("close it", p.close(fd) == 0);
}

pub const SCENARIO: Scenario = Scenario {
    name: "mem/secret",
    run,
    covers: &[Syscall::N_memfd_secret],
    symbols: &[
        "syscall",
        "fcntl",
        "fstat",
        "ftruncate",
        "mmap",
        "munmap",
        "read",
        "write",
        "close",
    ],
    needs: &[Need::SecretMemory],
    gaps: &[Gap {
        status: Status::Pending(Arc::MemoryIpc),
        vehicles: Vehicle::ALL,
        what: "memfd_secret is Trap(unmodeled) in the registry (patina-syscalls linux.rs), so the SUD dispatcher aborts by name on every door (its libc spelling is syscall(2): the shim defines no memfd_secret wrapper)",
        failure: Failure::Stops {
            events: 0,
            ending: Ending::Signal(libc::SIGABRT),
            diagnostic: "patina: SUD trapped unsupported syscall memfd_secret (nr",
        },
    }],
    ..DEFAULTS
};
