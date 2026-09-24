//! mem/remap_file_pages — the deprecated nonlinear-mapping row, emulated
//! since Linux 4.0 by a fresh `mmap` of the page range (man 2
//! remap_file_pages; mm/mmap.c `SYSCALL_DEFINE5(remap_file_pages)`): over a
//! shared mapping it makes a page show another page of the same object;
//! `prot` must be 0 and a zero size is `EINVAL`, as is a private mapping or
//! an address outside every mapping; flags other than `MAP_NONBLOCK` are
//! dropped, not refused. A shared anonymous mapping is a
//! shmem object, so no file is needed.

use crate::catalog::{Arc, DEFAULTS, Gap, KernelFloor, Scenario, Status};
use crate::compare::{Ending, Failure};
use crate::probe::{At, Probe, neg, page_size};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

const RW: i32 = PROT_READ | PROT_WRITE;

pub fn run(p: &Probe) {
    let page = page_size();
    let null = At::null();
    let (r, s) = p.mmap("s", &null, 2 * page, RW, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    p.require("map two shared pages", r >= 0);
    let s = s.unwrap();
    s.fill(0, b"first");
    s.fill(page, b"second");
    p.check(
        "page 0 remapped to the object's page 1",
        p.remap_file_pages(&s.at(0), page, 0, 1, 0) == 0,
    );
    p.check(
        "shows page 1's bytes",
        s.bytes(0, 6) == b"second" && s.bytes(page, 6) == b"second",
    );
    s.store(0, b'S');
    p.check("and is the same page as page 1", s.load(page) == b'S');
    p.check(
        "a nonzero prot is EINVAL",
        p.remap_file_pages(&s.at(0), page, PROT_READ, 0, 0) == neg(EINVAL),
    );
    p.check(
        "a zero size is EINVAL",
        p.remap_file_pages(&s.at(0), 0, 0, 0, 0) == neg(EINVAL),
    );
    p.check(
        "flags other than MAP_NONBLOCK are dropped, not refused",
        p.remap_file_pages(&s.at(0), page, 0, 0, MAP_FIXED | MAP_POPULATE) == 0,
    );
    p.check(
        "page 0 shows the object's page 0 again",
        s.bytes(0, 5) == b"first",
    );

    let (r, private) = p.mmap("p", &null, page, RW, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    p.require("map a private page", r >= 0);
    let private = private.unwrap();
    p.check(
        "a private mapping is EINVAL",
        p.remap_file_pages(&private.at(0), page, 0, 0, 0) == neg(EINVAL),
    );
    p.check(
        "unmap the private page",
        p.munmap(&private.at(0), page) == 0,
    );
    p.check(
        "an address outside every mapping is EINVAL",
        p.remap_file_pages(&private.at(0), page, 0, 0, 0) == neg(EINVAL),
    );
    p.check("unmap the shared pages", p.munmap(&s.at(0), 2 * page) == 0);
}

pub const SCENARIO: Scenario = Scenario {
    name: "mem/remap_file_pages",
    run,
    covers: &[Syscall::N_remap_file_pages],
    symbols: &["syscall", "mmap", "munmap"],
    gaps: &[Gap {
        status: Status::Pending(Arc::MemoryIpc),
        vehicles: Vehicle::ALL,
        what: "remap_file_pages is Trap(unmodeled) in the registry (patina-syscalls linux.rs), so the SUD dispatcher aborts by name on every door (its libc spelling is syscall(2): the shim defines no remap_file_pages wrapper)",
        failure: Failure::Stops {
            events: 1,
            ending: Ending::Signal(libc::SIGABRT),
            diagnostic: "patina: SUD trapped unsupported syscall remap_file_pages (nr",
        },
    }],
    kernel_floor: Some(KernelFloor {
        release: "4.0",
        why: "remap_file_pages is an emulation over a fresh mmap since Linux 4.0",
    }),
    ..DEFAULTS
};
