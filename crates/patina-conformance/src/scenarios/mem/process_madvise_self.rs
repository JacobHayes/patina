//! mem/process_madvise_self — what an accepted `process_madvise` through the
//! process's own pidfd does (man 2 process_madvise; mm/madvise.c
//! `vector_madvise`): it answers the number of bytes advised for each
//! non-destructive advice, leaving the bytes as they were; a vector stops at
//! the first range that is not mapped — the bytes advised before it, or
//! `ENOMEM` when there are none; an empty vector advises 0 bytes. Through
//! one's own pidfd every advice is accepted, destructive ones included:
//! `MADV_DONTNEED` zero-fills a private page.
//!
//! Linux 6.13 (`mm/madvise: unrestrict process_madvise() for current
//! process`) made advising oneself unprivileged and admitted every advice for
//! it; before that it needed `CAP_SYS_NICE` and took the non-destructive set
//! only, so 6.13 is the scenario's floor.

use crate::catalog::{Arc, DEFAULTS, Gap, KernelFloor, Scenario, Status};
use crate::compare::{Ending, Failure};
use crate::probe::{At, Probe, neg, page_size};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

pub fn run(p: &Probe) {
    let page = page_size();
    let (r, a) = p.mmap(
        "a",
        &At::null(),
        3 * page,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    p.require("map three pages", r >= 0);
    let a = a.unwrap();
    a.fill(0, b"advised");
    a.fill(page, b"kept");
    p.check("unmap the last page", p.munmap(&a.at(2 * page), page) == 0);
    let pid = p.getpid() as i32;
    let pidfd = p.pidfd_open(pid, 0);
    p.require("open this process's pidfd", pidfd >= 0);

    let both = [(a.at(0), 2 * page)];
    for (advice, label) in [
        (MADV_COLD, "MADV_COLD advises every byte"),
        (MADV_PAGEOUT, "MADV_PAGEOUT advises every byte"),
        (MADV_WILLNEED, "MADV_WILLNEED advises every byte"),
    ] {
        p.check(
            label,
            p.process_madvise(pidfd, &both, advice, 0) == 2 * page as i64,
        );
    }
    p.check("the advised bytes survive", a.bytes(0, 7) == b"advised");
    p.check(
        "MADV_DONTNEED through its own pidfd is accepted",
        p.process_madvise(pidfd, &[(a.at(0), page)], MADV_DONTNEED, 0) == page as i64,
    );
    p.check(
        "and zero-fills that private page alone",
        a.zeroed(0, page) && a.bytes(page, 4) == b"kept",
    );
    p.check(
        "a vector stops at an unmapped range, answering the bytes before it",
        p.process_madvise(
            pidfd,
            &[(a.at(0), page), (a.at(2 * page), page), (a.at(page), page)],
            MADV_COLD,
            0,
        ) == page as i64,
    );
    p.check(
        "an unmapped first range is ENOMEM",
        p.process_madvise(pidfd, &[(a.at(2 * page), page)], MADV_COLD, 0) == neg(ENOMEM),
    );
    p.check(
        "an empty vector advises 0 bytes",
        p.process_madvise(pidfd, &[], MADV_COLD, 0) == 0,
    );
    p.close(pidfd);
    p.check("unmap the rest", p.munmap(&a.at(0), 2 * page) == 0);
}

pub const SCENARIO: Scenario = Scenario {
    name: "mem/process_madvise_self",
    run,
    covers: &[Syscall::N_process_madvise],
    vehicles: Vehicle::KERNEL,
    kernel_floor: Some(KernelFloor {
        release: "6.13",
        why: "process_madvise through one's own pidfd is unprivileged and takes every advice",
    }),
    gaps: &[Gap {
        status: Status::Pending(Arc::SignalsThreadsProcess),
        vehicles: Vehicle::KERNEL,
        what: "pidfd_open is Trap(unmodeled) in the registry, the self pidfd the signals arc models (a pidfd kind for the process itself), so the SUD dispatcher aborts before process_madvise is reached (its own row is Trap(unmodeled) too, closing in the memory+ipc arc)",
        failure: Failure::Stops {
            events: 4,
            ending: Ending::Signal(libc::SIGABRT),
            diagnostic: "patina: SUD trapped unsupported syscall pidfd_open (nr",
        },
    }],
    ..DEFAULTS
};
