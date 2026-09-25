//! mem/process_madvise — advice through a pidfd, the refusals every kernel
//! judges before it asks whether the caller may advise the target (man 2
//! process_madvise; mm/madvise.c): a flag is `EINVAL` (judged first), a
//! descriptor that is not a pidfd `EBADF`, an unknown advice `EINVAL`, all
//! through the process's own pidfd. Which known advice is accepted grows by
//! kernel version (`MADV_DONTNEED` joined the set after 6.8), so none is
//! asserted refused. What an accepted call does is
//! `mem/process_madvise_self`.
//!
//! Only the process's own pidfd: advising another process is a
//! cross-process effect the single-process model has no counterpart for.

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
        page,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    p.require("map a page", r >= 0);
    let a = a.unwrap();
    let pid = p.getpid() as i32;
    let pidfd = p.pidfd_open(pid, 0);
    p.require("open this process's pidfd", pidfd >= 0);
    let range = [(a.at(0), page)];
    p.check(
        "a flag is EINVAL, judged before the descriptor",
        p.process_madvise(-1, &range, MADV_COLD, 1) == neg(EINVAL),
    );
    let (r, [rd, wr]) = p.pipe2(O_CLOEXEC);
    p.require("pipe2", r == 0);
    p.check(
        "a descriptor that is not a pidfd is EBADF",
        p.process_madvise(rd, &range, MADV_COLD, 0) == neg(EBADF),
    );
    p.check(
        "a closed descriptor is EBADF",
        p.process_madvise(4000, &range, MADV_COLD, 0) == neg(EBADF),
    );
    p.check(
        "an unknown advice is EINVAL",
        p.process_madvise(pidfd, &range, 12345, 0) == neg(EINVAL),
    );
    for fd in [rd, wr, pidfd] {
        p.close(fd);
    }
    p.check("unmap the page", p.munmap(&a.at(0), page) == 0);
}

pub const SCENARIO: Scenario = Scenario {
    name: "mem/process_madvise",
    run,
    covers: &[Syscall::N_process_madvise],
    vehicles: Vehicle::KERNEL,
    gaps: &[Gap {
        status: Status::Pending(Arc::SignalsThreadsProcess),
        vehicles: Vehicle::KERNEL,
        what: "pidfd_open is Trap(unmodeled) in the registry, the self pidfd the signals arc models (a pidfd kind for the process itself), so the SUD dispatcher aborts before process_madvise is reached (its own row is Trap(unmodeled) too, closing in the memory+ipc arc)",
        failure: Failure::Stops {
            events: 2,
            ending: Ending::Signal(libc::SIGABRT),
            diagnostic: "patina: SUD trapped unsupported syscall pidfd_open (nr",
        },
    }],
    kernel_floor: Some(KernelFloor {
        release: "5.10",
        why: "process_madvise first appears in Linux 5.10 (the registry row carries no date)",
    }),
    ..DEFAULTS
};
