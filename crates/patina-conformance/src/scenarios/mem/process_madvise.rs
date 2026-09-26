//! mem/process_madvise — advice through a pidfd, judged as 6.8 judges it
//! (man 2 process_madvise; mm/madvise.c): a flag is `EINVAL` (judged
//! first), a descriptor that is not a pidfd `EBADF`, an advice outside the
//! non-destructive set a pidfd takes `EINVAL` (an unknown one, and
//! `MADV_DONTNEED`); then, even through the process's own pidfd, a caller
//! without `CAP_SYS_NICE` is `EPERM` for every advice of the set — before
//! any range is looked at, so an unmapped range and an empty vector too —
//! and nothing is advised. (Linux 6.13 made advising oneself unprivileged
//! and admitted every advice for it; the pinned 6.8 does neither.)
//!
//! Only the process's own pidfd: advising another process is a
//! cross-process effect the single-process model has no counterpart for.
//!
//! The libc vehicle goes through glibc 2.36's `process_madvise`.

use crate::catalog::{DEFAULTS, KernelFloor, Need, Scenario};
use crate::probe::{Probe, neg, page_size};
use libc::*;
use patina_dst_syscalls::Syscall;

pub fn run(p: &Probe) {
    let page = page_size();
    let a = p.map_anon("a", 2 * page, MAP_PRIVATE);
    a.fill(0, b"advised");
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
    for (advice, label) in [
        (12345, "an unknown advice is EINVAL"),
        (
            MADV_DONTNEED,
            "MADV_DONTNEED is EINVAL, judged before privilege",
        ),
    ] {
        p.check(
            label,
            p.process_madvise(pidfd, &range, advice, 0) == neg(EINVAL),
        );
    }
    for (advice, label) in [
        (MADV_COLD, "MADV_COLD without CAP_SYS_NICE is EPERM"),
        (MADV_PAGEOUT, "MADV_PAGEOUT without CAP_SYS_NICE is EPERM"),
        (MADV_WILLNEED, "MADV_WILLNEED without CAP_SYS_NICE is EPERM"),
    ] {
        p.check(
            label,
            p.process_madvise(pidfd, &range, advice, 0) == neg(EPERM),
        );
    }
    p.require("unmap the second page", p.munmap(&a.at(page), page) == 0);
    p.check(
        "an unmapped range is EPERM: privilege is judged before any range",
        p.process_madvise(pidfd, &[(a.at(page), page)], MADV_COLD, 0) == neg(EPERM),
    );
    p.check(
        "an empty vector is EPERM",
        p.process_madvise(pidfd, &[], MADV_COLD, 0) == neg(EPERM),
    );
    p.check("nothing was advised", a.bytes(0, 7) == b"advised");
    for fd in [rd, wr, pidfd] {
        p.close(fd);
    }
    p.check("unmap the page", p.munmap(&a.at(0), page) == 0);
}

pub const SCENARIO: Scenario = Scenario {
    name: "mem/process_madvise",
    run,
    covers: &[Syscall::N_process_madvise],
    symbols: &["process_madvise"],
    needs: &[Need::Unprivileged],
    kernel_floor: Some(KernelFloor {
        release: "5.10",
        why: "process_madvise first appears in Linux 5.10 (the registry row carries no date)",
    }),
    ..DEFAULTS
};
