//! mem/mincore — page residency (man 2 mincore; mm/mincore.c): one vector
//! byte per page of the (rounded-up) range, bit 0 set for a resident page.
//! A private anonymous page is resident once touched and not before, and
//! `MADV_DONTNEED` drops it; a touched shared anonymous page is resident.
//! A misaligned address is `EINVAL`, a range that is not entirely mapped
//! `ENOMEM`, a NULL vector `EFAULT`; length 0 succeeds without writing.
//!
//! Which pages a touch makes resident is exact only while the region faults
//! in base pages: a transparent huge page size enabled `always` may populate
//! the neighbours too. `MADV_NOHUGEPAGE` on the region (unasserted: a kernel
//! without THP answers EINVAL and has no such hazard) makes the vectors the
//! same on every host, whatever its THP settings.

use crate::catalog::{DEFAULTS, Scenario};
use crate::probe::{At, Probe, neg, page_size};
use libc::*;
use patina_dst_syscalls::Syscall;

pub fn run(p: &Probe) {
    let page = page_size();
    let null = At::null();
    let (r, a) = p.mmap(
        "a",
        &null,
        4 * page,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    p.require("map four pages", r >= 0);
    let a = a.unwrap();
    p.madvise(&a.at(0), 4 * page, MADV_NOHUGEPAGE);
    let (r, resident) = p.mincore(&a.at(0), 4 * page, Some(4));
    p.check(
        "no untouched page is resident",
        r == 0 && resident == [0, 0, 0, 0],
    );
    a.store(0, 1);
    a.store(2 * page + 5, 1);
    let (r, resident) = p.mincore(&a.at(0), 4 * page, Some(4));
    p.check(
        "exactly the touched pages are resident",
        r == 0 && resident == [1, 0, 1, 0],
    );
    p.check(
        "MADV_DONTNEED drops a page",
        p.madvise(&a.at(0), page, MADV_DONTNEED) == 0,
    );
    let (r, resident) = p.mincore(&a.at(0), 4 * page, Some(4));
    p.check(
        "the dropped page is no longer resident",
        r == 0 && resident == [0, 0, 1, 0],
    );
    let (r, resident) = p.mincore(&a.at(2 * page), page + 1, Some(2));
    p.check(
        "a partial page counts as a page",
        r == 0 && resident == [1, 0],
    );
    p.check(
        "a misaligned address is EINVAL",
        p.mincore(&a.at(1), page, Some(1)).0 == neg(EINVAL),
    );
    p.check(
        "a NULL vector is EFAULT",
        p.mincore(&a.at(0), page, None).0 == neg(EFAULT),
    );
    let (r, resident) = p.mincore(&a.at(0), 0, Some(1));
    p.check(
        "length 0 succeeds and writes nothing",
        r == 0 && resident == [0],
    );

    let (r, s) = p.mmap(
        "s",
        &null,
        page,
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS,
        -1,
        0,
    );
    p.require("map a shared page", r >= 0);
    let s = s.unwrap();
    s.store(0, 1);
    let (r, resident) = p.mincore(&s.at(0), page, Some(1));
    p.check(
        "a touched shared page is resident",
        r == 0 && resident == [1],
    );
    p.check("unmap the shared page", p.munmap(&s.at(0), page) == 0);

    p.check("unmap the last page", p.munmap(&a.at(3 * page), page) == 0);
    p.check(
        "a range reaching past the mapping is ENOMEM",
        p.mincore(&a.at(0), 4 * page, Some(4)).0 == neg(ENOMEM),
    );
    p.check("unmap the rest", p.munmap(&a.at(0), 3 * page) == 0);
}

pub const SCENARIO: Scenario = Scenario {
    name: "mem/mincore",
    run,
    covers: &[Syscall::N_mincore],
    symbols: &["syscall", "mmap", "munmap"],
    ..DEFAULTS
};
