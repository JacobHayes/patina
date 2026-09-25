//! mem/mmap — anonymous mappings (man 2 mmap, man 2 munmap, man 2 madvise;
//! mm/mmap.c `do_mmap`, `do_vmi_munmap`; mm/madvise.c):
//!
//! * pages are zero-filled and page-aligned; `MAP_FIXED` replaces what it
//!   lands on with fresh zero pages, `MAP_FIXED_NOREPLACE` refuses an
//!   occupied range with `EEXIST` and takes a free one;
//! * refusals: length 0, neither `MAP_SHARED` nor `MAP_PRIVATE`,
//!   `MAP_SHARED_VALIDATE` on an anonymous mapping (only a file mapping
//!   validates flags), a misaligned offset or fixed address (`EINVAL`), a
//!   length past the address space (`ENOMEM`);
//! * `munmap` splits a mapping, succeeds over a hole, refuses a misaligned
//!   address or length 0;
//! * `madvise`: `MADV_DONTNEED` zero-fills a private page but keeps a shared
//!   one's bytes (they live in the shmem object), the hint advice succeeds,
//!   `MADV_REMOVE` of a private mapping, an unknown advice and a misaligned
//!   start are `EINVAL`, a range with a hole is `ENOMEM`, length 0 succeeds;
//! * the descriptor of a `MAP_ANONYMOUS` mapping is ignored (Linux only
//!   requires -1 of portable callers).

use crate::catalog::{DEFAULTS, KernelFloor, Scenario};
use crate::probe::{At, Probe, neg, page_size};
use libc::*;
use patina_dst_syscalls::Syscall;

const ANON: i32 = MAP_PRIVATE | MAP_ANONYMOUS;
const RW: i32 = PROT_READ | PROT_WRITE;
/// A flag bit no architecture defines: bit 21, between `MAP_FIXED_NOREPLACE`
/// (bit 20) and the huge-page size field (`MAP_HUGE_SHIFT`, 26); the newest
/// flag, `MAP_DROPPABLE` (6.11), is 0x08.
const UNKNOWN_MAP_FLAG: i32 = 0x0020_0000;

pub fn run(p: &Probe) {
    let page = page_size();
    let null = At::null();
    let (r, a) = p.mmap("a", &null, 3 * page, RW, ANON, -1, 0);
    p.require("map three private pages", r >= 0);
    let a = a.unwrap();
    p.check("an anonymous mapping is zero-filled", a.zeroed(0, 3 * page));
    a.fill(0, b"private");
    a.fill(2 * page, b"third");
    p.check(
        "its pages hold what was stored",
        a.bytes(0, 7) == b"private" && a.bytes(2 * page, 5) == b"third",
    );

    // ---- refusals ----
    p.check(
        "a zero length is EINVAL",
        p.mmap("-", &null, 0, RW, ANON, -1, 0).0 == neg(EINVAL),
    );
    p.check(
        "neither MAP_SHARED nor MAP_PRIVATE is EINVAL",
        p.mmap("-", &null, page, RW, MAP_ANONYMOUS, -1, 0).0 == neg(EINVAL),
    );
    p.check(
        "MAP_SHARED_VALIDATE on an anonymous mapping is EINVAL",
        p.mmap(
            "-",
            &null,
            page,
            RW,
            MAP_SHARED_VALIDATE | MAP_ANONYMOUS,
            -1,
            0,
        )
        .0 == neg(EINVAL),
    );
    p.check("an unknown flag beside MAP_PRIVATE is ignored", {
        let (r, extra) = p.mmap("x", &null, page, RW, ANON | UNKNOWN_MAP_FLAG, -1, 0);
        r >= 0 && p.munmap(&extra.unwrap().at(0), page) == 0
    });
    p.check(
        "a misaligned offset is EINVAL",
        p.mmap("-", &null, page, RW, ANON, -1, 1).0 == neg(EINVAL),
    );
    p.check(
        "MAP_FIXED at a misaligned address is EINVAL",
        p.mmap("-", &a.at(1), page, RW, ANON | MAP_FIXED, -1, 0).0 == neg(EINVAL),
    );
    p.check(
        "a length past the address space is ENOMEM",
        p.mmap("-", &null, 1 << 62, RW, ANON, -1, 0).0 == neg(ENOMEM),
    );

    // ---- fixed placement ----
    p.check(
        "MAP_FIXED_NOREPLACE over a live mapping is EEXIST",
        p.mmap("-", &a.at(0), page, RW, ANON | MAP_FIXED_NOREPLACE, -1, 0)
            .0
            == neg(EEXIST),
    );
    let (r, fixed) = p.mmap("f", &a.at(page), page, RW, ANON | MAP_FIXED, -1, 0);
    p.check(
        "MAP_FIXED over a live page lands exactly there",
        r >= 0 && fixed.is_some_and(|fixed| fixed.base == a.base + page),
    );
    a.store(page, b'm');
    p.check(
        "the replaced page is fresh and the neighbours keep their bytes",
        a.load(page) == b'm' && a.bytes(0, 7) == b"private" && a.bytes(2 * page, 5) == b"third",
    );

    // ---- munmap ----
    // The split and the refill of the hole are one straight run, labels
    // built first, so nothing the recorder maps can take the hole between.
    let a1 = a.at(page);
    let hole_spec = (page, RW, ANON | MAP_FIXED_NOREPLACE, -1, 0);
    let split = p.call_unrecorded(Syscall::N_munmap, [a1.raw as i64, page as i64, 0, 0, 0, 0]);
    let refilled = p.call_unrecorded(Syscall::N_mmap, Probe::mmap_args(&a1, hole_spec));
    p.record_range(Syscall::N_munmap, &a1, page, None, split);
    p.check("munmap of the middle page splits the mapping", split == 0);
    let (r, hole) = p.record_mmap(refilled, "h", &a1, hole_spec);
    p.check(
        "the hole takes a MAP_FIXED_NOREPLACE mapping",
        r >= 0 && hole.is_some_and(|hole| hole.base == a.base + page && hole.zeroed(0, page)),
    );
    p.check("unmap it again", p.munmap(&a1, page) == 0);
    p.check(
        "munmap over a hole succeeds",
        p.munmap(&a.at(page), page) == 0,
    );
    p.check(
        "munmap at a misaligned address is EINVAL",
        p.munmap(&a.at(1), page) == neg(EINVAL),
    );
    p.check(
        "munmap of length 0 is EINVAL",
        p.munmap(&a.at(0), 0) == neg(EINVAL),
    );
    p.check(
        "the pages around the hole keep their bytes",
        a.bytes(0, 7) == b"private" && a.bytes(2 * page, 5) == b"third",
    );

    // ---- madvise ----
    let (r, s) = p.mmap("s", &null, 2 * page, RW, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    p.require("map two shared pages", r >= 0);
    let s = s.unwrap();
    s.fill(0, b"shared");
    p.check(
        "MADV_DONTNEED of a shared page succeeds",
        p.madvise(&s.at(0), page, MADV_DONTNEED) == 0,
    );
    p.check(
        "a shared page keeps its bytes past MADV_DONTNEED",
        s.bytes(0, 6) == b"shared",
    );
    p.check(
        "MADV_DONTNEED of a private page succeeds",
        p.madvise(&a.at(0), page, MADV_DONTNEED) == 0,
    );
    p.check(
        "a private page reads zero after MADV_DONTNEED",
        a.zeroed(0, page),
    );
    for (advice, label) in [
        (MADV_WILLNEED, "MADV_WILLNEED succeeds"),
        (MADV_COLD, "MADV_COLD succeeds"),
    ] {
        p.check(label, p.madvise(&a.at(2 * page), page, advice) == 0);
    }
    p.check(
        "MADV_REMOVE of a private mapping is EINVAL",
        p.madvise(&a.at(2 * page), page, MADV_REMOVE) == neg(EINVAL),
    );
    p.check(
        "MADV_REMOVE of a shared anonymous page succeeds and zeroes it",
        p.madvise(&s.at(0), page, MADV_REMOVE) == 0 && s.zeroed(0, page),
    );
    p.check(
        "an unknown advice is EINVAL",
        p.madvise(&a.at(0), page, 12345) == neg(EINVAL),
    );
    p.check(
        "madvise at a misaligned address is EINVAL",
        p.madvise(&a.at(1), page, MADV_NORMAL) == neg(EINVAL),
    );
    p.check(
        "madvise of length 0 succeeds",
        p.madvise(&a.at(0), 0, MADV_NORMAL) == 0,
    );
    p.check(
        "madvise over a hole is ENOMEM",
        p.madvise(&a.at(0), 3 * page, MADV_WILLNEED) == neg(ENOMEM),
    );

    p.check("unmap the first page", p.munmap(&a.at(0), page) == 0);
    p.check("unmap the third page", p.munmap(&a.at(2 * page), page) == 0);
    p.check("unmap the shared pages", p.munmap(&s.at(0), 2 * page) == 0);

    // Last: the SUD door traps any descriptor but -1 as a file mapping.
    let (r, ignored) = p.mmap("d", &null, page, RW, ANON, 0, 0);
    p.check(
        "MAP_ANONYMOUS ignores the descriptor",
        r >= 0 && ignored.is_some_and(|ignored| ignored.zeroed(0, page)),
    );
    if let Some(ignored) = ignored {
        p.munmap(&ignored.at(0), page);
    }
}

pub const SCENARIO: Scenario = Scenario {
    name: "mem/mmap",
    run,
    covers: &[Syscall::N_mmap, Syscall::N_munmap, Syscall::N_madvise],
    symbols: &["mmap", "munmap"],
    kernel_floor: Some(KernelFloor {
        release: "5.4",
        why: "MAP_FIXED_NOREPLACE (4.17; older kernels ignore it and map over the page) and MADV_COLD (5.4)",
    }),
    ..DEFAULTS
};
