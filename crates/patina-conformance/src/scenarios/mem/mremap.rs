//! mem/mremap — resizing and moving mappings (man 2 mremap; mm/mremap.c):
//!
//! * shrinking stays in place; growing stays in place when the next pages
//!   are free and is `ENOMEM` without `MREMAP_MAYMOVE` when they are not;
//!   with it the mapping moves, bytes intact, and the old range is unmapped;
//! * `MREMAP_FIXED` needs `MREMAP_MAYMOVE`, refuses a target overlapping the
//!   source, and replaces whatever the target held;
//! * `MREMAP_DONTUNMAP` (same length, `MREMAP_MAYMOVE`) moves the pages and
//!   leaves the old private range mapped and empty;
//! * an old length of 0 duplicates a SHARED mapping — a second view of the
//!   same pages, coherent with the first — and is `EINVAL` for a private one;
//! * refusals: a misaligned address, a zero new length, unknown flags
//!   (`EINVAL`), an unmapped source (`EFAULT`).

use crate::catalog::{DEFAULTS, KernelFloor, Scenario};
use crate::probe::{ANON, At, Probe, RW, neg, page_size};
use libc::*;
use patina_dst_syscalls::Syscall;

/// A flag bit `mremap` does not define (`MREMAP_MAYMOVE` 1, `MREMAP_FIXED`
/// 2, `MREMAP_DONTUNMAP` 4 are all there are).
const UNKNOWN_FLAG: i32 = 0x80;

pub fn run(p: &Probe) {
    let page = page_size();
    let null = At::null();
    let a = p.map_anon("a", 4 * page, MAP_PRIVATE);
    a.fill(0, b"alpha");
    a.fill(page, b"beta");

    // ---- in place, then moved ----
    // One straight run with every label built first: the holes it opens
    // must stay free of anything the recorder could map in between.
    let (a0, a3) = (a.at(0), a.at(3 * page));
    let blocker_spec = (page, RW, ANON | MAP_FIXED_NOREPLACE, -1, 0);
    let vacated_spec = (3 * page, RW, ANON | MAP_FIXED_NOREPLACE, -1, 0);
    let remap = |old_len: usize, new_len: usize, flags: i32| {
        p.call_unrecorded(
            Syscall::N_mremap,
            [
                a0.raw as i64,
                old_len as i64,
                new_len as i64,
                flags as i64,
                0,
                0,
            ],
        )
    };
    let holds = |at: usize, bytes: &[u8]| {
        bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| a.load(at + index) == *byte)
    };
    let shrunk = remap(4 * page, 2 * page, 0);
    let shrunk_kept = shrunk >= 0 && holds(0, b"alpha") && holds(page, b"beta");
    let grown = remap(2 * page, 3 * page, 0);
    let grown_zero = grown >= 0 && a.zeroed(2 * page, page);
    let blocked = p.call_unrecorded(Syscall::N_mmap, Probe::mmap_args(&a3, blocker_spec));
    let refused = remap(3 * page, 4 * page, 0);
    let moved = remap(3 * page, 4 * page, MREMAP_MAYMOVE);
    let vacated_mapped = p.call_unrecorded(Syscall::N_mmap, Probe::mmap_args(&a0, vacated_spec));

    let (r, shrunk) = p.record_mremap(shrunk, "a", &a0, (4 * page, 2 * page, 0), &null);
    p.check(
        "shrinking stays in place and keeps the bytes",
        r >= 0 && shrunk.is_some_and(|s| s.base == a.base) && shrunk_kept,
    );
    let (r, grown) = p.record_mremap(grown, "a", &a0, (2 * page, 3 * page, 0), &null);
    p.check(
        "growing into free pages stays in place; the new page is zero",
        r >= 0 && grown.is_some_and(|g| g.base == a.base) && grown_zero,
    );
    let (r, blocker) = p.record_mmap(blocked, "b", &a3, blocker_spec);
    p.require("map the page after it", r >= 0);
    let blocker = blocker.unwrap();
    p.check(
        "growing into a taken page without MREMAP_MAYMOVE is ENOMEM",
        p.record_mremap(refused, "-", &a0, (3 * page, 4 * page, 0), &null)
            .0
            == neg(ENOMEM),
    );
    let (r, moved) = p.record_mremap(moved, "m", &a0, (3 * page, 4 * page, MREMAP_MAYMOVE), &null);
    p.require("grow with MREMAP_MAYMOVE", r >= 0);
    let moved = moved.unwrap();
    p.check(
        "the grown mapping moved with its bytes",
        moved.base != a.base && moved.bytes(0, 5) == b"alpha" && moved.bytes(page, 4) == b"beta",
    );
    let (r, vacated) = p.record_mmap(vacated_mapped, "v", &a0, vacated_spec);
    p.check(
        "the old range was unmapped",
        r >= 0 && vacated.is_some_and(|v| v.base == a.base),
    );
    let vacated = a;

    // ---- fixed targets ----
    p.check(
        "MREMAP_FIXED without MREMAP_MAYMOVE is EINVAL",
        p.mremap("-", &moved.at(0), page, page, MREMAP_FIXED, &vacated.at(0))
            .0
            == neg(EINVAL),
    );
    p.check(
        "a fixed target overlapping the source is EINVAL",
        p.mremap(
            "-",
            &moved.at(0),
            2 * page,
            2 * page,
            MREMAP_MAYMOVE | MREMAP_FIXED,
            &moved.at(page),
        )
        .0 == neg(EINVAL),
    );
    vacated.fill(0, b"doomed");
    let (r, fixed) = p.mremap(
        "t",
        &moved.at(0),
        2 * page,
        2 * page,
        MREMAP_MAYMOVE | MREMAP_FIXED,
        &vacated.at(0),
    );
    p.check(
        "a fixed move replaces the target's pages with the source's",
        r >= 0
            && fixed.is_some_and(|f| f.base == vacated.base)
            && vacated.bytes(0, 5) == b"alpha"
            && vacated.bytes(page, 4) == b"beta",
    );
    // `moved` now keeps only its last two pages.

    // ---- MREMAP_DONTUNMAP ----
    let (r, kept) = p.mremap(
        "k",
        &vacated.at(0),
        page,
        page,
        MREMAP_MAYMOVE | MREMAP_DONTUNMAP,
        &null,
    );
    p.check(
        "MREMAP_DONTUNMAP moves the page",
        r >= 0 && kept.is_some_and(|k| k.base != vacated.base && k.bytes(0, 5) == b"alpha"),
    );
    p.check(
        "and leaves the old private page mapped and empty",
        vacated.zeroed(0, page),
    );
    p.check(
        "MREMAP_DONTUNMAP with a new length is EINVAL",
        p.mremap(
            "-",
            &vacated.at(0),
            page,
            2 * page,
            MREMAP_MAYMOVE | MREMAP_DONTUNMAP,
            &null,
        )
        .0 == neg(EINVAL),
    );
    p.check(
        "MREMAP_DONTUNMAP without MREMAP_MAYMOVE is EINVAL",
        p.mremap("-", &vacated.at(0), page, page, MREMAP_DONTUNMAP, &null)
            .0
            == neg(EINVAL),
    );

    // ---- refusals ----
    p.check(
        "a misaligned old address is EINVAL",
        p.mremap("-", &vacated.at(1), page, page, MREMAP_MAYMOVE, &null)
            .0
            == neg(EINVAL),
    );
    p.check(
        "a zero new length is EINVAL",
        p.mremap("-", &vacated.at(0), page, 0, MREMAP_MAYMOVE, &null)
            .0
            == neg(EINVAL),
    );
    p.check(
        "an unknown flag is EINVAL",
        p.mremap("-", &vacated.at(0), page, page, UNKNOWN_FLAG, &null)
            .0
            == neg(EINVAL),
    );
    p.check(
        "an old length of 0 on a private mapping is EINVAL",
        p.mremap("-", &vacated.at(0), 0, page, MREMAP_MAYMOVE, &null)
            .0
            == neg(EINVAL),
    );
    p.require("unmap the blocker", p.munmap(&blocker.at(0), page) == 0);
    p.check(
        "an unmapped source is EFAULT",
        p.mremap("-", &blocker.at(0), page, 2 * page, MREMAP_MAYMOVE, &null)
            .0
            == neg(EFAULT),
    );

    // ---- a second view of shared pages ----
    let s = p.map_anon("s", page, MAP_SHARED);
    s.fill(0, b"one");
    let (r, twin) = p.mremap("d", &s.at(0), 0, page, MREMAP_MAYMOVE, &null);
    p.check(
        "an old length of 0 on a shared mapping maps it again elsewhere",
        r >= 0 && twin.is_some_and(|t| t.base != s.base && t.bytes(0, 3) == b"one"),
    );
    if let Some(twin) = twin {
        twin.fill(0, b"two");
        p.check(
            "the two views share their pages",
            s.bytes(0, 3) == b"two" && s.load(0) == twin.load(0),
        );
        p.check("unmap the second view", p.munmap(&twin.at(0), page) == 0);
    }
    p.check(
        "the first view outlives the second",
        s.bytes(0, 3) == b"two" && p.munmap(&s.at(0), page) == 0,
    );

    if let Some(kept) = kept {
        p.check("unmap the kept page", p.munmap(&kept.at(0), page) == 0);
    }
    p.check(
        "unmap the rest",
        p.munmap(&vacated.at(0), 3 * page) == 0 && p.munmap(&moved.at(0), 4 * page) == 0,
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "mem/mremap",
    run,
    covers: &[Syscall::N_mremap, Syscall::N_mmap, Syscall::N_munmap],
    symbols: &["mremap", "mmap", "munmap"],
    kernel_floor: Some(KernelFloor {
        release: "5.7",
        why: "MREMAP_DONTUNMAP first appears in Linux 5.7 (and MAP_FIXED_NOREPLACE in 4.17)",
    }),
    ..DEFAULTS
};
