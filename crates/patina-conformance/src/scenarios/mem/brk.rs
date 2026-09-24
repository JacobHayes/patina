//! mem/brk — the program break (man 2 brk; mm/mmap.c `SYSCALL_DEFINE1(brk)`):
//! the raw row never fails with an errno — it answers the new break, or the
//! unchanged one when it refuses. `brk(0)` queries; growing maps fresh
//! zero pages that are writable; shrinking back answers the requested break;
//! a break below the heap's start, or one reaching another mapping, is
//! refused with the current break.
//!
//! glibc's `malloc` grows its main arena with `sbrk`, which caches the break,
//! so every call that MOVES the break is issued unrecorded in one straight
//! run (nothing allocates until the break is back where glibc left it) and
//! recorded afterwards.

use crate::catalog::{DEFAULTS, Scenario};
use crate::probe::{At, Probe, page_size};
use patina_dst_syscalls::Syscall;

/// How many pages the scenario grows the break by.
const GROWTH_PAGES: usize = 16;

pub fn run(p: &Probe) {
    let page = page_size();
    let growth = GROWTH_PAGES * page;
    let null = At::null();
    let query = |at: &At| p.call_unrecorded(Syscall::N_brk, [at.raw as i64, 0, 0, 0, 0, 0]);

    // One straight run: query, grow, touch the fresh pages, shrink back. Every
    // label is built before the break moves (building one allocates).
    let current = query(&null);
    let current_at = At::named(current as usize, "current");
    let grown_at = At::named(current as usize + growth, "current+growth");
    let first_fresh = (current as usize).div_ceil(page) * page;
    let end = current as usize + growth;
    let grown = query(&grown_at);
    let (fresh_zero, stored) = if grown == end as i64 {
        // SAFETY: [first_fresh, end) is the heap growth the kernel just
        // mapped, and `end - 1` its final byte.
        unsafe {
            let zero = (first_fresh..end).all(|at| std::ptr::read_volatile(at as *const u8) == 0);
            std::ptr::write_volatile((end - 1) as *mut u8, 0x5a);
            (
                zero,
                std::ptr::read_volatile((end - 1) as *const u8) == 0x5a,
            )
        }
    } else {
        (false, false)
    };
    let shrunk = query(&current_at);

    let named = [("current", current as usize), ("current+growth", end)];
    p.record_brk(&null, current, &[("current", current as usize)]);
    p.check("brk(0) answers the current break", current > 0);
    p.record_brk(&grown_at, grown, &named);
    p.check(
        "growing the break answers the requested break",
        grown == end as i64,
    );
    p.check("the grown pages are zero-filled", fresh_zero);
    p.check("the grown pages are writable", stored);
    p.record_brk(&current_at, shrunk, &named);
    p.check(
        "shrinking back answers the requested break",
        shrunk == current,
    );

    // The recorder allocates between the calls below, so each compares with a
    // break queried right before it.
    let low = At::named(1, "below-start");
    let before = query(&null);
    let refused = query(&low);
    p.record_brk(&low, refused, &[("current", before as usize)]);
    p.check(
        "a break below the heap's start is refused: the current break",
        refused == before,
    );
    let (r, other) = p.mmap(
        "m",
        &null,
        page,
        libc::PROT_READ,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    p.require("map a page", r >= 0);
    let other = other.unwrap();
    let into = other.end();
    let before = query(&null);
    let refused = query(&into);
    p.record_brk(&into, refused, &[("current", before as usize)]);
    p.check(
        "a break reaching another mapping is refused: the current break",
        refused == before,
    );
    p.check("unmap the page", p.munmap(&other.at(0), page) == 0);
}

pub const SCENARIO: Scenario = Scenario {
    name: "mem/brk",
    run,
    covers: &[Syscall::N_brk],
    symbols: &["syscall", "mmap", "munmap"],
    ..DEFAULTS
};
