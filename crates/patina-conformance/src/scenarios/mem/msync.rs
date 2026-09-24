//! mem/msync — `msync` over anonymous memory and its flag rules (man 2
//! msync; mm/msync.c): an anonymous mapping has nothing to write back, so
//! `MS_SYNC`, `MS_ASYNC`, `MS_INVALIDATE` and no flag at all succeed; an
//! unknown flag, `MS_SYNC` with `MS_ASYNC`, and a misaligned address are
//! `EINVAL`; a range that is not entirely mapped is `ENOMEM`; length 0
//! succeeds. (A file mapping's write-back is `mem/mmap_file`.)

use crate::catalog::{DEFAULTS, Scenario};
use crate::probe::{At, Probe, neg, page_size};
use libc::*;
use patina_dst_syscalls::Syscall;

/// A flag bit `msync` does not define (`MS_ASYNC` 1, `MS_INVALIDATE` 2,
/// `MS_SYNC` 4).
const UNKNOWN_FLAG: i32 = 0x8;

pub fn run(p: &Probe) {
    let page = page_size();
    let (r, a) = p.mmap(
        "a",
        &At::null(),
        2 * page,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    p.require("map two pages", r >= 0);
    let a = a.unwrap();
    a.fill(0, b"anonymous");
    for (flags, label) in [
        (MS_SYNC, "MS_SYNC of anonymous memory succeeds"),
        (MS_ASYNC, "MS_ASYNC succeeds"),
        (MS_INVALIDATE, "MS_INVALIDATE succeeds"),
        (
            MS_SYNC | MS_INVALIDATE,
            "MS_SYNC with MS_INVALIDATE succeeds",
        ),
        (0, "no flag at all succeeds"),
    ] {
        p.check(label, p.msync(&a.at(0), 2 * page, flags) == 0);
    }
    p.check("the bytes survive", a.bytes(0, 9) == b"anonymous");
    p.check(
        "MS_SYNC with MS_ASYNC is EINVAL",
        p.msync(&a.at(0), page, MS_SYNC | MS_ASYNC) == neg(EINVAL),
    );
    p.check(
        "an unknown flag is EINVAL",
        p.msync(&a.at(0), page, MS_SYNC | UNKNOWN_FLAG) == neg(EINVAL),
    );
    p.check(
        "a misaligned address is EINVAL",
        p.msync(&a.at(1), page, MS_SYNC) == neg(EINVAL),
    );
    p.check("length 0 succeeds", p.msync(&a.at(0), 0, MS_SYNC) == 0);
    p.check("unmap the second page", p.munmap(&a.at(page), page) == 0);
    p.check(
        "a range reaching past the mapping is ENOMEM",
        p.msync(&a.at(0), 2 * page, MS_SYNC) == neg(ENOMEM),
    );
    p.check(
        "an unmapped range is ENOMEM",
        p.msync(&a.at(page), page, MS_ASYNC) == neg(ENOMEM),
    );
    p.check("unmap the first page", p.munmap(&a.at(0), page) == 0);
}

pub const SCENARIO: Scenario = Scenario {
    name: "mem/msync",
    run,
    covers: &[Syscall::N_msync],
    symbols: &["msync", "mmap", "munmap"],
    ..DEFAULTS
};
