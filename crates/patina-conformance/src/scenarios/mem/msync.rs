//! mem/msync — `msync` over anonymous memory and its flag rules (man 2
//! msync; mm/msync.c): an anonymous mapping has nothing to write back, so
//! `MS_SYNC`, `MS_ASYNC`, `MS_INVALIDATE` and no flag at all succeed; an
//! unknown flag, `MS_SYNC` with `MS_ASYNC`, and a misaligned address are
//! `EINVAL`; a range that is not entirely mapped is `ENOMEM`; length 0
//! succeeds. (A file mapping's write-back is `mem/mmap_file`.)

use crate::catalog::{Arc, DEFAULTS, Gap, Scenario, Status};
use crate::compare::{Difference, Ending, Failure, Observed};
use crate::probe::{At, Probe, neg, page_size};
use crate::vehicle::Vehicle;
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
    gaps: &[
        Gap {
            status: Status::Pending(Arc::MemoryIpc),
            vehicles: &[Vehicle::Libc],
            what: "the msync interposer (c/posix/mem.c) fails closed with ENOSYS for any range that is not a modeled file-backed mapping, anonymous memory included, before it judges flags, alignment or the range",
            failure: Failure::Differs(&[
                Difference::field(1, "msync", "errno", Observed::Str("ENOSYS")),
                Difference::field(1, "msync", "ret", Observed::Int(-1)),
                Difference::check(2, "MS_SYNC of anonymous memory succeeds"),
                Difference::field(3, "msync", "errno", Observed::Str("ENOSYS")),
                Difference::field(3, "msync", "ret", Observed::Int(-1)),
                Difference::check(4, "MS_ASYNC succeeds"),
                Difference::field(5, "msync", "errno", Observed::Str("ENOSYS")),
                Difference::field(5, "msync", "ret", Observed::Int(-1)),
                Difference::check(6, "MS_INVALIDATE succeeds"),
                Difference::field(7, "msync", "errno", Observed::Str("ENOSYS")),
                Difference::field(7, "msync", "ret", Observed::Int(-1)),
                Difference::check(8, "MS_SYNC with MS_INVALIDATE succeeds"),
                Difference::field(9, "msync", "errno", Observed::Str("ENOSYS")),
                Difference::field(9, "msync", "ret", Observed::Int(-1)),
                Difference::check(10, "no flag at all succeeds"),
                Difference::field(12, "msync", "errno", Observed::Str("ENOSYS")),
                Difference::check(13, "MS_SYNC with MS_ASYNC is EINVAL"),
                Difference::field(14, "msync", "errno", Observed::Str("ENOSYS")),
                Difference::check(15, "an unknown flag is EINVAL"),
                Difference::field(16, "msync", "errno", Observed::Str("ENOSYS")),
                Difference::check(17, "a misaligned address is EINVAL"),
                Difference::field(18, "msync", "errno", Observed::Str("ENOSYS")),
                Difference::field(18, "msync", "ret", Observed::Int(-1)),
                Difference::check(19, "length 0 succeeds"),
                Difference::field(22, "msync", "errno", Observed::Str("ENOSYS")),
                Difference::check(23, "a range reaching past the mapping is ENOMEM"),
                Difference::field(24, "msync", "errno", Observed::Str("ENOSYS")),
                Difference::check(25, "an unmapped range is ENOMEM"),
            ]),
        },
        Gap {
            status: Status::Pending(Arc::MemoryIpc),
            vehicles: &[
                Vehicle::Syscall,
                #[cfg(target_arch = "x86_64")]
                Vehicle::Raw,
            ],
            what: "msync is Trap(unmodeled) in the registry (patina-syscalls linux.rs), so the SUD dispatcher aborts by name",
            failure: Failure::Stops {
                events: 1,
                ending: Ending::Signal(libc::SIGABRT),
                diagnostic: "patina: SUD trapped unsupported syscall msync (nr",
            },
        },
    ],
    ..DEFAULTS
};
