//! mem/mlock — locking pages (man 2 mlock; mm/mlock.c):
//!
//! * `mlock` populates the range (its pages are resident without a touch);
//!   `mlock2(MLOCK_ONFAULT)` locks without populating; Linux rounds a
//!   misaligned address down (and the length up to cover it) instead of
//!   refusing it; length 0 succeeds; a range that is not entirely mapped is
//!   `ENOMEM` for both `mlock` and `munlock`; an unknown `mlock2` flag is
//!   `EINVAL`;
//! * `mlockall` needs `MCL_CURRENT` or `MCL_FUTURE` (`MCL_ONFAULT` alone, no
//!   flag, or an unknown one is `EINVAL`); `MCL_FUTURE` populates every later
//!   mapping, and `munlockall` ends that.
//!
//! What a lock may cost is `RLIMIT_MEMLOCK` (or `CAP_IPC_LOCK`): the
//! scenario locks at most four pages at once and needs that many. It never
//! uses `MCL_CURRENT`, whose success depends on the whole address space
//! fitting the limit — a host fact. Under `MCL_FUTURE` every new mapping of
//! the process is locked and charged to that limit, the heap's growth
//! included, so the window between `mlockall` and `munlockall` is one
//! unrecorded straight run with nothing allocated, recorded afterwards. The
//! residency vectors are exact per page because the regions refuse
//! transparent huge pages (`MADV_NOHUGEPAGE`, as `mem/mincore`).

use crate::catalog::{DEFAULTS, KernelFloor, Need, Scenario};
use crate::probe::{At, Probe, neg, page_size};
use libc::*;
use patina_dst_syscalls::Syscall;

const ANON: i32 = MAP_PRIVATE | MAP_ANONYMOUS;
const RW: i32 = PROT_READ | PROT_WRITE;
/// A flag bit `mlock2` does not define (`MLOCK_ONFAULT` is 1, its only one).
const UNKNOWN_MLOCK2: u32 = 0x2;
/// A flag bit `mlockall` does not define (`MCL_CURRENT` 1, `MCL_FUTURE` 2,
/// `MCL_ONFAULT` 4 are all there are; 0x100 is clear of arch variants).
const UNKNOWN_MCL: i32 = 0x100;

pub fn run(p: &Probe) {
    let page = page_size();
    let null = At::null();
    let (r, a) = p.mmap("a", &null, 4 * page, RW, ANON, -1, 0);
    p.require("map four pages", r >= 0);
    let a = a.unwrap();
    // Unasserted: a kernel without THP answers EINVAL, and then nothing
    // could fault in more than a page anyway.
    p.madvise(&a.at(0), 4 * page, MADV_NOHUGEPAGE);

    p.check("mlock two pages", p.mlock(&a.at(0), 2 * page) == 0);
    let (r, resident) = p.mincore(&a.at(0), 4 * page, Some(4));
    p.check(
        "mlock populates exactly its range",
        r == 0 && resident == [1, 1, 0, 0],
    );
    p.check("munlock them", p.munlock(&a.at(0), 2 * page) == 0);
    p.check("mlock of length 0 succeeds", p.mlock(&a.at(0), 0) == 0);
    p.check(
        "mlock2 MLOCK_ONFAULT locks a page",
        p.mlock2(&a.at(2 * page), page, MLOCK_ONFAULT) == 0,
    );
    let (r, resident) = p.mincore(&a.at(2 * page), page, Some(1));
    p.check("without populating it", r == 0 && resident == [0]);
    p.check("munlock it", p.munlock(&a.at(2 * page), page) == 0);
    p.check(
        "a misaligned address is not refused",
        p.mlock(&a.at(2 * page + 1), page) == 0,
    );
    let (r, resident) = p.mincore(&a.at(2 * page), 2 * page, Some(2));
    p.check(
        "it is rounded down, the length up to cover it: both pages populated",
        r == 0 && resident == [1, 1],
    );
    p.check("munlock them", p.munlock(&a.at(2 * page + 1), page) == 0);
    p.check(
        "an unknown mlock2 flag is EINVAL",
        p.mlock2(&a.at(0), page, UNKNOWN_MLOCK2) == neg(EINVAL),
    );

    p.check("unmap the last page", p.munmap(&a.at(3 * page), page) == 0);
    p.check(
        "mlock of a range reaching past the mapping is ENOMEM",
        p.mlock(&a.at(0), 4 * page) == neg(ENOMEM),
    );
    p.check(
        "munlock of it is ENOMEM",
        p.munlock(&a.at(0), 4 * page) == neg(ENOMEM),
    );

    p.check(
        "mlockall with no flag is EINVAL",
        p.mlockall(0) == neg(EINVAL),
    );
    p.check(
        "mlockall MCL_ONFAULT alone is EINVAL",
        p.mlockall(MCL_ONFAULT) == neg(EINVAL),
    );
    p.check(
        "mlockall with an unknown flag is EINVAL",
        p.mlockall(MCL_FUTURE | UNKNOWN_MCL) == neg(EINVAL),
    );

    // One straight run: nothing below allocates until `munlockall`.
    let spec = (page, RW, ANON, -1, 0);
    let map_args = Probe::mmap_args(&null, spec);
    let mut vector = vec![0u8; 1];
    let locked = p.call_unrecorded(Syscall::N_mlockall, [MCL_FUTURE as i64, 0, 0, 0, 0, 0]);
    let mapped = p.call_unrecorded(Syscall::N_mmap, map_args);
    let queried = if mapped >= 0 {
        p.call_unrecorded(
            Syscall::N_mincore,
            [mapped, page as i64, vector.as_mut_ptr() as i64, 0, 0, 0],
        )
    } else {
        mapped
    };
    let unlocked = p.call_unrecorded(Syscall::N_munlockall, [0; 6]);

    p.check(
        "mlockall MCL_FUTURE",
        p.record_mlockall(MCL_FUTURE, locked) == 0,
    );
    let (r, future) = p.record_mmap(mapped, "f", &null, spec);
    let populated =
        future.map(|future| p.record_mincore(&future.at(0), page, Some(&vector), queried));
    p.record_result(Syscall::N_munlockall, unlocked);
    p.check("munlockall", unlocked == 0);
    p.check(
        "under MCL_FUTURE a new mapping is populated",
        r >= 0 && populated.is_some_and(|(r, resident)| r == 0 && resident == [1]),
    );
    let (r, later) = p.mmap("l", &null, page, RW, ANON, -1, 0);
    let later_resident = later.map(|later| p.mincore(&later.at(0), page, Some(1)));
    p.check(
        "after munlockall a new mapping is not",
        r >= 0 && later_resident.is_some_and(|(r, resident)| r == 0 && resident == [0]),
    );
    p.check("munlockall again succeeds", p.munlockall() == 0);
    for region in [future, later].into_iter().flatten() {
        p.munmap(&region.at(0), page);
    }
    p.check("unmap the rest", p.munmap(&a.at(0), 3 * page) == 0);
}

pub const SCENARIO: Scenario = Scenario {
    name: "mem/mlock",
    run,
    covers: &[
        Syscall::N_mlock,
        Syscall::N_munlock,
        Syscall::N_mlock2,
        Syscall::N_mlockall,
        Syscall::N_munlockall,
    ],
    symbols: &["syscall", "mmap", "munmap"],
    needs: &[Need::LockedPages(4)],
    kernel_floor: Some(KernelFloor {
        release: "4.4",
        why: "mlock2, MLOCK_ONFAULT and MCL_ONFAULT first appear in Linux 4.4",
    }),
    ..DEFAULTS
};
