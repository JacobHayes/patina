//! mem/protect — page protection (man 2 mprotect; mm/mprotect.c
//! `do_mprotect_pkey`; arch/*/mm/fault.c for the signal):
//!
//! * `mprotect` refuses a misaligned address, a protection bit no
//!   architecture defines, and `PROT_GROWSDOWN` on a mapping that does not
//!   grow down (`EINVAL`); a range that is not entirely mapped is `ENOMEM`;
//!   length 0 succeeds;
//! * a store to a read-only page and a load from a `PROT_NONE` page raise
//!   SIGSEGV with `SEGV_ACCERR` at the faulting address; a load from an
//!   unmapped page raises it with `SEGV_MAPERR`. The scenario's handler
//!   repairs the page and returns, so the access retries and completes —
//!   the store lands, the loads read what the repaired page holds.

use super::fault::{self, Repair};
#[cfg(target_arch = "x86_64")]
use crate::catalog::{Arc, Gap, Status};
use crate::catalog::{DEFAULTS, Scenario};
#[cfg(target_arch = "x86_64")]
use crate::compare::{Ending, Failure};
use crate::probe::{At, Probe, neg, page_size};
#[cfg(target_arch = "x86_64")]
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

const ANON: i32 = MAP_PRIVATE | MAP_ANONYMOUS;
const RW: i32 = PROT_READ | PROT_WRITE;
/// A protection bit no architecture defines (arm64's `PROT_BTI`/`PROT_MTE`
/// are 0x10/0x20; `PROT_SEM` is 0x8).
const UNKNOWN_PROT: i32 = 0x40;
/// The `si_code`s of a SIGSEGV (asm-generic/siginfo.h).
const SEGV_MAPERR: i32 = 1;
const SEGV_ACCERR: i32 = 2;

pub fn run(p: &Probe) {
    let page = page_size();
    let null = At::null();
    let (r, a) = p.mmap("a", &null, 3 * page, RW, ANON, -1, 0);
    p.require("map three pages", r >= 0);
    let a = a.unwrap();
    a.fill(0, b"guarded");

    p.check(
        "mprotect to read-only succeeds",
        p.mprotect(&a.at(0), page, PROT_READ) == 0,
    );
    p.check("a read-only page reads", a.bytes(0, 7) == b"guarded");
    p.check(
        "mprotect at a misaligned address is EINVAL",
        p.mprotect(&a.at(1), page, PROT_READ) == neg(EINVAL),
    );
    p.check(
        "an undefined protection bit is EINVAL",
        p.mprotect(&a.at(0), page, PROT_READ | UNKNOWN_PROT) == neg(EINVAL),
    );
    p.check(
        "PROT_GROWSDOWN on a mapping that does not grow down is EINVAL",
        p.mprotect(&a.at(0), page, PROT_READ | PROT_GROWSDOWN) == neg(EINVAL),
    );
    p.check(
        "mprotect of length 0 succeeds",
        p.mprotect(&a.at(0), 0, PROT_NONE) == 0,
    );
    p.check("unmap the middle page", p.munmap(&a.at(page), page) == 0);
    p.check(
        "mprotect over a hole is ENOMEM",
        p.mprotect(&a.at(page), 2 * page, RW) == neg(ENOMEM),
    );
    p.check(
        "mprotect of an unmapped range is ENOMEM",
        p.mprotect(&a.at(page), page, RW) == neg(ENOMEM),
    );
    p.check(
        "page 0 is still read-only",
        p.mprotect(&a.at(0), page, PROT_READ) == 0,
    );

    // ---- faults, repaired by the handler ----
    let installed = fault::install();
    fault::arm(a.base, Repair::Protect);
    a.store(1, b'U');
    let seen = fault::observed();
    p.check(
        "a store to a read-only page faults once, SEGV_ACCERR at its address",
        seen.count == 1 && seen.code == SEGV_ACCERR && seen.address == a.base + 1,
    );
    p.check("the retried store lands", a.bytes(0, 7) == b"gUarded");
    p.check(
        "mprotect to PROT_NONE succeeds",
        p.mprotect(&a.at(0), page, PROT_NONE) == 0,
    );
    fault::arm(a.base, Repair::Protect);
    let byte = a.load(2);
    let seen = fault::observed();
    p.check(
        "a load from a PROT_NONE page faults, SEGV_ACCERR at its address",
        seen.count == 2 && seen.code == SEGV_ACCERR && seen.address == a.base + 2,
    );
    p.check("the retried load reads the page", byte == b'a');
    fault::arm(a.base + page, Repair::Map);
    let byte = a.load(page + 3);
    let seen = fault::observed();
    p.check(
        "a load from an unmapped page faults, SEGV_MAPERR at its address",
        seen.count == 3 && seen.code == SEGV_MAPERR && seen.address == a.base + page + 3,
    );
    p.check("the retried load reads the fresh page", byte == 0);
    drop(installed);

    p.check("unmap it all", p.munmap(&a.at(0), 3 * page) == 0);
}

pub const SCENARIO: Scenario = Scenario {
    name: "mem/protect",
    run,
    covers: &[Syscall::N_mprotect, Syscall::N_mmap, Syscall::N_munmap],
    symbols: &["mmap", "munmap"],
    #[cfg(target_arch = "x86_64")]
    gaps: &[Gap {
        status: Status::Pending(Arc::SignalsThreadsProcess),
        vehicles: Vehicle::ALL,
        what: "a guest SIGSEGV handler is refused: with the rdtsc trap armed (PR_TSC_SIGSEGV, tsc.rs) the shim reserves SIGSEGV and patina_signal_action (thread/signals.rs) aborts the registration instead of routing faults outside its own rdtsc sites to the guest's handler",
        failure: Failure::Stops {
            events: 20,
            ending: Ending::Signal(libc::SIGABRT),
            diagnostic: "patina native shim fatal: reserved signal registration would disable deterministic containment",
        },
    }],
    ..DEFAULTS
};
