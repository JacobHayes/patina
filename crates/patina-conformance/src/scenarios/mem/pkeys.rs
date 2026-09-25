//! mem/pkeys — memory protection keys (man 7 pkeys, man 2 pkey_alloc, man 2
//! pkey_mprotect; mm/mprotect.c): a key allocates with its access rights,
//! and a page tagged with a key whose rights forbid writing faults on a
//! store with `SEGV_PKUERR` although its protection allows it; key -1 makes
//! `pkey_mprotect` plain `mprotect`; an unknown flag, unknown rights, an
//! unallocated key (for `pkey_mprotect` and `pkey_free`) and a key freed
//! twice are `EINVAL`. On x86_64 the new key's rights are the calling
//! thread's PKRU bits for it (`rdpkru`).
//!
//! Keys are hardware: the scenario needs one to allocate.

use super::fault::{self, Repair};
use crate::catalog::{Arc, DEFAULTS, Gap, Need, Scenario, Status};
use crate::compare::{Ending, Failure};
use crate::probe::{At, Probe, neg, page_size};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

const RW: i32 = PROT_READ | PROT_WRITE;
/// `PKEY_DISABLE_ACCESS` / `PKEY_DISABLE_WRITE` (uapi/asm-generic/mman-common.h).
#[cfg(target_arch = "x86_64")]
const DISABLE_ACCESS: u32 = 0x1;
const DISABLE_WRITE: u32 = 0x2;
/// Access rights past every defined bit (`PKEY_DISABLE_ACCESS` 0x1,
/// `PKEY_DISABLE_WRITE` 0x2; arm64 POE adds 0x4 and 0x8).
const UNKNOWN_RIGHTS: u32 = 0x10;
/// A key this scenario never holds: x86 allocates the lowest free key
/// (the kernel's on-demand execute-only key included), so with at most
/// three taken, 15 is free in practice; on arm64 POE (8 keys) it is out of
/// range outright. Either way the kernel answers EINVAL.
const UNALLOCATED: i32 = 15;
/// `SEGV_PKUERR` (asm-generic/siginfo.h).
const SEGV_PKUERR: i32 = 4;

/// The calling thread's PKRU register.
#[cfg(target_arch = "x86_64")]
fn pkru() -> u32 {
    let value: u32;
    // SAFETY: rdpkru reads the calling thread's PKRU; ecx must be 0.
    unsafe {
        std::arch::asm!(".byte 0x0f, 0x01, 0xee", in("ecx") 0, out("eax") value, out("edx") _,
            options(nomem, nostack));
    }
    value
}

pub fn run(p: &Probe) {
    let page = page_size();
    let (r, a) = p.mmap(
        "a",
        &At::null(),
        2 * page,
        RW,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    p.require("map two pages", r >= 0);
    let a = a.unwrap();

    let key = p.pkey_alloc(0, 0);
    p.check("a key allocates", (1..16).contains(&key));
    let key = key as i32;
    p.check(
        "an unknown flag is EINVAL",
        p.pkey_alloc(1, 0) == neg(EINVAL),
    );
    p.check(
        "unknown access rights are EINVAL",
        p.pkey_alloc(0, UNKNOWN_RIGHTS) == neg(EINVAL),
    );
    p.check(
        "tag a page with the key",
        p.pkey_mprotect(&a.at(0), page, RW, key) == 0,
    );
    a.store(0, b'k');
    p.check("a key with full rights allows access", a.load(0) == b'k');
    p.check(
        "key -1 is plain mprotect",
        p.pkey_mprotect(&a.at(0), page, RW, -1) == 0,
    );
    p.check(
        "an unallocated key is EINVAL",
        p.pkey_mprotect(&a.at(0), page, RW, UNALLOCATED) == neg(EINVAL),
    );

    let guarded = p.pkey_alloc(0, DISABLE_WRITE);
    p.check("a write-disabled key allocates", (1..16).contains(&guarded));
    let guarded = guarded as i32;
    #[cfg(target_arch = "x86_64")]
    p.check(
        "its rights are this thread's PKRU bits for it",
        (pkru() >> (2 * guarded)) & (DISABLE_ACCESS | DISABLE_WRITE) == DISABLE_WRITE,
    );
    p.check(
        "tag the second page with it",
        p.pkey_mprotect(&a.at(page), page, RW, guarded) == 0,
    );
    p.check("its page still reads", a.load(page) == 0);
    let installed = fault::install();
    fault::arm(a.base + page, Repair::DefaultKey);
    a.store(page + 1, b'g');
    let seen = fault::observed();
    drop(installed);
    p.check(
        "a store under a write-disabled key faults with SEGV_PKUERR",
        seen.count == 1 && seen.code == SEGV_PKUERR && seen.address == a.base + page + 1,
    );
    p.check("the retried store lands", a.load(page + 1) == b'g');

    p.check("free the first key", p.pkey_free(key) == 0);
    p.check(
        "freeing it twice is EINVAL",
        p.pkey_free(key) == neg(EINVAL),
    );
    p.check(
        "a freed key tags nothing",
        p.pkey_mprotect(&a.at(0), page, RW, key) == neg(EINVAL),
    );
    p.check(
        "freeing an unallocated key is EINVAL",
        p.pkey_free(UNALLOCATED) == neg(EINVAL),
    );
    p.check("free the second key", p.pkey_free(guarded) == 0);
    p.check("unmap the pages", p.munmap(&a.at(0), 2 * page) == 0);
}

pub const SCENARIO: Scenario = Scenario {
    name: "mem/pkeys",
    run,
    covers: &[
        Syscall::N_pkey_alloc,
        Syscall::N_pkey_free,
        Syscall::N_pkey_mprotect,
    ],
    vehicles: Vehicle::KERNEL,
    needs: &[Need::ProtectionKeys],
    gaps: &[Gap {
        status: Status::Pending(Arc::MemoryIpc),
        vehicles: Vehicle::KERNEL,
        what: "pkey_alloc is Trap(unmodeled) in the registry (patina-syscalls linux.rs), so the SUD dispatcher aborts by name on every door",
        failure: Failure::Stops {
            events: 1,
            ending: Ending::Signal(libc::SIGABRT),
            diagnostic: "patina: SUD trapped unsupported syscall pkey_alloc (nr",
        },
    }],
    ..DEFAULTS
};
