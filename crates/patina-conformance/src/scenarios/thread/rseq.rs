//! thread/rseq — restartable-sequence registration (kernel/rseq.c
//! `sys_rseq`), as 6.8 answers a thread glibc 2.39 has already registered
//! (every thread, at its start, unless a tunable turns it off):
//!
//! * registering any other area is `EINVAL`: one registration per thread,
//!   judged before the new area is read;
//! * glibc's own area, at the length glibc registered it with, is refused
//!   as already registered with glibc's signature (`EBUSY`), as a signature
//!   mismatch with another (`EPERM`), and with another length (`EINVAL`);
//!   a flag other than `RSEQ_FLAG_UNREGISTER` is `EINVAL`, and
//!   unregistering with the wrong signature `EPERM`, so glibc's
//!   registration stays;
//! * the kernel keeps the registered area current: with the thread pinned
//!   to its CPU, `cpu_id` and `cpu_id_start` name the CPU `getcpu` answers,
//!   and pinned to another CPU of its mask (the same one on a machine with
//!   one), they follow it there.
//!
//! The host must leave glibc's registration live (`Need::RseqRegistered`:
//! not so under `GLIBC_TUNABLES=glibc.pthread.rseq=0`). The probe also
//! stops unless the first call shows a registration: on an unregistered
//! thread glibc's area would be registered, handing the kernel thread-local
//! memory to write CPU ids into.
//!
//! glibc wraps no rseq, so the scenario runs through the `syscall` vehicle,
//! and it finds the area through glibc's documented ABI words, linked
//! (patina's `dlsym` answers NULL for them). Every call is refused: glibc's
//! registration is never changed.

use super::thread_pointer;
use crate::catalog::{DEFAULTS, Need, Scenario};
use crate::probe::{Probe, Who, neg};
use crate::scenarios::sched::affinity::buffer_len;
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

/// `RSEQ_SIG`, the signature glibc registers with.
#[cfg(target_arch = "x86_64")]
const SIG: i64 = 0x5305_3053;
#[cfg(target_arch = "aarch64")]
const SIG: i64 = 0xd428_bc00;
/// `ORIG_RSEQ_SIZE`, the original `struct rseq`: the length of the
/// scenario's own area.
const LEN: i64 = 32;
/// `RSEQ_FLAG_UNREGISTER`.
const UNREGISTER: i64 = 1;
/// A flag no kernel defines for rseq (7.0's time-slice extension takes the
/// low bits).
const UNDEFINED_FLAG: i64 = 1 << 30;
unsafe extern "C" {
    /// ld.so's (`<sys/rseq.h>`, GLIBC_2.35), set before any user code runs:
    /// where each thread's area sits from the thread pointer, and the size
    /// of its active features.
    static __rseq_offset: isize;
    static __rseq_size: u32;
}

/// The calling thread's area as glibc registered it: its address and
/// length (sysdeps/unix/sysv/linux/rseq-internal.h: `__rseq_size`, raised
/// to the original 32 bytes). glibc 2.39 keeps the area in the thread
/// descriptor, and its `__rseq_size` is those 32 bytes. From 2.41 the area
/// is a TLS block after every module's own, so its offset grows with the
/// executable's thread-locals, and `__rseq_size` is the kernel's
/// `AT_RSEQ_FEATURE_SIZE`, which Linux 7.0's time-slice extension raises
/// to 33. Another length is `EINVAL` for glibc's own area too.
fn glibc_area() -> (usize, i64) {
    // SAFETY: plain reads of ld.so's initialized words.
    let (offset, size) = unsafe { (__rseq_offset, __rseq_size) };
    (
        thread_pointer().wrapping_add_signed(offset),
        i64::from(size).max(LEN),
    )
}

/// `struct rseq`, 32-byte aligned as the kernel requires.
#[repr(C, align(32))]
struct Area {
    cpu_id_start: u32,
    cpu_id: u32,
    rseq_cs: u64,
    flags: u32,
    node_id: u32,
    mm_cid: u32,
    end: u32,
}

/// An area of the scenario's own: writable (a kernel without a
/// registration would take it and write CPU ids into it, which a read-only
/// static would turn into a SIGSEGV) and alive for the whole process.
fn own_area() -> usize {
    let area: &'static mut Area = Box::leak(Box::new(Area {
        cpu_id_start: 0,
        cpu_id: 0,
        rseq_cs: 0,
        flags: 0,
        node_id: 0,
        mm_cid: 0,
        end: 0,
    }));
    area as *mut Area as usize
}

fn rseq(p: &Probe, area: usize, len: i64, flags: i64, sig: i64, what: &str) -> i64 {
    p.observed(
        Syscall::N_rseq,
        [area as i64, len, flags, sig, 0, 0],
        &[
            ("area", what.into()),
            ("len", len.into()),
            ("flags", flags.into()),
            ("sig_is_glibcs", (sig == SIG).into()),
        ],
    )
}

/// The area's `cpu_id_start` and `cpu_id`.
fn area_cpu(area: usize) -> (u32, u32) {
    // SAFETY: glibc's registered area, alive as long as this thread.
    unsafe {
        let area = area as *const Area;
        (
            std::ptr::read_volatile(&raw const (*area).cpu_id_start),
            std::ptr::read_volatile(&raw const (*area).cpu_id),
        )
    }
}

/// Pin the thread to the CPU it runs on, and compare the area's CPU fields
/// with `getcpu`'s answer there; then pin it to another CPU of its mask, and
/// compare again: the kernel writes the area on the return to user space
/// after a migration. The original affinity is restored.
fn area_names_the_cpu(p: &Probe, area: usize) {
    let len = buffer_len();
    let (r, original) = p.sched_getaffinity(Who::Caller, len, "sized");
    p.require("read the affinity", r >= 0);
    let (r, cpu, _) = p.getcpu(false);
    p.require("read the current CPU", r == 0);
    let mut one = vec![0u8; len];
    one[cpu as usize / 8] |= 1 << (cpu % 8);
    p.require(
        "pin the thread to its CPU",
        p.sched_setaffinity(Who::Caller, &one, "sized", "current-cpu") == 0,
    );
    let (r, pinned, _) = p.getcpu(false);
    let (start, id) = area_cpu(area);
    p.check(
        "pinned, the area names the CPU getcpu answers (cpu_id and cpu_id_start)",
        r == 0 && pinned == cpu && id == pinned && start == pinned,
    );
    let other = (0..(len * 8) as u32)
        .find(|candidate| {
            *candidate != cpu && original[*candidate as usize / 8] & (1 << (candidate % 8)) != 0
        })
        .unwrap_or(cpu);
    let mut moved = vec![0u8; len];
    moved[other as usize / 8] |= 1 << (other % 8);
    p.require(
        "pin the thread to another CPU of its mask",
        p.sched_setaffinity(Who::Caller, &moved, "sized", "another-cpu") == 0,
    );
    let (r, now, _) = p.getcpu(false);
    let (start, id) = area_cpu(area);
    p.check(
        "moved, the area follows to the CPU getcpu answers (cpu_id and cpu_id_start)",
        r == 0 && now == other && id == now && start == now,
    );
    p.require(
        "restore the affinity",
        p.sched_setaffinity(Who::Caller, &original, "sized", "original") == 0,
    );
}

pub fn run(p: &Probe) {
    let own = own_area();
    let r = rseq(p, own, LEN, 0, SIG, "own");
    p.check(
        "registering another area is EINVAL: glibc registered the thread",
        r == neg(EINVAL),
    );
    if r == 0 {
        // No registration existed and the kernel took the scenario's area:
        // give it back before stopping.
        p.rec
            .quiet(|| p.call_unrecorded(Syscall::N_rseq, [own as i64, LEN, UNREGISTER, SIG, 0, 0]));
    }
    // Without glibc's registration the calls below would register
    // thread-local memory: go no further.
    p.require("glibc registered the thread", r == neg(EINVAL));
    let (area, len) = glibc_area();
    p.check(
        "glibc's area with glibc's signature is EBUSY",
        rseq(p, area, len, 0, SIG, "glibc") == neg(EBUSY),
    );
    p.check(
        "another signature is EPERM",
        rseq(p, area, len, 0, SIG ^ 1, "glibc") == neg(EPERM),
    );
    p.check(
        "another length is EINVAL",
        rseq(p, area, len - 1, 0, SIG, "glibc") == neg(EINVAL),
    );
    p.check(
        "an undefined flag is EINVAL",
        rseq(p, area, len, UNDEFINED_FLAG, SIG, "glibc") == neg(EINVAL),
    );
    p.check(
        "unregistering with another signature is EPERM",
        rseq(p, area, len, UNREGISTER, SIG ^ 1, "glibc") == neg(EPERM),
    );
    p.check(
        "unregistering another area is EINVAL",
        rseq(p, own, LEN, UNREGISTER, SIG, "own") == neg(EINVAL),
    );
    area_names_the_cpu(p, area);
    p.check(
        "and glibc's registration stays",
        rseq(p, area, len, 0, SIG, "glibc") == neg(EBUSY),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "thread/rseq",
    run,
    vehicles: &[Vehicle::Syscall],
    covers: &[Syscall::N_rseq],
    needs: &[Need::RseqRegistered],
    ..DEFAULTS
};
