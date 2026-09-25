//! thread/rseq — restartable-sequence registration (kernel/rseq.c
//! `sys_rseq`), as 6.8 answers a thread glibc 2.39 has already registered
//! (every thread, at its start, unless a tunable turns it off):
//!
//! * registering any other area is `EINVAL`: one registration per thread,
//!   judged before the new area is read;
//! * glibc's own area — found near the thread pointer as the one address
//!   the kernel answers `EBUSY` for — is refused as already registered
//!   with glibc's signature (`EBUSY`), as a signature mismatch with another
//!   (`EPERM`), and with another length (`EINVAL`); a flag other than
//!   `RSEQ_FLAG_UNREGISTER` is `EINVAL`, and unregistering with the wrong
//!   signature `EPERM`, so glibc's registration stays;
//! * the kernel keeps the registered area current: with the thread pinned
//!   to its CPU, `cpu_id` and `cpu_id_start` name the CPU `getcpu` answers.
//!
//! The host must leave glibc's registration live (`Need::RseqRegistered`:
//! not so under `GLIBC_TUNABLES=glibc.pthread.rseq=0`). The probe also
//! stops before its search unless the first call shows a registration: on
//! an unregistered thread each candidate address would be registered,
//! handing the kernel thread-local memory to write CPU ids into.
//!
//! glibc wraps no rseq (its `__rseq_offset` names the area, but the registry
//! has no symbol row for it, so the probe binary cannot import it — the
//! pre-run audit would refuse it — and patina's `dlsym` answers NULL for
//! it), so the scenario finds the area through the kernel and runs through
//! the kernel vehicles. Every call is refused: glibc's registration is
//! never changed.

use super::thread_pointer;
use crate::catalog::{Arc, DEFAULTS, Gap, Need, Scenario, Status};
use crate::compare::{Difference, Ending, Failure, Observed};
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
/// glibc 2.39's registration length: `sizeof(struct rseq)`.
const LEN: i64 = 32;
/// `RSEQ_FLAG_UNREGISTER`.
const UNREGISTER: i64 = 1;
/// A flag no kernel defines for rseq (7.0's time-slice extension takes the
/// low bits).
const UNDEFINED_FLAG: i64 = 1 << 30;
/// How far from the thread pointer the search looks, each way: glibc keeps
/// the area in the thread descriptor, beside the thread pointer.
const SEARCH: isize = 4096;

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

/// glibc's area: the one 32-byte-aligned address near the thread pointer
/// that the kernel answers `EBUSY` for. Each other candidate must answer
/// `EINVAL` (another area than the registered one), which reads and changes
/// nothing; any other answer ends the search. One that registers the
/// candidate (0: the thread had no registration after all) is undone at
/// once, before the kernel writes CPU ids into thread-local memory.
fn registered_area(p: &Probe) -> Result<usize, String> {
    let tp = thread_pointer() as isize;
    p.rec.quiet(|| {
        for offset in (-SEARCH..SEARCH).step_by(32) {
            let candidate = (tp + offset) as usize & !31;
            let r = p.call_unrecorded(Syscall::N_rseq, [candidate as i64, LEN, 0, SIG, 0, 0]);
            if r == neg(EBUSY) {
                return Ok(candidate);
            }
            if r == 0 {
                p.call_unrecorded(
                    Syscall::N_rseq,
                    [candidate as i64, LEN, UNREGISTER, SIG, 0, 0],
                );
            }
            if r != neg(EINVAL) {
                return Err(format!("a candidate answered {r}"));
            }
        }
        Err("no candidate is registered".to_string())
    })
}

/// Pin the thread to the CPU it runs on, and compare the area's CPU fields
/// with `getcpu`'s answer there: the kernel writes the area on the return
/// to user space after a migration. The original affinity is restored.
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
    // SAFETY: glibc's registered area, alive as long as this thread.
    let (start, id) = unsafe {
        let area = area as *const Area;
        (
            std::ptr::read_volatile(&raw const (*area).cpu_id_start),
            std::ptr::read_volatile(&raw const (*area).cpu_id),
        )
    };
    p.check(
        "pinned, the area names the CPU getcpu answers (cpu_id and cpu_id_start)",
        r == 0 && pinned == cpu && id == pinned && start == pinned,
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
    // Without glibc's registration the search below would register
    // thread-local memory: go no further.
    p.require("glibc registered the thread", r == neg(EINVAL));
    let found = registered_area(p);
    if let Err(reason) = &found {
        p.require(&format!("find glibc's registered area: {reason}"), false);
    }
    let area = found.unwrap();
    p.check(
        "glibc's area with glibc's signature is EBUSY",
        rseq(p, area, LEN, 0, SIG, "glibc") == neg(EBUSY),
    );
    p.check(
        "another signature is EPERM",
        rseq(p, area, LEN, 0, SIG ^ 1, "glibc") == neg(EPERM),
    );
    p.check(
        "another length is EINVAL",
        rseq(p, area, LEN - 1, 0, SIG, "glibc") == neg(EINVAL),
    );
    p.check(
        "an undefined flag is EINVAL",
        rseq(p, area, LEN, UNDEFINED_FLAG, SIG, "glibc") == neg(EINVAL),
    );
    p.check(
        "unregistering with another signature is EPERM",
        rseq(p, area, LEN, UNREGISTER, SIG ^ 1, "glibc") == neg(EPERM),
    );
    p.check(
        "unregistering another area is EINVAL",
        rseq(p, own, LEN, UNREGISTER, SIG, "own") == neg(EINVAL),
    );
    area_names_the_cpu(p, area);
    p.check(
        "and glibc's registration stays",
        rseq(p, area, LEN, 0, SIG, "glibc") == neg(EBUSY),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "thread/rseq",
    run,
    vehicles: Vehicle::KERNEL,
    covers: &[Syscall::N_rseq],
    needs: &[Need::RseqRegistered],
    gaps: &[
        Gap {
            status: Status::Pending(Arc::SignalsThreadsProcess),
            vehicles: Vehicle::KERNEL,
            what: "rseq is SoftDeny(ENOSYS) in the registry, a kernel without restartable sequences, though every thread's glibc registration reaches the host kernel (ld.so's before SUD arms, a managed thread's from the host pthread_create), which keeps the area's CPU fields current: 6.8 has rseq, and refuses a second registration",
            failure: Failure::Differs(&[
                Difference::field(0, "rseq", "errno", Observed::Str("ENOSYS")),
                Difference::check(
                    1,
                    "registering another area is EINVAL: glibc registered the thread",
                ),
            ]),
        },
        Gap {
            status: Status::Pending(Arc::SignalsThreadsProcess),
            vehicles: Vehicle::KERNEL,
            what: "every rseq answers ENOSYS, so the scenario sees no glibc registration and stops before searching for one",
            failure: Failure::Stops {
                events: 2,
                ending: Ending::Exit(101),
                diagnostic: "cannot continue: glibc registered the thread",
            },
        },
    ],
    ..DEFAULTS
};
