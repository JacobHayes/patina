//! sched/affinity — CPU affinity and the current CPU (kernel/sched/
//! syscalls.c, kernel/sys.c getcpu):
//!
//! * `sched_getaffinity` answers a nonempty mask, a whole number of longs
//!   no longer than the buffer (glibc's wrapper answers 0 and zeroes the
//!   rest; the row answers the bytes it wrote); for the caller's own pid the
//!   same mask; a buffer too small for the kernel's mask (0 bytes) or not a
//!   whole number of longs is `EINVAL`; a pid no process has `ESRCH`;
//! * `getcpu` answers a CPU in that mask (and a NULL everything succeeds);
//!   glibc's `sched_getcpu` too; `sysconf(_SC_NPROCESSORS_ONLN)` counts at
//!   least the mask's CPUs, `_SC_NPROCESSORS_CONF` at least the online ones;
//! * pinned to the current CPU, the mask reads back as that CPU alone and
//!   the task runs there; an empty mask, and one naming only CPUs past the
//!   kernel's, are `EINVAL`; a pid no process has `ESRCH`; the original mask
//!   restores.
//!
//! Which and how many CPUs there are is the host's business (the virtual
//! kernel's is a model constant): masks and CPU numbers are related, never
//! recorded.

use crate::catalog::{DEFAULTS, Scenario};
use crate::probe::{Probe, Who, neg};
use libc::*;
use patina_dst_syscalls::Syscall;
use serde_json::Value;

/// A mask buffer with room for every CPU the kernel may know, and one long
/// more (so its last bit is past them): at least 1024 CPUs' worth, more on a
/// host configured with more (`sysconf(_SC_NPROCESSORS_CONF)`), recorded as
/// `sized`.
fn buffer_len() -> usize {
    // SAFETY: sysconf reads a constant.
    let configured = unsafe { sysconf(_SC_NPROCESSORS_CONF) }.max(1) as usize;
    let long = std::mem::size_of::<c_ulong>();
    (configured.div_ceil(8 * long) + 1).max(128 / long) * long
}

fn has(mask: &[u8], cpu: u32) -> bool {
    mask.get(cpu as usize / 8)
        .is_some_and(|byte| byte & (1 << (cpu % 8)) != 0)
}

fn count(mask: &[u8]) -> u32 {
    mask.iter().map(|byte| byte.count_ones()).sum()
}

pub fn run(p: &Probe) {
    let len = buffer_len();
    let pid = p.getpid() as i32;
    let (r, mask) = p.sched_getaffinity(Who::Caller, len, "sized");
    p.require("sched_getaffinity answers", r >= 0);
    p.check("the mask is nonempty", count(&mask) > 0);
    let (r, own) = p.sched_getaffinity(Who::Own(pid), len, "sized");
    p.check(
        "the caller's own pid answers the same mask",
        r >= 0 && own == mask,
    );
    let (r, cpu, _) = p.getcpu(false);
    p.check(
        "getcpu answers a CPU in the mask",
        r == 0 && has(&mask, cpu),
    );
    p.check(
        "getcpu with NULL everything succeeds",
        p.getcpu(true).0 == 0,
    );
    // SAFETY: sched_getcpu and sysconf read the calling thread's state.
    let (libc_cpu, online, configured) = unsafe {
        (
            sched_getcpu(),
            sysconf(_SC_NPROCESSORS_ONLN),
            sysconf(_SC_NPROCESSORS_CONF),
        )
    };
    p.mark(
        "sched_getcpu",
        &[(
            "in_mask",
            Value::from(libc_cpu >= 0 && has(&mask, libc_cpu as u32)),
        )],
    );
    p.check(
        "sched_getcpu answers a CPU in the mask",
        libc_cpu >= 0 && has(&mask, libc_cpu as u32),
    );
    p.mark(
        "sysconf",
        &[
            (
                "online_covers_mask",
                Value::from(online >= i64::from(count(&mask))),
            ),
            (
                "configured_covers_online",
                Value::from(configured >= online),
            ),
        ],
    );
    p.check(
        "the online CPUs cover the mask, the configured ones the online",
        online >= i64::from(count(&mask)) && configured >= online,
    );
    for short in [0, 4, 7] {
        p.check(
            "a buffer too small or not whole longs is EINVAL",
            p.sched_getaffinity(Who::Caller, short, &short.to_string())
                .0
                == neg(EINVAL),
        );
    }
    p.check(
        "sched_getaffinity of a pid no process has is ESRCH",
        p.sched_getaffinity(Who::Missing, len, "sized").0 == neg(ESRCH),
    );

    let mut one = vec![0u8; len];
    one[cpu as usize / 8] |= 1 << (cpu % 8);
    p.check(
        "pin to the current CPU",
        p.sched_setaffinity(Who::Caller, &one, "sized", "the current CPU") == 0,
    );
    let (r, pinned) = p.sched_getaffinity(Who::Caller, len, "sized");
    p.check(
        "the mask reads back as that CPU alone",
        r >= 0 && count(&pinned) == 1 && has(&pinned, cpu),
    );
    let (r, now, _) = p.getcpu(false);
    p.check("the task runs there", r == 0 && now == cpu);
    p.check(
        "an empty mask is EINVAL",
        p.sched_setaffinity(Who::Caller, &vec![0u8; len], "sized", "empty") == neg(EINVAL),
    );
    let mut beyond = vec![0u8; len];
    beyond[len - 1] = 0x80;
    p.check(
        "a mask naming only CPUs past the kernel's is EINVAL",
        p.sched_setaffinity(Who::Caller, &beyond, "sized", "the buffer's last CPU alone")
            == neg(EINVAL),
    );
    p.check(
        "sched_setaffinity of a pid no process has is ESRCH",
        p.sched_setaffinity(Who::Missing, &one, "sized", "the current CPU") == neg(ESRCH),
    );
    p.check(
        "the original mask restores",
        p.sched_setaffinity(Who::Caller, &mask, "sized", "the original") == 0,
    );
    let (r, restored) = p.sched_getaffinity(Who::Caller, len, "sized");
    p.check("and reads back", r >= 0 && restored == mask);
}

pub const SCENARIO: Scenario = Scenario {
    name: "sched/affinity",
    run,
    covers: &[
        Syscall::N_sched_getaffinity,
        Syscall::N_sched_setaffinity,
        Syscall::N_getcpu,
    ],
    symbols: &[
        "sched_getaffinity",
        "sched_setaffinity",
        "sched_getcpu",
        "sysconf",
        "getpid",
        "syscall",
    ],
    ..DEFAULTS
};
