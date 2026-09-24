//! sched/attr — `sched_setattr`/`sched_getattr` and the size negotiation of
//! their extensible struct (kernel/sched/syscalls.c sched_copy_attr,
//! sched_attr_copy_to_user):
//!
//! * `sched_getattr` answers a normal task's policy, flags, nice and
//!   priority; it writes `min(size, the kernel's size)` bytes and says so in
//!   `size` (48 for the first version, 56 — the kernel's own — for anything
//!   larger); the rest of a larger buffer is left alone up to Linux 6.12
//!   and zeroed from 6.13 (a host on the other side of that change from the
//!   virtual ABI level records the virtual ABI's answer and checks its own:
//!   `getattr_larger`); a size under the first version, above a page, a flag, or a negative pid is `EINVAL`, a
//!   pid no process has `ESRCH`;
//! * `sched_setattr` takes a size of 0 as the first version; a size under it
//!   is `E2BIG` with the kernel's size written back into `size`, and so is a
//!   larger struct whose bytes past the kernel's are not all zero (a zero
//!   tail is accepted); a flag argument, an unknown policy or an unknown
//!   `sched_flags` bit is `EINVAL`;
//! * the nice value moves down in priority freely; with `RLIMIT_NICE` at 0
//!   (lowered here; lowering is always allowed) it cannot move back up
//!   (`EPERM`).
//!
//! The utilization clamps (`sched_util_min`/`max`) are the host's kernel
//! configuration and are not recorded.

use crate::catalog::{DEFAULTS, KernelFloor, Need, Scenario};
use crate::probe::{Probe, SCHED_ATTR_SIZE_VER0, SCHED_ATTR_SIZE_VER1, SchedAttr, Who, neg};
use libc::*;
use patina_dst_syscalls::Syscall;
use patina_dst_syscalls::{VIRTUAL_ABI, parse_release};

/// A `sched_flags` bit past `SCHED_FLAG_ALL`.
const UNKNOWN_SCHED_FLAG: u64 = 1 << 20;

/// The release whose `sched_getattr` zeroes a larger buffer past the
/// kernel's struct: Linux 6.13, commit 112cca098a70 ("sched_getattr: port to
/// copy_struct_to_user", merged through vfs-6.13.usercopy). Up to 6.12 those
/// bytes were left alone (`sched_attr_copy_to_user` copied `min(usize,
/// ksize)` bytes only); a smaller buffer is written up to its size on both.
const ZEROES_TAIL_SINCE: &str = "6.13";

fn zeroes_tail(release: &str) -> bool {
    parse_release(release) >= parse_release(ZEROES_TAIL_SINCE)
}

fn tail_answer(zeroed: bool) -> &'static str {
    if zeroed { "zeroed" } else { "untouched" }
}

/// `sched_getattr(0, buf, 128, 0)` into a 128-byte buffer filled with
/// `0xa5`: the attribute and what became of the 72 bytes past the kernel's
/// 56 (`untouched`, `zeroed` or `written`), and the answer this host's
/// release gives. A host on the other side of 6.13 from the virtual ABI
/// level answers by declaration: its event records the virtual ABI's answer
/// (the declared-absent pattern, for one field), while its own answer is
/// still checked against its release. The virtual kernel's `uname` reports
/// its ABI level, so under patina the observation itself is recorded.
fn getattr_larger(p: &Probe) -> (i64, SchedAttr, &'static str, &'static str) {
    let host = zeroes_tail(&crate::host::kernel_release());
    let virtual_abi = zeroes_tail(VIRTUAL_ABI);
    let mut buf = vec![0xa5u8; 128];
    let result = p.call_unrecorded(
        Syscall::N_sched_getattr,
        [0, buf.as_mut_ptr() as i64, 128, 0, 0, 0],
    );
    // SAFETY: `buf` holds at least one SchedAttr; read unaligned.
    let attr: SchedAttr = unsafe { std::ptr::read_unaligned(buf.as_ptr().cast()) };
    let tail = &buf[SCHED_ATTR_SIZE_VER1 as usize..];
    let observed = if tail.iter().all(|b| *b == 0xa5) {
        "untouched"
    } else if tail.iter().all(|b| *b == 0) {
        "zeroed"
    } else {
        "written"
    };
    let recorded = if host == virtual_abi {
        observed
    } else {
        tail_answer(virtual_abi)
    };
    let builder = p
        .rec
        .event("sched_getattr", result)
        .arg("pid", 0)
        .arg("size", 128)
        .arg("flags", 0);
    let builder = if result == 0 {
        builder
            .field("attr_size", attr.size)
            .field("policy", attr.policy)
            .field("sched_flags", attr.flags)
            .field("nice", attr.nice)
            .field("priority", attr.priority)
            .field("tail", recorded)
    } else {
        builder
    };
    builder.emit();
    (result, attr, observed, tail_answer(host))
}

fn normal(size: u32, nice: i32) -> SchedAttr {
    SchedAttr {
        size,
        policy: SCHED_OTHER as u32,
        nice,
        ..SchedAttr::default()
    }
}

pub fn run(p: &Probe) {
    let pid = p.getpid() as i32;
    let (r, attr) = p.sched_getattr(Who::Caller, SCHED_ATTR_SIZE_VER1, 56, 0);
    p.check(
        "a normal task's attributes",
        r == 0
            && attr.size == SCHED_ATTR_SIZE_VER1
            && attr.policy == SCHED_OTHER as u32
            && attr.flags == 0
            && attr.nice == 0
            && attr.priority == 0,
    );
    let (r, attr) = p.sched_getattr(Who::Own(pid), SCHED_ATTR_SIZE_VER0, 64, 0);
    p.check(
        "the first version's size writes 48 bytes and says so",
        r == 0 && attr.size == SCHED_ATTR_SIZE_VER0,
    );
    let (r, attr, tail, expected) = getattr_larger(p);
    p.check(
        "a larger size writes the kernel's 56 and says so",
        r == 0 && attr.size == SCHED_ATTR_SIZE_VER1,
    );
    p.check(
        "the bytes past the kernel's struct are left alone (zeroed from 6.13)",
        r == 0 && tail == expected,
    );
    p.check(
        "a size under the first version is EINVAL",
        p.sched_getattr(Who::Caller, SCHED_ATTR_SIZE_VER0 - 1, 64, 0)
            .0
            == neg(EINVAL),
    );
    p.check(
        "a size above a page is EINVAL",
        p.sched_getattr(Who::Caller, 1 << 20, 64, 0).0 == neg(EINVAL),
    );
    p.check(
        "a flag is EINVAL",
        p.sched_getattr(Who::Caller, SCHED_ATTR_SIZE_VER1, 56, 1).0 == neg(EINVAL),
    );
    p.check(
        "a negative pid is EINVAL",
        p.sched_getattr(Who::Raw(-1), SCHED_ATTR_SIZE_VER1, 56, 0).0 == neg(EINVAL),
    );
    p.check(
        "a pid no process has is ESRCH",
        p.sched_getattr(Who::Missing, SCHED_ATTR_SIZE_VER1, 56, 0).0 == neg(ESRCH),
    );

    p.check(
        "sched_setattr of the current attributes",
        p.sched_setattr(Who::Caller, normal(SCHED_ATTR_SIZE_VER1, 0), 56, None, 0)
            .0
            == 0,
    );
    p.check(
        "a size of 0 is the first version",
        p.sched_setattr(Who::Caller, normal(0, 0), 56, None, 0).0 == 0,
    );
    let (r, size) = p.sched_setattr(Who::Caller, normal(40, 0), 56, None, 0);
    p.check(
        "a size under the first version is E2BIG, the kernel's size written back",
        r == neg(E2BIG) && size == SCHED_ATTR_SIZE_VER1,
    );
    let (r, size) = p.sched_setattr(Who::Caller, normal(64, 0), 64, Some(1), 0);
    p.check(
        "a larger struct with a nonzero tail is E2BIG, the kernel's size written back",
        r == neg(E2BIG) && size == SCHED_ATTR_SIZE_VER1,
    );
    p.check(
        "a larger struct with a zero tail is accepted",
        p.sched_setattr(Who::Caller, normal(64, 0), 64, None, 0).0 == 0,
    );
    p.check(
        "a flag argument is EINVAL",
        p.sched_setattr(Who::Caller, normal(SCHED_ATTR_SIZE_VER1, 0), 56, None, 1)
            .0
            == neg(EINVAL),
    );
    p.check(
        "an unknown policy is EINVAL",
        p.sched_setattr(
            Who::Caller,
            SchedAttr {
                policy: 99,
                ..normal(SCHED_ATTR_SIZE_VER1, 0)
            },
            56,
            None,
            0,
        )
        .0 == neg(EINVAL),
    );
    p.check(
        "an unknown sched_flags bit is EINVAL",
        p.sched_setattr(
            Who::Caller,
            SchedAttr {
                flags: UNKNOWN_SCHED_FLAG,
                ..normal(SCHED_ATTR_SIZE_VER1, 0)
            },
            56,
            None,
            0,
        )
        .0 == neg(EINVAL),
    );
    p.check(
        "a pid no process has is ESRCH",
        p.sched_setattr(Who::Missing, normal(SCHED_ATTR_SIZE_VER1, 0), 56, None, 0)
            .0
            == neg(ESRCH),
    );

    p.check(
        "nice moves down in priority",
        p.sched_setattr(Who::Caller, normal(SCHED_ATTR_SIZE_VER1, 1), 56, None, 0)
            .0
            == 0,
    );
    let (r, attr) = p.sched_getattr(Who::Caller, SCHED_ATTR_SIZE_VER1, 56, 0);
    p.check("and reads back", r == 0 && attr.nice == 1);
    p.check(
        "RLIMIT_NICE lowers to 0",
        p.setrlimit(RLIMIT_NICE as i32, 0, 0) == 0,
    );
    p.check(
        "then nice cannot move back up",
        p.sched_setattr(Who::Caller, normal(SCHED_ATTR_SIZE_VER1, 0), 56, None, 0)
            .0
            == neg(EPERM),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "sched/attr",
    run,
    covers: &[Syscall::N_sched_setattr, Syscall::N_sched_getattr],
    symbols: &["syscall", "getpid", "setrlimit"],
    needs: &[Need::Unprivileged, Need::NiceZero],
    kernel_floor: Some(KernelFloor {
        release: "5.3",
        why: "struct sched_attr's second version (56 bytes, the utilization clamps) first appears in Linux 5.3",
    }),
    ..DEFAULTS
};
