//! readiness/poll_fault — poll(2) over descriptor arrays the kernel cannot
//! use (fs/select.c `do_sys_poll`): more entries than `RLIMIT_NOFILE` is
//! `EINVAL`, judged before the array is read, and an unreadable array is
//! `EFAULT`. Its own scenario, because a door that reads the array first
//! ends the whole run (and a crash loses the captured event stream).
//!
//! glibc's wrapper cannot pass these shapes through, so the scenario runs
//! through the kernel vehicles only. The generic (arm64) table has no `poll`
//! row: there both issue `ppoll`.

use crate::catalog::{DEFAULTS, Scenario};
use crate::probe::{Probe, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

pub fn run(p: &Probe) {
    // The limit the check is about, as this process has it (the harness
    // pins it; the check does not repeat the number).
    let mut limit = rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: an out-pointer to a local rlimit.
    let r = unsafe { getrlimit(RLIMIT_NOFILE, &mut limit) };
    p.mark(
        "rlimit_nofile",
        &[
            ("ret", serde_json::Value::from(r)),
            ("soft", serde_json::Value::from(limit.rlim_cur)),
        ],
    );
    p.require("getrlimit(RLIMIT_NOFILE)", r == 0);
    p.check(
        "more descriptors than RLIMIT_NOFILE is EINVAL, before the array is read",
        p.poll_fault(limit.rlim_cur as usize + 1) == neg(EINVAL),
    );
    p.check(
        "an unreadable array is EFAULT",
        p.poll_fault(1) == neg(EFAULT),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "readiness/poll_fault",
    run,
    covers: &[
        #[cfg(target_arch = "x86_64")]
        Syscall::N_poll,
        #[cfg(not(target_arch = "x86_64"))]
        Syscall::N_ppoll,
    ],
    vehicles: Vehicle::KERNEL,
    ..DEFAULTS
};
