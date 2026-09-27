//! time/libc_fault — glibc's clock reads (`clock_gettime`, its internal
//! `__clock_gettime`, `clock_getres`) handed a time they cannot write. They
//! are not the rows (time/fault holds those): glibc asks the vDSO, which
//! answers the clocks the kernel keeps in user space (realtime, monotonic,
//! boottime, TAI, raw and coarse) and stores the answer there, so a pointer
//! it cannot write faults in the caller: a `SIGSEGV` at that address, which
//! the handler here repairs so the store retries and completes. The vDSO
//! hands every other clock (the CPU clocks, the alarm clocks) to the system
//! call, where it is `EFAULT`.
//!
//! glibc's `nanosleep` is `clock_nanosleep(CLOCK_REALTIME)`, the row: a NULL
//! or unreadable request is `EFAULT`, and a sleep that completes leaves
//! `rem` alone, read-only or not.
//!
//! libc only.

use super::fault::{UNMAPPED, read_only};
use crate::catalog::{DEFAULTS, Scenario};
use crate::probe::{Probe, neg};
use crate::scenarios::mem::fault::{self, Repair, SEGV_ACCERR};
use crate::vehicle::{Vehicle, fold_errno};
use libc::*;
use patina_dst_syscalls::Syscall;

type ClockFn = unsafe extern "C" fn(clockid_t, *mut timespec) -> c_int;

unsafe extern "C" {
    fn __clock_gettime(clock: clockid_t, time: *mut timespec) -> c_int;
}

pub fn run(p: &Probe) {
    let doors: [(&str, ClockFn); 3] = [
        ("clock_gettime", clock_gettime),
        ("__clock_gettime", __clock_gettime),
        ("clock_getres", clock_getres),
    ];
    let installed = fault::install();
    for (name, door) in doors {
        let page = read_only(timespec {
            tv_sec: -1,
            tv_nsec: -1,
        }) as usize;
        let before = fault::observed().count;
        fault::arm(page, Repair::Protect);
        // SAFETY: the door stores into the armed page, which the handler
        // makes writable.
        let r = fold_errno(i64::from(unsafe {
            door(CLOCK_MONOTONIC, page as *mut timespec)
        }));
        let seen = fault::observed();
        // SAFETY: the page is readable (and, repaired, written).
        let stored = unsafe { (page as *const timespec).read() }.tv_nsec >= 0;
        p.rec
            .event(name, r)
            .arg("clock", "monotonic")
            .field("faults", (seen.count - before) as i64)
            .field("accerr", seen.code == SEGV_ACCERR)
            .field("at_time", seen.address == page)
            .field("stored", stored)
            .emit();
        p.check(
            &format!("{name} of a vDSO clock into a read-only time faults in the caller"),
            r == 0 && seen.count == before + 1 && seen.code == SEGV_ACCERR && seen.address == page,
        );
        p.check("and the retried store lands", stored);
        // SAFETY: the system call answers EFAULT without storing.
        let r = fold_errno(i64::from(unsafe {
            door(CLOCK_PROCESS_CPUTIME_ID, UNMAPPED as *mut timespec)
        }));
        p.rec.event(name, r).arg("clock", "process_cputime").emit();
        p.check(
            &format!("{name} of a CPU clock into an unwritable time is EFAULT"),
            r == neg(EFAULT),
        );
    }
    drop(installed);

    let sleep = |request: *const timespec, rem: *mut timespec| {
        // SAFETY: nanosleep copies as the row does.
        fold_errno(i64::from(unsafe { nanosleep(request, rem) }))
    };
    p.check(
        "nanosleep from a NULL request is EFAULT",
        sleep(std::ptr::null(), std::ptr::null_mut()) == neg(EFAULT),
    );
    p.check(
        "and from an unreadable one",
        sleep(UNMAPPED as *const timespec, std::ptr::null_mut()) == neg(EFAULT),
    );
    let untouched = timespec {
        tv_sec: 7,
        tv_nsec: 7,
    };
    let rem = read_only(untouched) as *mut timespec;
    let nanosecond = timespec {
        tv_sec: 0,
        tv_nsec: 1,
    };
    p.check(
        "a completed nanosleep leaves a read-only rem alone",
        // SAFETY: `rem` is a readable page.
        sleep(&nanosecond, rem) == 0 && unsafe { (*rem).tv_sec == 7 && (*rem).tv_nsec == 7 },
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "time/libc_fault",
    run,
    vehicles: &[Vehicle::Libc],
    covers: &[
        Syscall::N_clock_gettime,
        Syscall::N_clock_getres,
        Syscall::N_nanosleep,
    ],
    symbols: &[
        "clock_gettime",
        "__clock_gettime",
        "clock_getres",
        "nanosleep",
    ],
    ..DEFAULTS
};
