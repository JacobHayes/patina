//! Compile-time (`#[cfg(feature = "profile")]`) inner-loop profiling instrumentation for
//! `patina-rt`.
//!
//! When the `profile` feature is disabled (default builds), every function here compiles to a
//! zero-instruction inline no-op.
//!
//! When enabled, timestamps are read with a raw `clock_gettime(CLOCK_MONOTONIC)` syscall through
//! the runtime's own syscall stub: both `x86_64` and `aarch64` run with `PR_SET_TSC` faulting
//! (`rdtsc`/`cntvct_el0` trigger SIGSEGV), so raw `CLOCK_MONOTONIC` is safe, architecture-uniform,
//! and shares the exact clock domain with the launcher and supervisor.

#[cfg(feature = "profile")]
mod imp {
    use crate::raw::{nr, sc2};
    use crate::state::{ctl_base, ctl_mapped};
    use proto::profile::ProfileTab;

    #[repr(C)]
    struct Timespec {
        tv_sec: i64,
        tv_nsec: i64,
    }

    const CLOCK_MONOTONIC: u64 = 1;

    #[inline]
    pub fn now_ns() -> u64 {
        let mut ts = Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        unsafe { sc2(nr::CLOCK_GETTIME, CLOCK_MONOTONIC, &mut ts as *mut _ as u64) };
        (ts.tv_sec as u64)
            .wrapping_mul(1_000_000_000)
            .wrapping_add(ts.tv_nsec as u64)
    }

    #[inline]
    fn tab() -> Option<&'static ProfileTab> {
        if !ctl_mapped() {
            return None;
        }
        Some(unsafe { ProfileTab::at(ctl_base()) })
    }

    #[inline]
    pub fn record_syscall(nr: u64, dt_ns: u64) {
        if let Some(t) = tab() {
            t.record_syscall(nr, dt_ns);
        }
    }

    #[inline]
    pub fn record_sigsys(dt_ns: u64) {
        if let Some(t) = tab() {
            t.record_sigsys(dt_ns);
        }
    }

    #[inline]
    pub fn record_fault(dt_ns: u64) {
        if let Some(t) = tab() {
            t.record_fault(dt_ns);
        }
    }

    #[inline]
    pub fn record_sup_ipc(dt_ns: u64) {
        if let Some(t) = tab() {
            t.record_sup_ipc(dt_ns);
        }
    }

    #[inline]
    pub fn record_compute_enter(dt_ns: u64) {
        if let Some(t) = tab() {
            t.record_compute_enter(dt_ns);
        }
    }

    #[inline]
    pub fn record_compute_exit(dt_ns: u64) {
        if let Some(t) = tab() {
            t.record_compute_exit(dt_ns);
        }
    }

    #[inline]
    pub fn record_compute_point(dt_ns: u64) {
        if let Some(t) = tab() {
            t.record_compute_point(dt_ns);
        }
    }

    #[inline]
    pub fn record_plan_on_map(dt_ns: u64) {
        if let Some(t) = tab() {
            t.record_plan_on_map(dt_ns);
        }
    }

    #[inline]
    pub fn record_plan_trap(dt_ns: u64) {
        if let Some(t) = tab() {
            t.record_plan_trap(dt_ns);
        }
    }

    #[inline]
    pub fn record_plan_entry(dt_ns: u64) {
        if let Some(t) = tab() {
            t.record_plan_entry(dt_ns);
        }
    }

    #[inline]
    pub fn record_log_trap(dt_ns: u64) {
        if let Some(t) = tab() {
            t.record_log_trap(dt_ns);
        }
    }

    #[inline]
    pub fn record_log_append(dt_ns: u64) {
        if let Some(t) = tab() {
            t.record_log_append(dt_ns);
        }
    }
}

#[cfg(not(feature = "profile"))]
mod imp {
    #[inline(always)]
    pub fn now_ns() -> u64 {
        0
    }
    #[inline(always)]
    pub fn record_syscall(_nr: u64, _dt_ns: u64) {}
    #[inline(always)]
    pub fn record_sigsys(_dt_ns: u64) {}
    #[inline(always)]
    pub fn record_fault(_dt_ns: u64) {}
    #[inline(always)]
    pub fn record_sup_ipc(_dt_ns: u64) {}
    #[inline(always)]
    pub fn record_compute_enter(_dt_ns: u64) {}
    #[inline(always)]
    pub fn record_compute_exit(_dt_ns: u64) {}
    #[inline(always)]
    pub fn record_compute_point(_dt_ns: u64) {}
    #[inline(always)]
    pub fn record_plan_on_map(_dt_ns: u64) {}
    #[inline(always)]
    pub fn record_plan_trap(_dt_ns: u64) {}
    #[inline(always)]
    pub fn record_plan_entry(_dt_ns: u64) {}
    #[inline(always)]
    pub fn record_log_trap(_dt_ns: u64) {}
    #[inline(always)]
    pub fn record_log_append(_dt_ns: u64) {}
}

pub use imp::*;
