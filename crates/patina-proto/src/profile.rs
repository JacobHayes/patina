//! Compile-time (`#[cfg(feature = "profile")]`) fine-grained inner-loop profiling counters
//! stored in shared `Ctl` memory.
//!
//! Zero bytes and zero instructions in default builds. When the `profile` feature is enabled,
//! `ProfileTab` lives right after `MachineTab` in the control memfd so both `patina-rt` (across
//! all guest processes) and the supervisor can accumulate host-monotonic timing and event counts
//! with relaxed atomics, and the launcher reads them at boot end without affecting `boundary.log`
//! or deterministic digests.

use core::sync::atomic::{AtomicU64, Ordering::Relaxed};

/// Syscall slots: `0..NR_COUNT` for native syscall numbers, `NR_COUNT` for `patina_sdk`,
/// `NR_COUNT + 1` for any out-of-range/unknown syscall number.
pub const SYSCALL_SDK_SLOT: usize = crate::nr::NR_COUNT;
pub const SYSCALL_OTHER_SLOT: usize = crate::nr::NR_COUNT + 1;
pub const PROFILE_SYSCALL_SLOTS: usize = crate::nr::NR_COUNT + 2;

/// Supervisor request op slots: covers all `Op` discriminants `0..=67`.
pub const PROFILE_OP_SLOTS: usize = 68;

/// Page-aligned offset of `ProfileTab` in the control memfd.
pub const PROFILE_TAB_OFFSET: usize =
    (crate::machine::MACHINE_TAB_OFFSET + crate::machine::MACHINE_TAB_SIZE + 0xfff) & !0xfff;

pub const PROFILE_TAB_SIZE: usize = core::mem::size_of::<ProfileTab>();

/// Fixed-size inner-loop profiling table in shared `Ctl` memory.
/// Every counter is an `AtomicU64` updated with `Relaxed` ordering so multi-process guests and
/// the supervisor can record into it without aliasing or locking.
#[repr(C)]
pub struct ProfileTab {
    /// Per-syscall trap counts and total host monotonic ns spent inside `on_sigsys`.
    pub syscalls_count: [AtomicU64; PROFILE_SYSCALL_SLOTS],
    pub syscalls_ns: [AtomicU64; PROFILE_SYSCALL_SLOTS],

    /// Total `on_sigsys` and `on_fault` counts and host monotonic ns.
    pub sigsys_count: AtomicU64,
    pub sigsys_ns: AtomicU64,
    pub fault_count: AtomicU64,
    pub fault_ns: AtomicU64,

    /// Guest-side supervisor IPC round-trips (`rt::sup::call_sup_raw`).
    pub sup_ipc_count: AtomicU64,
    pub sup_ipc_ns: AtomicU64,

    /// Supervisor-side per-`Op` request counts and handling time (host monotonic ns).
    pub sup_op_count: [AtomicU64; PROFILE_OP_SLOTS],
    pub sup_op_ns: [AtomicU64; PROFILE_OP_SLOTS],

    /// Compute-point runtime overhead (`rt::compute`).
    pub compute_enter_count: AtomicU64,
    pub compute_enter_ns: AtomicU64,
    pub compute_exit_count: AtomicU64,
    pub compute_exit_ns: AtomicU64,
    pub compute_point_count: AtomicU64,
    pub compute_point_ns: AtomicU64,

    /// Load-time plan runtime overhead (`rt::plans`).
    pub plan_on_map_count: AtomicU64,
    pub plan_on_map_ns: AtomicU64,
    pub plan_trap_count: AtomicU64,
    pub plan_trap_ns: AtomicU64,
    pub plan_entry_count: AtomicU64,
    pub plan_entry_ns: AtomicU64,

    /// Boundary log record write & hashing overhead (`rt::log`).
    pub log_trap_count: AtomicU64,
    pub log_trap_ns: AtomicU64,
    pub log_append_count: AtomicU64,
    pub log_append_ns: AtomicU64,
}

impl ProfileTab {
    /// View the `ProfileTab` inside the mapped control region at `ctl_base`.
    ///
    /// # Safety
    /// `ctl_base` must point to a valid, zero-initialized control mapping of at least `CTL_SIZE`
    /// bytes.
    #[inline]
    pub unsafe fn at<'a>(ctl_base: *mut u8) -> &'a ProfileTab {
        &*(ctl_base.add(PROFILE_TAB_OFFSET) as *const ProfileTab)
    }

    #[inline]
    pub fn record_syscall(&self, nr: u64, dt_ns: u64) {
        let slot = syscall_slot(nr);
        self.syscalls_count[slot].fetch_add(1, Relaxed);
        self.syscalls_ns[slot].fetch_add(dt_ns, Relaxed);
    }

    #[inline]
    pub fn record_sigsys(&self, dt_ns: u64) {
        self.sigsys_count.fetch_add(1, Relaxed);
        self.sigsys_ns.fetch_add(dt_ns, Relaxed);
    }

    #[inline]
    pub fn record_fault(&self, dt_ns: u64) {
        self.fault_count.fetch_add(1, Relaxed);
        self.fault_ns.fetch_add(dt_ns, Relaxed);
    }

    #[inline]
    pub fn record_sup_ipc(&self, dt_ns: u64) {
        self.sup_ipc_count.fetch_add(1, Relaxed);
        self.sup_ipc_ns.fetch_add(dt_ns, Relaxed);
    }

    #[inline]
    pub fn record_sup_op(&self, op: usize, dt_ns: u64) {
        if op < PROFILE_OP_SLOTS {
            self.sup_op_count[op].fetch_add(1, Relaxed);
            self.sup_op_ns[op].fetch_add(dt_ns, Relaxed);
        }
    }

    #[inline]
    pub fn record_compute_enter(&self, dt_ns: u64) {
        self.compute_enter_count.fetch_add(1, Relaxed);
        self.compute_enter_ns.fetch_add(dt_ns, Relaxed);
    }

    #[inline]
    pub fn record_compute_exit(&self, dt_ns: u64) {
        self.compute_exit_count.fetch_add(1, Relaxed);
        self.compute_exit_ns.fetch_add(dt_ns, Relaxed);
    }

    #[inline]
    pub fn record_compute_point(&self, dt_ns: u64) {
        self.compute_point_count.fetch_add(1, Relaxed);
        self.compute_point_ns.fetch_add(dt_ns, Relaxed);
    }

    #[inline]
    pub fn record_plan_on_map(&self, dt_ns: u64) {
        self.plan_on_map_count.fetch_add(1, Relaxed);
        self.plan_on_map_ns.fetch_add(dt_ns, Relaxed);
    }

    #[inline]
    pub fn record_plan_trap(&self, dt_ns: u64) {
        self.plan_trap_count.fetch_add(1, Relaxed);
        self.plan_trap_ns.fetch_add(dt_ns, Relaxed);
    }

    #[inline]
    pub fn record_plan_entry(&self, dt_ns: u64) {
        self.plan_entry_count.fetch_add(1, Relaxed);
        self.plan_entry_ns.fetch_add(dt_ns, Relaxed);
    }

    #[inline]
    pub fn record_log_trap(&self, dt_ns: u64) {
        self.log_trap_count.fetch_add(1, Relaxed);
        self.log_trap_ns.fetch_add(dt_ns, Relaxed);
    }

    #[inline]
    pub fn record_log_append(&self, dt_ns: u64) {
        self.log_append_count.fetch_add(1, Relaxed);
        self.log_append_ns.fetch_add(dt_ns, Relaxed);
    }
}

/// Map a raw syscall number to its slot in `ProfileTab::syscalls_*`.
#[inline]
pub fn syscall_slot(nr: u64) -> usize {
    if (nr as usize) < crate::nr::NR_COUNT {
        nr as usize
    } else if nr == crate::sdk::SYSCALL {
        SYSCALL_SDK_SLOT
    } else {
        SYSCALL_OTHER_SLOT
    }
}

/// Human-readable name for a `ProfileTab` syscall slot.
pub fn syscall_name(slot: usize) -> &'static str {
    if slot < crate::nr::NR_COUNT {
        crate::nr::NAMES[slot].unwrap_or("unknown")
    } else if slot == SYSCALL_SDK_SLOT {
        "patina_sdk"
    } else {
        "other"
    }
}

/// Human-readable name for a supervisor `Op` discriminant.
pub fn op_name(op: usize) -> &'static str {
    use crate::ctl::Op;
    match Op::from_u32(op as u32) {
        Some(Op::Hello) => "Hello",
        Some(Op::Yield) => "Yield",
        Some(Op::Sleep) => "Sleep",
        Some(Op::FutexWait) => "FutexWait",
        Some(Op::FutexWake) => "FutexWake",
        Some(Op::FutexRequeue) => "FutexRequeue",
        Some(Op::Park) => "Park",
        Some(Op::ThreadExit) => "ThreadExit",
        Some(Op::ProcExit) => "ProcExit",
        Some(Op::Forked) => "Forked",
        Some(Op::VforkStart) => "VforkStart",
        Some(Op::Exec) => "Exec",
        Some(Op::WaitPark) => "WaitPark",
        Some(Op::SigSend) => "SigSend",
        Some(Op::SigWait) => "SigWait",
        Some(Op::SigSuspend) => "SigSuspend",
        Some(Op::TimerSet) => "TimerSet",
        Some(Op::CrashPoint) => "CrashPoint",
        Some(Op::Stop) => "Stop",
        Some(Op::HostError) => "HostError",
        Some(Op::SigTake) => "SigTake",
        Some(Op::SigAction) => "SigAction",
        Some(Op::SigFd) => "SigFd",
        Some(Op::Shm) => "Shm",
        Some(Op::TimerFdSet) => "TimerFdSet",
        Some(Op::TimerFdGet) => "TimerFdGet",
        Some(Op::WireSocket) => "WireSocket",
        Some(Op::WireBind) => "WireBind",
        Some(Op::WireConnect) => "WireConnect",
        Some(Op::WireAccepted) => "WireAccepted",
        Some(Op::WireSent) => "WireSent",
        Some(Op::WireRenew) => "WireRenew",
        Some(Op::UdpSocket) => "UdpSocket",
        Some(Op::UdpBind) => "UdpBind",
        Some(Op::UdpConnect) => "UdpConnect",
        Some(Op::UdpSend) => "UdpSend",
        Some(Op::SdkViolation) => "SdkViolation",
        Some(Op::VtReclaim) => "VtReclaim",
        Some(Op::Net) => "Net",
        Some(Op::PidMachine) => "PidMachine",
        Some(Op::MapsSync) => "MapsSync",
        Some(Op::ShadowReclaim) => "ShadowReclaim",
        Some(Op::Machine) => "Machine",
        Some(Op::Settle) => "Settle",
        None => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_tab_layout_and_helpers() {
        const { assert!(PROFILE_TAB_OFFSET & 0xfff == 0) };
        const { assert!(PROFILE_TAB_SIZE > 0) };
        assert_eq!(syscall_slot(crate::sdk::SYSCALL), SYSCALL_SDK_SLOT);
        assert_eq!(syscall_name(SYSCALL_SDK_SLOT), "patina_sdk");
        assert_eq!(syscall_slot(u64::MAX), SYSCALL_OTHER_SLOT);
        assert_eq!(syscall_name(SYSCALL_OTHER_SLOT), "other");
        assert_eq!(op_name(crate::ctl::Op::Hello as usize), "Hello");
        assert_eq!(op_name(crate::ctl::Op::Yield as usize), "Yield");
        assert_eq!(op_name(crate::ctl::Op::Settle as usize), "Settle");
    }
}
