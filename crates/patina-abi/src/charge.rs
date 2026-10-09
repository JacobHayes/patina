//! What guest calls cost the virtual CPU: the model's fixed per-call charges.
//!
//! Every guest call into the runtime (a libc entry, a trapped syscall, a
//! counter read) is charged once, by its class, as user and system time.
//! These are model constants, like the virtual kernel's `HZ`: experimental
//! defaults chosen near native costs, not native timing claims, and never
//! calibrated against the host.

/// The kind of guest call a charge is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ChargeClass {
    /// A clock read: `clock_gettime`, `gettimeofday`, a trapped `rdtsc`
    /// (natively a vDSO read, all user time).
    Clock,
    /// An uncontended synchronization fast path or a cached identity query:
    /// a mutex, rwlock, once or semaphore that need not wait, `getpid`
    /// (natively user time).
    Sync,
    /// Anything else: a system call (a short user-side wrapper, the rest in
    /// the kernel).
    Syscall,
}

impl ChargeClass {
    pub const ALL: [ChargeClass; 3] = [ChargeClass::Clock, ChargeClass::Sync, ChargeClass::Syscall];

    /// What one call of this class costs.
    pub const fn cost(self) -> CpuCharge {
        match self {
            ChargeClass::Clock => CpuCharge::new(25, 0),
            ChargeClass::Sync => CpuCharge::new(20, 0),
            ChargeClass::Syscall => CpuCharge::new(50, 200),
        }
    }

    const fn index(self) -> usize {
        match self {
            ChargeClass::Clock => 0,
            ChargeClass::Sync => 1,
            ChargeClass::Syscall => 2,
        }
    }
}

/// Virtual CPU time, split as the kernel accounts it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CpuCharge {
    pub user_ns: u64,
    pub system_ns: u64,
}

impl CpuCharge {
    pub const fn new(user_ns: u64, system_ns: u64) -> Self {
        Self { user_ns, system_ns }
    }

    /// User plus system time: what the CPU clocks read.
    pub const fn total_ns(self) -> u64 {
        self.user_ns.saturating_add(self.system_ns)
    }

    pub fn add(&mut self, other: CpuCharge) {
        self.user_ns = self.user_ns.saturating_add(other.user_ns);
        self.system_ns = self.system_ns.saturating_add(other.system_ns);
    }
}

/// The startup work a process has done when `main` starts
/// ([`STARTUP_CPU_NANOS`](crate::STARTUP_CPU_NANOS), split between user and
/// system time).
pub const STARTUP_CPU_CHARGE: CpuCharge = CpuCharge::new(
    crate::STARTUP_CPU_NANOS / 2,
    crate::STARTUP_CPU_NANOS - crate::STARTUP_CPU_NANOS / 2,
);

/// Guest calls counted by class, not yet charged.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ChargeCounts([u64; 3]);

impl ChargeCounts {
    /// Count one call of `class`.
    pub fn count(&mut self, class: ChargeClass) {
        self.add(class, 1);
    }

    /// Count `calls` calls of `class`.
    pub fn add(&mut self, class: ChargeClass, calls: u64) {
        let slot = &mut self.0[class.index()];
        *slot = slot.saturating_add(calls);
    }

    /// No calls counted.
    pub const fn new() -> Self {
        Self([0; 3])
    }

    pub fn calls(&self, class: ChargeClass) -> u64 {
        self.0[class.index()]
    }

    pub fn is_empty(&self) -> bool {
        self.0 == [0; 3]
    }

    /// What the counted calls cost.
    pub fn charge(&self) -> CpuCharge {
        let mut total = CpuCharge::default();
        for class in ChargeClass::ALL {
            let cost = class.cost();
            let calls = self.calls(class);
            total.add(CpuCharge::new(
                cost.user_ns.saturating_mul(calls),
                cost.system_ns.saturating_mul(calls),
            ));
        }
        total
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counted_calls_charge_their_class_costs() {
        let mut counts = ChargeCounts::default();
        counts.count(ChargeClass::Clock);
        counts.count(ChargeClass::Sync);
        counts.count(ChargeClass::Syscall);
        let expected = [ChargeClass::Clock, ChargeClass::Sync, ChargeClass::Syscall]
            .into_iter()
            .fold(CpuCharge::default(), |mut total, class| {
                total.add(class.cost());
                total
            });
        assert_eq!(counts.charge(), expected);
        assert!(!counts.is_empty() && ChargeCounts::new().is_empty());
        assert_eq!(STARTUP_CPU_CHARGE.total_ns(), crate::STARTUP_CPU_NANOS);
    }
}
