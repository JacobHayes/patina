//! The CPU time guest calls are charged (the model's per-call costs,
//! [`ChargeClass`](patina_dst_abi::ChargeClass)), per task.
//!
//! Inert for now: totals accumulate, but no clock, CPU clock or timer reads
//! them yet. Embedders charge once per guest call; internal operations (the
//! scheduler's, a rescue's, expiry settlement) are never charged.
//!
//! Charging never allocates, because an embedder may charge from a signal
//! handler that interrupted the guest's allocator (the native counter trap).
//! A task's entry is reserved when it is spawned (or by the embedder,
//! [`Context::reserve_charge`]); a charge to a task with no entry lands in a
//! fixed `unreserved` total that the facts report, never in a new entry.

use std::collections::BTreeMap;

use patina_dst_abi::{ChargeClass, ChargeCounts, CpuCharge, STARTUP_CPU_CHARGE, TaskId};
use serde_json::{Map, Value};

use crate::Context;

/// Charged CPU time per task; `None` is the main thread before the embedder
/// manages its first task, and starts with the process's startup work.
#[derive(Debug)]
pub(crate) struct Charges {
    by_task: BTreeMap<Option<TaskId>, CpuCharge>,
    /// Charges to a task with no reserved entry: an embedder that charged
    /// before reserving. Never expected; reported when nonzero.
    unreserved: CpuCharge,
    /// The calls charged to the task charged last, not yet in `by_task`: a
    /// run of charges to one task (the common case, one thread's calls
    /// between switches) costs no map lookup each.
    hot: (Option<TaskId>, ChargeCounts),
}

impl Default for Charges {
    fn default() -> Self {
        Self {
            by_task: BTreeMap::from([(None, STARTUP_CPU_CHARGE)]),
            unreserved: CpuCharge::default(),
            hot: (None, ChargeCounts::new()),
        }
    }
}

impl Charges {
    /// Reserve `task`'s entry, so charging it never allocates. What was
    /// charged before is settled first, where it landed then: a charge to
    /// `task` before its reservation stays `unreserved`.
    pub(crate) fn reserve(&mut self, task: Option<TaskId>) {
        let counts = std::mem::replace(&mut self.hot.1, ChargeCounts::new());
        self.settle(self.hot.0, counts);
        self.by_task.entry(task).or_default();
    }

    /// Charge `calls` to `task`. Allocation-free.
    fn charge(&mut self, task: Option<TaskId>, calls: ChargeCounts) {
        if self.hot.0 != task {
            let (previous, counts) = std::mem::replace(&mut self.hot, (task, ChargeCounts::new()));
            self.settle(previous, counts);
        }
        for class in ChargeClass::ALL {
            self.hot.1.add(class, calls.calls(class));
        }
    }

    /// Land `counts` in `task`'s entry, or in `unreserved` without one.
    fn settle(&mut self, task: Option<TaskId>, counts: ChargeCounts) {
        if counts.is_empty() {
            return;
        }
        match self.by_task.get_mut(&task) {
            Some(charge) => charge.add(counts.charge()),
            None => self.unreserved.add(counts.charge()),
        }
    }

    /// The charges as they stand, the hot task's included.
    fn settled(&self) -> (BTreeMap<Option<TaskId>, CpuCharge>, CpuCharge) {
        let (mut by_task, mut unreserved) = (self.by_task.clone(), self.unreserved);
        let (task, counts) = self.hot;
        match by_task.get_mut(&task) {
            Some(charge) => charge.add(counts.charge()),
            None => unreserved.add(counts.charge()),
        }
        (by_task, unreserved)
    }

    /// The facts document's `cpu_charges`: every task's charge, the startup
    /// work under `initial`, and `unreserved` when anything landed there.
    pub(crate) fn facts(&self) -> Value {
        fn entry(charge: CpuCharge) -> Value {
            let mut entry = Map::new();
            entry.insert("user_ns".into(), Value::from(charge.user_ns));
            entry.insert("system_ns".into(), Value::from(charge.system_ns));
            Value::Object(entry)
        }
        let (by_task, unreserved) = self.settled();
        let mut map = Map::new();
        for (task, charge) in &by_task {
            let key = match task {
                None => "initial".to_string(),
                Some(task) => format!("task{}", task.0),
            };
            map.insert(key, entry(*charge));
        }
        if unreserved != CpuCharge::default() {
            map.insert("unreserved".into(), entry(unreserved));
        }
        Value::Object(map)
    }
}

impl Context {
    /// Charge `calls`, guest calls counted by class, to `task` (`None`: the
    /// main thread before the embedder manages its first task). Unrecorded:
    /// the calls a guest makes are the same on record and replay.
    /// Allocation-free: see the module documentation.
    pub fn charge_calls(&mut self, task: Option<TaskId>, calls: ChargeCounts) {
        if !calls.is_empty() {
            self.charges.charge(task, calls);
        }
    }

    /// Reserve `task`'s charge entry ahead of its first charge: an embedder
    /// whose tasks are known before the runtime spawns them (the native main
    /// thread). Spawned tasks are reserved by [`Context::task_spawn`].
    pub fn reserve_charge(&mut self, task: Option<TaskId>) {
        self.charges.reserve(task);
    }

    /// The CPU time charged to `task` so far.
    pub fn cpu_charge(&self, task: Option<TaskId>) -> CpuCharge {
        let charges = &self.charges;
        let Some(mut charge) = charges.by_task.get(&task).copied() else {
            return CpuCharge::default();
        };
        if charges.hot.0 == task {
            charge.add(charges.hot.1.charge());
        }
        charge
    }
}
