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

use patina_dst_abi::{ChargeCounts, CpuCharge, STARTUP_CPU_CHARGE, TaskId};
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
}

impl Default for Charges {
    fn default() -> Self {
        Self {
            by_task: BTreeMap::from([(None, STARTUP_CPU_CHARGE)]),
            unreserved: CpuCharge::default(),
        }
    }
}

impl Charges {
    /// Reserve `task`'s entry, so charging it never allocates.
    pub(crate) fn reserve(&mut self, task: Option<TaskId>) {
        self.by_task.entry(task).or_default();
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
        let mut map = Map::new();
        for (task, charge) in &self.by_task {
            let key = match task {
                None => "initial".to_string(),
                Some(task) => format!("task{}", task.0),
            };
            map.insert(key, entry(*charge));
        }
        if self.unreserved != CpuCharge::default() {
            map.insert("unreserved".into(), entry(self.unreserved));
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
        if calls.is_empty() {
            return;
        }
        let charges = &mut self.charges;
        match charges.by_task.get_mut(&task) {
            Some(charge) => charge.add(calls.charge()),
            None => charges.unreserved.add(calls.charge()),
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
        self.charges.by_task.get(&task).copied().unwrap_or_default()
    }
}
