//! The CPU time guest calls are charged (the model's per-call costs,
//! [`ChargeClass`](patina_dst_abi::ChargeClass)), per task, and the
//! monotonic time those charges move.
//!
//! Embedders charge once per guest call; internal operations (the
//! scheduler's, expiry settlement) are never charged. The process's CPU time
//! is the startup work plus every charge, split as user and system time.
//! The monotonic clock moves by every charge ([`Context::show_carry`]) and by
//! idle advances (a sleep or wait no runnable task is computing through),
//! and by nothing else.
//!
//! Charging never allocates its own bookkeeping, because an embedder may
//! charge from a signal handler that interrupted the guest's allocator (the
//! native counter trap). A task's entry is reserved when it is spawned (or
//! by the embedder, [`Context::reserve_charge`]); a charge to a task with no
//! entry lands in a fixed `unreserved` total that the facts report, never in
//! a new entry.

use std::collections::BTreeMap;

use patina_dst_abi::{ChargeClass, ChargeCounts, ClockKind, CpuCharge, STARTUP_CPU_CHARGE, TaskId};
use serde_json::{Map, Value};

use crate::{Context, RuntimeError};

/// Absolute deadlines on the process's CPU-time lines: its earliest armed
/// CPU-time timer on user time (`ITIMER_VIRTUAL`, a `CPUCLOCK_VIRT` timer)
/// and on user plus system time (`ITIMER_PROF`, the other CPU clocks). An
/// embedder publishes them ([`Context::set_cpu_alarms`]) so an escalated
/// poll charges up to the earliest instead of ramping toward it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CpuAlarms {
    pub user_ns: Option<u64>,
    pub total_ns: Option<u64>,
}

/// Charged CPU time per task; `None` is the main thread before the embedder
/// manages its first task, and starts with the process's startup work.
#[derive(Debug)]
pub(crate) struct Charges {
    by_task: BTreeMap<Option<TaskId>, CpuCharge>,
    /// Charges to a task with no reserved entry: an embedder that charged
    /// before reserving. Never expected; reported when nonzero.
    unreserved: CpuCharge,
    /// The calls charged to the task charged last, not yet in `by_task`: a
    /// run of charges to one task (one thread's calls between switches)
    /// costs no map lookup each.
    hot: (Option<TaskId>, ChargeCounts),
    /// The process's CPU time: the startup work and every charge.
    total: CpuCharge,
    /// The task the scheduler last selected: the one an escalation charges.
    pub(crate) running: Option<TaskId>,
    /// Charged time the monotonic clock does not show yet: what a charge
    /// stopped short of at a pending deadline, or what was charged where
    /// the clock may not move (an embedder section, an embedder's gateway).
    /// Shown by the next [`Context::show_carry`].
    carry: u64,
    pub(crate) alarms: CpuAlarms,
}

impl Default for Charges {
    fn default() -> Self {
        Self {
            by_task: BTreeMap::from([(None, STARTUP_CPU_CHARGE)]),
            unreserved: CpuCharge::default(),
            hot: (None, ChargeCounts::new()),
            total: STARTUP_CPU_CHARGE,
            running: None,
            carry: 0,
            alarms: CpuAlarms::default(),
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
    pub(crate) fn charge(&mut self, task: Option<TaskId>, calls: ChargeCounts) {
        if self.hot.0 != task {
            let (previous, counts) = std::mem::replace(&mut self.hot, (task, ChargeCounts::new()));
            self.settle(previous, counts);
        }
        for class in ChargeClass::ALL {
            self.hot.1.add(class, calls.calls(class));
        }
        let charge = calls.charge();
        self.total.add(charge);
        self.carry = self.carry.saturating_add(charge.total_ns());
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

    pub(crate) fn total(&self) -> CpuCharge {
        self.total
    }

    pub(crate) fn carry(&self) -> u64 {
        self.carry
    }

    /// An idle advance of `nanos`: the charged work still to show ran before
    /// the wait began, so the wait's time covers it.
    pub(crate) fn absorb_idle(&mut self, nanos: u64) {
        self.carry = self.carry.saturating_sub(nanos);
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
    /// main thread before the embedder manages its first task), and move
    /// monotonic time by what they cost ([`Context::show_carry`]).
    /// Unrecorded: the calls a guest makes are the same on record and
    /// replay.
    pub fn charge_calls(
        &mut self,
        task: Option<TaskId>,
        calls: ChargeCounts,
    ) -> Result<(), RuntimeError> {
        self.charges.charge(task, calls);
        self.show_carry()
    }

    /// Charge `calls` to `task` as [`Context::charge_calls`] does, their time
    /// carried until the next [`Context::show_carry`]: for an embedder that
    /// charges where it may hold a decision an expiry would make stale (the
    /// native shim's gateways, which can sit between choosing a task to wake
    /// and waking it). Never expires anything and never allocates.
    ///
    /// An embedder that charges its calls this way also applies the
    /// escalation a poll streak earns itself, at the end of the guest call
    /// that completed it ([`Context::take_poll_streak`],
    /// [`Context::escalate_call`]).
    pub fn accrue_calls(&mut self, task: Option<TaskId>, calls: ChargeCounts) {
        if !calls.is_empty() {
            self.spin.paced = true;
            self.charges.charge(task, calls);
        }
    }

    /// Show the charged time the clock does not show yet. The clock stops at
    /// the earliest pending deadline (a timed park's, or the embedder's
    /// alarm), expires the parks due there, in `(deadline, registration)`
    /// order, and carries the rest to the next show, so every deadline is
    /// reached exactly; CPU time is never held back. An alarm the clock has
    /// reached stays a barrier until its owner settles it and publishes the
    /// next. A no-op inside an embedder section, where time stands still:
    /// the embedder cannot settle an expiry there.
    pub fn show_carry(&mut self) -> Result<(), RuntimeError> {
        if self.embedder_section || self.charges.carry == 0 || self.clock.is_none() {
            return Ok(());
        }
        let now = self.current_monotonic()?;
        let wanted = now.saturating_add(self.charges.carry);
        let target = self
            .next_barrier(now)
            .map_or(wanted, |deadline| deadline.min(wanted));
        if target == now {
            return Ok(());
        }
        self.charges.carry -= target - now;
        self.clock
            .as_mut()
            .expect("driver was checked")
            .sleep_until(ClockKind::Monotonic, target)?;
        self.expire_due_timers()
    }

    /// The earliest point a charge may not move the clock past from `now`:
    /// a later timed park's deadline, or the embedder's alarm, even one the
    /// clock has reached and its owner has not settled yet.
    fn next_barrier(&self, now: u64) -> Option<u64> {
        let park = self
            .timers
            .keys()
            .map(|(deadline, _)| *deadline)
            .find(|deadline| *deadline > now);
        let alarm = self.alarm.filter(|deadline| *deadline >= now);
        [park, alarm].into_iter().flatten().min()
    }

    /// The earliest monotonic deadline after `now`: a timed park's or the
    /// embedder's alarm.
    pub(crate) fn earliest_deadline_after(&self, now: u64) -> Option<u64> {
        let park = self
            .timers
            .keys()
            .map(|(deadline, _)| *deadline)
            .find(|deadline| *deadline > now);
        [park, self.alarm]
            .into_iter()
            .flatten()
            .filter(|deadline| *deadline > now)
            .min()
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

    /// The process's CPU time: the startup work and every charge since.
    /// Unrecorded: a pure function of the guest's calls and the recorded
    /// stream.
    pub fn cpu_time(&self) -> CpuCharge {
        self.charges.total()
    }

    /// Publish the process's earliest CPU-time timer deadlines (see
    /// [`CpuAlarms`]). Unrecorded bookkeeping the embedder derives from the
    /// guest's own calls, like [`Context::set_alarm`].
    pub fn set_cpu_alarms(&mut self, alarms: CpuAlarms) {
        self.charges.alarms = alarms;
    }
}
