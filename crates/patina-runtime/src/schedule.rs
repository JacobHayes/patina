//! Task scheduling, timer rescue, and schedule diagnostics.

use crate::recording::{decode_optional_task, decode_task, decode_unit};
use crate::{Context, RuntimeError};
use patina_dst_abi::{ClockKind, EffectError, ErrorCode, Operation, Outcome, TaskId};
use patina_dst_driver_api::SchedulerDriver;
use patina_dst_trace::{Replayer, TraceError};
use std::collections::BTreeMap;

/// How a task's schedule accounting ended. Derived purely from the task-lifecycle
/// shadow at report time — driven by the same recorded ops on record and replay,
/// so it reproduces exactly. There is no panic/abort cause at this layer: a guest
/// panic aborts the process, so a task the runtime observed is either one it saw
/// completed or one still live when the run ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskCompletionCause {
    /// The task ran a `TaskComplete` boundary (a std thread body returned and was
    /// joined, or the guest completed the task explicitly).
    Completed,
    /// The task was still live when the run ended — the initial thread of control
    /// that reached process exit, or a detached worker never joined.
    LiveAtExit,
}

impl TaskCompletionCause {
    /// Stable machine-readable token used in the `PATINA_SCHEDULE_REPORT` line.
    pub(super) fn as_str(self) -> &'static str {
        match self {
            TaskCompletionCause::Completed => "completed",
            TaskCompletionCause::LiveAtExit => "live-at-exit",
        }
    }
}

/// Per-task scheduling-boundary count and whether the task's body was
/// effectively unexplorable — it ran from first scheduled to completion without
/// ever passing a scheduling boundary (yield or park), so no seed could
/// interleave anything inside it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TaskScheduleStat {
    pub task: TaskId,
    /// Voluntary reschedules taken on the interposed effect surface. Scale with a
    /// genuine concurrent loop; zero means an atomics-only (unschedulable) body.
    pub yields: u64,
    /// Blocking waits. For an atomics-only worker these are only spawn/join
    /// housekeeping and do not scale with its work.
    pub parks: u64,
    /// Total scheduling boundaries (`yields + parks`) between spawn and
    /// completion.
    pub boundaries: u64,
    /// Global scheduling-event steps the task was live for: the span of
    /// task-lifecycle boundaries (across all tasks) between this task's spawn and
    /// its completion (or the run's end, for a task still live). Orthogonal to
    /// `boundaries` (this task's own activity): it captures longevity/overlap, so
    /// a short-lived helper and a run-long coordinator are distinguishable even
    /// when their own boundary counts match.
    pub lifetime: u64,
    /// How the task's accounting ended (completed vs still live at run end).
    pub cause: TaskCompletionCause,
    /// A spawned worker (not the initial task) that completed without ever
    /// yielding on the effect surface: its interleavings are unreachable at any
    /// seed.
    pub vacuous: bool,
}

/// End-of-run schedule-exploration diagnostics. Surfaces whether a multithreaded
/// guest's schedule was actually explorable, so "N seeds explored, all clean"
/// can never silently mean "nothing inside a thread was ever schedulable".
/// Computed from the runtime's task-lifecycle shadow, which is maintained
/// identically on record and replay, so the diagnostic reproduces on replay.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScheduleDiagnostics {
    /// Distinct tasks the guest spawned, including the initial task.
    pub tasks_spawned: u64,
    /// High-water mark of concurrently-live tasks.
    pub max_concurrent: u64,
    /// Total yield/park boundaries across every task.
    pub total_boundaries: u64,
    /// Per-completed-task boundary counts, in spawn order.
    pub tasks: Vec<TaskScheduleStat>,
    /// Spawned workers that ran start-to-finish with zero boundaries.
    pub vacuous: Vec<TaskId>,
}

impl ScheduleDiagnostics {
    /// Whether there was any concurrency to explore at all. A single-task run
    /// has no schedule, so the diagnostic stays silent for it.
    pub fn had_concurrency(&self) -> bool {
        self.tasks_spawned >= 2
    }
}

/// A task still running (spawned, not yet completed) with its spawn order and
/// the scheduling boundaries it has passed so far, split by kind. `yields` are
/// voluntary reschedules the guest takes every time it touches the interposed
/// effect surface (a lock/unlock, syscall, sleep, …); they scale with a genuine
/// concurrent loop. `parks` are blocking waits, which for an atomics-only worker
/// are only spawn/join housekeeping and do not scale with its work.
struct LiveTask {
    order: u64,
    yields: u64,
    parks: u64,
    /// Global scheduling-step clock value when this task was spawned.
    spawn_step: u64,
}

/// A completed task's final schedule accounting.
struct CompletedTask {
    task: TaskId,
    order: u64,
    yields: u64,
    parks: u64,
    /// Global scheduling-step clock value at spawn and at completion; their
    /// difference is the task's lifetime in scheduling steps.
    spawn_step: u64,
    complete_step: u64,
}

/// Yield count that spawning and joining a std thread incurs on its own —
/// independent of what the thread's body does. A spawned worker whose yields do
/// not exceed this baseline performed zero interposed operations of its own: it
/// never touched the effect surface at a schedulable point, so any loop it ran
/// was atomics-only (a `std::sync::RwLock` fast-path read-modify-write, say) and
/// completely invisible to the runtime. Yields are the stable signal — blocking
/// parks vary by seed, but the scaffolding yield count is invariant to the body's
/// iteration count. A worker at or below it is unexplorable; one real interposed
/// op lifts it above, a `--yield-points` build to tens, an interposed sync loop
/// (contended mutexes) to hundreds.
///
/// The baseline is platform-specific and measured with the do-nothing-thread
/// experiment (spawn a worker with an empty body, read its yields from
/// `PATINA_SCHEDULE_REPORT`):
///
/// - **macOS = 4.** Rust std's Darwin thread `Parker` spins on the interposed
///   `dispatch_semaphore` during the spawn/join handshake, so the *worker* incurs
///   four scheduling boundaries before its body runs.
/// - **Linux = 0.** Std lowers parking to raw `futex`, and the join handshake
///   parks the *main* thread, not the worker; a do-nothing worker reaches
///   completion with zero worker-side boundaries. Measured on glibc 2.39/aarch64:
///   an empty-body worker reports `0y+0p`, an uncontended-`Mutex` worker likewise
///   `0y+0p` (uncontended locks are pure userspace atomics), and a `--yield-points`
///   worker reports tens — so a floor of 0 flags exactly the atomics-only workers
///   (an atomics-only lost-update race) while one interposed boundary clears it.
#[cfg(target_os = "macos")]
const SCAFFOLDING_YIELD_FLOOR: u64 = 4;

#[cfg(not(target_os = "macos"))]
const SCAFFOLDING_YIELD_FLOOR: u64 = 0;

/// Per-task scheduling-boundary accounting backing [`ScheduleDiagnostics`].
/// Every field is driven by the recorded task-lifecycle ops, so it is populated
/// identically on record and replay.
#[derive(Default)]
pub(super) struct ScheduleTracker {
    live: BTreeMap<TaskId, LiveTask>,
    completed: Vec<CompletedTask>,
    spawned: u64,
    max_concurrent: u64,
    /// Monotonic global scheduling-event clock: every task-lifecycle boundary
    /// (spawn/yield/park/complete, on any task) advances it by one. Stamped at a
    /// task's spawn and completion to derive its lifetime. Driven entirely by the
    /// recorded ops, so it advances identically on record and replay.
    steps: u64,
}

impl ScheduleTracker {
    fn on_spawn(&mut self, task: TaskId) {
        let order = self.spawned;
        self.spawned += 1;
        self.steps += 1;
        self.live.insert(
            task,
            LiveTask {
                order,
                yields: 0,
                parks: 0,
                spawn_step: self.steps,
            },
        );
        self.max_concurrent = self.max_concurrent.max(self.live.len() as u64);
    }

    fn on_yield(&mut self, task: TaskId) {
        self.steps += 1;
        if let Some(live) = self.live.get_mut(&task) {
            live.yields += 1;
        }
    }

    fn on_park(&mut self, task: TaskId) {
        self.steps += 1;
        if let Some(live) = self.live.get_mut(&task) {
            live.parks += 1;
        }
    }

    fn on_complete(&mut self, task: TaskId) {
        self.steps += 1;
        if let Some(live) = self.live.remove(&task) {
            self.completed.push(CompletedTask {
                task,
                order: live.order,
                yields: live.yields,
                parks: live.parks,
                spawn_step: live.spawn_step,
                complete_step: self.steps,
            });
        }
    }

    /// Total `TaskYield` boundaries this run has taken for `task` so far,
    /// whether the task is still live or already completed. Divergence
    /// diagnostics use this for record-vs-replay yield accounting.
    fn yields_for(&self, task: TaskId) -> u64 {
        self.live
            .get(&task)
            .map(|live| live.yields)
            .or_else(|| {
                self.completed
                    .iter()
                    .find(|done| done.task == task)
                    .map(|done| done.yields)
            })
            .unwrap_or(0)
    }

    pub(super) fn diagnostics(&self) -> ScheduleDiagnostics {
        // Each record carries the completion step as `Option`: `Some` for a task
        // the runtime saw complete, `None` for one still live at run end (whose
        // lifetime runs to the current step clock).
        let mut records: Vec<(u64, TaskId, u64, u64, u64, Option<u64>)> = self
            .completed
            .iter()
            .map(|done| {
                (
                    done.order,
                    done.task,
                    done.yields,
                    done.parks,
                    done.spawn_step,
                    Some(done.complete_step),
                )
            })
            .chain(self.live.iter().map(|(task, live)| {
                (
                    live.order,
                    *task,
                    live.yields,
                    live.parks,
                    live.spawn_step,
                    None,
                )
            }))
            .collect();
        records.sort_by_key(|(order, _, _, _, _, _)| *order);
        let total_boundaries = records
            .iter()
            .map(|(_, _, yields, parks, _, _)| yields + parks)
            .sum();
        let mut vacuous = Vec::new();
        let tasks = records
            .iter()
            .map(|&(order, task, yields, parks, spawn_step, complete_step)| {
                // Lifetime spans global scheduling steps from spawn to completion
                // (or to the run's end for a still-live task). Cause distinguishes
                // the two.
                let (lifetime, cause) = match complete_step {
                    Some(end) => (
                        end.saturating_sub(spawn_step),
                        TaskCompletionCause::Completed,
                    ),
                    None => (
                        self.steps.saturating_sub(spawn_step),
                        TaskCompletionCause::LiveAtExit,
                    ),
                };
                // The initial task (spawn order 0) is the guest's own thread of
                // control, not a spawned worker, so it is not a vacuity signal.
                // A spawned worker whose yields do not clear the thread-lifecycle
                // scaffolding floor exposed no schedulable body: any loop it ran
                // was atomics-only and unschedulable at any seed. That is the
                // exact shape of an atomics-only lost-update race window, and
                // the yield count is invariant to its iteration count.
                // A spawned worker (order > 0) is vacuous when its yields do not
                // exceed the platform scaffolding floor. Written as `!(> floor)`
                // rather than `<= floor` so the comparison stays valid when the
                // floor is the type minimum (Linux = 0), where `<= 0` would trip
                // clippy::absurd_extreme_comparisons; newer clippy flags this
                // form as nonminimal_bool instead, hence the scoped allow.
                #[allow(clippy::nonminimal_bool)]
                let is_vacuous = order > 0 && !(yields > SCAFFOLDING_YIELD_FLOOR);
                if is_vacuous {
                    vacuous.push(task);
                }
                TaskScheduleStat {
                    task,
                    yields,
                    parks,
                    boundaries: yields + parks,
                    lifetime,
                    cause,
                    vacuous: is_vacuous,
                }
            })
            .collect();
        ScheduleDiagnostics {
            tasks_spawned: self.spawned,
            max_concurrent: self.max_concurrent,
            total_boundaries,
            tasks,
            vacuous,
        }
    }
}

/// Detection for the yield-accounting failure class: a replayed scheduler-op
/// stream that stops matching the recording at a `TaskYield`. The bare trace
/// error ("trace ended before operation N") says nothing about WHY; when a
/// `TaskYield` sits on either side of the divergence, fold in per-task
/// record-vs-replay yield accounting so a guard hit count that is not a pure
/// function of the program surfaces as a specific, self-explaining failure.
/// Any other divergence passes through unchanged.
pub(super) fn classify_yield_divergence(
    schedule: &ScheduleTracker,
    replayer: &Replayer,
    error: TraceError,
) -> RuntimeError {
    let yield_task = |operation: &Operation| match operation {
        Operation::TaskYield { task } => Some(*task),
        _ => None,
    };
    let (task, run_ahead) = match &error {
        // The run produced a TaskYield the recording does not have (either past
        // the end of the trace or where the recording expects a different op).
        TraceError::ReplayExhausted { actual, .. } => match yield_task(actual) {
            Some(task) => (task, true),
            None => return error.into(),
        },
        TraceError::OperationMismatch {
            expected, actual, ..
        } => match (yield_task(actual), yield_task(expected)) {
            (Some(task), _) => (task, true),
            // The recording expects a TaskYield the run did not produce.
            (None, Some(task)) => (task, false),
            (None, None) => return error.into(),
        },
        _ => return error.into(),
    };
    let executed = schedule.yields_for(task);
    let recorded = replayer.recorded_yields_for(task);
    let direction = if run_ahead {
        format!("this run reached TaskYield #{} for that task", executed + 1)
    } else {
        format!(
            "this run has taken {executed} TaskYield operations for that task and now performs a \
different operation where the recording expects another TaskYield"
        )
    };
    RuntimeError::ScheduleDivergence {
        detail: format!(
            "yield-point replay divergence on task {}: {direction}, but the recording holds \
{recorded} TaskYield operations for it ({} recorded operations in total). Yield-point guard hits \
must be a pure function of the program; a record/replay count difference means instrumented guest \
code branched differently between the two runs (canonical cause: a host-timing-dependent branch, \
e.g. racing reference-count drops against a still-exiting host thread). Underlying trace error: \
{error}",
            task.0,
            replayer.total(),
        ),
    }
}

impl Context {
    /// End-of-run schedule-exploration diagnostics. See [`ScheduleDiagnostics`].
    /// Also emitted to stderr by [`Context::finish`] for multithreaded runs.
    pub fn schedule_diagnostics(&self) -> ScheduleDiagnostics {
        self.schedule.diagnostics()
    }

    pub fn task_spawn(&mut self, label: &str) -> Result<TaskId, RuntimeError> {
        if self.scheduler.is_none() {
            return Err(EffectError::missing_driver("scheduler").into());
        }
        let operation = Operation::TaskSpawn {
            label: label.into(),
        };
        let expected = self.replay_expected(&operation)?;
        let result = self
            .scheduler
            .as_mut()
            .expect("driver was checked")
            .spawn(label);
        let actual = match result {
            Ok(task) => Outcome::Task(task),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        let task = decode_task(&operation, outcome)?;
        self.scheduler_tasks.insert(task);
        self.schedule.on_spawn(task);
        Ok(task)
    }

    /// Record a successful virtual signal generation, including coalesced and
    /// ignored instances. Delivery is derived from this stream and task state.
    pub fn signal_generated(
        &mut self,
        seq: u64,
        sig: u8,
        target: patina_dst_abi::SignalTarget,
        code: i32,
        value: i64,
    ) -> Result<(), RuntimeError> {
        let operation = Operation::SignalGenerated {
            seq,
            sig,
            target,
            code,
            value,
        };
        let expected = self.replay_expected(&operation)?;
        let outcome = self.reconcile(operation.clone(), expected, Outcome::Unit)?;
        decode_unit(&operation, outcome)
    }

    pub fn task_yield(&mut self, task: TaskId) -> Result<(), RuntimeError> {
        self.scheduler_unit(Operation::TaskYield { task }, |scheduler| {
            scheduler.yield_task(task)
        })?;
        // A yield leaves the task runnable; a yielded task is never parked.
        self.parked_tasks.remove(&task);
        self.schedule.on_yield(task);
        Ok(())
    }

    pub fn task_park(&mut self, task: TaskId, reason: &str) -> Result<(), RuntimeError> {
        self.scheduler_unit(
            Operation::TaskPark {
                task,
                reason: reason.into(),
            },
            |scheduler| scheduler.park(task, reason),
        )?;
        self.parked_tasks.insert(task);
        self.schedule.on_park(task);
        Ok(())
    }

    /// Park `task` with a virtual-clock deadline. The scheduler parks it exactly
    /// like [`Context::task_park`]; the runtime additionally registers a timer
    /// that expires when virtual time reaches the deadline (see
    /// [`Context::expire_due_timers`]). A deadline already reached expires at
    /// registration, so the task is woken before this returns: an absolute wait
    /// whose time has passed never stays parked beside a runnable peer.
    /// `deadline_nanos` is interpreted in the `clock` domain and converted to
    /// monotonic at registration through recorded clock reads, so the registry
    /// key is stable across record and replay.
    pub fn task_park_timed(
        &mut self,
        task: TaskId,
        reason: &str,
        clock: ClockKind,
        deadline_nanos: u64,
    ) -> Result<(), RuntimeError> {
        if self.scheduler.is_none() {
            return Err(EffectError::missing_driver("scheduler").into());
        }
        // Registration expires a reached deadline, which reads the clock: a
        // missing clock fails here, before the task is parked.
        if self.clock.is_none() {
            return Err(EffectError::missing_driver("clock").into());
        }
        // Reserve the registration sequence up front so an exhausted counter
        // fails closed before the task is parked with no way to wake it.
        let seq = self.timer_seq;
        let next_seq = seq.checked_add(1).ok_or_else(|| {
            EffectError::new(
                ErrorCode::InvalidInput,
                "virtual timer registration sequence exhausted",
            )
        })?;
        let monotonic_deadline = self.monotonic_deadline(clock, deadline_nanos)?;
        // Every read that can fail precedes the park: the registration-time
        // expiry below judges against this reading, so a failing clock leaves
        // the task as it was, never parked with its timer inserted.
        let now = self.current_monotonic()?;
        let operation = Operation::TaskParkTimed {
            task,
            reason: reason.into(),
            deadline_nanos: monotonic_deadline,
        };
        let expected = self.replay_expected(&operation)?;
        let result = self
            .scheduler
            .as_mut()
            .expect("driver was checked")
            .park(task, reason);
        let actual = match result {
            Ok(()) => Outcome::Unit,
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_unit(&operation, outcome)?;
        self.parked_tasks.insert(task);
        self.schedule.on_park(task);
        self.timer_seq = next_seq;
        let key = (monotonic_deadline, seq);
        if let Some(previous) = self.timer_by_task.insert(task, key) {
            self.timers.remove(&previous);
        }
        self.timers.insert(key, task);
        self.expire_due_at(now)
    }

    /// Whether `task` is parked with a timer still in the future. The timer
    /// registry holds only future deadlines: registration and every clock
    /// advance expire the due ones ([`Context::expire_due_timers`]), so a
    /// registered timer is a wake that virtual time has yet to reach.
    pub(super) fn has_future_deadline(&self, task: TaskId) -> bool {
        self.timer_by_task.contains_key(&task)
    }

    pub fn task_wake(&mut self, task: TaskId) -> Result<(), RuntimeError> {
        self.scheduler_unit(Operation::TaskWake { task }, |scheduler| {
            scheduler.wake(task)
        })?;
        self.parked_tasks.remove(&task);
        self.deregister_timer(task);
        Ok(())
    }

    pub fn task_complete(&mut self, task: TaskId) -> Result<(), RuntimeError> {
        self.scheduler_unit(Operation::TaskComplete { task }, |scheduler| {
            scheduler.complete(task)
        })?;
        self.scheduler_tasks.remove(&task);
        self.parked_tasks.remove(&task);
        self.deregister_timer(task);
        self.schedule.on_complete(task);
        Ok(())
    }

    /// Convert an absolute `deadline_nanos` in the `clock` domain to the
    /// monotonic domain used by the timer registry. Realtime deadlines read
    /// both clocks (recorded boundary observations) so the epoch is consistent
    /// across record and replay; monotonic deadlines pass through unchanged.
    /// The one realtime-to-monotonic mapping of absolute deadlines: a sleep's
    /// and an embedder timer's (`TIMER_ABSTIME` on a realtime clock) resolve
    /// alike, including under an epoch jump, which the realtime read carries.
    pub fn monotonic_deadline(
        &mut self,
        clock: ClockKind,
        deadline_nanos: u64,
    ) -> Result<u64, RuntimeError> {
        match clock {
            ClockKind::Monotonic => Ok(deadline_nanos),
            ClockKind::Realtime => {
                let realtime = self.now(ClockKind::Realtime)?;
                let monotonic = self.now(ClockKind::Monotonic)?;
                let epoch = realtime.saturating_sub(monotonic);
                Ok(deadline_nanos.saturating_sub(epoch))
            }
        }
    }

    fn deregister_timer(&mut self, task: TaskId) {
        if let Some(key) = self.timer_by_task.remove(&task) {
            self.timers.remove(&key);
        }
    }

    /// Read the current monotonic virtual time directly from the clock driver
    /// without recording a boundary observation. The rescue path uses this to
    /// determine which timers are due after advancing the clock; the driver's
    /// monotonic value is maintained identically on record and replay by the
    /// recorded `SleepUntil`, so the result is deterministic.
    pub(super) fn current_monotonic(&mut self) -> Result<u64, RuntimeError> {
        self.clock
            .as_mut()
            .ok_or_else(|| EffectError::missing_driver("clock"))?
            .now(ClockKind::Monotonic)
            .map_err(Into::into)
    }

    /// Whether `scheduler.next()` would report a deadlock: tasks exist but every
    /// one is parked. Derived from the runtime's shadow of scheduler state,
    /// which mirrors the driver op-for-op on both record and replay.
    pub(super) fn scheduler_would_deadlock(&self) -> bool {
        !self.scheduler_tasks.is_empty()
            && self
                .scheduler_tasks
                .iter()
                .all(|task| self.parked_tasks.contains(task))
    }

    /// Drain the tasks whose timed parks expired since the last drain, in
    /// expiry order, so an embedder can settle their waits as timeouts
    /// (unlink them from its own wait queues) before anything else can wake
    /// them. Deterministic and unrecorded: expiry populates it identically on
    /// record and replay.
    pub fn take_expired_timeouts(&mut self) -> Vec<TaskId> {
        std::mem::take(&mut self.expired)
    }

    /// Whether expired timed parks await [`Context::take_expired_timeouts`].
    pub fn has_expired_timeouts(&self) -> bool {
        !self.expired.is_empty()
    }

    /// Run `body` as part of an embedder's locked section: a stretch in which
    /// the embedder holds its own wait state (the native shim's thread
    /// runtime) and so cannot settle expiries until it lets go. Inside it a
    /// clock read observes virtual time but never advances it: the
    /// advance-on-spin rescue waits for the first read outside (the streak
    /// keeps counting). The only expiries a section can then produce are the
    /// scheduling ones (a timed park, a pick, an idle advance), which the
    /// embedder settles before it goes on. Sections nest.
    pub fn in_embedder_section<T>(&mut self, body: impl FnOnce(&mut Self) -> T) -> T {
        let outer = std::mem::replace(&mut self.embedder_section, true);
        let result = body(self);
        self.embedder_section = outer;
        result
    }

    /// The single expiry authority: wake every timed park whose deadline
    /// virtual time has reached, in `(deadline, registration)` order, and queue
    /// it for the embedder's settlement. Called after every clock advance (the
    /// only one is [`Context::sleep_until`]) and at every timed-park
    /// registration, so the registry never holds a reached deadline.
    pub(super) fn expire_due_timers(&mut self) -> Result<(), RuntimeError> {
        if self.timers.is_empty() {
            return Ok(());
        }
        let now = self.current_monotonic()?;
        self.expire_due_at(now)
    }

    /// [`Context::expire_due_timers`] against a monotonic reading `now`
    /// already taken.
    fn expire_due_at(&mut self, now: u64) -> Result<(), RuntimeError> {
        let due: Vec<TaskId> = self
            .timers
            .iter()
            .take_while(|((deadline, _), _)| *deadline <= now)
            .map(|(_, task)| *task)
            .collect();
        for task in due {
            self.task_wake(task)?;
            self.expired.push(task);
        }
        Ok(())
    }

    pub fn scheduler_next(&mut self) -> Result<Option<TaskId>, RuntimeError> {
        if self.scheduler.is_none() {
            return Err(EffectError::missing_driver("scheduler").into());
        }
        // Deadlock-rescue: while every task is parked but a timer pends, advance
        // virtual time to the single earliest deadline and wake every task due
        // at the new time, in ascending `(deadline, seq)` order. This runs
        // before the `SchedulerNext` boundary op is recorded/matched, so the
        // recorded stream for a rescued step is `SleepUntil`, the due `TaskWake`s,
        // then `SchedulerNext`. Because the shadow scheduler state and the timer
        // registry are maintained identically on record and replay, the rescue
        // re-executes deterministically and consumes those events in order.
        while !self.timers.is_empty() && self.scheduler_would_deadlock() {
            let (earliest_deadline, _) = *self
                .timers
                .keys()
                .next()
                .expect("timer registry is non-empty");
            self.sleep_until(ClockKind::Monotonic, earliest_deadline)?;
        }
        let operation = Operation::SchedulerNext;
        let expected = self.replay_expected(&operation)?;
        let result = match expected.as_ref().map(|(_, outcome)| outcome) {
            Some(Outcome::OptionalTask(task)) => self
                .scheduler
                .as_mut()
                .expect("driver was checked")
                .select(*task)
                .map(|()| *task),
            _ => self.scheduler.as_mut().expect("driver was checked").next(),
        };
        let actual = match result {
            Ok(task) => Outcome::OptionalTask(task),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        let selected = decode_optional_task(&operation, outcome)?;
        self.cpu.running = selected;
        Ok(selected)
    }

    /// The process's virtual CPU time in nanoseconds (see [`CpuTime`]).
    /// Unrecorded: a pure function of the recorded stream.
    pub fn cpu_time_nanos(&self) -> u64 {
        self.cpu.total
    }

    fn scheduler_unit(
        &mut self,
        operation: Operation,
        invoke: impl FnOnce(&mut dyn SchedulerDriver) -> Result<(), EffectError>,
    ) -> Result<(), RuntimeError> {
        if self.scheduler.is_none() {
            return Err(EffectError::missing_driver("scheduler").into());
        }
        let expected = self.replay_expected(&operation)?;
        let result = invoke(
            self.scheduler
                .as_mut()
                .expect("driver was checked")
                .as_mut(),
        );
        let actual = match result {
            Ok(()) => Outcome::Unit,
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_unit(&operation, outcome)
    }
}

#[cfg(test)]
mod tests;
