//! Seeded cooperative task scheduling: the runtime's one scheduler.
//!
//! The default policy selects one runnable task uniformly at random from a
//! stable, sorted set — the historical behavior, preserved byte-for-byte so
//! every canonical seed sequence is unchanged. One opt-in *exploration policy*
//! layers over the same runnable set to steer which interleavings are reached:
//!
//! - **PCT** (Probabilistic Concurrency Testing, Burckhardt et al., PLDI 2010):
//!   each task is assigned a random priority; `d-1` seed-placed priority-change
//!   points demote the running task as the schedule advances; the highest-priority
//!   runnable task always runs. This gives a probabilistic guarantee of finding
//!   bugs of ordering-depth `d`.
//!
//! The policy draws exclusively from its own domain-separated `SplitMix64`
//! stream, never the default selection generator, so enabling it leaves the
//! default stream untouched. It affects only the record/seeded selection path
//! (`next()`); on replay the recorded task is applied directly through
//! `select()`, so replay is independent of the policy.

use std::collections::BTreeMap;

use patina_dst_abi::{EffectError, ErrorCode, TaskId};
use patina_dst_driver_api::DriverResult;
use patina_dst_rng_seeded::{SplitMix64, domain_seed, fault_domain};

/// End-of-run summary of an exploration scheduling policy (PCT priority-change
/// points). Populated only during a live selection run
/// (`next()` decisions), so it reflects the record/seeded schedule; on replay the
/// recorded task selections are consumed through `select()` and `next()` is not
/// called, so a replay reports the inert default. The runtime folds these counts
/// into the facts document's `schedule_policy` and the
/// bug-depth annotation of a failing schedule.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SchedulePolicyReport {
    /// Whether the PCT (Probabilistic Concurrency Testing) policy was active.
    pub pct: bool,
    /// Configured PCT bug-depth `d` (number of priority bands; `d-1` change
    /// points).
    pub pct_depth: u32,
    /// Configured number of priority-change points (`d-1`).
    pub pct_change_points: u32,
    /// Number of priority-change points that were actually reached during the
    /// schedule (a live change point demoted a running task). This is the PCT
    /// contribution to the bug-depth estimate of a schedule.
    pub pct_change_points_hit: u32,
    /// Total scheduling decisions (`next()` calls) observed under the policy.
    pub decisions: u64,
}

impl SchedulePolicyReport {
    /// Whether any exploration policy was active this run.
    pub fn is_active(&self) -> bool {
        self.pct
    }

    /// The bug-depth estimate for the realized schedule: the number of ordering
    /// decisions (priority-change points hit) that
    /// were live in the schedule. A failure found under a schedule with a higher
    /// estimate exercised a deeper interleaving.
    pub fn bug_depth(&self) -> u64 {
        u64::from(self.pct_change_points_hit)
    }
}

/// Configuration for the PCT (Probabilistic Concurrency Testing) policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PctConfig {
    /// Target bug depth `d` (>= 1). `d-1` priority-change points are placed over
    /// the schedule, so `d = 1` is priority-ordering with no preemption and
    /// `d >= 2` introduces `d-1` preemptions.
    pub depth: u32,
    /// Expected schedule length (number of scheduling decisions) over which the
    /// `d-1` change points are distributed. A shorter real run simply leaves the
    /// later change points unreached; a longer one is bounded at depth `d`.
    pub steps: u64,
}

/// The exploration scheduling policy. `Default` (`pct` is `None`) is the historical
/// uniform-random policy and is byte-for-byte identical to the pre-policy
/// scheduler.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SchedulePolicy {
    pub pct: Option<PctConfig>,
}

impl SchedulePolicy {
    pub fn is_default(&self) -> bool {
        self.pct.is_none()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum TaskState {
    Runnable,
    Running,
    Parked(String),
}

/// PCT live state: per-task priorities, the seed-placed change points, and the
/// running decision counter.
struct PctState {
    depth: u32,
    /// Change points keyed by decision step, valued by the priority the running
    /// task is demoted to at that step (the low band `1..=d-1`).
    change_points: BTreeMap<u64, i64>,
    priorities: BTreeMap<TaskId, i64>,
    rng: SplitMix64,
    /// Monotonic count of scheduling decisions taken under the policy.
    step: u64,
    /// The task selected at the previous decision (the one a change point
    /// demotes).
    last_selected: Option<TaskId>,
    change_points_hit: u32,
}

/// The high band a freshly spawned task draws its priority from: `depth +
/// [0, PCT_PRIORITY_BAND)`, always strictly above every change-point priority
/// (`1..=depth-1`). Ties are broken by lowest task id, so exact collisions are
/// harmless.
const PCT_PRIORITY_BAND: u64 = 1 << 20;

impl PctState {
    fn new(config: PctConfig, seed: u64) -> Self {
        let depth = config.depth.max(1);
        let mut rng = SplitMix64::new(domain_seed(seed, fault_domain::SCHED_PCT));
        // Place d-1 change points at seed-chosen decision steps in [1, steps].
        // The i-th change point (1-based, in step order) demotes the running task
        // to priority i, exactly as in PCT: earlier change points give lower
        // (more-preemptible) priorities, so multiple demotions compose into a
        // depth-d ordering.
        let count = depth.saturating_sub(1);
        let span = config.steps.max(1);
        let mut steps: Vec<u64> = (0..count).map(|_| 1 + (rng.next_u64() % span)).collect();
        steps.sort_unstable();
        let mut change_points = BTreeMap::new();
        for (index, step) in steps.into_iter().enumerate() {
            // Priority ordinal 1..=d-1 in ascending step order. Collisions on the
            // same step keep the last (lowest-priority) assignment, which only
            // makes that step a deeper demotion — still bounded by depth.
            change_points.insert(step, (index as i64) + 1);
        }
        Self {
            depth,
            change_points,
            priorities: BTreeMap::new(),
            rng,
            step: 0,
            last_selected: None,
            change_points_hit: 0,
        }
    }

    fn on_spawn(&mut self, task: TaskId) {
        let priority = i64::from(self.depth) + (self.rng.next_u64() % PCT_PRIORITY_BAND) as i64;
        self.priorities.insert(task, priority);
    }

    fn on_complete(&mut self, task: TaskId) {
        self.priorities.remove(&task);
        if self.last_selected == Some(task) {
            self.last_selected = None;
        }
    }

    /// Advance the decision counter and, if this step is a change point, demote
    /// the currently-running task so a higher-priority task preempts it.
    fn advance(&mut self) {
        self.step += 1;
        if let Some(&new_priority) = self.change_points.get(&self.step)
            && let Some(task) = self.last_selected
            && let Some(slot) = self.priorities.get_mut(&task)
        {
            *slot = new_priority;
            self.change_points_hit += 1;
        }
    }

    /// Whether, at this decision, PCT is deferring a strictly-lower-priority
    /// runnable task in favor of a higher-priority one (a priority deferral the
    /// liveness watchdog must treat as policy-explained). True when the candidate
    /// set holds at least two distinct priorities, so a lower-priority runnable
    /// task is passed over.
    fn defers(&self, candidates: &[TaskId]) -> bool {
        if candidates.len() < 2 {
            return false;
        }
        let priority = |task: &TaskId| {
            self.priorities
                .get(task)
                .copied()
                .unwrap_or(i64::from(self.depth))
        };
        let max = candidates.iter().map(priority).max().expect("non-empty");
        candidates.iter().any(|task| priority(task) < max)
    }

    /// Pick the highest-priority task among `candidates`, ties broken by lowest
    /// task id. `candidates` is non-empty.
    fn pick(&mut self, candidates: &[TaskId]) -> TaskId {
        let selected = *candidates
            .iter()
            .max_by(|a, b| {
                let pa = self
                    .priorities
                    .get(*a)
                    .copied()
                    .unwrap_or(i64::from(self.depth));
                let pb = self
                    .priorities
                    .get(*b)
                    .copied()
                    .unwrap_or(i64::from(self.depth));
                // Higher priority wins; on a tie the LOWER task id wins, so invert
                // the id comparison relative to the priority comparison.
                pa.cmp(&pb).then_with(|| b.0.cmp(&a.0))
            })
            .expect("candidate set is non-empty");
        self.last_selected = Some(selected);
        selected
    }
}

/// A scheduler that chooses one runnable task from a stable, sorted set.
pub struct DetScheduler {
    generator: SplitMix64,
    tasks: BTreeMap<TaskId, TaskState>,
    next_task: u64,
    pct: Option<PctState>,
    /// Whether the most recent `choose` deliberately withheld a runnable task
    /// from selection under an active exploration policy (PCT priority ordering
    /// deferring a lower-priority runnable task). Exposed through
    /// [`DetScheduler::liveness_deferring`] so the liveness watchdog never
    /// misreports a policy-explained non-progress window. Reset to `false` before
    /// every default (policy-free) selection.
    last_decision_deferred: bool,
}

impl DetScheduler {
    pub fn new(seed: u64) -> Self {
        Self::with_policy(seed, SchedulePolicy::default())
    }

    pub fn with_policy(seed: u64, policy: SchedulePolicy) -> Self {
        Self {
            generator: SplitMix64::new(domain_seed(seed, fault_domain::SCHED_MAIN)),
            tasks: BTreeMap::new(),
            next_task: 1,
            pct: policy.pct.map(|config| PctState::new(config, seed)),
            last_decision_deferred: false,
        }
    }

    pub fn runnable(&self) -> Vec<TaskId> {
        self.tasks
            .iter()
            .filter_map(|(task, state)| (state == &TaskState::Runnable).then_some(*task))
            .collect()
    }

    fn state_mut(&mut self, task: TaskId) -> DriverResult<&mut TaskState> {
        self.tasks.get_mut(&task).ok_or_else(|| {
            EffectError::new(
                ErrorCode::InvalidHandle,
                format!("scheduler task {} does not exist", task.0),
            )
        })
    }

    /// The selection among runnable tasks, applying the active exploration
    /// policy. `runnable` is non-empty. Returns the selected task; the caller
    /// transitions it to `Running`.
    fn choose(&mut self, runnable: &[TaskId]) -> TaskId {
        // Default (no policy): byte-for-byte the historical uniform-random draw
        // over the full runnable set, consuming the selection generator exactly
        // as before so every canonical seed sequence is unchanged.
        if self.pct.is_none() {
            self.last_decision_deferred = false;
            let index = (self.generator.next_u64() % runnable.len() as u64) as usize;
            return runnable[index];
        }

        // Advance policy decision counters for this step first, so change points
        // and interval boundaries are keyed on the decision index.
        if let Some(pct) = self.pct.as_mut() {
            pct.advance();
        }
        let candidates = runnable;
        let pct_deferring = self
            .pct
            .as_ref()
            .map(|pct| pct.defers(candidates))
            .unwrap_or(false);
        self.last_decision_deferred = pct_deferring;

        let pct = self.pct.as_mut().expect("checked: policy is active");
        pct.pick(candidates)
    }
}

/// Task-state transitions and selection.
impl DetScheduler {
    pub fn spawn(&mut self, _label: &str) -> DriverResult<TaskId> {
        let task = TaskId(self.next_task);
        self.next_task = self.next_task.checked_add(1).ok_or_else(|| {
            EffectError::new(
                ErrorCode::InvalidHandle,
                "scheduler task identifiers exhausted",
            )
        })?;
        self.tasks.insert(task, TaskState::Runnable);
        if let Some(pct) = self.pct.as_mut() {
            pct.on_spawn(task);
        }
        Ok(task)
    }

    pub fn yield_task(&mut self, task: TaskId) -> DriverResult<()> {
        let state = self.state_mut(task)?;
        if state != &TaskState::Running {
            return Err(invalid_transition(task, "yield", state));
        }
        *state = TaskState::Runnable;
        Ok(())
    }

    pub fn park(&mut self, task: TaskId, reason: &str) -> DriverResult<()> {
        let state = self.state_mut(task)?;
        if state != &TaskState::Running {
            return Err(invalid_transition(task, "park", state));
        }
        *state = TaskState::Parked(reason.into());
        Ok(())
    }

    pub fn wake(&mut self, task: TaskId) -> DriverResult<()> {
        let state = self.state_mut(task)?;
        if !matches!(state, TaskState::Parked(_)) {
            return Err(invalid_transition(task, "wake", state));
        }
        *state = TaskState::Runnable;
        Ok(())
    }

    pub fn complete(&mut self, task: TaskId) -> DriverResult<()> {
        let state = self.state_mut(task)?;
        if state != &TaskState::Running {
            return Err(invalid_transition(task, "complete", state));
        }
        self.tasks.remove(&task);
        if let Some(pct) = self.pct.as_mut() {
            pct.on_complete(task);
        }
        Ok(())
    }

    // Not an iterator: selection fails on deadlock and mutates task state.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> DriverResult<Option<TaskId>> {
        if let Some((task, _)) = self
            .tasks
            .iter()
            .find(|(_, state)| matches!(state, TaskState::Running))
        {
            return Err(EffectError::new(
                ErrorCode::InvalidState,
                format!(
                    "task {} is still running; yield, park, or complete it before scheduling",
                    task.0
                ),
            ));
        }
        let runnable = self.runnable();
        if runnable.is_empty() {
            if self.tasks.is_empty() {
                return Ok(None);
            }
            let parked = self
                .tasks
                .iter()
                .filter_map(|(task, state)| match state {
                    TaskState::Parked(reason) => Some(format!("{} ({reason})", task.0)),
                    _ => None,
                })
                .collect::<Vec<_>>();
            return Err(EffectError::new(
                ErrorCode::Deadlock,
                format!("no runnable tasks; parked tasks: {}", parked.join(", ")),
            ));
        }
        let selected = self.choose(&runnable);
        self.select(Some(selected))?;
        Ok(Some(selected))
    }

    pub fn select(&mut self, task: Option<TaskId>) -> DriverResult<()> {
        let Some(task) = task else {
            if self.tasks.is_empty() {
                return Ok(());
            }
            return Err(EffectError::new(
                ErrorCode::InvalidState,
                "cannot select no task while scheduler tasks still exist",
            ));
        };
        if self
            .tasks
            .values()
            .any(|state| matches!(state, TaskState::Running))
        {
            return Err(EffectError::new(
                ErrorCode::InvalidState,
                "cannot select a task while another task is running",
            ));
        }
        let state = self.state_mut(task)?;
        if state != &TaskState::Runnable {
            return Err(invalid_transition(task, "select", state));
        }
        *state = TaskState::Running;
        Ok(())
    }

    pub fn policy_report(&self) -> Option<SchedulePolicyReport> {
        let pct = self.pct.as_ref()?;
        Some(SchedulePolicyReport {
            pct: true,
            pct_depth: pct.depth,
            pct_change_points: pct.change_points.len() as u32,
            pct_change_points_hit: pct.change_points_hit,
            decisions: pct.step,
        })
    }

    pub fn liveness_deferring(&self) -> bool {
        self.last_decision_deferred
    }
}

fn invalid_transition(task: TaskId, action: &str, state: &TaskState) -> EffectError {
    EffectError::new(
        ErrorCode::InvalidState,
        format!(
            "cannot {action} scheduler task {} in state {state:?}",
            task.0
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schedule(seed: u64, rounds: usize) -> Vec<TaskId> {
        let mut scheduler = DetScheduler::new(seed);
        for label in ["a", "b", "c"] {
            scheduler.spawn(label).unwrap();
        }
        let mut selected = Vec::new();
        for _ in 0..rounds {
            let task = scheduler.next().unwrap().unwrap();
            selected.push(task);
            scheduler.yield_task(task).unwrap();
        }
        selected
    }

    #[test]
    fn scheduler_has_a_known_seed_dependent_sequence() {
        assert_eq!(
            schedule(7, 8),
            [
                TaskId(2),
                TaskId(2),
                TaskId(1),
                TaskId(2),
                TaskId(3),
                TaskId(2),
                TaskId(1),
                TaskId(2),
            ]
        );
        assert_ne!(schedule(7, 8), schedule(8, 8));
    }

    #[test]
    fn park_wake_deadlock_and_completion_are_explicit() {
        let mut scheduler = DetScheduler::new(1);
        let task = scheduler.spawn("worker").unwrap();
        assert_eq!(scheduler.next().unwrap(), Some(task));
        scheduler.park(task, "waiting for packet").unwrap();
        let deadlock = scheduler.next().unwrap_err();
        assert_eq!(deadlock.code, ErrorCode::Deadlock);
        assert!(deadlock.message.contains("waiting for packet"));

        scheduler.wake(task).unwrap();
        assert_eq!(scheduler.next().unwrap(), Some(task));
        scheduler.complete(task).unwrap();
        assert_eq!(scheduler.next().unwrap(), None);
    }

    /// Drive a fixed cooperative workload (all tasks always runnable) under a
    /// policy and return the selection order.
    fn drive(scheduler: &mut DetScheduler, n_tasks: u64, rounds: usize) -> Vec<TaskId> {
        for label in 0..n_tasks {
            scheduler.spawn(&format!("t{label}")).unwrap();
        }
        let mut order = Vec::new();
        for _ in 0..rounds {
            let task = scheduler.next().unwrap().unwrap();
            order.push(task);
            scheduler.yield_task(task).unwrap();
        }
        order
    }

    #[test]
    fn pct_depth_one_runs_highest_priority_to_completion_without_preemption() {
        // With d = 1 there are no change points, so priorities never change: the
        // single highest-priority task is selected every round (all tasks stay
        // runnable), i.e. no preemption at all.
        let policy = SchedulePolicy {
            pct: Some(PctConfig {
                depth: 1,
                steps: 100,
            }),
        };
        let mut sched = DetScheduler::with_policy(5, policy);
        let order = drive(&mut sched, 4, 20);
        assert!(
            order.iter().all(|task| *task == order[0]),
            "d=1 must never preempt: {order:?}"
        );
        let report = sched.policy_report().unwrap();
        assert_eq!(report.pct_change_points, 0);
        assert_eq!(report.pct_change_points_hit, 0);
    }

    #[test]
    fn pct_depth_two_preempts_at_a_live_change_point() {
        // d = 2 places exactly one change point; with all tasks runnable it must
        // fire and demote the running task, producing at least one preemption.
        // Seed 4 (not the first tried) is required: at depth 2/steps 10 some
        // seeds place their sole change point at decision step 1, which can
        // never be live (nothing has run yet to demote) — an inherent property
        // of change-point semantics, not a derivation bug.
        let policy = SchedulePolicy {
            pct: Some(PctConfig {
                depth: 2,
                steps: 10,
            }),
        };
        let mut sched = DetScheduler::with_policy(4, policy);
        let order = drive(&mut sched, 3, 30);
        let report = sched.policy_report().unwrap();
        assert_eq!(report.pct_change_points, 1);
        assert_eq!(
            report.pct_change_points_hit, 1,
            "the change point must be live"
        );
        // A live change point demotes the running task, so the selection changes
        // at least once — the schedule is not a single task throughout.
        assert!(
            order.iter().any(|task| *task != order[0]),
            "a live change point must preempt: {order:?}"
        );
    }

    #[test]
    fn default_policy_reports_nothing_and_never_defers_liveness() {
        // The uniform-random policy never withholds a runnable task, so the
        // liveness watchdog stays fully live for a plain run.
        let mut sched = DetScheduler::new(7);
        for label in ["a", "b", "c"] {
            sched.spawn(label).unwrap();
        }
        for _ in 0..20 {
            let task = sched.next().unwrap().unwrap();
            assert!(
                !sched.liveness_deferring(),
                "default policy must never defer"
            );
            sched.yield_task(task).unwrap();
        }
        assert!(sched.policy_report().is_none());
    }

    #[test]
    fn pct_reports_liveness_deferral_across_priorities() {
        // With multiple tasks at distinct PCT priorities, a lower-priority
        // runnable task is deferred by priority ordering.
        let policy = SchedulePolicy {
            pct: Some(PctConfig {
                depth: 3,
                steps: 40,
            }),
        };
        let mut sched = DetScheduler::with_policy(3, policy);
        for label in 0..4u64 {
            sched.spawn(&format!("t{label}")).unwrap();
        }
        let mut saw_deferral = false;
        for _ in 0..20 {
            let task = sched.next().unwrap().unwrap();
            saw_deferral |= sched.liveness_deferring();
            sched.yield_task(task).unwrap();
        }
        assert!(
            saw_deferral,
            "PCT priority ordering must defer a lower-priority runnable task"
        );
    }
}
