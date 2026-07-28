//! Seeded cooperative task scheduling.
//!
//! The default policy selects one runnable task uniformly at random from a
//! stable, sorted set — the historical behavior, preserved byte-for-byte so
//! every canonical seed sequence is unchanged. Two opt-in *exploration policies*
//! layer over the same runnable set to steer which interleavings are reached:
//!
//! - **PCT** (Probabilistic Concurrency Testing, Burckhardt et al., PLDI 2010):
//!   each task is assigned a random priority; `d-1` seed-placed priority-change
//!   points demote the running task as the schedule advances; the highest-priority
//!   runnable task always runs. This gives a probabilistic guarantee of finding
//!   bugs of ordering-depth `d`.
//! - **Starvation intervals**: bounded, seed-chosen windows during which a
//!   seed-chosen subset of tasks is deliberately not selected, to surface
//!   liveness/starvation assumptions. Intervals always end (bounded length), and
//!   a step that would starve *every* runnable task falls back to the full set
//!   (liveness safety) while counting the vacuous hit for diagnosis.
//!
//! Both policies draw exclusively from their own domain-separated `SplitMix64`
//! streams, never the default selection generator, so enabling one leaves the
//! other's stream — and the default stream — untouched. The policies affect only
//! the record/seeded selection path (`next()`); on replay the recorded task is
//! applied directly through `select()`, so replay is independent of the policy.

use std::collections::{BTreeMap, BTreeSet};

use patina_dst_abi::{EffectError, ErrorCode, TaskId};
use patina_dst_driver_api::{DriverResult, SchedulePolicyReport, SchedulerDriver};
use patina_dst_rng_seeded::SplitMix64;

/// Domain separators mixed into the root seed so a policy's stream never
/// correlates with the default selection generator or the other policy.
const PCT_SEED_DOMAIN: u64 = 0x9C17_C011_ED00_5EED;
const STARVE_SEED_DOMAIN: u64 = 0x57A2_5E11_047E_5EED;

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

/// Configuration for the starvation-interval policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StarvationConfig {
    /// Number of bounded starvation intervals to place over the schedule.
    pub intervals: u32,
    /// Maximum length (in scheduling decisions) of any interval. Every interval
    /// is at least one step and at most this many, so it always ends — the
    /// bound is what keeps starvation liveness-safe.
    pub max_len: u64,
    /// Interval starts are placed uniformly in `[1, window]`.
    pub window: u64,
}

/// The exploration scheduling policy. `Default` (both `None`) is the historical
/// uniform-random policy and is byte-for-byte identical to the pre-policy
/// scheduler.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SchedulePolicy {
    pub pct: Option<PctConfig>,
    pub starvation: Option<StarvationConfig>,
}

impl SchedulePolicy {
    pub fn is_default(&self) -> bool {
        self.pct.is_none() && self.starvation.is_none()
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
        let mut rng = SplitMix64::new(seed ^ PCT_SEED_DOMAIN);
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
        if let Some(&new_priority) = self.change_points.get(&self.step) {
            if let Some(task) = self.last_selected {
                if let Some(slot) = self.priorities.get_mut(&task) {
                    *slot = new_priority;
                    self.change_points_hit += 1;
                }
            }
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

/// A single bounded starvation interval: during `[start, end)` (decision steps)
/// the tasks whose id satisfies `id % modulus == residue` are not selected.
#[derive(Clone, Copy, Debug)]
struct StarveInterval {
    start: u64,
    end: u64,
    modulus: u64,
    residue: u64,
}

impl StarveInterval {
    fn contains(&self, step: u64) -> bool {
        step >= self.start && step < self.end
    }

    fn starves(&self, task: TaskId) -> bool {
        self.modulus >= 2 && task.0 % self.modulus == self.residue
    }
}

/// Starvation live state: the seed-generated intervals and the running counters.
struct StarvationState {
    intervals: Vec<StarveInterval>,
    step: u64,
    starve_events: u64,
    starve_vacuous: u64,
    warned_vacuous: bool,
    /// Per-task count of *consecutive* scheduling decisions the task was runnable
    /// but excluded by starvation. Reset to zero when the task is scheduled or is
    /// not in any starving interval. Backs the aging guarantee below.
    skips: BTreeMap<TaskId, u64>,
    /// Aging cap: a task skipped this many consecutive decisions becomes
    /// force-eligible for one decision regardless of the interval, guaranteeing
    /// liveness. Without it a *non-starved* task that merely spins at a scheduling
    /// boundary (e.g. a macOS `sched_yield` lock backoff) would be selected
    /// forever while the starved lock holder it waits on never runs — a livelock.
    /// The cap bounds any task's starvation to at most this many decisions, which
    /// is exactly "the interval must end" expressed in decision space.
    aging_cap: u64,
}

impl StarvationState {
    fn new(config: StarvationConfig, seed: u64) -> Self {
        let mut rng = SplitMix64::new(seed ^ STARVE_SEED_DOMAIN);
        let window = config.window.max(1);
        let max_len = config.max_len.max(1);
        let intervals = (0..config.intervals)
            .map(|_| {
                let start = 1 + (rng.next_u64() % window);
                // Length in [1, max_len] — strictly positive and bounded, so the
                // interval always ends.
                let len = 1 + (rng.next_u64() % max_len);
                // A seed-chosen subset: starve one residue class of task ids. The
                // modulus is 2 or 3, so an interval starves roughly a half or a
                // third of tasks — never all of them by construction (the other
                // residue classes stay schedulable), and the runtime fallback
                // covers any step where only starved tasks are runnable.
                let modulus = 2 + (rng.next_u64() % 2); // 2 or 3
                let residue = rng.next_u64() % modulus;
                StarveInterval {
                    start,
                    end: start + len,
                    modulus,
                    residue,
                }
            })
            .collect();
        Self {
            intervals,
            step: 0,
            starve_events: 0,
            starve_vacuous: 0,
            warned_vacuous: false,
            skips: BTreeMap::new(),
            aging_cap: max_len,
        }
    }

    fn advance(&mut self) {
        self.step += 1;
    }

    fn interval_starves(&self, task: TaskId) -> bool {
        self.intervals
            .iter()
            .any(|interval| interval.contains(self.step) && interval.starves(task))
    }

    /// Record the outcome of a decision and advance aging. Every runnable task
    /// that is interval-starved and was NOT selected has its consecutive-skip
    /// counter incremented (in every path, including the vacuous fallback, so
    /// aging always progresses toward the cap); the selected task and every
    /// currently-unstarved task reset to zero. Counts a `starve_events` whenever
    /// at least one starved task was deferred this decision.
    fn record_decision(&mut self, runnable: &[TaskId], selected: TaskId) {
        let mut any_deferred = false;
        for &task in runnable {
            if task == selected || !self.interval_starves(task) {
                self.skips.insert(task, 0);
            } else {
                *self.skips.entry(task).or_insert(0) += 1;
                any_deferred = true;
            }
        }
        if any_deferred {
            self.starve_events += 1;
        }
    }

    fn on_complete(&mut self, task: TaskId) {
        self.skips.remove(&task);
    }
}

/// A scheduler that chooses one runnable task from a stable, sorted set.
pub struct DetScheduler {
    generator: SplitMix64,
    tasks: BTreeMap<TaskId, TaskState>,
    next_task: u64,
    pct: Option<PctState>,
    starvation: Option<StarvationState>,
    /// Whether the most recent `choose` deliberately withheld a runnable task
    /// from selection under an active exploration policy (a starvation interval
    /// excluding a runnable task, or PCT priority ordering deferring a
    /// lower-priority runnable task). Exposed through
    /// [`SchedulerDriver::liveness_deferring`] so the liveness watchdog never
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
            generator: SplitMix64::new(seed),
            tasks: BTreeMap::new(),
            next_task: 1,
            pct: policy.pct.map(|config| PctState::new(config, seed)),
            starvation: policy
                .starvation
                .map(|config| StarvationState::new(config, seed)),
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
        if self.pct.is_none() && self.starvation.is_none() {
            self.last_decision_deferred = false;
            let index = (self.generator.next_u64() % runnable.len() as u64) as usize;
            return runnable[index];
        }

        // Advance policy decision counters for this step first, so change points
        // and interval boundaries are keyed on the decision index.
        if let Some(pct) = self.pct.as_mut() {
            pct.advance();
        }
        if let Some(starve) = self.starvation.as_mut() {
            starve.advance();
        }

        // Starvation partitions the runnable set into three groups:
        //   * `free`    — not in any starving interval this decision;
        //   * `aged`    — interval-starved but skipped `aging_cap` consecutive
        //                 decisions, so force-eligible (the liveness guarantee);
        //   * `excluded`— interval-starved and not yet aged out.
        // A `forced` flag records whether an aged task must run this decision. If
        // it must, it is selected preferentially (highest skip count, ties by
        // lowest id), overriding PCT/uniform so no task is starved unboundedly —
        // aging alone (making a task merely eligible) is not enough, since a
        // uniform pick could keep choosing a spinner over the starved holder.
        let mut forced: Option<TaskId> = None;
        let candidates: Vec<TaskId> = if let Some(starve) = self.starvation.as_ref() {
            let mut free = Vec::new();
            let mut aged: Vec<TaskId> = Vec::new();
            let mut excluded = 0usize;
            for &task in runnable {
                if !starve.interval_starves(task) {
                    free.push(task);
                } else if starve.skips.get(&task).copied().unwrap_or(0) >= starve.aging_cap {
                    aged.push(task);
                } else {
                    excluded += 1;
                }
            }
            if let Some(&must) = aged.iter().max_by(|a, b| {
                let sa = starve.skips.get(*a).copied().unwrap_or(0);
                let sb = starve.skips.get(*b).copied().unwrap_or(0);
                sa.cmp(&sb).then_with(|| b.0.cmp(&a.0))
            }) {
                // An aged-out task must run now (liveness override).
                forced = Some(must);
                vec![must]
            } else if !free.is_empty() {
                free
            } else {
                // Every runnable task is interval-starved and none has aged out
                // yet: fall back to the full set for this decision so the run
                // never wedges, recording the vacuous hit and warning once.
                let _ = excluded;
                let (warn, step) = {
                    let starve = self.starvation.as_mut().expect("checked");
                    starve.starve_vacuous += 1;
                    let first = !starve.warned_vacuous;
                    starve.warned_vacuous = true;
                    (first, starve.step)
                };
                if warn {
                    eprintln!(
                        "PATINA WARNING: vacuous starvation interval — at scheduling decision {step} every \
runnable task was in the starved subset, so no task could be scheduled without deadlocking the run. \
The interval is being ignored for this step to preserve liveness; a starvation configuration that \
routinely starves the only runnable task is testing nothing. Narrow the starved subset or the \
interval window.",
                    );
                }
                runnable.to_vec()
            }
        } else {
            runnable.to_vec()
        };

        // A starvation interval that excludes at least one currently-runnable task
        // is an active policy deferral this decision (whichever branch selects the
        // task: free pool, forced aging, or vacuous fallback). The step counter has
        // already advanced, so `interval_starves` keys on the correct decision.
        let starve_deferring = self
            .starvation
            .as_ref()
            .map(|starve| runnable.iter().any(|task| starve.interval_starves(*task)))
            .unwrap_or(false);
        let pct_deferring = self
            .pct
            .as_ref()
            .map(|pct| pct.defers(&candidates))
            .unwrap_or(false);
        self.last_decision_deferred = starve_deferring || pct_deferring;

        let selected = if let Some(task) = forced {
            task
        } else if let Some(pct) = self.pct.as_mut() {
            pct.pick(&candidates)
        } else {
            // Starvation-only: uniform random over the surviving candidates,
            // using the selection generator. Enabling starvation is an opt-in,
            // fingerprinted policy, so a differing generator consumption here is
            // expected and isolated from default runs.
            let index = (self.generator.next_u64() % candidates.len() as u64) as usize;
            candidates[index]
        };
        if let Some(starve) = self.starvation.as_mut() {
            starve.record_decision(runnable, selected);
        }
        selected
    }
}

impl SchedulerDriver for DetScheduler {
    fn spawn(&mut self, _label: &str) -> DriverResult<TaskId> {
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

    fn yield_task(&mut self, task: TaskId) -> DriverResult<()> {
        let state = self.state_mut(task)?;
        if state != &TaskState::Running {
            return Err(invalid_transition(task, "yield", state));
        }
        *state = TaskState::Runnable;
        Ok(())
    }

    fn park(&mut self, task: TaskId, reason: &str) -> DriverResult<()> {
        let state = self.state_mut(task)?;
        if state != &TaskState::Running {
            return Err(invalid_transition(task, "park", state));
        }
        *state = TaskState::Parked(reason.into());
        Ok(())
    }

    fn wake(&mut self, task: TaskId) -> DriverResult<()> {
        let state = self.state_mut(task)?;
        if !matches!(state, TaskState::Parked(_)) {
            return Err(invalid_transition(task, "wake", state));
        }
        *state = TaskState::Runnable;
        Ok(())
    }

    fn complete(&mut self, task: TaskId) -> DriverResult<()> {
        let state = self.state_mut(task)?;
        if state != &TaskState::Running {
            return Err(invalid_transition(task, "complete", state));
        }
        self.tasks.remove(&task);
        if let Some(pct) = self.pct.as_mut() {
            pct.on_complete(task);
        }
        if let Some(starve) = self.starvation.as_mut() {
            starve.on_complete(task);
        }
        Ok(())
    }

    fn next(&mut self) -> DriverResult<Option<TaskId>> {
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

    fn select(&mut self, task: Option<TaskId>) -> DriverResult<()> {
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

    fn policy_report(&self) -> Option<SchedulePolicyReport> {
        if self.pct.is_none() && self.starvation.is_none() {
            return None;
        }
        let mut report = SchedulePolicyReport::default();
        if let Some(pct) = self.pct.as_ref() {
            report.pct = true;
            report.pct_depth = pct.depth;
            report.pct_change_points = pct.change_points.len() as u32;
            report.pct_change_points_hit = pct.change_points_hit;
            report.decisions = report.decisions.max(pct.step);
        }
        if let Some(starve) = self.starvation.as_ref() {
            report.starvation = true;
            report.starve_events = starve.starve_events;
            report.starve_vacuous = starve.starve_vacuous;
            report.decisions = report.decisions.max(starve.step);
        }
        Some(report)
    }

    fn liveness_deferring(&self) -> bool {
        self.last_decision_deferred
    }
}

/// The set of task ids currently known to the scheduler. Exposed for the runtime
/// to reason about starvation subsets when composing diagnostics.
impl DetScheduler {
    pub fn known_tasks(&self) -> BTreeSet<TaskId> {
        self.tasks.keys().copied().collect()
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
    fn scheduler_has_a_known_seeded_sequence() {
        assert_eq!(
            schedule(7, 8),
            [
                TaskId(1),
                TaskId(1),
                TaskId(1),
                TaskId(1),
                TaskId(2),
                TaskId(1),
                TaskId(2),
                TaskId(1),
            ]
        );
    }

    #[test]
    fn a_thousand_seeds_repeat_schedules_with_park_and_wake() {
        fn with_park_and_wake(seed: u64) -> Vec<TaskId> {
            let mut scheduler = DetScheduler::new(seed);
            for label in ["a", "b", "c"] {
                scheduler.spawn(label).unwrap();
            }
            let parked = scheduler.next().unwrap().unwrap();
            scheduler.park(parked, "blocked").unwrap();
            let running = scheduler.next().unwrap().unwrap();
            scheduler.yield_task(running).unwrap();
            scheduler.wake(parked).unwrap();
            let mut selected = vec![parked, running];
            for _ in 0..20 {
                let task = scheduler.next().unwrap().unwrap();
                selected.push(task);
                scheduler.yield_task(task).unwrap();
            }
            selected
        }

        for seed in 0..1_000 {
            assert_eq!(
                with_park_and_wake(seed),
                with_park_and_wake(seed),
                "seed {seed}"
            );
        }
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
    fn pct_is_deterministic_per_seed() {
        let policy = SchedulePolicy {
            pct: Some(PctConfig {
                depth: 3,
                steps: 40,
            }),
            starvation: None,
        };
        let mut a = DetScheduler::with_policy(11, policy);
        let mut b = DetScheduler::with_policy(11, policy);
        assert_eq!(drive(&mut a, 4, 40), drive(&mut b, 4, 40));
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
            starvation: None,
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
        let policy = SchedulePolicy {
            pct: Some(PctConfig {
                depth: 2,
                steps: 10,
            }),
            starvation: None,
        };
        let mut sched = DetScheduler::with_policy(3, policy);
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
    fn starvation_actually_excludes_and_ends() {
        // A wide interval starving one residue class must skip those tasks while
        // active, then release them once the bounded interval ends.
        let policy = SchedulePolicy {
            pct: None,
            starvation: Some(StarvationConfig {
                intervals: 1,
                max_len: 6,
                window: 2,
            }),
        };
        let mut sched = DetScheduler::with_policy(9, policy);
        let order = drive(&mut sched, 4, 60);
        let report = sched.policy_report().unwrap();
        assert!(report.starvation);
        assert!(
            report.starve_events > 0,
            "the interval must exclude at least one runnable task"
        );
        // Every task is still runnable throughout, and the interval is bounded, so
        // by the end of the 60-round run every task has been scheduled at least
        // once (starvation ended and released the starved class).
        let mut seen = BTreeSet::new();
        for task in &order {
            seen.insert(*task);
        }
        assert_eq!(seen.len(), 4, "starvation must end and release every task");
    }

    #[test]
    fn starving_the_only_runnable_task_falls_back_and_warns() {
        // Only one task exists, and a very wide interval with modulus that starves
        // it. Every step would starve the only runnable task; the policy must fall
        // back to scheduling it (liveness) and count the vacuous hits.
        let policy = SchedulePolicy {
            pct: None,
            starvation: Some(StarvationConfig {
                intervals: 8,
                max_len: 50,
                window: 4,
            }),
        };
        // Search a few seeds for one that actually starves task 1 at some step;
        // the fallback and vacuous accounting must engage without deadlocking.
        let mut any_vacuous = false;
        for seed in 0..64 {
            let mut sched = DetScheduler::with_policy(seed, policy);
            sched.spawn("solo").unwrap();
            for _ in 0..40 {
                // Must never deadlock: the only task is always eventually returned.
                let task = sched.next().unwrap().unwrap();
                assert_eq!(task, TaskId(1));
                sched.yield_task(task).unwrap();
            }
            if sched.policy_report().unwrap().starve_vacuous > 0 {
                any_vacuous = true;
            }
        }
        assert!(
            any_vacuous,
            "at least one seed must exercise the vacuous-starvation fallback"
        );
    }

    #[test]
    fn starvation_aging_bounds_consecutive_skips_guaranteeing_liveness() {
        // Model exactly the livelock the aging guarantee prevents: task B spins
        // forever at a scheduling boundary (always runnable, never starved), while
        // task A — the resource holder another task needs — is starved by an
        // interval that never ends on its own. Without aging the scheduler would
        // pick the sole free candidate B forever and A would never run (the real
        // starvation hang). A deterministic always-starve-A interval isolates the
        // guarantee: A must be force-scheduled at least once every `aging_cap + 1`
        // decisions.
        let aging_cap = 6;
        let mut sched = DetScheduler::new(1);
        // Inject a deterministic starvation state: an unbounded interval starving
        // odd task ids (modulus 2, residue 1 → task 1 = A), never task 2 = B.
        sched.starvation = Some(StarvationState {
            intervals: vec![StarveInterval {
                start: 0,
                end: u64::MAX,
                modulus: 2,
                residue: 1,
            }],
            step: 0,
            starve_events: 0,
            starve_vacuous: 0,
            warned_vacuous: false,
            skips: BTreeMap::new(),
            aging_cap,
        });
        let a = sched.spawn("holder").unwrap();
        let b = sched.spawn("spinner").unwrap();
        assert_eq!(a, TaskId(1));
        assert_eq!(b, TaskId(2));
        let mut consecutive_a_missing = 0u64;
        let mut a_runs = 0u64;
        for round in 0..500 {
            let task = sched.next().unwrap().unwrap();
            if task == a {
                consecutive_a_missing = 0;
                a_runs += 1;
            } else {
                consecutive_a_missing += 1;
            }
            assert!(
                consecutive_a_missing <= aging_cap,
                "round {round}: task A starved {consecutive_a_missing} decisions > aging_cap {aging_cap}"
            );
            // Both stay runnable (spinner semantics).
            sched.yield_task(task).unwrap();
        }
        // A ran roughly once per (aging_cap + 1) decisions — real, bounded progress
        // despite a never-ending starvation interval.
        assert!(
            a_runs >= 500 / (aging_cap + 2),
            "A made too little progress: {a_runs}"
        );
        let report = sched.policy_report().unwrap();
        assert!(report.starve_events > 0);
    }

    #[test]
    fn default_policy_reports_none() {
        let mut sched = DetScheduler::new(1);
        sched.spawn("a").unwrap();
        sched.spawn("b").unwrap();
        assert!(sched.policy_report().is_none());
    }

    #[test]
    fn default_policy_never_reports_liveness_deferral() {
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
    }

    #[test]
    fn starvation_reports_liveness_deferral_while_excluding() {
        // A wide interval excluding a residue class reports a policy deferral for
        // at least one decision, so the watchdog excuses that non-progress window.
        let policy = SchedulePolicy {
            pct: None,
            starvation: Some(StarvationConfig {
                intervals: 1,
                max_len: 6,
                window: 2,
            }),
        };
        let mut sched = DetScheduler::with_policy(9, policy);
        for label in 0..4u64 {
            sched.spawn(&format!("t{label}")).unwrap();
        }
        let mut saw_deferral = false;
        for _ in 0..60 {
            let task = sched.next().unwrap().unwrap();
            saw_deferral |= sched.liveness_deferring();
            sched.yield_task(task).unwrap();
        }
        assert!(
            saw_deferral,
            "an active starvation interval must report a deferral"
        );
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
            starvation: None,
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
