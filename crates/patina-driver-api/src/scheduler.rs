//! Scheduler driver operations and exploration-policy reports.

use crate::DriverResult;
use patina_dst_abi::TaskId;

/// End-of-run summary of an exploration scheduling policy (PCT priority-change
/// points, starvation intervals). Populated only during a live selection run
/// (`next()` decisions), so it reflects the record/seeded schedule; on replay the
/// recorded task selections are consumed through `select()` and `next()` is not
/// called, so a replay reports the inert default. The runtime folds these counts
/// into the machine-readable `PATINA_SCHEDULE_POLICY` diagnostic line and the
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
    /// Whether the starvation-interval policy was active.
    pub starvation: bool,
    /// Number of scheduling decisions where the starvation policy actually
    /// excluded at least one runnable task from selection.
    pub starve_events: u64,
    /// Number of scheduling decisions where honoring the starvation set would
    /// have left no schedulable task (every runnable task starved). The policy
    /// falls back to the full runnable set at those steps (liveness safety) and
    /// counts them here so a vacuous starvation configuration is diagnosed.
    pub starve_vacuous: u64,
    /// Total scheduling decisions (`next()` calls) observed under the policy.
    pub decisions: u64,
}

impl SchedulePolicyReport {
    /// Whether any exploration policy was active this run.
    pub fn is_active(&self) -> bool {
        self.pct || self.starvation
    }

    /// The bug-depth estimate for the realized schedule: the number of ordering
    /// decisions (priority-change points hit plus starvation exclusions) that
    /// were live in the schedule. A failure found under a schedule with a higher
    /// estimate exercised a deeper interleaving.
    pub fn bug_depth(&self) -> u64 {
        u64::from(self.pct_change_points_hit) + self.starve_events
    }
}

pub trait SchedulerDriver: Send {
    fn spawn(&mut self, label: &str) -> DriverResult<TaskId>;
    fn yield_task(&mut self, task: TaskId) -> DriverResult<()>;
    fn park(&mut self, task: TaskId, reason: &str) -> DriverResult<()>;
    fn wake(&mut self, task: TaskId) -> DriverResult<()>;
    fn complete(&mut self, task: TaskId) -> DriverResult<()>;
    fn next(&mut self) -> DriverResult<Option<TaskId>>;
    fn select(&mut self, task: Option<TaskId>) -> DriverResult<()>;
    /// End-of-run exploration-policy summary. The default scheduler policy
    /// (uniform random selection) reports `None`; PCT and starvation policies
    /// report their live counts. Read once at run finalization.
    fn policy_report(&self) -> Option<SchedulePolicyReport> {
        None
    }

    /// Whether the most recent scheduling decision deliberately withheld a
    /// runnable task from selection because of an active exploration policy — a
    /// starvation interval excluding a runnable task, or PCT priority ordering
    /// preferring a higher-priority task over an available strictly-lower-priority
    /// one. The liveness watchdog consults this so a *policy-explained*
    /// non-progress window (a deliberate starvation interval or a PCT priority
    /// deferral) is never misreported as a liveness violation: only genuine
    /// no-progress beyond policy-explained deferral trips the watchdog. The
    /// default (uniform-random) policy never defers, so it reports `false` and
    /// the watchdog is fully live for a plain run. Reflects the last `next()`
    /// decision; on replay `next()` is not called, so it reports `false`.
    fn liveness_deferring(&self) -> bool {
        false
    }
}
