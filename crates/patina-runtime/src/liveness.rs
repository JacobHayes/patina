//! Progress watchdogs, spin rescue, CPU time, and compute stops.

use crate::config::{LivenessConfig, RuntimeConfig};
use crate::recording::{Execution, RecordSink};
use crate::{Context, RuntimeError, facts};
use patina_dst_abi::{ClockKind, Operation, Outcome, TaskId};

use std::collections::BTreeMap;

/// Minimum number of consecutive non-progress operations a no-progress window must
/// contain before the watchdog may fire, so a single long-but-legitimate sleep
/// (one non-progress op) can never trip it — only genuine churn (a timer/park spin
/// issuing many scheduling ops) does.
const LIVENESS_MIN_STALL_OPS: u64 = 4;

/// What one boundary operation contributes to the progress trackers (the
/// liveness watchdog and the advance-on-spin streak).
///
/// Progress is genuine guest-visible state change. Not progress: the pure
/// scheduling/time/wait operations the runtime uses to rotate tasks and move
/// virtual time — reading the clock, sleeping, yielding, parking (timed or
/// not), waking, the scheduler decision itself, the park-until-delivery probe
/// — and an empty poll: a non-blocking network receive or accept that found
/// nothing to take (`EAGAIN`), which a polling loop repeats while it waits for
/// a peer. Everything else — every filesystem effect, entropy draw, task
/// spawn/completion, network data movement, and every failed operation — is
/// progress, as before outcomes were classified.
///
/// Consequence (documented): a system that keeps doing real I/O (e.g.
/// exchanging network messages) but never reaches an application-level goal is
/// NOT caught by this generic detector, because its I/O counts as progress; that
/// requires an application-level oracle. The watchdog catches the *pure-churn
/// wedge* — a run that has stopped issuing genuine effects and only spins on
/// timers, parks and empty polls while virtual time marches on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Progress {
    /// Genuine progress, whatever the outcome.
    Always,
    /// Never progress.
    Never,
    /// Decided by the outcome ([`outcome_is_progress`]): the trackers see the
    /// operation when its outcome is settled (`Context::reconcile`), on record
    /// and replay alike.
    ByOutcome,
}

pub(super) fn progress_of(operation: &Operation) -> Progress {
    match operation {
        Operation::ClockNow { .. }
        | Operation::SleepUntil { .. }
        | Operation::TaskYield { .. }
        | Operation::TaskPark { .. }
        | Operation::TaskParkTimed { .. }
        | Operation::TaskWake { .. }
        | Operation::SchedulerNext
        | Operation::NetNextDelivery { .. } => Progress::Never,
        Operation::NetRecv { .. }
        | Operation::NetTcpRecv { .. }
        | Operation::NetTcpAccept { .. } => Progress::ByOutcome,
        _ => Progress::Always,
    }
}

/// Whether a [`Progress::ByOutcome`] operation's outcome is progress: anything
/// but an empty poll. A stream's end of file (`Some(empty)`) and every error
/// are outcomes the guest acts on, so they count.
pub(super) fn outcome_is_progress(operation: &Operation, outcome: &Outcome) -> bool {
    !matches!(
        (operation, outcome),
        (Operation::NetRecv { .. }, Outcome::Datagram(None))
            | (Operation::NetTcpRecv { .. }, Outcome::OptionalBytes(None))
            | (Operation::NetTcpAccept { .. }, Outcome::TcpAccepted(None))
    )
}

/// Which watchdog arm fired.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LivenessKind {
    /// The generic no-progress arm (armed from run start).
    NoProgress,
    /// The heal-then-converge arm (armed at the fault-window end).
    HealThenConverge,
}

impl LivenessKind {
    /// The stable category token (the second field of the `PATINA_VIOLATION`
    /// line): `liveness` for the generic no-progress arm, `converge` for the
    /// heal-then-converge arm. A downstream campaign classifier keys on it.
    pub const fn as_str(&self) -> &'static str {
        match self {
            LivenessKind::NoProgress => "liveness",
            LivenessKind::HealThenConverge => "converge",
        }
    }

    /// The short kebab-case reason (`detail=…`) describing the specific failure.
    pub const fn reason(&self) -> &'static str {
        match self {
            LivenessKind::NoProgress => "no-progress",
            LivenessKind::HealThenConverge => "did-not-converge",
        }
    }
}

/// A structured liveness-watchdog violation, formatted into the stable
/// `PATINA_VIOLATION` interface-contract line a downstream campaign consumer
/// parses. `vtime_ns` is the absolute virtual-monotonic time at the fire;
/// `last_fault_vtime_ns` is the converge arm's fault-window-end arm time (the
/// `--heal-after` / buggify-cutoff instant), meaningful only for the converge arm.
#[derive(Clone, Copy, Debug)]
pub(super) struct LivenessViolation {
    pub(super) kind: LivenessKind,
    pub(super) vtime_ns: u64,
    pub(super) budget_ns: u64,
    pub(super) last_fault_vtime_ns: u64,
}

impl LivenessViolation {
    /// The single stderr line per the interface contract:
    /// `PATINA_VIOLATION liveness detail=no-progress vtime_ns=<n> budget_ns=<n>` and
    /// `PATINA_VIOLATION converge detail=did-not-converge vtime_ns=<n> budget_ns=<n> last_fault_vtime_ns=<n>`.
    fn marker_line(&self) -> String {
        match self.kind {
            LivenessKind::NoProgress => format!(
                "PATINA_VIOLATION liveness detail={} vtime_ns={} budget_ns={}",
                self.kind.reason(),
                self.vtime_ns,
                self.budget_ns,
            ),
            LivenessKind::HealThenConverge => format!(
                "PATINA_VIOLATION converge detail={} vtime_ns={} budget_ns={} last_fault_vtime_ns={}",
                self.kind.reason(),
                self.vtime_ns,
                self.budget_ns,
                self.last_fault_vtime_ns,
            ),
        }
    }
}

/// One virtual-time no-progress budget the watchdog enforces. Each arm tracks the
/// virtual time of the last genuine progress (its `baseline`) and the count of
/// consecutive non-progress ops since then; it fires when the run has churned
/// (`>= LIVENESS_MIN_STALL_OPS` non-progress ops) for more than `budget` virtual
/// nanoseconds past the baseline without any progress and without a
/// policy-explained deferral.
#[derive(Clone, Copy, Debug)]
pub(super) struct WatchdogArm {
    pub(super) kind: LivenessKind,
    /// Virtual time (nanoseconds) at which this arm becomes active. The generic
    /// arm arms at run start; the converge arm arms at the fault-window end.
    arm_time_nanos: u64,
    pub(super) budget_nanos: u64,
    /// Whether virtual time has reached `arm_time_nanos` yet.
    pub(super) armed: bool,
    /// Virtual time of the last progress (or of arming), from which the budget is
    /// measured.
    baseline_nanos: u64,
    /// Consecutive non-progress ops since the baseline.
    pub(super) stall_ops: u64,
}

impl WatchdogArm {
    /// Observe one boundary op at virtual time `now`. Returns a
    /// [`LivenessViolation`] if this arm fires. `progress` is whether the op
    /// advanced genuine state; `deferring` is whether the scheduler is deliberately
    /// withholding a runnable task (a policy-explained window that must not count
    /// as no-progress).
    fn observe(&mut self, now: u64, progress: bool, deferring: bool) -> Option<LivenessViolation> {
        if !self.armed {
            if now < self.arm_time_nanos {
                return None;
            }
            // Arm now: start measuring no-progress from this instant, so nothing
            // before the arm-time counts against the budget.
            self.armed = true;
            self.baseline_nanos = now;
            self.stall_ops = 0;
        }
        if progress || deferring {
            self.baseline_nanos = now;
            self.stall_ops = 0;
            return None;
        }
        self.stall_ops += 1;
        let elapsed = now.saturating_sub(self.baseline_nanos);
        if self.stall_ops >= LIVENESS_MIN_STALL_OPS && elapsed > self.budget_nanos {
            Some(LivenessViolation {
                kind: self.kind,
                vtime_ns: now,
                budget_ns: self.budget_nanos,
                last_fault_vtime_ns: self.arm_time_nanos,
            })
        } else {
            None
        }
    }
}

/// The deterministic, virtual-time-only liveness watchdog. It never records a
/// boundary operation and never perturbs scheduler selection — it only READS the
/// virtual clock and the scheduler's policy-deferral state and, on a genuine
/// no-progress wedge, ADDS a structured `PATINA_VIOLATION` line. That is why
/// enabling it is schedule-invariant (byte-identical trace when no violation
/// fires) and needs no fingerprint component.
///
/// Detection is live-selection only (record/seeded), like the exploration-policy
/// report: on replay the recorded trace is authoritative and already reflects any
/// abort, and the scheduler's live deferral state is not available, so the
/// watchdog stays inert on replay.
pub(super) struct LivenessWatchdog {
    pub(super) arms: Vec<WatchdogArm>,
    /// Whether detection is live this run (record/seeded and at least one arm).
    pub(super) active: bool,
    pub(super) fired: bool,
    /// The violation that fired, kept so the structured facts document can carry
    /// the same fields the `PATINA_VIOLATION` line carries.
    pub(super) violation: Option<LivenessViolation>,
}

impl LivenessWatchdog {
    /// Build the watchdog from the resolved config. `heal_after_nanos` is the
    /// converge arm's arm-time already resolved by the caller (buggify cutoff or
    /// override). `active` gates whether detection actually runs.
    pub(super) fn new(
        config: LivenessConfig,
        heal_after_nanos: u64,
        origin: u64,
        active: bool,
    ) -> Self {
        let heal_after_nanos = origin.saturating_add(heal_after_nanos);
        let mut arms = Vec::new();
        if let Some(budget) = config.no_progress_budget_nanos {
            arms.push(WatchdogArm {
                kind: LivenessKind::NoProgress,
                arm_time_nanos: origin,
                budget_nanos: budget,
                armed: false,
                baseline_nanos: origin,
                stall_ops: 0,
            });
        }
        if let Some(budget) = config.converge_budget_nanos {
            arms.push(WatchdogArm {
                kind: LivenessKind::HealThenConverge,
                arm_time_nanos: heal_after_nanos,
                budget_nanos: budget,
                armed: false,
                baseline_nanos: heal_after_nanos,
                stall_ops: 0,
            });
        }
        Self {
            active: active && !arms.is_empty(),
            arms,
            fired: false,
            violation: None,
        }
    }

    /// Observe one boundary op across every arm; return the first arm that fires.
    fn observe(&mut self, now: u64, progress: bool, deferring: bool) -> Option<LivenessViolation> {
        for arm in &mut self.arms {
            if let Some(violation) = arm.observe(now, progress, deferring) {
                self.fired = true;
                self.violation = Some(violation);
                return Some(violation);
            }
        }
        None
    }
}

/// Consecutive clock-observation boundary ops — at unchanged virtual time and
/// with no intervening progress op — that the runtime treats as a spin.
///
/// Why 1024. The streak is only broken by a *progress* op (see
/// [`progress_of`]) or by virtual time actually moving, so real code
/// cannot accumulate it: any effect, entropy draw, spawn, or sleep resets it,
/// and a clock read is nearly always followed by one of those. 1024 puts the
/// trigger an order of magnitude beyond even a pathological polling loop that
/// re-reads the clock a few dozen times per decision, which is what keeps the
/// rescue invisible to every existing workload (the acceptance constraint: no
/// recorded artifact anywhere in the tree may change). It is simultaneously
/// cheap for a genuine spin: the canonical calibration loop issues two clock
/// ops per iteration, so 1024 is 512 iterations — microseconds of host time.
pub(super) const SPIN_RESCUE_CLOCK_OPS: u64 = 1_024;

/// The first rescue's advance within a spin episode: 1 µs, deliberately tiny.
/// A guest that is merely polling hard — a 100 µs busy-wait, say — must see a
/// nudge rather than a jump, so the elapsed time it eventually derives is close
/// to what it asked for instead of being rounded up to the rescue granularity.
const SPIN_RESCUE_TOKEN_MIN_NANOS: u64 = 1_000;

/// The per-rescue ceiling the token escalates to: 1 ms. The escalation (doubling
/// per rescue) is what makes a real wedge converge in tens of rescues instead of
/// millions of loop iterations; the ceiling is what bounds the resulting
/// overshoot. The calibration pattern in the wild measures a 10 ms window, so a
/// 1 ms ceiling caps the overshoot on that window at 10%.
///
/// Worked example (the fastant calibration loop, 10 ms window): tokens
/// 1, 2, 4, … 512 µs sum to ~1.02 ms over ten rescues, then the ceiling carries
/// the remaining ~9 ms in nine more — ~19 rescues, ~19 × 1024 ≈ 20k recorded
/// clock ops per window. Well under [`patina_dst_trace::MAX_TIMELINE_EVENTS`].
const SPIN_RESCUE_TOKEN_MAX_NANOS: u64 = 1_000_000;

/// Rescues within one spin episode after which the run is aborted as
/// frozen-clock churn: 256.
///
/// Why 256. At the token ceiling this is >250 ms of virtual time advanced with
/// zero genuine progress — 25× the 10 ms window the calibration pattern uses,
/// and ~5× the longest window (50 ms) seen in the crates that use it. A loop
/// still spinning after that is not *waiting* for time, it is *ignoring* it, and
/// no amount of further advancing will unwedge it. Bounded trace cost: at most
/// 256 × 1024 ≈ 262k recorded clock ops before the named abort, so the trace
/// that explains the wedge is still writable and loadable.
const SPIN_CHURN_ABORT_RESCUES: u64 = 256;

/// Advance-on-spin state: the runnable-churn counterpart to the deadlock rescue.
///
/// The deadlock rescue advances virtual time when the guest *waits* — every task
/// parked with a timer pending. The gap it leaves is a guest that is *runnable*
/// and doing nothing but reading the clock: virtual time only moves through a
/// recorded `SleepUntil`, so a loop whose exit condition is "10 ms of monotonic
/// progress" and whose body performs no wait never terminates. That is the
/// pre-`main` calibration shape (`fastant`/`minstant`/`quanta` measure the
/// timestamp counter against the OS clock over a fixed window at startup), and
/// it is common in exactly the crates a DST user wants to instrument.
///
/// Two levels of state, deliberately distinct:
///
/// - The **streak** (`clock_ops` measured from `baseline_nanos`) is the trigger.
///   It counts consecutive clock observations at unchanged virtual time; it is
///   reset by a genuine progress op, and by virtual time moving for any reason
///   other than this rescue's own advance.
/// - The **episode** (`rescues`, `advanced_nanos`) survives across rescues and
///   drives both the token escalation and the frozen-clock-churn backstop. Only
///   a progress op — or a time move the guest itself caused — ends an episode.
///
/// Every input is a recorded boundary op or the driver's monotonic value, both
/// maintained identically on record and replay, so the rescue re-executes at the
/// same point on replay and the trace is byte-identical.
#[derive(Debug, Default)]
pub(super) struct SpinRescue {
    /// Consecutive clock-observation ops since `baseline_nanos`.
    pub(super) clock_ops: u64,
    /// The virtual time the current streak is measured at. A clock op observing
    /// a different time means time moved, which ends the streak (and, unless
    /// this rescue moved it, the episode).
    pub(super) baseline_nanos: u64,
    /// Rescues performed in the current episode; drives the token escalation and
    /// is what [`SPIN_CHURN_ABORT_RESCUES`] bounds.
    pub(super) rescues: u64,
    /// Virtual nanoseconds this episode's rescues have advanced in total, for
    /// the churn diagnostic.
    pub(super) advanced_nanos: u64,
    /// Set while the rescue emits its own `SleepUntil`, so that op does not
    /// disturb the state the rescue is about to update itself.
    pub(super) rescuing: bool,
    /// The virtual time the frozen-clock-churn backstop fired at, so the facts
    /// document can carry the same finding the marker line carries.
    pub(super) churn_vtime_nanos: Option<u64>,
}

impl SpinRescue {
    /// The next rescue's advance: [`SPIN_RESCUE_TOKEN_MIN_NANOS`] doubled once
    /// per rescue already taken in this episode, saturating at
    /// [`SPIN_RESCUE_TOKEN_MAX_NANOS`].
    fn token_nanos(&self) -> u64 {
        // The shift is clamped to the last doubling that can matter (ten of them
        // take the token past the ceiling). Leaving it unclamped is a trap:
        // `1_000 << rescues` overflows u64 around rescue 55 and WRAPS to a
        // SMALLER token, silently slowing convergence at exactly the point the
        // churn backstop is counting on it.
        const MAX_SHIFT: u32 = SPIN_RESCUE_TOKEN_MAX_NANOS.ilog2() + 1;
        let shift = u32::try_from(self.rescues)
            .unwrap_or(MAX_SHIFT)
            .min(MAX_SHIFT);
        (SPIN_RESCUE_TOKEN_MIN_NANOS << shift).min(SPIN_RESCUE_TOKEN_MAX_NANOS)
    }

    /// End the episode entirely: the guest made genuine progress, or time moved
    /// without this rescue moving it.
    fn end_episode(&mut self, now: u64) {
        self.clock_ops = 0;
        self.baseline_nanos = now;
        self.rescues = 0;
        self.advanced_nanos = 0;
    }

    /// Record one completed rescue: the streak restarts at the new virtual time
    /// while the episode carries on.
    fn on_rescued(&mut self, target: u64, token: u64) {
        self.clock_ops = 0;
        self.baseline_nanos = target;
        self.rescues += 1;
        self.advanced_nanos = self.advanced_nanos.saturating_add(token);
    }

    /// The loud, machine-parseable line the frozen-clock-churn abort emits. It
    /// reuses the established `PATINA_VIOLATION liveness …` interface contract —
    /// this IS a liveness failure, and a downstream campaign consumer already
    /// classifies that prefix — with its own `detail=` reason and its own facts.
    fn churn_marker_line(&self, vtime_nanos: u64) -> String {
        format!(
            "PATINA_VIOLATION liveness detail=frozen-clock-churn vtime_ns={} rescues={} \
advanced_ns={} clock_ops_per_rescue={}",
            vtime_nanos, self.rescues, self.advanced_nanos, SPIN_RESCUE_CLOCK_OPS,
        )
    }
}

/// Virtual CPU time. The process and its main thread start at
/// [`patina_dst_abi::STARTUP_CPU_NANOS`], the modeled cost of the exec, loader
/// and libc startup a Linux process has run before `main`. From there, CPU
/// time is charged by one thing only: the advance-on-spin rescue, i.e. a task
/// observing the clock again and again at frozen virtual time. Virtual time
/// also moves on a guest sleep or wait, the deadlock rescue, and injected
/// latency, but no task computes through those. A loop that computes without
/// reading the clock (a hash, a compression pass, a spin on a flag) is not
/// charged, because virtual time does not move under it. Each rescue is
/// charged to the task the scheduler last selected, or to `None`, the main
/// thread before the embedder first schedules a task. Every input is a
/// recorded op or the rescue that replays with it, so the figures are
/// identical on record and replay.
#[derive(Debug)]
pub(super) struct CpuTime {
    pub(super) running: Option<TaskId>,
    by_task: BTreeMap<Option<TaskId>, u64>,
    pub(super) total: u64,
}

impl Default for CpuTime {
    fn default() -> Self {
        CpuTime {
            running: None,
            by_task: BTreeMap::from([(None, patina_dst_abi::STARTUP_CPU_NANOS)]),
            total: patina_dst_abi::STARTUP_CPU_NANOS,
        }
    }
}

impl CpuTime {
    fn charge(&mut self, nanos: u64) {
        self.total = self.total.saturating_add(nanos);
        let task = self.by_task.entry(self.running).or_default();
        *task = task.saturating_add(nanos);
    }
}

/// Resolve the heal-then-converge arm-time for a config: an explicit override,
/// else the buggify damage-control cutoff (when buggify is enabled), else run
/// start. Shared by the metadata record and the built watchdog so they agree.
pub(super) fn resolve_heal_after(config: &RuntimeConfig) -> u64 {
    match config.liveness.heal_after_nanos {
        Some(nanos) => nanos,
        None if config.buggify.enabled => config.buggify.cutoff_nanos,
        None => 0,
    }
}

impl Context {
    /// Read-only native watchdog observation. The embedder must hold its
    /// context AND thread-transition locks. Existing scheduler bookkeeping is
    /// the authority; untimed parked peers and a lone running task never qualify.
    /// A peer parked until a future deadline qualifies: call-free code keeps
    /// that deadline from arriving, since only a boundary operation advances
    /// virtual time. The expiry authority answers which deadlines are future;
    /// a reached one has already expired and left its task runnable.
    /// Host-time detection is disabled on replay: its recorded stop is final.
    pub fn compute_watchdog_candidate(&self) -> Option<(u64, TaskId)> {
        if !matches!(self.execution, Execution::Seeded | Execution::Record { .. }) {
            return None;
        }
        let running = self.cpu.running?;
        self.compute_starves_peer(running)
            .then_some((self.steps, running))
    }

    fn compute_starves_peer(&self, running: TaskId) -> bool {
        self.cpu.running == Some(running)
            && self.scheduler_tasks.contains(&running)
            && !self.parked_tasks.contains(&running)
            && self.scheduler_tasks.iter().any(|task| {
                *task != running
                    && (!self.parked_tasks.contains(task) || self.has_future_deadline(*task))
            })
    }

    /// A replay terminal boundary already reached, without asking the guest for
    /// another operation (it may be in call-free code forever).
    pub fn replay_compute_stop_due(&self) -> Option<patina_dst_trace::ComputeStop> {
        self.compute_stop.filter(|stop| stop.steps <= self.steps)
    }

    /// Commit a native host-time stop. This changes no driver or scheduler
    /// answer. The valid recorded prefix and its terminal fact are flushed once.
    pub fn stop_compute_bound(&mut self, task: TaskId) -> RuntimeError {
        if !self.compute_starves_peer(task) {
            return RuntimeError::ComputeStopState;
        }
        // steps counts an operation at begin, before custom perform has an
        // outcome. Only recorder decisions form a replayable prefix. Refuse an
        // overflowed recorder BEFORE any serializer or boxed I/O error path.
        let steps = match &self.execution {
            Execution::Record { recorder, .. } => match recorder.committed_prefix_len() {
                Some(steps) => steps,
                None => return RuntimeError::ComputeStopOverflow,
            },
            _ => self.compute_stop.map_or(self.steps, |stop| stop.steps),
        };
        let stop = patina_dst_trace::ComputeStop { steps, task };
        if let Execution::Record { recorder, .. } = &mut self.execution {
            recorder.set_compute_stop(stop);
        }
        self.compute_stop = Some(stop);
        // An asynchronous observer may interrupt an allocator critical section.
        // Export borrowed data only, without ordinary finish-time enrichment.
        if !self.facts_emitted {
            self.facts_emitted = true;
            if let Some(output) = self.facts.as_mut() {
                let mut bytes = [0u8; 512];
                let mut cursor = std::io::Cursor::new(&mut bytes[..]);
                use std::io::Write;
                let encoded = facts::write_compute_bound_facts(stop, &mut cursor);
                let newline = cursor.write_all(b"\n");
                let length = cursor.position() as usize;
                if encoded.is_err() || newline.is_err() || output.write(&bytes[..length]).is_err() {
                    return RuntimeError::ComputeStopExport;
                }
            }
        }
        if !self.recording_flushed
            && let Execution::Record { recorder, sink } = &mut self.execution
        {
            self.recording_flushed = true;
            let result = match sink {
                RecordSink::Transport(transport) => transport.write_prefix(recorder),
                RecordSink::Path { path, .. } => std::fs::File::create(path)
                    .and_then(|file| recorder.write_prefix(file).map_err(std::io::Error::other)),
            };
            if result.is_err() {
                return RuntimeError::ComputeStopExport;
            }
        }
        RuntimeError::ComputeBound { task, steps }
    }

    /// The virtual CPU time charged to `task`; `None` is the main thread
    /// before the embedder first scheduled a task, and holds the startup
    /// cost.
    pub fn task_cpu_time_nanos(&self, task: Option<TaskId>) -> u64 {
        self.cpu.by_task.get(&task).copied().unwrap_or(0)
    }

    /// Set the earliest monotonic deadline of the embedder's process timers
    /// (`None`: none armed). Unrecorded bookkeeping the embedder derives from
    /// the guest's own calls, so it is identical on record and replay; the
    /// advance-on-spin rescue does not step over it.
    pub fn set_alarm(&mut self, deadline: Option<u64>) {
        self.alarm = deadline;
    }

    /// Set the CPU time the embedder's earliest CPU-time timer still needs
    /// (`None`: none armed). Unrecorded bookkeeping the embedder derives from
    /// the guest's own calls, like [`Context::set_alarm`]. While it is set,
    /// the advance-on-spin rescue's token is what the timer still needs, up
    /// to the token ceiling, from the first rescue: the task computes toward a
    /// deadline it declared, so the rescue lands on it instead of ramping.
    pub fn set_cpu_alarm(&mut self, remaining: Option<u64>) {
        self.cpu_alarm = remaining.map(|remaining| (remaining, self.cpu.total));
    }

    /// Idle time up to a process timer's deadline: when every task is parked
    /// and `deadline` lies ahead of both the clock and every parked task's
    /// own deadline, advance virtual time to it (a recorded `SleepUntil`, as
    /// the deadlock rescue does) and answer `true`, so the embedder fires the
    /// timer — which may wake a task — before it asks for the next task. A
    /// deadline a parked task shares is left to the deadlock rescue.
    pub fn advance_idle_to(&mut self, deadline: u64) -> Result<bool, RuntimeError> {
        if self.clock.is_none() || !self.scheduler_would_deadlock() {
            return Ok(false);
        }
        let now = self.current_monotonic()?;
        let before_tasks = self
            .timers
            .keys()
            .next()
            .is_none_or(|(task_deadline, _)| deadline < *task_deadline);
        if deadline <= now || !before_tasks {
            return Ok(false);
        }
        self.sleep_until(ClockKind::Monotonic, deadline)?;
        Ok(true)
    }

    /// Feed one beginning boundary operation to the progress trackers, unless
    /// its progress waits on its outcome ([`Context::track_outcome`]).
    pub(super) fn track_begin(&mut self, operation: &Operation) -> Result<(), RuntimeError> {
        let progress = match progress_of(operation) {
            Progress::Always => true,
            Progress::Never => false,
            Progress::ByOutcome => return Ok(()),
        };
        self.liveness_track(progress)?;
        self.spin_track(operation, progress)
    }

    /// Feed a [`Progress::ByOutcome`] operation to the progress trackers once
    /// its outcome is settled. Called with the outcome replay returns (the
    /// recorded one) and record keeps, at the same point of both.
    pub(super) fn track_outcome(
        &mut self,
        operation: &Operation,
        outcome: &Outcome,
    ) -> Result<(), RuntimeError> {
        if progress_of(operation) != Progress::ByOutcome {
            return Ok(());
        }
        let progress = outcome_is_progress(operation, outcome);
        self.liveness_track(progress)?;
        self.spin_track(operation, progress)
    }

    /// Advance the liveness watchdog for one boundary op. Reads virtual time and
    /// the scheduler's policy-deferral state WITHOUT recording anything or
    /// perturbing selection; returns a [`RuntimeError::Liveness`] (after emitting
    /// the loud, classifiable `PATINA_VIOLATION` line) when a no-progress budget is
    /// exceeded. Inert unless the watchdog is active (record/seeded with a budget
    /// configured), so a plain run and every replay are unaffected.
    fn liveness_track(&mut self, progress: bool) -> Result<(), RuntimeError> {
        if !self.liveness.active || self.clock.is_none() {
            return Ok(());
        }
        // Arm offsets were anchored to run start at construction; observations
        // and diagnostic timestamps stay in the trace's monotonic domain.
        let now = self.current_monotonic()?;
        let deferring = self
            .scheduler
            .as_ref()
            .map(|scheduler| scheduler.liveness_deferring())
            .unwrap_or(false);
        if let Some(violation) = self.liveness.observe(now, progress, deferring) {
            // The single interface-contract line, loud and machine-parseable.
            // Emitted from the runtime so it reaches stderr regardless of the
            // driving surface, exactly like the vacuous-starvation `PATINA WARNING`.
            let marker = violation.marker_line();
            eprintln!("{marker}");
            // The interposed families abort the process on this error without
            // ever reaching `finish`, so the facts document — which carries this
            // very violation as a `runtime_findings` entry — has to be written
            // here or it is never written at all. Idempotent: `finish` will not
            // write a second one.
            self.emit_facts();
            return Err(RuntimeError::Liveness {
                kind: violation.kind,
                detail: marker,
            });
        }
        Ok(())
    }

    /// Advance the spin tracker for one boundary op, on both record and replay.
    /// Pure bookkeeping over the recorded op stream and the driver's monotonic
    /// value — it records nothing and reads no host state — so the trigger point
    /// is reproduced exactly on replay.
    ///
    /// Three cases, in the order the trigger is defined (K consecutive clock
    /// observations, zero virtual-time advance, no intervening progress op):
    /// a progress op ends the episode; a scheduling/wait op is neutral (it
    /// neither counts nor breaks the streak, so a spinning thread in a
    /// multi-task run still accumulates); a clock op counts, unless virtual time
    /// has moved since the streak began, which ends the episode instead.
    fn spin_track(&mut self, operation: &Operation, progress: bool) -> Result<(), RuntimeError> {
        // The rescue's own `SleepUntil`: the rescue updates the state itself.
        if self.spin.rescuing {
            return Ok(());
        }
        if progress {
            // Genuine state advancement. Whatever this guest is doing, it is not
            // churning on the clock — drop the whole episode, escalation included.
            self.spin.end_episode(self.spin.baseline_nanos);
            return Ok(());
        }
        if !matches!(operation, Operation::ClockNow { .. }) {
            return Ok(());
        }
        if self.clock.is_none() {
            return Ok(());
        }
        let now = self.current_monotonic()?;
        if now != self.spin.baseline_nanos {
            // Virtual time moved and this rescue did not move it, so the guest
            // waited: that is the wait the rescue exists to substitute for.
            self.spin.end_episode(now);
        }
        self.spin.clock_ops += 1;
        Ok(())
    }

    /// The advance-on-spin rescue itself, invoked from [`Context::now`] before
    /// the clock observation is recorded. A no-op until the streak reaches
    /// [`SPIN_RESCUE_CLOCK_OPS`], which is why a run that never spins is
    /// byte-for-byte unchanged.
    ///
    /// It rides the same mechanism as the deadlock rescue: a recorded
    /// `SleepUntil` on the monotonic clock, replayed from the trace like any
    /// other. The advance is clamped so it never steps over a pending timer
    /// deadline. Reaching it expires the due timed parks (the advance runs the
    /// single expiry path), so their tasks are runnable at the next decision.
    pub(super) fn spin_rescue(&mut self) -> Result<(), RuntimeError> {
        if self.spin.clock_ops < SPIN_RESCUE_CLOCK_OPS {
            return Ok(());
        }
        let now = self.current_monotonic()?;
        // The streak counts reads; this is the trigger's other half — that
        // virtual time did not move across them. It is enforced HERE and not
        // only in `spin_track` because the op between the streak's last read and
        // this one may have been the guest's own sleep: `sleep_for` reads the
        // clock (counted) and only then advances it. Without this check a
        // poll-and-sleep loop would be rescued on its very next read.
        if now != self.spin.baseline_nanos {
            self.spin.end_episode(now);
            return Ok(());
        }
        // Backstop first: a loop that ignores time rather than waiting for it
        // must become a named abort, not an unbounded stream of rescues.
        if self.spin.rescues >= SPIN_CHURN_ABORT_RESCUES {
            return Err(self.frozen_clock_churn(now));
        }
        // Toward a CPU-time timer, the time it still needs (charged since it
        // was published counts), up to the ceiling; otherwise the escalating
        // token.
        let token = match self.cpu_alarm {
            Some((remaining, at)) => {
                match remaining.saturating_sub(self.cpu.total.saturating_sub(at)) {
                    0 => self.spin.token_nanos(),
                    remaining => remaining.min(SPIN_RESCUE_TOKEN_MAX_NANOS),
                }
            }
            None => self.spin.token_nanos(),
        };
        let target = now.saturating_add(token);
        // Never advance past the earliest still-future timer deadline, a
        // parked task's or the embedder's process timers'.
        let task_deadline = self.timers.keys().next().map(|(deadline, _)| *deadline);
        let target = [task_deadline, self.alarm]
            .into_iter()
            .flatten()
            .filter(|deadline| *deadline > now)
            .fold(target, u64::min);
        self.spin.rescuing = true;
        let result = self.sleep_until(ClockKind::Monotonic, target);
        self.spin.rescuing = false;
        result?;
        // The baton holder observed the clock through this advance: CPU time.
        self.cpu.charge(target.saturating_sub(now));
        self.spin.on_rescued(target, target.saturating_sub(now));
        Ok(())
    }

    /// The frozen-clock churn abort: [`SPIN_CHURN_ABORT_RESCUES`] token advances
    /// bought no genuine progress, so the guest is in a loop that ignores the
    /// clock it is reading. Loud (a `PATINA_VIOLATION liveness` line naming the
    /// pattern and what the guest was doing) and fail-closed, in the shape the
    /// liveness watchdog established.
    fn frozen_clock_churn(&mut self, now: u64) -> RuntimeError {
        self.spin.churn_vtime_nanos = Some(now);
        let marker = self.spin.churn_marker_line(now);
        eprintln!("{marker}");
        eprintln!(
            "patina: frozen-clock churn — the guest has issued {} clock observations per rescue \
across {} advance-on-spin rescues ({} ns of virtual time) without one genuine boundary effect \
in between. It is not waiting for the clock it is reading, it is ignoring it: a busy-wait whose \
exit condition never depends on the value, or one waiting on state only another task can \
publish. Give the loop a wait the runtime can see (sleep/yield/park), or bound the run with \
--budget.",
            SPIN_RESCUE_CLOCK_OPS, self.spin.rescues, self.spin.advanced_nanos,
        );
        // The interposed families abort on this without reaching `finish`, so
        // the artifacts that explain the wedge have to be written here.
        self.emit_facts();
        self.flush_recording();
        RuntimeError::FrozenClockChurn { detail: marker }
    }
}

#[cfg(test)]
mod tests;
