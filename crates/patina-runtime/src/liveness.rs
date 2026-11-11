//! Progress watchdogs, poll escalation, and compute stops.

use crate::config::{LivenessConfig, RuntimeConfig};
use crate::recording::Execution;
use crate::{Context, RuntimeError, facts};
use patina_dst_abi::{
    ChargeClass, ChargeCounts, ClockKind, EffectClass, Operation, Outcome, TaskId,
};

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
    if operation.effect_class() == EffectClass::Schedule {
        Progress::Never
    } else if operation.is_poll() {
        Progress::ByOutcome
    } else {
        Progress::Always
    }
}

/// Whether a [`Progress::ByOutcome`] operation's outcome is progress: anything
/// but an empty poll. A stream's end of file (`Some(empty)`) and every error
/// are outcomes the guest acts on, so they count.
pub(super) fn outcome_is_progress(operation: &Operation, outcome: &Outcome) -> bool {
    !(operation.is_poll() && outcome.is_empty_poll())
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
/// A replay runs the recording's watchdog (its metadata is authoritative),
/// and its scheduler keeps PCT's state as the recording's decisions left it,
/// so it reaches a recorded stop at the same operation.
pub(super) struct LivenessWatchdog {
    pub(super) arms: Vec<WatchdogArm>,
    /// Whether detection is live this run (at least one arm).
    pub(super) active: bool,
    pub(super) fired: bool,
    /// The violation that fired, kept so the structured facts document can carry
    /// the same fields the `PATINA_VIOLATION` line carries.
    pub(super) violation: Option<LivenessViolation>,
}

impl LivenessWatchdog {
    /// Build the watchdog from the resolved config. `heal_after_nanos` is the
    /// converge arm's arm-time already resolved by the caller (buggify cutoff or
    /// override).
    pub(super) fn new(config: LivenessConfig, heal_after_nanos: u64, origin: u64) -> Self {
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
            active: !arms.is_empty(),
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

/// Consecutive polls without progress after which a poll is escalated:
/// 1024.
///
/// A poll is a clock observation, an operation whose outcome found nothing
/// to take (see [`outcome_is_progress`]), or the guest's own request to yield
/// ([`Context::yield_poll`]); a progress operation ends the count, and the
/// scheduling and wait operations between polls neither count nor end it, so
/// a polling thread in a multi-task run still accumulates. 1024 is an order
/// of magnitude beyond a loop that re-reads the clock a few dozen times per
/// decision, and still cheap for a genuine spin: the canonical calibration
/// loop issues two clock reads per iteration, so 1024 is 512 iterations,
/// microseconds of host time.
pub const ESCALATION_POLLS: u64 = 1_024;

/// The first escalation's CPU time within an episode: 1 µs, deliberately
/// tiny. A guest merely polling hard (a 100 µs busy-wait) sees a nudge rather
/// than a jump, so the elapsed time it derives stays close to what it asked
/// for.
const ESCALATION_TOKEN_MIN_NANOS: u64 = 1_000;

/// What the token doubles to: 1 ms. The doubling is what makes a short
/// calibration loop converge in tens of escalations instead of millions of
/// iterations; 1 ms bounds the overshoot of any wait under a second (10% of
/// the 10 ms window the calibration pattern measures).
///
/// Worked example (the fastant calibration loop, 10 ms window): tokens
/// 1, 2, 4, … 512 µs sum to ~1.02 ms over ten escalations, then 1 ms tokens
/// carry the remaining ~9 ms in nine more: ~19 escalations, ~19 × 1024 ≈
/// 20k recorded clock reads per window.
const ESCALATION_TOKEN_STEP_NANOS: u64 = 1_000_000;

/// The share of what an episode has charged that its next token is, once
/// that is more than [`ESCALATION_TOKEN_STEP_NANOS`]: 1/256.
///
/// It bounds how late a long busy-wait ends, as a fraction of the wait
/// (0.4%), and sets how fast a streak that never ends reaches the
/// no-progress horizon ([`Busy`]): about two million polls, few enough that
/// the stop comes in seconds and its trace can still be written. A smaller share
/// is more exact and slower on both counts. The 1 ms step is 1/256 of 256 ms,
/// so the two parts of the token meet a quarter of a second into a streak.
const ESCALATION_TOKEN_SHARE: u64 = 256;

/// Whether an operation that made no progress is a poll: a clock observation,
/// or an operation whose outcome found nothing to take.
fn is_poll(operation: &Operation) -> bool {
    matches!(operation, Operation::ClockNow { .. }) || progress_of(operation) == Progress::ByOutcome
}

/// The class of call a poll operation stands for: a clock read, or a system
/// call.
fn poll_class(operation: &Operation) -> ChargeClass {
    match operation {
        Operation::ClockNow { .. } => ChargeClass::Clock,
        _ => ChargeClass::Syscall,
    }
}

/// Poll escalation: a loop that polls for something only time can bring.
///
/// Natively a busy poller burns CPU for the whole wait, and that CPU time
/// moves the clock. The simulation charges only the iterations it executes,
/// so a loop waiting for a 1 ms deadline would take thousands of them. Every
/// [`ESCALATION_POLLS`] polls without progress, one poll is escalated: it is
/// charged as `k` more calls of its class, standing for the iterations the
/// simulation did not run, so the user/system split stays the poller's own.
/// `k` is the episode's token's worth ([`Escalation::token_nanos`]), and
/// that is all: an escalation never reaches for a deadline some other task
/// is waiting on, because a streak of polls may just as well be work that
/// reads the clock as it goes, and that work must not make a peer's timeout
/// pass. The clock follows the charge like any other, stopping at each
/// pending deadline on the way. Only a CPU-time timer bounds `k`: CPU time
/// is the charges themselves, with nothing to carry, so the escalation
/// charges no more than reaches the earliest one.
///
/// Two levels of state, deliberately distinct:
///
/// - The **streak** (`polls`) is the trigger. It counts polls since the
///   episode began or the last escalation.
/// - The **episode** (`escalations`, `charged_nanos`) survives escalations
///   and drives the token. A progress operation or an idle advance (the
///   guest waited) ends it.
///
/// Escalation is charged after the escalated poll's outcome, so the poll
/// itself observes the time before it. Every input is a recorded operation,
/// its outcome, or the charges the guest's calls make, all identical on
/// record and replay, and nothing is recorded: the escalated charge replays
/// with the poll that triggers it.
#[derive(Debug, Default)]
pub(super) struct Escalation {
    /// Polls since the episode began or the last escalation.
    pub(super) polls: u64,
    /// Escalations in the current episode.
    pub(super) escalations: u64,
    /// CPU time the episode's escalations charged: what the token follows.
    pub(super) charged_nanos: u64,
    /// An escalation a completed streak earned, with the class of the poll
    /// that completed it. Taken at once: by the operation's own outcome, or
    /// by the embedder's gateway for the guest call that made it.
    due: Option<ChargeClass>,
    /// Whether the embedder charges each guest call ([`Context::accrue_calls`]):
    /// it then applies an escalation at the end of the call that earned it,
    /// in that call's task and class ([`Context::take_poll_streak`],
    /// [`Context::escalate_call`]), once all its reads are done. Without one,
    /// each operation is a call and is escalated at its outcome.
    pub(super) paced: bool,
}

impl Escalation {
    /// The next token: [`ESCALATION_TOKEN_MIN_NANOS`] doubled once per
    /// escalation already taken in this episode up to
    /// [`ESCALATION_TOKEN_STEP_NANOS`], and from then on
    /// 1/[`ESCALATION_TOKEN_SHARE`] of what the episode has charged, once
    /// that is more.
    ///
    /// So a poll costs about 1 µs for the first quarter second of a streak
    /// (1 ms per 1024 polls), and after that about four millionths of the
    /// time the streak has spent. The first part keeps work that polls as it
    /// goes cheap and a short wait exact to the millisecond. The second is
    /// what lets a busy-wait reach a deadline seconds or minutes away in a
    /// million polls or two rather than a million a second, late by at most
    /// 0.4% of the wait, and what brings a loop that will never end to the
    /// no-progress horizon.
    fn token_nanos(&self) -> u64 {
        // The shift is clamped to the last doubling that can matter (ten of
        // them take the token past the step): `1_000 << escalations` would
        // overflow u64 around escalation 55 and WRAP to a smaller token.
        const MAX_SHIFT: u32 = ESCALATION_TOKEN_STEP_NANOS.ilog2() + 1;
        let shift = u32::try_from(self.escalations)
            .unwrap_or(MAX_SHIFT)
            .min(MAX_SHIFT);
        (ESCALATION_TOKEN_MIN_NANOS << shift)
            .min(ESCALATION_TOKEN_STEP_NANOS)
            .max(self.charged_nanos / ESCALATION_TOKEN_SHARE)
    }

    /// Count one poll; the one that completes a streak makes an escalation
    /// of `class` due. The streak is spent as it completes, whenever its
    /// escalation is applied: the polls after it start the next one.
    fn poll(&mut self, class: ChargeClass) {
        self.polls += 1;
        if self.polls >= ESCALATION_POLLS {
            self.polls = 0;
            self.due = Some(class);
        }
    }

    /// End the episode: the guest made progress or waited.
    pub(super) fn end_episode(&mut self) {
        self.polls = 0;
        self.escalations = 0;
        self.charged_nanos = 0;
        self.due = None;
    }

    /// Record one escalation: the streak restarts while the episode carries
    /// on.
    fn on_escalated(&mut self, nanos: u64) {
        self.polls = 0;
        self.escalations += 1;
        self.charged_nanos = self.charged_nanos.saturating_add(nanos);
    }
}

/// How long a running task may compute before a compute point lets a
/// waiting peer run: 1 ms of CPU time, a scheduler's time slice.
const COMPUTE_SLICE_NANOS: u64 = 1_000_000;

/// The two bounds on CPU time, and the time slice, all measured in charged
/// CPU time (the guest's calls, poll escalations and metered computation;
/// never an idle advance, which is the guest waiting, not working).
///
/// - The **no-progress horizon**: CPU time charged since the run last made
///   progress (an operation [`progress_of`] counts) reaching the budget is
///   a liveness finding. A PCT deferral does not reset it: PCT runs a
///   deferred task within its starvation bound, far inside the horizon. The budget is the
///   liveness watchdog's (`--liveness-watchdog`), else
///   [`crate::DEFAULT_LIVENESS_BUDGET_NANOS`]. Because only CPU time counts,
///   a guest that sleeps or waits never reaches it, however long; a guest
///   that spins, polls or yields with nothing else happening does, whatever
///   it spins on.
/// - The **compute budget**: metered computation charged with no operation
///   but scheduling points in between reaching
///   [`RuntimeConfig::with_compute_budget`]'s budget stops the run as
///   `compute_bound`. It bounds a computation that never calls into the
///   runtime, where the horizon would take minutes of host time.
/// - The **slice**: a task that has computed [`COMPUTE_SLICE_NANOS`] since
///   it was selected yields to a runnable peer at its next compute point.
///
/// Every input is a charge or a recorded operation, the same on record and
/// replay, and the budgets are recorded, so a replay stops where the
/// recording did.
#[derive(Debug, Default)]
pub(super) struct Busy {
    /// The CPU total when the run last made progress.
    baseline_nanos: u64,
    pub(super) budget_nanos: u64,
    /// Metered computation charged since the last operation other than a
    /// scheduling point.
    pub(super) compute_nanos: u64,
    pub(super) compute_budget_nanos: u64,
    /// The CPU total when the scheduler last selected a task.
    slice_origin_nanos: u64,
    /// The step at which the run last made progress.
    progress_step: u64,
    /// The step of the previous `sched_yield`, by any task.
    yield_step: Option<u64>,
    /// All metered computation charged in the run.
    computed_nanos: u64,
    /// [`Busy::computed_nanos`] at the previous `sched_yield`.
    yield_computed_nanos: u64,
}

impl Busy {
    pub(super) fn new(budget_nanos: u64, compute_budget_nanos: u64, startup_nanos: u64) -> Self {
        Self {
            baseline_nanos: startup_nanos,
            budget_nanos,
            compute_budget_nanos,
            slice_origin_nanos: startup_nanos,
            ..Self::default()
        }
    }

    /// Note metered computation charged.
    pub(super) fn computed(&mut self, nanos: u64) {
        self.compute_nanos = self.compute_nanos.saturating_add(nanos);
        self.computed_nanos = self.computed_nanos.saturating_add(nanos);
    }

    /// The scheduler selected a task: its slice starts.
    pub(super) fn selected(&mut self, total_nanos: u64) {
        self.slice_origin_nanos = total_nanos;
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

/// How far the guest has come, as the native compute observer sees it
/// ([`Context::compute_watchdog_candidate`]): two equal stamps a bound apart
/// are a guest that was charged no virtual time and began no boundary
/// operation in between.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ComputeStamp {
    /// Boundary operations begun, not counting a task's yield and the
    /// scheduler's decision.
    pub operations: u64,
    /// The CPU time charged to the guest's calls.
    pub charged_nanos: u64,
}

impl Context {
    /// Read-only native watchdog observation: what the host-time observer
    /// compares between two looks, and the task it would stop. The embedder
    /// must hold its context AND thread-transition locks.
    ///
    /// The stamp changes whenever the guest reaches the runtime in a way
    /// that can lead somewhere: its calls are charged (a call's charge, or a
    /// compute meter's batch, handed over at a gateway, which moves virtual
    /// time), or an operation other than a yield and the decision that
    /// follows it begins. A yield that charges nothing is an instrumented
    /// build's edge hook (`--yield-stride`): it lets the scheduler choose,
    /// but a guest that does nothing else between two of them has moved no
    /// time, exactly like the same loop without the hook, so it must not
    /// look like progress here. A call answered without a gateway (a cached
    /// identity query) moves nothing either until the next gateway hands
    /// its charge over, so a loop of only those is one more loop that
    /// reaches nothing.
    ///
    /// A candidate exists while a thread runs guest code: the task the
    /// scheduler selected, unparked, or the main thread before the embedder
    /// manages any task (`None`). Nothing else can end such a run: only a
    /// boundary operation advances virtual time, so a peer's deadline never
    /// arrives, and with no peer at all there is nothing left to wait for.
    /// Host-time detection is disabled on replay: its recorded stop is final.
    pub fn compute_watchdog_candidate(&self) -> Option<(ComputeStamp, Option<TaskId>)> {
        if !matches!(self.execution, Execution::Seeded | Execution::Record { .. }) {
            return None;
        }
        let running = self.charges.running;
        self.computing(running).then_some((
            ComputeStamp {
                operations: self.steps - self.yield_steps,
                charged_nanos: self.charges.total().total_ns(),
            },
            running,
        ))
    }

    /// Whether `running` is the thread that runs guest code now: the selected,
    /// unparked task, or (`None`) the main thread of a run with no task yet.
    fn computing(&self, running: Option<TaskId>) -> bool {
        match running {
            Some(task) => {
                self.charges.running == Some(task)
                    && self.scheduler_tasks.contains(&task)
                    && !self.parked_tasks.contains(&task)
            }
            None => self.charges.running.is_none() && self.scheduler_tasks.is_empty(),
        }
    }

    /// A replay terminal boundary already reached, without asking the guest for
    /// another operation (it may be in call-free code forever).
    pub fn replay_compute_stop_due(&self) -> Option<patina_dst_trace::ComputeStop> {
        self.compute_stop.filter(|stop| stop.steps <= self.steps)
    }

    /// Commit a native host-time stop. This changes no driver or scheduler
    /// answer. The valid recorded prefix and its terminal fact are flushed once.
    pub fn stop_compute_bound(&mut self, task: Option<TaskId>) -> RuntimeError {
        if !self.computing(task) {
            return RuntimeError::ComputeStopState;
        }
        // Only recorder decisions form a replayable prefix. A recorder that already abandoned its trace has none: the run stops
        // the same way, under the same class, and its trace is reported lost.
        let prefix = match &self.execution {
            Execution::Record { recorder, .. } => recorder.committed_prefix_len(),
            _ => Some(self.compute_stop.map_or(self.steps, |stop| stop.steps)),
        };
        let steps = prefix.unwrap_or(self.steps);
        let stop = patina_dst_trace::ComputeStop { steps, task };
        if prefix.is_some()
            && let Execution::Record { recorder, .. } = &mut self.execution
        {
            recorder.set_compute_stop(stop);
        }
        self.compute_stop = Some(stop);
        // An asynchronous observer may interrupt an allocator critical section.
        // Export borrowed data only, without ordinary finish-time enrichment.
        if !self.facts_sealed {
            self.facts_sealed = true;
            if let Some(output) = self.facts.as_mut() {
                let mut bytes = [0u8; 512];
                let mut cursor = std::io::Cursor::new(&mut bytes[..]);
                use std::io::Write;
                let encoded =
                    facts::write_compute_bound_facts(self.facts_context, stop, &mut cursor);
                let newline = cursor.write_all(b"\n");
                let length = cursor.position() as usize;
                if encoded.is_err()
                    || newline.is_err()
                    || output.write_facts(&bytes[..length]).is_err()
                {
                    return RuntimeError::ComputeStopExport;
                }
            }
        }
        if !self.recording_flushed
            && let Execution::Record {
                recorder,
                transport,
            } = &mut self.execution
        {
            self.recording_flushed = true;
            let exported = match prefix {
                Some(_) => transport.write_prefix(recorder),
                // The marker a reader takes for "abandoned", not for the
                // empty file of a recorder that died: a constant, since
                // nothing here may allocate.
                None => transport.write_bundle(patina_dst_trace::ABANDONED_AT_STOP_MARKER),
            };
            if exported.is_err() {
                return RuntimeError::ComputeStopExport;
            }
        }
        RuntimeError::ComputeBound { task, steps }
    }

    /// Set the earliest monotonic deadline of the embedder's process timers
    /// (`None`: none armed). Unrecorded bookkeeping the embedder derives from
    /// the guest's own calls, so it is identical on record and replay; a
    /// charge stops the clock at it ([`Context::charge`]).
    pub fn set_alarm(&mut self, deadline: Option<u64>) {
        self.alarm = deadline;
    }

    /// Idle time up to a process timer's deadline: when every task is parked
    /// and `deadline` lies ahead of both the clock and every parked task's
    /// own deadline, advance virtual time to it (a recorded `SleepUntil`, as
    /// the deadlock rescue does) and answer `true`, so the embedder fires the
    /// timer — which may wake a task — before it asks for the next task. A
    /// deadline a parked task shares is left to the deadlock rescue.
    pub fn advance_idle_to(&mut self, deadline: u64) -> Result<bool, RuntimeError> {
        if !self.scheduler_would_deadlock() {
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
        if matches!(
            operation,
            Operation::TaskYield { .. } | Operation::SchedulerNext
        ) {
            self.yield_steps += 1;
            // A scheduling point inside a computation (a compute meter's or
            // an instrumented edge's) is where its budget is checked.
            if matches!(operation, Operation::TaskYield { .. })
                && self.busy.compute_nanos >= self.busy.compute_budget_nanos
            {
                return Err(self.compute_budget_stop());
            }
        } else {
            self.busy.compute_nanos = 0;
        }
        let progress = match progress_of(operation) {
            Progress::Always => true,
            Progress::Never => false,
            Progress::ByOutcome => return Ok(()),
        };
        self.track(operation, progress)
    }

    /// Feed one operation, progress or not, to every progress tracker.
    fn track(&mut self, operation: &Operation, progress: bool) -> Result<(), RuntimeError> {
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
        self.track(operation, outcome_is_progress(operation, outcome))
    }

    /// Advance the liveness watchdog for one boundary op. Reads virtual time and
    /// the scheduler's policy-deferral state WITHOUT recording anything or
    /// perturbing selection; returns a [`RuntimeError::Liveness`] (after emitting
    /// the loud, classifiable `PATINA_VIOLATION` line) when a no-progress budget is
    /// exceeded. Inert unless a budget is configured, so a plain run is
    /// unaffected.
    fn liveness_track(&mut self, progress: bool) -> Result<(), RuntimeError> {
        // A PCT deferral does not excuse the horizon: PCT's starvation
        // bound runs a deferred task within a bounded number of decisions
        // (about a virtual second of a spinner's slices), far inside the
        // default horizon, so a deferred task that could make progress does
        // before it is reached. A budget set below that can stop a spin-wait
        // whose setter PCT is still deferring.
        if progress {
            self.busy.baseline_nanos = self.charges.total().total_ns();
            self.busy.progress_step = self.steps;
        } else {
            self.busy_check()?;
        }
        let deferring = self.scheduler.liveness_deferring();
        if !self.liveness.active {
            return Ok(());
        }
        // Arm offsets were anchored to run start at construction; observations
        // and diagnostic timestamps stay in the trace's monotonic domain.
        let now = self.current_monotonic()?;
        if let Some(violation) = self.liveness.observe(now, progress, deferring) {
            return Err(self.liveness_stop(violation));
        }
        Ok(())
    }

    /// The no-progress horizon ([`Busy`]): a liveness stop once the CPU
    /// time charged since the last progress reaches the budget.
    fn busy_check(&mut self) -> Result<(), RuntimeError> {
        let busy = self
            .charges
            .total()
            .total_ns()
            .saturating_sub(self.busy.baseline_nanos);
        if busy < self.busy.budget_nanos {
            return Ok(());
        }
        let now = self.current_monotonic()?;
        let violation = LivenessViolation {
            kind: LivenessKind::NoProgress,
            vtime_ns: now,
            budget_ns: self.busy.budget_nanos,
            last_fault_vtime_ns: 0,
        };
        self.liveness.fired = true;
        self.liveness.violation = Some(violation);
        crate::reports::diagnostic!(
            "patina: the guest was charged {busy} ns of CPU time (its calls, polls and \
computation) with no progress in between: no effect but reading the clock, finding nothing to take, \
yielding, sleeping, waiting or waking another thread. If it waits for state another thread \
publishes, nothing ran that publishes it; if it waits for a time further off than this, give it a \
wait the runtime can see (a sleep or a timed wait) instead of a busy-wait; if it computes this long \
with no I/O by design, raise the horizon with --liveness-watchdog."
        );
        Err(self.liveness_stop(violation))
    }

    /// Stop the run for `violation`: the loud line, the facts and the
    /// recording, then the error.
    fn liveness_stop(&mut self, violation: LivenessViolation) -> RuntimeError {
        // The single interface-contract line, loud.
        // Emitted from the runtime so it reaches stderr regardless of the
        // driving surface, exactly like the vacuous-schedule `PATINA WARNING`.
        let marker = violation.marker_line();
        crate::reports::diagnostic!("{marker}");
        // The interposed families abort the process on this error without
        // ever reaching `finish`, so the facts document — which carries this
        // very violation as a `runtime_findings` entry — has to be written
        // here or it is never written at all. So does the recording: the
        // stop is the one finding that most needs its trace.
        self.emit_facts();
        self.flush_recording();
        RuntimeError::Liveness {
            kind: violation.kind,
            detail: marker,
        }
    }

    /// The compute budget's stop ([`Busy`]): loud, with the facts and the
    /// recording written, as a liveness stop is.
    fn compute_budget_stop(&mut self) -> RuntimeError {
        let task = self.charges.running;
        let detail = format!(
            "PATINA_STOP compute_bound task={} compute_ns={} budget_ns={}",
            task.map_or_else(|| "main".to_owned(), |task| task.0.to_string()),
            self.busy.compute_nanos,
            self.busy.compute_budget_nanos,
        );
        crate::reports::diagnostic!("{detail}");
        crate::reports::diagnostic!(
            "patina: the guest computed {} ns of virtual CPU time without calling into the \
runtime (no operation but scheduling points), past the compute budget; raise it with \
--compute-watchdog-ms if the computation is meant to run longer",
            self.busy.compute_nanos
        );
        self.compute_budget_fired = true;
        self.emit_facts();
        self.flush_recording();
        RuntimeError::ComputeBudget { task, detail }
    }

    /// A compute point: an instrumented build's edge hook hands over a
    /// batch of edges (charged as computation through the embedder's
    /// gateway) and asks whether to take a scheduling point. The charged
    /// time moves the clock (expiring the parks it reaches), the
    /// no-progress horizon and the compute budget are checked, and the
    /// answer is yes once the running task has used its slice
    /// ([`COMPUTE_SLICE_NANOS`]) and another task is runnable.
    pub fn compute_point(&mut self) -> Result<bool, RuntimeError> {
        self.show_carry()?;
        self.busy_check()?;
        if self.busy.compute_nanos >= self.busy.compute_budget_nanos {
            return Err(self.compute_budget_stop());
        }
        let total = self.charges.total().total_ns();
        if total.saturating_sub(self.busy.slice_origin_nanos) < COMPUTE_SLICE_NANOS {
            return Ok(false);
        }
        let running = self.charges.running;
        Ok(self
            .scheduler_tasks
            .iter()
            .any(|task| Some(*task) != running && !self.parked_tasks.contains(task)))
    }

    /// Advance the poll streak for one boundary op, on both record and
    /// replay. Pure bookkeeping over the recorded op stream: a progress op
    /// ends the episode; a poll counts, and the one that completes the
    /// streak makes an escalation due, of the class of the guest call that
    /// polled ([`Context::escalate_due`], [`Context::accrue_calls`]); any
    /// other op is neutral.
    fn spin_track(&mut self, operation: &Operation, progress: bool) -> Result<(), RuntimeError> {
        if progress {
            self.spin.end_episode();
            return Ok(());
        }
        if !is_poll(operation) {
            return Ok(());
        }
        self.spin.poll(poll_class(operation));
        Ok(())
    }

    /// The guest asked to yield (`sched_yield`): a poll, of a system call's
    /// class, unless some task made progress or was charged metered
    /// computation since the previous yield, by any task. The yield found
    /// nothing to take, as an empty receive does, so a loop of them is
    /// escalated like a loop of clock reads: time passes for it, a sleeping
    /// peer's deadline arrives, and one that nothing will ever free reaches
    /// the no-progress horizon instead of yielding for good. That holds for
    /// tasks that only yield to each other too. A yield after progress or
    /// computation is no poll: something is moving, and a yield-heavy
    /// library backoff beside a peer doing I/O or computing must not make
    /// time run away from it. Computation moves time and counts toward the
    /// horizon itself, so a spinner that computes between its yields is
    /// still stopped there if nothing ever frees it.
    /// A guest's yield is also a call that reaches the runtime, so it ends
    /// the compute budget's count.
    /// Unrecorded bookkeeping the embedder derives from the guest's own
    /// calls, identical on record and replay. The scheduling points an
    /// embedder takes for its own reasons (at a call's entry, at an
    /// instrumented edge) are not the guest's request and are not polls.
    pub fn yield_poll(&mut self) {
        self.busy.compute_nanos = 0;
        let previous = self.busy.yield_step.replace(self.steps);
        let computed = std::mem::replace(
            &mut self.busy.yield_computed_nanos,
            self.busy.computed_nanos,
        ) != self.busy.computed_nanos;
        if computed || previous.is_some_and(|previous| self.busy.progress_step > previous) {
            return;
        }
        self.spin.poll(ChargeClass::Syscall);
    }

    /// For an embedder that does not charge its calls, where each operation
    /// is a call: charge the escalation the op just completed is due, if
    /// any, once its outcome is settled (and recorded), so the poll observed
    /// the time before it. A no-op for every op that does not complete a
    /// streak, which is why a run that never polls is unchanged by it.
    pub(super) fn escalate_due(&mut self) -> Result<(), RuntimeError> {
        if self.spin.paced {
            return Ok(());
        }
        let Some(class) = self.spin.due.take() else {
            return Ok(());
        };
        self.escalate(self.charges.running, class)?;
        self.show_carry()
    }

    /// Whether the operation just made completed a poll streak, earning an
    /// escalation, which the embedder that charges its calls takes here, at
    /// the gateway of the guest call that made it, and applies at that
    /// call's end ([`Context::escalate_call`]).
    pub fn take_poll_streak(&mut self) -> bool {
        self.spin.paced && self.spin.due.take().is_some()
    }

    /// Apply an escalation [`Context::take_poll_streak`] handed out: charge
    /// it to `task`, the task whose call earned it, as `class`, that call's
    /// class. The embedder calls this at the end of that call (as it
    /// returns, parks, or ends its thread), after all its reads.
    pub fn escalate_call(
        &mut self,
        task: Option<TaskId>,
        class: ChargeClass,
    ) -> Result<(), RuntimeError> {
        self.escalate(task, class)?;
        self.show_carry()
    }

    /// Charge one escalation of `class` to `task`. Its time is carried like
    /// any charge.
    fn escalate(&mut self, task: Option<TaskId>, class: ChargeClass) -> Result<(), RuntimeError> {
        // The horizon first: a streak that has polled it away must become a
        // named stop, not an unbounded stream of escalations.
        self.busy_check()?;
        let mut calls = ChargeCounts::new();
        calls.add(class, self.escalation_calls(class));
        self.spin.on_escalated(calls.charge().total_ns());
        self.charges.charge(task, calls);
        Ok(())
    }

    /// How many more calls of `class` an escalation charges: the episode's
    /// token's worth, and no more than reaches the earliest published
    /// CPU-time timer.
    fn escalation_calls(&self, class: ChargeClass) -> u64 {
        let cost = class.cost();
        let per_call = cost.total_ns().max(1);
        let cpu = self.charges.total();
        let alarms = self.charges.alarms;
        let user = alarms
            .user_ns
            .filter(|deadline| *deadline > cpu.user_ns && cost.user_ns > 0)
            .map(|deadline| (deadline - cpu.user_ns).div_ceil(cost.user_ns));
        let total = alarms
            .total_ns
            .filter(|deadline| *deadline > cpu.total_ns())
            .map(|deadline| (deadline - cpu.total_ns()).div_ceil(per_call));
        [user, total]
            .into_iter()
            .flatten()
            .fold(self.spin.token_nanos().div_ceil(per_call), u64::min)
    }
}

#[cfg(test)]
mod tests;
