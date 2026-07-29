//! Runtime registry, deterministic drivers, and trace execution modes.

use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};

use patina_dst_abi::{
    ClockKind, Datagram, EffectError, ErrorCode, Fd, FsDirectoryEntry, FsMetadata, OpenFlags,
    Operation, Outcome, SeekWhence, SendReport, ShutdownHow, SocketId, TaskId, TcpAccepted,
};
use patina_dst_driver_api::{ClockDriver, EntropyDriver, FsDriver, NetDriver, SchedulerDriver};
use patina_dst_fs_crash::CrashFs;
pub use patina_dst_fs_crash::TornGranularity;
use patina_dst_fs_mem::MemFs;
use patina_dst_net_sim::SimNet;
use patina_dst_rng_seeded::{SeededEntropy, SplitMix64};
use patina_dst_sched_det::{DetScheduler, PctConfig, SchedulePolicy, StarvationConfig};
use patina_dst_time_virtual::VirtualClock;
pub use patina_dst_trace::MAX_TRACE_BYTES;
use patina_dst_trace::{BranchSession, Recorder, Replayer, RunMetadata, TraceBundle, TraceError};

pub const ENV_MODE: &str = "PATINA_MODE";
pub const ENV_SEED: &str = "PATINA_SEED";
pub const ENV_TRACE: &str = "PATINA_TRACE";
pub const ENV_TRACE_FD: &str = "PATINA_TRACE_FD";
/// Inherited host descriptor carrying an encoded `patina_dst_fs_mem::FsImage`. When
/// set, `native-run` streams a read-only host directory tree into the guest and
/// the shim rebuilds it as the deterministic filesystem instead of an empty one,
/// so a fully interposed guest sees a fixed corpus without touching the host.
/// The image's hash is folded into the run fingerprint, so replay rejects a
/// different corpus. Off when unset.
pub const ENV_FS_IMAGE_FD: &str = "PATINA_FS_IMAGE_FD";
pub const ENV_FINGERPRINT: &str = "PATINA_FINGERPRINT";
/// Deferred-initialization flag for the shim-backed harness (see
/// `patina-dst-harness`, HARNESS-DESIGN.md startup Option B). When present (`=1`)
/// alongside `PATINA_MODE`, the packaged native constructor captures and scrubs
/// the control plane and registers finalization but does NOT install the runtime;
/// `patina_dst_harness::run`/`run_with` installs it explicitly, after applying
/// the harness's configuration overlay. An interposed effect that reaches the
/// boundary before the harness installs fails closed loudly (never auto-inits).
/// Set by `cargo patina run --harness` (and the matching `replay`). Off when
/// unset (the ordinary constructor-installs-at-startup path).
pub const ENV_DEFER_INIT: &str = "PATINA_DEFER_INIT";
pub const ENV_BRANCH_FROM: &str = "PATINA_BRANCH_FROM";
pub const ENV_BRANCH_SEED: &str = "PATINA_BRANCH_SEED";
pub const ENV_BRANCH_ID: &str = "PATINA_BRANCH_ID";
pub const ENV_PARENT_TIMELINE: &str = "PATINA_PARENT_TIMELINE";
pub const ENV_TIMELINE: &str = "PATINA_TIMELINE";
pub const ENV_STEP_BUDGET: &str = "PATINA_STEP_BUDGET";
pub const ENV_PARAMS_JSON: &str = "PATINA_PARAMS_JSON";
/// The guest program arguments (`argv[1..]`, i.e. everything after `--`) as a
/// JSON string array. The supervisor forwards this in record mode so the run's
/// arguments are captured into the trace metadata; the runtime records them and
/// a later `replay` restores them without re-passing the `--` section. Absent
/// leaves the recorded argv unset. Malformed JSON is rejected fail-closed.
pub const ENV_GUEST_ARGV: &str = "PATINA_GUEST_ARGV";
/// Base link latency in nanoseconds applied to the default `SimNet` datagram
/// network. Blocking receives under a non-zero value park on the virtual-clock
/// timer queue until delivery. Invalid values are rejected fail-closed.
pub const ENV_NET_LATENCY: &str = "PATINA_NET_LATENCY_NANOS";
/// Seeded per-datagram delivery jitter range `MIN..MAX` in nanoseconds applied
/// to the default `SimNet`. Varying jitter reorders datagrams relative to their
/// send order — the UDP-reorder fault. Off when unset.
pub const ENV_NET_JITTER: &str = "PATINA_NET_JITTER_NANOS";
/// Seeded datagram drop probability in per-mille (0..=1000) applied to the
/// default `SimNet`. Off (zero) when unset.
pub const ENV_NET_DROP_PERMILLE: &str = "PATINA_NET_DROP_PERMILLE";
/// Seeded extra latency `MIN..MAX` in nanoseconds added to every guest sleep,
/// inflating virtual elapsed time to trip wall-clock deadline assumptions. Off
/// when unset.
pub const ENV_SLEEP_JITTER: &str = "PATINA_SLEEP_JITTER_NANOS";
/// Filesystem crash-injection point, e.g. `close:1`, `write:3`, `sync:2`,
/// `open:1`. When set the default filesystem becomes a `CrashFs` and the runtime
/// injects a crash immediately after the selected boundary operation, dropping
/// unsynced data. Off when unset.
pub const ENV_FS_CRASH_AT: &str = "PATINA_FS_CRASH_AT";
/// Torn-write granularity for an injected crash: `block` (default, whole-block
/// revert) or `byte` (the final unsynced write may survive partially at
/// sub-block byte granularity, modeling a torn in-flight page). Only meaningful
/// alongside [`ENV_FS_CRASH_AT`]. Off (block) when unset.
pub const ENV_FS_TORN_GRANULARITY: &str = "PATINA_FS_TORN_GRANULARITY";
/// Suppress the default-on end-of-run schedule diagnostic when set to a false-y
/// value (`0`, `off`, `false`, `no`). The diagnostic is on by default.
pub const ENV_SCHEDULE_REPORT: &str = "PATINA_SCHEDULE_REPORT";
/// Enable cooperative-SUT (buggify) fault injection. Its value is the
/// per-evaluation firing probability in per-mille for an active site (0..=1000);
/// an empty value uses the FoundationDB default of 25% (250). Presence of the
/// variable enables buggify; absence disables it (zero behavior change).
pub const ENV_BUGGIFY: &str = "PATINA_BUGGIFY";
/// Per-run site activation probability in per-mille (0..=1000): the fraction of
/// buggify sites made active for the run. Default 25% (250). Inert without
/// [`ENV_BUGGIFY`].
pub const ENV_BUGGIFY_ACTIVATION: &str = "PATINA_BUGGIFY_ACTIVATION_PERMILLE";
/// Virtual-time monotonic-nanoseconds cutoff after which buggify stops firing
/// (the FoundationDB damage-control window). Default 300 virtual seconds. Inert
/// without [`ENV_BUGGIFY`].
pub const ENV_BUGGIFY_CUTOFF: &str = "PATINA_BUGGIFY_CUTOFF_NANOS";
/// Declare that the guest calls `patina_dst::lifecycle::setup_complete()`, gating
/// buggify off until that call. A false-y value (or absence) leaves it off.
/// Inert without [`ENV_BUGGIFY`]. When set and the guest never calls
/// `setup_complete()`, the run fails loudly at finalization.
pub const ENV_BUGGIFY_AFTER_SETUP: &str = "PATINA_BUGGIFY_AFTER_SETUP";
/// Suppress the default-on end-of-run cooperative-SUT diagnostic when set to a
/// false-y value (`0`, `off`, `false`, `no`). On by default when buggify is
/// enabled.
pub const ENV_SDK_REPORT: &str = "PATINA_SDK_REPORT";
/// Enable the PCT (Probabilistic Concurrency Testing) exploration scheduling
/// policy. Its value is the target bug depth `d` (>= 1); an empty value uses the
/// default depth. Presence enables PCT; absence leaves the default uniform
/// policy (zero behavior change). Folds a `+pct` fingerprint component.
pub const ENV_SCHED_PCT: &str = "PATINA_SCHED_PCT";
/// Expected schedule length over which PCT distributes its `d-1` priority-change
/// points. Default [`DEFAULT_PCT_STEPS`]. Inert without [`ENV_SCHED_PCT`].
pub const ENV_SCHED_PCT_STEPS: &str = "PATINA_SCHED_PCT_STEPS";
/// Enable the starvation-interval exploration scheduling policy. Its value is the
/// number of bounded intervals to place (>= 1); an empty value uses the default
/// count. Presence enables starvation; absence leaves it off. Folds a `+starve`
/// fingerprint component.
pub const ENV_SCHED_STARVE: &str = "PATINA_SCHED_STARVE";
/// Maximum length (scheduling decisions) of any starvation interval — the bound
/// that keeps starvation liveness-safe. Default [`DEFAULT_STARVE_MAX_LEN`]. Inert
/// without [`ENV_SCHED_STARVE`].
pub const ENV_SCHED_STARVE_MAX_LEN: &str = "PATINA_SCHED_STARVE_MAX_LEN";
/// Window `[1, N]` over which starvation interval starts are placed. Default
/// [`DEFAULT_STARVE_WINDOW`]. Inert without [`ENV_SCHED_STARVE`].
pub const ENV_SCHED_STARVE_WINDOW: &str = "PATINA_SCHED_STARVE_WINDOW";
/// Enable swarm fault-class selection: a seed-derived subset of the enabled fault
/// classes is applied this generation instead of all of them. A false-y value
/// (or absence) keeps the existing always-all behavior. Folds a `+swarm`
/// fingerprint component.
pub const ENV_SWARM: &str = "PATINA_SWARM";
/// Suppress the default-on end-of-run exploration-policy diagnostic
/// (`PATINA_SCHEDULE_POLICY`) when set to a false-y value. On by default when a
/// policy is active.
pub const ENV_SCHEDULE_POLICY_REPORT: &str = "PATINA_SCHEDULE_POLICY_REPORT";

/// Enable the generic liveness watchdog with a virtual-time no-progress budget in
/// nanoseconds (armed from run start). A bare/empty value uses
/// [`DEFAULT_LIVENESS_BUDGET_NANOS`].
pub const ENV_LIVENESS_WATCHDOG: &str = "PATINA_LIVENESS_WATCHDOG_NANOS";
/// Enable the heal-then-converge watchdog with a virtual-time convergence budget
/// in nanoseconds, armed at the fault-window end. A bare/empty value uses
/// [`DEFAULT_CONVERGE_BUDGET_NANOS`].
pub const ENV_CONVERGE_WITHIN: &str = "PATINA_CONVERGE_WITHIN_NANOS";
/// Explicit override for the heal-then-converge arm-time (virtual nanoseconds).
/// When unset and converge is enabled, the runtime derives it from the buggify
/// damage-control cutoff (if buggify is enabled) else 0.
pub const ENV_HEAL_AFTER: &str = "PATINA_HEAL_AFTER_NANOS";
/// Suppress the default-on end-of-run liveness-watchdog diagnostic
/// (`PATINA_LIVENESS_REPORT`) when set to a false-y value.
pub const ENV_LIVENESS_REPORT: &str = "PATINA_LIVENESS_REPORT";

// Return codes for the shim's `patina_harness_install` C ABI, shared by the
// native shim (which returns them) and `patina-dst-harness` (which maps them to
// its `HarnessError` variants). Distinct, stable sentinels so the harness can
// discriminate the fail-closed reasons without parsing stderr; the shim also
// prints a loud diagnostic for each nonzero case.
/// Harness install succeeded: the runtime is installed with the overlay applied.
pub const HARNESS_OK: i32 = 0;
/// No `PATINA_MODE` in the control plane: the harness binary was not run under
/// `cargo patina run --harness` (plain execution or missing supervisor protocol).
pub const HARNESS_ERR_NOT_UNDER_PATINA: i32 = -1;
/// The runtime is already installed (a non-deferred startup, or a second
/// `run`/`run_with`): the harness cannot install a second context.
pub const HARNESS_ERR_ALREADY_INSTALLED: i32 = -2;
/// A deterministic boundary effect was already observed before the harness
/// installed: reconfiguring after events would make replay semantics ambiguous.
pub const HARNESS_ERR_BOUNDARY_BEFORE_INSTALL: i32 = -3;
/// The runtime configuration built from the (overlaid) control plane failed to
/// validate/build (bad knob value, fingerprint/replay reconciliation conflict).
pub const HARNESS_ERR_CONFIG: i32 = -4;

/// Default generic no-progress budget: 600 virtual seconds. Generous by design —
/// the budget must exceed the longest legitimate quiescent (single-sleep) period,
/// so a real workload's ordinary waiting never trips it.
pub const DEFAULT_LIVENESS_BUDGET_NANOS: u64 = 600_000_000_000;
/// Default heal-then-converge budget: 300 virtual seconds after the fault window.
pub const DEFAULT_CONVERGE_BUDGET_NANOS: u64 = 300_000_000_000;
/// Minimum number of consecutive non-progress operations a no-progress window must
/// contain before the watchdog may fire, so a single long-but-legitimate sleep
/// (one non-progress op) can never trip it — only genuine churn (a timer/park spin
/// issuing many scheduling ops) does.
const LIVENESS_MIN_STALL_OPS: u64 = 4;

/// Default PCT target bug depth when `--sched-pct` is given without a value.
pub const DEFAULT_PCT_DEPTH: u32 = 3;
/// Default PCT expected schedule length.
pub const DEFAULT_PCT_STEPS: u64 = 2_000;
/// Default number of starvation intervals when `--starve` is given bare.
pub const DEFAULT_STARVE_INTERVALS: u32 = 3;
/// Default maximum starvation interval length (bounded → liveness-safe).
pub const DEFAULT_STARVE_MAX_LEN: u64 = 32;
/// Default starvation interval start window.
pub const DEFAULT_STARVE_WINDOW: u64 = 512;

const DEFAULT_FINGERPRINT: &str = "direct-seeded-run-v1";

/// FoundationDB's default per-evaluation buggify firing probability, in per-mille.
pub const DEFAULT_BUGGIFY_FIRE_PERMILLE: u16 = 250;
/// FoundationDB's default per-run buggify site activation probability, in per-mille.
pub const DEFAULT_BUGGIFY_ACTIVATION_PERMILLE: u16 = 250;
/// Default buggify damage-control cutoff: 300 virtual seconds, in nanoseconds.
pub const DEFAULT_BUGGIFY_CUTOFF_NANOS: u64 = 300_000_000_000;
const READ_CHUNK_SIZE: usize = 4096;
const MAX_READ_FILE_BYTES: usize = 64 * 1024 * 1024;

/// Byte-level trace channel supplied by an embedder when the runtime must not
/// open trace files itself (for example inside a fully interposed native
/// process whose ambient file symbols route back into Patina).
pub trait TraceTransport: Send {
    /// Read the complete serialized trace bundle for replay.
    fn read_bundle(&mut self) -> std::io::Result<Vec<u8>>;
    /// Deliver the complete serialized trace bundle at record finalization.
    fn write_bundle(&mut self, bytes: &[u8]) -> std::io::Result<()>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecutionMode {
    Seeded,
    Record {
        path: PathBuf,
    },
    /// Record through an installed [`TraceTransport`] instead of a path.
    RecordTransport,
    Replay {
        path: PathBuf,
        timeline: String,
    },
    /// Replay through an installed [`TraceTransport`] instead of a path.
    ReplayTransport {
        timeline: String,
    },
    Branch {
        path: PathBuf,
        parent: String,
        from_sequence: u64,
        branch_id: String,
        branch_seed: u64,
    },
}

/// A boundary operation kind that a filesystem crash can be pinned to. The
/// runtime crashes immediately after the Nth matching operation completes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrashOp {
    Open,
    Write,
    Sync,
    Close,
}

/// Where a filesystem crash is injected: after the `ordinal`-th (1-based)
/// occurrence of `op`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CrashPoint {
    pub op: CrashOp,
    pub ordinal: u64,
}

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
    fn as_str(self) -> &'static str {
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

/// Seed-driven, default-off fault knobs layered onto the deterministic drivers.
/// Every field is inert at its default so a run that configures no fault behaves
/// exactly as before.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FaultConfig {
    /// Inject a filesystem crash after a chosen boundary operation.
    crash_at: Option<CrashPoint>,
    /// Granularity at which the injected crash tears the final unsynced write.
    /// Inert without `crash_at`; defaults to whole-block.
    torn_granularity: TornGranularity,
    /// Inclusive `[min, max]` nanoseconds of seeded extra latency per guest sleep.
    sleep_jitter_nanos: Option<(u64, u64)>,
    /// Inclusive `[min, max]` nanoseconds of seeded per-datagram delivery jitter.
    net_jitter_nanos: Option<(u64, u64)>,
    /// Seeded datagram drop probability in per-mille (0..=1000).
    net_drop_permille: u16,
}

/// Seed-driven cooperative-SUT (buggify) configuration. Inert (`enabled =
/// false`) by default, so a run that does not opt in behaves exactly as before.
/// When enabled, activation and firing are pure deterministic functions of the
/// root seed, the site label, and these knobs; the internal `Buggify` state uses
/// this configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BuggifyConfig {
    /// Whether buggify is active this run.
    pub enabled: bool,
    /// Per-evaluation firing probability (per-mille) for an active site.
    pub fire_permille: u16,
    /// Per-run site activation probability (per-mille).
    pub activation_permille: u16,
    /// Virtual monotonic-time cutoff (nanoseconds) after which firing stops.
    pub cutoff_nanos: u64,
    /// When set, the runner has declared that the guest calls
    /// `patina_dst::lifecycle::setup_complete()`, so buggify stays inert until that
    /// call (a causal gate — intent comes from the flag, not from predicting the
    /// guest). If the guest never calls it, the run fails loudly at finalization.
    pub after_setup: bool,
}

impl Default for BuggifyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            fire_permille: DEFAULT_BUGGIFY_FIRE_PERMILLE,
            activation_permille: DEFAULT_BUGGIFY_ACTIVATION_PERMILLE,
            cutoff_nanos: DEFAULT_BUGGIFY_CUTOFF_NANOS,
            after_setup: false,
        }
    }
}

/// Liveness-watchdog configuration: a deterministic, virtual-time-only no-progress
/// detector. Default (all `None`) is disabled, so a run that does not opt in is
/// byte-for-byte unchanged. The internal liveness watchdog owns the detection
/// semantics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LivenessConfig {
    /// Generic no-progress budget (virtual nanoseconds), armed from run start.
    /// `Some(0)` is rejected at parse time. `None` disables the generic arm.
    pub no_progress_budget_nanos: Option<u64>,
    /// Heal-then-converge budget (virtual nanoseconds), armed at the fault-window
    /// end (the buggify cutoff when buggify is enabled, else 0, unless
    /// [`heal_after_nanos`](Self::heal_after_nanos) overrides). `None` disables it.
    pub converge_budget_nanos: Option<u64>,
    /// Explicit override for the converge arm's arm-time (virtual nanoseconds).
    /// `None` derives it from the buggify cutoff / run start.
    pub heal_after_nanos: Option<u64>,
}

impl LivenessConfig {
    /// Whether any watchdog arm is configured.
    pub fn is_enabled(&self) -> bool {
        self.no_progress_budget_nanos.is_some() || self.converge_budget_nanos.is_some()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeConfig {
    seed: u64,
    mode: ExecutionMode,
    fingerprint: String,
    step_budget: Option<u64>,
    params: BTreeMap<String, String>,
    net_latency_nanos: u64,
    faults: FaultConfig,
    buggify: BuggifyConfig,
    /// The exploration scheduling policy (PCT / starvation). Default is the
    /// uniform-random policy, byte-for-byte the historical scheduler.
    schedule_policy: SchedulePolicy,
    /// Whether swarm fault-class selection is enabled: a seed-derived subset of
    /// the enabled fault classes is applied this run instead of all of them.
    swarm: bool,
    /// The guest program arguments (`argv[1..]`) recorded into the trace so a
    /// `replay` restores them flag-free. `None` records nothing (unset); `Some`
    /// (possibly empty) records the exact list. Not a fingerprint input.
    guest_argv: Option<Vec<String>>,
    /// The liveness-watchdog configuration. Default (disabled) leaves a run
    /// byte-for-byte unchanged; enabling it only ADDS a possible violation report
    /// and is deliberately NOT a fingerprint input (schedule-invariant).
    liveness: LivenessConfig,
}

impl RuntimeConfig {
    pub fn seeded(seed: u64) -> Self {
        Self {
            seed,
            mode: ExecutionMode::Seeded,
            fingerprint: DEFAULT_FINGERPRINT.into(),
            step_budget: None,
            params: BTreeMap::new(),
            net_latency_nanos: 0,
            faults: FaultConfig::default(),
            buggify: BuggifyConfig::default(),
            schedule_policy: SchedulePolicy::default(),
            swarm: false,
            guest_argv: None,
            liveness: LivenessConfig::default(),
        }
    }

    pub fn record(seed: u64, path: impl Into<PathBuf>, fingerprint: impl Into<String>) -> Self {
        Self {
            seed,
            mode: ExecutionMode::Record { path: path.into() },
            fingerprint: fingerprint.into(),
            step_budget: None,
            params: BTreeMap::new(),
            net_latency_nanos: 0,
            faults: FaultConfig::default(),
            buggify: BuggifyConfig::default(),
            schedule_policy: SchedulePolicy::default(),
            swarm: false,
            guest_argv: None,
            liveness: LivenessConfig::default(),
        }
    }

    pub fn replay(path: impl Into<PathBuf>, fingerprint: impl Into<String>) -> Self {
        Self::replay_timeline(path, "main", fingerprint)
    }

    /// Record through a [`TraceTransport`] installed on the builder.
    pub fn record_transport(seed: u64, fingerprint: impl Into<String>) -> Self {
        Self {
            seed,
            mode: ExecutionMode::RecordTransport,
            fingerprint: fingerprint.into(),
            step_budget: None,
            params: BTreeMap::new(),
            net_latency_nanos: 0,
            faults: FaultConfig::default(),
            buggify: BuggifyConfig::default(),
            schedule_policy: SchedulePolicy::default(),
            swarm: false,
            guest_argv: None,
            liveness: LivenessConfig::default(),
        }
    }

    /// Replay a timeline through a [`TraceTransport`] installed on the builder.
    pub fn replay_transport_timeline(
        timeline: impl Into<String>,
        fingerprint: impl Into<String>,
    ) -> Self {
        Self {
            seed: 0,
            mode: ExecutionMode::ReplayTransport {
                timeline: timeline.into(),
            },
            fingerprint: fingerprint.into(),
            step_budget: None,
            params: BTreeMap::new(),
            net_latency_nanos: 0,
            faults: FaultConfig::default(),
            buggify: BuggifyConfig::default(),
            schedule_policy: SchedulePolicy::default(),
            swarm: false,
            guest_argv: None,
            liveness: LivenessConfig::default(),
        }
    }

    pub fn replay_timeline(
        path: impl Into<PathBuf>,
        timeline: impl Into<String>,
        fingerprint: impl Into<String>,
    ) -> Self {
        Self {
            seed: 0,
            mode: ExecutionMode::Replay {
                path: path.into(),
                timeline: timeline.into(),
            },
            fingerprint: fingerprint.into(),
            step_budget: None,
            params: BTreeMap::new(),
            net_latency_nanos: 0,
            faults: FaultConfig::default(),
            buggify: BuggifyConfig::default(),
            schedule_policy: SchedulePolicy::default(),
            swarm: false,
            guest_argv: None,
            liveness: LivenessConfig::default(),
        }
    }

    pub fn branch(
        path: impl Into<PathBuf>,
        parent: impl Into<String>,
        from_sequence: u64,
        branch_id: impl Into<String>,
        branch_seed: u64,
        fingerprint: impl Into<String>,
    ) -> Self {
        Self {
            seed: branch_seed,
            mode: ExecutionMode::Branch {
                path: path.into(),
                parent: parent.into(),
                from_sequence,
                branch_id: branch_id.into(),
                branch_seed,
            },
            fingerprint: fingerprint.into(),
            step_budget: None,
            params: BTreeMap::new(),
            net_latency_nanos: 0,
            faults: FaultConfig::default(),
            buggify: BuggifyConfig::default(),
            schedule_policy: SchedulePolicy::default(),
            swarm: false,
            guest_argv: None,
            liveness: LivenessConfig::default(),
        }
    }

    pub fn with_step_budget(mut self, budget: u64) -> Self {
        self.step_budget = Some(budget);
        self
    }

    /// Set the base link latency applied to the default `SimNet` network.
    pub fn with_net_latency_nanos(mut self, nanos: u64) -> Self {
        self.net_latency_nanos = nanos;
        self
    }

    pub const fn net_latency_nanos(&self) -> u64 {
        self.net_latency_nanos
    }

    /// Inject a filesystem crash after the `ordinal`-th (1-based) `op` boundary.
    pub fn with_crash_at(mut self, op: CrashOp, ordinal: u64) -> Self {
        self.faults.crash_at = Some(CrashPoint { op, ordinal });
        self
    }

    /// Select whole-block or sub-block byte-granularity tearing for an injected
    /// crash. Inert without [`RuntimeConfig::with_crash_at`].
    pub fn with_fs_torn_granularity(mut self, granularity: TornGranularity) -> Self {
        self.faults.torn_granularity = granularity;
        self
    }

    /// Add seeded extra latency to every guest sleep, drawn from `[min, max]`.
    pub fn with_sleep_jitter_nanos(mut self, min: u64, max: u64) -> Self {
        self.faults.sleep_jitter_nanos = Some((min, max));
        self
    }

    /// Add seeded per-datagram delivery jitter drawn from `[min, max]`.
    pub fn with_net_jitter_nanos(mut self, min: u64, max: u64) -> Self {
        self.faults.net_jitter_nanos = Some((min, max));
        self
    }

    /// Drop datagrams with the given per-mille (0..=1000) probability.
    pub fn with_net_drop_permille(mut self, permille: u16) -> Self {
        self.faults.net_drop_permille = permille;
        self
    }

    pub const fn crash_at(&self) -> Option<CrashPoint> {
        self.faults.crash_at
    }

    /// The configured torn-write granularity for `--fs-crash-at`. `Block`
    /// (whole-block revert) unless `--fs-torn-granularity byte` selected the
    /// sub-block model.
    pub const fn torn_granularity(&self) -> TornGranularity {
        self.faults.torn_granularity
    }

    /// Apply the fault-injection knobs from a control-plane accessor. Shared by
    /// [`RuntimeConfig::from_env`] (reading the process environment) and the
    /// native shim (reading its scrubbed constructor-time control plane), so both
    /// entry points parse the fault protocol identically and fail closed on any
    /// malformed value. Each knob defaults off when its variable is absent.
    pub fn apply_fault_env<F>(mut self, get: F) -> Result<Self, RuntimeError>
    where
        F: Fn(&str) -> Option<String>,
    {
        if let Some(value) = get(ENV_FS_CRASH_AT) {
            self.faults.crash_at = Some(parse_crash_point(&value)?);
        }
        if let Some(value) = get(ENV_FS_TORN_GRANULARITY) {
            self.faults.torn_granularity = parse_torn_granularity(&value)?;
        }
        if let Some(value) = get(ENV_SLEEP_JITTER) {
            self.faults.sleep_jitter_nanos = Some(parse_nanos_range(ENV_SLEEP_JITTER, &value)?);
        }
        if let Some(value) = get(ENV_NET_JITTER) {
            self.faults.net_jitter_nanos = Some(parse_nanos_range(ENV_NET_JITTER, &value)?);
        }
        if let Some(value) = get(ENV_NET_DROP_PERMILLE) {
            let permille: u16 = value.parse().map_err(|_| {
                RuntimeError::Config(format!(
                    "{ENV_NET_DROP_PERMILLE} must be an integer in [0, 1000]"
                ))
            })?;
            if permille > 1000 {
                return Err(RuntimeError::Config(format!(
                    "{ENV_NET_DROP_PERMILLE} must be within [0, 1000] per-mille"
                )));
            }
            self.faults.net_drop_permille = permille;
        }
        Ok(self)
    }

    /// The run's cooperative-SUT (buggify) configuration.
    pub const fn buggify(&self) -> BuggifyConfig {
        self.buggify
    }

    /// Set the run's cooperative-SUT (buggify) configuration directly (used by
    /// tests and explicit-API embedders).
    #[must_use]
    pub fn with_buggify(mut self, buggify: BuggifyConfig) -> Self {
        self.buggify = buggify;
        self
    }

    /// Apply the cooperative-SUT (buggify) knobs from a control-plane accessor,
    /// mirroring [`RuntimeConfig::apply_fault_env`]. Presence of [`ENV_BUGGIFY`]
    /// enables buggify; its value (if non-empty) is the per-evaluation firing
    /// per-mille. Activation and cutoff come from their own variables, defaulting
    /// to the FoundationDB defaults. Absence leaves buggify disabled (zero
    /// behavior change).
    pub fn apply_buggify_env<F>(mut self, get: F) -> Result<Self, RuntimeError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let Some(fire) = get(ENV_BUGGIFY) else {
            return Ok(self);
        };
        self.buggify.enabled = true;
        let fire = fire.trim();
        if !fire.is_empty() {
            self.buggify.fire_permille = parse_permille(ENV_BUGGIFY, fire)?;
        }
        if let Some(value) = get(ENV_BUGGIFY_ACTIVATION) {
            self.buggify.activation_permille =
                parse_permille(ENV_BUGGIFY_ACTIVATION, value.trim())?;
        }
        if let Some(value) = get(ENV_BUGGIFY_CUTOFF) {
            self.buggify.cutoff_nanos = value.trim().parse().map_err(|_| {
                RuntimeError::Config(format!(
                    "{ENV_BUGGIFY_CUTOFF} must be an unsigned 64-bit integer"
                ))
            })?;
        }
        if let Some(value) = get(ENV_BUGGIFY_AFTER_SETUP) {
            self.buggify.after_setup = !matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "" | "0" | "off" | "false" | "no"
            );
        }
        Ok(self)
    }

    /// The recorded guest program arguments (`argv[1..]`), or `None` when unset.
    pub fn guest_argv(&self) -> Option<&[String]> {
        self.guest_argv.as_deref()
    }

    /// Set the guest program arguments recorded into the trace directly (used by
    /// tests and explicit-API embedders).
    #[must_use]
    pub fn with_guest_argv(mut self, guest_argv: Option<Vec<String>>) -> Self {
        self.guest_argv = guest_argv;
        self
    }

    /// Apply the guest program arguments from a control-plane accessor, mirroring
    /// [`RuntimeConfig::apply_fault_env`]. Presence of [`ENV_GUEST_ARGV`] sets the
    /// recorded argv from its JSON string-array value; absence leaves it unset
    /// (zero behavior change). Malformed JSON is rejected fail-closed. Shared by
    /// [`RuntimeConfig::from_env`] and the native shim so both entry points parse
    /// the argv protocol identically.
    pub fn apply_guest_argv_env<F>(mut self, get: F) -> Result<Self, RuntimeError>
    where
        F: Fn(&str) -> Option<String>,
    {
        if let Some(value) = get(ENV_GUEST_ARGV) {
            let argv: Vec<String> = serde_json::from_str(&value).map_err(|error| {
                RuntimeError::Config(format!("{ENV_GUEST_ARGV} is invalid: {error}"))
            })?;
            self.guest_argv = Some(argv);
        }
        Ok(self)
    }

    /// The run's exploration scheduling policy.
    pub const fn schedule_policy(&self) -> SchedulePolicy {
        self.schedule_policy
    }

    /// Set the exploration scheduling policy directly (tests, explicit embedders).
    #[must_use]
    pub fn with_schedule_policy(mut self, policy: SchedulePolicy) -> Self {
        self.schedule_policy = policy;
        self
    }

    /// Whether swarm fault-class selection is enabled for this run.
    pub const fn swarm(&self) -> bool {
        self.swarm
    }

    /// Enable or disable swarm fault-class selection directly.
    #[must_use]
    pub fn with_swarm(mut self, swarm: bool) -> Self {
        self.swarm = swarm;
        self
    }

    /// Apply the exploration scheduling-policy knobs from a control-plane
    /// accessor, mirroring [`RuntimeConfig::apply_fault_env`]. Presence of
    /// [`ENV_SCHED_PCT`] enables PCT (its value is the bug depth `d`, empty =
    /// default); presence of [`ENV_SCHED_STARVE`] enables starvation intervals
    /// (its value is the interval count). Absence leaves the default uniform
    /// policy (zero behavior change). Malformed values are rejected fail-closed.
    pub fn apply_schedule_env<F>(mut self, get: F) -> Result<Self, RuntimeError>
    where
        F: Fn(&str) -> Option<String>,
    {
        if let Some(value) = get(ENV_SCHED_PCT) {
            let value = value.trim();
            let depth = if value.is_empty() {
                DEFAULT_PCT_DEPTH
            } else {
                let depth: u32 = value.parse().map_err(|_| {
                    RuntimeError::Config(format!(
                        "{ENV_SCHED_PCT} must be an unsigned integer >= 1"
                    ))
                })?;
                if depth < 1 {
                    return Err(RuntimeError::Config(format!(
                        "{ENV_SCHED_PCT} bug depth must be >= 1"
                    )));
                }
                depth
            };
            let steps = match get(ENV_SCHED_PCT_STEPS) {
                Some(value) => value.trim().parse().map_err(|_| {
                    RuntimeError::Config(format!(
                        "{ENV_SCHED_PCT_STEPS} must be an unsigned 64-bit integer"
                    ))
                })?,
                None => DEFAULT_PCT_STEPS,
            };
            if steps < 1 {
                return Err(RuntimeError::Config(format!(
                    "{ENV_SCHED_PCT_STEPS} must be >= 1"
                )));
            }
            self.schedule_policy.pct = Some(PctConfig { depth, steps });
        }
        if let Some(value) = get(ENV_SCHED_STARVE) {
            let value = value.trim();
            let intervals = if value.is_empty() {
                DEFAULT_STARVE_INTERVALS
            } else {
                value.parse().map_err(|_| {
                    RuntimeError::Config(format!(
                        "{ENV_SCHED_STARVE} must be an unsigned integer >= 1"
                    ))
                })?
            };
            if intervals < 1 {
                return Err(RuntimeError::Config(format!(
                    "{ENV_SCHED_STARVE} interval count must be >= 1"
                )));
            }
            let max_len = match get(ENV_SCHED_STARVE_MAX_LEN) {
                Some(value) => value.trim().parse().map_err(|_| {
                    RuntimeError::Config(format!(
                        "{ENV_SCHED_STARVE_MAX_LEN} must be an unsigned 64-bit integer"
                    ))
                })?,
                None => DEFAULT_STARVE_MAX_LEN,
            };
            let window = match get(ENV_SCHED_STARVE_WINDOW) {
                Some(value) => value.trim().parse().map_err(|_| {
                    RuntimeError::Config(format!(
                        "{ENV_SCHED_STARVE_WINDOW} must be an unsigned 64-bit integer"
                    ))
                })?,
                None => DEFAULT_STARVE_WINDOW,
            };
            if max_len < 1 || window < 1 {
                return Err(RuntimeError::Config(format!(
                    "{ENV_SCHED_STARVE_MAX_LEN} and {ENV_SCHED_STARVE_WINDOW} must be >= 1 so \
                     intervals are bounded and placeable"
                )));
            }
            self.schedule_policy.starvation = Some(StarvationConfig {
                intervals,
                max_len,
                window,
            });
        }
        Ok(self)
    }

    /// Apply the swarm fault-class-selection knob from a control-plane accessor.
    /// Presence of a truthy [`ENV_SWARM`] enables swarm; a false-y value (or
    /// absence) leaves it off (the existing always-all behavior).
    pub fn apply_swarm_env<F>(mut self, get: F) -> Result<Self, RuntimeError>
    where
        F: Fn(&str) -> Option<String>,
    {
        if let Some(value) = get(ENV_SWARM) {
            self.swarm = !matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "" | "0" | "off" | "false" | "no"
            );
        }
        Ok(self)
    }

    /// Install the liveness-watchdog configuration.
    #[must_use]
    pub fn with_liveness(mut self, liveness: LivenessConfig) -> Self {
        self.liveness = liveness;
        self
    }

    /// The configured liveness-watchdog knobs.
    pub const fn liveness(&self) -> LivenessConfig {
        self.liveness
    }

    /// Apply the liveness-watchdog knobs from a control-plane accessor. A present
    /// [`ENV_LIVENESS_WATCHDOG`] enables the generic no-progress arm (its value, if
    /// non-empty, being the budget in nanoseconds); [`ENV_CONVERGE_WITHIN`] enables
    /// the heal-then-converge arm; [`ENV_HEAL_AFTER`] overrides its arm-time. A
    /// zero budget is rejected so the watchdog cannot be armed to fire vacuously.
    pub fn apply_liveness_env<F>(mut self, get: F) -> Result<Self, RuntimeError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let parse_budget = |name: &str, value: String, default: u64| -> Result<u64, RuntimeError> {
            let value = value.trim();
            if value.is_empty() {
                return Ok(default);
            }
            let nanos: u64 = value.parse().map_err(|_| {
                RuntimeError::Config(format!("{name} must be an unsigned 64-bit integer"))
            })?;
            if nanos == 0 {
                return Err(RuntimeError::Config(format!(
                    "{name} budget must be > 0 so the watchdog cannot fire vacuously"
                )));
            }
            Ok(nanos)
        };
        if let Some(value) = get(ENV_LIVENESS_WATCHDOG) {
            self.liveness.no_progress_budget_nanos = Some(parse_budget(
                ENV_LIVENESS_WATCHDOG,
                value,
                DEFAULT_LIVENESS_BUDGET_NANOS,
            )?);
        }
        if let Some(value) = get(ENV_CONVERGE_WITHIN) {
            self.liveness.converge_budget_nanos = Some(parse_budget(
                ENV_CONVERGE_WITHIN,
                value,
                DEFAULT_CONVERGE_BUDGET_NANOS,
            )?);
        }
        if let Some(value) = get(ENV_HEAL_AFTER) {
            let value = value.trim();
            if !value.is_empty() {
                self.liveness.heal_after_nanos = Some(value.parse().map_err(|_| {
                    RuntimeError::Config(format!(
                        "{ENV_HEAL_AFTER} must be an unsigned 64-bit integer"
                    ))
                })?);
            }
        }
        Ok(self)
    }

    pub fn with_param(
        mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, RuntimeError> {
        let key = key.into();
        if key.is_empty() {
            return Err(RuntimeError::Config(
                "runtime parameter key must not be empty".into(),
            ));
        }
        self.params.insert(key, value.into());
        Ok(self)
    }

    pub fn from_env() -> Result<Self, RuntimeError> {
        let mode = env::var(ENV_MODE).unwrap_or_else(|_| "seeded".into());
        let seed = parse_seed(env::var(ENV_SEED).ok())?;
        let trace_fd = trace_fd_from_env()?;
        if trace_fd.is_some() && env::var_os(ENV_TRACE).is_some_and(|value| !value.is_empty()) {
            return Err(RuntimeError::Config(format!(
                "{ENV_TRACE} and {ENV_TRACE_FD} must not both be set"
            )));
        }
        let config = match (mode.as_str(), trace_fd) {
            ("seeded", None) => Self::seeded(seed),
            ("seeded", Some(_)) => {
                return Err(RuntimeError::Config(format!(
                    "{ENV_TRACE_FD} is only meaningful in record or replay mode"
                )));
            }
            ("record", None) => Self::record(
                seed,
                required_path(ENV_TRACE)?,
                required_string(ENV_FINGERPRINT)?,
            ),
            ("record", Some(_)) => Self::record_transport(seed, required_string(ENV_FINGERPRINT)?),
            ("replay", None) => Self::replay_timeline(
                required_path(ENV_TRACE)?,
                env::var(ENV_TIMELINE).unwrap_or_else(|_| "main".into()),
                required_string(ENV_FINGERPRINT)?,
            ),
            ("replay", Some(_)) => Self::replay_transport_timeline(
                env::var(ENV_TIMELINE).unwrap_or_else(|_| "main".into()),
                required_string(ENV_FINGERPRINT)?,
            ),
            ("branch", None) => Self::branch(
                required_path(ENV_TRACE)?,
                env::var(ENV_PARENT_TIMELINE).unwrap_or_else(|_| "main".into()),
                required_u64(ENV_BRANCH_FROM)?,
                required_string(ENV_BRANCH_ID)?,
                required_u64(ENV_BRANCH_SEED)?,
                required_string(ENV_FINGERPRINT)?,
            ),
            ("branch", Some(_)) => {
                return Err(RuntimeError::Config(format!(
                    "branch mode requires a {ENV_TRACE} path; {ENV_TRACE_FD} is unsupported"
                )));
            }
            (value, _) => {
                return Err(RuntimeError::Config(format!(
                    "{ENV_MODE} must be seeded, record, replay, or branch; got {value:?}"
                )));
            }
        };
        let mut config = match env::var(ENV_STEP_BUDGET) {
            Ok(value) => config.with_step_budget(value.parse().map_err(|_| {
                RuntimeError::Config(format!(
                    "{ENV_STEP_BUDGET} must be an unsigned 64-bit integer"
                ))
            })?),
            Err(env::VarError::NotPresent) => config,
            Err(env::VarError::NotUnicode(_)) => {
                return Err(RuntimeError::Config(format!(
                    "{ENV_STEP_BUDGET} must be valid UTF-8"
                )));
            }
        };
        if let Some(value) = env::var_os(ENV_PARAMS_JSON) {
            let value = value.into_string().map_err(|_| {
                RuntimeError::Config(format!("{ENV_PARAMS_JSON} must be valid UTF-8"))
            })?;
            let params: BTreeMap<String, String> =
                serde_json::from_str(&value).map_err(|error| {
                    RuntimeError::Config(format!("{ENV_PARAMS_JSON} is invalid: {error}"))
                })?;
            if params.keys().any(String::is_empty) {
                return Err(RuntimeError::Config(
                    "runtime parameter key must not be empty".into(),
                ));
            }
            config.params = params;
        }
        config.net_latency_nanos = match env::var(ENV_NET_LATENCY) {
            Ok(value) => value.parse().map_err(|_| {
                RuntimeError::Config(format!(
                    "{ENV_NET_LATENCY} must be an unsigned 64-bit integer"
                ))
            })?,
            Err(env::VarError::NotPresent) => 0,
            Err(env::VarError::NotUnicode(_)) => {
                return Err(RuntimeError::Config(format!(
                    "{ENV_NET_LATENCY} must be valid UTF-8"
                )));
            }
        };
        let config = config.apply_fault_env(|name| env::var(name).ok())?;
        let config = config.apply_buggify_env(|name| env::var(name).ok())?;
        let config = config.apply_schedule_env(|name| env::var(name).ok())?;
        let config = config.apply_swarm_env(|name| env::var(name).ok())?;
        let config = config.apply_liveness_env(|name| env::var(name).ok())?;
        let config = config.apply_guest_argv_env(|name| env::var(name).ok())?;
        Ok(config)
    }

    pub const fn seed(&self) -> u64 {
        self.seed
    }

    pub const fn mode(&self) -> &ExecutionMode {
        &self.mode
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

/// Low-level explicit-context entry point: run a closure against a [`Context`]
/// with deterministic default drivers configured from `PATINA_*`.
///
/// This is the mode-3 explicit-context API of `HARNESS-DESIGN.md`. It creates an
/// explicit context and does **not** control unrelated `std::fs`/`std::net`/clock
/// calls in the rest of the program — those are interposed by the native shim or
/// WASI host under `cargo patina build`/`run`. To configure Patina and then drive
/// ordinary application code, use the shim-backed `patina-dst-harness` crate.
///
/// The context is always finalized. If both the closure and finalization fail,
/// the returned error retains both failures.
pub fn run<T>(
    operation: impl FnOnce(&mut Context) -> Result<T, RuntimeError>,
) -> Result<T, RuntimeError> {
    run_with(|builder| builder, operation)
}

/// Like [`run`] but allows typed driver replacement before the context is built.
///
/// The builder starts from [`RuntimeConfig::from_env`] with the default drivers
/// installed; `configure` may swap in alternative drivers (network, filesystem,
/// clock, …) before the context runs.
pub fn run_with<T>(
    configure: impl FnOnce(RuntimeBuilder) -> RuntimeBuilder,
    operation: impl FnOnce(&mut Context) -> Result<T, RuntimeError>,
) -> Result<T, RuntimeError> {
    let builder = RuntimeBuilder::new(RuntimeConfig::from_env()?).with_default_drivers();
    run_with_context(configure(builder).build()?, operation)
}

fn run_with_context<T>(
    mut context: Context,
    operation: impl FnOnce(&mut Context) -> Result<T, RuntimeError>,
) -> Result<T, RuntimeError> {
    let run_result = operation(&mut context);
    let finish_result = context.finish();
    match (run_result, finish_result) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(run), Err(finalize)) => Err(RuntimeError::RunAndFinalize {
            run: Box::new(run),
            finalize: Box::new(finalize),
        }),
    }
}

pub struct RuntimeBuilder {
    config: RuntimeConfig,
    install_defaults: bool,
    trace_transport: Option<Box<dyn TraceTransport>>,
    filesystem: Option<Box<dyn FsDriver>>,
    filesystem_is_capture: bool,
    /// Durable base image for the runtime-built crash/mem filesystem. Callers
    /// that want config-driven crash-consistency (the shim, and any operator
    /// path) supply the image here rather than pre-installing a filesystem, so
    /// `build` is the single choke point that constructs the `CrashFs` from
    /// `config.faults`. A pre-installed `filesystem` and an `fs_image` are
    /// mutually exclusive.
    fs_image: Option<MemFs>,
    clock: Option<Box<dyn ClockDriver>>,
    entropy: Option<Box<dyn EntropyDriver>>,
    scheduler: Option<Box<dyn SchedulerDriver>>,
    network: Option<Box<dyn NetDriver>>,
}

impl RuntimeBuilder {
    pub fn new(config: RuntimeConfig) -> Self {
        Self {
            config,
            install_defaults: false,
            trace_transport: None,
            filesystem: None,
            filesystem_is_capture: false,
            fs_image: None,
            clock: None,
            entropy: None,
            scheduler: None,
            network: None,
        }
    }

    pub fn with_default_drivers(mut self) -> Self {
        self.install_defaults = true;
        self
    }

    /// Install the byte-level trace channel required by the transport modes.
    pub fn with_trace_transport(mut self, transport: impl TraceTransport + 'static) -> Self {
        self.trace_transport = Some(Box::new(transport));
        self
    }

    pub fn with_filesystem(mut self, driver: impl FsDriver + 'static) -> Self {
        self.filesystem = Some(Box::new(driver));
        self.filesystem_is_capture = false;
        self
    }

    /// Supply the durable base image the runtime wraps in its own
    /// config-driven filesystem. When `--fs-crash-at` is configured, `build`
    /// wraps this image in a [`CrashFs`] seeded and torn-write-configured from
    /// `config.faults`; otherwise the image is used directly. This is the path
    /// production callers (the shim) must use so no parsed fault knob can be
    /// silently dropped by a pre-installed filesystem — the crash filesystem is
    /// only ever constructed at the single choke point in `build`.
    pub fn with_fs_image(mut self, image: MemFs) -> Self {
        self.fs_image = Some(image);
        self
    }

    /// Install an explicitly allowlisted host-capture filesystem.
    ///
    /// Replay returns recorded filesystem outcomes without contacting the
    /// host. A branch that reaches an unrecorded filesystem operation fails.
    pub fn with_captured_filesystem(mut self, driver: impl FsDriver + 'static) -> Self {
        self.filesystem = Some(Box::new(driver));
        self.filesystem_is_capture = true;
        self
    }

    pub fn with_clock(mut self, driver: impl ClockDriver + 'static) -> Self {
        self.clock = Some(Box::new(driver));
        self
    }

    pub fn with_entropy(mut self, driver: impl EntropyDriver + 'static) -> Self {
        self.entropy = Some(Box::new(driver));
        self
    }

    pub fn with_scheduler(mut self, driver: impl SchedulerDriver + 'static) -> Self {
        self.scheduler = Some(Box::new(driver));
        self
    }

    pub fn with_network(mut self, driver: impl NetDriver + 'static) -> Self {
        self.network = Some(Box::new(driver));
        self
    }

    pub fn build(mut self) -> Result<Context, RuntimeError> {
        if self.config.fingerprint.is_empty() {
            return Err(RuntimeError::Config(
                "runtime compatibility fingerprint must not be empty".into(),
            ));
        }

        match self.config.mode {
            ExecutionMode::RecordTransport | ExecutionMode::ReplayTransport { .. } => {
                if self.trace_transport.is_none() {
                    return Err(RuntimeError::Config(
                        "trace transport mode requires an installed trace transport".into(),
                    ));
                }
            }
            _ => {
                if self.trace_transport.is_some() {
                    return Err(RuntimeError::Config(
                        "a trace transport is only usable with transport record/replay modes"
                            .into(),
                    ));
                }
            }
        }

        // Swarm fault-class selection: for a record/seeded run, mask the enabled
        // fault classes down to a seed-derived subset BEFORE any driver or
        // metadata record consumes `self.config.faults`. Not applied on
        // replay/branch, where the trace's recorded (already-masked) fault config
        // is authoritative and re-masking would double-select. The record is
        // attached to the recorder metadata below.
        let swarm_record = if self.config.swarm
            && matches!(
                self.config.mode,
                ExecutionMode::Seeded
                    | ExecutionMode::Record { .. }
                    | ExecutionMode::RecordTransport
            ) {
            Some(apply_swarm_mask(&mut self.config))
        } else {
            None
        };

        // A replayed or branched trace supplies its own authoritative fault
        // configuration, applied to `self.config` after the match releases its
        // borrow. `None` leaves the operator-supplied configuration in place.
        let mut replay_fault_override: Option<(FaultConfig, u64)> = None;
        // Same contract for the cooperative-SUT (buggify) configuration: a
        // replayed/branched trace's recorded config is authoritative.
        let mut replay_buggify_override: Option<BuggifyConfig> = None;
        // Same contract for the exploration scheduling policy.
        let mut replay_schedule_override: Option<SchedulePolicy> = None;
        let (execution, root_seed) = match &self.config.mode {
            ExecutionMode::Seeded => (Execution::Seeded, self.config.seed),
            ExecutionMode::Record { path } => (
                Execution::Record {
                    recorder: Recorder::new(
                        RunMetadata::new(self.config.seed, self.config.fingerprint.clone())
                            .with_faults(Some(fault_record(&self.config)))
                            .with_buggify(buggify_record(&self.config))
                            .with_schedule_policy(schedule_policy_record(&self.config))
                            .with_swarm(swarm_record.clone())
                            .with_watchdog(watchdog_record(&self.config))
                            .with_guest_argv(self.config.guest_argv.clone()),
                    ),
                    sink: RecordSink::Path {
                        path: path.clone(),
                        _reservation: RecordReservation::acquire(path)?,
                    },
                },
                self.config.seed,
            ),
            ExecutionMode::RecordTransport => (
                Execution::Record {
                    recorder: Recorder::new(
                        RunMetadata::new(self.config.seed, self.config.fingerprint.clone())
                            .with_faults(Some(fault_record(&self.config)))
                            .with_buggify(buggify_record(&self.config))
                            .with_schedule_policy(schedule_policy_record(&self.config))
                            .with_swarm(swarm_record.clone())
                            .with_watchdog(watchdog_record(&self.config))
                            .with_guest_argv(self.config.guest_argv.clone()),
                    ),
                    sink: RecordSink::Transport(
                        self.trace_transport.take().expect("transport was checked"),
                    ),
                },
                self.config.seed,
            ),
            ExecutionMode::Replay { path, timeline } => {
                let replayer = Replayer::open_timeline(path, &self.config.fingerprint, timeline)?;
                let root_seed = replayer.root_seed();
                // The trace's fault configuration is authoritative on replay.
                replay_fault_override =
                    reconcile_replay_faults(&self.config, replayer.fault_config())?;
                replay_buggify_override =
                    reconcile_replay_buggify(&self.config, replayer.buggify_config())?;
                replay_schedule_override =
                    reconcile_replay_schedule_policy(&self.config, replayer.schedule_policy())?;
                (Execution::Replay(replayer), root_seed)
            }
            ExecutionMode::ReplayTransport { timeline } => {
                let mut transport = self.trace_transport.take().expect("transport was checked");
                let bytes = transport.read_bundle().map_err(|source| RuntimeError::Io {
                    action: "read trace bundle from trace transport".into(),
                    source,
                })?;
                let bundle = TraceBundle::from_slice(&bytes)?;
                let replayer = Replayer::from_bundle(bundle, &self.config.fingerprint, timeline)?;
                let root_seed = replayer.root_seed();
                replay_fault_override =
                    reconcile_replay_faults(&self.config, replayer.fault_config())?;
                replay_buggify_override =
                    reconcile_replay_buggify(&self.config, replayer.buggify_config())?;
                replay_schedule_override =
                    reconcile_replay_schedule_policy(&self.config, replayer.schedule_policy())?;
                (Execution::Replay(replayer), root_seed)
            }
            ExecutionMode::Branch {
                path,
                parent,
                from_sequence,
                branch_id,
                branch_seed,
            } => {
                let reservation = RecordReservation::acquire_branch(path)?;
                let session = BranchSession::open(
                    path,
                    &self.config.fingerprint,
                    parent,
                    *from_sequence,
                    branch_id.clone(),
                    *branch_seed,
                )?;
                // A branch replays the parent prefix, so it inherits the parent
                // trace's fault configuration for the replayed drivers.
                replay_fault_override =
                    reconcile_replay_faults(&self.config, session.fault_config())?;
                replay_buggify_override =
                    reconcile_replay_buggify(&self.config, session.buggify_config())?;
                replay_schedule_override =
                    reconcile_replay_schedule_policy(&self.config, session.schedule_policy())?;
                (
                    Execution::Branch {
                        session: Box::new(session),
                        _reservation: reservation,
                    },
                    *branch_seed,
                )
            }
        };

        // Adopt the trace's authoritative fault configuration before any driver
        // is constructed from it, so a flag-free replay rebuilds the same
        // CrashFs/SimNet the recording used.
        if let Some((faults, net_latency_nanos)) = replay_fault_override {
            self.config.faults = faults;
            self.config.net_latency_nanos = net_latency_nanos;
        }
        // Adopt the trace's authoritative buggify configuration so a flag-free
        // replay re-derives the same activation and firing decisions.
        if let Some(buggify) = replay_buggify_override {
            self.config.buggify = buggify;
        }
        // Adopt the trace's authoritative exploration scheduling policy. Replay
        // consumes recorded task selections directly (through `select`), so the
        // policy does not steer replay; adopting it keeps the built scheduler
        // consistent and the reconcile above provides the fail-closed guard.
        if let Some(policy) = replay_schedule_override {
            self.config.schedule_policy = policy;
        }

        // The crash-consistency filesystem is built HERE, and only here, from
        // `config.faults` — the single choke point that always consumes the
        // parsed crash knobs. Callers pass the durable base image via
        // `with_fs_image`; they must not pre-install the final filesystem, so a
        // knob like `--fs-torn-granularity` can never be silently dropped by a
        // filesystem that bypassed the fault config (the gap this replaced).
        let crash_knobs_set = self.config.faults.crash_at.is_some()
            || self.config.faults.torn_granularity != TornGranularity::default();
        if self.filesystem.is_some() {
            // An explicit filesystem (`with_filesystem`/`with_captured_filesystem`)
            // cannot reflect config-driven crash knobs, and an accompanying base
            // image would be ignored. Fail closed rather than proceed silently.
            if crash_knobs_set {
                return Err(RuntimeError::Config(
                    "a filesystem was installed explicitly while crash-consistency \
                     fault knobs (--fs-crash-at / --fs-torn-granularity) are set; \
                     those knobs would be silently ignored. Supply the durable \
                     image via RuntimeBuilder::with_fs_image so the runtime builds \
                     the crash filesystem from the fault configuration."
                        .into(),
                ));
            }
            if self.fs_image.is_some() {
                return Err(RuntimeError::Config(
                    "both an explicit filesystem and a base image were provided; \
                     use exactly one"
                        .into(),
                ));
            }
        }
        if self.install_defaults {
            // The base image is ALWAYS wrapped in a config-driven `CrashFs`,
            // whether or not `--fs-crash-at` is set. This preserves the historical
            // always-`CrashFs` behavior the shim relied on: a `CrashFs` is
            // crashable, so imperative callers that trigger `fs_crash()` manually
            // (the C-ABI `patina_init_crash` path, the WASI-host crash probes)
            // keep working. A bare `MemFs` cannot crash — `FsDriver::crash`
            // returns `InvalidState` — so installing one here regressed those
            // paths. An un-crashed `CrashFs` reads/writes identically to its inner
            // `MemFs` and consumes no seeded entropy, so non-crash runs are
            // byte-for-byte unchanged.
            if self.filesystem.is_none() {
                // NOT `unwrap_or_default()`: `MemFs::new()` seeds the root `/`
                // directory, while `MemFs::default()` is ROOTLESS. A caller that
                // uses `with_default_drivers` without `with_fs_image` (e.g.
                // `Context::from_config`) would otherwise get a rootless
                // filesystem and fail every path op with NotFound. Clippy's
                // `unwrap_or_default` suggestion is wrong here because the two
                // constructors are not equivalent.
                #[allow(clippy::unwrap_or_default)]
                let base = self.fs_image.take().unwrap_or_else(MemFs::new);
                self.filesystem = Some(Box::new(
                    CrashFs::builder()
                        .filesystem(base)
                        .seed(root_seed)
                        .torn_granularity(self.config.faults.torn_granularity)
                        .build()
                        .map_err(RuntimeError::Effect)?,
                ));
            }
            self.clock
                .get_or_insert_with(|| Box::new(VirtualClock::default()));
            self.entropy
                .get_or_insert_with(|| Box::new(SeededEntropy::new(root_seed)));
            self.scheduler.get_or_insert_with(|| {
                Box::new(DetScheduler::with_policy(
                    root_seed,
                    self.config.schedule_policy,
                ))
            });
            if self.network.is_none() {
                let mut network = SimNet::builder()
                    .base_latency_nanos(self.config.net_latency_nanos)
                    .fault_seed(root_seed)
                    .drop_permille(self.config.faults.net_drop_permille);
                if let Some((min, max)) = self.config.faults.net_jitter_nanos {
                    network = network.jitter_nanos(min, max);
                }
                self.network = Some(Box::new(network.build().map_err(RuntimeError::Effect)?));
            }
        }

        // A base image is only ever consumed by the default-driver choke point
        // above. If one survives, `with_fs_image` was used without
        // `with_default_drivers`, so it would be silently dropped — fail closed.
        if self.fs_image.is_some() {
            return Err(RuntimeError::Config(
                "with_fs_image requires with_default_drivers so the runtime can \
                 build the filesystem from it"
                    .into(),
            ));
        }

        // Build the liveness watchdog before the Context literal consumes
        // `self.config` fields. The heal-then-converge arm arms at the fault-window
        // end: an explicit override, else the buggify damage-control cutoff (when
        // buggify is enabled), else run start. Detection is live only on a
        // record/seeded run; a replay consumes the authoritative trace.
        let liveness = LivenessWatchdog::new(
            self.config.liveness,
            resolve_heal_after(&self.config),
            matches!(
                self.config.mode,
                ExecutionMode::Seeded
                    | ExecutionMode::Record { .. }
                    | ExecutionMode::RecordTransport
            ),
        );

        Ok(Context {
            root_seed,
            step_budget: self.config.step_budget,
            steps: 0,
            params: self.config.params,
            execution,
            filesystem: self.filesystem,
            filesystem_is_capture: self.filesystem_is_capture,
            clock: self.clock,
            entropy: self.entropy,
            scheduler: self.scheduler,
            network: self.network,
            timers: BTreeMap::new(),
            timer_by_task: BTreeMap::new(),
            timer_seq: 0,
            scheduler_tasks: std::collections::BTreeSet::new(),
            parked_tasks: std::collections::BTreeSet::new(),
            rescued: Vec::new(),
            crash_at: self.config.faults.crash_at,
            crash_counts: CrashCounts::default(),
            crash_fired: false,
            sleep_jitter_nanos: self.config.faults.sleep_jitter_nanos,
            // Domain-separated seed so sleep-jitter draws do not correlate with
            // the entropy or scheduler streams that also derive from root_seed.
            sleep_jitter_rng: SplitMix64::new(root_seed ^ 0x5EED_1A7E_0FF5_E720),
            schedule: ScheduleTracker::default(),
            buggify: Buggify::new(self.config.buggify, root_seed),
            liveness,
        })
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

/// Whether a boundary operation represents *genuine progress* (guest-driven state
/// advancement) rather than pure scheduling/time housekeeping. The liveness
/// watchdog resets its no-progress clock on a progress op and accumulates only on
/// non-progress ops.
///
/// Non-progress = the pure scheduling/time/wait ops the runtime uses to rotate
/// tasks and advance virtual time without any guest state change: reading the
/// clock, sleeping, yielding, parking (timed or not), waking, the scheduler
/// decision itself, and the park-until-delivery probe. Everything else — every
/// filesystem effect, entropy draw, task spawn/completion, and network data
/// movement — is genuine progress.
///
/// Consequence (documented): a system that keeps doing real I/O (e.g. exchanging
/// network messages) but never reaches an application-level goal is NOT caught by
/// this generic detector, because its I/O counts as progress; that requires an
/// application-level oracle. The watchdog catches the *pure-churn wedge* — a run
/// that has stopped issuing genuine effects and only spins on timers/parks while
/// virtual time marches on.
fn operation_is_progress(operation: &Operation) -> bool {
    !matches!(
        operation,
        Operation::ClockNow { .. }
            | Operation::SleepUntil { .. }
            | Operation::TaskYield { .. }
            | Operation::TaskPark { .. }
            | Operation::TaskParkTimed { .. }
            | Operation::TaskWake { .. }
            | Operation::SchedulerNext
            | Operation::NetNextDelivery { .. }
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
struct LivenessViolation {
    kind: LivenessKind,
    vtime_ns: u64,
    budget_ns: u64,
    last_fault_vtime_ns: u64,
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
struct WatchdogArm {
    kind: LivenessKind,
    /// Virtual time (nanoseconds) at which this arm becomes active. The generic
    /// arm arms at 0; the converge arm arms at the fault-window end.
    arm_time_nanos: u64,
    budget_nanos: u64,
    /// Whether virtual time has reached `arm_time_nanos` yet.
    armed: bool,
    /// Virtual time of the last progress (or of arming), from which the budget is
    /// measured.
    baseline_nanos: u64,
    /// Consecutive non-progress ops since the baseline.
    stall_ops: u64,
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
struct LivenessWatchdog {
    arms: Vec<WatchdogArm>,
    /// Whether detection is live this run (record/seeded and at least one arm).
    active: bool,
    fired: bool,
}

impl LivenessWatchdog {
    /// Build the watchdog from the resolved config. `heal_after_nanos` is the
    /// converge arm's arm-time already resolved by the caller (buggify cutoff or
    /// override). `active` gates whether detection actually runs.
    fn new(config: LivenessConfig, heal_after_nanos: u64, active: bool) -> Self {
        let mut arms = Vec::new();
        if let Some(budget) = config.no_progress_budget_nanos {
            arms.push(WatchdogArm {
                kind: LivenessKind::NoProgress,
                arm_time_nanos: 0,
                budget_nanos: budget,
                armed: false,
                baseline_nanos: 0,
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
        }
    }

    /// Observe one boundary op across every arm; return the first arm that fires.
    fn observe(&mut self, now: u64, progress: bool, deferring: bool) -> Option<LivenessViolation> {
        for arm in &mut self.arms {
            if let Some(violation) = arm.observe(now, progress, deferring) {
                self.fired = true;
                return Some(violation);
            }
        }
        None
    }
}

/// Per-task scheduling-boundary accounting backing [`ScheduleDiagnostics`].
/// Every field is driven by the recorded task-lifecycle ops, so it is populated
/// identically on record and replay.
#[derive(Default)]
struct ScheduleTracker {
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

    fn diagnostics(&self) -> ScheduleDiagnostics {
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

/// Per-operation-kind occurrence counters used to fire a crash at the Nth
/// boundary op of a chosen kind.
#[derive(Default)]
struct CrashCounts {
    open: u64,
    write: u64,
    sync: u64,
    close: u64,
}

enum Execution {
    Seeded,
    Record {
        recorder: Recorder,
        sink: RecordSink,
    },
    Replay(Replayer),
    Branch {
        // Boxed: a `BranchSession` is by far the largest variant payload, and
        // branch runs are the rare path, so keeping it out of line avoids
        // inflating every `Execution` (clippy::large_enum_variant).
        session: Box<BranchSession>,
        _reservation: RecordReservation,
    },
}

enum RecordSink {
    Path {
        path: PathBuf,
        _reservation: RecordReservation,
    },
    Transport(Box<dyn TraceTransport>),
}

struct RecordReservation {
    lock_path: PathBuf,
}

impl RecordReservation {
    fn acquire(trace_path: &Path) -> Result<Self, RuntimeError> {
        let reservation = Self::acquire_lock(trace_path)?;
        if trace_path.exists() {
            return Err(RuntimeError::Config(format!(
                "refusing to overwrite existing trace {}",
                trace_path.display()
            )));
        }
        Ok(reservation)
    }

    fn acquire_branch(trace_path: &Path) -> Result<Self, RuntimeError> {
        if !trace_path.is_file() {
            return Err(RuntimeError::Config(format!(
                "cannot branch from missing trace {}",
                trace_path.display()
            )));
        }
        Self::acquire_lock(trace_path)
    }

    fn acquire_lock(trace_path: &Path) -> Result<Self, RuntimeError> {
        let parent = trace_path
            .parent()
            .filter(|value| !value.as_os_str().is_empty());
        if let Some(parent) = parent {
            fs::create_dir_all(parent).map_err(|source| RuntimeError::Io {
                action: format!("create trace directory {}", parent.display()),
                source,
            })?;
        }
        let lock_path = record_lock_path(trace_path)?;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
            .map_err(|source| RuntimeError::Io {
                action: format!(
                    "reserve trace {} using {}; another Patina recorder may be active",
                    trace_path.display(),
                    lock_path.display()
                ),
                source,
            })?;
        Ok(Self { lock_path })
    }
}

impl Drop for RecordReservation {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_path);
    }
}

enum FilesystemExpected {
    Execute(Option<(u64, Outcome)>),
    Captured(Outcome),
}

/// Domain separators for the buggify PRF, so activation, firing, knob, and delay
/// draws for one site never correlate.
mod buggify_domain {
    pub const ACTIVATION: u64 = 0x4143_5449_5641_5445; // "ACTIVATE"
    pub const FIRING: u64 = 0x4649_5249_4e47_5f5f; // "FIRING__"
    pub const KNOB: u64 = 0x4b4e_4f42_5f5f_5f5f; // "KNOB____"
    pub const DELAY: u64 = 0x4445_4c41_595f_5f5f; // "DELAY___"
    pub const RNG: u64 = 0x524e_475f_5f5f_5f5f; // "RNG_____"
}

/// A deterministic 64-bit hash of a site label, stable across builds, platforms,
/// and Rust versions (unlike `DefaultHasher`) so cross-machine replay agrees.
/// FNV-1a over the UTF-8 bytes.
fn label_hash(label: &str) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in label.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// A domain-separated deterministic pseudo-random value from a set of 64-bit
/// inputs, built from the specified SplitMix64 finalizer so it needs no state
/// beyond the inputs and reproduces exactly across processes.
fn buggify_prf(inputs: &[u64]) -> u64 {
    let mut acc = 0xa5a5_a5a5_5a5a_5a5a_u64;
    for &value in inputs {
        acc = SplitMix64::new(acc ^ value).next_u64();
        acc = acc.wrapping_add(value.rotate_left(17));
    }
    SplitMix64::new(acc).next_u64()
}

/// What a registered buggify site is used for. Purely descriptive: it drives the
/// `PATINA_SDK_REPORT` categorization and never the firing decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuggifyKind {
    /// `buggify!` / `buggify_with_prob!` — a probabilistic fault trigger.
    Fault,
    /// `buggify_delay!` — a probabilistic deterministic delay.
    Delay,
    /// `buggify_knob!` — a per-run perturbed value.
    Knob,
    /// `always!` — an invariant whose violation is fatal.
    Always,
    /// `sometimes!` — a coverage oracle (should be true at least once).
    Sometimes,
    /// `reachable!` — a coverage oracle (this site should be reached).
    Reachable,
}

impl BuggifyKind {
    fn as_str(self) -> &'static str {
        match self {
            BuggifyKind::Fault => "fault",
            BuggifyKind::Delay => "delay",
            BuggifyKind::Knob => "knob",
            BuggifyKind::Always => "always",
            BuggifyKind::Sometimes => "sometimes",
            BuggifyKind::Reachable => "reachable",
        }
    }
}

/// The result of evaluating a cooperative-SUT site, for the embedder (the native
/// shim) to act on. The runtime never performs process I/O or aborts itself; it
/// returns the signal and the embedder emits the marker line and aborts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SiteOutcome {
    /// Proceed normally: the buggify site did not fire, or the oracle was noted.
    Ok,
    /// The buggify site fired — the embedder injects the fault / takes the branch.
    Fire,
    /// An `always!` invariant was violated: the embedder emits the
    /// `PATINA_ALWAYS_VIOLATION` marker for the label and aborts.
    AlwaysViolation,
    /// The label is reused at a different call site: a fatal duplicate. The
    /// embedder emits the `PATINA_BUGGIFY_DUPLICATE_LABEL` marker and aborts.
    DuplicateLabel,
}

/// One registered cooperative-SUT site, keyed by its unique explicit label.
#[derive(Clone, Debug)]
struct BuggifySite {
    /// The `file:line` identity captured by the macro, used only to detect a
    /// duplicate label reused at a different call site.
    site: String,
    kind: BuggifyKind,
    /// Per-run activation decision (fault/delay/knob sites). Pure function of
    /// `(seed, label, activation_permille)`.
    active: bool,
    /// Firing-PRF counter, incremented on every evaluation. Advances identically
    /// on record and replay because the same code runs on both.
    eval_count: u64,
    fire_count: u64,
    reachable: bool,
    sometimes_satisfied: bool,
    always_violated: bool,
    knob: Option<i64>,
}

/// End-of-run cooperative-SUT diagnostics, surfaced in `PATINA_SDK_REPORT` and,
/// via the internal buggify trace record, in the trace metadata.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BuggifyDiagnostics {
    pub enabled: bool,
    pub fire_permille: u16,
    pub activation_permille: u16,
    pub cutoff_nanos: u64,
    pub cutoff_reached: bool,
    pub sites_registered: u64,
    pub sites_activated: u64,
    pub total_firings: u64,
    pub cutoff_suppressed: u64,
    pub after_setup: bool,
    pub setup_complete: bool,
    /// Per-site rows in label order: (label, kind, active, evals, fires,
    /// reachable, sometimes_satisfied, always_violated, knob).
    pub sites: Vec<BuggifySiteReport>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuggifySiteReport {
    pub label: String,
    pub kind: BuggifyKind,
    pub active: bool,
    pub evals: u64,
    pub fires: u64,
    pub reachable: bool,
    pub sometimes_satisfied: bool,
    pub always_violated: bool,
    pub knob: Option<i64>,
}

/// The cooperative-SUT (buggify) site registry and deterministic decision
/// engine. All randomness derives from the root seed and the site's explicit
/// label through [`buggify_prf`]; nothing is recorded per-evaluation, so replay
/// re-derives every decision from the seed and the trace's recorded config.
struct Buggify {
    config: BuggifyConfig,
    seed: u64,
    /// Lifecycle marker state. Firing is not gated on it (see the crate/module
    /// docs on the causal limitation); it is reported and, for a guest that
    /// places its workload sites after the call, marks the setup boundary.
    setup_complete: bool,
    sites: BTreeMap<String, BuggifySite>,
    rng: SplitMix64,
    cutoff_suppressed: u64,
    /// Set once the cutoff has been observed passed at a firing check.
    cutoff_reached: bool,
}

impl Buggify {
    fn new(config: BuggifyConfig, seed: u64) -> Self {
        Self {
            config,
            seed,
            setup_complete: false,
            sites: BTreeMap::new(),
            rng: SplitMix64::new(buggify_prf(&[seed, buggify_domain::RNG])),
            cutoff_suppressed: 0,
            cutoff_reached: false,
        }
    }

    /// Whether a site's label activates it this run. Pure function of the seed,
    /// the label, and the activation per-mille.
    fn label_is_active(&self, label_hash: u64) -> bool {
        (buggify_prf(&[self.seed, label_hash, buggify_domain::ACTIVATION]) % 1000)
            < u64::from(self.config.activation_permille)
    }

    /// Register (or revisit) a site under `label`, returning its stable label
    /// hash. A label reused at a different call `site` is a fatal duplicate
    /// (returned as `Err(existing_site)`). On first registration the activation
    /// decision is computed once and frozen.
    fn register(&mut self, label: &str, site: &str, kind: BuggifyKind) -> Result<u64, String> {
        let hash = label_hash(label);
        match self.sites.get(label) {
            Some(existing) if existing.site != site => return Err(existing.site.clone()),
            Some(_) => {}
            None => {
                let active = self.label_is_active(hash);
                self.sites.insert(
                    label.to_string(),
                    BuggifySite {
                        site: site.to_string(),
                        kind,
                        active,
                        eval_count: 0,
                        fire_count: 0,
                        reachable: false,
                        sometimes_satisfied: false,
                        always_violated: false,
                        knob: None,
                    },
                );
            }
        }
        Ok(hash)
    }

    /// The firing decision for an active site at its current evaluation, given a
    /// (possibly overridden) firing per-mille. Increments the evaluation counter
    /// as a side effect so consecutive evaluations use independent draws.
    fn fire_draw(hash: u64, seed: u64, eval_count: u64, fire_permille: u16) -> bool {
        (buggify_prf(&[seed, hash, buggify_domain::FIRING, eval_count]) % 1000)
            < u64::from(fire_permille)
    }

    fn diagnostics(&self, cutoff_reached_now: bool) -> BuggifyDiagnostics {
        let mut sites = Vec::with_capacity(self.sites.len());
        let mut activated = 0_u64;
        let mut firings = 0_u64;
        for (label, site) in &self.sites {
            if site.active {
                activated += 1;
            }
            firings += site.fire_count;
            sites.push(BuggifySiteReport {
                label: label.clone(),
                kind: site.kind,
                active: site.active,
                evals: site.eval_count,
                fires: site.fire_count,
                reachable: site.reachable,
                sometimes_satisfied: site.sometimes_satisfied,
                always_violated: site.always_violated,
                knob: site.knob,
            });
        }
        BuggifyDiagnostics {
            enabled: self.config.enabled,
            fire_permille: self.config.fire_permille,
            activation_permille: self.config.activation_permille,
            cutoff_nanos: self.config.cutoff_nanos,
            cutoff_reached: self.cutoff_reached || cutoff_reached_now,
            sites_registered: self.sites.len() as u64,
            sites_activated: activated,
            total_firings: firings,
            cutoff_suppressed: self.cutoff_suppressed,
            after_setup: self.config.after_setup,
            setup_complete: self.setup_complete,
            sites,
        }
    }

    /// The realized configuration and per-site picks recorded into the trace
    /// metadata, or `None` when buggify is disabled.
    fn to_record(&self) -> Option<patina_dst_trace::BuggifyConfigRecord> {
        if !self.config.enabled {
            return None;
        }
        let active_sites = self
            .sites
            .iter()
            .filter(|(_, site)| site.active)
            .map(|(label, _)| label.clone())
            .collect();
        let knobs = self
            .sites
            .iter()
            .filter_map(|(label, site)| site.knob.map(|value| (label.clone(), value)))
            .collect();
        Some(patina_dst_trace::BuggifyConfigRecord {
            fire_permille: self.config.fire_permille,
            activation_permille: self.config.activation_permille,
            cutoff_nanos: self.config.cutoff_nanos,
            after_setup: self.config.after_setup,
            active_sites,
            knobs,
        })
    }

    /// Whether the run declared `--buggify-after-setup` but the guest never
    /// reached `setup_complete()`: a harness bug that must fail loudly, not a
    /// silent no-fault run.
    fn setup_violation(&self) -> bool {
        self.config.enabled && self.config.after_setup && !self.setup_complete
    }

    /// Whether firing is currently armed: always, unless gated behind a
    /// setup-complete the guest has not reached yet.
    fn armed(&self) -> bool {
        !self.config.after_setup || self.setup_complete
    }
}

/// The runtime context through which initial Patina effects are performed.
pub struct Context {
    root_seed: u64,
    step_budget: Option<u64>,
    steps: u64,
    params: BTreeMap<String, String>,
    execution: Execution,
    filesystem: Option<Box<dyn FsDriver>>,
    filesystem_is_capture: bool,
    clock: Option<Box<dyn ClockDriver>>,
    entropy: Option<Box<dyn EntropyDriver>>,
    scheduler: Option<Box<dyn SchedulerDriver>>,
    network: Option<Box<dyn NetDriver>>,
    /// Virtual-clock timer queue. Ordered by `(monotonic_deadline_nanos,
    /// registration_seq)` so the deadlock-rescue path advances to the single
    /// earliest deadline and wakes due tasks in a stable order. Maintained
    /// identically on record and replay because every park/wake runs on both.
    timers: BTreeMap<(u64, u64), TaskId>,
    /// Reverse index enforcing at most one live timer per task and enabling
    /// deregistration when a task is woken early (by signal or data).
    timer_by_task: BTreeMap<TaskId, (u64, u64)>,
    timer_seq: u64,
    /// Shadow of the scheduler's task set and which tasks are parked, so the
    /// runtime can tell — without a new `SchedulerDriver` method — when
    /// `scheduler.next()` would deadlock and a timer rescue is warranted.
    scheduler_tasks: std::collections::BTreeSet<TaskId>,
    parked_tasks: std::collections::BTreeSet<TaskId>,
    /// Tasks woken by the most recent deadlock-rescue (their timers fired), for
    /// an embedder to drain and resolve as timeouts.
    rescued: Vec<TaskId>,
    /// Configured filesystem crash point, or `None` when crash injection is off.
    /// Consulted after each matching boundary operation; the crash fires exactly
    /// once. The op sequence is identical on record and replay, so the injected
    /// `FsCrash` lands at the same position and reconciles.
    crash_at: Option<CrashPoint>,
    crash_counts: CrashCounts,
    crash_fired: bool,
    /// Inclusive `[min, max]` nanoseconds of seeded latency added to each guest
    /// sleep, or `None` when latency injection is off.
    sleep_jitter_nanos: Option<(u64, u64)>,
    sleep_jitter_rng: SplitMix64,
    /// Per-task scheduling-boundary accounting for the vacuous-schedule
    /// diagnostic emitted at [`Context::finish`].
    schedule: ScheduleTracker,
    /// Cooperative-SUT (buggify) site registry and decision engine. Inert when
    /// buggify is disabled, so a run that does not opt in is unaffected.
    buggify: Buggify,
    /// Virtual-time liveness watchdog. Inert (`active == false`) unless a budget is
    /// configured on a record/seeded run, so a run that does not opt in — and every
    /// replay — is byte-for-byte unchanged.
    liveness: LivenessWatchdog,
}

impl Context {
    pub fn from_config(config: RuntimeConfig) -> Result<Self, RuntimeError> {
        RuntimeBuilder::new(config).with_default_drivers().build()
    }

    pub fn from_env() -> Result<Self, RuntimeError> {
        Self::from_config(RuntimeConfig::from_env()?)
    }

    pub const fn root_seed(&self) -> u64 {
        self.root_seed
    }

    pub const fn steps(&self) -> u64 {
        self.steps
    }

    /// End-of-run schedule-exploration diagnostics. See [`ScheduleDiagnostics`].
    /// Also emitted to stderr by [`Context::finish`] for multithreaded runs.
    pub fn schedule_diagnostics(&self) -> ScheduleDiagnostics {
        self.schedule.diagnostics()
    }

    pub fn param(&self, key: &str) -> Option<&str> {
        self.params.get(key).map(String::as_str)
    }

    // ---- Cooperative-SUT (buggify) surface -----------------------------------
    //
    // These methods are the runtime side of the `patina` crate's `buggify!`,
    // `always!`, `sometimes!`, `reachable!`, and lifecycle macros, invoked
    // through thin C-ABI wrappers in the native shim. All randomness derives from
    // the root seed and the site's explicit label; nothing is recorded per
    // evaluation, so replay re-derives every decision. The only recorded effect
    // is `buggify_delay!`'s virtual-time advance, which rides the existing
    // `SleepUntil` boundary op and therefore reproduces exactly on replay.

    /// Whether execution is under the deterministic simulator. Always true for an
    /// installed [`Context`] — the `patina_dst::is_simulated()` hook.
    pub const fn is_simulated(&self) -> bool {
        true
    }

    /// Whether cooperative-SUT fault injection is enabled this run.
    pub const fn buggify_enabled(&self) -> bool {
        self.buggify.config.enabled
    }

    /// Evaluate a `buggify!` / `buggify_with_prob!` site. `prob_permille`
    /// overrides the run-default firing probability when `Some`. Fires only when
    /// buggify is enabled, the label activated this run, and the virtual clock is
    /// before the damage-control cutoff.
    pub fn buggify_evaluate(
        &mut self,
        label: &str,
        site: &str,
        prob_permille: Option<u16>,
    ) -> Result<SiteOutcome, RuntimeError> {
        let enabled = self.buggify.config.enabled;
        let now = if enabled {
            Some(self.current_monotonic()?)
        } else {
            None
        };
        let hash = match self.buggify.register(label, site, BuggifyKind::Fault) {
            Ok(hash) => hash,
            Err(_) => return Ok(SiteOutcome::DuplicateLabel),
        };
        let (active, eval) = {
            let entry = self.buggify.sites.get_mut(label).expect("registered");
            entry.reachable = true;
            let eval = entry.eval_count;
            entry.eval_count += 1;
            (entry.active, eval)
        };
        if !enabled || !active || !self.buggify.armed() {
            return Ok(SiteOutcome::Ok);
        }
        if now.is_some_and(|now| now >= self.buggify.config.cutoff_nanos) {
            self.buggify.cutoff_reached = true;
            self.buggify.cutoff_suppressed += 1;
            return Ok(SiteOutcome::Ok);
        }
        let permille = prob_permille.unwrap_or(self.buggify.config.fire_permille);
        if Buggify::fire_draw(hash, self.buggify.seed, eval, permille) {
            self.buggify
                .sites
                .get_mut(label)
                .expect("registered")
                .fire_count += 1;
            Ok(SiteOutcome::Fire)
        } else {
            Ok(SiteOutcome::Ok)
        }
    }

    /// Evaluate a `buggify_delay!` site. On firing, advance the virtual clock by
    /// a seed-derived amount through the recorded `SleepUntil` path — never a real
    /// sleep — so the perturbation reproduces on replay. Returns [`SiteOutcome::Fire`]
    /// when it delayed.
    pub fn buggify_delay(&mut self, label: &str, site: &str) -> Result<SiteOutcome, RuntimeError> {
        let enabled = self.buggify.config.enabled;
        let now = if enabled {
            Some(self.current_monotonic()?)
        } else {
            None
        };
        let hash = match self.buggify.register(label, site, BuggifyKind::Delay) {
            Ok(hash) => hash,
            Err(_) => return Ok(SiteOutcome::DuplicateLabel),
        };
        let (active, eval) = {
            let entry = self.buggify.sites.get_mut(label).expect("registered");
            entry.reachable = true;
            let eval = entry.eval_count;
            entry.eval_count += 1;
            (entry.active, eval)
        };
        if !enabled || !active || !self.buggify.armed() {
            return Ok(SiteOutcome::Ok);
        }
        let now = now.expect("time read when enabled");
        if now >= self.buggify.config.cutoff_nanos {
            self.buggify.cutoff_reached = true;
            self.buggify.cutoff_suppressed += 1;
            return Ok(SiteOutcome::Ok);
        }
        if !Buggify::fire_draw(
            hash,
            self.buggify.seed,
            eval,
            self.buggify.config.fire_permille,
        ) {
            return Ok(SiteOutcome::Ok);
        }
        // A seed-derived delay in [1ms, 5s], deterministic per (seed, label,
        // eval). Routed through the recorded clock path so replay reproduces it.
        const MIN_DELAY_NANOS: u64 = 1_000_000;
        const MAX_DELAY_NANOS: u64 = 5_000_000_000;
        let span = MAX_DELAY_NANOS - MIN_DELAY_NANOS + 1;
        let delay = MIN_DELAY_NANOS
            + (buggify_prf(&[self.buggify.seed, hash, buggify_domain::DELAY, eval]) % span);
        self.buggify
            .sites
            .get_mut(label)
            .expect("registered")
            .fire_count += 1;
        let deadline = now.saturating_add(delay);
        self.sleep_until(ClockKind::Monotonic, deadline)?;
        Ok(SiteOutcome::Fire)
    }

    /// Evaluate a `buggify_knob!` site: return a per-run perturbed value within
    /// `[lo, hi]` (deterministic from seed and label) for an active site under an
    /// enabled run, or `default` otherwise. `Err(())` marks a duplicate label.
    pub fn buggify_knob(
        &mut self,
        label: &str,
        site: &str,
        default: i64,
        lo: i64,
        hi: i64,
    ) -> Result<Result<i64, ()>, RuntimeError> {
        let hash = match self.buggify.register(label, site, BuggifyKind::Knob) {
            Ok(hash) => hash,
            Err(_) => return Ok(Err(())),
        };
        let (lo, hi) = if lo <= hi { (lo, hi) } else { (hi, lo) };
        let enabled = self.buggify.config.enabled;
        let entry = self.buggify.sites.get_mut(label).expect("registered");
        entry.reachable = true;
        let value = if enabled && entry.active {
            let span = (hi as i128 - lo as i128 + 1) as u128;
            let draw = buggify_prf(&[self.buggify.seed, hash, buggify_domain::KNOB]) as u128;
            (lo as i128 + (draw % span) as i128) as i64
        } else {
            default.clamp(lo, hi)
        };
        entry.knob = Some(value);
        Ok(Ok(value))
    }

    /// Evaluate an `always!` invariant. A false condition is a fatal violation
    /// whenever running under the simulator, independent of buggify being
    /// enabled — the embedder emits the marker and aborts.
    pub fn always_check(
        &mut self,
        label: &str,
        site: &str,
        condition: bool,
    ) -> Result<SiteOutcome, RuntimeError> {
        if self
            .buggify
            .register(label, site, BuggifyKind::Always)
            .is_err()
        {
            return Ok(SiteOutcome::DuplicateLabel);
        }
        let entry = self.buggify.sites.get_mut(label).expect("registered");
        entry.reachable = true;
        entry.eval_count += 1;
        if condition {
            Ok(SiteOutcome::Ok)
        } else {
            entry.always_violated = true;
            Ok(SiteOutcome::AlwaysViolation)
        }
    }

    /// Evaluate a `sometimes!` coverage oracle: note the site reached, and
    /// satisfied when `condition` is true at least once across the run.
    pub fn sometimes_check(
        &mut self,
        label: &str,
        site: &str,
        condition: bool,
    ) -> Result<SiteOutcome, RuntimeError> {
        if self
            .buggify
            .register(label, site, BuggifyKind::Sometimes)
            .is_err()
        {
            return Ok(SiteOutcome::DuplicateLabel);
        }
        let entry = self.buggify.sites.get_mut(label).expect("registered");
        entry.reachable = true;
        entry.eval_count += 1;
        if condition {
            entry.sometimes_satisfied = true;
        }
        Ok(SiteOutcome::Ok)
    }

    /// Mark a `reachable!` coverage site reached.
    pub fn reachable_mark(&mut self, label: &str, site: &str) -> Result<SiteOutcome, RuntimeError> {
        if self
            .buggify
            .register(label, site, BuggifyKind::Reachable)
            .is_err()
        {
            return Ok(SiteOutcome::DuplicateLabel);
        }
        let entry = self.buggify.sites.get_mut(label).expect("registered");
        entry.reachable = true;
        entry.eval_count += 1;
        Ok(SiteOutcome::Ok)
    }

    /// Draw a deterministic 64-bit value from the buggify entropy stream — the
    /// `patina_dst::rng()` hook, bridged to the root seed. Not recorded: it is a pure
    /// function of the seed and the call count, so replay reproduces it.
    pub fn buggify_rng(&mut self) -> u64 {
        self.buggify.rng.next_u64()
    }

    /// Mark the `patina_dst::lifecycle::setup_complete()` boundary.
    pub fn lifecycle_setup_complete(&mut self) {
        self.buggify.setup_complete = true;
    }

    /// Whether the run declared `--buggify-after-setup` but the guest never
    /// reached `setup_complete()`. The embedder checks this at finalization and
    /// fails the run loudly — a declared-but-never-called gate is a harness bug,
    /// not a silent no-fault run.
    pub fn buggify_setup_violation(&self) -> bool {
        self.buggify.setup_violation()
    }

    /// End-of-run cooperative-SUT diagnostics. See [`BuggifyDiagnostics`]. Also
    /// emitted to stderr by [`Context::finish`] via `PATINA_SDK_REPORT`.
    pub fn buggify_diagnostics(&mut self) -> BuggifyDiagnostics {
        let cutoff_reached_now = self.buggify.config.enabled
            && self
                .current_monotonic()
                .is_ok_and(|now| now >= self.buggify.config.cutoff_nanos);
        self.buggify.diagnostics(cutoff_reached_now)
    }

    pub fn entropy_bytes(&mut self, len: usize) -> Result<Vec<u8>, RuntimeError> {
        if self.entropy.is_none() {
            return Err(EffectError::missing_driver("entropy").into());
        }
        let operation = Operation::EntropyFill { len };
        if let Some((_, recorded)) = self.replay_expected(&operation)? {
            return decode_bytes(&operation, recorded);
        }

        let mut bytes = vec![0; len];
        let result = self
            .entropy
            .as_mut()
            .expect("driver was checked")
            .fill(&mut bytes);
        let outcome = match result {
            Ok(()) => Outcome::Bytes(bytes),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.complete(operation.clone(), outcome);
        decode_bytes(&operation, outcome)
    }

    pub fn now(&mut self, clock: ClockKind) -> Result<u64, RuntimeError> {
        if self.clock.is_none() {
            return Err(EffectError::missing_driver("clock").into());
        }
        let operation = Operation::ClockNow { clock };
        if let Some((_, recorded)) = self.replay_expected(&operation)? {
            return decode_u64(&operation, recorded);
        }

        let result = self.clock.as_mut().expect("driver was checked").now(clock);
        let outcome = match result {
            Ok(nanos) => Outcome::U64(nanos),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.complete(operation.clone(), outcome);
        decode_u64(&operation, outcome)
    }

    /// Sleep until `deadline_nanos`. Plain: latency jitter is applied by the
    /// caller through [`Context::apply_sleep_jitter`] so that the single
    /// guest-sleep entry point (which may park managed tasks rather than route
    /// through this method) jitters exactly once, while runtime-internal sleeps
    /// (the deadlock-rescue advancing to a timer) never do.
    pub fn sleep_until(
        &mut self,
        clock: ClockKind,
        deadline_nanos: u64,
    ) -> Result<(), RuntimeError> {
        if self.clock.is_none() {
            return Err(EffectError::missing_driver("clock").into());
        }
        let operation = Operation::SleepUntil {
            clock,
            deadline_nanos,
        };
        let expected = self.replay_expected(&operation)?;
        let result = self
            .clock
            .as_mut()
            .expect("driver was checked")
            .sleep_until(clock, deadline_nanos);
        let actual = match result {
            Ok(()) => Outcome::Unit,
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_unit(&operation, outcome)
    }

    /// Add the configured seeded sleep-latency jitter to an absolute sleep
    /// deadline, returning it unchanged when latency injection is off. Drawn from
    /// a domain-separated seeded stream so the inflation is deterministic per seed
    /// and reproduced on replay. A single decision-free range value consumes no
    /// draw. The embedder applies this once, at the guest-facing sleep entry,
    /// before parking a managed task or calling [`Context::sleep_until`].
    pub fn apply_sleep_jitter(&mut self, deadline_nanos: u64) -> u64 {
        let jitter = match self.sleep_jitter_nanos {
            None => return deadline_nanos,
            Some((min, max)) if min == max => min,
            Some((min, max)) => {
                let span = max - min + 1;
                min + (self.sleep_jitter_rng.next_u64() % span)
            }
        };
        deadline_nanos.saturating_add(jitter)
    }

    pub fn sleep_for(&mut self, duration_nanos: u64) -> Result<(), RuntimeError> {
        let now = self.now(ClockKind::Monotonic)?;
        let deadline = now.checked_add(duration_nanos).ok_or_else(|| {
            EffectError::new(ErrorCode::InvalidInput, "virtual sleep deadline overflowed")
        })?;
        // Direct-API sleeps jitter here (the native embedder jitters at its own
        // sleep entry instead); either way a guest sleep is jittered exactly once.
        let deadline = self.apply_sleep_jitter(deadline);
        self.sleep_until(ClockKind::Monotonic, deadline)
    }

    pub fn fs_open(&mut self, path: &str, flags: OpenFlags) -> Result<Fd, RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        let operation = Operation::FsOpen {
            path: path.into(),
            flags,
        };
        let expected = match self.filesystem_expected(&operation)? {
            FilesystemExpected::Execute(expected) => expected,
            FilesystemExpected::Captured(outcome) => return decode_handle(&operation, outcome),
        };
        let result = self
            .filesystem
            .as_mut()
            .expect("driver was checked")
            .open(path, flags);
        let actual = match result {
            Ok(fd) => Outcome::Handle(fd),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        let decoded = decode_handle(&operation, outcome);
        self.maybe_inject_crash(CrashOp::Open)?;
        decoded
    }

    pub fn fs_read(&mut self, fd: Fd, max_len: usize) -> Result<Vec<u8>, RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        let operation = Operation::FsRead { fd, max_len };
        let expected = match self.filesystem_expected(&operation)? {
            FilesystemExpected::Execute(expected) => expected,
            FilesystemExpected::Captured(outcome) => return decode_bytes(&operation, outcome),
        };
        let result = self
            .filesystem
            .as_mut()
            .expect("driver was checked")
            .read(fd, max_len);
        let actual = match result {
            Ok(bytes) => Outcome::Bytes(bytes),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_bytes(&operation, outcome)
    }

    pub fn fs_write(&mut self, fd: Fd, bytes: &[u8]) -> Result<usize, RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        let operation = Operation::FsWrite {
            fd,
            bytes: bytes.to_vec(),
        };
        let expected = match self.filesystem_expected(&operation)? {
            FilesystemExpected::Execute(expected) => expected,
            FilesystemExpected::Captured(outcome) => return decode_usize(&operation, outcome),
        };
        let result = self
            .filesystem
            .as_mut()
            .expect("driver was checked")
            .write(fd, bytes);
        let actual = match result {
            Ok(written) => Outcome::Usize(written),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        let decoded = decode_usize(&operation, outcome);
        self.maybe_inject_crash(CrashOp::Write)?;
        decoded
    }

    /// Positional read (`pread`): read at an explicit offset without moving the
    /// file cursor. Recorded as [`Operation::FsReadAt`], distinct from a cursor
    /// read, and -- like a cursor read -- fires no crash-injection boundary.
    pub fn fs_read_at(
        &mut self,
        fd: Fd,
        offset: u64,
        max_len: usize,
    ) -> Result<Vec<u8>, RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        let operation = Operation::FsReadAt {
            fd,
            offset,
            max_len,
        };
        let expected = match self.filesystem_expected(&operation)? {
            FilesystemExpected::Execute(expected) => expected,
            FilesystemExpected::Captured(outcome) => return decode_bytes(&operation, outcome),
        };
        let result = self
            .filesystem
            .as_mut()
            .expect("driver was checked")
            .read_at(fd, offset, max_len);
        let actual = match result {
            Ok(bytes) => Outcome::Bytes(bytes),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_bytes(&operation, outcome)
    }

    /// Positional write (`pwrite`): write at an explicit offset without moving
    /// the file cursor. Recorded as [`Operation::FsWriteAt`] and counts toward
    /// the `write` crash ordinal, so `--fs-crash-at write:N` fires on a guest's
    /// positional page writes.
    pub fn fs_write_at(
        &mut self,
        fd: Fd,
        offset: u64,
        bytes: &[u8],
    ) -> Result<usize, RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        let operation = Operation::FsWriteAt {
            fd,
            offset,
            bytes: bytes.to_vec(),
        };
        let expected = match self.filesystem_expected(&operation)? {
            FilesystemExpected::Execute(expected) => expected,
            FilesystemExpected::Captured(outcome) => return decode_usize(&operation, outcome),
        };
        let result = self
            .filesystem
            .as_mut()
            .expect("driver was checked")
            .write_at(fd, offset, bytes);
        let actual = match result {
            Ok(written) => Outcome::Usize(written),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        let decoded = decode_usize(&operation, outcome);
        self.maybe_inject_crash(CrashOp::Write)?;
        decoded
    }

    pub fn fs_close(&mut self, fd: Fd) -> Result<(), RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        let operation = Operation::FsClose { fd };
        let expected = match self.filesystem_expected(&operation)? {
            FilesystemExpected::Execute(expected) => expected,
            FilesystemExpected::Captured(outcome) => return decode_unit(&operation, outcome),
        };
        let result = self
            .filesystem
            .as_mut()
            .expect("driver was checked")
            .close(fd);
        let actual = match result {
            Ok(()) => Outcome::Unit,
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        let decoded = decode_unit(&operation, outcome);
        self.maybe_inject_crash(CrashOp::Close)?;
        decoded
    }

    pub fn fs_dup(&mut self, fd: Fd) -> Result<Fd, RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        let operation = Operation::FsDup { fd };
        let expected = match self.filesystem_expected(&operation)? {
            FilesystemExpected::Execute(expected) => expected,
            FilesystemExpected::Captured(outcome) => return decode_handle(&operation, outcome),
        };
        let result = self
            .filesystem
            .as_mut()
            .expect("driver was checked")
            .dup(fd);
        let actual = match result {
            Ok(fd) => Outcome::Handle(fd),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_handle(&operation, outcome)
    }

    pub fn fs_seek(
        &mut self,
        fd: Fd,
        offset: i64,
        whence: SeekWhence,
    ) -> Result<u64, RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        let operation = Operation::FsSeek { fd, offset, whence };
        let expected = match self.filesystem_expected(&operation)? {
            FilesystemExpected::Execute(expected) => expected,
            FilesystemExpected::Captured(outcome) => return decode_u64(&operation, outcome),
        };
        let result = self
            .filesystem
            .as_mut()
            .expect("driver was checked")
            .seek(fd, offset, whence);
        let actual = match result {
            Ok(position) => Outcome::U64(position),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_u64(&operation, outcome)
    }

    pub fn fs_metadata(&mut self, path: &str) -> Result<FsMetadata, RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        let operation = Operation::FsMetadata { path: path.into() };
        let expected = match self.filesystem_expected(&operation)? {
            FilesystemExpected::Execute(expected) => expected,
            FilesystemExpected::Captured(outcome) => return decode_metadata(&operation, outcome),
        };
        let result = self
            .filesystem
            .as_mut()
            .expect("driver was checked")
            .metadata(path);
        let actual = match result {
            Ok(metadata) => Outcome::Metadata(metadata),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_metadata(&operation, outcome)
    }

    pub fn fs_fd_metadata(&mut self, fd: Fd) -> Result<FsMetadata, RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        let operation = Operation::FsFdMetadata { fd };
        let expected = match self.filesystem_expected(&operation)? {
            FilesystemExpected::Execute(expected) => expected,
            FilesystemExpected::Captured(outcome) => return decode_metadata(&operation, outcome),
        };
        let result = self
            .filesystem
            .as_mut()
            .expect("driver was checked")
            .fd_metadata(fd);
        let actual = match result {
            Ok(metadata) => Outcome::Metadata(metadata),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_metadata(&operation, outcome)
    }

    pub fn fs_create_directory(&mut self, path: &str) -> Result<(), RuntimeError> {
        self.filesystem_unit(
            Operation::FsCreateDirectory { path: path.into() },
            |filesystem| filesystem.create_directory(path),
        )
    }

    pub fn fs_remove_file(&mut self, path: &str) -> Result<(), RuntimeError> {
        self.filesystem_unit(
            Operation::FsRemoveFile { path: path.into() },
            |filesystem| filesystem.remove_file(path),
        )
    }

    pub fn fs_sync(&mut self, fd: Fd) -> Result<(), RuntimeError> {
        let result =
            self.filesystem_unit(Operation::FsSync { fd }, |filesystem| filesystem.sync(fd));
        self.maybe_inject_crash(CrashOp::Sync)?;
        result
    }

    pub fn fs_set_len(&mut self, fd: Fd, len: u64) -> Result<(), RuntimeError> {
        self.filesystem_unit(Operation::FsSetLength { fd, len }, |filesystem| {
            filesystem.set_len(fd, len)
        })
    }

    pub fn fs_set_times(
        &mut self,
        fd: Fd,
        atime_nanos: Option<u64>,
        mtime_nanos: Option<u64>,
    ) -> Result<(), RuntimeError> {
        self.filesystem_unit(
            Operation::FsSetTimes {
                fd,
                atime_nanos,
                mtime_nanos,
            },
            |filesystem| filesystem.set_times(fd, atime_nanos, mtime_nanos),
        )
    }

    pub fn fs_set_times_by_path(
        &mut self,
        path: &str,
        atime_nanos: Option<u64>,
        mtime_nanos: Option<u64>,
    ) -> Result<(), RuntimeError> {
        self.filesystem_unit(
            Operation::FsSetTimesByPath {
                path: path.into(),
                atime_nanos,
                mtime_nanos,
            },
            |filesystem| filesystem.set_times_by_path(path, atime_nanos, mtime_nanos),
        )
    }

    pub fn fs_read_directory(&mut self, path: &str) -> Result<Vec<FsDirectoryEntry>, RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        let operation = Operation::FsReadDirectory { path: path.into() };
        let expected = match self.filesystem_expected(&operation)? {
            FilesystemExpected::Execute(expected) => expected,
            FilesystemExpected::Captured(outcome) => {
                return decode_directory_entries(&operation, outcome);
            }
        };
        let result = self
            .filesystem
            .as_mut()
            .expect("driver was checked")
            .read_directory(path);
        let actual = match result {
            Ok(entries) => Outcome::DirectoryEntries(entries),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_directory_entries(&operation, outcome)
    }

    pub fn fs_remove_directory(&mut self, path: &str) -> Result<(), RuntimeError> {
        self.filesystem_unit(
            Operation::FsRemoveDirectory { path: path.into() },
            |filesystem| filesystem.remove_directory(path),
        )
    }

    pub fn fs_rename(&mut self, from: &str, to: &str) -> Result<(), RuntimeError> {
        self.filesystem_unit(
            Operation::FsRename {
                from: from.into(),
                to: to.into(),
            },
            |filesystem| filesystem.rename(from, to),
        )
    }

    pub fn fs_link(&mut self, from: &str, to: &str) -> Result<(), RuntimeError> {
        self.filesystem_unit(
            Operation::FsLink {
                from: from.into(),
                to: to.into(),
            },
            |filesystem| filesystem.link(from, to),
        )
    }

    pub fn fs_symlink(&mut self, target: &str, link_path: &str) -> Result<(), RuntimeError> {
        self.filesystem_unit(
            Operation::FsSymlink {
                target: target.into(),
                link_path: link_path.into(),
            },
            |filesystem| filesystem.symlink(target, link_path),
        )
    }

    pub fn fs_read_link(&mut self, path: &str) -> Result<String, RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        let operation = Operation::FsReadLink { path: path.into() };
        let expected = match self.filesystem_expected(&operation)? {
            FilesystemExpected::Execute(expected) => expected,
            FilesystemExpected::Captured(outcome) => return decode_string(&operation, outcome),
        };
        let result = self
            .filesystem
            .as_mut()
            .expect("driver was checked")
            .read_link(path);
        let actual = match result {
            Ok(target) => Outcome::Bytes(target.into_bytes()),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_string(&operation, outcome)
    }

    pub fn fs_crash(&mut self) -> Result<(), RuntimeError> {
        self.filesystem_unit(Operation::FsCrash, |filesystem| filesystem.crash())
    }

    /// Fire the configured filesystem crash if the just-completed boundary
    /// operation is the selected Nth occurrence. Called after each counted fs op
    /// completes; the crash is injected exactly once. Because the boundary-op
    /// sequence is identical on record and replay, the injected `FsCrash` lands
    /// at the same position and reconciles without the flag being re-supplied
    /// having any different effect (a mismatched flag fails closed like any other
    /// operation divergence).
    fn maybe_inject_crash(&mut self, op: CrashOp) -> Result<(), RuntimeError> {
        if self.crash_fired {
            return Ok(());
        }
        let Some(point) = self.crash_at else {
            return Ok(());
        };
        let count = match op {
            CrashOp::Open => {
                self.crash_counts.open += 1;
                self.crash_counts.open
            }
            CrashOp::Write => {
                self.crash_counts.write += 1;
                self.crash_counts.write
            }
            CrashOp::Sync => {
                self.crash_counts.sync += 1;
                self.crash_counts.sync
            }
            CrashOp::Close => {
                self.crash_counts.close += 1;
                self.crash_counts.close
            }
        };
        if point.op == op && count == point.ordinal {
            self.crash_fired = true;
            self.fs_crash()?;
        }
        Ok(())
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
    /// so the deadlock-rescue in [`Context::scheduler_next`] wakes it when
    /// virtual time reaches the deadline. `deadline_nanos` is interpreted in the
    /// `clock` domain and converted to monotonic at registration through
    /// recorded clock reads, so the registry key is stable across record and
    /// replay.
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
        Ok(())
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
    fn monotonic_deadline(
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
    fn current_monotonic(&mut self) -> Result<u64, RuntimeError> {
        self.clock
            .as_mut()
            .ok_or_else(|| EffectError::missing_driver("clock"))?
            .now(ClockKind::Monotonic)
            .map_err(Into::into)
    }

    /// Whether `scheduler.next()` would report a deadlock: tasks exist but every
    /// one is parked. Derived from the runtime's shadow of scheduler state,
    /// which mirrors the driver op-for-op on both record and replay.
    fn scheduler_would_deadlock(&self) -> bool {
        !self.scheduler_tasks.is_empty()
            && self
                .scheduler_tasks
                .iter()
                .all(|task| self.parked_tasks.contains(task))
    }

    /// Drain the tasks woken by the most recent deadlock-rescue so an embedder
    /// (the native shim) can resolve their timed waits as timeouts. Deterministic
    /// and unrecorded: the rescue populates this identically on record/replay.
    pub fn take_rescued_timeouts(&mut self) -> Vec<TaskId> {
        std::mem::take(&mut self.rescued)
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
            let now = self.current_monotonic()?;
            let due: Vec<TaskId> = self
                .timers
                .iter()
                .take_while(|((deadline, _), _)| *deadline <= now)
                .map(|(_, task)| *task)
                .collect();
            for task in due {
                self.task_wake(task)?;
                self.rescued.push(task);
            }
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
        decode_optional_task(&operation, outcome)
    }

    pub fn net_bind(&mut self, address: &str) -> Result<SocketId, RuntimeError> {
        if self.network.is_none() {
            return Err(EffectError::missing_driver("network").into());
        }
        let operation = Operation::NetBind {
            address: address.into(),
        };
        let expected = self.replay_expected(&operation)?;
        let result = self
            .network
            .as_mut()
            .expect("driver was checked")
            .bind(address);
        let actual = match result {
            Ok(socket) => Outcome::Socket(socket),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_socket(&operation, outcome)
    }

    pub fn net_send(
        &mut self,
        socket: SocketId,
        to: &str,
        bytes: &[u8],
    ) -> Result<SendReport, RuntimeError> {
        if self.network.is_none() {
            return Err(EffectError::missing_driver("network").into());
        }
        let now_nanos = self.now(ClockKind::Monotonic)?;
        let operation = Operation::NetSend {
            socket,
            to: to.into(),
            bytes: bytes.to_vec(),
            now_nanos,
        };
        let expected = self.replay_expected(&operation)?;
        let result = self
            .network
            .as_mut()
            .expect("driver was checked")
            .send(socket, to, bytes, now_nanos);
        let actual = match result {
            Ok(report) => Outcome::SendReport(report),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_send_report(&operation, outcome)
    }

    pub fn net_recv(&mut self, socket: SocketId) -> Result<Option<Datagram>, RuntimeError> {
        if self.network.is_none() {
            return Err(EffectError::missing_driver("network").into());
        }
        let now_nanos = self.now(ClockKind::Monotonic)?;
        let operation = Operation::NetRecv { socket, now_nanos };
        let expected = self.replay_expected(&operation)?;
        let result = self
            .network
            .as_mut()
            .expect("driver was checked")
            .recv(socket, now_nanos);
        let actual = match result {
            Ok(datagram) => Outcome::Datagram(datagram),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_datagram(&operation, outcome)
    }

    pub fn net_next_delivery(&mut self, socket: SocketId) -> Result<Option<u64>, RuntimeError> {
        if self.network.is_none() {
            return Err(EffectError::missing_driver("network").into());
        }
        let now_nanos = self.now(ClockKind::Monotonic)?;
        let operation = Operation::NetNextDelivery { socket, now_nanos };
        let expected = self.replay_expected(&operation)?;
        let result = self
            .network
            .as_ref()
            .expect("driver was checked")
            .next_delivery(socket, now_nanos);
        let actual = match result {
            Ok(deadline) => Outcome::OptionalU64(deadline),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_optional_u64(&operation, outcome)
    }

    pub fn net_close(&mut self, socket: SocketId) -> Result<(), RuntimeError> {
        if self.network.is_none() {
            return Err(EffectError::missing_driver("network").into());
        }
        let operation = Operation::NetClose { socket };
        let expected = self.replay_expected(&operation)?;
        let result = self
            .network
            .as_mut()
            .expect("driver was checked")
            .close(socket);
        let actual = match result {
            Ok(()) => Outcome::Unit,
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_unit(&operation, outcome)
    }

    pub fn net_tcp_listen(
        &mut self,
        address: &str,
        backlog: usize,
    ) -> Result<SocketId, RuntimeError> {
        if self.network.is_none() {
            return Err(EffectError::missing_driver("network").into());
        }
        let operation = Operation::NetTcpListen {
            address: address.into(),
            backlog,
        };
        let expected = self.replay_expected(&operation)?;
        let result = self
            .network
            .as_mut()
            .expect("driver was checked")
            .tcp_listen(address, backlog);
        let actual = match result {
            Ok(socket) => Outcome::Socket(socket),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_socket(&operation, outcome)
    }

    pub fn net_tcp_accept(
        &mut self,
        listener: SocketId,
    ) -> Result<Option<TcpAccepted>, RuntimeError> {
        if self.network.is_none() {
            return Err(EffectError::missing_driver("network").into());
        }
        let now_nanos = self.now(ClockKind::Monotonic)?;
        let operation = Operation::NetTcpAccept {
            listener,
            now_nanos,
        };
        let expected = self.replay_expected(&operation)?;
        let result = self
            .network
            .as_mut()
            .expect("driver was checked")
            .tcp_accept(listener, now_nanos);
        let actual = match result {
            Ok(accepted) => Outcome::TcpAccepted(accepted),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_tcp_accepted(&operation, outcome)
    }

    pub fn net_tcp_connect(&mut self, address: &str, to: &str) -> Result<SocketId, RuntimeError> {
        if self.network.is_none() {
            return Err(EffectError::missing_driver("network").into());
        }
        let now_nanos = self.now(ClockKind::Monotonic)?;
        let operation = Operation::NetTcpConnect {
            address: address.into(),
            to: to.into(),
            now_nanos,
        };
        let expected = self.replay_expected(&operation)?;
        let result = self
            .network
            .as_mut()
            .expect("driver was checked")
            .tcp_connect(address, to, now_nanos);
        let actual = match result {
            Ok(socket) => Outcome::Socket(socket),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_socket(&operation, outcome)
    }

    pub fn net_tcp_send(&mut self, socket: SocketId, bytes: &[u8]) -> Result<usize, RuntimeError> {
        if self.network.is_none() {
            return Err(EffectError::missing_driver("network").into());
        }
        let now_nanos = self.now(ClockKind::Monotonic)?;
        let operation = Operation::NetTcpSend {
            socket,
            bytes: bytes.to_vec(),
            now_nanos,
        };
        let expected = self.replay_expected(&operation)?;
        let result = self
            .network
            .as_mut()
            .expect("driver was checked")
            .tcp_send(socket, bytes, now_nanos);
        let actual = match result {
            Ok(written) => Outcome::Usize(written),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_usize(&operation, outcome)
    }

    pub fn net_tcp_recv(
        &mut self,
        socket: SocketId,
        max_len: usize,
    ) -> Result<Option<Vec<u8>>, RuntimeError> {
        if self.network.is_none() {
            return Err(EffectError::missing_driver("network").into());
        }
        let now_nanos = self.now(ClockKind::Monotonic)?;
        let operation = Operation::NetTcpRecv {
            socket,
            max_len,
            now_nanos,
        };
        let expected = self.replay_expected(&operation)?;
        let result = self
            .network
            .as_mut()
            .expect("driver was checked")
            .tcp_recv(socket, max_len, now_nanos);
        let actual = match result {
            Ok(bytes) => Outcome::OptionalBytes(bytes),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_optional_bytes(&operation, outcome)
    }

    pub fn net_tcp_shutdown(
        &mut self,
        socket: SocketId,
        how: ShutdownHow,
    ) -> Result<(), RuntimeError> {
        if self.network.is_none() {
            return Err(EffectError::missing_driver("network").into());
        }
        let operation = Operation::NetTcpShutdown { socket, how };
        let expected = self.replay_expected(&operation)?;
        let result = self
            .network
            .as_mut()
            .expect("driver was checked")
            .tcp_shutdown(socket, how);
        let actual = match result {
            Ok(()) => Outcome::Unit,
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_unit(&operation, outcome)
    }

    pub fn write_file(&mut self, path: &str, bytes: &[u8]) -> Result<(), RuntimeError> {
        let fd = self.fs_open(path, OpenFlags::create_truncate_write())?;
        let written = self.fs_write(fd, bytes)?;
        if written != bytes.len() {
            return Err(EffectError::new(
                ErrorCode::InvalidInput,
                format!(
                    "short virtual write to {path}: wrote {written} of {} bytes",
                    bytes.len()
                ),
            )
            .into());
        }
        self.fs_close(fd)
    }

    pub fn read_file(&mut self, path: &str) -> Result<Vec<u8>, RuntimeError> {
        let fd = self.fs_open(path, OpenFlags::read_only())?;
        let mut contents = Vec::new();
        loop {
            let chunk = self.fs_read(fd, READ_CHUNK_SIZE)?;
            if chunk.is_empty() {
                break;
            }
            if contents.len().saturating_add(chunk.len()) > MAX_READ_FILE_BYTES {
                return Err(EffectError::new(
                    ErrorCode::InvalidInput,
                    format!("virtual file exceeds read_file limit of {MAX_READ_FILE_BYTES} bytes"),
                )
                .into());
            }
            contents.extend_from_slice(&chunk);
        }
        self.fs_close(fd)?;
        Ok(contents)
    }

    pub fn finish(mut self) -> Result<(), RuntimeError> {
        emit_schedule_report(&self.schedule.diagnostics());
        // Exploration-policy diagnostic (PCT / starvation). Populated from live
        // selection, so it reflects a record/seeded run; a replay reports the
        // inert default because recorded selections bypass the policy.
        if let Some(report) = self.scheduler.as_ref().and_then(|s| s.policy_report()) {
            emit_schedule_policy_report(&report);
        }
        // Liveness-watchdog diagnostic: prove the watchdog was actually armed and
        // ran to a clean finish (it did NOT fire — a fired watchdog aborts before
        // finish()). Default-on so "watchdog enabled, run OK" is never silently
        // vacuous; suppressed by a false-y PATINA_LIVENESS_REPORT.
        if self.liveness.active {
            emit_liveness_report(&self.liveness);
        }
        // Cooperative-SUT diagnostic + metadata. Computed before the execution is
        // consumed so the record sink can fold in the run's realized active-site
        // set and knob picks.
        let buggify_diag = self.buggify_diagnostics();
        emit_sdk_report(&buggify_diag);
        let buggify_record = self.buggify.to_record();
        match self.execution {
            Execution::Seeded => Ok(()),
            Execution::Record { mut recorder, sink } => match sink {
                RecordSink::Path { path, _reservation } => {
                    recorder.set_buggify(buggify_record);
                    recorder.finish(path).map_err(Into::into)
                }
                RecordSink::Transport(mut transport) => {
                    recorder.set_buggify(buggify_record);
                    let bytes = recorder.into_bundle().to_bytes()?;
                    transport
                        .write_bundle(&bytes)
                        .map_err(|source| RuntimeError::Io {
                            action: "write trace bundle to trace transport".into(),
                            source,
                        })
                }
            },
            Execution::Replay(replayer) => replayer.finish().map_err(Into::into),
            Execution::Branch {
                session,
                _reservation,
            } => session.finish().map_err(Into::into),
        }
    }

    fn filesystem_expected(
        &mut self,
        operation: &Operation,
    ) -> Result<FilesystemExpected, RuntimeError> {
        let expected = self.replay_expected(operation)?;
        if !self.filesystem_is_capture {
            return Ok(FilesystemExpected::Execute(expected));
        }
        if let Some((_, outcome)) = expected {
            return Ok(FilesystemExpected::Captured(outcome));
        }
        if matches!(self.execution, Execution::Branch { .. }) {
            return Err(EffectError::new(
                ErrorCode::Denied,
                format!(
                    "host-capture replay reached unrecorded filesystem operation {operation:?}"
                ),
            )
            .into());
        }
        Ok(FilesystemExpected::Execute(None))
    }

    fn filesystem_unit(
        &mut self,
        operation: Operation,
        invoke: impl FnOnce(&mut dyn FsDriver) -> Result<(), EffectError>,
    ) -> Result<(), RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        let expected = match self.filesystem_expected(&operation)? {
            FilesystemExpected::Execute(expected) => expected,
            FilesystemExpected::Captured(outcome) => return decode_unit(&operation, outcome),
        };
        let result = invoke(
            self.filesystem
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

    /// Advance the liveness watchdog for one boundary op. Reads virtual time and
    /// the scheduler's policy-deferral state WITHOUT recording anything or
    /// perturbing selection; returns a [`RuntimeError::Liveness`] (after emitting
    /// the loud, classifiable `PATINA_VIOLATION` line) when a no-progress budget is
    /// exceeded. Inert unless the watchdog is active (record/seeded with a budget
    /// configured), so a plain run and every replay are unaffected.
    fn liveness_track(&mut self, operation: &Operation) -> Result<(), RuntimeError> {
        if !self.liveness.active || self.clock.is_none() {
            return Ok(());
        }
        let now = self.current_monotonic()?;
        let progress = operation_is_progress(operation);
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
            return Err(RuntimeError::Liveness {
                kind: violation.kind,
                detail: marker,
            });
        }
        Ok(())
    }

    fn replay_expected(
        &mut self,
        operation: &Operation,
    ) -> Result<Option<(u64, Outcome)>, RuntimeError> {
        if self.step_budget.is_some_and(|budget| self.steps >= budget) {
            return Err(RuntimeError::StepBudgetExceeded {
                budget: self.step_budget.expect("budget was checked"),
            });
        }
        self.steps += 1;
        self.liveness_track(operation)?;
        match &mut self.execution {
            Execution::Replay(replayer) => {
                let sequence = replayer.consumed();
                Ok(Some((sequence, replayer.expect(operation)?)))
            }
            Execution::Branch { session, .. } => {
                session.expect_prefix(operation).map_err(Into::into)
            }
            _ => Ok(None),
        }
    }

    fn complete(&mut self, operation: Operation, actual: Outcome) -> Outcome {
        match &mut self.execution {
            Execution::Record { recorder, .. } => {
                recorder.observe(operation, actual.clone());
            }
            Execution::Branch { session, .. } => {
                session.observe(operation, actual.clone());
            }
            _ => {}
        }
        actual
    }

    fn reconcile(
        &mut self,
        operation: Operation,
        expected: Option<(u64, Outcome)>,
        actual: Outcome,
    ) -> Result<Outcome, RuntimeError> {
        if let Some((sequence, recorded)) = expected {
            match &self.execution {
                Execution::Replay(replayer) => {
                    replayer.compare_outcome(sequence, &recorded, &actual)?;
                }
                Execution::Branch { session, .. } => {
                    session.compare_outcome(sequence, &recorded, &actual)?;
                }
                _ => {}
            }
            Ok(recorded)
        } else {
            Ok(self.complete(operation, actual))
        }
    }
}

#[derive(Debug)]
pub enum RuntimeError {
    Config(String),
    Io {
        action: String,
        source: std::io::Error,
    },
    Effect(EffectError),
    Trace(TraceError),
    StepBudgetExceeded {
        budget: u64,
    },
    /// The liveness watchdog observed a genuine no-progress wedge: virtual time
    /// advanced past the configured budget with only scheduling/wait churn and no
    /// policy-explained deferral. Loud (a `PATINA_VIOLATION` line was emitted) and
    /// classifiable. `detail` holds the emitted marker line.
    Liveness {
        kind: LivenessKind,
        detail: String,
    },
    InvalidOutcome {
        operation: Box<Operation>,
        outcome: Box<Outcome>,
    },
    RunAndFinalize {
        run: Box<RuntimeError>,
        finalize: Box<RuntimeError>,
    },
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(message) => write!(f, "invalid Patina configuration: {message}"),
            Self::Io { action, source } => write!(f, "failed to {action}: {source}"),
            Self::Effect(error) => error.fmt(f),
            Self::Trace(error) => error.fmt(f),
            Self::StepBudgetExceeded { budget } => {
                write!(
                    f,
                    "Patina step budget of {budget} boundary operations was exhausted"
                )
            }
            Self::Liveness { detail, .. } => {
                write!(f, "Patina liveness watchdog violation: {detail}")
            }
            Self::InvalidOutcome { operation, outcome } => write!(
                f,
                "invalid outcome {outcome:?} for Patina operation {operation:?}"
            ),
            Self::RunAndFinalize { run, finalize } => write!(
                f,
                "Patina run failed ({run}) and trace finalization also failed ({finalize})"
            ),
        }
    }
}

impl std::error::Error for RuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Effect(error) => Some(error),
            Self::Trace(error) => Some(error),
            Self::RunAndFinalize { run, .. } => Some(run),
            _ => None,
        }
    }
}

impl From<EffectError> for RuntimeError {
    fn from(value: EffectError) -> Self {
        Self::Effect(value)
    }
}

impl From<TraceError> for RuntimeError {
    fn from(value: TraceError) -> Self {
        Self::Trace(value)
    }
}

fn record_lock_path(trace_path: &Path) -> Result<PathBuf, RuntimeError> {
    let file_name = trace_path.file_name().ok_or_else(|| {
        RuntimeError::Config(format!(
            "trace path has no file name: {}",
            trace_path.display()
        ))
    })?;
    let mut lock_name = OsString::from(".");
    lock_name.push(file_name);
    lock_name.push(".lock");
    Ok(trace_path.with_file_name(lock_name))
}

/// Parse the documented `PATINA_TRACE_FD` variable into a raw descriptor.
///
/// Embedders that can service the descriptor (for example the native shim)
/// use this to build a [`TraceTransport`]; `RuntimeConfig::from_env` uses it
/// to select the transport execution modes.
pub fn trace_fd_from_env() -> Result<Option<i32>, RuntimeError> {
    match env::var(ENV_TRACE_FD) {
        Ok(value) => {
            let fd: i32 = value.parse().map_err(|_| {
                RuntimeError::Config(format!("{ENV_TRACE_FD} must be a non-negative descriptor"))
            })?;
            if fd < 0 {
                return Err(RuntimeError::Config(format!(
                    "{ENV_TRACE_FD} must be a non-negative descriptor"
                )));
            }
            Ok(Some(fd))
        }
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => Err(RuntimeError::Config(format!(
            "{ENV_TRACE_FD} must be valid UTF-8"
        ))),
    }
}

/// Parse a `close:1`/`write:3`/`sync:2`/`open:1` crash point. A bare op name
/// (`close`) means the first occurrence.
fn parse_crash_point(value: &str) -> Result<CrashPoint, RuntimeError> {
    let (op_text, ordinal) = match value.split_once(':') {
        Some((op_text, ordinal_text)) => {
            let ordinal = ordinal_text.parse::<u64>().map_err(|_| {
                RuntimeError::Config(format!(
                    "{ENV_FS_CRASH_AT} ordinal must be a positive integer: {value:?}"
                ))
            })?;
            (op_text, ordinal)
        }
        None => (value, 1),
    };
    if ordinal == 0 {
        return Err(RuntimeError::Config(format!(
            "{ENV_FS_CRASH_AT} ordinal is 1-based and must be at least 1: {value:?}"
        )));
    }
    let op = match op_text {
        "open" => CrashOp::Open,
        "write" => CrashOp::Write,
        "sync" => CrashOp::Sync,
        "close" => CrashOp::Close,
        other => {
            return Err(RuntimeError::Config(format!(
                "{ENV_FS_CRASH_AT} op must be open, write, sync, or close; got {other:?}"
            )));
        }
    };
    Ok(CrashPoint { op, ordinal })
}

fn parse_torn_granularity(value: &str) -> Result<TornGranularity, RuntimeError> {
    match value {
        "block" => Ok(TornGranularity::Block),
        "byte" => Ok(TornGranularity::Byte),
        other => Err(RuntimeError::Config(format!(
            "{ENV_FS_TORN_GRANULARITY} must be block or byte; got {other:?}"
        ))),
    }
}

/// Map the runtime crash op to the serializable trace-record op.
fn crash_op_to_record(op: CrashOp) -> patina_dst_trace::FaultCrashOp {
    match op {
        CrashOp::Open => patina_dst_trace::FaultCrashOp::Open,
        CrashOp::Write => patina_dst_trace::FaultCrashOp::Write,
        CrashOp::Sync => patina_dst_trace::FaultCrashOp::Sync,
        CrashOp::Close => patina_dst_trace::FaultCrashOp::Close,
    }
}

fn crash_op_from_record(op: patina_dst_trace::FaultCrashOp) -> CrashOp {
    match op {
        patina_dst_trace::FaultCrashOp::Open => CrashOp::Open,
        patina_dst_trace::FaultCrashOp::Write => CrashOp::Write,
        patina_dst_trace::FaultCrashOp::Sync => CrashOp::Sync,
        patina_dst_trace::FaultCrashOp::Close => CrashOp::Close,
    }
}

fn torn_granularity_to_record(granularity: TornGranularity) -> patina_dst_trace::TornGranularity {
    match granularity {
        TornGranularity::Block => patina_dst_trace::TornGranularity::Block,
        TornGranularity::Byte => patina_dst_trace::TornGranularity::Byte,
    }
}

fn torn_granularity_from_record(granularity: patina_dst_trace::TornGranularity) -> TornGranularity {
    match granularity {
        patina_dst_trace::TornGranularity::Block => TornGranularity::Block,
        patina_dst_trace::TornGranularity::Byte => TornGranularity::Byte,
    }
}

/// Resolve the heal-then-converge arm-time for a config: an explicit override,
/// else the buggify damage-control cutoff (when buggify is enabled), else run
/// start. Shared by the metadata record and the built watchdog so they agree.
fn resolve_heal_after(config: &RuntimeConfig) -> u64 {
    match config.liveness.heal_after_nanos {
        Some(nanos) => nanos,
        None if config.buggify.enabled => config.buggify.cutoff_nanos,
        None => 0,
    }
}

/// Serialize the run's liveness-watchdog configuration into the trace metadata.
/// Informational only — NOT a fingerprint input and NOT reconciled on replay,
/// because the watchdog is schedule-invariant. `None` when the watchdog is off.
fn watchdog_record(config: &RuntimeConfig) -> Option<patina_dst_trace::WatchdogConfigRecord> {
    if !config.liveness.is_enabled() {
        return None;
    }
    Some(patina_dst_trace::WatchdogConfigRecord {
        no_progress_budget_nanos: config.liveness.no_progress_budget_nanos,
        converge_budget_nanos: config.liveness.converge_budget_nanos,
        heal_after_nanos: config
            .liveness
            .converge_budget_nanos
            .map(|_| resolve_heal_after(config)),
    })
}

/// Serialize the run's effective fault configuration into the trace record so a
/// fault run replays self-contained. `net_latency_nanos` is folded in because it
/// too shapes the recorded operation stream, so a flag-free replay must restore
/// it as well.
fn fault_record(config: &RuntimeConfig) -> patina_dst_trace::FaultConfigRecord {
    patina_dst_trace::FaultConfigRecord {
        crash_at: config
            .faults
            .crash_at
            .map(|point| patina_dst_trace::CrashPointRecord {
                op: crash_op_to_record(point.op),
                ordinal: point.ordinal,
            }),
        torn_granularity: torn_granularity_to_record(config.faults.torn_granularity),
        sleep_jitter_nanos: config.faults.sleep_jitter_nanos,
        net_jitter_nanos: config.faults.net_jitter_nanos,
        net_drop_permille: config.faults.net_drop_permille,
        net_latency_nanos: config.net_latency_nanos,
    }
}

/// Rebuild the runtime fault configuration and base net latency from a recorded
/// trace's authoritative fault metadata.
fn fault_config_from_record(record: &patina_dst_trace::FaultConfigRecord) -> (FaultConfig, u64) {
    let faults = FaultConfig {
        crash_at: record.crash_at.map(|point| CrashPoint {
            op: crash_op_from_record(point.op),
            ordinal: point.ordinal,
        }),
        torn_granularity: torn_granularity_from_record(record.torn_granularity),
        sleep_jitter_nanos: record.sleep_jitter_nanos,
        net_jitter_nanos: record.net_jitter_nanos,
        net_drop_permille: record.net_drop_permille,
    };
    (faults, record.net_latency_nanos)
}

/// Reconcile a recorded trace's authoritative fault configuration with any fault
/// knobs the operator also supplied at replay. The trace is authoritative: when
/// no knobs are supplied (the default), the stored configuration is adopted
/// verbatim so replay is byte-identical; when knobs ARE supplied they must match
/// the recording exactly or replay fails closed rather than silently running a
/// different fault schedule. A pre-metadata trace (`None`) keeps the historical
/// re-supply behavior.
fn reconcile_replay_faults(
    config: &RuntimeConfig,
    recorded: Option<&patina_dst_trace::FaultConfigRecord>,
) -> Result<Option<(FaultConfig, u64)>, RuntimeError> {
    let Some(record) = recorded else {
        return Ok(None);
    };
    let (stored_faults, stored_latency) = fault_config_from_record(record);
    let supplied_any = config.faults != FaultConfig::default() || config.net_latency_nanos != 0;
    if supplied_any
        && (config.faults != stored_faults || config.net_latency_nanos != stored_latency)
    {
        return Err(RuntimeError::Config(
            "replay fault knobs conflict with the trace's recorded configuration; \
             the trace is authoritative, so omit the flags (or supply matching values)"
                .into(),
        ));
    }
    Ok(Some((stored_faults, stored_latency)))
}

/// The buggify configuration recorded into a trace at build time. `active_sites`
/// and `knobs` are filled in at finalization from the run's realized picks; here
/// they start empty. `None` when buggify is disabled, so a disabled run records
/// no buggify metadata at all and is indistinguishable from an old trace.
fn buggify_record(config: &RuntimeConfig) -> Option<patina_dst_trace::BuggifyConfigRecord> {
    if !config.buggify.enabled {
        return None;
    }
    Some(patina_dst_trace::BuggifyConfigRecord {
        fire_permille: config.buggify.fire_permille,
        activation_permille: config.buggify.activation_permille,
        cutoff_nanos: config.buggify.cutoff_nanos,
        after_setup: config.buggify.after_setup,
        active_sites: Vec::new(),
        knobs: BTreeMap::new(),
    })
}

/// Rebuild a [`BuggifyConfig`] from a recorded trace's authoritative buggify
/// metadata.
fn buggify_config_from_record(record: &patina_dst_trace::BuggifyConfigRecord) -> BuggifyConfig {
    BuggifyConfig {
        enabled: true,
        fire_permille: record.fire_permille,
        activation_permille: record.activation_permille,
        cutoff_nanos: record.cutoff_nanos,
        after_setup: record.after_setup,
    }
}

/// Reconcile a recorded trace's authoritative buggify configuration with any
/// buggify knobs the operator also supplied at replay, mirroring
/// [`reconcile_replay_faults`]. The trace is authoritative: with no knobs the
/// stored config is adopted verbatim (byte-identical replay); supplied knobs
/// must match exactly or replay fails closed. A trace recorded without buggify
/// (`None`) means the operator's configuration stands — and if the operator
/// tries to enable buggify on a non-buggify trace, that is caught earlier by the
/// `+buggify` fingerprint mismatch.
fn reconcile_replay_buggify(
    config: &RuntimeConfig,
    recorded: Option<&patina_dst_trace::BuggifyConfigRecord>,
) -> Result<Option<BuggifyConfig>, RuntimeError> {
    let Some(record) = recorded else {
        return Ok(None);
    };
    let stored = buggify_config_from_record(record);
    if config.buggify.enabled && config.buggify != stored {
        return Err(RuntimeError::Config(
            "replay buggify knobs conflict with the trace's recorded configuration; \
             the trace is authoritative, so omit the flags (or supply matching values)"
                .into(),
        ));
    }
    Ok(Some(stored))
}

/// The exploration scheduling policy recorded into a trace at build time. `None`
/// under the default uniform policy, so a default run records no policy metadata
/// at all and is indistinguishable from an old trace.
fn schedule_policy_record(
    config: &RuntimeConfig,
) -> Option<patina_dst_trace::SchedulePolicyRecord> {
    let policy = config.schedule_policy;
    if policy.is_default() {
        return None;
    }
    Some(patina_dst_trace::SchedulePolicyRecord {
        pct: policy.pct.map(|pct| patina_dst_trace::PctPolicyRecord {
            depth: pct.depth,
            steps: pct.steps,
        }),
        starvation: policy
            .starvation
            .map(|starve| patina_dst_trace::StarvationPolicyRecord {
                intervals: starve.intervals,
                max_len: starve.max_len,
                window: starve.window,
            }),
    })
}

/// Rebuild a [`SchedulePolicy`] from a recorded trace's authoritative policy
/// metadata.
fn schedule_policy_from_record(record: &patina_dst_trace::SchedulePolicyRecord) -> SchedulePolicy {
    SchedulePolicy {
        pct: record.pct.map(|pct| PctConfig {
            depth: pct.depth,
            steps: pct.steps,
        }),
        starvation: record.starvation.map(|starve| StarvationConfig {
            intervals: starve.intervals,
            max_len: starve.max_len,
            window: starve.window,
        }),
    }
}

/// Reconcile a recorded trace's authoritative exploration scheduling policy with
/// any policy the operator also supplied at replay, mirroring
/// [`reconcile_replay_faults`]. The trace is authoritative: with no policy
/// supplied the stored one is adopted verbatim; a conflicting supplied policy
/// fails closed. A trace recorded under the default policy (`None`) leaves the
/// operator's configuration in place — and an operator trying to *enable* a
/// policy on a default trace is caught earlier by the `+pct`/`+starve`
/// fingerprint mismatch.
fn reconcile_replay_schedule_policy(
    config: &RuntimeConfig,
    recorded: Option<&patina_dst_trace::SchedulePolicyRecord>,
) -> Result<Option<SchedulePolicy>, RuntimeError> {
    let Some(record) = recorded else {
        return Ok(None);
    };
    let stored = schedule_policy_from_record(record);
    if !config.schedule_policy.is_default() && config.schedule_policy != stored {
        return Err(RuntimeError::Config(
            "replay scheduling-policy knobs conflict with the trace's recorded configuration; \
             the trace is authoritative, so omit the flags (or supply matching values)"
                .into(),
        ));
    }
    Ok(Some(stored))
}

/// Apply swarm fault-class selection to a record/seeded run's configuration: for
/// each enabled fault class, a domain-separated seed-derived coin decides whether
/// it stays active this generation. The masked configuration is what every driver
/// and the recorded [`FaultConfigRecord`] then consume, so replay reproduces the
/// selected subset verbatim; the returned [`SwarmConfigRecord`] documents the
/// candidate set and the seed's selection so the trace is self-describing. Each
/// class draws independently, so subsets vary across generations (seeds).
fn apply_swarm_mask(config: &mut RuntimeConfig) -> patina_dst_trace::SwarmConfigRecord {
    // Stable class tokens paired with a live predicate and a dropper. A class is
    // a candidate only when currently enabled (non-default).
    let mut candidates: Vec<&'static str> = Vec::new();
    let mut selected: Vec<String> = Vec::new();
    let seed = config.seed;
    // Independent per-class coin, domain-separated from every other seeded stream
    // and from the other classes by hashing the class token into the draw.
    let keep = |class: &str| -> bool {
        let mut rng = SplitMix64::new(seed ^ 0x5A20_4C1A_5500_5EED ^ splitmix_hash_str(class));
        rng.next_u64() & 1 == 1
    };

    if config.faults.crash_at.is_some()
        || config.faults.torn_granularity != TornGranularity::default()
    {
        candidates.push("crash");
        if keep("crash") {
            selected.push("crash".into());
        } else {
            config.faults.crash_at = None;
            config.faults.torn_granularity = TornGranularity::default();
        }
    }
    if config.faults.sleep_jitter_nanos.is_some() {
        candidates.push("sleep_jitter");
        if keep("sleep_jitter") {
            selected.push("sleep_jitter".into());
        } else {
            config.faults.sleep_jitter_nanos = None;
        }
    }
    if config.faults.net_jitter_nanos.is_some() {
        candidates.push("net_jitter");
        if keep("net_jitter") {
            selected.push("net_jitter".into());
        } else {
            config.faults.net_jitter_nanos = None;
        }
    }
    if config.faults.net_drop_permille != 0 {
        candidates.push("net_drop");
        if keep("net_drop") {
            selected.push("net_drop".into());
        } else {
            config.faults.net_drop_permille = 0;
        }
    }
    if config.net_latency_nanos != 0 {
        candidates.push("net_latency");
        if keep("net_latency") {
            selected.push("net_latency".into());
        } else {
            config.net_latency_nanos = 0;
        }
    }
    if config.buggify.enabled {
        candidates.push("buggify");
        if keep("buggify") {
            selected.push("buggify".into());
        } else {
            config.buggify.enabled = false;
        }
    }

    patina_dst_trace::SwarmConfigRecord {
        candidate_classes: candidates.into_iter().map(String::from).collect(),
        selected_classes: selected,
    }
}

/// A stable SplitMix64-style hash of a class token, for domain-separating swarm
/// per-class coins. Order-independent and platform-independent.
fn splitmix_hash_str(text: &str) -> u64 {
    let mut state: u64 = 0xD1B5_4A32_D192_ED03;
    for byte in text.bytes() {
        state = state
            .wrapping_add(u64::from(byte))
            .wrapping_add(0x9E37_79B9_7F4A_7C15);
        state = (state ^ (state >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        state = (state ^ (state >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        state ^= state >> 31;
    }
    state
}

/// Emit the default-on liveness-watchdog diagnostic at a clean finish. Proves the
/// watchdog was armed and did not fire (a fired watchdog aborts before finish), so
/// "watchdog on, run OK" is demonstrably non-vacuous. Suppressed by a false-y
/// `PATINA_LIVENESS_REPORT`.
fn emit_liveness_report(watchdog: &LivenessWatchdog) {
    if let Ok(value) = env::var(ENV_LIVENESS_REPORT) {
        if matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "0" | "off" | "false" | "no"
        ) {
            return;
        }
    }
    let mut line = format!(
        "PATINA_LIVENESS_REPORT armed={} fired={}",
        watchdog.arms.len(),
        u8::from(watchdog.fired),
    );
    for arm in &watchdog.arms {
        line.push_str(&format!(
            " {}=budget{}/armed{}/stall{}",
            arm.kind.as_str(),
            arm.budget_nanos,
            u8::from(arm.armed),
            arm.stall_ops,
        ));
    }
    eprintln!("{line}");
}

/// Emit the default-on schedule-exploration diagnostic to stderr for a
/// multithreaded run. Single-task runs (no concurrency to explore) stay silent.
/// The machine-readable `PATINA_SCHEDULE_REPORT` line lets a campaign tell a
/// genuinely-explored "all clean" from a vacuous one; a loud warning fires when
/// a spawned worker ran start-to-finish with zero scheduling boundaries.
fn emit_schedule_report(diag: &ScheduleDiagnostics) {
    if !diag.had_concurrency() {
        return;
    }
    if let Ok(value) = env::var(ENV_SCHEDULE_REPORT) {
        if matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "0" | "off" | "false" | "no"
        ) {
            return;
        }
    }
    let mut line = format!(
        "PATINA_SCHEDULE_REPORT tasks_spawned={} max_concurrent={} total_boundaries={} vacuous_threads={}",
        diag.tasks_spawned,
        diag.max_concurrent,
        diag.total_boundaries,
        diag.vacuous.len(),
    );
    for stat in &diag.tasks {
        line.push_str(&format!(
            " task{}={}y+{}p/life={}/cause={}",
            stat.task.0,
            stat.yields,
            stat.parks,
            stat.lifetime,
            stat.cause.as_str()
        ));
    }
    eprintln!("{line}");
    if !diag.vacuous.is_empty() {
        let ids = diag
            .vacuous
            .iter()
            .map(|task| task.0.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        eprintln!(
            "PATINA WARNING: vacuous schedule exploration — {} spawned thread(s) (task id {ids}) ran \
to completion with no more scheduling boundaries than thread spawn/join alone incurs. Any loop in \
their body was atomics-only and thus invisible to the scheduler, so their internal interleavings \
are UNREACHABLE at any seed and a clean result here does NOT mean the concurrency was tested. \
Rebuild with `cargo patina build --yield-points` to make atomics-only race windows \
schedulable.",
            diag.vacuous.len(),
        );
    }
}

/// Emit the machine-readable `PATINA_SCHEDULE_POLICY` line for a run that used an
/// exploration scheduling policy (PCT / starvation). One line, same spirit as
/// `PATINA_SCHEDULE_REPORT`: a sweep parses it to annotate a found failure with a
/// bug-depth estimate and to detect a vacuous starvation configuration. Suppressed
/// by a false-y [`ENV_SCHEDULE_POLICY_REPORT`].
fn emit_schedule_policy_report(report: &patina_dst_driver_api::SchedulePolicyReport) {
    if !report.is_active() {
        return;
    }
    if let Ok(value) = env::var(ENV_SCHEDULE_POLICY_REPORT) {
        if matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "0" | "off" | "false" | "no"
        ) {
            return;
        }
    }
    eprintln!(
        "PATINA_SCHEDULE_POLICY pct={} pct_depth={} pct_change_points={} pct_change_points_hit={} \
starvation={} starve_events={} starve_vacuous={} decisions={} bug_depth={}",
        u8::from(report.pct),
        report.pct_depth,
        report.pct_change_points,
        report.pct_change_points_hit,
        u8::from(report.starvation),
        report.starve_events,
        report.starve_vacuous,
        report.decisions,
        report.bug_depth(),
    );
    if report.starve_vacuous > 0 {
        eprintln!(
            "PATINA WARNING: vacuous starvation configuration — {} scheduling decision(s) would have \
starved every runnable task and were forced to schedule anyway to preserve liveness. A starvation \
configuration that routinely starves the only runnable task is testing nothing; narrow the starved \
subset or the interval window.",
            report.starve_vacuous,
        );
    }
}

/// Emit the machine-readable `PATINA_SDK_REPORT` line for a run that registered
/// any cooperative-SUT sites (or enabled buggify). One line, same spirit as
/// `PATINA_SCHEDULE_REPORT`: a campaign parses it to accumulate per-site coverage
/// across generations. Suppressed by a false-y [`ENV_SDK_REPORT`]. Per-site token
/// is `site=<label>|<kind>|a<0|1>|e<evals>|f<fires>|r<0|1>|s<0|1>|v<0|1>|k<knob|->`.
fn emit_sdk_report(diag: &BuggifyDiagnostics) {
    if !diag.enabled && diag.sites_registered == 0 {
        return;
    }
    if let Ok(value) = env::var(ENV_SDK_REPORT) {
        if matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "0" | "off" | "false" | "no"
        ) {
            return;
        }
    }
    let mut line = format!(
        "PATINA_SDK_REPORT enabled={} fire_permille={} activation_permille={} cutoff_nanos={} \
cutoff_reached={} sites_registered={} sites_activated={} total_firings={} cutoff_suppressed={} \
after_setup={} setup_complete={}",
        u8::from(diag.enabled),
        diag.fire_permille,
        diag.activation_permille,
        diag.cutoff_nanos,
        u8::from(diag.cutoff_reached),
        diag.sites_registered,
        diag.sites_activated,
        diag.total_firings,
        diag.cutoff_suppressed,
        u8::from(diag.after_setup),
        u8::from(diag.setup_complete),
    );
    for site in &diag.sites {
        let knob = site
            .knob
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string());
        line.push_str(&format!(
            " site={}|{}|a{}|e{}|f{}|r{}|s{}|v{}|k{}",
            site.label,
            site.kind.as_str(),
            u8::from(site.active),
            site.evals,
            site.fires,
            u8::from(site.reachable),
            u8::from(site.sometimes_satisfied),
            u8::from(site.always_violated),
            knob,
        ));
    }
    eprintln!("{line}");
}

/// Parse an inclusive `MIN..MAX` nanosecond range, requiring `MIN <= MAX`.
fn parse_permille(name: &str, value: &str) -> Result<u16, RuntimeError> {
    let permille: u16 = value
        .parse()
        .map_err(|_| RuntimeError::Config(format!("{name} must be an integer in [0, 1000]")))?;
    if permille > 1000 {
        return Err(RuntimeError::Config(format!(
            "{name} must be within [0, 1000] per-mille"
        )));
    }
    Ok(permille)
}

fn parse_nanos_range(name: &str, value: &str) -> Result<(u64, u64), RuntimeError> {
    let (min_text, max_text) = value.split_once("..").ok_or_else(|| {
        RuntimeError::Config(format!("{name} must be a MIN..MAX range; got {value:?}"))
    })?;
    let min = min_text
        .parse::<u64>()
        .map_err(|_| RuntimeError::Config(format!("{name} MIN must be an unsigned integer")))?;
    let max = max_text
        .parse::<u64>()
        .map_err(|_| RuntimeError::Config(format!("{name} MAX must be an unsigned integer")))?;
    if min > max {
        return Err(RuntimeError::Config(format!(
            "{name} requires MIN <= MAX; got {value:?}"
        )));
    }
    Ok((min, max))
}

fn parse_seed(value: Option<String>) -> Result<u64, RuntimeError> {
    value.map_or(Ok(0), |value| {
        value.parse().map_err(|_| {
            RuntimeError::Config(format!("{ENV_SEED} must be an unsigned 64-bit integer"))
        })
    })
}

fn required_u64(name: &str) -> Result<u64, RuntimeError> {
    required_string(name)?
        .parse()
        .map_err(|_| RuntimeError::Config(format!("{name} must be an unsigned 64-bit integer")))
}

fn required_path(name: &str) -> Result<PathBuf, RuntimeError> {
    env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| RuntimeError::Config(format!("{name} is required for this mode")))
}

fn required_string(name: &str) -> Result<String, RuntimeError> {
    env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| RuntimeError::Config(format!("{name} is required for this mode")))
}

fn invalid_outcome(operation: &Operation, outcome: Outcome) -> RuntimeError {
    RuntimeError::InvalidOutcome {
        operation: Box::new(operation.clone()),
        outcome: Box::new(outcome),
    }
}

fn decode_unit(operation: &Operation, outcome: Outcome) -> Result<(), RuntimeError> {
    match outcome {
        Outcome::Unit => Ok(()),
        Outcome::Error(error) => Err(error.into()),
        other => Err(invalid_outcome(operation, other)),
    }
}

fn decode_handle(operation: &Operation, outcome: Outcome) -> Result<Fd, RuntimeError> {
    match outcome {
        Outcome::Handle(fd) => Ok(fd),
        Outcome::Error(error) => Err(error.into()),
        other => Err(invalid_outcome(operation, other)),
    }
}

fn decode_bytes(operation: &Operation, outcome: Outcome) -> Result<Vec<u8>, RuntimeError> {
    match outcome {
        Outcome::Bytes(bytes) => Ok(bytes),
        Outcome::Error(error) => Err(error.into()),
        other => Err(invalid_outcome(operation, other)),
    }
}

fn decode_string(operation: &Operation, outcome: Outcome) -> Result<String, RuntimeError> {
    let bytes = decode_bytes(operation, outcome)?;
    String::from_utf8(bytes).map_err(|error| {
        EffectError::new(
            ErrorCode::InvalidInput,
            format!("filesystem read_link target is not UTF-8: {error}"),
        )
        .into()
    })
}

fn decode_u64(operation: &Operation, outcome: Outcome) -> Result<u64, RuntimeError> {
    match outcome {
        Outcome::U64(value) => Ok(value),
        Outcome::Error(error) => Err(error.into()),
        other => Err(invalid_outcome(operation, other)),
    }
}

fn decode_usize(operation: &Operation, outcome: Outcome) -> Result<usize, RuntimeError> {
    match outcome {
        Outcome::Usize(value) => Ok(value),
        Outcome::Error(error) => Err(error.into()),
        other => Err(invalid_outcome(operation, other)),
    }
}

fn decode_metadata(operation: &Operation, outcome: Outcome) -> Result<FsMetadata, RuntimeError> {
    match outcome {
        Outcome::Metadata(metadata) => Ok(metadata),
        Outcome::Error(error) => Err(error.into()),
        other => Err(invalid_outcome(operation, other)),
    }
}

fn decode_directory_entries(
    operation: &Operation,
    outcome: Outcome,
) -> Result<Vec<FsDirectoryEntry>, RuntimeError> {
    match outcome {
        Outcome::DirectoryEntries(entries) => Ok(entries),
        Outcome::Error(error) => Err(error.into()),
        other => Err(invalid_outcome(operation, other)),
    }
}

fn decode_task(operation: &Operation, outcome: Outcome) -> Result<TaskId, RuntimeError> {
    match outcome {
        Outcome::Task(task) => Ok(task),
        Outcome::Error(error) => Err(error.into()),
        other => Err(invalid_outcome(operation, other)),
    }
}

fn decode_optional_task(
    operation: &Operation,
    outcome: Outcome,
) -> Result<Option<TaskId>, RuntimeError> {
    match outcome {
        Outcome::OptionalTask(task) => Ok(task),
        Outcome::Error(error) => Err(error.into()),
        other => Err(invalid_outcome(operation, other)),
    }
}

fn decode_socket(operation: &Operation, outcome: Outcome) -> Result<SocketId, RuntimeError> {
    match outcome {
        Outcome::Socket(socket) => Ok(socket),
        Outcome::Error(error) => Err(error.into()),
        other => Err(invalid_outcome(operation, other)),
    }
}

fn decode_send_report(operation: &Operation, outcome: Outcome) -> Result<SendReport, RuntimeError> {
    match outcome {
        Outcome::SendReport(report) => Ok(report),
        Outcome::Error(error) => Err(error.into()),
        other => Err(invalid_outcome(operation, other)),
    }
}

fn decode_optional_u64(
    operation: &Operation,
    outcome: Outcome,
) -> Result<Option<u64>, RuntimeError> {
    match outcome {
        Outcome::OptionalU64(value) => Ok(value),
        Outcome::Error(error) => Err(error.into()),
        other => Err(invalid_outcome(operation, other)),
    }
}

fn decode_datagram(
    operation: &Operation,
    outcome: Outcome,
) -> Result<Option<Datagram>, RuntimeError> {
    match outcome {
        Outcome::Datagram(datagram) => Ok(datagram),
        Outcome::Error(error) => Err(error.into()),
        other => Err(invalid_outcome(operation, other)),
    }
}

fn decode_tcp_accepted(
    operation: &Operation,
    outcome: Outcome,
) -> Result<Option<TcpAccepted>, RuntimeError> {
    match outcome {
        Outcome::TcpAccepted(accepted) => Ok(accepted),
        Outcome::Error(error) => Err(error.into()),
        other => Err(invalid_outcome(operation, other)),
    }
}

fn decode_optional_bytes(
    operation: &Operation,
    outcome: Outcome,
) -> Result<Option<Vec<u8>>, RuntimeError> {
    match outcome {
        Outcome::OptionalBytes(bytes) => Ok(bytes),
        Outcome::Error(error) => Err(error.into()),
        other => Err(invalid_outcome(operation, other)),
    }
}

#[cfg(test)]
mod tests {
    use patina_dst_abi::ErrorCode;
    use patina_dst_fs_crash::CrashFs;
    use patina_dst_fs_host::HostCaptureFs;
    use tempfile::tempdir;

    use super::*;

    fn buggify_context(seed: u64, config: BuggifyConfig) -> Context {
        Context::from_config(RuntimeConfig::seeded(seed).with_buggify(config)).unwrap()
    }

    const BUGGIFY_ALL_ACTIVE: BuggifyConfig = BuggifyConfig {
        enabled: true,
        fire_permille: DEFAULT_BUGGIFY_FIRE_PERMILLE,
        activation_permille: 1000,
        cutoff_nanos: DEFAULT_BUGGIFY_CUTOFF_NANOS,
        after_setup: false,
    };

    #[test]
    fn buggify_activation_is_a_deterministic_function_of_seed_and_label() {
        // Same (seed, label, permille) always agrees; the realized fraction of
        // active sites tracks the activation per-mille.
        let buggify = Buggify::new(
            BuggifyConfig {
                enabled: true,
                activation_permille: 250,
                ..BuggifyConfig::default()
            },
            7,
        );
        let mut active = 0;
        for index in 0..2000 {
            let hash = label_hash(&format!("site-{index}"));
            let decision = buggify.label_is_active(hash);
            assert_eq!(
                decision,
                buggify.label_is_active(hash),
                "activation is stable"
            );
            if decision {
                active += 1;
            }
        }
        // ~25% of 2000, generous band for a 2000-sample draw.
        assert!(
            (400..=600).contains(&active),
            "activation fraction off: {active}"
        );

        // A different seed reshuffles which labels are active.
        let other = Buggify::new(
            BuggifyConfig {
                enabled: true,
                activation_permille: 250,
                ..BuggifyConfig::default()
            },
            8,
        );
        let differ = (0..2000).any(|index| {
            let hash = label_hash(&format!("site-{index}"));
            buggify.label_is_active(hash) != other.label_is_active(hash)
        });
        assert!(differ, "distinct seeds must reshuffle activation");
    }

    #[test]
    fn buggify_firing_prf_is_deterministic_and_seed_varying() {
        let fire_pattern = |seed: u64| {
            let mut context = buggify_context(seed, BUGGIFY_ALL_ACTIVE);
            (0..40)
                .map(|_| {
                    matches!(
                        context
                            .buggify_evaluate("commit-early-return", "f.rs:1", None)
                            .unwrap(),
                        SiteOutcome::Fire
                    )
                })
                .collect::<Vec<_>>()
        };
        // Byte-identical across two fresh contexts at the same seed.
        assert_eq!(fire_pattern(5), fire_pattern(5));
        // Some firings occurred (fire_permille = 250 over 40 evals).
        assert!(
            fire_pattern(5).iter().any(|fired| *fired),
            "no firing at seed 5"
        );
        // A different seed yields a different firing pattern.
        assert_ne!(fire_pattern(5), fire_pattern(6));
    }

    #[test]
    fn buggify_duplicate_label_is_detected() {
        let mut context = buggify_context(1, BUGGIFY_ALL_ACTIVE);
        // Same label, same call site: fine (re-evaluation).
        assert_ne!(
            context.buggify_evaluate("dup", "a.rs:1", None).unwrap(),
            SiteOutcome::DuplicateLabel
        );
        assert_ne!(
            context.buggify_evaluate("dup", "a.rs:1", None).unwrap(),
            SiteOutcome::DuplicateLabel
        );
        // Same label at a DIFFERENT call site: fatal duplicate.
        assert_eq!(
            context.buggify_evaluate("dup", "b.rs:9", None).unwrap(),
            SiteOutcome::DuplicateLabel
        );
        // A collision across macro kinds is caught too.
        assert_eq!(
            context.always_check("dup", "c.rs:3", true).unwrap(),
            SiteOutcome::DuplicateLabel
        );
    }

    #[test]
    fn buggify_disabled_is_inert_and_records_nothing() {
        let mut context = buggify_context(3, BuggifyConfig::default());
        for _ in 0..100 {
            assert_eq!(
                context.buggify_evaluate("never", "x.rs:1", None).unwrap(),
                SiteOutcome::Ok
            );
        }
        // always! still fires its invariant even with buggify disabled.
        assert_eq!(
            context.always_check("inv", "x.rs:2", false).unwrap(),
            SiteOutcome::AlwaysViolation
        );
        let diag = context.buggify_diagnostics();
        assert!(!diag.enabled);
        assert_eq!(diag.total_firings, 0);
        assert_eq!(context.buggify.to_record(), None);
    }

    #[test]
    fn buggify_knob_is_deterministic_and_in_range() {
        let mut a = buggify_context(9, BUGGIFY_ALL_ACTIVE);
        let mut b = buggify_context(9, BUGGIFY_ALL_ACTIVE);
        let va = a
            .buggify_knob("batch", "k.rs:1", 10, 1, 100)
            .unwrap()
            .unwrap();
        let vb = b
            .buggify_knob("batch", "k.rs:1", 10, 1, 100)
            .unwrap()
            .unwrap();
        assert_eq!(va, vb, "knob is deterministic per seed+label");
        assert!((1..=100).contains(&va), "knob out of range: {va}");
        // Disabled / inactive returns the clamped default.
        let mut off = buggify_context(9, BuggifyConfig::default());
        assert_eq!(
            off.buggify_knob("batch", "k.rs:1", 10, 1, 100)
                .unwrap()
                .unwrap(),
            10
        );
    }

    #[test]
    fn buggify_cutoff_suppresses_firing_after_the_window() {
        let mut context = buggify_context(
            5,
            BuggifyConfig {
                enabled: true,
                fire_permille: 1000,
                activation_permille: 1000,
                cutoff_nanos: 1_000,
                after_setup: false,
            },
        );
        // Before the cutoff (virtual time 0) an always-fire site fires.
        assert_eq!(
            context.buggify_evaluate("c", "c.rs:1", None).unwrap(),
            SiteOutcome::Fire
        );
        // Advance virtual time past the cutoff, then firing is suppressed.
        context.sleep_for(2_000).unwrap();
        assert_eq!(
            context.buggify_evaluate("c", "c.rs:1", None).unwrap(),
            SiteOutcome::Ok
        );
        assert!(context.buggify_diagnostics().cutoff_suppressed >= 1);
    }

    #[test]
    fn buggify_after_setup_gates_firing_and_flags_never_called() {
        let config = BuggifyConfig {
            enabled: true,
            fire_permille: 1000,
            activation_permille: 1000,
            cutoff_nanos: DEFAULT_BUGGIFY_CUTOFF_NANOS,
            after_setup: true,
        };
        // Before setup_complete, an always-fire site stays inert.
        let mut context = buggify_context(2, config);
        assert_eq!(
            context.buggify_evaluate("g", "g.rs:1", None).unwrap(),
            SiteOutcome::Ok,
            "site must be inert before setup_complete"
        );
        // The site is still marked reachable (coverage) even while gated.
        assert!(
            context
                .buggify_diagnostics()
                .sites
                .iter()
                .any(|s| s.reachable)
        );
        // A run that never reaches setup_complete is a declared-but-never-called
        // violation.
        assert!(context.buggify_setup_violation());
        // After setup_complete, firing arms.
        context.lifecycle_setup_complete();
        assert_eq!(
            context.buggify_evaluate("g", "g.rs:1", None).unwrap(),
            SiteOutcome::Fire
        );
        assert!(!context.buggify_setup_violation());
    }

    #[test]
    fn buggify_rng_is_seed_deterministic() {
        let mut a = buggify_context(11, BuggifyConfig::default());
        let mut b = buggify_context(11, BuggifyConfig::default());
        let seq_a: Vec<u64> = (0..8).map(|_| a.buggify_rng()).collect();
        let seq_b: Vec<u64> = (0..8).map(|_| b.buggify_rng()).collect();
        assert_eq!(seq_a, seq_b);
        let mut c = buggify_context(12, BuggifyConfig::default());
        let seq_c: Vec<u64> = (0..8).map(|_| c.buggify_rng()).collect();
        assert_ne!(seq_a, seq_c);
    }

    #[test]
    fn buggify_record_replay_reproduces_decisions_without_re_supplying_flags() {
        let directory = tempdir().unwrap();
        let trace = directory.path().join("buggify.patina");
        let config = BuggifyConfig {
            enabled: true,
            fire_permille: 500,
            activation_permille: 1000,
            cutoff_nanos: DEFAULT_BUGGIFY_CUTOFF_NANOS,
            after_setup: false,
        };

        // Record: interleave a recorded entropy op with buggify evaluations and a
        // fired delay (which records a SleepUntil), then finalize the trace.
        let mut recorded_fires = Vec::new();
        let mut context =
            Context::from_config(RuntimeConfig::record(3, &trace, "fp").with_buggify(config))
                .unwrap();
        context.entropy_bytes(4).unwrap();
        for _ in 0..20 {
            recorded_fires.push(matches!(
                context.buggify_evaluate("s", "r.rs:1", None).unwrap(),
                SiteOutcome::Fire
            ));
            let _ = context.buggify_delay("d", "r.rs:2").unwrap();
        }
        context.finish().unwrap();

        // Replay WITHOUT re-supplying buggify flags: the trace's recorded config
        // is authoritative and the pure-function decisions must reproduce exactly.
        let mut replay_fires = Vec::new();
        let mut replay = Context::from_config(RuntimeConfig::replay(&trace, "fp")).unwrap();
        replay.entropy_bytes(4).unwrap();
        for _ in 0..20 {
            replay_fires.push(matches!(
                replay.buggify_evaluate("s", "r.rs:1", None).unwrap(),
                SiteOutcome::Fire
            ));
            let _ = replay.buggify_delay("d", "r.rs:2").unwrap();
        }
        // No divergence at finalization means every recorded op (entropy +
        // delay-driven SleepUntil) was consumed in the same order.
        replay.finish().unwrap();

        assert_eq!(recorded_fires, replay_fires);
        assert!(
            recorded_fires.iter().any(|fired| *fired),
            "expected some firing"
        );
    }

    /// Drive a fixed multi-task cooperative schedule through a context, returning
    /// the order in which `scheduler_next` selected tasks. Tasks all stay runnable
    /// (yield, never park/complete until the end), so the policy fully controls
    /// the order.
    fn drive_schedule(context: &mut Context, n_workers: usize, rounds: usize) -> Vec<u64> {
        let mut workers = Vec::new();
        for index in 0..n_workers {
            workers.push(context.task_spawn(&format!("w{index}")).unwrap());
        }
        let mut order = Vec::new();
        for _ in 0..rounds {
            let task = context.scheduler_next().unwrap().unwrap();
            order.push(task.0);
            context.task_yield(task).unwrap();
        }
        drop(workers);
        // Drain: complete whatever task each decision selects until none remain.
        while let Some(task) = context.scheduler_next().unwrap() {
            context.task_complete(task).unwrap();
        }
        order
    }

    #[test]
    fn pct_record_replay_reproduces_schedule_and_records_policy() {
        let directory = tempdir().unwrap();
        let trace = directory.path().join("pct.patina");
        let policy = SchedulePolicy {
            pct: Some(PctConfig {
                depth: 3,
                steps: 50,
            }),
            starvation: None,
        };
        let config = RuntimeConfig::record(11, &trace, "fp+pct").with_schedule_policy(policy);
        let mut record = Context::from_config(config).unwrap();
        let recorded = drive_schedule(&mut record, 4, 40);
        record.finish().unwrap();

        // The trace records the policy metadata authoritatively.
        let bundle = patina_dst_trace::TraceBundle::load(&trace).unwrap();
        let recorded_policy = bundle.metadata.schedule_policy.expect("policy recorded");
        assert_eq!(recorded_policy.pct.unwrap().depth, 3);

        // Replay WITHOUT re-supplying the policy reproduces the exact selection
        // order (decisions come from the recorded op-stream).
        let mut replay = Context::from_config(RuntimeConfig::replay(&trace, "fp+pct")).unwrap();
        let replayed = drive_schedule(&mut replay, 4, 40);
        replay.finish().unwrap();
        assert_eq!(recorded, replayed);
        // A depth-3 PCT schedule over four always-runnable workers preempts, so
        // more than one task id appears.
        assert!(
            recorded
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                > 1
        );
    }

    #[test]
    fn reconcile_replay_schedule_policy_enforces_the_authoritative_trace_contract() {
        let stored = patina_dst_trace::SchedulePolicyRecord {
            pct: Some(patina_dst_trace::PctPolicyRecord {
                depth: 3,
                steps: 100,
            }),
            starvation: None,
        };
        // A default-policy trace (None) yields no override.
        assert_eq!(
            reconcile_replay_schedule_policy(&RuntimeConfig::seeded(0), None).unwrap(),
            None
        );
        // Flag-free replay adopts the stored policy verbatim.
        let adopted = reconcile_replay_schedule_policy(&RuntimeConfig::seeded(0), Some(&stored))
            .unwrap()
            .expect("stored policy adopted");
        assert_eq!(adopted.pct.unwrap().depth, 3);
        // A conflicting supplied policy fails closed.
        let conflicting = RuntimeConfig::seeded(0).with_schedule_policy(SchedulePolicy {
            pct: Some(PctConfig {
                depth: 9,
                steps: 100,
            }),
            starvation: None,
        });
        assert!(reconcile_replay_schedule_policy(&conflicting, Some(&stored)).is_err());
    }

    #[test]
    fn swarm_masks_a_subset_and_records_candidates_and_selection() {
        let directory = tempdir().unwrap();
        // Enable several fault classes plus buggify, then record under swarm.
        let build = |seed: u64| {
            let trace = directory.path().join(format!("swarm-{seed}.patina"));
            let config = RuntimeConfig::record(seed, &trace, "fp+swarm")
                .with_crash_at(CrashOp::Close, 1)
                .with_net_drop_permille(100)
                .with_sleep_jitter_nanos(1, 2)
                .with_buggify(BuggifyConfig {
                    enabled: true,
                    ..BuggifyConfig::default()
                })
                .with_swarm(true);
            let context = Context::from_config(config).unwrap();
            context.finish().unwrap();
            patina_dst_trace::TraceBundle::load(&trace).unwrap()
        };
        let bundle = build(1);
        let swarm = bundle.metadata.swarm.expect("swarm recorded");
        // All four enabled classes are candidates.
        assert_eq!(
            swarm.candidate_classes,
            vec!["crash", "sleep_jitter", "net_drop", "buggify"]
        );
        // The selected subset is a subset of candidates and reflects the applied
        // (masked) config: exactly the classes that survived masking.
        for class in &swarm.selected_classes {
            assert!(swarm.candidate_classes.contains(class));
        }
        let faults = bundle.metadata.faults.expect("faults recorded");
        assert_eq!(
            faults.crash_at.is_some(),
            swarm.selected_classes.iter().any(|c| c == "crash")
        );
        assert_eq!(
            bundle.metadata.buggify.is_some(),
            swarm.selected_classes.iter().any(|c| c == "buggify")
        );

        // Across seeds the selected subset actually varies (swarm testing).
        let subsets: std::collections::BTreeSet<Vec<String>> = (100..112)
            .map(|seed| build(seed).metadata.swarm.unwrap().selected_classes)
            .collect();
        assert!(
            subsets.len() > 1,
            "swarm subset must vary across seeds: {subsets:?}"
        );
    }

    #[test]
    fn apply_schedule_and_swarm_env_parse_the_control_plane() {
        let vars: BTreeMap<&str, String> = [
            (ENV_SCHED_PCT, "4".to_string()),
            (ENV_SCHED_PCT_STEPS, "123".to_string()),
            (ENV_SCHED_STARVE, "2".to_string()),
            (ENV_SCHED_STARVE_MAX_LEN, "16".to_string()),
            (ENV_SCHED_STARVE_WINDOW, "64".to_string()),
            (ENV_SWARM, "1".to_string()),
        ]
        .into_iter()
        .collect();
        let get = |name: &str| vars.get(name).cloned();
        let config = RuntimeConfig::seeded(0)
            .apply_schedule_env(get)
            .unwrap()
            .apply_swarm_env(get)
            .unwrap();
        let policy = config.schedule_policy();
        assert_eq!(
            policy.pct,
            Some(PctConfig {
                depth: 4,
                steps: 123
            })
        );
        assert_eq!(
            policy.starvation,
            Some(StarvationConfig {
                intervals: 2,
                max_len: 16,
                window: 64
            })
        );
        assert!(config.swarm());

        // A malformed PCT depth fails closed.
        let bad: BTreeMap<&str, String> =
            [(ENV_SCHED_PCT, "abc".to_string())].into_iter().collect();
        assert!(
            RuntimeConfig::seeded(0)
                .apply_schedule_env(|name| bad.get(name).cloned())
                .is_err()
        );
    }

    #[test]
    fn reconcile_replay_buggify_enforces_the_authoritative_trace_contract() {
        let stored = patina_dst_trace::BuggifyConfigRecord {
            fire_permille: 250,
            activation_permille: 250,
            cutoff_nanos: 300_000_000_000,
            after_setup: false,
            active_sites: vec!["s".into()],
            knobs: BTreeMap::new(),
        };
        // A trace without buggify yields no override.
        assert_eq!(
            reconcile_replay_buggify(&RuntimeConfig::seeded(0), None).unwrap(),
            None
        );
        // Flag-free replay adopts the stored config verbatim.
        let adopted = reconcile_replay_buggify(&RuntimeConfig::seeded(0), Some(&stored))
            .unwrap()
            .expect("stored config adopted");
        assert!(adopted.enabled);
        assert_eq!(adopted.fire_permille, 250);
        // Conflicting knobs fail closed.
        let conflicting = RuntimeConfig::seeded(0).with_buggify(BuggifyConfig {
            enabled: true,
            fire_permille: 999,
            ..BuggifyConfig::default()
        });
        assert!(reconcile_replay_buggify(&conflicting, Some(&stored)).is_err());
    }

    #[test]
    fn reconcile_replay_faults_enforces_the_authoritative_trace_contract() {
        use patina_dst_trace::{CrashPointRecord, FaultConfigRecord, FaultCrashOp};

        let stored = FaultConfigRecord {
            crash_at: Some(CrashPointRecord {
                op: FaultCrashOp::Close,
                ordinal: 1,
            }),
            torn_granularity: patina_dst_trace::TornGranularity::Byte,
            net_latency_nanos: 500,
            ..FaultConfigRecord::default()
        };

        // A pre-metadata trace (None) yields no override: the operator-supplied
        // configuration is kept, preserving the historical re-supply contract.
        let supplied = RuntimeConfig::seeded(0).with_crash_at(CrashOp::Close, 2);
        assert_eq!(reconcile_replay_faults(&supplied, None).unwrap(), None);

        // Flag-free replay adopts the stored configuration verbatim, so replay is
        // byte-identical without any knobs.
        let (faults, latency) = reconcile_replay_faults(&RuntimeConfig::seeded(0), Some(&stored))
            .unwrap()
            .expect("stored config adopted");
        assert_eq!(
            faults.crash_at,
            Some(CrashPoint {
                op: CrashOp::Close,
                ordinal: 1
            })
        );
        assert_eq!(faults.torn_granularity, TornGranularity::Byte);
        assert_eq!(latency, 500);

        // Explicit knobs that MATCH the recording are accepted.
        let matching = RuntimeConfig::seeded(0)
            .with_crash_at(CrashOp::Close, 1)
            .with_fs_torn_granularity(TornGranularity::Byte)
            .with_net_latency_nanos(500);
        reconcile_replay_faults(&matching, Some(&stored))
            .unwrap()
            .expect("matching config adopted");

        // Explicit knobs that DIVERGE fail closed before any driver is built.
        let mismatched = RuntimeConfig::seeded(0).with_crash_at(CrashOp::Close, 2);
        assert!(matches!(
            reconcile_replay_faults(&mismatched, Some(&stored)),
            Err(RuntimeError::Config(_))
        ));
    }

    fn exercise(context: &mut Context) -> Result<Vec<u8>, RuntimeError> {
        let entropy = context.entropy_bytes(12)?;
        context.write_file("/state/value", &entropy)?;
        assert_eq!(context.read_file("/state/value")?, entropy);
        context.sleep_for(250)?;
        assert_eq!(context.now(ClockKind::Monotonic)?, 250);
        Ok(entropy)
    }

    /// Drive the scheduler until `worker` completes, parking any other task that
    /// is scheduled first and yielding the worker `yields` times before it runs
    /// to completion. `yields == 0` models a worker whose whole body runs under a
    /// single selection with no scheduling boundary.
    fn run_worker(context: &mut Context, worker: TaskId, yields: u32) {
        let mut remaining = yields;
        loop {
            let selected = context.scheduler_next().unwrap().unwrap();
            if selected == worker {
                if remaining > 0 {
                    remaining -= 1;
                    context.task_yield(worker).unwrap();
                } else {
                    context.task_complete(worker).unwrap();
                    return;
                }
            } else {
                context.task_park(selected, "wait-for-worker").unwrap();
            }
        }
    }

    #[test]
    fn vacuous_worker_that_never_yields_is_flagged() {
        // RED: a spawned worker that runs from first scheduled to completion with
        // zero scheduling boundaries — like a lost-update race on an
        // atomics-only RwLock fast path — must be reported as vacuous.
        let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
        let _main = context.task_spawn("main").unwrap();
        let worker = context.task_spawn("worker").unwrap();
        run_worker(&mut context, worker, 0);

        let diagnostics = context.schedule_diagnostics();
        assert!(diagnostics.had_concurrency());
        assert_eq!(diagnostics.vacuous, vec![worker]);
        let stat = diagnostics
            .tasks
            .iter()
            .find(|stat| stat.task == worker)
            .expect("worker recorded");
        assert_eq!(stat.boundaries, 0);
        assert!(stat.vacuous);
    }

    #[test]
    fn worker_that_passes_a_boundary_is_not_flagged() {
        // GREEN: a worker that clears the scaffolding floor with real scheduling
        // boundaries — like the `deadlock` mode's interposed mutex loop, which
        // yields on every lock/unlock — is explorable and must NOT be flagged.
        let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
        let _main = context.task_spawn("main").unwrap();
        let worker = context.task_spawn("worker").unwrap();
        run_worker(&mut context, worker, SCAFFOLDING_YIELD_FLOOR as u32 + 1);

        let diagnostics = context.schedule_diagnostics();
        assert!(diagnostics.had_concurrency());
        assert!(
            diagnostics.vacuous.is_empty(),
            "worker cleared the scaffolding floor; must not be vacuous: {diagnostics:?}"
        );
        let stat = diagnostics
            .tasks
            .iter()
            .find(|stat| stat.task == worker)
            .expect("worker recorded");
        assert!(stat.yields > SCAFFOLDING_YIELD_FLOOR);
        assert!(!stat.vacuous);
    }

    #[test]
    fn single_task_run_reports_no_concurrency() {
        // A run with only the initial task has no schedule to explore, so the
        // diagnostic stays silent.
        let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
        let solo = context.task_spawn("main").unwrap();
        let selected = context.scheduler_next().unwrap().unwrap();
        assert_eq!(selected, solo);
        context.task_complete(solo).unwrap();

        let diagnostics = context.schedule_diagnostics();
        assert!(!diagnostics.had_concurrency());
        assert!(diagnostics.vacuous.is_empty());
    }

    #[test]
    fn task_lifetime_and_completion_cause_are_annotated() {
        // A joined worker is reported `Completed` with a positive lifetime (it
        // spans at least its own spawn->complete steps); the initial thread of
        // control, still live at run end, is reported `LiveAtExit`.
        let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
        let main = context.task_spawn("main").unwrap();
        let worker = context.task_spawn("worker").unwrap();
        run_worker(&mut context, worker, 2);

        let diagnostics = context.schedule_diagnostics();
        let worker_stat = diagnostics
            .tasks
            .iter()
            .find(|stat| stat.task == worker)
            .expect("worker recorded");
        assert_eq!(worker_stat.cause, TaskCompletionCause::Completed);
        assert!(
            worker_stat.lifetime > 0,
            "a completed worker spans at least one scheduling step: {worker_stat:?}"
        );

        let main_stat = diagnostics
            .tasks
            .iter()
            .find(|stat| stat.task == main)
            .expect("main recorded");
        assert_eq!(main_stat.cause, TaskCompletionCause::LiveAtExit);
    }

    #[test]
    fn same_seed_repeats_and_different_seed_varies() {
        let mut first = Context::from_config(RuntimeConfig::seeded(7)).unwrap();
        let first_result = exercise(&mut first).unwrap();
        first.finish().unwrap();

        let mut second = Context::from_config(RuntimeConfig::seeded(7)).unwrap();
        let second_result = exercise(&mut second).unwrap();
        second.finish().unwrap();

        let mut different = Context::from_config(RuntimeConfig::seeded(8)).unwrap();
        let different_result = exercise(&mut different).unwrap();
        different.finish().unwrap();

        assert_eq!(first_result, second_result);
        assert_ne!(first_result, different_result);
    }

    #[test]
    fn record_and_replay_cover_all_initial_effects() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("run.patina");
        let mut record =
            Context::from_config(RuntimeConfig::record(99, &path, "fixture-v1")).unwrap();
        let expected = exercise(&mut record).unwrap();
        record.finish().unwrap();

        let mut replay = Context::from_config(RuntimeConfig::replay(&path, "fixture-v1")).unwrap();
        assert_eq!(replay.root_seed(), 99);
        assert_eq!(exercise(&mut replay).unwrap(), expected);
        replay.finish().unwrap();
    }

    #[derive(Clone, Default)]
    struct SharedTransport {
        bytes: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    }

    impl SharedTransport {
        fn stored(&self) -> Vec<u8> {
            self.bytes.lock().unwrap().clone()
        }
    }

    impl TraceTransport for SharedTransport {
        fn read_bundle(&mut self) -> std::io::Result<Vec<u8>> {
            Ok(self.stored())
        }

        fn write_bundle(&mut self, bytes: &[u8]) -> std::io::Result<()> {
            *self.bytes.lock().unwrap() = bytes.to_vec();
            Ok(())
        }
    }

    #[test]
    fn trace_transport_records_and_replays_without_paths() {
        let transport = SharedTransport::default();
        let mut record = RuntimeBuilder::new(RuntimeConfig::record_transport(99, "fixture-v1"))
            .with_default_drivers()
            .with_trace_transport(transport.clone())
            .build()
            .unwrap();
        let expected = exercise(&mut record).unwrap();
        record.finish().unwrap();
        assert!(!transport.stored().is_empty());

        let mut replay = RuntimeBuilder::new(RuntimeConfig::replay_transport_timeline(
            "main",
            "fixture-v1",
        ))
        .with_default_drivers()
        .with_trace_transport(transport.clone())
        .build()
        .unwrap();
        assert_eq!(replay.root_seed(), 99);
        assert_eq!(exercise(&mut replay).unwrap(), expected);
        replay.finish().unwrap();

        let unconsumed = RuntimeBuilder::new(RuntimeConfig::replay_transport_timeline(
            "main",
            "fixture-v1",
        ))
        .with_default_drivers()
        .with_trace_transport(transport)
        .build()
        .unwrap();
        assert!(matches!(
            unconsumed.finish(),
            Err(RuntimeError::Trace(TraceError::UnconsumedEvents { .. }))
        ));
    }

    #[test]
    fn trace_transport_configuration_fails_loudly() {
        assert!(matches!(
            RuntimeBuilder::new(RuntimeConfig::record_transport(1, "fixture-v1"))
                .with_default_drivers()
                .build(),
            Err(RuntimeError::Config(_))
        ));
        assert!(matches!(
            RuntimeBuilder::new(RuntimeConfig::seeded(1))
                .with_default_drivers()
                .with_trace_transport(SharedTransport::default())
                .build(),
            Err(RuntimeError::Config(_))
        ));
    }

    #[test]
    fn replay_rejects_changed_operations_and_unconsumed_events() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("run.patina");
        let mut record =
            Context::from_config(RuntimeConfig::record(1, &path, "fixture-v1")).unwrap();
        record.entropy_bytes(4).unwrap();
        record.finish().unwrap();

        let mut changed = Context::from_config(RuntimeConfig::replay(&path, "fixture-v1")).unwrap();
        assert!(matches!(
            changed.entropy_bytes(5),
            Err(RuntimeError::Trace(TraceError::OperationMismatch { .. }))
        ));

        let untouched = Context::from_config(RuntimeConfig::replay(&path, "fixture-v1")).unwrap();
        assert!(matches!(
            untouched.finish(),
            Err(RuntimeError::Trace(TraceError::UnconsumedEvents { .. }))
        ));
    }

    #[test]
    fn record_mode_rejects_concurrent_and_existing_trace_writers() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("run.patina");
        let first = Context::from_config(RuntimeConfig::record(1, &path, "fixture-v1")).unwrap();
        assert!(matches!(
            Context::from_config(RuntimeConfig::record(1, &path, "fixture-v1")),
            Err(RuntimeError::Io { .. })
        ));
        drop(first);

        Context::from_config(RuntimeConfig::record(1, &path, "fixture-v1"))
            .unwrap()
            .finish()
            .unwrap();
        assert!(matches!(
            Context::from_config(RuntimeConfig::record(1, &path, "fixture-v1")),
            Err(RuntimeError::Config(message)) if message.contains("refusing to overwrite")
        ));
    }

    #[test]
    fn replay_rejects_a_changed_fingerprint() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("run.patina");
        Context::from_config(RuntimeConfig::record(1, &path, "fixture-v1"))
            .unwrap()
            .finish()
            .unwrap();
        assert!(matches!(
            Context::from_config(RuntimeConfig::replay(&path, "fixture-v2")),
            Err(RuntimeError::Trace(TraceError::FingerprintMismatch { .. }))
        ));
    }

    #[test]
    fn record_and_replay_cross_scheduler_network_clock_and_filesystem() {
        fn simulation(context: &mut Context) -> Result<(TaskId, Vec<u8>), RuntimeError> {
            let first = context.task_spawn("first")?;
            context.task_spawn("second")?;
            let selected = context.scheduler_next()?.expect("tasks are runnable");
            context.task_yield(selected)?;

            let left = context.net_bind("left")?;
            let right = context.net_bind("right")?;
            context.net_send(left, "right", b"packet")?;
            let packet = context
                .net_recv(right)?
                .expect("zero-latency packet is ready");
            context.write_file("/state/packet", &packet.bytes)?;
            context.net_close(left)?;
            context.net_close(right)?;
            assert_eq!(first, TaskId(1));
            Ok((selected, context.read_file("/state/packet")?))
        }

        let directory = tempdir().unwrap();
        let path = directory.path().join("simulation.patina");
        let mut record =
            Context::from_config(RuntimeConfig::record(77, &path, "simulation-v1")).unwrap();
        let expected = simulation(&mut record).unwrap();
        record.finish().unwrap();

        let mut replay =
            Context::from_config(RuntimeConfig::replay(&path, "simulation-v1")).unwrap();
        assert_eq!(simulation(&mut replay).unwrap(), expected);
        replay.finish().unwrap();
    }

    #[test]
    fn tcp_operations_record_and_replay_byte_identically() {
        fn simulation(context: &mut Context) -> Result<(String, Vec<u8>, Vec<u8>), RuntimeError> {
            let listener = context.net_tcp_listen("server", 2)?;
            let client = context.net_tcp_connect("client", "server")?;
            let accepted = context
                .net_tcp_accept(listener)?
                .expect("connect queued an accept");
            context.net_tcp_send(client, b"ping")?;
            context.net_tcp_send(accepted.socket, b"pong")?;
            context.net_tcp_shutdown(client, ShutdownHow::Write)?;
            let request = context.net_tcp_recv(accepted.socket, 16)?.unwrap();
            let eof = context.net_tcp_recv(accepted.socket, 16)?.unwrap();
            let reply = context.net_tcp_recv(client, 16)?.unwrap();
            context.net_close(client)?;
            context.net_close(accepted.socket)?;
            context.net_close(listener)?;
            Ok((accepted.peer, request, [eof, reply].concat()))
        }

        let directory = tempdir().unwrap();
        let path = directory.path().join("tcp.patina");
        let mut record = Context::from_config(RuntimeConfig::record(10, &path, "tcp-v1")).unwrap();
        let expected = simulation(&mut record).unwrap();
        record.finish().unwrap();

        let mut replay = Context::from_config(RuntimeConfig::replay(&path, "tcp-v1")).unwrap();
        assert_eq!(simulation(&mut replay).unwrap(), expected);
        replay.finish().unwrap();
    }

    #[test]
    fn tcp_replay_rejects_a_divergent_payload() {
        fn program(context: &mut Context, bytes: &[u8]) -> Result<(), RuntimeError> {
            let listener = context.net_tcp_listen("server", 1)?;
            let client = context.net_tcp_connect("client", "server")?;
            let accepted = context.net_tcp_accept(listener)?.unwrap();
            context.net_tcp_send(client, bytes)?;
            context.net_close(client)?;
            context.net_close(accepted.socket)?;
            context.net_close(listener)
        }

        let directory = tempdir().unwrap();
        let path = directory.path().join("tcp-divergent.patina");
        let mut record = Context::from_config(RuntimeConfig::record(11, &path, "tcp-v1")).unwrap();
        program(&mut record, b"same").unwrap();
        record.finish().unwrap();

        let mut replay = Context::from_config(RuntimeConfig::replay(&path, "tcp-v1")).unwrap();
        assert!(matches!(
            program(&mut replay, b"different"),
            Err(RuntimeError::Trace(TraceError::OperationMismatch { .. }))
        ));
    }

    #[test]
    fn tcp_blocking_pattern_parks_and_wakes_deterministically() {
        fn program(context: &mut Context) -> Result<(TaskId, TaskId, String), RuntimeError> {
            let acceptor_task = context.task_spawn("acceptor")?;
            let connector_task = context.task_spawn("connector")?;
            let selected = context.scheduler_next()?.expect("a task is runnable");
            let listener = context.net_tcp_listen("server", 1)?;
            assert!(context.net_tcp_accept(listener)?.is_none());
            context.task_park(selected, "tcp-accept")?;
            let client = context.net_tcp_connect("client", "server")?;
            context.task_wake(selected)?;
            let accepted = context.net_tcp_accept(listener)?.unwrap();
            context.net_close(client)?;
            context.net_close(accepted.socket)?;
            context.net_close(listener)?;
            Ok((acceptor_task, connector_task, accepted.peer))
        }

        let directory = tempdir().unwrap();
        let path = directory.path().join("tcp-park.patina");
        let mut record = Context::from_config(RuntimeConfig::record(12, &path, "tcp-v1")).unwrap();
        let expected = program(&mut record).unwrap();
        record.finish().unwrap();

        let mut replay = Context::from_config(RuntimeConfig::replay(&path, "tcp-v1")).unwrap();
        assert_eq!(program(&mut replay).unwrap(), expected);
        replay.finish().unwrap();
    }

    #[test]
    fn branch_replays_the_prefix_and_uses_a_new_seed_for_the_suffix() {
        fn two_decisions(context: &mut Context) -> Result<(Vec<u8>, Vec<u8>), RuntimeError> {
            Ok((context.entropy_bytes(8)?, context.entropy_bytes(8)?))
        }

        let directory = tempdir().unwrap();
        let path = directory.path().join("branches.patina");
        let mut record =
            Context::from_config(RuntimeConfig::record(7, &path, "branches-v1")).unwrap();
        let main = two_decisions(&mut record).unwrap();
        record.finish().unwrap();

        let mut branch = Context::from_config(RuntimeConfig::branch(
            &path,
            "main",
            1,
            "branch-99",
            99,
            "branches-v1",
        ))
        .unwrap();
        let branched = two_decisions(&mut branch).unwrap();
        branch.finish().unwrap();
        assert_eq!(branched.0, main.0, "the prefix must replay exactly");
        assert_ne!(branched.1, main.1, "the suffix must use the branch seed");

        let mut replay = Context::from_config(RuntimeConfig::replay_timeline(
            &path,
            "branch-99",
            "branches-v1",
        ))
        .unwrap();
        assert_eq!(two_decisions(&mut replay).unwrap(), branched);
        replay.finish().unwrap();
    }

    #[test]
    fn guest_argv_env_parses_a_json_array_and_fails_closed_on_garbage() {
        // A JSON string array sets the recorded argv, preserving order; an empty
        // array is a valid zero-argument recording distinct from absence.
        fn map(value: &'static str) -> impl Fn(&str) -> Option<String> {
            move |name: &str| (name == ENV_GUEST_ARGV).then(|| value.to_string())
        }
        let config = RuntimeConfig::record(0, "/trace", "fp")
            .apply_guest_argv_env(map(r#"["--tick-millis","50"]"#))
            .unwrap();
        assert_eq!(
            config.guest_argv(),
            Some(["--tick-millis".to_string(), "50".to_string()].as_slice())
        );
        let empty = RuntimeConfig::record(0, "/trace", "fp")
            .apply_guest_argv_env(map("[]"))
            .unwrap();
        assert_eq!(empty.guest_argv(), Some([].as_slice()));

        // Absent variable leaves argv unset (no behavior change).
        let unset = RuntimeConfig::record(0, "/trace", "fp")
            .apply_guest_argv_env(|_| None)
            .unwrap();
        assert_eq!(unset.guest_argv(), None);

        // Malformed JSON is rejected fail-closed rather than silently dropped.
        let error = RuntimeConfig::record(0, "/trace", "fp")
            .apply_guest_argv_env(map("not json"))
            .unwrap_err();
        assert!(matches!(error, RuntimeError::Config(_)), "{error:?}");
    }

    #[test]
    fn typed_builder_parameters_are_explicit() {
        let config = RuntimeConfig::seeded(1).with_param("zone", "a").unwrap();
        let context = Context::from_config(config).unwrap();
        assert_eq!(context.param("zone"), Some("a"));
        assert_eq!(context.param("missing"), None);
    }

    #[test]
    fn step_budget_stops_before_an_unrecorded_boundary_operation() {
        let mut context =
            Context::from_config(RuntimeConfig::seeded(1).with_step_budget(2)).unwrap();
        context.entropy_bytes(1).unwrap();
        context.now(ClockKind::Monotonic).unwrap();
        assert_eq!(context.steps(), 2);
        assert!(matches!(
            context.entropy_bytes(1),
            Err(RuntimeError::StepBudgetExceeded { budget: 2 })
        ));
        assert_eq!(context.steps(), 2);
    }

    #[test]
    fn missing_drivers_fail_without_fallback() {
        let mut context = RuntimeBuilder::new(RuntimeConfig::seeded(1))
            .build()
            .unwrap();
        let error = context.entropy_bytes(1).unwrap_err();
        assert!(matches!(
            error,
            RuntimeError::Effect(EffectError {
                code: ErrorCode::MissingDriver,
                ..
            })
        ));
    }

    struct WrongHandleFs;

    impl FsDriver for WrongHandleFs {
        fn open(&mut self, _path: &str, _flags: OpenFlags) -> Result<Fd, EffectError> {
            Ok(Fd(999))
        }

        fn read(&mut self, _fd: Fd, _max_len: usize) -> Result<Vec<u8>, EffectError> {
            unreachable!()
        }

        fn write(&mut self, _fd: Fd, _bytes: &[u8]) -> Result<usize, EffectError> {
            unreachable!()
        }

        fn close(&mut self, _fd: Fd) -> Result<(), EffectError> {
            unreachable!()
        }
    }

    #[test]
    fn fs_dup_records_replays_and_reconciles_handle_identity() {
        fn exercise_dup(context: &mut Context) -> Result<Vec<u8>, RuntimeError> {
            let write = context.fs_open("/value", OpenFlags::create_truncate_write())?;
            context.fs_write(write, b"abcdef")?;
            context.fs_close(write)?;
            let first = context.fs_open("/value", OpenFlags::read_only())?;
            let second = context.fs_dup(first)?;
            assert_eq!(second, Fd(first.0 + 1));
            context.fs_seek(second, 1, SeekWhence::Start)?;
            let bytes = context.fs_read(first, 2)?;
            context.fs_close(first)?;
            context.fs_close(second)?;
            Ok(bytes)
        }

        let directory = tempdir().unwrap();
        let trace = directory.path().join("dup.patina");
        let mut record = Context::from_config(RuntimeConfig::record(11, &trace, "dup-v1")).unwrap();
        assert_eq!(exercise_dup(&mut record).unwrap(), b"bc");
        record.finish().unwrap();

        let mut replay = Context::from_config(RuntimeConfig::replay(&trace, "dup-v1")).unwrap();
        assert_eq!(exercise_dup(&mut replay).unwrap(), b"bc");
        replay.finish().unwrap();

        let mut tampered = TraceBundle::load(&trace).unwrap();
        for event in &mut tampered.timelines[0].decisions {
            if matches!(event.operation, Operation::FsDup { .. }) {
                event.outcome = Outcome::Handle(Fd(999));
                break;
            }
        }
        let tampered_path = directory.path().join("dup-tampered.patina");
        tampered.write_atomic(&tampered_path).unwrap();
        let mut replay =
            Context::from_config(RuntimeConfig::replay(&tampered_path, "dup-v1")).unwrap();
        let error = exercise_dup(&mut replay).unwrap_err();
        assert!(matches!(
            error,
            RuntimeError::Trace(TraceError::OutcomeMismatch { .. })
        ));
    }

    #[test]
    fn captured_host_files_replay_without_host_access_and_fail_on_branch_miss() {
        let directory = tempdir().unwrap();
        let host = directory.path().join("host");
        std::fs::create_dir(&host).unwrap();
        std::fs::write(host.join("value"), b"captured").unwrap();
        let trace = directory.path().join("capture.patina");

        let config = RuntimeConfig::record(3, &trace, "capture-v1");
        let mut record = RuntimeBuilder::new(config)
            .with_captured_filesystem(HostCaptureFs::new("/fixtures", &host).unwrap())
            .build()
            .unwrap();
        let fd = record
            .fs_open("/fixtures/value", OpenFlags::read_only())
            .unwrap();
        assert_eq!(record.fs_read(fd, 32).unwrap(), b"captured");
        record.fs_close(fd).unwrap();
        record.finish().unwrap();

        std::fs::remove_file(host.join("value")).unwrap();
        let config = RuntimeConfig::replay(&trace, "capture-v1");
        let mut replay = RuntimeBuilder::new(config)
            .with_captured_filesystem(HostCaptureFs::new("/fixtures", &host).unwrap())
            .build()
            .unwrap();
        let fd = replay
            .fs_open("/fixtures/value", OpenFlags::read_only())
            .unwrap();
        assert_eq!(replay.fs_read(fd, 32).unwrap(), b"captured");
        replay.fs_close(fd).unwrap();
        replay.finish().unwrap();

        let config = RuntimeConfig::branch(&trace, "main", 1, "capture-miss", 4, "capture-v1");
        let mut branch = RuntimeBuilder::new(config)
            .with_captured_filesystem(HostCaptureFs::new("/fixtures", &host).unwrap())
            .build()
            .unwrap();
        let fd = branch
            .fs_open("/fixtures/value", OpenFlags::read_only())
            .unwrap();
        assert!(matches!(
            branch.fs_read(fd, 32),
            Err(RuntimeError::Effect(EffectError {
                code: ErrorCode::Denied,
                ..
            }))
        ));
    }

    #[test]
    fn crash_filesystem_record_and_replay_restore_the_synced_checkpoint() {
        fn exercise(context: &mut Context) -> Result<Vec<u8>, RuntimeError> {
            let fd = context.fs_open("/state", OpenFlags::create_truncate_write())?;
            context.fs_write(fd, b"stable")?;
            context.fs_sync(fd)?;
            context.fs_write(fd, b"-volatile")?;
            context.fs_crash()?;
            assert!(matches!(
                context.fs_write(fd, b"stale"),
                Err(RuntimeError::Effect(EffectError {
                    code: ErrorCode::InvalidHandle,
                    ..
                }))
            ));
            context.read_file("/state")
        }

        let directory = tempdir().unwrap();
        let trace = directory.path().join("crash.patina");
        let config = RuntimeConfig::record(71, &trace, "crash-v1");
        let mut record = RuntimeBuilder::new(config)
            .with_default_drivers()
            .with_filesystem(CrashFs::default())
            .build()
            .unwrap();
        assert_eq!(exercise(&mut record).unwrap(), b"stable");
        record.finish().unwrap();

        let config = RuntimeConfig::replay(&trace, "crash-v1");
        let mut replay = RuntimeBuilder::new(config)
            .with_default_drivers()
            .with_filesystem(CrashFs::default())
            .build()
            .unwrap();
        assert_eq!(exercise(&mut replay).unwrap(), b"stable");
        replay.finish().unwrap();
    }

    #[test]
    fn crash_torn_writes_record_and_replay_reproduce_the_same_image() {
        fn crash_fs() -> CrashFs {
            CrashFs::builder()
                .seed(9)
                .torn_write_granularity(2)
                .torn_write_probability(0.5)
                .build()
                .unwrap()
        }

        fn exercise(context: &mut Context) -> Result<Vec<u8>, RuntimeError> {
            let fd = context.fs_open("/log", OpenFlags::create_truncate_write())?;
            context.fs_write(fd, b"AAAAAAAA")?;
            context.fs_sync(fd)?;
            context.fs_seek(fd, 0, SeekWhence::Start)?;
            context.fs_write(fd, b"BBBBBBBB")?;
            context.fs_crash()?;
            // The pre-crash handle is stale after the modeled restart.
            assert!(matches!(
                context.fs_write(fd, b"stale"),
                Err(RuntimeError::Effect(EffectError {
                    code: ErrorCode::InvalidHandle,
                    ..
                }))
            ));
            context.read_file("/log")
        }

        let directory = tempdir().unwrap();
        let trace = directory.path().join("torn.patina");
        let config = RuntimeConfig::record(3, &trace, "crash-torn-v1");
        let mut record = RuntimeBuilder::new(config)
            .with_default_drivers()
            .with_filesystem(crash_fs())
            .build()
            .unwrap();
        let recorded = exercise(&mut record).unwrap();
        record.finish().unwrap();

        // The seeded tear is a real per-block mix, not a whole-image outcome.
        assert_eq!(recorded.len(), 8);
        assert!(
            recorded
                .chunks(2)
                .all(|block| block == b"AA" || block == b"BB")
        );
        assert!(recorded.chunks(2).any(|block| block == b"AA"));
        assert!(recorded.chunks(2).any(|block| block == b"BB"));

        let config = RuntimeConfig::replay(&trace, "crash-torn-v1");
        let mut replay = RuntimeBuilder::new(config)
            .with_default_drivers()
            .with_filesystem(crash_fs())
            .build()
            .unwrap();
        assert_eq!(exercise(&mut replay).unwrap(), recorded);
        replay.finish().unwrap();
    }

    // Structural guard for the "parsed fault knob silently ignored because a
    // pre-installed filesystem bypassed the config" gap class: an explicit
    // filesystem MUST NOT coexist with config-driven crash knobs. `build` fails
    // closed instead of dropping them. (The historical bug installed a default
    // CrashFs and let `--fs-torn-granularity byte` be silently ignored.)
    #[test]
    fn explicit_filesystem_with_crash_knobs_fails_closed() {
        // `Context` is not `Debug`, so assert on the Result shape directly.
        // Explicit filesystem + a crash point -> refuse.
        let result = RuntimeBuilder::new(RuntimeConfig::seeded(1).with_crash_at(CrashOp::Write, 1))
            .with_default_drivers()
            .with_filesystem(CrashFs::default())
            .build();
        assert!(matches!(result, Err(RuntimeError::Config(_))));

        // Explicit filesystem + a non-default torn granularity -> refuse, even
        // with no crash point, because the granularity would be dropped.
        let result = RuntimeBuilder::new(
            RuntimeConfig::seeded(1).with_fs_torn_granularity(TornGranularity::Byte),
        )
        .with_default_drivers()
        .with_filesystem(CrashFs::default())
        .build();
        assert!(matches!(result, Err(RuntimeError::Config(_))));

        // An explicit filesystem with NO crash knobs is still fine (tests /
        // embedders that drive `fs_crash` manually).
        assert!(
            RuntimeBuilder::new(RuntimeConfig::seeded(1))
                .with_default_drivers()
                .with_filesystem(CrashFs::default())
                .build()
                .is_ok()
        );

        // Supplying both a base image and an explicit filesystem is ambiguous.
        let result = RuntimeBuilder::new(RuntimeConfig::seeded(1))
            .with_default_drivers()
            .with_filesystem(MemFs::new())
            .with_fs_image(MemFs::new())
            .build();
        assert!(matches!(result, Err(RuntimeError::Config(_))));
    }

    // The single choke point builds the crash filesystem from the fault config:
    // a base image + `--fs-crash-at` + `--fs-torn-granularity byte` yields a
    // sub-block partial tear, while the default (block) granularity reverts the
    // final write wholesale. This is the runtime-level guarantee the shim relies
    // on instead of constructing the CrashFs itself.
    #[test]
    fn fs_image_choke_point_honors_configured_torn_granularity() {
        fn recovered_image(granularity: TornGranularity) -> Vec<u8> {
            let mut config = RuntimeConfig::seeded(1).with_crash_at(CrashOp::Write, 2);
            if granularity == TornGranularity::Byte {
                config = config.with_fs_torn_granularity(TornGranularity::Byte);
            }
            let mut context = RuntimeBuilder::new(config)
                .with_default_drivers()
                .with_fs_image(MemFs::new())
                .build()
                .unwrap();
            // Durable baseline, then one unsynced overwrite (crash fires after
            // this second write), then read the recovered image.
            let fd = context
                .fs_open("/f", OpenFlags::create_truncate_write())
                .unwrap();
            context.fs_write_at(fd, 0, &[b'A'; 16]).unwrap(); // write 1
            context.fs_sync(fd).unwrap();
            let _ = context.fs_write_at(fd, 0, &[b'B'; 16]); // write 2 -> crash
            context.read_file("/f").unwrap_or_default()
        }

        let block = recovered_image(TornGranularity::Block);
        let byte = recovered_image(TornGranularity::Byte);
        assert_eq!(
            block,
            vec![b'A'; 16],
            "block granularity should revert wholesale"
        );
        assert_ne!(
            byte, block,
            "byte granularity should not match the block revert"
        );
        assert!(
            byte.contains(&b'B') && byte.contains(&b'A'),
            "byte granularity should leave a partial live/durable mix: {byte:?}"
        );
    }

    // Regression for two bugs the shim/WASI paths hit, both via
    // `with_default_drivers` WITHOUT `with_fs_image` (exactly what
    // `Context::from_config` — the WASI `wasi-run` path — does), knob-free:
    //   (a) the choke point used `MemFs::default()` as the base, which is
    //       ROOTLESS (no `/`), so every path op (create_dir/open) failed with
    //       NotFound; it must use `MemFs::new()`.
    //   (b) a bare `MemFs` cannot crash — `crash()` returns `InvalidState`
    //       (errno 13) — so imperative `fs_crash()` callers broke; the base must
    //       be wrapped in a `CrashFs`.
    // This single test exercises both: a rooted directory/file op AND a manual
    // crash with no `--fs-crash-at` configured.
    #[test]
    fn context_from_config_filesystem_is_rooted_and_crashable() {
        let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
        // (a) Rooted: create a directory and a file under `/`, write, sync.
        context.fs_create_directory("/state").unwrap();
        let fd = context
            .fs_open("/state/value", OpenFlags::create_truncate_write())
            .unwrap();
        context.fs_write_at(fd, 0, b"durable").unwrap();
        context.fs_sync(fd).unwrap();
        context.fs_write_at(fd, 0, b"volatile").unwrap(); // unsynced overwrite
        // (b) Crashable: an imperative crash with NO crash_at must succeed and
        // drop the unsynced overwrite back to the durable bytes.
        context
            .fs_crash()
            .expect("imperative fs_crash must succeed");
        assert_eq!(context.read_file("/state/value").unwrap(), b"durable");
    }

    /// Drive the runtime the way the shim does: spawn two tasks, park each with
    /// a virtual-clock deadline, then let `scheduler_next` rescue the deadlock by
    /// advancing time and waking the earliest-due task. Returns the observed wake
    /// order and the virtual time at each wake.
    fn timed_rescue(context: &mut Context) -> Result<Vec<(TaskId, u64)>, RuntimeError> {
        let a = context.task_spawn("a")?;
        let b = context.task_spawn("b")?;
        // Park the first-selected task at 200 and the other at 100 so the wake
        // order is determined by deadline, not by spawn or selection order.
        let first = context.scheduler_next()?.expect("a task is runnable");
        context.task_park_timed(first, "wait", ClockKind::Monotonic, 200)?;
        let second = context.scheduler_next()?.expect("a task is runnable");
        context.task_park_timed(second, "wait", ClockKind::Monotonic, 100)?;
        let mut wakes = Vec::new();
        // Both tasks are parked; each `scheduler_next` now rescues in turn.
        for _ in 0..2 {
            let woken = context.scheduler_next()?.expect("a timer wakes a task");
            wakes.push((woken, context.now(ClockKind::Monotonic)?));
            context.task_complete(woken)?;
        }
        assert!(context.scheduler_next()?.is_none());
        let _ = (a, b);
        Ok(wakes)
    }

    #[test]
    fn deadlock_rescue_advances_time_and_wakes_in_deadline_order() {
        let mut context = Context::from_config(RuntimeConfig::seeded(5)).unwrap();
        let wakes = timed_rescue(&mut context).unwrap();
        // The task parked at 100 wakes first at virtual time 100, then the task
        // parked at 200 wakes at 200 — deadline order, not registration order.
        assert_eq!(wakes.len(), 2);
        assert_eq!(wakes[0].1, 100);
        assert_eq!(wakes[1].1, 200);
        assert_ne!(wakes[0].0, wakes[1].0);
        context.finish().unwrap();
    }

    #[test]
    fn deadlock_rescue_records_and_replays_byte_identically() {
        let directory = tempdir().unwrap();
        let first = directory.path().join("timer-a.patina");
        let second = directory.path().join("timer-b.patina");
        for path in [&first, &second] {
            let mut record =
                Context::from_config(RuntimeConfig::record(9, path, "timer-v1")).unwrap();
            timed_rescue(&mut record).unwrap();
            record.finish().unwrap();
        }
        // Two independent record processes with the same seed are byte-identical.
        assert_eq!(fs::read(&first).unwrap(), fs::read(&second).unwrap());

        // Replay consumes every recorded SleepUntil/TaskWake/SchedulerNext event.
        let mut replay = Context::from_config(RuntimeConfig::replay(&first, "timer-v1")).unwrap();
        timed_rescue(&mut replay).unwrap();
        replay.finish().unwrap();
    }

    #[test]
    fn realtime_deadlines_convert_through_the_clock_epoch() {
        // A clock whose realtime epoch is 1_000ns ahead of monotonic: a realtime
        // deadline of 1_150 must register (and rescue-advance) at monotonic 150.
        let mut context = RuntimeBuilder::new(RuntimeConfig::seeded(1))
            .with_default_drivers()
            .with_clock(VirtualClock::new(1_000))
            .build()
            .unwrap();
        let task = context.task_spawn("sleeper").unwrap();
        let running = context.scheduler_next().unwrap().unwrap();
        assert_eq!(running, task);
        context
            .task_park_timed(task, "sleep", ClockKind::Realtime, 1_150)
            .unwrap();
        let woken = context.scheduler_next().unwrap().unwrap();
        assert_eq!(woken, task);
        assert_eq!(context.now(ClockKind::Monotonic).unwrap(), 150);
        assert_eq!(context.now(ClockKind::Realtime).unwrap(), 1_150);
        context.task_complete(task).unwrap();
        context.finish().unwrap();
    }

    #[test]
    fn an_early_wake_deregisters_the_timer_so_the_rescue_skips_it() {
        let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
        let a = context.task_spawn("a").unwrap();
        let b = context.task_spawn("b").unwrap();
        // `a` parks with an early deadline, then is woken by a "signal" before it
        // fires; only `b`'s later timer should drive a rescue.
        let first = context.scheduler_next().unwrap().unwrap();
        context
            .task_park_timed(first, "wait", ClockKind::Monotonic, 50)
            .unwrap();
        let second = context.scheduler_next().unwrap().unwrap();
        context
            .task_park_timed(second, "wait", ClockKind::Monotonic, 500)
            .unwrap();
        // Signal-wake `first` (deregisters its 50ns timer). It must not be woken
        // again by the rescue, which should advance straight to 500 for `second`.
        context.task_wake(first).unwrap();
        let resumed = context.scheduler_next().unwrap().unwrap();
        assert_eq!(
            resumed, first,
            "the signalled task runs without advancing time"
        );
        assert_eq!(context.now(ClockKind::Monotonic).unwrap(), 0);
        context.task_park(first, "again").unwrap();
        let rescued = context.scheduler_next().unwrap().unwrap();
        assert_eq!(rescued, second);
        assert_eq!(context.now(ClockKind::Monotonic).unwrap(), 500);
        let _ = (a, b);
    }

    #[test]
    fn a_timed_park_with_no_other_runnable_task_rescues_itself() {
        // Single-task program: the sleeper is the only task, so the very next
        // `scheduler_next` deadlocks, the rescue advances time, and it wakes.
        let mut context = Context::from_config(RuntimeConfig::seeded(3)).unwrap();
        let task = context.task_spawn("only").unwrap();
        assert_eq!(context.scheduler_next().unwrap(), Some(task));
        context
            .task_park_timed(task, "sleep", ClockKind::Monotonic, 4_096)
            .unwrap();
        assert_eq!(context.scheduler_next().unwrap(), Some(task));
        assert_eq!(context.now(ClockKind::Monotonic).unwrap(), 4_096);
        assert!(context.take_rescued_timeouts().contains(&task));
        context.task_complete(task).unwrap();
    }

    #[test]
    fn replay_compares_deterministic_driver_outcomes() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("run.patina");
        let mut record =
            Context::from_config(RuntimeConfig::record(1, &path, "fixture-v1")).unwrap();
        record
            .fs_open("/value", OpenFlags::create_truncate_write())
            .unwrap();
        record.finish().unwrap();

        let mut replay = RuntimeBuilder::new(RuntimeConfig::replay(&path, "fixture-v1"))
            .with_filesystem(WrongHandleFs)
            .build()
            .unwrap();
        assert!(matches!(
            replay.fs_open("/value", OpenFlags::create_truncate_write()),
            Err(RuntimeError::Trace(TraceError::OutcomeMismatch { .. }))
        ));
    }

    // -- Liveness watchdog --------------------------------------------------

    #[test]
    fn operation_progress_classification_is_correct() {
        // Pure scheduling/time/wait ops are non-progress; genuine effects are.
        assert!(!operation_is_progress(&Operation::SchedulerNext));
        assert!(!operation_is_progress(&Operation::ClockNow {
            clock: ClockKind::Monotonic
        }));
        assert!(!operation_is_progress(&Operation::SleepUntil {
            clock: ClockKind::Monotonic,
            deadline_nanos: 1
        }));
        assert!(!operation_is_progress(&Operation::TaskParkTimed {
            task: TaskId(1),
            reason: "x".into(),
            deadline_nanos: 1
        }));
        assert!(operation_is_progress(&Operation::FsWrite {
            fd: Fd(1),
            bytes: vec![1]
        }));
        assert!(operation_is_progress(&Operation::TaskComplete {
            task: TaskId(1)
        }));
        assert!(operation_is_progress(&Operation::EntropyFill { len: 4 }));
    }

    #[test]
    fn watchdog_arm_excuses_policy_deferral_windows() {
        // The CRITICAL COUPLING: while the scheduler reports a deliberate
        // deferral, no-progress must NOT accrue toward the budget — a starvation
        // interval or PCT priority deferral is never a liveness violation.
        let mut arm = WatchdogArm {
            kind: LivenessKind::NoProgress,
            arm_time_nanos: 0,
            budget_nanos: 1_000,
            armed: false,
            baseline_nanos: 0,
            stall_ops: 0,
        };
        // Virtual time races far past the budget, but every step is a policy
        // deferral, so the arm never fires and the baseline keeps advancing.
        for now in [500u64, 1_000, 5_000, 50_000, 500_000] {
            assert!(arm.observe(now, false, true).is_none());
        }
        // Once deferral stops, genuine no-progress accrues from the current time
        // and eventually trips the budget.
        assert!(arm.observe(500_500, false, false).is_none()); // stall 1
        assert!(arm.observe(501_000, false, false).is_none()); // stall 2
        assert!(arm.observe(501_400, false, false).is_none()); // stall 3
        // stall 4 and elapsed (501_600-500_000=1_600) > 1_000 -> fire.
        assert!(arm.observe(501_600, false, false).is_some());
    }

    #[test]
    fn watchdog_arm_ignores_a_single_long_but_legitimate_sleep() {
        // One huge no-progress jump (a single legitimate sleep) must not trip the
        // watchdog: only genuine churn (>= LIVENESS_MIN_STALL_OPS non-progress
        // ops) can. A progress op then resets the clock.
        let mut arm = WatchdogArm {
            kind: LivenessKind::NoProgress,
            arm_time_nanos: 0,
            budget_nanos: 1_000,
            armed: false,
            baseline_nanos: 0,
            stall_ops: 0,
        };
        // A single sleep past the budget: only one stall op, below the floor.
        assert!(arm.observe(1_000_000, false, false).is_none());
        // Genuine progress resets.
        assert!(arm.observe(1_000_001, true, false).is_none());
        assert_eq!(arm.stall_ops, 0);
    }

    #[test]
    fn liveness_watchdog_fires_on_virtual_time_no_progress_wedge() {
        // A single-task loop that only advances the virtual clock (sleep) with no
        // genuine effect is a pure-churn wedge: the watchdog fires deterministically
        // rather than letting virtual time march to a step budget silently.
        let mut context =
            Context::from_config(RuntimeConfig::seeded(1).with_liveness(LivenessConfig {
                no_progress_budget_nanos: Some(1_000),
                converge_budget_nanos: None,
                heal_after_nanos: None,
            }))
            .unwrap();
        let mut fired = None;
        for _ in 0..1_000 {
            if let Err(error) = context.sleep_for(500) {
                fired = Some(error);
                break;
            }
        }
        match fired {
            Some(RuntimeError::Liveness { kind, .. }) => {
                assert_eq!(kind, LivenessKind::NoProgress);
            }
            other => panic!("expected a liveness violation, got {other:?}"),
        }
    }

    #[test]
    fn heal_then_converge_only_arms_after_the_fault_window() {
        // The converge arm arms at H (here 5_000 ns) and must not fire before then,
        // even though the guest is already wedged; after H it enforces the
        // convergence budget and fires.
        let mut context =
            Context::from_config(RuntimeConfig::seeded(1).with_liveness(LivenessConfig {
                no_progress_budget_nanos: None,
                converge_budget_nanos: Some(1_000),
                heal_after_nanos: Some(5_000),
            }))
            .unwrap();
        let mut fired_at_iter = None;
        for iteration in 0..1_000 {
            if let Err(RuntimeError::Liveness { kind, .. }) = context.sleep_for(500) {
                assert_eq!(kind, LivenessKind::HealThenConverge);
                fired_at_iter = Some(iteration);
                break;
            }
        }
        // sleep_for advances 500 ns/iteration, so ~10 iterations to reach H=5_000
        // and ~2 more (plus the min-stall floor) before the 1_000 ns budget trips.
        let fired = fired_at_iter.expect("converge watchdog must fire");
        assert!(
            fired >= 10,
            "must not fire before the fault window (H): {fired}"
        );
    }

    #[test]
    fn liveness_watchdog_does_not_fire_on_a_run_that_makes_progress() {
        // A run that keeps doing genuine effects (writes) between sleeps never
        // trips the watchdog: each write resets the no-progress clock.
        let mut context =
            Context::from_config(RuntimeConfig::seeded(1).with_liveness(LivenessConfig {
                no_progress_budget_nanos: Some(1_000),
                converge_budget_nanos: None,
                heal_after_nanos: None,
            }))
            .unwrap();
        for index in 0..50 {
            context
                .write_file(&format!("/f{index}"), b"progress")
                .unwrap();
            context.sleep_for(10_000).unwrap();
        }
        context.finish().unwrap();
    }

    #[test]
    fn liveness_watchdog_is_schedule_invariant_when_no_violation_fires() {
        // The schedule-invariance proof: recording a healthy run with the watchdog
        // enabled produces a byte-identical recorded op stream to recording it
        // without. The watchdog only ADDS a possible report; it never records a
        // boundary op nor perturbs selection. The metadata differs only by the
        // informational (non-fingerprinted) watchdog field.
        let dir = tempdir().unwrap();
        let plain = dir.path().join("plain.patina");
        let watched = dir.path().join("watched.patina");
        let run = |path: &std::path::Path, liveness: LivenessConfig| {
            let mut context = Context::from_config(
                RuntimeConfig::record(7, path, "wd-invariance-v1").with_liveness(liveness),
            )
            .unwrap();
            context.write_file("/f", b"hello").unwrap();
            context.sleep_for(1_000).unwrap();
            let _ = context.read_file("/f").unwrap();
            context.finish().unwrap();
        };
        run(&plain, LivenessConfig::default());
        run(
            &watched,
            LivenessConfig {
                no_progress_budget_nanos: Some(10_000_000_000),
                converge_budget_nanos: Some(10_000_000_000),
                heal_after_nanos: None,
            },
        );
        let a = TraceBundle::load(&plain).unwrap();
        let b = TraceBundle::load(&watched).unwrap();
        assert_eq!(
            a.timelines, b.timelines,
            "the watchdog must not perturb the recorded op stream"
        );
        assert!(a.metadata.watchdog.is_none());
        let record = b.metadata.watchdog.expect("watchdog recorded");
        assert_eq!(record.no_progress_budget_nanos, Some(10_000_000_000));
        assert_eq!(record.converge_budget_nanos, Some(10_000_000_000));
        // Fingerprint is unchanged by the watchdog (schedule-invariant).
        assert_eq!(a.metadata.fingerprint, b.metadata.fingerprint);
    }

    #[test]
    fn watchdog_config_is_recorded_and_replay_ignores_it() {
        // A watchdog trace replays against a build with no watchdog (informational
        // metadata, not reconciled fail-closed) — the op stream is authoritative.
        let dir = tempdir().unwrap();
        let path = dir.path().join("wd.patina");
        {
            let mut context = Context::from_config(
                RuntimeConfig::record(3, &path, "wd-replay-v1").with_liveness(LivenessConfig {
                    no_progress_budget_nanos: Some(1_000_000),
                    converge_budget_nanos: None,
                    heal_after_nanos: None,
                }),
            )
            .unwrap();
            context.write_file("/f", b"data").unwrap();
            context.finish().unwrap();
        }
        // Replay with NO watchdog configured: must succeed (config not reconciled).
        // Re-issue the same recorded op stream (the write).
        let mut replay =
            Context::from_config(RuntimeConfig::replay(&path, "wd-replay-v1")).unwrap();
        replay.write_file("/f", b"data").unwrap();
        replay.finish().unwrap();
    }

    #[test]
    fn run_with_context_finalizes_recording_when_the_application_returns_an_error() {
        // The explicit-context `run` path always finalizes: a recorded run whose
        // closure fails still flushes the trace and surfaces the closure error.
        let directory = tempdir().unwrap();
        let trace = directory.path().join("failed-run.patina");
        let context = Context::from_config(RuntimeConfig::record(5, &trace, "fixture-v1")).unwrap();
        let result = run_with_context(context, |_| {
            Err::<(), _>(EffectError::new(ErrorCode::Denied, "application failed").into())
        });
        assert!(matches!(result, Err(RuntimeError::Effect(_))));
        assert!(trace.is_file());
    }
}
