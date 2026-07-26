//! Runtime registry, deterministic drivers, and trace execution modes.

use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};

use patina_abi::{
    ClockKind, Datagram, EffectError, ErrorCode, Fd, FsDirectoryEntry, FsMetadata, OpenFlags,
    Operation, Outcome, SeekWhence, SendReport, ShutdownHow, SocketId, TaskId, TcpAccepted,
};
use patina_driver_api::{ClockDriver, EntropyDriver, FsDriver, NetDriver, SchedulerDriver};
use patina_fs_crash::CrashFs;
pub use patina_fs_crash::TornGranularity;
use patina_fs_mem::MemFs;
use patina_net_sim::SimNet;
use patina_rng_seeded::{SeededEntropy, SplitMix64};
use patina_sched_det::DetScheduler;
use patina_time_virtual::VirtualClock;
pub use patina_trace::MAX_TRACE_BYTES;
use patina_trace::{BranchSession, Recorder, Replayer, RunMetadata, TraceBundle, TraceError};

pub const ENV_MODE: &str = "PATINA_MODE";
pub const ENV_SEED: &str = "PATINA_SEED";
pub const ENV_TRACE: &str = "PATINA_TRACE";
pub const ENV_TRACE_FD: &str = "PATINA_TRACE_FD";
/// Inherited host descriptor carrying an encoded `patina_fs_mem::FsImage`. When
/// set, `native-run` streams a read-only host directory tree into the guest and
/// the shim rebuilds it as the deterministic filesystem instead of an empty one,
/// so a fully interposed guest sees a fixed corpus without touching the host.
/// The image's hash is folded into the run fingerprint, so replay rejects a
/// different corpus. Off when unset.
pub const ENV_FS_IMAGE_FD: &str = "PATINA_FS_IMAGE_FD";
pub const ENV_FINGERPRINT: &str = "PATINA_FINGERPRINT";
pub const ENV_BRANCH_FROM: &str = "PATINA_BRANCH_FROM";
pub const ENV_BRANCH_SEED: &str = "PATINA_BRANCH_SEED";
pub const ENV_BRANCH_ID: &str = "PATINA_BRANCH_ID";
pub const ENV_PARENT_TIMELINE: &str = "PATINA_PARENT_TIMELINE";
pub const ENV_TIMELINE: &str = "PATINA_TIMELINE";
pub const ENV_STEP_BUDGET: &str = "PATINA_STEP_BUDGET";
pub const ENV_PARAMS_JSON: &str = "PATINA_PARAMS_JSON";
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

const DEFAULT_FINGERPRINT: &str = "direct-seeded-run-v1";
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeConfig {
    seed: u64,
    mode: ExecutionMode,
    fingerprint: String,
    step_budget: Option<u64>,
    params: BTreeMap<String, String>,
    net_latency_nanos: u64,
    faults: FaultConfig,
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

pub struct RuntimeBuilder {
    config: RuntimeConfig,
    install_defaults: bool,
    trace_transport: Option<Box<dyn TraceTransport>>,
    filesystem: Option<Box<dyn FsDriver>>,
    filesystem_is_capture: bool,
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

        // A replayed or branched trace supplies its own authoritative fault
        // configuration, applied to `self.config` after the match releases its
        // borrow. `None` leaves the operator-supplied configuration in place.
        let mut replay_fault_override: Option<(FaultConfig, u64)> = None;
        let (execution, root_seed) = match &self.config.mode {
            ExecutionMode::Seeded => (Execution::Seeded, self.config.seed),
            ExecutionMode::Record { path } => (
                Execution::Record {
                    recorder: Recorder::new(
                        RunMetadata::new(self.config.seed, self.config.fingerprint.clone())
                            .with_faults(Some(fault_record(&self.config))),
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
                            .with_faults(Some(fault_record(&self.config))),
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

        if self.install_defaults {
            // A configured crash point upgrades the default filesystem to the
            // crash-consistency model so an injected crash drops unsynced data.
            // An explicitly installed filesystem is left untouched.
            if self.filesystem.is_none() {
                self.filesystem = Some(if self.config.faults.crash_at.is_some() {
                    Box::new(
                        CrashFs::builder()
                            .seed(root_seed)
                            .torn_granularity(self.config.faults.torn_granularity)
                            .build()
                            .map_err(RuntimeError::Effect)?,
                    )
                } else {
                    Box::new(MemFs::new())
                });
            }
            self.clock
                .get_or_insert_with(|| Box::new(VirtualClock::default()));
            self.entropy
                .get_or_insert_with(|| Box::new(SeededEntropy::new(root_seed)));
            self.scheduler
                .get_or_insert_with(|| Box::new(DetScheduler::new(root_seed)));
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
///   (buggy-smoke `lost-update`) while one interposed boundary clears it.
#[cfg(target_os = "macos")]
const SCAFFOLDING_YIELD_FLOOR: u64 = 4;
#[cfg(not(target_os = "macos"))]
const SCAFFOLDING_YIELD_FLOOR: u64 = 0;

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
                    Some(end) => (end.saturating_sub(spawn_step), TaskCompletionCause::Completed),
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
                // exact shape of the buggy-smoke `lost-update` race window, and
                // the yield count is invariant to its iteration count.
                // A spawned worker (order > 0) is vacuous when its yields do not
                // exceed the platform scaffolding floor. Written as `!(> floor)`
                // rather than `<= floor` so the comparison stays valid when the
                // floor is the type minimum (Linux = 0), where `<= 0` would trip
                // clippy::absurd_extreme_comparisons.
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
    /// the `write` crash ordinal, so `--fs-crash-at write:N` fires on redb's
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

    pub fn finish(self) -> Result<(), RuntimeError> {
        emit_schedule_report(&self.schedule.diagnostics());
        match self.execution {
            Execution::Seeded => Ok(()),
            Execution::Record { recorder, sink } => match sink {
                RecordSink::Path { path, _reservation } => {
                    recorder.finish(path).map_err(Into::into)
                }
                RecordSink::Transport(mut transport) => {
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
fn crash_op_to_record(op: CrashOp) -> patina_trace::FaultCrashOp {
    match op {
        CrashOp::Open => patina_trace::FaultCrashOp::Open,
        CrashOp::Write => patina_trace::FaultCrashOp::Write,
        CrashOp::Sync => patina_trace::FaultCrashOp::Sync,
        CrashOp::Close => patina_trace::FaultCrashOp::Close,
    }
}

fn crash_op_from_record(op: patina_trace::FaultCrashOp) -> CrashOp {
    match op {
        patina_trace::FaultCrashOp::Open => CrashOp::Open,
        patina_trace::FaultCrashOp::Write => CrashOp::Write,
        patina_trace::FaultCrashOp::Sync => CrashOp::Sync,
        patina_trace::FaultCrashOp::Close => CrashOp::Close,
    }
}

fn torn_granularity_to_record(granularity: TornGranularity) -> patina_trace::TornGranularity {
    match granularity {
        TornGranularity::Block => patina_trace::TornGranularity::Block,
        TornGranularity::Byte => patina_trace::TornGranularity::Byte,
    }
}

fn torn_granularity_from_record(granularity: patina_trace::TornGranularity) -> TornGranularity {
    match granularity {
        patina_trace::TornGranularity::Block => TornGranularity::Block,
        patina_trace::TornGranularity::Byte => TornGranularity::Byte,
    }
}

/// Serialize the run's effective fault configuration into the trace record so a
/// fault run replays self-contained. `net_latency_nanos` is folded in because it
/// too shapes the recorded operation stream, so a flag-free replay must restore
/// it as well.
fn fault_record(config: &RuntimeConfig) -> patina_trace::FaultConfigRecord {
    patina_trace::FaultConfigRecord {
        crash_at: config
            .faults
            .crash_at
            .map(|point| patina_trace::CrashPointRecord {
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
fn fault_config_from_record(record: &patina_trace::FaultConfigRecord) -> (FaultConfig, u64) {
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
    recorded: Option<&patina_trace::FaultConfigRecord>,
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
Rebuild with `cargo patina native-build --yield-points` to make atomics-only race windows \
schedulable.",
            diag.vacuous.len(),
        );
    }
}

/// Parse an inclusive `MIN..MAX` nanosecond range, requiring `MIN <= MAX`.
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
    use patina_abi::ErrorCode;
    use patina_fs_crash::CrashFs;
    use patina_fs_host::HostCaptureFs;
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn reconcile_replay_faults_enforces_the_authoritative_trace_contract() {
        use patina_trace::{CrashPointRecord, FaultConfigRecord, FaultCrashOp};

        let stored = FaultConfigRecord {
            crash_at: Some(CrashPointRecord {
                op: FaultCrashOp::Close,
                ordinal: 1,
            }),
            torn_granularity: patina_trace::TornGranularity::Byte,
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
        // zero scheduling boundaries — like buggy-smoke `lost-update` on an
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
}
