//! Runtime configuration, fault settings, and control-plane parsing.

use crate::fs_crash::{CrashOp, CrashPoint};
use crate::network::builtin_dns_resolution;
use crate::reports::ReportConfig;
use crate::{
    DEFAULT_BOOT_ORIGIN_NANOS, DEFAULT_BUGGIFY_ACTIVATION_PERMILLE, DEFAULT_BUGGIFY_CUTOFF_NANOS,
    DEFAULT_BUGGIFY_FIRE_PERMILLE, DEFAULT_REALTIME_EPOCH_NANOS, ENV_GUEST_CWD, HOSTNAME_MAX_BYTES,
    RuntimeError, TornGranularity,
};
use patina_dst_sched_det::SchedulePolicy;
use std::collections::{BTreeMap, BTreeSet};

use std::path::PathBuf;

const DEFAULT_FINGERPRINT: &str = "direct-seeded-run-v1";

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

/// Seed-driven, default-off fault knobs layered onto the deterministic drivers.
/// Every field is inert at its default so a run that configures no fault behaves
/// exactly as before. Knobs are grouped by domain so new domains add a sub-struct
/// instead of more loose top-level fields.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FaultConfig {
    pub fs: FsFaultConfig,
    pub net: NetFaultConfig,
    pub clock: ClockFaultConfig,
    pub dns: DnsFaultConfig,
    pub entropy: EntropyFaultConfig,
    pub custom_op: CustomOpFaultConfig,
}

/// Filesystem fault knobs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FsFaultConfig {
    /// Inject a filesystem crash after a chosen boundary operation.
    pub crash_at: Option<CrashPoint>,
    /// Granularity at which the injected crash tears the final unsynced write.
    /// Inert without `crash_at`; defaults to whole-block.
    pub torn_granularity: TornGranularity,
    /// Seeded filesystem error probability in per-mille (0..=1000).
    pub error_permille: u16,
    /// Seeded short-read/short-write probability in per-mille (0..=1000).
    pub short_permille: u16,
    /// Inclusive `[min, max]` nanoseconds of seeded extra latency applied to
    /// every fault-eligible filesystem operation before it executes.
    pub latency_nanos: Option<(u64, u64)>,
}

/// Network fault knobs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NetFaultConfig {
    /// Base link latency in nanoseconds applied to the default `SimNet` network.
    pub latency_nanos: u64,
    /// Inclusive `[min, max]` nanoseconds of seeded per-datagram/segment delivery jitter.
    pub jitter_nanos: Option<(u64, u64)>,
    /// Seeded datagram drop probability in per-mille (0..=1000).
    pub drop_permille: u16,
    /// Seeded datagram duplication probability in per-mille (0..=1000). A
    /// duplicate is an independent copy with its own jitter draw.
    pub duplicate_permille: u16,
    /// Seeded probability in per-mille (0..=1000) that an otherwise-establishable
    /// TCP connection is refused.
    pub connect_refuse_permille: u16,
    /// Seeded probability in per-mille (0..=1000) that a fault-eligible
    /// established-stream operation tears the stream down with a reset.
    pub reset_permille: u16,
    /// Statically partitioned address pairs. Both directions of each pair are
    /// blocked: a datagram addressed across it is dropped and a connect across it
    /// is refused. Deterministic (rate 1.0), unlike the seeded knobs above.
    pub partitions: BTreeSet<(String, String)>,
    /// Virtual TCP receive-buffer size in bytes. `None` uses the driver default.
    /// Not a fault: a capacity setting whose smaller values make would-block
    /// behavior — and the guest's backpressure handling — reachable, so it has a
    /// swarm class (an environment shape a generation may or may not adopt) but
    /// no vacuity class (there is no "should have fired N times" rate to judge).
    pub tcp_buffer_bytes: Option<usize>,
}

/// DNS fault knobs. They act only on names the run's host table DEFINES: an
/// undefined name is NXDOMAIN as semantics, not as an injected fault.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DnsFaultConfig {
    /// Seeded resolution-failure probability in per-mille (0..=1000). On fire, a
    /// second draw picks NXDOMAIN (a stale or deleted record) or a transient
    /// timeout (a slow or unreachable resolver).
    pub fail_permille: u16,
    /// Inclusive `[min, max]` nanoseconds of seeded latency applied before every
    /// eligible resolution.
    pub latency_nanos: Option<(u64, u64)>,
}

/// Entropy fault knobs. Guest entropy has no undefined-input exemption the way
/// DNS does — every `Context::entropy_bytes` call is fault-eligible — so there is
/// only the one knob, no host-table-shaped semantic configuration alongside it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EntropyFaultConfig {
    /// Seeded entropy-request failure probability in per-mille (0..=1000). On
    /// fire, the request returns a deterministic named error instead of bytes.
    pub fail_permille: u16,
}

/// Guest custom-operation fault knobs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CustomOpFaultConfig {
    /// Seeded failure probability in per-mille (0..=1000) for custom operations
    /// the guest declared fault-eligible. On fire the operation's `perform`
    /// closure does NOT run and the guest receives the failure it declared,
    /// exactly as if the wrapped effect had failed.
    ///
    /// Applies only to declared-eligible operations: a custom op that declares
    /// no failure shape has no error the runtime could invent for it, and
    /// inventing one would mean handing a guest a value its own type does not
    /// admit.
    pub fail_permille: u16,
}

/// Clock fault knobs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClockFaultConfig {
    /// Inclusive `[min, max]` nanoseconds of seeded extra latency per guest sleep.
    pub sleep_jitter_nanos: Option<(u64, u64)>,
    /// Magnitude in nanoseconds of the seeded signed realtime-epoch jump applied
    /// to each `ClockKind::Realtime` read: an offset drawn uniformly in `[-hi,
    /// hi]`, independently per read. Zero (the default) is off.
    pub epoch_jump_nanos: u64,
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
    /// Elapsed virtual nanoseconds since guest start after which firing stops.
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
    /// Explicit converge arm-time: virtual nanoseconds elapsed since guest start.
    /// `None` derives it from the buggify cutoff / run start.
    pub heal_after_nanos: Option<u64>,
}

impl LivenessConfig {
    /// Whether any watchdog arm is configured.
    pub fn is_enabled(&self) -> bool {
        self.no_progress_budget_nanos.is_some() || self.converge_budget_nanos.is_some()
    }
}

/// Everything that determines a run: seed, [`ExecutionMode`], compatibility
/// fingerprint, fault/buggify/schedule/liveness knobs, and optional trace
/// metadata (guest argv, params).
///
/// Construct one with [`RuntimeConfig::seeded`] (or
/// [`record`](RuntimeConfig::record)/[`replay`](RuntimeConfig::replay)/
/// [`branch`](RuntimeConfig::branch)) and refine it with the `with_*` builder
/// methods, or read the whole thing from the `PATINA_*` control plane with
/// [`RuntimeConfig::from_env`]. Two runs with equal configs (and an identical
/// guest) produce byte-identical effect sequences.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeConfig {
    pub(super) seed: u64,
    pub(super) mode: ExecutionMode,
    pub(super) fingerprint: String,
    pub(super) step_budget: Option<u64>,
    pub(super) params: BTreeMap<String, String>,
    pub(super) faults: FaultConfig,
    pub(super) buggify: BuggifyConfig,
    /// The exploration scheduling policy (PCT / starvation). Default is the
    /// uniform-random policy, byte-for-byte the historical scheduler.
    pub(super) schedule_policy: SchedulePolicy,
    /// Whether swarm fault-class selection is enabled: a seed-derived subset of
    /// the enabled fault classes is applied this run instead of all of them.
    pub(super) swarm: bool,
    /// The guest program arguments (`argv[1..]`) recorded into the trace so a
    /// `replay` restores them flag-free. `None` records nothing (unset); `Some`
    /// (possibly empty) records the exact list. Not a fingerprint input.
    pub(super) guest_argv: Option<Vec<String>>,
    /// Deterministic guest environment values supplied at run startup. Empty by
    /// default; recorded into trace metadata when non-empty and restored on
    /// replay. Not a fingerprint input.
    pub(super) guest_env: BTreeMap<String, String>,
    /// The guest's initial working directory (a canonical absolute virtual
    /// path), or `None` for `/`. Recorded into trace metadata when supplied and
    /// restored on replay. Not a fingerprint input. The live cwd (`chdir`) is
    /// process state the native shim keeps; only the starting point is here.
    pub(super) guest_cwd: Option<String>,
    /// The run's virtual realtime epoch (Unix-time nanoseconds read by
    /// `ClockKind::Realtime` at monotonic zero), or `None` for
    /// [`DEFAULT_REALTIME_EPOCH_NANOS`]. `Some` only when supplied explicitly
    /// (or adopted from a replayed trace), which is what lets replay tell a
    /// conflicting operator value from the default. Recorded into trace
    /// metadata on every run and authoritative on replay. Not a fingerprint
    /// input.
    pub(super) realtime_epoch_nanos: Option<u64>,
    /// Machine uptime at guest start; recorded and authoritative on replay.
    /// None selects [`DEFAULT_BOOT_ORIGIN_NANOS`].
    pub(super) boot_origin_nanos: Option<u64>,
    /// The node name the guest's virtual kernel reports, or `None` for
    /// `patina_dst_syscalls::IDENTITY_HOSTNAME`. `Some` only when supplied
    /// explicitly (or adopted from a replayed trace), exactly like
    /// `realtime_epoch_nanos`. Recorded on every run, authoritative on replay,
    /// not a fingerprint input.
    pub(super) hostname: Option<String>,
    /// The DNS host table: the names this run resolves, and the virtual IPv4
    /// address each resolves to. Semantic configuration rather than a fault knob
    /// (like `params`): an undefined name is NXDOMAIN deterministically, and the
    /// `--dns-*` fault knobs act only on the names defined here. Recorded into
    /// trace metadata and reconciled on replay so a resolution reproduces without
    /// re-supplying the table. Not a fingerprint input — the recorded op stream
    /// already reflects every resolution outcome.
    pub(super) dns_entries: BTreeMap<String, String>,
    /// The liveness-watchdog configuration. Default (disabled) leaves a run
    /// byte-for-byte unchanged; enabling it only ADDS a possible violation report
    /// and is deliberately NOT a fingerprint input (schedule-invariant).
    pub(super) liveness: LivenessConfig,
    /// Which end-of-run diagnostic reports print. Presentation only: resolved
    /// once from the family's control plane, never fingerprinted, never recorded,
    /// never reconciled — a replay may silence a report the recording printed and
    /// still produce the identical op stream.
    pub(super) reports: ReportConfig,
    /// Whether syscall-user-dispatch was armed for this run (Linux/x86_64 managed
    /// run on a SUD kernel). Recorded into the trace's [`RunMetadata::sud`] so a
    /// cross-kernel replay is refused up front. `None` on every non-SUD run
    /// (macOS, non-SUD kernel, standalone). Set by the native shim from the C
    /// arming state; not a fingerprint input. SUD-DESIGN.md §7.3.
    pub(super) sud: Option<bool>,
    /// Whether the timestamp-counter trap (`prctl(PR_SET_TSC, PR_TSC_SIGSEGV)`)
    /// was armed for this run, so `rdtsc`/`rdtscp` were answered from the virtual
    /// clock. Recorded into the trace's [`RunMetadata::tsc`] and reconciled on
    /// replay for the same reason as `sud`: the two states observe the counter at
    /// different boundaries. `None` on every run that did not arm it.
    pub(super) tsc: Option<bool>,
    /// Where the runtime writes this run's structured facts document, or `None`
    /// (the default) to produce none. Presentation-adjacent like `reports`: it
    /// reaches no recorded byte, is never fingerprinted, and is never reconciled
    /// on replay.
    pub(super) facts_path: Option<std::path::PathBuf>,
    /// Native crash-restart incarnation id. Direct/cargo/WASI contexts stay at 0.
    pub(super) incarnation: u64,
    pub(super) require_crash_selector_reached: bool,
}

impl RuntimeConfig {
    pub fn seeded(seed: u64) -> Self {
        Self {
            seed,
            mode: ExecutionMode::Seeded,
            boot_origin_nanos: None,
            fingerprint: DEFAULT_FINGERPRINT.into(),
            step_budget: None,
            params: BTreeMap::new(),
            faults: FaultConfig::default(),
            buggify: BuggifyConfig::default(),
            schedule_policy: SchedulePolicy::default(),
            swarm: false,
            guest_argv: None,
            guest_env: BTreeMap::new(),
            guest_cwd: None,
            realtime_epoch_nanos: None,
            hostname: None,
            dns_entries: BTreeMap::new(),
            liveness: LivenessConfig::default(),
            reports: ReportConfig::default(),
            sud: None,
            tsc: None,
            facts_path: None,
            incarnation: 0,
            require_crash_selector_reached: false,
        }
    }

    pub fn record(seed: u64, path: impl Into<PathBuf>, fingerprint: impl Into<String>) -> Self {
        Self {
            seed,
            mode: ExecutionMode::Record { path: path.into() },
            boot_origin_nanos: None,
            fingerprint: fingerprint.into(),
            step_budget: None,
            params: BTreeMap::new(),
            faults: FaultConfig::default(),
            buggify: BuggifyConfig::default(),
            schedule_policy: SchedulePolicy::default(),
            swarm: false,
            guest_argv: None,
            guest_env: BTreeMap::new(),
            guest_cwd: None,
            realtime_epoch_nanos: None,
            hostname: None,
            dns_entries: BTreeMap::new(),
            liveness: LivenessConfig::default(),
            reports: ReportConfig::default(),
            sud: None,
            tsc: None,
            facts_path: None,
            incarnation: 0,
            require_crash_selector_reached: false,
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
            boot_origin_nanos: None,
            fingerprint: fingerprint.into(),
            step_budget: None,
            params: BTreeMap::new(),
            faults: FaultConfig::default(),
            buggify: BuggifyConfig::default(),
            schedule_policy: SchedulePolicy::default(),
            swarm: false,
            guest_argv: None,
            guest_env: BTreeMap::new(),
            guest_cwd: None,
            realtime_epoch_nanos: None,
            hostname: None,
            dns_entries: BTreeMap::new(),
            liveness: LivenessConfig::default(),
            reports: ReportConfig::default(),
            sud: None,
            tsc: None,
            facts_path: None,
            incarnation: 0,
            require_crash_selector_reached: false,
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
            boot_origin_nanos: None,
            fingerprint: fingerprint.into(),
            step_budget: None,
            params: BTreeMap::new(),
            faults: FaultConfig::default(),
            buggify: BuggifyConfig::default(),
            schedule_policy: SchedulePolicy::default(),
            swarm: false,
            guest_argv: None,
            guest_env: BTreeMap::new(),
            guest_cwd: None,
            realtime_epoch_nanos: None,
            hostname: None,
            dns_entries: BTreeMap::new(),
            liveness: LivenessConfig::default(),
            reports: ReportConfig::default(),
            sud: None,
            tsc: None,
            facts_path: None,
            incarnation: 0,
            require_crash_selector_reached: false,
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
            boot_origin_nanos: None,
            fingerprint: fingerprint.into(),
            step_budget: None,
            params: BTreeMap::new(),
            faults: FaultConfig::default(),
            buggify: BuggifyConfig::default(),
            schedule_policy: SchedulePolicy::default(),
            swarm: false,
            guest_argv: None,
            guest_env: BTreeMap::new(),
            guest_cwd: None,
            realtime_epoch_nanos: None,
            hostname: None,
            dns_entries: BTreeMap::new(),
            liveness: LivenessConfig::default(),
            reports: ReportConfig::default(),
            sud: None,
            tsc: None,
            facts_path: None,
            incarnation: 0,
            require_crash_selector_reached: false,
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
            boot_origin_nanos: None,
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
            faults: FaultConfig::default(),
            buggify: BuggifyConfig::default(),
            schedule_policy: SchedulePolicy::default(),
            swarm: false,
            guest_argv: None,
            guest_env: BTreeMap::new(),
            guest_cwd: None,
            realtime_epoch_nanos: None,
            hostname: None,
            dns_entries: BTreeMap::new(),
            liveness: LivenessConfig::default(),
            reports: ReportConfig::default(),
            sud: None,
            tsc: None,
            facts_path: None,
            incarnation: 0,
            require_crash_selector_reached: false,
        }
    }

    pub fn with_step_budget(mut self, budget: u64) -> Self {
        self.step_budget = Some(budget);
        self
    }

    /// Set the base link latency applied to the default `SimNet` network.
    pub fn with_net_latency_nanos(mut self, nanos: u64) -> Self {
        self.faults.net.latency_nanos = nanos;
        self
    }

    pub const fn net_latency_nanos(&self) -> u64 {
        self.faults.net.latency_nanos
    }

    /// Inject a filesystem crash after the `ordinal`-th (1-based) `op` boundary.
    pub fn with_crash_at(mut self, op: CrashOp, ordinal: u64) -> Self {
        self.faults.fs.crash_at = Some(CrashPoint { op, ordinal });
        self
    }

    /// Select whole-block or sub-block byte-granularity tearing for an injected
    /// crash. Inert without [`RuntimeConfig::with_crash_at`].
    pub fn with_fs_torn_granularity(mut self, granularity: TornGranularity) -> Self {
        self.faults.fs.torn_granularity = granularity;
        self
    }

    /// Fail eligible filesystem operations with the given per-mille (0..=1000)
    /// probability, choosing a seeded errno from the operation's error set.
    pub fn with_fs_error_permille(mut self, permille: u16) -> Self {
        self.faults.fs.error_permille = permille;
        self
    }

    /// Truncate filesystem reads and writes with the given per-mille (0..=1000)
    /// probability.
    pub fn with_fs_short_permille(mut self, permille: u16) -> Self {
        self.faults.fs.short_permille = permille;
        self
    }

    /// Add seeded extra latency to every fault-eligible filesystem operation,
    /// drawn from `[min, max]` and applied before the operation executes.
    pub fn with_fs_latency_nanos(mut self, min: u64, max: u64) -> Self {
        self.faults.fs.latency_nanos = Some((min, max));
        self
    }

    /// Fail eligible DNS resolutions with the given per-mille (0..=1000)
    /// probability, choosing NXDOMAIN or a transient timeout on each fire.
    pub fn with_dns_fail_permille(mut self, permille: u16) -> Self {
        self.faults.dns.fail_permille = permille;
        self
    }

    /// Add seeded extra latency to every eligible name resolution.
    pub fn with_dns_latency_nanos(mut self, min: u64, max: u64) -> Self {
        self.faults.dns.latency_nanos = Some((min, max));
        self
    }

    /// Fail guest entropy requests with the given per-mille (0..=1000)
    /// probability, returning a deterministic named error instead of bytes.
    pub fn with_entropy_fail_permille(mut self, permille: u16) -> Self {
        self.faults.entropy.fail_permille = permille;
        self
    }

    /// Fail guest custom operations that declared a failure shape with the given
    /// per-mille (0..=1000) probability, handing the guest its declared failure
    /// instead of running `perform`.
    pub fn with_custom_op_fail_permille(mut self, permille: u16) -> Self {
        self.faults.custom_op.fail_permille = permille;
        self
    }

    /// Define a name in the run's DNS host table. Names not defined here are
    /// NXDOMAIN; the `--dns-*` fault knobs act only on defined ones.
    pub fn with_dns_entry(
        mut self,
        name: impl Into<String>,
        address: impl Into<String>,
    ) -> Result<Self, RuntimeError> {
        let (name, address) = (name.into(), address.into());
        validate_dns_entry(&name, &address)?;
        self.dns_entries.insert(name, address);
        Ok(self)
    }

    /// The run's DNS host table.
    pub const fn dns_entries(&self) -> &BTreeMap<String, String> {
        &self.dns_entries
    }

    /// Add seeded extra latency to every guest sleep, drawn from `[min, max]`.
    pub fn with_sleep_jitter_nanos(mut self, min: u64, max: u64) -> Self {
        self.faults.clock.sleep_jitter_nanos = Some((min, max));
        self
    }

    /// Jump each realtime-epoch read by a seeded signed offset drawn uniformly
    /// in `[-hi, hi]`, saturating at 0.
    pub fn with_epoch_jump_nanos(mut self, hi: u64) -> Self {
        self.faults.clock.epoch_jump_nanos = hi;
        self
    }

    /// Add seeded per-datagram delivery jitter drawn from `[min, max]`.
    pub fn with_net_jitter_nanos(mut self, min: u64, max: u64) -> Self {
        self.faults.net.jitter_nanos = Some((min, max));
        self
    }

    /// Drop datagrams with the given per-mille (0..=1000) probability.
    pub fn with_net_drop_permille(mut self, permille: u16) -> Self {
        self.faults.net.drop_permille = permille;
        self
    }

    /// Deliver datagrams twice with the given per-mille (0..=1000) probability.
    pub fn with_net_duplicate_permille(mut self, permille: u16) -> Self {
        self.faults.net.duplicate_permille = permille;
        self
    }

    /// Refuse otherwise-establishable TCP connections with the given per-mille
    /// (0..=1000) probability.
    pub fn with_net_connect_refuse_permille(mut self, permille: u16) -> Self {
        self.faults.net.connect_refuse_permille = permille;
        self
    }

    /// Reset established TCP streams with the given per-mille (0..=1000)
    /// probability per fault-eligible stream operation.
    pub fn with_net_reset_permille(mut self, permille: u16) -> Self {
        self.faults.net.reset_permille = permille;
        self
    }

    /// Partition both directions between two exact virtual addresses.
    pub fn with_net_partition(mut self, left: impl Into<String>, right: impl Into<String>) -> Self {
        let left = left.into();
        let right = right.into();
        self.faults
            .net
            .partitions
            .insert((left.clone(), right.clone()));
        self.faults.net.partitions.insert((right, left));
        self
    }

    /// Set the virtual TCP receive-buffer size in bytes.
    pub fn with_net_tcp_buffer_bytes(mut self, bytes: usize) -> Self {
        self.faults.net.tcp_buffer_bytes = Some(bytes);
        self
    }

    pub const fn crash_at(&self) -> Option<CrashPoint> {
        self.faults.fs.crash_at
    }

    /// The configured torn-write granularity for `--fs-crash-at`. `Block`
    /// (whole-block revert) unless `--fs-torn-granularity byte` selected the
    /// sub-block model.
    pub const fn torn_granularity(&self) -> TornGranularity {
        self.faults.fs.torn_granularity
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

    /// Deterministic guest environment values supplied at startup.
    pub fn guest_env(&self) -> &BTreeMap<String, String> {
        &self.guest_env
    }

    /// Set deterministic guest environment values directly (tests and embedders).
    #[must_use]
    pub fn with_guest_env(mut self, guest_env: BTreeMap<String, String>) -> Self {
        self.guest_env = guest_env;
        self
    }

    /// The guest's initial working directory, or `None` for `/`.
    pub fn guest_cwd(&self) -> Option<&str> {
        self.guest_cwd.as_deref()
    }

    /// Set the guest's initial working directory directly (tests and
    /// embedders). Validated and canonicalized exactly as [`ENV_GUEST_CWD`] is.
    pub fn with_guest_cwd(mut self, guest_cwd: Option<&str>) -> Result<Self, RuntimeError> {
        self.guest_cwd = guest_cwd.map(validate_guest_cwd).transpose()?;
        Ok(self)
    }

    /// The run's virtual realtime epoch: the Unix-time nanoseconds
    /// `ClockKind::Realtime` reads at monotonic zero. The explicitly configured
    /// value, else [`DEFAULT_REALTIME_EPOCH_NANOS`].
    pub fn realtime_epoch_nanos(&self) -> u64 {
        self.realtime_epoch_nanos
            .unwrap_or(DEFAULT_REALTIME_EPOCH_NANOS)
    }

    /// Set the run's virtual realtime epoch explicitly (tests and embedders).
    /// The default clock adds uptime to it, the trace records it, and a replay
    /// whose trace recorded a different one is refused.
    #[must_use]
    pub fn with_realtime_epoch_nanos(mut self, realtime_epoch_nanos: u64) -> Self {
        self.realtime_epoch_nanos = Some(realtime_epoch_nanos);
        self
    }

    /// Initial monotonic/boottime reading, not elapsed execution or CPU time.
    pub fn boot_origin_nanos(&self) -> u64 {
        self.boot_origin_nanos.unwrap_or(DEFAULT_BOOT_ORIGIN_NANOS)
    }

    /// Configure machine uptime at guest start. Replayed traces supply their
    /// own origin; a conflicting explicit value is refused. The origin must be
    /// nonzero, and both it and epoch + origin must fit signed 64-bit nanoseconds.
    pub fn with_boot_origin_nanos(mut self, nanos: u64) -> Self {
        self.boot_origin_nanos = Some(nanos);
        self
    }

    /// The node name the guest's virtual kernel reports: the explicitly
    /// configured one, else `patina_dst_syscalls::IDENTITY_HOSTNAME`.
    pub fn hostname(&self) -> &str {
        self.hostname
            .as_deref()
            .unwrap_or(patina_dst_syscalls::IDENTITY_HOSTNAME)
    }

    /// Set the guest's node name explicitly (tests and embedders), validated by
    /// [`validate_hostname`]. Recorded into the trace; a replay whose trace
    /// recorded a different name is refused.
    pub fn with_hostname(mut self, hostname: &str) -> Result<Self, RuntimeError> {
        validate_hostname(hostname).map_err(RuntimeError::Config)?;
        self.hostname = Some(hostname.to_owned());
        Ok(self)
    }

    /// Whether syscall-user-dispatch was armed for this run, or `None` when SUD
    /// is not applicable.
    pub const fn sud(&self) -> Option<bool> {
        self.sud
    }

    /// Whether the timestamp-counter trap was armed for this run, or `None` when
    /// it was not (see the field docs).
    pub const fn tsc(&self) -> Option<bool> {
        self.tsc
    }

    /// Set whether syscall-user-dispatch was armed for this run. The native shim
    /// calls this from the C arming state so record captures it into the trace
    /// and replay reconciles it. `Some(true)` when armed; `None` otherwise.
    #[must_use]
    pub fn with_sud(mut self, sud: Option<bool>) -> Self {
        self.sud = sud;
        self
    }

    /// Record whether this run armed the timestamp-counter trap.
    #[must_use]
    pub fn with_tsc(mut self, tsc: Option<bool>) -> Self {
        self.tsc = tsc;
        self
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

    /// Install the end-of-run report-suppression preferences wholesale, for a
    /// family that resolved them from its own control plane (the native shim
    /// parses its pre-scrub environment snapshot once and shares the result with
    /// its own coverage finalization).
    #[must_use]
    pub const fn with_reports(mut self, reports: ReportConfig) -> Self {
        self.reports = reports;
        self
    }

    /// Write this run's structured [`patina.runfacts/v1`](FACTS_SCHEMA) document
    /// to `path` at finalization. The document carries the same per-plane
    /// accounting the `PATINA_*_REPORT` lines carry, built from the report
    /// structs; the lines still print. Independent of [`ReportConfig`], which
    /// governs printing only.
    #[must_use]
    pub fn with_facts_path(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.facts_path = Some(path.into());
        self
    }

    /// Which end-of-run diagnostic reports this run prints.
    #[must_use]
    pub const fn reports(&self) -> ReportConfig {
        self.reports
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

    pub const fn seed(&self) -> u64 {
        self.seed
    }

    pub const fn mode(&self) -> &ExecutionMode {
        &self.mode
    }

    pub fn with_incarnation(mut self, incarnation: u64) -> Self {
        self.incarnation = incarnation;
        self
    }

    pub fn require_crash_selector_reached(mut self) -> Self {
        self.require_crash_selector_reached = true;
        self
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

/// The kernel's rules for a node name, as `sethostname` applies them: at most
/// [`HOSTNAME_MAX_BYTES`] bytes (`__NEW_UTS_LEN`), and no NUL byte — the name
/// travels as a C string and an environment variable, where a NUL would
/// silently truncate it. The empty name is the kernel's to allow, so it is
/// allowed. Shared by the runtime and the CLI registry's value grammar, so the
/// flag and the control plane accept exactly the same names.
pub fn validate_hostname(hostname: &str) -> Result<(), String> {
    if hostname.contains('\0') {
        return Err(format!("hostname {hostname:?} contains a NUL byte"));
    }
    if hostname.len() > HOSTNAME_MAX_BYTES {
        return Err(format!(
            "hostname {hostname:?} is {} bytes; the kernel stores at most {HOSTNAME_MAX_BYTES}",
            hostname.len()
        ));
    }
    Ok(())
}

/// Reject a partition the network could not honor: an empty address on either
/// side, or a pair that partitions an address from itself. Fails closed at
/// configuration time, like [`validate_dns_entry`] — but note that a partition
/// naming addresses the run never uses is NOT rejected here (it cannot be known
/// up front); the network fault report's partition class diagnoses that at the
/// end of the run instead.
pub(super) fn validate_partition(left: &str, right: &str) -> Result<(), RuntimeError> {
    if left.trim().is_empty() || right.trim().is_empty() {
        return Err(RuntimeError::Config(
            "a network partition needs two non-empty virtual addresses".into(),
        ));
    }
    if left == right {
        return Err(RuntimeError::Config(format!(
            "a network partition needs two DIFFERENT addresses; got {left:?} twice"
        )));
    }
    Ok(())
}

/// Reject a DNS entry the resolver could not honor: an empty or address-shaped
/// name, or an address that is not a dotted-quad IPv4 literal. Fails closed at
/// configuration time rather than at the first lookup, so a typo in
/// `--dns-entry` is reported before the guest runs.
pub(super) fn validate_dns_entry(name: &str, address: &str) -> Result<(), RuntimeError> {
    if name.trim().is_empty() {
        return Err(RuntimeError::Config(
            "DNS entry name must not be empty".into(),
        ));
    }
    if builtin_dns_resolution(name).is_some() {
        return Err(RuntimeError::Config(format!(
            "DNS entry {name:?} shadows a built-in resolution (a numeric literal or localhost), \
             which resolves without the host table"
        )));
    }
    let octets: Vec<&str> = address.split('.').collect();
    if octets.len() != 4 || !octets.iter().all(|o| o.parse::<u8>().is_ok()) {
        return Err(RuntimeError::Config(format!(
            "DNS entry {name:?} must resolve to a dotted-quad IPv4 address; got {address:?}"
        )));
    }
    Ok(())
}

/// The initial working directory's invariant: absolute, NUL-free, no `..`
/// (a starting point is a NAME, and a name with parent traversal is a spelling
/// the resolver would have to walk symlinks to decide), canonicalized lexically
/// so `/work/` and `/work//./` name the same recorded value.
pub(super) fn validate_guest_cwd(path: &str) -> Result<String, RuntimeError> {
    if !path.starts_with('/') {
        return Err(RuntimeError::Config(format!(
            "{ENV_GUEST_CWD} must be an absolute virtual path, got {path:?}"
        )));
    }
    if path.contains('\0') {
        return Err(RuntimeError::Config(format!(
            "{ENV_GUEST_CWD} must not contain NUL bytes"
        )));
    }
    if path.split('/').any(|component| component == "..") {
        return Err(RuntimeError::Config(format!(
            "{ENV_GUEST_CWD} must not contain a `..` component, got {path:?}"
        )));
    }
    patina_dst_driver_api::canonicalize_path(path)
        .map_err(|error| RuntimeError::Config(format!("{ENV_GUEST_CWD}: {error}")))
}

pub(super) fn validate_guest_env(env: &BTreeMap<String, String>) -> Result<(), RuntimeError> {
    for (key, value) in env {
        validate_guest_env_entry(key, value)?;
    }
    Ok(())
}

/// The key half of the guest-environment invariant, shared by startup validation
/// and the in-run mutators so a `setenv` can never install an entry the startup
/// path would have rejected.
fn validate_guest_env_key(key: &str) -> Result<(), RuntimeError> {
    if key.is_empty() {
        return Err(RuntimeError::Config(
            "guest environment keys must not be empty".into(),
        ));
    }
    if key.contains('=') {
        return Err(RuntimeError::Config(format!(
            "guest environment key {key:?} must not contain '='"
        )));
    }
    if key.contains('\0') {
        return Err(RuntimeError::Config(format!(
            "guest environment entry {key:?} must not contain NUL bytes"
        )));
    }
    Ok(())
}

fn validate_guest_env_entry(key: &str, value: &str) -> Result<(), RuntimeError> {
    validate_guest_env_key(key)?;
    if value.contains('\0') {
        return Err(RuntimeError::Config(format!(
            "guest environment entry {key:?} must not contain NUL bytes"
        )));
    }
    Ok(())
}

#[cfg(test)]
pub(super) mod tests {
    use crate::config::{
        ClockFaultConfig, CustomOpFaultConfig, DnsFaultConfig, EntropyFaultConfig, FaultConfig,
        FsFaultConfig, NetFaultConfig, RuntimeConfig,
    };
    use crate::fs_crash::{CrashOp, CrashPoint};
    use crate::replay::{fault_config_from_record, fault_record};
    use crate::{Context, FaultKnob, Plane, TornGranularity};

    use std::collections::BTreeSet;

    /// Every fault knob must survive the trace round trip. A knob the record
    /// does not carry replays as its default — the run reproduces WITHOUT the
    /// fault that was recorded, which is silent inertness wearing a replay's
    /// clothes. Driven off [`FaultKnob::ALL`], so the gate grows with the enum
    /// rather than with a hand-kept sample list.
    #[test]
    fn every_fault_knob_survives_the_trace_record_round_trip() {
        for knob in FaultKnob::ALL {
            if knob.meta().plane != Plane::Fault {
                // The DNS host table has its own record (`DnsConfigRecord`) and
                // its own replay reconciliation; see `reconcile_replay_dns`.
                continue;
            }
            let mut config = RuntimeConfig::seeded(1);
            knob.set_sample(&mut config.faults);
            let record = fault_record(&config);
            assert_ne!(
                record,
                patina_dst_trace::FaultConfigRecord::default(),
                "{knob:?} left no trace in the recorded fault configuration"
            );
            assert_eq!(
                fault_config_from_record(&record),
                config.faults,
                "{knob:?} did not survive the record round trip"
            );
        }
    }

    /// The two halves of "every knob" must describe the same configuration: the
    /// FIELD view below, whose exhaustive struct literals make a new
    /// `*FaultConfig` field a compile error, and the KNOB view, whose exhaustive
    /// `set_sample` match makes a new [`FaultKnob`] one. A field added without a
    /// knob (unreachable from any CLI) or a knob added without a field (carried
    /// to the guest and then dropped) shows up here as a mismatch.
    #[test]
    fn fault_config_fields_and_fault_knobs_describe_the_same_configuration() {
        let mut from_knobs = FaultConfig::default();
        for knob in FaultKnob::ALL {
            knob.set_sample(&mut from_knobs);
        }
        assert_eq!(from_knobs, every_fault_knob_enabled());
    }

    /// Every fault knob at a non-default value, written as EXHAUSTIVE struct
    /// literals on purpose: a field added to any `*FaultConfig` sub-struct is a
    /// compile error right here, which is what drags a new knob through the
    /// swarm-coverage gate below instead of letting it land outside the swarm
    /// table unnoticed. (A `..Default::default()` tail would leave a new field
    /// silently absent — exactly the drift this gate exists to prevent.)
    pub(crate) fn every_fault_knob_enabled() -> FaultConfig {
        FaultConfig {
            fs: FsFaultConfig {
                crash_at: Some(CrashPoint {
                    op: CrashOp::Close,
                    ordinal: 1,
                }),
                torn_granularity: TornGranularity::Byte,
                error_permille: 1,
                short_permille: 1,
                latency_nanos: Some((1, 2)),
            },
            net: NetFaultConfig {
                latency_nanos: 1,
                jitter_nanos: Some((1, 2)),
                drop_permille: 1,
                duplicate_permille: 1,
                connect_refuse_permille: 1,
                reset_permille: 1,
                partitions: BTreeSet::from([
                    ("a".to_string(), "b".to_string()),
                    ("b".to_string(), "a".to_string()),
                ]),
                tcp_buffer_bytes: Some(4096),
            },
            clock: ClockFaultConfig {
                sleep_jitter_nanos: Some((1, 2)),
                epoch_jump_nanos: 1,
            },
            dns: DnsFaultConfig {
                fail_permille: 1,
                latency_nanos: Some((1, 2)),
            },
            entropy: EntropyFaultConfig { fail_permille: 1 },
            custom_op: CustomOpFaultConfig { fail_permille: 1 },
        }
    }

    #[test]
    fn typed_builder_parameters_are_explicit() {
        let config = RuntimeConfig::seeded(1).with_param("zone", "a").unwrap();
        let context = Context::from_config(config).unwrap();
        assert_eq!(context.param("zone"), Some("a"));
        assert_eq!(context.param("missing"), None);
    }
}
