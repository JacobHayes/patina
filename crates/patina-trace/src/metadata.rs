//! Run metadata and recorded configuration.

use std::collections::{BTreeMap, BTreeSet};

use patina_dst_abi::TaskId;
use serde::{Deserialize, Serialize};

/// The boundary-operation kind a filesystem crash is pinned to. Serialized by
/// name (snake_case) so it round-trips independent of declaration order, mirror
/// of the runtime's `CrashOp`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FaultCrashOp {
    Open,
    Write,
    Sync,
    Close,
}

/// Granularity at which a torn write reverts on crash, mirror of the fs-crash
/// `TornGranularity`. Serialized by name so the default stays legible.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TornGranularity {
    #[default]
    Block,
    Byte,
}

/// Where a filesystem crash is injected: after the `ordinal`-th (1-based)
/// occurrence of `op`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrashPointRecord {
    pub op: FaultCrashOp,
    pub ordinal: u64,
}

/// The full seed-driven fault-injection configuration of a recorded run. Stored
/// in the trace metadata so replay reproduces the run's faults without any flag
/// re-supply. Every field defaults to inert and is omitted from the serialized
/// form when at its default, so a fault-free run records a compact empty object.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FaultConfigRecord {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crash_at: Option<CrashPointRecord>,
    #[serde(default, skip_serializing_if = "torn_granularity_is_block")]
    pub torn_granularity: TornGranularity,
    #[serde(default, skip_serializing_if = "is_zero_u16")]
    pub fs_error_permille: u16,
    #[serde(default, skip_serializing_if = "is_zero_u16")]
    pub fs_short_permille: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fs_latency_nanos: Option<(u64, u64)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sleep_jitter_nanos: Option<(u64, u64)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub net_jitter_nanos: Option<(u64, u64)>,
    #[serde(default, skip_serializing_if = "is_zero_u16")]
    pub net_drop_permille: u16,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub net_latency_nanos: u64,
    #[serde(default, skip_serializing_if = "is_zero_u16")]
    pub net_duplicate_permille: u16,
    #[serde(default, skip_serializing_if = "is_zero_u16")]
    pub net_connect_refuse_permille: u16,
    #[serde(default, skip_serializing_if = "is_zero_u16")]
    pub net_reset_permille: u16,
    /// Statically partitioned address pairs, in the runtime's stable key order.
    /// Both directions of each pair are stored, so the record is the partition
    /// set verbatim rather than a canonical half of it.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub net_partitions: BTreeSet<(String, String)>,
    /// Virtual TCP receive-buffer size in bytes, `u64` rather than `usize` so the
    /// record is independent of the recording target's pointer width.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub net_tcp_buffer_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "is_zero_u16")]
    pub dns_fail_permille: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_latency_nanos: Option<(u64, u64)>,
    #[serde(default, skip_serializing_if = "is_zero_u16")]
    pub entropy_fail_permille: u16,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub epoch_jump_nanos: u64,
    /// Per-mille rate at which a guest-declared fault-eligible custom operation
    /// returns its declared failure instead of running `perform`.
    #[serde(default, skip_serializing_if = "is_zero_u16")]
    pub custom_op_fail_permille: u16,
}

/// The DNS host table of a recorded run: the names it could resolve and the
/// virtual IPv4 address each resolved to. Stored in the trace metadata so a
/// replay is flag-free and a conflicting table at replay fails closed, exactly
/// like [`FaultConfigRecord`]. Resolution OUTCOMES are recorded operations in
/// their own right, so this record is for self-description and conflict
/// detection rather than for correctness.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsConfigRecord {
    /// Name -> dotted-quad IPv4 address, in the runtime's stable key order.
    pub entries: BTreeMap<String, String>,
}

/// The seed-driven cooperative-SUT (buggify) configuration of a recorded run.
/// Stored in the trace metadata so replay reproduces the same activation and
/// firing decisions without any flag re-supply, exactly like [`FaultConfigRecord`].
///
/// Buggify decisions are pure deterministic functions of `(root_seed, site
/// label, config)` and are NOT recorded per-evaluation (that would bloat the
/// trace), so replay re-derives them from this config. The `active_sites` and
/// `knobs` fields are the run's realized activation/knob picks: authoritative on
/// replay and surfaced in the `PATINA_SDK_REPORT` line, they also make a trace
/// self-describing. This field is absent (`None`) in traces recorded before
/// buggify shipped, which the runtime treats as buggify-disabled.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuggifyConfigRecord {
    /// Per-evaluation firing probability in per-mille (0..=1000) for an active
    /// site. FoundationDB's default is 25% (250).
    pub fire_permille: u16,
    /// Per-run site activation probability in per-mille (0..=1000): the fraction
    /// of sites made active for this run. FoundationDB's default is 25% (250).
    pub activation_permille: u16,
    /// Elapsed virtual nanoseconds since guest start after which buggify stops firing
    /// (FoundationDB's damage-control window), so late-run steady state is not
    /// perturbed forever. Default 300 virtual seconds.
    pub cutoff_nanos: u64,
    /// Whether the runner declared (`--buggify-after-setup`) that the guest calls
    /// `patina_dst::lifecycle::setup_complete()`, so buggify stays inert until that
    /// call. Recorded so replay reproduces the same gating. Omitted when false.
    #[serde(default, skip_serializing_if = "is_false")]
    pub after_setup: bool,
    /// Labels of the sites that were activated during the run, in first-seen
    /// order. Authoritative on replay and reported at finalization.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub active_sites: Vec<String>,
    /// Realized per-run knob values keyed by site label, in label order.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub knobs: BTreeMap<String, i64>,
}

/// The PCT (Probabilistic Concurrency Testing) scheduling parameters of a
/// recorded run. Mirror of the runtime's `PctConfig`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PctPolicyRecord {
    /// Target bug depth `d`; `d-1` priority-change points are placed.
    pub depth: u32,
    /// Expected schedule length over which the change points are distributed.
    pub steps: u64,
}

/// The starvation-interval scheduling parameters of a recorded run. Mirror of the
/// runtime's `StarvationConfig`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StarvationPolicyRecord {
    /// Number of bounded starvation intervals placed over the schedule.
    pub intervals: u32,
    /// Maximum length (scheduling decisions) of any interval; every interval is
    /// bounded so it always ends.
    pub max_len: u64,
    /// Interval starts are placed uniformly in `[1, window]`.
    pub window: u64,
}

/// The seed-driven exploration scheduling policy (PCT priority-change points,
/// starvation intervals) of a recorded run. Stored in the trace metadata so a
/// replay knows the policy that produced the recorded schedule, and enabling a
/// non-default policy folds a fingerprint component so a cross-policy replay
/// fails closed. Absent (`None`) in traces recorded under the default uniform
/// policy or before this field existed — either way the runtime treats a missing
/// field as the default policy, and `deny_unknown_fields` means an older runtime
/// reading a newer trace rejects the unknown field rather than silently ignoring
/// the policy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulePolicyRecord {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pct: Option<PctPolicyRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub starvation: Option<StarvationPolicyRecord>,
}

impl SchedulePolicyRecord {
    /// Whether this record describes any non-default policy.
    pub fn is_active(&self) -> bool {
        self.pct.is_some() || self.starvation.is_some()
    }
}

/// Swarm fault-class selection of a recorded run: the candidate fault classes the
/// operator enabled and the seed-derived subset actually applied this generation.
/// The applied [`FaultConfigRecord`] already reflects the masked (selected)
/// configuration, so replay reproduces the faults from it verbatim; this record
/// documents the swarm *intent* (candidates) and *decision* (selection) so the
/// trace is self-describing and a `+swarm` fingerprint rejects a non-swarm
/// replay. Class names are stable snake_case tokens (`crash`, `fs_error`,
/// `fs_short`, `sleep_jitter`, `net_jitter`, `net_drop`, `net_latency`,
/// `buggify`). Absent (`None`) when swarm was not enabled.
///
/// The two lists partition the run's swarm decision: `selected_classes` is a
/// subset of `candidate_classes` (enforced by [`TraceBundle::validate`]), so the
/// complement — the classes this generation dropped — is exactly
/// [`SwarmConfigRecord::deselected_classes`]. A class the operator never enabled
/// appears in NEITHER list, which is what makes "swarm dropped it here"
/// distinguishable from "it was never asked for": the first names the class as a
/// candidate, the second does not mention it at all.
///
/// A dropped class is also retracted from the run's compatibility fingerprint
/// (see `patina_dst_runtime::FINGERPRINT_BUGGIFY`), so a masked run's fingerprint
/// and its `buggify`/`faults` records agree — the trace never declares coverage
/// this generation did not carry.
///
/// Both lists are in the runtime's stable class-table order, not alphabetical
/// order; that order is a property of the table, so it is stable across runs and
/// safe to compare byte-for-byte.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwarmConfigRecord {
    /// Fault classes that were candidates for this run (the operator-enabled
    /// set), in stable class-table order.
    pub candidate_classes: Vec<String>,
    /// Fault classes the run seed selected to keep active this generation, in
    /// stable class-table order — a subset of `candidate_classes`.
    pub selected_classes: Vec<String>,
}

impl SwarmConfigRecord {
    /// Whether `class` was a candidate this run that the seed's swarm draw
    /// dropped. False both for a selected class and for a class that was never a
    /// candidate; callers needing to tell those apart also consult
    /// [`SwarmConfigRecord::was_candidate`].
    pub fn deselected(&self, class: &str) -> bool {
        self.was_candidate(class) && !self.selected_classes.iter().any(|name| name == class)
    }

    /// Whether `class` was enabled by the operator and therefore subject to this
    /// run's swarm draw.
    pub fn was_candidate(&self, class: &str) -> bool {
        self.candidate_classes.iter().any(|name| name == class)
    }

    /// Whether the swarm draw had nothing to draw from: the run asked for swarm
    /// fault-class selection while no swarm-maskable fault class was enabled, so
    /// the draw could neither keep nor drop anything and the run explored exactly
    /// the configuration it would have explored without swarm. An empty selection
    /// over a NON-empty candidate set is not vacuous — dropping every candidate is
    /// a legitimate draw, and exploring that subset is the point of swarm testing.
    pub fn is_vacuous(&self) -> bool {
        self.candidate_classes.is_empty()
    }

    /// The candidate classes this generation dropped, in candidate order. Derived
    /// from the two stored lists rather than stored alongside them, so the
    /// partition cannot drift out of agreement with itself.
    pub fn deselected_classes(&self) -> Vec<&str> {
        self.candidate_classes
            .iter()
            .filter(|class| !self.selected_classes.iter().any(|name| name == *class))
            .map(String::as_str)
            .collect()
    }
}

/// The liveness-watchdog configuration of a recorded run. The watchdog is a
/// virtual-time no-progress detector: it reports a structured `PATINA_LIVENESS`
/// violation rather than letting a wedged run advance virtual time forever.
///
/// This record is **purely informational**: unlike the fault, buggify, and
/// schedule-policy records it is deliberately *not* folded into the compatibility
/// fingerprint and is *not* reconciled fail-closed on replay. The watchdog only
/// ever ADDS a violation report — it never records a boundary operation and never
/// perturbs scheduler selection — so a trace recorded with the watchdog enabled is
/// byte-for-byte identical to one recorded without it (when no violation fires),
/// and either trace replays against a build with any watchdog configuration.
/// Recording it keeps the trace self-describing (which budgets were armed).
/// Absent (`None`) in traces recorded with the watchdog disabled or before this
/// field existed, which the runtime treats as "no watchdog".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchdogConfigRecord {
    /// Generic no-progress budget in virtual nanoseconds, armed from run start.
    /// Absent when the generic arm was not enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_progress_budget_nanos: Option<u64>,
    /// Heal-then-converge budget in virtual nanoseconds, armed at the fault-window
    /// end. Absent when the converge arm was not enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub converge_budget_nanos: Option<u64>,
    /// The virtual monotonic time (nanoseconds) at which the converge arm arms
    /// (the fault-window end). Absent when the converge arm was not enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heal_after_nanos: Option<u64>,
}

impl WatchdogConfigRecord {
    /// Whether any watchdog arm was configured.
    pub fn is_active(&self) -> bool {
        self.no_progress_budget_nanos.is_some() || self.converge_budget_nanos.is_some()
    }
}

fn torn_granularity_is_block(granularity: &TornGranularity) -> bool {
    matches!(granularity, TornGranularity::Block)
}

fn is_zero_u16(value: &u16) -> bool {
    *value == 0
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn is_zero_u64(value: &u64) -> bool {
    *value == 0
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunMetadata {
    pub root_seed: u64,
    pub decision_policy: String,
    pub fingerprint: String,
    /// The run's fault-injection configuration, authoritative on replay.
    /// Absent (`None`) in traces recorded before format 4, which the runtime
    /// treats as the pre-metadata re-supply contract.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub faults: Option<FaultConfigRecord>,
    /// The run's cooperative-SUT (buggify) configuration, authoritative on
    /// replay. Additive: absent (`None`) in traces recorded without buggify,
    /// which the runtime treats as buggify-disabled. A native trace whose textual
    /// fingerprint declares `+buggify` must not omit this field; that would claim
    /// SDK-fault coverage without an armed SDK config. A conflicting explicit
    /// knob at replay fails closed exactly like
    /// [`RunMetadata::faults`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub buggify: Option<BuggifyConfigRecord>,
    /// The run's DNS host table, authoritative on replay. Additive exactly like
    /// [`RunMetadata::faults`]: absent in traces recorded without a table, which
    /// the runtime treats as an empty one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsConfigRecord>,
    /// The guest program arguments (everything after `--`, i.e. `argv[1..]`) the
    /// run was executed with, recorded so a `replay` reproduces them without the
    /// operator re-passing the `--` section. Additive exactly like
    /// [`RunMetadata::faults`] and [`RunMetadata::buggify`]: absent (`None`) in
    /// traces recorded before argv was captured,
    /// which the replay path treats as "no recorded argv" and falls back to the
    /// historical contract of taking the arguments from the command line. A run
    /// with no guest arguments records an empty vector (`Some([])`), which is
    /// distinct from an old trace's absent field (`None`) — so replaying a
    /// zero-argument run reproduces zero arguments rather than silently accepting
    /// whatever the command line supplies. [`RunMetadata::root_seed`] is not a
    /// fingerprint input and neither is this: the recorded op-stream already
    /// reflects any argv-dependent guest behavior.
    ///
    /// `argv[0]` is deliberately not recorded: it is supervisor-synthesized to a
    /// fixed, machine-independent value (never the host binary path), so there is
    /// nothing run-specific to reproduce.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guest_argv: Option<Vec<String>>,
    /// Deterministic guest environment values supplied by the supervisor (native
    /// `run --env KEY=VALUE`). Additive exactly like [`guest_argv`](RunMetadata::guest_argv):
    /// absent (`None`) in traces recorded before env capture or when no values
    /// were supplied; present values are authoritative on replay so a flag-free
    /// replay reproduces environment-dependent guest behavior.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guest_env: Option<BTreeMap<String, String>>,
    /// The guest's initial working directory (native `run --cwd PATH`), the
    /// canonical absolute virtual path the run's `getcwd` starts at. Additive
    /// exactly like [`guest_env`](RunMetadata::guest_env): absent (`None`) when
    /// the run started at `/` (the default) or predates cwd capture; present
    /// values are authoritative on replay so a flag-free replay resolves the
    /// same relative paths. `chdir` is guest-driven and unrecorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guest_cwd: Option<String>,
    /// The run's exploration scheduling policy (PCT / starvation), authoritative
    /// on replay. Additive exactly like [`faults`](RunMetadata::faults): absent
    /// (`None`) in traces recorded under the default uniform policy, which the
    /// runtime treats as the default. Enabling a non-default policy folds a
    /// fingerprint component so a cross-policy replay fails closed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule_policy: Option<SchedulePolicyRecord>,
    /// The run's swarm fault-class selection. Additive: absent (`None`) when
    /// swarm was not enabled. See [`SwarmConfigRecord`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub swarm: Option<SwarmConfigRecord>,
    /// The run's liveness-watchdog configuration. Additive and *informational
    /// only*: NOT a fingerprint input and NOT reconciled fail-closed on replay,
    /// because the watchdog is schedule-invariant (it only adds a violation
    /// report). Absent (`None`) when the watchdog was disabled. See
    /// [`WatchdogConfigRecord`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub watchdog: Option<WatchdogConfigRecord>,
    /// Native host-time refusal, after exactly this recorded prefix. This is a
    /// terminal control-plane fact, never a scheduling decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compute_stop: Option<ComputeStop>,
    /// Whether syscall-user-dispatch (SUD) was armed for this run — recorded only
    /// when it was (`Some(true)`); absent (`None`) on every other run (macOS,
    /// a non-SUD kernel, a standalone binary, and all pre-SUD traces). Additive
    /// exactly like [`faults`](RunMetadata::faults). It exists so a cross-kernel
    /// replay is refused UP FRONT rather than diverging mid-run: a binary with
    /// raw inline syscalls can only run armed, so replaying its `sud:true` trace
    /// on a kernel without SUD (or vice versa) is reconciled fail-closed before
    /// the first op is replayed. SUD-DESIGN.md §7.3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sud: Option<bool>,
    /// Whether the timestamp-counter trap (`prctl(PR_SET_TSC, PR_TSC_SIGSEGV)`)
    /// was armed for this run — recorded only when it was (`Some(true)`); absent
    /// (`None`) on every other run (macOS, arm64, a kernel without `PR_SET_TSC`,
    /// a standalone binary, and all traces predating the trap). Additive exactly
    /// like [`sud`](RunMetadata::sud), and reconciled the same way: a guest whose
    /// `rdtsc`/`rdtscp` were answered from the virtual clock records `tsc:true`,
    /// and replaying that trace on a run that leaves the counter readable would
    /// read the HOST counter — so the mismatch is refused before the first op is
    /// replayed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tsc: Option<bool>,
    /// The run's virtual realtime epoch: the Unix time in nanoseconds that
    /// `ClockKind::Realtime` read at monotonic zero (`--realtime-epoch`, default
    /// `patina_dst_abi::DEFAULT_REALTIME_EPOCH_NANOS`). Required, not additive:
    /// every bundle states it. Authoritative on replay — the
    /// runtime rebuilds its default clock on this epoch, and an explicitly
    /// configured epoch that differs is refused — because filesystem timestamps
    /// are stamped from the realtime clock without a recorded read. Not a
    /// fingerprint input: a replay already reconciles it field-for-field.
    pub realtime_epoch_nanos: u64,
    /// Machine uptime at guest start. Required and authoritative on replay,
    /// including for unrecorded clock reads and run-relative fault windows.
    pub boot_origin_nanos: u64,
    /// The node name the guest's virtual kernel reports (`uname`,
    /// `gethostname`; `--hostname`, default `patina`). Required exactly like
    /// [`realtime_epoch_nanos`](RunMetadata::realtime_epoch_nanos).
    /// Authoritative on replay; a conflicting explicit name is refused.
    /// Not a fingerprint input.
    pub hostname: String,
    /// The virtual-time model the run was recorded under
    /// ([`patina_dst_abi::TIME_MODEL`]). Required; a bundle recorded under any
    /// other model is refused when it is decoded.
    pub time_model: u32,
}

/// A native compute-bound refusal at a boundary-operation prefix. PCs and host
/// elapsed time are deliberately absent: neither is replayable run state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComputeStop {
    pub steps: u64,
    pub task: TaskId,
}

impl RunMetadata {
    /// The metadata every recording carries. The realtime epoch and the node
    /// name are required run facts. The origin defaults to the ABI constant;
    /// runtime builders set the actual initial reading with `with_boot_origin_nanos`.
    /// Deserialization requires all three fields; it never fills in defaults.
    pub fn new(
        root_seed: u64,
        fingerprint: impl Into<String>,
        realtime_epoch_nanos: u64,
        hostname: impl Into<String>,
    ) -> Self {
        Self {
            root_seed,
            decision_policy: "splitmix64-v1".into(),
            fingerprint: fingerprint.into(),
            faults: None,
            buggify: None,
            dns: None,
            guest_argv: None,
            guest_env: None,
            guest_cwd: None,
            schedule_policy: None,
            swarm: None,
            watchdog: None,
            compute_stop: None,
            sud: None,
            tsc: None,
            realtime_epoch_nanos,
            boot_origin_nanos: patina_dst_abi::DEFAULT_BOOT_ORIGIN_NANOS,
            time_model: patina_dst_abi::TIME_MODEL,
            hostname: hostname.into(),
        }
    }

    /// Record an explicit clock's or runtime's initial monotonic reading.
    #[must_use]
    pub fn with_boot_origin_nanos(mut self, nanos: u64) -> Self {
        self.boot_origin_nanos = nanos;
        self
    }

    /// Attach the run's fault-injection configuration recorded into the trace.
    #[must_use]
    pub fn with_faults(mut self, faults: Option<FaultConfigRecord>) -> Self {
        self.faults = faults;
        self
    }

    /// Attach the run's cooperative-SUT (buggify) configuration recorded into
    /// the trace.
    #[must_use]
    pub fn with_buggify(mut self, buggify: Option<BuggifyConfigRecord>) -> Self {
        self.buggify = buggify;
        self
    }

    /// Attach the guest program arguments (`argv[1..]`) recorded into the trace,
    /// so a `replay` reproduces them without the operator re-passing the `--`
    /// section. `None` records nothing (an old-style trace); `Some(vec)` — even
    /// an empty vector — records the exact argument list.
    #[must_use]
    pub fn with_guest_argv(mut self, guest_argv: Option<Vec<String>>) -> Self {
        self.guest_argv = guest_argv;
        self
    }

    /// Attach deterministic guest environment values recorded into the trace.
    /// `None` records nothing; `Some(map)` records exactly the supplied values.
    #[must_use]
    /// Record the run's DNS host table. `None` records nothing.
    pub fn with_dns(mut self, dns: Option<DnsConfigRecord>) -> Self {
        self.dns = dns;
        self
    }

    pub fn with_guest_env(mut self, guest_env: Option<BTreeMap<String, String>>) -> Self {
        self.guest_env = guest_env;
        self
    }

    /// Attach the guest's initial working directory recorded into the trace.
    /// `None` records nothing (the run started at `/`).
    #[must_use]
    pub fn with_guest_cwd(mut self, guest_cwd: Option<String>) -> Self {
        self.guest_cwd = guest_cwd;
        self
    }

    /// Attach the run's exploration scheduling policy recorded into the trace.
    #[must_use]
    pub fn with_schedule_policy(mut self, policy: Option<SchedulePolicyRecord>) -> Self {
        self.schedule_policy = policy;
        self
    }

    /// Attach the run's swarm fault-class selection recorded into the trace.
    #[must_use]
    pub fn with_swarm(mut self, swarm: Option<SwarmConfigRecord>) -> Self {
        self.swarm = swarm;
        self
    }

    /// Attach the run's liveness-watchdog configuration recorded into the trace.
    /// Informational only — see [`WatchdogConfigRecord`].
    #[must_use]
    pub fn with_watchdog(mut self, watchdog: Option<WatchdogConfigRecord>) -> Self {
        self.watchdog = watchdog;
        self
    }

    /// Attach whether syscall-user-dispatch was armed for this run. `Some(true)`
    /// records it; `None` records nothing (see [`RunMetadata::sud`]).
    #[must_use]
    pub fn with_sud(mut self, sud: Option<bool>) -> Self {
        self.sud = sud;
        self
    }

    /// Record that the timestamp-counter trap was armed for this run;
    /// `None` records nothing (see [`RunMetadata::tsc`]).
    #[must_use]
    pub fn with_tsc(mut self, tsc: Option<bool>) -> Self {
        self.tsc = tsc;
        self
    }
}

#[cfg(test)]
mod tests;
