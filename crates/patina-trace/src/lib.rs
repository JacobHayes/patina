//! Versioned trace bundles and strict replay matching.
//!
//! Internal crate: the `.patina` trace format — recording boundary events into a
//! versioned JSON bundle (run metadata, timelines, branch sessions), migrating
//! older format versions forward, and replaying with strict reconciliation
//! (any operation/outcome divergence fails closed rather than lying). Adopters
//! produce and consume traces through `cargo patina run --record` / `replay`
//! and the `patina-dst-runtime` execution modes, not this crate directly.
//! See [ARCHITECTURE.md] for the trace design and its guarantees.
//!
//! [ARCHITECTURE.md]: https://github.com/JacobHayes/patina/blob/main/ARCHITECTURE.md

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use patina_dst_abi::{Operation, Outcome, TaskId};
use serde::{Deserialize, Serialize};

/// The trace bundle format this runtime writes. It is the only version ever
/// serialized; older supported versions are upgraded in memory on load.
///
/// Format 3 keeps the JSON bundle shape of format 2 but changes only its
/// on-disk encoding: byte payloads are base64 strings rather than JSON number
/// arrays (see `bytes_base64` in `patina-dst-abi`) and the bundle is serialized
/// compactly rather than pretty printed. Both changes shrink the dominant cost
/// (recorded byte payloads) by several times while keeping the file valid,
/// greppable JSON. Additive ABI variants, such as the TCP operations and
/// outcomes, do not require a format bump because older traces never contain
/// those enum tags and serde's name-tagged representation preserves old events.
///
/// Format 4 records the run's fault-injection configuration in the bundle
/// metadata ([`RunMetadata::faults`]) so a fault run replays self-contained: the
/// stored config is authoritative and no `--fs-crash-at`/jitter/drop flags need
/// re-supplying. A format 3 (or earlier) bundle carries no such field — its
/// `faults` migrates to `None`, which the runtime reads as "pre-metadata trace"
/// and falls back to the historical re-supply contract. The metadata field is a
/// new struct key, not a new operation, so recorded event streams are byte-for-
/// byte unchanged across the bump.
pub const TRACE_FORMAT_VERSION: u32 = 4;
/// The oldest trace format version this runtime can read. A bundle at this
/// version, or any later supported version, is migrated in memory through the
/// `MIGRATIONS` chain up to [`TRACE_FORMAT_VERSION`] and then validated by
/// the normal structural oracle. Versions below this floor, or above
/// [`TRACE_FORMAT_VERSION`], are rejected with
/// [`TraceError::UnsupportedVersion`].
pub const MIN_SUPPORTED_FORMAT_VERSION: u32 = 1;
pub const MAX_TRACE_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_TIMELINE_EVENTS: usize = 1_000_000;
const MAIN_TIMELINE: &str = "main";
static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

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
    /// Virtual-time monotonic-nanoseconds cutoff after which buggify stops firing
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
    /// SDK-fault coverage without an armed SDK config. An old trace therefore
    /// migrates clean unless it also carries the `+buggify` capability suffix, and
    /// a conflicting explicit knob at replay fails closed exactly like
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
}

impl RunMetadata {
    pub fn new(root_seed: u64, fingerprint: impl Into<String>) -> Self {
        Self {
            root_seed,
            decision_policy: "splitmix64-v1".into(),
            fingerprint: fingerprint.into(),
            faults: None,
            buggify: None,
            dns: None,
            guest_argv: None,
            guest_env: None,
            schedule_policy: None,
            swarm: None,
            watchdog: None,
            sud: None,
            tsc: None,
        }
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceEvent {
    pub sequence: u64,
    pub operation: Operation,
    pub outcome: Outcome,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Timeline {
    pub id: String,
    pub parent: Option<String>,
    pub from_sequence: Option<u64>,
    pub branch_seed: Option<u64>,
    pub decisions: Vec<TraceEvent>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceBundle {
    pub format_version: u32,
    pub metadata: RunMetadata,
    pub timelines: Vec<Timeline>,
}

impl TraceBundle {
    pub fn new(metadata: RunMetadata, decisions: Vec<TraceEvent>) -> Self {
        Self {
            format_version: TRACE_FORMAT_VERSION,
            metadata,
            timelines: vec![Timeline {
                id: MAIN_TIMELINE.into(),
                parent: None,
                from_sequence: None,
                branch_seed: None,
                decisions,
            }],
        }
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, TraceError> {
        let path = path.as_ref();
        let file = File::open(path).map_err(|source| TraceError::Io {
            action: format!("open trace {}", path.display()),
            source,
        })?;
        let size = file
            .metadata()
            .map_err(|source| TraceError::Io {
                action: format!("inspect trace {}", path.display()),
                source,
            })?
            .len();
        enforce_trace_byte_limit(size, MAX_TRACE_BYTES, "trace file")?;
        if size == 0 {
            return Err(TraceError::Incomplete {
                path: path.to_path_buf(),
                reason: "empty trace file; record finalization did not complete".into(),
            });
        }
        let value: serde_json::Value =
            serde_json::from_reader(BufReader::new(file)).map_err(|source| {
                if source.is_eof() {
                    TraceError::Incomplete {
                        path: path.to_path_buf(),
                        reason: format!("truncated JSON trace: {source}"),
                    }
                } else {
                    TraceError::Parse {
                        path: path.to_path_buf(),
                        source,
                    }
                }
            })?;
        Self::decode(value, path.to_path_buf())
    }

    /// Parse and validate a bundle from in-memory bytes, enforcing the same
    /// size limit as file loading.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, TraceError> {
        enforce_trace_byte_limit(
            bytes.len() as u64,
            MAX_TRACE_BYTES,
            "trace transport payload",
        )?;
        let path = PathBuf::from("<trace-transport>");
        if bytes.is_empty() {
            return Err(TraceError::Incomplete {
                path,
                reason: "empty trace transport payload; record finalization did not complete"
                    .into(),
            });
        }
        let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|source| {
            if source.is_eof() {
                TraceError::Incomplete {
                    path: path.clone(),
                    reason: format!("truncated JSON trace: {source}"),
                }
            } else {
                TraceError::Parse {
                    path: path.clone(),
                    source,
                }
            }
        })?;
        Self::decode(value, path)
    }

    /// Upgrade a decoded bundle to the current format, then deserialize and
    /// validate it.
    ///
    /// A bundle already at [`TRACE_FORMAT_VERSION`] is deserialized unchanged.
    /// A supported prior version is walked forward through the [`MIGRATIONS`]
    /// chain in memory - the source file is never rewritten - and the upgraded
    /// value is then subjected to the same structural [`validate`](Self::validate)
    /// oracle as a natively current bundle. Unsupported versions are rejected by
    /// [`migrate_to_current`] before any structural interpretation.
    fn decode(value: serde_json::Value, path: PathBuf) -> Result<Self, TraceError> {
        let value = migrate_to_current(value)?;
        require_complete_current_bundle(&value, &path)?;
        let bundle: Self =
            serde_json::from_value(value).map_err(|source| TraceError::Parse { path, source })?;
        bundle.validate()?;
        Ok(bundle)
    }

    /// Validate and serialize this bundle to the canonical byte encoding.
    ///
    /// The canonical form is compact (single-line) JSON with base64 byte
    /// payloads - the format 3 encoding. It stays valid JSON, so a bundle can be
    /// inspected with any JSON tool (`jq . run.patina`,
    /// `python3 -m json.tool run.patina`) when a human-readable view is wanted;
    /// nothing here is a bespoke binary framing that would need a dedicated
    /// dump command.
    pub fn to_bytes(&self) -> Result<Vec<u8>, TraceError> {
        self.to_bytes_with_limit(MAX_TRACE_BYTES)
    }

    fn to_bytes_with_limit(&self, max_bytes: u64) -> Result<Vec<u8>, TraceError> {
        self.validate()?;
        let mut bytes = serde_json::to_vec(self).map_err(TraceError::Serialize)?;
        bytes.push(b'\n');
        enforce_trace_byte_limit(bytes.len() as u64, max_bytes, "serialized trace")?;
        Ok(bytes)
    }

    pub fn write_atomic(&self, path: impl AsRef<Path>) -> Result<(), TraceError> {
        self.write_atomic_with_limit(path, MAX_TRACE_BYTES)
    }

    fn write_atomic_with_limit(
        &self,
        path: impl AsRef<Path>,
        max_bytes: u64,
    ) -> Result<(), TraceError> {
        let bytes = self.to_bytes_with_limit(max_bytes)?;
        let path = path.as_ref();
        let parent = path.parent().filter(|value| !value.as_os_str().is_empty());
        if let Some(parent) = parent {
            fs::create_dir_all(parent).map_err(|source| TraceError::Io {
                action: format!("create trace directory {}", parent.display()),
                source,
            })?;
        }
        let temp_path = temporary_path(path);
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .map_err(|source| TraceError::Io {
                action: format!("create temporary trace {}", temp_path.display()),
                source,
            })?;

        let write_result = (|| {
            let mut writer = BufWriter::new(file);
            writer.write_all(&bytes).map_err(|source| TraceError::Io {
                action: format!("write temporary trace {}", temp_path.display()),
                source,
            })?;
            writer.flush().map_err(|source| TraceError::Io {
                action: format!("flush temporary trace {}", temp_path.display()),
                source,
            })?;
            writer
                .get_ref()
                .sync_all()
                .map_err(|source| TraceError::Io {
                    action: format!("sync temporary trace {}", temp_path.display()),
                    source,
                })
        })();

        if let Err(error) = write_result {
            let _ = fs::remove_file(&temp_path);
            return Err(error);
        }

        if let Err(source) = fs::rename(&temp_path, path) {
            let _ = fs::remove_file(&temp_path);
            return Err(TraceError::Io {
                action: format!(
                    "atomically rename {} to {}",
                    temp_path.display(),
                    path.display()
                ),
                source,
            });
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), TraceError> {
        if self.format_version != TRACE_FORMAT_VERSION {
            return Err(TraceError::UnsupportedVersion {
                found: self.format_version,
                supported: TRACE_FORMAT_VERSION,
            });
        }
        if self.metadata.fingerprint.is_empty() {
            return Err(TraceError::Invalid(
                "trace compatibility fingerprint is empty".into(),
            ));
        }
        if self.metadata.decision_policy.is_empty() {
            return Err(TraceError::Invalid(
                "trace decision policy identifier is empty".into(),
            ));
        }
        if fingerprint_declares_component(&self.metadata.fingerprint, "buggify")
            && self.metadata.buggify.is_none()
        {
            return Err(TraceError::Invalid(
                "fingerprint declares +buggify but trace metadata has no buggify config".into(),
            ));
        }
        // The swarm record must partition cleanly: every selected class was a
        // candidate, and no class is listed twice. Consumers derive "swarm
        // dropped this class" as the complement of the two lists, so a record
        // that is not a clean partition would make that derivation lie.
        if let Some(swarm) = &self.metadata.swarm {
            let mut candidates = BTreeSet::new();
            for class in &swarm.candidate_classes {
                if !candidates.insert(class.as_str()) {
                    return Err(TraceError::Invalid(format!(
                        "swarm candidate class {class:?} is listed more than once"
                    )));
                }
            }
            let mut selected = BTreeSet::new();
            for class in &swarm.selected_classes {
                if !selected.insert(class.as_str()) {
                    return Err(TraceError::Invalid(format!(
                        "swarm selected class {class:?} is listed more than once"
                    )));
                }
                if !candidates.contains(class.as_str()) {
                    return Err(TraceError::Invalid(format!(
                        "swarm selected class {class:?} was not a candidate; \
                         the selection must be a subset of the candidates"
                    )));
                }
            }
        }
        let Some(main) = self.timelines.first() else {
            return Err(TraceError::Invalid("trace has no main timeline".into()));
        };
        if main.id != MAIN_TIMELINE
            || main.parent.is_some()
            || main.from_sequence.is_some()
            || main.branch_seed.is_some()
        {
            return Err(TraceError::Invalid(
                "the first timeline must be an unbranched main timeline".into(),
            ));
        }

        let mut ids = BTreeSet::new();
        for (timeline_index, timeline) in self.timelines.iter().enumerate() {
            if timeline.decisions.len() > MAX_TIMELINE_EVENTS {
                return Err(TraceError::ResourceLimit(format!(
                    "timeline {} has {} events; limit is {MAX_TIMELINE_EVENTS}",
                    timeline.id,
                    timeline.decisions.len()
                )));
            }
            if timeline.id.is_empty() || !ids.insert(timeline.id.clone()) {
                return Err(TraceError::Invalid(format!(
                    "timeline id is empty or duplicated: {:?}",
                    timeline.id
                )));
            }
            let start = if timeline_index == 0 {
                0
            } else {
                let parent = timeline.parent.as_ref().ok_or_else(|| {
                    TraceError::Invalid(format!("timeline {} has no parent", timeline.id))
                })?;
                let parent_index = self.timelines[..timeline_index]
                    .iter()
                    .position(|candidate| &candidate.id == parent)
                    .ok_or_else(|| {
                        TraceError::Invalid(format!(
                            "timeline {} refers to missing or later parent {parent}",
                            timeline.id
                        ))
                    })?;
                let from = timeline.from_sequence.ok_or_else(|| {
                    TraceError::Invalid(format!("timeline {} has no branch sequence", timeline.id))
                })?;
                if timeline.branch_seed.is_none() {
                    return Err(TraceError::Invalid(format!(
                        "timeline {} has no branch seed",
                        timeline.id
                    )));
                }
                let parent_len = self.resolve_by_index(parent_index)?.len() as u64;
                if from > parent_len {
                    return Err(TraceError::Invalid(format!(
                        "timeline {} branches at {from}, beyond parent length {parent_len}",
                        timeline.id
                    )));
                }
                from
            };
            for (index, event) in timeline.decisions.iter().enumerate() {
                let expected = start + index as u64;
                if event.sequence != expected {
                    return Err(TraceError::Invalid(format!(
                        "event {index} in timeline {} has sequence {}, expected {expected}",
                        timeline.id, event.sequence
                    )));
                }
            }
        }
        Ok(())
    }

    pub fn resolved_timeline(&self, id: &str) -> Result<Vec<TraceEvent>, TraceError> {
        self.validate()?;
        let index = self
            .timelines
            .iter()
            .position(|timeline| timeline.id == id)
            .ok_or_else(|| TraceError::UnknownTimeline(id.into()))?;
        self.resolve_by_index(index)
    }

    fn resolve_by_index(&self, index: usize) -> Result<Vec<TraceEvent>, TraceError> {
        let timeline = &self.timelines[index];
        let Some(parent) = &timeline.parent else {
            return Ok(timeline.decisions.clone());
        };
        let parent_index = self.timelines[..index]
            .iter()
            .position(|candidate| &candidate.id == parent)
            .ok_or_else(|| TraceError::UnknownTimeline(parent.clone()))?;
        let mut decisions = self.resolve_by_index(parent_index)?;
        decisions.truncate(timeline.from_sequence.unwrap_or(0) as usize);
        decisions.extend(timeline.decisions.clone());
        Ok(decisions)
    }
}

pub struct Recorder {
    metadata: RunMetadata,
    decisions: Vec<TraceEvent>,
}

impl Recorder {
    pub fn new(metadata: RunMetadata) -> Self {
        Self {
            metadata,
            decisions: Vec::new(),
        }
    }

    pub fn observe(&mut self, operation: Operation, outcome: Outcome) {
        self.decisions.push(TraceEvent {
            sequence: self.decisions.len() as u64,
            operation,
            outcome,
        });
    }

    /// Overwrite the recorded buggify configuration at finalization. The run's
    /// realized active-site set and knob picks are only known after execution, so
    /// the runtime records the static config at build time and calls this to fold
    /// in the accrued detail before the bundle is written.
    pub fn set_buggify(&mut self, buggify: Option<BuggifyConfigRecord>) {
        self.metadata.buggify = buggify;
    }

    pub fn finish(self, path: impl AsRef<Path>) -> Result<(), TraceError> {
        self.finish_with_limit(path, MAX_TRACE_BYTES)
    }

    fn finish_with_limit(self, path: impl AsRef<Path>, max_bytes: u64) -> Result<(), TraceError> {
        self.into_bundle().write_atomic_with_limit(path, max_bytes)
    }

    /// Convert the recorded decisions into a bundle without touching storage.
    pub fn into_bundle(self) -> TraceBundle {
        TraceBundle::new(self.metadata, self.decisions)
    }

    /// A bundle of the decisions recorded SO FAR, leaving the recorder usable.
    /// The runtime writes one of these when a run is stopped mid-flight (step
    /// budget exhausted, frozen-clock churn) and the consuming
    /// [`Recorder::into_bundle`] at finalization is never reached — a truncated
    /// but structurally valid trace beats the empty file the abort would leave.
    pub fn to_bundle(&self) -> TraceBundle {
        TraceBundle::new(self.metadata.clone(), self.decisions.clone())
    }
}

pub struct Replayer {
    metadata: RunMetadata,
    decisions: Vec<TraceEvent>,
    next: usize,
}

impl Replayer {
    pub fn open(path: impl AsRef<Path>, expected_fingerprint: &str) -> Result<Self, TraceError> {
        Self::open_timeline(path, expected_fingerprint, MAIN_TIMELINE)
    }

    pub fn open_timeline(
        path: impl AsRef<Path>,
        expected_fingerprint: &str,
        timeline: &str,
    ) -> Result<Self, TraceError> {
        Self::from_bundle(TraceBundle::load(path)?, expected_fingerprint, timeline)
    }

    /// Build a replayer from an already-loaded bundle.
    pub fn from_bundle(
        bundle: TraceBundle,
        expected_fingerprint: &str,
        timeline: &str,
    ) -> Result<Self, TraceError> {
        if bundle.metadata.fingerprint != expected_fingerprint {
            return Err(TraceError::FingerprintMismatch {
                expected: expected_fingerprint.into(),
                recorded: bundle.metadata.fingerprint,
            });
        }
        let decisions = bundle.resolved_timeline(timeline)?;
        let execution_seed = bundle
            .timelines
            .iter()
            .find(|candidate| candidate.id == timeline)
            .and_then(|candidate| candidate.branch_seed)
            .unwrap_or(bundle.metadata.root_seed);
        let mut metadata = bundle.metadata;
        metadata.root_seed = execution_seed;
        Ok(Self {
            metadata,
            decisions,
            next: 0,
        })
    }

    pub const fn root_seed(&self) -> u64 {
        self.metadata.root_seed
    }

    /// The recorded fault-injection configuration, authoritative on replay.
    /// `None` for a pre-format-4 trace that carried no such metadata.
    pub const fn fault_config(&self) -> Option<&FaultConfigRecord> {
        self.metadata.faults.as_ref()
    }

    /// The recorded cooperative-SUT (buggify) configuration, authoritative on
    /// replay. `None` for a trace recorded without buggify.
    pub const fn buggify_config(&self) -> Option<&BuggifyConfigRecord> {
        self.metadata.buggify.as_ref()
    }

    /// The recorded exploration scheduling policy, authoritative on replay.
    /// `None` for a trace recorded under the default uniform policy.
    pub const fn schedule_policy(&self) -> Option<&SchedulePolicyRecord> {
        self.metadata.schedule_policy.as_ref()
    }

    /// The recorded swarm fault-class selection. `None` when swarm was disabled.
    pub const fn swarm_config(&self) -> Option<&SwarmConfigRecord> {
        self.metadata.swarm.as_ref()
    }

    /// The recorded guest program arguments (`argv[1..]`). `None` for a trace
    /// recorded before argv capture; `Some` (possibly empty) otherwise.
    pub fn guest_argv(&self) -> Option<&[String]> {
        self.metadata.guest_argv.as_deref()
    }

    /// Deterministic guest environment values recorded into the trace.
    /// `None` for a trace recorded before env capture or with no supplied values.
    pub fn guest_env(&self) -> Option<&BTreeMap<String, String>> {
        self.metadata.guest_env.as_ref()
    }

    /// The DNS host table recorded into the trace, authoritative on replay.
    /// `None` for a trace recorded without one.
    pub const fn dns_config(&self) -> Option<&DnsConfigRecord> {
        self.metadata.dns.as_ref()
    }

    /// Whether the trace was recorded under syscall-user-dispatch. `Some(true)`
    /// when it was; `None` otherwise (see [`RunMetadata::sud`]).
    pub const fn sud(&self) -> Option<bool> {
        self.metadata.sud
    }

    /// Whether the trace was recorded with the timestamp-counter trap armed, or
    /// `None` otherwise (see [`RunMetadata::tsc`]).
    pub const fn tsc(&self) -> Option<bool> {
        self.metadata.tsc
    }

    pub fn expect(&mut self, operation: &Operation) -> Result<Outcome, TraceError> {
        let event = self
            .decisions
            .get(self.next)
            .ok_or_else(|| TraceError::ReplayExhausted {
                sequence: self.next as u64,
                actual: operation.clone(),
            })?;
        if &event.operation != operation {
            return Err(TraceError::OperationMismatch {
                sequence: event.sequence,
                expected: Box::new(event.operation.clone()),
                actual: Box::new(operation.clone()),
            });
        }
        self.next += 1;
        Ok(event.outcome.clone())
    }

    pub fn compare_outcome(
        &self,
        sequence: u64,
        recorded: &Outcome,
        actual: &Outcome,
    ) -> Result<(), TraceError> {
        if recorded != actual {
            return Err(TraceError::OutcomeMismatch {
                sequence,
                recorded: Box::new(recorded.clone()),
                actual: Box::new(actual.clone()),
            });
        }
        Ok(())
    }

    pub const fn consumed(&self) -> u64 {
        self.next as u64
    }

    pub fn total(&self) -> usize {
        self.decisions.len()
    }

    /// How many `TaskYield` operations the full recorded timeline holds for
    /// `task`. Divergence diagnostics use this to report record-vs-replay yield
    /// accounting instead of a bare "trace ended" cursor position.
    pub fn recorded_yields_for(&self, task: TaskId) -> usize {
        self.decisions
            .iter()
            .filter(|event| event.operation == Operation::TaskYield { task })
            .count()
    }

    pub fn finish(self) -> Result<(), TraceError> {
        if self.next != self.decisions.len() {
            return Err(TraceError::UnconsumedEvents {
                consumed: self.next,
                total: self.decisions.len(),
            });
        }
        Ok(())
    }
}

/// Replays an exact parent prefix and records a new deterministic suffix.
pub struct BranchSession {
    path: PathBuf,
    bundle: TraceBundle,
    parent: String,
    branch_id: String,
    branch_seed: u64,
    from_sequence: u64,
    prefix: Replayer,
    suffix: Vec<TraceEvent>,
}

impl BranchSession {
    pub fn open(
        path: impl AsRef<Path>,
        expected_fingerprint: &str,
        parent: &str,
        from_sequence: u64,
        branch_id: impl Into<String>,
        branch_seed: u64,
    ) -> Result<Self, TraceError> {
        let path = path.as_ref().to_path_buf();
        let bundle = TraceBundle::load(&path)?;
        if bundle.metadata.fingerprint != expected_fingerprint {
            return Err(TraceError::FingerprintMismatch {
                expected: expected_fingerprint.into(),
                recorded: bundle.metadata.fingerprint.clone(),
            });
        }
        let branch_id = branch_id.into();
        if branch_id.is_empty()
            || bundle
                .timelines
                .iter()
                .any(|timeline| timeline.id == branch_id)
        {
            return Err(TraceError::DuplicateTimeline(branch_id));
        }
        let mut prefix_decisions = bundle.resolved_timeline(parent)?;
        if from_sequence > prefix_decisions.len() as u64 {
            return Err(TraceError::Invalid(format!(
                "branch sequence {from_sequence} exceeds parent timeline length {}",
                prefix_decisions.len()
            )));
        }
        prefix_decisions.truncate(from_sequence as usize);
        let prefix = Replayer {
            metadata: bundle.metadata.clone(),
            decisions: prefix_decisions,
            next: 0,
        };
        Ok(Self {
            path,
            bundle,
            parent: parent.into(),
            branch_id,
            branch_seed,
            from_sequence,
            prefix,
            suffix: Vec::new(),
        })
    }

    /// The parent trace's recorded fault-injection configuration, inherited by
    /// the branch so its replayed prefix uses the same fault drivers. `None` for
    /// a pre-format-4 parent trace.
    pub const fn fault_config(&self) -> Option<&FaultConfigRecord> {
        self.bundle.metadata.faults.as_ref()
    }

    /// The parent trace's recorded cooperative-SUT (buggify) configuration,
    /// inherited by the branch. `None` for a parent trace recorded without
    /// buggify.
    pub const fn buggify_config(&self) -> Option<&BuggifyConfigRecord> {
        self.bundle.metadata.buggify.as_ref()
    }

    /// The parent trace's recorded exploration scheduling policy, inherited by
    /// the branch. `None` for a parent trace recorded under the default policy.
    pub const fn schedule_policy(&self) -> Option<&SchedulePolicyRecord> {
        self.bundle.metadata.schedule_policy.as_ref()
    }

    /// The parent trace's recorded swarm fault-class selection. `None` when the
    /// parent was recorded without swarm.
    pub const fn swarm_config(&self) -> Option<&SwarmConfigRecord> {
        self.bundle.metadata.swarm.as_ref()
    }

    /// Deterministic guest environment values inherited from the parent trace.
    /// `None` for a trace recorded before env capture or with no supplied values.
    pub fn guest_env(&self) -> Option<&BTreeMap<String, String>> {
        self.bundle.metadata.guest_env.as_ref()
    }

    /// The DNS host table inherited from the parent trace.
    pub const fn dns_config(&self) -> Option<&DnsConfigRecord> {
        self.bundle.metadata.dns.as_ref()
    }

    pub fn expect_prefix(
        &mut self,
        operation: &Operation,
    ) -> Result<Option<(u64, Outcome)>, TraceError> {
        if self.prefix.consumed() as usize == self.prefix.total() {
            return Ok(None);
        }
        let sequence = self.prefix.consumed();
        Ok(Some((sequence, self.prefix.expect(operation)?)))
    }

    pub fn compare_outcome(
        &self,
        sequence: u64,
        recorded: &Outcome,
        actual: &Outcome,
    ) -> Result<(), TraceError> {
        self.prefix.compare_outcome(sequence, recorded, actual)
    }

    pub fn observe(&mut self, operation: Operation, outcome: Outcome) {
        self.suffix.push(TraceEvent {
            sequence: self.from_sequence + self.suffix.len() as u64,
            operation,
            outcome,
        });
    }

    pub fn finish(self) -> Result<(), TraceError> {
        self.prefix.finish()?;
        let mut bundle = self.bundle;
        bundle.timelines.push(Timeline {
            id: self.branch_id,
            parent: Some(self.parent),
            from_sequence: Some(self.from_sequence),
            branch_seed: Some(self.branch_seed),
            decisions: self.suffix,
        });
        bundle.write_atomic(self.path)
    }
}

fn fingerprint_declares_component(fingerprint: &str, component: &str) -> bool {
    fingerprint.split('+').skip(1).any(|part| part == component)
}

#[derive(Debug)]
pub enum TraceError {
    Io {
        action: String,
        source: std::io::Error,
    },
    Parse {
        path: PathBuf,
        source: serde_json::Error,
    },
    /// A trace stopped before a complete bundle was written: empty/truncated JSON
    /// or missing top-level/core metadata fields. This is a distinct refusal so
    /// replay reports "the record never finalized" rather than a generic JSON
    /// parse error at first use.
    Incomplete {
        path: PathBuf,
        reason: String,
    },
    Serialize(serde_json::Error),
    UnsupportedVersion {
        found: u32,
        supported: u32,
    },
    Invalid(String),
    ResourceLimit(String),
    UnknownTimeline(String),
    DuplicateTimeline(String),
    FingerprintMismatch {
        expected: String,
        recorded: String,
    },
    ReplayExhausted {
        sequence: u64,
        actual: Operation,
    },
    OperationMismatch {
        sequence: u64,
        expected: Box<Operation>,
        actual: Box<Operation>,
    },
    OutcomeMismatch {
        sequence: u64,
        recorded: Box<Outcome>,
        actual: Box<Outcome>,
    },
    UnconsumedEvents {
        consumed: usize,
        total: usize,
    },
}

impl fmt::Display for TraceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { action, source } => write!(f, "failed to {action}: {source}"),
            Self::Parse { path, source } => {
                write!(f, "failed to parse trace {}: {source}", path.display())
            }
            Self::Incomplete { path, reason } => {
                write!(f, "incomplete trace {}: {reason}", path.display())
            }
            Self::Serialize(source) => write!(f, "failed to serialize trace: {source}"),
            Self::UnsupportedVersion { found, supported } => write!(
                f,
                "unsupported trace format version {found}; this runtime supports {supported}"
            ),
            Self::Invalid(message) => write!(f, "invalid trace: {message}"),
            Self::ResourceLimit(message) => write!(f, "trace resource limit exceeded: {message}"),
            Self::UnknownTimeline(timeline) => {
                write!(f, "trace has no timeline named {timeline:?}")
            }
            Self::DuplicateTimeline(timeline) => {
                write!(f, "trace already has a timeline named {timeline:?}")
            }
            Self::FingerprintMismatch { expected, recorded } => write!(
                f,
                "trace fingerprint mismatch: runtime is {expected}, trace is {recorded}"
            ),
            Self::ReplayExhausted { sequence, actual } => write!(
                f,
                "trace ended before operation {sequence}; actual operation was {actual:?}"
            ),
            Self::OperationMismatch {
                sequence,
                expected,
                actual,
            } => write!(
                f,
                "trace operation mismatch at {sequence}: expected {expected:?}, got {actual:?}"
            ),
            Self::OutcomeMismatch {
                sequence,
                recorded,
                actual,
            } => write!(
                f,
                "deterministic outcome mismatch at {sequence}: trace has {recorded:?}, driver produced {actual:?}"
            ),
            Self::UnconsumedEvents { consumed, total } => {
                write!(f, "replay consumed {consumed} of {total} trace events")
            }
        }
    }
}

impl std::error::Error for TraceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Parse { source, .. } | Self::Serialize(source) => Some(source),
            _ => None,
        }
    }
}

/// A pure, total upgrade of a trace bundle's JSON representation from one
/// format version to the next. Migrations run entirely in memory and never
/// rewrite the source file.
type Migration = fn(serde_json::Value) -> Result<serde_json::Value, TraceError>;

/// Ordered migration steps bridging every supported prior format up to
/// [`TRACE_FORMAT_VERSION`]. Element `i` upgrades version
/// `MIN_SUPPORTED_FORMAT_VERSION + i` to the following version, so a future
/// format bump needs exactly one new step appended here (and the constant
/// [`TRACE_FORMAT_VERSION`] raised). No plugin system: the chain is a fixed,
/// auditable slice.
const MIGRATIONS: &[Migration] = &[migrate_v1_to_v2, migrate_v2_to_v3, migrate_v3_to_v4];

// One migration step must exist for each supported prior version; this keeps
// the chain and the version window from drifting apart on a future bump.
const _: () = assert!(
    MIGRATIONS.len() == (TRACE_FORMAT_VERSION - MIN_SUPPORTED_FORMAT_VERSION) as usize,
    "MIGRATIONS must contain one step per supported prior format version",
);

/// Read the declared format version from a decoded bundle when it is present as
/// a non-negative integer. A missing or non-integer field yields `None`, so the
/// caller defers to typed deserialization for a precise parse error rather than
/// guessing a version.
fn format_version_of(value: &serde_json::Value) -> Option<u32> {
    u32::try_from(value.get("format_version")?.as_u64()?).ok()
}

/// Upgrade a decoded bundle to [`TRACE_FORMAT_VERSION`].
///
/// The current version is returned untouched. A supported prior version is
/// walked forward through [`MIGRATIONS`]. Any other declared version - below
/// [`MIN_SUPPORTED_FORMAT_VERSION`] or newer than this runtime understands - is
/// rejected with [`TraceError::UnsupportedVersion`] rather than a generic parse
/// failure, keeping the distinction visible in the error taxonomy.
fn migrate_to_current(mut value: serde_json::Value) -> Result<serde_json::Value, TraceError> {
    let Some(found) = format_version_of(&value) else {
        return Ok(value);
    };
    if !(MIN_SUPPORTED_FORMAT_VERSION..=TRACE_FORMAT_VERSION).contains(&found) {
        return Err(TraceError::UnsupportedVersion {
            found,
            supported: TRACE_FORMAT_VERSION,
        });
    }
    let start = (found - MIN_SUPPORTED_FORMAT_VERSION) as usize;
    for migrate in &MIGRATIONS[start..] {
        value = migrate(value)?;
    }
    Ok(value)
}

/// Upgrade the pre-branching format 1 layout to format 2.
///
/// Format 1 stored a single flat `decisions` array with no timelines and no
/// branch metadata. In format 2 terms that is exactly one unbranched `main`
/// timeline, so the upgrade is lossless: the decisions move verbatim into a
/// `main` timeline with absent parent, branch point, and branch seed. The
/// upgraded value is validated by the normal structural oracle after the chain
/// completes.
fn migrate_v1_to_v2(mut value: serde_json::Value) -> Result<serde_json::Value, TraceError> {
    let object = value
        .as_object_mut()
        .ok_or_else(|| TraceError::Invalid("format 1 trace is not a JSON object".into()))?;
    let decisions = object.remove("decisions").ok_or_else(|| {
        TraceError::Invalid("format 1 trace is missing its decisions array".into())
    })?;
    if !decisions.is_array() {
        return Err(TraceError::Invalid(
            "format 1 trace decisions must be an array".into(),
        ));
    }
    let main = serde_json::json!({
        "id": MAIN_TIMELINE,
        "parent": null,
        "from_sequence": null,
        "branch_seed": null,
        "decisions": decisions,
    });
    object.insert("timelines".into(), serde_json::Value::Array(vec![main]));
    object.insert("format_version".into(), serde_json::Value::from(2u32));
    Ok(value)
}

/// Upgrade the format 2 layout to format 3.
///
/// Format 3 changes only the on-disk encoding, not the logical schema: byte
/// payloads become base64 strings instead of JSON number arrays and the bundle
/// is serialized compactly. The decoded `Value` tree is structurally identical
/// across the two versions, so this step only rewrites the version tag. The
/// legacy number-array payloads a format 2 bundle carries are decoded by the
/// tolerant `bytes_base64` reader in `patina-dst-abi` when the migrated value is
/// finally deserialized, which is what keeps the upgrade lossless without a
/// per-payload rewrite here.
fn migrate_v2_to_v3(mut value: serde_json::Value) -> Result<serde_json::Value, TraceError> {
    let object = value
        .as_object_mut()
        .ok_or_else(|| TraceError::Invalid("format 2 trace is not a JSON object".into()))?;
    object.insert("format_version".into(), serde_json::Value::from(3u32));
    Ok(value)
}

/// Upgrade the format 3 layout to format 4.
///
/// Format 4 adds the optional `faults` key to the bundle metadata. A format 3
/// bundle carries no such key, and its absence deserializes to `None` through
/// `serde(default)` once the version tag is bumped — the runtime reads that
/// `None` as a pre-metadata trace and keeps the historical fault re-supply
/// contract. So the upgrade is purely a version-tag bump, exactly like v2→v3;
/// no recorded event is touched.
fn migrate_v3_to_v4(mut value: serde_json::Value) -> Result<serde_json::Value, TraceError> {
    let object = value
        .as_object_mut()
        .ok_or_else(|| TraceError::Invalid("format 3 trace is not a JSON object".into()))?;
    object.insert("format_version".into(), serde_json::Value::from(4u32));
    Ok(value)
}

fn require_complete_current_bundle(
    value: &serde_json::Value,
    path: &Path,
) -> Result<(), TraceError> {
    let object = value
        .as_object()
        .ok_or_else(|| TraceError::Invalid("trace bundle must be a JSON object".into()))?;
    for field in ["format_version", "metadata", "timelines"] {
        if !object.contains_key(field) {
            return Err(TraceError::Incomplete {
                path: path.to_path_buf(),
                reason: format!("trace bundle is missing required field `{field}`"),
            });
        }
    }
    let metadata = object["metadata"]
        .as_object()
        .ok_or_else(|| TraceError::Incomplete {
            path: path.to_path_buf(),
            reason: "trace metadata is missing or not an object".into(),
        })?;
    for field in ["root_seed", "decision_policy", "fingerprint"] {
        if !metadata.contains_key(field) {
            return Err(TraceError::Incomplete {
                path: path.to_path_buf(),
                reason: format!("trace metadata is missing required field `{field}`"),
            });
        }
    }
    Ok(())
}

fn enforce_trace_byte_limit(
    size: u64,
    max_bytes: u64,
    description: &'static str,
) -> Result<(), TraceError> {
    if size <= max_bytes {
        return Ok(());
    }
    Err(TraceError::ResourceLimit(format!(
        "{description} is {size} bytes; limit is {max_bytes}; reduce recorded event count or payload volume, or split the run"
    )))
}

fn temporary_path(path: &Path) -> PathBuf {
    let counter = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("trace.patina");
    path.with_file_name(format!(".{name}.tmp-{}-{counter}", std::process::id()))
}

#[cfg(test)]
mod tests {
    use patina_dst_abi::{ClockKind, Fd};
    use tempfile::tempdir;

    use super::*;

    fn operation() -> Operation {
        Operation::ClockNow {
            clock: ClockKind::Monotonic,
        }
    }

    #[test]
    fn byte_encoding_round_trips_and_matches_files() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("run.patina");
        let mut recorder = Recorder::new(RunMetadata::new(7, "fingerprint"));
        recorder.observe(operation(), Outcome::U64(10));
        recorder.observe(Operation::FsDup { fd: Fd(3) }, Outcome::Handle(Fd(4)));
        let bundle = recorder.into_bundle();
        let bytes = bundle.to_bytes().unwrap();
        bundle.write_atomic(&path).unwrap();
        assert_eq!(fs::read(&path).unwrap(), bytes);

        let parsed = TraceBundle::from_slice(&bytes).unwrap();
        assert_eq!(parsed, bundle);
        let mut replay = Replayer::from_bundle(parsed, "fingerprint", "main").unwrap();
        assert_eq!(replay.expect(&operation()).unwrap(), Outcome::U64(10));
        assert_eq!(
            replay.expect(&Operation::FsDup { fd: Fd(3) }).unwrap(),
            Outcome::Handle(Fd(4))
        );
        replay.finish().unwrap();

        assert!(matches!(
            TraceBundle::from_slice(b"not json"),
            Err(TraceError::Parse { .. })
        ));
    }

    #[test]
    fn records_loads_and_strictly_replays() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("run.patina");
        let mut recorder = Recorder::new(RunMetadata::new(7, "fingerprint"));
        recorder.observe(operation(), Outcome::U64(10));
        recorder.finish(&path).unwrap();

        let mut replay = Replayer::open(&path, "fingerprint").unwrap();
        assert_eq!(replay.root_seed(), 7);
        assert_eq!(replay.expect(&operation()).unwrap(), Outcome::U64(10));
        replay.finish().unwrap();
        assert_eq!(
            TraceBundle::load(&path).unwrap().format_version,
            TRACE_FORMAT_VERSION
        );
        assert_eq!(
            fs::read_dir(directory.path()).unwrap().count(),
            1,
            "atomic write must not leave a temporary file"
        );
    }

    #[test]
    fn save_paths_reject_serialized_trace_that_exceeds_byte_limit() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("oversized.patina");
        let event = TraceEvent {
            sequence: 0,
            operation: operation(),
            outcome: Outcome::U64(10),
        };
        let bundle = TraceBundle::new(RunMetadata::new(7, "fingerprint"), vec![event]);
        let serialized_len = {
            let mut bytes = serde_json::to_vec(&bundle).unwrap();
            bytes.push(b'\n');
            bytes.len() as u64
        };
        let limit = serialized_len - 1;

        let error = bundle.to_bytes_with_limit(limit).unwrap_err();
        assert!(
            matches!(&error, TraceError::ResourceLimit(message) if message.contains("serialized trace")),
            "unexpected error: {error}"
        );

        let error = bundle.write_atomic_with_limit(&path, limit).unwrap_err();
        assert!(
            matches!(&error, TraceError::ResourceLimit(message) if message.contains("serialized trace")),
            "unexpected error: {error}"
        );
        assert!(
            !path.exists(),
            "save-time refusal must not leave a trace file"
        );
        assert_eq!(
            fs::read_dir(directory.path()).unwrap().count(),
            0,
            "save-time refusal must not leave a temporary file"
        );

        let mut recorder = Recorder::new(RunMetadata::new(7, "fingerprint"));
        recorder.observe(operation(), Outcome::U64(10));
        let error = recorder.finish_with_limit(&path, limit).unwrap_err();
        assert!(
            matches!(&error, TraceError::ResourceLimit(message) if message.contains("serialized trace")),
            "unexpected error: {error}"
        );
        assert!(!path.exists(), "Recorder::finish must fail before writing");
    }

    #[test]
    fn rejects_fingerprint_operation_and_trailing_event_mismatches() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("run.patina");
        let mut recorder = Recorder::new(RunMetadata::new(7, "fingerprint"));
        recorder.observe(operation(), Outcome::U64(10));
        recorder.finish(&path).unwrap();

        assert!(matches!(
            Replayer::open(&path, "changed"),
            Err(TraceError::FingerprintMismatch { .. })
        ));

        let mut replay = Replayer::open(&path, "fingerprint").unwrap();
        let mismatch = replay
            .expect(&Operation::EntropyFill { len: 1 })
            .unwrap_err();
        assert!(matches!(mismatch, TraceError::OperationMismatch { .. }));

        let replay = Replayer::open(&path, "fingerprint").unwrap();
        assert!(matches!(
            replay.finish(),
            Err(TraceError::UnconsumedEvents { .. })
        ));
    }

    #[test]
    fn branches_replay_an_exact_prefix_and_append_a_suffix() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("run.patina");
        let mut recorder = Recorder::new(RunMetadata::new(7, "fingerprint"));
        recorder.observe(operation(), Outcome::U64(10));
        recorder.observe(Operation::EntropyFill { len: 1 }, Outcome::Bytes(vec![1]));
        recorder.finish(&path).unwrap();

        let mut branch =
            BranchSession::open(&path, "fingerprint", "main", 1, "branch-1", 99).unwrap();
        assert_eq!(
            branch.expect_prefix(&operation()).unwrap().unwrap().1,
            Outcome::U64(10)
        );
        assert_eq!(
            branch
                .expect_prefix(&Operation::EntropyFill { len: 1 })
                .unwrap(),
            None
        );
        branch.observe(Operation::EntropyFill { len: 1 }, Outcome::Bytes(vec![9]));
        branch.finish().unwrap();

        let bundle = TraceBundle::load(&path).unwrap();
        assert_eq!(bundle.timelines.len(), 2);
        let resolved = bundle.resolved_timeline("branch-1").unwrap();
        assert_eq!(resolved[0].outcome, Outcome::U64(10));
        assert_eq!(resolved[1].outcome, Outcome::Bytes(vec![9]));
        assert_eq!(bundle.timelines[1].branch_seed, Some(99));
    }

    #[test]
    fn fault_config_metadata_round_trips_and_omits_defaults() {
        let faults = FaultConfigRecord {
            crash_at: Some(CrashPointRecord {
                op: FaultCrashOp::Write,
                ordinal: 34,
            }),
            torn_granularity: TornGranularity::Byte,
            fs_error_permille: 100,
            fs_short_permille: 200,
            net_drop_permille: 250,
            ..FaultConfigRecord::default()
        };
        let metadata = RunMetadata::new(7, "fingerprint").with_faults(Some(faults.clone()));
        let bundle = TraceBundle::new(metadata, Vec::new());
        let bytes = bundle.to_bytes().unwrap();
        let text = String::from_utf8(bytes.clone()).unwrap();
        // Enum tags serialize by name, and inert knobs are omitted entirely.
        assert!(text.contains("\"op\":\"write\""), "{text}");
        assert!(text.contains("\"torn_granularity\":\"byte\""), "{text}");
        assert!(text.contains("\"fs_error_permille\":100"), "{text}");
        assert!(text.contains("\"fs_short_permille\":200"), "{text}");
        assert!(!text.contains("sleep_jitter_nanos"), "{text}");
        assert!(!text.contains("net_latency_nanos"), "{text}");

        let reloaded = TraceBundle::from_slice(&bytes).unwrap();
        assert_eq!(reloaded.metadata.faults, Some(faults));

        // A fault-free run records a compact empty object, still distinct from a
        // pre-metadata trace whose field is absent (None).
        let empty = TraceBundle::new(
            RunMetadata::new(7, "fingerprint").with_faults(Some(FaultConfigRecord::default())),
            Vec::new(),
        );
        let text = String::from_utf8(empty.to_bytes().unwrap()).unwrap();
        assert!(text.contains("\"faults\":{}"), "{text}");
    }

    #[test]
    fn buggify_config_metadata_round_trips_and_is_additive() {
        let mut knobs = BTreeMap::new();
        knobs.insert("commit-batch".to_string(), 42);
        let buggify = BuggifyConfigRecord {
            fire_permille: 250,
            activation_permille: 250,
            cutoff_nanos: 300_000_000_000,
            after_setup: true,
            active_sites: vec!["commit-early-return".to_string()],
            knobs,
        };
        let metadata =
            RunMetadata::new(7, "fingerprint+buggify").with_buggify(Some(buggify.clone()));
        let bundle = TraceBundle::new(metadata, Vec::new());
        let bytes = bundle.to_bytes().unwrap();
        let reloaded = TraceBundle::from_slice(&bytes).unwrap();
        assert_eq!(reloaded.metadata.buggify, Some(buggify));

        // A trace recorded without buggify keeps the field absent, so an old
        // trace and a buggify-disabled run are indistinguishable (both None).
        let plain = TraceBundle::new(RunMetadata::new(7, "fingerprint"), Vec::new());
        let text = String::from_utf8(plain.to_bytes().unwrap()).unwrap();
        assert!(!text.contains("buggify"), "{text}");
        let reloaded_plain = TraceBundle::from_slice(plain.to_bytes().unwrap().as_slice()).unwrap();
        assert_eq!(reloaded_plain.metadata.buggify, None);
    }

    #[test]
    fn buggify_fingerprint_requires_buggify_metadata() {
        // Class-level pairing for SDK buggify value-form point pins: a trace whose
        // fingerprint declares `+buggify` must carry the authoritative buggify
        // config, or the run is vacuous and replay cannot reproduce SDK decisions.
        let invalid = serde_json::json!({
            "format_version": TRACE_FORMAT_VERSION,
            "metadata": {
                "root_seed": 7,
                "decision_policy": "splitmix64-v1",
                "fingerprint": "fingerprint+buggify"
            },
            "timelines": [{
                "id": MAIN_TIMELINE,
                "decisions": []
            }]
        });
        let bytes = serde_json::to_vec(&invalid).unwrap();
        let error = TraceBundle::from_slice(&bytes).expect_err("missing buggify config must fail");
        assert!(
            error
                .to_string()
                .contains("fingerprint declares +buggify but trace metadata has no buggify config"),
            "{error}"
        );
    }

    #[test]
    fn schedule_policy_metadata_round_trips_and_is_additive() {
        let policy = SchedulePolicyRecord {
            pct: Some(PctPolicyRecord {
                depth: 3,
                steps: 512,
            }),
            starvation: Some(StarvationPolicyRecord {
                intervals: 2,
                max_len: 64,
                window: 256,
            }),
        };
        let metadata =
            RunMetadata::new(7, "fingerprint+pct+starve").with_schedule_policy(Some(policy));
        let bundle = TraceBundle::new(metadata, Vec::new());
        let bytes = bundle.to_bytes().unwrap();
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(text.contains("\"depth\":3"), "{text}");
        assert!(text.contains("\"intervals\":2"), "{text}");
        let reloaded = TraceBundle::from_slice(&bytes).unwrap();
        assert_eq!(reloaded.metadata.schedule_policy, Some(policy));
        assert!(reloaded.metadata.schedule_policy.unwrap().is_active());

        // A default-policy run keeps the field absent, indistinguishable from an
        // old trace (both None).
        let plain = TraceBundle::new(RunMetadata::new(7, "fingerprint"), Vec::new());
        let text = String::from_utf8(plain.to_bytes().unwrap()).unwrap();
        assert!(!text.contains("schedule_policy"), "{text}");
        let reloaded_plain = TraceBundle::from_slice(plain.to_bytes().unwrap().as_slice()).unwrap();
        assert_eq!(reloaded_plain.metadata.schedule_policy, None);
    }

    #[test]
    fn swarm_config_metadata_round_trips_and_is_additive() {
        let swarm = SwarmConfigRecord {
            candidate_classes: vec![
                "crash".to_string(),
                "net_drop".to_string(),
                "sleep_jitter".to_string(),
            ],
            selected_classes: vec!["crash".to_string(), "sleep_jitter".to_string()],
        };
        let metadata = RunMetadata::new(7, "fingerprint+swarm").with_swarm(Some(swarm.clone()));
        let bundle = TraceBundle::new(metadata, Vec::new());
        let bytes = bundle.to_bytes().unwrap();
        let reloaded = TraceBundle::from_slice(&bytes).unwrap();
        assert_eq!(reloaded.metadata.swarm, Some(swarm));

        let plain = TraceBundle::new(RunMetadata::new(7, "fingerprint"), Vec::new());
        let text = String::from_utf8(plain.to_bytes().unwrap()).unwrap();
        assert!(!text.contains("swarm"), "{text}");
    }

    /// The candidate/selected lists are the machine-readable record of what swarm
    /// dropped, so consumers derive deselection as their complement. Prove the
    /// derivation and the validation that keeps it meaningful.
    #[test]
    fn swarm_record_partitions_candidates_into_selected_and_deselected() {
        let swarm = SwarmConfigRecord {
            candidate_classes: vec![
                "crash".to_string(),
                "net_drop".to_string(),
                "buggify".to_string(),
            ],
            selected_classes: vec!["crash".to_string()],
        };
        assert_eq!(swarm.deselected_classes(), vec!["net_drop", "buggify"]);
        assert!(swarm.deselected("buggify"));
        assert!(!swarm.deselected("crash"));
        // A class the operator never enabled is in neither list: it was not a
        // candidate, so it was not "deselected" either. That distinction is the
        // whole point — it separates "swarm dropped it" from "never requested".
        assert!(!swarm.was_candidate("fs_error"));
        assert!(!swarm.deselected("fs_error"));
        TraceBundle::new(
            RunMetadata::new(7, "fingerprint+swarm").with_swarm(Some(swarm)),
            Vec::new(),
        )
        .validate()
        .expect("a clean partition validates");

        // RED: a selection that is not a subset of the candidates would make the
        // complement nonsense, so the trace is refused.
        let broken = SwarmConfigRecord {
            candidate_classes: vec!["crash".to_string()],
            selected_classes: vec!["buggify".to_string()],
        };
        let error = TraceBundle::new(
            RunMetadata::new(7, "fingerprint+swarm").with_swarm(Some(broken)),
            Vec::new(),
        )
        .validate()
        .expect_err("a selection outside the candidates must be refused");
        assert!(
            format!("{error}").contains("was not a candidate"),
            "{error}"
        );

        // RED: a duplicated class would double-count in any accumulation.
        let duplicated = SwarmConfigRecord {
            candidate_classes: vec!["crash".to_string(), "crash".to_string()],
            selected_classes: Vec::new(),
        };
        let error = TraceBundle::new(
            RunMetadata::new(7, "fingerprint+swarm").with_swarm(Some(duplicated)),
            Vec::new(),
        )
        .validate()
        .expect_err("a duplicated candidate must be refused");
        assert!(format!("{error}").contains("more than once"), "{error}");
    }

    /// A swarm draw over an empty candidate set is the inert-knob signature: the
    /// operator asked for `--swarm` and the run had nothing to select from.
    /// Dropping every candidate of a non-empty set is the opposite — a legitimate
    /// draw — so the two must not collapse into one predicate.
    #[test]
    fn swarm_record_is_vacuous_exactly_when_there_were_no_candidates() {
        assert!(SwarmConfigRecord::default().is_vacuous());
        let all_dropped = SwarmConfigRecord {
            candidate_classes: vec!["crash".to_string(), "buggify".to_string()],
            selected_classes: Vec::new(),
        };
        assert!(!all_dropped.is_vacuous());
        let all_kept = SwarmConfigRecord {
            candidate_classes: vec!["crash".to_string()],
            selected_classes: vec!["crash".to_string()],
        };
        assert!(!all_kept.is_vacuous());
    }

    #[test]
    fn sud_metadata_round_trips_and_is_additive() {
        // An armed run records `sud:true` and round-trips.
        let metadata = RunMetadata::new(7, "fingerprint").with_sud(Some(true));
        let bundle = TraceBundle::new(metadata, Vec::new());
        let text = String::from_utf8(bundle.to_bytes().unwrap()).unwrap();
        assert!(text.contains("\"sud\":true"), "{text}");
        let reloaded = TraceBundle::from_slice(bundle.to_bytes().unwrap().as_slice()).unwrap();
        assert_eq!(reloaded.metadata.sud, Some(true));

        // Every other run (macOS, non-SUD kernel, standalone, pre-SUD trace)
        // records nothing: the field is omitted, so old and new traces are
        // byte-identical.
        let plain = TraceBundle::new(
            RunMetadata::new(7, "fingerprint").with_sud(None),
            Vec::new(),
        );
        let text = String::from_utf8(plain.to_bytes().unwrap()).unwrap();
        assert!(!text.contains("sud"), "{text}");
        let reloaded_plain = TraceBundle::from_slice(plain.to_bytes().unwrap().as_slice()).unwrap();
        assert_eq!(reloaded_plain.metadata.sud, None);
    }

    #[test]
    fn tsc_metadata_round_trips_and_is_additive() {
        // A run that armed the timestamp-counter trap records `tsc:true` and
        // round-trips, independently of the SUD field.
        let metadata = RunMetadata::new(7, "fingerprint").with_tsc(Some(true));
        let bundle = TraceBundle::new(metadata, Vec::new());
        let text = String::from_utf8(bundle.to_bytes().unwrap()).unwrap();
        assert!(text.contains("\"tsc\":true"), "{text}");
        let reloaded = TraceBundle::from_slice(bundle.to_bytes().unwrap().as_slice()).unwrap();
        assert_eq!(reloaded.metadata.tsc, Some(true));
        assert_eq!(reloaded.metadata.sud, None);

        // Every run that did not arm it records nothing, so a trace taken before
        // the trap existed stays byte-identical.
        let plain = TraceBundle::new(
            RunMetadata::new(7, "fingerprint").with_tsc(None),
            Vec::new(),
        );
        let text = String::from_utf8(plain.to_bytes().unwrap()).unwrap();
        assert!(!text.contains("tsc"), "{text}");
        let reloaded_plain = TraceBundle::from_slice(plain.to_bytes().unwrap().as_slice()).unwrap();
        assert_eq!(reloaded_plain.metadata.tsc, None);
    }

    #[test]
    fn guest_argv_metadata_round_trips_and_is_additive() {
        // A recorded argument list round-trips exactly, including order.
        let argv = vec!["--replay-commands".to_string(), "3,1,2".to_string()];
        let metadata = RunMetadata::new(7, "fingerprint").with_guest_argv(Some(argv.clone()));
        let bundle = TraceBundle::new(metadata, Vec::new());
        let bytes = bundle.to_bytes().unwrap();
        let reloaded = TraceBundle::from_slice(&bytes).unwrap();
        assert_eq!(reloaded.metadata.guest_argv, Some(argv));

        // An empty argument list is recorded as `Some([])` and stays distinct
        // from an old trace's absent field: a zero-argument run must reproduce
        // zero arguments on replay, not inherit whatever the command line gives.
        let empty = TraceBundle::new(
            RunMetadata::new(7, "fingerprint").with_guest_argv(Some(Vec::new())),
            Vec::new(),
        );
        let text = String::from_utf8(empty.to_bytes().unwrap()).unwrap();
        assert!(text.contains("\"guest_argv\":[]"), "{text}");
        let reloaded_empty = TraceBundle::from_slice(empty.to_bytes().unwrap().as_slice()).unwrap();
        assert_eq!(reloaded_empty.metadata.guest_argv, Some(Vec::new()));

        // A trace recorded before argv capture keeps the field absent, so it and
        // the "no arguments recorded" case are distinguishable (None vs Some([])).
        let plain = TraceBundle::new(RunMetadata::new(7, "fingerprint"), Vec::new());
        let text = String::from_utf8(plain.to_bytes().unwrap()).unwrap();
        assert!(!text.contains("guest_argv"), "{text}");
        let reloaded_plain = TraceBundle::from_slice(plain.to_bytes().unwrap().as_slice()).unwrap();
        assert_eq!(reloaded_plain.metadata.guest_argv, None);
    }

    #[test]
    fn guest_env_metadata_round_trips_and_is_additive() {
        let env = BTreeMap::from([("RUST_LOG".to_string(), "debug".to_string())]);
        let metadata = RunMetadata::new(7, "fingerprint").with_guest_env(Some(env.clone()));
        let bundle = TraceBundle::new(metadata, Vec::new());
        let text = String::from_utf8(bundle.to_bytes().unwrap()).unwrap();
        assert!(text.contains("\"guest_env\":{"), "{text}");
        assert!(text.contains("\"RUST_LOG\":\"debug\""), "{text}");
        let reloaded = TraceBundle::from_slice(bundle.to_bytes().unwrap().as_slice()).unwrap();
        assert_eq!(reloaded.metadata.guest_env, Some(env));

        let plain = TraceBundle::new(RunMetadata::new(7, "fingerprint"), Vec::new());
        let text = String::from_utf8(plain.to_bytes().unwrap()).unwrap();
        assert!(!text.contains("guest_env"), "{text}");
        let reloaded_plain = TraceBundle::from_slice(plain.to_bytes().unwrap().as_slice()).unwrap();
        assert_eq!(reloaded_plain.metadata.guest_env, None);
    }

    #[test]
    fn pre_metadata_trace_migrates_to_absent_fault_config() {
        // A format-3 bundle carries no `faults` key; after migration it is None,
        // the runtime's signal to fall back to the re-supply contract.
        let mut v3 = TraceBundle::new(RunMetadata::new(1, "fingerprint"), Vec::new());
        v3.format_version = 3;
        let mut value = serde_json::to_value(&v3).unwrap();
        // Emulate an on-disk v3 trace: strip the additive metadata field.
        value["metadata"].as_object_mut().unwrap().remove("faults");
        value["format_version"] = serde_json::Value::from(3u32);
        let bytes = serde_json::to_vec(&value).unwrap();
        let migrated = TraceBundle::from_slice(&bytes).unwrap();
        assert_eq!(migrated.format_version, TRACE_FORMAT_VERSION);
        assert_eq!(migrated.metadata.faults, None);
    }

    #[test]
    fn rejects_non_contiguous_sequences() {
        let mut bundle = TraceBundle::new(
            RunMetadata::new(1, "fingerprint"),
            vec![TraceEvent {
                sequence: 4,
                operation: operation(),
                outcome: Outcome::U64(0),
            }],
        );
        bundle.timelines[0].decisions[0].sequence = 4;
        assert!(matches!(bundle.validate(), Err(TraceError::Invalid(_))));
    }

    #[test]
    fn rejects_malformed_incomplete_and_unsupported_trace_files() {
        let directory = tempdir().unwrap();
        let malformed = directory.path().join("malformed.patina");
        fs::write(&malformed, b"not json").unwrap();
        assert!(matches!(
            TraceBundle::load(&malformed),
            Err(TraceError::Parse { .. })
        ));

        let empty = directory.path().join("empty.patina");
        fs::write(&empty, b"").unwrap();
        let error = TraceBundle::load(&empty).unwrap_err();
        assert!(
            matches!(&error, TraceError::Incomplete { reason, .. } if reason.contains("empty trace")),
            "unexpected error: {error}"
        );

        let truncated = directory.path().join("truncated.patina");
        fs::write(&truncated, b"{\"format_version\":4,").unwrap();
        let error = TraceBundle::load(&truncated).unwrap_err();
        assert!(
            matches!(&error, TraceError::Incomplete { reason, .. } if reason.contains("truncated JSON")),
            "unexpected error: {error}"
        );

        let incomplete_metadata = directory.path().join("incomplete-metadata.patina");
        fs::write(
            &incomplete_metadata,
            br#"{"format_version":4,"metadata":{"root_seed":1,"decision_policy":"splitmix64-v1"},"timelines":[]}"#,
        )
        .unwrap();
        let error = TraceBundle::load(&incomplete_metadata).unwrap_err();
        assert!(
            matches!(&error, TraceError::Incomplete { reason, .. } if reason.contains("trace metadata") && reason.contains("fingerprint")),
            "unexpected error: {error}"
        );

        assert!(matches!(
            TraceBundle::from_slice(b""),
            Err(TraceError::Incomplete { .. })
        ));

        let unsupported = directory.path().join("unsupported.patina");
        let mut bundle = TraceBundle::new(RunMetadata::new(1, "fingerprint"), Vec::new());
        bundle.format_version = TRACE_FORMAT_VERSION + 1;
        fs::write(&unsupported, serde_json::to_vec(&bundle).unwrap()).unwrap();
        assert!(matches!(
            TraceBundle::load(&unsupported),
            Err(TraceError::UnsupportedVersion { .. })
        ));

        let oversized = directory.path().join("oversized.patina");
        File::create(&oversized)
            .unwrap()
            .set_len(MAX_TRACE_BYTES + 1)
            .unwrap();
        assert!(matches!(
            TraceBundle::load(&oversized),
            Err(TraceError::ResourceLimit(_))
        ));
    }
}
