//! Versioned trace bundles and strict replay matching.
//!
//! Internal crate: the `.patina` trace format — recording boundary events into a
//! versioned JSON bundle (run metadata, timelines, branch sessions), refusing
//! any other format version, and replaying with strict reconciliation
//! (any operation/outcome divergence fails closed rather than lying). Adopters
//! produce and consume traces through `cargo patina run --record` / `replay`
//! and the `patina-dst-runtime` execution modes, not this crate directly.
//! See [ARCHITECTURE.md] for the trace design and its guarantees.
//!
//! [ARCHITECTURE.md]: https://github.com/JacobHayes/patina/blob/main/ARCHITECTURE.md

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use patina_dst_abi::{Operation, Outcome, TaskId};
use serde::{Deserialize, Serialize};

mod crash_restart;
mod file_lock;
mod handoff;
pub use crash_restart::CrashRestartSegments;
pub use file_lock::{create_scratch, lock_exclusive, path_names, remove_dead_scratch};
pub use handoff::{
    HandoffConsumedState, HandoffError, HandoffSealKey, IncarnationHandoff,
    MAX_HANDOFF_PAYLOAD_BYTES, VerifiedIncarnationHandoff,
};

/// The trace bundle format this runtime writes and the only one it reads: a
/// bundle declaring any other `format_version` is refused with
/// [`TraceError::UnsupportedVersion`].
///
/// What each version added:
/// - 2: named timelines with branch metadata.
/// - 3: compact JSON with base64 byte payloads.
/// - 4: the fault-injection configuration in [`RunMetadata::faults`].
/// - 5: incarnation and order on every event, and lifecycle markers.
/// - 6: the creation mode on every creating filesystem operation.
/// - 7: `path_only` (`O_PATH`) in `fs_open`'s flags.
/// - 8: change and birth times on every metadata outcome.
/// - 9: the `signal_generated` operation.
/// - 10: the filesystem and memory families' operations.
/// - 11: the required [`RunMetadata::realtime_epoch_nanos`] and
///   [`RunMetadata::hostname`].
/// - 12: the network family's operations: `net_bind_shared` (one member of an
///   `SO_REUSEPORT` group), `net_connect` (a datagram socket pinned to its
///   peer), `net_mark` (the type of service and source address its sends
///   carry), the address a datagram was dialed at and its mark, and the
///   `unreachable` send disposition for a datagram nothing is bound to take.
pub const TRACE_FORMAT_VERSION: u32 = 12;
pub const MAX_TRACE_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_TIMELINE_EVENTS: usize = 1_000_000;

/// The sole top-level key of an *abandoned-trace marker*: the one-line JSON
/// document a recorder writes into a trace channel INSTEAD of a bundle when it
/// deliberately gives up on the artifact (today: the run outgrew
/// [`MAX_TRACE_BYTES`]). The marker exists so an abandoned trace is never
/// mistaken for either a complete one or a crash-truncated one: it is a
/// positive, self-describing statement that no bundle is coming and why.
///
/// A bundle can never collide with it — a bundle's top-level object always
/// carries `format_version` and never this key — so [`TraceBundle::decode`]
/// recognizes a marker and refuses it as [`TraceError::Incomplete`], which is
/// what makes `cargo patina replay` say "the recorder abandoned this trace"
/// rather than misread a marker file as a corrupt bundle.
pub const ABANDONED_TRACE_KEY: &str = "patina_trace_abandoned";

/// Why a recorder abandoned a trace, as read back off an abandoned-trace
/// marker. `reason` is the stable machine token (`resource-limit`); `detail` is
/// the human sentence that goes with it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AbandonedTrace {
    pub reason: String,
    pub detail: String,
}

/// Serialize an abandoned-trace marker, newline terminated, ready to be written
/// to a trace path or trace descriptor in place of a bundle.
pub fn abandoned_trace_marker(reason: &str, detail: &str) -> Vec<u8> {
    let document = serde_json::json!({
        ABANDONED_TRACE_KEY: AbandonedTrace {
            reason: reason.to_string(),
            detail: detail.to_string(),
        }
    });
    let mut bytes = serde_json::to_vec(&document).unwrap_or_else(|_| {
        // Unreachable in practice (two owned strings always serialize), but the
        // recorder is already on a degraded path here and must not panic while
        // reporting it, so fall back to a marker with no detail.
        format!("{{\"{ABANDONED_TRACE_KEY}\":{{\"reason\":\"unknown\",\"detail\":\"\"}}}}")
            .into_bytes()
    });
    bytes.push(b'\n');
    bytes
}

/// The machine-greppable line a supervisor classifies an abandoned trace on,
/// newline terminated, carrying the figures when the budget is a byte one.
///
/// Shared because a trace can be abandoned from two places — the shim's
/// shutdown path, and a runtime-initiated stop that never reaches shutdown —
/// and a sweep greps for one token, not two spellings of it.
pub fn resource_limit_infra_line(error: &TraceError) -> String {
    let mut line = String::from("PATINA_INFRA trace=incomplete reason=resource-limit");
    if let Some((bytes, limit)) = error.resource_limit_bytes() {
        line.push_str(&format!(" bytes={bytes} limit={limit}"));
    }
    line.push('\n');
    line
}

/// Read an abandoned-trace marker back, or `None` if these bytes are not one.
pub fn parse_abandoned_trace_marker(bytes: &[u8]) -> Option<AbandonedTrace> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    serde_json::from_value(value.get(ABANDONED_TRACE_KEY)?.clone()).ok()
}

const MAIN_TIMELINE: &str = "main";

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
    /// The node name the guest's virtual kernel reports (`uname`,
    /// `gethostname`; `--hostname`, default `patina`). Required exactly like
    /// [`realtime_epoch_nanos`](RunMetadata::realtime_epoch_nanos).
    /// Authoritative on replay; a conflicting explicit name is refused.
    /// Not a fingerprint input.
    pub hostname: String,
}

impl RunMetadata {
    /// The metadata every recording carries. The realtime epoch and the node
    /// name are required run facts, so the caller states them rather than
    /// inheriting a default the trace crate would have to guess.
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
            sud: None,
            tsc: None,
            realtime_epoch_nanos,
            hostname: hostname.into(),
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

/// One incarnation lifecycle marker in a timeline's global logical order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleEvent {
    /// Global order slot within this timeline. Operation events carry their own
    /// `order`; lifecycle and operation orders share one namespace and must be
    /// unique, so crash/restart boundaries can be placed between successful
    /// boundary operations without changing operation sequence numbers.
    pub order: u64,
    #[serde(flatten)]
    pub kind: LifecycleEventKind,
}

/// Lifecycle transitions for crash->fresh-incarnation traces.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LifecycleEventKind {
    Start {
        incarnation: u64,
    },
    Crash {
        incarnation: u64,
        snapshot_digest: String,
    },
    Restart {
        from_incarnation: u64,
        to_incarnation: u64,
        snapshot_digest: String,
    },
    End {
        incarnation: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceEvent {
    /// Operation sequence number, contiguous among boundary operations only.
    pub sequence: u64,
    /// Global order slot shared with lifecycle markers.
    pub order: u64,
    /// Guest incarnation that issued this operation.
    pub incarnation: u64,
    pub operation: Operation,
    pub outcome: Outcome,
}

impl TraceEvent {
    pub fn new(sequence: u64, operation: Operation, outcome: Outcome) -> Self {
        Self {
            sequence,
            order: sequence.saturating_add(1),
            incarnation: 0,
            operation,
            outcome,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Timeline {
    pub id: String,
    pub parent: Option<String>,
    pub from_sequence: Option<u64>,
    pub branch_seed: Option<u64>,
    pub lifecycle: Vec<LifecycleEvent>,
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
        Self::linear(metadata, 0, decisions)
    }

    /// A trace of one incarnation from start to end: every decision belongs to
    /// `incarnation`, between its `Start` and `End` markers.
    pub fn linear(metadata: RunMetadata, incarnation: u64, mut decisions: Vec<TraceEvent>) -> Self {
        for event in &mut decisions {
            event.incarnation = incarnation;
        }
        let start_order = decisions
            .first()
            .map(|event| event.order.saturating_sub(1))
            .unwrap_or(0);
        Self {
            format_version: TRACE_FORMAT_VERSION,
            metadata,
            timelines: vec![Timeline {
                id: MAIN_TIMELINE.into(),
                parent: None,
                from_sequence: None,
                branch_seed: None,
                lifecycle: linear_lifecycle_from_start_and_incarnation(
                    start_order,
                    incarnation,
                    &decisions,
                ),
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

    /// Check a decoded bundle's version, then deserialize and validate it.
    ///
    /// Only a bundle at [`TRACE_FORMAT_VERSION`] is deserialized; any other
    /// declared version is refused before any structural interpretation.
    fn decode(value: serde_json::Value, path: PathBuf) -> Result<Self, TraceError> {
        // An abandoned-trace marker is a valid JSON document that is not a
        // bundle. Recognize it FIRST so the refusal names what actually
        // happened — the recorder gave up on this trace, and why — instead of
        // the "missing format_version" confusion the version check would
        // otherwise report for a file that is not corrupt at all.
        if let Some(abandoned) = value
            .get(ABANDONED_TRACE_KEY)
            .and_then(|marker| serde_json::from_value::<AbandonedTrace>(marker.clone()).ok())
        {
            return Err(TraceError::Incomplete {
                path,
                reason: format!(
                    "the recorder abandoned this trace ({}): {}; it holds no events and cannot be \
                     replayed",
                    abandoned.reason, abandoned.detail
                ),
            });
        }
        if let Some(found) = format_version_of(&value) {
            if found != TRACE_FORMAT_VERSION {
                return Err(TraceError::UnsupportedVersion { found });
            }
        }
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
        remove_dead_scratch(path);
        let (temp_path, file) = create_scratch(path).map_err(|source| TraceError::Io {
            action: format!("create temporary trace beside {}", path.display()),
            source,
        })?;

        let write_result = (|| {
            let mut writer = BufWriter::new(&file);
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
                return Err(TraceError::ResourceLimit {
                    message: format!(
                        "timeline {} has {} events; limit is {MAX_TIMELINE_EVENTS}",
                        timeline.id,
                        timeline.decisions.len()
                    ),
                    bytes: None,
                });
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
            validate_timeline_lifecycle(timeline)?;
            for (index, event) in timeline.decisions.iter().enumerate() {
                let expected = start + index as u64;
                if event.sequence != expected {
                    return Err(TraceError::Invalid(format!(
                        "event {index} in timeline {} has sequence {}, expected {expected}",
                        timeline.id, event.sequence
                    )));
                }
                if index > 0 && event.order <= timeline.decisions[index - 1].order {
                    return Err(TraceError::Invalid(format!(
                        "event {index} in timeline {} has non-increasing global order {}",
                        timeline.id, event.order
                    )));
                }
            }
        }
        for index in 0..self.timelines.len() {
            self.validate_resolved_orders_by_index(index)?;
        }
        Ok(())
    }

    fn validate_resolved_orders_by_index(&self, index: usize) -> Result<(), TraceError> {
        let timeline = &self.timelines[index];
        let decisions = self.resolve_by_index(index)?;
        let lifecycle = self.resolve_lifecycle_by_index(index)?;
        validate_lifecycle_events(
            &format!("resolved timeline {}", timeline.id),
            &lifecycle,
            &decisions,
        )?;
        let mut previous_order = None;
        for event in &decisions {
            if previous_order.is_some_and(|previous| event.order <= previous) {
                return Err(TraceError::Invalid(format!(
                    "resolved timeline {} operation sequence {} has non-increasing global order {}",
                    timeline.id, event.sequence, event.order
                )));
            }
            previous_order = Some(event.order);
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

    pub fn resolved_lifecycle(&self, id: &str) -> Result<Vec<LifecycleEvent>, TraceError> {
        self.validate()?;
        let index = self
            .timelines
            .iter()
            .position(|timeline| timeline.id == id)
            .ok_or_else(|| TraceError::UnknownTimeline(id.into()))?;
        self.resolve_lifecycle_by_index(index)
    }

    fn resolve_lifecycle_by_index(&self, index: usize) -> Result<Vec<LifecycleEvent>, TraceError> {
        let timeline = &self.timelines[index];
        let Some(parent) = &timeline.parent else {
            return Ok(timeline.lifecycle.clone());
        };
        let parent_index = self.timelines[..index]
            .iter()
            .position(|candidate| &candidate.id == parent)
            .ok_or_else(|| TraceError::UnknownTimeline(parent.clone()))?;
        let parent_lifecycle = self.resolve_lifecycle_by_index(parent_index)?;
        let parent_prefix = self.resolve_by_index(parent_index)?;
        let from = timeline.from_sequence.unwrap_or(0) as usize;
        let prefix_last = parent_prefix.get(from.saturating_sub(1));
        let prefix_end_order = prefix_last
            .map(|event| event.order.saturating_add(1))
            .unwrap_or(0);
        let parent_active = prefix_last.map(|event| event.incarnation);
        let mut lifecycle: Vec<_> = parent_lifecycle
            .into_iter()
            .filter(|marker| marker.order < prefix_end_order)
            .collect();
        let mut suffix_lifecycle = timeline.lifecycle.clone();
        if let (Some(active), Some(first)) = (parent_active, suffix_lifecycle.first()) {
            if matches!(first.kind, LifecycleEventKind::Start { incarnation } if incarnation == active)
            {
                suffix_lifecycle.remove(0);
            }
        }
        lifecycle.extend(suffix_lifecycle);
        Ok(lifecycle)
    }
}

fn validate_timeline_lifecycle(timeline: &Timeline) -> Result<(), TraceError> {
    validate_lifecycle_events(
        &format!("timeline {}", timeline.id),
        &timeline.lifecycle,
        &timeline.decisions,
    )
}

fn validate_lifecycle_events(
    label: &str,
    lifecycle: &[LifecycleEvent],
    decisions: &[TraceEvent],
) -> Result<(), TraceError> {
    if lifecycle.len() < 2 {
        return Err(TraceError::Invalid(format!(
            "{label} must record at least Start and End lifecycle events"
        )));
    }

    let mut global_orders = BTreeSet::new();
    let mut active = None;
    let mut pending_restart_start = None;
    let mut last_crash: Option<(u64, &str)> = None;
    for (index, marker) in lifecycle.iter().enumerate() {
        if !global_orders.insert(marker.order) {
            return Err(TraceError::Invalid(format!(
                "{label} has duplicate global order {}",
                marker.order
            )));
        }
        if index > 0 && marker.order <= lifecycle[index - 1].order {
            return Err(TraceError::Invalid(format!(
                "{label} lifecycle order {} is not strictly increasing",
                marker.order
            )));
        }
        match &marker.kind {
            LifecycleEventKind::Start { incarnation } => {
                if active.is_some() {
                    return Err(TraceError::Invalid(format!(
                        "{label} starts incarnation {incarnation} while another incarnation is active"
                    )));
                }
                if let Some(expected) = pending_restart_start.take() {
                    if *incarnation != expected {
                        return Err(TraceError::Invalid(format!(
                            "{label} starts incarnation {incarnation} but restart expected {expected}"
                        )));
                    }
                } else if index != 0 {
                    return Err(TraceError::Invalid(format!(
                        "{label} has Start({incarnation}) without a preceding Restart"
                    )));
                }
                active = Some(*incarnation);
            }
            LifecycleEventKind::Crash {
                incarnation,
                snapshot_digest,
            } => {
                Sha256Digest::parse(snapshot_digest)?;
                if active != Some(*incarnation) {
                    return Err(TraceError::Invalid(format!(
                        "{label} crashes inactive incarnation {incarnation}"
                    )));
                }
                active = None;
                last_crash = Some((*incarnation, snapshot_digest.as_str()));
            }
            LifecycleEventKind::Restart {
                from_incarnation,
                to_incarnation,
                snapshot_digest,
            } => {
                Sha256Digest::parse(snapshot_digest)?;
                if active.is_some() {
                    return Err(TraceError::Invalid(format!(
                        "{label} restarts while an incarnation is still active"
                    )));
                }
                let Some((crashed, crash_digest)) = last_crash.take() else {
                    return Err(TraceError::Invalid(format!(
                        "{label} has Restart without a preceding Crash"
                    )));
                };
                if crashed != *from_incarnation || crash_digest != snapshot_digest {
                    return Err(TraceError::Invalid(format!(
                        "{label} Restart does not match preceding Crash"
                    )));
                }
                if to_incarnation <= from_incarnation {
                    return Err(TraceError::Invalid(format!(
                        "{label} Restart target must be greater than source"
                    )));
                }
                pending_restart_start = Some(*to_incarnation);
            }
            LifecycleEventKind::End { incarnation } => {
                if active != Some(*incarnation) {
                    return Err(TraceError::Invalid(format!(
                        "{label} ends inactive incarnation {incarnation}"
                    )));
                }
                active = None;
            }
        }
    }
    if active.is_some() || pending_restart_start.is_some() || last_crash.is_some() {
        return Err(TraceError::Invalid(format!(
            "{label} lifecycle does not end cleanly"
        )));
    }

    for event in decisions {
        if !global_orders.insert(event.order) {
            return Err(TraceError::Invalid(format!(
                "{label} operation sequence {} reuses global order {}",
                event.sequence, event.order
            )));
        }
        let active_incarnation =
            active_incarnation_at_order(lifecycle, event.order).ok_or_else(|| {
                TraceError::Invalid(format!(
                    "{label} operation sequence {} at order {} is outside any active incarnation",
                    event.sequence, event.order
                ))
            })?;
        if event.incarnation != active_incarnation {
            return Err(TraceError::Invalid(format!(
                "{label} operation sequence {} declares incarnation {}, expected {} from lifecycle",
                event.sequence, event.incarnation, active_incarnation
            )));
        }
    }
    Ok(())
}

fn active_incarnation_at_order(lifecycle: &[LifecycleEvent], order: u64) -> Option<u64> {
    let mut active = None;
    let mut pending_restart_start = None;
    for marker in lifecycle {
        if marker.order >= order {
            break;
        }
        match marker.kind {
            LifecycleEventKind::Start { incarnation } => {
                if pending_restart_start.is_none_or(|expected| expected == incarnation) {
                    active = Some(incarnation);
                    pending_restart_start = None;
                }
            }
            LifecycleEventKind::Crash { .. } | LifecycleEventKind::End { .. } => {
                active = None;
            }
            LifecycleEventKind::Restart { to_incarnation, .. } => {
                pending_restart_start = Some(to_incarnation);
            }
        }
    }
    active
}

/// A SHA-256 digest in its one text form, `sha256:` followed by 64 lowercase
/// hex digits: how a lifecycle marker names the recovered filesystem snapshot,
/// and how the supervisor reports digests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sha256Digest(pub [u8; 32]);

impl Sha256Digest {
    const PREFIX: &'static str = "sha256:";

    pub fn parse(text: &str) -> Result<Self, TraceError> {
        let invalid = || {
            TraceError::Invalid(format!(
                "digest {text:?} must use sha256:<64 lowercase hex>"
            ))
        };
        let hex = text.strip_prefix(Self::PREFIX).ok_or_else(invalid)?;
        if hex.len() != 64
            || !hex
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(invalid());
        }
        let mut digest = [0_u8; 32];
        for (byte, pair) in digest.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
            let pair = std::str::from_utf8(pair).map_err(|_| invalid())?;
            *byte = u8::from_str_radix(pair, 16).map_err(|_| invalid())?;
        }
        Ok(Self(digest))
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(Self::PREFIX)?;
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// A `Write` sink that counts bytes instead of keeping them, so a value can be
/// measured in its serialized encoding without ever materializing it.
struct ByteCounter(u64);

impl Write for ByteCounter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.saturating_add(buf.len() as u64);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Exactly how many bytes `event` occupies inside a serialized bundle, or
/// `None` when it does not serialize at all.
///
/// A `None` is deliberately NOT a budget event: an event that will not
/// serialize means a broken recorder, and the loud finalization failure that
/// diagnoses it must be reached rather than pre-empted by a graceful budget
/// refusal. The ledger charges nothing for such an event and lets finalization
/// fail the run (see [`EventLedger::admit`]).
fn serialized_event_len(event: &TraceEvent) -> Option<u64> {
    let mut counter = ByteCounter(0);
    serde_json::to_writer(&mut counter, event).ok()?;
    Some(counter.0)
}

/// A budget refusal decided in flight, kept as the parts of the
/// [`TraceError::ResourceLimit`] it becomes: `TraceError` is not `Clone`, and
/// the refusal has to be reproducible at every finalization entry point.
#[derive(Clone, Debug)]
struct Overflow {
    message: String,
    bytes: Option<(u64, u64)>,
}

impl Overflow {
    fn to_error(&self) -> TraceError {
        TraceError::ResourceLimit {
            message: self.message.clone(),
            bytes: self.bytes,
        }
    }
}

/// What the events a recorder is holding will cost in the serialized bundle,
/// tallied as they arrive, and the budget they are held against.
///
/// A recorder used to learn it had outgrown [`MAX_TRACE_BYTES`] only when it
/// serialized at finalization — by which time the entire run was already in
/// memory (gigabytes for a long guest) and the artifact was lost anyway. The
/// ledger moves that discovery to the event that crosses the budget, so a
/// doomed recording costs a bounded amount of RAM instead of an unbounded one.
/// The run itself is untouched: recording is write-only, so a recorder that
/// goes inert cannot change what the guest does or what verdict it reaches.
///
/// An event is charged its EXACT serialized length plus the one separator byte
/// that will precede it in the `decisions` array, so the running total is a
/// true count of the events' share of the bundle. It deliberately excludes the
/// bundle's framing and metadata, which makes the total a strict UNDER-estimate
/// of the file: a recording that would have fit can therefore never be
/// abandoned in flight, and a trace under budget is byte-identical to one
/// recorded without a ledger at all. The exact, authoritative check still
/// happens at serialization ([`TraceBundle::to_bytes_with_limit`]) — this is a
/// bound on memory, not a second opinion about the limit.
///
/// The decision is a pure function of the recorded event stream: the same run
/// records the same events in the same order and therefore overflows at exactly
/// the same event, on every host and on every re-run. Nothing here consults the
/// clock, the allocator, or how much memory the machine has.
struct EventLedger {
    /// Serialized bytes of the events admitted so far, separators included.
    bytes: u64,
    /// Events admitted so far, including the one that overflowed.
    events: u64,
    max_bytes: u64,
    max_events: u64,
    overflow: Option<Overflow>,
}

impl EventLedger {
    const fn new(max_bytes: u64) -> Self {
        Self::with_limits(max_bytes, MAX_TIMELINE_EVENTS as u64)
    }

    const fn with_limits(max_bytes: u64, max_events: u64) -> Self {
        Self {
            bytes: 0,
            events: 0,
            max_bytes,
            max_events,
            overflow: None,
        }
    }

    const fn overflowed(&self) -> bool {
        self.overflow.is_some()
    }

    fn overflow_error(&self) -> Option<TraceError> {
        self.overflow.as_ref().map(Overflow::to_error)
    }

    /// Charge one more event. `true` if the caller may go on holding it;
    /// `false` once the budget is spent, which means the caller must drop
    /// everything it holds and record nothing further — the trace is abandoned.
    ///
    /// Both of the bundle's recorded budgets are enforced here, the byte budget
    /// and [`MAX_TIMELINE_EVENTS`], because either one reached at finalization
    /// costs the artifact anyway; reaching them in flight at least stops paying
    /// for it in memory.
    fn admit(&mut self, event: &TraceEvent, timeline: &str) -> bool {
        if self.overflowed() {
            return false;
        }
        let separator = u64::from(self.events > 0);
        self.bytes = self
            .bytes
            .saturating_add(separator)
            .saturating_add(serialized_event_len(event).unwrap_or(0));
        self.events += 1;
        if self.events > self.max_events {
            self.overflow = Some(Overflow {
                message: format!(
                    "timeline {timeline} reached {} events while recording; limit is {}; the \
                     recorder abandoned the trace rather than hold more",
                    self.events, self.max_events
                ),
                bytes: None,
            });
            return false;
        }
        if self.bytes > self.max_bytes {
            self.overflow = Some(Overflow {
                message: format!(
                    "recorded trace reached {} bytes of events at event {} of timeline \
                     {timeline}; limit is {}; the recorder abandoned the trace rather than hold \
                     more; reduce recorded event count or payload volume, or split the run",
                    self.bytes, self.events, self.max_bytes
                ),
                bytes: Some((self.bytes, self.max_bytes)),
            });
            return false;
        }
        true
    }
}

pub struct Recorder {
    metadata: RunMetadata,
    incarnation: u64,
    decisions: Vec<TraceEvent>,
    ledger: EventLedger,
}

impl Recorder {
    pub fn new(metadata: RunMetadata) -> Self {
        Self::with_limit(metadata, MAX_TRACE_BYTES)
    }

    /// A recorder that abandons after `max_bytes` of recorded events instead of
    /// [`MAX_TRACE_BYTES`], so the in-flight budget is testable without
    /// recording a quarter of a gigabyte.
    fn with_limit(metadata: RunMetadata, max_bytes: u64) -> Self {
        Self::with_limits(metadata, max_bytes, MAX_TIMELINE_EVENTS as u64)
    }

    fn with_limits(metadata: RunMetadata, max_bytes: u64, max_events: u64) -> Self {
        Self {
            metadata,
            incarnation: 0,
            decisions: Vec::new(),
            ledger: EventLedger::with_limits(max_bytes, max_events),
        }
    }

    /// Record the operations of `incarnation` of a crash-restart run; every
    /// other recording is incarnation 0.
    #[must_use]
    pub fn with_incarnation(mut self, incarnation: u64) -> Self {
        self.incarnation = incarnation;
        self
    }

    /// Record one boundary decision — unless this trace has already been
    /// abandoned for outgrowing its budget, after which the recorder is inert
    /// and holds nothing. See [`EventLedger`] for why abandoning early is safe.
    pub fn observe(&mut self, operation: Operation, outcome: Outcome) {
        if self.ledger.overflowed() {
            return;
        }
        let mut event = TraceEvent::new(self.decisions.len() as u64, operation, outcome);
        event.incarnation = self.incarnation;
        if self.ledger.admit(&event, MAIN_TIMELINE) {
            self.decisions.push(event);
        } else {
            // Release the held events AND their capacity the moment the trace
            // is abandoned: the whole point is that a doomed recording stops
            // costing memory here rather than at finalization.
            self.decisions = Vec::new();
        }
    }

    /// Overwrite the recorded buggify configuration at finalization. The run's
    /// realized active-site set and knob picks are only known after execution, so
    /// the runtime records the static config at build time and calls this to fold
    /// in the accrued detail before the bundle is written.
    pub fn set_buggify(&mut self, buggify: Option<BuggifyConfigRecord>) {
        self.metadata.buggify = buggify;
    }

    pub fn finish(self, path: impl AsRef<Path>) -> Result<(), TraceError> {
        let max_bytes = self.ledger.max_bytes;
        self.finish_with_limit(path, max_bytes)
    }

    fn finish_with_limit(self, path: impl AsRef<Path>, max_bytes: u64) -> Result<(), TraceError> {
        self.into_bundle()?.write_atomic_with_limit(path, max_bytes)
    }

    /// Convert the recorded decisions into a bundle without touching storage,
    /// or refuse with the budget error when the trace was abandoned in flight.
    ///
    /// The refusal is the SAME [`TraceError::ResourceLimit`] the serialization
    /// check would have raised, so every consumer of the graceful budget path —
    /// the shim's shutdown downgrade, the abandoned-trace marker, the
    /// `PATINA_INFRA` line — behaves exactly as it did when the overflow was
    /// only discovered at finalization. An abandoned recorder must never yield
    /// a bundle: it holds no events, and a structurally valid trace claiming
    /// zero decisions would replay as a lie.
    pub fn into_bundle(self) -> Result<TraceBundle, TraceError> {
        match self.ledger.overflow_error() {
            Some(error) => Err(error),
            None => Ok(TraceBundle::linear(
                self.metadata,
                self.incarnation,
                self.decisions,
            )),
        }
    }

    /// A bundle of the decisions recorded SO FAR, leaving the recorder usable.
    /// The runtime writes one of these when a run is stopped mid-flight (step
    /// budget exhausted, frozen-clock churn) and the consuming
    /// [`Recorder::into_bundle`] at finalization is never reached — a truncated
    /// but structurally valid trace beats the empty file the abort would leave.
    /// An abandoned trace refuses here too, for the reason above.
    pub fn to_bundle(&self) -> Result<TraceBundle, TraceError> {
        match self.ledger.overflow_error() {
            Some(error) => Err(error),
            None => Ok(TraceBundle::linear(
                self.metadata.clone(),
                self.incarnation,
                self.decisions.clone(),
            )),
        }
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

    /// The guest's initial working directory recorded into the trace. `None`
    /// for a run that started at `/` or a trace recorded before cwd capture.
    pub fn guest_cwd(&self) -> Option<&str> {
        self.metadata.guest_cwd.as_deref()
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

    /// The virtual realtime epoch the trace was recorded on (see
    /// [`RunMetadata::realtime_epoch_nanos`]).
    pub const fn realtime_epoch_nanos(&self) -> u64 {
        self.metadata.realtime_epoch_nanos
    }

    /// The node name the trace was recorded under (see
    /// [`RunMetadata::hostname`]).
    pub fn hostname(&self) -> &str {
        &self.metadata.hostname
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
    suffix_next_order: u64,
    suffix_incarnation: u64,
    /// Bounds the branch's OWN suffix the way [`Recorder`]'s ledger bounds a
    /// recording. The inherited parent bundle is already bounded by the load-
    /// time byte limit, and budgeting the suffix alone keeps the in-flight
    /// total a strict under-estimate of the written file, so a branch that
    /// would have fit is never abandoned.
    ledger: EventLedger,
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
        let suffix_next_order = prefix_decisions
            .last()
            .map(|event| event.order.saturating_add(2))
            .unwrap_or(1);
        let suffix_incarnation = prefix_decisions
            .last()
            .map(|event| event.incarnation)
            .unwrap_or(0);
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
            suffix_next_order,
            suffix_incarnation,
            ledger: EventLedger::new(MAX_TRACE_BYTES),
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

    /// The guest's initial working directory inherited from the parent trace.
    pub fn guest_cwd(&self) -> Option<&str> {
        self.bundle.metadata.guest_cwd.as_deref()
    }

    /// The virtual realtime epoch inherited from the parent trace.
    pub const fn realtime_epoch_nanos(&self) -> u64 {
        self.bundle.metadata.realtime_epoch_nanos
    }

    /// The node name inherited from the parent trace.
    pub fn hostname(&self) -> &str {
        &self.bundle.metadata.hostname
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
        if self.ledger.overflowed() {
            return;
        }
        let mut event = TraceEvent::new(
            self.from_sequence + self.suffix.len() as u64,
            operation,
            outcome,
        );
        event.order = self
            .suffix_next_order
            .saturating_add(self.suffix.len() as u64);
        event.incarnation = self.suffix_incarnation;
        if self.ledger.admit(&event, &self.branch_id) {
            self.suffix.push(event);
        } else {
            self.suffix = Vec::new();
        }
    }

    pub fn finish(self) -> Result<(), TraceError> {
        // Prefix reconciliation first: a divergence from the parent trace is a
        // real finding and stays loud, ahead of the graceful budget refusal.
        self.prefix.finish()?;
        if let Some(error) = self.ledger.overflow_error() {
            return Err(error);
        }
        let mut bundle = self.bundle;
        let lifecycle = linear_lifecycle_from_start_and_incarnation(
            self.suffix_next_order.saturating_sub(1),
            self.suffix_incarnation,
            &self.suffix,
        );
        bundle.timelines.push(Timeline {
            id: self.branch_id,
            parent: Some(self.parent),
            from_sequence: Some(self.from_sequence),
            branch_seed: Some(self.branch_seed),
            lifecycle,
            decisions: self.suffix,
        });
        bundle.write_atomic(self.path)
    }
}

fn linear_lifecycle_from_start_and_incarnation(
    start_order: u64,
    incarnation: u64,
    decisions: &[TraceEvent],
) -> Vec<LifecycleEvent> {
    let end_order = decisions
        .last()
        .map(|event| event.order.saturating_add(1))
        .unwrap_or(start_order.saturating_add(1));
    vec![
        LifecycleEvent {
            order: start_order,
            kind: LifecycleEventKind::Start { incarnation },
        },
        LifecycleEvent {
            order: end_order,
            kind: LifecycleEventKind::End { incarnation },
        },
    ]
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
    /// The bundle declares a `format_version` other than
    /// [`TRACE_FORMAT_VERSION`].
    UnsupportedVersion {
        found: u32,
    },
    Invalid(String),
    /// A *budget* refusal: the trace is larger than a configured limit allows.
    /// Distinct in kind from every other variant here — nothing is broken or
    /// corrupt, the run simply produced more than the budget carries — so a
    /// consumer that must tell "patina is misbehaving" from "this run outgrew
    /// its budget" can branch on it. `bytes` carries the observed size and the
    /// limit for a byte budget (`None` for the event-count budget) so that
    /// consumer can report the numbers without parsing `message` back apart.
    ResourceLimit {
        message: String,
        bytes: Option<(u64, u64)>,
    },
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

impl TraceError {
    /// Whether this refusal is a budget refusal (see
    /// [`TraceError::ResourceLimit`]) rather than a broken, corrupt, or
    /// unwritable trace. Callers that must keep failing closed on a genuine
    /// recorder fault, while treating "the run outgrew its trace budget" as a
    /// lost artifact rather than a lost run, branch on this.
    pub fn is_resource_limit(&self) -> bool {
        matches!(self, Self::ResourceLimit { .. })
    }

    /// The observed size and the budget, in bytes, when this refusal is a
    /// *byte* budget refusal. `None` for every other refusal, including the
    /// event-count budget, which has no byte figures to report.
    pub fn resource_limit_bytes(&self) -> Option<(u64, u64)> {
        match self {
            Self::ResourceLimit { bytes, .. } => *bytes,
            _ => None,
        }
    }
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
            Self::UnsupportedVersion { found } => write!(
                f,
                "trace format version {found} is not supported; this runtime reads format {TRACE_FORMAT_VERSION}"
            ),
            Self::Invalid(message) => write!(f, "invalid trace: {message}"),
            Self::ResourceLimit { message, .. } => {
                write!(f, "trace resource limit exceeded: {message}")
            }
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

/// Read the declared format version from a decoded bundle when it is present as
/// a non-negative integer. A missing or non-integer field yields `None`, so the
/// caller defers to typed deserialization for a precise parse error rather than
/// guessing a version.
fn format_version_of(value: &serde_json::Value) -> Option<u32> {
    u32::try_from(value.get("format_version")?.as_u64()?).ok()
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
    Err(TraceError::ResourceLimit {
        message: format!(
            "{description} is {size} bytes; limit is {max_bytes}; reduce recorded event count or payload volume, or split the run"
        ),
        bytes: Some((size, max_bytes)),
    })
}

#[cfg(test)]
mod tests {
    use patina_dst_abi::{
        ClockKind, Datagram, Fd, SendDisposition, SendReport, SignalTarget, SocketId, TaskId,
    };
    use tempfile::tempdir;

    use super::*;

    fn operation() -> Operation {
        Operation::ClockNow {
            clock: ClockKind::Monotonic,
        }
    }

    #[test]
    fn a_current_bundle_must_state_its_run_facts() {
        // The realtime epoch and the node name are required: a bundle missing
        // either does not parse.
        let bytes = include_bytes!("../tests/fixtures/format-12.patina");
        for field in ["realtime_epoch_nanos", "hostname"] {
            let mut value: serde_json::Value = serde_json::from_slice(bytes).unwrap();
            assert!(
                value["metadata"]
                    .as_object_mut()
                    .unwrap()
                    .remove(field)
                    .is_some()
            );
            let bytes = serde_json::to_vec(&value).unwrap();
            assert!(
                matches!(
                    TraceBundle::from_slice(&bytes),
                    Err(TraceError::Parse { .. })
                ),
                "a bundle without {field} must not parse"
            );
        }
    }

    #[test]
    fn run_facts_round_trip_through_the_metadata() {
        let metadata = RunMetadata::new(7, "fingerprint", 1_000_000_000, "db-1");
        let bundle = TraceBundle::new(metadata, Vec::new());
        let reloaded = TraceBundle::from_slice(&bundle.to_bytes().unwrap()).unwrap();
        assert_eq!(reloaded.metadata.realtime_epoch_nanos, 1_000_000_000);
        assert_eq!(reloaded.metadata.hostname, "db-1");
        let replay = Replayer::from_bundle(reloaded, "fingerprint", "main").unwrap();
        assert_eq!(replay.realtime_epoch_nanos(), 1_000_000_000);
        assert_eq!(replay.hostname(), "db-1");
    }

    #[test]
    fn memory_operations_fixture_decodes_and_replays() {
        // Checked-in feature fixture pins the page cache's and anonymous
        // files' operations and one of the filesystem family's.
        let bytes = include_bytes!("../tests/fixtures/format-12-memory.patina");
        let bundle = TraceBundle::from_slice(bytes).unwrap();
        bundle.validate().unwrap();
        assert_eq!(bundle.to_bytes().unwrap(), bytes);
        let expected = [
            (
                Operation::FsCreateAnonymous {
                    name: "buffer".into(),
                    mode: 0o777,
                    seals: 1,
                    huge_page: 0,
                },
                Outcome::Handle(Fd(4)),
            ),
            (
                Operation::FsAddSeals {
                    fd: Fd(4),
                    seals: 8,
                    writably_mapped: false,
                },
                Outcome::Unit,
            ),
            (Operation::FsSeals { fd: Fd(4) }, Outcome::U64(9)),
            (
                Operation::FsWriteBackAt {
                    fd: Fd(3),
                    offset: 4096,
                    bytes: b"mapped".to_vec(),
                },
                Outcome::Usize(6),
            ),
            (
                Operation::FsRenameWhiteout {
                    from: "/a".into(),
                    to: "/b".into(),
                },
                Outcome::Unit,
            ),
        ];
        let mut replay = Replayer::from_bundle(bundle, "fixture-fingerprint", "main").unwrap();
        for (operation, outcome) in expected {
            assert_eq!(replay.expect(&operation).unwrap(), outcome);
        }
        replay.finish().unwrap();
    }

    #[test]
    fn network_operations_fixture_decodes_and_replays() {
        // Checked-in feature fixture pins the network family's operations and
        // a marked datagram's encoding.
        let bytes = include_bytes!("../tests/fixtures/format-12-network.patina");
        let expected = [
            (
                Operation::NetBindShared {
                    address: "127.0.0.1:80".into(),
                },
                Outcome::Socket(SocketId(1)),
            ),
            (
                Operation::NetConnect {
                    socket: SocketId(1),
                    local: "127.0.0.1:80".into(),
                    peer: Some("127.0.0.1:81".into()),
                },
                Outcome::Unit,
            ),
            (
                Operation::NetMark {
                    socket: SocketId(1),
                    tos: 0x10,
                    source: Some("127.0.0.2".into()),
                },
                Outcome::Unit,
            ),
            (
                Operation::NetSend {
                    socket: SocketId(1),
                    to: "127.0.0.1:9".into(),
                    bytes: b"nobody".to_vec(),
                    now_nanos: 0,
                },
                Outcome::SendReport(SendReport {
                    written: 6,
                    copies: 0,
                    delivery_nanos: Vec::new(),
                    disposition: SendDisposition::Unreachable,
                }),
            ),
            (
                Operation::NetRecv {
                    socket: SocketId(1),
                    now_nanos: 0,
                },
                Outcome::Datagram(Some(Datagram {
                    packet_id: 3,
                    from: "127.0.0.1:81".into(),
                    to: "0.0.0.0:80".into(),
                    bytes: b"hi".to_vec(),
                    delivery_nanos: 0,
                    dialed: "127.0.0.1:80".into(),
                    tos: 0x10,
                })),
            ),
        ];
        // The fixture is exactly what a recording of these decisions writes.
        let recorded = TraceBundle::new(
            RunMetadata::new(42, "fixture-fingerprint", 0, "patina"),
            expected
                .iter()
                .enumerate()
                .map(|(sequence, (operation, outcome))| {
                    TraceEvent::new(sequence as u64, operation.clone(), outcome.clone())
                })
                .collect(),
        );
        assert_eq!(
            String::from_utf8(recorded.to_bytes().unwrap()).unwrap(),
            String::from_utf8(bytes.to_vec()).unwrap()
        );
        let bundle = TraceBundle::from_slice(bytes).unwrap();
        bundle.validate().unwrap();
        assert_eq!(bundle.format_version, TRACE_FORMAT_VERSION);
        let mut replay = Replayer::from_bundle(bundle, "fixture-fingerprint", "main").unwrap();
        for (operation, outcome) in expected {
            assert_eq!(replay.expect(&operation).unwrap(), outcome);
        }
        replay.finish().unwrap();
    }

    #[test]
    fn signal_operations_fixture_decodes_and_replays() {
        // Checked-in feature fixture pins both target encodings and every field.
        const SIGUSR1: u8 = 10;
        const SIGUSR2: u8 = 12;
        const SI_USER: i32 = 0;
        const SI_TKILL: i32 = -6;
        let bytes = include_bytes!("../tests/fixtures/format-12-signals.patina");
        let bundle = TraceBundle::from_slice(bytes).unwrap();
        bundle.validate().unwrap();
        assert_eq!(bundle.format_version, TRACE_FORMAT_VERSION);
        assert_eq!(bundle.to_bytes().unwrap(), bytes);
        let expected = [
            Operation::SignalGenerated {
                seq: 1,
                sig: SIGUSR1,
                target: SignalTarget::Process,
                code: SI_USER,
                value: 0,
            },
            Operation::SignalGenerated {
                seq: 2,
                sig: SIGUSR2,
                target: SignalTarget::Task(TaskId(2)),
                code: SI_TKILL,
                value: 123,
            },
        ];
        let mut replay = Replayer::from_bundle(bundle, "fixture-fingerprint", "main").unwrap();
        for operation in expected {
            assert_eq!(replay.expect(&operation).unwrap(), Outcome::Unit);
        }
        replay.finish().unwrap();
    }

    #[test]
    fn byte_encoding_round_trips_and_matches_files() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("run.patina");
        let mut recorder = Recorder::new(RunMetadata::new(7, "fingerprint", 0, "patina"));
        recorder.observe(operation(), Outcome::U64(10));
        recorder.observe(Operation::FsDup { fd: Fd(3) }, Outcome::Handle(Fd(4)));
        let bundle = recorder.into_bundle().unwrap();
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
        let mut recorder = Recorder::new(RunMetadata::new(7, "fingerprint", 0, "patina"));
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

    /// A writer that dies mid-write leaves its scratch file behind, and a
    /// scratch name derived from the pid is the name the next process given
    /// that pid picks. Red while scratch names were `.<trace>.tmp-<pid>-<n>`
    /// opened with `create_new`: these leftovers refused the write.
    #[test]
    fn a_dead_writers_scratch_file_does_not_block_a_write() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("run.patina");
        for counter in 0..1024 {
            let name = format!(".run.patina.tmp-{}-{counter}", std::process::id());
            File::create(directory.path().join(name)).unwrap();
        }
        let mut recorder = Recorder::new(RunMetadata::new(7, "fingerprint", 0, "patina"));
        recorder.observe(operation(), Outcome::U64(10));
        recorder.finish(&path).unwrap();
        TraceBundle::load(&path).unwrap();
    }

    /// A write sweeps the scratch files beside its trace that no writer holds
    /// and spares one a live writer holds.
    #[test]
    fn a_write_sweeps_dead_scratch_and_spares_live_scratch() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("run.patina");
        let (live, _held) = create_scratch(&path).unwrap();
        let dead = directory.path().join(".run.patina.tmp.dead");
        File::create(&dead).unwrap();
        let other_trace = directory.path().join(".run.patina2.tmp.dead");
        File::create(&other_trace).unwrap();

        TraceBundle::new(RunMetadata::new(7, "fingerprint", 0, "patina"), Vec::new())
            .write_atomic(&path)
            .unwrap();
        assert!(!dead.exists(), "a dead writer's scratch is swept");
        assert!(live.exists(), "a live writer's scratch is spared");
        assert!(other_trace.exists(), "another trace's scratch is not swept");
    }

    #[test]
    fn save_paths_reject_serialized_trace_that_exceeds_byte_limit() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("oversized.patina");
        let event = TraceEvent::new(0, operation(), Outcome::U64(10));
        let bundle = TraceBundle::new(RunMetadata::new(7, "fingerprint", 0, "patina"), vec![event]);
        let serialized_len = {
            let mut bytes = serde_json::to_vec(&bundle).unwrap();
            bytes.push(b'\n');
            bytes.len() as u64
        };
        let limit = serialized_len - 1;

        let error = bundle.to_bytes_with_limit(limit).unwrap_err();
        assert!(
            matches!(&error, TraceError::ResourceLimit { message, bytes: Some(_) } if message.contains("serialized trace")),
            "unexpected error: {error}"
        );

        let error = bundle.write_atomic_with_limit(&path, limit).unwrap_err();
        assert!(
            matches!(&error, TraceError::ResourceLimit { message, bytes: Some(_) } if message.contains("serialized trace")),
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

        let mut recorder = Recorder::new(RunMetadata::new(7, "fingerprint", 0, "patina"));
        recorder.observe(operation(), Outcome::U64(10));
        let error = recorder.finish_with_limit(&path, limit).unwrap_err();
        assert!(
            matches!(&error, TraceError::ResourceLimit { message, bytes: Some(_) } if message.contains("serialized trace")),
            "unexpected error: {error}"
        );
        assert!(!path.exists(), "Recorder::finish must fail before writing");
    }

    #[test]
    fn rejects_fingerprint_operation_and_trailing_event_mismatches() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("run.patina");
        let mut recorder = Recorder::new(RunMetadata::new(7, "fingerprint", 0, "patina"));
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
        let mut recorder = Recorder::new(RunMetadata::new(7, "fingerprint", 0, "patina"));
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
        assert_eq!(resolved[0].order, 1);
        assert_eq!(resolved[1].order, 3);
        assert_eq!(resolved[0].incarnation, 0);
        assert_eq!(resolved[1].incarnation, 0);
        let lifecycle = bundle.resolved_lifecycle("branch-1").unwrap();
        assert_eq!(
            lifecycle,
            vec![
                LifecycleEvent {
                    order: 0,
                    kind: LifecycleEventKind::Start { incarnation: 0 },
                },
                LifecycleEvent {
                    order: 4,
                    kind: LifecycleEventKind::End { incarnation: 0 },
                },
            ],
            "resolved branch lifecycle continues the inherited incarnation instead of duplicating Start(0)"
        );
        assert_eq!(bundle.timelines[1].lifecycle[0].order, 2);
        assert_eq!(
            bundle.timelines[1].lifecycle[0].kind,
            LifecycleEventKind::Start { incarnation: 0 }
        );
        assert_eq!(bundle.timelines[1].branch_seed, Some(99));
    }

    #[test]
    fn resolved_branch_lifecycle_state_is_validated() {
        let mut main_event = TraceEvent::new(0, operation(), Outcome::U64(10));
        main_event.order = 1;
        let mut branch_event = TraceEvent::new(1, operation(), Outcome::U64(20));
        branch_event.order = 3;
        branch_event.incarnation = 1;
        let bundle = TraceBundle {
            format_version: TRACE_FORMAT_VERSION,
            metadata: RunMetadata::new(7, "fingerprint", 0, "patina"),
            timelines: vec![
                Timeline {
                    id: MAIN_TIMELINE.into(),
                    parent: None,
                    from_sequence: None,
                    branch_seed: None,
                    lifecycle: vec![
                        LifecycleEvent {
                            order: 0,
                            kind: LifecycleEventKind::Start { incarnation: 0 },
                        },
                        LifecycleEvent {
                            order: 2,
                            kind: LifecycleEventKind::End { incarnation: 0 },
                        },
                    ],
                    decisions: vec![main_event],
                },
                Timeline {
                    id: "branch-1".into(),
                    parent: Some(MAIN_TIMELINE.into()),
                    from_sequence: Some(1),
                    branch_seed: Some(99),
                    lifecycle: vec![
                        LifecycleEvent {
                            order: 2,
                            kind: LifecycleEventKind::Start { incarnation: 1 },
                        },
                        LifecycleEvent {
                            order: 4,
                            kind: LifecycleEventKind::End { incarnation: 1 },
                        },
                    ],
                    decisions: vec![branch_event],
                },
            ],
        };
        let error = bundle.validate().unwrap_err();
        assert!(
            matches!(&error, TraceError::Invalid(message) if message.contains("resolved timeline branch-1 starts incarnation 1 while another incarnation is active")),
            "unexpected error: {error}"
        );
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
        let metadata =
            RunMetadata::new(7, "fingerprint", 0, "patina").with_faults(Some(faults.clone()));
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
            RunMetadata::new(7, "fingerprint", 0, "patina")
                .with_faults(Some(FaultConfigRecord::default())),
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
        let metadata = RunMetadata::new(7, "fingerprint+buggify", 0, "patina")
            .with_buggify(Some(buggify.clone()));
        let bundle = TraceBundle::new(metadata, Vec::new());
        let bytes = bundle.to_bytes().unwrap();
        let reloaded = TraceBundle::from_slice(&bytes).unwrap();
        assert_eq!(reloaded.metadata.buggify, Some(buggify));

        // A trace recorded without buggify keeps the field absent, so an old
        // trace and a buggify-disabled run are indistinguishable (both None).
        let plain = TraceBundle::new(RunMetadata::new(7, "fingerprint", 0, "patina"), Vec::new());
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
                "fingerprint": "fingerprint+buggify",
                "realtime_epoch_nanos": 0,
                "hostname": "patina"
            },
            "timelines": [{
                "id": MAIN_TIMELINE,
                "parent": null,
                "from_sequence": null,
                "branch_seed": null,
                "lifecycle": [
                    {"order": 0, "kind": "start", "incarnation": 0},
                    {"order": 1, "kind": "end", "incarnation": 0}
                ],
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
        let metadata = RunMetadata::new(7, "fingerprint+pct+starve", 0, "patina")
            .with_schedule_policy(Some(policy));
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
        let plain = TraceBundle::new(RunMetadata::new(7, "fingerprint", 0, "patina"), Vec::new());
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
        let metadata =
            RunMetadata::new(7, "fingerprint+swarm", 0, "patina").with_swarm(Some(swarm.clone()));
        let bundle = TraceBundle::new(metadata, Vec::new());
        let bytes = bundle.to_bytes().unwrap();
        let reloaded = TraceBundle::from_slice(&bytes).unwrap();
        assert_eq!(reloaded.metadata.swarm, Some(swarm));

        let plain = TraceBundle::new(RunMetadata::new(7, "fingerprint", 0, "patina"), Vec::new());
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
            RunMetadata::new(7, "fingerprint+swarm", 0, "patina").with_swarm(Some(swarm)),
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
            RunMetadata::new(7, "fingerprint+swarm", 0, "patina").with_swarm(Some(broken)),
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
            RunMetadata::new(7, "fingerprint+swarm", 0, "patina").with_swarm(Some(duplicated)),
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
        let metadata = RunMetadata::new(7, "fingerprint", 0, "patina").with_sud(Some(true));
        let bundle = TraceBundle::new(metadata, Vec::new());
        let text = String::from_utf8(bundle.to_bytes().unwrap()).unwrap();
        assert!(text.contains("\"sud\":true"), "{text}");
        let reloaded = TraceBundle::from_slice(bundle.to_bytes().unwrap().as_slice()).unwrap();
        assert_eq!(reloaded.metadata.sud, Some(true));

        // Every other run (macOS, non-SUD kernel, standalone, pre-SUD trace)
        // records nothing: the field is omitted, so old and new traces are
        // byte-identical.
        let plain = TraceBundle::new(
            RunMetadata::new(7, "fingerprint", 0, "patina").with_sud(None),
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
        let metadata = RunMetadata::new(7, "fingerprint", 0, "patina").with_tsc(Some(true));
        let bundle = TraceBundle::new(metadata, Vec::new());
        let text = String::from_utf8(bundle.to_bytes().unwrap()).unwrap();
        assert!(text.contains("\"tsc\":true"), "{text}");
        let reloaded = TraceBundle::from_slice(bundle.to_bytes().unwrap().as_slice()).unwrap();
        assert_eq!(reloaded.metadata.tsc, Some(true));
        assert_eq!(reloaded.metadata.sud, None);

        // Every run that did not arm it records nothing, so a trace taken before
        // the trap existed stays byte-identical.
        let plain = TraceBundle::new(
            RunMetadata::new(7, "fingerprint", 0, "patina").with_tsc(None),
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
        let metadata =
            RunMetadata::new(7, "fingerprint", 0, "patina").with_guest_argv(Some(argv.clone()));
        let bundle = TraceBundle::new(metadata, Vec::new());
        let bytes = bundle.to_bytes().unwrap();
        let reloaded = TraceBundle::from_slice(&bytes).unwrap();
        assert_eq!(reloaded.metadata.guest_argv, Some(argv));

        // An empty argument list is recorded as `Some([])` and stays distinct
        // from an old trace's absent field: a zero-argument run must reproduce
        // zero arguments on replay, not inherit whatever the command line gives.
        let empty = TraceBundle::new(
            RunMetadata::new(7, "fingerprint", 0, "patina").with_guest_argv(Some(Vec::new())),
            Vec::new(),
        );
        let text = String::from_utf8(empty.to_bytes().unwrap()).unwrap();
        assert!(text.contains("\"guest_argv\":[]"), "{text}");
        let reloaded_empty = TraceBundle::from_slice(empty.to_bytes().unwrap().as_slice()).unwrap();
        assert_eq!(reloaded_empty.metadata.guest_argv, Some(Vec::new()));

        // A trace recorded before argv capture keeps the field absent, so it and
        // the "no arguments recorded" case are distinguishable (None vs Some([])).
        let plain = TraceBundle::new(RunMetadata::new(7, "fingerprint", 0, "patina"), Vec::new());
        let text = String::from_utf8(plain.to_bytes().unwrap()).unwrap();
        assert!(!text.contains("guest_argv"), "{text}");
        let reloaded_plain = TraceBundle::from_slice(plain.to_bytes().unwrap().as_slice()).unwrap();
        assert_eq!(reloaded_plain.metadata.guest_argv, None);
    }

    #[test]
    fn guest_cwd_metadata_round_trips_and_is_additive() {
        let metadata =
            RunMetadata::new(7, "fingerprint", 0, "patina").with_guest_cwd(Some("/work".into()));
        let bundle = TraceBundle::new(metadata, Vec::new());
        let text = String::from_utf8(bundle.to_bytes().unwrap()).unwrap();
        assert!(text.contains("\"guest_cwd\":\"/work\""), "{text}");
        let reloaded = TraceBundle::from_slice(bundle.to_bytes().unwrap().as_slice()).unwrap();
        assert_eq!(reloaded.metadata.guest_cwd.as_deref(), Some("/work"));

        let plain = TraceBundle::new(RunMetadata::new(7, "fingerprint", 0, "patina"), Vec::new());
        let text = String::from_utf8(plain.to_bytes().unwrap()).unwrap();
        assert!(!text.contains("guest_cwd"), "{text}");
        let reloaded_plain = TraceBundle::from_slice(plain.to_bytes().unwrap().as_slice()).unwrap();
        assert_eq!(reloaded_plain.metadata.guest_cwd, None);
    }

    #[test]
    fn guest_env_metadata_round_trips_and_is_additive() {
        let env = BTreeMap::from([("RUST_LOG".to_string(), "debug".to_string())]);
        let metadata =
            RunMetadata::new(7, "fingerprint", 0, "patina").with_guest_env(Some(env.clone()));
        let bundle = TraceBundle::new(metadata, Vec::new());
        let text = String::from_utf8(bundle.to_bytes().unwrap()).unwrap();
        assert!(text.contains("\"guest_env\":{"), "{text}");
        assert!(text.contains("\"RUST_LOG\":\"debug\""), "{text}");
        let reloaded = TraceBundle::from_slice(bundle.to_bytes().unwrap().as_slice()).unwrap();
        assert_eq!(reloaded.metadata.guest_env, Some(env));

        let plain = TraceBundle::new(RunMetadata::new(7, "fingerprint", 0, "patina"), Vec::new());
        let text = String::from_utf8(plain.to_bytes().unwrap()).unwrap();
        assert!(!text.contains("guest_env"), "{text}");
        let reloaded_plain = TraceBundle::from_slice(plain.to_bytes().unwrap().as_slice()).unwrap();
        assert_eq!(reloaded_plain.metadata.guest_env, None);
    }

    #[test]
    fn recorder_stamps_its_incarnation_on_every_event_and_marker() {
        let mut recorder =
            Recorder::new(RunMetadata::new(7, "fingerprint", 0, "patina")).with_incarnation(1);
        recorder.observe(operation(), Outcome::U64(0));
        let bundle = recorder.into_bundle().unwrap();
        let main = &bundle.timelines[0];
        assert_eq!(main.decisions[0].incarnation, 1);
        assert_eq!(
            main.lifecycle[0].kind,
            LifecycleEventKind::Start { incarnation: 1 }
        );
        assert_eq!(
            main.lifecycle[1].kind,
            LifecycleEventKind::End { incarnation: 1 }
        );
    }

    #[test]
    fn sha256_digest_text_round_trips() {
        let digest = Sha256Digest([0xab; 32]);
        let text = digest.to_string();
        assert_eq!(text, format!("sha256:{}", "ab".repeat(32)));
        assert_eq!(Sha256Digest::parse(&text).unwrap(), digest);
    }

    #[test]
    fn sha256_digest_refuses_uppercase_hex() {
        let text = format!("sha256:{}", "AB".repeat(32));
        assert!(Sha256Digest::parse(&text).is_err());
    }

    #[test]
    fn lifecycle_models_crash_restart_with_global_order() {
        let digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let bundle = TraceBundle {
            format_version: TRACE_FORMAT_VERSION,
            metadata: RunMetadata::new(7, "fingerprint+crash-restart", 0, "patina"),
            timelines: vec![Timeline {
                id: MAIN_TIMELINE.into(),
                parent: None,
                from_sequence: None,
                branch_seed: None,
                lifecycle: vec![
                    LifecycleEvent {
                        order: 0,
                        kind: LifecycleEventKind::Start { incarnation: 0 },
                    },
                    LifecycleEvent {
                        order: 2,
                        kind: LifecycleEventKind::Crash {
                            incarnation: 0,
                            snapshot_digest: digest.into(),
                        },
                    },
                    LifecycleEvent {
                        order: 3,
                        kind: LifecycleEventKind::Restart {
                            from_incarnation: 0,
                            to_incarnation: 1,
                            snapshot_digest: digest.into(),
                        },
                    },
                    LifecycleEvent {
                        order: 4,
                        kind: LifecycleEventKind::Start { incarnation: 1 },
                    },
                    LifecycleEvent {
                        order: 6,
                        kind: LifecycleEventKind::End { incarnation: 1 },
                    },
                ],
                decisions: vec![
                    TraceEvent {
                        sequence: 0,
                        order: 1,
                        incarnation: 0,
                        operation: Operation::FsWrite {
                            fd: Fd(3),
                            bytes: b"trigger".to_vec(),
                        },
                        outcome: Outcome::Usize(7),
                    },
                    TraceEvent {
                        sequence: 1,
                        order: 5,
                        incarnation: 1,
                        operation: operation(),
                        outcome: Outcome::U64(11),
                    },
                ],
            }],
        };
        bundle.validate().unwrap();
        let bytes = bundle.to_bytes().unwrap();
        let reloaded = TraceBundle::from_slice(&bytes).unwrap();
        assert_eq!(reloaded, bundle);
        assert_eq!(
            reloaded.to_bytes().unwrap(),
            bytes,
            "v5 lifecycle encoding is canonical"
        );
    }

    #[test]
    fn lifecycle_ordering_and_incarnation_mismatches_are_refused() {
        let mut bundle = TraceBundle::new(
            RunMetadata::new(1, "fingerprint", 0, "patina"),
            vec![TraceEvent::new(0, operation(), Outcome::U64(0))],
        );
        bundle.timelines[0].decisions[0].order = 0;
        let error = bundle.validate().unwrap_err();
        assert!(
            error.to_string().contains("reuses global order"),
            "duplicate lifecycle/operation order must be named: {error}"
        );

        let mut bundle = TraceBundle::new(
            RunMetadata::new(1, "fingerprint", 0, "patina"),
            vec![TraceEvent::new(0, operation(), Outcome::U64(0))],
        );
        bundle.timelines[0].decisions[0].incarnation = 1;
        let error = bundle.validate().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("declares incarnation 1, expected 0"),
            "incarnation/lifecycle mismatch must be named: {error}"
        );
    }

    #[test]
    fn lifecycle_missing_crash_digest_mismatch_and_unended_states_are_refused() {
        let digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let other = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let mut bundle = crash_restart_bundle(digest);
        bundle.timelines[0].lifecycle[1].kind = LifecycleEventKind::End { incarnation: 0 };
        let error = bundle.validate().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Restart without a preceding Crash"),
            "missing crash must be named: {error}"
        );

        let mut bundle = crash_restart_bundle(digest);
        if let LifecycleEventKind::Restart {
            snapshot_digest, ..
        } = &mut bundle.timelines[0].lifecycle[2].kind
        {
            *snapshot_digest = other.into();
        }
        let error = bundle.validate().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Restart does not match preceding Crash"),
            "digest mismatch must be named: {error}"
        );

        let mut bundle = crash_restart_bundle(digest);
        bundle.timelines[0].lifecycle.pop();
        let error = bundle.validate().unwrap_err();
        assert!(
            error.to_string().contains("lifecycle does not end cleanly"),
            "unended lifecycle must be named: {error}"
        );
    }

    fn crash_restart_bundle(digest: &str) -> TraceBundle {
        TraceBundle {
            format_version: TRACE_FORMAT_VERSION,
            metadata: RunMetadata::new(7, "fingerprint+crash-restart", 0, "patina"),
            timelines: vec![Timeline {
                id: MAIN_TIMELINE.into(),
                parent: None,
                from_sequence: None,
                branch_seed: None,
                lifecycle: vec![
                    LifecycleEvent {
                        order: 0,
                        kind: LifecycleEventKind::Start { incarnation: 0 },
                    },
                    LifecycleEvent {
                        order: 2,
                        kind: LifecycleEventKind::Crash {
                            incarnation: 0,
                            snapshot_digest: digest.into(),
                        },
                    },
                    LifecycleEvent {
                        order: 3,
                        kind: LifecycleEventKind::Restart {
                            from_incarnation: 0,
                            to_incarnation: 1,
                            snapshot_digest: digest.into(),
                        },
                    },
                    LifecycleEvent {
                        order: 4,
                        kind: LifecycleEventKind::Start { incarnation: 1 },
                    },
                    LifecycleEvent {
                        order: 6,
                        kind: LifecycleEventKind::End { incarnation: 1 },
                    },
                ],
                decisions: vec![
                    TraceEvent {
                        sequence: 0,
                        order: 1,
                        incarnation: 0,
                        operation: Operation::FsWrite {
                            fd: Fd(3),
                            bytes: b"trigger".to_vec(),
                        },
                        outcome: Outcome::Usize(7),
                    },
                    TraceEvent {
                        sequence: 1,
                        order: 5,
                        incarnation: 1,
                        operation: operation(),
                        outcome: Outcome::U64(11),
                    },
                ],
            }],
        }
    }

    #[test]
    fn rejects_non_contiguous_sequences() {
        let mut bundle = TraceBundle::new(
            RunMetadata::new(1, "fingerprint", 0, "patina"),
            vec![TraceEvent::new(4, operation(), Outcome::U64(0))],
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
        fs::write(&truncated, b"{\"format_version\":12,").unwrap();
        let error = TraceBundle::load(&truncated).unwrap_err();
        assert!(
            matches!(&error, TraceError::Incomplete { reason, .. } if reason.contains("truncated JSON")),
            "unexpected error: {error}"
        );

        let incomplete_metadata = directory.path().join("incomplete-metadata.patina");
        fs::write(
            &incomplete_metadata,
            br#"{"format_version":12,"metadata":{"root_seed":1,"decision_policy":"splitmix64-v1"},"timelines":[]}"#,
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
        let mut bundle =
            TraceBundle::new(RunMetadata::new(1, "fingerprint", 0, "patina"), Vec::new());
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
            Err(TraceError::ResourceLimit { .. })
        ));
    }

    /// A budget refusal must be distinguishable from a broken trace WITHOUT
    /// string matching, and must carry the two numbers a diagnostic reports.
    /// The native shim keeps a run's verdict on the budget refusal and aborts
    /// on every other one, so this is the seam that decision rests on.
    #[test]
    fn a_budget_refusal_is_classifiable_and_carries_its_numbers() {
        let bundle = TraceBundle::new(RunMetadata::new(7, "fingerprint", 0, "patina"), Vec::new());
        let serialized_len = bundle.to_bytes().unwrap().len() as u64;
        let limit = serialized_len - 1;

        let error = bundle.to_bytes_with_limit(limit).unwrap_err();
        assert!(error.is_resource_limit(), "unexpected error: {error}");
        assert_eq!(error.resource_limit_bytes(), Some((serialized_len, limit)));

        let mut oversized =
            TraceBundle::new(RunMetadata::new(7, "fingerprint", 0, "patina"), Vec::new());
        oversized.timelines[0].decisions =
            vec![TraceEvent::new(0, operation(), Outcome::U64(0)); MAX_TIMELINE_EVENTS + 1];
        let error = oversized.validate().unwrap_err();
        assert!(error.is_resource_limit(), "unexpected error: {error}");
        assert_eq!(
            error.resource_limit_bytes(),
            None,
            "an event-count budget has no byte figures to report"
        );

        let broken = TraceError::Invalid("something is wrong".into());
        assert!(!broken.is_resource_limit());
    }

    /// The recorder-memory fix. A recording that outgrows its byte budget must
    /// stop HOLDING events at the event that crosses it, rather than discover
    /// the overflow at finalization with the whole run resident — the shape
    /// that cost ~1.9 GB of RSS per long generation and lost the trace anyway.
    ///
    /// Three things are pinned: the memory really is bounded (the held events
    /// never exceed the budget by more than the single event that crossed it,
    /// and are released outright at the crossing); the crossing is a pure
    /// function of the event stream, so a run that abandons abandons at the
    /// same event every time; and the refusal is still the SAME graceful budget
    /// error, carrying its figures and writing no file, so the shim's shutdown
    /// downgrade keeps the guest's own verdict exactly as before.
    #[test]
    fn an_over_budget_recording_stops_holding_events_and_still_refuses() {
        let limit = 64 * 1024;
        let payload = vec![b'p'; 512];
        let widest = serialized_event_len(&TraceEvent::new(
            u64::MAX,
            operation(),
            Outcome::Bytes(payload.clone()),
        ))
        .unwrap()
            + 1;

        let record = || {
            let mut recorder =
                Recorder::with_limit(RunMetadata::new(7, "fingerprint", 0, "patina"), limit);
            let mut crossed_at = None;
            for index in 0..4_096u64 {
                recorder.observe(operation(), Outcome::Bytes(payload.clone()));
                assert!(
                    recorder.ledger.bytes <= limit + widest,
                    "held events must never exceed the budget by more than the event that \
                     crossed it; {} bytes after event {index}",
                    recorder.ledger.bytes
                );
                if recorder.ledger.overflowed() && crossed_at.is_none() {
                    crossed_at = Some(index);
                }
                if crossed_at.is_some() {
                    assert!(
                        recorder.decisions.is_empty() && recorder.decisions.capacity() == 0,
                        "an abandoned recorder must hold nothing, and keep holding nothing"
                    );
                }
            }
            (crossed_at.expect("the budget must be crossed"), recorder)
        };

        let (crossing, recorder) = record();
        let (crossing_again, _) = record();
        assert_eq!(
            crossing, crossing_again,
            "the abandon point must be a function of the recorded events alone"
        );
        assert!(
            crossing > 0 && crossing < 4_096,
            "the crossing must land inside the run; got {crossing}"
        );

        let held = recorder.ledger.bytes;
        assert!(held > limit && held <= limit + widest);
        let directory = tempdir().unwrap();
        let path = directory.path().join("abandoned.patina");
        let error = recorder.finish(&path).unwrap_err();
        assert!(
            error.is_resource_limit(),
            "the shutdown downgrade keys off this predicate; got {error}"
        );
        assert_eq!(error.resource_limit_bytes(), Some((held, limit)));
        assert!(!path.exists(), "an abandoned trace must write no file");
        assert_eq!(
            fs::read_dir(directory.path()).unwrap().count(),
            0,
            "an abandoned trace must not leave a temporary file either"
        );
        // The refusal is the one the graceful path already knows how to report.
        assert_eq!(
            parse_abandoned_trace_marker(&abandoned_trace_marker(
                "resource-limit",
                &error.to_string()
            ))
            .unwrap()
            .reason,
            "resource-limit"
        );
        assert!(resource_limit_infra_line(&error).starts_with(&format!(
            "PATINA_INFRA trace=incomplete reason=resource-limit bytes={held} limit={limit}"
        )));
    }

    /// The event-count budget bounds memory the same way, for a run whose
    /// events are too small to reach the byte budget first.
    #[test]
    fn an_over_long_recording_is_abandoned_at_the_event_budget() {
        let mut recorder = Recorder::with_limits(
            RunMetadata::new(7, "fingerprint", 0, "patina"),
            MAX_TRACE_BYTES,
            8,
        );
        for index in 0..64u64 {
            recorder.observe(operation(), Outcome::U64(index));
            assert!(recorder.decisions.len() <= 8);
        }
        assert!(recorder.decisions.is_empty());
        let error = recorder.into_bundle().unwrap_err();
        assert!(error.is_resource_limit(), "unexpected error: {error}");
        assert_eq!(
            error.resource_limit_bytes(),
            None,
            "an event-count budget has no byte figures to report"
        );
        assert!(
            error.to_string().contains("reached 9 events"),
            "the refusal must name the count that crossed the budget; got {error}"
        );
    }

    /// The other half of the bargain: a recording that FITS its budget is
    /// byte-identical to the bundle built straight from its events, and the
    /// ledger that watched it is an exact tally of those events and a strict
    /// under-estimate of the whole file — which is why it can never abandon a
    /// recording that would have fit.
    #[test]
    fn an_under_budget_recording_is_byte_identical_and_exactly_tallied() {
        let mut recorder = Recorder::new(RunMetadata::new(7, "fingerprint", 0, "patina"));
        let mut events = Vec::new();
        for index in 0..64u64 {
            let outcome = Outcome::Bytes(vec![index as u8; index as usize]);
            recorder.observe(operation(), outcome.clone());
            events.push(TraceEvent::new(index, operation(), outcome));
        }

        let tallied = recorder.ledger.bytes;
        let expected: u64 = events
            .iter()
            .map(|event| serde_json::to_vec(event).unwrap().len() as u64)
            .sum::<u64>()
            + events.len() as u64
            - 1;
        assert_eq!(tallied, expected, "the ledger must tally events exactly");

        let bundle = TraceBundle::new(RunMetadata::new(7, "fingerprint", 0, "patina"), events);
        let expected_bytes = bundle.to_bytes().unwrap();
        assert!(
            tallied < expected_bytes.len() as u64,
            "the tally must stay under the size of the file it bounds"
        );
        assert_eq!(
            recorder.into_bundle().unwrap().to_bytes().unwrap(),
            expected_bytes,
            "a trace under budget must be byte-identical to one recorded without a ledger"
        );
    }

    /// An abandoned trace must never be replayable as if it were a recording.
    /// The marker is what a reader sees in place of a bundle, so loading one
    /// has to refuse by NAME — "the recorder abandoned this trace" — rather
    /// than as an unexplained parse failure.
    #[test]
    fn an_abandoned_trace_marker_is_refused_by_name() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("abandoned.patina");
        let marker = abandoned_trace_marker(
            "resource-limit",
            "serialized trace is 999 bytes; limit is 100",
        );
        assert_eq!(
            parse_abandoned_trace_marker(&marker),
            Some(AbandonedTrace {
                reason: "resource-limit".into(),
                detail: "serialized trace is 999 bytes; limit is 100".into(),
            })
        );
        fs::write(&path, &marker).unwrap();

        let error = TraceBundle::load(&path).unwrap_err();
        let message = error.to_string();
        assert!(
            matches!(&error, TraceError::Incomplete { .. })
                && message.contains("abandoned this trace")
                && message.contains("resource-limit")
                && message.contains("cannot be replayed"),
            "an abandoned trace must be refused by name; got {message}"
        );
        assert!(
            TraceBundle::from_slice(&marker).is_err(),
            "the transport path must refuse a marker too"
        );

        // A real bundle is never mistaken for a marker.
        let bundle = TraceBundle::new(RunMetadata::new(7, "fingerprint", 0, "patina"), Vec::new());
        assert_eq!(
            parse_abandoned_trace_marker(&bundle.to_bytes().unwrap()),
            None
        );
    }
}
