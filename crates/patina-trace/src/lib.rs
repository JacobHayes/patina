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

use std::fmt;
use std::path::PathBuf;

use patina_dst_abi::{Operation, Outcome};
use serde::{Deserialize, Serialize};

mod branch;
mod bundle;
mod crash_restart;
mod digest;
mod file_lock;
mod handoff;
mod lifecycle;
mod metadata;
mod recorder;
mod replay;

pub use branch::BranchSession;
pub use bundle::{Timeline, TraceBundle, TraceEvent};
pub use crash_restart::CrashRestartSegments;
pub use digest::Sha256Digest;
pub use file_lock::{create_scratch, lock_exclusive, lock_shared, path_names, remove_dead_scratch};
pub use handoff::{
    HandoffConsumedState, HandoffError, HandoffSealKey, IncarnationHandoff,
    MAX_HANDOFF_PAYLOAD_BYTES, VerifiedIncarnationHandoff,
};
pub use lifecycle::{LifecycleEvent, LifecycleEventKind};
pub use metadata::{
    BuggifyConfigRecord, ComputeStop, CrashPointRecord, DnsConfigRecord, FaultConfigRecord,
    FaultCrashOp, PctPolicyRecord, RunMetadata, SchedulePolicyRecord, StarvationPolicyRecord,
    SwarmConfigRecord, TornGranularity, WatchdogConfigRecord,
};
pub use recorder::{PrefixWriteError, Recorder};
pub use replay::Replayer;

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
/// - 13: the inode of every directory-listing entry, and the `.` and `..` a
///   descriptor listing starts with; `fs_fd_ino`, the inode an open descriptor
///   names, which record and `flock` locks key on; signed timestamps: every
///   metadata outcome's and set-times operation's nanoseconds may be negative
///   (before the epoch) or past what 64 bits hold (up to the volume's range).
/// - 14: the allocated `blocks` on every metadata outcome; `fs_seek`'s `data`
///   and `hole` whences (`SEEK_DATA`/`SEEK_HOLE`) and the `no_such_position`
///   error; `fs_allocate`'s `mode` (`reserve`, `punch_hole`, `zero_range`) in
///   place of its `zero` flag.
/// - 15: required boot origin (machine uptime at guest start).
/// - 16: timed parks expire at registration and at every clock advance, not
///   only when every task has parked: a past or reached deadline records its
///   `task_wake` where earlier formats recorded none. No field changed; the
///   events a run records did.
/// - 17: the required [`RunMetadata::time_model`]; a bundle recorded under
///   another time model is refused ([`TraceError::UnsupportedTimeModel`]).
pub const TRACE_FORMAT_VERSION: u32 = 17;
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
    /// The bundle was recorded under a virtual-time model other than
    /// [`patina_dst_abi::TIME_MODEL`].
    UnsupportedTimeModel {
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
            Self::UnsupportedTimeModel { found } => write!(
                f,
                "trace was recorded under virtual-time model {found}; this runtime implements model {}, \
                 so the recorded clock and timer behaviour cannot replay; re-record the run",
                patina_dst_abi::TIME_MODEL
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

#[cfg(test)]
mod tests;
