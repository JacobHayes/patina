//! Guest verdicts, exits, refusals, and marker recognition.

use super::*;

/// One verdict the run reported through the verdict ABI, for the envelope's
/// `verdicts[]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerdictFact {
    pub seq: u64,
    pub kind: VerdictKind,
    pub label: String,
    pub detail: String,
}

/// Collect the run's `PATINA_VERDICT` lines into structured verdicts, in the
/// order the guest reported them.
///
/// The trace carries the same stream as `Operation::Verdict` events, but a plain
/// seeded run writes no trace and an aborting guest never finalizes one, so the
/// marker line is the channel that always exists. Decoding uses the ABI crate's
/// codec, the same one the runtime renders with, and a malformed line is dropped
/// rather than half-decoded into a verdict that would read as real.
pub(super) fn extract_verdicts(stdout: &str, stderr: &str) -> Vec<VerdictFact> {
    stdout
        .lines()
        .chain(stderr.lines())
        .filter(|line| line.trim_start().starts_with(verdict_line::PREFIX))
        .filter_map(|line| {
            let (seq, kind, label, detail) = verdict_line::parse(line)?;
            Some(VerdictFact {
                seq,
                kind,
                label,
                detail,
            })
        })
        .collect()
}

/// How the guest process ended, structurally. `code` is the process exit status
/// the CLI itself returns; `signal` is present only when the guest died on a
/// signal, which `code` alone cannot express (it is `128 + signal` there, the
/// same value a guest could have returned deliberately).
pub struct GuestExit {
    pub(super) code: i32,
    pub(super) signal: Option<i32>,
    pub(super) core: bool,
}

/// The portable signal names worth spelling out. A signal outside this set keeps
/// its number and gets no name — a wrong name is worse than none.
pub(super) const SIGNAL_NAMES: &[(i32, &str)] = &[
    (2, "SIGINT"),
    (4, "SIGILL"),
    (5, "SIGTRAP"),
    (6, "SIGABRT"),
    (8, "SIGFPE"),
    (9, "SIGKILL"),
    (11, "SIGSEGV"),
    (13, "SIGPIPE"),
    (15, "SIGTERM"),
];

/// Patina's own fail-closed refusals, keyed by the text each one already prints.
///
/// This is the historical fail-closed marker taxonomy made *attributable*:
/// instead of one undifferentiated "something failed closed" bucket, each refusal
/// carries a stable class and the line that announced it. Ordered most specific
/// first — the first match wins.
///
/// Only refusals belong here — cases where PATINA declined to run or continue.
/// A *consequence* of the guest dying (notably an incomplete recorded trace,
/// which every guest that aborts mid-record leaves behind) is not a refusal: the
/// absence of a refusal is what attributes an abort to the guest, so a
/// consequence listed here would attribute every guest abort to patina and make
/// `GUEST_ABORT` unreachable.
const REFUSAL_CLASSES: &[(&str, &str)] = &[
    ("PATINA_BUGGIFY_DUPLICATE_LABEL", "buggify_duplicate_label"),
    (
        "PATINA_BUGGIFY_SETUP_NEVER_CALLED",
        "buggify_setup_never_called",
    ),
    ("fingerprint mismatch", "fingerprint_mismatch"),
    ("trace operation mismatch", "trace_operation_mismatch"),
    ("operation mismatch", "trace_operation_mismatch"),
    (
        "the deterministic runtime failed to initialize",
        "runtime_init_failure",
    ),
    ("must run under `cargo patina run`", "no_runtime_installed"),
    (
        "harness has not installed the runtime yet",
        "harness_before_install",
    ),
    (
        "interposed call before deterministic runtime initialization",
        "preinit_interposed_call",
    ),
    ("patina native shim fatal:", "shim_fatal"),
    ("unsupported-import", "unsupported_import"),
    ("unknown-import", "unknown_import"),
    ("patina: starvation stall", "starvation_stall"),
    // Patina's OWN recorder gave out at the end of the run — the trace resource
    // limit exceeded, the trace file unwritable — and the shim `abort()`s. The
    // guest is then killed by a SIGABRT it did not raise, which without this
    // entry surfaces as an unattributed GUEST abort: a bug reported against the
    // system under test for a failure inside patina, whose reproduce command
    // does not even reproduce it (the abort needs the recording that the
    // reproduce command omits).
    ("patina: runtime shutdown failed", "shutdown_failure"),
    // The trace CHANNEL failed under a run that otherwise completed: the
    // recorder's scratch file could not be opened, read, or renamed. Unlike the
    // truncated trace a dying guest leaves — which is a consequence of the run
    // and is deliberately NOT in this table — nothing about the guest went
    // wrong here, so the supervisor states it as its own refusal, with the
    // guest's status attached. That is what lets a whole campaign's worth of
    // them collapse onto one INFRA signature instead of one finding each.
    (crate::TRACE_CHANNEL_UNAVAILABLE, "trace_unavailable"),
];

/// Patina's own refusal for this run, or `None` when patina did not fail closed.
///
/// A clean exit is never a refusal, and neither is a nonzero exit that matched no
/// class — the absence is the whole point: an abort with no refusal record is the
/// *guest's* own doing, not patina's.
pub(super) fn refusal(exit_code: i32, stdout: &str, stderr: &str) -> Option<Refusal> {
    if exit_code == 0 {
        return None;
    }
    let lines: Vec<&str> = stdout.lines().chain(stderr.lines()).collect();
    REFUSAL_CLASSES.iter().find_map(|(needle, class)| {
        let line = lines.iter().find(|line| line.contains(needle))?;
        Some(Refusal {
            class: (*class).to_string(),
            message: line.trim().to_string(),
            guest_exit_code: guest_exit_code(line),
        })
    })
}

/// The guest's own exit status, when the refusal line names it.
///
/// Only the shim's shutdown-failure line carries `guest_exit_code=`; it is
/// written there because that refusal `abort()`s the process, so the status the
/// GUEST reached is otherwise destroyed. Parsed structurally here — once, at the
/// envelope boundary — so the campaign classifier keeps deciding on fields
/// rather than on text.
pub(super) fn guest_exit_code(line: &str) -> Option<i32> {
    line.split_whitespace()
        .find_map(|token| token.strip_prefix("guest_exit_code="))
        .and_then(|value| value.parse().ok())
}

/// A patina fail-closed refusal: which class, the line that announced it, and —
/// when the refusal destroyed the guest's own exit status by aborting — what
/// that status was.
pub struct Refusal {
    pub(super) class: String,
    pub(super) message: String,
    pub(super) guest_exit_code: Option<i32>,
}

/// Known structured marker prefixes **patina itself** emits, worth surfacing
/// verbatim in the envelope and failure report.
///
/// Patina's own prefixes only: core patina is guest-agnostic, so a guest's
/// private marker dialect never appears here. A guest that wants its markers
/// classified declares them in its campaign spec (`classify.patterns`); a guest
/// that wants them structured calls the verdict ABI, and they surface in
/// `verdicts[]`.
const MARKER_PREFIXES: &[&str] = &[
    "PATINA_RESULT",
    "PATINA_VIOLATION",
    "PATINA_SCHEDULE_REPORT",
    "PATINA_COVERAGE_REPORT",
    "PATINA_COVERAGE",
    "PATINA_DEPTH_REPORT",
    "PATINA_SDK_REPORT",
    "PATINA_SWARM_REPORT",
    "PATINA_LIVENESS_REPORT",
    "PATINA_INFRA",
    "PATINA_VERDICT",
    "PATINA_BUGGIFY_DUPLICATE_LABEL",
    "PATINA_BUGGIFY_SETUP_NEVER_CALLED",
];

pub(super) fn extract_markers(stdout: &str, stderr: &str) -> Vec<String> {
    let mut markers = Vec::new();
    for line in stdout.lines().chain(stderr.lines()) {
        let trimmed = line.trim();
        if MARKER_PREFIXES.iter().any(|p| trimmed.starts_with(p))
            || trimmed.contains("trace operation mismatch")
            || trimmed.contains("fingerprint mismatch")
        {
            markers.push(trimmed.to_string());
        }
    }
    markers
}

#[cfg(test)]
mod tests;
