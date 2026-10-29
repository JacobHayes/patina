//! Machine-readable result envelopes (`--format json`), timeline rendering
//! (`--render`), and per-failure reports (`--report`) for the CLI verbs.
//!
//! These are cross-cutting *output* concerns, orthogonal to a run's semantics.
//! To keep the hook-in edits in `lib.rs` small and additive (so concurrent work
//! on the runtime/CLI merges cleanly), the parsed options live in a set-once
//! process global rather than being threaded through every invocation struct and
//! `execute_*` signature. `entrypoint` strips the flags from the argument vector
//! once and installs the options; the verbs read them here.

use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::sync::OnceLock;

use sha2::{Digest, Sha256};

use crate::help::{self, Flag};
use crate::render::{self, FailureSummary};
use crate::{CliError, exit_code};

mod capture;
mod envelope;
mod markers;
mod outcomes;
mod reports;

pub use capture::Captured;
pub use capture::capture_active;
pub use capture::end_guest_line;
pub use capture::execute_command;
pub use capture::facts_active;
pub use capture::json_active;
pub use capture::parse_facts;
pub use envelope::CRASH_REPLAY_DIVERGED;
pub use envelope::Envelope;
use markers::result_line;
pub use outcomes::GuestExit;
pub use outcomes::Refusal;
use outcomes::SIGNAL_NAMES;
use outcomes::refusal;
pub use reports::CoverageReport;
pub use reports::Qualification;
pub use reports::RunReport;
pub(crate) use reports::TraceFacts;
pub use reports::finalize_run;

/// The stable schema identifier stamped into every JSON envelope. Bump the
/// version suffix only on a breaking change to the documented shape.
pub const ENVELOPE_SCHEMA: &str = "patina.result/v1";

/// How the CLI presents its result.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OutputFormat {
    /// Human passthrough (default): guest output streams unchanged, verbs print
    /// their existing markers.
    #[default]
    Human,
    /// A single JSON result envelope on stdout ([`ENVELOPE_SCHEMA`]).
    Json,
}

/// Parsed cross-cutting output options for one invocation.
#[derive(Clone, Debug, Default)]
pub struct OutputOptions {
    pub format: OutputFormat,
    /// `--render PATH`: always write the timeline HTML for a run/replay that has
    /// a trace (record or replay mode).
    pub render: Option<PathBuf>,
    /// `--report PATH`: write the timeline HTML *only when the run failed*, with a
    /// prominent failure-summary section.
    pub report: Option<PathBuf>,
}

impl OutputOptions {
    /// Whether the guest's stdout/stderr must be captured rather than inherited.
    /// Capture is needed to build a JSON envelope, and to populate a render/report
    /// failure summary. When false the human default (inherited streaming) holds.
    pub fn wants_capture(&self) -> bool {
        self.format == OutputFormat::Json || self.render.is_some() || self.report.is_some()
    }

    pub fn is_json(&self) -> bool {
        self.format == OutputFormat::Json
    }
}

static OPTIONS: OnceLock<OutputOptions> = OnceLock::new();

/// When set, per-run finalization (capture, envelope, render) is suppressed.
/// `explore` sets this so its per-seed child runs stream normally and it emits a
/// single campaign-level envelope of its own instead of one per seed.
static SUPPRESS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Suppress per-run finalization for the remainder of the process (used by
/// `explore`, which drives many child runs and reports once).
pub fn suppress_run_finalize() {
    SUPPRESS.store(true, std::sync::atomic::Ordering::SeqCst);
}

fn suppressed() -> bool {
    SUPPRESS.load(std::sync::atomic::Ordering::SeqCst)
}

/// Install the parsed options once, at the top of `entrypoint`. A second call is
/// ignored (the first install wins); unit tests that never install get defaults.
pub fn install(options: OutputOptions) {
    let _ = OPTIONS.set(options);
}

/// The installed options, or defaults (Human, no render/report) if none were set.
pub fn options() -> &'static OutputOptions {
    OPTIONS.get_or_init(OutputOptions::default)
}

/// Strip the global output flags from the leading (pre-`--`) region of
/// an argument list, returning the parsed options and the remaining arguments.
/// Flags after a `--` separator are left in place — there they belong to the
/// guest program, not Patina.
///
/// These are parsed once, globally, before any per-verb routing, because they
/// decide how the CLI reports whatever the verb goes on to do. Arity comes from
/// the same registry rows that document them (`help::GLOBAL_OUTPUT`).
pub fn extract(arguments: Vec<OsString>) -> Result<(OutputOptions, Vec<OsString>), CliError> {
    let flags: Vec<&'static Flag> = help::GLOBAL_OUTPUT.iter().collect();
    let (found, rest) = crate::cli::strip(&flags, arguments)?;
    // A typed flag wins; otherwise its `PATINA_<FLAG>` default applies.
    let value = |name: &str| -> Result<Option<OsString>, CliError> {
        match crate::cli::single(&found, name)? {
            Some(value) => Ok(Some(value)),
            None => crate::cli::env_value(
                flags
                    .iter()
                    .copied()
                    .find(|flag| flag.name == name)
                    .expect("global output flag"),
            ),
        }
    };
    let mut options = OutputOptions::default();
    if let Some(format) = value("--format")? {
        options.format = parse_format(&format.to_string_lossy())?;
    }
    options.render = value("--render")?.map(PathBuf::from);
    options.report = value("--report")?.map(PathBuf::from);
    Ok((options, rest))
}

fn parse_format(value: &str) -> Result<OutputFormat, CliError> {
    match value {
        "human" => Ok(OutputFormat::Human),
        "json" => Ok(OutputFormat::Json),
        other => Err(CliError::usage(format!(
            "--format must be human or json; got {other:?}"
        ))),
    }
}

/// Emit a verb's envelope for the audit path: the findings are the flagged
/// imports.
pub fn emit_audit(
    verb: &str,
    family: &str,
    artifact: &str,
    findings: Vec<String>,
    finding_details: Vec<serde_json::Value>,
    exit_code: i32,
) {
    if !options().is_json() {
        return;
    }
    let result = if exit_code == 0 { "ok" } else { "violation" };
    let mut env = Envelope::new(verb, result, exit_code);
    env.family = Some(family.to_string());
    env.artifact = Some(artifact.to_string());
    env.findings = findings;
    env.finding_details = finding_details;
    env.emit();
}

/// Emit a verb's envelope for the build path, hashing the produced artifact.
pub fn emit_build(family: &str, output_path: &Path) {
    if !options().is_json() {
        return;
    }
    let mut env = Envelope::new("build", "ok", 0);
    env.family = Some(family.to_string());
    env.output_path = Some(output_path.to_string_lossy().into_owned());
    if let Ok(bytes) = std::fs::read(output_path) {
        // digest 0.11's output array no longer implements LowerHex; encode bytes.
        let hash: String = Sha256::digest(&bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        env.content_hash = Some(format!("sha256:{hash}"));
    }
    env.emit();
}

/// Emit a generic envelope for a verb that produced no rich structured result
/// (explore/minimize), or for a CLI error surfaced under `--output json`.
pub fn emit_simple(verb: &str, result: &str, exit_code: i32, message: Option<String>) {
    if !options().is_json() {
        return;
    }
    let mut env = Envelope::new(verb, result, exit_code);
    env.message = message;
    env.emit();
}

/// This class is emitted only by the native audit gate, before guest launch.
pub(crate) const NATIVE_PRERUN_REFUSAL: &str = "native_prerun_audit";

/// The class of a replay refused because the trace belongs to another build.
/// The native supervisor emits it before guest launch; the same class names a
/// runtime's own fingerprint refusal read off a dying child's output.
pub(crate) const FINGERPRINT_MISMATCH_REFUSAL: &str = "fingerprint_mismatch";

/// Emit the envelope of a native run the supervisor refused before the guest
/// started, so no `guest_exit` exists.
pub(crate) fn emit_native_refusal(artifact: &Path, class: &str, message: String) {
    emit_native_mismatch_refusal(artifact, class, message, None);
}

/// [`emit_native_refusal`] of a mismatch the supervisor judged, naming which
/// input differs (`refusal.mismatch`) when it knows.
pub(crate) fn emit_native_mismatch_refusal(
    artifact: &Path,
    class: &str,
    message: String,
    mismatch: Option<&'static str>,
) {
    let mut env = Envelope::new("run", "error", 2);
    env.family = Some("native".into());
    env.artifact = Some(artifact.to_string_lossy().into_owned());
    env.refusal = Some(Refusal {
        class: class.into(),
        message: message.clone(),
        guest_exit_code: None,
        mismatch,
    });
    env.message = Some(message);
    env.emit();
}

pub(crate) fn emit_harness_result(
    result: &str,
    exit_code: i32,
    message: String,
    trace: Option<TraceFacts>,
) {
    if !options().is_json() {
        return;
    }
    let mut env = Envelope::new("test", result, exit_code);
    env.message = Some(message);
    env.trace = trace;
    env.emit();
}

#[cfg(test)]
mod tests;
