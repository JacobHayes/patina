//! Machine-readable result envelopes (`--format json`), timeline rendering
//! (`--render`) for the CLI verbs.
//!
//! These are cross-cutting *output* concerns, orthogonal to a run's semantics.
//! To keep the hook-in edits in `lib.rs` small and additive (so concurrent work
//! on the runtime/CLI merges cleanly), the parsed options live in a set-once
//! process global rather than being threaded through every invocation struct and
//! `execute_*` signature. `entrypoint` strips the flags from the argument vector
//! once and installs the options; the verbs read them here.

use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use sha2::{Digest, Sha256};

use crate::CliError;
use crate::help::{self, Flag};
use crate::render::{self, FailureSummary};

mod artifacts;
mod capture;
mod envelope;
mod markers;
mod outcomes;
pub mod progress;
mod reports;

pub use artifacts::{describe as describe_artifact, limit_artifact};
pub use capture::Captured;
pub use capture::StopChannel;
pub use capture::capture_active;
pub use capture::end_guest_line;
pub use capture::parse_facts;
pub use capture::parse_stop;
pub use envelope::CRASH_FAILED;
pub use envelope::CRASH_REPLAY_DIVERGED;
pub use envelope::Envelope;
use markers::result_line;
pub use outcomes::GuestExit;
pub(crate) use outcomes::HOST_KILL_STOP;
pub use outcomes::Outcome;
pub(crate) use outcomes::PRERUN_AUDIT_STOP;
use outcomes::SIGNAL_NAMES;
pub use outcomes::Stop;
pub(crate) use outcomes::TRACE_MISMATCH_STOP;
#[cfg(test)]
pub(crate) use outcomes::TRACE_UNAVAILABLE_STOP;
pub(crate) use outcomes::location_json;
use patina_dst_abi::RunClass;
pub use reports::CoverageReport;
pub use reports::Qualification;
pub use reports::RunReport;
pub(crate) use reports::TraceFacts;
pub use reports::TraceIncomplete;
pub use reports::finalize_run;

/// The stable schema identifier stamped into every JSON envelope. Bump the
/// version suffix only on a breaking change to the documented shape.
pub const ENVELOPE_SCHEMA: &str = "patina.result/v2";

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
    /// `--render PATH`: always write the timeline HTML of a run or replay.
    pub render: Option<PathBuf>,
    /// `--verbose`: print Patina's own diagnostics beside the result.
    pub verbose: bool,
    /// `--progress`: under `--format json`, stream [`progress::PROGRESS_SCHEMA`]
    /// lines on stderr while the verb runs.
    pub progress: bool,
    /// The verb the flags were stripped from, which progress lines name.
    pub verb: Option<String>,
}

impl OutputOptions {
    /// Whether the guest's stdout/stderr must be captured rather than inherited.
    /// Capture is needed to build a JSON envelope, and to populate a render
    /// failure summary. When false the human default (inherited streaming) holds.
    pub fn wants_capture(&self) -> bool {
        self.format == OutputFormat::Json || self.render.is_some()
    }

    pub fn is_json(&self) -> bool {
        self.format == OutputFormat::Json
    }
}

static OPTIONS: OnceLock<OutputOptions> = OnceLock::new();
static ARGUMENTS: OnceLock<Vec<OsString>> = OnceLock::new();

/// Keep the words the tool was given (the verb first), for a run that has to
/// say how to repeat itself.
pub fn install_arguments(arguments: Vec<OsString>) {
    let _ = ARGUMENTS.set(arguments);
}

/// The `patina run` command that repeats this process's run under `seed`:
/// the words it was given, with the seed spelled out when they left it to the
/// default.
/// `None` when the tool was not started as `run` (a unit test).
pub fn run_again_command(seed: u64) -> Option<String> {
    let arguments = ARGUMENTS.get()?;
    if arguments.first().map(OsString::as_os_str) != Some(OsStr::new("run")) {
        return None;
    }
    let guest_arguments = arguments
        .iter()
        .position(|word| word == "--")
        .unwrap_or(arguments.len());
    let (own, guest) = arguments.split_at(guest_arguments);
    let mut words: Vec<OsString> = own.to_vec();
    let seeded = own
        .iter()
        .any(|word| word == "--seed" || word.to_string_lossy().starts_with("--seed="));
    if !seeded {
        words.push("--seed".into());
        words.push(seed.to_string().into());
    }
    words.extend_from_slice(guest);
    let mut command = String::from("patina");
    for word in &words {
        command.push(' ');
        command.push_str(&crate::cli::shell_quote(word));
    }
    Some(command)
}

/// Install the parsed options once, at the top of `entrypoint`. A second call is
/// ignored (the first install wins); unit tests that never install get defaults.
pub fn install(options: OutputOptions) {
    let _ = OPTIONS.set(options);
    progress::start_clock();
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
    let value = |name: &str| crate::cli::single(&found, name);
    let mut options = OutputOptions::default();
    // A typed --format wins; otherwise PATINA_FORMAT applies.
    let format = match value("--format")? {
        Some(format) => Some(format),
        None => crate::cli::env_value(crate::cli::flag("run", "--format"))?,
    };
    if let Some(format) = format {
        options.format = parse_format(&format.to_string_lossy())?;
    }
    options.render = value("--render")?.map(PathBuf::from);
    options.verbose = value("--verbose")?.is_some();
    options.progress = value("--progress")?.is_some();
    options.verb = rest.first().map(|verb| verb.to_string_lossy().into_owned());
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
/// imports, and an audit that flags any is `unsupported`.
pub fn emit_audit(
    verb: &str,
    artifact: &str,
    findings: Vec<String>,
    finding_details: Vec<serde_json::Value>,
    result: RunClass,
) {
    if !options().is_json() {
        return;
    }
    let mut env = Envelope::new(verb, result);
    env.artifact = Some(artifact.to_string());
    env.findings = findings;
    env.finding_details = finding_details;
    env.emit();
}

/// Emit a verb's envelope for the build path, hashing the produced artifact.
pub fn emit_build(output_path: &Path) {
    if !options().is_json() {
        return;
    }
    let mut env = Envelope::new("build", RunClass::Ok);
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
/// (minimize), or for a CLI error surfaced under `--format json`.
pub fn emit_simple(verb: &str, result: RunClass, message: Option<String>) {
    if !options().is_json() {
        return;
    }
    let mut env = Envelope::new(verb, result);
    env.message = message;
    env.emit();
}

/// Report a native run the supervisor stopped before the guest started, so no
/// `guest_exit` exists: under `--format json` its envelope, otherwise the
/// outcome's headline and the message on stderr. Returns the tool's exit
/// status for `class`. The one way a pre-run stop is reported, so it cannot
/// leave without a class.
pub(crate) fn report_prerun_stop(artifact: &Path, class: RunClass, stop: Stop) -> i32 {
    let outcome = Outcome::of(class, Some(stop));
    if options().is_json() {
        let mut env = Envelope::new("run", outcome.class);
        env.artifact = Some(artifact.to_string_lossy().into_owned());
        env.message = outcome.stop.as_ref().map(|stop| stop.detail.clone());
        env.stop = outcome.stop;
        env.emit();
    } else {
        if let Some(headline) = outcome.headline(None) {
            eprintln!("{headline}");
        }
        // The headline carries the detail's first line; a refusal that lists
        // what it refused (the audit's symbols) follows whole.
        if let Some(stop) = &outcome.stop
            && stop.detail.lines().count() > 1
        {
            eprintln!("{}", stop.detail);
        }
    }
    class.exit_code()
}

#[cfg(test)]
mod tests;
