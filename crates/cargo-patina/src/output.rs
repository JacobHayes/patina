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

use crate::render::{self, FailureSummary};
use crate::{CliError, exit_code};

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

/// Strip `--format <fmt>`, `--render <path>`, and `--report <path>` from the
/// leading (pre-`--`) region of an argument list, returning the parsed options
/// and the arguments with those flags removed. Flags after a `--` separator are
/// left in place — there they belong to the guest program, not Patina.
///
/// Mirrors [`crate::extract_target`] so these options can be parsed once,
/// globally, without touching any per-verb flag loop.
pub fn extract(arguments: Vec<OsString>) -> Result<(OutputOptions, Vec<OsString>), CliError> {
    let mut options = OutputOptions::default();
    let mut rest: Vec<OsString> = Vec::new();
    let mut iterator = arguments.into_iter();
    let mut after_separator = false;
    while let Some(argument) = iterator.next() {
        if after_separator {
            rest.push(argument);
            continue;
        }
        if argument == "--" {
            after_separator = true;
            rest.push(argument);
            continue;
        }
        match argument.to_str() {
            // `--format`, not `--output`: `--output <PATH>` is already the
            // artifact-path flag for `build` and `minimize`, so the machine-
            // readable envelope selector uses the distinct, collision-free
            // `--format <human|json>` (conventional, like cargo's
            // `--message-format`).
            Some("--format") => {
                let value = iterator
                    .next()
                    .and_then(|value| value.into_string().ok())
                    .ok_or_else(|| CliError::usage("--format requires a value (human or json)"))?;
                options.format = parse_format(&value)?;
            }
            Some(value) if value.starts_with("--format=") => {
                options.format = parse_format(&value["--format=".len()..])?;
            }
            Some("--render") => {
                let value = iterator
                    .next()
                    .ok_or_else(|| CliError::usage("--render requires an output HTML path"))?;
                options.render = Some(PathBuf::from(value));
            }
            Some(value) if value.starts_with("--render=") => {
                options.render = Some(PathBuf::from(&value["--render=".len()..]));
            }
            Some("--report") => {
                let value = iterator
                    .next()
                    .ok_or_else(|| CliError::usage("--report requires an output HTML path"))?;
                options.report = Some(PathBuf::from(value));
            }
            Some(value) if value.starts_with("--report=") => {
                options.report = Some(PathBuf::from(&value["--report=".len()..]));
            }
            _ => rest.push(argument),
        }
    }
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

/// A run's captured (or streamed) result: the exit code plus, when captured, the
/// guest's stdout/stderr bytes. `captured == false` means the streams already
/// went to the terminal (human default) and the byte buffers are empty.
pub struct Captured {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub captured: bool,
}

/// Run a fully-configured child command, capturing its output when the installed
/// options require it (JSON / render / report) and otherwise inheriting the
/// caller's streams unchanged (the human default). Signal death maps to a
/// `CliError` exactly like [`crate::exit_code`].
/// Whether guest output will be captured (JSON / render / report active and not
/// suppressed). Exposed so callers that must run the child themselves (e.g. the
/// starvation stall backstop's kill-able wait loop) can mirror
/// [`execute_command`]'s capture semantics exactly.
pub fn capture_active() -> bool {
    options().wants_capture() && !suppressed()
}

pub fn execute_command(command: &mut Command) -> Result<Captured, CliError> {
    if capture_active() {
        let output = command
            .output()
            .map_err(|error| CliError(format!("failed to execute child process: {error}")))?;
        Ok(Captured {
            exit_code: exit_code(output.status)?,
            stdout: output.stdout,
            stderr: output.stderr,
            captured: true,
        })
    } else {
        let status: ExitStatus = command
            .status()
            .map_err(|error| CliError(format!("failed to execute child process: {error}")))?;
        Ok(Captured {
            exit_code: exit_code(status)?,
            stdout: Vec::new(),
            stderr: Vec::new(),
            captured: false,
        })
    }
}

/// Everything needed to finalize a run/replay: emit any envelope, render any
/// timeline/report, and echo captured guest output back for the human format.
pub struct RunReport<'a> {
    pub verb: &'a str,
    pub family: &'a str,
    pub artifact: &'a str,
    /// The on-disk trace path for a record/replay run, or `None` for a plain
    /// seeded run (no trace was written).
    pub trace_path: Option<PathBuf>,
    pub timeline: &'a str,
    pub fingerprint: Option<String>,
    pub seed: Option<u64>,
}

/// Finalize a run/replay after the guest returns: echo captured output for the
/// human format, render the timeline/failure report if requested, emit the JSON
/// envelope if requested, and return the process exit code.
pub fn finalize_run(report: RunReport<'_>, captured: Captured) -> Result<i32, CliError> {
    if suppressed() {
        return Ok(captured.exit_code);
    }
    let opts = options();
    let stdout_text = String::from_utf8_lossy(&captured.stdout).into_owned();
    let stderr_text = String::from_utf8_lossy(&captured.stderr).into_owned();

    // For the human format, captured guest output must still be visible: re-emit
    // it on the real streams (the JSON format keeps stdout clean for the
    // envelope and folds the output into the envelope instead).
    if captured.captured && !opts.is_json() {
        let _ = std::io::stdout().write_all(&captured.stdout);
        let _ = std::io::stderr().write_all(&captured.stderr);
    }

    let classification = classify(captured.exit_code, &stdout_text, &stderr_text);
    let failed = classification != "ok";

    // Render the timeline when `--render` is set (always) or `--report` is set and
    // the run failed. Both need a trace on disk.
    let mut render_path: Option<String> = None;
    let want_render = opts.render.is_some() || (opts.report.is_some() && failed);
    if want_render {
        let out = opts.render.as_ref().or(opts.report.as_ref());
        if let Some(out) = out {
            let trace = report.trace_path.as_ref().ok_or_else(|| {
                CliError(
                    "--render/--report needs a recorded or replayed trace; a plain seeded run writes none (use --record PATH or replay a trace)"
                        .into(),
                )
            })?;
            let failure = failed.then(|| {
                failure_summary(
                    captured.exit_code,
                    &classification,
                    &stdout_text,
                    &stderr_text,
                )
            });
            let html = render::render_trace_file(
                &trace.to_string_lossy(),
                report.artifact,
                report.family,
                report.timeline,
                failure,
            )
            .map_err(|error| CliError(format!("failed to render trace timeline: {error}")))?;
            std::fs::write(out, html).map_err(|error| {
                CliError(format!(
                    "failed to write render output {}: {error}",
                    out.display()
                ))
            })?;
            render_path = Some(out.to_string_lossy().into_owned());
            if !opts.is_json() {
                eprintln!("PATINA_RENDER output={}", out.display());
            }
        }
    }

    if opts.is_json() {
        let mut env = Envelope::new(report.verb, &classification, captured.exit_code);
        env.family = Some(report.family.to_string());
        env.artifact = Some(report.artifact.to_string());
        env.fingerprint = report.fingerprint.clone();
        env.seed = report.seed;
        env.render = render_path.clone();
        if let Some(trace) = &report.trace_path {
            env.trace = trace_facts(trace, report.timeline);
        }
        env.markers = extract_markers(&stdout_text, &stderr_text);
        env.result_line = result_line(&stdout_text, &stderr_text);
        env.stdout = Some(stdout_text);
        env.stderr = Some(stderr_text);
        env.emit();
    }

    Ok(captured.exit_code)
}

/// Finalize a WASI run (executed in-process, so its output is already in hand)
/// exactly like [`finalize_run`], without a child process.
pub fn finalize_inprocess(
    report: RunReport<'_>,
    exit: i32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
) -> Result<i32, CliError> {
    finalize_run(
        report,
        Captured {
            exit_code: exit,
            stdout,
            stderr,
            captured: true,
        },
    )
}

/// Classify a run's outcome for the envelope and failure report.
fn classify(exit_code: i32, stdout: &str, stderr: &str) -> String {
    if exit_code == 0 {
        return "ok".to_string();
    }
    let combined = format!("{stdout}\n{stderr}");
    // A liveness-watchdog violation is its own classification (a virtual-time
    // no-progress wedge), distinct from a safety violation, so triage can tell a
    // "converges wrong" bug from a "never converges" one. Emitted per the interface
    // contract as `PATINA_VIOLATION liveness …` / `PATINA_VIOLATION converge …`.
    if combined.contains("PATINA_VIOLATION liveness ")
        || combined.contains("PATINA_VIOLATION converge ")
    {
        return "liveness".to_string();
    }
    if combined.contains("VIOLATION")
        || combined.contains("BUG_CAUGHT")
        || combined.contains("mismatch")
        || combined.contains("PATINA_BUGGIFY_SETUP_NEVER_CALLED")
        || combined.contains("PATINA_BUGGIFY_DUPLICATE_LABEL")
    {
        return "violation".to_string();
    }
    "failure".to_string()
}

/// Known structured marker prefixes emitted by the runtime/SDK/harnesses, worth
/// surfacing verbatim in the envelope and failure report.
const MARKER_PREFIXES: &[&str] = &[
    "PATINA_RESULT",
    "PATINA_VIOLATION",
    "PATINA_SCHEDULE_REPORT",
    "PATINA_SDK_REPORT",
    "PATINA_LIVENESS_REPORT",
    "PATINA_ALWAYS_VIOLATION",
    "PATINA_BUGGIFY_DUPLICATE_LABEL",
    "PATINA_BUGGIFY_SETUP_NEVER_CALLED",
    "WORKQ_RESULT",
    "WORKQ_VIOLATION",
    "BUG_CAUGHT",
];

fn extract_markers(stdout: &str, stderr: &str) -> Vec<String> {
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

/// The single most representative result line for the failure summary: a
/// violation marker if present, else the guest's `PATINA_RESULT`, else the last
/// non-empty stderr line.
fn result_line(stdout: &str, stderr: &str) -> Option<String> {
    let combined: Vec<&str> = stdout.lines().chain(stderr.lines()).collect();
    for needle in ["PATINA_VIOLATION", "VIOLATION", "BUG_CAUGHT", "mismatch"] {
        if let Some(line) = combined.iter().find(|l| l.contains(needle)) {
            return Some(line.trim().to_string());
        }
    }
    if let Some(line) = combined
        .iter()
        .find(|l| l.trim_start().starts_with("PATINA_RESULT"))
    {
        return Some(line.trim().to_string());
    }
    stderr
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .map(|l| l.trim().to_string())
}

fn failure_summary(
    exit_code: i32,
    classification: &str,
    stdout: &str,
    stderr: &str,
) -> FailureSummary {
    let markers = extract_markers(stdout, stderr);
    let mut facts: Vec<(String, String)> = Vec::new();
    for marker in &markers {
        if let Some((head, rest)) = marker.split_once(' ') {
            facts.push((head.to_string(), rest.to_string()));
        }
    }
    FailureSummary {
        result_line: result_line(stdout, stderr).unwrap_or_default(),
        classification: classification.to_string(),
        exit_code,
        facts,
        messages: markers,
    }
}

/// Compact facts about a trace on disk for the envelope's `trace` field. Best
/// effort: a load failure yields `None` rather than aborting the run's exit.
fn trace_facts(path: &Path, timeline: &str) -> Option<TraceFacts> {
    let bundle = patina_dst_trace::TraceBundle::load(path).ok()?;
    let events = bundle
        .resolved_timeline(timeline)
        .map(|d| d.len())
        .unwrap_or_else(|_| {
            bundle
                .timelines
                .first()
                .map(|t| t.decisions.len())
                .unwrap_or(0)
        });
    // Read the raw metadata generically so future fields still surface.
    let raw: serde_json::Value = std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(serde_json::Value::Null);
    let metadata = raw
        .get("metadata")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    Some(TraceFacts {
        path: path.to_string_lossy().into_owned(),
        format_version: bundle.format_version,
        timelines: bundle.timelines.iter().map(|t| t.id.clone()).collect(),
        event_count: events,
        metadata,
    })
}

// ---------------------------------------------------------------------------
// The JSON envelope. Serialized by hand (small, fixed shape) so the schema is
// visible in one place and stable regardless of internal type churn.
// ---------------------------------------------------------------------------

struct TraceFacts {
    path: String,
    format_version: u32,
    timelines: Vec<String>,
    event_count: usize,
    metadata: serde_json::Value,
}

/// A machine-readable result envelope. Fields absent for a given verb are
/// omitted from the JSON. Documented in `llms.txt` and `TUTORIAL.md`.
pub struct Envelope {
    verb: String,
    result: String,
    exit_code: i32,
    family: Option<String>,
    artifact: Option<String>,
    fingerprint: Option<String>,
    seed: Option<u64>,
    trace: Option<TraceFacts>,
    render: Option<String>,
    /// audit findings / build outputs / mismatch detail — a list of strings.
    findings: Vec<String>,
    output_path: Option<String>,
    content_hash: Option<String>,
    markers: Vec<String>,
    result_line: Option<String>,
    stdout: Option<String>,
    stderr: Option<String>,
    message: Option<String>,
}

impl Envelope {
    pub fn new(verb: &str, result: &str, exit_code: i32) -> Self {
        Self {
            verb: verb.to_string(),
            result: result.to_string(),
            exit_code,
            family: None,
            artifact: None,
            fingerprint: None,
            seed: None,
            trace: None,
            render: None,
            findings: Vec::new(),
            output_path: None,
            content_hash: None,
            markers: Vec::new(),
            result_line: None,
            stdout: None,
            stderr: None,
            message: None,
        }
    }

    fn to_json(&self) -> serde_json::Value {
        use serde_json::{Map, Value};
        let mut m = Map::new();
        m.insert("schema".into(), Value::from(ENVELOPE_SCHEMA));
        m.insert("verb".into(), Value::from(self.verb.clone()));
        m.insert("result".into(), Value::from(self.result.clone()));
        m.insert("exit_code".into(), Value::from(self.exit_code));
        if let Some(v) = &self.family {
            m.insert("family".into(), Value::from(v.clone()));
        }
        if let Some(v) = &self.artifact {
            m.insert("artifact".into(), Value::from(v.clone()));
        }
        if let Some(v) = &self.fingerprint {
            m.insert("fingerprint".into(), Value::from(v.clone()));
        }
        if let Some(v) = self.seed {
            m.insert("seed".into(), Value::from(v));
        }
        if let Some(t) = &self.trace {
            let mut tm = Map::new();
            tm.insert("path".into(), Value::from(t.path.clone()));
            tm.insert("format_version".into(), Value::from(t.format_version));
            tm.insert("timelines".into(), Value::from(t.timelines.clone()));
            tm.insert("event_count".into(), Value::from(t.event_count));
            tm.insert("metadata".into(), t.metadata.clone());
            m.insert("trace".into(), Value::Object(tm));
        }
        if let Some(v) = &self.render {
            m.insert("render".into(), Value::from(v.clone()));
        }
        if !self.findings.is_empty() {
            m.insert("findings".into(), Value::from(self.findings.clone()));
        }
        if let Some(v) = &self.output_path {
            m.insert("output_path".into(), Value::from(v.clone()));
        }
        if let Some(v) = &self.content_hash {
            m.insert("content_hash".into(), Value::from(v.clone()));
        }
        if !self.markers.is_empty() {
            m.insert("markers".into(), Value::from(self.markers.clone()));
        }
        if let Some(v) = &self.result_line {
            m.insert("result_line".into(), Value::from(v.clone()));
        }
        if let Some(v) = &self.stdout {
            m.insert("stdout".into(), Value::from(v.clone()));
        }
        if let Some(v) = &self.stderr {
            m.insert("stderr".into(), Value::from(v.clone()));
        }
        if let Some(v) = &self.message {
            m.insert("message".into(), Value::from(v.clone()));
        }
        Value::Object(m)
    }

    /// Print the envelope as one line of JSON to stdout.
    pub fn emit(&self) {
        let mut out = std::io::stdout().lock();
        let _ = writeln!(out, "{}", self.to_json());
    }
}

/// Emit a verb's envelope for the audit path: the findings are the flagged /
/// listed imports.
pub fn emit_audit(verb: &str, family: &str, artifact: &str, findings: Vec<String>, exit_code: i32) {
    if !options().is_json() {
        return;
    }
    let result = if exit_code == 0 { "ok" } else { "violation" };
    let mut env = Envelope::new(verb, result, exit_code);
    env.family = Some(family.to_string());
    env.artifact = Some(artifact.to_string());
    env.findings = findings;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_pulls_flags_and_leaves_program_args() {
        let args: Vec<OsString> = [
            "replay",
            "bin",
            "t.patina",
            "--render",
            "out.html",
            "--format",
            "json",
            "--",
            "--render",
            "guestflag",
        ]
        .iter()
        .map(OsString::from)
        .collect();
        let (opts, rest) = extract(args).unwrap();
        assert_eq!(opts.format, OutputFormat::Json);
        assert_eq!(opts.render, Some(PathBuf::from("out.html")));
        // The post-`--` `--render` is a guest flag and must survive.
        let rest: Vec<String> = rest
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            rest,
            vec!["replay", "bin", "t.patina", "--", "--render", "guestflag"]
        );
    }

    #[test]
    fn extract_supports_equals_form() {
        let args: Vec<OsString> = ["run", "--format=json", "--report=r.html"]
            .iter()
            .map(OsString::from)
            .collect();
        let (opts, rest) = extract(args).unwrap();
        assert_eq!(opts.format, OutputFormat::Json);
        assert_eq!(opts.report, Some(PathBuf::from("r.html")));
        assert_eq!(rest.len(), 1);
    }

    #[test]
    fn extract_leaves_build_output_path_untouched() {
        // Regression: `--output` is the build/minimize artifact-path flag and must
        // never be swallowed by the format selector.
        let args: Vec<OsString> = ["build", "demo.rs", "--output", "demo"]
            .iter()
            .map(OsString::from)
            .collect();
        let (opts, rest) = extract(args).unwrap();
        assert_eq!(opts.format, OutputFormat::Human);
        let rest: Vec<String> = rest
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(rest, vec!["build", "demo.rs", "--output", "demo"]);
    }

    #[test]
    fn bad_format_is_rejected() {
        let args: Vec<OsString> = ["run", "--format", "yaml"]
            .iter()
            .map(OsString::from)
            .collect();
        assert!(extract(args).is_err());
    }

    #[test]
    fn envelope_serializes_stable_shape() {
        let mut env = Envelope::new("audit", "ok", 0);
        env.family = Some("native".into());
        env.findings = vec!["libc::open".into()];
        let json = env.to_json();
        assert_eq!(json["schema"], ENVELOPE_SCHEMA);
        assert_eq!(json["verb"], "audit");
        assert_eq!(json["result"], "ok");
        assert_eq!(json["findings"][0], "libc::open");
        // Absent fields are omitted.
        assert!(json.get("trace").is_none());
        assert!(json.get("seed").is_none());
    }

    #[test]
    fn classify_detects_violation_markers() {
        assert_eq!(classify(0, "", ""), "ok");
        assert_eq!(classify(3, "WORKQ_VIOLATION two-leaders", ""), "violation");
        assert_eq!(
            classify(2, "", "trace operation mismatch at 4"),
            "violation"
        );
        assert_eq!(classify(1, "panic somewhere", ""), "failure");
    }

    #[test]
    fn classify_detects_liveness_violations_distinctly() {
        assert_eq!(
            classify(
                1,
                "",
                "PATINA_VIOLATION converge detail=did-not-converge vtime_ns=400 budget_ns=300 last_fault_vtime_ns=0"
            ),
            "liveness"
        );
        assert_eq!(
            classify(
                1,
                "",
                "PATINA_VIOLATION liveness detail=no-progress vtime_ns=700 budget_ns=600"
            ),
            "liveness"
        );
        // The finish-time report alone (armed, did not fire) is not a violation.
        assert_eq!(
            classify(0, "", "PATINA_LIVENESS_REPORT armed=1 fired=0"),
            "ok"
        );
    }
}
