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

use patina_dst_abi::{VerdictKind, verdict_line};
use sha2::{Digest, Sha256};

use crate::help::{self, Flag};
use crate::render::{self, FailureSummary};
use crate::{CliError, config, exit_code};

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
    /// `--no-config`: skip `.patina/config.toml` discovery for hermetic invocations.
    pub no_config: bool,
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

/// Strip the global output/config flags from the leading (pre-`--`) region of
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
    let mut options = OutputOptions::default();
    if let Some(value) = crate::cli::single(&found, "--format")? {
        options.format = parse_format(&value.to_string_lossy())?;
    }
    options.render = crate::cli::single(&found, "--render")?.map(PathBuf::from);
    options.report = crate::cli::single(&found, "--report")?.map(PathBuf::from);
    options.no_config = found.contains_key("--no-config");
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoverageReport {
    pub edges_total: u64,
    pub edges_covered: u64,
    pub covered_permille: u64,
    pub hits_total: u64,
    pub hits_max: u32,
    pub saturated: u64,
    pub map_path: Option<PathBuf>,
}

/// The WASI family's depth proxy: fuel plus per-import hostcall counts. Depth is
/// deliberately NOT called coverage — it measures how far a guest ran, not which
/// edges it reached (`docs/arcs/coverage-depth.md` §5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DepthReport {
    pub family: String,
    pub fuel_consumed: u64,
    /// Per-import call counts in import-name order. An import the guest never
    /// called has no row at all, so "no depth data" can never be read as "zero".
    pub hostcalls: Vec<(String, u64)>,
}

impl DepthReport {
    pub fn hostcalls_total(&self) -> u64 {
        self.hostcalls
            .iter()
            .fold(0u64, |total, (_, count)| total.saturating_add(*count))
    }

    /// The stderr marker line. Every value is an integer and the row order is the
    /// map's, so the line is a deterministic function of the run.
    pub fn marker_line(&self) -> String {
        let mut line = format!(
            "PATINA_DEPTH_REPORT family={} fuel_consumed={} hostcalls_total={}",
            self.family,
            self.fuel_consumed,
            self.hostcalls_total()
        );
        for (name, count) in &self.hostcalls {
            line.push_str(&format!(" {name}={count}"));
        }
        line
    }
}

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
    pub coverage: Option<CoverageReport>,
    pub depth: Option<DepthReport>,
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
        env.coverage = report
            .coverage
            .clone()
            .or_else(|| coverage_report_line(&stdout_text, &stderr_text));
        env.depth = report
            .depth
            .clone()
            .or_else(|| depth_report_line(&stdout_text, &stderr_text));
        env.verdicts = extract_verdicts(&stdout_text, &stderr_text);
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
    if combined.contains("PATINA_INFRA") || combined.contains("incomplete trace") {
        return "infra".to_string();
    }
    "failure".to_string()
}

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
fn extract_verdicts(stdout: &str, stderr: &str) -> Vec<VerdictFact> {
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

/// Known structured marker prefixes emitted by the runtime/SDK/harnesses, worth
/// surfacing verbatim in the envelope and failure report.
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

fn coverage_report_line(stdout: &str, stderr: &str) -> Option<CoverageReport> {
    stdout
        .lines()
        .chain(stderr.lines())
        .find_map(parse_coverage_report_line)
}

fn parse_coverage_report_line(line: &str) -> Option<CoverageReport> {
    let mut parts = line.split_whitespace();
    if parts.next()? != "PATINA_COVERAGE_REPORT" {
        return None;
    }
    let mut edges_total = None;
    let mut edges_covered = None;
    let mut covered_permille = None;
    let mut hits_total = None;
    let mut hits_max = None;
    let mut saturated = None;
    for part in parts {
        let (key, value) = part.split_once('=')?;
        match key {
            "edges_total" => edges_total = value.parse().ok(),
            "edges_covered" => edges_covered = value.parse().ok(),
            "covered_permille" => covered_permille = value.parse().ok(),
            "hits_total" => hits_total = value.parse().ok(),
            "hits_max" => hits_max = value.parse().ok(),
            "saturated" => saturated = value.parse().ok(),
            _ => {}
        }
    }
    Some(CoverageReport {
        edges_total: edges_total?,
        edges_covered: edges_covered?,
        covered_permille: covered_permille?,
        hits_total: hits_total?,
        hits_max: hits_max?,
        saturated: saturated?,
        map_path: None,
    })
}

fn depth_report_line(stdout: &str, stderr: &str) -> Option<DepthReport> {
    stdout
        .lines()
        .chain(stderr.lines())
        .find_map(parse_depth_report_line)
}

/// Parse a `PATINA_DEPTH_REPORT` marker back into its structured form. The three
/// fixed keys are reserved; every other `name=count` token is a hostcall row, so
/// a newly counted import needs no parser change. A line whose declared
/// `hostcalls_total` disagrees with its rows is rejected rather than silently
/// re-derived — a truncated depth line must not read as a smaller-but-valid one.
pub(crate) fn parse_depth_report_line(line: &str) -> Option<DepthReport> {
    let mut parts = line.split_whitespace();
    if parts.next()? != "PATINA_DEPTH_REPORT" {
        return None;
    }
    let mut family: Option<String> = None;
    let mut fuel_consumed: Option<u64> = None;
    let mut declared_total: Option<u64> = None;
    let mut hostcalls: Vec<(String, u64)> = Vec::new();
    for part in parts {
        let (key, value) = part.split_once('=')?;
        match key {
            "family" => family = Some(value.to_string()),
            "fuel_consumed" => fuel_consumed = Some(value.parse().ok()?),
            "hostcalls_total" => declared_total = Some(value.parse().ok()?),
            name => hostcalls.push((name.to_string(), value.parse().ok()?)),
        }
    }
    let report = DepthReport {
        family: family?,
        fuel_consumed: fuel_consumed?,
        hostcalls,
    };
    if report.hostcalls_total() != declared_total? {
        return None;
    }
    Some(report)
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
    coverage: Option<CoverageReport>,
    depth: Option<DepthReport>,
    render: Option<String>,
    /// audit findings / build outputs / mismatch detail — a list of strings.
    findings: Vec<String>,
    /// Structured audit finding details; additive companion to `findings`.
    finding_details: Vec<serde_json::Value>,
    output_path: Option<String>,
    content_hash: Option<String>,
    /// Guest verdicts reported through the verdict ABI, in call order. Additive:
    /// omitted entirely when the run reported none.
    verdicts: Vec<VerdictFact>,
    markers: Vec<String>,
    result_line: Option<String>,
    stdout: Option<String>,
    stderr: Option<String>,
    message: Option<String>,
    config: Option<serde_json::Value>,
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
            coverage: None,
            depth: None,
            render: None,
            findings: Vec::new(),
            finding_details: Vec::new(),
            output_path: None,
            content_hash: None,
            verdicts: Vec::new(),
            markers: Vec::new(),
            result_line: None,
            stdout: None,
            stderr: None,
            message: None,
            config: config::provenance_json(),
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
        if let Some(c) = &self.coverage {
            let mut cm = Map::new();
            cm.insert("edges_total".into(), Value::from(c.edges_total));
            cm.insert("edges_covered".into(), Value::from(c.edges_covered));
            cm.insert("covered_permille".into(), Value::from(c.covered_permille));
            cm.insert("hits_total".into(), Value::from(c.hits_total));
            cm.insert("hits_max".into(), Value::from(c.hits_max));
            cm.insert("saturated".into(), Value::from(c.saturated));
            if let Some(path) = &c.map_path {
                cm.insert(
                    "map_path".into(),
                    Value::from(path.to_string_lossy().into_owned()),
                );
            }
            m.insert("coverage".into(), Value::Object(cm));
        }
        if let Some(d) = &self.depth {
            let mut dm = Map::new();
            dm.insert("family".into(), Value::from(d.family.clone()));
            dm.insert("fuel_consumed".into(), Value::from(d.fuel_consumed));
            dm.insert("hostcalls_total".into(), Value::from(d.hostcalls_total()));
            let mut hm = Map::new();
            for (name, count) in &d.hostcalls {
                hm.insert(name.clone(), Value::from(*count));
            }
            dm.insert("hostcalls".into(), Value::Object(hm));
            m.insert("depth".into(), Value::Object(dm));
        }
        if let Some(v) = &self.render {
            m.insert("render".into(), Value::from(v.clone()));
        }
        if !self.findings.is_empty() {
            m.insert("findings".into(), Value::from(self.findings.clone()));
        }
        if !self.finding_details.is_empty() {
            m.insert(
                "finding_details".into(),
                Value::from(self.finding_details.clone()),
            );
        }
        if let Some(v) = &self.output_path {
            m.insert("output_path".into(), Value::from(v.clone()));
        }
        if let Some(v) = &self.content_hash {
            m.insert("content_hash".into(), Value::from(v.clone()));
        }
        if !self.verdicts.is_empty() {
            let rows: Vec<Value> = self
                .verdicts
                .iter()
                .map(|verdict| {
                    let mut vm = Map::new();
                    vm.insert("seq".into(), Value::from(verdict.seq));
                    vm.insert("kind".into(), Value::from(verdict.kind.as_str()));
                    vm.insert("label".into(), Value::from(verdict.label.clone()));
                    vm.insert("detail".into(), Value::from(verdict.detail.clone()));
                    Value::Object(vm)
                })
                .collect();
            m.insert("verdicts".into(), Value::Array(rows));
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
        if let Some(v) = &self.config {
            m.insert("config".into(), v.clone());
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
    emit_audit_with_details(verb, family, artifact, findings, Vec::new(), exit_code);
}

pub fn emit_audit_with_details(
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
            "--no-config",
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
        assert!(opts.no_config);
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
    fn parses_coverage_report_marker_for_json_envelope() {
        let coverage = parse_coverage_report_line(
            "PATINA_COVERAGE_REPORT edges_total=10 edges_covered=4 covered_permille=400 hits_total=99 hits_max=12 saturated=1",
        )
        .unwrap();
        assert_eq!(coverage.edges_total, 10);
        assert_eq!(coverage.edges_covered, 4);
        assert_eq!(coverage.covered_permille, 400);
        assert_eq!(coverage.hits_total, 99);
        assert_eq!(coverage.hits_max, 12);
        assert_eq!(coverage.saturated, 1);
        assert!(coverage.map_path.is_none());
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
    fn envelope_carries_verdicts_in_report_order() {
        let stderr = format!(
            "noise\n{}\n{}\n",
            verdict_line::render(0, VerdictKind::Pass, "queue-drained", ""),
            verdict_line::render(1, VerdictKind::Violation, "two leaders", "{\"term\": 4}"),
        );
        let mut env = Envelope::new("run", "violation", 3);
        env.verdicts = extract_verdicts("", &stderr);
        let json = env.to_json();
        assert_eq!(json["verdicts"][0]["seq"], 0);
        assert_eq!(json["verdicts"][0]["kind"], "pass");
        assert_eq!(json["verdicts"][0]["label"], "queue-drained");
        assert_eq!(json["verdicts"][0]["detail"], "");
        assert_eq!(json["verdicts"][1]["kind"], "violation");
        // Spaces survive the escape round trip in both label and detail.
        assert_eq!(json["verdicts"][1]["label"], "two leaders");
        assert_eq!(json["verdicts"][1]["detail"], "{\"term\": 4}");
    }

    #[test]
    fn envelope_omits_verdicts_when_the_run_reported_none() {
        let env = Envelope::new("run", "ok", 0);
        assert!(env.to_json().get("verdicts").is_none());
        assert!(extract_verdicts("hello\n", "PATINA_SDK_REPORT enabled=0\n").is_empty());
    }

    #[test]
    fn a_malformed_verdict_line_is_dropped_not_half_decoded() {
        // Truncated (no detail) and unknown-kind lines must not become verdicts:
        // a partially understood result is worse than no result.
        let stderr = "PATINA_VERDICT seq=1 kind=pass label=x\nPATINA_VERDICT seq=2 kind=nope label=x detail=\n";
        assert!(extract_verdicts("", stderr).is_empty());
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
    fn classify_detects_infra_markers() {
        assert_eq!(
            classify(
                134,
                "",
                "PATINA_INFRA native_run signal=6 trace=incomplete reason=empty"
            ),
            "infra"
        );
        assert_eq!(
            classify(2, "", "incomplete trace run.patina: empty trace file"),
            "infra"
        );
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
