//! Run finalization, classification, and trace facts.

use super::*;

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
    /// Supervisor-owned native crash-restart facts. These are produced by the
    /// native parent, not recovered by parsing stderr markers, so JSON consumers
    /// can reason about restarts structurally.
    pub crash_restart: Option<serde_json::Value>,
    /// The runtime's own `patina.runfacts/v1` document for this run, when the
    /// facts channel was installed and the run produced one. Read from the
    /// channel, never re-derived from the `PATINA_*_REPORT` stderr lines.
    pub facts: Option<serde_json::Value>,
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
        env.crash_restart = report.crash_restart.clone();
        env.verdicts = extract_verdicts(&stdout_text, &stderr_text);
        // Runtime-owned structured facts, lifted verbatim out of the run's own
        // `patina.runfacts/v1` document. The `PATINA_*_REPORT` lines still print
        // and still land in `stderr`/`markers`; these fields are the parallel
        // structured source, so nothing here parses a line back.
        if let Some(facts) = &report.facts {
            env.fault_reports = facts.get("fault_reports").cloned();
            env.runtime_findings = facts
                .get("runtime_findings")
                .and_then(serde_json::Value::as_array)
                .cloned()
                .unwrap_or_default();
        }
        // Refusal attribution is the PARENT's job: a fail-closed abort kills the
        // child before it can write anything structured, so what it already
        // printed and the code it died with are all there is to work from. This
        // is what makes an *unattributed* abort meaningful.
        env.refusal = refusal(captured.exit_code, &stdout_text, &stderr_text);
        env.guest_exit = Some(GuestExit {
            code: captured.exit_code,
            signal: captured.signal,
            core: captured.core,
        });
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
            signal: None,
            core: false,
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

#[derive(Clone, serde::Deserialize)]
pub(crate) struct TraceFacts {
    pub(crate) path: String,
    pub(super) format_version: u32,
    pub(super) timelines: Vec<String>,
    pub(super) event_count: usize,
    pub(super) metadata: serde_json::Value,
}

#[cfg(test)]
mod tests;
