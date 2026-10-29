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

pub struct RunReport<'a> {
    pub verb: &'a str,
    pub family: &'a str,
    pub artifact: &'a str,
    /// The on-disk trace path for a record/replay run, or `None` for a plain
    /// seeded run (no trace was written).
    pub trace_path: Option<PathBuf>,
    /// The facts of the trace at `trace_path`, when the caller already loaded
    /// it; `None` reads them from `trace_path`.
    pub trace_facts: Option<TraceFacts>,
    pub timeline: &'a str,
    pub fingerprint: Option<String>,
    pub seed: Option<u64>,
    pub coverage: Option<CoverageReport>,
    /// Supervisor-owned native crash-restart facts. These are produced by the
    /// native parent, not recovered by parsing stderr markers, so JSON consumers
    /// can reason about restarts structurally.
    pub crash_restart: Option<serde_json::Value>,
    /// The runtime's own `patina.runfacts/v1` document for this run, when the
    /// facts channel was installed and the run produced one. The one machine
    /// channel out of the run: nothing here reads the `PATINA_*` stderr lines.
    pub facts: Option<serde_json::Value>,
    /// Whether the native supervisor saw the guest die on a signal or lose its
    /// trace (and said so on its `PATINA_INFRA native_run` line). Always false
    /// for the other families.
    pub supervisor_infra: bool,
    /// What the operator relaxed for this run, each one a reason its
    /// determinism is not guaranteed. Empty for an unqualified run.
    pub qualifications: Vec<Qualification>,
}

/// One operator-accepted relaxation that qualifies a run's determinism.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Qualification {
    /// Machine-readable name: `randomized_address_layout`,
    /// `unsupported_symbols`.
    pub kind: &'static str,
    /// What was relaxed, for a reader.
    pub detail: String,
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

    // Refusal attribution is the PARENT's job: a fail-closed abort kills the
    // child before it can write anything structured, so what it already
    // printed and the code it died with are all there is to work from. This
    // is what makes an *unattributed* abort meaningful.
    let refusal = refusal(captured.exit_code, &stdout_text, &stderr_text);
    let classification = classify(
        captured.exit_code,
        report.facts.as_ref(),
        refusal.as_ref(),
        report.supervisor_infra,
    );
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
                    report.facts.as_ref(),
                    refusal.as_ref(),
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
        env.trace = report.trace_facts.clone().or_else(|| {
            report
                .trace_path
                .as_ref()
                .and_then(|trace| trace_facts(trace, report.timeline))
        });
        env.coverage = report.coverage.clone();
        env.crash_restart = report.crash_restart.clone();
        env.qualifications = report.qualifications.clone();
        // Runtime-owned structured facts, lifted verbatim out of the run's own
        // `patina.runfacts/v1` document.
        if let Some(facts) = &report.facts {
            env.verdicts = facts.get("verdicts").cloned();
            env.sdk = facts.get("sdk").cloned();
            env.schedule_policy = facts.get("schedule_policy").cloned();
            env.fault_reports = facts.get("fault_reports").cloned();
            env.runtime_findings = facts
                .get("runtime_findings")
                .and_then(serde_json::Value::as_array)
                .cloned()
                .unwrap_or_default();
            env.cpu_charges = facts.get("cpu_charges").cloned();
            env.replay_divergence = facts
                .get("replay_divergence")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string);
        }
        env.refusal = refusal;
        env.guest_exit = Some(GuestExit {
            code: captured.exit_code,
            signal: captured.signal,
            core: captured.core,
        });
        env.result_line = result_line(&stdout_text, &stderr_text);
        env.stdout = Some(stdout_text);
        env.stderr = Some(stderr_text);
        env.emit();
    }

    Ok(captured.exit_code)
}

/// Classify a run's outcome for the envelope and failure report, from the
/// structured facts alone: the runtime's facts document, patina's refusal
/// attribution and the native supervisor's own observation. A guest that only
/// prints failure text, without the verdict ABI, is a plain `failure`.
fn classify(
    exit_code: i32,
    facts: Option<&serde_json::Value>,
    refusal: Option<&Refusal>,
    supervisor_infra: bool,
) -> String {
    if exit_code == 0 {
        return "ok".to_string();
    }
    let findings = facts
        .and_then(|facts| facts.get("runtime_findings"))
        .and_then(serde_json::Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    // A liveness-watchdog violation (a no-progress wedge, a host-time compute
    // bound) is its own classification, distinct from a safety violation, so
    // triage can tell a "converges wrong" bug from a "never converges" one.
    if findings.iter().any(|finding| {
        finding.get("source").and_then(serde_json::Value::as_str) == Some("liveness")
    }) {
        return "liveness".to_string();
    }
    let violation_verdict = facts
        .and_then(|facts| facts.get("verdicts"))
        .and_then(serde_json::Value::as_array)
        .is_some_and(|verdicts| {
            verdicts.iter().any(|verdict| {
                verdict.get("kind").and_then(serde_json::Value::as_str) == Some("violation")
            })
        });
    let buggify_misuse = refusal.is_some_and(|refusal| refusal.class.starts_with("buggify_"));
    if violation_verdict || buggify_misuse {
        return "violation".to_string();
    }
    let replay_diverged = facts.is_some_and(|facts| facts.get("replay_divergence").is_some());
    if refusal.is_some() || supervisor_infra || replay_diverged {
        return "infra".to_string();
    }
    "failure".to_string()
}

/// The failure report's labeled facts, from the same structured sources the
/// classification read: the guest's verdicts, the runtime's findings and
/// patina's refusal.
fn failure_summary(
    exit_code: i32,
    classification: &str,
    facts: Option<&serde_json::Value>,
    refusal: Option<&Refusal>,
    stdout: &str,
    stderr: &str,
) -> FailureSummary {
    let text = |value: &serde_json::Value, key: &str| {
        value
            .get(key)
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let rows = |key: &str| {
        facts
            .and_then(|facts| facts.get(key))
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default()
    };
    let mut labeled: Vec<(String, String)> = Vec::new();
    for verdict in rows("verdicts") {
        labeled.push((
            format!("verdict {}", text(&verdict, "kind")),
            format!("{} {}", text(&verdict, "label"), text(&verdict, "detail"))
                .trim()
                .to_string(),
        ));
    }
    for finding in rows("runtime_findings") {
        labeled.push((
            format!("{} finding", text(&finding, "source")),
            format!("{} {}", text(&finding, "kind"), text(&finding, "detail"))
                .trim()
                .to_string(),
        ));
    }
    let mut messages = Vec::new();
    if let Some(refusal) = refusal {
        labeled.push(("refusal".to_string(), refusal.class.clone()));
        messages.push(refusal.message.clone());
    }
    FailureSummary {
        result_line: result_line(stdout, stderr).unwrap_or_default(),
        classification: classification.to_string(),
        exit_code,
        facts: labeled,
        messages,
    }
}

/// Compact facts about a trace on disk for the envelope's `trace` field. Best
/// effort: a load failure yields `None` rather than aborting the run's exit.
fn trace_facts(path: &Path, timeline: &str) -> Option<TraceFacts> {
    let bundle = patina_dst_trace::TraceBundle::load(path).ok()?;
    Some(TraceFacts::of(path, &bundle, timeline))
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

impl TraceFacts {
    /// The facts of `bundle`, already loaded from `path`, so a caller holding
    /// the bundle does not read the trace again.
    pub(crate) fn of(path: &Path, bundle: &patina_dst_trace::TraceBundle, timeline: &str) -> Self {
        let event_count = bundle
            .resolved_timeline(timeline)
            .map(|decisions| decisions.len())
            .unwrap_or_else(|_| {
                bundle
                    .timelines
                    .first()
                    .map(|timeline| timeline.decisions.len())
                    .unwrap_or(0)
            });
        Self {
            path: path.to_string_lossy().into_owned(),
            format_version: bundle.format_version,
            timelines: bundle
                .timelines
                .iter()
                .map(|timeline| timeline.id.clone())
                .collect(),
            event_count,
            // Every metadata field is typed and unknown fields are refused on
            // load, so the typed metadata serializes back to what the file
            // holds.
            metadata: serde_json::to_value(&bundle.metadata).unwrap_or(serde_json::Value::Null),
        }
    }
}

#[cfg(test)]
mod tests;
