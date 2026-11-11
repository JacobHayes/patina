//! Run finalization, classification, and trace facts.

use super::outcomes::{RunEvidence, classify};
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
    pub artifact: &'a str,
    /// The on-disk trace path for a record/replay run, or `None` for a plain
    /// seeded run (no trace was written).
    pub trace_path: Option<PathBuf>,
    /// The trace is scratch, recorded only to draw a page from (`--render`
    /// without `--record`) and removed with the run: the result
    /// names no trace.
    pub trace_scratch: bool,
    /// The facts of the trace at `trace_path`, when the caller already loaded
    /// it; `None` reads them from `trace_path`.
    pub trace_facts: Option<TraceFacts>,
    pub timeline: &'a str,
    pub fingerprint: Option<String>,
    /// What the guest's build does with its computation
    /// (`native_build::BuildKind`): `instrumented`, `go`, `python` or `plain`.
    pub build: Option<&'static str>,
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
    /// Patina's end-of-run reports (and their warnings), apart from the guest's output: printed on `--verbose`,
    /// carried in the envelope, read by nothing that judges the run.
    pub reports: String,
    /// Whether the shim reported the runtime installed: the guest ran under
    /// patina rather than ending before patina's runtime started.
    pub runtime_started: bool,
    /// What the supervisor could not read off the facts channel or the stop
    /// pipe: a defect in patina's own channels, which leaves the run unjudged.
    pub channel_defect: Option<String>,
    /// Why the supervisor could not commit the run's recording, when the
    /// reason is patina's own (the channel failed, or the bundle of a guest
    /// that exited clean would not validate) rather than the guest dying
    /// mid-record.
    pub trace_lost: Option<String>,
    /// The recording this run was asked for was not written, and why. A fact
    /// beside the run's class, which it never changes by itself.
    pub trace_incomplete: Option<TraceIncomplete>,
    /// What the operator relaxed for this run, each one a reason its
    /// determinism is not guaranteed. Empty for an unqualified run.
    pub qualifications: Vec<Qualification>,
    /// Whether the guest is a program Rust's runtime starts, whose exit
    /// status 101 is that runtime's for a panic.
    pub rust_program: bool,
    /// The command that repeats this run, for a run that does not end clean:
    /// the replay of its recording when it kept one, else the `run` itself.
    pub reproduce: Option<String>,
    /// The host directory the run's filesystem was captured from, which a
    /// likely artifact's missing host path is judged against.
    pub mount: Option<crate::mount::Mount>,
}

/// Why a run's recording is not at the path it was asked for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceIncomplete {
    /// Machine-readable name: `resource_limit` (the recording outgrew the
    /// trace budget and was dropped), `channel_unavailable` (its scratch
    /// file could not be read or moved), `incomplete` (the guest ended before
    /// the recording was finalized, or left one that does not load).
    pub reason: &'static str,
    /// What happened, for a reader.
    pub detail: String,
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

    let crash_outcome = report
        .crash_restart
        .as_ref()
        .and_then(|crash| crash.pointer("/terminal_outcome/kind"))
        .and_then(serde_json::Value::as_str);
    let crash_replay_diverged = crash_outcome == Some(CRASH_REPLAY_DIVERGED);
    let outcome = classify(&RunEvidence {
        exit_code: captured.exit_code,
        signal: captured.signal,
        facts: report.facts.as_ref(),
        crash_replay_diverged,
        crash_failed: crash_outcome == Some(CRASH_FAILED),
        runtime_started: report.runtime_started,
        channel_defect: report.channel_defect.as_deref(),
        trace_lost: report.trace_lost.as_deref(),
        rust_program: report.rust_program,
        trace_abandoned: report
            .trace_incomplete
            .as_ref()
            .is_some_and(|trace| trace.reason == "resource_limit"),
    });
    let failed = outcome.class.is_failure();
    let likely_artifacts = if failed {
        super::artifacts::likely_artifacts(
            outcome.stop.as_ref().map(|stop| stop.reason.as_str()),
            report.facts.as_ref(),
            report.mount.as_ref(),
        )
    } else {
        Vec::new()
    };
    let guest_exit = GuestExit {
        code: captured.exit_code,
        signal: captured.signal,
        core: captured.core,
    };

    // The timeline page `--render` asks for, drawn from the run's trace; a
    // failed run's page leads with the failure summary.
    let mut render_path: Option<String> = None;
    let mut render = |out: &PathBuf| -> Result<(), CliError> {
        let trace = report.trace_path.as_ref().ok_or_else(|| {
            CliError("--render found no trace to draw: the run left no complete recording".into())
        })?;
        let failure = failed.then(|| {
            failure_summary(
                captured.exit_code,
                &outcome,
                report.facts.as_ref(),
                &stdout_text,
                &stderr_text,
            )
        });
        let html = render::render_trace_file(
            &trace.to_string_lossy(),
            report.artifact,
            report.timeline,
            failure,
        )
        .map_err(|error| CliError(format!("failed to render trace timeline: {error}")))?;
        std::fs::write(out, &html).map_err(|error| {
            CliError(format!(
                "failed to write render output {}: {error}",
                out.display()
            ))
        })?;
        render_path = Some(out.to_string_lossy().into_owned());
        if !opts.is_json() {
            eprintln!("PATINA_RENDER output={}", out.display());
        }
        Ok(())
    };
    if let Some(out) = &opts.render
        && let Err(error) = render(out)
    {
        // A page that could not be rendered must not take a failed run's
        // class with it: the run is still reported, the page's error beside
        // it. A clean run has nothing to lose, and fails on the error.
        if !failed {
            return Err(error);
        }
        eprintln!("patina: {error}");
    }

    if opts.is_json() {
        let mut env = Envelope::new(report.verb, outcome.class);
        env.artifact = Some(report.artifact.to_string());
        env.fingerprint = report.fingerprint.clone();
        env.build = report.build;
        env.seed = report.seed;
        env.render = render_path.clone();
        if !report.trace_scratch {
            env.trace = report.trace_facts.clone().or_else(|| {
                report
                    .trace_path
                    .as_ref()
                    .and_then(|trace| trace_facts(trace, report.timeline))
            });
        }
        env.coverage = report.coverage.clone();
        env.crash_restart = report.crash_restart.clone();
        env.qualifications = report.qualifications.clone();
        env.trace_incomplete = report.trace_incomplete.clone();
        // Runtime-owned structured facts, lifted verbatim out of the run's own
        // `patina.runfacts` document.
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
            env.executable_unavailable = facts
                .get("executable_unavailable")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
        }
        env.likely_artifacts = likely_artifacts;
        env.stop = outcome.stop.clone();
        if failed {
            env.reproduce = report.reproduce.clone();
        }
        env.trace_unusable = outcome.trace_unusable;
        env.guest_exit = Some(guest_exit);
        env.result_line = result_line(&stdout_text, &stderr_text);
        env.stdout = Some(stdout_text);
        env.stderr = Some(stderr_text);
        env.reports = Some(report.reports.clone());
        env.emit();
    } else {
        if opts.verbose {
            let _ = std::io::stderr().write_all(report.reports.as_bytes());
        } else if let Some(planes) = vacuous_planes(report.facts.as_ref()) {
            // A fault the run was asked for that never landed is news even on
            // a quiet run: the clean result did not test it.
            eprintln!(
                "patina: warning: the requested {planes} faults never landed, so this run did \
                 not test them (--verbose shows each plane's report)"
            );
        }
        // Only a run that did not end clean has a backtrace worth explaining.
        if outcome.class.attribution().is_some()
            && report
                .facts
                .as_ref()
                .and_then(|facts| facts.get("executable_unavailable"))
                .is_some_and(|value| value == true)
        {
            eprintln!(
                "patina: note: the guest looked for its own executable (/proc/self/exe or \
                 /proc/self/maps), which the simulated filesystem does not hold, so a backtrace \
                 it printed has no symbols; RUST_BACKTRACE=full prints the frames' addresses, \
                 which addr2line resolves against the binary (docs/GUIDE.md, \"Backtraces\")"
            );
        }
        for line in likely_artifacts
            .iter()
            .filter_map(super::artifacts::describe)
        {
            eprintln!("patina: likely artifact: {line}");
        }
        if let Some(headline) = outcome.headline(Some(&guest_exit)) {
            // The one line that says whose move it is, after everything the guest
            // printed: the first thing a reader is told about how the run ended.
            eprintln!("{headline}");
            // A failure is a seed, and a seed is a command: say it.
            if let Some(command) = &report.reproduce {
                eprintln!("patina: reproduce: {command}");
            }
        }
    }

    // The tool's own status follows the run's class: 0 clean, 1 a finding in
    // the guest, 2 patina could not do what was asked. The guest's status is
    // reported (`guest_exit`), never passed through.
    Ok(outcome.class.exit_code())
}

/// The fault planes the run's facts call vacuous (configured, given traffic,
/// and never fired), joined for a reader; `None` when there are none.
/// Exploration planes (schedule, swarm) are left to `--verbose`.
fn vacuous_planes(facts: Option<&serde_json::Value>) -> Option<String> {
    let planes = facts?.get("fault_reports")?.as_object()?;
    let vacuous: Vec<&str> = planes
        .iter()
        .filter(|(name, _)| !matches!(name.as_str(), "schedule" | "swarm"))
        .filter(|(_, plane)| {
            plane.get("vacuous").and_then(serde_json::Value::as_bool) == Some(true)
        })
        .map(|(name, _)| name.as_str())
        .collect();
    (!vacuous.is_empty()).then(|| vacuous.join(", "))
}

/// The failure report's labeled facts, from the same structured sources the
/// classification read: the guest's verdicts, the runtime's findings and
/// what stopped the run.
fn failure_summary(
    exit_code: i32,
    outcome: &Outcome,
    facts: Option<&serde_json::Value>,
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
    if let Some(attribution) = outcome.class.attribution() {
        labeled.push(("attribution".to_string(), attribution.to_string()));
    }
    if let Some(stop) = &outcome.stop {
        labeled.push(("stop".to_string(), stop.reason.clone()));
        messages.push(stop.detail.clone());
    }
    FailureSummary {
        result_line: result_line(stdout, stderr).unwrap_or_default(),
        classification: outcome.class.to_string(),
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
    pub(crate) event_count: usize,
    pub(super) metadata: serde_json::Value,
}

impl TraceFacts {
    /// The facts as an envelope's `trace` object.
    pub(crate) fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "path": self.path,
            "format_version": self.format_version,
            "timelines": self.timelines,
            "event_count": self.event_count,
            "metadata": self.metadata,
        })
    }

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
