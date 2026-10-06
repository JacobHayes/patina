//! Failure artifacts and recorded generation reproduction.

use super::generation::{GenerationFiles, run_generation};
use super::state::{load_campaign_state, verify_artifact_identity};
use super::{GenerationRun, VerdictFacts, invocation_flags};
use crate::CliError;
use std::path::{Path, PathBuf};

pub(super) fn reproduce_command(
    artifact: &Path,
    seed: u64,
    flags: &[String],
    invocation: &[String],
    guest_args: &[String],
    trace: Option<&str>,
    record: &str,
) -> String {
    // A valid recorded trace replays flag-free EXCEPT for the invocation shape the
    // trace cannot carry (`--harness`, the pre-run gate surface): every semantic
    // input is authoritative in the trace, but a harness binary replayed without
    // `--harness` fails closed, so those flags ride along. A traceless failure (a
    // mid-run abort) reproduces by a deterministic re-run, whose `flags` already
    // contain them.
    if let Some(trace) = trace {
        let mut parts = vec![
            "cargo patina replay".to_string(),
            artifact.display().to_string(),
            trace.to_string(),
        ];
        parts.extend(invocation.iter().cloned());
        return parts.join(" ");
    }
    let mut parts = vec![
        "cargo patina run".to_string(),
        artifact.display().to_string(),
        "--seed".to_string(),
        seed.to_string(),
        // `--record` is part of the EXPERIMENT, not a convenience: the child runs
        // with it, and recording changes what the run does — it costs memory and
        // it can fail at the end (the trace resource limit), which is itself a
        // way a generation dies. A reproduce command without it runs a different
        // experiment, and for that whole class of failure it silently "passes".
        //
        // The destination is a BARE filename, deliberately not the campaign's own
        // `<out>/traces/` scratch path: the operator gets a trace in their own
        // working directory instead of needing write access to the campaign
        // output (and instead of overwriting its scratch), and the command stays
        // a pure function of the generation — two runs of the same campaign into
        // two different output directories then record identical signature
        // stores, which is what makes the stores comparable at all.
        "--record".to_string(),
        record.to_string(),
    ];
    parts.extend(flags.iter().cloned());
    if !guest_args.is_empty() {
        parts.push("--".to_string());
        parts.extend(guest_args.iter().cloned());
    }
    parts.join(" ")
}

/// Save a failing generation's trace into `<out>/failures/`, but ONLY when the
/// child wrote a complete, validated bundle. A mid-run abort or timeout never
/// reaches `Context::finish`; an empty/truncated scratch trace is skipped rather
/// than copied forward as a future replay surprise.
pub(super) fn save_failure_trace(
    out_dir: &Path,
    trace_path: &Path,
    generation: u64,
) -> Option<String> {
    let bundle = patina_dst_trace::TraceBundle::load(trace_path).ok()?;
    let failures_dir = out_dir.join("failures");
    std::fs::create_dir_all(&failures_dir).ok()?;
    let dest = failures_dir.join(format!("generation-{generation}.patina"));
    bundle.write_atomic(&dest).ok()?;
    Some(dest.display().to_string())
}

/// Keep a failing generation's captured streams when it left no replayable
/// trace. Best effort: forensics must never fail a campaign.
pub(super) fn save_failure_log(
    out_dir: &Path,
    generation: u64,
    stdout: &str,
    stderr: &str,
) -> Option<String> {
    if stdout.trim().is_empty() && stderr.trim().is_empty() {
        return None;
    }
    let relative = format!("failures/generation-{generation}.log");
    let dest = out_dir.join(&relative);
    std::fs::create_dir_all(dest.parent()?).ok()?;
    let body = format!("== stdout ==\n{stdout}\n== stderr ==\n{stderr}\n");
    std::fs::write(&dest, body).ok()?;
    // Relative: see `SignatureRecord::log`. The summary joins it back onto the
    // output directory for display, so the operator still gets a full path.
    Some(relative)
}

/// Best-effort wave-14 `--report` HTML for a failing generation with a trace.
pub(super) fn render_failure_report(
    out_dir: &Path,
    trace: Option<&str>,
    artifact: &Path,
    family: &'static str,
    generation: u64,
) -> Option<String> {
    let trace = trace?;
    let reports_dir = out_dir.join("reports");
    std::fs::create_dir_all(&reports_dir).ok()?;
    let dest = reports_dir.join(format!("generation-{generation}.html"));
    let html = crate::render::render_trace_file(
        trace,
        &artifact.display().to_string(),
        family,
        "main",
        None,
    )
    .ok()?;
    std::fs::write(&dest, html).ok()?;
    Some(dest.display().to_string())
}

/// Everything needed to re-run one recorded generation of a finished campaign,
/// read back out of its out-dir.
///
/// This is the handoff `minimize --generation` reduces: the campaign drew the
/// fault-knob vector, so the campaign module is where the knowledge of what a
/// generation *was* lives, and minimize only reduces it.
pub(crate) struct GenerationRepro {
    pub(crate) artifact: PathBuf,
    pub(crate) seed: u64,
    /// The generation's full child-`run` flag vector, seed-derived knobs and
    /// invocation shape together, exactly as the campaign spelled it.
    pub(crate) flags: Vec<String>,
    /// The subset of `flags` that is invocation shape rather than a fault knob
    /// (`--harness`, the pre-run gate surface). These are host/build facts the
    /// guest needs to run at all, so a reducer must never drop them: doing so
    /// would lose the failure for a reason that has nothing to do with faults.
    pub(crate) pinned: Vec<String>,
    pub(crate) guest_args: Vec<String>,
    pub(crate) timeout_secs: u64,
    pub(crate) class: String,
    /// The verdicts the campaign recognized in this generation, in call order.
    /// `minimize --generation` targets these when no `--marker` is given.
    pub(crate) verdicts: Vec<VerdictFacts>,
}

/// Read one generation of a recorded campaign back out of its out-dir.
///
/// Refuses loudly rather than reducing something that is not what the campaign
/// ran: an out-dir with no state, a generation the campaign never recorded as
/// notable, or an artifact that has changed since the sweep.
pub(crate) fn generation_repro(
    out_dir: &Path,
    generation: u64,
) -> Result<GenerationRepro, CliError> {
    let state_path = out_dir.join("campaign-state.json");
    if !state_path.is_file() {
        return Err(CliError(format!(
            "campaign out-dir {} has no campaign-state.json; --generation reduces a recorded campaign generation, so point --out-dir at the out-dir a `cargo patina campaign` run wrote",
            out_dir.display()
        )));
    }
    let state = load_campaign_state(&state_path)?;
    verify_artifact_identity(&state.artifact)?;
    let outcome = state
        .notable_runs
        .iter()
        .find(|run| run.generation == generation)
        .ok_or_else(|| {
            let mut failing: Vec<String> = state
                .notable_runs
                .iter()
                .filter(|run| run.class.is_failure())
                .map(|run| run.generation.to_string())
                .collect();
            failing.sort();
            let known = if failing.is_empty() {
                "it recorded no failing generation at all".to_string()
            } else {
                format!("its failing generations are {}", failing.join(", "))
            };
            CliError(format!(
                "campaign out-dir {} has no recorded generation {generation}; {known}",
                out_dir.display()
            ))
        })?;
    Ok(GenerationRepro {
        artifact: PathBuf::from(&state.artifact.path),
        seed: outcome.seed,
        flags: outcome.flags.clone(),
        pinned: invocation_flags(&state.spec, state.artifact.family),
        guest_args: state.spec.guest_args.clone(),
        timeout_secs: state.spec.timeout_secs,
        class: outcome.class.as_str().to_string(),
        verdicts: outcome.verdicts.clone(),
    })
}

/// Run one child `run` exactly as a campaign generation would have, for a
/// caller reducing that generation. Same child shape, same scrubbed
/// environment, same pinned reports — the point is that a reduced flag vector is
/// judged by the same execution the campaign judged.
pub(crate) fn run_reduced_generation(
    self_exe: &Path,
    artifact: &Path,
    seed: u64,
    flags: &[String],
    trace_path: &Path,
    guest_args: &[String],
    timeout_secs: u64,
) -> Result<GenerationRun, CliError> {
    run_generation(
        self_exe,
        artifact,
        seed,
        flags,
        GenerationFiles {
            trace_path,
            coverage_out: None,
        },
        guest_args,
        timeout_secs,
    )
}

#[cfg(test)]
mod tests {
    use super::super::state::{spec_from_state_json, spec_to_json};
    use super::super::{
        CampaignSpec, derive_flags, generation_hash, invocation_flags, non_native_invocation_flag,
        parse,
    };
    use super::*;
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    #[test]
    fn a_reproduce_command_carries_the_invocation_flags_the_trace_cannot() {
        let spec = CampaignSpec {
            harness: true,
            allow_unsupported_symbols: Some("all".into()),
            ..CampaignSpec::default()
        };
        let invocation = invocation_flags(&spec, "native");
        let artifact = PathBuf::from("guest-bin");
        // The trace form: replay restores every SEMANTIC input, but `--harness` and
        // the gate surface are host/build facts it cannot carry, so a repro line
        // without them fails closed on the operator.
        let replay = reproduce_command(
            &artifact,
            7,
            &derive_flags(&spec, &generation_hash(0, 0), "native"),
            &invocation,
            &[],
            Some("out/failures/generation-0.patina"),
            "generation-0.patina",
        );
        assert_eq!(
            replay,
            "cargo patina replay guest-bin out/failures/generation-0.patina --harness \
             --allow-unsupported-symbols all"
        );
        // The traceless form re-runs, and its flag list already contains them.
        let rerun = reproduce_command(
            &artifact,
            7,
            &derive_flags(&spec, &generation_hash(0, 0), "native"),
            &invocation,
            &[],
            None,
            "generation-0.patina",
        );
        assert!(
            rerun.contains("--harness") && rerun.contains("--allow-unsupported-symbols all"),
            "the re-run repro dropped the invocation shape: {rerun}"
        );
        // `--record` is part of the experiment the campaign actually ran: without
        // it the repro is a DIFFERENT run, and a failure that only happens while
        // recording (the trace resource limit) silently "passes" on re-run.
        assert!(
            rerun.contains("--record generation-0.patina"),
            "the re-run repro dropped the recording the child ran with: {rerun}"
        );
        // A bare destination, so the command is a pure function of the generation
        // and two campaigns into different output directories record the same
        // store — an absolute out-dir path here made identical failures compare
        // as different.
        assert!(
            !rerun.contains("--record /") && !rerun.contains("--record out/"),
            "the re-run repro baked an output-directory path into --record: {rerun}"
        );
    }

    #[test]
    fn compute_watchdog_configuration_survives_campaign_reproduction() {
        let args = ["art", "--compute-watchdog-ms", "5000"]
            .into_iter()
            .map(OsString::from)
            .collect();
        let spec = parse(args).unwrap().spec;
        assert_eq!(spec.compute_watchdog_ms, Some(5000));
        assert_eq!(spec_from_state_json(&spec_to_json(&spec)).unwrap(), spec);
        assert_eq!(
            non_native_invocation_flag(&spec),
            Some("--compute-watchdog-ms")
        );
        let flags = invocation_flags(&spec, "native");
        assert_eq!(flags, ["--compute-watchdog-ms", "5000"]);
        assert!(invocation_flags(&spec, "wasi").is_empty());
        let derived = derive_flags(&spec, &generation_hash(0, 0), "native");
        assert_eq!(
            derived
                .iter()
                .filter(|flag| *flag == "--compute-watchdog-ms")
                .count(),
            1
        );
        for trace in [None, Some("stop.patina")] {
            let command = reproduce_command(
                Path::new("guest"),
                7,
                &derived,
                &flags,
                &[],
                trace,
                "stop.patina",
            );
            assert!(command.contains("--compute-watchdog-ms 5000"), "{command}");
        }
        assert!(
            spec_to_json(&CampaignSpec::default())
                .get("compute_watchdog_ms")
                .is_none()
        );
        for bound in [0, 86_400_001] {
            assert!(
                CampaignSpec::default()
                    .apply_json(&serde_json::json!({"compute_watchdog_ms": bound}))
                    .is_err()
            );
        }
    }
}
