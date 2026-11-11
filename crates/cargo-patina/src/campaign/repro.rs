//! Failure artifacts and recorded generation reproduction.

use super::generation::{GenerationFiles, run_generation};
use super::state::{load_campaign_state, verify_campaign_build};
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
    // trace cannot carry (the pre-run gate surface): every semantic input is
    // authoritative in the trace, but a guest replayed without its allow list
    // fails closed, so those flags ride along. A traceless failure (a
    // mid-run abort) reproduces by a deterministic re-run, whose `flags` already
    // contain them.
    if let Some(trace) = trace {
        let mut parts = vec![
            "patina replay".to_string(),
            artifact.display().to_string(),
            trace.to_string(),
        ];
        parts.extend(invocation.iter().cloned());
        return crate::cli::shell_words(&parts);
    }
    let mut parts = vec![
        "patina run".to_string(),
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
    crate::cli::shell_words(&parts)
}

/// The generation flags and invocation shape a reproduce command is built from,
/// with `--coverage-out` added to both when the generation itself wrote an edge
/// coverage map. Like `--record`, coverage is part of the experiment: the shim
/// finalizes the map at shutdown and can fail the run there, so a repro without
/// it is a different run that silently passes. The destination is a bare
/// filename for the same reason `--record`'s is.
pub(super) fn reproduce_inputs(
    flags: &[String],
    invocation: &[String],
    wrote_coverage: bool,
    generation: u64,
) -> (Vec<String>, Vec<String>) {
    let mut flags = flags.to_vec();
    let mut invocation = invocation.to_vec();
    if wrote_coverage {
        let coverage = [
            "--coverage-out".to_string(),
            format!("generation-{generation}.covmap"),
        ];
        flags.extend(coverage.iter().cloned());
        invocation.extend(coverage);
    }
    (flags, invocation)
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
    /// (the pre-run gate surface). These are host/build facts the
    /// guest needs to run at all, so a reducer must never drop them: doing so
    /// would lose the failure for a reason that has nothing to do with faults.
    pub(crate) pinned: Vec<String>,
    pub(crate) guest_args: Vec<String>,
    pub(crate) timeout_secs: u64,
    pub(crate) class: String,
    /// The class is a property of two runs (`NONDETERMINISM`), which no oracle
    /// judging one run can preserve.
    pub(crate) cross_run: bool,
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
            "campaign out-dir {} has no campaign-state.json; --generation reduces a recorded campaign generation, so point --out-dir at the out-dir a `patina campaign` run wrote",
            out_dir.display()
        )));
    }
    let state = load_campaign_state(&state_path)?;
    verify_campaign_build(&state)?;
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
        pinned: invocation_flags(&state.spec),
        guest_args: state.spec.guest_args.clone(),
        timeout_secs: state.spec.timeout_secs,
        class: outcome.class.as_str().to_string(),
        cross_run: super::classify::is_cross_run(outcome.class),
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
        CampaignSpec, derive_flags, generation_hash, invocation_flags, parse, replay_flags,
    };
    use super::*;
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    #[test]
    fn a_generation_that_wrote_coverage_reproduces_with_coverage() {
        let flags = vec!["--seed-flag".to_string()];
        let invocation = vec!["--allow-unsupported-symbols".to_string(), "all".to_string()];
        let artifact = PathBuf::from("guest-bin");
        for trace in [Some("out/failures/generation-4.patina"), None] {
            for wrote_coverage in [true, false] {
                let (repro_flags, repro_invocation) =
                    reproduce_inputs(&flags, &invocation, wrote_coverage, 4);
                let command = reproduce_command(
                    &artifact,
                    7,
                    &repro_flags,
                    &repro_invocation,
                    &[],
                    trace,
                    "generation-4.patina",
                );
                // Coverage finalization runs at shutdown and can fail the run,
                // so a repro without it is a different experiment; its
                // destination is bare, like `--record`'s.
                assert_eq!(
                    command.contains("--coverage-out generation-4.covmap"),
                    wrote_coverage,
                    "trace={trace:?} wrote_coverage={wrote_coverage}: {command}"
                );
            }
        }
    }

    /// A corpus mounted at a guest directory keeps it: in the state a
    /// continuation reads, in the corpus hash it pins, and in the flag every
    /// generation and reproduce command takes.
    #[test]
    fn a_mount_at_a_guest_directory_keeps_it_everywhere() {
        let corpus = tempfile::tempdir().unwrap();
        std::fs::write(corpus.path().join("f"), b"one").unwrap();
        let host = std::fs::canonicalize(corpus.path()).unwrap();
        let host = host.to_str().unwrap();
        let value = format!("{host}:/data/in");
        let mut spec = parse(
            ["art", "--mount", value.as_str()]
                .into_iter()
                .map(OsString::from)
                .collect(),
        )
        .unwrap()
        .spec;
        super::super::spec::resolve_mount(&mut spec).unwrap();
        let mount = spec.mount.clone().unwrap();
        assert_eq!(
            (mount.dir.as_str(), mount.guest.as_str()),
            (host, "/data/in")
        );
        assert_eq!(invocation_flags(&spec), ["--mount", value.as_str()]);
        assert_eq!(spec_from_state_json(&spec_to_json(&spec)).unwrap(), spec);
        let mut at_root = mount.clone();
        at_root.guest = "/".into();
        assert_ne!(
            super::super::spec::absolute_mount(&at_root).unwrap().hash,
            mount.hash,
            "the guest directory is part of the corpus"
        );
    }

    #[test]
    fn a_mounted_corpus_reaches_every_generation_and_reproduce_command() {
        let corpus = tempfile::tempdir().unwrap();
        // A space in the path: every reproduce form must pass it as one word.
        let nested = corpus.path().join("my image");
        std::fs::create_dir(&nested).unwrap();
        std::fs::write(nested.join("f"), b"one").unwrap();
        // A relative spelling is stored absolute, so a continuation or a
        // pasted reproduce command run from elsewhere names the same corpus.
        let previous = std::env::current_dir().unwrap();
        std::env::set_current_dir(corpus.path()).unwrap();
        let parsed = parse(
            ["art", "--mount", "my image"]
                .into_iter()
                .map(OsString::from)
                .collect(),
        );
        let mut spec = parsed.unwrap().spec;
        let resolved = super::super::spec::resolve_mount(&mut spec);
        std::env::set_current_dir(previous).unwrap();
        resolved.unwrap();
        let absolute = std::fs::canonicalize(&nested).unwrap();
        let mount = spec.mount.clone().expect("the corpus is recorded");
        assert_eq!(mount.dir, absolute.to_str().unwrap());
        assert_eq!(spec_from_state_json(&spec_to_json(&spec)).unwrap(), spec);
        let flags = invocation_flags(&spec);
        assert_eq!(flags, ["--mount", absolute.to_str().unwrap()]);
        let derived = derive_flags(&spec, &generation_hash(0, 0));
        assert_eq!(derived.iter().filter(|flag| *flag == "--mount").count(), 1);
        // A replay re-supplies the corpus so its fingerprint verifies, and a
        // re-run captures it again; a guest argument with spaces stays one word.
        let quoted = crate::cli::shell_quote(absolute.as_os_str());
        assert!(quoted.starts_with('\''), "{quoted}");
        for trace in [None, Some("stop.patina")] {
            let command = reproduce_command(
                Path::new("guest"),
                7,
                &derived,
                &flags,
                &["{\"a\": 1}".to_string()],
                trace,
                "g.patina",
            );
            assert!(
                command.contains(&format!("--mount {quoted}")),
                "trace={trace:?}: {command}"
            );
            if trace.is_none() {
                assert!(command.ends_with("-- '{\"a\": 1}'"), "{command}");
            }
        }
        // The campaign pins the corpus it started from: a changed corpus is
        // refused rather than mixed into the same campaign.
        let mut state_spec = spec_to_json(&spec);
        let reloaded = spec_from_state_json(&state_spec).unwrap();
        assert_eq!(reloaded.mount, Some(mount.clone()));
        std::fs::write(nested.join("f"), b"two").unwrap();
        let changed = super::super::spec::absolute_mount(&mount).unwrap();
        assert_ne!(
            changed.hash, mount.hash,
            "the corpus hash must see a content change"
        );
        state_spec["mount"]["hash"] = serde_json::Value::String(changed.hash.clone());
        assert_eq!(
            spec_from_state_json(&state_spec).unwrap().mount,
            Some(changed)
        );
        // A corpus that is not a directory is refused before any generation
        // runs, not in every generation's child run.
        let file = corpus.path().join("file");
        std::fs::write(&file, b"x").unwrap();
        for dir in [file.as_path(), &corpus.path().join("missing")] {
            let args = ["art", "--mount", dir.to_str().unwrap()]
                .into_iter()
                .map(OsString::from)
                .collect();
            let mut spec = parse(args).unwrap().spec;
            assert!(
                super::super::spec::resolve_mount(&mut spec).is_err(),
                "{}",
                dir.display()
            );
        }
    }

    #[test]
    fn a_reproduce_command_carries_the_invocation_flags_the_trace_cannot() {
        let spec = CampaignSpec {
            allow_unsupported_symbols: Some("all".into()),
            address_layout: Some(patina_dst_trace::AddressLayout::Randomized),
            ..CampaignSpec::default()
        };
        let invocation = replay_flags(&spec);
        let artifact = PathBuf::from("guest-bin");
        // The trace form: replay restores every input the trace carries, the
        // address layout included, but the gate surface is a host fact it
        // cannot carry, so a repro line without it fails closed on the operator.
        let replay = reproduce_command(
            &artifact,
            7,
            &derive_flags(&spec, &generation_hash(0, 0)),
            &invocation,
            &[],
            Some("out/failures/generation-0.patina"),
            "generation-0.patina",
        );
        assert_eq!(
            replay,
            "patina replay guest-bin out/failures/generation-0.patina \
             --allow-unsupported-symbols all"
        );
        // The traceless form re-runs, and its flag list already contains them.
        let rerun = reproduce_command(
            &artifact,
            7,
            &derive_flags(&spec, &generation_hash(0, 0)),
            &invocation,
            &[],
            None,
            "generation-0.patina",
        );
        assert!(
            rerun.contains("--allow-unsupported-symbols all")
                && rerun.contains("--allow-randomized-address-layout"),
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
        // The native compute watchdog is invocation shape too: recorded, forwarded
        // once, and in the re-run form; a replay follows the recorded stop.
        {
            let args = ["art", "--compute-watchdog-ms", "5000"]
                .into_iter()
                .map(OsString::from)
                .collect();
            let spec = parse(args).unwrap().spec;
            assert_eq!(spec.compute_watchdog_ms, Some(5000));
            assert_eq!(spec_from_state_json(&spec_to_json(&spec)).unwrap(), spec);
            let flags = invocation_flags(&spec);
            assert_eq!(flags, ["--compute-watchdog-ms", "5000"]);
            let derived = derive_flags(&spec, &generation_hash(0, 0));
            assert_eq!(
                derived
                    .iter()
                    .filter(|flag| *flag == "--compute-watchdog-ms")
                    .count(),
                1
            );
            let rerun = reproduce_command(
                Path::new("guest"),
                7,
                &derived,
                &replay_flags(&spec),
                &[],
                None,
                "stop.patina",
            );
            assert!(rerun.contains("--compute-watchdog-ms 5000"), "{rerun}");
        }
    }
}
