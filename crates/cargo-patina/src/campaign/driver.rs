//! Campaign execution and continuation orchestration.

use super::classify::{campaign_result, is_conclusive};
use super::generation::{GenerationFiles, run_generation};
use super::observe::{
    fold_edge_coverage_generation, fold_sites_generation, generation_reached_shutdown,
    guidance_source_or_refuse, guided_generation, initialize_edge_coverage,
};
use super::parse::CampaignMode;
use super::report::{
    CampaignEnvelopeInput, CampaignSummaryInput, CoverageGate, ProgressHeartbeatInput,
    build_campaign_envelope, coverage_verdict, flush_stdout, novel_findings,
    print_campaign_summary, print_progress_heartbeat,
};
use super::repro::{
    render_failure_report, reproduce_command, reproduce_inputs, save_failure_log,
    save_failure_trace,
};
use super::state::{
    CampaignLock, CampaignState, GenerationOutcome, InvocationRecord, SignatureRecord,
    absolute_out_dir, artifact_identity, class_counts_failures, load_campaign_state,
    load_coverage_tally, spec_to_json, verify_campaign_build, write_campaign_checkpoint,
};
use super::verify::{
    Attempt, Observation, VerificationSummary, Verifier, VerifyStatus, nondeterminism_signature,
    samples_clean_rerun, trace_digest,
};
use super::{
    CampaignInvocation, RunClass, classify, derive_flags, generation_hash, invocation_flags,
    mutation_units, signature,
};
use crate::CliError;
use crate::guided::{GuidanceDecision, GuidanceTally};
use crate::sdk_report::CoverageTally;
use std::fs;
use std::path::{Path, PathBuf};

pub(super) fn run_campaign(invocation: CampaignInvocation) -> Result<i32, CliError> {
    let CampaignInvocation {
        artifact,
        out_dir,
        spec,
        mode,
        timeout_secs_override,
        progress_every,
        cli,
        ..
    } = invocation;

    // Resolve the out-dir ONCE, here, before a single path is derived from it.
    // Every generation child is handed a `--record` path built from this one, and
    // a RELATIVE out-dir would be re-resolved by each child against its own cwd:
    // the same directory under two names in the logs, and — if a cwd ever
    // differs — a scratch file created in one place and looked for in another,
    // which surfaces as a bewildering ENOENT on an artifact nobody moved.
    let out_dir = absolute_out_dir(&out_dir)?;

    let state_path = out_dir.join("campaign-state.json");
    let store_path = out_dir.join("signatures.json");
    let sites_path = out_dir.join("sites.json");

    if !matches!(mode, CampaignMode::Fresh) && !state_path.is_file() {
        return Err(CliError(format!(
            "campaign out-dir {} has no campaign-state.json; nothing recorded to continue",
            out_dir.display()
        )));
    }

    if matches!(mode, CampaignMode::Fresh) {
        fs::create_dir_all(&out_dir)
            .map_err(|e| CliError(format!("failed to create campaign output dir: {e}")))?;
    }
    let _lock = CampaignLock::acquire(&out_dir)?;
    let mut scratch_guest = None;

    // A campaign command given again for the out-dir it already wrote
    // continues that campaign: see `continue_recorded`.
    let recorded = if state_path.exists() {
        Some(load_campaign_state(&state_path)?)
    } else {
        None
    };
    let continuing = recorded.is_some();
    let mut state = match (mode, recorded) {
        (CampaignMode::Fresh, recorded) => {
            let artifact = artifact.expect("fresh campaign parser requires an artifact");
            // Resolve the artifact once, then sweep the SAME binary across every
            // generation, its replays and any continuation: a source is built
            // here, into the out-dir, never by a generation's own run.
            let binary = match crate::parse::resolve_positional("campaign", artifact.as_os_str())? {
                crate::ArtifactRef::Prebuilt(path) => path,
                crate::ArtifactRef::Build(spec) if recorded.is_none() => {
                    crate::native_build::build_into(*spec, out_dir.join("guest"))?
                }
                // The recorded generations ran the guest the out-dir holds:
                // the source is built again beside it, never over it.
                crate::ArtifactRef::Build(spec) => {
                    let scratch = tempfile::tempdir_in(&out_dir).map_err(|error| {
                        CliError(format!("failed to create a build directory: {error}"))
                    })?;
                    scratch_guest = Some(scratch);
                    let scratch = scratch_guest.as_ref().expect("just set").path();
                    crate::native_build::build_into(*spec, scratch.join("guest"))?
                }
            };
            let identity = artifact_identity(&binary)?;
            let mut spec = spec;
            // A campaign records its layout policy from the start, fixed unless
            // the operator asked otherwise, so a continuation can tell.
            spec.address_layout
                .get_or_insert(patina_dst_trace::AddressLayout::Fixed);
            // Likewise its CPU count, so a continuation pins it.
            spec.cpus.get_or_insert(patina_dst_abi::DEFAULT_CPUS);
            // And its corpus, absolute and hashed, so a continuation can tell
            // whether it changed.
            super::spec::resolve_mount(&mut spec)?;
            match recorded {
                None => CampaignState::fresh(
                    identity,
                    spec,
                    crate::supervisor_identity::supervisor_sha256()?.to_string(),
                ),
                Some(recorded) => continue_recorded(recorded, &identity, spec, &out_dir)?,
            }
        }
        (CampaignMode::Resume | CampaignMode::Extend { .. }, Some(recorded)) => recorded,
        (CampaignMode::Resume | CampaignMode::Extend { .. }, None) => {
            unreachable!("a continuation without a recorded campaign was refused above")
        }
    };
    drop(scratch_guest);

    let mut coverage = if continuing {
        load_coverage_tally(&sites_path, state.generations_done)?
    } else {
        CoverageTally::default()
    };

    let artifact_path = PathBuf::from(&state.artifact.path);
    verify_campaign_build(&state)?;

    if let CampaignMode::Resume = mode
        && state.generations_done == state.spec.generations
    {
        return Err(CliError(format!(
            "campaign complete at {}/{}; use --extend N to continue",
            state.generations_done, state.spec.generations
        )));
    }
    if let CampaignMode::Extend { additional } = mode {
        state.spec.generations = state
            .spec
            .generations
            .checked_add(additional)
            .ok_or_else(|| CliError::usage("--extend would overflow the generation target"))?;
    }

    let mut edge_coverage = initialize_edge_coverage(&out_dir, &state, state.generations_done)?;
    if state.spec.guided {
        // Fail closed rather than quietly degrading to the unguided scheme: a
        // campaign asked to steer with no signal to steer by is not a campaign
        // with slightly worse selection, it is a campaign silently running a
        // different mode than the operator asked for.
        guidance_source_or_refuse(&edge_coverage)?;
    }
    let mut guidance = GuidanceTally::default();
    let units = if state.spec.guided {
        mutation_units(&state.spec)
    } else {
        Vec::new()
    };

    let traces_dir = out_dir.join("traces");
    fs::create_dir_all(&traces_dir)
        .map_err(|e| CliError(format!("failed to create traces dir: {e}")))?;

    let self_exe = std::env::current_exe()
        .map_err(|e| CliError(format!("failed to resolve patina binary path: {e}")))?;

    let json_output = crate::output::options().is_json();
    let full_stream = progress_every == 1;
    let start = std::time::Instant::now();
    let from_gen = state.generations_done;
    let effective_timeout_secs = timeout_secs_override.unwrap_or(state.spec.timeout_secs);
    state.invocations.push(InvocationRecord {
        cli,
        from_gen,
        gens_run: 0,
        timeout_secs: effective_timeout_secs,
        elapsed_secs: 0,
    });
    let invocation_index = state.invocations.len() - 1;

    write_campaign_checkpoint(
        &state_path,
        &store_path,
        &sites_path,
        &state,
        &coverage,
        &edge_coverage,
    )?;

    if !json_output {
        if continuing {
            println!(
                "PATINA_CAMPAIGN_RESUME out={} done={} target={} artifact={} sha256={}",
                out_dir.display(),
                from_gen,
                state.spec.generations,
                artifact_path.display(),
                state.artifact.sha256,
            );
        } else {
            println!(
                "PATINA_CAMPAIGN_START artifact={} generations={} seed_base={} out={}",
                artifact_path.display(),
                state.spec.generations,
                state.spec.seed_base,
                out_dir.display(),
            );
        }
        flush_stdout();
    }
    crate::output::progress::emit(
        "campaign_started",
        serde_json::json!({
            "artifact": artifact_path.to_string_lossy(),
            "out_dir": out_dir.to_string_lossy(),
            "done": from_gen,
            "target": state.spec.generations,
        }),
    );

    // Human-mode progress disclosure: at cadence 1 every generation prints its
    // per-generation line (the full legacy stream, no separate heartbeat); at any
    // higher cadence only novel/failing generations print a per-generation line,
    // plus a periodic `PATINA_CAMPAIGN_PROGRESS` heartbeat answering "is it still
    // running?". The wall-clock start is used only for the heartbeat's `elapsed_secs`
    // — it never enters a deterministic (`PATINA_CAMPAIGN_GEN`) line.
    let mut failures_so_far = class_counts_failures(&state.classes);
    let mut novel_so_far = novel_findings(&state.signatures);

    // The invocation shape a trace cannot carry, and everything else a
    // reproduction attempt shares across generations.
    let invocation = invocation_flags(&state.spec);
    let rules = state.spec.classify.clone();
    let guest_args = state.spec.guest_args.clone();
    let verifier = Verifier {
        self_exe: &self_exe,
        artifact: &artifact_path,
        invocation: &invocation,
        guest_args: &guest_args,
        timeout_secs: effective_timeout_secs,
        rules: &rules,
        traces_dir: &traces_dir,
    };

    for generation in from_gen..state.spec.generations {
        // Unguided: the pure per-generation material. Guided: possibly a local
        // mutation of a previously productive generation's material. Either way
        // ONE value feeds both the seed and every knob, so guidance needs no
        // per-knob special case and the derivation stays a pure function.
        let (hash, decision) = if state.spec.guided {
            guided_generation(&state.spec, &units, &mut edge_coverage, generation)
        } else {
            (
                generation_hash(state.spec.seed_base, generation),
                GuidanceDecision::NoAncestors,
            )
        };
        if state.spec.guided {
            guidance.record(decision);
        }
        let seed = hash.seed();
        let flags = derive_flags(&state.spec, &hash);
        let trace_path = traces_dir.join(format!("generation-{generation}.patina"));
        let _ = fs::remove_file(&trace_path);
        crate::remove_dead_scratch(&trace_path);
        let coverage_map_path = edge_coverage
            .active()
            .map(|store| store.generation_covmap_path(generation));

        let run = run_generation(
            &self_exe,
            &artifact_path,
            seed,
            &flags,
            GenerationFiles {
                trace_path: &trace_path,
                coverage_out: coverage_map_path.as_deref(),
            },
            &state.spec.guest_args,
            effective_timeout_secs,
        )?;
        let _sites_fold = fold_sites_generation(&mut coverage, generation, seed, run.sdk.as_ref())?;
        let stderr = run.stderr;
        let observed_class = classify(&run.facts, &state.spec.classify);
        // Edge coverage folds AFTER classification: the shim writes the coverage
        // map at SHUTDOWN, so whether a missing map is a tolerable "this
        // generation never got there" or a loud plumbing failure depends
        // entirely on how the generation ended.
        let _edge_fold = fold_edge_coverage_generation(
            &mut edge_coverage,
            generation,
            coverage_map_path.as_deref(),
            generation_reached_shutdown(&run.facts.facts),
        )?;

        // A failure that ran to a clean finish left a valid trace; a mid-run
        // abort (a liveness violation, an always-violation trap) left none. The
        // reproduce command is `replay <trace>` when a valid trace exists, else
        // a deterministic re-run from the recorded seed and knobs. Saved before
        // verification, so verification replays the trace the store names.
        let observed_signature = observed_class
            .is_failure()
            .then(|| signature(observed_class, &run.facts));
        let mut saved_trace = observed_class
            .is_failure()
            .then(|| save_failure_trace(&out_dir, &trace_path, generation))
            .flatten();
        let filed_nondeterministic = nondeterminism_signature(observed_signature.as_ref());
        let attempt = Attempt {
            generation,
            seed,
            flags: &flags,
            coverage: coverage_map_path.is_some(),
        };
        let (class, verification) = match &observed_signature {
            // A repeat of a signature already found not to reproduce is that
            // nondeterminism again, not the finding it pretends to be.
            Some(_) if state.signatures.contains_key(&filed_nondeterministic.key()) => {
                (RunClass::Nondeterministic, None)
            }
            // A novel finding: run its reproduce path once before reporting it.
            Some(seen)
                if state.spec.verify
                    && is_conclusive(observed_class)
                    && !state.signatures.contains_key(&seen.key()) =>
            {
                let observed = Observation::new(observed_class, &run.facts, None);
                let verification =
                    verifier.reproduce(&attempt, observed, saved_trace.as_deref())?;
                (verification.class(), Some(verification))
            }
            // A sampled clean generation: run it twice and compare the traces.
            None if state.spec.verify
                && observed_class == RunClass::Ok
                && samples_clean_rerun(state.spec.seed_base, generation) =>
            {
                let observed =
                    Observation::new(observed_class, &run.facts, trace_digest(&trace_path));
                let verification = verifier.rerun(&attempt, observed)?;
                state.clean_reruns.runs += 1;
                if verification.status == VerifyStatus::Infra {
                    state.clean_reruns.infra += 1;
                }
                if verification.class().is_failure() {
                    saved_trace = save_failure_trace(&out_dir, &trace_path, generation);
                }
                (verification.class(), Some(verification))
            }
            _ => (observed_class, None),
        };
        *state.classes.entry(class.as_str().to_string()).or_insert(0) += 1;

        let mut novel = false;
        let mut signature_key = None;
        if class.is_failure() {
            let sig = match class {
                RunClass::Nondeterministic => filed_nondeterministic,
                _ => observed_signature.expect("a failing class was observed as a failure"),
            };
            let key = sig.key();
            signature_key = Some(key.clone());
            // A failure with no valid bundle leaves no `failures/` trace and no
            // `reports/` HTML, and the child's streams are dropped right after
            // this — so the generation used to leave NOTHING on disk, even when
            // the child's stderr said in plain words what had happened. Keep
            // them: for exactly the failures that cannot be replayed, the log is
            // the only forensics there is.
            let saved_log = match saved_trace {
                Some(_) => None,
                None => save_failure_log(&out_dir, generation, &run.stdout, &stderr),
            };
            // A clean generation that did not reproduce has no failing trace to
            // replay: its reproduce command is the run it was verified by.
            let replayable = saved_trace
                .as_deref()
                .filter(|_| observed_class.is_failure());
            let (repro_flags, repro_invocation) =
                reproduce_inputs(&flags, &invocation, coverage_map_path.is_some(), generation);
            let reproduce = reproduce_command(
                &artifact_path,
                seed,
                &repro_flags,
                &repro_invocation,
                &state.spec.guest_args,
                replayable,
                &format!("generation-{generation}.patina"),
            );
            let report = if state.spec.report {
                render_failure_report(&out_dir, saved_trace.as_deref(), &artifact_path, generation)
            } else {
                None
            };
            state
                .signatures
                .entry(key.clone())
                .and_modify(|record| record.count += 1)
                .or_insert_with(|| {
                    // A first-of-its-kind inconclusive condition is recorded but
                    // is not "novel": the campaign learned nothing from it.
                    novel = is_conclusive(class);
                    SignatureRecord {
                        class,
                        shape: sig.shape.clone(),
                        policy: sig.policy.clone(),
                        first_seen_gen: generation,
                        count: 1,
                        seed,
                        reproduce,
                        trace: saved_trace,
                        log: saved_log,
                        report,
                        verification: verification.clone(),
                    }
                });
        }
        // The per-generation record path is transient scratch: a kept failure was
        // already copied into `failures/`, and a clean generation keeps nothing.
        // Remove the scratch file (including an empty abort-reservation file) so the
        // output directory holds only real artifacts.
        let _ = fs::remove_file(&trace_path);
        crate::remove_dead_scratch(&trace_path);

        if novel {
            novel_so_far += 1;
        }
        if class.is_failure() {
            failures_so_far += 1;
        }
        let outcome = GenerationOutcome {
            generation,
            seed,
            class,
            flags,
            novel,
            signature_key,
            verdicts: run.facts.facts.verdicts.clone(),
            verification,
        };
        if state.spec.generation_log {
            append_generation_log(&out_dir, &outcome)?;
        }
        if outcome.is_notable() {
            state.notable_runs.push(outcome.clone());
        }
        state.generations_done = generation + 1;
        state.invocations[invocation_index].gens_run = state.generations_done - from_gen;
        state.invocations[invocation_index].elapsed_secs = start.elapsed().as_secs();

        if !json_output {
            // Always surface a novel or failing generation; surface an ordinary OK
            // generation only in the full-stream mode. The line format is unchanged
            // (and wall-clock-free) so replay/reproduce consumers and the
            // determinism check stay stable.
            if novel || class.is_failure() || full_stream {
                let tag = if novel { " NOVEL" } else { "" };
                // The guidance decision rides the deterministic line (and only
                // under --guided, so an unguided stream is byte-unchanged): it is
                // a pure function of the same inputs, and without it there is no
                // way to see WHICH generations were steered or from where.
                let steer = match (state.spec.guided, decision) {
                    (false, _) => String::new(),
                    (true, GuidanceDecision::Exploit { ancestor }) => {
                        format!(" guided=exploit:{ancestor}")
                    }
                    (true, GuidanceDecision::Explore) => " guided=explore".to_string(),
                    (true, GuidanceDecision::NoAncestors) => " guided=none".to_string(),
                };
                // Which run a nondeterministic generation was observed as, and
                // how a verified one was checked — so the line that names the
                // class also says what it rests on.
                let mut verified = String::new();
                if class == RunClass::Nondeterministic {
                    verified.push_str(&format!(" observed={}", observed_class.as_str()));
                }
                if let Some(verification) = &outcome.verification {
                    verified.push_str(&format!(
                        " verify={}:{}",
                        verification.path.as_str(),
                        verification.status.as_str()
                    ));
                }
                println!(
                    "PATINA_CAMPAIGN_GEN generation={generation} seed={seed} class={}{tag}{steer}{verified}",
                    class.as_str()
                );
            }
            // Heartbeat every `progress_every` generations (suppressed in the
            // full-stream mode, where each generation already prints a line).
            if !full_stream && progress_every > 0 && (generation + 1) % progress_every == 0 {
                print_progress_heartbeat(ProgressHeartbeatInput {
                    done: generation + 1,
                    total: state.spec.generations,
                    elapsed_secs: start.elapsed().as_secs(),
                    failures: failures_so_far,
                    novel: novel_so_far,
                    class_counts: &state.classes,
                    coverage: &coverage,
                    edge_coverage: &edge_coverage,
                    guidance: state.spec.guided.then_some(guidance),
                });
            }
            flush_stdout();
        }
        write_campaign_checkpoint(
            &state_path,
            &store_path,
            &sites_path,
            &state,
            &coverage,
            &edge_coverage,
        )?;
        // `--progress`: the same disclosure as the human lines above (every
        // notable generation, and a heartbeat at the `--progress-every`
        // cadence), plus the last generation, so the stream ends at the target.
        // Sent after the checkpoint, so `done` is what the out-dir holds.
        let heartbeat = progress_every > 0 && state.generations_done % progress_every == 0;
        if novel
            || class.is_failure()
            || heartbeat
            || state.generations_done == state.spec.generations
        {
            crate::output::progress::emit(
                "generation",
                serde_json::json!({
                    "generation": generation,
                    "seed": seed,
                    "class": class.as_str(),
                    "novel": novel,
                    "done": state.generations_done,
                    "target": state.spec.generations,
                    "failures": failures_so_far,
                    "novel_signatures": novel_so_far,
                    "classes": &state.classes,
                }),
            );
        }
    }

    let failures = class_counts_failures(&state.classes);
    let novel_count = novel_findings(&state.signatures);
    let coverage_verdict = coverage_verdict(&coverage, state.spec.allow_unmet_sometimes);
    let coverage_failure = coverage_verdict.gate == CoverageGate::Fail;
    // The campaign's own class, and through it its exit status: the same
    // table every run's is read from.
    let result = campaign_result(
        state
            .classes
            .iter()
            .filter(|(_, count)| **count > 0)
            .filter_map(|(class, _)| RunClass::from_name(class)),
        coverage_failure,
    );
    let exit_code = result.exit_code();

    if json_output {
        let envelope = build_campaign_envelope(CampaignEnvelopeInput {
            result,
            state: &state,
            coverage: &coverage,
            coverage_verdict: &coverage_verdict,
            edge_coverage: &edge_coverage,
            guidance: state.spec.guided.then_some(guidance),
            out_dir: &out_dir,
            state_path: &state_path,
            sites_path: &sites_path,
        });
        println!("{envelope}");
    } else {
        print_campaign_summary(CampaignSummaryInput {
            class_counts: &state.classes,
            signatures: &state.signatures,
            coverage: &coverage,
            coverage_verdict: &coverage_verdict,
            edge_coverage: &edge_coverage,
            guidance: state.spec.guided.then_some(guidance),
            verification: VerificationSummary::of(&state),
            artifact_path: &artifact_path,
            failures,
            novel: novel_count,
            generations: state.spec.generations,
            result,
            store_path: &store_path,
            sites_path: &sites_path,
        });
        flush_stdout();
    }
    Ok(exit_code)
}

/// A campaign command given again for the out-dir it already wrote.
///
/// The same artifact and settings continue the recorded campaign toward the
/// larger of the two generation counts: an interrupted campaign finishes, a
/// larger `--gens` adds generations, and a finished one runs nothing and
/// reports what the out-dir holds. Anything else would put two campaigns'
/// outcomes in one directory, and is refused naming what differs.
fn continue_recorded(
    mut recorded: CampaignState,
    artifact: &super::state::ArtifactIdentity,
    spec: super::CampaignSpec,
    out_dir: &Path,
) -> Result<CampaignState, CliError> {
    let mut differs = Vec::new();
    if recorded.artifact.sha256 != artifact.sha256 {
        differs.push("the artifact".to_string());
    }
    let (was, now) = (spec_to_json(&recorded.spec), spec_to_json(&spec));
    if let (Some(was), Some(now)) = (was.as_object(), now.as_object()) {
        let keys: std::collections::BTreeSet<&String> = was.keys().chain(now.keys()).collect();
        differs.extend(
            keys.into_iter()
                .filter(|key| *key != "generations" && was.get(*key) != now.get(*key))
                .cloned(),
        );
    }
    if !differs.is_empty() {
        return Err(CliError(format!(
            "campaign out-dir {} holds a campaign this command does not continue: {} differ{}. \
             Pick a new --out-dir or delete the old one (--extend N and --resume continue the \
             recorded campaign as it is)",
            out_dir.display(),
            differs.join(", "),
            if differs.len() == 1 { "s" } else { "" },
        )));
    }
    recorded.spec.generations = recorded.spec.generations.max(spec.generations);
    Ok(recorded)
}

/// Append one generation's record to `<out>/generations.jsonl` (`--generation-log`).
///
/// A run killed mid-write leaves an unterminated last line; it is cut back to
/// the last complete record before appending, so a resumed generation's
/// record is never glued onto a torn one. Each record goes out in one write.
fn append_generation_log(out_dir: &Path, outcome: &GenerationOutcome) -> Result<(), CliError> {
    use std::io::{Seek as _, SeekFrom, Write as _};
    let path = out_dir.join("generations.jsonl");
    let error =
        |error: std::io::Error| CliError(format!("generation log {}: {error}", path.display()));
    let mut file = fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&path)
        .map_err(error)?;
    cut_torn_tail(&mut file).map_err(error)?;
    file.seek(SeekFrom::End(0)).map_err(error)?;
    let mut line = outcome.to_json().to_string();
    line.push('\n');
    file.write_all(line.as_bytes()).map_err(error)
}

/// Cut an unterminated last line off `file`, keeping every complete
/// newline-terminated record; reads only the tail (in bounded chunks).
fn cut_torn_tail(file: &mut fs::File) -> std::io::Result<()> {
    use std::io::{Read as _, Seek as _, SeekFrom};
    let len = file.seek(SeekFrom::End(0))?;
    if len == 0 {
        return Ok(());
    }
    let mut last = [0u8];
    file.seek(SeekFrom::Start(len - 1))?;
    file.read_exact(&mut last)?;
    if last[0] == b'\n' {
        return Ok(());
    }
    let mut keep = 0;
    let mut end = len;
    let mut chunk = vec![0u8; GENERATION_LOG_CHUNK];
    while end > 0 {
        let start = end.saturating_sub(chunk.len() as u64);
        let buf = &mut chunk[..(end - start) as usize];
        file.seek(SeekFrom::Start(start))?;
        file.read_exact(buf)?;
        if let Some(at) = buf.iter().rposition(|byte| *byte == b'\n') {
            keep = start + at as u64 + 1;
            break;
        }
        end = start;
    }
    file.set_len(keep)
}

const GENERATION_LOG_CHUNK: usize = 64 * 1024;

#[cfg(test)]
mod generation_log_tests {
    use super::{GENERATION_LOG_CHUNK, cut_torn_tail};
    use std::fs;

    fn cut(content: &[u8]) -> Vec<u8> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("generations.jsonl");
        fs::write(&path, content).unwrap();
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        cut_torn_tail(&mut file).unwrap();
        drop(file);
        fs::read(&path).unwrap()
    }

    #[test]
    fn only_an_unterminated_last_line_is_cut() {
        assert_eq!(cut(b""), b"");
        assert_eq!(cut(b"{\"a\":1}\n{\"b\":2}\n"), b"{\"a\":1}\n{\"b\":2}\n");
        assert_eq!(cut(b"{\"a\":1}\n{\"b"), b"{\"a\":1}\n");
        assert_eq!(cut(b"{\"torn"), b"");
        // A torn line longer than one read chunk, after a complete record.
        let mut long = b"{\"a\":1}\n".to_vec();
        long.extend(std::iter::repeat_n(b'x', 3 * GENERATION_LOG_CHUNK + 7));
        assert_eq!(cut(&long), b"{\"a\":1}\n");
        let torn_only = vec![b'x'; 2 * GENERATION_LOG_CHUNK];
        assert_eq!(cut(&torn_only), b"");
    }
}
