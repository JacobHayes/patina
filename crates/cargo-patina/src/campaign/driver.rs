//! Campaign execution and continuation orchestration.

use super::generation::{GenerationFiles, run_generation};
use super::observe::{
    fold_depth_generation, fold_edge_coverage_generation, fold_sites_generation,
    generation_reached_shutdown, guidance_plan, guidance_source_or_refuse, initialize_depth,
    initialize_edge_coverage,
};
use super::parse::CampaignMode;
use super::report::{
    CampaignEnvelopeInput, CampaignSummaryInput, CoverageGate, ProgressHeartbeatInput,
    build_campaign_envelope, coverage_verdict, flush_stdout, novel_findings,
    print_campaign_summary, print_progress_heartbeat,
};
use super::repro::{
    render_failure_report, reproduce_command, save_failure_log, save_failure_trace,
};
use super::state::{
    CampaignLock, CampaignState, GenerationOutcome, InvocationRecord, SignatureRecord,
    absolute_out_dir, artifact_identity, class_counts_failures, load_campaign_state,
    load_coverage_tally, verify_artifact_identity, write_campaign_checkpoint,
};
use super::{
    CampaignInvocation, classify, derive_flags, gen_byte, generation_hash, invocation_flags,
    non_native_invocation_flag, signature,
};
use crate::CliError;
use crate::guided::{GuidanceDecision, GuidanceTally};
use crate::sdk_report::CoverageTally;
use std::fs;
use std::path::PathBuf;

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

    let mut state = match mode {
        CampaignMode::Fresh => {
            if state_path.exists() {
                return Err(CliError(format!(
                    "campaign out-dir {} already contains campaign-state.json; use --extend N or --resume, pick a new --out-dir, or delete the old one",
                    out_dir.display()
                )));
            }
            let artifact = artifact.expect("fresh campaign parser requires an artifact");
            // Resolve the artifact once (build a source on the fly), then sweep the SAME
            // built artifact across every generation — never rebuilt per generation.
            let resolved = crate::resolve_artifact(crate::ArtifactRef::Prebuilt(artifact))?;
            let identity = artifact_identity(&resolved.path)?;
            CampaignState::fresh(identity, spec)
        }
        CampaignMode::Resume | CampaignMode::Extend { .. } => load_campaign_state(&state_path)?,
    };

    let mut coverage = match mode {
        CampaignMode::Fresh => CoverageTally::default(),
        CampaignMode::Resume | CampaignMode::Extend { .. } => {
            load_coverage_tally(&sites_path, state.generations_done)?
        }
    };

    let artifact_path = PathBuf::from(&state.artifact.path);
    verify_artifact_identity(&state.artifact)?;

    // The DNS family exception, enforced where the artifact family is finally
    // known: wasip1 has no name-resolution surface, so a WASI campaign carrying a
    // host table is refused rather than silently sweeping without it.
    if state.artifact.family == "wasi" && !state.spec.dns_entries.is_empty() {
        return Err(CliError::usage(
            "--dns-entry is not supported for a WASI campaign: wasip1 has no name-resolution \
             surface (no getaddrinfo, no sock_addr_resolve), so the host table could never be \
             consulted; sweep a native artifact for DNS faults",
        ));
    }

    // The same shape for the forwarded `run <BINARY>` surface: campaign has one
    // parsing family, so the native-only restriction is enforced here, where the
    // artifact family is finally known, and the refusal names the flag the
    // operator typed rather than silently dropping it from every generation.
    if state.artifact.family != "native"
        && let Some(flag) = non_native_invocation_flag(&state.spec)
    {
        return Err(CliError::usage(format!(
            "{flag} is a native `run` option, but this campaign's artifact is a {} module: \
                 the native invocation controls belong to the native supervisor; sweep a \
                 native artifact to use it",
            state.artifact.family
        )));
    }

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
    let mut depth = initialize_depth(&out_dir, &state, state.generations_done)?;
    if state.spec.guided {
        // Fail closed rather than quietly degrading to the unguided scheme: a
        // campaign asked to steer with no signal to steer by is not a campaign
        // with slightly worse selection, it is a campaign silently running a
        // different mode than the operator asked for.
        guidance_source_or_refuse(&edge_coverage, &depth, state.artifact.family)?;
    }
    let mut guidance = GuidanceTally::default();

    let traces_dir = out_dir.join("traces");
    fs::create_dir_all(&traces_dir)
        .map_err(|e| CliError(format!("failed to create traces dir: {e}")))?;

    let self_exe = std::env::current_exe()
        .map_err(|e| CliError(format!("failed to resolve cargo-patina binary path: {e}")))?;

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
        &depth,
    )?;

    if !json_output {
        match mode {
            CampaignMode::Fresh => println!(
                "PATINA_CAMPAIGN_START artifact={} family={} generations={} seed_base={} out={}",
                artifact_path.display(),
                state.artifact.family,
                state.spec.generations,
                state.spec.seed_base,
                out_dir.display(),
            ),
            CampaignMode::Extend { .. } | CampaignMode::Resume => println!(
                "PATINA_CAMPAIGN_RESUME out={} done={} target={} artifact={} sha256={}",
                out_dir.display(),
                from_gen,
                state.spec.generations,
                artifact_path.display(),
                state.artifact.sha256,
            ),
        }
        flush_stdout();
    }

    // Human-mode progress disclosure: at cadence 1 every generation prints its
    // per-generation line (the full legacy stream, no separate heartbeat); at any
    // higher cadence only novel/failing generations print a per-generation line,
    // plus a periodic `PATINA_CAMPAIGN_PROGRESS` heartbeat answering "is it still
    // running?". The wall-clock start is used only for the heartbeat's `elapsed_secs`
    // — it never enters a deterministic (`PATINA_CAMPAIGN_GEN`) line.
    let mut failures_so_far = class_counts_failures(&state.classes);
    let mut novel_so_far = novel_findings(&state.signatures);

    for generation in from_gen..state.spec.generations {
        // Unguided: the pure per-generation hash. Guided: possibly a mutation of
        // a previously productive generation's hash. Either way ONE 32-byte value
        // feeds both the seed and every knob, so guidance needs no per-knob
        // special case and the derivation stays a pure function.
        let (hash, decision) = if state.spec.guided {
            let plan = guidance_plan(&state.spec, &edge_coverage, &depth);
            plan.generation_hash(generation)
        } else {
            (
                generation_hash(state.spec.seed_base, generation),
                GuidanceDecision::NoAncestors,
            )
        };
        if state.spec.guided {
            guidance.record(decision);
        }
        let seed = u64::from_le_bytes(hash[gen_byte::SEED].try_into().expect("32-byte hash"));
        let flags = derive_flags(&state.spec, &hash, state.artifact.family);
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
        let exit = run.facts.facts.exit_code;
        let timed_out = run.facts.facts.timed_out;
        let stderr = run.stderr;
        let _sites_fold = fold_sites_generation(&mut coverage, generation, seed, &stderr)?;
        let class = classify(&run.facts, &state.spec.classify);
        // Edge coverage folds AFTER classification, for the same reason depth does
        // below: the shim writes the coverage map at SHUTDOWN, so whether a missing
        // map is a tolerable "this generation never got there" or a loud plumbing
        // failure depends entirely on how the generation ended.
        let _edge_fold = fold_edge_coverage_generation(
            &mut edge_coverage,
            generation,
            coverage_map_path.as_deref(),
            generation_reached_shutdown(&run.facts.facts),
        )?;
        *state.classes.entry(class.as_str().to_string()).or_insert(0) += 1;
        // Depth folds AFTER classification: whether a missing depth line is a
        // tolerable "the guest never finished" or a loud plumbing failure depends
        // on how the generation ended.
        let _depth_fold = fold_depth_generation(&mut depth, generation, exit, timed_out, &stderr)?;

        let mut novel = false;
        let mut signature_key = None;
        if class.is_failure() {
            let sig = signature(class, &run.facts);
            let key = sig.key();
            signature_key = Some(key.clone());
            // A failure that ran to a clean finish left a valid trace; a mid-run
            // abort (a liveness violation, an always-violation trap) left none. The
            // reproduce command is `replay <trace>` when a valid trace exists, else
            // a deterministic re-run from the recorded seed and knobs.
            let saved_trace = save_failure_trace(&out_dir, &trace_path, generation);
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
            let reproduce = reproduce_command(
                &artifact_path,
                seed,
                &flags,
                &invocation_flags(&state.spec, state.artifact.family),
                &state.spec.guest_args,
                saved_trace.as_deref(),
                &format!("generation-{generation}.patina"),
            );
            let report = if state.spec.report {
                render_failure_report(
                    &out_dir,
                    saved_trace.as_deref(),
                    &artifact_path,
                    state.artifact.family,
                    generation,
                )
            } else {
                None
            };
            state
                .signatures
                .entry(key.clone())
                .and_modify(|record| record.count += 1)
                .or_insert_with(|| {
                    // A first-of-its-kind INFRA condition is recorded but is not
                    // "novel": it is not a bug the campaign found.
                    novel = class.is_finding();
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
        };
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
                println!(
                    "PATINA_CAMPAIGN_GEN generation={generation} seed={seed} class={}{tag}{steer}",
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
                    depth: &depth,
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
            &depth,
        )?;
    }

    let failures = class_counts_failures(&state.classes);
    let novel_count = novel_findings(&state.signatures);
    let coverage_verdict = coverage_verdict(&coverage, state.spec.allow_unmet_sometimes);
    let coverage_failure = coverage_verdict.gate == CoverageGate::Fail;
    let result = if failures == 0 && !coverage_failure {
        "ok"
    } else {
        "failure"
    };
    let exit_code = if failures == 0 && !coverage_failure {
        0
    } else {
        1
    };

    if json_output {
        let envelope = build_campaign_envelope(CampaignEnvelopeInput {
            result,
            exit_code,
            state: &state,
            coverage: &coverage,
            coverage_verdict: &coverage_verdict,
            edge_coverage: &edge_coverage,
            depth: &depth,
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
            depth: &depth,
            guidance: state.spec.guided.then_some(guidance),
            artifact_path: &artifact_path,
            failures,
            novel: novel_count,
            generations: state.spec.generations,
            store_path: &store_path,
            sites_path: &sites_path,
        });
        flush_stdout();
    }
    Ok(exit_code)
}
