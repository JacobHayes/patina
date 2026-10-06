//! Campaign-generation minimization.

use super::*;

/// The failure `minimize --generation N` will preserve.
///
/// Explicit wins: a `--marker` the operator typed is what they meant, whatever
/// the generation reported. Otherwise the campaign's own recognition of the
/// generation is the target, and a generation with nothing to target is a
/// refusal that names both ways forward — never a guess, because guessing here
/// means silently minimizing against a failure nobody asked for.
fn generation_target(
    marker: Option<&str>,
    generation: u64,
    repro: &crate::campaign::GenerationRepro,
) -> Result<Target, CliError> {
    if let Some(text) = marker {
        return Ok(Target::Marker(Marker::parse(text)?));
    }
    if let Some(target) = VerdictTarget::capture(&repro.verdicts) {
        return Ok(Target::Verdicts(target));
    }
    let reported = if repro.verdicts.is_empty() {
        "it reported no verdict at all".to_string()
    } else {
        format!(
            "its only verdicts are [{}], and a `pass` verdict reports that a property HELD, so \
             there is no failure in it to preserve",
            repro
                .verdicts
                .iter()
                .map(|verdict| format!("{}:{}", verdict.kind, verdict.label))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    Err(CliError(format!(
        "generation {generation} has no failure verdict to target, so `minimize --generation` \
         cannot derive what to preserve: {reported}. The campaign classified it {}. Two ways \
         forward: report the failure through the verdict ABI (`patina_dst::verdict(VerdictKind::\
         Violation, \"<label>\", ...)`, or `patina_verdict` directly from a non-Rust guest), which \
         also makes the campaign classify it structurally; or pass --marker <TEXT> to name the \
         failure text this reduction should look for. Not every failing class travels on the \
         verdict channel — a LIVENESS wedge is a runtime finding and a vacuity class is fault \
         accounting, neither of which is a guest verdict — so --marker is the answer for those.",
        repro.class,
    )))
}

pub(super) fn execute_generation(invocation: GenerationMinimize) -> Result<i32, CliError> {
    let repro = crate::campaign::generation_repro(&invocation.out_dir, invocation.generation)?;
    let target = generation_target(invocation.marker.as_deref(), invocation.generation, &repro)?;
    let self_exe = std::env::current_exe().map_err(|error| {
        CliError(format!(
            "failed to resolve the cargo-patina binary: {error}"
        ))
    })?;
    let jobs = invocation.jobs.unwrap_or_else(default_jobs);

    // The pinned invocation flags lead the recorded vector, so dropping them
    // from the front leaves exactly the seed-derived knobs.
    let recorded = split_knobs(&repro.flags)?;
    let pinned = split_knobs(&repro.pinned)?;
    let knobs: Vec<Knob> = recorded
        .iter()
        .filter(|knob| !pinned.contains(knob))
        .cloned()
        .collect();
    let oracle = KnobOracle {
        self_exe: self_exe.clone(),
        artifact: repro.artifact.clone(),
        seed: repro.seed,
        pinned: repro.pinned.clone(),
        guest_args: repro.guest_args.clone(),
        timeout_secs: repro.timeout_secs,
        target: target.clone(),
        jobs,
        runs: AtomicU64::new(0),
    };
    let mut memo = KnobMemo::new();

    // Nothing may be dropped before the failure is shown to reproduce from what
    // the campaign recorded: without that, every "removable" knob is only
    // evidence that the target was never there. This is the polarity guard's
    // shape one level up — an auto-derived target is no more trustworthy than a
    // typed one until a run has actually exhibited it, and a target that never
    // reproduces would let the search "reduce" every knob away.
    if !oracle.judge(&knobs, &mut memo)? {
        let advice = match &target {
            Target::Marker(..) => {
                "check the marker text against that generation's output, and re-run the printed \
                 command to see what it does print"
            }
            Target::Verdicts(..) => {
                "the campaign recorded those verdicts for this generation, so a re-run that does \
                 not report them means the failure is not a function of the seed and knobs alone \
                 (an unmodelled host effect, or a guest whose outcome depends on something \
                 patina does not control); re-run the printed command to see what it does report"
            }
        };
        return Err(CliError(format!(
            "generation {} does not reproduce {} from its recorded seed and fault knobs, so there \
             is nothing to reduce. The campaign classified it {}; {advice}:\n  {}",
            invocation.generation,
            target.render(),
            repro.class,
            repro_command(&oracle, &knobs),
        )));
    }
    let minimal = reduce_knobs(&oracle, &knobs, &mut memo)?;
    let knob_runs = oracle.runs.load(Ordering::Relaxed);
    let command = repro_command(&oracle, &minimal);

    let minimized_dir = invocation.out_dir.join("minimized");
    std::fs::create_dir_all(&minimized_dir).map_err(|error| {
        CliError(format!(
            "failed to create {}: {error}",
            minimized_dir.display()
        ))
    })?;
    let repro_path = minimized_dir.join(format!("generation-{}.repro", invocation.generation));
    std::fs::write(&repro_path, format!("{command}\n"))
        .map_err(|error| CliError(format!("failed to write {}: {error}", repro_path.display())))?;
    let output_path = invocation.output.clone().unwrap_or_else(|| {
        minimized_dir.join(format!("generation-{}.patina", invocation.generation))
    });

    // Record the minimal-knob run: this is the trace the second phase shrinks,
    // and the artifact a flag-free replay reproduces from even when there is no
    // second phase.
    let recording = tempfile::tempdir()
        .map_err(|error| CliError(format!("failed to create a recording directory: {error}")))?;
    let recorded_trace = recording.path().join("minimal.patina");
    if !oracle.run(&minimal, Some(&recorded_trace))? {
        return Err(CliError(format!(
            "the reduced fault knobs stopped reproducing {} when re-run for recording; this \
             generation's failure is not a function of its seed and knobs alone, so it cannot be \
             reduced to a standalone command:\n  {command}",
            target.render()
        )));
    }
    let recorded_bundle = TraceBundle::load(&recorded_trace).map_err(|error| {
        CliError(format!(
            "failed to load the trace recorded from the reduced knobs: {error}"
        ))
    })?;
    let before = event_count(&recorded_bundle, None, false);

    let mut after = before;
    let mut trace_calls = 0;
    if invocation.trace_phase {
        let mut trace_oracle = ReplayOracle {
            self_exe,
            artifact: repro.artifact.clone(),
            invocation: repro.pinned.clone(),
            target: target.clone(),
            jobs,
            calls: AtomicU64::new(0),
        };
        let whole = whole_bundle(&recorded_bundle, None, false);
        let mut trace_memo = CandidateMemo::new();
        reject_inverted_polarity(
            &recorded_bundle,
            None,
            whole,
            &mut trace_oracle,
            &mut trace_memo,
        )?;
        let minimized = minimize_to_fixed_point(
            &recorded_bundle,
            None,
            whole,
            &mut trace_oracle,
            &mut trace_memo,
        )
        .map_err(|error| CliError(format!("trace minimization failed: {error}")))?;
        after = event_count(&minimized, None, whole);
        trace_calls = trace_oracle.calls.load(Ordering::Relaxed);
        minimized.write_atomic(&output_path)
    } else {
        recorded_bundle.write_atomic(&output_path)
    }
    .map_err(|error| {
        CliError(format!(
            "failed to write {}: {error}",
            output_path.display()
        ))
    })?;

    let detail = format!(
        "generation={} target={} knobs_before={} knobs_after={} knob_runs={knob_runs} \
         before={before} after={after} oracle_runs={trace_calls} jobs={jobs} repro={} output={}",
        invocation.generation,
        target.render(),
        knobs.len(),
        minimal.len(),
        repro_path.display(),
        output_path.display(),
    );
    if output::options().is_json() {
        output::emit_simple(
            "minimize",
            "ok",
            0,
            Some(format!("{detail} command={command}")),
        );
    } else {
        println!("PATINA_MINIMIZE_GENERATION_COMPLETE {detail}");
        println!("reproduce: {command}");
        if minimal.is_empty() {
            println!(
                "note: no fault knob is needed at all — this failure reproduces from the seed alone"
            );
        } else {
            println!(
                "the failure needs only: {}",
                minimal
                    .iter()
                    .map(Knob::render)
                    .collect::<Vec<_>>()
                    .join(" ")
            );
        }
    }
    Ok(0)
}

#[cfg(test)]
mod tests;
