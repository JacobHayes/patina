//! `minimize`: reducing a failing campaign generation, a recorded trace, or an
//! experiment's inputs.
//!
//! # Knobs before decisions
//!
//! A campaign failure arrives as a generation: a seed plus a 17-18 flag fault
//! vector the campaign drew, and a recorded trace of what happened. Both can be
//! reduced, but they answer different questions and they do not cost remotely
//! the same. Delta-debugging the *decision stream* of a measured workq failure
//! took 9 014 oracle calls and 290 s to remove 1.8 % of the trace, because under
//! strict replay almost any deletion desynchronizes the recorded stream and
//! fails closed. Delta-debugging the *fault vector* of the same failure took 20
//! runs and 0.3 s to go from 17 knobs to 2 — and "only the short-write fault
//! matters" is the answer an operator actually wants
//! (`docs/probes/minimize-oracle-perf.md`).
//!
//! So `minimize --generation` runs the knob reducer first and hands the trace
//! reducer a trace recorded from the *minimal-knob* run. Each knob candidate is
//! a fresh seeded `run`, spelled exactly as the campaign spelled its
//! generations, so the reduction's output is a standalone reproduction command
//! rather than a smaller artifact.
//!
//! # The oracle patina owns
//!
//! An external oracle is an opaque command: patina writes a candidate to
//! `$PATINA_MINIMIZE_TRACE`, runs it, and reads an exit code. That is enough to
//! be useful and not enough to be parallel — patina cannot know whether two
//! concurrent invocations of someone's shell script would collide on a shared
//! path, so an external oracle stays serial unless `--jobs` opts in.
//!
//! The built-in oracle is different, and the difference is architectural rather
//! than a promise: it replays the candidate through `cargo patina replay`, whose
//! filesystem, clock, network and entropy are all virtualized, into a temp
//! directory of its own. Two candidates cannot observe each other — they bind
//! the same ports, write the same paths, and read the same clock without
//! interacting — so patina parallelizes its own oracle by default. It also fails
//! closed where a hand-written oracle usually does not: a candidate counts as
//! still-failing only when the target is present AND the replay did not diverge,
//! so a candidate whose replay aborts after the guest already announced the
//! failure is rejected rather than accepted.
//!
//! # What the oracle targets
//!
//! `minimize --generation N` derives its target from the campaign: the verdicts
//! that generation reported through the verdict ABI are recorded in the out-dir,
//! and the oracle's question becomes "does this candidate still report them?"
//! (outcome-channel arc §4.5 — one recognition primitive,
//! [`crate::campaign::recognize_verdicts`], two consumers). The campaign already
//! recognized the failure; making the operator re-encode it as a substring was
//! asking them to reproduce work patina had done.
//!
//! `--marker TEXT` overrides that, and is the level-1 escape hatch for a guest
//! that announces nothing structurally: the same role spec-declared
//! `classify.patterns` play for the classifier (arc §4.3). A generation with no
//! failure verdict and no `--marker` is refused by name rather than reduced
//! against a guessed target.

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use patina_dst_minimize::{
    CandidateMemo, FailureOracle, MinimizeError, Scenario, judge_with_memo, minimize_all_with_memo,
    minimize_branch_tree_with_memo, minimize_main_with_memo, minimize_timeline_with_memo,
    reduce_scenario, reduce_schedule_with_memo,
};
use patina_dst_trace::TraceBundle;

use crate::campaign::VerdictFacts;
use crate::help;
use crate::output;
use crate::{CliError, ENV_MODE, ENV_PARAMS_JSON, ENV_SEED};

mod generation;
mod knobs;
mod oracle;
mod reduction;

use generation::execute_generation;
use knobs::Knob;
use knobs::KnobMemo;
use knobs::KnobOracle;
use knobs::reduce_knobs;
use knobs::repro_command;
use knobs::split_knobs;
use oracle::CandidateOutcome;
use oracle::ExternalOracle;
use oracle::Marker;
use oracle::ReplayOracle;
use oracle::Target;
use oracle::VerdictTarget;
use oracle::default_jobs;
use oracle::judge_concurrently;
use reduction::event_count;
use reduction::minimize_to_fixed_point;
use reduction::reject_inverted_polarity;
use reduction::whole_bundle;

/// A `minimize` request.
pub(crate) enum MinimizeInvocation {
    Trace(TraceMinimize),
    Generation(GenerationMinimize),
    Scenario(ScenarioMinimize),
}

pub(crate) struct TraceMinimize {
    pub(crate) trace: PathBuf,
    pub(crate) output: PathBuf,
    pub(crate) timeline: Option<String>,
    pub(crate) prune: bool,
    pub(crate) oracle: Vec<OsString>,
    /// Explicit `--jobs`. Absent means serial, because the oracle is external.
    pub(crate) jobs: Option<usize>,
}

pub(crate) struct GenerationMinimize {
    pub(crate) out_dir: PathBuf,
    pub(crate) generation: u64,
    /// The explicit `--marker` override. Absent means the target is auto-derived
    /// from the verdicts the campaign recorded for this generation.
    pub(crate) marker: Option<String>,
    /// Where the reduced trace lands; defaults under the out-dir.
    pub(crate) output: Option<PathBuf>,
    /// Whether to delta-debug a trace after the knobs (`--no-trace-phase`).
    pub(crate) trace_phase: bool,
    pub(crate) jobs: Option<usize>,
}

pub(crate) struct ScenarioMinimize {
    pub(crate) seed: u64,
    pub(crate) params: std::collections::BTreeMap<String, String>,
    pub(crate) seed_budget: u64,
    pub(crate) oracle: Vec<OsString>,
}

pub(crate) fn execute(invocation: MinimizeInvocation) -> Result<i32, CliError> {
    match invocation {
        MinimizeInvocation::Trace(trace) => execute_trace(trace),
        MinimizeInvocation::Generation(generation) => execute_generation(generation),
        MinimizeInvocation::Scenario(scenario) => execute_scenario(scenario),
    }
}

fn execute_trace(invocation: TraceMinimize) -> Result<i32, CliError> {
    let original = TraceBundle::load(&invocation.trace).map_err(|error| {
        CliError(format!(
            "failed to load trace {}: {error}",
            invocation.trace.display()
        ))
    })?;
    // Pick the strategy automatically: a leaf timeline (or an unbranched main)
    // uses the strict suffix path; a non-leaf target or a branched bundle uses
    // the non-leaf branch-tree policy so shrinking never invalidates an
    // inherited replay prefix. `--prune-branches` additionally drops whole
    // branch subtrees the failure does not need.
    let whole = whole_bundle(&original, invocation.timeline.as_deref(), invocation.prune);
    let before = event_count(&original, invocation.timeline.as_deref(), whole);

    let jobs = match invocation.jobs {
        Some(jobs) => jobs,
        None => {
            eprintln!(
                "patina: minimize is evaluating candidates one at a time. Parallel evaluation is \
                 on by default only for patina's own oracle (`minimize --generation --marker`), \
                 which is hermetic by construction: it replays each candidate in its own temp \
                 directory with the guest's filesystem, clock, network and entropy virtualized. \
                 An oracle command is opaque to patina, so it is not parallelized without being \
                 asked. Pass --jobs N to parallelize this one once you have checked that \
                 concurrent runs of it cannot collide — each candidate arrives at its own \
                 $PATINA_MINIMIZE_TRACE, but an oracle that also writes a fixed shared path must \
                 stay serial."
            );
            1
        }
    };
    let mut oracle = ExternalOracle {
        command: invocation.oracle,
        jobs,
        calls: AtomicU64::new(0),
    };
    let mut memo = CandidateMemo::new();
    reject_inverted_polarity(
        &original,
        invocation.timeline.as_deref(),
        whole,
        &mut oracle,
        &mut memo,
    )?;

    let minimized = if invocation.prune {
        // `--prune-branches` runs the full pipeline: drop whole subtrees, then
        // shrink and canonicalize to a joint fixed point.
        minimize_all_with_memo(&original, &mut oracle, &mut memo)
    } else {
        minimize_to_fixed_point(
            &original,
            invocation.timeline.as_deref(),
            whole,
            &mut oracle,
            &mut memo,
        )
    }
    .map_err(|error| CliError(format!("trace minimization failed: {error}")))?;

    let after = event_count(&minimized, invocation.timeline.as_deref(), whole);
    minimized
        .write_atomic(&invocation.output)
        .map_err(|error| {
            CliError(format!(
                "failed to write minimized trace {}: {error}",
                invocation.output.display()
            ))
        })?;
    let calls = oracle.calls.load(Ordering::Relaxed);
    let detail = format!(
        "before={before} after={after} oracle_runs={calls} jobs={jobs} output={}",
        invocation.output.display()
    );
    if output::options().is_json() {
        output::emit_simple("minimize", "ok", 0, Some(detail));
    } else {
        println!("PATINA_MINIMIZE_COMPLETE {detail}");
    }
    Ok(0)
}

fn execute_scenario(invocation: ScenarioMinimize) -> Result<i32, CliError> {
    let mut base = Scenario::new(invocation.seed);
    base.params = invocation.params;
    let mut calls = 0_u64;
    // Each candidate runs the oracle as a fresh seeded child, handing it the
    // seed and parameters through the same PATINA_* environment protocol a
    // recorded run uses. A non-zero exit means the failure still reproduces.
    let mut oracle = |candidate: &Scenario| -> io::Result<bool> {
        calls += 1;
        let mut command = Command::new(&invocation.oracle[0]);
        command
            .args(&invocation.oracle[1..])
            .env(ENV_MODE, "seeded")
            .env(ENV_SEED, candidate.seed.to_string())
            .env_remove(ENV_PARAMS_JSON);
        if !candidate.params.is_empty() {
            let params = serde_json::to_string(&candidate.params).map_err(io::Error::other)?;
            command.env(ENV_PARAMS_JSON, params);
        }
        let status = command.status()?;
        Ok(!status.success())
    };
    let reduced = reduce_scenario(&base, &mut oracle, invocation.seed_budget)
        .map_err(|error| CliError(format!("scenario minimization failed: {error}")))?;
    let params = reduced
        .params
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join(",");
    let detail = format!(
        "seed={} params=[{params}] oracle_runs={calls}",
        reduced.seed
    );
    if output::options().is_json() {
        output::emit_simple("minimize", "ok", 0, Some(detail));
    } else {
        println!("PATINA_MINIMIZE_SCENARIO_COMPLETE {detail}");
    }
    Ok(0)
}

#[cfg(test)]
mod tests;
