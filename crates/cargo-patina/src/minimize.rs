//! `minimize`: reducing a failing campaign generation's inputs, or an
//! experiment's inputs. Knobs and inputs only; recorded decisions are never
//! edited.
//!
//! # Knobs, not decisions
//!
//! A campaign failure arrives as a generation: a seed plus a 17-18 flag fault
//! vector the campaign drew. Delta-debugging the *decision stream* of a
//! measured workq failure took 9 014 oracle calls and 290 s to remove 1.8 % of
//! the trace, because under strict replay almost any deletion desynchronizes
//! the recorded stream and fails closed. Delta-debugging the *fault vector* of
//! the same failure took 20 runs and 0.3 s to go from 17 knobs to 2 - and "only
//! the short-write fault matters" is the answer an operator actually wants.
//!
//! So `minimize --generation` reduces the knob vector and then records the
//! minimal-knob run, so the failure replays without flags. Recording is not a
//! reduction. Each knob candidate is a fresh seeded `run`, spelled exactly as
//! the campaign spelled its generations, so the output is a standalone
//! reproduction command. `minimize --scenario` reduces the seed and parameters
//! of an experiment against an oracle command.
//!
//! # Candidates are independent
//!
//! Each knob candidate runs through `cargo patina run`, whose filesystem, clock,
//! network and entropy are all virtualized, into a temp directory of its own.
//! Two candidates cannot observe each other, so patina runs them in parallel
//! by default.
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
//!
//! A `NONDETERMINISM` generation is refused by name too, `--marker` or not:
//! its failure is that two runs disagree, and every oracle here judges one.

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use patina_dst_minimize::{Scenario, reduce_scenario};
use patina_dst_trace::TraceBundle;

use crate::campaign::VerdictFacts;
use crate::help;
use crate::output;
use crate::{CliError, ENV_MODE, ENV_PARAMS_JSON, ENV_SEED};

mod generation;
mod knobs;
mod oracle;

use generation::execute_generation;
use knobs::Knob;
use knobs::KnobMemo;
use knobs::KnobOracle;
use knobs::reduce_knobs;
use knobs::repro_command;
use knobs::split_knobs;
use oracle::CandidateOutcome;
use oracle::Marker;
use oracle::Target;
use oracle::VerdictTarget;
use oracle::default_jobs;
use oracle::judge_concurrently;

/// A `minimize` request.
pub(crate) enum MinimizeInvocation {
    Generation(GenerationMinimize),
    Scenario(ScenarioMinimize),
}

pub(crate) struct GenerationMinimize {
    pub(crate) out_dir: PathBuf,
    pub(crate) generation: u64,
    /// The explicit `--marker` override. Absent means the target is auto-derived
    /// from the verdicts the campaign recorded for this generation.
    pub(crate) marker: Option<String>,
    /// Where the reduced trace lands; defaults under the out-dir.
    pub(crate) output: Option<PathBuf>,
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
        MinimizeInvocation::Generation(generation) => execute_generation(generation),
        MinimizeInvocation::Scenario(scenario) => execute_scenario(scenario),
    }
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
