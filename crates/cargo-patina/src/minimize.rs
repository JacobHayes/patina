//! `minimize`: reducing a failing campaign generation's fault knobs, or a
//! failing run's parameters. Knobs and inputs only; recorded decisions are never
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
//! reproduction command. `minimize --params` reduces the `--param` set of a
//! failing `patina run`.
//!
//! # Candidates are independent
//!
//! Each knob candidate runs through `patina run`, whose filesystem, clock,
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

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use patina_dst_trace::TraceBundle;

use crate::CliError;
use crate::campaign::VerdictFacts;
use crate::help;
use crate::output;

mod generation;
mod knobs;
mod oracle;
mod params;

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
    Params(ParamsMinimize),
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

/// `minimize --params`: reduce the `--param` set of a failing command.
pub(crate) struct ParamsMinimize {
    /// The failing command with its `--param` words lifted out: the words
    /// before the parameters' insertion point (the command's own `--`, or its
    /// end) and the words from it on.
    pub(crate) head: Vec<OsString>,
    pub(crate) tail: Vec<OsString>,
    pub(crate) params: BTreeMap<String, String>,
}

impl ParamsMinimize {
    /// The command with `params` spliced back in.
    fn command(&self, params: &BTreeMap<String, String>) -> Vec<OsString> {
        let mut words = self.head.clone();
        for (key, value) in params {
            words.push(OsString::from("--param"));
            words.push(OsString::from(format!("{key}={value}")));
        }
        words.extend(self.tail.iter().cloned());
        words
    }

    /// The command as a candidate is judged: asked for its result envelope,
    /// ahead of the command's own `--`.
    fn oracle_command(&self, params: &BTreeMap<String, String>) -> Vec<OsString> {
        let mut words = self.head.clone();
        words.push(OsString::from("--format"));
        words.push(OsString::from("json"));
        for (key, value) in params {
            words.push(OsString::from("--param"));
            words.push(OsString::from(format!("{key}={value}")));
        }
        words.extend(self.tail.iter().cloned());
        words
    }
}

pub(crate) fn execute(invocation: MinimizeInvocation) -> Result<i32, CliError> {
    match invocation {
        MinimizeInvocation::Generation(generation) => execute_generation(generation),
        MinimizeInvocation::Params(params) => execute_params(&params),
    }
}

/// How a candidate `patina run` ended, read off its `patina.result/v1`
/// envelope: the result it reported, and the guest's own exit code or the
/// signal that killed it, so two different failures stay two.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Ending {
    result: String,
    guest_code: Option<i64>,
    guest_signal: Option<i64>,
}

impl Ending {
    fn of_envelope(envelope: &serde_json::Value) -> Self {
        Self {
            result: envelope
                .get("result")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            guest_code: envelope
                .pointer("/guest_exit/code")
                .and_then(serde_json::Value::as_i64),
            guest_signal: envelope
                .pointer("/guest_exit/signal")
                .and_then(serde_json::Value::as_i64),
        }
    }
}

/// The `PATINA_<FLAG>` variable that defaults `--param`. A candidate runs
/// without it, so a parameter the reduction removed cannot come back through
/// the environment, and the printed reproduction unsets it too.
fn param_env() -> Option<String> {
    crate::cli::flag("run", "--param").env_name()
}

/// Run one candidate of a `--params` reduction and read how its run ended, or
/// `None` when the command reported no run at all: it printed no
/// `patina.result/v1` run envelope, so it is not a `patina run`, or patina
/// refused it before any guest ran.
fn ending_of(words: &[OsString]) -> Result<Option<Ending>, CliError> {
    let mut command = Command::new(&words[0]);
    command
        .args(&words[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if let Some(name) = param_env() {
        command.env_remove(name);
    }
    let output = command.output().map_err(|error| {
        CliError(format!(
            "failed to run {}: {error}",
            words[0].to_string_lossy()
        ))
    })?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(crate::campaign::run_envelope(&stdout)
        .filter(|envelope| envelope.get("guest_exit").is_some())
        .as_ref()
        .map(Ending::of_envelope))
}

/// Reduce the command's parameters; the reduced set and the commands run.
fn minimize_params(
    invocation: &ParamsMinimize,
) -> Result<(BTreeMap<String, String>, u64), CliError> {
    // The target is the original run's own failure, as patina reported it: a
    // candidate still fails only when its run ends the same way (the same
    // result, guest exit code and signal), so a candidate that fails
    // differently (a usage error, a refusal) is not mistaken for the failure
    // being minimized. A command that reports no run is not one this verb can
    // judge, whatever its exit status.
    let Some(target) = ending_of(&invocation.oracle_command(&invocation.params))? else {
        return Err(CliError::usage(
            "minimize --params: the command after `--` reported no run result, so there is \
             nothing to minimize; it must be a `patina run` that starts its guest",
        ));
    };
    if target.result == "ok" {
        return Err(CliError(
            "minimize --params: the run succeeds with its parameters, so there is no \
             failure to preserve"
                .into(),
        ));
    }
    let mut calls = 1_u64;
    let reduced = params::reduce(&invocation.params, |candidate| {
        calls += 1;
        Ok(ending_of(&invocation.oracle_command(candidate))?.as_ref() == Some(&target))
    })?;
    Ok((reduced, calls))
}

fn execute_params(invocation: &ParamsMinimize) -> Result<i32, CliError> {
    let (reduced, calls) = minimize_params(invocation)?;
    let rendered = reduced
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join(",");
    let mut repro = invocation
        .command(&reduced)
        .iter()
        .map(|word| crate::cli::shell_quote(word))
        .collect::<Vec<_>>()
        .join(" ");
    if let Some(name) = param_env().filter(|name| std::env::var_os(name).is_some()) {
        repro = format!("env -u {name} {repro}");
    }
    let detail = format!("params=[{rendered}] oracle_runs={calls} repro: {repro}");
    if output::options().is_json() {
        output::emit_simple("minimize", "ok", 0, Some(detail));
    } else {
        println!("PATINA_MINIMIZE_PARAMS_COMPLETE {detail}");
    }
    Ok(0)
}

#[cfg(test)]
mod tests;
