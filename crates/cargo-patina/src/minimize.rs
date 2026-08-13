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
//! The built-in oracle (`--marker`) is different, and the difference is
//! architectural rather than a promise: it replays the candidate through
//! `cargo patina replay`, whose filesystem, clock, network and entropy are all
//! virtualized, into a temp directory of its own. Two candidates cannot observe
//! each other — they bind the same ports, write the same paths, and read the
//! same clock without interacting — so patina parallelizes its own oracle by
//! default. It also fails closed where a hand-written oracle usually does not:
//! a candidate counts as still-failing only when the marker appears AND the
//! replay did not diverge, so a candidate whose replay aborts after the guest
//! already printed the marker is rejected rather than accepted.

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

use crate::help;
use crate::output;
use crate::{CliError, ENV_MODE, ENV_PARAMS_JSON, ENV_SEED};

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
    pub(crate) marker: String,
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

// ===========================================================================
// Oracles
// ===========================================================================

/// The line the native supervisor prints when a replayed candidate stops
/// matching its recorded stream.
const REPLAY_DIVERGENCE: &str = "patina native shim fatal";

/// How many candidates patina evaluates at once when it owns the oracle.
///
/// Half the CPUs. Measured replay throughput on a 10-CPU host climbs 62 -> 303
/// replays/s from 1 to 8 workers and only reaches 323 at 12, so the last
/// doublings buy little, and a minimize run shares the machine with whatever
/// else the operator is doing.
fn default_jobs() -> usize {
    std::thread::available_parallelism()
        .map(|count| count.get() / 2)
        .unwrap_or(1)
        .max(1)
}

/// The failure text an oracle looks for, as a set of alternatives: `A|B`
/// matches a candidate whose output contains either.
///
/// Literal substrings rather than a regular expression, so what an operator
/// types on the command line means the same thing patina looks for, with no
/// second escaping layer between them.
#[derive(Clone, Debug)]
struct Marker {
    alternatives: Vec<String>,
}

impl Marker {
    fn parse(text: &str) -> Result<Self, CliError> {
        let alternatives: Vec<String> = text
            .split('|')
            .map(str::trim)
            .filter(|piece| !piece.is_empty())
            .map(str::to_string)
            .collect();
        if alternatives.is_empty() {
            return Err(CliError::usage(
                "--marker requires the failure text to look for; `A|B` matches either",
            ));
        }
        Ok(Self { alternatives })
    }

    fn matches(&self, haystack: &str) -> bool {
        self.alternatives
            .iter()
            .any(|alternative| haystack.contains(alternative.as_str()))
    }

    /// Whether one candidate's output means "the failure is still present".
    ///
    /// Both halves are load-bearing. The marker alone is fail-open: a candidate
    /// whose replay diverges *after* the guest printed the marker would be
    /// accepted, and the search would then keep deleting on the strength of a
    /// failure it never actually reproduced.
    fn preserved(&self, stdout: &str, stderr: &str) -> bool {
        if stderr.contains(REPLAY_DIVERGENCE) || stdout.contains(REPLAY_DIVERGENCE) {
            return false;
        }
        self.matches(stderr) || self.matches(stdout)
    }
}

/// Patina's own trace oracle: replay the candidate and require the marker plus a
/// clean replay.
struct ReplayOracle {
    self_exe: PathBuf,
    artifact: PathBuf,
    /// Flags a trace cannot carry (`--harness`, the pre-run gate surface), which
    /// a replay of this guest still needs.
    invocation: Vec<String>,
    marker: Marker,
    jobs: usize,
    calls: AtomicU64,
}

impl ReplayOracle {
    fn judge(&self, candidate: &TraceBundle) -> io::Result<bool> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        // A directory per candidate, so concurrent candidates share no path.
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("candidate.patina");
        candidate.write_atomic(&path).map_err(io::Error::other)?;
        let mut command = Command::new(&self.self_exe);
        command
            .arg("replay")
            .arg("--no-config")
            .arg(&self.artifact)
            .arg(&path);
        for flag in &self.invocation {
            command.arg(flag);
        }
        crate::config::scrub_child_config_env(&mut command, "replay");
        let output = command.output()?;
        Ok(self.marker.preserved(
            &String::from_utf8_lossy(&output.stdout),
            &String::from_utf8_lossy(&output.stderr),
        ))
    }
}

impl FailureOracle for ReplayOracle {
    type Error = io::Error;

    fn preserves_failure(&mut self, candidate: &TraceBundle) -> io::Result<bool> {
        self.judge(candidate)
    }

    fn batch_width(&self) -> usize {
        self.jobs
    }

    fn judge_batch(&mut self, candidates: &[&TraceBundle]) -> io::Result<Vec<bool>> {
        judge_concurrently(candidates, |candidate| self.judge(candidate))
    }
}

/// The caller's oracle command: write the candidate, run it, read its exit code.
struct ExternalOracle {
    command: Vec<OsString>,
    jobs: usize,
    calls: AtomicU64,
}

impl ExternalOracle {
    fn judge(&self, candidate: &TraceBundle) -> io::Result<bool> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("candidate.patina");
        candidate.write_atomic(&path).map_err(io::Error::other)?;
        let status = Command::new(&self.command[0])
            .args(&self.command[1..])
            .env("PATINA_MINIMIZE_TRACE", &path)
            .status()?;
        Ok(!status.success())
    }
}

impl FailureOracle for ExternalOracle {
    type Error = io::Error;

    fn preserves_failure(&mut self, candidate: &TraceBundle) -> io::Result<bool> {
        self.judge(candidate)
    }

    fn batch_width(&self) -> usize {
        self.jobs
    }

    fn judge_batch(&mut self, candidates: &[&TraceBundle]) -> io::Result<Vec<bool>> {
        judge_concurrently(candidates, |candidate| self.judge(candidate))
    }
}

/// Judge a window of candidates on one thread each, returning verdicts in the
/// window's order however the threads finish.
fn judge_concurrently<T: Sync>(
    candidates: &[&T],
    judge: impl Fn(&T) -> io::Result<bool> + Sync,
) -> io::Result<Vec<bool>> {
    if candidates.len() == 1 {
        return Ok(vec![judge(candidates[0])?]);
    }
    let judge = &judge;
    std::thread::scope(|scope| {
        let handles: Vec<_> = candidates
            .iter()
            .map(|candidate| {
                let candidate = *candidate;
                scope.spawn(move || judge(candidate))
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| {
                handle
                    .join()
                    .unwrap_or_else(|_| Err(io::Error::other("a minimize oracle worker panicked")))
            })
            .collect()
    })
}

// ===========================================================================
// Fault-knob reduction
// ===========================================================================

/// One knob of a generation's flag vector: a flag and the tokens that belong to
/// it (`["--fs-short-permille", "122"]`, `["--swarm"]`).
#[derive(Clone, Debug, PartialEq, Eq)]
struct Knob {
    tokens: Vec<String>,
}

impl Knob {
    fn render(&self) -> String {
        self.tokens.join(" ")
    }
}

/// Split a generation's flag vector into knobs.
///
/// Arity comes from the `run` registry, the same table the campaign built these
/// flags through, so a value can never be mistaken for a flag or a flag for a
/// value — including the `=`-only optional-value forms, which carry their value
/// in one token.
fn split_knobs(flags: &[String]) -> Result<Vec<Knob>, CliError> {
    let mut knobs = Vec::new();
    let mut index = 0;
    while index < flags.len() {
        let token = &flags[index];
        let name = token.split('=').next().unwrap_or(token);
        let arity = help::flag_arity("run", name).ok_or_else(|| {
            CliError(format!(
                "recorded generation flag {token:?} is not a `run` flag; this out-dir was written \
                 by a different cargo-patina version"
            ))
        })?;
        let mut tokens = vec![token.clone()];
        if matches!(arity, help::Value::Required(..)) && !token.contains('=') {
            index += 1;
            let value = flags.get(index).ok_or_else(|| {
                CliError(format!(
                    "recorded generation flag {token:?} has no value; this out-dir is corrupt"
                ))
            })?;
            tokens.push(value.clone());
        }
        index += 1;
        knobs.push(Knob { tokens });
    }
    Ok(knobs)
}

/// Verdicts already observed for knob vectors, keyed by the flag tokens the
/// child run would receive.
type KnobMemo = std::collections::HashMap<Vec<String>, bool>;

/// Patina's knob oracle: run the candidate flag vector as a fresh seeded child
/// and require the marker.
///
/// The child is spelled by the campaign's own generation runner, so a candidate
/// is judged by the same execution the campaign judged: same scrubbed
/// environment, same pinned reports, same wall-clock backstop.
struct KnobOracle {
    self_exe: PathBuf,
    artifact: PathBuf,
    seed: u64,
    /// Invocation shape every candidate keeps (`--harness`, the pre-run gate).
    pinned: Vec<String>,
    guest_args: Vec<String>,
    timeout_secs: u64,
    marker: Marker,
    jobs: usize,
    runs: AtomicU64,
}

impl KnobOracle {
    /// The full child-`run` flag vector for a knob subset.
    fn flags(&self, knobs: &[Knob]) -> Vec<String> {
        let mut flags = self.pinned.clone();
        for knob in knobs {
            flags.extend(knob.tokens.iter().cloned());
        }
        flags
    }

    /// Run one candidate, optionally keeping its trace, and report whether the
    /// marker survived.
    fn run(&self, knobs: &[Knob], record: Option<&Path>) -> Result<bool, CliError> {
        self.runs.fetch_add(1, Ordering::Relaxed);
        let scratch = tempfile::tempdir().map_err(|error| {
            CliError(format!("failed to create a candidate directory: {error}"))
        })?;
        let scratch_trace = scratch.path().join("candidate.patina");
        let trace_path = record.unwrap_or(&scratch_trace);
        let run = crate::campaign::run_reduced_generation(
            &self.self_exe,
            &self.artifact,
            self.seed,
            &self.flags(knobs),
            trace_path,
            &self.guest_args,
            self.timeout_secs,
        )?;
        let (stdout, stderr) = run.streams();
        // A candidate that had to be killed never reached its own verdict, so it
        // is rejected rather than read for a marker it may have printed on the
        // way to hanging.
        Ok(!run.timed_out() && self.marker.preserved(stdout, stderr))
    }

    /// The verdict for one knob vector, from the memo when it has been run
    /// before.
    fn judge(&self, knobs: &[Knob], memo: &mut KnobMemo) -> Result<bool, CliError> {
        let key = self.flags(knobs);
        if let Some(verdict) = memo.get(&key) {
            return Ok(*verdict);
        }
        let verdict = self.run(knobs, None)?;
        memo.insert(key, verdict);
        Ok(verdict)
    }

    /// Verdicts for a whole sweep of candidates, `jobs` at a time.
    fn judge_all(
        &self,
        candidates: &[Vec<Knob>],
        memo: &mut KnobMemo,
    ) -> Result<Vec<bool>, CliError> {
        let mut verdicts = vec![false; candidates.len()];
        let mut pending: Vec<usize> = Vec::new();
        for (index, candidate) in candidates.iter().enumerate() {
            match memo.get(&self.flags(candidate)) {
                Some(verdict) => verdicts[index] = *verdict,
                None => pending.push(index),
            }
        }
        for window in pending.chunks(self.jobs.max(1)) {
            let bundle: Vec<&Vec<Knob>> = window.iter().map(|index| &candidates[*index]).collect();
            let observed = judge_concurrently(&bundle, |knobs| {
                self.run(knobs, None)
                    .map_err(|error| io::Error::other(error.0))
            })
            .map_err(|error| CliError(format!("knob candidate run failed: {error}")))?;
            for (index, verdict) in window.iter().zip(observed) {
                verdicts[*index] = verdict;
                memo.insert(self.flags(&candidates[*index]), verdict);
            }
        }
        Ok(verdicts)
    }
}

/// Delta-debug a generation's fault-knob vector.
///
/// A sweep judges every single-knob removal, then drops *every* knob whose
/// removal individually preserved the failure and re-verifies the combined
/// candidate before keeping it: two knobs can each be individually removable and
/// jointly required, so the combined drop is a speculation the oracle has to
/// confirm. When it does not confirm, the sweep falls back to accepting in scan
/// order — the first removable knob only — which is exactly what a
/// one-at-a-time search would have done. The result is therefore decided by scan
/// order and never by which candidate finished first, at any `--jobs`.
fn reduce_knobs(
    oracle: &KnobOracle,
    knobs: &[Knob],
    memo: &mut KnobMemo,
) -> Result<Vec<Knob>, CliError> {
    let mut current = knobs.to_vec();
    while !current.is_empty() {
        let candidates: Vec<Vec<Knob>> = (0..current.len())
            .map(|dropped| {
                let mut candidate = current.clone();
                candidate.remove(dropped);
                candidate
            })
            .collect();
        let verdicts = oracle.judge_all(&candidates, memo)?;
        let removable: Vec<usize> = verdicts
            .iter()
            .enumerate()
            .filter(|(_, verdict)| **verdict)
            .map(|(index, _)| index)
            .collect();
        let Some(&first) = removable.first() else {
            break;
        };
        if removable.len() == 1 {
            current = candidates[first].clone();
            continue;
        }
        let combined: Vec<Knob> = current
            .iter()
            .enumerate()
            .filter(|(index, _)| !removable.contains(index))
            .map(|(_, knob)| knob.clone())
            .collect();
        current = if oracle.judge(&combined, memo)? {
            combined
        } else {
            candidates[first].clone()
        };
    }
    Ok(current)
}

/// The standalone command that reproduces a reduced generation.
fn repro_command(oracle: &KnobOracle, knobs: &[Knob]) -> String {
    let mut parts = vec![
        "cargo patina run".to_string(),
        oracle.artifact.display().to_string(),
        "--seed".to_string(),
        oracle.seed.to_string(),
    ];
    parts.extend(oracle.flags(knobs));
    if !oracle.guest_args.is_empty() {
        parts.push("--".to_string());
        parts.extend(oracle.guest_args.iter().cloned());
    }
    parts.join(" ")
}

// ===========================================================================
// Trace reduction
// ===========================================================================

/// Refuse a search whose oracle accepts a candidate with nothing left in it.
///
/// Deleting every reducible decision and still being told "the failure is
/// present" means the oracle is not deciding from the candidate at all. The
/// usual cause is inverted exit polarity — `minimize` reads a NON-ZERO exit as
/// "still failing", so a shell oracle that exits 0 when it finds its marker
/// inverts every verdict — and the search then "succeeds" by deleting the whole
/// trace. One oracle call turns that silently useless result into a loud one.
///
/// A bundle whose emptied form does not validate is skipped rather than forced:
/// the guard exists to catch an inverted oracle, not to invent a candidate the
/// search would never propose.
fn reject_inverted_polarity<O: FailureOracle>(
    bundle: &TraceBundle,
    timeline: Option<&str>,
    whole_bundle: bool,
    oracle: &mut O,
    memo: &mut CandidateMemo,
) -> Result<(), CliError>
where
    O::Error: std::fmt::Display,
{
    let mut empty = bundle.clone();
    for (index, target) in empty.timelines.iter_mut().enumerate() {
        let selected = if whole_bundle {
            true
        } else {
            match timeline {
                Some(id) => target.id == id,
                None => index == 0,
            }
        };
        if selected {
            target.decisions.clear();
        }
    }
    if empty == *bundle || empty.validate().is_err() {
        return Ok(());
    }
    // The memo is the caller's, so this verdict is not paid for twice if the
    // search proposes the same candidate later.
    let accepted = judge_with_memo(&empty, oracle, memo)
        .map_err(|error| CliError(format!("trace minimization failed: {error}")))?;
    if !accepted {
        return Ok(());
    }
    Err(CliError(format!(
        "refusing to minimize: the oracle reports that the failure is still present in a candidate \
         with every reducible decision deleted, so minimizing against it would \"succeed\" by \
         deleting the whole trace. The usual cause is inverted exit polarity — `cargo patina \
         minimize` treats a NON-ZERO oracle exit as \"the failure is still present\" and a zero \
         exit as \"the failure is gone\", so an oracle that exits 0 when it sees the failure \
         marker answers every candidate backwards. Check the oracle against the unmodified trace \
         ({} decisions): it must exit non-zero there.",
        bundle
            .timelines
            .iter()
            .map(|timeline| timeline.decisions.len())
            .sum::<usize>()
    )))
}

/// Delta-debug a trace to a joint fixed point of deletion and schedule
/// canonicalization.
///
/// The schedule pass runs AFTER the deletion pass has settled rather than inside
/// every round. Deletion settles on its own: the single-timeline sweeps exit
/// only on a pass that accepted nothing, which is the fixed point, so re-running
/// them to "confirm" costs a full sweep (1 864 of 9 014 oracle calls on the
/// measured workq trace) and can never accept anything. The branch-tree path is
/// the exception — it shrinks timelines in turn and shrinking a later one can
/// unblock a deletion in an earlier one — so there the delete pass is repeated
/// until it stops changing. The joint loop then re-enters only when the schedule
/// pass actually rewrote something, since only a rewrite can unblock a deletion.
fn minimize_to_fixed_point<O: FailureOracle>(
    original: &TraceBundle,
    timeline: Option<&str>,
    whole_bundle: bool,
    oracle: &mut O,
    memo: &mut CandidateMemo,
) -> Result<TraceBundle, MinimizeError<O::Error>> {
    let mut current = original.clone();
    loop {
        loop {
            let deleted = if whole_bundle {
                minimize_branch_tree_with_memo(&current, oracle, memo)?
            } else if let Some(timeline) = timeline {
                minimize_timeline_with_memo(&current, timeline, oracle, memo)?
            } else {
                minimize_main_with_memo(&current, oracle, memo)?
            };
            let settled = !whole_bundle || deleted == current;
            current = deleted;
            if settled {
                break;
            }
        }
        let scheduled = reduce_schedule_with_memo(&current, oracle, memo)?;
        if scheduled == current {
            return Ok(current);
        }
        current = scheduled;
    }
}

/// Count the decisions the reported before/after totals should cover: every
/// timeline for a whole-bundle run, one named timeline, or the main timeline.
fn event_count(bundle: &TraceBundle, timeline: Option<&str>, whole_bundle: bool) -> usize {
    if whole_bundle {
        return bundle
            .timelines
            .iter()
            .map(|timeline| timeline.decisions.len())
            .sum();
    }
    timeline
        .map_or_else(
            || bundle.timelines.first(),
            |id| bundle.timelines.iter().find(|timeline| timeline.id == id),
        )
        .map(|timeline| timeline.decisions.len())
        .unwrap_or(0)
}

/// Whether a target is minimized as a whole bundle (branch-tree policy) rather
/// than as a single timeline.
fn whole_bundle(bundle: &TraceBundle, timeline: Option<&str>, prune: bool) -> bool {
    let target_has_children = timeline.is_some_and(|id| {
        bundle
            .timelines
            .iter()
            .any(|timeline| timeline.parent.as_deref() == Some(id))
    });
    prune || target_has_children || (timeline.is_none() && bundle.timelines.len() > 1)
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

fn execute_generation(invocation: GenerationMinimize) -> Result<i32, CliError> {
    let repro = crate::campaign::generation_repro(&invocation.out_dir, invocation.generation)?;
    let marker = Marker::parse(&invocation.marker)?;
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
        marker: marker.clone(),
        jobs,
        runs: AtomicU64::new(0),
    };
    let mut memo = KnobMemo::new();

    // Nothing may be dropped before the failure is shown to reproduce from what
    // the campaign recorded: without that, every "removable" knob is only
    // evidence that the marker was never there.
    if !oracle.judge(&knobs, &mut memo)? {
        return Err(CliError(format!(
            "generation {} does not reproduce {:?} from its recorded seed and fault knobs, so \
             there is nothing to reduce. The campaign classified it {}; check the marker text \
             against that generation's output, and re-run the printed command to see what it \
             does print:\n  {}",
            invocation.generation,
            invocation.marker,
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
            "the reduced fault knobs stopped reproducing {:?} when re-run for recording; this \
             generation's failure is not a function of its seed and knobs alone, so it cannot be \
             reduced to a standalone command:\n  {command}",
            invocation.marker
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
            marker,
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
        "generation={} knobs_before={} knobs_after={} knob_runs={knob_runs} before={before} \
         after={after} oracle_runs={trace_calls} jobs={jobs} repro={} output={}",
        invocation.generation,
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
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    fn clock_event(sequence: u64, value: u64) -> patina_dst_trace::TraceEvent {
        patina_dst_trace::TraceEvent {
            sequence,
            operation: patina_dst_abi::Operation::ClockNow {
                clock: patina_dst_abi::ClockKind::Monotonic,
            },
            outcome: patina_dst_abi::Outcome::U64(value),
        }
    }

    #[test]
    fn executes_trace_minimization_with_an_external_oracle() {
        use patina_dst_abi::Outcome;
        use patina_dst_trace::RunMetadata;

        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("input.patina");
        let output = directory.path().join("output.patina");
        let decisions = (0..6)
            .map(|sequence| clock_event(sequence, if sequence == 4 { 999 } else { sequence }))
            .collect();
        TraceBundle::new(RunMetadata::new(1, "fixture"), decisions)
            .write_atomic(&input)
            .unwrap();
        execute_trace(TraceMinimize {
            trace: input,
            output: output.clone(),
            timeline: None,
            prune: false,
            jobs: Some(1),
            oracle: strings(&[
                "sh",
                "-c",
                "grep -q 999 \"$PATINA_MINIMIZE_TRACE\" && exit 1; exit 0",
            ]),
        })
        .unwrap();
        let minimized = TraceBundle::load(output).unwrap();
        assert_eq!(minimized.timelines[0].decisions.len(), 1);
        assert_eq!(
            minimized.timelines[0].decisions[0].outcome,
            Outcome::U64(999)
        );
    }

    #[test]
    fn an_oracle_with_inverted_exit_polarity_is_refused_rather_than_obeyed() {
        use patina_dst_trace::RunMetadata;

        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("input.patina");
        let output = directory.path().join("output.patina");
        let decisions = (0..6)
            .map(|sequence| clock_event(sequence, if sequence == 4 { 999 } else { sequence }))
            .collect();
        TraceBundle::new(RunMetadata::new(1, "fixture"), decisions)
            .write_atomic(&input)
            .unwrap();
        // The same oracle as above with its exits swapped — the footgun a
        // reader writes by accident, because "found the failure" reads like
        // success. Every verdict is backwards, so the search would "succeed" by
        // deleting the entire trace.
        let error = execute_trace(TraceMinimize {
            trace: input,
            output: output.clone(),
            timeline: None,
            prune: false,
            jobs: Some(1),
            oracle: strings(&[
                "sh",
                "-c",
                "grep -q 999 \"$PATINA_MINIMIZE_TRACE\" && exit 0; exit 1",
            ]),
        })
        .unwrap_err();
        assert!(
            error.0.contains("inverted exit polarity"),
            "unexpected error: {}",
            error.0
        );
        assert!(
            !output.exists(),
            "a refused minimization must not write an output trace"
        );
    }

    fn branched_input(path: &Path) {
        use patina_dst_trace::{RunMetadata, Timeline};
        // main -> keeper (holds the 999 marker plus a removable suffix) and
        // main -> disposable (dead weight the oracle never needs).
        let mut bundle = TraceBundle::new(RunMetadata::new(1, "fixture"), vec![clock_event(0, 0)]);
        bundle.timelines.push(Timeline {
            id: "keeper".into(),
            parent: Some("main".into()),
            from_sequence: Some(1),
            branch_seed: Some(7),
            decisions: vec![clock_event(1, 999), clock_event(2, 2), clock_event(3, 3)],
        });
        bundle.timelines.push(Timeline {
            id: "disposable".into(),
            parent: Some("main".into()),
            from_sequence: Some(1),
            branch_seed: Some(8),
            decisions: vec![clock_event(1, 11), clock_event(2, 12)],
        });
        bundle.write_atomic(path).unwrap();
    }

    #[test]
    fn executes_non_leaf_branch_tree_minimization_automatically() {
        use patina_dst_abi::Outcome;

        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("input.patina");
        let output = directory.path().join("output.patina");
        branched_input(&input);

        // A branched bundle with no --timeline automatically uses the branch-tree
        // policy: each timeline's safe suffix shrinks, but no subtree is dropped.
        execute_trace(TraceMinimize {
            trace: input,
            output: output.clone(),
            timeline: None,
            prune: false,
            jobs: Some(1),
            oracle: strings(&[
                "sh",
                "-c",
                "grep -q 999 \"$PATINA_MINIMIZE_TRACE\" && exit 1; exit 0",
            ]),
        })
        .unwrap();

        let minimized = TraceBundle::load(output).unwrap();
        let ids: Vec<&str> = minimized.timelines.iter().map(|t| t.id.as_str()).collect();
        assert_eq!(ids, vec!["main", "keeper", "disposable"]);
        assert_eq!(minimized.timelines[1].decisions.len(), 1);
        assert_eq!(
            minimized.timelines[1].decisions[0].outcome,
            Outcome::U64(999)
        );
        minimized.validate().unwrap();
    }

    #[test]
    fn executes_branch_pruning_dropping_and_shrinking() {
        use patina_dst_abi::Outcome;

        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("input.patina");
        let output = directory.path().join("output.patina");
        branched_input(&input);

        execute_trace(TraceMinimize {
            trace: input,
            output: output.clone(),
            timeline: None,
            prune: true,
            jobs: Some(1),
            oracle: strings(&[
                "sh",
                "-c",
                "grep -q 999 \"$PATINA_MINIMIZE_TRACE\" && exit 1; exit 0",
            ]),
        })
        .unwrap();

        let minimized = TraceBundle::load(output).unwrap();
        let ids: Vec<&str> = minimized.timelines.iter().map(|t| t.id.as_str()).collect();
        assert_eq!(ids, vec!["main", "keeper"]);
        assert_eq!(minimized.timelines[1].decisions.len(), 1);
        assert_eq!(
            minimized.timelines[1].decisions[0].outcome,
            Outcome::U64(999)
        );
    }

    #[test]
    fn executes_scenario_minimization_shrinking_seed_and_params() {
        // Smoke-check the scenario reducer end to end through a real oracle:
        // the failure needs seed >= 3 and the `keep` parameter present, both
        // read from the PATINA_* environment protocol.
        let invocation = ScenarioMinimize {
            seed: 9,
            params: [("keep", "1"), ("drop", "5")]
                .into_iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect(),
            seed_budget: 64,
            oracle: strings(&[
                "sh",
                "-c",
                "test \"$PATINA_SEED\" -ge 3 \
                 && printf '%s' \"$PATINA_PARAMS_JSON\" | grep -q '\"keep\"' && exit 1; exit 0",
            ]),
        };
        assert_eq!(execute_scenario(invocation).unwrap(), 0);
    }
    #[test]
    fn knobs_split_on_the_run_registry_arity_not_on_leading_dashes() {
        let flags = vec![
            "--swarm".to_string(),
            "--fs-short-permille".to_string(),
            "122".to_string(),
            "--fs-crash-at".to_string(),
            "write:3".to_string(),
            "--dns-entry".to_string(),
            "workq-server=127.0.0.1".to_string(),
        ];
        let knobs = split_knobs(&flags).unwrap();
        assert_eq!(
            knobs.iter().map(Knob::render).collect::<Vec<_>>(),
            vec![
                "--swarm",
                "--fs-short-permille 122",
                "--fs-crash-at write:3",
                "--dns-entry workq-server=127.0.0.1",
            ]
        );
    }

    #[test]
    fn an_unregistered_recorded_flag_is_refused_rather_than_guessed() {
        let error = split_knobs(&["--not-a-run-flag".to_string()]).unwrap_err();
        assert!(
            error.0.contains("is not a `run` flag"),
            "unexpected error: {}",
            error.0
        );
    }

    #[test]
    fn a_marker_matches_any_alternative_and_needs_a_clean_replay() {
        let marker = Marker::parse("GUEST_VIOLATION|GUEST_ABORT final-wal wal corruption").unwrap();
        assert!(marker.preserved("", "boom: GUEST_VIOLATION no-loss"));
        assert!(marker.preserved("", "GUEST_ABORT final-wal wal corruption"));
        assert!(!marker.preserved("", "clean run"));
        // The fail-open direction the probe named: the marker is present, but
        // the replay diverged after printing it.
        assert!(!marker.preserved(
            "",
            "GUEST_VIOLATION no-loss\npatina native shim fatal: trace operation mismatch"
        ));
    }

    #[test]
    fn an_empty_marker_is_refused() {
        assert!(Marker::parse("").is_err());
        assert!(Marker::parse("|").is_err());
    }
}
