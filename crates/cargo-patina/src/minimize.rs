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
}

/// The verdicts a candidate must still report for the seed generation's failure
/// to count as preserved: the `(kind, label)` pairs the campaign recognized in
/// that generation, deduplicated.
///
/// Two choices are worth naming, both narrowing what is targeted rather than
/// widening it:
///
/// * **Only failure verdicts.** A `pass` is the guest reporting that a property
///   HELD, so preserving it would be preserving a success — and a reduced
///   candidate that legitimately stops reaching some unrelated check would be
///   rejected for it. `violation` and `abort_intent` are what a failure is made
///   of ([`VerdictFacts::is_failure`]).
/// * **Containment, not equality.** A candidate must still report every target
///   verdict; verdicts it reports *in addition* are free. Equality would reject a
///   candidate over an unrelated verdict it gained or lost, which has nothing to
///   do with whether the targeted failure survived.
///
/// Every target verdict is required rather than any one of them, because the
/// failure being preserved is the whole set the campaign found: a candidate that
/// reproduces one of two broken invariants reproduces a different, weaker
/// failure. `--marker` is the escape hatch for an operator who wants a looser
/// question asked.
///
/// `detail` never participates — it is free-form per-call payload
/// ([`crate::campaign::VerdictFacts`]).
#[derive(Clone, Debug)]
struct VerdictTarget {
    wanted: Vec<VerdictFacts>,
}

impl VerdictTarget {
    /// The failure verdicts of a recorded generation, deduplicated and ordered so
    /// the rendering is stable. `None` when the generation reported none, which
    /// is the caller's cue to refuse rather than to target nothing.
    fn capture(recorded: &[VerdictFacts]) -> Option<Self> {
        let mut wanted: Vec<VerdictFacts> = recorded
            .iter()
            .filter(|verdict| verdict.is_failure())
            .cloned()
            .collect();
        wanted.sort();
        wanted.dedup();
        (!wanted.is_empty()).then_some(Self { wanted })
    }

    fn matches(&self, reported: &[VerdictFacts]) -> bool {
        self.wanted
            .iter()
            .all(|target| reported.iter().any(|verdict| verdict == target))
    }

    fn render(&self) -> String {
        self.wanted
            .iter()
            .map(|verdict| format!("{}:{}", verdict.kind, verdict.label))
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// What one candidate run produced, as an oracle sees it.
struct CandidateOutcome<'a> {
    stdout: &'a str,
    stderr: &'a str,
    /// The candidate's own verdicts, from [`crate::campaign::recognize_verdicts`]
    /// over its result envelope.
    verdicts: &'a [VerdictFacts],
}

/// The failure `minimize --generation` is preserving.
///
/// Auto-target is the default and the `--marker` text is the explicit override
/// (outcome-channel arc §4.5): the campaign already recognized what the seed
/// generation was, so re-encoding it as a substring is work the operator should
/// not have to do. `--marker` remains the level-1 escape hatch for a guest that
/// reports nothing through the verdict ABI.
#[derive(Clone, Debug)]
enum Target {
    Marker(Marker),
    Verdicts(VerdictTarget),
}

impl Target {
    /// Whether one candidate's outcome means "the failure is still present".
    ///
    /// The divergence half is load-bearing for both targets and is checked first.
    /// Either signal alone is fail-open: a candidate whose replay diverges
    /// *after* the guest reported the failure never actually reproduced it, and
    /// the search would then keep deleting on the strength of a failure it never
    /// observed.
    fn preserved(&self, outcome: &CandidateOutcome<'_>) -> bool {
        if outcome.stderr.contains(REPLAY_DIVERGENCE) || outcome.stdout.contains(REPLAY_DIVERGENCE)
        {
            return false;
        }
        match self {
            Target::Marker(marker) => {
                marker.matches(outcome.stderr) || marker.matches(outcome.stdout)
            }
            Target::Verdicts(target) => target.matches(outcome.verdicts),
        }
    }

    /// How the target reads in a refusal and in the completion line's `target=`
    /// field. Whitespace-free, because that line is a key=value stream readers
    /// split on spaces.
    fn render(&self) -> String {
        match self {
            Target::Marker(marker) => format!("marker[{}]", marker.alternatives.join("|")),
            Target::Verdicts(target) => format!("verdicts[{}]", target.render()),
        }
    }

    /// Whether judging a candidate needs its structured result envelope.
    ///
    /// A marker is looked for in the human-format output an operator would read,
    /// exactly as they typed it; a verdict target reads `verdicts[]` off the
    /// `patina.result/v1` envelope, which only `--format json` emits. Each target
    /// asks its own question through the channel that carries the answer.
    fn needs_envelope(&self) -> bool {
        matches!(self, Target::Verdicts(..))
    }
}

/// Patina's own trace oracle: replay the candidate and require the target plus a
/// clean replay.
struct ReplayOracle {
    self_exe: PathBuf,
    artifact: PathBuf,
    /// Flags a trace cannot carry (`--harness`, the pre-run gate surface), which
    /// a replay of this guest still needs.
    invocation: Vec<String>,
    target: Target,
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
        command.arg("replay").arg("--no-config");
        if self.target.needs_envelope() {
            command.arg("--format").arg("json");
        }
        command.arg(&self.artifact).arg(&path);
        for flag in &self.invocation {
            command.arg(flag);
        }
        crate::config::scrub_child_config_env(&mut command, "replay");
        let output = command.output()?;
        let child_stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let child_stderr = String::from_utf8_lossy(&output.stderr).into_owned();

        // Under `--format json` the guest's own streams travel INSIDE the
        // envelope; without one (patina refused to replay at all) the child's raw
        // streams are all there is, and a candidate that never ran reports
        // nothing. Same shape the campaign uses for its generations, so the two
        // read a child's result the same way.
        let envelope = crate::campaign::run_envelope(&child_stdout);
        let verdicts = envelope
            .as_ref()
            .map(crate::campaign::recognize_verdicts)
            .unwrap_or_default();
        let stream = |key: &str| {
            envelope
                .as_ref()
                .and_then(|envelope| envelope.get(key))
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        };
        let stdout = stream("stdout").unwrap_or(child_stdout);
        // The supervisor's own diagnostics (a divergence abort note) ride the
        // child's stderr rather than the guest's; keep both.
        let mut stderr = stream("stderr").unwrap_or_default();
        stderr.push_str(&child_stderr);
        Ok(self.target.preserved(&CandidateOutcome {
            stdout: &stdout,
            stderr: &stderr,
            verdicts: &verdicts,
        }))
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
/// and require the target.
///
/// The child is spelled by the campaign's own generation runner, so a candidate
/// is judged by the same execution the campaign judged: same scrubbed
/// environment, same pinned reports, same wall-clock backstop — and, since that
/// runner already asks for `--format json`, the same structured envelope the
/// campaign classified from.
struct KnobOracle {
    self_exe: PathBuf,
    artifact: PathBuf,
    seed: u64,
    /// Invocation shape every candidate keeps (`--harness`, the pre-run gate).
    pinned: Vec<String>,
    guest_args: Vec<String>,
    timeout_secs: u64,
    target: Target,
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
    /// target survived.
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
        // is rejected rather than read for a failure it may have announced on the
        // way to hanging.
        Ok(!run.timed_out()
            && self.target.preserved(&CandidateOutcome {
                stdout,
                stderr,
                verdicts: run.verdicts(),
            }))
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

fn execute_generation(invocation: GenerationMinimize) -> Result<i32, CliError> {
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

    fn verdict(kind: &str, label: &str) -> VerdictFacts {
        VerdictFacts {
            kind: kind.to_string(),
            label: label.to_string(),
        }
    }

    /// A candidate that reported `verdicts` and nothing else on either stream.
    fn reported(verdicts: &[VerdictFacts]) -> CandidateOutcome<'_> {
        CandidateOutcome {
            stdout: "",
            stderr: "",
            verdicts,
        }
    }

    #[test]
    fn a_marker_matches_any_alternative_and_needs_a_clean_replay() {
        let target = Target::Marker(
            Marker::parse("GUEST_VIOLATION|GUEST_ABORT final-wal wal corruption").unwrap(),
        );
        let saw = |stderr: &str| {
            target.preserved(&CandidateOutcome {
                stdout: "",
                stderr,
                verdicts: &[],
            })
        };
        assert!(saw("boom: GUEST_VIOLATION no-loss"));
        assert!(saw("GUEST_ABORT final-wal wal corruption"));
        assert!(!saw("clean run"));
        // The fail-open direction the probe named: the marker is present, but
        // the replay diverged after printing it.
        assert!(!saw(
            "GUEST_VIOLATION no-loss\npatina native shim fatal: trace operation mismatch"
        ));
    }

    #[test]
    fn an_empty_marker_is_refused() {
        assert!(Marker::parse("").is_err());
        assert!(Marker::parse("|").is_err());
    }

    #[test]
    fn a_verdict_target_captures_only_the_failure_verdicts_deduplicated() {
        // A generation's recorded stream: the same violation reported twice (the
        // ABI aggregates by label, so repeats are normal), a second violation,
        // an abort intent, and a pass.
        let target = VerdictTarget::capture(&[
            verdict("violation", "durability"),
            verdict("pass", "queue-drained"),
            verdict("violation", "durability"),
            verdict("abort_intent", "final-wal"),
            verdict("violation", "wal-integrity"),
        ])
        .expect("a generation with violations has a target");
        assert_eq!(
            target.render(),
            "abort_intent:final-wal,violation:durability,violation:wal-integrity"
        );
    }

    #[test]
    fn a_generation_whose_only_verdicts_are_passes_has_no_target() {
        assert!(
            VerdictTarget::capture(&[verdict("pass", "queue-drained")]).is_none(),
            "a `pass` reports that a property HELD; there is no failure in it to preserve"
        );
        assert!(VerdictTarget::capture(&[]).is_none());
    }

    #[test]
    fn a_verdict_target_is_containment_on_kind_and_label_not_equality() {
        let target = VerdictTarget::capture(&[
            verdict("violation", "durability"),
            verdict("violation", "wal-integrity"),
        ])
        .unwrap();
        let target = Target::Verdicts(target);

        // Exactly the target: preserved.
        assert!(target.preserved(&reported(&[
            verdict("violation", "durability"),
            verdict("violation", "wal-integrity"),
        ])));
        // Extra verdicts are free — including a PASS the seed run never had, and
        // one the reduction dropped. Only the targeted failure decides.
        assert!(target.preserved(&reported(&[
            verdict("pass", "queue-drained"),
            verdict("violation", "wal-integrity"),
            verdict("violation", "durability"),
            verdict("violation", "some-other-invariant"),
        ])));
        // A candidate that reproduces only half the failure reproduces a
        // different, weaker failure.
        assert!(!target.preserved(&reported(&[verdict("violation", "durability")])));
        // Same label, different kind: not the same verdict.
        assert!(!target.preserved(&reported(&[
            verdict("violation", "durability"),
            verdict("abort_intent", "wal-integrity"),
        ])));
        // Nothing reported at all — a candidate patina refused to replay.
        assert!(!target.preserved(&reported(&[])));
    }

    #[test]
    fn a_verdict_target_still_needs_a_clean_replay() {
        let target =
            Target::Verdicts(VerdictTarget::capture(&[verdict("violation", "no-loss")]).unwrap());
        let verdicts = [verdict("violation", "no-loss")];
        assert!(target.preserved(&reported(&verdicts)));
        // The same fail-open direction the marker path closes: the guest reported
        // the violation, then the replay diverged, so the candidate never
        // actually reproduced the failure.
        assert!(!target.preserved(&CandidateOutcome {
            stdout: "",
            stderr: "patina native shim fatal: trace operation mismatch",
            verdicts: &verdicts,
        }));
    }

    fn repro_with(class: &str, verdicts: Vec<VerdictFacts>) -> crate::campaign::GenerationRepro {
        crate::campaign::GenerationRepro {
            artifact: PathBuf::from("guest"),
            seed: 7,
            flags: Vec::new(),
            pinned: Vec::new(),
            guest_args: Vec::new(),
            timeout_secs: 30,
            class: class.to_string(),
            verdicts,
        }
    }

    #[test]
    fn an_explicit_marker_overrides_the_recorded_verdicts() {
        let repro = repro_with("VIOLATION", vec![verdict("violation", "durability")]);
        let target = generation_target(Some("GUEST_TORN"), 14, &repro).unwrap();
        assert_eq!(target.render(), "marker[GUEST_TORN]");
    }

    #[test]
    fn a_generation_with_verdicts_targets_them_without_a_marker() {
        let repro = repro_with(
            "VIOLATION",
            vec![
                verdict("violation", "durability"),
                verdict("pass", "queue-drained"),
            ],
        );
        let target = generation_target(None, 14, &repro).unwrap();
        assert_eq!(target.render(), "verdicts[violation:durability]");
    }

    #[test]
    fn a_generation_with_no_failure_verdict_and_no_marker_is_refused_naming_both_options() {
        // The classes that do not travel on the verdict channel at all: a
        // liveness wedge is a runtime finding, not a guest verdict.
        let error = generation_target(None, 14, &repro_with("LIVENESS", Vec::new())).unwrap_err();
        assert!(
            error.0.contains("no failure verdict to target")
                && error.0.contains("reported no verdict at all"),
            "unexpected error: {}",
            error.0
        );
        assert!(
            error.0.contains("patina_dst::verdict") && error.0.contains("--marker"),
            "the refusal must name BOTH ways forward: {}",
            error.0
        );

        // A guest that reports only successes is refused for its own reason,
        // rather than being minimized against a `pass`.
        let passes = generation_target(
            None,
            14,
            &repro_with("UNCLASSIFIED", vec![verdict("pass", "queue-drained")]),
        )
        .unwrap_err();
        assert!(
            passes.0.contains("pass:queue-drained") && passes.0.contains("HELD"),
            "unexpected error: {}",
            passes.0
        );
    }
}
