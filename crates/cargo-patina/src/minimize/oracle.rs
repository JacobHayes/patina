//! Failure targets and replay/external oracles.

use super::*;

// ===========================================================================
// Oracles
// ===========================================================================

/// How many candidates patina evaluates at once when it owns the oracle.
///
/// Half the CPUs. Measured replay throughput on a 10-CPU host climbs 62 -> 303
/// replays/s from 1 to 8 workers and only reaches 323 at 12, so the last
/// doublings buy little, and a minimize run shares the machine with whatever
/// else the operator is doing.
pub(super) fn default_jobs() -> usize {
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
pub(super) struct Marker {
    alternatives: Vec<String>,
}

impl Marker {
    pub(super) fn parse(text: &str) -> Result<Self, CliError> {
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
pub(super) struct VerdictTarget {
    wanted: Vec<VerdictFacts>,
}

impl VerdictTarget {
    /// The failure verdicts of a recorded generation, deduplicated and ordered so
    /// the rendering is stable. `None` when the generation reported none, which
    /// is the caller's cue to refuse rather than to target nothing.
    pub(super) fn capture(recorded: &[VerdictFacts]) -> Option<Self> {
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
pub(super) struct CandidateOutcome<'a> {
    pub(super) stdout: &'a str,
    pub(super) stderr: &'a str,
    /// The candidate's own verdicts, from [`crate::campaign::recognize_verdicts`]
    /// over its result envelope.
    pub(super) verdicts: &'a [VerdictFacts],
}

/// The failure `minimize --generation` is preserving.
///
/// Auto-target is the default and the `--marker` text is the explicit override
/// (outcome-channel arc §4.5): the campaign already recognized what the seed
/// generation was, so re-encoding it as a substring is work the operator should
/// not have to do. `--marker` remains the level-1 escape hatch for a guest that
/// reports nothing through the verdict ABI.
#[derive(Clone, Debug)]
pub(super) enum Target {
    Marker(Marker),
    Verdicts(VerdictTarget),
}

impl Target {
    /// Whether one candidate's outcome still shows the failure. For a replayed
    /// candidate this is half the question: [`ReplayOracle::judge`] first
    /// requires evidence that the replay followed the candidate at all.
    pub(super) fn preserved(&self, outcome: &CandidateOutcome<'_>) -> bool {
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
    pub(super) fn render(&self) -> String {
        match self {
            Target::Marker(marker) => format!("marker[{}]", marker.alternatives.join("|")),
            Target::Verdicts(target) => format!("verdicts[{}]", target.render()),
        }
    }
}

/// Patina's own trace oracle: replay the candidate and require the target plus a
/// replay that followed it.
pub(super) struct ReplayOracle {
    pub(super) self_exe: PathBuf,
    pub(super) artifact: PathBuf,
    /// Flags a trace cannot carry (`--harness`, the pre-run gate surface), which
    /// a replay of this guest still needs.
    pub(super) invocation: Vec<String>,
    pub(super) target: Target,
    /// How the recording the candidates are cut from ended
    /// ([`crate::campaign::RunFacts::exit_status`]).
    pub(super) recorded_exit: String,
    pub(super) jobs: usize,
    pub(super) calls: AtomicU64,
}

impl ReplayOracle {
    pub(super) fn judge(&self, candidate: &TraceBundle) -> io::Result<bool> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        // A directory per candidate, so concurrent candidates share no path.
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("candidate.patina");
        candidate.write_atomic(&path).map_err(io::Error::other)?;
        let mut command = Command::new(&self.self_exe);
        // The envelope is the only channel that carries the replay's typed
        // divergence, and the one the knob phase judged the same target on.
        command
            .arg("replay")
            .arg("--no-config")
            .arg("--format")
            .arg("json");
        command.arg(&self.artifact).arg(&path);
        for flag in &self.invocation {
            command.arg(flag);
        }
        crate::config::scrub_child_config_env(&mut command, "replay");
        crate::supervisor_identity::expect_this_supervisor(&mut command)
            .map_err(|error| io::Error::other(error.to_string()))?;
        let output = command.output()?;
        let child_stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let child_stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        if let Some(refusal) =
            crate::supervisor_identity::supervisor_mismatch(&child_stdout, &child_stderr)
        {
            return Err(io::Error::other(format!(
                "stopping: a candidate replay ran another supervisor build than this \
                 reduction. {refusal}"
            )));
        }

        // A candidate counts only on positive evidence that its replay followed
        // it: a run envelope (patina refused to replay at all otherwise), no
        // divergence on the typed facts channel, and the exit the recording
        // reached. No text on a stream can stand in for that: a replay that
        // stops before its trace does ends in an ordinary exit and prints no
        // shim-fatal line.
        let Some(envelope) = crate::campaign::run_envelope(&child_stdout) else {
            return Ok(false);
        };
        let facts = crate::campaign::child_facts(Some(&envelope), output.status);
        if !replay_followed(&facts, &self.recorded_exit) {
            return Ok(false);
        }
        let stream = |key: &str| {
            envelope
                .get(key)
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
        };
        Ok(self.target.preserved(&CandidateOutcome {
            stdout: stream("stdout"),
            stderr: &candidate_stderr(stream("stderr"), &output.stderr),
            verdicts: &facts.verdicts,
        }))
    }
}

/// Whether a replay's facts show it followed its candidate: no divergence on
/// the typed facts channel, and the exit status the recording reached.
fn replay_followed(facts: &crate::campaign::RunFacts, recorded_exit: &str) -> bool {
    !facts.replay_diverged && facts.exit_status() == recorded_exit
}

/// A replayed candidate's stderr: the guest's, then the supervisor's own
/// diagnostics, which ride the child's stderr, starting on a line of their own.
fn candidate_stderr(guest: &str, supervisor: &[u8]) -> String {
    let mut stderr = guest.as_bytes().to_vec();
    output::end_guest_line(&mut stderr);
    stderr.extend_from_slice(supervisor);
    String::from_utf8_lossy(&stderr).into_owned()
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
pub(super) struct ExternalOracle {
    pub(crate) command: Vec<OsString>,
    pub(crate) jobs: usize,
    pub(crate) calls: AtomicU64,
}

impl ExternalOracle {
    pub(super) fn judge(&self, candidate: &TraceBundle) -> io::Result<bool> {
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
pub(super) fn judge_concurrently<T: Sync>(
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

#[cfg(test)]
mod tests;
