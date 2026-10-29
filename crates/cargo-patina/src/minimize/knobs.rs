//! Fault-knob reduction and reproduction commands.

use super::*;

// ===========================================================================
// Fault-knob reduction
// ===========================================================================

/// One knob of a generation's flag vector: a flag and the tokens that belong to
/// it (`["--fs-short-permille", "122"]`, `["--swarm"]`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Knob {
    tokens: Vec<String>,
}

impl Knob {
    pub(super) fn render(&self) -> String {
        self.tokens.join(" ")
    }
}

/// Split a generation's flag vector into knobs.
///
/// Arity comes from the `run` registry, the same table the campaign built these
/// flags through, so a value can never be mistaken for a flag or a flag for a
/// value — including the `=`-only optional-value forms, which carry their value
/// in one token.
pub(super) fn split_knobs(flags: &[String]) -> Result<Vec<Knob>, CliError> {
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
pub(super) type KnobMemo = std::collections::HashMap<Vec<String>, bool>;

/// Patina's knob oracle: run the candidate flag vector as a fresh seeded child
/// and require the target, under the refusal the unreduced vector's run ended
/// under, if any.
///
/// The child is spelled by the campaign's own generation runner, so a candidate
/// is judged by the same execution the campaign judged: same scrubbed
/// environment, same pinned reports, same wall-clock backstop — and, since that
/// runner already asks for `--format json`, the same structured envelope the
/// campaign classified from.
pub(super) struct KnobOracle {
    pub(super) self_exe: PathBuf,
    pub(super) artifact: PathBuf,
    pub(super) seed: u64,
    /// Invocation shape every candidate keeps (`--harness`, the pre-run gate).
    pub(super) pinned: Vec<String>,
    pub(super) guest_args: Vec<String>,
    pub(super) timeout_secs: u64,
    pub(super) target: Target,
    /// How the unreduced vector's run ended, once [`KnobOracle::establish`]
    /// has run it ([`candidate_counts`] says what a candidate is held to).
    pub(super) original: Option<RunEnd>,
    pub(super) jobs: usize,
    pub(super) runs: AtomicU64,
}

/// How a knob candidate's run ended.
#[derive(Clone, Debug)]
pub(super) struct RunEnd {
    /// [`crate::campaign::RunFacts::exit_status`].
    pub(super) exit: String,
    /// Patina's refusal class from the result envelope, when it refused.
    pub(super) refusal: Option<String>,
}

/// Whether a knob candidate still shows the generation's failure: it finished
/// (a killed candidate never reached its own verdict, whatever it announced on
/// the way to hanging), it shows the target, and it ended under the refusal
/// class the unreduced run ended under (`original`; none to match before that
/// run is established). A candidate that shows the target and then ends under
/// another refusal — the guest, no longer steered by a fault, reaching
/// something patina refuses — reached a different failure. The guest's own exit code is
/// free: a fresh seeded run that keeps the target may legitimately exit
/// differently once a fault is gone.
pub(super) fn candidate_counts(
    end: &RunEnd,
    timed_out: bool,
    shows_target: bool,
    original: Option<&RunEnd>,
) -> bool {
    !timed_out && shows_target && original.is_none_or(|original| original.refusal == end.refusal)
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

    /// Run the unreduced knob vector, the evidence every reduction rests on,
    /// and report whether it shows the target. When it does, the refusal it
    /// ended under is the one every candidate must end under.
    pub(super) fn establish(
        &mut self,
        knobs: &[Knob],
        memo: &mut KnobMemo,
    ) -> Result<bool, CliError> {
        // The unreduced run is held to no run of its own.
        self.original = None;
        self.original = self.run_keeping(knobs, None)?;
        let shown = self.original.is_some();
        memo.insert(self.flags(knobs), shown);
        Ok(shown)
    }

    /// Run one candidate and report whether the target survived.
    fn run(&self, knobs: &[Knob]) -> Result<bool, CliError> {
        Ok(self.run_keeping(knobs, None)?.is_some())
    }

    /// Run a knob subset into `trace`, the recording a trace reduction starts
    /// from: how the run ended, when the target survived it.
    pub(super) fn record(&self, knobs: &[Knob], trace: &Path) -> Result<Option<String>, CliError> {
        Ok(self.run_keeping(knobs, Some(trace))?.map(|end| end.exit))
    }

    /// Run one candidate, optionally keeping its trace: how it ended, or
    /// `None` when the target did not survive or the run ended under another
    /// refusal than the unreduced one.
    fn run_keeping(
        &self,
        knobs: &[Knob],
        record: Option<&Path>,
    ) -> Result<Option<RunEnd>, CliError> {
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
        let end = RunEnd {
            exit: run.exit_status(),
            refusal: run.refusal().map(str::to_string),
        };
        let shows_target = self.target.preserved(&CandidateOutcome {
            stdout,
            stderr,
            verdicts: run.verdicts(),
        });
        let counts = candidate_counts(&end, run.timed_out(), shows_target, self.original.as_ref());
        Ok(counts.then_some(end))
    }

    /// The verdict for one knob vector, from the memo when it has been run
    /// before.
    pub(super) fn judge(&self, knobs: &[Knob], memo: &mut KnobMemo) -> Result<bool, CliError> {
        let key = self.flags(knobs);
        if let Some(verdict) = memo.get(&key) {
            return Ok(*verdict);
        }
        let verdict = self.run(knobs)?;
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
                self.run(knobs).map_err(|error| io::Error::other(error.0))
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
pub(super) fn reduce_knobs(
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
pub(super) fn repro_command(oracle: &KnobOracle, knobs: &[Knob]) -> String {
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
    // The oracle ran it as an isolated child from these flags alone.
    crate::cli::without_env_defaults(parts.join(" "))
}

#[cfg(test)]
mod tests;
