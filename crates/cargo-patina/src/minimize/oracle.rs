//! Failure targets and concurrent candidate judging.

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
    /// Whether one candidate's outcome still shows the failure.
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
