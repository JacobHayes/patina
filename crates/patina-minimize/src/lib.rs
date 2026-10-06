//! Failure-preserving reducers for trace bundles and experiment inputs.

use patina_dst_trace::{TraceBundle, TraceError};
use std::convert::Infallible;
use std::fmt;

mod memo;
mod scenario;
mod schedule;
mod trace_reduce;

pub use memo::{CandidateMemo, judge_with_memo};
pub use scenario::{Scenario, ScenarioOracle, reduce_params, reduce_scenario, reduce_seed};
pub use schedule::{reduce_schedule, reduce_schedule_with_memo};
pub use trace_reduce::{
    minimize_branch_tree, minimize_branch_tree_with_memo, minimize_branches, minimize_main,
    minimize_main_with_memo, minimize_timeline, minimize_timeline_with_memo, prune_branches,
    prune_branches_with_memo,
};

pub trait FailureOracle {
    type Error;

    /// Return true only when the candidate preserves the selected failure.
    fn preserves_failure(&mut self, candidate: &TraceBundle) -> Result<bool, Self::Error>;

    /// How many candidates this oracle wants handed to it at once.
    ///
    /// The reducers ask before each scan step and offer a window of at most this
    /// many candidates, in the exact order a one-at-a-time scan would have tried
    /// them. The default 1 keeps every oracle that does not override this on the
    /// serial path.
    fn batch_width(&self) -> usize {
        1
    }

    /// Judge a whole window of candidates, one verdict per candidate in order.
    ///
    /// The window is *speculative*: it holds the candidates a serial scan would
    /// try if each earlier one were rejected, so an implementation may evaluate
    /// them concurrently. The reducer keeps only the first accepted candidate in
    /// scan order and re-uses the rest as cached verdicts, which is what makes a
    /// widened window produce byte-identical output to a serial one rather than
    /// output that depends on which worker finished first.
    ///
    /// An implementation that runs candidates concurrently owes the same
    /// isolation the serial path gets for free: a candidate must be judged from
    /// its own bytes alone, with no shared mutable path between concurrent
    /// evaluations.
    fn judge_batch(&mut self, candidates: &[&TraceBundle]) -> Result<Vec<bool>, Self::Error> {
        let mut verdicts = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            verdicts.push(self.preserves_failure(candidate)?);
        }
        Ok(verdicts)
    }
}

impl<F, E> FailureOracle for F
where
    F: FnMut(&TraceBundle) -> Result<bool, E>,
{
    type Error = E;

    fn preserves_failure(&mut self, candidate: &TraceBundle) -> Result<bool, Self::Error> {
        self(candidate)
    }
}

/// How a verdict reads in a diagnostic: an oracle answers whether the selected
/// failure is still present.
fn verdict_word(verdict: bool) -> &'static str {
    if verdict {
        "still failing"
    } else {
        "no longer failing"
    }
}

/// The full trace-minimization pipeline: drop unneeded branch subtrees, then
/// delta-debug every surviving timeline's reducible suffix and canonicalize its
/// schedule, repeating the shrink/schedule pair to a *joint* fixed point.
///
/// This extends [`minimize_branches`] with [`reduce_schedule`] so a caller gets
/// structural, per-timeline, and scheduling reduction in one call. The shrink
/// and schedule passes are interleaved to a joint fixed point because they can
/// unblock each other: deleting a run can remove a context switch that then
/// lets the schedule canonicalize, and canonicalizing a schedule can expose a
/// now-redundant run for deletion. Each sub-pass re-checks the failure up front
/// and preserves it through every accepted candidate, so the same safety
/// guarantees hold: no surviving branch's inherited replay prefix is removed,
/// renumbered, or rewritten.
pub fn minimize_all<O: FailureOracle>(
    bundle: &TraceBundle,
    oracle: &mut O,
) -> Result<TraceBundle, MinimizeError<O::Error>> {
    minimize_all_with_memo(bundle, oracle, &mut CandidateMemo::new())
}

/// [`minimize_all`] over a caller-owned [`CandidateMemo`].
///
/// The schedule pass runs once the deletion pass has settled rather than inside
/// every round: only a schedule rewrite can unblock a further deletion, so a
/// round that rewrote nothing has already proved the joint fixed point and the
/// confirmation sweep it used to cost accepts nothing by construction.
pub fn minimize_all_with_memo<O: FailureOracle>(
    bundle: &TraceBundle,
    oracle: &mut O,
    memo: &mut CandidateMemo,
) -> Result<TraceBundle, MinimizeError<O::Error>> {
    let mut current = prune_branches_with_memo(bundle, oracle, memo)?;
    loop {
        // The branch-tree pass shrinks timelines in turn, and shrinking a later
        // one can unblock a deletion in an earlier one, so it is repeated until
        // it stops changing.
        loop {
            let deleted = minimize_branch_tree_with_memo(&current, oracle, memo)?;
            let settled = deleted == current;
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

#[derive(Debug)]
pub enum MinimizeError<E = Infallible> {
    Trace(TraceError),
    Oracle(E),
    OriginalDoesNotFail,
    BranchedBundle,
    TimelineHasChildren(String),
    /// A sampled re-run of a cached candidate contradicted the verdict the same
    /// bytes produced earlier: the oracle is not a function of its input, so
    /// every accept and reject in the run is suspect.
    NondeterministicOracle {
        digest: String,
        cached: bool,
        observed: bool,
    },
    /// A batching oracle answered a different number of candidates than it was
    /// asked about, so no verdict can be matched to a candidate.
    OracleBatchArity {
        asked: usize,
        answered: usize,
    },
}

impl<E: fmt::Display> fmt::Display for MinimizeError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Trace(error) => error.fmt(f),
            Self::Oracle(error) => write!(f, "failure oracle failed: {error}"),
            Self::OriginalDoesNotFail => {
                f.write_str("the original trace does not preserve the selected failure")
            }
            Self::BranchedBundle => {
                f.write_str("main-timeline minimization does not accept branched bundles")
            }
            Self::TimelineHasChildren(timeline) => write!(
                f,
                "refusing to shrink timeline {timeline}: it has child branches whose inherited \
                 replay prefix would be silently invalidated; minimize leaf timelines first, or \
                 use branch-tree minimization to shrink only the safe suffix"
            ),
            Self::NondeterministicOracle {
                digest,
                cached,
                observed,
            } => write!(
                f,
                "the failure oracle is nondeterministic: candidate sha256:{digest} was judged \
                 {} when first run and {} on a sampled re-run of the identical bytes; \
                 minimization reuses verdicts per candidate and cannot trust an oracle that \
                 answers differently for the same input - make the oracle decide from the \
                 candidate alone (no shared state, no wall-clock or timeout-dependent verdict, \
                 no unseeded randomness) and re-run",
                verdict_word(*cached),
                verdict_word(*observed),
            ),
            Self::OracleBatchArity { asked, answered } => write!(
                f,
                "the failure oracle was asked to judge {asked} candidates and answered {answered}: \
                 a batching oracle must return exactly one verdict per candidate, in order"
            ),
        }
    }
}

impl<E> std::error::Error for MinimizeError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Trace(error) => Some(error),
            Self::Oracle(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests;
