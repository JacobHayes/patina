//! Trace reduction mechanics.

use super::*;

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
pub(super) fn reject_inverted_polarity<O: FailureOracle>(
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
pub(super) fn minimize_to_fixed_point<O: FailureOracle>(
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
pub(super) fn event_count(
    bundle: &TraceBundle,
    timeline: Option<&str>,
    whole_bundle: bool,
) -> usize {
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
pub(super) fn whole_bundle(bundle: &TraceBundle, timeline: Option<&str>, prune: bool) -> bool {
    let target_has_children = timeline.is_some_and(|id| {
        bundle
            .timelines
            .iter()
            .any(|timeline| timeline.parent.as_deref() == Some(id))
    });
    prune || target_has_children || (timeline.is_none() && bundle.timelines.len() > 1)
}
