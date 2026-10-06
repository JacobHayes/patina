//! Timeline deletion, branch pruning, and lifecycle renumbering.

use crate::{CandidateMemo, FailureOracle, MinimizeError};
use patina_dst_trace::{LifecycleEvent, LifecycleEventKind, TraceBundle, TraceError, TraceEvent};
use std::collections::BTreeSet;

/// Delta-debug the decisions in an unbranched main timeline.
///
/// Candidates are structurally validated and accepted only when the oracle
/// confirms that the selected failure remains. Use [`minimize_timeline`] for
/// leaf suffixes in branched bundles.
pub fn minimize_main<O: FailureOracle>(
    bundle: &TraceBundle,
    oracle: &mut O,
) -> Result<TraceBundle, MinimizeError<O::Error>> {
    minimize_main_with_memo(bundle, oracle, &mut CandidateMemo::new())
}

/// [`minimize_main`] over a caller-owned [`CandidateMemo`].
///
/// The passes of a joint search propose many of the same candidates - a
/// confirmation sweep re-walks a trace it has stopped changing, a second pass
/// re-proposes what the first already judged - so sharing one memo across them
/// judges each distinct candidate once instead of once per pass.
pub fn minimize_main_with_memo<O: FailureOracle>(
    bundle: &TraceBundle,
    oracle: &mut O,
    memo: &mut CandidateMemo,
) -> Result<TraceBundle, MinimizeError<O::Error>> {
    bundle.validate().map_err(MinimizeError::Trace)?;
    if bundle.timelines.len() != 1 {
        return Err(MinimizeError::BranchedBundle);
    }
    if !memo.decide(bundle, oracle)? {
        return Err(MinimizeError::OriginalDoesNotFail);
    }

    minimize_index(bundle, 0, 0, oracle, memo)
}

/// Delta-debug the recorded suffix of a leaf timeline.
///
/// The inherited prefix and every other timeline remain byte-for-byte intact.
/// A timeline with children is rejected with
/// [`MinimizeError::TimelineHasChildren`] because shortening it could invalidate
/// descendant branch points. Callers can minimize leaves first, or use
/// [`minimize_branch_tree`] / [`minimize_branches`] to shrink a non-leaf
/// timeline's safe suffix without that risk.
pub fn minimize_timeline<O: FailureOracle>(
    bundle: &TraceBundle,
    timeline_id: &str,
    oracle: &mut O,
) -> Result<TraceBundle, MinimizeError<O::Error>> {
    minimize_timeline_with_memo(bundle, timeline_id, oracle, &mut CandidateMemo::new())
}

/// [`minimize_timeline`] over a caller-owned [`CandidateMemo`].
///
/// The passes of a joint search propose many of the same candidates - a
/// confirmation sweep re-walks a trace it has stopped changing, a second pass
/// re-proposes what the first already judged - so sharing one memo across them
/// judges each distinct candidate once instead of once per pass.
pub fn minimize_timeline_with_memo<O: FailureOracle>(
    bundle: &TraceBundle,
    timeline_id: &str,
    oracle: &mut O,
    memo: &mut CandidateMemo,
) -> Result<TraceBundle, MinimizeError<O::Error>> {
    bundle.validate().map_err(MinimizeError::Trace)?;
    let index = bundle
        .timelines
        .iter()
        .position(|timeline| timeline.id == timeline_id)
        .ok_or_else(|| MinimizeError::Trace(TraceError::UnknownTimeline(timeline_id.into())))?;
    if index == 0 && bundle.timelines.len() != 1 {
        return Err(MinimizeError::BranchedBundle);
    }
    if bundle
        .timelines
        .iter()
        .any(|timeline| timeline.parent.as_deref() == Some(timeline_id))
    {
        return Err(MinimizeError::TimelineHasChildren(timeline_id.into()));
    }
    if !memo.decide(bundle, oracle)? {
        return Err(MinimizeError::OriginalDoesNotFail);
    }
    minimize_index(bundle, index, 0, oracle, memo)
}

/// Minimize every timeline in a branched bundle under the non-leaf policy.
///
/// # Non-leaf branch minimization policy
///
/// A timeline's decisions split at each child's branch point. Everything a
/// child inherits - the parent decisions strictly before `from_sequence` - is a
/// *protected prefix* that must survive byte-for-byte, because removing or
/// renumbering it would silently rewrite the child's replayed history or push a
/// recorded branch point out of range. Everything at or beyond the largest
/// child branch point is a *reducible suffix* that no descendant depends on.
///
/// This function delta-debugs only the reducible suffix of each timeline, so a
/// non-leaf timeline (including `main`) can be shortened without invalidating
/// its descendants. Because a child's `from_sequence` is independent of its own
/// suffix length, timelines can be processed in any order; this walks them in
/// declaration order. A leaf timeline has no children, so its whole suffix is
/// reducible and the result matches [`minimize_timeline`]. The failure is
/// re-checked once up front and preserved through every accepted candidate.
pub fn minimize_branch_tree<O: FailureOracle>(
    bundle: &TraceBundle,
    oracle: &mut O,
) -> Result<TraceBundle, MinimizeError<O::Error>> {
    minimize_branch_tree_with_memo(bundle, oracle, &mut CandidateMemo::new())
}

/// [`minimize_branch_tree`] over a caller-owned [`CandidateMemo`].
///
/// The passes of a joint search propose many of the same candidates - a
/// confirmation sweep re-walks a trace it has stopped changing, a second pass
/// re-proposes what the first already judged - so sharing one memo across them
/// judges each distinct candidate once instead of once per pass.
pub fn minimize_branch_tree_with_memo<O: FailureOracle>(
    bundle: &TraceBundle,
    oracle: &mut O,
    memo: &mut CandidateMemo,
) -> Result<TraceBundle, MinimizeError<O::Error>> {
    bundle.validate().map_err(MinimizeError::Trace)?;
    if !memo.decide(bundle, oracle)? {
        return Err(MinimizeError::OriginalDoesNotFail);
    }
    let mut current = bundle.clone();
    for index in 0..current.timelines.len() {
        let protected = protected_prefix_len(&current, index);
        current = minimize_index(&current, index, protected, oracle, memo)?;
    }
    Ok(current)
}

/// Fully minimize a branched bundle: drop unneeded branch subtrees, then shrink
/// every surviving timeline's reducible suffix.
///
/// This composes [`prune_branches`] with [`minimize_branch_tree`] so a caller
/// gets both structural (whole-subtree) and per-timeline (suffix) reduction
/// under the non-leaf branch policy, with the same safety guarantees: no
/// surviving branch's inherited replay prefix is ever removed or renumbered.
pub fn minimize_branches<O: FailureOracle>(
    bundle: &TraceBundle,
    oracle: &mut O,
) -> Result<TraceBundle, MinimizeError<O::Error>> {
    let memo = &mut CandidateMemo::new();
    let pruned = prune_branches_with_memo(bundle, oracle, memo)?;
    minimize_branch_tree_with_memo(&pruned, oracle, memo)
}

/// Drop whole branch subtrees the failure does not need.
///
/// Every non-`main` timeline roots a subtree: itself plus all of its transitive
/// descendants. This tries removing each still-present subtree in turn and keeps
/// the removal whenever the oracle still fails without it, repeating to a fixed
/// point. The `main` timeline can never be dropped.
///
/// Removing a subtree whole is the only branch-structural edit that is always
/// safe: because a surviving timeline's parent is never inside a removed
/// subtree (or the survivor would itself be in that subtree), every remaining
/// branch keeps its parent and its inherited replay prefix intact. Partial
/// edits that would orphan a child or truncate an inherited prefix are never
/// attempted here; the strict single-timeline path rejects them with
/// [`MinimizeError::TimelineHasChildren`].
pub fn prune_branches<O: FailureOracle>(
    bundle: &TraceBundle,
    oracle: &mut O,
) -> Result<TraceBundle, MinimizeError<O::Error>> {
    prune_branches_with_memo(bundle, oracle, &mut CandidateMemo::new())
}

/// [`prune_branches`] over a caller-owned [`CandidateMemo`].
///
/// The passes of a joint search propose many of the same candidates - a
/// confirmation sweep re-walks a trace it has stopped changing, a second pass
/// re-proposes what the first already judged - so sharing one memo across them
/// judges each distinct candidate once instead of once per pass.
pub fn prune_branches_with_memo<O: FailureOracle>(
    bundle: &TraceBundle,
    oracle: &mut O,
    memo: &mut CandidateMemo,
) -> Result<TraceBundle, MinimizeError<O::Error>> {
    bundle.validate().map_err(MinimizeError::Trace)?;
    if !memo.decide(bundle, oracle)? {
        return Err(MinimizeError::OriginalDoesNotFail);
    }
    let mut current = bundle.clone();
    loop {
        let mut removed_any = false;
        let mut index = 1;
        while index < current.timelines.len() {
            let subtree = subtree_ids(&current, index);
            let mut candidate = current.clone();
            candidate
                .timelines
                .retain(|timeline| !subtree.contains(&timeline.id));
            candidate.validate().map_err(MinimizeError::Trace)?;
            if memo.decide(&candidate, oracle)? {
                current = candidate;
                removed_any = true;
            } else {
                index += 1;
            }
        }
        if !removed_any {
            break;
        }
    }
    Ok(current)
}

/// The ids of the subtree rooted at `root_index`: that timeline plus every
/// timeline reachable from it through parent links.
fn subtree_ids(bundle: &TraceBundle, root_index: usize) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    ids.insert(bundle.timelines[root_index].id.clone());
    loop {
        let mut added = false;
        for timeline in &bundle.timelines {
            if let Some(parent) = &timeline.parent
                && ids.contains(parent)
                && ids.insert(timeline.id.clone())
            {
                added = true;
            }
        }
        if !added {
            break;
        }
    }
    ids
}

/// The number of leading decisions in a timeline that a descendant branch
/// inherits and that must therefore be preserved. A timeline with no children
/// protects nothing; otherwise it protects every decision strictly before the
/// largest child branch point.
pub(super) fn protected_prefix_len(bundle: &TraceBundle, timeline_index: usize) -> usize {
    let timeline = &bundle.timelines[timeline_index];
    let from = timeline.from_sequence.unwrap_or(0);
    let max_child_branch = bundle
        .timelines
        .iter()
        .filter(|child| child.parent.as_deref() == Some(timeline.id.as_str()))
        .filter_map(|child| child.from_sequence)
        .max()
        .unwrap_or(from);
    (max_child_branch.saturating_sub(from) as usize).min(timeline.decisions.len())
}

/// Delta-debug one timeline's reducible region by *resuming* sweeps.
///
/// The ladder is textbook ddmin - cut the reducible window into `granularity`
/// chunks, try deleting each in order, double the granularity when a whole pass
/// is rejected, stop once a pass at granularity >= window (chunk size 1) accepts
/// nothing, which is the classic 1-minimality fixed point.
///
/// What differs from a restart-at-zero ddmin is what happens *after* an accept.
/// Restarting the scan at index 0 (and dropping back toward coarse chunks) makes
/// the cost of a deletion proportional to the whole window: on real traces
/// accepts landed every 650-850 oracle calls, 449-655 calls per productive
/// deletion, and 15-19 % of all candidates were exact repeats of ones already
/// judged. Here an accepted deletion instead leaves the scan position alone -
/// the decisions after the deleted chunk slide down into it, so the same index
/// now names new content - and the pass runs on to the end of the window. A pass
/// that accepted anything is then repeated at the same granularity, so a
/// deletion that only became possible because of an earlier one (including one
/// the sweep had already walked past) is still found; the pass repeats until it
/// accepts nothing, which is the fixed point that makes the resumed scan as
/// complete as the restarting one.
///
/// Resuming plus the verdict cache measured 3-3.7x fewer oracle calls than the
/// restarting search on two real workq traces, for byte-identical output
/// (`docs/probes/minimize-oracle-perf.md`). That measurement drove a ladder-free
/// single-decision sweep; the coarse rungs kept here cost about 15 % of a run on
/// those traces and are what shrinks a trace with genuinely removable blocks in
/// a handful of calls instead of one per decision.
fn minimize_index<O: FailureOracle>(
    bundle: &TraceBundle,
    timeline_index: usize,
    protected: usize,
    oracle: &mut O,
    memo: &mut CandidateMemo,
) -> Result<TraceBundle, MinimizeError<O::Error>> {
    let mut current = bundle.clone();
    let mut granularity = 2usize;
    loop {
        let window = reducible_window(&current, timeline_index, protected);
        if window < 2 {
            break;
        }
        let chunk_size = window.div_ceil(granularity);
        let mut reduced = false;
        let mut start = 0usize;
        loop {
            // Recomputed every step: an accepted deletion shrinks the window
            // under the scan position.
            let live = reducible_window(&current, timeline_index, protected);
            if start >= live {
                break;
            }
            // Build the candidates a one-at-a-time scan would try next if each
            // were rejected, up to the oracle's batch width. A reject leaves
            // `current` alone, so every candidate here is the same one the
            // serial scan would have built; only the first accept is kept, so
            // the accepted sequence - and therefore the result - is the serial
            // one whatever the width.
            let width = oracle.batch_width().max(1);
            let mut candidates = Vec::with_capacity(width);
            let mut starts = Vec::with_capacity(width);
            let mut cursor = start;
            while candidates.len() < width && cursor < live {
                let end = (cursor + chunk_size).min(live);
                let mut candidate = current.clone();
                candidate.timelines[timeline_index]
                    .decisions
                    .drain(protected + cursor..protected + end);
                renumber(&mut candidate, timeline_index);
                candidate.validate().map_err(MinimizeError::Trace)?;
                candidates.push(candidate);
                starts.push(cursor);
                cursor = end;
            }
            let borrowed: Vec<&TraceBundle> = candidates.iter().collect();
            match memo.first_accepted(&borrowed, oracle)? {
                Some(index) => {
                    // The scan position stays put: the decisions after the
                    // deleted chunk slide down into it.
                    start = starts[index];
                    current = candidates
                        .into_iter()
                        .nth(index)
                        .expect("accepted candidate");
                    reduced = true;
                }
                None => start = cursor,
            }
        }
        if !reduced {
            if granularity >= window {
                break;
            }
            granularity = (granularity * 2).min(window);
        }
    }
    Ok(current)
}

/// The number of decisions in a timeline that may be deleted: everything past
/// the prefix a descendant branch inherits.
fn reducible_window(bundle: &TraceBundle, timeline_index: usize, protected: usize) -> usize {
    bundle.timelines[timeline_index]
        .decisions
        .len()
        .saturating_sub(protected)
}

pub(super) fn renumber(bundle: &mut TraceBundle, timeline_index: usize) {
    let start = bundle.timelines[timeline_index].from_sequence.unwrap_or(0);
    let linear_incarnation_zero =
        is_linear_incarnation_zero(&bundle.timelines[timeline_index].lifecycle);
    let start_order = bundle.timelines[timeline_index]
        .lifecycle
        .first()
        .map(|event| event.order)
        .unwrap_or(start);
    for (index, event) in bundle.timelines[timeline_index]
        .decisions
        .iter_mut()
        .enumerate()
    {
        event.sequence = start + index as u64;
        if linear_incarnation_zero {
            event.order = start_order.saturating_add(1).saturating_add(index as u64);
            event.incarnation = 0;
        }
    }
    if linear_incarnation_zero {
        bundle.timelines[timeline_index].lifecycle =
            linear_lifecycle_from_start(start_order, &bundle.timelines[timeline_index].decisions);
    }
}

fn is_linear_incarnation_zero(lifecycle: &[LifecycleEvent]) -> bool {
    matches!(
        lifecycle,
        [
            LifecycleEvent {
                kind: LifecycleEventKind::Start { incarnation: 0 },
                ..
            },
            LifecycleEvent {
                kind: LifecycleEventKind::End { incarnation: 0 },
                ..
            },
        ]
    )
}

pub(super) fn linear_lifecycle_from_start(
    start_order: u64,
    decisions: &[TraceEvent],
) -> Vec<LifecycleEvent> {
    let end_order = decisions
        .last()
        .map(|event| event.order.saturating_add(1))
        .unwrap_or(start_order.saturating_add(1));
    vec![
        LifecycleEvent {
            order: start_order,
            kind: LifecycleEventKind::Start { incarnation: 0 },
        },
        LifecycleEvent {
            order: end_order,
            kind: LifecycleEventKind::End { incarnation: 0 },
        },
    ]
}

#[cfg(test)]
mod tests;
