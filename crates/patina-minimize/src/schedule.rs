//! Failure-preserving schedule rewriting and canonicalization.

use crate::trace_reduce::protected_prefix_len;
use crate::*;
use patina_dst_abi::{Operation, Outcome, TaskId};
use patina_dst_trace::{Timeline, TraceBundle, TraceEvent};
use std::collections::BTreeSet;

/// Canonicalize the schedule of a bundle toward a simpler, more readable
/// interleaving while preserving the failure.
///
/// Every other reducer in this crate only *deletes* decisions. This one only
/// *rewrites* the outcome of [`Operation::SchedulerNext`] events - the forced
/// task selections that drive a replayed schedule - and never changes the
/// position, count, operation, or any non-scheduler outcome of a decision.
/// Deleting decisions stays the job of the shrink reducers; this pass runs at
/// the same recorded length and merely reorders which task each surviving
/// scheduling point runs.
///
/// # Passes
///
/// Applied per timeline, each repeated to a fixed point, then the whole set
/// repeated to a fixed point:
///
/// 1. *Switch-collapsing*: for each adjacent pair of scheduling points that
///    select different tasks, try rewriting the later one to the earlier task,
///    extending the earlier task's run and removing a context switch. Repeated,
///    this batches a ping-pong interleaving into longer contiguous runs.
/// 2. *Canonical ordering*: for each scheduling point, try rewriting its
///    selection to the lowest already-observed task id the failure still
///    tolerates, biasing the trace toward "run the lowest task id first".
///
/// # Safety and honesty about what gets accepted
///
/// A rewritten selection is only a *candidate*. It is structurally validated
/// and then handed to the oracle, exactly like a delta-debug deletion, and is
/// kept only if the oracle confirms the failure survives. This pass never
/// reasons about whether a forced selection is legal at replay time; it relies
/// entirely on the oracle to reject one that is not. Under the runtime's strict
/// replay a rewritten [`Operation::SchedulerNext`] forces `scheduler.select` of
/// the new task, and every following task-tagged operation (a recorded
/// `TaskYield`/`TaskComplete` still naming the *original* task) must continue to
/// match; a rewrite the recorded operation stream still depends on therefore
/// fails replay and is discarded. Consequently, against a strict full-replay
/// oracle this pass is a sound no-op, and it produces real simplification only
/// when the selected failure is genuinely schedule-order-independent - for
/// example a marker-based oracle, or a program whose recorded operations do not
/// depend on which task ran. The candidate set is bounded (only ids the run
/// already scheduled, only rewrites toward a lower or earlier-running task) and
/// deterministic, so the search terminates without RNG.
///
/// Branched bundles follow the same protected-prefix policy as
/// [`minimize_branch_tree`]: a scheduling point inside a child's inherited
/// prefix (see `protected_prefix_len`) is never rewritten, so no descendant's
/// replayed history is silently altered. The failure is re-checked once up
/// front and preserved through every accepted candidate.
pub fn reduce_schedule<O: FailureOracle>(
    bundle: &TraceBundle,
    oracle: &mut O,
) -> Result<TraceBundle, MinimizeError<O::Error>> {
    reduce_schedule_with_memo(bundle, oracle, &mut CandidateMemo::new())
}

/// [`reduce_schedule`] over a caller-owned [`CandidateMemo`].
///
/// The passes of a joint search propose many of the same candidates - a
/// confirmation sweep re-walks a trace it has stopped changing, a second pass
/// re-proposes what the first already judged - so sharing one memo across them
/// judges each distinct candidate once instead of once per pass.
pub fn reduce_schedule_with_memo<O: FailureOracle>(
    bundle: &TraceBundle,
    oracle: &mut O,
    memo: &mut CandidateMemo,
) -> Result<TraceBundle, MinimizeError<O::Error>> {
    bundle.validate().map_err(MinimizeError::Trace)?;
    if !memo.decide(bundle, oracle)? {
        return Err(MinimizeError::OriginalDoesNotFail);
    }
    // The candidate ids canonicalization may rewrite toward are fixed from the
    // *original* trace: only tasks the run actually scheduled, per timeline.
    // Capturing them up front lets canonicalization pull a scheduling point back
    // to a lower id even after switch-collapsing extended a higher-id run over
    // it, so the joint fixed point is the lowest-id-first schedule the failure
    // tolerates rather than whichever ordering a pass happened to reach first.
    // Reducing never deletes or renumbers decisions, so these positions and the
    // protected-prefix boundary stay valid across the whole search.
    let universes: Vec<Vec<TaskId>> = (0..bundle.timelines.len())
        .map(|index| {
            scheduled_ids(
                &bundle.timelines[index],
                protected_prefix_len(bundle, index),
            )
        })
        .collect();
    let mut current = bundle.clone();
    loop {
        let mut changed = false;
        for (index, universe) in universes.iter().enumerate() {
            let protected = protected_prefix_len(&current, index);
            changed |= collapse_switches(&mut current, index, protected, oracle, memo)?;
            changed |= canonicalize_order(&mut current, index, protected, universe, oracle, memo)?;
        }
        if !changed {
            break;
        }
    }
    Ok(current)
}

/// Repeatedly merge adjacent differing scheduling points in one timeline's
/// reducible region, rewriting the later selection to the earlier task, until
/// no such collapse is accepted. Returns whether anything changed.
fn collapse_switches<O: FailureOracle>(
    current: &mut TraceBundle,
    index: usize,
    protected: usize,
    oracle: &mut O,
    memo: &mut CandidateMemo,
) -> Result<bool, MinimizeError<O::Error>> {
    let mut changed = false;
    loop {
        // The rewrites this pass would try, in scan order. Only the (position,
        // task) pairs are enumerated up front - a candidate bundle is cloned
        // one window at a time, so a long timeline does not materialize a
        // thousand copies of itself.
        let positions = scheduler_positions(&current.timelines[index], protected);
        let rewrites: Vec<(usize, TaskId)> = positions
            .windows(2)
            .filter_map(|pair| {
                let (earlier, later) = (pair[0], pair[1]);
                let earlier_task = selected_task(&current.timelines[index].decisions[earlier])?;
                let later_task = selected_task(&current.timelines[index].decisions[later])?;
                (earlier_task != later_task).then_some((later, earlier_task))
            })
            .collect();
        let accepted = first_accepted_rewrite(current, index, &rewrites, oracle, memo)?;
        match accepted {
            Some(candidate) => {
                *current = candidate;
                changed = true;
            }
            None => break,
        }
    }
    Ok(changed)
}

/// Repeatedly lower the task selected at each scheduling point in one
/// timeline's reducible region toward the smallest already-observed id the
/// oracle still accepts, until no further lowering is accepted. Returns whether
/// anything changed.
fn canonicalize_order<O: FailureOracle>(
    current: &mut TraceBundle,
    index: usize,
    protected: usize,
    ids: &[TaskId],
    oracle: &mut O,
    memo: &mut CandidateMemo,
) -> Result<bool, MinimizeError<O::Error>> {
    let mut changed = false;
    loop {
        // Every lowering this pass would try, flattened in scan order: each
        // scheduling point paired with each already-observed id below the one it
        // currently selects.
        let positions = scheduler_positions(&current.timelines[index], protected);
        let mut rewrites: Vec<(usize, TaskId)> = Vec::new();
        for position in positions {
            let Some(current_task) = selected_task(&current.timelines[index].decisions[position])
            else {
                continue;
            };
            for &candidate_task in ids {
                if candidate_task.0 >= current_task.0 {
                    break;
                }
                rewrites.push((position, candidate_task));
            }
        }
        let accepted = first_accepted_rewrite(current, index, &rewrites, oracle, memo)?;
        match accepted {
            Some(candidate) => {
                *current = candidate;
                changed = true;
            }
            None => break,
        }
    }
    Ok(changed)
}

/// Try `rewrites` against one timeline in scan order and return the first
/// candidate the oracle accepts.
///
/// Candidates are cloned one window at a time (the oracle's batch width), so a
/// batching oracle sees the same speculative window the delete reducer gives it
/// while memory stays proportional to the width rather than to the number of
/// rewrites a pass considers. A rejected rewrite leaves the base bundle
/// untouched, so every candidate in a window is exactly the one a one-at-a-time
/// scan would have built next.
fn first_accepted_rewrite<O: FailureOracle>(
    current: &TraceBundle,
    index: usize,
    rewrites: &[(usize, TaskId)],
    oracle: &mut O,
    memo: &mut CandidateMemo,
) -> Result<Option<TraceBundle>, MinimizeError<O::Error>> {
    let width = oracle.batch_width().max(1);
    let mut base = 0usize;
    while base < rewrites.len() {
        let end = (base + width).min(rewrites.len());
        let mut candidates = Vec::with_capacity(end - base);
        for &(position, task) in &rewrites[base..end] {
            let mut candidate = current.clone();
            set_selected(&mut candidate.timelines[index].decisions[position], task);
            // A rewrite only touches scheduler outcomes, so validation cannot
            // fail on a well-formed input, but it is kept for parity with the
            // delete reducers and to reject any malformed bundle before the
            // oracle runs.
            candidate.validate().map_err(MinimizeError::Trace)?;
            candidates.push(candidate);
        }
        let borrowed: Vec<&TraceBundle> = candidates.iter().collect();
        if let Some(accepted) = memo.first_accepted(&borrowed, oracle)? {
            return Ok(Some(
                candidates
                    .into_iter()
                    .nth(accepted)
                    .expect("accepted candidate"),
            ));
        }
        base = end;
    }
    Ok(None)
}

/// The decision indices at or beyond `protected` that are schedule decisions
/// selecting a concrete task, i.e. the rewrite-eligible scheduling points.
fn scheduler_positions(timeline: &Timeline, protected: usize) -> Vec<usize> {
    timeline
        .decisions
        .iter()
        .enumerate()
        .skip(protected)
        .filter_map(|(index, event)| selected_task(event).map(|_| index))
        .collect()
}

/// The task a decision forced, or `None` for any non-scheduler event or a
/// recorded "no task" (all-idle) scheduling point. Rewrites move only between
/// concrete selections and never disturb a `None` decision.
fn selected_task(event: &TraceEvent) -> Option<TaskId> {
    match (&event.operation, &event.outcome) {
        (Operation::SchedulerNext, Outcome::OptionalTask(task)) => *task,
        _ => None,
    }
}

/// Overwrite a schedule decision's forced selection. Only ever called on an
/// index [`selected_task`] already reported as a concrete selection.
fn set_selected(event: &mut TraceEvent, task: TaskId) {
    event.outcome = Outcome::OptionalTask(Some(task));
}

/// The distinct task ids selected within a timeline's reducible region,
/// ascending. Canonicalization draws candidates only from this set, so it never
/// invents a task the run never scheduled.
fn scheduled_ids(timeline: &Timeline, protected: usize) -> Vec<TaskId> {
    scheduler_positions(timeline, protected)
        .into_iter()
        .filter_map(|index| selected_task(&timeline.decisions[index]).map(|task| task.0))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(TaskId)
        .collect()
}

#[cfg(test)]
mod tests;
