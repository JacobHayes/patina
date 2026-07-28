//! Failure-preserving reducers for trace bundles and experiment inputs.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashSet;
use std::convert::Infallible;
use std::fmt;

use patina_dst_abi::{Operation, Outcome, TaskId};
use patina_dst_trace::{Timeline, TraceBundle, TraceError, TraceEvent};

pub trait FailureOracle {
    type Error;

    /// Return true only when the candidate preserves the selected failure.
    fn preserves_failure(&mut self, candidate: &TraceBundle) -> Result<bool, Self::Error>;
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

/// Delta-debug the decisions in an unbranched main timeline.
///
/// Candidates are structurally validated and accepted only when the oracle
/// confirms that the selected failure remains. Use [`minimize_timeline`] for
/// leaf suffixes in branched bundles.
pub fn minimize_main<O: FailureOracle>(
    bundle: &TraceBundle,
    oracle: &mut O,
) -> Result<TraceBundle, MinimizeError<O::Error>> {
    bundle.validate().map_err(MinimizeError::Trace)?;
    if bundle.timelines.len() != 1 {
        return Err(MinimizeError::BranchedBundle);
    }
    if !oracle
        .preserves_failure(bundle)
        .map_err(MinimizeError::Oracle)?
    {
        return Err(MinimizeError::OriginalDoesNotFail);
    }

    minimize_index(bundle, 0, 0, oracle)
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
    if !oracle
        .preserves_failure(bundle)
        .map_err(MinimizeError::Oracle)?
    {
        return Err(MinimizeError::OriginalDoesNotFail);
    }
    minimize_index(bundle, index, 0, oracle)
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
    bundle.validate().map_err(MinimizeError::Trace)?;
    if !oracle
        .preserves_failure(bundle)
        .map_err(MinimizeError::Oracle)?
    {
        return Err(MinimizeError::OriginalDoesNotFail);
    }
    let mut current = bundle.clone();
    for index in 0..current.timelines.len() {
        let protected = protected_prefix_len(&current, index);
        current = minimize_index(&current, index, protected, oracle)?;
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
    let pruned = prune_branches(bundle, oracle)?;
    minimize_branch_tree(&pruned, oracle)
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
    let mut current = prune_branches(bundle, oracle)?;
    loop {
        let before = current.clone();
        current = minimize_branch_tree(&current, oracle)?;
        current = reduce_schedule(&current, oracle)?;
        if current == before {
            break;
        }
    }
    Ok(current)
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
    bundle.validate().map_err(MinimizeError::Trace)?;
    if !oracle
        .preserves_failure(bundle)
        .map_err(MinimizeError::Oracle)?
    {
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
            if oracle
                .preserves_failure(&candidate)
                .map_err(MinimizeError::Oracle)?
            {
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
            if let Some(parent) = &timeline.parent {
                if ids.contains(parent) && ids.insert(timeline.id.clone()) {
                    added = true;
                }
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
fn protected_prefix_len(bundle: &TraceBundle, timeline_index: usize) -> usize {
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

fn minimize_index<O: FailureOracle>(
    bundle: &TraceBundle,
    timeline_index: usize,
    protected: usize,
    oracle: &mut O,
) -> Result<TraceBundle, MinimizeError<O::Error>> {
    let mut current = bundle.clone();
    let mut granularity = 2usize;
    loop {
        let window = current.timelines[timeline_index]
            .decisions
            .len()
            .saturating_sub(protected);
        if window < 2 {
            break;
        }
        let chunk_size = window.div_ceil(granularity);
        let mut reduced = false;
        let mut start = 0usize;
        while start < window {
            let end = (start + chunk_size).min(window);
            let mut candidate = current.clone();
            candidate.timelines[timeline_index]
                .decisions
                .drain(protected + start..protected + end);
            renumber(&mut candidate, timeline_index);
            candidate.validate().map_err(MinimizeError::Trace)?;
            if oracle
                .preserves_failure(&candidate)
                .map_err(MinimizeError::Oracle)?
            {
                current = candidate;
                granularity = granularity.saturating_sub(1).max(2);
                reduced = true;
                break;
            }
            start = end;
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

fn renumber(bundle: &mut TraceBundle, timeline_index: usize) {
    let start = bundle.timelines[timeline_index].from_sequence.unwrap_or(0);
    for (index, event) in bundle.timelines[timeline_index]
        .decisions
        .iter_mut()
        .enumerate()
    {
        event.sequence = start + index as u64;
    }
}

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
    bundle.validate().map_err(MinimizeError::Trace)?;
    if !oracle
        .preserves_failure(bundle)
        .map_err(MinimizeError::Oracle)?
    {
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
            changed |= collapse_switches(&mut current, index, protected, oracle)?;
            changed |= canonicalize_order(&mut current, index, protected, universe, oracle)?;
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
) -> Result<bool, MinimizeError<O::Error>> {
    let mut changed = false;
    loop {
        let positions = scheduler_positions(&current.timelines[index], protected);
        let mut collapsed = false;
        for pair in positions.windows(2) {
            let (earlier, later) = (pair[0], pair[1]);
            let (Some(earlier_task), Some(later_task)) = (
                selected_task(&current.timelines[index].decisions[earlier]),
                selected_task(&current.timelines[index].decisions[later]),
            ) else {
                continue;
            };
            if earlier_task == later_task {
                continue;
            }
            let mut candidate = current.clone();
            set_selected(
                &mut candidate.timelines[index].decisions[later],
                earlier_task,
            );
            if accept_candidate(&candidate, oracle)? {
                *current = candidate;
                changed = true;
                collapsed = true;
                break;
            }
        }
        if !collapsed {
            break;
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
) -> Result<bool, MinimizeError<O::Error>> {
    let mut changed = false;
    loop {
        let positions = scheduler_positions(&current.timelines[index], protected);
        let mut lowered = false;
        for position in positions {
            let Some(current_task) = selected_task(&current.timelines[index].decisions[position])
            else {
                continue;
            };
            for &candidate_task in ids {
                if candidate_task.0 >= current_task.0 {
                    break;
                }
                let mut candidate = current.clone();
                set_selected(
                    &mut candidate.timelines[index].decisions[position],
                    candidate_task,
                );
                if accept_candidate(&candidate, oracle)? {
                    *current = candidate;
                    changed = true;
                    lowered = true;
                    break;
                }
            }
            if lowered {
                break;
            }
        }
        if !lowered {
            break;
        }
    }
    Ok(changed)
}

/// Structurally validate a rewritten candidate, then ask the oracle whether the
/// failure survives. A rewrite only touches scheduler outcomes, so validation
/// cannot fail on a well-formed input, but it is kept for parity with the
/// delete reducers and to reject any malformed bundle before running the oracle.
fn accept_candidate<O: FailureOracle>(
    candidate: &TraceBundle,
    oracle: &mut O,
) -> Result<bool, MinimizeError<O::Error>> {
    candidate.validate().map_err(MinimizeError::Trace)?;
    oracle
        .preserves_failure(candidate)
        .map_err(MinimizeError::Oracle)
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

/// The externally varied inputs that select one deterministic run: the root
/// seed and the key/value parameters exposed through `Context::param`. Reducing
/// a scenario shrinks a reproduction toward the smallest inputs that still
/// trigger the failure, complementing the trace reducers that shrink recorded
/// decisions.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Scenario {
    pub seed: u64,
    pub params: BTreeMap<String, String>,
}

impl Scenario {
    pub fn new(seed: u64) -> Self {
        Self {
            seed,
            params: BTreeMap::new(),
        }
    }

    /// Add or replace a parameter, returning the scenario for chaining.
    pub fn with_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.params.insert(key.into(), value.into());
        self
    }
}

/// Decides whether a candidate [`Scenario`] still reproduces the failure. The
/// caller owns running the scenario (typically a fresh process); the reducers
/// only propose candidates and never touch the filesystem or spawn work.
pub trait ScenarioOracle {
    type Error;

    /// Return true only when the candidate scenario reproduces the failure.
    fn reproduces_failure(&mut self, scenario: &Scenario) -> Result<bool, Self::Error>;
}

impl<F, E> ScenarioOracle for F
where
    F: FnMut(&Scenario) -> Result<bool, E>,
{
    type Error = E;

    fn reproduces_failure(&mut self, scenario: &Scenario) -> Result<bool, Self::Error> {
        self(scenario)
    }
}

/// Reduce a scenario across all of its inputs.
///
/// The seed is canonicalized first (see [`reduce_seed`]) and the parameters are
/// then reduced (see [`reduce_params`]); the two passes repeat to a fixed point
/// so a smaller seed can unlock further parameter shrinking and vice versa.
/// `seed_budget` bounds the seed search on each pass. Returns
/// [`MinimizeError::OriginalDoesNotFail`] if the input scenario does not
/// reproduce the failure.
pub fn reduce_scenario<O: ScenarioOracle>(
    scenario: &Scenario,
    oracle: &mut O,
    seed_budget: u64,
) -> Result<Scenario, MinimizeError<O::Error>> {
    require_reproduces(scenario, oracle)?;
    let mut current = scenario.clone();
    loop {
        let before = current.clone();
        current = reduce_seed(&current, oracle, seed_budget)?;
        current = reduce_params(&current, oracle)?;
        if current == before {
            break;
        }
    }
    Ok(current)
}

/// Canonicalize the root seed toward the smallest value that still reproduces
/// the failure.
///
/// Seeds have no structural order - any change yields an unrelated run - so this
/// is a bounded ascending *search*, not a delta-debug: it tries seeds `0, 1, 2,
/// …` below the current seed and returns the first that reproduces, trying at
/// most `budget` candidates. If none reproduces within the budget the original
/// failing scenario is returned unchanged. A `budget` of zero leaves the seed
/// untouched.
pub fn reduce_seed<O: ScenarioOracle>(
    scenario: &Scenario,
    oracle: &mut O,
    budget: u64,
) -> Result<Scenario, MinimizeError<O::Error>> {
    require_reproduces(scenario, oracle)?;
    let mut tried = 0u64;
    let mut candidate_seed = 0u64;
    while candidate_seed < scenario.seed && tried < budget {
        let mut candidate = scenario.clone();
        candidate.seed = candidate_seed;
        if oracle
            .reproduces_failure(&candidate)
            .map_err(MinimizeError::Oracle)?
        {
            return Ok(candidate);
        }
        tried += 1;
        candidate_seed += 1;
    }
    Ok(scenario.clone())
}

/// Reduce the parameter map while preserving the failure.
///
/// Each pass first drops any parameter that is not needed to reproduce the
/// failure, then shrinks each surviving value toward a simpler form (numeric
/// values toward zero, any value toward the empty string). Passes repeat until a
/// full pass changes nothing, yielding a locally minimal set of parameters and
/// values. Returns [`MinimizeError::OriginalDoesNotFail`] if the input scenario
/// does not reproduce the failure.
pub fn reduce_params<O: ScenarioOracle>(
    scenario: &Scenario,
    oracle: &mut O,
) -> Result<Scenario, MinimizeError<O::Error>> {
    require_reproduces(scenario, oracle)?;
    let mut current = scenario.clone();
    loop {
        let mut changed = false;
        for key in current.params.keys().cloned().collect::<Vec<_>>() {
            let mut candidate = current.clone();
            candidate.params.remove(&key);
            if oracle
                .reproduces_failure(&candidate)
                .map_err(MinimizeError::Oracle)?
            {
                current = candidate;
                changed = true;
            }
        }
        for key in current.params.keys().cloned().collect::<Vec<_>>() {
            let value = current.params[&key].clone();
            for smaller in shrink_value(&value) {
                let mut candidate = current.clone();
                candidate.params.insert(key.clone(), smaller);
                if oracle
                    .reproduces_failure(&candidate)
                    .map_err(MinimizeError::Oracle)?
                {
                    current = candidate;
                    changed = true;
                    break;
                }
            }
        }
        if !changed {
            break;
        }
    }
    Ok(current)
}

/// Ordered replacement candidates for a parameter value, simplest first and
/// never equal to the original: numeric values step toward zero by halving,
/// and any non-empty value can collapse to the empty string.
fn shrink_value(value: &str) -> Vec<String> {
    let mut candidates = Vec::new();
    if let Ok(number) = value.parse::<u64>() {
        if number != 0 {
            candidates.push("0".to_string());
            let mut half = number / 2;
            while half > 0 {
                candidates.push(half.to_string());
                half /= 2;
            }
        }
    }
    if !value.is_empty() {
        candidates.push(String::new());
    }
    let mut seen = HashSet::new();
    candidates
        .into_iter()
        .filter(|candidate| candidate != value && seen.insert(candidate.clone()))
        .collect()
}

fn require_reproduces<O: ScenarioOracle>(
    scenario: &Scenario,
    oracle: &mut O,
) -> Result<(), MinimizeError<O::Error>> {
    if oracle
        .reproduces_failure(scenario)
        .map_err(MinimizeError::Oracle)?
    {
        Ok(())
    } else {
        Err(MinimizeError::OriginalDoesNotFail)
    }
}

#[derive(Debug)]
pub enum MinimizeError<E = Infallible> {
    Trace(TraceError),
    Oracle(E),
    OriginalDoesNotFail,
    BranchedBundle,
    TimelineHasChildren(String),
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
mod tests {
    use patina_dst_abi::{ClockKind, Operation, Outcome};
    use patina_dst_trace::{RunMetadata, Timeline, TraceEvent};

    use super::*;

    #[test]
    fn delta_debugging_preserves_only_the_failure_inducing_decision() {
        let mut decisions = (0..10)
            .map(|sequence| TraceEvent {
                sequence,
                operation: Operation::ClockNow {
                    clock: ClockKind::Monotonic,
                },
                outcome: Outcome::U64(sequence),
            })
            .collect::<Vec<_>>();
        decisions[6].outcome = Outcome::U64(999);
        let bundle = TraceBundle::new(RunMetadata::new(1, "fixture"), decisions);
        let mut calls = 0;
        let minimized = minimize_main(&bundle, &mut |candidate: &TraceBundle| {
            calls += 1;
            Ok::<_, Infallible>(
                candidate.timelines[0]
                    .decisions
                    .iter()
                    .any(|event| event.outcome == Outcome::U64(999)),
            )
        })
        .unwrap();
        assert!(calls > 1);
        assert_eq!(minimized.timelines[0].decisions.len(), 1);
        assert_eq!(minimized.timelines[0].decisions[0].sequence, 0);
        assert_eq!(
            minimized.timelines[0].decisions[0].outcome,
            Outcome::U64(999)
        );
    }

    #[test]
    fn minimizes_a_leaf_branch_without_changing_its_inherited_prefix() {
        let main = (0..3)
            .map(|sequence| TraceEvent {
                sequence,
                operation: Operation::ClockNow {
                    clock: ClockKind::Monotonic,
                },
                outcome: Outcome::U64(sequence),
            })
            .collect::<Vec<_>>();
        let mut bundle = TraceBundle::new(RunMetadata::new(1, "fixture"), main.clone());
        bundle.timelines.push(Timeline {
            id: "failure".into(),
            parent: Some("main".into()),
            from_sequence: Some(2),
            branch_seed: Some(9),
            decisions: (2..8)
                .map(|sequence| TraceEvent {
                    sequence,
                    operation: Operation::ClockNow {
                        clock: ClockKind::Monotonic,
                    },
                    outcome: Outcome::U64(if sequence == 6 { 999 } else { sequence }),
                })
                .collect(),
        });
        let minimized = minimize_timeline(&bundle, "failure", &mut |candidate: &TraceBundle| {
            Ok::<_, Infallible>(
                candidate.timelines[1]
                    .decisions
                    .iter()
                    .any(|event| event.outcome == Outcome::U64(999)),
            )
        })
        .unwrap();
        assert_eq!(minimized.timelines[0].decisions, main);
        assert_eq!(minimized.timelines[1].decisions.len(), 1);
        assert_eq!(minimized.timelines[1].decisions[0].sequence, 2);
        assert_eq!(minimized.resolved_timeline("failure").unwrap().len(), 3);
    }

    #[test]
    fn refuses_to_minimize_a_timeline_with_children() {
        let mut bundle = TraceBundle::new(RunMetadata::new(1, "fixture"), Vec::new());
        bundle.timelines.push(Timeline {
            id: "parent".into(),
            parent: Some("main".into()),
            from_sequence: Some(0),
            branch_seed: Some(2),
            decisions: Vec::new(),
        });
        bundle.timelines.push(Timeline {
            id: "child".into(),
            parent: Some("parent".into()),
            from_sequence: Some(0),
            branch_seed: Some(3),
            decisions: Vec::new(),
        });
        let error = minimize_timeline(&bundle, "parent", &mut |_candidate: &TraceBundle| {
            Ok::<_, Infallible>(true)
        })
        .unwrap_err();
        assert!(matches!(error, MinimizeError::TimelineHasChildren(_)));
    }

    #[test]
    fn refuses_to_minimize_when_the_original_does_not_fail() {
        let bundle = TraceBundle::new(RunMetadata::new(1, "fixture"), Vec::new());
        let result = minimize_main(&bundle, &mut |_candidate: &TraceBundle| {
            Ok::<_, Infallible>(false)
        });
        assert!(matches!(result, Err(MinimizeError::OriginalDoesNotFail)));
    }

    fn clock_event(sequence: u64, value: u64) -> TraceEvent {
        TraceEvent {
            sequence,
            operation: Operation::ClockNow {
                clock: ClockKind::Monotonic,
            },
            outcome: Outcome::U64(value),
        }
    }

    fn sched_event(sequence: u64, task: u64) -> TraceEvent {
        TraceEvent {
            sequence,
            operation: Operation::SchedulerNext,
            outcome: Outcome::OptionalTask(Some(TaskId(task))),
        }
    }

    fn selected_tasks(timeline: &Timeline) -> Vec<u64> {
        timeline
            .decisions
            .iter()
            .filter_map(|event| match (&event.operation, &event.outcome) {
                (Operation::SchedulerNext, Outcome::OptionalTask(Some(task))) => Some(task.0),
                _ => None,
            })
            .collect()
    }

    fn switch_count(tasks: &[u64]) -> usize {
        tasks.windows(2).filter(|pair| pair[0] != pair[1]).count()
    }

    #[test]
    fn tree_minimization_preserves_a_non_leaf_protected_prefix_and_shrinks_its_suffix() {
        // A three-level chain main -> mid -> leaf. `mid` is a non-leaf timeline
        // that `leaf` branches from at sequence 4, so mid's first two decisions
        // (sequences 2 and 3) are an inherited, protected prefix, and mid's
        // remaining decisions (sequences 4..8) are a reducible suffix no
        // descendant depends on. The failure marker sits in the protected prefix.
        let mut bundle = TraceBundle::new(
            RunMetadata::new(1, "fixture"),
            vec![clock_event(0, 0), clock_event(1, 1)],
        );
        bundle.timelines.push(Timeline {
            id: "mid".into(),
            parent: Some("main".into()),
            from_sequence: Some(2),
            branch_seed: Some(7),
            decisions: vec![
                clock_event(2, 999),
                clock_event(3, 3),
                clock_event(4, 4),
                clock_event(5, 5),
                clock_event(6, 6),
                clock_event(7, 7),
            ],
        });
        bundle.timelines.push(Timeline {
            id: "leaf".into(),
            parent: Some("mid".into()),
            from_sequence: Some(4),
            branch_seed: Some(11),
            decisions: vec![clock_event(4, 40), clock_event(5, 50)],
        });
        let mid_protected = bundle.timelines[1].decisions[..2].to_vec();
        let leaf_inherited = bundle.resolved_timeline("leaf").unwrap()[..4].to_vec();

        // The failure is present when leaf's inherited prefix still carries the
        // 999 marker; nothing in any reducible suffix matters.
        let minimized = minimize_branch_tree(&bundle, &mut |candidate: &TraceBundle| {
            Ok::<_, Infallible>(
                candidate
                    .resolved_timeline("leaf")
                    .unwrap()
                    .iter()
                    .take(4)
                    .any(|event| event.outcome == Outcome::U64(999)),
            )
        })
        .unwrap();

        // main is entirely inherited by mid, so it is untouched.
        assert_eq!(
            minimized.timelines[0].decisions,
            vec![clock_event(0, 0), clock_event(1, 1)]
        );
        // mid's protected prefix survives byte-for-byte while its suffix shrank.
        let mid = &minimized.timelines[1];
        assert_eq!(mid.decisions[..2].to_vec(), mid_protected);
        assert_eq!(mid.decisions[0].outcome, Outcome::U64(999));
        assert!(mid.decisions.len() >= 2 && mid.decisions.len() < 6);
        // The recorded branch point stays valid and leaf's inherited prefix is
        // unchanged after its parent shrank.
        assert_eq!(minimized.timelines[2].from_sequence, Some(4));
        minimized.validate().unwrap();
        assert_eq!(
            minimized.resolved_timeline("leaf").unwrap()[..4].to_vec(),
            leaf_inherited
        );
    }

    #[test]
    fn tree_minimization_matches_leaf_minimization_for_a_single_timeline() {
        let mut decisions: Vec<TraceEvent> = (0..8).map(|s| clock_event(s, s)).collect();
        decisions[5].outcome = Outcome::U64(999);
        let bundle = TraceBundle::new(RunMetadata::new(1, "fixture"), decisions);
        let mut oracle = |candidate: &TraceBundle| {
            Ok::<_, Infallible>(
                candidate.timelines[0]
                    .decisions
                    .iter()
                    .any(|event| event.outcome == Outcome::U64(999)),
            )
        };
        let tree = minimize_branch_tree(&bundle, &mut oracle).unwrap();
        assert_eq!(tree.timelines[0].decisions.len(), 1);
        assert_eq!(tree.timelines[0].decisions[0].outcome, Outcome::U64(999));
    }

    fn branched_bundle() -> TraceBundle {
        // main -> keeper (carries the 999 marker) and main -> disposable, plus
        // disposable -> grandchild so pruning must drop a whole subtree.
        let mut bundle = TraceBundle::new(
            RunMetadata::new(1, "fixture"),
            vec![clock_event(0, 0), clock_event(1, 1)],
        );
        bundle.timelines.push(Timeline {
            id: "keeper".into(),
            parent: Some("main".into()),
            from_sequence: Some(2),
            branch_seed: Some(7),
            decisions: vec![clock_event(2, 999)],
        });
        bundle.timelines.push(Timeline {
            id: "disposable".into(),
            parent: Some("main".into()),
            from_sequence: Some(2),
            branch_seed: Some(8),
            decisions: vec![clock_event(2, 2), clock_event(3, 3)],
        });
        bundle.timelines.push(Timeline {
            id: "grandchild".into(),
            parent: Some("disposable".into()),
            from_sequence: Some(3),
            branch_seed: Some(9),
            decisions: vec![clock_event(3, 30)],
        });
        bundle
    }

    #[test]
    fn prune_branches_drops_a_whole_orphan_subtree_the_oracle_does_not_need() {
        let bundle = branched_bundle();
        // The failure lives only in `keeper`; the `disposable` subtree is dead
        // weight and should be removed together with its `grandchild`.
        let pruned = prune_branches(&bundle, &mut |candidate: &TraceBundle| {
            Ok::<_, Infallible>(candidate.timelines.iter().any(|timeline| {
                timeline
                    .decisions
                    .iter()
                    .any(|event| event.outcome == Outcome::U64(999))
            }))
        })
        .unwrap();
        let ids: Vec<&str> = pruned.timelines.iter().map(|t| t.id.as_str()).collect();
        assert_eq!(ids, vec!["main", "keeper"]);
        pruned.validate().unwrap();
    }

    #[test]
    fn prune_branches_keeps_a_subtree_the_failure_still_needs() {
        let bundle = branched_bundle();
        // The failure now depends on `grandchild`, so neither it nor its parent
        // `disposable` may be dropped; `keeper` still goes.
        let pruned = prune_branches(&bundle, &mut |candidate: &TraceBundle| {
            Ok::<_, Infallible>(candidate.timelines.iter().any(|t| t.id == "grandchild"))
        })
        .unwrap();
        let ids: Vec<&str> = pruned.timelines.iter().map(|t| t.id.as_str()).collect();
        assert_eq!(ids, vec!["main", "disposable", "grandchild"]);
        pruned.validate().unwrap();
    }

    #[test]
    fn minimize_branches_prunes_then_shrinks_surviving_suffixes() {
        let mut bundle = branched_bundle();
        // Give `keeper` a long removable suffix after its marker so the combined
        // pass both drops `disposable`/`grandchild` and shrinks `keeper`.
        bundle.timelines[1].decisions = vec![
            clock_event(2, 999),
            clock_event(3, 3),
            clock_event(4, 4),
            clock_event(5, 5),
        ];
        let minimized = minimize_branches(&bundle, &mut |candidate: &TraceBundle| {
            Ok::<_, Infallible>(candidate.timelines.iter().any(|timeline| {
                timeline
                    .decisions
                    .iter()
                    .any(|event| event.outcome == Outcome::U64(999))
            }))
        })
        .unwrap();
        let ids: Vec<&str> = minimized.timelines.iter().map(|t| t.id.as_str()).collect();
        assert_eq!(ids, vec!["main", "keeper"]);
        assert_eq!(minimized.timelines[1].decisions.len(), 1);
        assert_eq!(
            minimized.timelines[1].decisions[0].outcome,
            Outcome::U64(999)
        );
        minimized.validate().unwrap();
    }

    #[test]
    fn schedule_reduction_collapses_a_ping_pong_into_longer_runs() {
        let bundle = TraceBundle::new(
            RunMetadata::new(1, "fixture"),
            vec![
                sched_event(0, 1),
                sched_event(1, 2),
                sched_event(2, 1),
                sched_event(3, 2),
            ],
        );
        assert_eq!(switch_count(&selected_tasks(&bundle.timelines[0])), 3);
        // Order-independent marker: both tasks must still be scheduled somewhere,
        // so the reducer can batch runs but cannot drop a task entirely.
        let reduced = reduce_schedule(&bundle, &mut |candidate: &TraceBundle| {
            let tasks = selected_tasks(&candidate.timelines[0]);
            Ok::<_, Infallible>(tasks.contains(&1) && tasks.contains(&2))
        })
        .unwrap();
        let tasks = selected_tasks(&reduced.timelines[0]);
        assert!(tasks.contains(&1) && tasks.contains(&2), "marker preserved");
        assert!(
            switch_count(&tasks) < 3,
            "context switches reduced from a ping-pong: {tasks:?}"
        );
        // Positions and count never change; only scheduler outcomes are rewritten.
        assert_eq!(reduced.timelines[0].decisions.len(), 4);
        reduced.validate().unwrap();
    }

    #[test]
    fn schedule_reduction_prefers_the_lowest_task_id() {
        // The higher id is scheduled first; an id- and order-independent marker
        // (two scheduling decisions) lets canonicalization pull every point down
        // to the lowest observed id, overriding switch-collapsing's own bias
        // toward extending the earlier - here higher - task's run.
        let bundle = TraceBundle::new(
            RunMetadata::new(1, "fixture"),
            vec![sched_event(0, 2), sched_event(1, 1)],
        );
        let reduced = reduce_schedule(&bundle, &mut |candidate: &TraceBundle| {
            Ok::<_, Infallible>(selected_tasks(&candidate.timelines[0]).len() == 2)
        })
        .unwrap();
        assert_eq!(selected_tasks(&reduced.timelines[0]), vec![1, 1]);
    }

    #[test]
    fn schedule_reduction_never_rewrites_a_protected_prefix() {
        // main is a non-leaf timeline; `child` branches at sequence 2, so main's
        // first two scheduling points are an inherited, protected prefix that must
        // survive byte-for-byte even though the all-accepting marker would
        // tolerate rewriting them.
        let mut bundle = TraceBundle::new(
            RunMetadata::new(1, "fixture"),
            vec![
                sched_event(0, 2),
                sched_event(1, 2),
                sched_event(2, 2),
                sched_event(3, 1),
            ],
        );
        bundle.timelines.push(Timeline {
            id: "child".into(),
            parent: Some("main".into()),
            from_sequence: Some(2),
            branch_seed: Some(5),
            decisions: vec![sched_event(2, 2)],
        });
        let protected_before = bundle.timelines[0].decisions[..2].to_vec();
        let reduced = reduce_schedule(&bundle, &mut |_candidate: &TraceBundle| {
            Ok::<_, Infallible>(true)
        })
        .unwrap();
        // The protected prefix is untouched...
        assert_eq!(
            reduced.timelines[0].decisions[..2].to_vec(),
            protected_before
        );
        // ...while the reducible suffix was canonicalized toward the lowest id.
        assert_eq!(
            selected_tasks(&reduced.timelines[0])[2..].to_vec(),
            vec![1, 1]
        );
        reduced.validate().unwrap();
    }

    #[test]
    fn schedule_reduction_leaves_the_bundle_unchanged_when_every_rewrite_is_rejected() {
        let bundle = TraceBundle::new(
            RunMetadata::new(1, "fixture"),
            vec![sched_event(0, 1), sched_event(1, 2), sched_event(2, 1)],
        );
        // The oracle demands the exact original schedule, so the up-front check
        // passes but no rewrite is ever accepted.
        let original = selected_tasks(&bundle.timelines[0]);
        let reduced = reduce_schedule(&bundle, &mut |candidate: &TraceBundle| {
            Ok::<_, Infallible>(selected_tasks(&candidate.timelines[0]) == original)
        })
        .unwrap();
        assert_eq!(reduced, bundle);
    }

    #[test]
    fn schedule_reduction_reaches_a_fixed_point() {
        let bundle = TraceBundle::new(
            RunMetadata::new(1, "fixture"),
            vec![
                sched_event(0, 1),
                sched_event(1, 2),
                sched_event(2, 1),
                sched_event(3, 2),
            ],
        );
        let mut marker = |candidate: &TraceBundle| {
            let tasks = selected_tasks(&candidate.timelines[0]);
            Ok::<_, Infallible>(tasks.contains(&1) && tasks.contains(&2))
        };
        let once = reduce_schedule(&bundle, &mut marker).unwrap();
        let twice = reduce_schedule(&once, &mut marker).unwrap();
        assert_eq!(
            once, twice,
            "a second pass changes nothing at the fixed point"
        );
    }

    #[test]
    fn schedule_reduction_rejects_an_input_that_does_not_fail() {
        let bundle = TraceBundle::new(RunMetadata::new(1, "fixture"), vec![sched_event(0, 1)]);
        let result = reduce_schedule(&bundle, &mut |_c: &TraceBundle| Ok::<_, Infallible>(false));
        assert!(matches!(result, Err(MinimizeError::OriginalDoesNotFail)));
    }

    #[test]
    fn minimize_all_shrinks_and_canonicalizes_together() {
        // A single main timeline with a ping-pong schedule followed by removable
        // filler clock events; the failure needs the 999 marker and both tasks.
        let bundle = TraceBundle::new(
            RunMetadata::new(1, "fixture"),
            vec![
                sched_event(0, 1),
                sched_event(1, 2),
                sched_event(2, 1),
                clock_event(3, 999),
                clock_event(4, 4),
                clock_event(5, 5),
            ],
        );
        let minimized = minimize_all(&bundle, &mut |candidate: &TraceBundle| {
            let tasks = selected_tasks(&candidate.timelines[0]);
            let marker = candidate.timelines[0]
                .decisions
                .iter()
                .any(|event| event.outcome == Outcome::U64(999));
            Ok::<_, Infallible>(marker && tasks.contains(&1) && tasks.contains(&2))
        })
        .unwrap();
        minimized.validate().unwrap();
        let tasks = selected_tasks(&minimized.timelines[0]);
        assert!(tasks.contains(&1) && tasks.contains(&2), "marker preserved");
        // The filler clock events are shrunk away while the 999 marker stays.
        assert!(
            minimized.timelines[0]
                .decisions
                .iter()
                .any(|event| event.outcome == Outcome::U64(999))
        );
        assert!(
            !minimized.timelines[0]
                .decisions
                .iter()
                .any(|event| event.outcome == Outcome::U64(4) || event.outcome == Outcome::U64(5))
        );
        // ...and the schedule is canonicalized to at most one context switch.
        assert!(
            switch_count(&tasks) <= 1,
            "schedule canonicalized: {tasks:?}"
        );
    }

    #[test]
    fn reduce_params_drops_unneeded_keys_and_keeps_the_load_bearing_one() {
        let scenario = Scenario::new(0)
            .with_param("a", "1")
            .with_param("b", "2")
            .with_param("c", "3");
        let reduced = reduce_params(&scenario, &mut |candidate: &Scenario| {
            Ok::<_, Infallible>(candidate.params.get("b").map(String::as_str) == Some("2"))
        })
        .unwrap();
        assert_eq!(reduced.params.len(), 1);
        assert_eq!(reduced.params.get("b").map(String::as_str), Some("2"));
    }

    #[test]
    fn reduce_params_shrinks_a_numeric_value_toward_the_failure_boundary() {
        let scenario = Scenario::new(0).with_param("n", "100");
        let reduced = reduce_params(&scenario, &mut |candidate: &Scenario| {
            let value = candidate
                .params
                .get("n")
                .map_or(0, |v| v.parse().unwrap_or(0));
            Ok::<_, Infallible>(value >= 10)
        })
        .unwrap();
        let value: u64 = reduced.params["n"].parse().unwrap();
        assert!(value >= 10, "must still reproduce the failure");
        assert!(value < 100, "must have shrunk from the original");
    }

    #[test]
    fn reduce_seed_finds_the_smallest_reproducing_seed_within_budget() {
        let scenario = Scenario::new(9);
        let reduced = reduce_seed(
            &scenario,
            &mut |candidate: &Scenario| Ok::<_, Infallible>(candidate.seed >= 3),
            64,
        )
        .unwrap();
        assert_eq!(reduced.seed, 3);
    }

    #[test]
    fn reduce_seed_keeps_the_original_when_the_budget_is_exhausted() {
        let scenario = Scenario::new(100);
        let reduced = reduce_seed(
            &scenario,
            &mut |candidate: &Scenario| Ok::<_, Infallible>(candidate.seed >= 50),
            10,
        )
        .unwrap();
        assert_eq!(reduced.seed, 100);
    }

    #[test]
    fn reduce_scenario_canonicalizes_the_seed_and_the_parameters_together() {
        let scenario = Scenario::new(5)
            .with_param("keep", "1")
            .with_param("drop", "9");
        let reduced = reduce_scenario(
            &scenario,
            &mut |candidate: &Scenario| {
                Ok::<_, Infallible>(candidate.seed >= 2 && candidate.params.contains_key("keep"))
            },
            64,
        )
        .unwrap();
        assert_eq!(reduced.seed, 2);
        assert_eq!(reduced.params.len(), 1);
        assert!(reduced.params.contains_key("keep"));
    }

    #[test]
    fn scenario_reducers_reject_an_input_that_does_not_fail() {
        let scenario = Scenario::new(1).with_param("a", "1");
        let result = reduce_params(&scenario, &mut |_candidate: &Scenario| {
            Ok::<_, Infallible>(false)
        });
        assert!(matches!(result, Err(MinimizeError::OriginalDoesNotFail)));
    }
}
