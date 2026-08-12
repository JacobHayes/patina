//! Failure-preserving reducers for trace bundles and experiment inputs.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::collections::HashSet;
use std::convert::Infallible;
use std::fmt;

use patina_dst_abi::{Operation, Outcome, TaskId};
use patina_dst_trace::{Timeline, TraceBundle, TraceError, TraceEvent};
use sha2::{Digest, Sha256};

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

/// One in this many cache hits is re-run against the real oracle, so a
/// nondeterministic oracle is surfaced rather than silently trusted.
const VERIFICATION_PERIOD: u64 = 16;

/// A verdict already observed for one candidate, plus how many times the cached
/// answer has been served, which paces the sampled re-verification.
#[derive(Clone, Copy, Debug)]
struct CachedVerdict {
    verdict: bool,
    hits: u64,
}

/// Remembers the oracle's verdict for each distinct candidate of one
/// minimization.
///
/// The first cache hit of a run is always re-verified and one in
/// [`VERIFICATION_PERIOD`] hits after that, so the soundness guard below can
/// never sit unused on a short run.
///
/// A reducer proposes the same candidate repeatedly - a sweep that re-tries a
/// position after an unrelated deletion, a confirmation pass that re-walks a
/// trace it has stopped changing, an up-front failure re-check shared by several
/// passes. Every such repeat is byte-for-byte the same input the oracle already
/// judged (measured at 15-19 % of all calls on real workq traces, 55-63 % inside
/// a confirmation round), so the verdict can be reused. Candidates are keyed by
/// the SHA-256 of [`TraceBundle::to_bytes`] - the exact canonical bytes a caller
/// hands its oracle - so two candidates share a verdict only when the oracle
/// cannot tell them apart.
///
/// # Soundness
///
/// Reuse is sound exactly as far as the oracle is a function of its candidate.
/// Rather than assume that, the memo re-runs a deterministic sample of its cache
/// hits and refuses the whole minimization with
/// [`MinimizeError::NondeterministicOracle`] if a re-run disagrees with the
/// cached verdict: a flaky oracle invalidates every result built on top of it,
/// so it is reported loudly instead of being averaged over. The sample is
/// derived from the candidate digest and the hit ordinal - never from a clock or
/// an RNG - so a repeated run re-verifies exactly the same hits and the search
/// stays reproducible.
#[derive(Debug)]
pub struct CandidateMemo {
    verdicts: HashMap<[u8; 32], CachedVerdict>,
    hits: u64,
    misses: u64,
    verifications: u64,
    verification_period: u64,
}

impl Default for CandidateMemo {
    fn default() -> Self {
        Self::new()
    }
}

impl CandidateMemo {
    /// A fresh memo. Share one across the passes of a joint search (see the
    /// `*_with_memo` entry points) so a candidate two passes both propose is
    /// judged once.
    pub fn new() -> Self {
        Self::with_verification_period(VERIFICATION_PERIOD)
    }

    /// A memo that re-verifies one in `period` cache hits. `period` of 1
    /// verifies every hit, which the guard's own tests use to make the
    /// disagreement path fire deterministically.
    fn with_verification_period(period: u64) -> Self {
        Self {
            verdicts: HashMap::new(),
            hits: 0,
            misses: 0,
            verifications: 0,
            verification_period: period.max(1),
        }
    }

    /// The verdict for `candidate`, from the cache when it has been judged
    /// before and from `oracle` otherwise.
    fn decide<O: FailureOracle>(
        &mut self,
        candidate: &TraceBundle,
        oracle: &mut O,
    ) -> Result<bool, MinimizeError<O::Error>> {
        Ok(self.first_accepted(&[candidate], oracle)?.is_some())
    }

    /// Judge a window of candidates in scan order and return the position of the
    /// first one the oracle accepts, if any.
    ///
    /// Every candidate in the window is judged (or served from the cache), not
    /// just the ones up to the accept: the window is handed to the oracle in one
    /// [`FailureOracle::judge_batch`] call, so a concurrent oracle has already
    /// paid for the later verdicts and caching them is free. The *result* is
    /// still the first accept in scan order, which is what a serial scan would
    /// have returned, so widening the window changes throughput and never the
    /// answer.
    ///
    /// Two candidates in the SAME window that happen to be byte-identical are
    /// judged twice rather than deduplicated, because neither one's verdict
    /// exists yet when the window is planned. That costs a redundant oracle call
    /// on a trace with interchangeable decisions and changes nothing else: the
    /// verdicts agree for any oracle that is a function of its candidate, which
    /// is the assumption the whole cache rests on and which the sampled
    /// re-verification below polices.
    fn first_accepted<O: FailureOracle>(
        &mut self,
        candidates: &[&TraceBundle],
        oracle: &mut O,
    ) -> Result<Option<usize>, MinimizeError<O::Error>> {
        // Plan every candidate against the cache BEFORE the oracle runs: a miss
        // must be judged, and a sampled hit must be re-judged so the soundness
        // guard fires on the same hits it would have sampled one at a time.
        let mut digests = Vec::with_capacity(candidates.len());
        let mut plans = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            let digest: [u8; 32] =
                Sha256::digest(candidate.to_bytes().map_err(MinimizeError::Trace)?)
                    .as_slice()
                    .try_into()
                    .expect("SHA-256 produces 32 bytes");
            let plan = match self.verdicts.get(&digest).copied() {
                None => {
                    self.misses += 1;
                    CandidatePlan::Judge
                }
                Some(cached) => {
                    self.hits += 1;
                    let hits = cached.hits + 1;
                    self.verdicts.insert(
                        digest,
                        CachedVerdict {
                            verdict: cached.verdict,
                            hits,
                        },
                    );
                    // The first repeat of a run is always re-verified, so the
                    // guard runs at least once against any oracle that is asked
                    // the same question twice; after that the content-derived
                    // sample paces it.
                    if self.verifications > 0 && !self.verifies(&digest, hits) {
                        CandidatePlan::Cached(cached.verdict)
                    } else {
                        self.verifications += 1;
                        CandidatePlan::Verify(cached.verdict)
                    }
                }
            };
            digests.push(digest);
            plans.push(plan);
        }

        let pending: Vec<&TraceBundle> = plans
            .iter()
            .zip(candidates)
            .filter(|(plan, _)| !matches!(plan, CandidatePlan::Cached(_)))
            .map(|(_, candidate)| *candidate)
            .collect();
        let observed = if pending.is_empty() {
            Vec::new()
        } else {
            let verdicts = oracle
                .judge_batch(&pending)
                .map_err(MinimizeError::Oracle)?;
            if verdicts.len() != pending.len() {
                return Err(MinimizeError::OracleBatchArity {
                    asked: pending.len(),
                    answered: verdicts.len(),
                });
            }
            verdicts
        };

        let mut observed = observed.into_iter();
        let mut accepted = None;
        for (index, plan) in plans.into_iter().enumerate() {
            let verdict = match plan {
                CandidatePlan::Cached(verdict) => verdict,
                CandidatePlan::Judge => {
                    let verdict = observed
                        .next()
                        .expect("one verdict per candidate handed to the oracle");
                    self.verdicts
                        .insert(digests[index], CachedVerdict { verdict, hits: 0 });
                    verdict
                }
                CandidatePlan::Verify(cached) => {
                    let observed = observed
                        .next()
                        .expect("one verdict per candidate handed to the oracle");
                    if observed != cached {
                        return Err(MinimizeError::NondeterministicOracle {
                            digest: hex(&digests[index]),
                            cached,
                            observed,
                        });
                    }
                    observed
                }
            };
            if verdict && accepted.is_none() {
                accepted = Some(index);
            }
        }
        Ok(accepted)
    }

    /// Whether this hit is the sampled one. Both inputs are fixed by the search
    /// itself - the candidate's content and how often it has recurred - so the
    /// sample is identical on every repeat of the same minimization.
    fn verifies(&self, digest: &[u8; 32], hits: u64) -> bool {
        u64::from(digest[0]).wrapping_add(hits) % self.verification_period == 0
    }
}

/// What one candidate of a window needs before its verdict is known.
enum CandidatePlan {
    /// Never judged before: the oracle must see it.
    Judge,
    /// Judged before, and this repeat is not the sampled one.
    Cached(bool),
    /// Judged before, and this repeat is the sampled one: the oracle must see it
    /// again and agree.
    Verify(bool),
}

fn hex(digest: &[u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
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

/// Ask the oracle about one candidate through a caller-owned memo.
///
/// The reducers judge their input this way before shrinking it. It is public so
/// a caller can probe a candidate of its own — a pre-flight check, a guard
/// against an oracle that answers every candidate the same way — and have the
/// verdict cached for the search that follows rather than paid for twice.
pub fn judge_with_memo<O: FailureOracle>(
    candidate: &TraceBundle,
    oracle: &mut O,
    memo: &mut CandidateMemo,
) -> Result<bool, MinimizeError<O::Error>> {
    candidate.validate().map_err(MinimizeError::Trace)?;
    memo.decide(candidate, oracle)
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

    /// A single-timeline bundle whose decisions carry `values`, one per clock
    /// event, so a scripted oracle can be written as a predicate over `Vec<u64>`.
    fn value_bundle(values: &[u64]) -> TraceBundle {
        TraceBundle::new(
            RunMetadata::new(1, "fixture"),
            values
                .iter()
                .enumerate()
                .map(|(index, &value)| clock_event(index as u64, value))
                .collect(),
        )
    }

    fn values(bundle: &TraceBundle) -> Vec<u64> {
        bundle.timelines[0]
            .decisions
            .iter()
            .map(|event| match event.outcome {
                Outcome::U64(value) => value,
                _ => unreachable!("value bundles carry only U64 outcomes"),
            })
            .collect()
    }

    /// The search this crate used before the resume sweep: restart the scan at
    /// index 0 and step the granularity back toward coarse after *every*
    /// accepted deletion. Kept as the reference the current search is checked
    /// against - same fixed point, fewer oracle calls. It takes the same verdict
    /// cache the current search does, so a call-count comparison measures the
    /// two searches rather than the presence of the cache.
    fn restart_minimize_main<O: FailureOracle>(
        bundle: &TraceBundle,
        oracle: &mut O,
        memo: &mut CandidateMemo,
    ) -> Result<TraceBundle, MinimizeError<O::Error>> {
        bundle.validate().map_err(MinimizeError::Trace)?;
        if !memo.decide(bundle, oracle)? {
            return Err(MinimizeError::OriginalDoesNotFail);
        }
        let mut current = bundle.clone();
        let mut granularity = 2usize;
        loop {
            let window = current.timelines[0].decisions.len();
            if window < 2 {
                break;
            }
            let chunk_size = window.div_ceil(granularity);
            let mut reduced = false;
            let mut start = 0usize;
            while start < window {
                let end = (start + chunk_size).min(window);
                let mut candidate = current.clone();
                candidate.timelines[0].decisions.drain(start..end);
                renumber(&mut candidate, 0);
                candidate.validate().map_err(MinimizeError::Trace)?;
                if memo.decide(&candidate, oracle)? {
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

    /// One resumed single-event sweep with no repetition: what the search would
    /// do if the fixed-point iteration over sweeps were dropped. Used to show
    /// that the iteration is load-bearing rather than defensive.
    fn one_resumed_sweep(start_values: &[u64], predicate: impl Fn(&[u64]) -> bool) -> Vec<u64> {
        let mut current = start_values.to_vec();
        let mut index = 0usize;
        while index < current.len() {
            let mut candidate = current.clone();
            candidate.remove(index);
            if predicate(&candidate) {
                current = candidate;
            } else {
                index += 1;
            }
        }
        current
    }

    /// The trace length of the "single-decision deletions only" shape.
    const SINGLE_DELETE_EVENTS: usize = 20;

    /// A scripted oracle: a pure predicate over one candidate's decision values.
    type Predicate = fn(&[u64]) -> bool;

    /// A named scripted case - what the search starts from and what the oracle
    /// accepts.
    type Shape = (&'static str, Vec<u64>, Predicate);

    /// Every scripted shape below is a pure predicate over the decision values,
    /// so both searches see exactly the same oracle and any difference in the
    /// result is a difference between the searches.
    fn shapes() -> Vec<Shape> {
        fn marker(values: &[u64]) -> bool {
            values.contains(&999)
        }
        fn two_markers(values: &[u64]) -> bool {
            values.contains(&999) && values.contains(&888)
        }
        fn at_least_three(values: &[u64]) -> bool {
            values.len() >= 3
        }
        fn marker_and_even_length(values: &[u64]) -> bool {
            values.contains(&999) && values.len() % 2 == 0
        }
        fn every_even_value_survives(values: &[u64]) -> bool {
            // Only the odd decisions are droppable, and they alternate with the
            // mandatory even ones, so every multi-decision chunk is rejected and
            // every accepted deletion is a single decision. No two candidates
            // are alike, so the verdict cache cannot help here: the calls saved
            // are exactly the ones a restart-at-index-0 scan re-spends walking
            // back to where it already was.
            values
                .iter()
                .copied()
                .filter(|value| value % 2 == 0)
                .eq((0..SINGLE_DELETE_EVENTS as u64).step_by(2))
        }
        fn marker_and_prefix_tail(values: &[u64]) -> bool {
            // The marker plus a *prefix* of the original tail: a decision can
            // only be deleted once every decision after it is already gone, so
            // progress runs backwards through the trace and a scan that walks
            // forward finds one deletion per sweep.
            let Some((first, tail)) = values.split_first() else {
                return false;
            };
            *first == 999 && tail.iter().copied().eq(1..=tail.len() as u64)
        }
        vec![
            (
                "single marker",
                (0..10).map(|v| if v == 6 { 999 } else { v }).collect(),
                marker as Predicate,
            ),
            // Interchangeable filler: deleting any one of the repeated
            // decisions - or any equal-length run of them - yields the same
            // candidate bytes, which is where duplicate oracle calls come from
            // on real traces.
            (
                "interchangeable filler",
                duplicate_heavy().0,
                duplicate_heavy().1,
            ),
            (
                "two markers",
                (0..16)
                    .map(|v| {
                        if v == 3 {
                            999
                        } else if v == 12 {
                            888
                        } else {
                            v
                        }
                    })
                    .collect(),
                two_markers,
            ),
            ("length threshold", (0..12).collect(), at_least_three),
            (
                "single-decision deletions only",
                (0..SINGLE_DELETE_EVENTS as u64).collect(),
                every_even_value_survives,
            ),
            (
                "marker with even length",
                (0..12).map(|v| if v == 7 { 999 } else { v }).collect(),
                marker_and_even_length,
            ),
            (
                "deletion unblocks deletion",
                vec![999, 1, 2, 3, 4, 5],
                marker_and_prefix_tail,
            ),
        ]
    }

    /// Run `minimize_main` over a scripted predicate, returning the result and
    /// the exact sequence of candidates the oracle was asked about.
    fn run_scripted(
        start_values: &[u64],
        predicate: impl Fn(&[u64]) -> bool,
    ) -> (Vec<u64>, Vec<Vec<u64>>) {
        let bundle = value_bundle(start_values);
        let mut asked = Vec::new();
        let result = minimize_main(&bundle, &mut |candidate: &TraceBundle| {
            let candidate = values(candidate);
            let verdict = predicate(&candidate);
            asked.push(candidate);
            Ok::<_, Infallible>(verdict)
        })
        .unwrap();
        (values(&result), asked)
    }

    /// Run one search over a scripted predicate with a fresh verdict cache,
    /// returning the result values and the memo the run filled in.
    fn run_search(start: &[u64], predicate: Predicate, resumed: bool) -> (Vec<u64>, CandidateMemo) {
        let bundle = value_bundle(start);
        let mut memo = CandidateMemo::new();
        let mut oracle =
            |candidate: &TraceBundle| Ok::<_, Infallible>(predicate(&values(candidate)));
        let result = if resumed {
            minimize_main_with_memo(&bundle, &mut oracle, &mut memo)
        } else {
            restart_minimize_main(&bundle, &mut oracle, &mut memo)
        }
        .unwrap();
        (values(&result), memo)
    }

    #[test]
    fn resume_sweep_reaches_the_same_fixed_point_as_the_restarting_search() {
        for (name, start, predicate) in shapes() {
            let (reference, _) = run_search(&start, predicate, false);
            let (result, _) = run_search(&start, predicate, true);
            assert_eq!(
                result, reference,
                "{name}: resumed sweep and restarting search must agree"
            );
            assert!(predicate(&result), "{name}: the failure must survive");
            value_bundle(&result).validate().unwrap();
            // The same result also comes back through the public entry point,
            // which is what callers actually reach.
            let (public, _) = run_scripted(&start, predicate);
            assert_eq!(public, result, "{name}: public entry point agrees");
        }
    }

    #[test]
    fn resume_sweep_costs_fewer_oracle_calls_than_restarting() {
        // Both searches are measured with the same verdict cache, so the
        // difference is the search and not the memo; `hits + misses` is what
        // each would have cost without the cache.
        let mut restart_total = 0usize;
        let mut resume_total = 0usize;
        for (name, start, predicate) in shapes() {
            let (_, restart) = run_search(&start, predicate, false);
            let (_, resume) = run_search(&start, predicate, true);
            let restart_calls = (restart.misses + restart.verifications) as usize;
            let resume_calls = (resume.misses + resume.verifications) as usize;
            println!(
                "{name}: {} events, restart {restart_calls} calls ({} without the cache), \
                 resume {resume_calls} calls ({} without the cache)",
                start.len(),
                restart.hits + restart.misses,
                resume.hits + resume.misses
            );
            if name == "single-decision deletions only" {
                // Every accepted deletion is a single decision and no two
                // candidates are alike, so the cache cannot help either search:
                // the whole saving is the rescan the resumed sweep does not pay.
                assert!(
                    resume_calls < restart_calls,
                    "{name}: expected strictly fewer oracle calls, \
                     got {resume_calls} vs {restart_calls}"
                );
            }
            if name == "interchangeable filler" {
                // The duplicate-heavy case the probe measured: here the cache is
                // what pays, and it must actually pay.
                assert!(
                    resume.hits > 0 && resume_calls < (resume.hits + resume.misses) as usize,
                    "{name}: the cache saved nothing"
                );
            }
            // On ten-decision traces the two searches are within a couple of
            // calls of each other either way - restarting at index 0 is cheap
            // when the whole window is that small. The measured 3-3.7x is a
            // 944-decision effect (docs/probes/minimize-oracle-perf.md); what
            // matters here is that no shape blows up.
            assert!(
                resume_calls <= restart_calls + 2,
                "{name}: resumed sweep cost {resume_calls} calls against restart's {restart_calls}"
            );
            restart_total += restart_calls;
            resume_total += resume_calls;
        }
        assert!(
            resume_total < restart_total,
            "across all shapes: resume {resume_total} calls, restart {restart_total}"
        );
    }

    /// The interchangeable-filler shape: deleting any one of the repeated
    /// decisions produces the same candidate, so the search proposes the same
    /// bytes many times over.
    fn duplicate_heavy() -> (Vec<u64>, Predicate) {
        fn predicate(values: &[u64]) -> bool {
            values.contains(&999) && values.len() >= 8
        }
        (
            std::iter::once(999)
                .chain(std::iter::repeat_n(7, 15))
                .collect(),
            predicate,
        )
    }

    #[test]
    fn repeated_candidates_are_decided_once() {
        let (start, predicate) = duplicate_heavy();
        let bundle = value_bundle(&start);
        let mut memo = CandidateMemo::new();
        let mut asked = Vec::new();
        minimize_main_with_memo(
            &bundle,
            &mut |candidate: &TraceBundle| {
                asked.push(values(candidate));
                Ok::<_, Infallible>(predicate(&values(candidate)))
            },
            &mut memo,
        )
        .unwrap();
        assert!(
            memo.hits > 0,
            "the shape must actually repeat candidates, or this proves nothing"
        );
        // Every oracle call is a distinct candidate except the sampled re-runs
        // the soundness guard deliberately repeats.
        let distinct: HashSet<Vec<u64>> = asked.iter().cloned().collect();
        assert_eq!(
            asked.len() - memo.verifications as usize,
            distinct.len(),
            "the oracle re-judged a candidate outside the sampled re-verification: \
             {} calls, {} verifications, {} distinct candidates",
            asked.len(),
            memo.verifications,
            distinct.len()
        );
    }

    #[test]
    fn sweeps_iterate_to_a_fixed_point_rather_than_stopping_after_one_pass() {
        // Deleting a decision here requires every later decision to be gone
        // already, so one forward sweep can only ever remove the last one.
        let start = vec![999, 1, 2, 3, 4, 5];
        let predicate = |values: &[u64]| {
            let Some((first, tail)) = values.split_first() else {
                return false;
            };
            *first == 999 && tail.iter().copied().eq(1..=tail.len() as u64)
        };
        assert_eq!(
            one_resumed_sweep(&start, predicate),
            vec![999, 1, 2, 3, 4],
            "a single sweep stops one deletion in"
        );
        let (result, _) = run_scripted(&start, predicate);
        assert_eq!(
            result,
            vec![999],
            "the iterated search reaches the fixed point"
        );
    }

    #[test]
    fn the_search_asks_the_same_questions_in_the_same_order_on_a_repeat_run() {
        for (name, start, predicate) in shapes() {
            let (first_result, first_asked) = run_scripted(&start, predicate);
            let (second_result, second_asked) = run_scripted(&start, predicate);
            assert_eq!(first_result, second_result, "{name}: same result");
            assert_eq!(
                first_asked, second_asked,
                "{name}: same candidate sequence, including which cache hits were re-verified"
            );
        }
    }

    #[test]
    fn the_sampling_policy_is_content_derived_and_hits_its_advertised_rate() {
        let memo = CandidateMemo::new();
        let sampled = (0..=u8::MAX)
            .filter(|&byte| {
                let mut digest = [0u8; 32];
                digest[0] = byte;
                memo.verifies(&digest, 1)
            })
            .count();
        assert_eq!(
            sampled,
            256 / VERIFICATION_PERIOD as usize,
            "one hit in {VERIFICATION_PERIOD} must be re-verified"
        );
        // The same digest at successive hits moves in and out of the sample, so
        // a candidate that recurs often is re-verified repeatedly rather than
        // trusted forever, and one that never recurs costs nothing.
        let digest = [0u8; 32];
        assert!((1..=VERIFICATION_PERIOD).any(|hits| memo.verifies(&digest, hits)));
        let every = CandidateMemo::with_verification_period(1);
        assert!((1..=8).all(|hits| every.verifies(&digest, hits)));
    }

    /// An oracle that answers honestly the first time it sees a candidate and
    /// inverts itself on every later look at the identical bytes - exactly the
    /// flakiness a verdict cache would otherwise launder into a wrong result.
    fn contradicting_oracle<'a>(
        seen: &'a mut HashMap<Vec<u64>, bool>,
        predicate: Predicate,
    ) -> impl FnMut(&TraceBundle) -> Result<bool, Infallible> + 'a {
        move |candidate: &TraceBundle| {
            let candidate = values(candidate);
            let honest = predicate(&candidate);
            Ok(match seen.insert(candidate, honest) {
                Some(previous) => !previous,
                None => honest,
            })
        }
    }

    #[test]
    fn a_contradicting_oracle_aborts_the_run_instead_of_being_trusted() {
        let (start, predicate) = duplicate_heavy();
        let bundle = value_bundle(&start);
        let mut seen = HashMap::new();
        let error = minimize_main_with_memo(
            &bundle,
            &mut contradicting_oracle(&mut seen, predicate),
            // Verify every hit so the disagreement is reached deterministically
            // on this small trace.
            &mut CandidateMemo::with_verification_period(1),
        )
        .unwrap_err();
        let MinimizeError::NondeterministicOracle {
            digest,
            cached,
            observed,
        } = &error
        else {
            panic!("expected a nondeterminism refusal, got {error}");
        };
        assert_eq!(digest.len(), 64, "the refusal names the candidate digest");
        assert_ne!(cached, observed);
        let message = error.to_string();
        assert!(
            message.contains("nondeterministic") && message.contains("sha256:"),
            "the refusal must be legible: {message}"
        );
    }

    #[test]
    fn the_default_sample_re_runs_cache_hits_and_still_catches_a_contradiction() {
        let (start, predicate) = duplicate_heavy();

        // Non-vacuity: under the shipped sampling period a normal run really does
        // re-run some of its cache hits.
        let bundle = value_bundle(&start);
        let mut memo = CandidateMemo::new();
        minimize_main_with_memo(
            &bundle,
            &mut |candidate: &TraceBundle| Ok::<_, Infallible>(predicate(&values(candidate))),
            &mut memo,
        )
        .unwrap();
        assert!(memo.hits > 0, "the run must exercise the cache at all");
        assert!(
            memo.verifications > 0,
            "the re-verification never fired: {} hits, {} misses",
            memo.hits,
            memo.misses
        );

        // And that sample is what catches a self-contradicting oracle without
        // any test-only period.
        let mut seen = HashMap::new();
        let error = minimize_main_with_memo(
            &bundle,
            &mut contradicting_oracle(&mut seen, predicate),
            &mut CandidateMemo::new(),
        )
        .unwrap_err();
        assert!(
            matches!(error, MinimizeError::NondeterministicOracle { .. }),
            "expected a nondeterminism refusal, got {error}"
        );
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

    /// An oracle that answers a whole window at once, standing in for one that
    /// evaluates its window concurrently. The verdict function is identical at
    /// every width, so any difference in the result is a difference the width
    /// caused.
    struct WindowedOracle {
        predicate: Predicate,
        width: usize,
        /// Verdicts produced, i.e. what a real oracle would have executed.
        verdicts: usize,
        /// Windows handed over, i.e. how many round trips the search made.
        windows: usize,
    }

    impl FailureOracle for WindowedOracle {
        type Error = Infallible;

        fn preserves_failure(&mut self, candidate: &TraceBundle) -> Result<bool, Infallible> {
            self.verdicts += 1;
            Ok((self.predicate)(&values(candidate)))
        }

        fn batch_width(&self) -> usize {
            self.width
        }

        fn judge_batch(&mut self, candidates: &[&TraceBundle]) -> Result<Vec<bool>, Infallible> {
            self.windows += 1;
            let mut verdicts = Vec::with_capacity(candidates.len());
            for candidate in candidates {
                verdicts.push(self.preserves_failure(candidate)?);
            }
            Ok(verdicts)
        }
    }

    #[test]
    fn a_widened_candidate_window_changes_throughput_and_not_the_result() {
        for (name, start, predicate) in shapes() {
            let bundle = value_bundle(&start);
            let mut serial = WindowedOracle {
                predicate,
                width: 1,
                verdicts: 0,
                windows: 0,
            };
            let reference = minimize_main(&bundle, &mut serial).unwrap();
            for width in [2usize, 3, 8, 64] {
                let mut batched = WindowedOracle {
                    predicate,
                    width,
                    verdicts: 0,
                    windows: 0,
                };
                let result = minimize_main(&bundle, &mut batched).unwrap();
                assert_eq!(
                    values(&result),
                    values(&reference),
                    "{name}: width {width} moved the result"
                );
                assert_eq!(
                    result.to_bytes().unwrap(),
                    reference.to_bytes().unwrap(),
                    "{name}: width {width} produced different bytes"
                );
                assert!(
                    batched.windows <= serial.windows,
                    "{name}: width {width} made {} round trips against serial's {}",
                    batched.windows,
                    serial.windows
                );
            }
        }
    }

    #[test]
    fn a_wide_window_actually_batches_rather_than_falling_back_to_one_at_a_time() {
        // The saving is real work per round trip: a serial run makes one round
        // trip per verdict, a batched one must make strictly fewer.
        let (start, predicate) = duplicate_heavy();
        let bundle = value_bundle(&start);
        let mut batched = WindowedOracle {
            predicate,
            width: 8,
            verdicts: 0,
            windows: 0,
        };
        minimize_main(&bundle, &mut batched).unwrap();
        assert!(
            batched.windows * 2 < batched.verdicts,
            "width 8 made {} round trips for {} verdicts",
            batched.windows,
            batched.verdicts
        );
    }

    /// The self-contradicting oracle above, batching. The window is where a
    /// disagreement could plausibly get lost: several candidates are judged for
    /// one scan step, but only one of them is kept, so a search that stopped
    /// reading verdicts at its accept would skip the re-verification of every
    /// later member and launder exactly the flakiness the guard exists to catch.
    struct ContradictingWindowedOracle<'a> {
        seen: &'a mut HashMap<Vec<u64>, bool>,
        predicate: Predicate,
        width: usize,
    }

    impl FailureOracle for ContradictingWindowedOracle<'_> {
        type Error = Infallible;

        fn preserves_failure(&mut self, candidate: &TraceBundle) -> Result<bool, Infallible> {
            let candidate = values(candidate);
            let honest = (self.predicate)(&candidate);
            Ok(match self.seen.insert(candidate, honest) {
                Some(previous) => !previous,
                None => honest,
            })
        }

        fn batch_width(&self) -> usize {
            self.width
        }
    }

    #[test]
    fn a_contradiction_inside_a_speculative_window_still_aborts_the_run() {
        let (start, predicate) = duplicate_heavy();
        let bundle = value_bundle(&start);
        for width in [2usize, 8, 64] {
            let mut seen = HashMap::new();
            let mut oracle = ContradictingWindowedOracle {
                seen: &mut seen,
                predicate,
                width,
            };
            let error = minimize_main_with_memo(
                &bundle,
                &mut oracle,
                &mut CandidateMemo::with_verification_period(1),
            )
            .unwrap_err();
            assert!(
                matches!(error, MinimizeError::NondeterministicOracle { .. }),
                "width {width}: expected a nondeterminism refusal, got {error}"
            );
        }
    }

    #[test]
    fn a_contradiction_after_the_accept_in_a_window_is_not_lost() {
        // The precise hazard batching introduces, arranged rather than hoped
        // for: the window's FIRST candidate is accepted and its SECOND is a
        // cache hit whose sampled re-run disagrees. The accept is the answer
        // the search wants, so an implementation that stopped reading verdicts
        // once it had one would return that accept and never see the
        // contradiction - laundering a flaky oracle exactly when the window is
        // wide. Every verdict in a window is resolved, so it aborts instead.
        let accepted = value_bundle(&[999, 1]);
        let contradicted = value_bundle(&[999, 2]);
        let mut memo = CandidateMemo::with_verification_period(1);
        // Seed the cache with an honest "still failing" verdict for the second
        // candidate, so the window below is a hit rather than a miss.
        let seeded = judge_with_memo(
            &contradicted,
            &mut |_: &TraceBundle| Ok::<_, Infallible>(true),
            &mut memo,
        )
        .unwrap();
        assert!(seeded, "the cache must be seeded with a positive verdict");

        struct AcceptFirstDenySecond;
        impl FailureOracle for AcceptFirstDenySecond {
            type Error = Infallible;

            fn preserves_failure(&mut self, candidate: &TraceBundle) -> Result<bool, Infallible> {
                // The first candidate still fails; the second now contradicts
                // the verdict its identical bytes already produced.
                Ok(values(candidate) == vec![999, 1])
            }

            fn batch_width(&self) -> usize {
                2
            }
        }

        let error = memo
            .first_accepted(&[&accepted, &contradicted], &mut AcceptFirstDenySecond)
            .unwrap_err();
        assert!(
            matches!(error, MinimizeError::NondeterministicOracle { .. }),
            "a contradiction behind an accept was lost: {error}"
        );
    }

    /// An oracle that drops verdicts on the floor: a search that matched the
    /// remaining ones up positionally would silently attribute one candidate's
    /// verdict to another.
    struct ShortAnsweringOracle;

    impl FailureOracle for ShortAnsweringOracle {
        type Error = Infallible;

        fn preserves_failure(&mut self, _candidate: &TraceBundle) -> Result<bool, Infallible> {
            Ok(true)
        }

        fn batch_width(&self) -> usize {
            8
        }

        fn judge_batch(&mut self, candidates: &[&TraceBundle]) -> Result<Vec<bool>, Infallible> {
            Ok(vec![true; candidates.len().saturating_sub(1)])
        }
    }

    #[test]
    fn an_oracle_that_answers_the_wrong_number_of_candidates_is_refused() {
        let bundle = value_bundle(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let error = minimize_main(&bundle, &mut ShortAnsweringOracle).unwrap_err();
        assert!(
            matches!(error, MinimizeError::OracleBatchArity { .. }),
            "expected a batch-arity refusal, got {error}"
        );
    }
}
