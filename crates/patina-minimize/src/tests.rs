//! Shared test fixtures and cross-module minimization tests.

use super::*;
use crate::trace_reduce::{linear_lifecycle_from_start, renumber};
use patina_dst_abi::{ClockKind, Operation, Outcome, TaskId};
use patina_dst_trace::{RunMetadata, Timeline, TraceEvent};
use std::collections::{HashMap, HashSet};

pub(super) fn clock_event(sequence: u64, value: u64) -> TraceEvent {
    TraceEvent::new(
        sequence,
        Operation::ClockNow {
            clock: ClockKind::Monotonic,
        },
        Outcome::U64(value),
    )
}

pub(super) fn sched_event(sequence: u64, task: u64) -> TraceEvent {
    TraceEvent::new(
        sequence,
        Operation::SchedulerNext,
        Outcome::OptionalTask(Some(TaskId(task))),
    )
}

pub(super) fn test_timeline(
    id: &str,
    parent: &str,
    from_sequence: u64,
    branch_seed: u64,
    mut decisions: Vec<TraceEvent>,
) -> Timeline {
    let start_order = from_sequence.saturating_mul(10).saturating_add(1);
    for (index, event) in decisions.iter_mut().enumerate() {
        event.order = start_order.saturating_add(1).saturating_add(index as u64);
        event.incarnation = 0;
    }
    let lifecycle = linear_lifecycle_from_start(start_order, &decisions);
    Timeline {
        id: id.into(),
        parent: Some(parent.into()),
        from_sequence: Some(from_sequence),
        branch_seed: Some(branch_seed),
        lifecycle,
        decisions,
    }
}

/// A single-timeline bundle whose decisions carry `values`, one per clock
/// event, so a scripted oracle can be written as a predicate over `Vec<u64>`.
pub(super) fn value_bundle(values: &[u64]) -> TraceBundle {
    TraceBundle::new(
        RunMetadata::new(1, "fixture", 0, "patina"),
        values
            .iter()
            .enumerate()
            .map(|(index, &value)| clock_event(index as u64, value))
            .collect(),
    )
}

pub(super) fn values(bundle: &TraceBundle) -> Vec<u64> {
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
pub(super) fn shapes() -> Vec<Shape> {
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
pub(super) fn run_scripted(
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
    let mut oracle = |candidate: &TraceBundle| Ok::<_, Infallible>(predicate(&values(candidate)));
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

pub(super) fn selected_tasks(timeline: &Timeline) -> Vec<u64> {
    timeline
        .decisions
        .iter()
        .filter_map(|event| match (&event.operation, &event.outcome) {
            (Operation::SchedulerNext, Outcome::OptionalTask(Some(task))) => Some(task.0),
            _ => None,
        })
        .collect()
}

pub(super) fn switch_count(tasks: &[u64]) -> usize {
    tasks.windows(2).filter(|pair| pair[0] != pair[1]).count()
}

#[test]
fn minimize_all_shrinks_and_canonicalizes_together() {
    // A single main timeline with a ping-pong schedule followed by removable
    // filler clock events; the failure needs the 999 marker and both tasks.
    let bundle = TraceBundle::new(
        RunMetadata::new(1, "fixture", 0, "patina"),
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
