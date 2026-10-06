//! Tests for bounded event recording and allocation-free borrowed prefix export.

use super::*;
use crate::tests::operation;
use crate::{
    ComputeStop, LifecycleEventKind, MAX_TRACE_BYTES, RunMetadata, TraceBundle, TraceEvent,
    abandoned_trace_marker, parse_abandoned_trace_marker, resource_limit_infra_line,
};
use patina_dst_abi::{Outcome, TaskId};
use std::fs;
use tempfile::tempdir;

#[test]
fn borrowed_prefix_matches_the_ordinary_bundle() {
    for incarnation in [0, 1] {
        for count in [0, 1, 9] {
            let mut recorder = Recorder::new(RunMetadata::new(7, "fingerprint", 0, "patina"))
                .with_incarnation(incarnation);
            for _ in 0..count {
                recorder.observe(operation(), Outcome::U64(0));
            }
            recorder.set_compute_stop(ComputeStop {
                steps: count,
                task: TaskId(1),
            });
            let mut bytes = Vec::new();
            recorder.write_prefix(&mut bytes).unwrap();
            assert_eq!(
                TraceBundle::from_slice(&bytes).unwrap(),
                recorder.to_bundle().unwrap()
            );
        }
    }
    let mut recorder = Recorder::new(RunMetadata::new(7, "fingerprint", 0, "patina"));
    recorder.observe(operation(), Outcome::U64(0));
    struct Broken;
    impl std::io::Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    assert!(recorder.write_prefix(Broken).is_err());
}

#[test]
fn abandoned_prefix_returns_a_plain_status_before_serialization() {
    struct MustNotWrite;
    impl std::io::Write for MustNotWrite {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            panic!("abandoned prefix entered serialization");
        }
        fn flush(&mut self) -> std::io::Result<()> {
            panic!("abandoned prefix flushed");
        }
    }
    for (bytes, events) in [(0, 10), (4096, 0)] {
        let mut recorder = Recorder::with_limits(
            RunMetadata::new(7, "fingerprint", 0, "patina"),
            bytes,
            events,
        );
        assert_eq!(recorder.committed_prefix_len(), Some(0));
        recorder.observe(operation(), Outcome::U64(0));
        assert_eq!(recorder.committed_prefix_len(), None);
        assert!(matches!(
            recorder.write_prefix(MustNotWrite),
            Err(PrefixWriteError::Overflow)
        ));
        assert!(recorder.decisions.is_empty());
    }
}

#[test]
fn recorder_stamps_its_incarnation_on_every_event_and_marker() {
    let mut recorder =
        Recorder::new(RunMetadata::new(7, "fingerprint", 0, "patina")).with_incarnation(1);
    recorder.observe(operation(), Outcome::U64(0));
    let bundle = recorder.into_bundle().unwrap();
    let main = &bundle.timelines[0];
    assert_eq!(main.decisions[0].incarnation, 1);
    assert_eq!(
        main.lifecycle[0].kind,
        LifecycleEventKind::Start { incarnation: 1 }
    );
    assert_eq!(
        main.lifecycle[1].kind,
        LifecycleEventKind::End { incarnation: 1 }
    );
}

/// The recorder-memory fix. A recording that outgrows its byte budget must
/// stop HOLDING events at the event that crosses it, rather than discover
/// the overflow at finalization with the whole run resident — the shape
/// that cost ~1.9 GB of RSS per long generation and lost the trace anyway.
///
/// Three things are pinned: the memory really is bounded (the held events
/// never exceed the budget by more than the single event that crossed it,
/// and are released outright at the crossing); the crossing is a pure
/// function of the event stream, so a run that abandons abandons at the
/// same event every time; and the refusal is still the SAME graceful budget
/// error, carrying its figures and writing no file, so the shim's shutdown
/// downgrade keeps the guest's own verdict exactly as before.
#[test]
fn an_over_budget_recording_stops_holding_events_and_still_refuses() {
    let limit = 64 * 1024;
    let payload = vec![b'p'; 512];
    let widest = serialized_event_len(&TraceEvent::new(
        u64::MAX,
        operation(),
        Outcome::Bytes(payload.clone()),
    ))
    .unwrap()
        + 1;

    let record = || {
        let mut recorder =
            Recorder::with_limit(RunMetadata::new(7, "fingerprint", 0, "patina"), limit);
        let mut crossed_at = None;
        for index in 0..4_096u64 {
            recorder.observe(operation(), Outcome::Bytes(payload.clone()));
            assert!(
                recorder.ledger.bytes <= limit + widest,
                "held events must never exceed the budget by more than the event that \
                     crossed it; {} bytes after event {index}",
                recorder.ledger.bytes
            );
            if recorder.ledger.overflowed() && crossed_at.is_none() {
                crossed_at = Some(index);
            }
            if crossed_at.is_some() {
                assert!(
                    recorder.decisions.is_empty() && recorder.decisions.capacity() == 0,
                    "an abandoned recorder must hold nothing, and keep holding nothing"
                );
            }
        }
        (crossed_at.expect("the budget must be crossed"), recorder)
    };

    let (crossing, recorder) = record();
    let (crossing_again, _) = record();
    assert_eq!(
        crossing, crossing_again,
        "the abandon point must be a function of the recorded events alone"
    );
    assert!(
        crossing > 0 && crossing < 4_096,
        "the crossing must land inside the run; got {crossing}"
    );

    let held = recorder.ledger.bytes;
    assert!(held > limit && held <= limit + widest);
    let directory = tempdir().unwrap();
    let path = directory.path().join("abandoned.patina");
    let error = recorder.finish(&path).unwrap_err();
    assert!(
        error.is_resource_limit(),
        "the shutdown downgrade keys off this predicate; got {error}"
    );
    assert_eq!(error.resource_limit_bytes(), Some((held, limit)));
    assert!(!path.exists(), "an abandoned trace must write no file");
    assert_eq!(
        fs::read_dir(directory.path()).unwrap().count(),
        0,
        "an abandoned trace must not leave a temporary file either"
    );
    // The refusal is the one the graceful path already knows how to report.
    assert_eq!(
        parse_abandoned_trace_marker(&abandoned_trace_marker(
            "resource-limit",
            &error.to_string()
        ))
        .unwrap()
        .reason,
        "resource-limit"
    );
    assert!(resource_limit_infra_line(&error).starts_with(&format!(
        "PATINA_INFRA trace=incomplete reason=resource-limit bytes={held} limit={limit}"
    )));
}

/// The event-count budget bounds memory the same way, for a run whose
/// events are too small to reach the byte budget first.
#[test]
fn an_over_long_recording_is_abandoned_at_the_event_budget() {
    let mut recorder = Recorder::with_limits(
        RunMetadata::new(7, "fingerprint", 0, "patina"),
        MAX_TRACE_BYTES,
        8,
    );
    for index in 0..64u64 {
        recorder.observe(operation(), Outcome::U64(index));
        assert!(recorder.decisions.len() <= 8);
    }
    assert!(recorder.decisions.is_empty());
    let error = recorder.into_bundle().unwrap_err();
    assert!(error.is_resource_limit(), "unexpected error: {error}");
    assert_eq!(
        error.resource_limit_bytes(),
        None,
        "an event-count budget has no byte figures to report"
    );
    assert!(
        error.to_string().contains("reached 9 events"),
        "the refusal must name the count that crossed the budget; got {error}"
    );
}

/// The other half of the bargain: a recording that FITS its budget is
/// byte-identical to the bundle built straight from its events, and the
/// ledger that watched it is an exact tally of those events and a strict
/// under-estimate of the whole file — which is why it can never abandon a
/// recording that would have fit.
#[test]
fn an_under_budget_recording_is_byte_identical_and_exactly_tallied() {
    let mut recorder = Recorder::new(RunMetadata::new(7, "fingerprint", 0, "patina"));
    let mut events = Vec::new();
    for index in 0..64u64 {
        let outcome = Outcome::Bytes(vec![index as u8; index as usize]);
        recorder.observe(operation(), outcome.clone());
        events.push(TraceEvent::new(index, operation(), outcome));
    }

    let tallied = recorder.ledger.bytes;
    let expected: u64 = events
        .iter()
        .map(|event| serde_json::to_vec(event).unwrap().len() as u64)
        .sum::<u64>()
        + events.len() as u64
        - 1;
    assert_eq!(tallied, expected, "the ledger must tally events exactly");

    let bundle = TraceBundle::new(RunMetadata::new(7, "fingerprint", 0, "patina"), events);
    let expected_bytes = bundle.to_bytes().unwrap();
    assert!(
        tallied < expected_bytes.len() as u64,
        "the tally must stay under the size of the file it bounds"
    );
    assert_eq!(
        recorder.into_bundle().unwrap().to_bytes().unwrap(),
        expected_bytes,
        "a trace under budget must be byte-identical to one recorded without a ledger"
    );
}
