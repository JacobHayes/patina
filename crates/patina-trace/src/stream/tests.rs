//! Tests for streaming trace reads.

use super::*;
use crate::tests::operation;
use crate::{LifecycleEventKind, MAIN_TIMELINE};
use patina_dst_abi::{CrashKind, Outcome};
use std::fs;
use tempfile::tempdir;

fn metadata() -> RunMetadata {
    RunMetadata::new(1, "fingerprint", 0, "patina")
}

fn events(range: std::ops::Range<u64>) -> Vec<TraceEvent> {
    range
        .map(|index| TraceEvent::new(index, operation(), Outcome::U64(index)))
        .collect()
}

/// A crash-restart run: lifecycle markers between decisions, and decisions
/// in two incarnations.
fn crash_restart() -> TraceBundle {
    let digest = format!("sha256:{}", "ab".repeat(32));
    let mut bundle = TraceBundle::new(metadata(), events(0..5));
    let timeline = &mut bundle.timelines[0];
    for (index, event) in timeline.decisions.iter_mut().enumerate() {
        event.order = [1, 2, 6, 7, 8][index];
        event.incarnation = u64::from(index >= 2);
    }
    let marker = |order, kind| LifecycleEvent { order, kind };
    timeline.lifecycle = vec![
        marker(0, LifecycleEventKind::Start { incarnation: 0 }),
        marker(
            3,
            LifecycleEventKind::Crash {
                incarnation: 0,
                crash_kind: CrashKind::Process,
                snapshot_digest: digest.clone(),
            },
        ),
        marker(
            4,
            LifecycleEventKind::Restart {
                from_incarnation: 0,
                to_incarnation: 1,
                snapshot_digest: digest,
            },
        ),
        marker(5, LifecycleEventKind::Start { incarnation: 1 }),
        marker(9, LifecycleEventKind::End { incarnation: 1 }),
    ];
    bundle
}

/// A main timeline with an order gap, and a branch from its second decision.
fn branched() -> TraceBundle {
    let mut bundle = TraceBundle::linear(metadata(), 3, events(0..4));
    for event in &mut bundle.timelines[0].decisions[2..] {
        event.order += 5;
    }
    bundle.timelines[0].lifecycle[1].order += 7;
    let mut branch = bundle.timelines[0].clone();
    branch.id = "branch".into();
    branch.parent = Some(MAIN_TIMELINE.into());
    branch.from_sequence = Some(2);
    branch.branch_seed = Some(9);
    branch.decisions.truncate(2);
    for (index, event) in branch.decisions.iter_mut().enumerate() {
        event.sequence = 2 + index as u64;
        event.order = 20 + index as u64;
    }
    branch.lifecycle[0].order = 19;
    branch.lifecycle[1].order = 22;
    bundle.timelines.push(branch);
    bundle
}

fn streamed(stream: &mut TraceStream, id: &str) -> Vec<TraceEvent> {
    let mut events = Vec::new();
    stream
        .for_each_resolved(id, |event| {
            events.push(event);
            Ok::<_, ()>(())
        })
        .unwrap()
        .unwrap();
    events
}

/// Every timeline of every bundle reads back from a stream as `load`
/// resolves it, and the stream holds no decision while it waits.
#[test]
fn a_stream_resolves_every_timeline_as_load_does() {
    let directory = tempdir().unwrap();
    for (name, bundle) in [
        ("linear", TraceBundle::new(metadata(), events(0..6))),
        ("empty", TraceBundle::new(metadata(), Vec::new())),
        ("crash-restart", crash_restart()),
        ("branched", branched()),
    ] {
        let path = directory.path().join(format!("{name}.patina"));
        bundle.write_atomic(&path).unwrap();
        let loaded = TraceBundle::load(&path).unwrap();
        let mut stream = TraceStream::open(&path).unwrap();
        assert!(
            matches!(stream.source, Source::Streamed { .. }),
            "{name} fell back to a full load"
        );
        for timeline in &loaded.timelines {
            let id = timeline.id.as_str();
            let resolved = loaded.resolved_timeline(id).unwrap();
            assert_eq!(stream.resolved_len(id).unwrap(), resolved.len(), "{name}");
            assert_eq!(
                stream.resolved_lifecycle(id).unwrap(),
                loaded.resolved_lifecycle(id).unwrap(),
                "{name}"
            );
            assert_eq!(streamed(&mut stream, id), resolved, "{name} {id}");
        }
        assert!(matches!(
            stream.resolved_len("missing"),
            Err(TraceError::UnknownTimeline(_))
        ));
    }
}

/// The array form derived deserializers accept for a bundle and a timeline
/// (their fields, in order) streams like the object form.
#[test]
fn a_stream_reads_bundles_written_as_arrays() {
    let directory = tempdir().unwrap();
    let bundle = branched();
    let value: serde_json::Value = serde_json::from_slice(&bundle.to_bytes().unwrap()).unwrap();
    let as_array = |object: &serde_json::Value, fields: &[&str]| {
        serde_json::Value::Array(fields.iter().map(|field| object[*field].clone()).collect())
    };
    let timelines: Vec<_> = value["timelines"]
        .as_array()
        .unwrap()
        .iter()
        .map(|timeline| {
            as_array(
                timeline,
                &[
                    "id",
                    "parent",
                    "from_sequence",
                    "branch_seed",
                    "lifecycle",
                    "decisions",
                ],
            )
        })
        .collect();
    let mut arrays = value.clone();
    arrays["timelines"] = timelines.into();
    let arrays = as_array(&arrays, &["format_version", "metadata", "timelines"]);
    let path = directory.path().join("arrays.patina");
    fs::write(&path, serde_json::to_vec(&arrays).unwrap()).unwrap();

    assert_eq!(TraceBundle::load(&path).unwrap(), bundle);
    let mut stream = TraceStream::open(&path).unwrap();
    assert!(matches!(stream.source, Source::Streamed { .. }));
    for timeline in &bundle.timelines {
        let id = timeline.id.as_str();
        assert_eq!(
            streamed(&mut stream, id),
            bundle.resolved_timeline(id).unwrap()
        );
    }

    // An array one field short is refused, as `load` refuses it.
    let mut short = arrays;
    short.as_array_mut().unwrap().pop();
    fs::write(&path, serde_json::to_vec(&short).unwrap()).unwrap();
    assert_eq!(
        TraceStream::open(&path).unwrap_err().to_string(),
        TraceBundle::load(&path).unwrap_err().to_string()
    );
}

/// A reader's error stops the stream and comes back as it was returned.
#[test]
fn a_reader_error_stops_the_stream() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("run.patina");
    TraceBundle::new(metadata(), events(0..6))
        .write_atomic(&path)
        .unwrap();
    let mut stream = TraceStream::open(&path).unwrap();
    let mut seen = 0;
    let result = stream
        .for_each_resolved(MAIN_TIMELINE, |event| {
            seen += 1;
            if event.sequence == 2 {
                Err(event.sequence)
            } else {
                Ok(())
            }
        })
        .unwrap();
    assert_eq!((result, seen), (Err(2), 3));
    // The stream reads again from the start.
    assert_eq!(streamed(&mut stream, MAIN_TIMELINE).len(), 6);
}

/// A stream refuses what `load` refuses, with `load`'s error.
#[test]
fn a_stream_refuses_what_load_refuses() {
    let directory = tempdir().unwrap();
    let good = TraceBundle::new(metadata(), events(0..3))
        .to_bytes()
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&good).unwrap();
    let edit = |change: &dyn Fn(&mut serde_json::Value)| {
        let mut value = value.clone();
        change(&mut value);
        serde_json::to_vec(&value).unwrap()
    };
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", Vec::new()),
        ("not json", b"not json".to_vec()),
        ("truncated", good[..good.len() / 2].to_vec()),
        ("trailing", [&good[..], b"{}"].concat()),
        ("version", edit(&|v| v["format_version"] = 1.into())),
        (
            "unknown field",
            edit(&|v| v["timelines"][0]["extra"] = 1.into()),
        ),
        (
            "bad operation",
            edit(&|v| v["timelines"][0]["decisions"][1][0]["kind"] = "nope".into()),
        ),
        (
            "order reused",
            edit(&|v| {
                v["timelines"][0]["decisions"][2]
                    .as_array_mut()
                    .unwrap()
                    .push(1.into())
            }),
        ),
        (
            "outside an incarnation",
            edit(&|v| {
                v["timelines"][0]["decisions"][0]
                    .as_array_mut()
                    .unwrap()
                    .push(99.into())
            }),
        ),
        (
            "missing decisions",
            edit(&|v| {
                v["timelines"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("decisions");
            }),
        ),
    ];
    for (name, bytes) in cases {
        let path = directory.path().join("bad.patina");
        fs::write(&path, &bytes).unwrap();
        let loaded = TraceBundle::load(&path).unwrap_err().to_string();
        let streamed = TraceStream::open(&path).unwrap_err().to_string();
        assert_eq!(streamed, loaded, "{name}");
    }
}
