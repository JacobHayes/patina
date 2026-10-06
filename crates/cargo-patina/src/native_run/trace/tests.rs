//! Regression tests for trace.

use super::*;

use std::fs;

use patina_dst_trace::remove_dead_scratch;

/// A trace whose scratch file is GONE at commit — it was swept out from
/// under the run, or its directory was — is the artifact channel failing,
/// not the run failing. It is reported as its own kind so the campaign can
/// file it as INFRA under one shared shape, while a trace that is present
/// but empty (what a guest that died mid-record leaves) stays Broken and
/// keeps failing the run.
#[cfg(unix)]
#[test]
fn a_vanished_scratch_file_is_a_channel_failure_not_a_broken_trace() {
    let directory = tempfile::tempdir().unwrap();

    let final_path = directory.path().join("vanished.patina");
    let sink = NativeTraceSink::create(&final_path).unwrap();
    fs::remove_file(&sink.temp_path).unwrap();
    let failure = sink.commit().unwrap_err();
    assert!(
        matches!(failure, TraceCommitFailure::Unavailable(_)),
        "a vanished scratch file is a channel failure; got {}",
        failure.reason()
    );

    // RED twin: the file is there and simply holds no bundle. That is the
    // run's own doing and must stay a failure.
    let final_path = directory.path().join("empty.patina");
    let sink = NativeTraceSink::create(&final_path).unwrap();
    assert!(matches!(
        sink.commit().unwrap_err(),
        TraceCommitFailure::Broken(_)
    ));
}

/// The scratch sweep clears what a DEAD recorder left behind and nothing
/// else. A file a recorder still holds belongs to a live run — two
/// campaigns sharing an out-dir is how that happens — and deleting it
/// destroys that run's trace, surfacing much later as an unexplained
/// missing artifact. Liveness is the recorder's lock on its file, never its
/// pid: a pid is reused, and one in another pid namespace or owned by
/// another user reads as dead to `kill(pid, 0)`.
#[cfg(unix)]
#[test]
fn the_scratch_sweep_spares_a_live_recorders_file() {
    let directory = tempfile::tempdir().unwrap();
    let trace_path = directory.path().join("generation-7.patina");

    let live = NativeTraceSink::create(&trace_path).unwrap();
    let stale = directory.path().join(".generation-7.patina.tmp.1.0");
    let other_generation = directory.path().join(".generation-70.patina.tmp.1.0");
    for path in [&stale, &other_generation] {
        fs::write(path, b"x").unwrap();
    }

    remove_dead_scratch(&trace_path);
    assert!(
        live.temp_path.exists(),
        "a live recorder's scratch must be spared"
    );
    assert!(!stale.exists(), "a dead recorder's scratch must be swept");
    assert!(
        other_generation.exists(),
        "another generation's scratch is not this one's to sweep"
    );
}

/// The supervisor's half of the recorder-budget fix. A trace that never
/// landed fails the run — EXCEPT when the recorder left an abandoned-trace
/// marker saying it gave up after the guest had already finished, in which
/// case the guest's own status is the run's answer. Both cases still remove
/// the scratch file, so nothing unreplayable is left behind for a later
/// `replay` to trip over.
#[cfg(unix)]
#[test]
fn an_abandoned_trace_is_reported_while_a_missing_one_fails() {
    use patina_dst_trace::abandoned_trace_marker;
    use std::io::Write;

    let directory = tempfile::tempdir().unwrap();

    let final_path = directory.path().join("abandoned.patina");
    let mut sink = NativeTraceSink::create(&final_path).unwrap();
    let temp_path = sink.temp_path.clone();
    sink.file
        .as_mut()
        .unwrap()
        .write_all(&abandoned_trace_marker(
            "resource-limit",
            "serialized trace is 999 bytes; limit is 100",
        ))
        .unwrap();
    let failure = sink.commit().unwrap_err();
    assert!(
        matches!(failure, TraceCommitFailure::Abandoned(_)),
        "a marker must classify as abandoned; got {}",
        failure.reason()
    );
    assert!(
        failure.reason().contains("abandoned this trace")
            && failure.reason().contains("resource-limit"),
        "the reported reason must name what happened; got {}",
        failure.reason()
    );
    assert!(!temp_path.exists() && !final_path.exists());

    // An empty trace is what a guest that died mid-run leaves: nothing said
    // why, so it stays a failure.
    let final_path = directory.path().join("empty.patina");
    let sink = NativeTraceSink::create(&final_path).unwrap();
    let temp_path = sink.temp_path.clone();
    let failure = sink.commit().unwrap_err();
    assert!(
        matches!(failure, TraceCommitFailure::Broken(_)),
        "an unexplained empty trace must stay a failure; got {}",
        failure.reason()
    );
    assert!(!temp_path.exists() && !final_path.exists());
}
