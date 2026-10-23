//! Regression tests for trace.

use super::*;

use std::fs;

use patina_dst_trace::{RunMetadata, Sha256Digest, remove_dead_scratch};

fn identity() -> NativeIdentityRecord {
    NativeIdentityRecord {
        executable_sha256: Sha256Digest([1; 32]),
        supervisor_sha256: Sha256Digest([2; 32]),
        patina_version: "1.0.0".into(),
        shim_bundle_sha256: Sha256Digest([3; 32]),
        target: "x86_64-unknown-linux-gnu".into(),
    }
}

/// The supervisor, not the recorder linked into the guest, puts the build
/// identity into a recording: a recorder that writes none (one linked before
/// identities existed, or one that is not told about them) still commits a
/// trace that names its build, so it replays against that build.
#[cfg(unix)]
#[test]
fn commit_stamps_the_build_identity_into_a_trace_the_recorder_left_without_one() {
    use std::io::Write;

    let directory = tempfile::tempdir().unwrap();
    let final_path = directory.path().join("stamped.patina");
    let recorded = TraceBundle::new(RunMetadata::new(7, "fp-test", 0, "patina"), Vec::new());
    assert!(recorded.metadata.native.is_none());
    let mut sink = NativeTraceSink::create(&final_path).unwrap();
    let temp_path = sink.temp_path.clone();
    sink.file
        .as_mut()
        .unwrap()
        .write_all(&recorded.to_bytes().unwrap())
        .unwrap();

    assert_eq!(sink.commit(&identity()).ok(), Some(final_path.clone()));
    let committed = TraceBundle::load(&final_path).unwrap();
    assert_eq!(committed.metadata.native, Some(identity()));
    let mut unstamped = committed.clone();
    unstamped.metadata.native = None;
    assert_eq!(
        unstamped, recorded,
        "the stamp must carry everything else as recorded"
    );
    assert!(!temp_path.exists());
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
fn commit_failures_are_classified_by_what_the_channel_saw() {
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
    let failure = sink.commit(&identity()).unwrap_err();
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
    let failure = sink.commit(&identity()).unwrap_err();
    assert!(
        matches!(failure, TraceCommitFailure::Broken(_)),
        "an unexplained empty trace must stay a failure; got {}",
        failure.reason()
    );
    assert!(!temp_path.exists() && !final_path.exists());
    // A vanished scratch file, or a complete trace the filesystem refuses to stamp, is the artifact
    // channel failing, not the run.
    {
        use std::io::Write;

        let directory = tempfile::tempdir().unwrap();

        let final_path = directory.path().join("vanished.patina");
        let sink = NativeTraceSink::create(&final_path).unwrap();
        fs::remove_file(&sink.temp_path).unwrap();
        let failure = sink.commit(&identity()).unwrap_err();
        assert!(
            matches!(failure, TraceCommitFailure::Unavailable(_)),
            "a vanished scratch file is a channel failure; got {}",
            failure.reason()
        );

        let final_path = directory.path().join("unstampable.patina");
        let recorded = TraceBundle::new(RunMetadata::new(7, "fp-test", 0, "patina"), Vec::new());
        let mut sink = NativeTraceSink::create(&final_path).unwrap();
        sink.file
            .as_mut()
            .unwrap()
            .write_all(&recorded.to_bytes().unwrap())
            .unwrap();
        // A read-only descriptor of the same complete file: it loads, and every
        // write to it fails.
        sink.file = Some(fs::File::open(&sink.temp_path).unwrap());
        let temp_path = sink.temp_path.clone();
        let failure = sink.commit(&identity()).unwrap_err();
        assert!(
            matches!(failure, TraceCommitFailure::Unavailable(_)),
            "a refused stamp is a channel failure; got {}",
            failure.reason()
        );
        assert!(!temp_path.exists() && !final_path.exists());
    }
}
