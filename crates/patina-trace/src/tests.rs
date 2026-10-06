//! Cross-module trace fixture and integration tests.

use super::*;
use patina_dst_abi::{
    ClockKind, Datagram, Fd, Operation, Outcome, SendDisposition, SendReport, SignalTarget,
    SocketId, TaskId,
};
use std::fs;
use tempfile::tempdir;

pub(super) fn operation() -> Operation {
    Operation::ClockNow {
        clock: ClockKind::Monotonic,
    }
}

#[test]
fn a_current_bundle_must_state_its_run_facts() {
    // Epoch, boot origin and node name are required: a bundle missing
    // either does not parse.
    let bytes = include_bytes!("../tests/fixtures/format-15.patina");
    for field in ["realtime_epoch_nanos", "boot_origin_nanos", "hostname"] {
        let mut value: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        assert!(
            value["metadata"]
                .as_object_mut()
                .unwrap()
                .remove(field)
                .is_some()
        );
        let bytes = serde_json::to_vec(&value).unwrap();
        assert!(
            matches!(
                TraceBundle::from_slice(&bytes),
                Err(TraceError::Parse { .. })
            ),
            "a bundle without {field} must not parse"
        );
    }
}

#[test]
fn memory_operations_fixture_decodes_and_replays() {
    // Checked-in feature fixture pins the page cache's and anonymous
    // files' operations and one of the filesystem family's.
    let bytes = include_bytes!("../tests/fixtures/format-15-memory.patina");
    let bundle = TraceBundle::from_slice(bytes).unwrap();
    bundle.validate().unwrap();
    assert_eq!(bundle.to_bytes().unwrap(), bytes);
    let expected = [
        (
            Operation::FsCreateAnonymous {
                name: "buffer".into(),
                mode: 0o777,
                seals: 1,
                huge_page: 0,
            },
            Outcome::Handle(Fd(4)),
        ),
        (
            Operation::FsAddSeals {
                fd: Fd(4),
                seals: 8,
                writably_mapped: false,
            },
            Outcome::Unit,
        ),
        (Operation::FsSeals { fd: Fd(4) }, Outcome::U64(9)),
        (
            Operation::FsWriteBackAt {
                fd: Fd(3),
                offset: 4096,
                bytes: b"mapped".to_vec(),
            },
            Outcome::Usize(6),
        ),
        (
            Operation::FsRenameWhiteout {
                from: "/a".into(),
                to: "/b".into(),
            },
            Outcome::Unit,
        ),
    ];
    let mut replay = Replayer::from_bundle(bundle, "fixture-fingerprint", "main").unwrap();
    for (operation, outcome) in expected {
        assert_eq!(replay.expect(&operation).unwrap(), outcome);
    }
    replay.finish().unwrap();
}

#[test]
fn sparse_file_operations_fixture_decodes_and_replays() {
    // Checked-in feature fixture pins a file's allocation at the boundary:
    // `fs_allocate`'s mode, `fs_seek`'s data and hole whences and their
    // `ENXIO` answer, and the allocated blocks a metadata outcome carries.
    use patina_dst_abi::{
        EffectError, ErrorCode, FsAllocateMode, FsEntryKind, FsMetadata, SeekWhence,
    };
    let bytes = include_bytes!("../tests/fixtures/format-15-sparse.patina");
    let bundle = TraceBundle::from_slice(bytes).unwrap();
    bundle.validate().unwrap();
    assert_eq!(bundle.to_bytes().unwrap(), bytes);
    let expected = [
        (
            Operation::FsAllocate {
                fd: Fd(3),
                offset: 4096,
                len: 8192,
                mode: FsAllocateMode::PunchHole,
                keep_size: true,
            },
            Outcome::Unit,
        ),
        (
            Operation::FsSeek {
                fd: Fd(3),
                offset: 0,
                whence: SeekWhence::Data,
            },
            Outcome::U64(12288),
        ),
        (
            Operation::FsSeek {
                fd: Fd(3),
                offset: 1 << 40,
                whence: SeekWhence::Hole,
            },
            Outcome::Error(EffectError::new(ErrorCode::NoSuchPosition, "past the end")),
        ),
        (
            Operation::FsFdMetadata { fd: Fd(3) },
            Outcome::Metadata(FsMetadata {
                kind: FsEntryKind::File,
                len: 10_737_418_245,
                blocks: 16,
                ino: 5,
                nlink: 1,
                atime_nanos: 0,
                mtime_nanos: 0,
                ctime_nanos: 0,
                btime_nanos: 0,
                mode: 0o644,
            }),
        ),
    ];
    let mut replay = Replayer::from_bundle(bundle, "fixture-fingerprint", "main").unwrap();
    for (operation, outcome) in expected {
        assert_eq!(replay.expect(&operation).unwrap(), outcome);
    }
    replay.finish().unwrap();
}

#[test]
fn network_operations_fixture_decodes_and_replays() {
    // Checked-in feature fixture pins the network family's operations and
    // a marked datagram's encoding.
    let bytes = include_bytes!("../tests/fixtures/format-15-network.patina");
    let expected = [
        (
            Operation::NetBindShared {
                address: "127.0.0.1:80".into(),
            },
            Outcome::Socket(SocketId(1)),
        ),
        (
            Operation::NetConnect {
                socket: SocketId(1),
                local: "127.0.0.1:80".into(),
                peer: Some("127.0.0.1:81".into()),
            },
            Outcome::Unit,
        ),
        (
            Operation::NetMark {
                socket: SocketId(1),
                tos: 0x10,
                source: Some("127.0.0.2".into()),
            },
            Outcome::Unit,
        ),
        (
            Operation::NetSend {
                socket: SocketId(1),
                to: "127.0.0.1:9".into(),
                bytes: b"nobody".to_vec(),
                now_nanos: 0,
            },
            Outcome::SendReport(SendReport {
                written: 6,
                copies: 0,
                delivery_nanos: Vec::new(),
                disposition: SendDisposition::Unreachable,
            }),
        ),
        (
            Operation::NetRecv {
                socket: SocketId(1),
                now_nanos: 0,
            },
            Outcome::Datagram(Some(Datagram {
                packet_id: 3,
                from: "127.0.0.1:81".into(),
                to: "0.0.0.0:80".into(),
                bytes: b"hi".to_vec(),
                delivery_nanos: 0,
                dialed: "127.0.0.1:80".into(),
                tos: 0x10,
            })),
        ),
    ];
    // The fixture is exactly what a recording of these decisions writes.
    let recorded = TraceBundle::new(
        RunMetadata::new(42, "fixture-fingerprint", 0, "patina").with_boot_origin_nanos(1000),
        expected
            .iter()
            .enumerate()
            .map(|(sequence, (operation, outcome))| {
                TraceEvent::new(sequence as u64, operation.clone(), outcome.clone())
            })
            .collect(),
    );
    assert_eq!(
        String::from_utf8(recorded.to_bytes().unwrap()).unwrap(),
        String::from_utf8(bytes.to_vec()).unwrap()
    );
    let bundle = TraceBundle::from_slice(bytes).unwrap();
    bundle.validate().unwrap();
    assert_eq!(bundle.format_version, TRACE_FORMAT_VERSION);
    let mut replay = Replayer::from_bundle(bundle, "fixture-fingerprint", "main").unwrap();
    for (operation, outcome) in expected {
        assert_eq!(replay.expect(&operation).unwrap(), outcome);
    }
    replay.finish().unwrap();
}

#[test]
fn signal_operations_fixture_decodes_and_replays() {
    // Checked-in feature fixture pins both target encodings and every field.
    const SIGUSR1: u8 = 10;
    const SIGUSR2: u8 = 12;
    const SI_USER: i32 = 0;
    const SI_TKILL: i32 = -6;
    let bytes = include_bytes!("../tests/fixtures/format-15-signals.patina");
    let bundle = TraceBundle::from_slice(bytes).unwrap();
    bundle.validate().unwrap();
    assert_eq!(bundle.format_version, TRACE_FORMAT_VERSION);
    assert_eq!(bundle.to_bytes().unwrap(), bytes);
    let expected = [
        Operation::SignalGenerated {
            seq: 1,
            sig: SIGUSR1,
            target: SignalTarget::Process,
            code: SI_USER,
            value: 0,
        },
        Operation::SignalGenerated {
            seq: 2,
            sig: SIGUSR2,
            target: SignalTarget::Task(TaskId(2)),
            code: SI_TKILL,
            value: 123,
        },
    ];
    let mut replay = Replayer::from_bundle(bundle, "fixture-fingerprint", "main").unwrap();
    for operation in expected {
        assert_eq!(replay.expect(&operation).unwrap(), Outcome::Unit);
    }
    replay.finish().unwrap();
}

#[test]
fn records_loads_and_strictly_replays() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("run.patina");
    let mut recorder = Recorder::new(RunMetadata::new(7, "fingerprint", 0, "patina"));
    recorder.observe(operation(), Outcome::U64(10));
    recorder.finish(&path).unwrap();

    let mut replay = Replayer::open(&path, "fingerprint").unwrap();
    assert_eq!(replay.root_seed(), 7);
    assert_eq!(replay.expect(&operation()).unwrap(), Outcome::U64(10));
    replay.finish().unwrap();
    assert_eq!(
        TraceBundle::load(&path).unwrap().format_version,
        TRACE_FORMAT_VERSION
    );
    assert_eq!(
        fs::read_dir(directory.path()).unwrap().count(),
        1,
        "atomic write must not leave a temporary file"
    );
}

/// An abandoned trace must never be replayable as if it were a recording.
/// The marker is what a reader sees in place of a bundle, so loading one
/// has to refuse by NAME — "the recorder abandoned this trace" — rather
/// than as an unexplained parse failure.
#[test]
fn an_abandoned_trace_marker_is_refused_by_name() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("abandoned.patina");
    let marker = abandoned_trace_marker(
        "resource-limit",
        "serialized trace is 999 bytes; limit is 100",
    );
    assert_eq!(
        parse_abandoned_trace_marker(&marker),
        Some(AbandonedTrace {
            reason: "resource-limit".into(),
            detail: "serialized trace is 999 bytes; limit is 100".into(),
        })
    );
    fs::write(&path, &marker).unwrap();

    let error = TraceBundle::load(&path).unwrap_err();
    let message = error.to_string();
    assert!(
        matches!(&error, TraceError::Incomplete { .. })
            && message.contains("abandoned this trace")
            && message.contains("resource-limit")
            && message.contains("cannot be replayed"),
        "an abandoned trace must be refused by name; got {message}"
    );
    assert!(
        TraceBundle::from_slice(&marker).is_err(),
        "the transport path must refuse a marker too"
    );

    // A real bundle is never mistaken for a marker.
    let bundle = TraceBundle::new(RunMetadata::new(7, "fingerprint", 0, "patina"), Vec::new());
    assert_eq!(
        parse_abandoned_trace_marker(&bundle.to_bytes().unwrap()),
        None
    );
}
