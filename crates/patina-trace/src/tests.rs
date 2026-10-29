//! Cross-module trace fixture and integration tests.

use super::*;
use patina_dst_abi::{
    ClockKind, Datagram, EffectError, ErrorCode, Fd, FsAllocateMode, FsEntryKind, FsMetadata,
    Operation, Outcome, SeekWhence, SendDisposition, SendReport, SignalTarget, SocketId, TaskId,
};
use std::fs;
use tempfile::tempdir;

pub(super) fn operation() -> Operation {
    Operation::ClockNow {
        clock: ClockKind::Monotonic,
    }
}

/// The run facts a current bundle must state: epoch, boot origin, node name,
/// CPU count and time model are required, the CPU count must be one a run can
/// have, and a bundle from another time model is refused by that model.
#[test]
fn a_current_bundle_must_state_valid_run_facts() {
    let bytes = include_bytes!("../tests/fixtures/current.patina");
    let edited = |edit: &dyn Fn(&mut serde_json::Map<String, serde_json::Value>)| {
        let mut value: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        edit(value["metadata"].as_object_mut().unwrap());
        TraceBundle::from_slice(&serde_json::to_vec(&value).unwrap())
    };
    for field in [
        "realtime_epoch_nanos",
        "boot_origin_nanos",
        "hostname",
        "cpus",
        "time_model",
    ] {
        assert!(
            matches!(
                edited(&|metadata| assert!(metadata.remove(field).is_some())),
                Err(TraceError::Parse { .. })
            ),
            "a bundle without {field} must not parse"
        );
    }
    for cpus in [0, patina_dst_abi::MAX_CPUS + 1] {
        assert!(
            matches!(
                edited(&|metadata| {
                    metadata.insert("cpus".into(), cpus.into());
                }),
                Err(TraceError::Invalid(_))
            ),
            "a bundle stating {cpus} CPUs must be invalid"
        );
    }
    let bundle = edited(&|metadata| {
        metadata.insert("cpus".into(), patina_dst_abi::MAX_CPUS.into());
    })
    .unwrap();
    assert_eq!(bundle.metadata.cpus, patina_dst_abi::MAX_CPUS);
    for model in [
        patina_dst_abi::TIME_MODEL - 1,
        patina_dst_abi::TIME_MODEL + 1,
    ] {
        assert!(matches!(
            edited(&|metadata| {
                metadata.insert("time_model".into(), model.into());
            }),
            Err(TraceError::UnsupportedTimeModel { found }) if found == model
        ));
    }
}

/// Decode a checked-in feature fixture, require it to be the canonical
/// encoding, and strictly replay `expected` from it.
fn assert_fixture_replays(bytes: &[u8], expected: impl IntoIterator<Item = (Operation, Outcome)>) {
    let bundle = TraceBundle::from_slice(bytes).unwrap();
    bundle.validate().unwrap();
    assert_eq!(bundle.to_bytes().unwrap(), bytes);
    let mut replay = Replayer::from_bundle(bundle, "fixture-fingerprint", "main").unwrap();
    for (operation, outcome) in expected {
        assert_eq!(replay.expect(&operation).unwrap(), outcome);
    }
    replay.finish().unwrap();
}

/// Checked-in feature fixtures pin the on-disk encoding of each operation
/// family: the page cache's and anonymous files', a sparse file's allocation
/// and seek whences, the network family with a marked datagram, and both
/// signal target encodings.
#[test]
fn feature_fixtures_decode_canonically_and_replay() {
    let memory = [
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
    assert_fixture_replays(
        include_bytes!("../tests/fixtures/current-memory.patina"),
        memory,
    );

    let sparse = [
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
    assert_fixture_replays(
        include_bytes!("../tests/fixtures/current-sparse.patina"),
        sparse,
    );

    let network = [
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
    assert_fixture_replays(
        include_bytes!("../tests/fixtures/current-network.patina"),
        network,
    );

    const SIGUSR1: u8 = 10;
    const SIGUSR2: u8 = 12;
    const SI_USER: i32 = 0;
    const SI_TKILL: i32 = -6;
    let signals = [
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
    assert_fixture_replays(
        include_bytes!("../tests/fixtures/current-signals.patina"),
        signals.map(|operation| (operation, Outcome::Unit)),
    );
}

#[test]
fn records_loads_and_strictly_replays() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("run.patina");
    let mut recorder = Recorder::new(RunMetadata::new(7, "fingerprint", 0, "patina"));
    recorder.observe(operation(), Outcome::U64(10));
    recorder.observe(Operation::FsDup { fd: Fd(3) }, Outcome::Handle(Fd(4)));
    recorder.finish(&path).unwrap();
    assert_eq!(
        fs::read_dir(directory.path()).unwrap().count(),
        1,
        "atomic write must not leave a temporary file"
    );
    let bundle = TraceBundle::load(&path).unwrap();
    assert_eq!(bundle.format_version, TRACE_FORMAT_VERSION);
    assert_eq!(bundle.to_bytes().unwrap(), fs::read(&path).unwrap());

    let mut replay = Replayer::open(&path, "fingerprint").unwrap();
    assert_eq!(replay.root_seed(), 7);
    assert_eq!(replay.expect(&operation()).unwrap(), Outcome::U64(10));
    assert_eq!(
        replay.expect(&Operation::FsDup { fd: Fd(3) }).unwrap(),
        Outcome::Handle(Fd(4))
    );
    replay.finish().unwrap();
}

/// An abandoned trace must never be replayable as if it were a recording.
/// The marker is what a reader sees in place of a bundle, so loading one
/// refuses it as an incomplete trace carrying its reason, rather than as an
/// unexplained parse failure.
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
        matches!(&error, TraceError::Incomplete { .. }) && message.contains("resource-limit"),
        "an abandoned trace must be refused as one, with its reason; got {message}"
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
