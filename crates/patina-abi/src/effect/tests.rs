//! Effect serialization tags, payloads, and round-trip tests.

use super::*;

#[test]
fn operation_variant_tags_are_pinned_by_name_not_declaration_order() {
    // `Operation` is `#[serde(tag = "kind", rename_all = "snake_case")]`, so
    // every variant's trace tag is its snake_case NAME, not a discriminant
    // derived from declaration order. Inserting a new variant anywhere is
    // therefore additive and can never renumber an existing one. This test
    // pins the exact tag string of representative pre-existing variants
    // (and the two positional-I/O additions) so any accidental switch to
    // order-based tagging -- or a variant rename -- breaks loudly and every
    // recorded trace stops decoding at the same instant this test fails.
    let cases: &[(Operation, &str)] = &[
        (
            Operation::FsRead {
                fd: Fd(3),
                max_len: 8,
            },
            "fs_read",
        ),
        (
            Operation::FsWrite {
                fd: Fd(3),
                bytes: vec![1],
            },
            "fs_write",
        ),
        (
            Operation::FsSeek {
                fd: Fd(3),
                offset: 0,
                whence: SeekWhence::Start,
            },
            "fs_seek",
        ),
        (Operation::FsClose { fd: Fd(3) }, "fs_close"),
        (Operation::FsSync { fd: Fd(3) }, "fs_sync"),
        (Operation::FsCrash, "fs_crash"),
        (
            Operation::FsReadAt {
                fd: Fd(3),
                offset: 4096,
                max_len: 8,
            },
            "fs_read_at",
        ),
        (
            Operation::FsWriteAt {
                fd: Fd(3),
                offset: 4096,
                bytes: vec![1],
            },
            "fs_write_at",
        ),
    ];
    for (operation, tag) in cases {
        let json = serde_json::to_string(operation).unwrap();
        let needle = format!("\"kind\":\"{tag}\"");
        assert!(
            json.contains(&needle),
            "variant tag drifted: expected {needle} in {json}"
        );
        assert_eq!(
            &serde_json::from_str::<Operation>(&json).unwrap(),
            operation
        );
    }
}

#[test]
fn signal_generated_round_trips_and_mismatches() {
    let operation = Operation::SignalGenerated {
        seq: 7,
        sig: 10,
        target: SignalTarget::Task(TaskId(3)),
        code: -6,
        value: 42,
    };
    let json = serde_json::to_string(&operation).unwrap();
    assert!(json.contains("\"kind\":\"signal_generated\""));
    assert!(json.contains("\"seq\":7"));
    assert!(json.contains("\"sig\":10"));
    assert!(json.contains("\"target\":{"));
    assert!(json.contains("\"code\":-6"));
    assert!(json.contains("\"value\":42"));
    assert_eq!(serde_json::from_str::<Operation>(&json).unwrap(), operation);

    let different_seq = Operation::SignalGenerated {
        seq: 8,
        sig: 10,
        target: SignalTarget::Task(TaskId(3)),
        code: -6,
        value: 42,
    };
    let different_sig = Operation::SignalGenerated {
        seq: 7,
        sig: 12,
        target: SignalTarget::Task(TaskId(3)),
        code: -6,
        value: 42,
    };
    let different_target = Operation::SignalGenerated {
        seq: 7,
        sig: 10,
        target: SignalTarget::Process,
        code: -6,
        value: 42,
    };
    assert_ne!(different_seq, operation);
    assert_ne!(different_sig, operation);
    assert_ne!(different_target, operation);
}

#[test]
fn positional_io_offset_survives_round_trip() {
    // The positional offset must be preserved exactly through the trace so a
    // pread/pwrite reconciles only against the same offset on replay.
    for operation in [
        Operation::FsReadAt {
            fd: Fd(7),
            offset: 1 << 40,
            max_len: 4096,
        },
        Operation::FsWriteAt {
            fd: Fd(7),
            offset: 1 << 40,
            bytes: vec![9, 8, 7],
        },
    ] {
        let json = serde_json::to_string(&operation).unwrap();
        assert!(
            json.contains("\"offset\":1099511627776"),
            "offset lost: {json}"
        );
        assert_eq!(serde_json::from_str::<Operation>(&json).unwrap(), operation);
    }
}

#[test]
fn operation_json_is_tagged_and_round_trips() {
    let operations = [
        Operation::FsOpen {
            path: "/state".into(),
            flags: OpenFlags::read_only(),
        },
        Operation::FsSetTimes {
            fd: Fd(3),
            atime_nanos: Some(11),
            mtime_nanos: None,
        },
        Operation::FsSetTimesByPath {
            path: "/state".into(),
            atime_nanos: None,
            mtime_nanos: Some(22),
        },
        Operation::FsLink {
            from: "/state/a".into(),
            to: "/state/b".into(),
        },
        Operation::FsSymlink {
            target: "../target".into(),
            link_path: "/state/link".into(),
        },
        Operation::FsReadLink {
            path: "/state/link".into(),
        },
        Operation::FsMakeFifo {
            path: "/state/pipe".into(),
            mode: 0o644,
        },
    ];
    for operation in operations {
        let json = serde_json::to_string(&operation).unwrap();
        assert!(json.contains("\"kind\""));
        assert_eq!(serde_json::from_str::<Operation>(&json).unwrap(), operation);
    }
}

#[test]
fn byte_payloads_serialize_as_base64_strings_and_round_trip() {
    // Byte payloads must serialize as base64 strings rather than JSON number
    // arrays; this is the whole point of the compact trace encoding.
    let write = Operation::FsWrite {
        fd: Fd(3),
        bytes: vec![1, 2, 3, 4],
    };
    let json = serde_json::to_string(&write).unwrap();
    assert!(
        json.contains("\"bytes\":\"AQIDBA==\""),
        "unexpected JSON: {json}"
    );
    assert!(
        !json.contains('['),
        "byte payload leaked a number array: {json}"
    );
    assert_eq!(serde_json::from_str::<Operation>(&json).unwrap(), write);

    let outcome = Outcome::Bytes(vec![255, 0, 128]);
    let json = serde_json::to_string(&outcome).unwrap();
    assert_eq!(json, "{\"kind\":\"bytes\",\"value\":\"/wCA\"}");
    assert_eq!(serde_json::from_str::<Outcome>(&json).unwrap(), outcome);
}

#[test]
fn byte_payloads_refuse_a_number_array() {
    // Base64 is the only payload encoding read.
    let array = "{\"kind\":\"bytes\",\"value\":[1,2,3,4]}";
    assert!(serde_json::from_str::<Outcome>(array).is_err());
}

#[test]
fn verdict_operation_tag_is_its_snake_case_name() {
    let operation = Operation::Verdict {
        verdict_kind: VerdictKind::AbortIntent,
        label: "checksum".into(),
        detail: "{\"page\":7}".into(),
    };
    let json = serde_json::to_string(&operation).unwrap();
    assert!(json.contains("\"kind\":\"verdict\""), "{json}");
    assert!(json.contains("\"abort_intent\""), "{json}");
    assert_eq!(serde_json::from_str::<Operation>(&json).unwrap(), operation);
}

// The custom-op key is arbitrary guest bytes, not text: it must survive the
// trace round trip verbatim, including bytes that are not valid UTF-8 and the
// empty key. A key that silently re-encoded would make a replay key check
// compare something other than what the guest asked.
#[test]
fn custom_op_operation_tag_and_opaque_key_round_trip() {
    let operation = Operation::CustomOp {
        label: "s3.get_object".into(),
        key: vec![0x00, 0xff, 0xfe, b'k', 0x80],
    };
    let json = serde_json::to_string(&operation).unwrap();
    assert!(json.contains("\"kind\":\"custom_op\""), "{json}");
    assert_eq!(serde_json::from_str::<Operation>(&json).unwrap(), operation);

    let empty = Operation::CustomOp {
        label: String::new(),
        key: Vec::new(),
    };
    let json = serde_json::to_string(&empty).unwrap();
    assert_eq!(serde_json::from_str::<Operation>(&json).unwrap(), empty);
}
