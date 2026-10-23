//! Effect serialization tags, payloads, and round-trip tests.

use super::*;

/// Every variant's trace tag is its snake_case name, not a discriminant from
/// declaration order, so a rename or a switch to order-based tagging breaks
/// here and every recorded trace stops decoding at the same instant.
#[test]
fn operation_variant_tags_are_pinned_by_name_not_declaration_order() {
    let cases: &[(Operation, &str)] = &[
        (
            Operation::FsRead {
                fd: Fd(3),
                max_len: 8,
            },
            "fs_read",
        ),
        (
            Operation::FsSeek {
                fd: Fd(3),
                offset: 0,
                whence: SeekWhence::Start,
            },
            "fs_seek",
        ),
        (Operation::FsCrash, "fs_crash"),
        (
            // The positional offset survives exactly, so a pread/pwrite
            // reconciles only against the same offset on replay.
            Operation::FsReadAt {
                fd: Fd(7),
                offset: 1 << 40,
                max_len: 4096,
            },
            "fs_read_at",
        ),
        (
            Operation::FsWriteAt {
                fd: Fd(7),
                offset: 1 << 40,
                bytes: vec![9, 8, 7],
            },
            "fs_write_at",
        ),
        (
            Operation::FsSetTimesByPath {
                path: "/state".into(),
                atime_nanos: None,
                mtime_nanos: Some(22),
            },
            "fs_set_times_by_path",
        ),
        (
            Operation::SignalGenerated {
                seq: 7,
                sig: 10,
                target: SignalTarget::Task(TaskId(3)),
                code: -6,
                value: 42,
            },
            "signal_generated",
        ),
        (
            Operation::Verdict {
                verdict_kind: VerdictKind::AbortIntent,
                label: "checksum".into(),
                detail: "{\"page\":7}".into(),
            },
            "verdict",
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

/// Byte payloads serialize as base64 strings, never JSON number arrays, and
/// base64 is the only payload encoding read. A custom-op key is arbitrary guest
/// bytes, so non-UTF-8 and empty keys survive verbatim.
#[test]
fn byte_payloads_are_base64_strings_and_refuse_number_arrays() {
    let write = Operation::FsWrite {
        fd: Fd(3),
        bytes: vec![1, 2, 3, 4],
    };
    let json = serde_json::to_string(&write).unwrap();
    assert!(
        json.contains("\"bytes\":\"AQIDBA==\""),
        "unexpected JSON: {json}"
    );
    assert_eq!(serde_json::from_str::<Operation>(&json).unwrap(), write);

    let outcome = Outcome::Bytes(vec![255, 0, 128]);
    let json = serde_json::to_string(&outcome).unwrap();
    assert_eq!(json, "{\"kind\":\"bytes\",\"value\":\"/wCA\"}");
    assert_eq!(serde_json::from_str::<Outcome>(&json).unwrap(), outcome);

    let array = "{\"kind\":\"bytes\",\"value\":[1,2,3,4]}";
    assert!(serde_json::from_str::<Outcome>(array).is_err());

    for key in [vec![0x00, 0xff, 0xfe, b'k', 0x80], Vec::new()] {
        let operation = Operation::CustomOp {
            label: "s3.get_object".into(),
            key,
        };
        let json = serde_json::to_string(&operation).unwrap();
        assert_eq!(serde_json::from_str::<Operation>(&json).unwrap(), operation);
    }
}
