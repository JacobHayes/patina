//! The trace format on disk: current-format fixtures load, validate and
//! re-encode byte-for-byte, any other format version is refused, and malformed
//! inputs are rejected with the typed error taxonomy.

use std::path::PathBuf;

use patina_dst_abi::Outcome;
use patina_dst_trace::{TRACE_FORMAT_VERSION, TraceBundle, TraceError};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

#[test]
fn current_format_fixture_parses_validates_and_is_canonically_encoded() {
    let bundle = TraceBundle::load(fixture("format-11.patina")).unwrap();
    assert_eq!(bundle.format_version, TRACE_FORMAT_VERSION);
    bundle.validate().unwrap();
    // A run recorded with no fault configuration omits the field from the
    // canonical form rather than writing an explicit empty object.
    assert_eq!(bundle.metadata.faults, None);
    let main = bundle.resolved_timeline("main").unwrap();
    assert_eq!(main.len(), 2);
    assert_eq!(main[0].outcome, Outcome::U64(1000));
    assert_eq!(main[1].outcome, Outcome::Bytes(vec![1, 2, 3, 4]));

    // The current-format fixture is exactly what the writer emits: compact,
    // single-line JSON with base64 byte payloads. This both documents the
    // on-disk encoding and guards against the fixture drifting from the writer.
    let reencoded = bundle.to_bytes().unwrap();
    assert_eq!(
        std::fs::read(fixture("format-11.patina")).unwrap(),
        reencoded
    );
    let text = String::from_utf8(reencoded).unwrap();
    assert!(
        text.contains("\"value\":\"AQIDBA==\""),
        "bytes not base64: {text}"
    );
    assert_eq!(
        text.lines().count(),
        1,
        "current encoding must be single-line"
    );
}

#[test]
fn current_crash_restart_fixture_parses_validates_and_is_canonical() {
    let bundle = TraceBundle::load(fixture("format-11-crash-restart.patina")).unwrap();
    bundle.validate().unwrap();
    assert_eq!(bundle.format_version, TRACE_FORMAT_VERSION);
    assert_eq!(bundle.timelines[0].lifecycle.len(), 5);
    assert_eq!(bundle.timelines[0].decisions[0].order, 1);
    assert_eq!(bundle.timelines[0].decisions[1].incarnation, 1);
    assert_eq!(
        std::fs::read(fixture("format-11-crash-restart.patina")).unwrap(),
        bundle.to_bytes().unwrap()
    );
}

#[test]
fn any_other_format_version_is_refused() {
    // The reader decodes only the current format: any other version tag, older
    // or newer, is refused before the body is interpreted, even when the body
    // is otherwise a valid current bundle.
    let current = std::fs::read(fixture("format-11.patina")).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&current).unwrap();
    for version in [0, TRACE_FORMAT_VERSION - 1, TRACE_FORMAT_VERSION + 1, 99] {
        value["format_version"] = serde_json::Value::from(version);
        let bytes = serde_json::to_vec(&value).unwrap();
        let error = TraceBundle::from_slice(&bytes).unwrap_err();
        assert!(
            matches!(error, TraceError::UnsupportedVersion { found } if found == version),
            "format {version}: expected UnsupportedVersion, got {error:?}"
        );
    }
}

#[test]
fn malformed_fixture_is_rejected_as_a_parse_error() {
    let error = TraceBundle::load(fixture("malformed.patina")).unwrap_err();
    assert!(
        matches!(error, TraceError::Parse { .. }),
        "expected Parse, got {error:?}"
    );
}
