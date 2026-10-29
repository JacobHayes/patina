//! Regression tests for envelope.

use super::*;

/// Absent, never zero: fields nothing produced are omitted, so a consumer
/// never reads a fabricated empty object as "the plane reported nothing".
#[test]
fn envelope_omits_fields_nothing_produced() {
    let mut env = Envelope::new("audit", "ok", 0);
    env.family = Some("native".into());
    env.findings = vec!["libc::open".into()];
    let json = env.to_json();
    assert_eq!(json["schema"], ENVELOPE_SCHEMA);
    assert_eq!(json["verb"], "audit");
    assert_eq!(json["result"], "ok");
    assert_eq!(json["findings"][0], "libc::open");
    for absent in ["seed", "fault_reports", "refusal", "verdicts"] {
        assert!(json.get(absent).is_none(), "{absent} must be omitted");
    }
}
