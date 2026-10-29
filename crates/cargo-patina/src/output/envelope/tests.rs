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
    for absent in [
        "trace",
        "seed",
        "fault_reports",
        "runtime_findings",
        "crash_restart",
        "refusal",
        "guest_exit",
        "verdicts",
        "sdk",
        "schedule_policy",
    ] {
        assert!(json.get(absent).is_none(), "{absent} must be omitted");
    }
}

/// Every key a fully-populated run envelope emits, pinned. The list is the
/// contract: an existing key that disappears or is renamed by a later change
/// breaks this outright, which is the point — the outcome-channel fields are
/// strictly ADDITIVE to `patina.result/v1`.
const ENVELOPE_KEYS: &[&str] = &[
    "artifact",
    "content_hash",
    "coverage",
    "crash_restart",
    "exit_code",
    "family",
    "fault_reports",
    "finding_details",
    "findings",
    "fingerprint",
    "guest_exit",
    "message",
    "output_path",
    "refusal",
    "render",
    "result",
    "result_line",
    "runtime_findings",
    "schedule_policy",
    "schema",
    "sdk",
    "seed",
    "stderr",
    "stdout",
    "trace",
    "verb",
    "verdicts",
];

fn fully_populated_envelope() -> Envelope {
    let mut env = Envelope::new("run", "violation", 134);
    env.family = Some("native".into());
    env.artifact = Some("guest".into());
    env.fingerprint = Some("patina-native".into());
    env.seed = Some(7);
    env.coverage = Some(CoverageReport {
        edges_total: 10,
        edges_covered: 4,
        covered_permille: 400,
        hits_total: 99,
        hits_max: 12,
        saturated: 1,
        map_path: Some(PathBuf::from("run.covmap")),
    });
    env.render = Some("out.html".into());
    env.findings = vec!["libc::open".into()];
    env.finding_details = vec![serde_json::json!({"symbol": "libc::open"})];
    env.output_path = Some("guest".into());
    env.content_hash = Some("sha256:00".into());
    env.result_line = Some("PATINA_RESULT ok=1".into());
    env.verdicts = Some(serde_json::json!([
        {"seq": 0, "kind": "pass", "label": "queue-drained", "detail": ""}
    ]));
    env.sdk = Some(serde_json::json!({"enabled": true, "sites": []}));
    env.schedule_policy = Some(serde_json::json!({"pct": true, "bug_depth": 1}));
    env.fault_reports = Some(serde_json::json!({"fs": {"vacuous": false}}));
    env.runtime_findings = vec![serde_json::json!({"source": "liveness"})];
    env.crash_restart = Some(serde_json::json!({
        "reached": true,
        "crash_count": 1,
        "restart_count": 1
    }));
    env.refusal = Some(Refusal {
        class: "fingerprint_mismatch".into(),
        message: "trace fingerprint mismatch".into(),
        guest_exit_code: None,
        mismatch: Some("mount_metadata"),
    });
    env.guest_exit = Some(GuestExit {
        code: 134,
        signal: Some(6),
        core: false,
    });
    env.stdout = Some(String::new());
    env.stderr = Some(String::new());
    env.message = Some("detail".into());
    env.trace = Some(TraceFacts {
        path: "t.patina".into(),
        format_version: 4,
        timelines: vec!["main".into()],
        event_count: 3,
        metadata: serde_json::Value::Null,
    });
    env
}

#[test]
fn envelope_keeps_every_field_and_adds_the_outcome_channel_ones() {
    let json = fully_populated_envelope().to_json();
    let mut keys: Vec<&str> = json
        .as_object()
        .expect("envelope is an object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, ENVELOPE_KEYS);
}
