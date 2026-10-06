//! Regression tests for envelope.

use super::*;

#[test]
fn envelope_serializes_stable_shape() {
    let mut env = Envelope::new("audit", "ok", 0);
    env.family = Some("native".into());
    env.findings = vec!["libc::open".into()];
    let json = env.to_json();
    assert_eq!(json["schema"], ENVELOPE_SCHEMA);
    assert_eq!(json["verb"], "audit");
    assert_eq!(json["result"], "ok");
    assert_eq!(json["findings"][0], "libc::open");
    // Absent fields are omitted.
    assert!(json.get("trace").is_none());
    assert!(json.get("seed").is_none());
}

/// Every key a fully-populated run envelope emits, pinned. The list is the
/// contract: an existing key that disappears or is renamed by a later change
/// breaks this outright, which is the point — the outcome-channel fields are
/// strictly ADDITIVE to `patina.result/v1`.
const ENVELOPE_KEYS: &[&str] = &[
    "artifact",
    "config",
    "content_hash",
    "coverage",
    "crash_restart",
    "depth",
    "exit_code",
    "family",
    "fault_reports",
    "finding_details",
    "findings",
    "fingerprint",
    "guest_exit",
    "markers",
    "message",
    "output_path",
    "refusal",
    "render",
    "result",
    "result_line",
    "runtime_findings",
    "schema",
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
    env.depth = Some(DepthReport {
        family: "wasi".into(),
        fuel_consumed: 12,
        hostcalls: vec![("fd_write".into(), 3)],
    });
    env.render = Some("out.html".into());
    env.findings = vec!["libc::open".into()];
    env.finding_details = vec![serde_json::json!({"symbol": "libc::open"})];
    env.output_path = Some("guest".into());
    env.content_hash = Some("sha256:00".into());
    env.markers = vec!["PATINA_RESULT ok=1".into()];
    env.result_line = Some("PATINA_RESULT ok=1".into());
    env.verdicts = extract_verdicts(
        "",
        &format!(
            "{}\n",
            verdict_line::render(0, VerdictKind::Pass, "queue-drained", "")
        ),
    );
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
    });
    env.guest_exit = Some(GuestExit {
        code: 134,
        signal: Some(6),
        core: false,
    });
    env.stdout = Some(String::new());
    env.stderr = Some(String::new());
    env.message = Some("detail".into());
    // Set explicitly: `Envelope::new` fills it from config discovery, which
    // finds nothing in a unit test.
    env.config = Some(serde_json::json!({"path": ".patina/config.toml"}));
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

#[test]
fn the_outcome_channel_fields_are_omitted_when_nothing_produced_them() {
    // Absent, never zero: a run with no facts channel, no refusal, and no
    // exit record must not fabricate empty objects a consumer would read as
    // "the plane reported nothing".
    let json = Envelope::new("run", "ok", 0).to_json();
    assert!(json.get("fault_reports").is_none());
    assert!(json.get("runtime_findings").is_none());
    assert!(json.get("crash_restart").is_none());
    assert!(json.get("refusal").is_none());
    assert!(json.get("guest_exit").is_none());
}

#[test]
fn envelope_carries_verdicts_in_report_order() {
    let stderr = format!(
        "noise\n{}\n{}\n",
        verdict_line::render(0, VerdictKind::Pass, "queue-drained", ""),
        verdict_line::render(1, VerdictKind::Violation, "two leaders", "{\"term\": 4}"),
    );
    let mut env = Envelope::new("run", "violation", 3);
    env.verdicts = extract_verdicts("", &stderr);
    let json = env.to_json();
    assert_eq!(json["verdicts"][0]["seq"], 0);
    assert_eq!(json["verdicts"][0]["kind"], "pass");
    assert_eq!(json["verdicts"][0]["label"], "queue-drained");
    assert_eq!(json["verdicts"][0]["detail"], "");
    assert_eq!(json["verdicts"][1]["kind"], "violation");
    // Spaces survive the escape round trip in both label and detail.
    assert_eq!(json["verdicts"][1]["label"], "two leaders");
    assert_eq!(json["verdicts"][1]["detail"], "{\"term\": 4}");
}

#[test]
fn envelope_omits_verdicts_when_the_run_reported_none() {
    let env = Envelope::new("run", "ok", 0);
    assert!(env.to_json().get("verdicts").is_none());
    assert!(extract_verdicts("hello\n", "PATINA_SDK_REPORT enabled=0\n").is_empty());
}
