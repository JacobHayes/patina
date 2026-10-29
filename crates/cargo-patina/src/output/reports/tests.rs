//! Regression tests for reports.

use super::*;

fn refused(class: &str) -> Refusal {
    Refusal {
        class: class.into(),
        message: String::new(),
        guest_exit_code: None,
        mismatch: None,
    }
}

#[test]
fn classify_reads_the_structured_channels_only() {
    let facts = |value: serde_json::Value| Some(value);
    assert_eq!(classify(0, None, None, false), "ok");
    // Guest text that only looks like a finding is a plain failure.
    assert_eq!(classify(3, None, None, false), "failure");
    assert_eq!(
        classify(
            1,
            facts(serde_json::json!({"verdicts": [{"kind": "violation"}]})).as_ref(),
            None,
            false
        ),
        "violation"
    );
    assert_eq!(
        classify(2, None, Some(&refused("buggify_duplicate_label")), false),
        "violation"
    );
    assert_eq!(
        classify(
            1,
            facts(serde_json::json!({"runtime_findings": [{"source": "liveness", "kind": "converge"}]}))
                .as_ref(),
            None,
            false
        ),
        "liveness"
    );
    assert_eq!(
        classify(134, None, Some(&refused("shim_fatal")), false),
        "infra"
    );
    assert_eq!(classify(134, None, None, true), "infra");
    assert_eq!(
        classify(
            2,
            facts(serde_json::json!({"replay_divergence": "operation_mismatch"})).as_ref(),
            None,
            false
        ),
        "infra"
    );
    // A finish-time report of an armed watchdog that did not fire is no finding.
    assert_eq!(
        classify(
            0,
            facts(serde_json::json!({"fault_reports": {}})).as_ref(),
            None,
            false
        ),
        "ok"
    );
}
