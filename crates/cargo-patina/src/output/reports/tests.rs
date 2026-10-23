//! Regression tests for reports.

use super::*;

#[test]
fn classify_separates_violation_liveness_infra_and_failure() {
    assert_eq!(classify(0, "", ""), "ok");
    assert_eq!(classify(3, "GUEST_VIOLATION two-leaders", ""), "violation");
    assert_eq!(
        classify(2, "", "trace operation mismatch at 4"),
        "violation"
    );
    assert_eq!(classify(1, "panic somewhere", ""), "failure");
    assert_eq!(
        classify(
            134,
            "",
            "PATINA_INFRA native_run signal=6 trace=incomplete reason=empty"
        ),
        "infra"
    );
    assert_eq!(
        classify(2, "", "incomplete trace run.patina: empty trace file"),
        "infra"
    );
    assert_eq!(
        classify(
            1,
            "",
            "PATINA_VIOLATION converge detail=did-not-converge vtime_ns=400 budget_ns=300 last_fault_vtime_ns=0"
        ),
        "liveness"
    );
    assert_eq!(
        classify(
            1,
            "",
            "PATINA_VIOLATION liveness detail=no-progress vtime_ns=700 budget_ns=600"
        ),
        "liveness"
    );
    // The finish-time report alone (armed, did not fire) is not a violation.
    assert_eq!(
        classify(0, "", "PATINA_LIVENESS_REPORT armed=1 fired=0"),
        "ok"
    );
}
