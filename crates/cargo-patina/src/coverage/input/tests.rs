//! Regression tests for input.

use super::*;

#[test]
fn offline_campaign_coverage_rejects_wrong_binary_hash() {
    let temp = tempfile::tempdir().unwrap();
    let good = temp.path().join("good-bin");
    let bad = temp.path().join("bad-bin");
    fs::write(&good, b"expected binary").unwrap();
    fs::write(&bad, b"wrong binary").unwrap();
    let mut data = synthetic_covmap(&[1], &[10]).as_coverage_data("campaign");
    data.artifact = Some(CoverageArtifact {
        path: "recorded-bin".into(),
        sha256: sha256_hex(b"expected binary"),
        family: "native".into(),
    });

    validate_coverage_binary(&good, &data).unwrap();
    let error = validate_coverage_binary(&bad, &data).unwrap_err();
    assert!(
        error
            .0
            .contains("coverage store records artifact recorded-bin sha256"),
        "unexpected error: {}",
        error.0
    );
}
