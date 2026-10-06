//! Regression tests for markers.

use super::*;

#[test]
fn parses_coverage_report_marker_for_json_envelope() {
    let coverage = parse_coverage_report_line(
            "PATINA_COVERAGE_REPORT edges_total=10 edges_covered=4 covered_permille=400 hits_total=99 hits_max=12 saturated=1",
        )
        .unwrap();
    assert_eq!(coverage.edges_total, 10);
    assert_eq!(coverage.edges_covered, 4);
    assert_eq!(coverage.covered_permille, 400);
    assert_eq!(coverage.hits_total, 99);
    assert_eq!(coverage.hits_max, 12);
    assert_eq!(coverage.saturated, 1);
    assert!(coverage.map_path.is_none());
}
