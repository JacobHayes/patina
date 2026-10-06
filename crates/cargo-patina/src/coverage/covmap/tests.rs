//! Regression tests for covmap.

use super::*;

use super::super::tests::*;

#[test]
fn covmap_parser_preserves_counters_and_deltas() {
    let path = Path::new("fixture.covmap");
    let map = parse_covmap_bytes(&covmap_bytes(&[0, 3, u32::MAX], &[-4, 8, 12]), path)
        .expect("valid covmap parses");
    assert_eq!(map.guard_count, 3);
    assert_eq!(map.counters, vec![0, 3, u32::MAX]);
    assert_eq!(map.deltas, vec![-4, 8, 12]);
    let summary = map.summary(None);
    assert_eq!(summary.edges_total, 3);
    assert_eq!(summary.edges_covered, 2);
    assert_eq!(summary.hits_total, u64::from(u32::MAX) + 3);
    assert_eq!(summary.saturated, 1);
}

#[test]
fn covmap_parser_rejects_range_mismatch() {
    let mut bytes = covmap_bytes(&[1, 2], &[10, 20]);
    // Corrupt pc_count in the single range.
    let pc_count_offset = COVERAGE_MAP_MAGIC.len() + 4 + 8 + 8 + 8 + 8 + 8;
    bytes[pc_count_offset..pc_count_offset + 8].copy_from_slice(&1u64.to_le_bytes());
    let error = parse_covmap_bytes(&bytes, Path::new("bad.covmap")).unwrap_err();
    assert!(
        error.0.contains("range 0 is inconsistent"),
        "unexpected error: {}",
        error.0
    );
}
