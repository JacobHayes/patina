//! Wire-tag agreement; variant coverage is enforced by the generated match.
use super::*;

#[test]
fn operation_kind_matches_serde_tags() {
    for (operation, _) in representative_events_for_all_op_kinds() {
        let encoded = serde_json::to_value(&operation).unwrap();
        assert_eq!(encoded["kind"], operation_kind(&operation));
    }
}
