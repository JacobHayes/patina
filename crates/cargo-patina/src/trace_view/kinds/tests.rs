//! Regression tests for kinds.

use super::*;

fn registry_coverage(registry: &[(&str, Category)]) -> Result<(), String> {
    let registered: BTreeMap<&str, Category> = registry.iter().copied().collect();
    for (operation, _) in representative_events_for_all_op_kinds() {
        let tag = operation_kind(&operation);
        if !registered.contains_key(tag) {
            return Err(format!("operation tag {tag:?} is missing from OP_KINDS"));
        }
        let encoded = serde_json::to_value(&operation).unwrap();
        assert_eq!(encoded["kind"], tag, "operation_kind must match serde tag");
    }
    Ok(())
}

#[test]
fn op_kind_registry_covers_every_operation_variant() {
    registry_coverage(OP_KINDS).unwrap();
}

#[test]
fn every_op_tag_gate_selftest_fires_on_planted_missing_tag() {
    if std::env::var_os("PATINA_TRACE_VIEW_PLANT_MISSING_TAG").is_none() {
        return;
    }
    let planted: Vec<_> = OP_KINDS
        .iter()
        .copied()
        .filter(|(tag, _)| *tag != "net_tcp_shutdown")
        .collect();
    registry_coverage(&planted).unwrap();
}
