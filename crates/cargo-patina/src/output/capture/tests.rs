//! Regression tests for capture.

use super::*;

#[test]
fn parse_facts_accepts_the_runtimes_document_and_refuses_anything_else() {
    assert!(parse_facts(b"").unwrap().is_none());
    assert!(parse_facts(b"  \n").unwrap().is_none());
    let document = format!(
        r#"{{"schema":"{}","fault_reports":{{"fs":{{"vacuous":true}}}}}}"#,
        patina_dst_runtime::FACTS_SCHEMA
    );
    let parsed = parse_facts(document.as_bytes()).unwrap().unwrap();
    assert_eq!(parsed["fault_reports"]["fs"]["vacuous"], true);
    // A channel carrying something else is patina's own bug, not a silent
    // "no facts".
    assert!(parse_facts(b"not json").is_err());
    assert!(parse_facts(br#"{"schema":"patina.result/v1"}"#).is_err());
}
