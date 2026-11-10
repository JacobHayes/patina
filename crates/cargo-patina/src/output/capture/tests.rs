//! Regression tests for capture.

use super::*;

fn document(vacuous: bool) -> String {
    format!(
        "{{\"schema\":\"{}\",\"fault_reports\":{{\"fs\":{{\"vacuous\":{vacuous}}}}}}}\n",
        patina_dst_runtime::FACTS_SCHEMA
    )
}

#[test]
fn parse_facts_takes_the_last_complete_document_and_refuses_anything_else() {
    assert!(parse_facts(b"").unwrap().is_none());
    assert!(parse_facts(b"  \n").unwrap().is_none());
    let parsed = parse_facts(document(true).as_bytes()).unwrap().unwrap();
    assert_eq!(parsed["fault_reports"]["fs"]["vacuous"], true);

    // A later document supersedes an earlier one; a torn tail the process did
    // not live to finish is ignored, and a lone torn document is no document.
    let rewritten = format!("{}{}", document(true), document(false));
    let parsed = parse_facts(rewritten.as_bytes()).unwrap().unwrap();
    assert_eq!(parsed["fault_reports"]["fs"]["vacuous"], false);
    let torn = format!("{}{{\"schema\":", document(true));
    let parsed = parse_facts(torn.as_bytes()).unwrap().unwrap();
    assert_eq!(parsed["fault_reports"]["fs"]["vacuous"], true);
    assert!(parse_facts(b"{\"schema\":").unwrap().is_none());

    // A complete line carrying something else is patina's own bug, not a
    // silent "no facts".
    assert!(parse_facts(b"not json\n").is_err());
    assert!(parse_facts(b"{\"schema\":\"patina.result/v1\"}\n").is_err());
}

/// The stop pipe: whether the runtime started, the first stop record, and a
/// refusal of anything else rather than a reading of "no stop".
#[test]
fn parse_stop_reads_the_start_and_the_first_stop_and_refuses_anything_else() {
    let schema = patina_dst_runtime::STOP_SCHEMA;
    let started = format!("{{\"schema\":\"{schema}\",\"started\":true}}\n");
    let record = |class: &str| {
        format!(
            "{{\"schema\":\"{schema}\",\"stop\":{{\"class\":\"{class}\",\"reason\":\"r\",\"detail\":\"d\"}}}}\n"
        )
    };
    assert_eq!(parse_stop(b"").unwrap(), StopChannel::default());
    let ran = parse_stop(started.as_bytes()).unwrap();
    assert!(ran.started && ran.stop.is_none());
    let both = format!("{started}{}{}", record("unsupported"), record("internal"));
    let stopped = parse_stop(both.as_bytes()).unwrap();
    assert!(stopped.started);
    assert_eq!(stopped.stop.unwrap()["class"], "unsupported");
    // A stop before the runtime started is still the shim's stop.
    let early = parse_stop(record("internal").as_bytes()).unwrap();
    assert!(!early.started && early.stop.is_some());
    assert!(parse_stop(b"not json\n").is_err());
    assert!(parse_stop(b"{\"schema\":\"patina.runstop/v0\",\"started\":true}\n").is_err());
    assert!(parse_stop(format!("{{\"schema\":\"{schema}\"}}\n").as_bytes()).is_err());
    assert!(parse_stop(document(true).as_bytes()).is_err());
}

#[test]
fn every_contexts_latest_verdicts_survive_later_documents() {
    let doc = |context: u64, verdicts: &str| {
        format!(
            "{{\"schema\":\"{}\",\"context\":{context}{verdicts}}}\n",
            patina_dst_runtime::FACTS_SCHEMA
        )
    };
    let channel = [
        doc(0, r#","verdicts":[{"seq":0,"kind":"violation","label":"a"}]"#),
        doc(0, r#","verdicts":[{"seq":0,"kind":"violation","label":"a"},{"seq":1,"kind":"pass","label":"b"}]"#),
        doc(1, r#","verdicts":[{"seq":0,"kind":"pass","label":"c"}]"#),
        // A later document of context 1 without verdicts (a compute-bound
        // stop's terminal document) erases nothing.
        doc(1, ""),
    ]
    .concat();
    let parsed = parse_facts(channel.as_bytes()).unwrap().unwrap();
    let labels: Vec<&str> = parsed["verdicts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|verdict| verdict["label"].as_str().unwrap())
        .collect();
    assert_eq!(labels, ["a", "b", "c"]);
    assert_eq!(parsed["context"], 1);
}
