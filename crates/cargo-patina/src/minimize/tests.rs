//! Regression tests for minimize.

use super::*;

pub(super) fn strings(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

#[test]
fn executes_scenario_minimization_shrinking_seed_and_params() {
    // Smoke-check the scenario reducer end to end through a real oracle:
    // the failure needs seed >= 3 and the `keep` parameter present, both
    // read from the PATINA_* environment protocol.
    let invocation = ScenarioMinimize {
        seed: 9,
        params: [("keep", "1"), ("drop", "5")]
            .into_iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect(),
        seed_budget: 64,
        oracle: strings(&[
            "sh",
            "-c",
            "test \"$PATINA_RT_SEED\" -ge 3 \
                 && printf '%s' \"$PATINA_RT_PARAMS_JSON\" | grep -q '\"keep\"' && exit 1; exit 0",
        ]),
    };
    assert_eq!(execute_scenario(invocation).unwrap(), 0);
}

pub(super) fn verdict(kind: &str, label: &str) -> VerdictFacts {
    VerdictFacts {
        kind: kind.to_string(),
        label: label.to_string(),
    }
}
