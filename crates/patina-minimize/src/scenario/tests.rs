//! Seed, parameter, and joint scenario reduction tests.

use super::*;
use std::convert::Infallible;

#[test]
fn reduce_params_drops_unneeded_keys_and_shrinks_the_load_bearing_values() {
    let scenario = Scenario::new(0)
        .with_param("a", "1")
        .with_param("b", "2")
        .with_param("c", "3");
    let reduced = reduce_params(&scenario, &mut |candidate: &Scenario| {
        Ok::<_, Infallible>(candidate.params.get("b").map(String::as_str) == Some("2"))
    })
    .unwrap();
    assert_eq!(reduced.params.len(), 1);
    assert_eq!(reduced.params.get("b").map(String::as_str), Some("2"));

    let scenario = Scenario::new(0).with_param("n", "100");
    let reduced = reduce_params(&scenario, &mut |candidate: &Scenario| {
        let value = candidate
            .params
            .get("n")
            .map_or(0, |v| v.parse().unwrap_or(0));
        Ok::<_, Infallible>(value >= 10)
    })
    .unwrap();
    let value: u64 = reduced.params["n"].parse().unwrap();
    assert!(value >= 10, "must still reproduce the failure");
    assert!(value < 100, "must have shrunk from the original");

    let result = reduce_params(&scenario, &mut |_candidate: &Scenario| {
        Ok::<_, Infallible>(false)
    });
    assert!(matches!(result, Err(MinimizeError::OriginalDoesNotFail)));
}

#[test]
fn reduce_seed_finds_the_smallest_reproducing_seed_within_its_budget() {
    let scenario = Scenario::new(9);
    let reduced = reduce_seed(
        &scenario,
        &mut |candidate: &Scenario| Ok::<_, Infallible>(candidate.seed >= 3),
        64,
    )
    .unwrap();
    assert_eq!(reduced.seed, 3);

    // An exhausted budget keeps the original.
    let scenario = Scenario::new(100);
    let reduced = reduce_seed(
        &scenario,
        &mut |candidate: &Scenario| Ok::<_, Infallible>(candidate.seed >= 50),
        10,
    )
    .unwrap();
    assert_eq!(reduced.seed, 100);
}

#[test]
fn reduce_scenario_canonicalizes_the_seed_and_the_parameters_together() {
    let scenario = Scenario::new(5)
        .with_param("keep", "1")
        .with_param("drop", "9");
    let reduced = reduce_scenario(
        &scenario,
        &mut |candidate: &Scenario| {
            Ok::<_, Infallible>(candidate.seed >= 2 && candidate.params.contains_key("keep"))
        },
        64,
    )
    .unwrap();
    assert_eq!(reduced.seed, 2);
    assert_eq!(reduced.params.len(), 1);
    assert!(reduced.params.contains_key("keep"));
}
