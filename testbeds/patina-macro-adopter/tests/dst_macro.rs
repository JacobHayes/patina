#[patina_dst::test(seeds = 2)]
fn deterministic_pass() {
    assert!(
        patina_dst::is_simulated(),
        "the macro body must execute inside the shim-linked guest"
    );
    let first = patina_dst::rng();
    let second = patina_dst::rng();
    assert_ne!(first, second, "the guest RNG stream should advance");
}

#[patina_dst::test(seed = 7)]
fn seeded_failure_reports_repro() {
    assert!(patina_dst::is_simulated());
    panic!(
        "DST_MACRO_PLANTED_FAILURE ticket={}",
        patina_dst::rng() % 1_000
    );
}

#[patina_dst::test]
fn path_scrub_refuses_missing_cli() {
    panic!("PATH_SCRUB_BODY_SHOULD_NOT_RUN");
}
