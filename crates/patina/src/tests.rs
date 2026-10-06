//! SDK macro and lifecycle integration tests outside Patina.

// Built WITHOUT `cfg(patina)`/`cfg(patina_shim)`, so this exercises the
// fallback behavior an ordinary `cargo build` of an adopter gets.
#[test]
fn macros_are_inert_outside_patina() {
    assert!(!super::is_simulated());
    assert!(!buggify!("outside-fault"));
    assert!(!buggify_with_prob!("outside-fault-prob", 0.9));
    assert!(!buggify_delay!("outside-delay"));
    assert_eq!(buggify_knob!("outside-knob", 7_i64, 1, 100), 7);
    // always! with a true condition is a no-op; sometimes/reachable no-op.
    always!(true, "outside-invariant");
    sometimes!(true, "outside-sometimes");
    reachable!("outside-reachable");
    super::lifecycle::setup_complete();
    super::lifecycle::event!("outside-event");
}
