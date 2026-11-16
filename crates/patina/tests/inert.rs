//! The SDK outside Patina: every call is answered locally.

#[test]
fn every_call_is_inert_outside_patina() {
    assert!(!patina_dst::is_simulated());
    patina_dst::always!(false, "inert-always", "detail {}", 1);
    patina_dst::unreachable!("inert-unreachable");
    patina_dst::sometimes!(true, "inert-sometimes");
    patina_dst::reachable!("inert-reachable");
    assert!(!patina_dst::buggify!("inert-buggify"));
    assert!(!patina_dst::buggify_with_prob!("inert-prob", 1.0));
    assert_eq!(patina_dst::buggify_knob!("inert-knob", 7, 1, 100), 7);
    assert!(!patina_dst::buggify_delay!("inert-delay"));
    patina_dst::mark!("inert-mark");
    patina_dst::setup_complete();
    patina_dst::violation("inert-violation", "detail");
}
