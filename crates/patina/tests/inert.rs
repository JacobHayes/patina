//! The SDK outside Patina.

/// Every site is inert outside Patina, as in the Go and Python SDKs: a
/// violated `always!` in a debug test build neither panics nor aborts.
#[test]
fn a_violated_always_is_inert_outside_patina() {
    let checked = std::panic::catch_unwind(|| patina_dst::always!(false, "inert-outside"));
    assert!(checked.is_ok());
}
