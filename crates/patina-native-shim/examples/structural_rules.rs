//! Emit registry-derived C syntax lints and their non-vacuity fixtures.
#[path = "structural_rules/mod.rs"]
mod structural_rules;

fn main() {
    let mut arguments = std::env::args().skip(1);
    let fixtures = match arguments.next().as_deref() {
        None => None,
        Some("--fixture-dir") => Some(std::path::PathBuf::from(
            arguments.next().expect("--fixture-dir needs a directory"),
        )),
        Some(argument) => panic!("unknown argument: {argument}"),
    };
    assert!(arguments.next().is_none(), "unexpected argument");
    structural_rules::emit(fixtures.as_deref());
}
