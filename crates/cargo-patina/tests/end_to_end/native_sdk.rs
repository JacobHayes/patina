//! Native cooperative SDK fixtures, site reporting, and buggify behavior.

use super::*;

// A guest whose buggify sites all activate and always fire under
// `--buggify=1000 --buggify-activation-permille 1000`, so the outcome is
// deterministic without hunting for a firing seed.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const BUGGIFY_SDK_MAIN: &str = r#"
fn main() {
    patina_dst::lifecycle::setup_complete();
    let mut fired = 0u32;
    let knob = patina_dst::buggify_knob!("batch", 10_i64, 1, 100);
    for i in 0..8 {
        patina_dst::reachable!("loop-body");
        if patina_dst::buggify!("early-return") {
            fired += 1;
        }
        patina_dst::sometimes!(i == 3, "index-is-three");
    }
    patina_dst::always!(fired <= 8, "fired-in-bounds");
    println!("RESULT knob={knob} fired={fired} rng={}", patina_dst::rng());
}
"#;

// A guest whose `reachable!` site is behind an argv branch the campaign never
// takes: invisible to lazy registration, visible through the link-time table.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const BUGGIFY_NEVER_REACHABLE_MAIN: &str = r#"
fn main() {
    patina_dst::lifecycle::setup_complete();
    if std::env::args().any(|arg| arg == "--take-never-branch") {
        patina_dst::reachable!("never-called-reachable");
    }
    println!("guest-finished");
}
"#;

// A guest that never calls setup_complete; under --buggify-after-setup this is a
// declared-but-never-called harness bug that must fail loudly.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const BUGGIFY_NO_SETUP_MAIN: &str = r#"
fn main() {
    for _ in 0..5 {
        let _ = patina_dst::buggify!("gated");
    }
    println!("guest-finished");
}
"#;

#[cfg(test)]
#[path = "native_sdk/tests.rs"]
mod tests;
