//! Argument parsing regression tests.

use super::*;
use crate::ExploreTarget;
use crate::tests::strings;

#[test]
fn parses_bounded_seed_exploration() {
    match parse(strings(&[
        "explore",
        "test",
        "--seeds=3",
        "--seed-start",
        "5",
        "--release",
    ]))
    .unwrap()
    {
        ParseResult::Explore(exploration) => {
            assert_eq!(exploration.start_seed, 5);
            assert_eq!(exploration.seed_count, 3);
            match exploration.target {
                ExploreTarget::Cargo(invocation) => {
                    assert_eq!(invocation.cargo_command, "test");
                    assert_eq!(invocation.cargo_args, strings(&["--release"]));
                }
                _ => panic!("expected a Cargo explore target"),
            }
        }
        _ => panic!("expected exploration"),
    }
    assert!(parse(strings(&["explore", "test", "--seeds", "0"])).is_err());
    assert!(parse(strings(&["explore", "test", "--record", "run.patina"])).is_err());
}

// ---- Phase 2: renames, uniform value syntax, fail-closed positionals ----

#[test]
fn explore_seed_start_replaces_start() {
    // The new spelling sets the range start.
    match parse(strings(&["explore", "test", "--seed-start=5"])).unwrap() {
        ParseResult::Explore(exploration) => assert_eq!(exploration.start_seed, 5),
        _ => panic!("expected exploration"),
    }
    // The old `--start` is no longer an explore flag; it forwards to the
    // wrapped command, so the range start falls back to the default (0).
    match parse(strings(&["explore", "test", "--start", "5"])).unwrap() {
        ParseResult::Explore(exploration) => assert_eq!(exploration.start_seed, 0),
        _ => panic!("expected exploration"),
    }
}
