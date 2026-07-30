//! Prints a Patina performance qualification report.
//!
//! Usage: `cargo run -p patina-dst-bench --release [-- <iterations> <campaign_runs>]`.

use std::process::ExitCode;

const DEFAULT_ITERATIONS: usize = 2000;
const DEFAULT_CAMPAIGN_RUNS: usize = 200;

const HELP: &str = "\
patina-dst-bench — Patina performance qualification harness

Runs the deterministic runtime's boundary-op workload and prints a report with
seeded/record/replay timings and a trace bytes-per-event figure, then applies the
same budget gates the crate's `cargo test` enforces.

Usage: patina-dst-bench [OPTIONS] [ITERATIONS] [CAMPAIGN_RUNS]

Arguments:
  ITERATIONS      Boundary operations per timed run (positive integer, default 2000).
  CAMPAIGN_RUNS   Record/replay campaign runs to measure (positive integer, default 200).

Options:
  -h, --help      Print this help and exit.

Both positionals must be positive integers; a non-numeric, zero, or negative value
is a hard error (exit 2). There is no silent fallback to the defaults.";

fn main() -> ExitCode {
    match parse_args(std::env::args().skip(1)) {
        Ok(Invocation::Help) => {
            println!("{HELP}");
            ExitCode::SUCCESS
        }
        Ok(Invocation::Run {
            iterations,
            campaign_runs,
        }) => match patina_dst_bench::qualify(iterations, campaign_runs) {
            Ok(report) => {
                println!("{}", report.render());
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("qualification failed: {error}");
                ExitCode::FAILURE
            }
        },
        Err(message) => {
            eprintln!("patina-dst-bench: {message}");
            eprintln!(
                "usage: patina-dst-bench [-h|--help] [ITERATIONS] [CAMPAIGN_RUNS]  \
                 (positive integers; defaults {DEFAULT_ITERATIONS} {DEFAULT_CAMPAIGN_RUNS})"
            );
            // Exit 2: a usage error, distinct from a qualification failure (exit 1).
            ExitCode::from(2)
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Invocation {
    Run {
        iterations: usize,
        campaign_runs: usize,
    },
    Help,
}

/// Parse the bench CLI. Positional `[ITERATIONS] [CAMPAIGN_RUNS]`, both optional
/// but each must be a positive integer when present — a typo never silently
/// benchmarks the default. `-h`/`--help` short-circuits to [`Invocation::Help`].
fn parse_args<I, S>(args: I) -> Result<Invocation, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut positionals: Vec<String> = Vec::new();
    for arg in args {
        let arg = arg.as_ref();
        if arg == "-h" || arg == "--help" {
            return Ok(Invocation::Help);
        }
        // A leading `-` is a flag UNLESS it is a (negative) number, which we want
        // to reach positional parsing so it errors as "must be positive" rather
        // than "unknown flag".
        let looks_like_flag =
            arg.starts_with('-') && arg.len() > 1 && !arg.as_bytes()[1].is_ascii_digit();
        if looks_like_flag {
            return Err(format!("unknown flag `{arg}` (see --help)"));
        }
        positionals.push(arg.to_string());
    }

    if positionals.len() > 2 {
        return Err(format!(
            "expected at most 2 positional arguments (ITERATIONS CAMPAIGN_RUNS), got {}",
            positionals.len()
        ));
    }

    let iterations = parse_positive(positionals.first(), "ITERATIONS", DEFAULT_ITERATIONS)?;
    let campaign_runs = parse_positive(positionals.get(1), "CAMPAIGN_RUNS", DEFAULT_CAMPAIGN_RUNS)?;
    Ok(Invocation::Run {
        iterations,
        campaign_runs,
    })
}

/// A present value must parse to a strictly positive `usize`; absent falls back
/// to `default`. Non-numeric, zero, or negative input is a loud error.
fn parse_positive(value: Option<&String>, name: &str, default: usize) -> Result<usize, String> {
    let Some(raw) = value else {
        return Ok(default);
    };
    let parsed: usize = raw
        .parse()
        .map_err(|_| format!("{name} must be a positive integer, got `{raw}`"))?;
    if parsed == 0 {
        return Err(format!("{name} must be greater than zero, got `{raw}`"));
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(iterations: usize, campaign_runs: usize) -> Invocation {
        Invocation::Run {
            iterations,
            campaign_runs,
        }
    }

    #[test]
    fn no_args_uses_the_documented_defaults() {
        let empty: [&str; 0] = [];
        assert_eq!(
            parse_args(empty).unwrap(),
            run(DEFAULT_ITERATIONS, DEFAULT_CAMPAIGN_RUNS)
        );
    }

    #[test]
    fn one_positional_sets_iterations_and_defaults_campaign_runs() {
        assert_eq!(
            parse_args(["500"]).unwrap(),
            run(500, DEFAULT_CAMPAIGN_RUNS)
        );
    }

    #[test]
    fn two_positionals_set_both() {
        assert_eq!(parse_args(["100", "50"]).unwrap(), run(100, 50));
    }

    #[test]
    fn help_flags_short_circuit() {
        assert_eq!(parse_args(["-h"]).unwrap(), Invocation::Help);
        assert_eq!(parse_args(["--help"]).unwrap(), Invocation::Help);
        // Detected even when it follows other arguments.
        assert_eq!(parse_args(["100", "--help"]).unwrap(), Invocation::Help);
    }

    #[test]
    fn non_numeric_is_a_hard_error_not_a_silent_default() {
        // The motivating bug: `20O0` (letter O) must NOT quietly benchmark 2000.
        let err = parse_args(["20O0"]).unwrap_err();
        assert!(err.contains("ITERATIONS"), "{err}");
        assert!(parse_args(["100", "5x"]).is_err());
    }

    #[test]
    fn zero_and_negative_are_rejected() {
        assert!(parse_args(["0"]).unwrap_err().contains("greater than zero"));
        assert!(parse_args(["100", "0"]).is_err());
        // A negative number reaches positional parsing (not treated as a flag).
        assert!(parse_args(["-5"]).unwrap_err().contains("positive integer"));
    }

    #[test]
    fn extra_positionals_error() {
        assert!(
            parse_args(["1", "2", "3"])
                .unwrap_err()
                .contains("at most 2")
        );
    }

    #[test]
    fn unknown_flags_error() {
        assert!(
            parse_args(["--bogus"])
                .unwrap_err()
                .contains("unknown flag")
        );
        assert!(parse_args(["-x"]).is_err());
    }
}
