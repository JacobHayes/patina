//! Prints a Patina performance qualification report.
//!
//! Usage: `cargo run -p patina-bench --release [-- <iterations> <campaign_runs>]`.

use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let iterations = parse(args.next(), 2000);
    let campaign_runs = parse(args.next(), 200);

    match patina_bench::qualify(iterations, campaign_runs) {
        Ok(report) => {
            println!("{}", report.render());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("qualification failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn parse(value: Option<String>, default: usize) -> usize {
    value
        .and_then(|value| value.parse().ok())
        .filter(|count| *count > 0)
        .unwrap_or(default)
}
