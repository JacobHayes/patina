//! Probe entry point: argument parsing, vehicle gating, and the `probe_main!`
//! macro every `probes/<family>/<name>.rs` expands.

use crate::calls::Probe;
use crate::vehicle::Vehicle;

/// The probe cannot issue calls through the requested vehicle on this build
/// (e.g. `raw` off x86_64 Linux). The runner counts this as a skip, never a pass.
pub const EXIT_VEHICLE_UNAVAILABLE: i32 = 4;
/// Usage error.
pub const EXIT_USAGE: i32 = 2;

pub struct Options {
    pub vehicle: Vehicle,
    /// `--strict`: a failed `check` panics (the native oracle leg). Under patina
    /// the runner leaves it off so a failed check is a recorded field divergence
    /// (`op":"check"`, `ret` 0) rather than an aborted stream.
    pub strict: bool,
}

pub fn usage(probe: &str) -> String {
    format!(
        "usage: {probe} [--vehicle libc|syscall|raw] [--strict]\n\
         \n\
         A syscall-conformance probe. Emits one JSON event per observed call on\n\
         stdout; asserts and panics go to stderr. --vehicle selects how calls are\n\
         issued (default libc). --strict makes a failed semantic check panic\n\
         (the native oracle leg); without it a failed check is recorded as a\n\
         `check` event with ret 0 and the probe continues.\n\
         Exit codes: 0 ok, 2 usage, {EXIT_VEHICLE_UNAVAILABLE} vehicle unavailable on this build, 101 panic."
    )
}

pub fn parse_options(probe: &str, args: &[String]) -> Result<Options, String> {
    let mut vehicle = Vehicle::Libc;
    let mut strict = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--vehicle" => {
                let value = iter
                    .next()
                    .ok_or_else(|| format!("--vehicle needs a value\n{}", usage(probe)))?;
                vehicle = Vehicle::parse(value)
                    .ok_or_else(|| format!("unknown vehicle {value:?}\n{}", usage(probe)))?;
            }
            "--strict" => strict = true,
            "--help" | "-h" => return Err(usage(probe)),
            other => return Err(format!("unknown argument {other:?}\n{}", usage(probe))),
        }
    }
    Ok(Options { vehicle, strict })
}

/// Parse argv, gate the vehicle, run `body`, exit.
pub fn run(probe: &'static str, body: fn(&Probe)) -> ! {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let options = match parse_options(probe, &args) {
        Ok(options) => options,
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(EXIT_USAGE);
        }
    };
    if !options.vehicle.available() {
        eprintln!(
            "{probe}: vehicle {} is unavailable on this build ({} {}); raw is x86_64 Linux only",
            options.vehicle.name(),
            std::env::consts::OS,
            std::env::consts::ARCH
        );
        std::process::exit(EXIT_VEHICLE_UNAVAILABLE);
    }
    let probe_state = Probe::new(probe, options.vehicle, options.strict);
    body(&probe_state);
    std::process::exit(0);
}

/// Expand to `fn main` for a probe: `probe_main!("fs/open_rw", scenario);` where
/// `scenario: fn(&Probe)`.
#[macro_export]
macro_rules! probe_main {
    ($id:literal, $body:path) => {
        fn main() {
            $crate::probe::run($id, $body)
        }
    };
}
