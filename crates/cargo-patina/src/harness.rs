//! `patina test`: a Cargo project's own test suite under the deterministic
//! runtime, one simulated run per test.
//!
//! Three phases, each once per invocation: build every selected libtest
//! target shim-linked and stage it ([`build`]); ask each staged harness for
//! its tests (`--list`, under the runtime) and pick the ones the filter
//! selects ([`run`]); then run every selected test, on every seed, as its own
//! child `patina run` in a world of its own, `--jobs` at a time. A test that
//! does not pass on a seed stops there; a finding is run again recorded, so
//! it can be replayed. [`report`] prints the outcome per test.
//!
//! `#[patina_dst::test]` is this same command for one test: the attribute's
//! host side runs `patina test` with the test's own target and exact name.

mod build;
mod report;
pub(crate) use select::{cargo_metadata, metadata_target_dir};
mod run;
mod select;
#[cfg(test)]
mod tests;

use crate::{CliError, KnobValues, NativeBuggify, NativeLiveness, NativeSchedule};
use patina_dst_abi::RunClass;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Instant;

/// One `patina test` invocation, as parsed.
pub(crate) struct TestInvocation {
    /// The package path as given (or `.` for the working directory's own),
    /// for the rerun commands to name.
    pub(crate) origin: PathBuf,
    pub(crate) manifest: PathBuf,
    pub(crate) selection: Selection,
    /// The trailing TESTNAME: a substring of a test's path within its target,
    /// or with `exact` the whole path.
    pub(crate) filter: Option<String>,
    /// libtest's `--skip`: a test whose path contains one of these (or with
    /// `exact` equals one) is not run.
    pub(crate) skip: Vec<String>,
    pub(crate) exact: bool,
    pub(crate) include_ignored: bool,
    pub(crate) features: CargoFeatures,
    pub(crate) release: bool,
    pub(crate) instrument: bool,
    pub(crate) no_run: bool,
    pub(crate) seeds: Seeds,
    pub(crate) jobs: usize,
    /// Host-time backstop per test run, in seconds; 0 waits forever.
    pub(crate) timeout_secs: u64,
    /// Texts whose presence in an `unsupported` test's stop keeps it from
    /// raising the exit status.
    pub(crate) accept_unsupported: Vec<String>,
    pub(crate) run: RunFlags,
}

/// Which packages and targets to test, in `cargo test`'s own terms.
#[derive(Clone, Debug, Default)]
pub(crate) struct Selection {
    pub(crate) packages: Vec<String>,
    pub(crate) workspace: bool,
    pub(crate) lib: bool,
    pub(crate) bins: Vec<String>,
    pub(crate) all_bins: bool,
    pub(crate) tests: Vec<String>,
    pub(crate) all_tests: bool,
    /// Targets, by name, left out of what the other flags select.
    pub(crate) skip_targets: Vec<String>,
}

impl Selection {
    /// Whether any target flag was given; without one, the default set.
    fn names_targets(&self) -> bool {
        self.lib
            || self.all_bins
            || self.all_tests
            || !self.bins.is_empty()
            || !self.tests.is_empty()
    }
}

/// Cargo feature selection, forwarded to every build.
#[derive(Clone, Debug, Default)]
pub(crate) struct CargoFeatures {
    pub(crate) features: Option<String>,
    pub(crate) all_features: bool,
    pub(crate) no_default_features: bool,
}

impl CargoFeatures {
    /// The Cargo arguments that reproduce this selection.
    fn cargo_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        if let Some(features) = &self.features {
            args.push("--features".to_string());
            args.push(features.clone());
        }
        if self.all_features {
            args.push("--all-features".to_string());
        }
        if self.no_default_features {
            args.push("--no-default-features".to_string());
        }
        args
    }
}

/// The seeds every test runs on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Seeds {
    One(u64),
    /// Seeds `0..N`.
    Range(u64),
}

impl Seeds {
    fn list(self) -> Vec<u64> {
        match self {
            Seeds::One(seed) => vec![seed],
            Seeds::Range(count) => (0..count).collect(),
        }
    }
}

/// The run configuration every test's child `patina run` is given, flag for
/// flag ([`run::push_run_flags`]).
#[derive(Clone, Debug, Default)]
pub(crate) struct RunFlags {
    pub(crate) step_budget: Option<u64>,
    pub(crate) realtime_epoch: Option<String>,
    pub(crate) hostname: Option<String>,
    pub(crate) cpus: Option<u32>,
    pub(crate) params: BTreeMap<String, String>,
    pub(crate) env: BTreeMap<String, String>,
    pub(crate) mount: Option<crate::mount::Mount>,
    pub(crate) knobs: KnobValues,
    pub(crate) buggify: Option<NativeBuggify>,
    pub(crate) schedule: NativeSchedule,
    pub(crate) liveness: NativeLiveness,
    pub(crate) allow_randomized_layout: bool,
}

pub(super) fn execute_test(invocation: TestInvocation) -> Result<i32, CliError> {
    let started = Instant::now();
    let toolchain = build::toolchain()?;
    let metadata = select::cargo_metadata(&invocation.manifest, Some(&toolchain.rustc))?;
    let selected = select::select(&invocation, &metadata)?;
    crate::output::progress::emit(
        "build_started",
        serde_json::json!({ "targets": selected.targets.len() }),
    );
    let built = build::build_all(
        &invocation,
        &toolchain,
        &selected.targets,
        &selected.programs,
        &selected.target_dir,
    )?;
    let build_seconds = started.elapsed().as_secs_f64();
    crate::output::progress::emit(
        "build_finished",
        serde_json::json!({
            "targets": built.len(),
            "failed": built.iter().filter(|built| built.guest.is_err()).count(),
        }),
    );
    if invocation.no_run {
        return Ok(report::no_run(&built, &selected.skipped, build_seconds));
    }
    let running = Instant::now();
    let suite = run::run_suite(&invocation, &built)?;
    let outcome = report::Outcome {
        invocation: &invocation,
        built: &built,
        skipped_targets: &selected.skipped,
        suite: &suite,
        build_seconds,
        run_seconds: running.elapsed().as_secs_f64(),
    };
    Ok(outcome.report())
}

/// What one test, or one target that could not be listed, came to.
#[derive(Clone)]
pub(crate) struct Verdict {
    /// The class of the deciding run: the lowest seed that did not pass, or
    /// `Ok` when every seed passed.
    pub(crate) class: RunClass,
    /// The deciding run's seed.
    pub(crate) seed: u64,
    /// How many seeds ran clean (all of them, for a test that passed).
    pub(crate) seeds_passed: u64,
    pub(crate) run: Option<run::SeedRun>,
    /// For a finding: the recorded rerun of its seed, when one was made.
    pub(crate) recorded: Option<run::SeedRun>,
    /// Host time spent running this test, every seed and the recording.
    pub(crate) seconds: f64,
}
