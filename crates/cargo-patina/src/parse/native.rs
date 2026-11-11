//! Native-family invocation parsing.

use super::*;

pub(crate) fn parse_test_from(
    origin: PathBuf,
    manifest: PathBuf,
    filter: Option<String>,
    arguments: Vec<OsString>,
) -> Result<TestInvocation, CliError> {
    use crate::harness::{CargoFeatures, RunFlags, Seeds, Selection};
    let args = cli::parse("test", help::Family::Sole, arguments)?;
    let (seed, seeds) = args.exclusive(
        "--seed",
        "--seeds",
        "--seed and --seeds are mutually exclusive",
    )?;
    let seed = args.u64("--seed").filter(|_| seed);
    let seeds = args.u64("--seeds").filter(|_| seeds);
    if let Some(count) = seeds
        && count > 1_000_000
    {
        return Err(CliError::usage("--seeds must be between 1 and 1000000"));
    }
    if args.flag("--exact") && filter.is_none() && !args.supplied("--skip") {
        return Err(CliError::usage(
            "--exact matches TESTNAME (and --skip) exactly; give a TESTNAME",
        ));
    }
    if args.flag("--workspace") && args.supplied("--package") {
        return Err(CliError::usage(
            "--workspace tests every member; --package selects some of them: give one or the other",
        ));
    }
    let jobs = match args.u64("--jobs") {
        Some(jobs) => usize::try_from(jobs).map_err(|_| CliError::usage("--jobs is too large"))?,
        None => default_jobs(),
    };
    Ok(TestInvocation {
        origin,
        manifest,
        selection: Selection {
            packages: args
                .texts("--package")
                .into_iter()
                .map(str::to_owned)
                .collect(),
            workspace: args.flag("--workspace"),
            lib: args.flag("--lib"),
            bins: args.texts("--bin").into_iter().map(str::to_owned).collect(),
            all_bins: args.flag("--bins"),
            tests: args
                .texts("--test")
                .into_iter()
                .map(str::to_owned)
                .collect(),
            all_tests: args.flag("--tests"),
            skip_targets: args
                .texts("--skip-target")
                .into_iter()
                .map(str::to_owned)
                .collect(),
        },
        filter,
        skip: args
            .texts("--skip")
            .into_iter()
            .map(str::to_owned)
            .collect(),
        exact: args.flag("--exact"),
        include_ignored: args.flag("--include-ignored"),
        features: CargoFeatures {
            features: args.string("--features"),
            all_features: args.flag("--all-features"),
            no_default_features: args.flag("--no-default-features"),
        },
        release: args.flag("--release"),
        instrument: args.flag("--instrument"),
        no_run: args.flag("--no-run"),
        seeds: match (seed, seeds) {
            (_, Some(count)) => Seeds::Range(count),
            (seed, None) => Seeds::One(seed.unwrap_or(0)),
        },
        jobs,
        timeout_secs: args.u64("--timeout-secs").unwrap_or(300),
        accept_unsupported: args
            .texts("--accept-unsupported")
            .into_iter()
            .map(str::to_owned)
            .collect(),
        run: RunFlags {
            step_budget: args.u64("--budget"),
            realtime_epoch: args.string("--realtime-epoch"),
            hostname: args.string("--hostname"),
            cpus: args.u32("--cpus"),
            params: key_values(&args, "--param")?,
            env: key_values(&args, "--env")?,
            mount: args.mount("--mount")?,
            knobs: knobs_of(&args)?,
            buggify: buggify_of(&args),
            schedule: schedule_of(&args),
            liveness: NativeLiveness {
                compute_watchdog_ms: args.string("--compute-watchdog-ms"),
                ..liveness_of(&args)
            },
            allow_randomized_layout: args.flag("--allow-randomized-address-layout"),
        },
    })
}

/// `patina test`'s default `--jobs`: half the CPUs this process may use (its
/// affinity mask and cgroup quota, as the standard library reads them), at
/// least one. Each test run is a supervisor and a guest, and a shared machine
/// has other work on it; the whole machine is `--jobs` away.
pub(crate) fn default_jobs() -> usize {
    std::thread::available_parallelism().map_or(1, |cpus| cpus.get().div_ceil(2))
}

/// Parse the flags of a native `audit` given an already-resolved binary
/// reference (an existing binary or a build-on-the-fly spec).
pub(crate) fn parse_native_audit_from(
    binary: ArtifactRef,
    arguments: Vec<OsString>,
) -> Result<NativeAuditInvocation, CliError> {
    let args = cli::parse("audit", help::Family::Sole, arguments)?;
    let allow = allow_of(&args);
    if allow.contains(ALLOW_ALL) {
        return Err(CliError::usage(
            "audit reports every finding; `--allow all` is for run, replay and campaign",
        ));
    }
    Ok(NativeAuditInvocation {
        binary,
        allow,
        raw: args.flag("--raw"),
    })
}

pub(crate) fn parse_native_build(
    mut arguments: Vec<OsString>,
) -> Result<NativeBuildInvocation, CliError> {
    let rustc_args = split_trailing_args(&mut arguments);
    // The source/package path may follow options (`build --release ./pkg`), so
    // locate it registry-arity-aware instead of forcing it to lead. A flag-looking
    // token is never taken as the path — the remaining flags (including an unknown
    // one, or a `--release=x` with a stray value) are validated below and produce
    // a usage error naming the flag, not a bogus `--release=x/Cargo.toml`.
    let scan = locate_positionals("build", &arguments, 1);
    let path = scan.positionals.into_iter().next().map(PathBuf::from);
    let args = cli::parse("build", help::Family::Sole, scan.rest)?;
    // The path requirement is checked after the flag scan so an unknown flag or a
    // `--release=x` stray value is named first (a usage error about the flag,
    // never a bogus manifest path derived from a flag token).
    let path = path
        .ok_or_else(|| CliError::usage("build requires a Rust source path or a Cargo package"))?;
    let output = args.path("--output");
    let release = args.flag("--release");
    let instrument = args.flag("--instrument");

    if args.flag("--go") {
        return parse_go_build(&args, path, output, release, instrument, rustc_args);
    }
    if args.flag("--python") {
        return parse_python_build(&args, path, output, release, instrument, rustc_args);
    }
    if is_native_package_path(&path) {
        if let Some(rustc_arg) = rustc_args.first() {
            return Err(CliError::usage(format!(
                "trailing rustc options ({rustc_arg:?}) apply to a single-source build, not package builds"
            )));
        }
        if args.string("--edition").is_some() {
            return Err(CliError::usage(
                "--edition applies to a single-source build; a package's edition comes from its Cargo.toml",
            ));
        }
        Ok(NativeBuildInvocation {
            target: NativeBuildTarget::Package {
                manifest: native_manifest_path(&path),
                package: args.string("--package"),
                bin: args.string("--bin"),
            },
            output,
            release,
            instrument,
        })
    } else {
        if args.string("--package").is_some() || args.string("--bin").is_some() {
            return Err(CliError::usage(
                "--package and --bin apply to a Cargo-package build, not a single source file",
            ));
        }
        let output = output.ok_or_else(|| CliError::usage("build requires --output <PATH>"))?;
        Ok(NativeBuildInvocation {
            target: NativeBuildTarget::Source {
                source: path,
                edition: args
                    .string("--edition")
                    .unwrap_or_else(|| DEFAULT_NATIVE_EDITION.to_string()),
                rustc_args,
            },
            output: Some(output),
            release,
            instrument,
        })
    }
}

/// A `build --go` of the Go main package in `path`: the trailing arguments are
/// `go build` options, and only the options a Go build has a meaning for are
/// accepted. `--release` builds the shim in release mode; the Go code is
/// compiled as `go build` always compiles it.
fn parse_go_build(
    args: &cli::Args,
    path: PathBuf,
    output: Option<PathBuf>,
    release: bool,
    instrument: bool,
    go_args: Vec<OsString>,
) -> Result<NativeBuildInvocation, CliError> {
    for (flag, given) in [
        ("--edition", args.string("--edition").is_some()),
        ("--package", args.string("--package").is_some()),
        ("--bin", args.string("--bin").is_some()),
    ] {
        if given {
            return Err(CliError::usage(format!(
                "{flag} applies to a Rust build, not a Go package (--go)"
            )));
        }
    }
    if instrument {
        return Err(CliError::usage(
            "--instrument instruments Rust code through LLVM; a Go package (--go) takes no --instrument",
        ));
    }
    crate::go_build::check_go_args(&go_args)?;
    let test = args.flag("--go-test");
    if test {
        crate::go_build::check_go_test_args(&go_args)?;
    }
    let output = output.ok_or_else(|| CliError::usage("build --go requires --output <PATH>"))?;
    Ok(NativeBuildInvocation {
        target: NativeBuildTarget::Go {
            package_dir: path,
            go_args,
            test,
        },
        output: Some(output),
        release,
        instrument,
    })
}

/// A `build --python` of the script or application directory `path`. It
/// takes no trailing options: the interpreter is built by Patina's recipe.
fn parse_python_build(
    args: &cli::Args,
    path: PathBuf,
    output: Option<PathBuf>,
    release: bool,
    instrument: bool,
    trailing: Vec<OsString>,
) -> Result<NativeBuildInvocation, CliError> {
    for (flag, given) in [
        ("--edition", args.string("--edition").is_some()),
        ("--package", args.string("--package").is_some()),
        ("--bin", args.string("--bin").is_some()),
    ] {
        if given {
            return Err(CliError::usage(format!(
                "{flag} applies to a Rust build, not a Python application (--python)"
            )));
        }
    }
    if instrument {
        return Err(CliError::usage(
            "--instrument instruments Rust code through LLVM; a Python application (--python) takes no --instrument",
        ));
    }
    if let Some(argument) = trailing.first() {
        return Err(CliError::usage(format!(
            "a Python application (--python) takes no trailing build options ({argument:?})"
        )));
    }
    let output =
        output.ok_or_else(|| CliError::usage("build --python requires --output <PATH>"))?;
    let source = args.path("--python-source").map_or(
        crate::python_build::PythonSource::Pinned,
        crate::python_build::PythonSource::Given,
    );
    Ok(NativeBuildInvocation {
        target: NativeBuildTarget::Python {
            app: path,
            paths: args.paths("--python-path"),
            source,
        },
        output: Some(output),
        release,
        instrument,
    })
}

/// Classify a `build` path by shape (no filesystem access, so parsing
/// stays pure): a `.rs` file is a single source, and anything else — a
/// directory or a `Cargo.toml` — is a Cargo package. Existence is checked when
/// the build runs.
fn is_native_package_path(path: &Path) -> bool {
    if path.file_name() == Some(OsStr::new("Cargo.toml")) {
        return true;
    }
    path.extension().and_then(OsStr::to_str) != Some("rs")
}

/// Resolve a package path to its `Cargo.toml`: a manifest path is used as-is, a
/// directory gets `Cargo.toml` appended.
pub(super) fn native_manifest_path(path: &Path) -> PathBuf {
    if path.file_name() == Some(OsStr::new("Cargo.toml")) {
        path.to_path_buf()
    } else {
        path.join("Cargo.toml")
    }
}

/// Thin wrapper: treat the leading argument as an already-built binary. Used by
/// unit tests; `run` routing calls [`parse_native_run_from`] with a resolved ref.
#[cfg(test)]
pub(crate) fn parse_native_run(
    mut arguments: Vec<OsString>,
) -> Result<NativeRunInvocation, CliError> {
    // The binary is the first token, ahead of any `--` guest-args separator.
    if arguments.is_empty() || arguments[0] == "--" {
        return Err(CliError::usage(
            "run of a native binary requires a binary path",
        ));
    }
    let binary = ArtifactRef::Prebuilt(PathBuf::from(arguments.remove(0)));
    parse_native_run_from(binary, arguments)
}

/// The `--realtime-epoch` timestamp as Unix-time nanoseconds, or `None` when
/// the flag is absent. The registry's `UtcTimestamp` grammar has already
/// validated the text, so the conversion cannot fail here.
fn realtime_epoch_of(args: &cli::Args) -> Option<u64> {
    args.string("--realtime-epoch").map(|text| {
        values::utc_timestamp_nanos("--realtime-epoch", &text)
            .expect("the registry validated --realtime-epoch as a UtcTimestamp")
    })
}

/// Parse the flags of a native `run` given an already-resolved binary reference
/// (an existing binary or a build-on-the-fly spec). A trailing `-- ARGS` section
/// is the guest argument vector.
pub(crate) fn parse_native_run_from(
    binary: ArtifactRef,
    mut arguments: Vec<OsString>,
) -> Result<NativeRunInvocation, CliError> {
    let program_args = split_trailing_args(&mut arguments);
    let args = cli::parse("run", help::Family::Sole, arguments)?;
    let seed = args.u64("--seed").unwrap_or(0);
    let record = args.path("--record");
    Ok(NativeRunInvocation {
        binary,
        mode: match record {
            Some(path) => NativeRunMode::Record { seed, path },
            None => NativeRunMode::Seeded { seed },
        },
        program_args,
        environment: key_values(&args, "--env")?,
        params: key_values(&args, "--param")?,
        cwd: args.string("--cwd"),
        step_budget: args.u64("--budget"),
        realtime_epoch_nanos: realtime_epoch_of(&args),
        hostname: args.string("--hostname"),
        cpus: args.u32("--cpus"),
        knobs: knobs_of(&args)?,
        buggify: buggify_of(&args),
        schedule: schedule_of(&args),
        liveness: NativeLiveness {
            compute_watchdog_ms: args.string("--compute-watchdog-ms"),
            ..liveness_of(&args)
        },
        allow: allow_of(&args),
        allow_unsupported: unsupported_policy_of(&args),
        coverage_out: args.path("--coverage-out"),
        mount: args.mount("--mount")?,
        stdin: args.path("--stdin"),
        allow_randomized_layout: args.flag("--allow-randomized-address-layout"),
    })
}

/// Parse the native `replay <BINARY> <TRACE> [--mount
/// HOST_DIR] [--allow SYMBOL|all]...
/// [-- GUEST ARGS]` given an already-resolved binary reference and trace path.
///
/// Native replay restores every semantic input from the trace itself — seed,
/// fault knobs, buggify, guest arguments, and injected guest environment — so it
/// exposes NO semantic flags. The registry declares those refusals (see
/// `REPLAY`'s `refusals`), so each is answered by name rather than as an unknown
/// option, and a knob added to a shared slice is refused the day it is added.
/// The only flags are host/build facts the trace cannot carry:
/// `--mount` (re-supply the host corpus whose hash the fingerprint verifies),
/// and the machine-local pre-run audit surface. An optional trailing
/// `--` section is accepted only for script compatibility and must match the
/// recorded arguments byte-for-byte (enforced downstream by
/// `reconcile_replay_argv`).
pub(crate) fn parse_native_replay(
    binary: ArtifactRef,
    trace: PathBuf,
    mut arguments: Vec<OsString>,
) -> Result<NativeRunInvocation, CliError> {
    let program_args = split_trailing_args(&mut arguments);
    let args = cli::parse("replay", help::Family::Sole, arguments)?;
    Ok(NativeRunInvocation {
        binary,
        mode: NativeRunMode::Replay { path: trace },
        program_args,
        environment: BTreeMap::new(),
        // Nor --param: the trace restores the run parameters.
        params: BTreeMap::new(),
        // `replay` registers no --cwd either: the trace is authoritative.
        cwd: None,
        // `replay` registers no --budget: it re-executes a recorded operation
        // stream whose length is already fixed by the trace.
        step_budget: None,
        // Nor --realtime-epoch/--hostname: the trace restores both.
        realtime_epoch_nanos: None,
        hostname: None,
        // Nor --cpus, --stdin or the address layout: the trace restores them.
        cpus: None,
        // Like the fault knobs, the repeatable semantic knobs come from the
        // trace.
        knobs: KnobValues::default(),
        buggify: None,
        // Replay restores the scheduling policy and swarm selection from the
        // trace metadata; the run path reconstructs the fingerprint suffix from
        // the trace (see `native_schedule_from_trace`), so nothing is supplied.
        schedule: NativeSchedule::default(),
        // Liveness is schedule-invariant and informational-only in the trace, so a
        // replay does not re-supply or reconcile it; the compute watchdog does not
        // run on replay, which follows the recorded stop.
        liveness: NativeLiveness::default(),
        allow: allow_of(&args),
        allow_unsupported: unsupported_policy_of(&args),
        coverage_out: args.path("--coverage-out"),
        mount: args.mount("--mount")?,
        stdin: None,
        allow_randomized_layout: false,
    })
}

/// Split off a trailing `-- ARGS` section: everything after the first `--` is
/// the guest's argument vector.
fn split_trailing_args(arguments: &mut Vec<OsString>) -> Vec<OsString> {
    match arguments.iter().position(|argument| argument == "--") {
        Some(index) => {
            let trailing = arguments.split_off(index + 1);
            arguments.pop();
            trailing
        }
        None => Vec::new(),
    }
}

#[cfg(test)]
mod tests;
