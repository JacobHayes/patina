//! Native-family invocation parsing.

use super::*;

pub(crate) fn parse_native_harness_from(
    origin: PathBuf,
    manifest: PathBuf,
    arguments: Vec<OsString>,
) -> Result<NativeHarnessInvocation, CliError> {
    if arguments.iter().any(|argument| argument == "--") {
        return Err(CliError::usage(
            "test native harness mode does not accept a `--` tail; it supplies the libtest --exact filter itself",
        ));
    }
    let selection = take_package_bin(arguments)?;
    if selection.bin.is_some() {
        return Err(CliError::usage(
            "--bin does not select a libtest harness; use --harness-target with the Cargo test target name",
        ));
    }
    let args = cli::parse("test", help::Family::Harness, selection.rest)?;
    let seed = args.u64("--seed");
    let seeds = args.u64("--seeds");
    if seed.is_some() && seeds.is_some() {
        return Err(CliError::usage("--seed and --seeds are mutually exclusive"));
    }
    if let Some(count) = seeds {
        if count == 0 || count > 1_000_000 {
            return Err(CliError::usage("--seeds must be between 1 and 1000000"));
        }
    }
    Ok(NativeHarnessInvocation {
        origin,
        manifest,
        package: selection.package,
        harness_target: args.string("--harness-target").ok_or_else(|| {
            CliError::usage("test native harness mode requires --harness-target <NAME>")
        })?,
        exact: args
            .string("--exact")
            .ok_or_else(|| CliError::usage("test native harness mode requires --exact <PATH>"))?,
        seeds: seed
            .map(HarnessSeeds::One)
            .unwrap_or_else(|| HarnessSeeds::Range(seeds.unwrap_or(20))),
        release: args.flag("--release"),
        features: HarnessFeatures {
            features: args.string("--features"),
            all_features: args.flag("--all-features"),
            no_default_features: args.flag("--no-default-features"),
        },
        instrumentation: instrumentation_of(&args)?,
        step_budget: args.u64("--budget"),
        realtime_epoch: args.string("--realtime-epoch"),
        hostname: args.string("--hostname"),
        knobs: knobs_of(&args)?,
        buggify: buggify_of(&args),
        schedule: schedule_of(&args),
        liveness: NativeLiveness {
            compute_watchdog_ms: args.string("--compute-watchdog-ms"),
            ..liveness_of(&args)
        },
    })
}

/// Thin wrapper: treat the leading argument as an already-built binary. Used by
/// unit tests; `audit` routing calls [`parse_native_audit_from`].
#[cfg(test)]
fn parse_native_audit(mut arguments: Vec<OsString>) -> Result<NativeAuditInvocation, CliError> {
    if arguments.is_empty() {
        return Err(CliError::usage(
            "audit of a native binary requires a binary path",
        ));
    }
    let binary = ArtifactRef::Prebuilt(PathBuf::from(arguments.remove(0)));
    parse_native_audit_from(binary, arguments)
}

/// Parse the flags of a native `audit` given an already-resolved binary
/// reference (an existing binary or a build-on-the-fly spec).
pub(crate) fn parse_native_audit_from(
    binary: ArtifactRef,
    arguments: Vec<OsString>,
) -> Result<NativeAuditInvocation, CliError> {
    let args = cli::parse("audit", help::Family::Native, arguments)?;
    Ok(NativeAuditInvocation {
        binary,
        allow: allow_of(&args),
        raw: args.flag("--raw"),
    })
}

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
    let args = cli::parse("build", help::Family::Native, scan.rest)?;
    // The path requirement is checked after the flag scan so an unknown flag or a
    // `--release=x` stray value is named first (a usage error about the flag,
    // never a bogus manifest path derived from a flag token).
    let path = path
        .ok_or_else(|| CliError::usage("build requires a Rust source path or a Cargo package"))?;
    let output = args.path("--output");
    let release = args.flag("--release");
    let instrumentation = instrumentation_of(&args)?;

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
            instrumentation,
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
            instrumentation,
        })
    }
}

/// Classify a `native-build` path by shape (no filesystem access, so parsing
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
pub(super) fn realtime_epoch_of(args: &cli::Args) -> Option<u64> {
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
    let args = cli::parse("run", help::Family::Native, arguments)?;
    let seed = args.u64("--seed").unwrap_or(0);
    let record = args.path("--record");
    // The label is only ever read back off a recorded trace, and the seeded
    // control plane sets no `PATINA_FINGERPRINT` at all, so `--fingerprint` is
    // registered as dependent on `--record` (see the native run group in
    // `help.rs`): a seeded run carrying one is refused by the generic registry
    // check rather than silently discarding it.
    let fingerprint = args
        .string("--fingerprint")
        .unwrap_or_else(|| DEFAULT_NATIVE_FINGERPRINT.to_string());
    Ok(NativeRunInvocation {
        binary,
        mode: match record {
            Some(path) => NativeRunMode::Record {
                seed,
                path,
                fingerprint,
            },
            None => NativeRunMode::Seeded { seed },
        },
        program_args,
        environment: key_values(&args, "--env")?,
        cwd: args.string("--cwd"),
        step_budget: args.u64("--budget"),
        realtime_epoch_nanos: realtime_epoch_of(&args),
        hostname: args.string("--hostname"),
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
        mount: args.path("--mount"),
        harness: args.flag("--harness"),
    })
}

/// Parse the native `replay <BINARY> <TRACE> [--fingerprint STR] [--mount
/// HOST_DIR] [--allow SYMBOL]... [--allow-unsupported-symbols <all|name,...>]
/// [-- GUEST ARGS]` given an already-resolved binary reference and trace path.
///
/// Native replay restores every semantic input from the trace itself — seed,
/// fault knobs, buggify, guest arguments, and injected guest environment — so it
/// exposes NO semantic flags. The registry declares those refusals (see
/// `REPLAY`'s `refusals`), so each is answered by name rather than as an unknown
/// option, and a knob added to a shared slice is refused the day it is added.
/// The only flags are host/build facts the trace cannot carry: `--fingerprint`,
/// `--mount` (re-supply the host corpus whose hash the fingerprint verifies),
/// `--harness`, and the machine-local pre-run audit surface. An optional trailing
/// `--` section is accepted only for script compatibility and must match the
/// recorded arguments byte-for-byte (enforced downstream by
/// `reconcile_replay_argv`).
pub(crate) fn parse_native_replay(
    binary: ArtifactRef,
    trace: PathBuf,
    mut arguments: Vec<OsString>,
) -> Result<NativeRunInvocation, CliError> {
    let program_args = split_trailing_args(&mut arguments);
    let args = cli::parse("replay", help::Family::Native, arguments)?;
    Ok(NativeRunInvocation {
        binary,
        mode: NativeRunMode::Replay {
            path: trace,
            fingerprint: args
                .string("--fingerprint")
                .unwrap_or_else(|| DEFAULT_NATIVE_FINGERPRINT.to_string()),
        },
        program_args,
        environment: BTreeMap::new(),
        // `replay` registers no --cwd either: the trace is authoritative.
        cwd: None,
        // `replay` registers no --budget: it re-executes a recorded operation
        // stream whose length is already fixed by the trace.
        step_budget: None,
        // Nor --realtime-epoch/--hostname: the trace restores both.
        realtime_epoch_nanos: None,
        hostname: None,
        // Like the fault knobs, the repeatable semantic knobs come from the
        // trace.
        knobs: KnobValues::default(),
        buggify: None,
        // Replay restores the scheduling policy and swarm selection from the
        // trace metadata; the run path reconstructs the fingerprint suffix from
        // the trace (see `native_schedule_from_trace`), so nothing is supplied.
        schedule: NativeSchedule::default(),
        // Liveness is schedule-invariant and informational-only in the trace, so a
        // replay does not re-supply or reconcile it.
        liveness: NativeLiveness {
            compute_watchdog_ms: args.string("--compute-watchdog-ms"),
            ..NativeLiveness::default()
        },
        allow: allow_of(&args),
        allow_unsupported: unsupported_policy_of(&args),
        coverage_out: args.path("--coverage-out"),
        mount: args.path("--mount"),
        harness: args.flag("--harness"),
    })
}

#[cfg(test)]
mod tests;
