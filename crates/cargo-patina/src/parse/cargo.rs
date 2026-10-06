//! Cargo-family and exploration parsing.

use super::*;

/// Parse the Cargo package family (`run`/`test` with no diverting artifact): the
/// seed/record machinery, seed-driven fault knobs, and typed `--param`s,
/// forwarding every unrecognized option to Cargo. Replaying a recording — strict
/// or branch-append — is the `replay` verb's job (see [`parse_cargo_replay`]), so
/// `run`/`test` carry no replay/branch/timeline flags.
pub(crate) fn parse_cargo(
    command: String,
    arguments: Vec<OsString>,
) -> Result<ParseResult, CliError> {
    let verb = help::verb(&command).expect("the Cargo family routes only `run` and `test`");
    let (owned, cargo_args) = cli::partition(verb, help::Family::Cargo, arguments);
    let args = cli::parse(&command, help::Family::Cargo, owned)?;
    let seed = args.u64("--seed").unwrap_or(0);
    Ok(ParseResult::Run(Invocation {
        cargo_command: command,
        cargo_args,
        mode: match args.path("--record") {
            Some(path) => Mode::Record { seed, path },
            None => Mode::Seeded { seed },
        },
        step_budget: args.u64("--budget"),
        realtime_epoch_nanos: realtime_epoch_of(&args),
        hostname: args.string("--hostname"),
        params: key_values(&args, "--param")?,
        knobs: knobs_of(&args)?,
        buggify: buggify_of(&args),
        working_dir: None,
    }))
}

/// Parse the cargo-family `replay <pkg> <trace>` verb. The `<pkg>` positional
/// (already resolved to its package directory) selects the workspace; the
/// `<trace>` positional replaces the old `--replay`/`--branch` PATH. Two shapes:
///
/// * strict replay — `replay <pkg> <trace> [--timeline ID]` — reproduces a
///   recorded timeline (default `main`);
/// * branch-append — `replay <pkg> <trace> --branch --from N --branch-seed S
///   --branch-id ID [--parent ID]` — replays the parent prefix then records a new
///   branch timeline.
///
/// Cargo selectors (`-p NAME`, `--example NAME`, a `-- ARGS` tail, ...) that are
/// not replay controls are forwarded to Cargo verbatim and folded into the
/// compatibility fingerprint exactly as on the recording, so they must match the
/// recorded run (a mismatch fails closed on the fingerprint). Fault knobs are
/// never accepted here: the trace's recorded fault configuration is authoritative
/// and restored by the runtime, so replay is flag-free.
pub(crate) fn parse_cargo_replay(
    package_dir: PathBuf,
    trace: PathBuf,
    arguments: Vec<OsString>,
) -> Result<ParseResult, CliError> {
    let verb = help::verb("replay").expect("`replay` is registered");
    let (owned, cargo_args) = cli::partition(verb, help::Family::Cargo, arguments);
    let args = cli::parse("replay", help::Family::Cargo, owned)?;
    Ok(ParseResult::Run(Invocation {
        // A recording is produced by `run`; its fingerprint hashes the cargo
        // subcommand, so replaying reproduces the `run` program under the runtime.
        cargo_command: "run".to_string(),
        cargo_args,
        mode: replay_mode(&args, trace)?,
        step_budget: None,
        // The trace restores the recorded epoch and node name; `replay`
        // refuses both flags.
        realtime_epoch_nanos: None,
        hostname: None,
        params: BTreeMap::new(),
        knobs: KnobValues::default(),
        buggify: None,
        working_dir: Some(package_dir),
    }))
}

pub(crate) fn parse_explore(arguments: Vec<OsString>) -> Result<ExploreInvocation, CliError> {
    let verb = help::verb("explore").expect("`explore` is registered");
    // Everything that is not an explore knob belongs to the wrapped `run`/`test`
    // command, including the verb token itself and anything past `--`.
    let (owned, forwarded) = cli::partition(verb, help::Family::Sole, arguments);
    let args = cli::parse("explore", help::Family::Sole, owned)?;
    // `explore run <artifact|src>` sweeps the native or WASI families; `explore
    // run`/`test` with no diverting artifact stays the Cargo package family. Every
    // family must be in a plain seeded mode — record/replay/branch pin a single
    // run and have nothing to sweep. The recursive `parse` re-points the current
    // verb at the wrapped `run`/`test`; restore `explore` so any later usage error
    // here prints the explore synopsis.
    let wrapped_command = forwarded.clone();
    let parsed = parse(forwarded)?;
    set_current_verb(Some("explore"));
    let (target, mode_seed) = match parsed {
        ParseResult::Run(invocation) => {
            let seed = explore_seed_of(&invocation.mode)?;
            (ExploreTarget::Cargo(invocation), seed)
        }
        ParseResult::WasiRun(invocation) => {
            let seed = explore_seed_of(&invocation.mode)?;
            (ExploreTarget::Wasi(invocation), seed)
        }
        ParseResult::NativeRun(invocation) => {
            let seed = explore_native_seed_of(&invocation.mode)?;
            (ExploreTarget::Native(invocation), seed)
        }
        _ => {
            return Err(CliError::usage(
                "explore requires a `run <artifact|source>`/`test` command",
            ));
        }
    };
    let seed_count = args.u64("--seeds").unwrap_or(100);
    if seed_count == 0 || seed_count > 1_000_000 {
        return Err(CliError::usage("--seeds must be between 1 and 1000000"));
    }
    let start_seed = args.u64("--seed-start").unwrap_or(mode_seed);
    start_seed
        .checked_add(seed_count - 1)
        .ok_or_else(|| CliError::usage("exploration seed range overflows u64"))?;
    Ok(ExploreInvocation {
        target,
        start_seed,
        seed_count,
        wrapped_command,
    })
}

/// The seed of a plain seeded [`Mode`], rejecting record/replay/branch which pin
/// a single run.
fn explore_seed_of(mode: &Mode) -> Result<u64, CliError> {
    match mode {
        Mode::Seeded { seed } => Ok(*seed),
        _ => Err(CliError::usage(
            "explore does not accept record, replay, or branch mode",
        )),
    }
}

/// The seed of a plain seeded [`NativeRunMode`], rejecting record/replay.
fn explore_native_seed_of(mode: &NativeRunMode) -> Result<u64, CliError> {
    match mode {
        NativeRunMode::Seeded { seed } => Ok(*seed),
        _ => Err(CliError::usage(
            "explore does not accept record or replay mode",
        )),
    }
}

/// Resolve a cargo-family `replay` positional to its package directory. The
/// origin must be a directory or a `Cargo.toml` (the shapes `resolve_positional`
/// classifies as the Cargo package family); anything else is neither an artifact
/// nor a package and is rejected naming the offending path.
pub(super) fn cargo_package_dir(origin: &OsStr) -> Result<PathBuf, CliError> {
    match classify_arg(origin)? {
        ArgKind::SourcePackage(manifest) => Ok(manifest
            .parent()
            .map(Path::to_path_buf)
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| PathBuf::from("."))),
        _ => Err(CliError::usage(format!(
            "replay target {} is neither a WASI module, a native binary, nor a Cargo package (a directory or Cargo.toml)",
            Path::new(origin).display()
        ))),
    }
}

#[cfg(test)]
mod tests;
