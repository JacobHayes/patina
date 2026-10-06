//! Minimization invocation parsing.

use super::*;

pub(crate) fn parse_minimize(
    mut arguments: Vec<OsString>,
) -> Result<minimize::MinimizeInvocation, CliError> {
    // `--generation` builds its own oracle, so it is the one form that takes no
    // `-- <ORACLE>` tail — and must be routed before the tail is demanded. The
    // name is read through the registry's splitter, so `--generation=14` routes
    // exactly like `--generation 14`.
    if has_minimize_flag(&arguments, "--generation") {
        return parse_minimize_generation(arguments).map(minimize::MinimizeInvocation::Generation);
    }
    let delimiter = arguments
        .iter()
        .position(|argument| argument == "--")
        .ok_or_else(|| CliError::usage("minimize requires `-- <ORACLE> [ARGS]...`"))?;
    let oracle = arguments.split_off(delimiter + 1);
    arguments.pop();
    if oracle.is_empty() {
        return Err(CliError::usage(
            "minimize requires an oracle command after `--`",
        ));
    }
    if has_minimize_flag(&arguments, "--scenario") {
        parse_minimize_scenario(arguments, oracle).map(minimize::MinimizeInvocation::Scenario)
    } else {
        parse_minimize_trace(arguments, oracle).map(minimize::MinimizeInvocation::Trace)
    }
}

/// Whether a `minimize` argument list carries `name`, in either the space or
/// the `=` form.
fn has_minimize_flag(arguments: &[OsString], name: &str) -> bool {
    arguments.iter().any(|argument| {
        argument
            .to_str()
            .is_some_and(|text| cli::split_name(text) == name)
    })
}

fn parse_minimize_trace(
    arguments: Vec<OsString>,
    oracle: Vec<OsString>,
) -> Result<minimize::TraceMinimize, CliError> {
    // The trace path may follow options (`minimize --output out.patina trace`),
    // so locate it registry-arity-aware rather than forcing it to lead.
    let scan = locate_positionals("minimize", &arguments, 1);
    let args = cli::parse("minimize", help::Family::Sole, scan.rest)?;
    let timeline = args.string("--timeline");
    let prune = args.flag("--prune-branches");
    if prune && timeline.is_some() {
        return Err(CliError::usage(
            "--prune-branches operates on the whole branch forest and cannot be combined with --timeline",
        ));
    }
    Ok(minimize::TraceMinimize {
        trace: scan
            .positionals
            .into_iter()
            .next()
            .map(PathBuf::from)
            .ok_or_else(|| CliError::usage("minimize requires a trace path"))?,
        output: args
            .path("--output")
            .ok_or_else(|| CliError::usage("minimize requires --output <PATH>"))?,
        timeline,
        prune,
        oracle,
        jobs: args.usize("--jobs"),
    })
}

fn parse_minimize_generation(
    arguments: Vec<OsString>,
) -> Result<minimize::GenerationMinimize, CliError> {
    if arguments.iter().any(|argument| argument == "--") {
        return Err(CliError::usage(
            "minimize --generation builds its own oracle from the generation's recorded verdicts \
             (or --marker) and takes no `-- <ORACLE>`",
        ));
    }
    let args = cli::parse("minimize", help::Family::Generation, arguments)?;
    Ok(minimize::GenerationMinimize {
        out_dir: args
            .path("--out-dir")
            .unwrap_or_else(|| PathBuf::from(campaign::DEFAULT_OUT_DIR)),
        generation: args
            .u64("--generation")
            .ok_or_else(|| CliError::usage("minimize --generation requires <N>"))?,
        // Absent is the normal case: the target is auto-derived from the
        // verdicts the campaign recorded for this generation, and a generation
        // with none is refused by name rather than guessed at.
        marker: args.string("--marker"),
        output: args.path("--output"),
        trace_phase: !args.flag("--no-trace-phase"),
        jobs: args.usize("--jobs"),
    })
}

fn parse_minimize_scenario(
    arguments: Vec<OsString>,
    oracle: Vec<OsString>,
) -> Result<minimize::ScenarioMinimize, CliError> {
    let args = cli::parse("minimize", help::Family::Scenario, arguments)?;
    Ok(minimize::ScenarioMinimize {
        seed: args
            .u64("--seed")
            .ok_or_else(|| CliError::usage("minimize --scenario requires --seed <U64>"))?,
        params: key_values(&args, "--param")?,
        seed_budget: args.u64("--seed-budget").unwrap_or(DEFAULT_SEED_BUDGET),
        oracle,
    })
}

#[cfg(test)]
mod tests;
