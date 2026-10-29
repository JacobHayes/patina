//! Minimization invocation parsing.

use super::*;

pub(crate) fn parse_minimize(
    mut arguments: Vec<OsString>,
) -> Result<minimize::MinimizeInvocation, CliError> {
    // `--generation` builds its own oracle, so it is the one form that takes no
    // `-- <ORACLE>` tail — and must be routed before the tail is demanded. The
    // name is read through the registry's splitter, so `--generation=14` routes
    // exactly like `--generation 14`. A selector's environment default routes
    // too, unless the other selector was typed.
    let typed_generation = has_minimize_flag(&arguments, "--generation");
    let typed_params = has_minimize_flag(&arguments, "--params");
    let selected = |name: &str, other_typed: bool| -> Result<bool, CliError> {
        Ok(!other_typed && cli::env_value(cli::flag("minimize", name))?.is_some())
    };
    if typed_generation || selected("--generation", typed_params)? {
        return parse_minimize_generation(arguments).map(minimize::MinimizeInvocation::Generation);
    }
    let delimiter = arguments
        .iter()
        .position(|argument| argument == "--")
        .ok_or_else(|| {
            CliError::usage(
                "minimize requires --generation <N>, or --params with `-- <COMMAND> [ARGS]...`",
            )
        })?;
    let oracle = arguments.split_off(delimiter + 1);
    arguments.pop();
    if oracle.is_empty() {
        return Err(CliError::usage(
            "minimize --params requires the failing command after `--`",
        ));
    }
    if typed_params || selected("--params", typed_generation)? {
        parse_minimize_params(arguments, oracle).map(minimize::MinimizeInvocation::Params)
    } else {
        Err(CliError::usage(
            "minimize requires --generation <N>, or --params with `-- <COMMAND> [ARGS]...`",
        ))
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
        jobs: args.usize("--jobs"),
    })
}

/// Parse `minimize --params -- <COMMAND>`: lift the command's own `--param`
/// words (space or `=` form) out of it, up to the command's `--`, which starts
/// a guest's arguments, and keep the rest verbatim.
fn parse_minimize_params(
    arguments: Vec<OsString>,
    command: Vec<OsString>,
) -> Result<minimize::ParamsMinimize, CliError> {
    cli::parse("minimize", help::Family::Params, arguments)?;
    let split = command
        .iter()
        .position(|word| word == "--")
        .unwrap_or(command.len());
    let (own, tail) = command.split_at(split);
    let mut head = Vec::new();
    let mut params = BTreeMap::new();
    let mut words = own.iter();
    while let Some(word) = words.next() {
        let entry = if word == "--param" {
            words.next().cloned().ok_or_else(|| {
                CliError::usage("minimize --params: the command's --param needs K=V")
            })?
        } else if let Some(entry) = word.to_str().and_then(|text| text.strip_prefix("--param=")) {
            OsString::from(entry)
        } else {
            head.push(word.clone());
            continue;
        };
        let (key, value) = entry
            .to_str()
            .and_then(|entry| entry.split_once('='))
            .filter(|(key, _)| !key.is_empty())
            .ok_or_else(|| {
                CliError::usage(format!(
                    "minimize --params: the command's --param {} is not K=V",
                    entry.to_string_lossy()
                ))
            })?;
        if params.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err(CliError::usage(format!(
                "minimize --params: the command sets --param {key} twice"
            )));
        }
    }
    if params.is_empty() {
        return Err(CliError::usage(
            "minimize --params: the command carries no --param K=V to reduce",
        ));
    }
    Ok(minimize::ParamsMinimize {
        head,
        tail: tail.to_vec(),
        params,
    })
}

#[cfg(test)]
mod tests;
