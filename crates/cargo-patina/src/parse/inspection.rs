//! Trace inspection subcommand parsing.

use super::*;

pub(crate) fn parse_trace(
    mut arguments: Vec<OsString>,
) -> Result<trace_cmd::TraceInvocation, CliError> {
    if arguments.is_empty() {
        return Err(CliError::usage(
            "trace requires a subcommand: info, events, stats, or diff",
        ));
    }
    let subcommand = arguments
        .remove(0)
        .into_string()
        .map_err(|_| CliError::usage("trace subcommand must be valid UTF-8"))?;
    match subcommand.as_str() {
        "info" => parse_trace_info(arguments).map(trace_cmd::TraceInvocation::Info),
        "events" => parse_trace_events(arguments).map(trace_cmd::TraceInvocation::Events),
        "stats" => parse_trace_stats(arguments).map(trace_cmd::TraceInvocation::Stats),
        "diff" => parse_trace_diff(arguments).map(trace_cmd::TraceInvocation::Diff),
        other => Err(CliError::usage(format!(
            "unsupported trace subcommand {other:?}; expected info, events, stats, or diff"
        ))),
    }
}

fn parse_trace_info(arguments: Vec<OsString>) -> Result<trace_cmd::TraceInfo, CliError> {
    let scan = locate_positionals("trace", &arguments, 1);
    let args = cli::parse("trace", help::Family::Info, scan.rest)?;
    Ok(trace_cmd::TraceInfo {
        path: scan
            .positionals
            .into_iter()
            .next()
            .map(PathBuf::from)
            .ok_or_else(|| CliError::usage("trace info requires a trace path"))?,
        timeline: timeline_or_main(&args),
    })
}

fn parse_trace_events(arguments: Vec<OsString>) -> Result<trace_cmd::TraceEvents, CliError> {
    let scan = locate_positionals("trace", &arguments, 1);
    let args = cli::parse("trace", help::Family::Events, scan.rest)?;
    let mut filters = trace_cmd::EventFilters {
        first: args.u64("--first"),
        last: args.u64("--last"),
        notable: args.flag("--notable"),
        seq: args
            .text("--seq")
            .map(|value| values::range_of("--seq", value, "..").expect("validated by the grammar")),
        ..trace_cmd::EventFilters::default()
    };
    for value in args.texts("--task") {
        filters.tasks.insert(match value {
            "main" => trace_view::LaneKey::Main,
            id => trace_view::LaneKey::Task(id.parse().expect("validated by the grammar")),
        });
    }
    if let Some(value) = args.text("--kind") {
        let (kinds, categories) = values::kind_list(value).expect("validated by the grammar");
        filters.op_kinds = kinds.into_iter().map(str::to_string).collect();
        filters.categories = categories.into_iter().collect();
    }
    if filters.first.is_some() && filters.last.is_some() {
        return Err(CliError::usage(
            "--first and --last are mutually exclusive for trace events",
        ));
    }
    Ok(trace_cmd::TraceEvents {
        path: scan
            .positionals
            .into_iter()
            .next()
            .map(PathBuf::from)
            .ok_or_else(|| CliError::usage("trace events requires a trace path"))?,
        timeline: timeline_or_main(&args),
        filters,
    })
}

fn parse_trace_stats(arguments: Vec<OsString>) -> Result<trace_cmd::TraceStats, CliError> {
    let scan = locate_positionals("trace", &arguments, 1);
    let args = cli::parse("trace", help::Family::Stats, scan.rest)?;
    Ok(trace_cmd::TraceStats {
        path: scan
            .positionals
            .into_iter()
            .next()
            .map(PathBuf::from)
            .ok_or_else(|| CliError::usage("trace stats requires a trace path"))?,
        timeline: timeline_or_main(&args),
    })
}

fn parse_trace_diff(arguments: Vec<OsString>) -> Result<trace_cmd::TraceDiff, CliError> {
    let scan = locate_positionals("trace", &arguments, 2);
    let args = cli::parse("trace", help::Family::Diff, scan.rest)?;
    if scan.positionals.len() < 2 {
        return Err(CliError::usage(if scan.positionals.is_empty() {
            "trace diff requires two trace paths"
        } else {
            "trace diff requires a second trace path"
        }));
    }
    Ok(trace_cmd::TraceDiff {
        a: PathBuf::from(&scan.positionals[0]),
        b: PathBuf::from(&scan.positionals[1]),
        timeline: timeline_or_main(&args),
        context: args.usize("--context").unwrap_or(3),
    })
}

#[cfg(test)]
mod tests;
