//! Argument parsing, artifact classification, and control-plane encoding.

use crate::native_build::DEFAULT_NATIVE_EDITION;
use crate::{
    ArtifactRef, BuildSpec, CliError, DEFAULT_NATIVE_FINGERPRINT, HarnessFeatures, HarnessSeeds,
    KnobValues, NativeAuditInvocation, NativeBuggify, NativeBuildInvocation, NativeBuildTarget,
    NativeHarnessInvocation, NativeLiveness, NativeRunInvocation, NativeRunMode, NativeSchedule,
    UnsupportedPolicy, campaign, cli, coverage, help, minimize, syscalls, trace_cmd, trace_view,
    values,
};
use patina_dst_runtime::{
    ENV_BUGGIFY, ENV_BUGGIFY_ACTIVATION, ENV_BUGGIFY_AFTER_SETUP, ENV_BUGGIFY_CUTOFF,
    ENV_CONVERGE_WITHIN, ENV_HEAL_AFTER, ENV_LIVENESS_WATCHDOG, ENV_SCHED_PCT, ENV_SCHED_PCT_STEPS,
    ENV_SCHED_YIELD_STRIDE, ENV_SWARM, FaultKnob, Plumbing,
};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};

mod artifact;
pub(crate) use artifact::*;
mod control;
mod native;
pub(super) use control::*;
mod inspection;
mod minimization;

pub(super) use inspection::parse_trace;
pub(super) use minimization::parse_minimize;
use native::native_manifest_path;
pub(super) use native::parse_native_audit_from;
pub(super) use native::parse_native_build;
pub(super) use native::parse_native_harness_from;
pub(super) use native::parse_native_replay;
#[cfg(test)]
pub(super) use native::parse_native_run;
pub(super) use native::parse_native_run_from;

pub(super) enum ParseResult {
    Help(help::Topic),
    Version,
    Campaign(campaign::CampaignInvocation),
    Coverage(coverage::CoverageInvocation),
    Syscalls(syscalls::SyscallsInvocation),
    NativeAudit(NativeAuditInvocation),
    NativeBuild(NativeBuildInvocation),
    NativeRun(NativeRunInvocation),
    NativeHarness(NativeHarnessInvocation),
    Minimize(minimize::MinimizeInvocation),
    Trace(trace_cmd::TraceInvocation),
}

thread_local! {
    /// The verb a usage error should print the synopsis for, set as soon as
    /// routing identifies it. Unset (`None`) before verb resolution, so a
    /// top-level error prints the compact synopsis list. A CLI process parses
    /// once, single-threaded, so a thread-local is ample.
    static CURRENT_VERB: std::cell::RefCell<Option<&'static str>> =
        const { std::cell::RefCell::new(None) };
}

fn set_current_verb(verb: Option<&'static str>) {
    CURRENT_VERB.with(|cell| *cell.borrow_mut() = verb);
}

pub(super) fn current_verb() -> Option<&'static str> {
    CURRENT_VERB.with(|cell| *cell.borrow())
}

/// Whether `flag`/`short` appears anywhere before a literal `--` separator. After
/// `--` the token belongs to the guest/oracle and is left untouched. The name may
/// be inline (`--flag=...` never applies to these valueless switches, so an exact
/// match is what matters).
fn flag_before_separator(arguments: &[OsString], long: &str, short: &str) -> bool {
    for argument in arguments {
        if argument == "--" {
            return false;
        }
        if argument == long || argument == short {
            return true;
        }
    }
    false
}

/// Whether `-h`/`--help` appears anywhere before a literal `--` separator.
fn help_requested(arguments: &[OsString]) -> bool {
    flag_before_separator(arguments, "--help", "-h")
}

/// Whether `-V`/`--version` appears anywhere before a literal `--` separator.
fn version_requested(arguments: &[OsString]) -> bool {
    flag_before_separator(arguments, "--version", "-V")
}

pub(super) fn parse(mut arguments: Vec<OsString>) -> Result<ParseResult, CliError> {
    // `cargo patina ...` invokes this binary with a leading `patina` argument.
    if arguments.first().and_then(|value| value.to_str()) == Some("patina") {
        arguments.remove(0);
    }
    if arguments.is_empty() {
        return Err(CliError::usage(
            "missing command (expected run, test, campaign, build, audit, replay, minimize, coverage, syscalls, or trace)",
        ));
    }
    // The routed verb (if any). Every known verb records itself so a usage error
    // prints that verb's synopsis, and `-h`/`--help` anywhere before `--` returns
    // that verb's focused help instead of being consumed as a positional. Owned so
    // the `arguments.remove(0)` below does not conflict with the borrow.
    let verb = arguments
        .first()
        .and_then(|value| value.to_str())
        .map(str::to_string);
    if let Some(name) = verb.as_deref()
        && help::verb(name).is_some()
    {
        arguments.remove(0);
        let topic = help::topic_for(name);
        // Record the canonical verb name (a `'static` from the registry) so
        // later usage errors in the family parser point at the right section.
        if let help::Topic::Verb(canonical) = topic {
            set_current_verb(Some(canonical));
        }
        if help_requested(&arguments) {
            return Ok(ParseResult::Help(topic));
        }
        // `-V`/`--version` is intercepted everywhere before `--`, exactly like
        // `--help`, so every verb honors it.
        if version_requested(&arguments) {
            return Ok(ParseResult::Version);
        }
        return match name {
            "campaign" => campaign::parse(arguments).map(ParseResult::Campaign),
            "coverage" => coverage::parse(arguments).map(ParseResult::Coverage),
            "syscalls" => syscalls::parse(arguments).map(ParseResult::Syscalls),
            "build" => parse_native_build(arguments).map(ParseResult::NativeBuild),
            "audit" => parse_audit(arguments),
            "run" => parse_run(arguments),
            "test" => parse_test(arguments),
            // `replay` is routed by the same artifact inference as `run`: it
            // restores the semantic config (seed, fault knobs, buggify, guest
            // argv) from the trace and exposes no semantic flags.
            "replay" => parse_replay(arguments),
            "minimize" => parse_minimize(arguments).map(ParseResult::Minimize),
            "trace" => parse_trace(arguments).map(ParseResult::Trace),
            _ => unreachable!("verb() gated the known-verb set"),
        };
    }
    match verb.as_deref() {
        Some("-h" | "--help") => Ok(ParseResult::Help(help::Topic::Overview)),
        Some("-V" | "--version") => Ok(ParseResult::Version),
        _ => Err(CliError::usage(format!(
            "unsupported command {:?}; expected run, test, campaign, build, audit, replay, minimize, coverage, syscalls, or trace",
            arguments[0].to_string_lossy()
        ))),
    }
}

/// The usage error for a verb whose leading region held no artifact: name the
/// unregistered flag the scan stopped at, if any, rather than a bare "requires".
fn missing_artifact(
    verb: &str,
    arguments: &[OsString],
    stop: Option<usize>,
    what: &str,
) -> CliError {
    match stop {
        Some(stop) => CliError::usage(format!(
            "unsupported option {:?} for `{verb}`; {verb} requires {what}",
            arguments[stop].to_string_lossy()
        )),
        None => CliError::usage(format!("{verb} requires {what}")),
    }
}

/// Route `run`: source-first with artifacts accepted uniformly. A built
/// artifact runs as-is; a `.rs` source or a dir/`Cargo.toml` package is built
/// shim-linked on the fly, then run under the pre-run gate.
fn parse_run(arguments: Vec<OsString>) -> Result<ParseResult, CliError> {
    // Options may lead the artifact: locate it registry-arity-aware rather than
    // insisting it be the first token.
    let scan = locate_positionals("run", &arguments, 1);
    let Some(first) = scan.positionals.first().cloned() else {
        return Err(missing_artifact(
            "run",
            &arguments,
            scan.stop,
            "an artifact, source, or package path",
        ));
    };
    let mut binary = resolve_positional("run", &first)?;
    let selection = take_package_bin(scan.rest)?;
    apply_package_selection(&mut binary, selection.package, selection.bin)?;
    apply_env_package_selection(&mut binary)?;
    let (release, rest) = take_release(selection.rest)?;
    apply_release(&mut binary, release)?;
    apply_env_release(&mut binary)?;
    parse_native_run_from(binary, rest).map(ParseResult::NativeRun)
}

/// Route `test <DIR|Cargo.toml>`: the native libtest harness mode used by
/// point-solution DST tests.
fn parse_test(arguments: Vec<OsString>) -> Result<ParseResult, CliError> {
    const WHAT: &str = "a Cargo package (directory or Cargo.toml)";
    let scan = locate_positionals("test", &arguments, 1);
    let Some(first) = scan.positionals.first().cloned() else {
        return Err(missing_artifact("test", &arguments, scan.stop, WHAT));
    };
    match classify_arg(&first)? {
        ArgKind::SourcePackage(manifest) => {
            parse_native_harness_from(PathBuf::from(&first), manifest, scan.rest)
                .map(ParseResult::NativeHarness)
        }
        _ => Err(CliError::usage(format!(
            "test requires {WHAT}, not {}",
            Path::new(&first).display()
        ))),
    }
}

/// Route `audit`: source-first, artifacts accepted. A native binary (built or
/// built on the fly) goes to the symbol audit.
fn parse_audit(arguments: Vec<OsString>) -> Result<ParseResult, CliError> {
    // Options may lead the artifact.
    let scan = locate_positionals("audit", &arguments, 1);
    let Some(first) = scan.positionals.first().cloned() else {
        return Err(missing_artifact(
            "audit",
            &arguments,
            scan.stop,
            "an artifact or source path",
        ));
    };
    let mut artifact = resolve_positional("audit", &first)?;
    // Source-first `--package`/`--bin` select the workspace member/binary to build
    // before the audit — the help advertises the form, so it must not be rejected.
    // Consumed here so the audit parser sees only its own flags.
    let selection = take_package_bin(scan.rest)?;
    apply_package_selection(&mut artifact, selection.package, selection.bin)?;
    apply_env_package_selection(&mut artifact)?;
    parse_native_audit_from(artifact, selection.rest).map(ParseResult::NativeAudit)
}

/// Route `replay <ARTIFACT|SOURCE|PKG> <TRACE>` by the same artifact inference
/// as `run`: a native binary (or a source/package built on the fly) replays
/// under the native supervisor, which restores the recorded semantic config from
/// the trace and loads it fail-closed BEFORE any guest execution.
fn parse_replay(arguments: Vec<OsString>) -> Result<ParseResult, CliError> {
    // The two positionals (artifact/source/package, then trace) may be
    // interleaved with options in any order, e.g. `replay --fingerprint f app
    // trace`; their relative order is preserved: the first is the origin, the
    // second the trace. A rebuilt binary is judged against the trace by the
    // fail-closed machinery (fingerprint + operation-mismatch).
    let scan = locate_positionals("replay", &arguments, 2);
    if scan.positionals.len() < 2 {
        let what = if scan.positionals.is_empty() {
            "an artifact/source/package path and a trace path"
        } else {
            "a trace path"
        };
        return Err(missing_artifact("replay", &arguments, scan.stop, what));
    }
    let binary = resolve_positional("replay", &scan.positionals[0])?;
    let trace = PathBuf::from(&scan.positionals[1]);
    parse_native_replay(binary, trace, scan.rest).map(ParseResult::NativeRun)
}

#[cfg(test)]
mod tests;
