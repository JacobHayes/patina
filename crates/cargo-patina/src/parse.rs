//! Argument parsing, artifact classification, and control-plane encoding.

use crate::native_build::{DEFAULT_NATIVE_EDITION, GuestInstrumentation};
use crate::{
    ArtifactRef, BuildSpec, BuildSpecKind, CliError, DEFAULT_NATIVE_FINGERPRINT,
    DEFAULT_SEED_BUDGET, ExploreInvocation, ExploreTarget, HarnessFeatures, HarnessSeeds,
    Invocation, KnobValues, Mode, NativeAuditInvocation, NativeBuggify, NativeBuildInvocation,
    NativeBuildTarget, NativeHarnessInvocation, NativeLiveness, NativeRunInvocation, NativeRunMode,
    NativeSchedule, PATINA_RUNTIME_CRATES, UnsupportedPolicy, WasiBuildInvocation, WasiInvocation,
    WasiPreopenConfig, WasiResourceLimitOverrides, WasiSocketConfig, campaign, cli, coverage, help,
    minimize, sites, syscalls, trace_cmd, trace_view, values,
};
use patina_dst_runtime::{
    ENV_BUGGIFY, ENV_BUGGIFY_ACTIVATION, ENV_BUGGIFY_AFTER_SETUP, ENV_BUGGIFY_CUTOFF,
    ENV_CONVERGE_WITHIN, ENV_HEAL_AFTER, ENV_LIVENESS_WATCHDOG, ENV_SCHED_PCT, ENV_SCHED_PCT_STEPS,
    ENV_SCHED_STARVE, ENV_SCHED_STARVE_MAX_LEN, ENV_SCHED_STARVE_WINDOW, ENV_SWARM, FaultKnob,
    Plumbing,
};
use patina_dst_wasi_host::{DEFAULT_WASM_FUEL, MountPolicy};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::{env, fs};

mod artifact;
pub(crate) use artifact::*;
mod cargo;
mod control;
mod native;
mod wasi;
pub(super) use control::*;
mod inspection;
mod minimization;

use cargo::cargo_package_dir;
pub(super) use cargo::parse_cargo;
pub(super) use cargo::parse_cargo_replay;
pub(super) use cargo::parse_explore;
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
use native::realtime_epoch_of;
use wasi::WasiHostInputs;
pub(super) use wasi::parse_wasi_replay;
#[cfg(test)]
pub(super) use wasi::parse_wasi_run;
pub(super) use wasi::parse_wasi_run_from;

pub(super) enum ParseResult {
    Help(help::Topic),
    Version,
    Run(Invocation),
    Campaign(campaign::CampaignInvocation),
    Coverage(coverage::CoverageInvocation),
    Sites(sites::SitesInvocation),
    Syscalls(syscalls::SyscallsInvocation),
    Explore(ExploreInvocation),
    WasiBuild(WasiBuildInvocation),
    WasiAudit(ArtifactRef),
    WasiRun(WasiInvocation),
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
            "missing command (expected run, test, campaign, explore, build, audit, replay, minimize, coverage, sites, syscalls, or trace)",
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
        // `--help`, so every verb honors it (not just the top level and the
        // cargo family).
        if version_requested(&arguments) {
            return Ok(ParseResult::Version);
        }
        return match name {
            "campaign" => campaign::parse(arguments).map(ParseResult::Campaign),
            "coverage" => coverage::parse(arguments).map(ParseResult::Coverage),
            "sites" => sites::parse(arguments).map(ParseResult::Sites),
            "syscalls" => syscalls::parse(arguments).map(ParseResult::Syscalls),
            "explore" => parse_explore(arguments).map(ParseResult::Explore),
            "build" => parse_build(arguments),
            "audit" => parse_audit(arguments),
            "run" => parse_run(arguments),
            "test" => parse_test(arguments),
            // `replay` is the sole replay entry point for all three families,
            // routed by the same artifact inference as `run`: it restores each
            // family's semantic config (seed, fault knobs, buggify, guest argv)
            // from the trace and exposes no semantic flags.
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
            "unsupported command {:?}; expected run, test, campaign, explore, build, audit, replay, minimize, coverage, sites, syscalls, or trace",
            arguments[0].to_string_lossy()
        ))),
    }
}

/// Route `run`: source-first with artifacts accepted uniformly. A built
/// artifact runs as-is (family from magic); a `.rs`/dir/`Cargo.toml` with
/// `--target` (or a lone `.rs`) builds on the fly then runs; a dir/`Cargo.toml`
/// with no `--target`, a leading flag, or no artifact is the Cargo package
/// family — the same machinery as `test`.
fn parse_run(arguments: Vec<OsString>) -> Result<ParseResult, CliError> {
    let (target, rest) = extract_target(arguments)?;
    // Options may lead the artifact: locate it registry-arity-aware rather than
    // insisting it be the first token.
    let scan = locate_positionals("run", &rest, 1);
    let Some(first) = scan.positionals.first().cloned() else {
        // No artifact located. If the scan stopped at an unknown flag, refuse
        // loudly when a real artifact is stranded behind it; otherwise the
        // unknown flag is a genuine forwarded cargo flag (`run --manifest-path X`)
        // and the whole list stays the Cargo package family.
        if let Some(stop) = scan.stop {
            reject_stranded_artifact("run", &rest[stop..])?;
        }
        if target.is_some() {
            return Err(CliError::usage(
                "--target requires a source or package to build; `run` with no artifact is the Cargo package family",
            ));
        }
        return parse_cargo("run".to_string(), rest);
    };
    // A directory/`Cargo.toml` positional (no `--target`) that integrates the
    // Patina runtime stays the cargo-family path — the linked runtime owns
    // seeding, recording, replay, and `--param`/`--budget`. A plain package has no
    // such runtime, so it falls through to `resolve_positional`, which builds it
    // shim-linked and runs it under the native pre-run gate exactly like `audit`
    // (and exactly like a prebuilt binary). Either way an existing directory
    // resolves as a source and is NEVER passed through as guest argv.
    if target.is_none()
        && let ArgKind::SourcePackage(manifest) = classify_arg(&first)?
        && package_integrates_patina(Some(&manifest), None)
    {
        return parse_cargo("run".to_string(), rest);
    }
    match resolve_positional(&first, target.as_deref())? {
        Some((ArtifactFamily::Wasm, mut module)) => {
            let selection = take_package_bin(scan.rest)?;
            apply_package_selection(&mut module, selection.package, selection.bin)?;
            let (release, rest) = take_release(selection.rest)?;
            apply_release(&mut module, release)?;
            parse_wasi_run_from(module, rest).map(ParseResult::WasiRun)
        }
        Some((ArtifactFamily::Native, mut binary)) => {
            let selection = take_package_bin(scan.rest)?;
            apply_package_selection(&mut binary, selection.package, selection.bin)?;
            let (release, rest) = take_release(selection.rest)?;
            apply_release(&mut binary, release)?;
            parse_native_run_from(binary, rest).map(ParseResult::NativeRun)
        }
        // Cargo package family: forward the whole argument list (including the
        // positional dir/Cargo.toml, which Cargo interprets) to `parse_cargo`.
        None => parse_cargo("run".to_string(), rest),
    }
}

/// Route `test`: with no source positional this remains the Cargo package
/// family; a directory or `Cargo.toml` positional selects the native libtest
/// harness mode used by point-solution DST tests.
fn parse_test(arguments: Vec<OsString>) -> Result<ParseResult, CliError> {
    let scan = locate_positionals("test", &arguments, 1);
    let Some(first) = scan.positionals.first().cloned() else {
        if let Some(stop) = scan.stop {
            reject_stranded_artifact("test", &arguments[stop..])?;
        }
        return parse_cargo("test".to_string(), arguments);
    };
    match classify_arg(&first)? {
        ArgKind::SourcePackage(manifest) => {
            parse_native_harness_from(PathBuf::from(&first), manifest, scan.rest)
                .map(ParseResult::NativeHarness)
        }
        ArgKind::SourceFile(_) => Err(CliError::usage(
            "test native harness mode requires a Cargo package (directory or Cargo.toml), not a single .rs source",
        )),
        ArgKind::Artifact(_) => Err(CliError::usage(
            "test native harness mode requires a Cargo package (directory or Cargo.toml), not a prebuilt artifact",
        )),
        ArgKind::Other => parse_cargo("test".to_string(), arguments),
    }
}

/// Route `audit`: source-first, artifacts accepted. A native binary (built or
/// built-on-the-fly) goes to the symbol audit; a WASI module lists its imports
/// (and takes no `--allow`, which is native-only). A dir/`Cargo.toml` with no
/// `--target` builds native (audit has no Cargo package family).
fn parse_audit(arguments: Vec<OsString>) -> Result<ParseResult, CliError> {
    let (target, rest) = extract_target(arguments)?;
    // Options may lead the artifact.
    let scan = locate_positionals("audit", &rest, 1);
    let Some(first) = scan.positionals.first().cloned() else {
        // `audit` has no Cargo package family, so a missing artifact is always an
        // error — but name the offending unknown flag (and refuse loudly if a real
        // artifact is stranded behind it) rather than a bare "requires an artifact".
        if let Some(stop) = scan.stop {
            reject_stranded_artifact("audit", &rest[stop..])?;
            return Err(CliError::usage(format!(
                "unsupported option {:?} for `audit`; audit requires an artifact or source path",
                rest[stop].to_string_lossy()
            )));
        }
        return Err(CliError::usage("audit requires an artifact or source path"));
    };
    let (family, mut artifact) = resolve_positional(&first, target.as_deref())?
        .ok_or_else(|| {
            CliError::usage(format!(
                "audit target {} is neither a WebAssembly module, a native binary, nor a source/package to build",
                Path::new(&first).display()
            ))
        })?;
    // Source-first `--package`/`--bin` select the workspace member/binary to build
    // before the audit — the help advertises the form, so it must not be rejected.
    // Consumed here, uniformly for both families, so the family parser sees only
    // its own flags.
    let selection = take_package_bin(scan.rest)?;
    apply_package_selection(&mut artifact, selection.package, selection.bin)?;
    let flags = selection.rest;
    match family {
        ArtifactFamily::Native => {
            parse_native_audit_from(artifact, flags).map(ParseResult::NativeAudit)
        }
        ArtifactFamily::Wasm => {
            cli::parse("audit", help::Family::Wasi, flags)?;
            Ok(ParseResult::WasiAudit(artifact))
        }
    }
}

/// Route `build`: extract `--target` (default `native`) and dispatch to the
/// native or WASI package builder. The rest of the argument vector is handed to
/// the per-target parser unchanged, so each target keeps its exact flag set.
fn parse_build(arguments: Vec<OsString>) -> Result<ParseResult, CliError> {
    let (target, rest) = extract_target(arguments)?;
    match target_family(target.as_deref().unwrap_or("native"))? {
        ArtifactFamily::Native => parse_native_build(rest).map(ParseResult::NativeBuild),
        ArtifactFamily::Wasm => parse_wasi_build(rest).map(ParseResult::WasiBuild),
    }
}

/// Parse `build --target wasi <DIR|Cargo.toml> [--package NAME] [--bin NAME]
/// [--release] [--output PATH]`. WASI is package-only: a single `.rs` source is
/// native-only, and `--yield-points` is meaningless without threads.
pub(super) fn parse_wasi_build(arguments: Vec<OsString>) -> Result<WasiBuildInvocation, CliError> {
    // The package path may follow options; locate it registry-arity-aware.
    let scan = locate_positionals("build", &arguments, 1);
    let package_path = scan.positionals.into_iter().next().map(PathBuf::from);
    let args = cli::parse("build", help::Family::Wasi, scan.rest)?;
    // Require the package path after the flag scan so an unknown flag is named
    // first (never taken as the path).
    let package_path = package_path.ok_or_else(|| {
        CliError::usage("build --target wasi requires a Cargo package (a directory or Cargo.toml)")
    })?;
    if package_path.extension().and_then(OsStr::to_str) == Some("rs") {
        return Err(CliError::usage(
            "build --target wasi compiles a Cargo package; a single .rs source is native-only",
        ));
    }
    Ok(WasiBuildInvocation {
        manifest: native_manifest_path(&package_path),
        package: args.string("--package"),
        bin: args.string("--bin"),
        release: args.flag("--release"),
        output: args.path("--output"),
    })
}

/// Route `replay <ARTIFACT|SOURCE|PKG> <TRACE>` by the same artifact inference as
/// `run`: a WebAssembly module replays under WASI, a native binary under the
/// native supervisor, and a directory/`Cargo.toml` (no `--target`) under the
/// Cargo package family. Each restores its recorded semantic config from the
/// trace and exposes only that family's genuine host inputs. The two positionals
/// (artifact/source/package, then trace) always lead; per-family flags and any
/// `--` section follow and are handled by the family parser.
fn parse_replay(arguments: Vec<OsString>) -> Result<ParseResult, CliError> {
    // `replay` is source-first like `run`/`audit`: the artifact may be built or a
    // source/package built on the fly (honoring `--target`). A rebuilt binary is
    // judged against the trace by the fail-closed machinery (fingerprint +
    // operation-mismatch), so no special-casing.
    let (target, rest) = extract_target(arguments)?;
    // The two positionals (artifact/source/package, then trace) may be interleaved
    // with options in any order, e.g. `replay --fingerprint f art.wasm trace`.
    // Their relative order is preserved: the first is the origin, the second the
    // trace.
    let scan = locate_positionals("replay", &rest, 2);
    if scan.positionals.len() < 2 {
        if let Some(stop) = scan.stop {
            reject_stranded_artifact("replay", &rest[stop..])?;
        }
        return Err(CliError::usage(if scan.positionals.is_empty() {
            "replay requires an artifact/source/package path and a trace path"
        } else {
            "replay requires a trace path"
        }));
    }
    let origin = scan.positionals[0].clone();
    let trace = PathBuf::from(&scan.positionals[1]);
    let flags = scan.rest;
    // A package that integrates the Patina runtime replays through the cargo
    // family (the linked runtime restores seed/faults/timeline and honors
    // `--branch`/`--timeline`); a plain package rebuilds shim-linked and replays
    // through the native path, where the trace is loaded and fail-closed BEFORE
    // any guest execution.
    if target.is_none()
        && let ArgKind::SourcePackage(manifest) = classify_arg(&origin)?
        && package_integrates_patina(Some(&manifest), None)
    {
        let package_dir = cargo_package_dir(&origin)?;
        return parse_cargo_replay(package_dir, trace, flags);
    }
    match resolve_positional(&origin, target.as_deref())? {
        Some((ArtifactFamily::Wasm, module)) => {
            parse_wasi_replay(module, trace, flags).map(ParseResult::WasiRun)
        }
        Some((ArtifactFamily::Native, binary)) => {
            parse_native_replay(binary, trace, flags).map(ParseResult::NativeRun)
        }
        // Neither an artifact nor a source/package (a leading flag or a plain
        // file): let `cargo_package_dir` produce the precise "neither ..." error.
        None => {
            let package_dir = cargo_package_dir(&origin)?;
            parse_cargo_replay(package_dir, trace, flags)
        }
    }
}

#[cfg(test)]
mod tests;
