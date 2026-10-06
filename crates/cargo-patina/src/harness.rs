//! Native test harnesses and bounded seed exploration.

use crate::native_build::{
    GuestInstrumentation, NATIVE_AUDIT_METADATA_ARGS, host_target_triple, native_package_link_args,
    native_package_rustflags, resolve_artifact, stage_sancov_stub,
};
use crate::native_run::execute_native_run;
use crate::parse::knob_flag_pairs;
use crate::shim_build::{
    PATINA_POSIX_OBJECT, RustcInvocation, apply_rustc_env, build_native_shim,
    check_native_toolchain_agreement, lock_target_dir, prepare_shim_sources,
    stage_instrumentation_object, stage_shim_object,
};
use crate::wasi_exec::execute_wasi_run;
use crate::{
    ArtifactRef, CliError, ExploreInvocation, ExploreTarget, Mode, NativeHarnessInvocation,
    NativeRunMode, execute, exit_code, output, shim_cache,
};
use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::{env, fs};

fn shell_quote(value: &OsStr) -> String {
    let text = value.to_string_lossy();
    if !text.is_empty()
        && text.chars().all(|ch| {
            ch.is_ascii_alphanumeric()
                || matches!(ch, '-' | '_' | '.' | '/' | ':' | '=' | '+' | ',')
        })
    {
        return text.into_owned();
    }
    format!("'{}'", text.replace('\'', "'\\''"))
}

fn command_line(prefix: &str, args: &[OsString]) -> String {
    let mut parts = vec![prefix.to_string()];
    parts.extend(args.iter().map(|arg| shell_quote(arg)));
    parts.join(" ")
}

fn command_with_seed(args: &[OsString], seed: u64) -> Vec<OsString> {
    let seed_text = seed.to_string();
    let mut out = Vec::with_capacity(args.len() + 2);
    let mut inserted = false;
    let mut index = 0;
    while index < args.len() {
        if args[index] == "--" {
            if !inserted {
                out.push(OsString::from("--seed"));
                out.push(OsString::from(&seed_text));
            }
            out.extend_from_slice(&args[index..]);
            return out;
        }
        if let Some(text) = args[index].to_str() {
            if text == "--seed" {
                out.push(OsString::from("--seed"));
                out.push(OsString::from(&seed_text));
                inserted = true;
                index += 2;
                continue;
            }
            if text.starts_with("--seed=") {
                out.push(OsString::from("--seed"));
                out.push(OsString::from(&seed_text));
                inserted = true;
                index += 1;
                continue;
            }
        }
        out.push(args[index].clone());
        index += 1;
    }
    if !inserted {
        out.push(OsString::from("--seed"));
        out.push(OsString::from(seed_text));
    }
    out
}

fn exploration_repro(wrapped_command: &[OsString], seed: u64) -> String {
    command_line("cargo patina", &command_with_seed(wrapped_command, seed))
}

struct BuiltNativeHarness {
    guest: PathBuf,
    directory: PathBuf,
    package_name: String,
}

struct NativeHarnessArtifact {
    executable: PathBuf,
    package_id: String,
}

struct HarnessSeedRun {
    exit_code: i32,
    result: String,
    stdout: String,
    stderr: String,
    message: Option<String>,
    // Choke point: HarnessSeedRun::trace is taken only from the child's receipt,
    // never inferred from a requested path or a file left by an earlier run.
    trace: Option<output::TraceFacts>,
    pre_run_refusal: bool,
}

fn record_harness_failure(
    first: &HarnessSeedRun,
    trace: &Path,
    record: impl FnOnce() -> Result<HarnessSeedRun, CliError>,
) -> Result<Option<HarnessSeedRun>, CliError> {
    if first.pre_run_refusal {
        // Nothing executed, so a recorded retry would only repeat the audit.
        return Ok(None);
    }
    match fs::remove_file(trace) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(CliError(format!(
                "failed to remove previous harness trace {}: {error}",
                trace.display()
            )));
        }
    }
    record().map(Some)
}

pub(super) fn execute_native_harness(invocation: NativeHarnessInvocation) -> Result<i32, CliError> {
    let built = build_native_harness(&invocation)?;
    let test_name = format!("{}::{}", invocation.harness_target, invocation.exact);
    for seed in invocation.seeds.iter() {
        let run = run_native_harness_seed(&invocation, &built.guest, seed, None)?;
        if run.exit_code != 0 {
            let trace = built.directory.join(format!("seed-{seed}.patina"));
            let recorded = record_harness_failure(&run, &trace, || {
                run_native_harness_seed(&invocation, &built.guest, seed, Some(&trace))
            })?;
            let reproduced = recorded
                .as_ref()
                .map(|recorded| recorded.exit_code == run.exit_code);
            let latest = recorded.as_ref().unwrap_or(&run);
            let block = native_harness_failure_block(NativeHarnessFailure {
                invocation: &invocation,
                built: &built,
                test_name: &test_name,
                seed,
                first: &run,
                latest,
                reproduced,
            });
            if !output::options().is_json() {
                eprintln!("{block}");
            }
            let exit = if reproduced == Some(false) {
                2
            } else {
                run.exit_code
            };
            let result = if reproduced == Some(false) {
                "error"
            } else {
                latest.result.as_str()
            };
            output::emit_harness_result(result, exit, block, latest.trace.clone());
            return Ok(exit);
        }
    }
    let message = format!(
        "patina dst test passed: {test_name} {} package={} guest={}",
        invocation.seeds.label(),
        built.package_name,
        built.guest.display()
    );
    if output::options().is_json() {
        output::emit_simple("test", "ok", 0, Some(message));
    } else {
        println!("PATINA_DST_TEST_PASS {message}");
    }
    Ok(0)
}

fn build_native_harness(
    invocation: &NativeHarnessInvocation,
) -> Result<BuiltNativeHarness, CliError> {
    if !invocation.manifest.is_file() {
        return Err(CliError(format!(
            "no Cargo manifest at {}",
            invocation.manifest.display()
        )));
    }
    let shim = prepare_shim_sources()?;
    let rustc = check_native_toolchain_agreement(&shim.dir)?;
    let built_shim = build_native_shim(
        invocation.release,
        &rustc,
        &shim,
        invocation.instrumentation,
    )?;
    let staticlib = &built_shim.staticlib;
    let host_target = host_target_triple(&rustc)?;
    let object = stage_shim_object(&built_shim, &PATINA_POSIX_OBJECT, &host_target, &[])?;
    let yield_object =
        stage_instrumentation_object(&built_shim, invocation.instrumentation, &host_target)?;
    let sancov_stub = stage_sancov_stub(&built_shim, yield_object.is_some(), &host_target)?;
    let rustflags = native_package_rustflags(sancov_stub.as_deref(), &host_target);
    let metadata = cargo_metadata(&invocation.manifest, Some(&rustc))?;
    let target_dir = metadata_target_dir(&metadata)?;
    let selected = select_native_harness_target(
        &metadata,
        &invocation.harness_target,
        invocation.package.as_deref(),
    )?;

    let mut command = Command::new(&rustc.cargo_command);
    command
        .arg("rustc")
        .arg("--manifest-path")
        .arg(&invocation.manifest)
        .arg("--package")
        .arg(&selected.package)
        .arg("--target")
        .arg(&host_target)
        .arg("--message-format=json-render-diagnostics")
        .env_remove("RUSTFLAGS")
        .env("CARGO_ENCODED_RUSTFLAGS", rustflags)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    apply_rustc_env(&mut command, &rustc);
    command.args(selected.kind.select_args(&selected.name));
    command.args(invocation.features.cargo_args());
    // `cargo rustc` builds a lib/bin target in test mode only under the `test` or
    // `bench` profile, and `--release` is rejected alongside `--profile`. `bench`
    // inherits `release`, so `--release` here means the same codegen settings a
    // `cargo test --release` harness would get, including any `[profile.release]`
    // overrides the package declares.
    command
        .arg("--profile")
        .arg(if invocation.release { "bench" } else { "test" });
    command
        .arg("--")
        .args(native_package_link_args(
            &object,
            staticlib,
            yield_object.as_deref(),
        ))
        .args(NATIVE_AUDIT_METADATA_ARGS);
    let _lock = lock_target_dir(&target_dir)?;
    shim_cache::inherit(&mut command, &built_shim._lease)?;
    let built = command.output().map_err(|error| {
        CliError(format!(
            "failed to run cargo rustc for native harness: {error}"
        ))
    })?;
    if !built.status.success() {
        return Err(CliError(format!(
            "building the native libtest harness {:?} failed",
            invocation.harness_target
        )));
    }
    let artifact = native_harness_executable(&built.stdout, &selected.name)?;
    let package_name = metadata_package_name(&metadata, &artifact.package_id)
        .unwrap_or_else(|| artifact.package_id.clone());
    let directory = selected.staging_directory(&target_dir, &package_name, &invocation.exact);
    fs::create_dir_all(&directory).map_err(|error| {
        CliError(format!(
            "failed to create native harness staging dir {}: {error}",
            directory.display()
        ))
    })?;
    let guest = directory.join("guest");
    fs::copy(&artifact.executable, &guest).map_err(|error| {
        CliError(format!(
            "failed to stage native harness {} at {}: {error}",
            artifact.executable.display(),
            guest.display()
        ))
    })?;
    let permissions = fs::metadata(&artifact.executable)
        .map_err(|error| {
            CliError(format!(
                "failed to read permissions for {}: {error}",
                artifact.executable.display()
            ))
        })?
        .permissions();
    fs::set_permissions(&guest, permissions).map_err(|error| {
        CliError(format!(
            "failed to copy permissions to staged native harness {}: {error}",
            guest.display()
        ))
    })?;
    Ok(BuiltNativeHarness {
        guest,
        directory,
        package_name,
    })
}

pub(super) fn cargo_metadata(
    manifest: &Path,
    rustc: Option<&RustcInvocation>,
) -> Result<serde_json::Value, CliError> {
    let cargo = rustc
        .map(|r| r.cargo_command.clone())
        .unwrap_or_else(|| env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo")));
    let mut command = Command::new(&cargo);
    if let Some(rustc) = rustc {
        apply_rustc_env(&mut command, rustc);
    }
    let output = command
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .arg("--manifest-path")
        .arg(manifest)
        .output()
        .map_err(|error| CliError(format!("failed to run cargo metadata: {error}")))?;
    if !output.status.success() {
        return Err(CliError(format!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| CliError(format!("failed to parse cargo metadata: {error}")))
}

pub(super) fn metadata_target_dir(metadata: &serde_json::Value) -> Result<PathBuf, CliError> {
    metadata
        .get("target_directory")
        .and_then(serde_json::Value::as_str)
        .map(PathBuf::from)
        .ok_or_else(|| CliError("cargo metadata did not report target_directory".into()))
}

fn metadata_package_name(metadata: &serde_json::Value, package_id: &str) -> Option<String> {
    metadata
        .get("packages")
        .and_then(serde_json::Value::as_array)?
        .iter()
        .find(|package| package.get("id").and_then(serde_json::Value::as_str) == Some(package_id))?
        .get("name")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

/// Which `cargo rustc` target-selection flag reaches a libtest harness target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HarnessTargetKind {
    /// The package's own library, built in test mode (`--harness-target <crate>`
    /// naming the crate itself — the common shape).
    Lib,
    /// An integration test under `tests/`.
    Test,
    /// A binary target's inline `#[test]`s.
    Bin,
}

impl HarnessTargetKind {
    fn name(self) -> &'static str {
        match self {
            Self::Lib => "lib",
            Self::Bin => "bin",
            Self::Test => "test",
        }
    }

    fn select_args(self, name: &str) -> Vec<String> {
        match self {
            HarnessTargetKind::Lib => vec!["--lib".to_string()],
            HarnessTargetKind::Test => vec!["--test".to_string(), name.to_string()],
            HarnessTargetKind::Bin => vec!["--bin".to_string(), name.to_string()],
        }
    }
}

/// The package and target kind a `--harness-target` name resolves to.
struct SelectedNativeHarness {
    package: String,
    name: String,
    kind: HarnessTargetKind,
}

impl SelectedNativeHarness {
    fn staging_directory(&self, target_dir: &Path, package_name: &str, exact: &str) -> PathBuf {
        target_dir
            .join("patina/dst")
            .join(safe_path_segment(package_name))
            .join(self.kind.name())
            .join(safe_path_segment(&self.name))
            .join(safe_path_segment(exact))
    }
}

/// Resolve `--harness-target` to exactly one package and target *before*
/// building, so the shim link arguments can be scoped to that one unit with
/// `cargo rustc` (see [`native_package_link_args`]). Fails closed on an unknown
/// or ambiguous name, listing what the workspace does offer.
fn select_native_harness_target(
    metadata: &serde_json::Value,
    harness_target: &str,
    package: Option<&str>,
) -> Result<SelectedNativeHarness, CliError> {
    let packages = metadata
        .get("packages")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| CliError("cargo metadata reported no packages".into()))?;
    let (kind_filter, target_name) = match harness_target.split_once(':') {
        Some(("lib", name)) => (Some(HarnessTargetKind::Lib), name),
        Some(("bin", name)) => (Some(HarnessTargetKind::Bin), name),
        Some(("test", name)) => (Some(HarnessTargetKind::Test), name),
        Some(_) => {
            return Err(CliError(format!(
                "invalid harness target {harness_target:?}; use NAME, lib:NAME, bin:NAME, or test:NAME"
            )));
        }
        None => (None, harness_target),
    };
    let mut matches: Vec<SelectedNativeHarness> = Vec::new();
    let mut available = BTreeSet::new();
    for entry in packages {
        let Some(package_name) = entry.get("name").and_then(serde_json::Value::as_str) else {
            continue;
        };
        if package.is_some_and(|wanted| wanted != package_name) {
            continue;
        }
        let targets = entry
            .get("targets")
            .and_then(serde_json::Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();
        for target in targets {
            let Some(name) = target.get("name").and_then(serde_json::Value::as_str) else {
                continue;
            };
            let kinds: Vec<&str> = target
                .get("kind")
                .and_then(serde_json::Value::as_array)
                .map(|kinds| kinds.iter().filter_map(serde_json::Value::as_str).collect())
                .unwrap_or_default();
            // A `[lib]` reports its declared crate types as its kinds, so a
            // dependency-style `crate-type = ["rlib", "cdylib"]` library is still
            // selected by `--lib`. Build scripts (`custom-build`) and examples
            // carry no libtest harness.
            let kind = if kinds
                .iter()
                .all(|kind| matches!(*kind, "lib" | "rlib" | "dylib" | "cdylib" | "proc-macro"))
                && !kinds.is_empty()
            {
                HarnessTargetKind::Lib
            } else if kinds == ["test"] {
                HarnessTargetKind::Test
            } else if kinds == ["bin"] {
                HarnessTargetKind::Bin
            } else {
                continue;
            };
            let prefix = kind.name();
            available.insert(format!("{prefix}:{name} (package {package_name})"));
            if name == target_name && kind_filter.is_none_or(|wanted| wanted == kind) {
                matches.push(SelectedNativeHarness {
                    package: package_name.to_string(),
                    name: name.to_string(),
                    kind,
                });
            }
        }
    }
    match matches.len() {
        1 => Ok(matches.remove(0)),
        0 => Err(CliError(format!(
            "no libtest harness target named {harness_target:?} in the workspace; available harness targets: {}",
            if available.is_empty() {
                "<none>".to_string()
            } else {
                available.into_iter().collect::<Vec<_>>().join(", ")
            }
        ))),
        _ => Err(CliError(format!(
            "multiple targets named {harness_target:?} were found; qualify the name with lib:, bin:, or test: and select a workspace member with --package if needed; available harness targets: {}",
            available.into_iter().collect::<Vec<_>>().join(", ")
        ))),
    }
}

fn native_harness_executable(
    stdout: &[u8],
    harness_target: &str,
) -> Result<NativeHarnessArtifact, CliError> {
    let mut matches = Vec::new();
    let mut available = BTreeSet::new();
    for line in stdout.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        let Ok(message) = serde_json::from_slice::<serde_json::Value>(line) else {
            continue;
        };
        if message.get("reason").and_then(serde_json::Value::as_str) != Some("compiler-artifact") {
            continue;
        }
        let Some(executable) = message
            .get("executable")
            .and_then(serde_json::Value::as_str)
        else {
            continue;
        };
        let is_test_profile = message
            .get("profile")
            .and_then(|profile| profile.get("test"))
            .and_then(serde_json::Value::as_bool)
            == Some(true);
        if !is_test_profile {
            continue;
        }
        let target_name = message
            .get("target")
            .and_then(|target| target.get("name"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("<unknown>");
        available.insert(target_name.to_string());
        if target_name == harness_target {
            let package_id = message
                .get("package_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("<unknown-package>")
                .to_string();
            matches.push(NativeHarnessArtifact {
                executable: PathBuf::from(executable),
                package_id,
            });
        }
    }
    match matches.len() {
        1 => Ok(matches.remove(0)),
        0 => Err(CliError(format!(
            "no libtest harness target named {harness_target:?} was reported by cargo rustc; available harness targets: {}",
            if available.is_empty() {
                "<none>".to_string()
            } else {
                available.into_iter().collect::<Vec<_>>().join(", ")
            }
        ))),
        _ => Err(CliError(format!(
            "internal error: cargo rustc reported multiple libtest executables for the single selected target {harness_target:?}"
        ))),
    }
}

fn safe_path_segment(value: &str) -> String {
    let mut segment = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
            segment.push(ch);
        } else {
            segment.push('_');
        }
    }
    if segment.is_empty() {
        "_".to_string()
    } else {
        segment
    }
}

fn run_native_harness_seed(
    invocation: &NativeHarnessInvocation,
    guest: &Path,
    seed: u64,
    record: Option<&Path>,
) -> Result<HarnessSeedRun, CliError> {
    let executable = env::current_exe().map_err(|error| {
        CliError(format!(
            "failed to locate current cargo-patina executable: {error}"
        ))
    })?;
    let mut args = vec![
        OsString::from("run"),
        OsString::from("--format"),
        OsString::from("json"),
    ];
    args.push(guest.as_os_str().to_owned());
    args.push(OsString::from("--seed"));
    args.push(OsString::from(seed.to_string()));
    if let Some(path) = record {
        args.push(OsString::from("--record"));
        args.push(path.as_os_str().to_owned());
    }
    append_native_harness_run_flags(&mut args, invocation);
    args.push(OsString::from("--"));
    args.push(OsString::from("--test-threads=1"));
    args.push(OsString::from("--exact"));
    args.push(OsString::from(&invocation.exact));
    args.push(OsString::from("--nocapture"));
    let output = Command::new(&executable)
        .args(&args)
        .output()
        .map_err(|error| CliError(format!("failed to run native harness seed {seed}: {error}")))?;
    let exit_code = exit_code(output.status)?;
    let stdout_text = String::from_utf8_lossy(&output.stdout).into_owned();
    let child_stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let json_line = stdout_text
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .ok_or_else(|| {
            CliError(format!(
                "native harness seed {seed} produced no JSON envelope\nstderr:\n{child_stderr}"
            ))
        })?;
    let envelope: serde_json::Value = serde_json::from_str(json_line).map_err(|error| {
        CliError(format!(
            "native harness seed {seed} did not produce a valid JSON envelope: {error}\nstdout:\n{stdout_text}\nstderr:\n{child_stderr}"
        ))
    })?;
    let result = envelope
        .get("result")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(if exit_code == 0 { "ok" } else { "failure" })
        .to_string();
    let guest_stdout = envelope
        .get("stdout")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string();
    let guest_stderr = envelope
        .get("stderr")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let mut stderr = String::new();
    if !child_stderr.is_empty() {
        stderr.push_str(&child_stderr);
        if !child_stderr.ends_with('\n') && !guest_stderr.is_empty() {
            stderr.push('\n');
        }
    }
    stderr.push_str(guest_stderr);
    let message = envelope
        .get("message")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    if stderr.trim().is_empty()
        && let Some(message) = &message
    {
        stderr.push_str(message);
    }
    Ok(HarnessSeedRun {
        exit_code,
        result,
        stdout: guest_stdout,
        stderr,
        message,
        trace: envelope
            .get("trace")
            .filter(|trace| !trace.is_null())
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| CliError(format!("invalid harness trace receipt: {error}")))?,
        pre_run_refusal: envelope["refusal"]["class"] == output::NATIVE_PRERUN_REFUSAL,
    })
}

fn append_native_harness_run_flags(args: &mut Vec<OsString>, invocation: &NativeHarnessInvocation) {
    if let Some(budget) = invocation.step_budget {
        args.push(OsString::from("--budget"));
        args.push(OsString::from(budget.to_string()));
    }
    if let Some(epoch) = &invocation.realtime_epoch {
        args.push(OsString::from("--realtime-epoch"));
        args.push(OsString::from(epoch));
    }
    if let Some(hostname) = &invocation.hostname {
        args.push(OsString::from("--hostname"));
        args.push(OsString::from(hostname));
    }
    // Every knob the registry defines, from the shared table: a flag the harness
    // parsed but did not re-emit would be silently inert here. That includes the
    // repeatable ones (`--dns-entry`, `--net-partition`), which the harness
    // family registers and which the historical `--dns-entry` bug parsed and
    // then dropped, so every lookup in a harness run went NXDOMAIN as if no
    // table had been supplied.
    for (flag, value) in knob_flag_pairs(&invocation.knobs) {
        args.push(OsString::from(flag));
        args.push(OsString::from(value));
    }
    if let Some(buggify) = &invocation.buggify {
        match &buggify.fire_permille {
            Some(value) => args.push(OsString::from(format!("--buggify={value}"))),
            None => args.push(OsString::from("--buggify")),
        }
        push_optional_arg(
            args,
            "--buggify-activation-permille",
            buggify.activation_permille.as_deref(),
        );
        push_optional_arg(
            args,
            "--buggify-cutoff-nanos",
            buggify.cutoff_nanos.as_deref(),
        );
        if buggify.after_setup {
            args.push(OsString::from("--buggify-after-setup"));
        }
    }
    push_optional_value_flag(args, "--sched-pct", invocation.schedule.pct.as_deref());
    push_optional_arg(
        args,
        "--sched-pct-steps",
        invocation.schedule.pct_steps.as_deref(),
    );
    push_optional_value_flag(args, "--starve", invocation.schedule.starve.as_deref());
    push_optional_arg(
        args,
        "--starve-max-len",
        invocation.schedule.starve_max_len.as_deref(),
    );
    push_optional_arg(
        args,
        "--starve-window",
        invocation.schedule.starve_window.as_deref(),
    );
    if invocation.schedule.swarm {
        args.push(OsString::from("--swarm"));
    }
    push_optional_arg(
        args,
        "--compute-watchdog-ms",
        invocation.liveness.compute_watchdog_ms.as_deref(),
    );
    push_optional_value_flag(
        args,
        "--liveness-watchdog",
        invocation.liveness.watchdog.as_deref(),
    );
    push_optional_value_flag(
        args,
        "--converge-within",
        invocation.liveness.converge.as_deref(),
    );
    push_optional_arg(
        args,
        "--heal-after",
        invocation.liveness.heal_after.as_deref(),
    );
}

fn push_optional_arg(args: &mut Vec<OsString>, flag: &str, value: Option<&str>) {
    if let Some(value) = value {
        args.push(OsString::from(flag));
        args.push(OsString::from(value));
    }
}

fn push_optional_value_flag(args: &mut Vec<OsString>, flag: &str, value: Option<&str>) {
    if let Some(value) = value {
        if value.is_empty() {
            args.push(OsString::from(flag));
        } else {
            args.push(OsString::from(format!("{flag}={value}")));
        }
    }
}

struct NativeHarnessFailure<'a> {
    invocation: &'a NativeHarnessInvocation,
    built: &'a BuiltNativeHarness,
    test_name: &'a str,
    seed: u64,
    first: &'a HarnessSeedRun,
    latest: &'a HarnessSeedRun,
    // None means the pre-run gate refused: no recorded retry was attempted.
    reproduced: Option<bool>,
}

fn native_harness_failure_block(failure: NativeHarnessFailure<'_>) -> String {
    let repro = native_harness_repro(failure.invocation, failure.seed);
    let (trace_note, replay) = match &failure.latest.trace {
        Some(trace) => (
            trace.path.clone(),
            format!(
                "\n    cargo patina replay {} {}",
                shell_quote(failure.built.guest.as_os_str()),
                shell_quote(OsStr::new(&trace.path))
            ),
        ),
        None => ("not produced".to_string(), String::new()),
    };
    let mut block = format!(
        "patina dst test failed: {}\n  {}  exit={}  class={}\n  trace: {}\n  stderr tail:\n{}\n  reproduce:\n    {repro}{replay}",
        failure.test_name,
        failure.invocation.seeds.contains(failure.seed),
        failure.first.exit_code,
        failure.latest.result,
        trace_note,
        indent_tail(&failure.latest.stderr, 20),
    );
    if failure.reproduced == Some(false) {
        block.push_str(&format!(
            "\n  record-on-failure mismatch: first exit={} recorded exit={}; refusing to call this deterministic",
            failure.first.exit_code, failure.latest.exit_code
        ));
    }
    if failure.reproduced == Some(false) && failure.first.stderr != failure.latest.stderr {
        block.push_str("\n  first-run stderr tail:\n");
        block.push_str(&indent_tail(&failure.first.stderr, 20));
    }
    if !failure.first.stdout.trim().is_empty() {
        block.push_str("\n  stdout tail:\n");
        block.push_str(&indent_tail(&failure.first.stdout, 10));
    }
    if let Some(message) = &failure.latest.message
        && !message.trim().is_empty()
        && !failure.latest.stderr.contains(message)
    {
        block.push_str(&format!("\n  message: {message}"));
    }
    block
}

fn native_harness_repro(invocation: &NativeHarnessInvocation, seed: u64) -> String {
    let mut args = vec![
        OsString::from("test"),
        invocation.origin.as_os_str().to_owned(),
    ];
    if let Some(package) = &invocation.package {
        args.push(OsString::from("--package"));
        args.push(OsString::from(package));
    }
    args.push(OsString::from("--harness-target"));
    args.push(OsString::from(&invocation.harness_target));
    args.push(OsString::from("--exact"));
    args.push(OsString::from(&invocation.exact));
    args.push(OsString::from("--seed"));
    args.push(OsString::from(seed.to_string()));
    if invocation.release {
        args.push(OsString::from("--release"));
    }
    args.extend(invocation.features.cargo_args());
    match invocation.instrumentation {
        GuestInstrumentation::None => {}
        GuestInstrumentation::YieldPoints => args.push(OsString::from("--yield-points")),
        GuestInstrumentation::CoveragePoints { stride: 0 } => {
            args.push(OsString::from("--coverage-points"));
        }
        GuestInstrumentation::CoveragePoints { stride } => {
            args.push(OsString::from(format!("--coverage-points={stride}")));
        }
    }
    append_native_harness_run_flags(&mut args, invocation);
    command_line("cargo patina", &args)
}

fn indent_tail(text: &str, max_lines: usize) -> String {
    let lines: Vec<&str> = text.lines().collect();
    if lines.is_empty() {
        return "    (empty)".to_string();
    }
    let start = lines.len().saturating_sub(max_lines);
    lines[start..]
        .iter()
        .map(|line| format!("    {line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

pub(super) fn execute_explore(exploration: ExploreInvocation) -> Result<i32, CliError> {
    // Explore drives many child runs and reports once, so per-seed run
    // finalization (capture/envelope/render) is suppressed here: each child
    // streams normally and this verb emits a single campaign-level envelope.
    output::suppress_run_finalize();
    let start = exploration.start_seed;
    let count = exploration.seed_count;
    // The native and WASI families build the artifact once, then run that SAME
    // built artifact across every seed — a source/package is never rebuilt per
    // seed. The resolved artifact (and its build workspace) is held for the whole
    // sweep so the built file outlives every run. The Cargo family instead re-runs
    // the whole command per seed (cargo caches the build).
    let prebuilt = match &exploration.target {
        ExploreTarget::Cargo(_) => None,
        ExploreTarget::Wasi(invocation) => Some(resolve_artifact(invocation.module.clone())?),
        ExploreTarget::Native(invocation) => Some(resolve_artifact(invocation.binary.clone())?),
    };
    let seed_at = |offset: u64| {
        start
            .checked_add(offset)
            .expect("exploration range was validated")
    };
    for offset in 0..count {
        let seed = seed_at(offset);
        let exit = match &exploration.target {
            ExploreTarget::Cargo(invocation) => {
                let mut invocation = invocation.clone();
                invocation.mode = Mode::Seeded { seed };
                execute(invocation)?
            }
            ExploreTarget::Wasi(invocation) => {
                let mut invocation = invocation.clone();
                invocation.module = ArtifactRef::Prebuilt(
                    prebuilt
                        .as_ref()
                        .expect("wasi explore resolved")
                        .path
                        .clone(),
                );
                invocation.mode = Mode::Seeded { seed };
                execute_wasi_run(invocation)?
            }
            ExploreTarget::Native(invocation) => {
                let mut invocation = invocation.clone();
                invocation.binary = ArtifactRef::Prebuilt(
                    prebuilt
                        .as_ref()
                        .expect("native explore resolved")
                        .path
                        .clone(),
                );
                invocation.mode = NativeRunMode::Seeded { seed };
                execute_native_run(invocation)?
            }
        };
        if exit != 0 {
            let repro = exploration_repro(&exploration.wrapped_command, seed);
            eprintln!(
                "PATINA_EXPLORE_FAILURE seed={seed} exit={exit} repro={:?}",
                repro
            );
            output::emit_simple(
                "explore",
                "failure",
                exit,
                Some(format!("seed {seed} exited {exit}; repro: {repro}")),
            );
            return Ok(exit);
        }
    }
    if output::options().is_json() {
        output::emit_simple(
            "explore",
            "ok",
            0,
            Some(format!("start={start} seeds={count}")),
        );
    } else {
        println!("PATINA_EXPLORE_COMPLETE start={start} seeds={count}");
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native_build::GuestInstrumentation;
    use crate::{
        HarnessFeatures, HarnessSeeds, NativeHarnessInvocation, NativeLiveness, NativeSchedule, cli,
    };
    use patina_dst_runtime::FaultKnob;
    use std::ffi::{OsStr, OsString};
    use std::path::{Path, PathBuf};

    use crate::help;
    use std::fs;

    use crate::parse::knobs_of;
    use crate::tests::knob_sample;

    #[test]
    fn native_harness_selection_disambiguates_target_kinds_and_packages() {
        let targets = serde_json::json!([
            {"name": "app", "kind": ["lib"]},
            {"name": "app", "kind": ["bin"]},
            {"name": "app", "kind": ["test"]}
        ]);
        let metadata = serde_json::json!({"packages": [
            {"name": "first", "targets": targets},
            {"name": "second", "targets": targets}
        ]});
        assert!(select_native_harness_target(&metadata, "app", Some("first")).is_err());
        for (prefix, kind) in [
            ("lib", HarnessTargetKind::Lib),
            ("bin", HarnessTargetKind::Bin),
            ("test", HarnessTargetKind::Test),
        ] {
            let selector = format!("{prefix}:app");
            assert!(select_native_harness_target(&metadata, &selector, None).is_err());
            let selected = select_native_harness_target(&metadata, &selector, Some("first"))
                .unwrap_or_else(|error| panic!("{selector}: {error}"));
            assert_eq!(selected.kind, kind);
            assert_eq!(selected.name, "app");
            assert_eq!(selected.package, "first");
        }
        for selector in ["example:app", "lib:missing", "lib:"] {
            assert!(select_native_harness_target(&metadata, selector, Some("first")).is_err());
        }
    }

    #[test]
    fn native_harness_records_failures_but_never_retries_a_prerun_refusal() {
        fn outcome(exit_code: i32, pre_run_refusal: bool) -> HarnessSeedRun {
            HarnessSeedRun {
                exit_code,
                result: "error".into(),
                stdout: String::new(),
                stderr: String::new(),
                message: None,
                trace: None,
                pre_run_refusal,
            }
        }
        // Exit 2 alone is not a pre-run refusal: other errors still get their
        // recording attempt, as do assertion failures and guest aborts.
        for (code, pre_run) in [(2, true), (2, false), (101, false), (134, false)] {
            let directory = tempfile::tempdir().unwrap();
            let trace = directory.path().join("seed-0.patina");
            fs::write(&trace, b"previous recording").unwrap();
            let mut calls = 0;
            let recorded = record_harness_failure(&outcome(code, pre_run), &trace, || {
                calls += 1;
                assert!(!trace.exists());
                Ok(outcome(code, false))
            })
            .unwrap();
            assert_eq!(calls, usize::from(!pre_run));
            assert_eq!(recorded.is_some(), !pre_run);
            if pre_run {
                assert_eq!(fs::read(trace).unwrap(), b"previous recording");
            }
        }
    }

    #[test]
    fn native_harness_staging_uses_resolved_kind_and_name() {
        let metadata = serde_json::json!({"packages": [{"name": "pkg", "targets": [
            {"name": "app", "kind": ["lib"]},
            {"name": "lib_app", "kind": ["test"]}
        ]}]});
        let directory = |selector| {
            select_native_harness_target(&metadata, selector, None)
                .unwrap()
                .staging_directory(Path::new("target"), "pkg", "tests::case")
        };
        assert_eq!(directory("app"), directory("lib:app"));
        assert_eq!(directory("lib_app"), directory("test:lib_app"));
        assert_ne!(directory("lib:app"), directory("lib_app"));
        assert_eq!(
            directory("app"),
            Path::new("target/patina/dst/pkg/lib/app/tests__case")
        );
    }

    #[test]
    fn the_native_harness_re_emits_every_fault_knob_it_parsed() {
        // Native harness mode runs each seed as a child `run`, so a knob it
        // parsed but did not re-emit is silently inert — the shape the
        // hand-maintained forwarding list had for the Wave B fs knobs, and the
        // shape the historical `--dns-entry` bug had (advertised by the harness
        // family, never forwarded to its child `run`). Every registered knob,
        // repeatable ones included, must survive the round trip.
        let mut tokens: Vec<OsString> = Vec::new();
        for knob in FaultKnob::ALL {
            tokens.push(OsString::from(knob.meta().flag));
            tokens.push(OsString::from(knob_sample(*knob)));
        }
        // The realtime epoch is run configuration, not a fault knob, but the
        // child `run` drops it just as silently if it is not re-emitted.
        tokens.push(OsString::from("--realtime-epoch"));
        tokens.push(OsString::from("2001-09-09T01:46:40Z"));
        tokens.push(OsString::from("--hostname"));
        tokens.push(OsString::from("db-1"));
        tokens.extend([
            OsString::from("--compute-watchdog-ms"),
            OsString::from("5000"),
        ]);

        let args = cli::parse("test", help::Family::Harness, tokens).expect("harness parse");
        let invocation = NativeHarnessInvocation {
            origin: PathBuf::new(),
            manifest: PathBuf::new(),
            package: None,
            harness_target: "t".into(),
            exact: "m::t".into(),
            seeds: HarnessSeeds::One(0),
            release: false,
            features: HarnessFeatures::default(),
            instrumentation: GuestInstrumentation::None,
            step_budget: Some(9),
            realtime_epoch: args.string("--realtime-epoch"),
            hostname: args.string("--hostname"),
            knobs: knobs_of(&args).expect("harness knob parse"),
            buggify: None,
            schedule: NativeSchedule::default(),
            liveness: NativeLiveness {
                compute_watchdog_ms: args.string("--compute-watchdog-ms"),
                ..NativeLiveness::default()
            },
        };
        let mut emitted: Vec<OsString> = Vec::new();
        append_native_harness_run_flags(&mut emitted, &invocation);
        for knob in FaultKnob::ALL {
            let flag = knob.meta().flag;
            let value = knob_sample(*knob);
            let at = emitted
                .iter()
                .position(|token| token == flag)
                .unwrap_or_else(|| {
                    panic!("native harness dropped {flag} on the way to its child run")
                });
            assert_eq!(
                emitted.get(at + 1).map(OsString::as_os_str),
                Some(OsStr::new(value)),
                "native harness re-emitted {flag} without its value"
            );
        }
        assert!(emitted.iter().any(|token| token == "--budget"));
        for (flag, value) in [
            ("--realtime-epoch", "2001-09-09T01:46:40Z"),
            ("--hostname", "db-1"),
            ("--compute-watchdog-ms", "5000"),
        ] {
            let at = emitted
                .iter()
                .position(|token| token == flag)
                .unwrap_or_else(|| {
                    panic!("native harness dropped {flag} on the way to its child run")
                });
            assert_eq!(
                emitted.get(at + 1).map(OsString::as_os_str),
                Some(OsStr::new(value))
            );
        }
    }
}
