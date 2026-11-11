//! Build each selected libtest target once, shim-linked, and stage it where
//! every test of the target runs from.

use super::CargoFeatures;
use super::TestInvocation;
use super::select::{Program, Target, TargetKind};
use crate::CliError;
use crate::native_build::{
    NATIVE_AUDIT_METADATA_ARGS, host_target_triple, install_built_executable,
    native_package_link_args, native_package_rustflags, stage_sancov_stub, stage_sdk_stub,
};
use crate::native_run::admission;
use crate::shim_build::{
    RustcInvocation, ShimSources, apply_rustc_env, build_native_shim,
    check_native_toolchain_agreement, lock_target_dir, prepare_shim_sources,
    stage_instrumentation_object,
};
use patina_dst_trace::NativeAdmittedProgram;
use serde_json::Value;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The compiler every build of this invocation uses: resolved once, before
/// Cargo is asked anything.
pub(super) struct Toolchain {
    shim: ShimSources,
    pub(super) rustc: RustcInvocation,
}

pub(super) fn toolchain() -> Result<Toolchain, CliError> {
    let shim = prepare_shim_sources()?;
    let rustc = check_native_toolchain_agreement(&shim.dir)?;
    Ok(Toolchain { shim, rustc })
}

/// A target's staged guest, or why it has none.
pub(crate) struct BuiltTarget {
    pub(crate) target: Target,
    /// `Ok(guest)`, or the reason the build failed (Cargo's own diagnostics
    /// went to stderr as it ran).
    pub(crate) guest: Result<PathBuf, String>,
    /// The programs its runs may spawn: each of its package's binaries by
    /// the path `CARGO_BIN_EXE_*` names, its shim-linked build staged beside
    /// the guests, and `patina test`'s verdict on that build.
    pub(crate) admit: Vec<NativeAdmittedProgram>,
}

/// The directory a target's guest is staged in, and its recordings beside it:
/// `<target-dir>/patina/dst/<package>/<kind>/<target>`. Stable, so tooling
/// that wants a target's guest can find it (`--no-run` prints it).
pub(crate) fn staging_directory(target_dir: &Path, target: &Target) -> PathBuf {
    target_dir
        .join("patina/dst")
        .join(safe_path_segment(&target.package))
        .join(target.kind.name())
        .join(safe_path_segment(&target.name))
}

pub(crate) fn safe_path_segment(value: &str) -> String {
    let segment: String = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect();
    if segment.is_empty() || segment.chars().all(|ch| ch == '.') {
        "_".to_string()
    } else {
        segment
    }
}

/// Build every target, one `cargo rustc` each: the shim's link arguments
/// must reach the selected target's link alone ([`native_package_link_args`]),
/// and `cargo rustc` takes them for one target at a time. Every build carries
/// the same `RUSTFLAGS`, so dependencies compile once for all of them. A target
/// that fails to build is reported and the others still run.
///
/// The selected packages' binaries (`programs`) are built the same way, as
/// the programs their tests may spawn, and judged once here
/// ([`admission::judge`]); each test's runs are handed its package's
/// verdicts, keyed by the path Cargo installs each binary at, which is what
/// `CARGO_BIN_EXE_*` names. Cargo builds a package's binaries beside its
/// integration tests without the shim; the shim-linked build is a unit of
/// its own (the link arguments are part of its identity), so neither build
/// invalidates the other. Both are installed at the one path Cargo names, so
/// each is staged as soon as it is built.
pub(super) fn build_all(
    invocation: &TestInvocation,
    toolchain: &Toolchain,
    targets: &[Target],
    programs: &[Program],
    target_dir: &Path,
) -> Result<Vec<BuiltTarget>, CliError> {
    let rustc = &toolchain.rustc;
    let built_shim = build_native_shim(invocation.release, rustc, &toolchain.shim)?;
    let host_target = host_target_triple(rustc)?;
    let yield_object =
        stage_instrumentation_object(&built_shim, invocation.instrument, &host_target)?;
    let sancov_stub = stage_sancov_stub(&built_shim, yield_object.is_some(), &host_target)?;
    // Building an integration test builds the package's binaries beside it,
    // without the shim; the stand-ins let one that calls the SDK link. Every
    // build carries them, so the flags, and with them the dependencies'
    // builds, are the same for every target.
    let sdk_stub = stage_sdk_stub(&built_shim, &host_target)?;
    let rustflags = native_package_rustflags(sancov_stub.as_deref(), Some(&sdk_stub), &host_target);
    let link_args = native_package_link_args(
        &built_shim.facade,
        &built_shim.engine,
        &built_shim.allocator_link_args(&host_target)?,
        yield_object.as_deref(),
    );
    let cargo_rustc =
        |package: &str, selection: Vec<String>, features: &CargoFeatures, profile: &str| {
            let mut command = Command::new(&rustc.cargo_command);
            command
                .arg("rustc")
                .arg("--manifest-path")
                .arg(&invocation.manifest)
                .arg("--package")
                .arg(package)
                .arg("--target")
                .arg(&host_target)
                .arg("--message-format=json-render-diagnostics")
                .env_remove("RUSTFLAGS")
                .env("CARGO_ENCODED_RUSTFLAGS", &rustflags)
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit());
            apply_rustc_env(&mut command, rustc);
            command.args(selection);
            command.args(features.cargo_args());
            // Cargo's progress lines are detail; its errors and warnings still print.
            if !crate::output::options().verbose {
                command.arg("--quiet");
            }
            command
                .arg("--profile")
                .arg(profile)
                .arg("--")
                .args(&link_args)
                .args(NATIVE_AUDIT_METADATA_ARGS);
            command
        };
    // Each package's programs, by the path Cargo installs each at, and
    // `patina test`'s verdict on it. Every test of the package is handed
    // these; a binary that did not build or stage is refused, and says why.
    let mut judged: Vec<(&str, NativeAdmittedProgram)> = Vec::with_capacity(programs.len());
    for Program { package, bin } in programs {
        // `cargo rustc` builds a binary in test mode under `test` or
        // `bench`, so it is built under the profiles those inherit. Cargo
        // builds the one beside an integration test under `test` or `bench`
        // itself: the two differ only where a package overrides
        // `[profile.test]` or `[profile.bench]`.
        let profile = if invocation.release { "release" } else { "dev" };
        let mut command = cargo_rustc(
            package,
            vec!["--bin".to_string(), bin.clone()],
            &invocation.features,
            profile,
        );
        let output = {
            let _lock = lock_target_dir(target_dir)?;
            command.output().map_err(|error| {
                CliError(format!(
                    "failed to run cargo rustc for {package} --bin {bin}: {error}"
                ))
            })?
        };
        // Where Cargo installs it, and so what the tests name it by.
        let named = target_dir
            .join(&host_target)
            .join(if invocation.release {
                "release"
            } else {
                "debug"
            })
            .join(bin);
        let staged = crate::sdk_version::check_guest_sdk(&output.stdout)
            .map_err(|error| error.to_string())
            .and_then(|()| {
                if output.status.success() {
                    stage_program(target_dir, package, bin, &named, &output.stdout)
                        .map_err(|error| error.to_string())
                } else {
                    Err(format!(
                        "{package} --bin {bin} did not build with the shim (Cargo's errors \
                         were printed by `patina test`)"
                    ))
                }
            });
        judged.push((
            package.as_str(),
            admission::judge(named.to_string_lossy().into_owned(), staged),
        ));
    }
    // Two selected packages that install a binary at one path: neither's
    // tests can know which they would spawn, so both are refused.
    for index in 0..judged.len() {
        let program = &judged[index].1.program;
        if judged
            .iter()
            .filter(|(_, other)| other.program == *program)
            .count()
            > 1
        {
            judged[index].1.refused = Some(format!(
                "more than one selected package installs a binary at {program}"
            ));
        }
    }
    let mut admit: BTreeMap<&str, Vec<NativeAdmittedProgram>> = BTreeMap::new();
    for (package, program) in judged {
        admit.entry(package).or_default().push(program);
    }
    let mut built = Vec::with_capacity(targets.len());
    for target in targets {
        // `cargo rustc` builds a target in test mode only under the `test` or
        // `bench` profile, and refuses `--release` beside `--profile`. `bench`
        // inherits `release`, so `--release` means the codegen a
        // `cargo test --release` harness gets, the package's
        // `[profile.release]` overrides included.
        let mut command = cargo_rustc(
            &target.package,
            target.cargo_args(),
            &invocation.features,
            if invocation.release { "bench" } else { "test" },
        );
        let output = {
            let _lock = lock_target_dir(target_dir)?;
            command.output().map_err(|error| {
                CliError(format!(
                    "failed to run cargo rustc for {}: {error}",
                    target.label()
                ))
            })?
        };
        crate::sdk_version::check_guest_sdk(&output.stdout)?;
        let guest = if output.status.success() {
            stage(target_dir, target, &output.stdout).map_err(|error| error.to_string())
        } else {
            Err(format!(
                "building {} failed (Cargo's errors are above)",
                target.label()
            ))
        };
        built.push(BuiltTarget {
            target: target.clone(),
            guest,
            admit: admit
                .get(target.package.as_str())
                .cloned()
                .unwrap_or_default(),
        });
    }
    Ok(built)
}

/// Copy the target's test executable, as Cargo reported it, to its staging
/// directory: through a rename, so a test still running from the previous
/// build keeps its own bytes.
fn stage(target_dir: &Path, target: &Target, messages: &[u8]) -> Result<PathBuf, CliError> {
    let executable = test_executable(messages, target)?;
    let directory = staging_directory(target_dir, target);
    fs::create_dir_all(&directory).map_err(|error| {
        CliError(format!(
            "failed to create the staging directory {}: {error}",
            directory.display()
        ))
    })?;
    let guest = directory.join("guest");
    install_built_executable(&executable, &guest)?;
    Ok(guest)
}

/// Stage the binary `bin` of `package` Cargo just built, which it installed
/// at `named`: copied to `<target-dir>/patina/dst/<package>/programs/<bin>`.
fn stage_program(
    target_dir: &Path,
    package: &str,
    bin: &str,
    named: &Path,
    messages: &[u8],
) -> Result<PathBuf, CliError> {
    let executable = messages
        .split(|byte| *byte == b'\n')
        .filter_map(|line| serde_json::from_slice::<Value>(line).ok())
        .find(|message| {
            message.get("reason").and_then(Value::as_str) == Some("compiler-artifact")
                && message.pointer("/profile/test").and_then(Value::as_bool) == Some(false)
                && message.pointer("/target/name").and_then(Value::as_str) == Some(bin)
                && message.pointer("/target/kind") == Some(&serde_json::json!(["bin"]))
        })
        .and_then(|message| message.get("executable")?.as_str().map(PathBuf::from))
        .ok_or_else(|| {
            CliError(format!(
                "cargo rustc reported no executable for {package} --bin {bin}"
            ))
        })?;
    if executable != named {
        return Err(CliError(format!(
            "Cargo installed {package} --bin {bin} at {}, not at {}",
            executable.display(),
            named.display()
        )));
    }
    let directory = target_dir
        .join("patina/dst")
        .join(safe_path_segment(package))
        .join("programs");
    fs::create_dir_all(&directory).map_err(|error| {
        CliError(format!(
            "failed to create the staging directory {}: {error}",
            directory.display()
        ))
    })?;
    let staged = directory.join(safe_path_segment(bin));
    install_built_executable(&executable, &staged)?;
    Ok(staged)
}

/// The test-profile executable Cargo reported for `target`.
fn test_executable(messages: &[u8], target: &Target) -> Result<PathBuf, CliError> {
    let mut found = Vec::new();
    for line in messages.split(|byte| *byte == b'\n') {
        let Ok(message) = serde_json::from_slice::<Value>(line) else {
            continue;
        };
        if message.get("reason").and_then(Value::as_str) != Some("compiler-artifact")
            || message.pointer("/profile/test").and_then(Value::as_bool) != Some(true)
            || message.pointer("/target/name").and_then(Value::as_str) != Some(&target.name)
        {
            continue;
        }
        let kinds: Vec<&str> = message
            .pointer("/target/kind")
            .and_then(Value::as_array)
            .map(|kinds| kinds.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let kind_matches = match target.kind {
            TargetKind::Test => kinds == ["test"],
            TargetKind::Bin => kinds == ["bin"],
            TargetKind::Lib => kinds != ["test"] && kinds != ["bin"],
        };
        if let Some(executable) = message.get("executable").and_then(Value::as_str)
            && kind_matches
        {
            found.push(PathBuf::from(executable));
        }
    }
    match found.len() {
        1 => Ok(found.remove(0)),
        0 => Err(CliError(format!(
            "cargo rustc reported no test executable for {}",
            target.label()
        ))),
        _ => Err(CliError(format!(
            "cargo rustc reported several test executables for {}",
            target.label()
        ))),
    }
}

/// The arguments a rerun command gives to rebuild exactly as this invocation
/// did.
pub(super) fn build_args(invocation: &TestInvocation) -> Vec<OsString> {
    let mut args: Vec<OsString> = Vec::new();
    if invocation.release {
        args.push("--release".into());
    }
    if !invocation.instrument {
        args.push("--no-instrument".into());
    }
    args.extend(
        invocation
            .features
            .cargo_args()
            .into_iter()
            .map(OsString::from),
    );
    args
}
