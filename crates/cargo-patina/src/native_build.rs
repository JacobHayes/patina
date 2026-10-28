//! Native artifact resolution, guest builds, instrumentation, and fingerprints.

use crate::harness::{cargo_metadata, metadata_target_dir};
use crate::native_run::target_has_sud;
use crate::shim_build::{
    BuiltNativeShim, PATINA_GO_METER_OBJECT, PATINA_SANCOV_STUB_OBJECT, RustcInvocation,
    apply_rustc_env, build_native_shim, check_native_toolchain_agreement, link_arg,
    lock_target_dir, prepare_shim_sources, stage_instrumentation_object, stage_shim_object,
};
use crate::wasi_exec::run_wasi_build;
use crate::{
    ArtifactRef, BuildSpec, BuildSpecKind, CliError, NativeBuildInvocation, NativeBuildTarget,
    NativeSchedule, hex, output,
};
use patina_dst_trace::TraceBundle;
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::{env, fs, io};

/// Build-time deterministic-preemption hook, linked only under `--yield-points`.
pub(super) const PATINA_YIELD_C: &str = include_str!("../c/patina_yield.c");
/// Edge-coverage instrumentation with optional SAMPLED preemption, linked only
/// under `--coverage-points[=<STRIDE>]` and mutually exclusive with
/// `PATINA_YIELD_C` (they define the same SanitizerCoverage entry points).
pub(super) const PATINA_COV_C: &str = include_str!("../c/patina_cov.c");
/// A Go guest's compute meter: the libFuzzer comparison hooks its
/// instrumentation calls, linked only by `cargo patina build --go`.
pub(super) const PATINA_GO_METER_C: &str = include_str!("../c/patina_go_meter.c");
/// Weak, inert SanitizerCoverage entry points so an instrumented artifact that
/// links on its own — a dependency's unused `cdylib` — resolves them. Linked only
/// under `--yield-points`/`--coverage-points`, alongside (and overridden by)
/// `PATINA_YIELD_C`/`PATINA_COV_C`.
pub(super) const PATINA_SANCOV_STUB_C: &str = include_str!("../c/patina_sancov_stub.c");
/// Marker string the `--yield-points` hook embeds; `native-run` looks for it in
/// the binary to fold yield-point scheduling into the compatibility fingerprint.
/// Unchanged, so a binary built before `--coverage-points` existed classifies and
/// fingerprints exactly as it always did.
const PATINA_YIELD_MARKER: &[u8] = b"PATINA_YIELD_POINTS_V1";
/// Marker PREFIX the `--coverage-points` hook embeds, immediately followed by the
/// baked-in sampling stride in decimal and a `;`. `native-run` recovers the
/// stride from the binary's bytes — there is no flag to re-pass — and folds it
/// into the compatibility fingerprint, so two strides never cross-replay.
const PATINA_COV_MARKER_PREFIX: &[u8] = b"PATINA_COVERAGE_POINTS_V1 stride=";
/// Fingerprint suffix distinguishing a yield-point binary's schedule policy from
/// a plain one, so their recorded traces never cross-replay.
const PATINA_YIELD_FINGERPRINT_SUFFIX: &str = "+yieldpoints";
/// Fingerprint suffix stem for a `--coverage-points` binary. The stride is
/// appended (`+covpoints:0`, `+covpoints:1024`) so the sampling rate — which is
/// part of the schedule policy — is part of the compatibility fingerprint.
const PATINA_COV_FINGERPRINT_SUFFIX: &str = "+covpoints";
/// How a native build instruments the guest, and therefore which schedule policy
/// its recorded traces belong to.
///
/// Edge coverage and scheduler preemption are two different needs that shared one
/// flag until `--coverage-points` split them. `--yield-points` buys both at once
/// and pays a scheduler round trip per basic block; `--coverage-points` buys the
/// counters alone, and `--coverage-points=N` adds preemption back at a chosen,
/// bounded rate. Every variant is a pure function of the build flags and is
/// recoverable from the built binary's own bytes ([`binary_instrumentation`]), so
/// `run`/`replay` never need the flag re-passed and a cross-mode replay fails
/// closed on the fingerprint.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) enum GuestInstrumentation {
    /// A plain build: no SanitizerCoverage, no edge counters, and preemption only
    /// at the boundaries Patina interposes.
    #[default]
    None,
    /// `--yield-points`: edge counters AND a scheduling point at every
    /// instrumented basic block.
    YieldPoints,
    /// `--coverage-points[=STRIDE]`: edge counters at every instrumented basic
    /// block, plus a scheduling point every `stride` blocks a thread executes.
    /// `stride == 0` is counters only — the guest keeps exactly the preemption
    /// boundaries a plain build has.
    CoveragePoints { stride: u32 },
}

impl GuestInstrumentation {
    /// Whether the guest carries SanitizerCoverage edge counters, i.e. whether
    /// `--coverage-out` and `campaign --guided` have anything to read.
    pub(super) fn has_coverage(self) -> bool {
        !matches!(self, GuestInstrumentation::None)
    }

    /// Whether EVERY basic block is a scheduling boundary. This is what makes
    /// `--starve` liveness-safe against a guest holding an invisible atomic
    /// spinlock: only a boundary inside that spin loop lets aging force the
    /// starved holder to run. A sampled stride bounds the blocks between
    /// boundaries by `stride`, which is the same guarantee at 1/stride the cost,
    /// so it counts too; counters-only does not.
    pub(super) fn preempts_inside_atomics(self) -> bool {
        match self {
            GuestInstrumentation::None => false,
            GuestInstrumentation::YieldPoints => true,
            GuestInstrumentation::CoveragePoints { stride } => stride > 0,
        }
    }

    /// The compatibility-fingerprint suffix for this instrumentation. A plain
    /// build contributes nothing, so its fingerprint is byte-for-byte what it was
    /// before any of this existed.
    pub(super) fn fingerprint_suffix(self) -> String {
        match self {
            GuestInstrumentation::None => String::new(),
            GuestInstrumentation::YieldPoints => PATINA_YIELD_FINGERPRINT_SUFFIX.to_string(),
            GuestInstrumentation::CoveragePoints { stride } => {
                format!("{PATINA_COV_FINGERPRINT_SUFFIX}:{stride}")
            }
        }
    }

    /// A single whitespace-free tag naming the mode AND its parameter, for the
    /// machine-readable build note. Keeping the stride in the tag means a log
    /// line records exactly which policy a binary was built under.
    pub(super) fn mode_tag(self) -> String {
        match self {
            GuestInstrumentation::None => "none".to_string(),
            GuestInstrumentation::YieldPoints => "yield-points".to_string(),
            GuestInstrumentation::CoveragePoints { stride } => {
                format!("coverage-points:{stride}")
            }
        }
    }

    /// A one-line human description for the build note and for diagnostics.
    pub(super) fn describe(self) -> String {
        match self {
            GuestInstrumentation::None => "none".to_string(),
            GuestInstrumentation::YieldPoints => "yield-points (every basic block)".to_string(),
            GuestInstrumentation::CoveragePoints { stride: 0 } => {
                "coverage-points (edge counters only; no added scheduling points)".to_string()
            }
            GuestInstrumentation::CoveragePoints { stride } => format!(
                "coverage-points (edge counters; a scheduling point every {stride} basic blocks per thread)"
            ),
        }
    }
}
pub(super) const DEFAULT_NATIVE_EDITION: &str = "2024";

/// A resolved run/audit/replay artifact: the concrete path to consume, a display
/// path (the source argument when built on the fly, so a WASI guest's `argv[0]`
/// and diagnostics name the source rather than a throwaway temp path), and an
/// optional workspace that must outlive its use.
pub(super) struct ResolvedArtifact {
    pub(super) path: PathBuf,
    pub(super) display: PathBuf,
    _workspace: Option<tempfile::TempDir>,
}

/// The single shared resolution step: an already-built artifact is used
/// directly; a source/package is built on the fly through the shared build
/// pipeline (printing a one-line identity note) and its product used.
pub(super) fn resolve_artifact(artifact: ArtifactRef) -> Result<ResolvedArtifact, CliError> {
    match artifact {
        ArtifactRef::Prebuilt(path) => Ok(ResolvedArtifact {
            display: path.clone(),
            path,
            _workspace: None,
        }),
        ArtifactRef::Build(spec) => build_on_the_fly(*spec),
    }
}

/// Build a source/package on the fly and return its artifact. Prints a one-line
/// identity note (`PATINA_BUILD_ON_RUN`) naming the source, the built artifact,
/// and its content hash, so an implicit rebuild never silently changes what ran.
fn build_on_the_fly(spec: BuildSpec) -> Result<ResolvedArtifact, CliError> {
    let workspace = tempfile::tempdir()
        .map_err(|error| CliError(format!("failed to create build workspace: {error}")))?;
    let (path, target_label) = match spec.kind {
        BuildSpecKind::Native(mut invocation) => {
            invocation.output = Some(workspace.path().join("patina-run-artifact"));
            (run_native_build(invocation)?, "native")
        }
        BuildSpecKind::Wasi(invocation) => {
            let output = workspace.path().join("patina-run-artifact.wasm");
            (run_wasi_build(&invocation, Some(&output))?, "wasi")
        }
    };
    let bytes = fs::read(&path).map_err(|error| {
        CliError(format!(
            "failed to read the built artifact {}: {error}",
            path.display()
        ))
    })?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    // Route this on-the-fly build note to stderr under `--output json` so stdout
    // stays a single clean JSON envelope; human output keeps it on stdout.
    let build_note = format!(
        "PATINA_BUILD_ON_RUN target={target_label} source={} artifact={} sha256={}",
        spec.origin.display(),
        path.display(),
        hex(&hasher.finalize())
    );
    if output::options().is_json() {
        eprintln!("{build_note}");
    } else {
        println!("{build_note}");
    }
    Ok(ResolvedArtifact {
        path,
        display: spec.origin,
        _workspace: Some(workspace),
    })
}

/// The `build` (native) verb: build and report the artifact path.
pub(super) fn execute_native_build(invocation: NativeBuildInvocation) -> Result<i32, CliError> {
    let path = run_native_build(invocation)?;
    if output::options().is_json() {
        output::emit_build("native", &path);
    } else {
        println!("PATINA_NATIVE_BUILD output={}", path.display());
    }
    Ok(0)
}

/// Run the native build pipeline and return the produced artifact path. Shared
/// by the `build` verb and build-on-the-fly (`run`/`audit`/`replay` of a
/// source): both go through exactly this code.
fn run_native_build(invocation: NativeBuildInvocation) -> Result<PathBuf, CliError> {
    if let Some(output) = &invocation.output {
        create_output_parent(output)?;
    }
    let shim = prepare_shim_sources()?;
    let rustc = check_native_toolchain_agreement(&shim.dir)?;
    let built_shim = build_native_shim(
        invocation.release,
        &rustc,
        &shim,
        invocation.instrumentation,
    )?;
    let host_target = host_target_triple(&rustc)?;

    // Stable immutable paths keep Cargo's link fingerprints warm. The owning
    // handle pins every input through compilation and the guest's final link.
    let object = built_shim.facade.clone();
    // The SanitizerCoverage hook object is compiled and linked only under
    // `--yield-points`/`--coverage-points`; a plain build never references
    // SanitizerCoverage symbols.
    let yield_object =
        stage_instrumentation_object(&built_shim, invocation.instrumentation, &host_target)?;
    let allocator = built_shim.allocator_link_args(&host_target)?;

    match invocation.target {
        NativeBuildTarget::Source {
            source,
            edition,
            rustc_args,
        } => build_native_source(
            &source,
            invocation
                .output
                .as_deref()
                .expect("single-source native-build requires --output"),
            &edition,
            invocation.release,
            &object,
            &built_shim,
            &allocator,
            yield_object.as_deref(),
            &rustc_args,
            &rustc,
        ),
        NativeBuildTarget::Package {
            manifest,
            package,
            bin,
        } => build_native_package(
            &manifest,
            package.as_deref(),
            bin.as_deref(),
            invocation.output.as_deref(),
            invocation.release,
            &host_target,
            &object,
            &built_shim,
            &allocator,
            yield_object.as_deref(),
            &rustc,
        ),
        NativeBuildTarget::Go {
            package_dir,
            go_args,
        } => crate::go_build::build_go_package(
            &package_dir,
            invocation
                .output
                .as_deref()
                .expect("a Go native-build requires --output"),
            &object,
            &stage_shim_object(
                &built_shim.objects,
                &PATINA_GO_METER_OBJECT,
                &host_target,
                &[],
            )?,
            &built_shim,
            &built_shim.allocator_linker_args(&host_target)?,
            &go_args,
        ),
    }
}

/// The rustc flags that turn on LLVM SanitizerCoverage trace-pc-guard
/// instrumentation at basic-block granularity (level 3 reaches loop backedges),
/// so `__sanitizer_cov_trace_pc_guard` — routed to `patina_yield_point` by the
/// linked hook — fires inside hot loops, not only at function entry. `-Cpasses`
/// and `-Cllvm-args` are stable rustc codegen flags, so this needs no nightly
/// toolchain and no `RUSTC_BOOTSTRAP`. The only version coupling is to LLVM's
/// internal pass name (`sancov-module`) and coverage cl::opts, which are stable
/// across the LLVM releases rustc ships but are not a rustc stability guarantee.
fn sancov_rustc_flags() -> [&'static str; 8] {
    [
        "-C",
        "passes=sancov-module",
        "-C",
        "llvm-args=-sanitizer-coverage-level=3",
        "-C",
        "llvm-args=-sanitizer-coverage-trace-pc-guard",
        "-C",
        "llvm-args=-sanitizer-coverage-pc-table",
    ]
}

/// The platform-specific shim arguments a native binary's link needs, as
/// compiler-driver arguments. On Linux the shim interposes thread creation with a plain strong
/// `pthread_create` def and reaches the real glibc creator through its host-alias
/// table (`dlsym(RTLD_NEXT, ...)`), so no link-time wrap is needed — and none is
/// used: gcc ships its own `__wrap_pthread_create` in libgcc's x86 split-stack
/// support, so `-Wl,--wrap=pthread_create` would `multiple definition`-clash at
/// link. macOS uses `pthread_create_suspended_np`. The shim objects also land
/// after the toolchain's own `-lc`, and glibc's `atexit` lives in
/// `libc_nonshared.a` (reached through the `libc.so` linker script); GNU ld scans
/// archives in a single pass, so libc must be scanned again after the shim
/// objects introduce their references.
///
/// Linux wraps `dlsym` so the shim's host-alias table can reach the real glibc
/// resolver through `__real_dlsym` while guest/std references to `dlsym`
/// still bind to the shim's `__wrap_dlsym` interposer (which resolves only
/// its deterministic entropy routing table — never a host symbol). This is
/// the Linux half of the host-alias doctrine: `dlsym(RTLD_NEXT, ...)`
/// resolves the trace-fd I/O, baton-semaphore, and host-thread-creation
/// vehicles at runtime, so `__read`/`__write`/`sem_*`/`pthread_create` no
/// longer appear in the guest import table.
pub(super) const PLATFORM_LINKER_ARGS: &[&str] = if cfg!(target_os = "linux") {
    &["-Wl,--wrap=dlsym", "-lc"]
} else {
    &[]
};

/// [`PLATFORM_LINKER_ARGS`] as rustc `-C` values.
fn platform_link_args() -> impl Iterator<Item = OsString> {
    PLATFORM_LINKER_ARGS
        .iter()
        .map(|arg| OsString::from(format!("link-arg={arg}")))
}

// Audit and execute the same symbol-bearing artifact. Cargo does not expose a
// separate pre-strip executable; preserve its boundaries at the final link,
// after profile/user strip settings, without changing dependency codegen.
pub(super) const NATIVE_AUDIT_METADATA_ARGS: [&str; 2] = ["-C", "strip=none"];

/// Compile a single Rust source, injecting cfg(patina)/cfg(dst) and linking the
/// POSIX object and shim staticlib below it. Built native for the host, so the
/// host OS selects the link recipe.
#[allow(clippy::too_many_arguments)]
fn build_native_source(
    source: &Path,
    output: &Path,
    edition: &str,
    release: bool,
    object: &Path,
    shim: &BuiltNativeShim,
    allocator: &[OsString],
    yield_object: Option<&Path>,
    rustc_args: &[OsString],
    rustc: &RustcInvocation,
) -> Result<PathBuf, CliError> {
    let engine = &shim.engine;
    let mut command = Command::new(&rustc.command);
    shim.inherit(&mut command)?;
    command
        .arg("--edition")
        .arg(edition)
        // `patina_shim` marks a shim-linked build: the `patina` crate's SDK
        // resolves its buggify FFI only under this cfg, so a plain/WASI/`run`
        // build (which also sets `patina`/`dst`) never references the shim
        // symbols and never fails to link.
        .args(["--cfg", "patina", "--cfg", "dst", "--cfg", "patina_shim"])
        .arg("-C")
        .arg(link_arg(object))
        .arg("-C")
        .arg(link_arg(engine));
    if let Some(yield_object) = yield_object {
        // SanitizerCoverage is driven entirely through stable `-C` codegen flags
        // (no `RUSTC_BOOTSTRAP`); the hook object below resolves the emitted
        // callbacks.
        command
            .args(sancov_rustc_flags())
            .arg("-C")
            .arg(link_arg(yield_object));
    }
    // Route the runtime's own Rust allocations to its arena, off the guest's
    // heap (`allocator_routing.rs`); empty where the platform routes nothing.
    for arg in allocator {
        command.arg("-C").arg(arg);
    }
    for arg in platform_link_args() {
        command.arg("-C").arg(arg);
    }
    if release {
        // Match cargo's `release` profile so a single-source guest behaves
        // identically to a package guest under `--release`: optimize, and compile
        // out `debug_assert!`/overflow checks (which turns those free failure
        // oracles into no-ops — see the debug-vs-release note). These are stable
        // `-C` codegen flags, so no nightly/`RUSTC_BOOTSTRAP`, and they compose
        // with the sancov yield-point flags above. Emitted before `rustc_args` so
        // an explicit trailing `-C opt-level=…` from the user still wins (rustc
        // takes the last value for a repeated `-C` option).
        command.args([
            "-C",
            "opt-level=3",
            "-C",
            "debug-assertions=off",
            "-C",
            "overflow-checks=off",
        ]);
    }
    // Link under one fixed name, then copy to `output`. The linker writes the
    // output's file name into the executable (the macOS ad-hoc code signature's
    // identifier and the image UUID), so linking straight to `output` would make
    // two builds of the same source differ by what they were called — and the
    // executable digest is the build identity a native trace replays against.
    let link_dir = tempfile::tempdir()
        .map_err(|error| CliError(format!("failed to create a link directory: {error}")))?;
    let linked = link_dir.path().join(SINGLE_SOURCE_LINK_NAME);
    command
        .arg(source)
        .arg("-o")
        .arg(&linked)
        .args(rustc_args)
        .args(NATIVE_AUDIT_METADATA_ARGS);
    let status = command
        .status()
        .map_err(|error| CliError(format!("failed to run rustc {:?}: {error}", rustc.command)))?;
    if !status.success() {
        return Err(CliError("linking the native Patina program failed".into()));
    }
    install_built_executable(&linked, output)?;
    Ok(output.to_path_buf())
}

/// The file name every single-source native guest is linked under.
const SINGLE_SOURCE_LINK_NAME: &str = "patina-guest";

/// Copy a freshly linked executable to `output` through a sibling file and a
/// rename, so a running copy of the previous build is replaced rather than
/// rewritten in place.
pub(super) fn install_built_executable(linked: &Path, output: &Path) -> Result<(), CliError> {
    let name = output.file_name().ok_or_else(|| {
        CliError(format!(
            "native build output {} has no file name",
            output.display()
        ))
    })?;
    let mut partial_name = OsString::from(".");
    partial_name.push(name);
    partial_name.push(".partial");
    let partial = output.with_file_name(partial_name);
    fs::copy(linked, &partial).map_err(|error| {
        CliError(format!(
            "failed to copy the linked program to {}: {error}",
            partial.display()
        ))
    })?;
    fs::rename(&partial, output).map_err(|error| {
        let _ = fs::remove_file(&partial);
        CliError(format!(
            "failed to install the linked program at {}: {error}",
            output.display()
        ))
    })
}

/// Drive a Cargo package's own build under Patina control, as `cargo rustc` so
/// the two injections land at their correct scopes. The cfg flags travel in
/// `CARGO_ENCODED_RUSTFLAGS` and reach every crate compiled from source, which
/// `cfg(patina)`-gated dependency code needs; the shim's link arguments travel
/// as `cargo rustc`'s trailing arguments and reach only the selected binary's
/// final link, never an intermediate dependency artifact
/// ([`native_package_link_args`] has the failure this prevents). The explicit
/// host `--target` additionally keeps the cfgs off build scripts and proc
/// macros, which Cargo compiles for the host without these flags.
#[allow(clippy::too_many_arguments)]
fn build_native_package(
    manifest: &Path,
    package: Option<&str>,
    bin: Option<&str>,
    output: Option<&Path>,
    release: bool,
    host_target: &str,
    object: &Path,
    shim: &BuiltNativeShim,
    allocator: &[OsString],
    yield_object: Option<&Path>,
    rustc: &RustcInvocation,
) -> Result<PathBuf, CliError> {
    if !manifest.is_file() {
        return Err(CliError(format!(
            "no Cargo manifest at {}",
            manifest.display()
        )));
    }
    let selected = select_native_package_bin(manifest, package, bin, Some(rustc))?;
    let sancov_stub = stage_sancov_stub(shim, yield_object.is_some(), host_target)?;
    let rustflags = native_package_rustflags(sancov_stub.as_deref(), host_target);

    let mut command = Command::new(&rustc.cargo_command);
    command
        .arg("rustc")
        .arg("--manifest-path")
        .arg(manifest)
        .arg("--package")
        .arg(&selected.package)
        .arg("--bin")
        .arg(&selected.bin)
        .arg("--target")
        .arg(host_target)
        .arg("--message-format=json-render-diagnostics")
        .env_remove("RUSTFLAGS")
        .env("CARGO_ENCODED_RUSTFLAGS", rustflags)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    apply_rustc_env(&mut command, rustc);
    // The SanitizerCoverage flags carried in the encoded rustflags are stable
    // `-C` codegen options, so no `RUSTC_BOOTSTRAP` is needed. They apply to every
    // crate Cargo compiles from source in this invocation (guest + its
    // path/registry deps); the precompiled std is untouched, so only guest code
    // gains yield points.
    if release {
        command.arg("--release");
    }
    command
        .arg("--")
        .args(native_package_link_args(
            object,
            &shim.engine,
            allocator,
            yield_object,
        ))
        .args(NATIVE_AUDIT_METADATA_ARGS);
    let _lock = lock_target_dir(&selected.target_dir)?;
    shim.inherit(&mut command)?;
    let built = command
        .output()
        .map_err(|error| CliError(format!("failed to run cargo rustc: {error}")))?;
    if !built.status.success() {
        return Err(CliError(format!(
            "building the native Patina package {:?} failed",
            selected.bin
        )));
    }
    let executable = native_build_executable(&built.stdout, &selected.bin)?;
    let final_path = if let Some(destination) = output {
        fs::copy(&executable, destination).map_err(|error| {
            CliError(format!(
                "failed to copy built binary {} to {}: {error}",
                executable.display(),
                destination.display()
            ))
        })?;
        destination.to_path_buf()
    } else {
        executable
    };
    Ok(final_path)
}

/// The package and binary a package `native-build` resolves to, and the
/// target dir Cargo builds it in.
pub(super) struct SelectedNativeBin {
    pub(super) package: String,
    pub(super) bin: String,
    pub(super) target_dir: PathBuf,
}

/// Resolve which package and which binary target `native-build` should compile,
/// failing closed on ambiguity rather than guessing. `cargo metadata` enumerates
/// the workspace members and their targets without touching the network for a
/// path-only graph.
pub(super) fn select_native_package_bin(
    manifest: &Path,
    package: Option<&str>,
    bin: Option<&str>,
    rustc: Option<&RustcInvocation>,
) -> Result<SelectedNativeBin, CliError> {
    let metadata = cargo_metadata(manifest, rustc)?;
    let packages = metadata
        .get("packages")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| CliError("cargo metadata reported no packages".into()))?;

    let selected = if let Some(name) = package {
        packages
            .iter()
            .find(|entry| entry.get("name").and_then(serde_json::Value::as_str) == Some(name))
            .ok_or_else(|| {
                CliError(format!(
                    "package {name:?} is not a member of {}",
                    manifest.display()
                ))
            })?
    } else {
        // With no --package, select the package defined by exactly this manifest
        // so a member of a larger workspace resolves unambiguously.
        let wanted = fs::canonicalize(manifest).unwrap_or_else(|_| manifest.to_path_buf());
        let mut matches = packages.iter().filter(|entry| {
            entry
                .get("manifest_path")
                .and_then(serde_json::Value::as_str)
                .map(|path| fs::canonicalize(path).unwrap_or_else(|_| PathBuf::from(path)))
                == Some(wanted.clone())
        });
        matches.next().ok_or_else(|| {
            CliError(format!(
                "{} defines no package (a virtual workspace); select a member with --package",
                manifest.display()
            ))
        })?
    };

    let package_name = selected
        .get("name")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| CliError("cargo metadata package has no name".into()))?
        .to_string();
    let mut binaries = selected
        .get("targets")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter(|target| {
            target
                .get("kind")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
                .any(|kind| kind.as_str() == Some("bin"))
        })
        .filter_map(|target| {
            target
                .get("name")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .collect::<Vec<_>>();
    binaries.sort();

    let chosen = if let Some(name) = bin {
        if !binaries.iter().any(|candidate| candidate == name) {
            return Err(CliError(format!(
                "package {package_name:?} has no binary target {name:?}; available: {}",
                binaries.join(", ")
            )));
        }
        name.to_string()
    } else {
        match binaries.as_slice() {
            [single] => single.clone(),
            [] => {
                return Err(CliError(format!(
                    "package {package_name:?} has no binary targets to build"
                )));
            }
            multiple => {
                return Err(CliError(format!(
                    "package {package_name:?} has multiple binary targets ({}); select one with --bin",
                    multiple.join(", ")
                )));
            }
        }
    };
    Ok(SelectedNativeBin {
        package: package_name,
        bin: chosen,
        target_dir: metadata_target_dir(&metadata)?,
    })
}

/// Create the directory a build's `--output` names, as `--record` does for a
/// trace, so the build can put its artifact there.
pub(super) fn create_output_parent(output: &Path) -> Result<(), CliError> {
    match output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        Some(parent) => fs::create_dir_all(parent).map_err(|error| {
            CliError(format!(
                "failed to create output directory {}: {error}",
                parent.display()
            ))
        }),
        None => Ok(()),
    }
}

/// Locate the executable Cargo emitted for `bin` from its JSON build output.
pub(super) fn native_build_executable(stdout: &[u8], bin: &str) -> Result<PathBuf, CliError> {
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
        let is_target_bin = message.get("target").is_some_and(|target| {
            target.get("name").and_then(serde_json::Value::as_str) == Some(bin)
        });
        if is_target_bin {
            return Ok(PathBuf::from(executable));
        }
    }
    Err(CliError(format!(
        "cargo build did not report an executable artifact for binary {bin:?}"
    )))
}

/// Read the verified guest identity's host target so no later probe re-enters
/// directory-scoped resolution; package link arguments stay host-only.
pub(super) fn host_target_triple(rustc: &RustcInvocation) -> Result<String, CliError> {
    rustc
        .identity
        .verbose
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .map(str::to_owned)
        .ok_or_else(|| CliError("rustc -vV did not report a host target triple".into()))
}

/// Build the `CARGO_ENCODED_RUSTFLAGS` value for a package build: the
/// cfg(patina)/cfg(dst) family plus, under `--yield-points`, the
/// SanitizerCoverage codegen flags. Encoded with the `0x1f` unit separator so values containing
/// spaces survive intact. Any pre-existing `RUSTFLAGS` are preserved ahead of
/// the injected flags, matching how `cargo patina run` layers its cfgs onto the
/// user's flags.
///
/// Everything here is deliberately whole-graph: Cargo forwards `RUSTFLAGS` to
/// every crate it compiles from source in the invocation, which is exactly what
/// `cfg(patina)`-gated guest/dependency code and yield-point instrumentation
/// need. The shim's *link* arguments must not be whole-graph and live in
/// [`native_package_link_args`] instead — with one exception, `sancov_stub`,
/// which is a link argument precisely because the instrumentation above is
/// whole-graph (see [`PATINA_SANCOV_STUB_OBJECT`]).
///
/// Nothing here keys the shim's bytes. Every shim link input reaches the link
/// under a path named by its content ([`publish_native_shim`],
/// [`stage_shim_object`]), and Cargo fingerprints both this string and the
/// `cargo rustc --` link arguments, so a changed input is a changed argument and
/// the guest relinks.
pub(super) fn native_package_rustflags(sancov_stub: Option<&Path>, target: &str) -> OsString {
    let mut tokens: Vec<OsString> = Vec::new();
    if let Some(existing) = env::var_os("RUSTFLAGS") {
        for part in existing.to_string_lossy().split_whitespace() {
            tokens.push(OsString::from(part));
        }
    }
    tokens.push(OsString::from("--cfg"));
    tokens.push(OsString::from("patina"));
    tokens.push(OsString::from("--cfg"));
    tokens.push(OsString::from("dst"));
    // Shim-linked build marker; see `compile_single_source` for why the SDK's
    // buggify FFI is gated on `patina_shim` rather than `patina`.
    tokens.push(OsString::from("--cfg"));
    tokens.push(OsString::from("patina_shim"));
    // rustix's DEFAULT Linux backend emits raw inline syscall instructions —
    // invisible to the import audit and refused by the instruction scan. On
    // targets WITHOUT syscall-user-dispatch (aarch64 Linux today; macOS uses
    // libc anyway so the cfg is inert), flip rustix to its libc backend with
    // its own escape hatch so those effects surface as interposable imports.
    // On a SUD-capable target (x86_64 Linux) we DROP the injection: the shim
    // arms SUD and traps the raw syscalls into the deterministic runtime, so
    // the workaround is unnecessary — and keeping it would be a permanent dual
    // path (SUD-DESIGN.md §9). No-cruft: a single conditional, no dead config.
    if !target_has_sud(target) {
        tokens.push(OsString::from("--cfg"));
        tokens.push(OsString::from("rustix_use_libc"));
    }
    if let Some(sancov_stub) = sancov_stub {
        for flag in sancov_rustc_flags() {
            tokens.push(OsString::from(flag));
        }
        tokens.push(OsString::from("-C"));
        tokens.push(link_arg(sancov_stub));
    }
    let mut encoded = OsString::new();
    for (index, token) in tokens.iter().enumerate() {
        if index > 0 {
            encoded.push("\u{1f}");
        }
        encoded.push(token);
    }
    encoded
}

/// Fold `path`'s bytes and length into `hasher`, streamed so the multi-megabyte
/// shim staticlib is never held in memory.
pub(super) fn hash_file_contents(hasher: &mut Sha256, path: &Path) -> Result<(), CliError> {
    use io::Read;

    let mut file = fs::File::open(path).map_err(|error| {
        CliError(format!(
            "failed to open the shim link input {}: {error}",
            path.display()
        ))
    })?;
    let mut buffer = vec![0u8; 64 * 1024];
    let mut length: u64 = 0;
    loop {
        let read = file.read(&mut buffer).map_err(|error| {
            CliError(format!(
                "failed to read the shim link input {}: {error}",
                path.display()
            ))
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        length += read as u64;
    }
    hasher.update(length.to_le_bytes());
    Ok(())
}

/// Stage [`PATINA_SANCOV_STUB_OBJECT`] when the build is instrumented. The stubs
/// exist only to answer the instrumentation, so a build without `--yield-points`
/// stages nothing and no Patina object reaches a dependency's link at all.
pub(super) fn stage_sancov_stub(
    shim: &BuiltNativeShim,
    yield_points: bool,
    target: &str,
) -> Result<Option<PathBuf>, CliError> {
    if !yield_points {
        return Ok(None);
    }
    stage_shim_object(&shim.objects, &PATINA_SANCOV_STUB_OBJECT, target, &[]).map(Some)
}

/// The shim's link arguments for a package build, as the trailing arguments of
/// `cargo rustc -- <args>`.
///
/// These must NOT travel in `RUSTFLAGS`. rustc forwards `-C link-arg` to the
/// system linker for every crate-type it actually links, so a whole-graph
/// injection reaches more than the guest binary: an `rlib` compile has no link
/// step and ignores them, but a dependency whose `[lib]` declares
/// `crate-type = ["rlib", "cdylib"]` (crc-fast 1.10.0, from the SlateDB
/// dogfooding feedback) runs a real `cdylib` link and receives the shim objects
/// and staticlib too. That link then fails on Linux — `duplicate symbol:
/// rust_eh_personality`, defined by both the sysroot libstd rlib and the copy of
/// std bundled inside `libpatina_dst_native_shim.a`, for any cdylib whose code
/// has landing pads — while producing nothing anyone loads. There is no avoiding
/// that build: Cargo produces every crate type a path dependency declares,
/// measured identically with `--target <host>`, without `--target`, and under a
/// plain `cargo build`. The dependency's link has to succeed, so the shim has to
/// stay off it.
///
/// `cargo rustc` passes its trailing arguments to the final compiler invocation
/// for the one selected target only, which is the scope the shim link line needs:
/// the guest binary (or libtest harness) and nothing else. Interposition is
/// unaffected — the shim's strong symbol definitions still land in that final
/// link.
pub(super) fn native_package_link_args(
    facade: &Path,
    engine: &Path,
    allocator: &[OsString],
    yield_object: Option<&Path>,
) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec![
        OsString::from("-C"),
        link_arg(facade),
        OsString::from("-C"),
        link_arg(engine),
    ];
    if let Some(yield_object) = yield_object {
        args.push(OsString::from("-C"));
        args.push(link_arg(yield_object));
    }
    // The allocator routing (`allocator_routing.rs`).
    for arg in allocator {
        args.push(OsString::from("-C"));
        args.push(arg.clone());
    }
    for arg in platform_link_args() {
        args.push(OsString::from("-C"));
        args.push(arg);
    }
    args
}

/// Which instrumentation the program whose bytes are `image` was built with,
/// recovered from the linked hook's embedded marker; `binary` names it in an
/// error.
///
/// This classification is load-bearing: it selects the compatibility-fingerprint
/// suffix, so a false negative silently records under — or cross-replays against
/// — the wrong schedule policy. The `--coverage-points` marker therefore carries
/// its sampling STRIDE as well as its mode, because the stride is part of that
/// policy: the run side reads it out of the bytes it is about to execute rather
/// than trusting a flag to be re-passed. Those bytes are the run's mapping of the
/// executable, so a read failure stops the run before this is asked, and never
/// reads as "not instrumented".
pub(super) fn binary_instrumentation(
    image: &[u8],
    binary: &Path,
) -> Result<GuestInstrumentation, CliError> {
    // The yield-point marker wins wherever it sits: the two hook objects are
    // mutually exclusive at link, so at most one can be present, and a binary
    // carrying both bytes could only be a doctored artifact — classify it under
    // the DENSER policy rather than the cheaper one.
    if memchr::memmem::find(image, PATINA_YIELD_MARKER).is_some() {
        return Ok(GuestInstrumentation::YieldPoints);
    }
    // The first coverage-points marker names the stride.
    let Some(at) = memchr::memmem::find(image, PATINA_COV_MARKER_PREFIX) else {
        return Ok(GuestInstrumentation::None);
    };
    let tail = &image[at + PATINA_COV_MARKER_PREFIX.len()..];
    let digits: Vec<u8> = tail
        .iter()
        .copied()
        .take(PATINA_COV_MARKER_TRAILING)
        .take_while(|byte| *byte != b';')
        .collect();
    let stride = std::str::from_utf8(&digits)
        .ok()
        .and_then(|text| text.parse::<u32>().ok())
        .ok_or_else(|| {
            CliError(format!(
                "{} carries a malformed Patina coverage-points marker; rebuild it with \
`cargo patina build --coverage-points`",
                binary.display()
            ))
        })?;
    Ok(GuestInstrumentation::CoveragePoints { stride })
}

/// The decimal digits (a `u32`: at most 10) plus the `;` terminator that follow
/// the coverage-points marker prefix.
const PATINA_COV_MARKER_TRAILING: usize = 11;

/// Append the instrumentation policy suffix to a base fingerprint, leaving a
/// plain binary's fingerprint untouched (the suffix is empty). A `--yield-points`
/// binary and a `--coverage-points=N` binary therefore never cross-replay, and
/// neither does one stride against another.
pub(super) fn instrumentation_fingerprint(
    base: &str,
    instrumentation: GuestInstrumentation,
) -> String {
    format!("{base}{}", instrumentation.fingerprint_suffix())
}

/// The compatibility fingerprint for a native run: the base fingerprint, then
/// the yield-point policy suffix, the mounted-corpus suffix, and the
/// cooperative-SUT (buggify) suffix. Folding the filesystem image hash in means
/// a trace recorded against one corpus fails closed on replay against a
/// different one, exactly like a schedule-policy mismatch. The `+buggify`
/// suffix means a buggify trace never cross-replays with a non-buggify build,
/// even though the per-site knobs live in (reconciled) metadata.
///
/// `+buggify` is a *request* here; it is the one component the guest may retract.
/// A `--swarm` generation whose seed deselects the buggify class strips it again
/// inside the runtime, so the fingerprint recorded into the trace describes the
/// run that happened. A flag-free replay of such a trace reconstructs the
/// component set from the metadata ([`trace_has_buggify`],
/// [`native_policy_from_trace`]) and therefore recomputes the same string.
pub(super) fn native_run_fingerprint(
    base: &str,
    instrumentation: GuestInstrumentation,
    image_hash: Option<&str>,
    buggify: bool,
    policy: &SchedulePolicyFingerprint,
) -> String {
    let (head, tail) = native_run_fingerprint_around(base, instrumentation, buggify, policy);
    match image_hash {
        Some(hash) => format!("{head}{IMAGE_FINGERPRINT_COMPONENT}{hash}{tail}"),
        None => head + &tail,
    }
}

/// The mounted-corpus component of a native run's fingerprint, before its
/// image hash.
pub(super) const IMAGE_FINGERPRINT_COMPONENT: &str = "+fsimg:";

/// A native run's fingerprint either side of its mounted-corpus component
/// ([`native_run_fingerprint`]): the base and instrumentation suffix, then
/// the buggify and policy suffixes. Where the image hash sits is known only
/// from these, never from the string itself, whose base is the user's free
/// text.
pub(super) fn native_run_fingerprint_around(
    base: &str,
    instrumentation: GuestInstrumentation,
    buggify: bool,
    policy: &SchedulePolicyFingerprint,
) -> (String, String) {
    let head = instrumentation_fingerprint(base, instrumentation);
    let mut fingerprint = String::new();
    if buggify {
        fingerprint.push('+');
        fingerprint.push_str(patina_dst_runtime::FINGERPRINT_BUGGIFY);
    }
    // Exploration-policy suffixes, in a fixed order so the fingerprint is stable.
    // Each folds only when active, so a plain run fingerprints exactly as before
    // these components existed — mirroring the conditional `+buggify` suffix.
    if policy.pct {
        fingerprint.push_str("+pct");
    }
    if policy.starvation {
        fingerprint.push_str("+starve");
    }
    if policy.swarm {
        fingerprint.push_str("+swarm");
    }
    (head, fingerprint)
}

/// The exploration-policy fingerprint components of a native run. On a fresh run
/// these come from the CLI flags; on replay they are reconstructed from the trace
/// metadata (see [`native_policy_from_trace`]), so replay is self-contained and a
/// policy trace never cross-replays with a plain build.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct SchedulePolicyFingerprint {
    pct: bool,
    starvation: bool,
    swarm: bool,
}

impl SchedulePolicyFingerprint {
    pub(super) fn from_schedule(schedule: &NativeSchedule) -> Self {
        Self {
            pct: schedule.pct.is_some(),
            starvation: schedule.starve.is_some(),
            swarm: schedule.swarm,
        }
    }
}

/// Whether a recorded trace carries buggify metadata. Used at replay so the
/// `+buggify` fingerprint component is reconstructed from the trace itself,
/// keeping replay self-contained (the operator need not re-pass `--buggify`).
pub(super) fn trace_has_buggify(bundle: &TraceBundle) -> bool {
    bundle.metadata.buggify.is_some()
}

/// Reconstruct the exploration-policy fingerprint components from a recorded
/// trace's metadata, so a flag-free replay recomputes the same fingerprint the
/// record run folded (`+pct`/`+starve`/`+swarm`) and a cross-policy replay fails
/// closed.
pub(super) fn native_policy_from_trace(bundle: &TraceBundle) -> SchedulePolicyFingerprint {
    let policy = bundle.metadata.schedule_policy.as_ref();
    SchedulePolicyFingerprint {
        pct: policy.is_some_and(|policy| policy.pct.is_some()),
        starvation: policy.is_some_and(|policy| policy.starvation.is_some()),
        swarm: bundle.metadata.swarm.is_some(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DEFAULT_NATIVE_FINGERPRINT;
    use crate::native_run::target_has_sud;
    use crate::parse::parse_native_build;
    use crate::tests::{native_build_invocation, strings};
    use std::path::Path;

    #[test]
    fn rustix_use_libc_is_dropped_only_on_sud_capable_targets() {
        // x86_64 Linux has kernel SUD, so the raw-syscall workaround is dropped
        // (SUD traps the raw syscalls); every other target keeps it. Guards the
        // no-cruft retirement against silently re-widening or over-dropping.
        assert!(target_has_sud("x86_64-unknown-linux-gnu"));
        assert!(target_has_sud("x86_64-unknown-linux-musl"));
        assert!(!target_has_sud("aarch64-unknown-linux-gnu")); // no SUD yet
        assert!(!target_has_sud("aarch64-apple-darwin")); // rustix uses libc
        assert!(!target_has_sud("x86_64-apple-darwin"));

        // The injected flags reflect it: present for aarch64-linux, absent for
        // x86_64-linux.
        let x86 = native_package_rustflags(None, "x86_64-unknown-linux-gnu");
        let arm = native_package_rustflags(None, "aarch64-unknown-linux-gnu");
        assert!(!x86.to_string_lossy().contains("rustix_use_libc"));
        assert!(arm.to_string_lossy().contains("rustix_use_libc"));
    }

    // The scoping split: the whole-graph
    // `RUSTFLAGS` carry cfgs and instrumentation, and the shim's link arguments
    // live in the `cargo rustc --` set that reaches one unit's final link. The
    // single deliberate exception is the weak SanitizerCoverage stub, which is
    // whole-graph because the instrumentation it answers for is. Any OTHER
    // link-arg leaking back into the rustflags side restores the
    // dependency-cdylib failure, so pin the boundary directly.
    #[test]
    fn shim_link_args_never_travel_in_whole_graph_rustflags() {
        let directory = Path::new("/shim");
        let object = directory.join("patina_posix.o");
        let staticlib = directory.join("libpatina_dst_native_shim.a");
        let yield_object = directory.join("patina_yield.o");
        let sancov_stub = directory.join("patina_sancov_stub.o");

        for stub in [None, Some(sancov_stub.as_path())] {
            let rustflags = native_package_rustflags(stub, "x86_64-unknown-linux-gnu");
            let rustflags = rustflags.to_string_lossy().into_owned();
            assert!(rustflags.contains("patina_shim"));
            // Yield-point instrumentation is codegen, not linking: it must stay
            // whole-graph so dependency code gains yield points too.
            assert_eq!(
                rustflags.contains("sanitizer-coverage-trace-pc-guard"),
                stub.is_some()
            );
            let link_args: Vec<&str> = rustflags
                .split('\u{1f}')
                .filter(|token| token.starts_with("link-arg="))
                .collect();
            match stub {
                None => assert!(
                    link_args.is_empty(),
                    "an uninstrumented build injects nothing whole-graph, got: {link_args:?}"
                ),
                Some(_) => assert_eq!(
                    link_args,
                    vec![format!("link-arg={}", sancov_stub.display()).as_str()]
                ),
            }
        }

        let allocator = [OsString::from("link-arg=routing.o")];
        let args = native_package_link_args(&object, &staticlib, &allocator, Some(&yield_object));
        let rendered: Vec<String> = args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert!(rendered.iter().any(|arg| arg.ends_with("patina_posix.o")));
        assert!(
            rendered
                .iter()
                .any(|arg| arg.ends_with("libpatina_dst_native_shim.a"))
        );
        assert!(rendered.iter().any(|arg| arg.ends_with("patina_yield.o")));
        for arg in &rendered {
            assert!(
                arg == "-C" || arg.starts_with("link-arg="),
                "the scoped set is link arguments only, got: {arg}"
            );
        }
        assert!(
            native_package_link_args(&object, &staticlib, &allocator, None)
                .iter()
                .all(|arg| !arg.to_string_lossy().ends_with("patina_yield.o"))
        );
    }

    #[test]
    fn yield_points_flag_and_fingerprint_suffix() {
        // Off by default on both target shapes.
        assert_eq!(
            native_build_invocation(&["native-build", "probe.rs", "--output", "p"]).instrumentation,
            GuestInstrumentation::None
        );
        assert_eq!(
            native_build_invocation(&["native-build", "pkg", "--output", "p"]).instrumentation,
            GuestInstrumentation::None
        );
        // `--yield-points` sets it on a single source and on a package.
        assert_eq!(
            native_build_invocation(&[
                "native-build",
                "probe.rs",
                "--output",
                "p",
                "--yield-points",
            ])
            .instrumentation,
            GuestInstrumentation::YieldPoints
        );
        assert_eq!(
            native_build_invocation(&["native-build", "pkg", "--output", "p", "--yield-points"])
                .instrumentation,
            GuestInstrumentation::YieldPoints
        );
        // `--coverage-points` bare is counters only; `=N` is the sampled stride.
        assert_eq!(
            native_build_invocation(&["native-build", "pkg", "--output", "p", "--coverage-points"])
                .instrumentation,
            GuestInstrumentation::CoveragePoints { stride: 0 }
        );
        assert_eq!(
            native_build_invocation(&[
                "native-build",
                "pkg",
                "--output",
                "p",
                "--coverage-points=1024",
            ])
            .instrumentation,
            GuestInstrumentation::CoveragePoints { stride: 1024 }
        );
        // The two modes are mutually exclusive: they define the same
        // SanitizerCoverage entry points, so linking both is not representable.
        let clash = parse_native_build(strings(&[
            "pkg",
            "--output",
            "p",
            "--yield-points",
            "--coverage-points=8",
        ]))
        .unwrap_err();
        assert!(
            clash.to_string().contains("mutually exclusive"),
            "expected a mutual-exclusion usage error, got: {clash}"
        );

        // The fingerprint gains a policy suffix only for an instrumented binary,
        // so a plain binary's traces stay compatible and cross-config replay is
        // rejected. The stride is PART of the suffix: two strides are two
        // different schedule policies and must not cross-replay.
        assert_eq!(
            instrumentation_fingerprint(DEFAULT_NATIVE_FINGERPRINT, GuestInstrumentation::None),
            DEFAULT_NATIVE_FINGERPRINT
        );
        assert_eq!(
            instrumentation_fingerprint(
                DEFAULT_NATIVE_FINGERPRINT,
                GuestInstrumentation::YieldPoints
            ),
            format!("{DEFAULT_NATIVE_FINGERPRINT}{PATINA_YIELD_FINGERPRINT_SUFFIX}")
        );
        assert_eq!(
            instrumentation_fingerprint(
                DEFAULT_NATIVE_FINGERPRINT,
                GuestInstrumentation::CoveragePoints { stride: 0 }
            ),
            format!("{DEFAULT_NATIVE_FINGERPRINT}{PATINA_COV_FINGERPRINT_SUFFIX}:0")
        );
        assert_ne!(
            instrumentation_fingerprint(
                DEFAULT_NATIVE_FINGERPRINT,
                GuestInstrumentation::CoveragePoints { stride: 512 }
            ),
            instrumentation_fingerprint(
                DEFAULT_NATIVE_FINGERPRINT,
                GuestInstrumentation::CoveragePoints { stride: 1024 }
            )
        );
        // Only a mode that actually preempts inside an atomics-only loop makes
        // `--starve` liveness-safe; counters alone do not.
        assert!(GuestInstrumentation::YieldPoints.preempts_inside_atomics());
        assert!(GuestInstrumentation::CoveragePoints { stride: 1 }.preempts_inside_atomics());
        assert!(!GuestInstrumentation::CoveragePoints { stride: 0 }.preempts_inside_atomics());
        assert!(!GuestInstrumentation::None.preempts_inside_atomics());
        // Both instrumented modes carry edge counters, so `--coverage-out` and
        // `campaign --guided` are available under either.
        assert!(GuestInstrumentation::CoveragePoints { stride: 0 }.has_coverage());
        assert!(GuestInstrumentation::YieldPoints.has_coverage());
        assert!(!GuestInstrumentation::None.has_coverage());
    }

    // The instrumentation classification is load-bearing for the compatibility
    // fingerprint, so its detector must report a clean absence as `None`, find
    // either marker anywhere in the image, and recover the coverage-point stride
    // from the binary's own bytes, since no flag re-states it at run time.
    #[test]
    fn instrumentation_is_read_from_the_image_bytes() {
        let classify = |image: &[u8]| binary_instrumentation(image, Path::new("guest")).ok();
        assert_eq!(
            classify(&vec![0u8; 200_000]),
            Some(GuestInstrumentation::None)
        );

        let mut image = vec![0u8; 200_000];
        let at = 64 * 1024 - (PATINA_YIELD_MARKER.len() / 2);
        image[at..at + PATINA_YIELD_MARKER.len()].copy_from_slice(PATINA_YIELD_MARKER);
        assert_eq!(classify(&image), Some(GuestInstrumentation::YieldPoints));

        let cov = |stride: u32| {
            format!(
                "{}{stride};",
                std::str::from_utf8(PATINA_COV_MARKER_PREFIX).unwrap()
            )
        };
        for stride in [0u32, 7, 4_294_967_295] {
            let mut image = vec![0u8; 200_000];
            image[1000..1000 + cov(stride).len()].copy_from_slice(cov(stride).as_bytes());
            assert_eq!(
                classify(&image),
                Some(GuestInstrumentation::CoveragePoints { stride }),
                "stride {stride}"
            );
        }

        // A yield-point marker wins even when a coverage prefix precedes it, and
        // among coverage prefixes the FIRST names the stride.
        let mut image = vec![0u8; 200_000];
        image[100..100 + cov(9).len()].copy_from_slice(cov(9).as_bytes());
        let late = 150_000;
        image[late..late + PATINA_YIELD_MARKER.len()].copy_from_slice(PATINA_YIELD_MARKER);
        assert_eq!(classify(&image), Some(GuestInstrumentation::YieldPoints));
        let mut image = vec![0u8; 200_000];
        image[100..100 + cov(9).len()].copy_from_slice(cov(9).as_bytes());
        image[late..late + cov(4).len()].copy_from_slice(cov(4).as_bytes());
        assert_eq!(
            classify(&image),
            Some(GuestInstrumentation::CoveragePoints { stride: 9 })
        );
    }
}
