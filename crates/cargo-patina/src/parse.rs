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
    if let Some(name) = verb.as_deref() {
        if help::verb(name).is_some() {
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

/// A compiled artifact's target family, inferred from its leading magic bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ArtifactFamily {
    /// A WebAssembly module (`\0asm` preamble) → the WASI runner/audit path.
    Wasm,
    /// A native executable (Mach-O or ELF magic) → the native runner/audit path.
    Native,
}

/// Classify a compiled artifact by its leading magic bytes. Pure and
/// filesystem-free so it is unit-testable on byte slices; returns `None` for
/// anything that is neither a WebAssembly module nor a native Mach-O/ELF image
/// (a `Cargo.toml`, a shell script, an empty file, ...).
fn detect_artifact_family(bytes: &[u8]) -> Option<ArtifactFamily> {
    // WebAssembly: the four-byte `\0asm` preamble.
    if bytes.starts_with(b"\0asm") {
        return Some(ArtifactFamily::Wasm);
    }
    // ELF: 0x7F 'E' 'L' 'F'.
    if bytes.starts_with(&[0x7f, b'E', b'L', b'F']) {
        return Some(ArtifactFamily::Native);
    }
    // Mach-O: thin 32/64-bit in either byte order, plus universal ("fat")
    // archives. Each four-byte magic is matched exactly.
    const MACH_O_MAGICS: [[u8; 4]; 6] = [
        [0xfe, 0xed, 0xfa, 0xce], // MH_MAGIC (32-bit)
        [0xce, 0xfa, 0xed, 0xfe], // MH_CIGAM (32-bit, byte-swapped)
        [0xfe, 0xed, 0xfa, 0xcf], // MH_MAGIC_64 (64-bit)
        [0xcf, 0xfa, 0xed, 0xfe], // MH_CIGAM_64 (64-bit, byte-swapped)
        [0xca, 0xfe, 0xba, 0xbe], // FAT_MAGIC (universal)
        [0xbe, 0xba, 0xfe, 0xca], // FAT_CIGAM (universal, byte-swapped)
    ];
    if MACH_O_MAGICS.iter().any(|magic| bytes.starts_with(magic)) {
        return Some(ArtifactFamily::Native);
    }
    None
}

/// Read the leading magic bytes of `path` and classify it with
/// [`detect_artifact_family`]. Only a short prefix is read, so a multi-megabyte
/// native binary is not slurped merely to route it.
fn artifact_family(path: &Path) -> Result<Option<ArtifactFamily>, CliError> {
    use std::io::Read;
    let mut file = fs::File::open(path).map_err(|error| {
        CliError(format!(
            "failed to open artifact {}: {error}",
            path.display()
        ))
    })?;
    let mut prefix = [0u8; 8];
    let read = file.read(&mut prefix).map_err(|error| {
        CliError(format!(
            "failed to read artifact {}: {error}",
            path.display()
        ))
    })?;
    Ok(detect_artifact_family(&prefix[..read]))
}

/// Extract a `--target native|wasi` selector from the leading (pre-`--`) region
/// of an argument list, returning it plus the arguments with the selector
/// removed. A `--target` after a `--` separator is left in place — there it is a
/// rustc/cargo flag, not Patina's family selector.
fn extract_target(arguments: Vec<OsString>) -> Result<(Option<String>, Vec<OsString>), CliError> {
    let (found, rest) = cli::strip(&[cli::flag("run", "--target")], arguments)?;
    let target = cli::single(&found, "--target")?.map(|value| value.to_string_lossy().into_owned());
    Ok((target, rest))
}

/// Map a `--target` value to its artifact family.
fn target_family(target: &str) -> Result<ArtifactFamily, CliError> {
    match target {
        "native" => Ok(ArtifactFamily::Native),
        "wasi" => Ok(ArtifactFamily::Wasm),
        other => Err(CliError::usage(format!(
            "--target must be native or wasi; got {other:?}"
        ))),
    }
}

/// How a run/audit/replay positional argument classifies. The single shared
/// resolution step (unit-tested via [`classify_arg`]) decides between using an
/// already-built artifact directly and building a source/package on the fly.
enum ArgKind {
    /// An existing file with WebAssembly or native Mach-O/ELF magic.
    Artifact(ArtifactFamily),
    /// A single `.rs` source (built native).
    SourceFile(PathBuf),
    /// A directory or `Cargo.toml` (a Cargo package), resolved to its manifest.
    SourcePackage(PathBuf),
    /// A leading flag, or a plain non-source file: neither artifact nor source.
    Other,
}

/// Whether a positional token is unmistakably a filesystem path (so a
/// nonexistent one is a mistake to surface, not a plausible bare Cargo argument):
/// it names a `.wasm`/`.rs`/`Cargo.toml`, or contains a path separator.
fn looks_like_path(raw: &OsStr) -> bool {
    let Some(text) = raw.to_str() else {
        // A non-UTF-8 token is never a bare Cargo argument; treat it as a path.
        return true;
    };
    text.ends_with(".wasm")
        || text.ends_with(".rs")
        || Path::new(text).file_name() == Some(OsStr::new("Cargo.toml"))
        || text.contains('/')
        || text.contains(std::path::MAIN_SEPARATOR)
}

/// Classify a run/audit/replay positional argument. A built artifact is
/// recognized by leading magic bytes (used directly); an existing `.rs`,
/// directory, or `Cargo.toml` is a source/package to build; a bare name that does
/// not exist is `Other` (a plausible Cargo argument, left to the cargo family).
/// A token that clearly names a file path (`.wasm`/`.rs`/`Cargo.toml`, or with a
/// separator) but does not exist is a hard error — fail closed rather than let
/// `run nonexistent.wasm` fall through to a confusing `cargo run` failure.
fn classify_arg(raw: &OsStr) -> Result<ArgKind, CliError> {
    if raw.to_str().is_some_and(|value| value.starts_with('-')) {
        return Ok(ArgKind::Other);
    }
    let path = Path::new(raw);
    if path.is_dir() {
        return Ok(ArgKind::SourcePackage(native_manifest_path(path)));
    }
    if path.is_file() {
        if let Some(family) = artifact_family(path)? {
            return Ok(ArgKind::Artifact(family));
        }
        if path.file_name() == Some(OsStr::new("Cargo.toml")) {
            return Ok(ArgKind::SourcePackage(path.to_path_buf()));
        }
        if path.extension().and_then(OsStr::to_str) == Some("rs") {
            return Ok(ArgKind::SourceFile(path.to_path_buf()));
        }
        // An existing file that is neither an artifact nor a source: not ours.
        return Ok(ArgKind::Other);
    }
    // The token does not exist. If it plainly names a file path, fail closed;
    // otherwise it is a bare name the cargo family may interpret.
    if looks_like_path(raw) {
        return Err(CliError::usage(format!("no such file: {}", path.display())));
    }
    Ok(ArgKind::Other)
}

/// Build spec for a single-source native build on the fly (defaults: current
/// edition, debug, no yield points, no extra rustc args).
fn native_source_spec(source: PathBuf) -> BuildSpec {
    BuildSpec {
        origin: source.clone(),
        kind: BuildSpecKind::Native(NativeBuildInvocation {
            target: NativeBuildTarget::Source {
                source,
                edition: DEFAULT_NATIVE_EDITION.to_string(),
                rustc_args: Vec::new(),
            },
            output: None,
            release: false,
            instrumentation: GuestInstrumentation::None,
        }),
    }
}

/// Build spec for a native Cargo-package build on the fly. Binary selection is
/// automatic (fails closed on ambiguity, like the `build` verb).
fn native_package_spec(origin: PathBuf, manifest: PathBuf) -> BuildSpec {
    BuildSpec {
        origin,
        kind: BuildSpecKind::Native(NativeBuildInvocation {
            target: NativeBuildTarget::Package {
                manifest,
                package: None,
                bin: None,
            },
            output: None,
            release: false,
            instrumentation: GuestInstrumentation::None,
        }),
    }
}

/// Build spec for a WASI Cargo-package build on the fly.
fn wasi_package_spec(origin: PathBuf, manifest: PathBuf) -> BuildSpec {
    BuildSpec {
        origin,
        kind: BuildSpecKind::Wasi(WasiBuildInvocation {
            manifest,
            package: None,
            bin: None,
            release: false,
            output: None,
        }),
    }
}

/// Extract source-first `--package NAME`/`-p NAME` and `--bin NAME` from the head
/// of a `run`/`audit` flag list and return them with the remaining flags. When a
/// `run`/`audit` argument is a directory/`Cargo.toml` built on the fly, these
/// select the workspace member and binary exactly as the `build` verb does — the
/// help advertises the form (`audit <Cargo.toml> --package X --bin Y`), so audit
/// and run must honor it rather than reject it. Scanning stops at a `--`
/// separator so a `--package` in the guest/rustc argument section is passed
/// through untouched, and the flags are consumed here (not by the family parser),
/// so a package build and a single-source/prebuilt input get a uniform, precise
/// error via [`apply_package_selection`].
struct SourceFirstSelection {
    package: Option<String>,
    bin: Option<String>,
    /// The flags with `--package`/`--bin` removed, handed to the family parser.
    rest: Vec<OsString>,
}

fn take_package_bin(flags: Vec<OsString>) -> Result<SourceFirstSelection, CliError> {
    let (found, rest) = cli::strip(
        &[cli::flag("run", "--package"), cli::flag("run", "--bin")],
        flags,
    )?;
    Ok(SourceFirstSelection {
        package: cli::single(&found, "--package")?
            .map(|value| value.to_string_lossy().into_owned()),
        bin: cli::single(&found, "--bin")?.map(|value| value.to_string_lossy().into_owned()),
        rest,
    })
}

/// Thread source-first `--package`/`--bin` selection into a build-on-the-fly
/// artifact. Only a Cargo-package build honors them (a workspace member and its
/// binary, exactly as the `build` verb selects them); a single `.rs` source or an
/// already-built artifact has nothing to select, so a stray flag fails closed
/// with a precise message rather than being silently ignored.
fn apply_package_selection(
    artifact: &mut ArtifactRef,
    package: Option<String>,
    bin: Option<String>,
) -> Result<(), CliError> {
    if package.is_none() && bin.is_none() {
        return Ok(());
    }
    match artifact {
        ArtifactRef::Build(spec) => match &mut spec.kind {
            BuildSpecKind::Native(invocation) => match &mut invocation.target {
                NativeBuildTarget::Package {
                    package: pkg,
                    bin: binary,
                    ..
                } => {
                    if package.is_some() {
                        *pkg = package;
                    }
                    if bin.is_some() {
                        *binary = bin;
                    }
                    Ok(())
                }
                NativeBuildTarget::Source { .. } => Err(CliError::usage(
                    "--package and --bin apply to a Cargo-package build, not a single source file",
                )),
            },
            BuildSpecKind::Wasi(invocation) => {
                if package.is_some() {
                    invocation.package = package;
                }
                if bin.is_some() {
                    invocation.bin = bin;
                }
                Ok(())
            }
        },
        ArtifactRef::Prebuilt(_) => Err(CliError::usage(
            "--package and --bin select a member to build; they do not apply to an already-built artifact",
        )),
    }
}

/// Extract a source-first `--release` switch from the head of a `run` flag list,
/// stopping at `--` so a guest/program `--release` after the separator passes
/// through untouched. Mirrors [`take_package_bin`]: the flag is consumed here so
/// the family parser (which rejects unknown options) never sees it. Repeats are
/// idempotent, matching the `build` parser; an inline `--release=VALUE` is
/// rejected because the switch takes no value.
fn take_release(flags: Vec<OsString>) -> Result<(bool, Vec<OsString>), CliError> {
    let (found, rest) = cli::strip(&[cli::flag("run", "--release")], flags)?;
    Ok((found.contains_key("--release"), rest))
}

/// Apply a source-first `--release` to a build-on-the-fly artifact: it selects the
/// release profile for the guest `run` builds itself (default debug). Release is a
/// build profile, so it applies only to a source/package built on the fly; an
/// already-built artifact carries no profile of its own, so `--release` on a
/// prebuilt positional fails closed rather than being silently ignored.
fn apply_release(artifact: &mut ArtifactRef, release: bool) -> Result<(), CliError> {
    if !release {
        return Ok(());
    }
    match artifact {
        ArtifactRef::Build(spec) => {
            match &mut spec.kind {
                BuildSpecKind::Native(invocation) => invocation.release = true,
                BuildSpecKind::Wasi(invocation) => invocation.release = true,
            }
            Ok(())
        }
        ArtifactRef::Prebuilt(_) => Err(CliError::usage(
            "--release selects a build profile for a source/package built on the fly; an already-built artifact has no build profile",
        )),
    }
}

/// Resolve a run/audit/replay positional to an [`ArtifactRef`], honoring
/// `--target` (default native) and building a source/package on the fly. A
/// directory/`Cargo.toml` resolves to a native (or, under `--target wasi`, WASI)
/// build-on-the-fly exactly like a `.rs` source — the SAME path `audit` uses, so
/// a positional naming an existing package is never silently reinterpreted as
/// guest argv. `None` is returned only when the positional is neither an
/// artifact nor a source (a leading flag or a plain file); the caller then falls
/// through to its no-artifact behavior. Whether a runtime-linked package is
/// instead kept on the cargo-family path is a routing decision the `run`/`replay`
/// callers make up front via [`package_integrates_patina`]; this resolver is pure
/// classification.
fn resolve_positional(
    raw: &OsStr,
    target: Option<&str>,
) -> Result<Option<(ArtifactFamily, ArtifactRef)>, CliError> {
    match classify_arg(raw)? {
        ArgKind::Artifact(family) => {
            if let Some(target) = target {
                let requested = target_family(target)?;
                if requested != family {
                    return Err(CliError::usage(format!(
                        "--target {target} does not match {}, an already-built {} artifact",
                        Path::new(raw).display(),
                        family_label(family)
                    )));
                }
            }
            Ok(Some((family, ArtifactRef::Prebuilt(PathBuf::from(raw)))))
        }
        ArgKind::SourceFile(source) => {
            let family = match target {
                Some(target) => target_family(target)?,
                None => ArtifactFamily::Native,
            };
            if family == ArtifactFamily::Wasm {
                return Err(CliError::usage(
                    "build --target wasi compiles a Cargo package; a single .rs source is native-only",
                ));
            }
            Ok(Some((
                family,
                ArtifactRef::Build(Box::new(native_source_spec(source))),
            )))
        }
        ArgKind::SourcePackage(manifest) => match target {
            None => Ok(Some((
                ArtifactFamily::Native,
                ArtifactRef::Build(Box::new(native_package_spec(PathBuf::from(raw), manifest))),
            ))),
            Some(target) => {
                let family = target_family(target)?;
                let spec = match family {
                    ArtifactFamily::Native => native_package_spec(PathBuf::from(raw), manifest),
                    ArtifactFamily::Wasm => wasi_package_spec(PathBuf::from(raw), manifest),
                };
                Ok(Some((family, ArtifactRef::Build(Box::new(spec)))))
            }
        },
        ArgKind::Other => {
            if target.is_some() {
                return Err(CliError::usage(format!(
                    "--target requires a source or package to build; {} is neither a .rs source, a directory, nor a Cargo.toml",
                    Path::new(raw).display()
                )));
            }
            Ok(None)
        }
    }
}

fn family_label(family: ArtifactFamily) -> &'static str {
    match family {
        ArtifactFamily::Wasm => "WebAssembly",
        ArtifactFamily::Native => "native",
    }
}

/// Does the Cargo package integrate the Patina runtime? True iff `cargo metadata
/// --no-deps` reports a declared dependency in [`PATINA_RUNTIME_CRATES`]. This is
/// the routing predicate that keeps a runtime-linked package on the cargo-family
/// path (where the linked runtime provides seeding, recording, replay, and
/// library-level determinism) while a plain package is built shim-linked and run
/// under the native pre-run gate. Any failure to resolve the metadata (no cargo,
/// an unreadable or invalid manifest, ...) answers `false`: a package we cannot
/// prove integrates the runtime is treated as plain — routed to the gated native
/// path or refused loudly — never silently trusted to a no-op cargo-family run.
///
/// `manifest` scopes the query to a positional package path; `cwd` scopes it to a
/// working directory (the cwd-package `run`). At most one is set.
pub(super) fn package_integrates_patina(manifest: Option<&Path>, cwd: Option<&Path>) -> bool {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let mut command = Command::new(&cargo);
    command
        .arg("metadata")
        .arg("--no-deps")
        .arg("--format-version")
        .arg("1")
        .stderr(Stdio::null());
    if let Some(manifest) = manifest {
        command.arg("--manifest-path").arg(manifest);
    }
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    let stdout = match command.output() {
        Ok(output) if output.status.success() => output.stdout,
        _ => return false,
    };
    let metadata: serde_json::Value = match serde_json::from_slice(&stdout) {
        Ok(value) => value,
        Err(_) => return false,
    };
    metadata
        .get("packages")
        .and_then(|value| value.as_array())
        .is_some_and(|packages| {
            packages.iter().any(|package| {
                package
                    .get("dependencies")
                    .and_then(|value| value.as_array())
                    .is_some_and(|deps| {
                        deps.iter().any(|dep| {
                            dep.get("name")
                                .and_then(|value| value.as_str())
                                .is_some_and(|name| PATINA_RUNTIME_CRATES.contains(&name))
                        })
                    })
            })
        })
}

/// The result of scanning a verb's leading region for its positional
/// argument(s) with [`locate_positionals`].
pub(crate) struct PositionalScan {
    /// The located positionals, in encounter order (at most `wanted`).
    pub(crate) positionals: Vec<OsString>,
    /// Every other token, order preserved, with the located positionals removed —
    /// handed to the family parser exactly as the whole tail was handed before.
    pub(crate) rest: Vec<OsString>,
    /// The index (into the scanned slice) of the first UNREGISTERED flag that
    /// halted the scan before `wanted` positionals were found, or `None` when the
    /// scan located everything or reached `--`/end seeing only registered flags.
    pub(crate) stop: Option<usize>,
}

/// Locate up to `wanted` leading positional argument(s) for `verb`, consulting
/// the registry ([`help::flag_arity`]) for flag arity so options may appear in
/// any order around the positional — the `cargo build`/`cargo run` ergonomic.
///
/// The scan walks the pre-`--` region left-to-right: a flag REGISTERED for
/// `verb` is skipped, and its value token too when the registry says the value
/// is `Required` and no inline `=` is present; the first UNREGISTERED
/// flag-looking token stops the scan conservatively — beyond it a token may be
/// the value of an unknown passthrough flag (a forwarded cargo flag like
/// `--manifest-path ./x/Cargo.toml`), and misreading a value as the artifact
/// would corrupt routing. Non-flag tokens are the positionals, collected in
/// order until `wanted` are found. The registry stays authoritative: arity comes
/// only from it, never a second table.
pub(crate) fn locate_positionals(
    verb: &str,
    arguments: &[OsString],
    wanted: usize,
) -> PositionalScan {
    let mut positionals = Vec::new();
    let mut taken = Vec::new();
    let mut stop = None;
    let mut index = 0;
    while index < arguments.len() && positionals.len() < wanted {
        let argument = &arguments[index];
        if argument == "--" {
            break;
        }
        if let Some(text) = argument.to_str() {
            if text.starts_with('-') {
                let name = cli::split_name(text);
                match help::flag_arity(verb, name) {
                    Some(help::Value::Required(..)) if name == text => {
                        // A registered value-taking flag consumes the next token.
                        index += 2;
                        continue;
                    }
                    Some(_) => {
                        // A registered valueless/optional flag, or one with an
                        // inline `=VALUE`: it consumes no separate token.
                        index += 1;
                        continue;
                    }
                    None => {
                        // Unknown flag: stop conservatively.
                        stop = Some(index);
                        break;
                    }
                }
            }
        }
        // A non-flag (or non-UTF-8) token is a positional.
        positionals.push(argument.clone());
        taken.push(index);
        index += 1;
    }
    let rest = arguments
        .iter()
        .enumerate()
        .filter(|(index, _)| !taken.contains(index))
        .map(|(_, argument)| argument.clone())
        .collect();
    PositionalScan {
        positionals,
        rest,
        stop,
    }
}

/// Whether `raw` is an existing file whose magic bytes identify it as a compiled
/// artifact (a `.wasm` module or a native binary). Such a file is NEVER the value
/// of a cargo flag, so an unknown flag standing in front of it is a misuse, not a
/// forwarded flag with a value.
fn existing_compiled_artifact(raw: &OsStr) -> bool {
    let path = Path::new(raw);
    path.is_file() && matches!(artifact_family(path), Ok(Some(_)))
}

/// Whether `raw` names an existing artifact or source/package (a compiled
/// binary, a `.rs` source, a `Cargo.toml`, or a directory) — anything the
/// positional resolver would route to a real family.
fn existing_artifact_or_source(raw: &OsStr) -> bool {
    matches!(
        classify_arg(raw),
        Ok(ArgKind::Artifact(_) | ArgKind::SourceFile(_) | ArgKind::SourcePackage(_))
    )
}

/// Whether `raw` is a path-like token (`.wasm`/`.rs`/`Cargo.toml`, or with a
/// separator) that does not exist — the same shape [`classify_arg`] fails closed
/// on. Behind an unknown flag it is a clearly-named artifact path the user
/// misplaced, not a plausible bare cargo argument.
fn stranded_path_like(raw: &OsStr) -> bool {
    !Path::new(raw).exists()
        && looks_like_path(raw)
        && !raw.to_str().is_some_and(|text| text.starts_with('-'))
}

/// The loud routing error raised when a genuine artifact is stranded behind an
/// unknown flag.
fn stranded_artifact_error(verb: &str, unknown_flag: &OsStr, artifact: &OsStr) -> CliError {
    CliError::usage(format!(
        "unknown option {:?} ahead of artifact {:?}; options and the artifact may appear in any \
order, but an unknown option is only forwarded in the Cargo package family — check the flag name \
(run `cargo patina {verb} --help`)",
        unknown_flag.to_string_lossy(),
        artifact.to_string_lossy(),
    ))
}

/// After [`locate_positionals`] halted on an unregistered flag without locating
/// the artifact, decide the honest outcome — never a silent surprise. `tail`
/// begins at that unknown flag. A genuine artifact/path stranded behind it is a
/// loud routing error (an unknown option only ever forwards in the Cargo family,
/// and every artifact family rejects an unknown flag anyway, so a real artifact
/// after it can only be a misuse); otherwise `Ok(())` lets the caller forward the
/// list to its no-artifact family. The token immediately after an unknown flag is
/// that flag's presumed value (`--manifest-path ./x/Cargo.toml`) and is exempt
/// UNLESS it is a compiled artifact, which is never a flag value.
pub(crate) fn reject_stranded_artifact(verb: &str, tail: &[OsString]) -> Result<(), CliError> {
    let unknown = tail.first().cloned().unwrap_or_default();
    let mut index = 0;
    let mut after_unknown_flag = false;
    while index < tail.len() {
        let argument = &tail[index];
        if argument == "--" {
            break;
        }
        if let Some(text) = argument.to_str() {
            if text.starts_with('-') {
                let name = cli::split_name(text);
                match help::flag_arity(verb, name) {
                    Some(help::Value::Required(..)) if name == text => {
                        index += 2;
                        after_unknown_flag = false;
                        continue;
                    }
                    Some(_) => {
                        index += 1;
                        after_unknown_flag = false;
                        continue;
                    }
                    None => {
                        after_unknown_flag = true;
                        index += 1;
                        continue;
                    }
                }
            }
        }
        if after_unknown_flag {
            // The presumed value of the preceding unknown flag: exempt unless it
            // is a compiled artifact (never a flag value).
            if existing_compiled_artifact(argument) {
                return Err(stranded_artifact_error(verb, &unknown, argument));
            }
            after_unknown_flag = false;
            index += 1;
            continue;
        }
        // A "free" token beyond any flag's value: an existing artifact/source or a
        // path-like nonexistent token here is a misplaced artifact.
        if existing_artifact_or_source(argument) || stranded_path_like(argument) {
            return Err(stranded_artifact_error(verb, &unknown, argument));
        }
        index += 1;
    }
    Ok(())
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
    if target.is_none() {
        if let ArgKind::SourcePackage(manifest) = classify_arg(&first)? {
            if package_integrates_patina(Some(&manifest), None) {
                return parse_cargo("run".to_string(), rest);
            }
        }
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

pub(super) fn parse_native_harness_from(
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

/// Parse the Cargo package family (`run`/`test` with no diverting artifact): the
/// seed/record machinery, seed-driven fault knobs, and typed `--param`s,
/// forwarding every unrecognized option to Cargo. Replaying a recording — strict
/// or branch-append — is the `replay` verb's job (see [`parse_cargo_replay`]), so
/// `run`/`test` carry no replay/branch/timeline flags.
pub(super) fn parse_cargo(
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
pub(super) fn parse_cargo_replay(
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

/// Thin wrapper: treat the leading argument as an already-built module. Used by
/// unit tests; `run` routing calls [`parse_wasi_run_from`] with a resolved ref.
#[cfg(test)]
pub(super) fn parse_wasi_run(mut arguments: Vec<OsString>) -> Result<WasiInvocation, CliError> {
    if arguments.is_empty() {
        return Err(CliError::usage(
            "run of a WASI module requires a .wasm path",
        ));
    }
    let module = ArtifactRef::Prebuilt(PathBuf::from(arguments.remove(0)));
    parse_wasi_run_from(module, arguments)
}

/// Parse the flags of a WASI `run` given an already-resolved module reference
/// The host-supplied inputs a WASI run/replay shares: fuel, guest argv, guest
/// environment, datagram sockets, preopens, and resource-limit overrides. These
/// are genuine host inputs (not recorded semantic state — except `--arg`, which
/// becomes the recorded guest argv), so both `run` and `replay` accept them and
/// they feed the WASI compatibility fingerprint.
#[derive(Default)]
struct WasiHostInputs {
    fuel: Option<u64>,
    arguments: Vec<String>,
    environment: BTreeMap<String, String>,
    sockets: Vec<WasiSocketConfig>,
    preopens: Vec<WasiPreopenConfig>,
    resource_limits: WasiResourceLimitOverrides,
}

/// Assemble a [`WasiInvocation`] from a parsed mode, the shared host inputs, and
/// the fault knobs. Shared tail of [`parse_wasi_run_from`] and
/// [`parse_wasi_replay`].
fn wasi_invocation_from(
    module: ArtifactRef,
    mode: Mode,
    inputs: WasiHostInputs,
    step_budget: Option<u64>,
    knobs: KnobValues,
    buggify: Option<NativeBuggify>,
    liveness: NativeLiveness,
) -> WasiInvocation {
    WasiInvocation {
        module,
        mode,
        fuel: inputs.fuel.unwrap_or(DEFAULT_WASM_FUEL),
        arguments: inputs.arguments,
        environment: inputs.environment,
        sockets: inputs.sockets,
        preopens: inputs.preopens,
        resource_limits: inputs.resource_limits,
        step_budget,
        // Set by `run` only; `replay` restores the recorded epoch.
        realtime_epoch_nanos: None,
        knobs,
        buggify,
        liveness,
    }
}

/// Parse the flags of a WASI `run` given an already-resolved module reference
/// (an existing `.wasm` or a build-on-the-fly spec). `run` produces a seeded or
/// `--record` run: replaying a recording is the `replay` verb's job, so the
/// replay/branch/timeline flags live there, not here. The seed-driven fault knobs
/// (including `--sleep-jitter-nanos`, honored at the wasip1 host's sleep entry)
/// and the cooperative-SUT (buggify) knobs are accepted and recorded exactly as
/// on the native family.
pub(super) fn parse_wasi_run_from(
    module: ArtifactRef,
    arguments: Vec<OsString>,
) -> Result<WasiInvocation, CliError> {
    let args = cli::parse("run", help::Family::Wasi, arguments)?;
    let seed = args.u64("--seed").unwrap_or(0);
    let mode = match args.path("--record") {
        Some(path) => Mode::Record { seed, path },
        None => Mode::Seeded { seed },
    };
    Ok(WasiInvocation {
        realtime_epoch_nanos: realtime_epoch_of(&args),
        ..wasi_invocation_from(
            module,
            mode,
            wasi_host_inputs_of(&args)?,
            args.u64("--budget"),
            knobs_of(&args)?,
            buggify_of(&args),
            liveness_of(&args),
        )
    })
}

/// Parse the WASI `replay <MODULE.wasm> <TRACE>` verb given an already-resolved
/// module reference and trace path. Flag-free for semantics: the seed and fault
/// knobs are restored from the trace, and `--arg` values (the recorded guest
/// argv) are restored and conflict-checked at execution. Only genuine host inputs
/// stay as flags (`--fuel`/`--env`/`--socket`/`--preopen`/resource limits), plus
/// the timeline selector and branch controls the WASI runtime supports.
pub(super) fn parse_wasi_replay(
    module: ArtifactRef,
    trace: PathBuf,
    arguments: Vec<OsString>,
) -> Result<WasiInvocation, CliError> {
    let args = cli::parse("replay", help::Family::Wasi, arguments)?;
    Ok(wasi_invocation_from(
        module,
        replay_mode(&args, trace)?,
        wasi_host_inputs_of(&args)?,
        // `replay` registers no --budget: it re-executes a recorded operation
        // stream whose length is already fixed by the trace.
        None,
        KnobValues::default(),
        None,
        NativeLiveness::default(),
    ))
}

pub(super) fn parse_explore(arguments: Vec<OsString>) -> Result<ExploreInvocation, CliError> {
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
pub(super) fn parse_native_audit_from(
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

pub(super) fn parse_native_build(
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
fn native_manifest_path(path: &Path) -> PathBuf {
    if path.file_name() == Some(OsStr::new("Cargo.toml")) {
        path.to_path_buf()
    } else {
        path.join("Cargo.toml")
    }
}

/// The control-plane payload for one repeatable knob's whole value set.
///
/// A repeatable knob carries a SET rather than one value: the control plane
/// takes the whole set as one encoded variable, while a child `run` command line
/// takes the flag once per element. Both shapes hang off the same
/// [`FaultKnob`] table, so neither has to be special-cased at a call site — the
/// bug that was live for `--dns-entry`, which `test`'s native-harness family
/// advertised and never forwarded, so every lookup in a harness run went
/// NXDOMAIN as if no table had been supplied.
pub(super) fn repeatable_payload(knob: FaultKnob, values: &[String]) -> Result<String, CliError> {
    match knob {
        FaultKnob::DnsEntry => encode_dns_entries(values),
        FaultKnob::NetPartition => encode_net_partitions(values),
        // Every other knob is `Plumbing::Scalar` and carries its one value
        // verbatim; the callers filter on plumbing before asking for a payload,
        // and `every_repeatable_knob_has_an_encoder` proves this arm is dead for
        // every knob the table marks repeatable.
        scalar => Err(CliError(format!(
            "{} is not a repeatable knob",
            scalar.meta().flag
        ))),
    }
}

/// The DNS host table as the JSON object the runtime's control plane carries.
fn encode_dns_entries(values: &[String]) -> Result<String, CliError> {
    let entries: BTreeMap<String, String> = values
        .iter()
        .map(|value| {
            let (name, address) = values::dns_entry("--dns-entry", value).map_err(CliError)?;
            Ok((name.to_string(), address.to_string()))
        })
        .collect::<Result<_, CliError>>()?;
    serde_json::to_string(&entries)
        .map_err(|error| CliError(format!("failed to encode the DNS host table: {error}")))
}

/// The partition set as the JSON array of pairs the control plane carries.
fn encode_net_partitions(values: &[String]) -> Result<String, CliError> {
    let pairs: Vec<(String, String)> = values
        .iter()
        .map(|value| {
            let (left, right) = values::address_pair("--net-partition", value).map_err(CliError)?;
            Ok((left.to_string(), right.to_string()))
        })
        .collect::<Result<_, CliError>>()?;
    serde_json::to_string(&pairs)
        .map_err(|error| CliError(format!("failed to encode the network partitions: {error}")))
}

/// Every fault knob this invocation set, read straight off [`FaultKnob::ALL`].
/// Repeatable values are encoded here as well as forwarded, so a malformed one is
/// reported before anything is built or run.
pub(super) fn knobs_of(args: &cli::Args) -> Result<KnobValues, CliError> {
    let mut values = BTreeMap::new();
    for knob in FaultKnob::ALL {
        let meta = knob.meta();
        // A knob the registry does not give this family is absent, not an error
        // to read: the DNS knobs are a declared WASI exception, and the exception
        // lives in the registry rather than being restated here.
        if !args.registered(meta.flag) {
            continue;
        }
        let texts: Vec<String> = match meta.plumbing {
            Plumbing::Scalar => args.string(meta.flag).into_iter().collect(),
            Plumbing::Repeatable => args
                .texts(meta.flag)
                .into_iter()
                .map(str::to_string)
                .collect(),
        };
        if texts.is_empty() {
            continue;
        }
        if meta.plumbing == Plumbing::Repeatable {
            repeatable_payload(*knob, &texts)?;
        }
        values.insert(*knob, texts);
    }
    Ok(KnobValues(values))
}

/// The `PATINA_*` control-plane pairs carrying this invocation's knobs to the
/// guest, in [`FaultKnob::ALL`] order, unset knobs omitted so a run that
/// configured none sets nothing. Used by the WASI in-process runtime (via
/// [`RuntimeConfig::apply_fault_env`]) and by the native and cargo subprocesses
/// (as real environment variables), so every family applies the identical
/// protocol the native shim reads.
pub(super) fn knob_env_pairs(knobs: &KnobValues) -> Result<Vec<(&'static str, String)>, CliError> {
    let mut pairs = Vec::new();
    for knob in FaultKnob::ALL {
        let values = knobs.get(*knob);
        if values.is_empty() {
            continue;
        }
        let meta = knob.meta();
        let payload = match meta.plumbing {
            Plumbing::Scalar => values[0].clone(),
            Plumbing::Repeatable => repeatable_payload(*knob, values)?,
        };
        pairs.push((meta.env, payload));
    }
    Ok(pairs)
}

/// This invocation's knobs as `(flag, value)` pairs — a repeatable flag repeated
/// once per element — for re-emission onto a child `run` command line.
pub(super) fn knob_flag_pairs(knobs: &KnobValues) -> Vec<(&'static str, &String)> {
    FaultKnob::ALL
        .iter()
        .flat_map(|knob| {
            knobs
                .get(*knob)
                .iter()
                .map(move |value| (knob.meta().flag, value))
        })
        .collect()
}

/// Every `PATINA_*` variable a fault knob can arrive on, for the scrub that keeps
/// an ambient environment from perturbing a run that requested no faults.
pub(super) fn knob_env_vars() -> impl Iterator<Item = &'static str> {
    FaultKnob::ALL.iter().map(|knob| knob.meta().env)
}

/// The cooperative-SUT (buggify) knobs, or `None` when buggify was not enabled.
/// Any of the four flags enables it — the three detail knobs each imply
/// `--buggify`, as their help says.
fn buggify_of(args: &cli::Args) -> Option<NativeBuggify> {
    let fire = args.text("--buggify");
    let activation = args.string("--buggify-activation-permille");
    let cutoff = args.string("--buggify-cutoff-nanos");
    let after_setup = args.flag("--buggify-after-setup");
    if fire.is_none() && activation.is_none() && cutoff.is_none() && !after_setup {
        return None;
    }
    Some(NativeBuggify {
        // A bare `--buggify` supplies no per-mille; the runtime default applies.
        fire_permille: fire.filter(|value| !value.is_empty()).map(str::to_string),
        activation_permille: activation,
        cutoff_nanos: cutoff,
        after_setup,
    })
}

/// Read the guest instrumentation a native `build`/`test` invocation asked for.
///
/// The two instrumentation flags are mutually exclusive by construction, not by
/// convention: `patina_yield.c` and `patina_cov.c` define the same
/// SanitizerCoverage entry points, so linking both would be a duplicate-symbol
/// error at best and a coin flip at worst. Refuse the combination here, where the
/// message can say which one to keep.
fn instrumentation_of(args: &cli::Args) -> Result<GuestInstrumentation, CliError> {
    let yield_points = args.flag("--yield-points");
    let coverage_points = args.string("--coverage-points");
    match (yield_points, coverage_points) {
        (true, Some(_)) => Err(CliError::usage(
            "--yield-points and --coverage-points are mutually exclusive: both instrument every \
basic block, and they differ only in what happens there. Use --yield-points for a scheduling point \
at EVERY block (densest, slowest), --coverage-points=N for one every N blocks, or bare \
--coverage-points for edge counters with no added scheduling points.",
        )),
        (true, None) => Ok(GuestInstrumentation::YieldPoints),
        (false, None) => Ok(GuestInstrumentation::None),
        // A bare `--coverage-points` arrives as the empty string: counters only.
        (false, Some(value)) if value.is_empty() => {
            Ok(GuestInstrumentation::CoveragePoints { stride: 0 })
        }
        (false, Some(value)) => {
            // The registry grammar already proved a positive integer; only the
            // u32 ceiling (the C counter's width) is left to check.
            let stride: u32 = value.parse().map_err(|_| {
                CliError::usage(format!(
                    "--coverage-points={value} is out of range; the sampling stride must fit in 32 \
bits"
                ))
            })?;
            Ok(GuestInstrumentation::CoveragePoints { stride })
        }
    }
}

/// The exploration scheduling knobs. The inert-knob rule (`--sched-pct-steps`
/// without `--sched-pct`, and so on) is declared in the registry and enforced
/// generically by the parser, so it is not repeated here.
fn schedule_of(args: &cli::Args) -> NativeSchedule {
    NativeSchedule {
        pct: args.string("--sched-pct"),
        pct_steps: args.string("--sched-pct-steps"),
        starve: args.string("--starve"),
        starve_max_len: args.string("--starve-max-len"),
        starve_window: args.string("--starve-window"),
        swarm: args.flag("--swarm"),
    }
}

/// The liveness-watchdog knobs.
fn liveness_of(args: &cli::Args) -> NativeLiveness {
    NativeLiveness {
        compute_watchdog_ms: None,
        watchdog: args.string("--liveness-watchdog"),
        converge: args.string("--converge-within"),
        heal_after: args.string("--heal-after"),
    }
}

/// The pre-run gate's allow list.
fn allow_of(args: &cli::Args) -> BTreeSet<String> {
    args.texts("--allow")
        .into_iter()
        .map(str::to_string)
        .collect()
}

/// The unsupported-symbol escape hatch, default-deny.
fn unsupported_policy_of(args: &cli::Args) -> UnsupportedPolicy {
    match args.text("--allow-unsupported-symbols") {
        None => UnsupportedPolicy::Deny,
        Some(value) => {
            match values::unsupported_symbols("--allow-unsupported-symbols", value)
                .expect("validated by the registry grammar")
            {
                None => UnsupportedPolicy::All,
                Some(symbols) => {
                    UnsupportedPolicy::Only(symbols.into_iter().map(str::to_string).collect())
                }
            }
        }
    }
}

/// A repeatable `KEY=VALUE` flag as a map. The grammar already guaranteed a
/// non-empty key; uniqueness is the cross-value rule that remains.
fn key_values(args: &cli::Args, flag: &str) -> Result<BTreeMap<String, String>, CliError> {
    let mut map = BTreeMap::new();
    for entry in args.texts(flag) {
        let (key, value) = entry.split_once('=').expect("KEY=VALUE grammar");
        if map.insert(key.to_string(), value.to_string()).is_some() {
            return Err(CliError::usage(format!(
                "{flag} keys must be non-empty and unique"
            )));
        }
    }
    Ok(map)
}

/// The host-supplied inputs a WASI run/replay shares.
fn wasi_host_inputs_of(args: &cli::Args) -> Result<WasiHostInputs, CliError> {
    let fuel = args.u64("--fuel");
    let mut sockets = Vec::new();
    let mut socket_fds = BTreeSet::new();
    for entry in args.texts("--socket") {
        let (fd, bind, peer) =
            values::socket("--socket", entry).expect("validated by the registry grammar");
        if !socket_fds.insert(fd) {
            return Err(CliError::usage(
                "--socket requires a unique FD above 3 and non-empty addresses",
            ));
        }
        sockets.push(WasiSocketConfig {
            fd,
            bind: bind.to_string(),
            peer: peer.to_string(),
        });
    }
    let preopens = args
        .texts("--preopen")
        .into_iter()
        .map(|entry| {
            let (guest_path, read_only) =
                values::preopen("--preopen", entry).expect("validated by the registry grammar");
            WasiPreopenConfig {
                guest_path: normalize_cli_preopen_path(guest_path),
                policy: if read_only {
                    MountPolicy::ReadOnly
                } else {
                    MountPolicy::ReadWrite
                },
            }
        })
        .collect();
    Ok(WasiHostInputs {
        fuel,
        arguments: args
            .texts("--arg")
            .into_iter()
            .map(str::to_string)
            .collect(),
        environment: key_values(args, "--env")?,
        sockets,
        preopens,
        resource_limits: WasiResourceLimitOverrides {
            fuel,
            max_memory_pages: args.u32("--max-memory-pages"),
            max_iovecs: args.usize("--max-iovecs"),
            max_io_bytes: args.usize("--max-io-bytes"),
            max_descriptors: args.usize("--max-descriptors"),
            max_preopens: args.usize("--max-preopens"),
            max_path_bytes: args.usize("--max-path-bytes"),
        },
    })
}

/// The timeline/branch selection shared by the Cargo package and WASI replay
/// families, which are the two that support branch-append.
fn replay_mode(args: &cli::Args, path: PathBuf) -> Result<Mode, CliError> {
    let timeline = args.string("--timeline");
    let from_sequence = args.u64("--from");
    let branch_seed = args.u64("--branch-seed");
    let branch_id = args.string("--branch-id");
    let parent = args.string("--parent");
    if !args.flag("--branch") {
        if from_sequence.is_some()
            || branch_seed.is_some()
            || branch_id.is_some()
            || parent.is_some()
        {
            return Err(CliError::usage(
                "--from/--branch-seed/--branch-id/--parent require --branch",
            ));
        }
        return Ok(Mode::Replay {
            path,
            timeline: timeline.unwrap_or_else(|| "main".into()),
        });
    }
    if timeline.is_some() {
        return Err(CliError::usage(
            "--timeline selects a timeline to replay and is not valid with --branch",
        ));
    }
    Ok(Mode::Branch {
        path,
        parent: parent.unwrap_or_else(|| "main".into()),
        from_sequence: from_sequence
            .ok_or_else(|| CliError::usage("replay --branch requires --from"))?,
        branch_seed: branch_seed
            .ok_or_else(|| CliError::usage("replay --branch requires --branch-seed"))?,
        branch_id: branch_id
            .ok_or_else(|| CliError::usage("replay --branch requires --branch-id"))?,
    })
}

/// The `--timeline` selector, defaulting to `main`.
fn timeline_or_main(args: &cli::Args) -> String {
    args.string("--timeline")
        .unwrap_or_else(|| "main".to_string())
}

/// Every `PATINA_BUGGIFY*` control-plane variable, for the scrub that keeps an
/// ambient environment from enabling buggify in a run that did not ask for it.
pub(super) const BUGGIFY_ENV_VARS: &[&str] = &[
    ENV_BUGGIFY,
    ENV_BUGGIFY_ACTIVATION,
    ENV_BUGGIFY_CUTOFF,
    ENV_BUGGIFY_AFTER_SETUP,
];

/// The cooperative-SUT (buggify) control-plane pairs for the in-process WASI
/// runtime, mirroring the env vars the native family forwards to its subprocess.
/// Presence of `PATINA_BUGGIFY` (its value, possibly empty, being the firing
/// per-mille) enables buggify; the optional knobs follow.
pub(super) fn buggify_env_pairs(buggify: &NativeBuggify) -> Vec<(&'static str, String)> {
    let mut pairs = vec![(
        ENV_BUGGIFY,
        buggify.fire_permille.clone().unwrap_or_default(),
    )];
    if let Some(value) = &buggify.activation_permille {
        pairs.push((ENV_BUGGIFY_ACTIVATION, value.clone()));
    }
    if let Some(value) = &buggify.cutoff_nanos {
        pairs.push((ENV_BUGGIFY_CUTOFF, value.clone()));
    }
    if buggify.after_setup {
        pairs.push((ENV_BUGGIFY_AFTER_SETUP, "1".to_string()));
    }
    pairs
}

/// The exploration scheduling-policy and swarm control-plane pairs. Presence of
/// `PATINA_SCHED_PCT` enables PCT (its value, possibly empty, being the bug
/// depth); `PATINA_SCHED_STARVE` enables starvation; `PATINA_SWARM` enables
/// swarm fault-class selection. Mirrors [`knob_env_pairs`] so the native family
/// forwards them to the subprocess and the WASI/Cargo families to the in-process
/// runtime through the same protocol.
pub(super) fn schedule_env_pairs(schedule: &NativeSchedule) -> Vec<(&'static str, String)> {
    let mut pairs = Vec::new();
    if let Some(depth) = &schedule.pct {
        pairs.push((ENV_SCHED_PCT, depth.clone()));
        if let Some(steps) = &schedule.pct_steps {
            pairs.push((ENV_SCHED_PCT_STEPS, steps.clone()));
        }
    }
    if let Some(count) = &schedule.starve {
        pairs.push((ENV_SCHED_STARVE, count.clone()));
        if let Some(len) = &schedule.starve_max_len {
            pairs.push((ENV_SCHED_STARVE_MAX_LEN, len.clone()));
        }
        if let Some(window) = &schedule.starve_window {
            pairs.push((ENV_SCHED_STARVE_WINDOW, window.clone()));
        }
    }
    if schedule.swarm {
        pairs.push((ENV_SWARM, "1".to_string()));
    }
    pairs
}

/// The liveness-watchdog control-plane pairs, mirroring [`schedule_env_pairs`] so
/// the native family forwards them to the subprocess and the WASI/Cargo families
/// to the in-process runtime through the same `apply_liveness_env` protocol.
pub(super) fn liveness_env_pairs(liveness: &NativeLiveness) -> Vec<(&'static str, String)> {
    let mut pairs = Vec::new();
    if let Some(bound) = &liveness.compute_watchdog_ms {
        pairs.push(("PATINA_COMPUTE_WATCHDOG_MS", bound.clone()));
    }
    if let Some(budget) = &liveness.watchdog {
        pairs.push((ENV_LIVENESS_WATCHDOG, budget.clone()));
    }
    if let Some(budget) = &liveness.converge {
        pairs.push((ENV_CONVERGE_WITHIN, budget.clone()));
        if let Some(heal_after) = &liveness.heal_after {
            pairs.push((ENV_HEAL_AFTER, heal_after.clone()));
        }
    }
    pairs
}

/// Thin wrapper: treat the leading argument as an already-built binary. Used by
/// unit tests; `run` routing calls [`parse_native_run_from`] with a resolved ref.
#[cfg(test)]
pub(super) fn parse_native_run(
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
fn realtime_epoch_of(args: &cli::Args) -> Option<u64> {
    args.string("--realtime-epoch").map(|text| {
        values::utc_timestamp_nanos("--realtime-epoch", &text)
            .expect("the registry validated --realtime-epoch as a UtcTimestamp")
    })
}

/// Parse the flags of a native `run` given an already-resolved binary reference
/// (an existing binary or a build-on-the-fly spec). A trailing `-- ARGS` section
/// is the guest argument vector.
pub(super) fn parse_native_run_from(
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
    if target.is_none() {
        if let ArgKind::SourcePackage(manifest) = classify_arg(&origin)? {
            if package_integrates_patina(Some(&manifest), None) {
                let package_dir = cargo_package_dir(&origin)?;
                return parse_cargo_replay(package_dir, trace, flags);
            }
        }
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

/// Resolve a cargo-family `replay` positional to its package directory. The
/// origin must be a directory or a `Cargo.toml` (the shapes `resolve_positional`
/// classifies as the Cargo package family); anything else is neither an artifact
/// nor a package and is rejected naming the offending path.
fn cargo_package_dir(origin: &OsStr) -> Result<PathBuf, CliError> {
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
pub(super) fn parse_native_replay(
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

pub(super) fn parse_trace(
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

pub(super) fn parse_minimize(
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

fn normalize_cli_preopen_path(path: &str) -> String {
    if !path.starts_with('/') || path.contains('\0') {
        return path.to_owned();
    }
    let mut components = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => return path.to_owned(),
            component => components.push(component),
        }
    }
    if components.is_empty() {
        "/".to_owned()
    } else {
        format!("/{}", components.join("/"))
    }
}

#[cfg(test)]
mod tests;
