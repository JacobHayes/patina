//! Artifact classification, source selection, and positional scanning.

use super::*;

/// A compiled artifact's target family, inferred from its leading magic bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ArtifactFamily {
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
pub(super) fn extract_target(
    arguments: Vec<OsString>,
) -> Result<(Option<String>, Vec<OsString>), CliError> {
    let (found, rest) = cli::strip(&[cli::flag("run", "--target")], arguments)?;
    let target = cli::single(&found, "--target")?.map(|value| value.to_string_lossy().into_owned());
    Ok((target, rest))
}

/// Map a `--target` value to its artifact family.
pub(super) fn target_family(target: &str) -> Result<ArtifactFamily, CliError> {
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
pub(super) enum ArgKind {
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
pub(super) fn classify_arg(raw: &OsStr) -> Result<ArgKind, CliError> {
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
pub(super) struct SourceFirstSelection {
    pub(crate) package: Option<String>,
    pub(crate) bin: Option<String>,
    /// The flags with `--package`/`--bin` removed, handed to the family parser.
    pub(crate) rest: Vec<OsString>,
}

pub(super) fn take_package_bin(flags: Vec<OsString>) -> Result<SourceFirstSelection, CliError> {
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
pub(super) fn apply_package_selection(
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
pub(super) fn take_release(flags: Vec<OsString>) -> Result<(bool, Vec<OsString>), CliError> {
    let (found, rest) = cli::strip(&[cli::flag("run", "--release")], flags)?;
    Ok((found.contains_key("--release"), rest))
}

/// Apply a source-first `--release` to a build-on-the-fly artifact: it selects the
/// release profile for the guest `run` builds itself (default debug). Release is a
/// build profile, so it applies only to a source/package built on the fly; an
/// already-built artifact carries no profile of its own, so `--release` on a
/// prebuilt positional fails closed rather than being silently ignored.
pub(super) fn apply_release(artifact: &mut ArtifactRef, release: bool) -> Result<(), CliError> {
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
pub(super) fn resolve_positional(
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
pub(crate) fn package_integrates_patina(manifest: Option<&Path>, cwd: Option<&Path>) -> bool {
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

#[cfg(test)]
mod tests;
