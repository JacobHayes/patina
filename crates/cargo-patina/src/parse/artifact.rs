//! Artifact classification, source selection, and positional scanning.

use super::*;

/// Whether `bytes` begin with native executable magic (Mach-O or ELF). Pure and
/// filesystem-free so it is unit-testable on byte slices; `false` for anything
/// else (a `Cargo.toml`, a shell script, an empty file, ...).
fn is_native_magic(bytes: &[u8]) -> bool {
    // ELF: 0x7F 'E' 'L' 'F'.
    if bytes.starts_with(&[0x7f, b'E', b'L', b'F']) {
        return true;
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
    MACH_O_MAGICS.iter().any(|magic| bytes.starts_with(magic))
}

/// Read the leading magic bytes of `path` and classify it with
/// [`is_native_magic`]. Only a short prefix is read, so a multi-megabyte native
/// binary is not slurped merely to route it.
fn is_native_binary(path: &Path) -> Result<bool, CliError> {
    use std::io::Read;
    let mut file = fs::File::open(path).map_err(|error| {
        CliError(format!(
            "failed to open artifact {}: {error}",
            path.display()
        ))
    })?;
    let mut prefix = [0u8; 4];
    let read = file.read(&mut prefix).map_err(|error| {
        CliError(format!(
            "failed to read artifact {}: {error}",
            path.display()
        ))
    })?;
    Ok(is_native_magic(&prefix[..read]))
}

/// How a run/audit/replay positional argument classifies. The single shared
/// resolution step (unit-tested via [`classify_arg`]) decides between using an
/// already-built artifact directly and building a source/package on the fly.
pub(super) enum ArgKind {
    /// An existing file with native Mach-O/ELF magic.
    Artifact,
    /// A single `.rs` source (built native).
    SourceFile(PathBuf),
    /// A directory or `Cargo.toml` (a Cargo package), resolved to its manifest.
    SourcePackage(PathBuf),
    /// A leading flag, or a plain non-source file: neither artifact nor source.
    Other,
}

/// Whether a positional token is unmistakably a filesystem path (so a
/// nonexistent one is a mistake to surface, not a plausible bare Cargo argument):
/// it names a `.rs`/`Cargo.toml`, or contains a path separator.
fn looks_like_path(raw: &OsStr) -> bool {
    let Some(text) = raw.to_str() else {
        // A non-UTF-8 token is never a bare Cargo argument; treat it as a path.
        return true;
    };
    text.ends_with(".rs")
        || Path::new(text).file_name() == Some(OsStr::new("Cargo.toml"))
        || text.contains('/')
        || text.contains(std::path::MAIN_SEPARATOR)
}

/// Classify a run/audit/replay positional argument. A built artifact is
/// recognized by leading magic bytes (used directly); an existing `.rs`,
/// directory, or `Cargo.toml` is a source/package to build; a bare name that does
/// not exist is `Other` (a plausible Cargo argument, left to the cargo family).
/// A token that clearly names a file path (`.rs`/`Cargo.toml`, or with a
/// separator) but does not exist is a hard error — fail closed rather than let
/// `run ./nonexistent` fall through to a confusing `cargo run` failure.
pub(super) fn classify_arg(raw: &OsStr) -> Result<ArgKind, CliError> {
    if raw.to_str().is_some_and(|value| value.starts_with('-')) {
        return Ok(ArgKind::Other);
    }
    let path = Path::new(raw);
    if path.is_dir() {
        return Ok(ArgKind::SourcePackage(native_manifest_path(path)));
    }
    if path.is_file() {
        if is_native_binary(path)? {
            return Ok(ArgKind::Artifact);
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
/// edition, debug, uninstrumented, no extra rustc args).
fn native_source_spec(source: PathBuf) -> BuildSpec {
    BuildSpec {
        origin: source.clone(),
        build: NativeBuildInvocation {
            target: NativeBuildTarget::Source {
                source,
                edition: DEFAULT_NATIVE_EDITION.to_string(),
                rustc_args: Vec::new(),
            },
            output: None,
            release: false,
            instrument: false,
        },
    }
}

/// Build spec for a native Cargo-package build on the fly. Binary selection is
/// automatic (fails closed on ambiguity, like the `build` verb).
fn native_package_spec(origin: PathBuf, manifest: PathBuf) -> BuildSpec {
    BuildSpec {
        origin,
        build: NativeBuildInvocation {
            target: NativeBuildTarget::Package {
                manifest,
                package: None,
                bin: None,
            },
            output: None,
            release: false,
            instrument: false,
        },
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
        ArtifactRef::Build(spec) => match &mut spec.build.target {
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
            NativeBuildTarget::Go { .. } => Err(CliError::usage(
                "--package and --bin apply to a Cargo-package build, not a Go package",
            )),
        },
        ArtifactRef::Prebuilt(_) => Err(CliError::usage(
            "--package and --bin select a member to build; they do not apply to an already-built artifact",
        )),
    }
}

/// Apply the `PATINA_PACKAGE`/`PATINA_BIN` environment defaults to a
/// Cargo-package build. A default fills only a selection nothing else made, and
/// only where a selection applies: unlike a typed flag, it is silently inert for
/// a single source, a Go package, or a prebuilt artifact.
pub(super) fn apply_env_package_selection(artifact: &mut ArtifactRef) -> Result<(), CliError> {
    if let ArtifactRef::Build(spec) = artifact
        && let NativeBuildTarget::Package { package, bin, .. } = &mut spec.build.target
    {
        if package.is_none() {
            *package = env_text(cli::flag("run", "--package"))?;
        }
        if bin.is_none() {
            *bin = env_text(cli::flag("run", "--bin"))?;
        }
    }
    Ok(())
}

/// Apply the `PATINA_RELEASE` environment default to a build on the fly; inert
/// for a prebuilt artifact, which has no build profile.
pub(super) fn apply_env_release(artifact: &mut ArtifactRef) -> Result<(), CliError> {
    if let ArtifactRef::Build(spec) = artifact
        && !spec.build.release
    {
        spec.build.release = cli::env_value(cli::flag("run", "--release"))?.is_some();
    }
    Ok(())
}

/// A text flag's environment default.
pub(super) fn env_text(flag: &'static help::Flag) -> Result<Option<String>, CliError> {
    Ok(cli::env_value(flag)?.map(|value| value.to_string_lossy().into_owned()))
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
            spec.build.release = true;
            Ok(())
        }
        ArtifactRef::Prebuilt(_) => Err(CliError::usage(
            "--release selects a build profile for a source/package built on the fly; an already-built artifact has no build profile",
        )),
    }
}

/// Resolve a run/audit/replay positional to an [`ArtifactRef`], building a
/// source/package on the fly. A directory/`Cargo.toml` resolves to a native
/// build-on-the-fly exactly like a `.rs` source — the SAME path `audit` uses, so
/// a positional naming an existing package is never silently reinterpreted as
/// guest argv. `None` is returned only when the positional is neither an
/// artifact nor a source (a leading flag or a plain file); the caller then falls
/// through to its no-artifact behavior. Whether a runtime-linked package is
/// instead kept on the cargo-family path is a routing decision the `run`/`replay`
/// callers make up front via [`package_integrates_patina`]; this resolver is pure
/// classification.
pub(super) fn resolve_positional(raw: &OsStr) -> Result<Option<ArtifactRef>, CliError> {
    Ok(match classify_arg(raw)? {
        ArgKind::Artifact => Some(ArtifactRef::Prebuilt(PathBuf::from(raw))),
        ArgKind::SourceFile(source) => {
            Some(ArtifactRef::Build(Box::new(native_source_spec(source))))
        }
        ArgKind::SourcePackage(manifest) => Some(ArtifactRef::Build(Box::new(
            native_package_spec(PathBuf::from(raw), manifest),
        ))),
        ArgKind::Other => None,
    })
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
        if let Some(text) = argument.to_str()
            && text.starts_with('-')
        {
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

/// Whether `raw` is an existing file whose magic bytes identify it as a native
/// binary. Such a file is NEVER the value of a cargo flag, so an unknown flag
/// standing in front of it is a misuse, not a forwarded flag with a value.
fn existing_compiled_artifact(raw: &OsStr) -> bool {
    let path = Path::new(raw);
    path.is_file() && matches!(is_native_binary(path), Ok(true))
}

/// Whether `raw` names an existing artifact or source/package (a compiled
/// binary, a `.rs` source, a `Cargo.toml`, or a directory) — anything the
/// positional resolver would route to a real family.
fn existing_artifact_or_source(raw: &OsStr) -> bool {
    matches!(
        classify_arg(raw),
        Ok(ArgKind::Artifact | ArgKind::SourceFile(_) | ArgKind::SourcePackage(_))
    )
}

/// Whether `raw` is a path-like token (`.rs`/`Cargo.toml`, or with a
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
/// and the native family rejects an unknown flag anyway, so a real artifact
/// after it can only be a misuse); otherwise `Ok(())` lets the caller forward the
/// list to its no-artifact family. The token immediately after an unknown flag is
/// that flag's presumed value (`--manifest-path ./x/Cargo.toml`) and is exempt
/// UNLESS it is a compiled artifact, which is never a flag value. Only the
/// verbs with a Cargo package family (`run`, `test`) forward unknown flags, so
/// only they need this; every other verb's parser refuses the flag by name.
pub(crate) fn reject_stranded_artifact(verb: &str, tail: &[OsString]) -> Result<(), CliError> {
    let unknown = tail.first().cloned().unwrap_or_default();
    let mut index = 0;
    let mut after_unknown_flag = false;
    while index < tail.len() {
        let argument = &tail[index];
        if argument == "--" {
            break;
        }
        if let Some(text) = argument.to_str()
            && text.starts_with('-')
        {
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
