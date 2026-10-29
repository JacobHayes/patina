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

/// Classify a run/audit/replay/test positional argument. A built artifact is
/// recognized by leading magic bytes (used directly); an existing `.rs`,
/// directory, or `Cargo.toml` is a source/package to build; an existing file that
/// is neither, or a flag, is `Other`. A token that does not exist is a hard
/// error: every positional these verbs take names a file.
pub(super) fn classify_arg(raw: &OsStr) -> Result<ArgKind, CliError> {
    if raw.to_str().is_some_and(|value| value.starts_with('-')) {
        return Ok(ArgKind::Other);
    }
    let path = Path::new(raw);
    if path.is_dir() {
        return Ok(ArgKind::SourcePackage(native_manifest_path(path)));
    }
    if !path.is_file() {
        return Err(CliError::usage(format!("no such file: {}", path.display())));
    }
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
/// source/package on the fly: a directory/`Cargo.toml` resolves to a native
/// build-on-the-fly exactly like a `.rs` source, so a positional naming an
/// existing package is never reinterpreted as guest argv. Anything else is a
/// usage error naming the offending path.
pub(super) fn resolve_positional(verb: &str, raw: &OsStr) -> Result<ArtifactRef, CliError> {
    Ok(match classify_arg(raw)? {
        ArgKind::Artifact => ArtifactRef::Prebuilt(PathBuf::from(raw)),
        ArgKind::SourceFile(source) => ArtifactRef::Build(Box::new(native_source_spec(source))),
        ArgKind::SourcePackage(manifest) => {
            ArtifactRef::Build(Box::new(native_package_spec(PathBuf::from(raw), manifest)))
        }
        ArgKind::Other => {
            return Err(CliError::usage(format!(
                "{verb} target {} is neither a native binary nor a source/package to build",
                Path::new(raw).display()
            )));
        }
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
/// flag-looking token stops the scan — its arity is unknown, so the token after
/// it may be its value, and the verb's error names the flag instead of
/// misreading that value as the artifact. Non-flag tokens are the positionals, collected in
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

#[cfg(test)]
mod tests;
