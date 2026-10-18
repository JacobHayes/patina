//! The build identity of the running `cargo-patina`.
//!
//! A recording depends on its supervisor as well as on its guest: the
//! supervisor builds the guest's initial state, its stack, environment block,
//! inherited descriptors and filesystem image, and decides which host traps it
//! arms. The package version cannot name that build, because it stays the same
//! across every development build of one release, so the supervisor is named by
//! the SHA-256 of its own executable. A byte-identical rebuild keeps the digest;
//! any other change gives a new one, including ones that cannot change a run
//! (help text, debug info). That conservative choice costs a re-record, while
//! one that accepted a stale supervisor would let a replay pass that no longer
//! means anything.

use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use patina_dst_trace::Sha256Digest;
use sha2::{Digest, Sha256};

use crate::CliError;

/// The environment variable a `cargo-patina` sets on the `cargo-patina`
/// children it runs (campaign generations, their verification replays, a
/// reduction's candidates): its own digest, which the child must match.
pub(crate) const ENV_EXPECTED_SUPERVISOR: &str = "PATINA_EXPECTED_SUPERVISOR_SHA256";

/// The prefix of the refusal a child prints when it is another build than the
/// `cargo-patina` that ran it. The parent stops on it rather than filing the
/// child's result.
pub(crate) const SUPERVISOR_MISMATCH: &str = "PATINA_INFRA supervisor_mismatch";

/// The running executable, opened once, with the path it was opened by.
static EXECUTABLE: OnceLock<Result<(PathBuf, fs::File), String>> = OnceLock::new();
static DIGEST: OnceLock<Result<Sha256Digest, String>> = OnceLock::new();

/// Open the running executable, and refuse to run as a child of another
/// `cargo-patina` build. Called first thing in the entry point, before any
/// build or launch.
///
/// The digest is computed later, the first time it is needed, but from the
/// descriptor opened here, so a verb that never records pays nothing for it.
/// That descriptor pins the file this process started from: replacing the
/// executable by a rename, which is how cargo installs a rebuild, leaves it
/// naming the original. An in-place rewrite of the same file would still show
/// through it. A child told its parent's digest hashes at once, because it has
/// to refuse before it runs anything.
pub(crate) fn establish() -> Result<(), CliError> {
    executable()
        .as_ref()
        .map_err(|error| CliError(error.clone()))?;
    if let Some(expected) = std::env::var_os(ENV_EXPECTED_SUPERVISOR) {
        let own = supervisor_sha256()?;
        if expected.to_str() != Some(own.to_string().as_str()) {
            return Err(CliError(format!(
                "{SUPERVISOR_MISMATCH}: this cargo-patina is {own}, but the cargo-patina that \
                 launched it is {}; its executable was replaced while it ran, so this run would \
                 not be comparable with the ones before it.",
                expected.to_string_lossy()
            )));
        }
    }
    Ok(())
}

/// The SHA-256 of the running `cargo-patina` executable, hashed once, from the
/// descriptor [`establish`] opened.
pub(crate) fn supervisor_sha256() -> Result<Sha256Digest, CliError> {
    DIGEST
        .get_or_init(|| {
            let (path, file) = executable().as_ref().map_err(Clone::clone)?;
            stream_sha256(file).map_err(|error| {
                format!(
                    "failed to read the running cargo-patina executable {} to compute its build \
                     identity: {error}",
                    path.display()
                )
            })
        })
        .clone()
        .map_err(CliError)
}

fn executable() -> &'static Result<(PathBuf, fs::File), String> {
    EXECUTABLE.get_or_init(|| {
        let path = running_executable().map_err(|error| {
            format!("failed to locate the running cargo-patina executable: {error}")
        })?;
        let file = fs::File::open(&path).map_err(|error| {
            format!(
                "failed to open the running cargo-patina executable {}: {error}",
                path.display()
            )
        })?;
        Ok((path, file))
    })
}

/// Require a `cargo-patina` child to be this same build.
pub(crate) fn expect_this_supervisor(command: &mut Command) -> Result<(), CliError> {
    command.env(ENV_EXPECTED_SUPERVISOR, supervisor_sha256()?.to_string());
    Ok(())
}

/// The refusal a child printed because it is another build, if it did.
pub(crate) fn supervisor_mismatch<'a>(stdout: &'a str, stderr: &'a str) -> Option<&'a str> {
    stderr
        .lines()
        .chain(stdout.lines())
        .find(|line| line.contains(SUPERVISOR_MISMATCH))
}

/// The file the kernel is executing. On Linux this is the process's own image
/// even when its path was replaced or unlinked after it started; elsewhere it
/// is the path the process was started by.
#[cfg(target_os = "linux")]
fn running_executable() -> io::Result<PathBuf> {
    Ok(PathBuf::from("/proc/self/exe"))
}

#[cfg(not(target_os = "linux"))]
fn running_executable() -> io::Result<PathBuf> {
    std::env::current_exe()
}

/// Stream `path` through SHA-256 in a bounded window, so hashing a large
/// executable adds no memory pressure of its own.
pub(crate) fn file_sha256(path: &Path) -> io::Result<Sha256Digest> {
    stream_sha256(&fs::File::open(path)?)
}

fn stream_sha256(mut file: &fs::File) -> io::Result<Sha256Digest> {
    let mut hasher = Sha256::new();
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        let read = file.read(&mut chunk)?;
        if read == 0 {
            return Ok(Sha256Digest(hasher.finalize().into()));
        }
        hasher.update(&chunk[..read]);
    }
}
