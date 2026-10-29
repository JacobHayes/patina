//! The build identity of the running `cargo-patina`.
//!
//! A recording depends on its supervisor as well as on its guest: the
//! supervisor builds the guest's initial state, its stack, environment block,
//! inherited descriptors and filesystem image, and decides which host traps it
//! arms. The package version cannot name that build, because it stays the same
//! across every development build of one release, so the supervisor is named by
//! the build ID its linker derived from the linked bytes (an ELF
//! `NT_GNU_BUILD_ID` note or a Mach-O `LC_UUID`), carried as the SHA-256 of
//! that ID. Reading the ID costs a header parse where hashing the executable
//! costs tens of milliseconds per run for a debug build. A byte-identical
//! rebuild keeps the ID; any other change gives a new one, including ones that
//! cannot change a run (help text, debug info). That conservative choice costs
//! a re-record, while one that accepted a stale supervisor would let a replay
//! pass that no longer means anything. An executable linked without a build ID
//! is named by the SHA-256 of its bytes instead.

use std::fs;
use std::io;
use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

use patina_dst_trace::Sha256Digest;
use sha2::{Digest, Sha256};

use crate::CliError;
use crate::run_cache::Image;

/// The environment variable a `cargo-patina` sets on the `cargo-patina`
/// children it runs (campaign generations, their verification replays, a
/// reduction's candidates): its own digest, which the child must match.
pub(crate) const ENV_EXPECTED_SUPERVISOR: &str = "PATINA_RT_EXPECTED_SUPERVISOR_SHA256";

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
/// The identity is read later, the first time it is needed, but from the
/// descriptor opened here, so a verb that never records pays nothing for it.
/// That descriptor pins the file this process started from: replacing the
/// executable by a rename, which is how cargo installs a rebuild, leaves it
/// naming the original. An in-place rewrite of the same file would still show
/// through it. A child told its parent's identity reads its own at once,
/// because it has to refuse before it runs anything.
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

/// The identity of the running `cargo-patina` executable, read from the
/// descriptor [`establish`] opened: the SHA-256 of its build ID, or of its
/// bytes when it carries none.
pub(crate) fn supervisor_sha256() -> Result<Sha256Digest, CliError> {
    DIGEST
        .get_or_init(|| {
            let image = image()?;
            let digest = match build_id_bytes(image) {
                Some(id) => Sha256::new()
                    .chain_update(b"cargo-patina build id\0")
                    .chain_update(&id)
                    .finalize(),
                None => Sha256::digest(image.bytes()),
            };
            Ok(Sha256Digest(digest.into()))
        })
        .clone()
        .map_err(CliError)
}

/// The build ID the linker gave the running `cargo-patina` (an ELF
/// `NT_GNU_BUILD_ID` note or a Mach-O `LC_UUID`), in hex: it names the
/// supervisor's run cache. `None` when it carries none.
pub(crate) fn build_id() -> Option<String> {
    build_id_bytes(image().ok()?).map(|id| crate::hex(&id))
}

fn build_id_bytes(image: &Image) -> Option<Vec<u8>> {
    let file = object::File::parse(image.bytes()).ok()?;
    let id = match object::Object::build_id(&file) {
        Ok(Some(id)) => id.to_vec(),
        _ => object::Object::mach_uuid(&file).ok()??.to_vec(),
    };
    (!id.is_empty()).then_some(id)
}

/// The running executable's bytes, mapped once from the descriptor
/// [`establish`] opened.
fn image() -> Result<&'static Image, String> {
    static IMAGE: OnceLock<Result<Image, String>> = OnceLock::new();
    IMAGE
        .get_or_init(|| {
            let (path, file) = executable().as_ref().map_err(Clone::clone)?;
            Image::map(file).map_err(|error| {
                format!(
                    "failed to read the running cargo-patina executable {} to compute its build \
                     identity: {error}",
                    path.display()
                )
            })
        })
        .as_ref()
        .map_err(Clone::clone)
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

/// Require a `cargo-patina` child to be this same build, and give it no
/// flag defaults from the operator's environment.
///
/// Every child this supervisor spawns is told exactly what to do by its argv:
/// a campaign generation's flags are recorded and replayed from the out-dir, a
/// reduction candidate's are the knob vector under test. An inherited
/// `PATINA_<FLAG>` would silently add a knob the parent never chose (a
/// `PATINA_BUGGIFY` turning buggify on in a generation recorded without it),
/// so the child sees none of them.
pub(crate) fn expect_this_supervisor(command: &mut Command) -> Result<(), CliError> {
    for name in crate::help::flag_env_names() {
        command.env_remove(name);
    }
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
