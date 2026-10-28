//! A `cargo-patina` child dies with the `cargo-patina` that ran it.
//!
//! A parent that runs `cargo-patina` children (campaign generations, their
//! verification reruns, a reduction's candidate replays) holds the write end of
//! one pipe for as long as it lives, and hands each child the read end. Nothing
//! is ever written: the child's watcher blocks reading it, and the read returns
//! end-of-file once the last write end is closed, which the kernel does when the
//! parent exits however it exits, SIGKILL included. The child then kills its own
//! process group, and its guest with it. Descriptor teardown at exit is the same
//! on Linux and macOS, so the one mechanism serves both, without polling.
//!
//! Without it a killed campaign leaves its in-flight generation running with no
//! timeout backstop, beside the `--resume` that re-runs the same generation into
//! the same coverage map and host mounts.

use std::process::Command;

use crate::CliError;

/// The environment variable naming the inherited read end in a child.
const ENV_LIFELINE_FD: &str = "PATINA_LIFELINE_FD";

#[cfg(unix)]
const SIGKILL: i32 = 9;

#[cfg(unix)]
unsafe extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}

/// Tie `command`'s process to this one: it runs in a process group of its own,
/// which it kills once this process is gone.
#[cfg(unix)]
pub(crate) fn tie(command: &mut Command) -> Result<(), CliError> {
    use std::os::fd::{AsRawFd, OwnedFd};
    use std::os::unix::process::CommandExt;
    use std::sync::OnceLock;

    /// Both ends, opened close-on-exec, and never closed in this process: the
    /// write end must outlive every child, and the read end is the one each
    /// child inherits.
    static PIPE: OnceLock<Result<(OwnedFd, OwnedFd), String>> = OnceLock::new();
    let (read, _write) = PIPE
        .get_or_init(|| {
            std::io::pipe()
                .map(|(read, write)| (read.into(), write.into()))
                .map_err(|error| error.to_string())
        })
        .as_ref()
        .map_err(|error| CliError(format!("failed to create a child run's lifeline: {error}")))?;
    let fd = read.as_raw_fd();
    // The child's group is what it kills, so it must be its own.
    command
        .process_group(0)
        .env(ENV_LIFELINE_FD, fd.to_string());
    // SAFETY: `fcntl` is async-signal-safe, and clearing close-on-exec here
    // touches only the forked child's descriptor table, so the read end reaches
    // this child alone and the write end (still close-on-exec) never does.
    unsafe {
        command.pre_exec(move || {
            if crate::fcntl(fd, crate::F_SETFD, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn tie(_command: &mut Command) -> Result<(), CliError> {
    Ok(())
}

/// In a child [`tie`] started, watch the lifeline, and kill this process group
/// once the parent is gone. Called first in the entry point, before this
/// process starts a thread or runs anything.
#[cfg(unix)]
pub(crate) fn watch() -> Result<(), CliError> {
    use std::io::Read;
    use std::os::fd::FromRawFd;

    let Some(value) = std::env::var_os(ENV_LIFELINE_FD) else {
        return Ok(());
    };
    // SAFETY: no other thread exists yet to read the environment concurrently.
    // Removed so nothing this process runs mistakes another descriptor for it.
    unsafe { std::env::remove_var(ENV_LIFELINE_FD) };
    let fd = value
        .to_str()
        .and_then(|value| value.parse::<i32>().ok())
        .filter(|fd| *fd >= 0)
        .ok_or_else(|| CliError(format!("{ENV_LIFELINE_FD} is not a descriptor: {value:?}")))?;
    // Close-on-exec from here on, so the guest and any build never inherit it.
    // SAFETY: `F_SETFD` only updates this descriptor's flags; it fails on a
    // descriptor that is not open.
    if unsafe { crate::fcntl(fd, crate::F_SETFD, crate::FD_CLOEXEC) } == -1 {
        return Err(CliError(format!(
            "the lifeline descriptor {fd} the parent run passed is not open: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: the descriptor is open, inherited for this purpose alone, and
    // owned by the watcher from here on.
    let mut lifeline = unsafe { std::fs::File::from_raw_fd(fd) };
    std::thread::Builder::new()
        .name("patina-lifeline".into())
        .spawn(move || {
            let mut byte = [0u8; 1];
            // Nothing is ever written, so any return but an interrupted one
            // means the parent is gone (or the descriptor broke, which is
            // treated the same rather than leaving the run untied).
            while let Err(error) = lifeline.read(&mut byte) {
                if error.kind() != std::io::ErrorKind::Interrupted {
                    break;
                }
            }
            // SAFETY: `tie` put this process in a group of its own, so 0 names
            // exactly this run and the processes it started.
            unsafe { kill(0, SIGKILL) };
        })
        .map_err(|error| CliError(format!("failed to start the lifeline watcher: {error}")))?;
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn watch() -> Result<(), CliError> {
    Ok(())
}
