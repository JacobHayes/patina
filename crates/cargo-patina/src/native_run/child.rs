//! Native child arguments, descriptors, spawning, and waiting.

use super::*;

/// Encode the guest program arguments (`argv[1..]`) as the JSON string array the
/// runtime records into the trace metadata. Recording requires UTF-8 arguments
/// (the trace bundle is UTF-8 JSON); a non-UTF-8 argument fails closed here,
/// before the guest runs, rather than corrupting the trace.
pub(super) fn encode_guest_argv(program_args: &[OsString]) -> Result<String, CliError> {
    let mut argv = Vec::with_capacity(program_args.len());
    for argument in program_args {
        let text = argument.to_str().ok_or_else(|| {
            CliError(format!(
                "cannot record the guest argument {argument:?}: --record requires UTF-8 guest \
arguments so they round-trip through the trace metadata"
            ))
        })?;
        argv.push(text.to_owned());
    }
    serde_json::to_string(&argv)
        .map_err(|error| CliError(format!("failed to encode guest arguments: {error}")))
}

/// Reconcile the guest arguments for a replay against the trace's recorded argv.
///
/// The trace records the `argv[1..]` it ran with, so a bare replay (no `--`
/// section) reproduces them and the operator need not re-pass the arguments —
/// fixing the incident where a divergent default argv caused a confusing mid-run
/// operation mismatch. If a `--` section IS supplied it must match the recording
/// byte-for-byte, otherwise the replay is refused UPFRONT naming both the
/// recorded and the passed arguments (a parse-time error, never a mid-run
/// divergence). A trace recorded before argv capture carries no recorded argv, so
/// the arguments are taken from the command line exactly as before — no new error
/// for old traces.
pub(super) fn reconcile_replay_argv(
    trace: &Path,
    bundle: &TraceBundle,
    passed: &[OsString],
) -> Result<Vec<OsString>, CliError> {
    let Some(recorded) = &bundle.metadata.guest_argv else {
        // Pre-argv trace: honor the historical contract (arguments from the
        // command line, and their absence behaves exactly as today).
        return Ok(passed.to_vec());
    };
    let recorded_os: Vec<OsString> = recorded.iter().map(OsString::from).collect();
    if passed.is_empty() || passed == recorded_os.as_slice() {
        Ok(recorded_os)
    } else {
        Err(CliError(format!(
            "replay guest-argument mismatch for {}: the trace recorded {recorded:?}, but the \
command line passed {passed:?} after `--`. Omit the `--` section to replay the recorded arguments, \
or pass them byte-for-byte identically.",
            trace.display()
        )))
    }
}

#[cfg(unix)]
pub(crate) struct InheritedFdGuard {
    saved: Vec<(i32, i32)>,
}

#[cfg(unix)]
impl InheritedFdGuard {
    pub(super) fn clear_cloexec(fds: &[i32]) -> Result<Self, CliError> {
        let mut saved = Vec::with_capacity(fds.len());
        for &fd in fds {
            // SAFETY: `fd` is an open descriptor owned by the supervisor.
            let flags = unsafe { fcntl(fd, F_GETFD, 0) };
            if flags < 0 {
                return Err(CliError(format!(
                    "failed to inspect inherited descriptor {fd}: {}",
                    io::Error::last_os_error()
                )));
            }
            saved.push((fd, flags));
            if flags & FD_CLOEXEC != 0 {
                // SAFETY: `F_SETFD` only updates descriptor flags on this fd.
                if unsafe { fcntl(fd, F_SETFD, flags & !FD_CLOEXEC) } < 0 {
                    return Err(CliError(format!(
                        "failed to make descriptor {fd} inheritable: {}",
                        io::Error::last_os_error()
                    )));
                }
                let cleared = unsafe { fcntl(fd, F_GETFD, 0) };
                if cleared < 0 || cleared & FD_CLOEXEC != 0 {
                    return Err(CliError(format!(
                        "failed to clear close-on-exec for descriptor {fd}: {}",
                        if cleared < 0 {
                            io::Error::last_os_error().to_string()
                        } else {
                            format!("descriptor flags are still {cleared}")
                        }
                    )));
                }
            }
        }
        Ok(Self { saved })
    }

    pub(super) fn restore(mut self) -> Result<(), CliError> {
        for (fd, flags) in self.saved.drain(..) {
            // SAFETY: Restore the exact descriptor flags saved before spawn.
            if unsafe { fcntl(fd, F_SETFD, flags) } < 0 {
                return Err(CliError(format!(
                    "failed to restore descriptor {fd} flags: {}",
                    io::Error::last_os_error()
                )));
            }
        }
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for InheritedFdGuard {
    fn drop(&mut self) {
        for (fd, flags) in self.saved.drain(..) {
            // Best-effort cleanup for early returns. Callers use `restore()` on
            // the normal path so restore errors can be reported explicitly.
            let _ = unsafe { fcntl(fd, F_SETFD, flags) };
        }
    }
}

#[cfg(unix)]
pub(super) fn spawn_native_child(
    command: &mut Command,
    binary: &Path,
    inherited_fds: &[i32],
) -> Result<(std::process::Child, InheritedFdGuard), CliError> {
    // Return the guard to the caller instead of restoring immediately: the
    // descriptor-inheritance contract is simple and conservative if the fds stay
    // inheritable for the whole child lifetime, and this supervisor process does
    // not spawn unrelated children while waiting for the guest.
    let guard = InheritedFdGuard::clear_cloexec(inherited_fds)?;
    let child = command.spawn().map_err(|error| {
        CliError(format!(
            "failed to run native program {}: {error}",
            binary.display()
        ))
    })?;
    Ok((child, guard))
}

#[cfg(unix)]
pub(crate) struct NativeChildStatus {
    pub(crate) exit_code: i32,
    pub(crate) signal: Option<i32>,
    pub(crate) core: bool,
}

#[cfg(unix)]
pub(crate) fn native_child_status(status: ExitStatus) -> NativeChildStatus {
    use std::os::unix::process::ExitStatusExt;

    if let Some(code) = status.code() {
        NativeChildStatus {
            exit_code: code,
            signal: None,
            core: false,
        }
    } else if let Some(signal) = status.signal() {
        NativeChildStatus {
            exit_code: 128 + signal,
            signal: Some(signal),
            core: status.core_dumped(),
        }
    } else {
        NativeChildStatus {
            exit_code: 2,
            signal: None,
            core: false,
        }
    }
}

pub(crate) const NATIVE_FS_CRASH_RESTART_EXIT: i32 = 112;

#[cfg(unix)]
pub(super) fn wait_native_child_once(
    command: &mut Command,
    binary: &Path,
    inherited_fds: &[i32],
) -> Result<(output::Captured, u32), CliError> {
    if output::capture_active() {
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        let (child, inherited_guard) = spawn_native_child(command, binary, inherited_fds)?;
        let host_pid = child.id();
        let output = child.wait_with_output().map_err(|error| {
            CliError(format!(
                "failed while waiting on native program {}: {error}",
                binary.display()
            ))
        })?;
        inherited_guard.restore()?;
        let NativeChildStatus {
            exit_code,
            signal,
            core,
        } = native_child_status(output.status);
        Ok((
            output::Captured {
                exit_code,
                stdout: output.stdout,
                stderr: output.stderr,
                captured: true,
                signal,
                core,
            },
            host_pid,
        ))
    } else {
        let (mut child, inherited_guard) = spawn_native_child(command, binary, inherited_fds)?;
        let host_pid = child.id();
        let status = child.wait().map_err(|error| {
            CliError(format!(
                "failed while waiting on native program {}: {error}",
                binary.display()
            ))
        })?;
        inherited_guard.restore()?;
        let NativeChildStatus {
            exit_code,
            signal,
            core,
        } = native_child_status(status);
        Ok((
            output::Captured {
                exit_code,
                stdout: Vec::new(),
                stderr: Vec::new(),
                captured: false,
                signal,
                core,
            },
            host_pid,
        ))
    }
}
