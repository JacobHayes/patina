//! Deadline cleanup must never broaden a child group into a user-wide signal.
use std::io;

pub const SIGKILL: i32 = 9;
// ESRCH is 3 on both supported hosts (Linux and macOS).
pub const ESRCH: i32 = 3;

/// Kill only a group whose leader is a child spawned with `process_group(0)`.
/// The caller must retain that child's identity for the duration of cleanup.
pub fn kill(child_id: u32) -> io::Result<()> {
    signal_with(child_id, |target, signal| {
        unsafe extern "C" {
            #[link_name = "kill"]
            fn host_kill(pid: i32, signal: i32) -> i32;
        }
        // SAFETY: signal_with validates the target before this syscall. No
        // external command/parser or PATH lookup participates in cleanup.
        if unsafe { host_kill(target, signal) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    })
}

/// [`kill`] with the signal boundary supplied by the caller: `send` receives
/// the target and the signal, and is reached only for a valid child group.
pub fn signal_with(child_id: u32, send: impl FnOnce(i32, i32) -> io::Result<()>) -> io::Result<()> {
    let leader = i32::try_from(child_id)
        .ok()
        .filter(|pid| *pid > 1)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid child process group")
        })?;
    match send(-leader, SIGKILL) {
        // The child and its descendants can exit just before the deadline.
        Err(error) if error.raw_os_error() == Some(ESRCH) => Ok(()),
        result => result,
    }
}
