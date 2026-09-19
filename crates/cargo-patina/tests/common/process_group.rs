//! Deadline cleanup must never broaden a child group into a user-wide signal.
use std::io;

const SIGKILL: i32 = 9;
// ESRCH is 3 on both supported hosts (Linux and macOS).
const ESRCH: i32 = 3;

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

fn signal_with(child_id: u32, send: impl FnOnce(i32, i32) -> io::Result<()>) -> io::Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;

    // Class-level pairing: deadline containment (docs/agent-operations.md).
    // These tests intercept the syscall boundary; even a broken selector never
    // sends real signals to the test host.
    #[test]
    fn rejects_broadcast_current_group_and_overflow_before_signaling() {
        for id in [0, 1, i32::MAX as u32 + 1, u32::MAX] {
            let mut called = false;
            let result = signal_with(id, |_, _| {
                called = true;
                Ok(())
            });
            assert!(!called, "invalid group {id} reached the signal boundary");
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn targets_only_the_validated_child_group() {
        for id in [2, 1016800, i32::MAX as u32] {
            let mut observed = None;
            signal_with(id, |target, signal| {
                observed = Some((target, signal));
                Ok(())
            })
            .unwrap();
            assert_eq!(observed, Some((-(id as i32), SIGKILL)));
        }
    }

    #[test]
    fn only_an_already_exited_group_is_tolerated() {
        signal_with(42, |_, _| Err(io::Error::from_raw_os_error(ESRCH))).unwrap();
        for errno in [1, 22] {
            let error =
                signal_with(42, |_, _| Err(io::Error::from_raw_os_error(errno))).unwrap_err();
            assert_eq!(error.raw_os_error(), Some(errno));
        }
    }
}
