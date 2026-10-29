#![cfg(any(target_os = "linux", target_os = "macos"))]
mod common;

/// Deadline cleanup never broadens a child group into a user-wide signal. The
/// signal boundary is intercepted, so even a broken selector signals nothing.
#[test]
fn deadline_cleanup_signals_only_a_validated_child_group() {
    use common::process_group::{ESRCH, SIGKILL, signal_with};
    use std::io;
    for id in [0, 1, i32::MAX as u32 + 1, u32::MAX] {
        let mut called = false;
        let result = signal_with(id, |_, _| {
            called = true;
            Ok(())
        });
        assert!(!called, "invalid group {id} reached the signal boundary");
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }
    for id in [2, 1016800, i32::MAX as u32] {
        let mut observed = None;
        signal_with(id, |target, signal| {
            observed = Some((target, signal));
            Ok(())
        })
        .unwrap();
        assert_eq!(observed, Some((-(id as i32), SIGKILL)));
    }
    signal_with(42, |_, _| Err(io::Error::from_raw_os_error(ESRCH))).unwrap();
    for errno in [1, 22] {
        let error = signal_with(42, |_, _| Err(io::Error::from_raw_os_error(errno))).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(errno));
    }
}
