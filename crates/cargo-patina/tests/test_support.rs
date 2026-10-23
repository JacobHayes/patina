#![cfg(any(target_os = "linux", target_os = "macos"))]
mod common;

use common::native::{
    assert_fields, assert_required_sud, assert_thread_counts, assert_thread_ids,
    assert_unique_line_payload,
};
use std::time::Duration;

#[test]
fn output_parsers_and_the_sud_requirement_reject_bad_input() {
    let fields = assert_fields(b"RESULT a=1 b=2\n", "RESULT ", &["a", "b"]);
    assert_eq!(fields["a"], "1");
    for bad in [
        "RESULT a=1 a=2\n",
        "RESULT a=1\n",
        "RESULT a=1 b\n",
        "RESULT a=1 b=\n",
    ] {
        assert!(
            std::panic::catch_unwind(|| assert_fields(bad.as_bytes(), "RESULT ", &["a", "b"]))
                .is_err()
        );
    }
    for bad in ["OTHER x\n", "RESULT x\nRESULT y\n"] {
        assert!(
            std::panic::catch_unwind(|| assert_unique_line_payload(bad.as_bytes(), "RESULT "))
                .is_err()
        );
    }
    assert_thread_counts(
        assert_thread_ids(b"ORDER [0, 1, 2, 2, 1, 0]\n", "ORDER "),
        3,
        2,
    );
    assert!(std::panic::catch_unwind(|| assert_thread_counts([0, 0, 1], 3, 1)).is_err());
    assert!(std::panic::catch_unwind(|| assert_thread_counts([0, 1, 3], 3, 1)).is_err());
    assert!(
        std::panic::catch_unwind(|| assert_thread_ids(b"ORDER [0, broken]\n", "ORDER ")).is_err()
    );
    assert_required_sud(true, Some("1"));
    assert_required_sud(false, None);
    assert_required_sud(false, Some("0"));
    assert!(
        std::panic::catch_unwind(|| assert_required_sud(false, Some("1"))).is_err(),
        "required SUD must reject a missing capability"
    );
}

#[test]
fn deadline_drains_large_output_and_kills_lingering_descendants() {
    let out = common::invoke_with_deadline(
        "/bin/sh",
        common::native_workspace(),
        &[
            "-c",
            "head -c 131072 /dev/zero; head -c 131072 /dev/zero >&2",
        ],
        Duration::from_secs(2),
    )
    .expect("large output must not be mistaken for a guest deadlock");
    let out = common::assert_success(out);
    assert_eq!(out.stdout, vec![0; 131072]);
    assert_eq!(out.stderr, vec![0; 131072]);
    // A descendant holding the output pipes is killed at the deadline.
    assert!(
        common::invoke_with_deadline(
            "/bin/sh",
            common::native_workspace(),
            &["-c", "sleep 30 & wait"],
            Duration::from_millis(100),
        )
        .is_none()
    );
}

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
