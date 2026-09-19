#![cfg(any(target_os = "linux", target_os = "macos"))]
mod common;

use common::native::{
    assert_fields, assert_required_sud, assert_thread_counts, assert_thread_ids,
    assert_unique_line_payload,
};
use std::time::Duration;

#[test]
fn output_parsers_reject_missing_duplicate_and_malformed_fields() {
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
}

#[test]
fn deadline_drains_both_pipes_beyond_pipe_capacity() {
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
}

#[test]
fn deadline_kills_descendants_holding_output_pipes() {
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

#[test]
fn required_sud_rejects_missing_capability() {
    assert_required_sud(true, Some("1"));
    assert_required_sud(false, None);
    assert_required_sud(false, Some("0"));
    let panic = std::panic::catch_unwind(|| assert_required_sud(false, Some("1")))
        .expect_err("required SUD must reject a missing capability");
    let message = panic
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| panic.downcast_ref::<&str>().copied())
        .unwrap();
    assert!(message.contains("PATINA_REQUIRE_SUD=1"));
}
