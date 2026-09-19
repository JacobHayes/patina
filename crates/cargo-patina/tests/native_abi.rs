//! ABI-door and scheduler integration pins. Unlike the Linux host-oracle
//! probes these also execute on macOS and Linux arm64, and pin virtual time.
#![cfg(any(target_os = "linux", target_os = "macos"))]
mod common;
use common::native::*;

#[test]
fn prefixed_c_abi_preserves_crash_checkpoint() {
    let g = assert_build_c_guest("probe.c", CLink::Shim);
    let first = assert_standalone_success(&g.binary, &["123"], &[]).stdout;
    assert_eq!(
        first,
        assert_standalone_success(&g.binary, &["123"], &[]).stdout
    );
    let fields = assert_fields(
        &first,
        "NATIVE_SHIM_RESULT ",
        &["seed", "random", "before", "after", "contents"],
    );
    assert_eq!(fields["seed"], "123");
    assert_lower_hex(fields["random"], 32);
    assert_eq!(fields["before"], "0");
    assert_eq!(fields["after"], "5000000");
    assert_eq!(fields["contents"], "stable");
    let other = assert_standalone_success(&g.binary, &["124"], &[]).stdout;
    let other = assert_fields(
        &other,
        "NATIVE_SHIM_RESULT ",
        &["seed", "random", "before", "after", "contents"],
    );
    assert_ne!(
        fields["random"], other["random"],
        "entropy must vary, not just the printed seed"
    );
}

#[test]
fn prefixed_c_env_protocol_records_and_replays_without_seed() {
    let g = assert_build_c_guest("probe.c", CLink::Shim);
    let trace = g.dir.path().join("env.patina");
    let env = [
        ("PATINA_MODE", "record"),
        ("PATINA_SEED", "123"),
        ("PATINA_TRACE", trace.to_str().unwrap()),
        ("PATINA_FINGERPRINT", "c-abi-v1"),
    ];
    let record = assert_standalone_success(&g.binary, &["env"], &env).stdout;
    let replay_env = [
        ("PATINA_MODE", "replay"),
        ("PATINA_TRACE", trace.to_str().unwrap()),
        ("PATINA_FINGERPRINT", "c-abi-v1"),
    ];
    assert_eq!(
        record,
        assert_standalone_success(&g.binary, &["env"], &replay_env).stdout
    );
}

#[test]
fn posix_descriptors_and_environment_are_virtualized() {
    let g = assert_build_c_guest("posix_probe.c", CLink::PosixShim);
    assert_standalone_success(
        &g.binary,
        &[],
        &[
            ("HOST_CANARY", "must-not-leak"),
            ("PATINA_HOST_CANARY", "must-not-leak"),
        ],
    );
}

#[test]
fn posix_at_paths_resolve_relative_to_directory_fds() {
    let g = assert_build_c_guest("openat_probe.c", CLink::PosixShim);
    let first = assert_standalone_success(&g.binary, &["5"], &[]).stdout;
    assert_eq!(
        first,
        assert_standalone_success(&g.binary, &["5"], &[]).stdout
    );
    assert_eq!(
        text(&first),
        "NATIVE_OPENAT_RESULT seed=5 contents=openat\n"
    );
}

#[test]
fn realpath_buffer_conventions_agree() {
    let g = assert_build_c_guest("realpath_probe.c", CLink::PosixShim);
    let first = assert_standalone_success(&g.binary, &["5"], &[]).stdout;
    assert_eq!(
        first,
        assert_standalone_success(&g.binary, &["5"], &[]).stdout
    );
    assert_eq!(
        text(&first),
        "NATIVE_REALPATH_RESULT seed=5 canonical=/root/fragments\n"
    );
}

#[test]
fn libc_at_calls_are_interposed_and_replayable() {
    let g = Guest::assert_build("at_family_probe.rs");
    let audit = g.assert_audit_clean();
    for symbol in ["symlinkat", "readlinkat"] {
        assert!(!text(&audit.stdout).contains(symbol));
    }
    g.assert_no_imports(&["symlinkat", "readlinkat"]);
    assert_eq!(
        text(&g.assert_seeded_record_replay_identity(1, &[])),
        "NATIVE_LIBC_AT_RESULT link=target.txt read=pointed-at abs=/state/target.txt\n"
    );
}

#[test]
fn std_file_clone_shares_cursor() {
    let g = Guest::assert_build("dup_probe.rs");
    g.assert_audit_clean();
    assert_eq!(
        text(&g.assert_seeded_record_replay_identity(3, &[])),
        "NATIVE_DUP_RESULT head=abc rest=def mid=bc\n"
    );
}

fn assert_repeated_output(g: &Guest, seeds: &[u64], expected: &str) {
    assert!(!seeds.is_empty(), "at least one seed must be checked");
    g.assert_audit_clean();
    for &seed in seeds {
        assert_eq!(text(&g.assert_seed_repeatability(seed, 2, &[])), expected);
    }
}

#[test]
fn pipe_reader_is_woken_by_writer_thread() {
    let g = Guest::assert_build("pipe_probe.rs");
    let expected = "NATIVE_PIPE_RESULT got=ping-pong\n";
    assert_repeated_output(&g, &[1, 2], expected);
    g.assert_record_replay_identity(1, &[], expected.as_bytes());
}

#[test]
fn socketpair_transfers_in_both_directions() {
    let g = Guest::assert_build("socketpair_probe.rs");
    let expected = "NATIVE_SOCKETPAIR_RESULT reply=PING\n";
    assert_repeated_output(&g, &[1, 2], expected);
    g.assert_record_replay_identity(1, &[], expected.as_bytes());
}

#[test]
fn closed_pipe_returns_epipe_without_sigpipe() {
    let g = Guest::assert_build("pipe_epipe_probe.rs");
    assert_repeated_output(&g, &[1], "NATIVE_PIPE_EPIPE_RESULT epipe=true eof=true\n");
}

#[test]
fn nonblocking_pipes_return_eagain() {
    let g = Guest::assert_build("pipe_nonblock_probe.rs");
    assert_repeated_output(&g, &[1], "NATIVE_PIPE_NONBLOCK_RESULT ok=true\n");
}

#[test]
fn pipe_aliases_keep_channels_alive() {
    let g = Guest::assert_build("pipe_dup_probe.rs");
    assert_repeated_output(
        &g,
        &[1],
        "NATIVE_PIPE_DUP_RESULT ok=true eof=true epipe=true\n",
    );
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    #[test]
    fn epoll_wakes_readers_and_refires_edges() {
        let g = Guest::assert_build("epoll_probe.rs");
        let expected = "NATIVE_EPOLL_RESULT latched=0 refired=1\n";
        assert_repeated_output(&g, &[1, 2], expected);
        g.assert_record_replay_identity(1, &[], expected.as_bytes());
    }

    #[test]
    fn eventfd_writer_wakes_epoll_waiter() {
        let g = Guest::assert_build("eventfd_probe.rs");
        assert_repeated_output(
            &g,
            &[1],
            "NATIVE_EVENTFD_RESULT woke=1 refired=1 sem_ok=true\n",
        );
    }

    #[test]
    fn epoll_timeout_advances_exact_virtual_time() {
        let g = Guest::assert_build("epoll_timeout_probe.rs");
        assert_repeated_output(&g, &[1], "NATIVE_EPOLL_TIMEOUT timeout_ms=50\n");
    }
}

#[cfg(target_os = "macos")]
mod darwin {
    use super::*;
    #[test]
    fn kqueue_reports_fields_and_wakes_reader() {
        let g = Guest::assert_build("kqueue_probe.rs");
        let expected = "NATIVE_KQUEUE_RESULT got=ping\n";
        assert_repeated_output(&g, &[1, 2], expected);
        g.assert_record_replay_identity(1, &[], expected.as_bytes());
    }

    #[test]
    fn kqueue_user_events_wake_and_timeout_exactly() {
        let g = Guest::assert_build("kqueue_user_probe.rs");
        assert_repeated_output(
            &g,
            &[1],
            "NATIVE_KQUEUE_USER_TIMEOUT user_ok=true timeout_ms=50\n",
        );
    }

    #[test]
    fn clock_nsec_matches_clock_gettime() {
        let g = Guest::assert_build("clock_nsec_probe.rs");
        g.assert_audit_clean();
        let out = g.assert_seed_repeatability(1, 2, &[]);
        let fields = assert_fields(&out, "CLOCK_NSEC_RESULT ", &["mono_ns", "real_ns"]);
        for value in fields.values() {
            assert!(
                value.bytes().all(|b| b.is_ascii_digit()),
                "nanosecond value: {value}"
            );
            value.parse::<u64>().expect("u64 nanoseconds");
        }
    }
}
