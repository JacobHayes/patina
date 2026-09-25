//! Ecosystem and std lowering: every fixture is independently targetable.
#![cfg(any(target_os = "linux", target_os = "macos"))]
mod common;
use common::native::*;

#[test]
fn std_runs_seeded_and_replayable_but_not_standalone() {
    let g = Guest::assert_build("std_probe.rs");
    g.assert_audit_clean();
    assert_success(g.command("audit", &["--allow", "dlsym"]));
    let standalone = std::process::Command::new(&g.binary)
        .env_clear()
        .output()
        .unwrap();
    assert_refused(standalone, &["must run under"]);
    let out = g.assert_seeded_record_replay_identity(9, &[]);
    assert_exact_line(&out, "PATINA_STRACE_MARKER");
    let fields = assert_fields(
        &out,
        "NATIVE_STD_RESULT ",
        &["epoch_ns", "first_hash", "second_hash", "fs"],
    );
    assert_eq!(
        fields["epoch_ns"],
        patina_dst_time_virtual::DEFAULT_REALTIME_EPOCH_NANOS.to_string()
    );
    assert_lower_hex(fields["first_hash"], 16);
    assert_lower_hex(fields["second_hash"], 16);
    assert_eq!(fields["fs"], "link:symlink,nested:dir,value:file");
    g.assert_seed_variation(&[9, 10], &[]);
}

#[test]
fn realtime_epoch_defaults_overrides_and_replays_flag_free() {
    const TEXT: &str = "2001-09-09T01:46:40Z";
    let g = Guest::assert_build("realtime_epoch_probe.rs");
    g.assert_audit_clean();
    let default = g.assert_run_success(3, &[]).stdout;
    let fields = assert_fields(
        &default,
        "NATIVE_REALTIME_EPOCH_RESULT ",
        &["epoch_ns", "mtime_ns"],
    );
    assert_eq!(
        fields["epoch_ns"],
        patina_dst_time_virtual::DEFAULT_REALTIME_EPOCH_NANOS.to_string()
    );

    // The flag moves the guest's wall clock, is recorded into the trace, and a
    // flag-free replay reproduces it (the identity helper replays flag-free).
    let flags = ["--realtime-epoch", TEXT];
    let baseline = g.assert_seed_repeatability(3, 2, &flags);
    let fields = assert_fields(
        &baseline,
        "NATIVE_REALTIME_EPOCH_RESULT ",
        &["epoch_ns", "mtime_ns"],
    );
    assert_eq!(fields["epoch_ns"], "1000000000000000000");
    let trace = g.assert_record_replay_identity(3, &flags, &baseline);
    assert_eq!(
        patina_dst_trace::TraceBundle::load(&trace)
            .unwrap()
            .metadata
            .realtime_epoch_nanos,
        1_000_000_000_000_000_000
    );
    assert_refused(
        g.command(
            "replay",
            &[trace.to_str().unwrap(), "--realtime-epoch", TEXT],
        ),
        &["--realtime-epoch"],
    );
}

const HOSTNAME_KEYS: [&str; 5] = ["hostname", "nodename", "sysname", "release", "machine"];

/// The rest of `uname` is the platform's modeled kernel, whatever the node
/// name: Linux at the virtual ABI level, or the modeled Darwin release, on the
/// build's machine — never the host's release.
fn assert_virtual_kernel(fields: &std::collections::BTreeMap<&str, &str>) {
    let arch = std::env::consts::ARCH;
    if cfg!(target_os = "macos") {
        assert_eq!(fields["sysname"], "Darwin");
        assert_eq!(fields["release"], patina_dst_syscalls::DARWIN_RELEASE);
        let machine = if arch == "aarch64" { "arm64" } else { arch };
        assert_eq!(fields["machine"], machine);
    } else {
        assert_eq!(fields["sysname"], "Linux");
        assert_eq!(
            patina_dst_syscalls::parse_release(fields["release"]),
            patina_dst_syscalls::parse_release(patina_dst_syscalls::VIRTUAL_ABI)
        );
        assert_eq!(fields["machine"], arch);
    }
}

#[test]
fn hostname_defaults_overrides_and_replays_flag_free() {
    const NAME: &str = "db-1.internal";
    let g = Guest::assert_build("hostname_probe.rs");
    g.assert_audit_clean();
    let default = g.assert_run_success(3, &[]).stdout;
    let fields = assert_fields(&default, "NATIVE_HOSTNAME_RESULT ", &HOSTNAME_KEYS);
    assert_eq!(fields["hostname"], patina_dst_syscalls::IDENTITY_HOSTNAME);
    assert_eq!(fields["nodename"], patina_dst_syscalls::IDENTITY_HOSTNAME);
    assert_virtual_kernel(&fields);

    // The flag renames the virtual machine for both readers, is recorded into
    // the trace, and a flag-free replay reproduces it (the identity helper
    // replays flag-free).
    let flags = ["--hostname", NAME];
    let baseline = g.assert_seed_repeatability(3, 2, &flags);
    let fields = assert_fields(&baseline, "NATIVE_HOSTNAME_RESULT ", &HOSTNAME_KEYS);
    assert_eq!(fields["hostname"], NAME);
    assert_eq!(fields["nodename"], NAME);
    assert_virtual_kernel(&fields);
    let trace = g.assert_record_replay_identity(3, &flags, &baseline);
    assert_eq!(
        patina_dst_trace::TraceBundle::load(&trace)
            .unwrap()
            .metadata
            .hostname,
        NAME
    );
    assert_refused(
        g.command("replay", &[trace.to_str().unwrap(), "--hostname", NAME]),
        &["--hostname"],
    );
}

#[test]
fn mutex_condvar_schedule_varies_by_seed() {
    let g = Guest::assert_build("thread_probe.rs");
    g.assert_audit_clean();
    let out = g.assert_seeded_record_replay_identity(7, &[]);
    let order = assert_unique_line_payload(&out, "NATIVE_THREAD_RESULT counter=12 order=");
    assert_thread_counts(
        order
            .chars()
            .map(|c| c.to_digit(10).expect("thread ID") as usize),
        3,
        4,
    );
    g.assert_seed_variation(&[1, 2, 3, 4, 5, 6], &[]);
}

#[test]
fn mutex_held_across_sleep_does_not_deadlock() {
    let g = Guest::assert_build("contend_probe.rs");
    g.assert_audit_clean();
    let out = g.assert_seed_repeatability(2, 2, &[]);
    assert!(
        matches!(
            text(&out).trim_end(),
            "NATIVE_CONTEND_RESULT worker=1 final=111"
                | "NATIVE_CONTEND_RESULT worker=111 final=111"
        ),
        "{}",
        text(&out)
    );
}

/// A normal mutex's owner relocking it before any thread exists is glibc's
/// self-deadlock: the run ends as the scheduler's deadlock, naming the wait,
/// not as a shim fault about the main task.
#[cfg(target_os = "linux")]
#[test]
fn mutex_relock_before_any_thread_is_a_deadlock() {
    let g = Guest::assert_build("mutex_relock_probe.rs");
    g.assert_audit_clean();
    let out = g.assert_run_refused(1, &["deadlock", "mutex-contended"]);
    assert_exact_line(&out.stdout, "MUTEX_RELOCK_LOCKED");
    assert!(
        !text(&out.stdout).contains("MUTEX_RELOCK_RETURNED"),
        "{}",
        text(&out.stdout)
    );
}

/// The default thread name is the basename of the supervisor's fixed
/// `argv[0]`, never the host binary's file name: a copy of the guest under
/// another name runs, and replays the original's trace, identically.
#[cfg(target_os = "linux")]
#[test]
fn thread_name_does_not_depend_on_the_binary_name() {
    let g = Guest::assert_build("thread_name_probe.rs");
    g.assert_audit_clean();
    let out = g.assert_seeded_record_replay_identity(1, &[]);
    assert_exact_line(&out, "THREAD_NAME main=patina-guest worker=patina-guest");
    let dir = tempfile::tempdir().unwrap();
    let binary = dir.path().join("a-differently-named-copy");
    std::fs::copy(&g.binary, &binary).unwrap();
    let copy = Guest { dir, binary };
    assert_eq!(out, copy.assert_run_success(1, &[]).stdout);
    let trace = g.dir.path().join("run.patina");
    let replay = assert_success(copy.command(
        "replay",
        &[
            trace.to_str().unwrap(),
            "--fingerprint",
            "native-boundary-v1",
        ],
    ));
    assert_eq!(out, replay.stdout, "the copy replays the original's trace");
}

#[test]
fn udp_arrival_order_varies_by_seed() {
    let g = Guest::assert_build("udp_probe.rs");
    g.assert_audit_clean();
    let out = g.assert_seeded_record_replay_identity(1, &[]);
    let mut order: Vec<_> = assert_unique_line_payload(&out, "NATIVE_UDP_RESULT order=")
        .chars()
        .collect();
    order.sort();
    assert_eq!(order, ['0', '1', '2']);
    g.assert_seed_variation(&[1, 2, 3, 4, 5, 6], &[]);
}

#[test]
fn hashmap_iteration_order_is_seeded() {
    let g = Guest::assert_build("hashmap_probe.rs");
    g.assert_audit_clean();
    let out = g.assert_seeded_record_replay_identity(1, &[]);
    let keys: std::collections::BTreeSet<_> =
        assert_unique_line_payload(&out, "NATIVE_HASHMAP_ORDER ")
            .split(',')
            .collect();
    let expected: std::collections::BTreeSet<_> = (0..16).map(|n| format!("key-{n}")).collect();
    assert_eq!(keys, expected.iter().map(String::as_str).collect());
    g.assert_seed_variation(&[1, 2], &[]);
}

#[test]
fn yield_points_preserve_single_threaded_output() {
    let g = Guest::assert_build("hashmap_probe.rs");
    let out = g.assert_run_success(1, &[]).stdout;
    let instrumented = Guest::assert_build_with("hashmap_probe.rs", &["--yield-points"]);
    assert_eq!(out, instrumented.assert_run_success(1, &[]).stdout);
}

#[test]
fn rand_rng_is_seeded_and_replayable() {
    let g = Guest::assert_build("rand-rng");
    g.assert_audit_clean();
    let out = g.assert_seeded_record_replay_identity(1, &[]);
    let fields = assert_fields(&out, "NATIVE_RAND_RNG ", &["first", "bytes"]);
    assert_lower_hex(fields["first"], 16);
    assert_lower_hex(fields["bytes"], 48);
    g.assert_seed_variation(&[1, 2], &[]);
}

#[test]
fn urandom_device_is_seeded_and_replayable() {
    let g = Guest::assert_build("urandom_probe.rs");
    g.assert_audit_clean();
    let out = g.assert_seeded_record_replay_identity(1, &[]);
    assert_lower_hex(
        assert_unique_line_payload(&out, "NATIVE_URANDOM bytes="),
        48,
    );
    g.assert_seed_variation(&[1, 2], &[]);
}

#[test]
fn condvar_waits_use_exact_virtual_deadlines() {
    let g = Guest::assert_build("timed_wait_probe.rs");
    g.assert_audit_clean();
    let expected =
        "NATIVE_TIMED_WAIT_RESULT signalled_elapsed_ns=25000000 timeout_elapsed_ns=100000000\n";
    for seed in [5, 6] {
        let baseline = g.assert_seed_repeatability(seed, 2, &[]);
        assert_eq!(text(&baseline), expected);
    }
    g.assert_record_replay_identity(5, &[], expected.as_bytes());
}

#[test]
fn recv_timeout_delivers_five_messages_and_five_timeouts() {
    let g = Guest::assert_build("recv_timeout_probe.rs");
    g.assert_audit_clean();
    g.assert_no_imports(&["dispatch_semaphore"]);
    let expected = "NATIVE_RECV_TIMEOUT_RESULT delivered=[0, 1, 2, 3, 4] timeouts=5\n";
    for seed in [5, 6, 7] {
        let baseline = g.assert_seed_repeatability(seed, 3, &[]);
        assert_eq!(text(&baseline), expected);
    }
    g.assert_record_replay_identity(5, &[], expected.as_bytes());
}

#[test]
fn pthread_rwlock_ffi_orders_are_repeatable_and_seeded() {
    let g = Guest::assert_build("rwlock_ffi_probe.rs");
    g.assert_audit_clean();
    g.assert_no_imports(&["pthread_rwlock"]);
    for seed in [1, 3, 5] {
        let out = g.assert_seed_repeatability(seed, 3, &[]);
        assert_thread_counts(
            assert_thread_ids(&out, "NATIVE_RWLOCK_FFI_RESULT order="),
            3,
            3,
        );
    }
    g.assert_seed_variation(&[1, 3, 5], &[]);
}

#[test]
fn sleep_only_advances_when_idle() {
    let g = Guest::assert_build("sleep_order_probe.rs");
    g.assert_audit_clean();
    for seed in [5, 6] {
        let out = g.assert_seed_repeatability(seed, 2, &[]);
        assert!(matches!(
            assert_unique_line_payload(&out, "NATIVE_SLEEP_ORDER_RESULT "),
            "order=AB a_elapsed_ns=100000000 work=4950"
                | "order=BA a_elapsed_ns=100000000 work=4950"
        ));
    }
}

#[test]
fn udp_latency_is_recorded_for_flag_free_replay() {
    let g = Guest::assert_build("udp_latency_probe.rs");
    g.assert_audit_clean();
    let out = g.assert_seeded_record_replay_identity(5, &["--net-latency-nanos", "250000000"]);
    assert_exact_line(
        &out,
        "NATIVE_UDP_LATENCY_RESULT elapsed_ns=250000000 payload=ping",
    );
    let zero = g.assert_seed_repeatability(5, 2, &["--net-latency-nanos", "0"]);
    assert_exact_line(&zero, "NATIVE_UDP_LATENCY_RESULT elapsed_ns=0 payload=ping");
}

#[test]
fn tcp_shutdown_dns_and_peer_are_deterministic() {
    let g = Guest::assert_build("tcp_probe.rs");
    g.assert_audit_clean();
    let expected =
        "NATIVE_TCP_RESULT reply=PING peer=127.0.0.1:32768 ipv6_loopback=true dns_nxdomain=true\n";
    for seed in [5, 6] {
        let baseline = g.assert_seed_repeatability(seed, 2, &[]);
        assert_eq!(text(&baseline), expected);
    }
    g.assert_record_replay_identity(5, &[], expected.as_bytes());
}

#[test]
fn tokio_signal_parking_lot_rustix_use_product_backend() {
    let g = Guest::assert_build("tokio");
    g.assert_audit_clean();
    assert_eq!(
        text(&g.assert_seeded_record_replay_identity(1, &[])),
        "NATIVE_TOKIO_RESULT client_got=pong server_got=ping lock=42 rustix_read=rustix-ok\n"
    );
}

#[cfg(target_os = "macos")]
mod darwin {
    use super::*;

    #[test]
    fn os_unfair_lock_contention_is_repeatable() {
        let g = Guest::assert_build("os_unfair_lock_probe.rs");
        g.assert_audit_clean();
        let out = g.assert_seed_repeatability(1, 2, &[]);
        assert_thread_counts(
            assert_thread_ids(&out, "OS_UNFAIR_LOCK_RESULT order="),
            3,
            3,
        );
    }
}

/// A process timer and a waiter's own deadline at one virtual instant: the
/// deadlock rescue wakes the waiter, and the timer's expiry, fired right
/// after, must not wake it a second time (an invalid scheduler transition
/// that aborted the run). An interval timer against `nanosleep`.
#[cfg(target_os = "linux")]
#[test]
fn an_interval_timer_and_a_sleep_ending_together_wake_the_sleeper_once() {
    let g = Guest::assert_build("itimer_deadline_probe.rs");
    g.assert_audit_clean();
    let out = g.assert_seeded_record_replay_identity(5, &[]);
    let fields = assert_fields(&out, "ITIMER_DEADLINE ", &["slept", "alarms"]);
    assert!(["0", "EINTR"].contains(&fields["slept"]), "{fields:?}");
    assert_eq!(fields["alarms"], "1");
}

/// The timer-descriptor twin: an expiration and a `poll` timeout at one
/// virtual instant wake the poller once, and the expiration is not lost.
#[cfg(target_os = "linux")]
#[test]
fn a_timerfd_and_a_poll_ending_together_wake_the_poller_once() {
    let g = Guest::assert_build("timerfd_deadline_probe.rs");
    g.assert_audit_clean();
    let out = g.assert_seeded_record_replay_identity(5, &[]);
    let fields = assert_fields(&out, "TIMERFD_DEADLINE ", &["ready", "expirations"]);
    assert!(["0", "1"].contains(&fields["ready"]), "{fields:?}");
    assert_eq!(fields["expirations"], "1");
}
