//! Ecosystem and std lowering: every fixture is independently targetable.
#![cfg(any(target_os = "linux", target_os = "macos"))]
mod common;
use common::native::*;

/// Class detector: call-free code with a runnable peer is a named terminal
/// limit, while identical compute with no runnable peer must complete.
#[test]
fn compute_watchdog_stops_starvation_and_replays_its_terminal_prefix() {
    assert_compute_watchdog_cases(
        &["starved", "worker-starved", "allocator-held", "finite"],
        true,
    );
}

#[test]
fn compute_watchdog_custom_perform_replays_the_committed_prefix() {
    assert_compute_watchdog_cases(&["custom-spin"], false);
}

#[test]
fn compute_watchdog_never_calls_looping_or_allocating_abort_handlers() {
    assert_compute_watchdog_cases(&["handler-loop", "handler-alloc"], false);
}

#[cfg(target_os = "linux")]
#[test]
fn compute_watchdog_synchronous_replay_salvages_buffered_c_stdout() {
    assert_compute_watchdog_cases(&["sync-buffer"], false);
}

#[test]
fn compute_watchdog_byte_prefix_export_does_not_enter_the_held_allocator() {
    assert_compute_watchdog_cases(&["payload-held"], false);
}

#[test]
fn compute_watchdog_overflowed_recorder_does_not_enter_the_held_allocator() {
    use std::process::Command;
    use std::time::Duration;
    let g = Guest::assert_build("compute_watchdog.rs");
    g.assert_audit_clean();
    let trace = g.dir.path().join("overflow.patina");
    let output = common::output_by_deadline(
        Command::new(env!("CARGO_BIN_EXE_cargo-patina"))
            .arg("run")
            .arg(&g.binary)
            .args(["--seed", "7", "--compute-watchdog-ms", "25", "--record"])
            .arg(&trace)
            .args(["--format", "json", "--", "overflow-held"]),
        Duration::from_secs(60),
    );
    let common::Deadlined::Finished(output) = output else {
        panic!("overflowed terminal export hung with the guest allocator held");
    };
    assert!(!output.status.success());
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["result"], "infra", "{result:#}");
    assert_eq!(result["guest_exit"]["signal_name"], "SIGABRT", "{result:#}");
    assert!(
        recorded_hazard(result["stderr"].as_str().unwrap(), "overflow-held"),
        "{result:#}"
    );
    assert!(
        result["stderr"]
            .as_str()
            .unwrap()
            .contains("reason=trace-overflow"),
        "{result:#}"
    );
    assert!(
        patina_dst_trace::TraceBundle::load(&trace).is_err(),
        "an abandoned recorder must not manufacture a replayable empty prefix"
    );
}

#[test]
fn compute_watchdog_host_bound_is_not_a_fixed_one_second_timeout() {
    use std::os::unix::process::ExitStatusExt;
    use std::process::Command;
    use std::time::{Duration, Instant};
    let g = Guest::assert_build("compute_watchdog.rs");
    let mut short = Vec::new();
    let mut long = Vec::new();
    // Interleave bounds and use minimums to avoid making a descheduled short
    // run into a false regression. No synchronization sleeps or tight upper
    // wall-clock ceilings; both legs must reach the same named terminal stop.
    for bound in [25, 4000, 4000, 25] {
        let started = Instant::now();
        let output = common::output_with_deadline(
            Command::new(&g.binary)
                .env_clear()
                .env("PATINA_MODE", "seeded")
                .env("PATINA_SEED", "7")
                .env("PATINA_COMPUTE_WATCHDOG_MS", bound.to_string())
                .arg("starved"),
            Duration::from_secs(30),
        )
        .expect("watchdog must terminate without an outer kill");
        let elapsed = started.elapsed();
        assert_eq!(output.status.signal(), Some(libc::SIGABRT));
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .lines()
                .any(|line| line.starts_with("PATINA_VIOLATION liveness "))
        );
        eprintln!("compute watchdog bound={bound}ms elapsed={elapsed:?}");
        if bound == 25 {
            short.push(elapsed);
        } else {
            assert!(
                elapsed >= Duration::from_millis(bound),
                "long bound fired early: {elapsed:?}"
            );
            long.push(elapsed);
        }
    }
    // Require a substantial shift, not jitter-sized ordering that could let
    // even a fixed four-second implementation pass by chance.
    assert!(
        *long.iter().min().unwrap() >= *short.iter().min().unwrap() + Duration::from_secs(2),
        "changing the bound must move the stop by seconds: short={short:?} long={long:?}"
    );
}

// Class pairing: the watchdog fixture still requires an authenticated nonzero
// PC when delivery wins, while the bounded-handshake path must name its one
// legitimate host-scheduling failure instead of silently omitting the sample.
// Replay may instead reach its terminal prefix at a synchronous boundary,
// which must explicitly say that no observer sampling attempt was made.
fn assert_terminal_sample(stderr: &str, context: &str, synchronous: bool) {
    if let Some(pc) = stderr
        .split_whitespace()
        .find_map(|field| field.strip_prefix("sampled_pc=0x"))
    {
        assert_ne!(
            usize::from_str_radix(pc, 16).unwrap(),
            0,
            "terminal sampler returned a zero PC: {context}\n{stderr}"
        );
        return;
    }
    assert!(
        stderr.lines().any(|line| {
            line == "patina: compute-bound sampled_pc=unavailable reason=sample-deadline"
                || (synchronous
                    && line
                        == "patina: compute-bound sampled_pc=unavailable reason=synchronous-stop")
        }),
        "terminal stop reported neither a PC nor a legitimate unavailable outcome: {context}\n{stderr}"
    );
}

// Class pairing: validate host-time terminal stops from the recorded scheduler
// state, alongside the runtime's runnable-versus-parked watchdog unit detector.
// This accepts any eligible prefix, without pinning platform-specific counts.
fn assert_compute_stop_eligible(
    events: &[patina_dst_trace::TraceEvent],
    stop: patina_dst_trace::ComputeStop,
) {
    use patina_dst_abi::{Operation, Outcome};
    let mut runnable = std::collections::BTreeSet::new();
    let mut running = None;
    for event in events {
        match (&event.operation, &event.outcome) {
            (Operation::TaskSpawn { .. }, Outcome::Task(task)) => {
                runnable.insert(*task);
            }
            (Operation::TaskYield { task } | Operation::TaskWake { task }, Outcome::Unit) => {
                runnable.insert(*task);
            }
            (
                Operation::TaskPark { task, .. }
                | Operation::TaskParkTimed { task, .. }
                | Operation::TaskComplete { task },
                Outcome::Unit,
            ) => {
                runnable.remove(task);
            }
            (Operation::SchedulerNext, Outcome::OptionalTask(task)) => running = *task,
            _ => {}
        }
    }
    assert_eq!(stop.steps as usize, events.len());
    assert_eq!(running, Some(stop.task), "stop must name the baton holder");
    assert!(
        runnable.contains(&stop.task),
        "stopped task must be runnable"
    );
    assert!(
        runnable.iter().any(|task| *task != stop.task),
        "stop must have a runnable peer"
    );
}

fn specialized_hazard(mode: &str) -> bool {
    matches!(
        mode,
        "allocator-held"
            | "payload-held"
            | "overflow-held"
            | "handler-loop"
            | "handler-alloc"
            | "custom-spin"
            | "sync-buffer"
            | "small-stack"
    )
}
fn recorded_hazard(stderr: &str, mode: &str) -> bool {
    let terminal = if mode == "overflow-held" {
        "PATINA_INFRA compute_stop_export_failed reason=trace-overflow"
    } else {
        "PATINA_VIOLATION liveness "
    };
    stderr
        .find(&format!("PATINA_LIFECYCLE_EVENT label=watchdog.{mode}\n"))
        .zip(stderr.find(terminal))
        .is_some_and(|(receipt, stop)| receipt < stop)
}

fn assert_compute_watchdog_cases(modes: &[&str], negative_controls: bool) {
    use std::process::Command;
    use std::time::{Duration, Instant};
    let g = Guest::assert_build("compute_watchdog.rs");
    g.assert_audit_clean();
    // Direct managed execution excludes supervisor/audit startup from timing.
    let direct = |mode: &str, bound: &str| {
        let started = Instant::now();
        let output = common::output_with_deadline(
            Command::new(&g.binary)
                .env_clear()
                .env("PATINA_MODE", "seeded")
                .env("PATINA_SEED", "7")
                .env("PATINA_COMPUTE_WATCHDOG_MS", bound)
                .arg(mode),
            Duration::from_secs(15),
        )
        .unwrap();
        (output, started.elapsed())
    };
    let run = |verb: &str, args: &[&str], bound: &str| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_cargo-patina"));
        command
            .arg(verb)
            .arg(&g.binary)
            .args(["--compute-watchdog-ms", bound])
            .args(args)
            // A valid CLI value must override even an invalid inherited knob.
            .env("PATINA_COMPUTE_WATCHDOG_MS", "0");
        let started = Instant::now();
        let output = common::output_with_deadline(&mut command, Duration::from_secs(15))
            .expect("compute watchdog must stop without an outer kill");
        (output, started.elapsed())
    };
    // finite is the record-short / replay-long case: unlike an infinite loop,
    // it would reach another operation and complete if replay forgot the stop.
    // The private signal stack must also work above a guarded 2 KiB stack.
    let small_stack: &[&str] =
        if negative_controls && cfg!(all(target_os = "linux", target_arch = "x86_64")) {
            &["small-stack"]
        } else {
            &[]
        };
    for mode in modes.iter().chain(small_stack).copied() {
        use std::os::unix::process::ExitStatusExt;
        let (stop, direct_elapsed) = direct(mode, "25");
        assert_eq!(stop.status.signal(), Some(libc::SIGABRT));
        // The outer deadline detects hangs, not timeout accuracy. A separate
        // paired-bound detector proves that the configured bound is load-bearing.
        eprintln!("compute watchdog {mode}: direct stop={direct_elapsed:?} bound=25ms");
        // Host time may truncate same-seed runs at different eligible prefixes,
        // including thread-startup waits before the intended compute region.
        // Replay each independently; compare only their overlapping decisions.
        let mut previous: Option<Vec<patina_dst_trace::TraceEvent>> = None;
        let mut reached_hazard = false;
        for repetition in 0..2 {
            let trace = g.dir.path().join(format!("{mode}-{repetition}.patina"));
            let (record, elapsed) = run(
                "run",
                &[
                    "--seed",
                    "7",
                    "--record",
                    trace.to_str().unwrap(),
                    "--format",
                    "json",
                    "--",
                    mode,
                ],
                "25",
            );
            assert!(!record.status.success());
            eprintln!("compute watchdog {mode}: record elapsed={elapsed:?} bound=25ms");
            let record: serde_json::Value = serde_json::from_slice(&record.stdout).unwrap();
            assert_eq!(
                record["result"], "liveness",
                "finding mode={mode}: {record}"
            );
            assert_eq!(
                record["guest_exit"]["signal_name"], "SIGABRT",
                "finding mode={mode}: {record}"
            );
            let finding = record["runtime_findings"]
                .as_array()
                .unwrap()
                .iter()
                .find(|finding| finding["detail"] == "compute-bound")
                .unwrap();
            assert_eq!(finding["known_limit"], true);
            let stderr = record["stderr"].as_str().unwrap();
            reached_hazard |= recorded_hazard(stderr, mode);
            assert!(
                stderr
                    .lines()
                    .any(|line| line.starts_with("PATINA_VIOLATION liveness ")),
                "marker must start at column zero: {stderr}"
            );
            if mode == "starved" {
                assert!(
                    stderr.contains("COMPUTE_PARTIAL_STDERR\nPATINA_VIOLATION "),
                    "{stderr}"
                );
            }
            assert_terminal_sample(
                stderr,
                &format!("record mode={mode} elapsed={elapsed:?}"),
                false,
            );
            let bundle = patina_dst_trace::TraceBundle::load(&trace).unwrap();
            let terminal = bundle
                .metadata
                .compute_stop
                .expect("recorded terminal fact");
            assert_eq!(terminal.task.0, finding["task"].as_u64().unwrap());
            assert_eq!(terminal.steps, finding["steps"].as_u64().unwrap());
            let events = bundle.resolved_timeline("main").unwrap();
            assert_compute_stop_eligible(&events, terminal);
            if let Some(previous) = previous.as_ref() {
                let common = previous.len().min(events.len());
                assert_eq!(
                    previous[..common],
                    events[..common],
                    "same-seed modeled decisions differ before the host-time stop: mode={mode}"
                );
            }
            previous = Some(events);
            // One day, rather than 25ms: replay must stop from the trace, not redetect.
            let (replay, elapsed) = run(
                "replay",
                &[trace.to_str().unwrap(), "--format", "json"],
                "86400000",
            );
            assert!(!replay.status.success());
            // Replay must finish well before its one-day bound, allowing loaded CI.
            assert!(
                elapsed < Duration::from_secs(12),
                "replay waited for host bound: {elapsed:?}"
            );
            eprintln!("compute watchdog {mode}: replay with one-day bound elapsed={elapsed:?}");
            let replay: serde_json::Value = serde_json::from_slice(&replay.stdout).unwrap();
            assert_eq!(replay["result"], "liveness", "{replay:#}");
            assert_eq!(replay["guest_exit"]["signal_name"], "SIGABRT");
            assert_terminal_sample(
                replay["stderr"].as_str().unwrap(),
                &format!("replay mode={mode}: {replay:#}"),
                true,
            );
            if mode == "sync-buffer" {
                assert!(
                    replay["stdout"]
                        .as_str()
                        .unwrap()
                        .contains("WATCHDOG_BUFFERED_C_STDOUT"),
                    "synchronous stop lost C stdout: {replay:#}"
                );
            }
            let replay_finding = replay["runtime_findings"]
                .as_array()
                .unwrap()
                .iter()
                .find(|finding| finding["detail"] == "compute-bound")
                .unwrap();
            assert_eq!(finding, replay_finding);
            eprintln!(
                "compute watchdog {mode} repetition={repetition}: record/replay terminal task={} steps={}",
                terminal.task.0, terminal.steps
            );
        }
        // Prefix/replay checks accept legitimate early startup stops, but
        // neither recording reaching the hazard is NOT specialized coverage.
        // Class pairing: planted pre-hazard compute must fail this detector.
        assert!(
            !specialized_hazard(mode) || reached_hazard,
            "neither recording exercised its specialized hazard: mode={mode}"
        );
    }
    if !negative_controls {
        return;
    }
    for mode in ["single", "parked", "finite"] {
        let bound = if mode == "finite" { "5000" } else { "25" };
        // Time the identical executable without the supervisor/audit startup;
        // otherwise that overhead could make an empty compute control pass.
        let (output, direct_elapsed) = direct(mode, bound);
        assert_success(output);
        assert!(
            direct_elapsed > Duration::from_millis(100),
            "direct compute was too short: {direct_elapsed:?}"
        );
        eprintln!("compute watchdog negative {mode}: direct compute={direct_elapsed:?}");
        if mode == "finite" {
            // At least two maximum-length polls, but below the configured bound.
            assert!(direct_elapsed > Duration::from_millis(250));
            assert!(direct_elapsed < Duration::from_millis(5000));
        }
        let negative_trace = g.dir.path().join(format!("negative-{mode}.patina"));
        let (output, elapsed) = run(
            "run",
            &[
                "--seed",
                "7",
                "--record",
                negative_trace.to_str().unwrap(),
                "--",
                mode,
            ],
            bound,
        );
        let output = assert_success(output);
        if mode == "single" {
            let bundle = patina_dst_trace::TraceBundle::load(&negative_trace).unwrap();
            let events = bundle.resolved_timeline("main").unwrap();
            assert!(
                events
                    .iter()
                    .filter(|e| matches!(e.operation, patina_dst_abi::Operation::TaskSpawn { .. }))
                    .count()
                    >= 2,
                "single must arm the observer by creating a peer first"
            );
            assert!(
                events
                    .iter()
                    .any(|e| matches!(e.operation, patina_dst_abi::Operation::TaskComplete { .. })),
                "single must join its peer before computing"
            );
        }
        eprintln!("compute watchdog negative {mode}: elapsed={elapsed:?} bound={bound}ms");
        assert_exact_line(&output.stdout, "COMPUTE_RESULT completed=true");
        assert!(
            elapsed > Duration::from_millis(100),
            "negative control did not exceed bound: {elapsed:?}"
        );
    }
}

/// Class pairing: live sys/keys_session differential + full trace identity.
#[cfg(target_os = "linux")]
#[test]
fn keyutils_password_lifecycle_is_isolated_and_replayable() {
    let g = Guest::assert_build("keyring-keyutils");
    g.assert_audit_clean();
    // This test thread alone joins an anonymous HOST ring. Child supervisors
    // inherit these exact credential names; the guest must still start empty.
    // The native red leg's backend can cache a canary in the host persistent
    // ring. Invalidate our keys on success or panic, removing every such link.
    struct Canaries(Vec<libc::c_long>);
    impl Drop for Canaries {
        fn drop(&mut self) {
            for &serial in &self.0 {
                // SAFETY: INVALIDATE of a key created and owned by this test.
                let result = unsafe { libc::syscall(libc::SYS_keyctl, 21, serial, 0, 0, 0) };
                if result != 0 {
                    let error = std::io::Error::last_os_error();
                    eprintln!("host canary cleanup failed: {error}");
                    assert!(std::thread::panicking(), "host canary cleanup: {error}");
                }
            }
        }
    }
    let mut canaries = Canaries(Vec::new());
    // SAFETY: integer arguments to anonymous JOIN_SESSION_KEYRING.
    let host_ring = unsafe { libc::syscall(libc::SYS_keyctl, 1, 0, 0, 0, 0) };
    if host_ring < 0 {
        let error = std::io::Error::last_os_error();
        assert!(
            matches!(
                error.raw_os_error(),
                Some(libc::EPERM | libc::EACCES | libc::ENOSYS)
            ),
            "{error}"
        );
        assert_ne!(
            std::env::var("PATINA_REQUIRE_HOST_ORACLE").as_deref(),
            Ok("1"),
            "host key canary unavailable: {error}"
        );
        eprintln!("NOT RUN: host keyring canary ({error}); virtual lifecycle still runs");
    } else {
        for name in [
            c"keyring-rs:password-user@patina-testbed",
            c"keyring:password-user@patina-testbed",
        ] {
            // SAFETY: valid type/description strings and a one-byte payload.
            let serial = unsafe {
                libc::syscall(
                    libc::SYS_add_key,
                    c"user".as_ptr(),
                    name.as_ptr(),
                    b"H".as_ptr(),
                    1,
                    host_ring,
                )
            };
            assert!(
                serial > 0,
                "host canary: {}",
                std::io::Error::last_os_error()
            );
            canaries.0.push(serial);
        }
        // A stock build is required: the shim-linked binary refuses standalone
        // startup, which would not prove that the canary detector can fail.
        let target = common::guest_target_dir("keyring-keyutils-native");
        let built =
            std::process::Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
                .args(["build", "--quiet", "--locked", "--manifest-path"])
                .arg(guest_source("keyring-keyutils").join("Cargo.toml"))
                .arg("--target-dir")
                .arg(&target)
                .status()
                .expect("native keyutils build runs");
        assert!(built.success(), "native keyutils build failed");
        let native = common::output_with_deadline(
            &mut std::process::Command::new(target.join("debug/keyring-keyutils")),
            std::time::Duration::from_secs(60),
        )
        .expect("native canary run exceeded deadline");
        assert_eq!(
            native.status.code(),
            Some(101),
            "native canary must fail the absence assertion: {native:?}"
        );
        assert_exact_line(&native.stdout, "KEYRING_RESULT initial=present");
        eprintln!("host-canary RED: native guest reported initial=present and exited 101");
    }
    let out = g.assert_seeded_record_replay_identity(7, &[]);
    assert_exact_line(
        &out,
        "KEYRING_RESULT empty,set,read,update,thread,delete,no-entry,recreate,current-backend",
    );
    for seed in [0, 1, 42, u64::MAX] {
        assert_eq!(g.assert_run_success(seed, &[]).stdout, out);
    }
}

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
        (patina_dst_time_virtual::DEFAULT_REALTIME_EPOCH_NANOS
            + patina_dst_runtime::DEFAULT_BOOT_ORIGIN_NANOS)
            .to_string()
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
        (patina_dst_time_virtual::DEFAULT_REALTIME_EPOCH_NANOS
            + patina_dst_runtime::DEFAULT_BOOT_ORIGIN_NANOS)
            .to_string()
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
    assert_eq!(
        fields["epoch_ns"].parse::<u64>().unwrap(),
        1_000_000_000_000_000_000 + patina_dst_runtime::DEFAULT_BOOT_ORIGIN_NANOS
    );
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

/// The main thread leaving through `pthread_exit` ends only itself, as under
/// glibc 2.39: its cleanup handler runs, a thread still running keeps the
/// process alive and ends it, and the last thread's `exit(0)` runs the atexit
/// handlers, with status 0 — the same on every run and on replay. The modes:
/// no other thread, a worker still sleeping, a detached worker already ended,
/// a worker joining the main thread (its join answers main's value).
#[cfg(target_os = "linux")]
#[test]
fn main_thread_pthread_exit_ends_only_the_main_thread() {
    let g = Guest::assert_build("main_exit_probe.rs");
    g.assert_audit_clean();
    for (mode, expected) in [
        ("alone", "MAIN_EXIT cleanup\nMAIN_EXIT atexit\n"),
        (
            "worker",
            "MAIN_EXIT cleanup\nMAIN_EXIT worker\nMAIN_EXIT atexit\n",
        ),
        (
            "detached",
            "MAIN_EXIT worker\nMAIN_EXIT cleanup\nMAIN_EXIT atexit\n",
        ),
        (
            "joiner",
            "MAIN_EXIT cleanup\nMAIN_EXIT joined 7\nMAIN_EXIT atexit\n",
        ),
    ] {
        let env = format!("MAIN_EXIT_MODE={mode}");
        let out = g.assert_seeded_record_replay_identity(1, &["--env", &env]);
        assert_eq!(text(&out), expected, "{mode}");
    }
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
fn every_guest_call_is_charged_to_a_reserved_task() {
    // Class pairing: the runtime's `charge_alloc` (charging never allocates,
    // so it never creates a task's entry). A single-threaded guest's calls,
    // made before the thread runtime numbers the main thread, still land on
    // its reserved task, never in the unreserved total.
    let g = Guest::assert_build("std_probe.rs");
    let output = g.command("run", &["--seed", "5", "--format", "json"]);
    assert!(output.status.success(), "{}", text(&output.stderr));
    let envelope: serde_json::Value =
        serde_json::from_slice(text(&output.stdout).lines().last().unwrap().as_bytes()).unwrap();
    let charges = &envelope["cpu_charges"];
    assert!(charges.get("unreserved").is_none(), "{charges}");
    assert!(
        charges["task1"]["system_ns"].as_u64().unwrap() > 0,
        "{charges}"
    );
}

#[test]
fn an_empty_udp_poll_on_a_sleeping_peer_lets_virtual_time_reach_it() {
    // Class pairing: the runtime's outcome classifier
    // (`liveness::tests::an_empty_poll_loop_keeps_the_spin_streak_and_replays`).
    // The budget turns the old failure, a poll that never let time move, into
    // a bounded refusal.
    let g = Guest::assert_build("poll_clock_probe.rs");
    g.assert_audit_clean();
    let budget = ["--budget", "2000000"];
    let expected =
        "NATIVE_POLL_CLOCK_RESULT first_empty=true payload=ping polled=true waited_1ms=true\n";
    for seed in [5, 6] {
        let baseline = g.assert_seed_repeatability(seed, 2, &budget);
        assert_eq!(text(&baseline), expected);
    }
    g.assert_record_replay_identity(5, &budget, expected.as_bytes());
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
