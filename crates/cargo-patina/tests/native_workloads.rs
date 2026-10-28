//! Ecosystem and std lowering: every fixture is independently targetable.
#![cfg(any(target_os = "linux", target_os = "macos"))]
mod common;
use common::native::*;

/// One seeded run's stdout, required to succeed: for a configuration whose
/// determinism the test leaves to another configuration's
/// [`Guest::assert_run_success`].
fn run_seeded(g: &Guest, seed: u64, flags: &[&str]) -> Vec<u8> {
    let seed = seed.to_string();
    assert_success(g.command("run", &[&["--seed", seed.as_str()][..], flags].concat())).stdout
}

#[path = "native_workloads/cpus.rs"]
mod cpus;
#[path = "native_workloads/fs_faults.rs"]
mod fs_faults;
#[cfg(target_os = "linux")]
#[path = "native_workloads/path_races.rs"]
mod path_races;
#[cfg(target_os = "linux")]
#[path = "native_workloads/two_copy.rs"]
mod two_copy;

/// One build of the watchdog guest covers the class: call-free code with a
/// runnable peer is a named terminal limit, recorded with an eligible prefix
/// that a replay reaches from the trace alone, while identical compute with no
/// runnable peer completes, and the configured bound moves the stop. The
/// stopped modes cover each place a starved guest can be caught: the main task
/// (`starved`) or a worker (`worker-starved`) spinning; compute that a replay
/// would finish if it forgot the stop (`finite`); a held allocator under a
/// byte-payload export (`payload-held`); an allocating abort handler that is
/// never called (`handler-alloc`); a custom perform replaying its committed
/// prefix (`custom-spin`, or on Linux `sync-buffer`, whose replay also
/// salvages buffered C stdout); and on Linux x86_64 a 2 KiB stack
/// (`small-stack`). A failure names its mode.
#[test]
fn compute_watchdog_stops_starvation_and_replays_its_terminal_prefix() {
    use std::os::unix::process::ExitStatusExt;
    use std::process::Command;
    use std::time::{Duration, Instant};
    let g = Guest::assert_build("compute_watchdog.rs");
    g.assert_audit_clean();
    let deadline = Duration::from_secs(15);
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
            deadline,
        )
        .expect("compute watchdog must stop without an outer kill");
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
        let output = common::output_with_deadline(&mut command, deadline)
            .expect("compute watchdog must stop without an outer kill");
        (output, started.elapsed())
    };
    let mut modes = vec![
        "starved",
        "worker-starved",
        "finite",
        "payload-held",
        "handler-alloc",
    ];
    modes.push(if cfg!(target_os = "linux") {
        "sync-buffer"
    } else {
        "custom-spin"
    });
    if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        modes.push("small-stack");
    }
    for mode in modes {
        // Host time may truncate same-seed runs at different eligible
        // prefixes, including descheduling before the intended compute
        // region. `starved` records twice and compares only the overlapping
        // decisions; each recording replays independently.
        let repetitions = if mode == "starved" { 2 } else { 1 };
        let mut previous: Option<Vec<patina_dst_trace::TraceEvent>> = None;
        let mut reached_hazard = false;
        for repetition in 0..repetitions {
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
            let finding = compute_bound_finding(&record);
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
            assert_eq!(finding, compute_bound_finding(&replay));
        }
        // Prefix/replay checks accept legitimate early stops, but a recording
        // that never reached its mode's hazard is not that mode's coverage.
        assert!(
            !specialized_hazard(mode) || reached_hazard,
            "no recording exercised its specialized hazard: mode={mode}"
        );
    }
    for mode in ["single", "parked", "finite"] {
        // single and parked leave no runnable peer, so even the tight bound
        // must not stop them. finite's peer stays runnable, so its bound is
        // the deadline: every compute the harness waits for ends inside it,
        // however loaded the host, so any stop fired before its bound.
        let bound = if mode == "finite" {
            deadline.as_millis().to_string()
        } else {
            "25".to_owned()
        };
        if mode == "finite" {
            // Timed without the supervisor's startup: the observer saw the
            // same runnable-peer candidate across at least two maximum-length
            // polls.
            let (output, elapsed) = direct(mode, &bound);
            assert_success(output);
            assert!(
                elapsed > Duration::from_millis(250),
                "direct compute was too short: {elapsed:?}"
            );
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
            &bound,
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
        assert_exact_line(&output.stdout, "COMPUTE_RESULT completed=true");
        assert!(
            elapsed > Duration::from_millis(100),
            "negative control did not exceed bound: {elapsed:?}"
        );
    }
    // The bound is load-bearing, not a fixed timeout: a long bound moves the
    // stop by most of a second. The long run is bracketed by short ones and
    // compared with the shorter, so one descheduled short run is no false
    // regression; a long run can only be late, never early.
    let (mut short, mut long) = (Duration::MAX, Duration::ZERO);
    for bound in [25, 1000, 25] {
        let (output, elapsed) = direct("starved", &bound.to_string());
        assert_eq!(output.status.signal(), Some(libc::SIGABRT));
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .lines()
                .any(|line| line.starts_with("PATINA_VIOLATION liveness "))
        );
        if bound == 25 {
            short = short.min(elapsed);
        } else {
            long = elapsed;
        }
    }
    assert!(
        long >= Duration::from_millis(1000) && long >= short + Duration::from_millis(500),
        "changing the bound must move the stop: short={short:?} long={long:?}"
    );
}

/// The `compute-bound` runtime finding of a `patina.result/v1` envelope.
fn compute_bound_finding(envelope: &serde_json::Value) -> &serde_json::Value {
    envelope["runtime_findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["detail"] == "compute-bound")
        .unwrap()
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

/// The modes whose recording must reach the guest's own hazard marker.
fn specialized_hazard(mode: &str) -> bool {
    matches!(
        mode,
        "payload-held" | "handler-alloc" | "custom-spin" | "sync-buffer" | "small-stack"
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

/// Class pairing: live sys/keys_session differential + full trace identity.
/// Host keys planted in this test thread's own session ring, which child
/// supervisors inherit, must stay invisible to the guest.
#[cfg(target_os = "linux")]
#[test]
fn keyutils_password_lifecycle_is_isolated_and_replayable() {
    let g = Guest::assert_build("keyring-keyutils");
    g.assert_audit_clean();
    // Invalidate the planted keys on success or panic.
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
    assert!(
        host_ring >= 0,
        "host key canary unavailable: {}",
        std::io::Error::last_os_error()
    );
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
    let out = g.assert_run_success(7, &[]).stdout;
    assert_exact_line(
        &out,
        "KEYRING_RESULT empty,set,read,update,thread,delete,no-entry,recreate,current-backend",
    );
}

/// An ordinary std program runs only under Patina, deterministically from
/// its seed: its wall clock starts at the virtual epoch, its hashers are
/// seeded (another seed changes them), its filesystem is the virtual one,
/// and every call it makes, even before the thread runtime numbers the main
/// thread, is charged to a reserved task (class pairing: the runtime's
/// `charge_alloc`, which never creates a task's entry).
#[test]
fn std_runs_seeded_and_replayable_but_not_standalone() {
    let g = Guest::assert_build("std_probe.rs");
    g.assert_audit_clean();
    let standalone = std::process::Command::new(&g.binary)
        .env_clear()
        .output()
        .unwrap();
    assert_refused(standalone, &["must run under"]);
    let out = g.assert_run_success(9, &[]).stdout;
    assert_exact_line(&out, "PATINA_STRACE_MARKER");
    let fields = assert_fields(
        &out,
        "NATIVE_STD_RESULT ",
        &["epoch_ns", "first_hash", "second_hash", "fs"],
    );
    assert_soon_after(
        fields["epoch_ns"],
        patina_dst_time_virtual::DEFAULT_REALTIME_EPOCH_NANOS
            + patina_dst_runtime::DEFAULT_BOOT_ORIGIN_NANOS,
    );
    assert_lower_hex(fields["first_hash"], 16);
    assert_lower_hex(fields["second_hash"], 16);
    assert_eq!(fields["fs"], "link:symlink,nested:dir,value:file");
    let output = g.command("run", &["--seed", "10", "--format", "json"]);
    assert!(output.status.success(), "{}", text(&output.stderr));
    let envelope: serde_json::Value =
        serde_json::from_slice(text(&output.stdout).lines().last().unwrap().as_bytes()).unwrap();
    assert_ne!(
        envelope["stdout"].as_str().unwrap().as_bytes(),
        out,
        "another seed must change the hashes"
    );
    let charges = &envelope["cpu_charges"];
    assert!(charges.get("unreserved").is_none(), "{charges}");
    assert!(
        charges["task1"]["system_ns"].as_u64().unwrap() > 0,
        "{charges}"
    );
}

/// The guest-start realtime, plus the calls charged before the read.
fn assert_soon_after(value: &str, start: u64) {
    let value: u64 = value.parse().unwrap();
    assert!((start..start + 100_000).contains(&value), "{value} {start}");
}

/// The realtime epoch: the default, and `--realtime-epoch`, which moves the
/// guest's wall clock and the filesystem timestamps stamped from it, is
/// recorded into the trace, and is adopted by a flag-free replay before any
/// file is stamped; a replay given the flag is refused.
#[test]
fn realtime_epoch_defaults_overrides_and_replays_flag_free() {
    const TEXT: &str = "2001-09-09T01:46:40Z";
    let g = Guest::assert_build("realtime_epoch_probe.rs");
    g.assert_audit_clean();
    let default = run_seeded(&g, 3, &[]);
    let fields = assert_fields(
        &default,
        "NATIVE_REALTIME_EPOCH_RESULT ",
        &["epoch_ns", "mtime_ns"],
    );
    assert_soon_after(
        fields["epoch_ns"],
        patina_dst_time_virtual::DEFAULT_REALTIME_EPOCH_NANOS
            + patina_dst_runtime::DEFAULT_BOOT_ORIGIN_NANOS,
    );
    let flags = ["--realtime-epoch", TEXT];
    let (baseline, trace) = g.assert_recorded(3, &flags);
    let fields = assert_fields(
        &baseline.stdout,
        "NATIVE_REALTIME_EPOCH_RESULT ",
        &["epoch_ns", "mtime_ns"],
    );
    assert_soon_after(
        fields["epoch_ns"],
        1_000_000_000_000_000_000 + patina_dst_runtime::DEFAULT_BOOT_ORIGIN_NANOS,
    );
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
    let default = run_seeded(&g, 3, &[]);
    let fields = assert_fields(&default, "NATIVE_HOSTNAME_RESULT ", &HOSTNAME_KEYS);
    assert_eq!(fields["hostname"], patina_dst_syscalls::IDENTITY_HOSTNAME);
    assert_eq!(fields["nodename"], patina_dst_syscalls::IDENTITY_HOSTNAME);
    assert_virtual_kernel(&fields);

    // The flag renames the virtual machine for both readers, is recorded into
    // the trace, and a flag-free replay reproduces it.
    let flags = ["--hostname", NAME];
    let (baseline, trace) = g.assert_recorded(3, &flags);
    let fields = assert_fields(&baseline.stdout, "NATIVE_HOSTNAME_RESULT ", &HOSTNAME_KEYS);
    assert_eq!(fields["hostname"], NAME);
    assert_eq!(fields["nodename"], NAME);
    assert_virtual_kernel(&fields);
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
    let out = g.assert_run_success(7, &[]).stdout;
    let order = assert_unique_line_payload(&out, "NATIVE_THREAD_RESULT counter=12 order=");
    assert_thread_counts(
        order
            .chars()
            .map(|c| c.to_digit(10).expect("thread ID") as usize),
        3,
        4,
    );
    g.assert_seed_variation(&[1, 2, 3], &[]);
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
/// handlers, with status 0. The modes: no other thread, a worker still
/// sleeping (also recorded and replayed), a worker joining the main thread
/// (its join answers main's value).
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
            "joiner",
            "MAIN_EXIT cleanup\nMAIN_EXIT joined 7\nMAIN_EXIT atexit\n",
        ),
    ] {
        let env = format!("MAIN_EXIT_MODE={mode}");
        let flags = ["--env", env.as_str()];
        let out = if mode == "worker" {
            g.assert_run_success(1, &flags).stdout
        } else {
            run_seeded(&g, 1, &flags)
        };
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
    let (out, trace) = g.assert_recorded(1, &[]);
    assert_exact_line(
        &out.stdout,
        "THREAD_NAME main=patina-guest worker=patina-guest",
    );
    let dir = tempfile::tempdir().unwrap();
    let binary = dir.path().join("a-differently-named-copy");
    std::fs::copy(&g.binary, &binary).unwrap();
    let copy = Guest { dir, binary };
    assert_eq!(out.stdout, run_seeded(&copy, 1, &[]));
    let replay = assert_success(copy.command("replay", &[trace.to_str().unwrap()]));
    assert_eq!(
        out.stdout, replay.stdout,
        "the copy replays the original's trace"
    );
}

#[test]
fn udp_arrival_order_varies_by_seed() {
    let g = Guest::assert_build("udp_probe.rs");
    g.assert_audit_clean();
    let out = g.assert_run_success(1, &[]).stdout;
    let mut order: Vec<_> = assert_unique_line_payload(&out, "NATIVE_UDP_RESULT order=")
        .chars()
        .collect();
    order.sort();
    assert_eq!(order, ['0', '1', '2']);
    g.assert_seed_variation(&[1, 2, 3, 4, 5, 6], &[]);
}

/// One seeded run under a certain entropy fault rate, as the guest's stdout and
/// the `fault_reports` object of its `patina.result/v1` envelope.
fn certain_entropy_fault_run(g: &Guest) -> (String, serde_json::Value) {
    let output = g.command(
        "run",
        &[
            "--seed",
            "1",
            "--entropy-fail-permille",
            "1000",
            "--format",
            "json",
        ],
    );
    assert!(
        output.status.success(),
        "{}: {}{}",
        output.status,
        text(&output.stdout),
        text(&output.stderr)
    );
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let stdout = envelope["stdout"].as_str().unwrap().to_string();
    (stdout, envelope["fault_reports"].clone())
}

/// The entropy fault reaches only an API the platform can really fail. A
/// thread's first `HashMap` draws from one that cannot fail on Darwin
/// (`CCRandomGenerateBytes`), so it runs under a certain failure rate. With no
/// eligible request, the entropy plane is absent: undiagnosable, never
/// vacuous. RED before: Darwin's `CCRandomGenerateBytes` trapped (signal 5).
/// Linux's twin is `entropy_fault_probe.rs`'s thread `HashMap`. Class pairing:
/// `Context::entropy_bytes` takes an `EntropyWait` from every caller, and only
/// `FailIfUnready` can be failed.
#[cfg(target_os = "macos")]
#[test]
fn a_thread_hashmap_runs_under_certain_entropy_failure() {
    let g = Guest::assert_build("thread_hashmap_probe.rs");
    let (stdout, reports) = certain_entropy_fault_run(&g);
    assert_eq!(
        assert_unique_line_payload(stdout.as_bytes(), "NATIVE_THREAD_HASHMAP len="),
        "1"
    );
    assert!(reports.get("entropy").is_none(), "{reports}");
}

/// On Linux, only a `GRND_NONBLOCK` read before the pool is known ready fails,
/// with `EAGAIN` (getrandom(2)), and the kernel decides that before it looks at
/// the buffer or the length: a NULL and an empty read fail the same way. An
/// empty `getentropy` never reaches the kernel, so it leaves the pool unknown.
/// Every other entry point (a thread's first `HashMap`'s `GRND_INSECURE` read
/// among them), and a nonblocking read once a waiting read has returned, gets
/// bytes. RED before: every request failed with `EINTR`, which glibc's
/// `getentropy` never returns, and std retried it forever; then the empty
/// `getentropy` showed the pool ready, and the NULL read answered `EFAULT`
/// without being counted.
#[cfg(target_os = "linux")]
#[test]
fn the_entropy_fault_fails_only_nonblocking_reads_of_an_unready_pool() {
    let g = Guest::assert_build("entropy_fault_probe.rs");
    let (stdout, reports) = certain_entropy_fault_run(&g);
    let eagain = format!("errno{}", libc::EAGAIN);
    assert_eq!(
        assert_unique_line_payload(stdout.as_bytes(), "NATIVE_ENTROPY_FAULT "),
        format!(
            "empty_getentropy=0 nonblocking_first={eagain} null_nonblocking={eagain} \
empty_nonblocking={eagain} insecure=16 hashmap=1 getentropy=0 nonblocking_after=16"
        )
    );
    let entropy = &reports["entropy"];
    assert_eq!(entropy["requests"], 3, "{reports}");
    assert_eq!(entropy["failures_injected"], 3, "{reports}");
    assert_eq!(entropy["vacuous"], false, "{reports}");
    g.assert_run_success(1, &["--entropy-fail-permille", "1000"]);
}

/// The libc entropy surface answers as the host's own libc does, the native
/// run being the oracle: `getentropy`'s size limit and errno (XNU `EINVAL`),
/// an empty request, and which names `dlsym` finds (libSystem defines no
/// `getrandom`). RED before: an oversized request was `EIO`. Linux's twin is
/// the entropy/getentropy conformance scenario, glibc's host oracle.
#[cfg(target_os = "macos")]
#[test]
fn the_libc_entropy_surface_answers_as_the_host_libc() {
    let g = Guest::assert_build("entropy_libc_probe.rs");
    let patina = run_seeded(&g, 1, &[]);
    let native = native_stdout("entropy_libc_probe.rs");
    assert_eq!(text(&patina), text(&native));
}

/// Entropy requests whose destination stops being writable answer as the host
/// kernel does, the native run being the oracle: on Linux the bytes written
/// before the fault, or `EFAULT` when none were; on macOS a short
/// `/dev/urandom` read is `EFAULT`. On Linux the Patina run gets a 1 GiB
/// address-space limit, so a request is never allocated whole: a NULL request
/// of `MAX_RW_COUNT` bytes is `EFAULT`, not an allocation failure. The native
/// run asks the kernel through `syscall(2)`; on Linux the Patina run asks
/// through it and through the exported `getrandom` wrapper
/// (`ENTROPY_BOUNDS_DOOR=libc`), and both must answer as the kernel did. RED
/// before: the run aborted allocating 2 GiB, a Linux partial write answered
/// `EFAULT`, and a macOS short read answered its byte count. The chunked
/// draws reproduce.
#[test]
fn entropy_into_a_faulting_buffer_answers_the_bytes_written() {
    let g = Guest::assert_build("entropy_bounds_probe.rs");
    let native = native_stdout("entropy_bounds_probe.rs");
    #[cfg(target_os = "linux")]
    let doors: &[&[&str]] = &[&[], &["--env", "ENTROPY_BOUNDS_DOOR=libc"]];
    #[cfg(not(target_os = "linux"))]
    let doors: &[&[&str]] = &[&[]];
    for &door in doors {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_cargo-patina"));
        command
            .current_dir(common::native_workspace())
            .args(["run", g.binary.to_str().unwrap(), "--seed", "1"])
            .args(door);
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::process::CommandExt;
            let limit = libc::rlimit {
                rlim_cur: 1 << 30,
                rlim_max: 1 << 30,
            };
            // SAFETY: setrlimit is async-signal-safe, and `limit` outlives the spawn.
            unsafe {
                command.pre_exec(move || {
                    if libc::setrlimit(libc::RLIMIT_AS, &limit) == 0 {
                        Ok(())
                    } else {
                        Err(std::io::Error::last_os_error())
                    }
                });
            }
        }
        let output = common::output_with_deadline(&mut command, std::time::Duration::from_secs(60))
            .expect("the bounded run exceeded 60s");
        assert!(
            output.status.success(),
            "{door:?}: {}: {}{}",
            output.status,
            text(&output.stdout),
            text(&output.stderr)
        );
        assert_eq!(text(&output.stdout), text(&native), "{door:?}");
    }
    g.assert_run_success(1, &[]);
}

#[test]
fn rand_rng_is_seeded_and_replayable() {
    let g = Guest::assert_build("rand-rng");
    g.assert_audit_clean();
    let out = g.assert_run_success(1, &[]).stdout;
    let fields = assert_fields(&out, "NATIVE_RAND_RNG ", &["first", "bytes"]);
    assert_lower_hex(fields["first"], 16);
    assert_lower_hex(fields["bytes"], 48);
}

#[test]
fn urandom_device_is_seeded_and_replayable() {
    let g = Guest::assert_build("urandom_probe.rs");
    g.assert_audit_clean();
    let out = g.assert_run_success(1, &[]).stdout;
    assert_lower_hex(
        assert_unique_line_payload(&out, "NATIVE_URANDOM bytes="),
        48,
    );
}

#[test]
fn a_thread_writing_to_dev_null_lets_a_sleeping_peer_run() {
    let g = Guest::assert_build("devnull_spin_probe.rs");
    let out = g.assert_run_success(1, &[]).stdout;
    assert_exact_line(&out, "NATIVE_DEVNULL_SPIN stopped=true");
}

#[test]
fn condvar_waits_use_exact_virtual_deadlines() {
    let g = Guest::assert_build("timed_wait_probe.rs");
    g.assert_audit_clean();
    assert_eq!(
        text(&g.assert_run_success(5, &[]).stdout),
        "NATIVE_TIMED_WAIT_RESULT signalled_elapsed_ms=25 timeout_elapsed_ms=100\n"
    );
}

/// The clock reads one recorded run of `futex_anchor_probe.rs` makes.
#[cfg(target_os = "linux")]
fn recorded_clock_reads(g: &Guest, waits: usize, timeout_ns: u64) -> u64 {
    let waits_env = format!("FUTEX_WAITS={waits}");
    let timeout_env = format!("FUTEX_TIMEOUT_NS={timeout_ns}");
    let trace = g
        .dir
        .path()
        .join(format!("futex-{waits}-{timeout_ns}.patina"));
    let output = assert_success(g.command(
        "run",
        &[
            "--seed",
            "1",
            "--env",
            &waits_env,
            "--env",
            &timeout_env,
            "--record",
            trace.to_str().unwrap(),
        ],
    ));
    assert_eq!(
        assert_unique_line_payload(&output.stdout, "NATIVE_FUTEX_ANCHOR "),
        waits.to_string(),
        "every wait times out"
    );
    let output = assert_success(
        common::invoke_with_deadline(
            env!("CARGO_BIN_EXE_cargo-patina"),
            common::native_workspace(),
            &[
                "trace",
                "stats",
                trace.to_str().unwrap(),
                "--format",
                "json",
            ],
            std::time::Duration::from_secs(60),
        )
        .expect("trace stats exceeded 60s"),
    );
    let stats: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    stats["trace_stats"]["kinds"]["clock_now"]["count"]
        .as_u64()
        .unwrap_or(0)
}

/// A relative timed wait's anchor is the kernel's own clock read, before it
/// parks: it records no clock read and so adds nothing to a poll streak; the
/// park and the sleep that ends it are what the runtime sees. So more timed
/// `futex` waits record no more clock reads. A relative wait whose timeout is
/// zero has expired as it begins: it returns without parking, so its read of
/// the clock is the guest's deadline check, recorded as a poll, and a loop of
/// such waits is a clock spin the runtime escalates: each records one clock
/// read. RED before: each timed wait recorded its anchor as a guest
/// `clock_now`, so a timed-wait loop read as a clock spin and escalated
/// sooner than the guest's own reads warrant; and with the zero timeout
/// anchored unrecorded, a spin of them never escalated.
#[cfg(target_os = "linux")]
#[test]
fn a_timed_waits_anchor_is_no_guest_clock_read_but_a_zero_timeout_is_a_poll() {
    let g = Guest::assert_build("futex_anchor_probe.rs");
    let [few, many] = [2, 6].map(|waits| recorded_clock_reads(&g, waits, 1_000_000));
    assert_eq!(few, many, "clock reads recorded for 2 and 6 timed waits");
    let [few, many] = [2, 6].map(|waits| recorded_clock_reads(&g, waits, 0));
    assert_eq!(many - few, 6 - 2, "one clock read per zero-timeout wait");
    g.assert_run_success(
        1,
        &["--env", "FUTEX_WAITS=2", "--env", "FUTEX_TIMEOUT_NS=0"],
    );
}

#[test]
fn recv_timeout_delivers_five_messages_and_five_timeouts() {
    let g = Guest::assert_build("recv_timeout_probe.rs");
    g.assert_audit_clean();
    g.assert_no_imports(&["dispatch_semaphore"]);
    assert_eq!(
        text(&g.assert_run_success(5, &[]).stdout),
        "NATIVE_RECV_TIMEOUT_RESULT delivered=[0, 1, 2, 3, 4] timeouts=5\n"
    );
}

/// syscall(2) is charged as the call it makes, like the trap for the raw
/// instruction: 10 000 identity queries cost no system time, where 10 000
/// system calls cost theirs. RED with syscall(2) charged as a plain door:
/// the two runs' system time is the same.
#[cfg(target_os = "linux")]
#[test]
fn syscall_is_charged_as_the_call_it_makes() {
    let g = Guest::assert_build("syscall_class_probe.rs");
    let system_ns = |which: &str| {
        let output = g.command("run", &["--seed", "5", "--format", "json", "--", which]);
        assert!(output.status.success(), "{}", text(&output.stderr));
        let envelope: serde_json::Value =
            serde_json::from_slice(text(&output.stdout).lines().last().unwrap().as_bytes())
                .unwrap();
        envelope["cpu_charges"]["task1"]["system_ns"]
            .as_u64()
            .unwrap()
    };
    let syscall = patina_dst_abi::ChargeClass::Syscall.cost().system_ns;
    assert_eq!(system_ns("getuid") - system_ns("getpid"), 10_000 * syscall);
}

/// A blocking receive that completes a poll streak, with only a CPU-time
/// timer pending: the escalation it earned is charged as it ends, before it
/// parks, so the timer fires and interrupts it. RED with the escalation
/// deferred to the next call: the receive parks with the timer out of reach
/// and the run stops as a deadlock for every poll count.
#[cfg(target_os = "linux")]
#[test]
fn a_blocking_receive_that_earns_an_escalation_reaches_its_cpu_timer() {
    let g = Guest::assert_build("prof_park_probe.rs");
    // Some count of nonblocking receives (each makes two polls, near 512 of
    // them to a streak) makes the blocking receive's poll the streak's last:
    // a smaller one leaves it short of the streak, a larger one fires the
    // one-shot timer during the polls. At seed 5 the hits sit near 510; the
    // search spirals out from there over a range wide enough that small drift
    // in the per-poll charge still lands inside it, and stops at the first hit.
    let mut counts: Vec<u32> = (496..560).collect();
    counts.sort_by_key(|polls| polls.abs_diff(510));
    let polls = counts
        .into_iter()
        .find(|polls| {
            let output = g.command("run", &["--seed", "5", "--", &polls.to_string()]);
            output.status.success()
                && text(&output.stdout)
                    .contains("PROF_PARK fired_before=false interrupted=true fired=true")
        })
        .expect("some poll count interrupts the blocking receive")
        .to_string();
    // Recorded and replayed alike.
    let trace = g.dir.path().join("prof-park.patina");
    let record = assert_success(g.command(
        "run",
        &[
            "--seed",
            "5",
            "--record",
            trace.to_str().unwrap(),
            "--",
            &polls,
        ],
    ));
    let replay = assert_success(g.command("replay", &[trace.to_str().unwrap()]));
    assert_eq!(record.stdout, replay.stdout);
}

/// A loop that only yields, waiting on a 10 µs sleeper and then on a 10 µs
/// ITIMER_REAL: each yield is a charged call, and its scheduling point shows
/// the time charged, so both arrive. RED with charged time shown only at a
/// door's gateway: time stays frozen through every yield and the run hits
/// its budget.
#[cfg(target_os = "linux")]
#[test]
fn a_yield_loop_reaches_a_sleeping_peer_and_a_real_timer() {
    let g = Guest::assert_build("yield_wait_probe.rs");
    g.assert_audit_clean();
    assert_eq!(
        text(&g.assert_run_success(1, &["--budget", "2000000"]).stdout),
        "NATIVE_YIELD_WAIT_RESULT sleeper_woke=true alarm_fired=true\n"
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
    assert_eq!(
        text(&g.assert_run_success(5, &["--budget", "2000000"]).stdout),
        "NATIVE_POLL_CLOCK_RESULT first_empty=true payload=ping polled=true waited_1ms=true\n"
    );
}

#[test]
fn a_poll_that_never_reads_the_clock_reaches_its_sleeping_peer() {
    // Class pairing: the runtime's escalation
    // (`liveness::tests::an_empty_poll_loop_is_escalated_to_its_peers_deadline_and_replays`).
    // RED before calls were charged: no call the poll made moved virtual time,
    // so the run hit the budget.
    let g = Guest::assert_build("poll_sleeper.rs");
    g.assert_audit_clean();
    assert_exact_line(
        &g.assert_run_success(5, &["--budget", "2000000"]).stdout,
        "NATIVE_POLL_SLEEPER_RESULT first_empty=true payload=ping polled=true",
    );
}

/// The CPU clocks, resource usage and CPU-time timers read the charged
/// calls, as they read the CPU a native run burns.
#[cfg(target_os = "linux")]
#[test]
fn cpu_time_is_the_charge_of_the_guests_calls() {
    let g = Guest::assert_build("cpu_charge_probe.rs");
    g.assert_audit_clean();
    assert_exact_line(
        &g.assert_run_success(5, &[]).stdout,
        "NATIVE_CPU_CHARGE_RESULT slept=true idle_cpu_under_1ms=true rises=true \
rusage_is_cpu_clock=true prof_fired=true prof_fired_yielding=true \
thread_timer_fired=true virtual_fired=true",
    );
}

#[test]
fn pthread_rwlock_ffi_orders_are_repeatable_and_seeded() {
    let g = Guest::assert_build("rwlock_ffi_probe.rs");
    g.assert_audit_clean();
    g.assert_no_imports(&["pthread_rwlock"]);
    let out = g.assert_run_success(1, &[]).stdout;
    assert_thread_counts(
        assert_thread_ids(&out, "NATIVE_RWLOCK_FFI_RESULT order="),
        3,
        3,
    );
    g.assert_seed_variation(&[1, 3, 5], &[]);
}

#[test]
fn sleep_only_advances_when_idle() {
    let g = Guest::assert_build("sleep_order_probe.rs");
    g.assert_audit_clean();
    let out = g.assert_run_success(5, &[]).stdout;
    assert!(matches!(
        assert_unique_line_payload(&out, "NATIVE_SLEEP_ORDER_RESULT "),
        "order=AB a_elapsed_ms=100 work=4950" | "order=BA a_elapsed_ms=100 work=4950"
    ));
}

#[test]
fn udp_latency_is_recorded_for_flag_free_replay() {
    let g = Guest::assert_build("udp_latency_probe.rs");
    g.assert_audit_clean();
    // The receiver's clock starts before the datagram is sent, so its wait
    // spans the whole latency, plus the calls charged around it.
    let elapsed_us = |out: &[u8]| -> u64 {
        let fields = assert_fields(
            out,
            "NATIVE_UDP_LATENCY_RESULT ",
            &["elapsed_us", "payload"],
        );
        assert_eq!(fields["payload"], "ping");
        fields["elapsed_us"].parse().unwrap()
    };
    let out = g
        .assert_run_success(5, &["--net-latency-nanos", "250000000"])
        .stdout;
    let waited = elapsed_us(&out);
    assert!((250_000..250_050).contains(&waited), "{}", text(&out));
    let zero = run_seeded(&g, 5, &["--net-latency-nanos", "0"]);
    assert!(elapsed_us(&zero) < 50, "{}", text(&zero));
}

#[test]
fn tcp_shutdown_dns_and_peer_are_deterministic() {
    let g = Guest::assert_build("tcp_probe.rs");
    g.assert_audit_clean();
    assert_eq!(
        text(&g.assert_run_success(5, &[]).stdout),
        "NATIVE_TCP_RESULT reply=PING peer=127.0.0.1:32768 ipv6_loopback=true dns_nxdomain=true\n"
    );
}

#[test]
fn tokio_signal_parking_lot_rustix_use_product_backend() {
    let g = Guest::assert_build("tokio");
    g.assert_audit_clean();
    assert_eq!(
        text(&g.assert_run_success(1, &[]).stdout),
        "NATIVE_TOKIO_RESULT client_got=pong server_got=ping lock=42 rustix_read=rustix-ok\n"
    );
}

fn tokio_tcp_elapsed_us(out: &[u8]) -> u64 {
    let fields = assert_fields(out, "NATIVE_TOKIO_TCP_RESULT ", &["reply", "elapsed_us"]);
    assert_eq!(fields["reply"], "pong", "{}", text(out));
    fields["elapsed_us"].parse().unwrap()
}

/// The workers a default `new_multi_thread()` runtime reports, after their
/// threads started.
fn tokio_workers(out: &[u8]) -> usize {
    let fields = assert_fields(out, "NATIVE_TOKIO_WORKERS ", &["workers", "started"]);
    assert_eq!(fields["started"], fields["workers"], "{}", text(out));
    fields["workers"].parse().unwrap()
}

/// A tokio TCP exchange, on each runtime shape a program builds:
///
/// * current-thread: a segment in flight to a socket the reactor waits on
///   arrives when virtual time reaches its delivery, so the park in
///   `epoll_wait` (`kevent` on macOS) ends there, not at the reactor's next
///   timer (the 1 s timeout the guest arms around the exchange). Class
///   pairing: every readiness park (epoll, kqueue, poll, select) takes its
///   deadline from the one fan-in registration, `register_readiness_waiters`,
///   which carries the earliest in-flight delivery among the watched sockets.
/// * two workers: the I/O driver parks in the reactor on one worker while the
///   other accepts, registers and drives the sockets. A registration wakes the
///   parked reactor to rescan (otherwise the accepted socket's queued bytes
///   are never seen and, with no timer armed, the run is a deadlock), and an
///   event that drains one waiter from several of its queues wakes it once
///   (otherwise the second wake is an invalid scheduler transition). Class
///   pairing: the scheduler refuses both failures loudly (`deadlock`,
///   `invalid_state`), on every seed explored.
/// * the default `new_multi_thread()`: one worker per virtual CPU, so the
///   default machine gives it several, and `--cpus 1` one.
///
/// A reactor wait nothing can end (a server reading a connection its client
/// never writes to, with no timer armed) is the scheduler's deadlock, naming
/// the wait.
#[test]
fn tokio_runtimes_drive_tcp_through_the_virtual_reactor() {
    let g = Guest::assert_build("tokio-tcp");
    g.assert_audit_clean();
    let out = run_seeded(
        &g,
        1,
        &[
            "--env",
            "TOKIO_TCP_MODE=current",
            "--net-latency-nanos",
            "2000000",
        ],
    );
    // Two 2 ms hops, plus the calls charged around them.
    let elapsed = tokio_tcp_elapsed_us(&out);
    assert!((4_000..4_100).contains(&elapsed), "{}", text(&out));

    let multi = ["--env", "TOKIO_TCP_MODE=multi"];
    tokio_tcp_elapsed_us(&g.assert_run_success(1, &multi).stdout);
    for seed in 2..=4 {
        tokio_tcp_elapsed_us(&run_seeded(&g, seed, &multi));
    }

    let out = run_seeded(&g, 3, &["--env", "TOKIO_TCP_MODE=default"]);
    tokio_tcp_elapsed_us(&out);
    assert_eq!(tokio_workers(&out), patina_dst_abi::DEFAULT_CPUS as usize);
    assert!(tokio_workers(&out) > 1, "{}", text(&out));
    let out = run_seeded(&g, 3, &["--env", "TOKIO_TCP_MODE=default", "--cpus", "1"]);
    tokio_tcp_elapsed_us(&out);
    assert_eq!(tokio_workers(&out), 1);

    let wait = if cfg!(target_os = "macos") {
        "kevent"
    } else {
        "epoll-wait"
    };
    assert_refused(
        g.command("run", &["--seed", "1", "--env", "TOKIO_TCP_MODE=stall"]),
        &["deadlock", wait],
    );
}

#[cfg(target_os = "macos")]
mod darwin {
    use super::*;

    #[test]
    fn os_unfair_lock_contention_is_repeatable() {
        let g = Guest::assert_build("os_unfair_lock_probe.rs");
        g.assert_audit_clean();
        let out = g.assert_run_success(1, &[]).stdout;
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
    let out = g.assert_run_success(5, &[]).stdout;
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
    let out = g.assert_run_success(5, &[]).stdout;
    let fields = assert_fields(&out, "TIMERFD_DEADLINE ", &["ready", "expirations"]);
    assert!(["0", "1"].contains(&fields["ready"]), "{fields:?}");
    assert_eq!(fields["expirations"], "1");
}
