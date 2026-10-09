//! Harness runtime installation, interposed services, threads, and replay.

#[cfg(test)]
mod tests {
    use super::super::*;

    /// The single `HARNESS_OUT ...` line the harness fixtures print.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn harness_out_line(output: &Output) -> String {
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .find(|line| line.starts_with("HARNESS_OUT"))
            .unwrap_or_else(|| {
                panic!(
                    "missing HARNESS_OUT in stdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                )
            })
            .to_owned()
    }

    /// Parse `elapsed=N` (virtual monotonic nanoseconds observed through std's clock)
    /// from a harness fixture's output line.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn harness_elapsed(output: &Output) -> u128 {
        harness_out_line(output)
            .split("elapsed=")
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(|| panic!("missing elapsed= in harness output"))
    }

    // A harness fixture that reads a file back through `std::fs` and times a
    // `std::thread::sleep` through std's clock — all interposed by the shim, so the
    // output (including the elapsed virtual-time reading) is a pure function of the
    // seed.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const HARNESS_DETERMINISM_SRC: &str = r#"
use std::time::Instant;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    patina_dst_harness::run(|| {
        std::fs::create_dir_all("/state")?;
        std::fs::write("/state/v", b"hello")?;
        let read = std::fs::read_to_string("/state/v")?;
        let start = Instant::now();
        std::thread::sleep(std::time::Duration::from_nanos(10));
        let elapsed = start.elapsed().as_nanos();
        println!("HARNESS_OUT read={read} elapsed={elapsed}");
        Ok::<(), std::io::Error>(())
    })?;
    Ok(())
}
"#;

    // Gate 1: a harness binary executed directly (no Patina control plane) fails
    // loudly with NotUnderPatina BEFORE any application code runs — never a silent
    // host-effect fallback.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn harness_direct_exec_without_patina_fails_closed() {
        let directory = tempdir().unwrap();
        let fixture = directory.path().join("det");
        write_harness_fixture(&fixture, "harness-det-direct", HARNESS_DETERMINISM_SRC);
        let bin = directory.path().join("harness-det-direct-bin");
        build_harness_bin(&fixture, &bin);

        // Direct exec with a scrubbed environment: no PATINA_MODE, so the shim's
        // constructor installs nothing and `run` fails closed.
        let output = Command::new(&bin).env_clear().output().unwrap();
        assert!(
            !output.status.success(),
            "harness binary ran to success without Patina"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("not running under `cargo patina run`"),
            "missing NotUnderPatina diagnostic:\nstderr:\n{stderr}"
        );
        assert!(
            !String::from_utf8_lossy(&output.stdout).contains("HARNESS_OUT"),
            "application code ran before the fail-closed check"
        );
    }

    // Gate 2: `cargo patina run --harness --target native` succeeds with std::fs and
    // the std clock interposed, and is byte-identical across repeated runs at the same
    // seed (determinism, including the std clock reads).
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn harness_run_is_deterministic_with_std_interposed() {
        let directory = tempdir().unwrap();
        let fixture = directory.path().join("det");
        write_harness_fixture(&fixture, "harness-det", HARNESS_DETERMINISM_SRC);
        let bin = directory.path().join("harness-det-bin");
        build_harness_bin(&fixture, &bin);

        let first = invoke(
            native_workspace(),
            &["run", bin.to_str().unwrap(), "--harness", "--seed", "1"],
        );
        let baseline = harness_out_line(&first);
        assert!(
            baseline.contains("read=hello"),
            "std::fs was not interposed (unexpected output): {baseline}"
        );
        for _ in 0..2 {
            let again = invoke(
                native_workspace(),
                &["run", bin.to_str().unwrap(), "--harness", "--seed", "1"],
            );
            assert_eq!(
                baseline,
                harness_out_line(&again),
                "harness output (incl. std clock reads) is not byte-identical across runs"
            );
        }
    }

    // A harness fixture whose configuration is toggled by a guest argument: with
    // `--jitter` the harness adds a fixed seeded sleep jitter, observable through the
    // same std clock the application reads.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const HARNESS_JITTER_TOGGLE_SRC: &str = r#"
use std::time::Instant;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    patina_dst_harness::run_with(
        |harness| {
            if std::env::args().any(|arg| arg == "--jitter") {
                Ok(harness.sleep_jitter_nanos(1_000_000, 1_000_000))
            } else {
                Ok(harness)
            }
        },
        || {
            let start = Instant::now();
            std::thread::sleep(std::time::Duration::from_nanos(10));
            println!("HARNESS_OUT elapsed={}", start.elapsed().as_nanos());
            Ok::<(), std::io::Error>(())
        },
    )?;
    Ok(())
}
"#;

    // Gate 3: a harness-configured knob observably affects behavior seen through
    // ordinary application code. A configured sleep jitter shifts the std-clock
    // elapsed reading by exactly the jitter, proving the overlay reached the same
    // `RuntimeConfig` field the CLI `--sleep-jitter-nanos` sets.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn harness_configured_knob_affects_std_observed_behavior() {
        let directory = tempdir().unwrap();
        let fixture = directory.path().join("jitter");
        write_harness_fixture(&fixture, "harness-jitter", HARNESS_JITTER_TOGGLE_SRC);
        let bin = directory.path().join("harness-jitter-bin");
        build_harness_bin(&fixture, &bin);

        let base = invoke(
            native_workspace(),
            &["run", bin.to_str().unwrap(), "--harness", "--seed", "1"],
        );
        let jittered = invoke(
            native_workspace(),
            &[
                "run",
                bin.to_str().unwrap(),
                "--harness",
                "--seed",
                "1",
                "--",
                "--jitter",
            ],
        );
        let base_elapsed = harness_elapsed(&base);
        let jittered_elapsed = harness_elapsed(&jittered);
        // The requested 10 ns, and the calls charged around the sleep.
        assert!(
            (10..10_000).contains(&base_elapsed),
            "baseline sleep should advance virtual time by the requested 10ns: {base_elapsed}"
        );
        assert_eq!(
            jittered_elapsed,
            base_elapsed + 1_000_000,
            "harness-configured sleep jitter did not shift the std-observed elapsed time"
        );
    }

    // Gate 4: record then flag-free replay of a harness-driven application is
    // byte-identical. Replay of a harness binary carries `--harness` (deferred init)
    // but no semantic flags — the trace is authoritative.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn harness_record_then_flag_free_replay_is_byte_identical() {
        let directory = tempdir().unwrap();
        let fixture = directory.path().join("det");
        write_harness_fixture(&fixture, "harness-replay", HARNESS_DETERMINISM_SRC);
        let bin = directory.path().join("harness-replay-bin");
        build_harness_bin(&fixture, &bin);

        let trace = directory.path().join("harness.patina");
        let recorded = invoke(
            native_workspace(),
            &[
                "run",
                bin.to_str().unwrap(),
                "--harness",
                "--seed",
                "1",
                "--record",
                trace.to_str().unwrap(),
                "--fingerprint",
                "harness-replay",
            ],
        );
        let replayed = invoke(
            native_workspace(),
            &[
                "replay",
                bin.to_str().unwrap(),
                trace.to_str().unwrap(),
                "--harness",
                "--fingerprint",
                "harness-replay",
            ],
        );
        assert_eq!(
            harness_out_line(&recorded),
            harness_out_line(&replayed),
            "record and flag-free harness replay diverged"
        );
    }

    // A harness fixture that unconditionally sets a fixed sleep jitter, so two builds
    // with different jitter values embed conflicting fault configuration.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn harness_fixed_jitter_src(jitter: u64) -> String {
        format!(
            r#"
fn main() -> Result<(), Box<dyn std::error::Error>> {{
    patina_dst_harness::run_with(
        |harness| Ok(harness.sleep_jitter_nanos({jitter}, {jitter})),
        || {{
            std::thread::sleep(std::time::Duration::from_nanos(1));
            println!("HARNESS_OUT ok");
            Ok::<(), std::io::Error>(())
        }},
    )?;
    Ok(())
}}
"#
        )
    }

    // Gate 5: replaying with a conflicting harness configuration fails closed. The
    // harness overlay flows through the same `RuntimeConfig::faults` field the CLI
    // sets, so the runtime's `reconcile_replay_faults` (the trace is authoritative)
    // catches a divergent harness-configured knob exactly like a CLI flag conflict.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn harness_replay_with_conflicting_config_fails_closed() {
        let directory = tempdir().unwrap();
        let fixture_a = directory.path().join("jit-a");
        let fixture_b = directory.path().join("jit-b");
        write_harness_fixture(
            &fixture_a,
            "harness-jit-a",
            &harness_fixed_jitter_src(1_000_000),
        );
        write_harness_fixture(
            &fixture_b,
            "harness-jit-b",
            &harness_fixed_jitter_src(2_000_000),
        );
        let bin_a = directory.path().join("harness-jit-a-bin");
        let bin_b = directory.path().join("harness-jit-b-bin");
        build_harness_bin(&fixture_a, &bin_a);
        build_harness_bin(&fixture_b, &bin_b);

        let trace = directory.path().join("jit.patina");
        invoke(
            native_workspace(),
            &[
                "run",
                bin_a.to_str().unwrap(),
                "--harness",
                "--seed",
                "1",
                "--record",
                trace.to_str().unwrap(),
                "--fingerprint",
                "harness-jit",
            ],
        );

        // Binary B embeds a different (conflicting) sleep jitter; both share the same
        // fingerprint (faults are reconciled from trace metadata, not fingerprinted),
        // so the run reaches fault reconciliation and fails closed there.
        let conflict = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            native_workspace(),
            &[
                "replay",
                bin_b.to_str().unwrap(),
                trace.to_str().unwrap(),
                "--harness",
                "--fingerprint",
                "harness-jit",
            ],
        );
        assert!(
            !conflict.status.success(),
            "replay with a conflicting harness config succeeded"
        );
        let stderr = String::from_utf8_lossy(&conflict.stderr);
        assert!(
            stderr.contains("conflict with the trace's recorded configuration"),
            "missing fault-reconciliation conflict diagnostic:\nstderr:\n{stderr}"
        );

        // The original binary (matching config) replays cleanly.
        let matching = invoke(
            native_workspace(),
            &[
                "replay",
                bin_a.to_str().unwrap(),
                trace.to_str().unwrap(),
                "--harness",
                "--fingerprint",
                "harness-jit",
            ],
        );
        assert!(harness_out_line(&matching).contains("ok"));
    }

    // A harness fixture that performs an interposed std effect BEFORE calling the
    // harness — the classic configure-after-boundary mistake.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const HARNESS_BOUNDARY_SRC: &str = r#"
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Interposed std effect before the harness installs the runtime.
    std::fs::create_dir_all("/early")?;
    println!("HARNESS_APP_RAN");
    patina_dst_harness::run(|| Ok::<(), std::io::Error>(()))?;
    Ok(())
}
"#;

    // Gate 6: an interposed effect before the harness installs the runtime fails
    // closed. Under deferred init the effect reaches the boundary with no context
    // installed and no auto-init is allowed, so the shim aborts loudly and the
    // application code never proceeds.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn harness_effect_before_install_fails_closed() {
        let directory = tempdir().unwrap();
        let fixture = directory.path().join("boundary");
        write_harness_fixture(&fixture, "harness-boundary", HARNESS_BOUNDARY_SRC);
        let bin = directory.path().join("harness-boundary-bin");
        build_harness_bin(&fixture, &bin);

        let output = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            native_workspace(),
            &["run", bin.to_str().unwrap(), "--harness", "--seed", "1"],
        );
        assert!(
            !output.status.success(),
            "an effect before the harness install did not fail the run"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("harness has not installed the runtime yet"),
            "missing boundary-before-install diagnostic:\nstderr:\n{stderr}"
        );
        assert!(
            !String::from_utf8_lossy(&output.stdout).contains("HARNESS_APP_RAN"),
            "application code ran past the pre-install boundary"
        );
    }

    // A harness that names its own services. `dns_service` allocates the virtual
    // address and inserts the host-table entry; `dns_entry` pins one explicitly. The
    // unregistered name must stay NXDOMAIN, so an over-broad table cannot make this
    // pass. The threaded wildcard-bind producer half has its own gate below
    // (`harness_dns_service_reaches_a_listener_thread_and_replays_flag_free`).
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const HARNESS_DNS_SRC: &str = r#"
use std::net::ToSocketAddrs;

fn resolve(name: &str) -> String {
    match (name, 9500).to_socket_addrs() {
        Ok(mut addrs) => match addrs.next() {
            Some(addr) => addr.ip().to_string(),
            None => "empty".to_string(),
        },
        Err(_) => "NXDOMAIN".to_string(),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    patina_dst_harness::run_with(
        |harness| {
            Ok(harness
                .dns_entry("pinned.internal", "10.9.9.9")
                .dns_service("db.internal"))
        },
        || {
            println!(
                "HARNESS_OUT service={} pinned={} absent={}",
                resolve("db.internal"),
                resolve("pinned.internal"),
                resolve("absent.internal"),
            );
            Ok::<(), std::io::Error>(())
        },
    )?;
    Ok(())
}
"#;

    // Gate: the harness DNS builders are the code-side twin of `--dns-entry`. They
    // must reach the SAME `RuntimeConfig` host table (so the names resolve, the
    // allocation is the documented one, and undefined names stay NXDOMAIN) and be
    // recorded into the trace so replay is flag-free — the harness closure re-applies
    // the overlay on replay, so this also proves the overlay and the authoritative
    // trace reconcile rather than conflict.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn harness_dns_service_and_entry_reach_the_host_table_and_replay_flag_free() {
        let directory = tempdir().unwrap();
        let fixture = directory.path().join("dns");
        write_harness_fixture(&fixture, "harness-dns", HARNESS_DNS_SRC);
        let bin = directory.path().join("harness-dns-bin");
        build_harness_bin(&fixture, &bin);

        let trace = directory.path().join("harness-dns.patina");
        let recorded = invoke(
            native_workspace(),
            &[
                "run",
                bin.to_str().unwrap(),
                "--harness",
                "--seed",
                "1",
                "--record",
                trace.to_str().unwrap(),
            ],
        );
        let line = harness_out_line(&recorded);
        assert!(
            line.contains("service=10.0.0.1"),
            "dns_service did not allocate the documented address: {line}"
        );
        assert!(
            line.contains("pinned=10.9.9.9"),
            "dns_entry did not reach the host table: {line}"
        );
        assert!(
            line.contains("absent=NXDOMAIN"),
            "an unregistered name must stay NXDOMAIN: {line}"
        );

        let replayed = invoke(
            native_workspace(),
            &[
                "replay",
                bin.to_str().unwrap(),
                trace.to_str().unwrap(),
                "--harness",
            ],
        );
        assert_eq!(
            harness_out_line(&replayed),
            line,
            "flag-free replay of a harness-configured DNS table diverged"
        );
    }

    // A harness whose application code spawns worker threads that do interposed work
    // and are joined inside the closure — the ordinary multi-threaded shape. Each
    // worker sleeps (an interposed clock effect) so it is a real managed task with
    // scheduling boundaries, not a scheduler-invisible one.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const HARNESS_THREAD_SRC: &str = r#"
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    patina_dst_harness::run(|| {
        let counter = Arc::new(AtomicU64::new(0));
        let mut workers = Vec::new();
        for step in 1..=3u64 {
            let counter = Arc::clone(&counter);
            workers.push(std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_nanos(step));
                counter.fetch_add(step, Ordering::SeqCst);
                step * 2
            }));
        }
        let mut doubled = 0u64;
        for worker in workers {
            doubled += worker.join().unwrap();
        }
        println!(
            "HARNESS_OUT total={} doubled={}",
            counter.load(Ordering::SeqCst),
            doubled
        );
        Ok::<(), std::io::Error>(())
    })?;
    Ok(())
}
"#;

    // Gate: a harness guest that spawns threads runs to a clean exit, its recorded
    // trace finalizes, and a flag-free replay is byte-identical.
    //
    // Regression pin for the harness thread-spawn abort: the runtime's end-of-run
    // multithreaded schedule diagnostic is emitted from `Context::finish()`, which
    // `patina_shutdown` reaches AFTER taking the context out of the slot. Its
    // suppression lookup went out through the interposed `getenv`, and under
    // deferred init (`--harness`) an absent context was classified as
    // "the harness has not installed the runtime yet" — so every harness guest that
    // spawned a thread aborted at shutdown (exit 134) with a never-finalized trace.
    // Single-threaded harness guests never reached it because the diagnostic is only
    // emitted for a run that had concurrency.
    //
    // Class-level pairing: the pre-install question now has one choke-point,
    // `missing_context_is_pre_harness_install` in the native shim, which every
    // interposer that can meet an absent context consults, and which keys on whether
    // the harness installed rather than on whether a context is currently present. A
    // new interposer misclassifying teardown as pre-install would have to bypass that
    // choke-point. `harness_effect_before_install_fails_closed` is its non-vacuity
    // partner: it proves the pre-install abort still fires, so this gate cannot be
    // satisfied by weakening the detector into silence.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn harness_guest_that_spawns_threads_finalizes_and_replays_flag_free() {
        let directory = tempdir().unwrap();
        let fixture = directory.path().join("threads");
        write_harness_fixture(&fixture, "harness-threads", HARNESS_THREAD_SRC);
        let bin = directory.path().join("harness-threads-bin");
        build_harness_bin(&fixture, &bin);

        let trace = directory.path().join("harness-threads.patina");
        let recorded = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            native_workspace(),
            &[
                "run",
                bin.to_str().unwrap(),
                "--harness",
                "--seed",
                "1",
                "--record",
                trace.to_str().unwrap(),
            ],
        );
        assert!(
            recorded.status.success(),
            "a harness guest that spawns threads did not exit cleanly:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&recorded.stdout),
            String::from_utf8_lossy(&recorded.stderr),
        );
        let line = harness_out_line(&recorded);
        assert!(
            line.contains("total=6") && line.contains("doubled=12"),
            "the worker threads did not all run: {line}"
        );
        assert!(
            fs::metadata(&trace).is_ok_and(|meta| meta.len() > 0),
            "the recorded trace was never finalized"
        );

        let replayed = invoke(
            native_workspace(),
            &[
                "replay",
                bin.to_str().unwrap(),
                trace.to_str().unwrap(),
                "--harness",
            ],
        );
        assert_eq!(
            harness_out_line(&replayed),
            line,
            "flag-free replay of a multi-threaded harness run diverged"
        );
    }

    // The headline threaded harness shape: a named service whose listener runs on
    // its own thread. The server is ordinary production code — it binds `0.0.0.0` and
    // never learns the name exists — and the client reaches it purely by resolving
    // the `dns_service` name the harness registered.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const HARNESS_DNS_SERVICE_THREAD_SRC: &str = r#"
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    patina_dst_harness::run_with(
        |harness| Ok(harness.dns_service("db.internal")),
        || {
            let listener = TcpListener::bind("0.0.0.0:9600")?;
            let server = std::thread::spawn(move || {
                let (mut socket, _) = listener.accept().expect("accept");
                let mut request = [0u8; 4];
                socket.read_exact(&mut request).expect("read request");
                socket.write_all(b"pong").expect("write reply");
                String::from_utf8_lossy(&request).into_owned()
            });
            let mut client = TcpStream::connect("db.internal:9600")?;
            let served = client.peer_addr()?.ip().to_string();
            client.write_all(b"ping")?;
            let mut reply = [0u8; 4];
            client.read_exact(&mut reply)?;
            let request = server.join().expect("listener thread");
            println!(
                "HARNESS_OUT dialed={served} served_request={request} reply={}",
                String::from_utf8_lossy(&reply)
            );
            Ok::<(), std::io::Error>(())
        },
    )?;
    Ok(())
}
"#;

    // Gate: the `dns_service` producer pattern works end to end from a harness — a
    // listener thread inside the closure receives traffic the client addressed to the
    // service's allocated virtual IP, and the whole run replays flag-free.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn harness_dns_service_reaches_a_listener_thread_and_replays_flag_free() {
        let directory = tempdir().unwrap();
        let fixture = directory.path().join("dns-thread");
        write_harness_fixture(
            &fixture,
            "harness-dns-thread",
            HARNESS_DNS_SERVICE_THREAD_SRC,
        );
        let bin = directory.path().join("harness-dns-thread-bin");
        build_harness_bin(&fixture, &bin);

        let trace = directory.path().join("harness-dns-thread.patina");
        let recorded = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            native_workspace(),
            &[
                "run",
                bin.to_str().unwrap(),
                "--harness",
                "--seed",
                "1",
                "--record",
                trace.to_str().unwrap(),
            ],
        );
        assert!(
            recorded.status.success(),
            "the harness listener-thread service run did not exit cleanly:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&recorded.stdout),
            String::from_utf8_lossy(&recorded.stderr),
        );
        let line = harness_out_line(&recorded);
        assert!(
            line.contains("dialed=10.0.0.1"),
            "the client did not dial the dns_service's allocated address: {line}"
        );
        assert!(
            line.contains("served_request=ping") && line.contains("reply=pong"),
            "the wildcard-bound listener thread did not serve the named request: {line}"
        );

        let replayed = invoke(
            native_workspace(),
            &[
                "replay",
                bin.to_str().unwrap(),
                trace.to_str().unwrap(),
                "--harness",
            ],
        );
        assert_eq!(
            harness_out_line(&replayed),
            line,
            "flag-free replay of the harness listener-thread service run diverged"
        );
    }

    // `--harness` is native-only: on a WASI run it is rejected up front (the WASI
    // supervisor owns run configuration), never silently ignored.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn harness_flag_rejected_for_wasi_target() {
        let directory = tempdir().unwrap();
        let module = directory.path().join("app.wasm");
        fs::write(
            &module,
            wat::parse_str("(module (func (export \"_start\")))").unwrap(),
        )
        .unwrap();
        let output = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            native_workspace(),
            &["run", module.to_str().unwrap(), "--harness"],
        );
        assert!(
            !output.status.success(),
            "--harness on a WASI run succeeded"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("`run` of a WASI module does not accept --harness"),
            "missing native-only rejection:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
