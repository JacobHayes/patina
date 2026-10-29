//! Harness runtime installation, interposed services, threads, and replay.

use super::*;

/// One `patina-dst-harness` guest whose first argument picks the scenario:
///
/// * none: an `std::fs` round trip and a timed `std::thread::sleep`, all
///   interposed, so the output (the elapsed virtual-time reading included) is
///   a pure function of the seed;
/// * `jitter`: the same body under a harness-configured fixed sleep jitter;
/// * `dns`: `dns_service` allocates a virtual address and `dns_entry` pins one,
///   while an unregistered name stays NXDOMAIN;
/// * `threads`: worker threads doing interposed sleeps, joined in the closure;
/// * `dns-thread`: a wildcard-bound listener thread served through the name a
///   `dns_service` registered;
/// * `knobs`: the `round_trip` body under buggify and PCT enabled in code;
/// * `boundary`: an interposed `std::fs` effect before the harness installs;
/// * `early-write`: captured output before the harness installs.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const HARNESS_SRC: &str = r#"
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn resolve(name: &str) -> String {
    match (name, 9500).to_socket_addrs() {
        Ok(mut addrs) => match addrs.next() {
            Some(addr) => addr.ip().to_string(),
            None => "empty".to_string(),
        },
        Err(_) => "NXDOMAIN".to_string(),
    }
}

fn round_trip() -> std::io::Result<()> {
    std::fs::create_dir_all("/state")?;
    std::fs::write("/state/v", b"hello")?;
    let read = std::fs::read_to_string("/state/v")?;
    let start = Instant::now();
    std::thread::sleep(Duration::from_nanos(10));
    let elapsed = start.elapsed().as_nanos();
    println!("HARNESS_OUT read={read} elapsed={elapsed}");
    Ok(())
}

fn threads() -> std::io::Result<()> {
    let counter = Arc::new(AtomicU64::new(0));
    let mut workers = Vec::new();
    for step in 1..=3u64 {
        let counter = Arc::clone(&counter);
        workers.push(std::thread::spawn(move || {
            std::thread::sleep(Duration::from_nanos(step));
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
    Ok(())
}

fn dns_thread() -> std::io::Result<()> {
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
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mode = std::env::args().nth(1).unwrap_or_default();
    match mode.as_str() {
        "boundary" => {
            // Interposed std effect before the harness installs the runtime.
            std::fs::create_dir_all("/early")?;
            println!("HARNESS_APP_RAN");
            patina_dst_harness::run(|| Ok::<(), std::io::Error>(()))?;
        }
        "early-write" => {
            // Captured output, which needs no runtime, before the harness
            // installs one.
            println!("HARNESS_EARLY_WRITE");
            patina_dst_harness::run(|| {
                println!("HARNESS_APP_RAN");
                Ok::<(), std::io::Error>(())
            })?;
        }
        _ => patina_dst_harness::run_with(
            |harness| {
                Ok(match mode.as_str() {
                    "jitter" => harness.sleep_jitter_nanos(1_000_000, 1_000_000),
                    "knobs" => harness.buggify().schedule_pct(2, 100),
                    "dns" => harness
                        .dns_entry("pinned.internal", "10.9.9.9")
                        .dns_service("db.internal"),
                    "dns-thread" => harness.dns_service("db.internal"),
                    _ => harness,
                })
            },
            || match mode.as_str() {
                "dns" => {
                    println!(
                        "HARNESS_OUT service={} pinned={} absent={}",
                        resolve("db.internal"),
                        resolve("pinned.internal"),
                        resolve("absent.internal"),
                    );
                    Ok(())
                }
                "threads" => threads(),
                "dns-thread" => dns_thread(),
                _ => round_trip(),
            },
        )?,
    }
    Ok(())
}
"#;

/// The [`HARNESS_SRC`] guest, built once per run.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn harness_guest() -> PathBuf {
    super::run_facts::shared_guest("harness-guest", |directory| {
        let package = directory.join("pkg");
        write_harness_fixture(&package, "harness-guest", HARNESS_SRC);
        // The package sits under the workspace's target base, so it declares
        // its own workspace root.
        let manifest = package.join("Cargo.toml");
        let mut contents = fs::read_to_string(&manifest).unwrap();
        contents.push_str("\n[workspace]\n");
        fs::write(&manifest, contents).unwrap();
        let binary = directory.join("harness-guest");
        build_harness_bin(&package, &binary);
        binary
    })
}

#[cfg(test)]
mod tests {
    use super::super::*;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use super::harness_guest;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use common::assert_success;

    /// The single `HARNESS_OUT ...` line the harness guest prints.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn harness_out_line(output: &Output) -> String {
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .find(|line| line.starts_with("HARNESS_OUT"))
            .unwrap_or_else(|| {
                panic!(
                    "missing HARNESS_OUT in stdout:\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                )
            })
            .to_owned()
    }

    /// Parse `elapsed=N` (virtual monotonic nanoseconds observed through std's
    /// clock) from a harness output line.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn harness_elapsed(line: &str) -> u128 {
        line.split("elapsed=")
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(|| panic!("missing elapsed= in {line}"))
    }

    /// A run of the harness binary in `mode` at seed 1, with the guest's arguments last.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn harness_run(bin: &Path, mode: &str, extra: &[&str]) -> Output {
        let mut args = vec!["run", bin.to_str().unwrap(), "--seed", "1"];
        args.extend_from_slice(extra);
        if !mode.is_empty() {
            args.extend(["--", mode]);
        }
        invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            native_workspace(),
            &args,
        )
    }

    // Knobs a harness turns on in code are recorded with the policy part of the
    // fingerprint computed by the runtime, so the trace replays with no flag on
    // the command line and a replay that arms them differently still fails closed.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_harness_that_enables_buggify_in_code_records_and_replays_without_flags() {
        let bin = harness_guest();
        let directory = tempdir().unwrap();
        let trace = directory.path().join("knobs.patina");
        let recorded = assert_success(harness_run(
            &bin,
            "knobs",
            &["--record", trace.to_str().unwrap()],
        ));
        let metadata = patina_dst_trace::TraceBundle::load(&trace)
            .unwrap()
            .metadata;
        assert!(metadata.buggify.is_some(), "buggify was not recorded");
        assert!(
            metadata.fingerprint.ends_with("+buggify+pct"),
            "the runtime must fold the harness-enabled knobs into the fingerprint: {}",
            metadata.fingerprint
        );
        let replayed = invoke(
            native_workspace(),
            &["replay", bin.to_str().unwrap(), trace.to_str().unwrap()],
        );
        assert_eq!(
            harness_out_line(&replayed),
            harness_out_line(&recorded),
            "a flag-free replay of a harness that enabled buggify diverged"
        );
    }

    // One harness binary carries every interposed-service claim. Executed directly
    // (no Patina control plane) it fails loudly with NotUnderPatina before any
    // application code runs, never a silent host-effect fallback. Under
    // `cargo patina run` each scenario runs with its std effects
    // interposed and its recording finalized, and a replay carrying no
    // flag (the binary's marker defers init: no semantic flags, no guest arguments, since the
    // trace is authoritative) prints the same bytes. The harness closure re-applies
    // its overlay on replay, so the DNS scenarios also prove the overlay and the
    // authoritative trace reconcile rather than conflict.
    //
    // The threaded scenario pins the harness thread-spawn abort: the runtime's
    // end-of-run multithreaded schedule diagnostic is emitted from
    // `Context::finish()`, after `patina_shutdown` took the context out of its
    // slot, and its interposed `getenv` once classified the absent context as "the
    // harness has not installed the runtime yet", so every harness guest that
    // spawned a thread aborted at shutdown with a never-finalized trace. The
    // pre-install question has one choke-point,
    // `missing_context_is_pre_harness_install` in the native shim, keyed on whether
    // the harness installed; `harness_boundary_effects_before_install_fail_closed`
    // is its non-vacuity partner.
    //
    // A harness-configured knob observably affects behavior seen through ordinary
    // application code: a configured sleep jitter shifts the std-clock elapsed
    // reading by exactly the jitter, so the overlay reached the same
    // `RuntimeConfig` field the CLI `--sleep-jitter-nanos` sets.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn harness_fails_closed_outside_patina_and_each_service_records_and_replays() {
        let bin = harness_guest();
        let directory = tempdir().unwrap();

        // Direct exec with a scrubbed environment: no PATINA_RT_MODE, so the shim's
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

        let mut lines = BTreeMap::new();
        for mode in ["", "dns", "threads", "dns-thread"] {
            let trace = directory.path().join(format!("harness-{mode}.patina"));
            let recorded = assert_success(harness_run(
                &bin,
                mode,
                &["--record", trace.to_str().unwrap()],
            ));
            let line = harness_out_line(&recorded);
            assert!(
                fs::metadata(&trace).is_ok_and(|meta| meta.len() > 0),
                "{mode:?}: the recorded trace was never finalized"
            );
            let replayed = invoke(
                native_workspace(),
                &["replay", bin.to_str().unwrap(), trace.to_str().unwrap()],
            );
            assert_eq!(
                harness_out_line(&replayed),
                line,
                "{mode:?}: record and harness replay diverged"
            );
            lines.insert(mode, line);
        }

        let base = &lines[""];
        assert!(
            base.contains("read=hello"),
            "std::fs was not interposed (unexpected output): {base}"
        );
        let base_elapsed = harness_elapsed(base);
        // The requested 10 ns, and the calls charged around the sleep.
        assert!(
            (10..10_000).contains(&base_elapsed),
            "baseline sleep should advance virtual time by the requested 10ns: {base_elapsed}"
        );
        let jittered = assert_success(harness_run(&bin, "jitter", &[]));
        assert_eq!(
            harness_elapsed(&harness_out_line(&jittered)),
            base_elapsed + 1_000_000,
            "harness-configured sleep jitter did not shift the std-observed elapsed time"
        );

        let dns = &lines["dns"];
        assert!(
            dns.contains("service=10.0.0.1"),
            "dns_service did not allocate the documented address: {dns}"
        );
        assert!(
            dns.contains("pinned=10.9.9.9"),
            "dns_entry did not reach the host table: {dns}"
        );
        assert!(
            dns.contains("absent=NXDOMAIN"),
            "an unregistered name must stay NXDOMAIN: {dns}"
        );

        let threads = &lines["threads"];
        assert!(
            threads.contains("total=6") && threads.contains("doubled=12"),
            "the worker threads did not all run: {threads}"
        );

        let served = &lines["dns-thread"];
        assert!(
            served.contains("dialed=10.0.0.1"),
            "the client did not dial the dns_service's allocated address: {served}"
        );
        assert!(
            served.contains("served_request=ping") && served.contains("reply=pong"),
            "the wildcard-bound listener thread did not serve the named request: {served}"
        );
    }

    // An effect before the harness installs the runtime fails closed. Under deferred
    // init an interposed effect reaches the boundary with no context installed and
    // no auto-init is allowed, so the shim aborts loudly. A guest write is a
    // boundary effect too, though capture answers it with no context installed: the
    // install that follows refuses. Either way the application code never proceeds.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn harness_boundary_effects_before_install_fail_closed() {
        let bin = harness_guest();
        for (mode, diagnostic) in [
            ("boundary", "harness has not installed the runtime yet"),
            // The shim's own refusal, written straight to the host: the guest's
            // report of the error is captured output, which macOS flushes only at
            // a shutdown this run never reaches.
            (
                "early-write",
                "boundary effect already ran before the harness",
            ),
        ] {
            let output = harness_run(&bin, mode, &[]);
            assert!(
                !output.status.success(),
                "{mode}: an effect before the harness install did not fail the run"
            );
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                stderr.contains(diagnostic),
                "{mode}: missing boundary-before-install diagnostic:\nstderr:\n{stderr}"
            );
            assert!(
                !String::from_utf8_lossy(&output.stdout).contains("HARNESS_APP_RAN"),
                "{mode}: application code ran past the pre-install boundary"
            );
        }
    }
}
