//! Native replay initialization, abort finalization, and restored guest argv.

use super::*;

/// One probe build carries every replay contract that reads only the trace,
/// the executable and the replay's own arguments: the trace names its build and
/// refuses any other, guest argv is restored, an incomplete trace is refused
/// before exec, a guest abort finalizes per platform, and a fail-closed replay
/// init reaches the guest through every bootstrap-window entry point.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_replay_ties_the_trace_to_its_build_and_argv() {
    let guest = native_build::source_guest("replay_probe", PROBE_SOURCE);
    let (recorded, trace) = guest.assert_recorded(5, &[]);
    let recorded_out = String::from_utf8_lossy(&recorded.stdout).into_owned();
    // argv[0] is the supervisor-synthesized fixed name, never the host binary
    // path, so a guest reading std::env::args().next() gets a portable value.
    assert!(
        recorded_out.contains("ARGV0=patina-guest")
            && !recorded_out.contains(guest.binary.to_str().unwrap()),
        "argv[0] must be normalized to a fixed name, got:\n{recorded_out}"
    );
    the_trace_names_its_build_and_refuses_any_other(&guest, &trace, &recorded_out);
    guest_argv_is_restored_on_replay(&guest);
    incomplete_traces_are_refused_before_guest_exec(&guest);
    guest_abort_trace_finalization_is_platform_specific(&guest);
    replay_init_error_reaches_every_bootstrap_window_entry_point(&guest);
}

/// A replay whose runtime initialization fails closed must reach the guest as a
/// named abort through EVERY interposed entry point, including the ones that
/// answer without calling `ensure_runtime`: the bootstrap-window arms take an
/// answer path that never consults the stored init error unless the shim checks
/// it there, and `stdout` would exit 0 with its output dropped.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn replay_init_error_reaches_every_bootstrap_window_entry_point(guest: &common::native::Guest) {
    let workspace = native_workspace();
    let bin = guest.binary.to_str().unwrap();
    let patina = env!("CARGO_BIN_EXE_cargo-patina");

    // Collected rather than asserted per entry: this is a class detector, so a
    // failure should name every entry point that swallows the error, not just
    // the first one.
    let mut swallowed: Vec<String> = Vec::new();
    for entry in BOOTSTRAP_WINDOW_ENTRY_POINTS {
        let trace = guest.dir.path().join(format!("{entry}.patina"));
        // Recording proves the arm runs at all: an unexpected result from the
        // call under test aborts the guest.
        let recorded = invoke_unchecked(
            patina,
            workspace,
            &[
                "run",
                bin,
                "--seed",
                "3",
                "--record",
                trace.to_str().unwrap(),
                "--fingerprint",
                "bootstrap-window-v1",
                "--",
                entry,
            ],
        );
        assert!(
            recorded.status.success(),
            "recording the {entry} bootstrap-window probe failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&recorded.stdout),
            String::from_utf8_lossy(&recorded.stderr)
        );

        // The same trace replayed under a different fingerprint: initialization
        // fails closed, and the guest must learn about it through this entry
        // point. The deadline turns the field symptom (an endless spin) into a
        // failure instead of a hung test.
        let replayed = invoke_with_deadline(
            patina,
            workspace,
            &[
                "replay",
                bin,
                trace.to_str().unwrap(),
                "--fingerprint",
                "bootstrap-window-other",
            ],
            Duration::from_secs(60),
        );
        let Some(replayed) = replayed else {
            swallowed.push(format!(
                "{entry}: still running at the deadline (the field symptom is a 100% CPU spin)"
            ));
            continue;
        };
        let stderr = String::from_utf8_lossy(&replayed.stderr).into_owned();
        if replayed.status.success() {
            swallowed.push(format!(
                "{entry}: exited successfully under a mismatched fingerprint"
            ));
        } else if !(stderr.contains("the deterministic runtime failed to initialize")
            && stderr.contains("fingerprint"))
        {
            swallowed.push(format!(
                "{entry}: failed without the init diagnostic:\n{stderr}"
            ));
        }
    }
    assert!(
        swallowed.is_empty(),
        "these bootstrap-window entry points swallowed a fail-closed replay init error:\n{}",
        swallowed.join("\n")
    );
}

/// The bootstrap-window init-error check must not turn a loud refusal into a
/// deadlock when the guest brings its own global allocator.
///
/// The window exists for exactly that guest: an allocator's init takes an
/// interposed `os_unfair_lock`, which the shim runs natively rather than through
/// the scheduler. Now that entering the window can abort, the diagnostic write —
/// which flushes captured stdio, and so deallocates through that same allocator
/// — can re-enter the check from inside a held shim spinlock. This is the leg
/// that would hang if the re-entrancy latch or the spinlock-first ordering in
/// the lock interposers were dropped, so it runs under a deadline.
#[cfg(target_os = "macos")]
#[test]
fn native_replay_init_error_aborts_under_a_custom_global_allocator() {
    let directory = tempdir().unwrap();
    let workspace = native_workspace();
    let source = directory.path().join("custom_alloc_init_error.rs");
    fs::write(&source, CUSTOM_ALLOCATOR_SOURCE).unwrap();
    let bin = directory.path().join("custom-alloc-init-error");
    invoke(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );
    let patina = env!("CARGO_BIN_EXE_cargo-patina");

    let trace = directory.path().join("custom-alloc.patina");
    let recorded = invoke_unchecked(
        patina,
        workspace,
        &[
            "run",
            bin.to_str().unwrap(),
            "--seed",
            "1",
            "--record",
            trace.to_str().unwrap(),
            "--fingerprint",
            "custom-alloc-v1",
        ],
    );
    assert!(
        recorded.status.success(),
        "recording the custom-allocator guest failed:\n{}",
        String::from_utf8_lossy(&recorded.stderr)
    );

    let replayed = invoke_with_deadline(
        patina,
        workspace,
        &[
            "replay",
            bin.to_str().unwrap(),
            trace.to_str().unwrap(),
            "--fingerprint",
            "custom-alloc-other",
        ],
        Duration::from_secs(60),
    )
    .expect("the custom-allocator guest wedged under a fail-closed init error instead of aborting");
    let stderr = String::from_utf8_lossy(&replayed.stderr).into_owned();
    assert!(
        !replayed.status.success()
            && stderr.contains("the deterministic runtime failed to initialize")
            && stderr.contains("fingerprint"),
        "the custom-allocator guest did not abort on the mismatched fingerprint:\n{stderr}"
    );
}

/// An explicit guest abort under `--record`: Linux finalizes the trace and
/// reports the signal death; macOS reports an infra failure and no trace.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn guest_abort_trace_finalization_is_platform_specific(guest: &common::native::Guest) {
    let directory = guest.dir.path();
    let bin = &guest.binary;
    let trace = directory.join("abort.patina");
    let ran = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        native_workspace(),
        &[
            "run",
            bin.to_str().unwrap(),
            "--seed",
            "1",
            "--record",
            trace.to_str().unwrap(),
            "--fingerprint",
            "abort-record",
            "--format",
            "json",
            "--",
            "abort",
        ],
    );
    assert_eq!(
        ran.status.code(),
        Some(134),
        "abort should be surfaced as 128+SIGABRT\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ran.stdout),
        String::from_utf8_lossy(&ran.stderr)
    );
    assert!(
        fs::read_dir(directory).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains("abort.patina.tmp")),
        "record abort must clean up its temporary trace"
    );
    let envelope: serde_json::Value = serde_json::from_slice(&ran.stdout).unwrap_or_else(|error| {
        panic!(
            "native run did not emit a JSON envelope: {error}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&ran.stdout),
            String::from_utf8_lossy(&ran.stderr)
        )
    });
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::ExitStatusExt;
        const SIGABRT: i32 = 6;
        let direct = Command::new(bin)
            .arg("abort")
            .env("PATINA_MODE", "seeded")
            .env("PATINA_SEED", "1")
            .output()
            .unwrap();
        assert_eq!(direct.status.signal(), Some(SIGABRT));
        assert_eq!(envelope["guest_exit"]["signal"], SIGABRT);
        assert_eq!(envelope["guest_exit"]["core"], direct.status.core_dumped());
        assert!(envelope.get("refusal").is_none(), "{envelope:#}");
        patina_dst_trace::TraceBundle::load(&trace)
            .expect("explicit guest abort finalizes; internal fatals do not");
        assert!(
            !envelope["stderr"]
                .as_str()
                .unwrap()
                .contains("trace=incomplete")
        );
    }
    #[cfg(target_os = "macos")]
    {
        assert!(!trace.exists(), "macOS abort is not a modeled guest event");
        assert_eq!(envelope["result"], "infra");
        assert!(
            envelope.get("trace").is_none(),
            "no absent trace fact should be advertised: {envelope:#}"
        );
        let stderr = envelope["stderr"].as_str().unwrap();
        for detail in [
            "PATINA_INFRA native_run",
            "signal=6",
            "trace=incomplete",
            "empty trace",
        ] {
            assert!(stderr.contains(detail), "missing {detail:?}: {stderr}");
        }
    }
}

/// An empty, truncated or metadata-incomplete trace is refused with the CLI
/// error exit before the guest is executed.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn incomplete_traces_are_refused_before_guest_exec(guest: &common::native::Guest) {
    let incomplete_metadata = format!(
        r#"{{"format_version":{},"metadata":{{"root_seed":1,"decision_policy":"splitmix64-v1"}},"timelines":[]}}"#,
        patina_dst_trace::TRACE_FORMAT_VERSION
    );
    let cases: [(&str, &[u8], &str); 3] = [
        ("empty", b"", "empty trace"),
        ("truncated", b"{\"format_version\":4,", "truncated JSON"),
        (
            "incomplete-metadata",
            incomplete_metadata.as_bytes(),
            "trace metadata is missing required field `fingerprint`",
        ),
    ];
    for (name, bytes, needle) in cases {
        let trace = guest.dir.path().join(format!("{name}.patina"));
        fs::write(&trace, bytes).unwrap();
        let replayed = guest.command("replay", &[trace.to_str().unwrap()]);
        let stderr = String::from_utf8_lossy(&replayed.stderr);
        assert_eq!(
            replayed.status.code(),
            Some(2),
            "{name} trace should refuse with the CLI error exit\nstderr:\n{stderr}"
        );
        assert!(
            stderr.contains("incomplete trace") && stderr.contains(needle),
            "{name} stderr:\n{stderr}"
        );
        assert!(
            !String::from_utf8_lossy(&replayed.stdout).contains("ARGV0="),
            "{name} replay executed the guest before refusing"
        );
    }
}

/// Guest argv is recorded into the trace metadata and restored on replay: a
/// bare `cargo patina replay <bin> <trace>` reproduces a run recorded with
/// non-default `-- ARGS`, a mismatched `--` section is refused up front naming
/// both argv lists, a matching one is accepted, and a trace without the field
/// still replays with explicit arguments.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn guest_argv_is_restored_on_replay(guest: &common::native::Guest) {
    let trace = guest.dir.path().join("argv.patina");
    let args = ["alpha", "--tick-millis", "50"];
    let mut record = vec!["--seed", "0", "--record", trace.to_str().unwrap(), "--"];
    record.extend(args);
    let recorded = common::native::assert_success(guest.command("run", &record));
    let recorded_out = String::from_utf8_lossy(&recorded.stdout).into_owned();
    assert!(
        recorded_out.contains("ARGS=[\"alpha\", \"--tick-millis\", \"50\"]")
            && recorded_out.contains("READBACK=alpha"),
        "record run did not see the passed guest arguments:\n{recorded_out}"
    );
    fn replay_args<'a>(bin: &'a str, trace: &'a Path, args: &[&'a str]) -> Vec<&'a str> {
        let mut argv = vec!["replay", bin, trace.to_str().unwrap()];
        if !args.is_empty() {
            argv.push("--");
            argv.extend_from_slice(args);
        }
        argv
    }
    let (exe, workspace) = (env!("CARGO_BIN_EXE_cargo-patina"), native_workspace());
    let bin = guest.binary.to_str().unwrap();
    for (what, args) in [("bare", &[][..]), ("matching", &args[..])] {
        let replayed = invoke_with(exe, workspace, &replay_args(bin, &trace, args));
        assert_eq!(
            String::from_utf8_lossy(&replayed.stdout),
            recorded_out,
            "a {what} replay must restore the recorded guest arguments"
        );
    }

    let mismatched = ["beta", "--tick-millis", "99"];
    let mismatch = invoke_unchecked(exe, workspace, &replay_args(bin, &trace, &mismatched));
    let mismatch_stderr = String::from_utf8_lossy(&mismatch.stderr);
    assert!(
        !mismatch.status.success()
            && mismatch_stderr.contains("alpha")
            && mismatch_stderr.contains("beta")
            && mismatch_stderr.contains("mismatch"),
        "a mismatched `--` section must be refused naming both argv lists:\n{mismatch_stderr}"
    );

    let old_trace = guest.dir.path().join("old-argv.patina");
    strip_guest_argv(&trace, &old_trace);
    let old_replay = invoke_with(exe, workspace, &replay_args(bin, &old_trace, &args));
    assert_eq!(
        String::from_utf8_lossy(&old_replay.stdout),
        recorded_out,
        "a trace without recorded argv must replay with explicit arguments"
    );
}

/// The supervisor stamps the build identity into the trace, naming the
/// executable and the supervisor whatever the guest's linked recorder writes.
/// Replay refuses, by component and before the guest starts, an executable one
/// inert byte away, a trace from another supervisor build of the same version,
/// and a trace with no identity. Rebuilding the one source, under another output
/// name, reproduces the executable, so a source-first replay matches.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn the_trace_names_its_build_and_refuses_any_other(
    guest: &common::native::Guest,
    trace: &Path,
    recorded_out: &str,
) {
    let directory = guest.dir.path();
    let bin = &guest.binary;
    let value: serde_json::Value = serde_json::from_slice(&fs::read(trace).unwrap()).unwrap();
    let native = &value["metadata"]["native"];
    assert_eq!(
        native["executable_sha256"].as_str(),
        Some(file_digest(bin).as_str()),
        "the trace must name the executable it was recorded from"
    );
    assert_eq!(
        native["supervisor_sha256"].as_str(),
        Some(file_digest(Path::new(env!("CARGO_BIN_EXE_cargo-patina"))).as_str()),
        "the trace must name the cargo-patina that recorded it"
    );

    let replay = |executable: &Path, trace: &Path, json: bool| {
        let mut args = vec!["replay"];
        if json {
            args.extend(["--format", "json"]);
        }
        args.extend([executable.to_str().unwrap(), trace.to_str().unwrap()]);
        invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            native_workspace(),
            &args,
        )
    };
    let assert_refused = |refused: &Output, component: &str| {
        let stderr = String::from_utf8_lossy(&refused.stderr);
        assert!(
            !refused.status.success()
                && stderr.contains("fingerprint mismatch")
                && stderr.contains(component),
            "the refusal must name {component:?}:\n{stderr}"
        );
        assert!(
            !String::from_utf8_lossy(&refused.stdout).contains("IDENTITY_PROBE"),
            "the guest must not start under a refused replay"
        );
    };

    let changed = directory.join("replay_probe-changed");
    flip_identity_probe_byte(bin, &changed);
    assert_refused(&replay(&changed, trace, false), "executable");
    // The structured result classifies it as Patina's own refusal, before any
    // guest ran.
    let json = replay(&changed, trace, true);
    let envelope: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(envelope["refusal"]["class"], "fingerprint_mismatch");
    assert!(
        envelope
            .get("guest_exit")
            .is_none_or(serde_json::Value::is_null)
    );

    let foreign = directory.join("foreign.patina");
    record_as_another_supervisor_build(trace, &foreign);
    assert_refused(&replay(bin, &foreign, false), "supervisor");

    let old = directory.join("old-identity.patina");
    strip_native_identity(trace, &old);
    assert_refused(&replay(bin, &old, false), "no native build identity");

    let source = directory.join("replay_probe.rs");
    let replayed = invoke(
        native_workspace(),
        &["replay", source.to_str().unwrap(), trace.to_str().unwrap()],
    );
    assert!(
        String::from_utf8_lossy(&replayed.stdout).contains(recorded_out.trim()),
        "a source-first replay must match the trace of the built binary:\n{}",
        String::from_utf8_lossy(&replayed.stdout)
    );
}
