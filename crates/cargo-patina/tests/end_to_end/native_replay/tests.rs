//! Native replay initialization, abort finalization, and restored guest argv.

use super::*;

/// A replay whose runtime initialization fails closed must reach the guest as a
/// named abort through EVERY interposed entry point, including the ones that
/// answer without calling `ensure_runtime`.
///
/// RED before the fix: `clock`/`clock-until`/`cpu-time`/`read-link` (and the
/// macOS lock arm) all take a bootstrap-window answer path that never consults
/// the stored init error, so the fingerprint mismatch is swallowed — `clock-until`
/// spins at 100% CPU until this test's deadline kills it, and the others exit 0.
/// `stdout` was swallowed the same way one layer out: captured stdio accepts
/// bytes with no context and shutdown then drops them, so the guest exited 0
/// with its output gone. Only the `sleep` control aborted. Every arm now aborts
/// on its first post-init-failure call.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_replay_init_error_reaches_every_bootstrap_window_entry_point() {
    let directory = tempdir().unwrap();
    let workspace = native_workspace();
    let source = directory.path().join("bootstrap_window_probe.rs");
    fs::write(&source, BOOTSTRAP_WINDOW_PROBE_SOURCE).unwrap();
    let bin = directory.path().join("bootstrap-window-probe");
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

    // Collected rather than asserted per entry: this is a class detector, so a
    // failure should name every entry point that swallows the error, not just
    // the first one.
    let mut swallowed: Vec<String> = Vec::new();
    for entry in BOOTSTRAP_WINDOW_ENTRY_POINTS {
        let trace = directory.path().join(format!("{entry}.patina"));
        // Recording proves the arm runs at all: an unrecognized entry (or an
        // unexpected result from the call under test) aborts the guest.
        let recorded = invoke_unchecked(
            patina,
            workspace,
            &[
                "run",
                bin.to_str().unwrap(),
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
        // point. The deadline is what turns the field symptom (an endless spin)
        // into a failure instead of a hung test.
        let replayed = invoke_with_deadline(
            patina,
            workspace,
            &[
                "replay",
                bin.to_str().unwrap(),
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

/// A `--record` run stopped by `--budget` used to lose the one artifact that
/// would explain the wedge: the supervisor's pre-created trace file stayed empty
/// because the abort skips record finalization. The stop now flushes a
/// truncated-but-valid trace first.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_budget_abort_under_record_preserves_a_loadable_trace() {
    let directory = tempdir().unwrap();
    let workspace = native_workspace();
    let source = directory.path().join("budget_record.rs");
    fs::write(&source, CALIBRATION_SPIN_SOURCE).unwrap();
    let bin = directory.path().join("budget-record");
    invoke(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );

    let trace = directory.path().join("budget.patina");
    let ran = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &[
            "run",
            bin.to_str().unwrap(),
            "--seed",
            "1",
            "--budget",
            "5000",
            "--record",
            trace.to_str().unwrap(),
            "--fingerprint",
            "budget-record",
        ],
    );
    assert!(
        !ran.status.success(),
        "the budget must stop this run\nstderr:\n{}",
        String::from_utf8_lossy(&ran.stderr)
    );
    let stderr = String::from_utf8_lossy(&ran.stderr).into_owned();
    assert!(
        stderr.contains("step budget of 5000"),
        "missing the budget diagnostic:\n{stderr}"
    );
    assert!(
        !stderr.contains("empty trace file"),
        "the budget abort still lost the recording:\n{stderr}"
    );
    assert!(
        trace.is_file(),
        "the budget abort must leave a truncated trace, not an absent one"
    );
    // The artifact is structurally valid and carries the run up to the stop.
    let bundle: serde_json::Value =
        serde_json::from_slice(&fs::read(&trace).unwrap()).expect("truncated trace must parse");
    let events = bundle["timelines"][0]["decisions"].as_array().unwrap();
    assert_eq!(
        events.len(),
        5000,
        "the truncated trace should hold every op performed before the stop"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_guest_abort_trace_finalization_is_platform_specific() {
    let directory = tempdir().unwrap();
    let workspace = native_workspace();
    let source = directory.path().join("abort_record.rs");
    fs::write(
        &source,
        r#"fn main() {
    eprintln!("guest-about-to-abort");
    std::process::abort();
}
"#,
    )
    .unwrap();
    let bin = directory.path().join("abort-record");
    invoke(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );

    let trace = directory.path().join("abort.patina");
    let ran = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
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
        fs::read_dir(directory.path()).unwrap().all(|entry| !entry
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
        let direct = Command::new(&bin)
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
        assert!(
            stderr.contains("PATINA_INFRA native_run"),
            "missing infra marker: {stderr}"
        );
        assert!(
            stderr.contains("signal=6"),
            "missing signal detail: {stderr}"
        );
        assert!(
            stderr.contains("trace=incomplete"),
            "missing trace detail: {stderr}"
        );
        assert!(
            stderr.contains("empty trace"),
            "missing empty-trace refusal: {stderr}"
        );
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_replay_refuses_incomplete_traces_before_guest_exec() {
    let directory = tempdir().unwrap();
    let workspace = native_workspace();
    let source = directory.path().join("noop_replay.rs");
    fs::write(&source, "fn main() { println!(\"SHOULD_NOT_RUN\"); }\n").unwrap();
    let bin = directory.path().join("noop-replay");
    invoke(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );

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
        let trace = directory.path().join(format!("{name}.patina"));
        fs::write(&trace, bytes).unwrap();
        let replayed = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &[
                "replay",
                bin.to_str().unwrap(),
                trace.to_str().unwrap(),
                "--fingerprint",
                "noop-replay",
            ],
        );
        assert_eq!(
            replayed.status.code(),
            Some(2),
            "{name} trace should refuse with the CLI error exit\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&replayed.stdout),
            String::from_utf8_lossy(&replayed.stderr)
        );
        let stderr = String::from_utf8_lossy(&replayed.stderr);
        assert!(
            stderr.contains("incomplete trace"),
            "{name} stderr:\n{stderr}"
        );
        assert!(stderr.contains(needle), "{name} stderr:\n{stderr}");
        assert!(
            !stderr.contains("terminated by a signal"),
            "{name} replay must refuse before guest exec, not die by signal:\n{stderr}"
        );
        assert!(
            !String::from_utf8_lossy(&replayed.stdout).contains("SHOULD_NOT_RUN"),
            "{name} replay executed the guest before refusing"
        );
    }
}

// Guest argv is recorded into the trace metadata and restored on replay: a bare
// `cargo patina replay <bin> <trace>` reproduces a run recorded with non-default
// `-- ARGS` byte-identically (the incident class), a mismatched `--` section is
// refused up front naming both argv lists, an old trace without the field still
// replays with explicit arguments, and `argv[0]` is normalized to a fixed,
// machine-independent value.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_replay_restores_guest_argv_and_normalizes_argv0() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("argv_echo.rs");
    fs::write(&source, ARGV_ECHO_SOURCE).unwrap();
    let workspace = native_workspace();
    let bin = directory.path().join("argv-echo");
    invoke(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );
    let exe = env!("CARGO_BIN_EXE_cargo-patina");

    // argv[0] is the supervisor-synthesized fixed name, never the host binary
    // path, so a guest reading std::env::args().next() gets a portable value.
    let seeded = invoke(workspace, &["run", bin.to_str().unwrap(), "--seed", "0"]);
    let seeded_out = String::from_utf8_lossy(&seeded.stdout);
    assert!(
        seeded_out.contains("ARGV0=patina-guest"),
        "argv[0] must be normalized to a fixed name, got:\n{seeded_out}"
    );
    assert!(
        !seeded_out.contains(bin.to_str().unwrap()),
        "the host binary path must not leak into the guest argv[0]:\n{seeded_out}"
    );

    // Record with NON-DEFAULT guest arguments (the real incident used a
    // non-default --tick-millis), then a BARE replay — no `--` section —
    // reproduces the run byte-identically because the arguments are restored
    // from the trace. Before argv capture this bare replay ran the guest with
    // default args and diverged with an operation mismatch.
    let trace = directory.path().join("argv.patina");
    let recorded = invoke(
        workspace,
        &[
            "run",
            bin.to_str().unwrap(),
            "--seed",
            "0",
            "--record",
            trace.to_str().unwrap(),
            "--",
            "alpha",
            "--tick-millis",
            "50",
        ],
    );
    let recorded_out = String::from_utf8_lossy(&recorded.stdout).into_owned();
    assert!(
        recorded_out.contains("ARGS=[\"alpha\", \"--tick-millis\", \"50\"]"),
        "record run did not see the passed guest arguments:\n{recorded_out}"
    );
    assert!(recorded_out.contains("READBACK=alpha"), "{recorded_out}");

    let bare_replay = invoke_with(
        exe,
        workspace,
        &["replay", bin.to_str().unwrap(), trace.to_str().unwrap()],
    );
    assert_eq!(
        String::from_utf8_lossy(&bare_replay.stdout),
        recorded_out,
        "bare `replay` must restore the recorded guest arguments and reproduce the run"
    );

    // A mismatched `--` section is refused UP FRONT, naming both the recorded and
    // the passed argument lists — never a confusing mid-run divergence.
    let mismatch = invoke_unchecked(
        exe,
        workspace,
        &[
            "replay",
            bin.to_str().unwrap(),
            trace.to_str().unwrap(),
            "--",
            "beta",
            "--tick-millis",
            "99",
        ],
    );
    let mismatch_stderr = String::from_utf8_lossy(&mismatch.stderr);
    assert!(
        !mismatch.status.success(),
        "a mismatched replay `--` section must fail:\nstderr:\n{mismatch_stderr}"
    );
    assert!(
        mismatch_stderr.contains("alpha")
            && mismatch_stderr.contains("beta")
            && mismatch_stderr.contains("mismatch"),
        "the mismatch error must name BOTH argv lists:\nstderr:\n{mismatch_stderr}"
    );

    // A matching `--` section is accepted (compat for scripts that still pass it).
    let matching = invoke_with(
        exe,
        workspace,
        &[
            "replay",
            bin.to_str().unwrap(),
            trace.to_str().unwrap(),
            "--",
            "alpha",
            "--tick-millis",
            "50",
        ],
    );
    assert_eq!(
        String::from_utf8_lossy(&matching.stdout),
        recorded_out,
        "a byte-identical `--` section must be accepted"
    );

    // Old-trace compatibility: synthesize a trace WITHOUT the guest_argv field
    // (a pre-argv recording) by stripping it, then replay with explicit
    // arguments exactly as before — no new error, arguments taken from the
    // command line.
    let old_trace = directory.path().join("old.patina");
    strip_guest_argv(&trace, &old_trace);
    let old_replay = invoke(
        workspace,
        &[
            "replay",
            bin.to_str().unwrap(),
            old_trace.to_str().unwrap(),
            "--",
            "alpha",
            "--tick-millis",
            "50",
        ],
    );
    assert_eq!(
        String::from_utf8_lossy(&old_replay.stdout),
        recorded_out,
        "an old trace without recorded argv must replay with explicit arguments as before"
    );
}

/// Build the identity probe at `bin` and record one run of it into `trace`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn record_identity_probe(directory: &Path, bin: &Path, trace: &Path) -> String {
    let workspace = native_workspace();
    let source = directory.join("identity_probe.rs");
    fs::write(&source, IDENTITY_PROBE_SOURCE).unwrap();
    invoke(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );
    let recorded = invoke(
        workspace,
        &[
            "run",
            bin.to_str().unwrap(),
            "--seed",
            "5",
            "--record",
            trace.to_str().unwrap(),
        ],
    );
    String::from_utf8_lossy(&recorded.stdout).into_owned()
}

/// A native trace replays against the executable it was recorded from, and is
/// refused, by component and before the guest starts, against one that differs
/// in a single byte.
///
/// RED before the fix: the flipped byte is one the guest never reads, so its
/// replay against the trace succeeds; nothing tied the trace to the bytes it
/// was recorded from.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_replay_refuses_an_executable_one_byte_away_and_names_it() {
    let directory = tempdir().unwrap();
    let workspace = native_workspace();
    let patina = env!("CARGO_BIN_EXE_cargo-patina");
    let bin = directory.path().join("identity-probe");
    let trace = directory.path().join("identity.patina");
    let recorded_out = record_identity_probe(directory.path(), &bin, &trace);

    let same = invoke(
        workspace,
        &["replay", bin.to_str().unwrap(), trace.to_str().unwrap()],
    );
    assert_eq!(
        String::from_utf8_lossy(&same.stdout),
        recorded_out,
        "the recorded executable must replay its own trace"
    );

    let changed = directory.path().join("identity-probe-changed");
    flip_identity_probe_byte(&bin, &changed);
    let refused = invoke_unchecked(
        patina,
        workspace,
        &["replay", changed.to_str().unwrap(), trace.to_str().unwrap()],
    );
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        !refused.status.success(),
        "a trace must not replay against a different executable\nstdout:\n{}\nstderr:\n{stderr}",
        String::from_utf8_lossy(&refused.stdout)
    );
    assert!(
        stderr.contains("fingerprint mismatch") && stderr.contains("executable"),
        "the refusal must name the differing component:\n{stderr}"
    );
    assert!(
        !String::from_utf8_lossy(&refused.stdout).contains("IDENTITY_PROBE"),
        "the guest must not start under a refused replay"
    );

    // The structured result classifies it as Patina's own refusal, before any
    // guest ran.
    let json = invoke_unchecked(
        patina,
        workspace,
        &[
            "replay",
            "--format",
            "json",
            changed.to_str().unwrap(),
            trace.to_str().unwrap(),
        ],
    );
    let envelope: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(envelope["refusal"]["class"], "fingerprint_mismatch");
    assert!(
        envelope
            .get("guest_exit")
            .is_none_or(serde_json::Value::is_null)
    );
}

/// The supervisor stamps the build identity into the trace it commits, so a
/// recording names its executable and its supervisor whatever the recorder
/// linked into the guest knows: that recorder writes no identity at all, as
/// one linked before identities existed does not.
///
/// RED before the fix: the identity rode the control plane to the guest's
/// recorder, so a binary whose recorder did not know it recorded none, exited
/// 0, and was then refused against itself.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_recording_names_its_build_whatever_the_recorder_writes() {
    let directory = tempdir().unwrap();
    let bin = directory.path().join("identity-probe");
    let trace = directory.path().join("identity.patina");
    record_identity_probe(directory.path(), &bin, &trace);

    let value: serde_json::Value = serde_json::from_slice(&fs::read(&trace).unwrap()).unwrap();
    let native = &value["metadata"]["native"];
    assert_eq!(
        native["executable_sha256"].as_str(),
        Some(file_digest(&bin).as_str()),
        "the trace must name the executable it was recorded from"
    );
    assert_eq!(
        native["supervisor_sha256"].as_str(),
        Some(file_digest(Path::new(env!("CARGO_BIN_EXE_cargo-patina"))).as_str()),
        "the trace must name the cargo-patina that recorded it"
    );
}

/// A native trace recorded by another `cargo-patina` build is refused, naming
/// the supervisor, even when both builds carry the same package version: the
/// supervisor builds the guest's initial state and arms its traps, and the
/// version stays the same across development builds that do so differently.
///
/// RED before the fix: the package version stood for the supervisor, so a
/// trace from another build of the same version replayed.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_replay_refuses_a_trace_from_another_supervisor_build_and_names_it() {
    let directory = tempdir().unwrap();
    let workspace = native_workspace();
    let bin = directory.path().join("identity-probe");
    let trace = directory.path().join("identity.patina");
    record_identity_probe(directory.path(), &bin, &trace);
    let foreign = directory.path().join("foreign.patina");
    record_as_another_supervisor_build(&trace, &foreign);

    let refused = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &["replay", bin.to_str().unwrap(), foreign.to_str().unwrap()],
    );
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        !refused.status.success(),
        "a trace from another supervisor build must not replay\nstdout:\n{}\nstderr:\n{stderr}",
        String::from_utf8_lossy(&refused.stdout)
    );
    assert!(
        stderr.contains("fingerprint mismatch") && stderr.contains("supervisor"),
        "the refusal must name the differing component:\n{stderr}"
    );
    assert!(
        !String::from_utf8_lossy(&refused.stdout).contains("IDENTITY_PROBE"),
        "the guest must not start under a refused replay"
    );
}

/// A native trace without a build identity, as one recorded before identities
/// existed reads, is refused rather than replayed on trust.
///
/// RED before the fix: no field was required, so the stripped trace replayed.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_replay_refuses_a_trace_without_a_build_identity() {
    let directory = tempdir().unwrap();
    let workspace = native_workspace();
    let bin = directory.path().join("identity-probe");
    let trace = directory.path().join("identity.patina");
    record_identity_probe(directory.path(), &bin, &trace);
    let old = directory.path().join("old.patina");
    strip_native_identity(&trace, &old);

    let refused = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &["replay", bin.to_str().unwrap(), old.to_str().unwrap()],
    );
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        !refused.status.success(),
        "a trace without a build identity must not replay\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("fingerprint mismatch") && stderr.contains("no native build identity"),
        "the refusal must say the identity is missing:\n{stderr}"
    );
}

/// Building one source twice, under different output names, reproduces the
/// executable, so a source-first replay matches a trace recorded from a built
/// binary.
///
/// RED before the fix on macOS: the linker writes the output's file name into
/// the executable (the ad-hoc signature identifier and the image UUID), so the
/// two builds differ and the source-first replay is refused.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_single_source_rebuild_reproduces_the_build_identity() {
    let directory = tempdir().unwrap();
    let workspace = native_workspace();
    let bin = directory.path().join("identity-probe");
    let trace = directory.path().join("identity.patina");
    let recorded_out = record_identity_probe(directory.path(), &bin, &trace);
    let source = directory.path().join("identity_probe.rs");

    let renamed = directory.path().join("renamed");
    invoke(
        workspace,
        &[
            "build",
            source.to_str().unwrap(),
            "--output",
            renamed.to_str().unwrap(),
        ],
    );
    assert!(
        fs::read(&bin).unwrap() == fs::read(&renamed).unwrap(),
        "two builds of one source must be byte-identical whatever they are named"
    );

    let replayed = invoke(
        workspace,
        &["replay", source.to_str().unwrap(), trace.to_str().unwrap()],
    );
    assert!(
        String::from_utf8_lossy(&replayed.stdout).contains(recorded_out.trim()),
        "a source-first replay must match the trace of the built binary:\n{}",
        String::from_utf8_lossy(&replayed.stdout)
    );
}
