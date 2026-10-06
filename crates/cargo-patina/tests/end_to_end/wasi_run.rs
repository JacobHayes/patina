//! WASI execution policy, realtime epochs, and flag-free replay.

#[cfg(test)]
mod tests {
    use super::super::*;

    #[test]
    fn wasi_run_preopen_policy_controls_write_access() {
        let directory = tempdir().unwrap();
        let module = directory.path().join("preopen-write.wasm");
        fs::write(
            &module,
            wat::parse_str(
                r#"(module
                (import "wasi_snapshot_preview1" "path_open"
                    (func $path_open
                        (param i32 i32 i32 i32 i32 i64 i64 i32 i32)
                        (result i32)))
                (import "wasi_snapshot_preview1" "fd_close"
                    (func $fd_close (param i32) (result i32)))
                (import "wasi_snapshot_preview1" "proc_exit"
                    (func $proc_exit (param i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "out")
                (func (export "_start")
                    (local $errno i32)
                    (local.set $errno
                        (call $path_open
                            (i32.const 3)   ;; preopened directory fd
                            (i32.const 0)   ;; lookup flags
                            (i32.const 0)   ;; path pointer
                            (i32.const 3)   ;; path length
                            (i32.const 1)   ;; oflags: create
                            (i64.const 66)  ;; rights: fd_read | fd_write
                            (i64.const 0)   ;; inheriting rights
                            (i32.const 0)   ;; fdflags
                            (i32.const 16))) ;; result fd pointer
                    (if (i32.ne (local.get $errno) (i32.const 0))
                        (then (call $proc_exit (local.get $errno))))
                    (drop (call $fd_close (i32.load (i32.const 16))))))"#,
            )
            .unwrap(),
        )
        .unwrap();

        let rw = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            directory.path(),
            &["run", module.to_str().unwrap(), "--preopen", "/rw:rw"],
        );
        assert!(
            rw.status.success(),
            "rw preopen failed with {}\nstdout:\n{}\nstderr:\n{}",
            rw.status,
            String::from_utf8_lossy(&rw.stdout),
            String::from_utf8_lossy(&rw.stderr)
        );

        let ro = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            directory.path(),
            &["run", module.to_str().unwrap(), "--preopen", "/ro:ro"],
        );
        assert_eq!(ro.status.code(), Some(69));
    }

    // The WASI family's realtime epoch: the default, the `--realtime-epoch`
    // override applied to the in-process clock, recorded into the trace, restored by
    // a flag-free replay, and refused when re-supplied to `replay`.
    #[test]
    fn wasi_realtime_epoch_defaults_overrides_and_replays_flag_free() {
        let directory = tempdir().unwrap();
        let cwd = directory.path();
        // `_start` subtracts monotonic from realtime, then selects by epoch:
        // default -> 9, configured -> 7, anything else -> 1. This checks the
        // clock-domain relationship independently of the boot origin.
        let module = directory.path().join("epoch.wasm");
        fs::write(
        &module,
        wat::parse_str(
            r#"(module
                (import "wasi_snapshot_preview1" "clock_time_get"
                    (func $clock_time_get (param i32 i64 i32) (result i32)))
                (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
                (memory (export "memory") 1)
                (func (export "_start")
                    (local $secs i64)
                    (drop (call $clock_time_get (i32.const 0) (i64.const 1) (i32.const 0)))
                    (drop (call $clock_time_get (i32.const 1) (i64.const 1) (i32.const 8)))
                    (local.set $secs
                        (i64.div_u (i64.sub (i64.load (i32.const 0)) (i64.load (i32.const 8))) (i64.const 1000000000)))
                    (call $proc_exit
                        (select
                            (i32.const 7)
                            (select
                                (i32.const 9)
                                (i32.const 1)
                                (i64.eq (local.get $secs) (i64.const 1784761209)))
                            (i64.eq (local.get $secs) (i64.const 1000000000))))))"#,
        )
        .unwrap(),
    )
    .unwrap();
        let patina = env!("CARGO_BIN_EXE_cargo-patina");
        let module = module.to_str().unwrap();

        let default = invoke_unchecked(patina, cwd, &["run", module, "--seed", "1"]);
        assert_eq!(
            default.status.code(),
            Some(9),
            "{}",
            String::from_utf8_lossy(&default.stderr)
        );

        let trace = directory.path().join("epoch.patina");
        let recorded = invoke_unchecked(
            patina,
            cwd,
            &[
                "run",
                module,
                "--seed",
                "1",
                "--realtime-epoch",
                "2001-09-09T01:46:40Z",
                "--record",
                trace.to_str().unwrap(),
            ],
        );
        assert_eq!(
            recorded.status.code(),
            Some(7),
            "{}",
            String::from_utf8_lossy(&recorded.stderr)
        );
        assert_eq!(
            patina_dst_trace::TraceBundle::load(&trace)
                .unwrap()
                .metadata
                .realtime_epoch_nanos,
            1_000_000_000_000_000_000
        );

        let replayed = invoke_unchecked(patina, cwd, &["replay", module, trace.to_str().unwrap()]);
        assert_eq!(
            replayed.status.code(),
            Some(7),
            "{}",
            String::from_utf8_lossy(&replayed.stderr)
        );
        let refused = invoke_unchecked(
            patina,
            cwd,
            &[
                "replay",
                module,
                trace.to_str().unwrap(),
                "--realtime-epoch",
                "2001-09-09T01:46:40Z",
            ],
        );
        assert!(!refused.status.success());
        assert!(
            String::from_utf8_lossy(&refused.stderr).contains("--realtime-epoch"),
            "{}",
            String::from_utf8_lossy(&refused.stderr)
        );
    }

    // A WASI record→`replay` round-trip: the `replay` verb restores the recorded
    // guest argv (the `--arg` values) and fault configuration from the trace, so a
    // replay is flag-free and byte-identical. A re-supplied `--arg` must match the
    // recording or the replay is refused up front, naming both.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn wasi_replay_restores_guest_argv_and_faults_flag_free() {
        let directory = tempdir().unwrap();
        let cwd = directory.path();
        // `_start` reads the argument count and exits with it, so the process exit
        // code is a pure function of the guest argv — a compact, observable proxy for
        // "the argv reached the guest".
        let module = directory.path().join("argc.wasm");
        fs::write(
            &module,
            wat::parse_str(
                r#"(module
                (import "wasi_snapshot_preview1" "args_sizes_get"
                    (func $args_sizes_get (param i32 i32) (result i32)))
                (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
                (memory (export "memory") 1)
                (func (export "_start")
                    (drop (call $args_sizes_get (i32.const 0) (i32.const 8)))
                    (call $proc_exit (i32.load (i32.const 0)))))"#,
            )
            .unwrap(),
        )
        .unwrap();

        let trace = directory.path().join("argc.patina");
        // Record with two guest arguments and a fault knob that this guest never
        // triggers (no filesystem ops): both are captured into the trace metadata.
        let recorded = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            cwd,
            &[
                "run",
                module.to_str().unwrap(),
                "--seed",
                "1",
                "--record",
                trace.to_str().unwrap(),
                "--fs-latency-nanos",
                "1..2",
                "--arg",
                "alpha",
                "--arg",
                "beta",
            ],
        );
        let recorded_code = recorded.status.code();
        assert!(
            matches!(recorded_code, Some(code) if code > 0),
            "expected a positive argc exit code, got {recorded_code:?}\nstderr:\n{}",
            String::from_utf8_lossy(&recorded.stderr)
        );

        // Flag-free replay: neither `--arg` nor `--fs-latency-nanos` is re-passed, yet the
        // run reproduces byte-identically because the trace is authoritative.
        let replayed = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            cwd,
            &["replay", module.to_str().unwrap(), trace.to_str().unwrap()],
        );
        assert_eq!(
            replayed.status.code(),
            recorded_code,
            "flag-free WASI replay diverged\nstderr:\n{}",
            String::from_utf8_lossy(&replayed.stderr)
        );

        // A re-supplied `--arg` matching the recording is accepted.
        let matching = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            cwd,
            &[
                "replay",
                module.to_str().unwrap(),
                trace.to_str().unwrap(),
                "--arg",
                "alpha",
                "--arg",
                "beta",
            ],
        );
        assert_eq!(matching.status.code(), recorded_code);

        // A conflicting `--arg` is refused up front, naming the conflict.
        let conflict = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            cwd,
            &[
                "replay",
                module.to_str().unwrap(),
                trace.to_str().unwrap(),
                "--arg",
                "gamma",
            ],
        );
        assert!(!conflict.status.success());
        let conflict_stderr = String::from_utf8_lossy(&conflict.stderr);
        assert!(
            conflict_stderr.contains("conflict") && conflict_stderr.contains("authoritative"),
            "missing argv-conflict diagnostic:\n{conflict_stderr}"
        );
    }
}
