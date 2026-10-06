//! WASI filesystem errors, short I/O, and latency faults.

#[cfg(test)]
mod tests {
    use super::super::*;

    const WASI_FS_EIO_READ: &str = r#"(module
  (import "wasi_snapshot_preview1" "path_filestat_get"
    (func $path_filestat_get (param i32 i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "file")
  (data (i32.const 128) "WASI_FS_FAULT_RESULT eio\n")
  (func $print
    (i32.store (i32.const 64) (i32.const 128))
    (i32.store (i32.const 68) (i32.const 25))
    (drop (call $fd_write (i32.const 1) (i32.const 64) (i32.const 1) (i32.const 80))))
  (func (export "_start")
    (local $errno i32)
    (local.set $errno
      (call $path_filestat_get
        (i32.const 3) (i32.const 0) (i32.const 0) (i32.const 4) (i32.const 100)))
    (if (i32.ne (local.get $errno) (i32.const 29)) (then (call $proc_exit (local.get $errno))))
    (call $print)))"#;

    const WASI_FS_ENOSPC_WRITE: &str = r#"(module
  (import "wasi_snapshot_preview1" "path_create_directory"
    (func $path_create_directory (param i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "dir")
  (data (i32.const 128) "WASI_FS_FAULT_RESULT enospc\n")
  (func $print
    (i32.store (i32.const 64) (i32.const 128))
    (i32.store (i32.const 68) (i32.const 28))
    (drop (call $fd_write (i32.const 1) (i32.const 64) (i32.const 1) (i32.const 80))))
  (func (export "_start")
    (local $errno i32)
    (local.set $errno (call $path_create_directory (i32.const 3) (i32.const 0) (i32.const 3)))
    (if (i32.ne (local.get $errno) (i32.const 51)) (then (call $proc_exit (local.get $errno))))
    (call $print)))"#;

    const WASI_FS_SHORT_WRITE: &str = r#"(module
  (import "wasi_snapshot_preview1" "path_open"
    (func $path_open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "file")
  (data (i32.const 16) "abcdef")
  (data (i32.const 128) "WASI_FS_FAULT_RESULT short_write\n")
  (func $print
    (i32.store (i32.const 64) (i32.const 128))
    (i32.store (i32.const 68) (i32.const 33))
    (drop (call $fd_write (i32.const 1) (i32.const 64) (i32.const 1) (i32.const 80))))
  (func (export "_start")
    (local $fd i32) (local $errno i32) (local $n i32)
    (local.set $errno
      (call $path_open
        (i32.const 3) (i32.const 0) (i32.const 0) (i32.const 4)
        (i32.const 1) (i64.const 66) (i64.const 0) (i32.const 0) (i32.const 100)))
    (if (i32.ne (local.get $errno) (i32.const 0)) (then (call $proc_exit (local.get $errno))))
    (local.set $fd (i32.load (i32.const 100)))
    (i32.store (i32.const 64) (i32.const 16))
    (i32.store (i32.const 68) (i32.const 6))
    (local.set $errno (call $fd_write (local.get $fd) (i32.const 64) (i32.const 1) (i32.const 80)))
    (if (i32.ne (local.get $errno) (i32.const 0)) (then (call $proc_exit (local.get $errno))))
    (local.set $n (i32.load (i32.const 80)))
    (if (i32.eqz (local.get $n)) (then (call $proc_exit (i32.const 70))))
    (if (i32.ge_u (local.get $n) (i32.const 6)) (then (call $proc_exit (i32.const 71))))
    (call $print)))"#;

    #[test]
    fn wasi_fs_latency_is_observable_in_the_guest_and_reported_non_vacuous() {
        let directory = tempdir().unwrap();
        let module = directory.path().join("latency.wasm");
        fs::write(&module, wat::parse_str(WASI_FS_LATENCY).unwrap()).unwrap();
        let patina = env!("CARGO_BIN_EXE_cargo-patina");

        // Control: without the knob the two clock reads bracket no delay at all, so
        // the guest takes its explicit failure exit. A knob-free run is unperturbed.
        let clean = invoke_unchecked(
            patina,
            directory.path(),
            &["run", module.to_str().unwrap(), "--seed", "3"],
        );
        assert_eq!(
            clean.status.code(),
            Some(70),
            "a knob-free run must not delay fs ops:\n{}",
            String::from_utf8_lossy(&clean.stderr)
        );

        // MUST delay: a fixed 1ms latency shows up as virtual elapsed time inside the
        // guest, across the WASI family, from a flag in the shared fault group.
        let output = invoke_unchecked(
            patina,
            directory.path(),
            &[
                "run",
                module.to_str().unwrap(),
                "--seed",
                "3",
                "--fs-latency-nanos",
                "1000000..1000000",
            ],
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "guest did not observe the injected fs latency:\n{stderr}"
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("WASI_FS_FAULT_RESULT latency"),
            "missing guest latency marker"
        );
        assert!(
            stderr.contains("PATINA_FS_FAULT_REPORT") && stderr.contains("vacuous=0"),
            "fs fault report must prove the latency knob was non-vacuous:\n{stderr}"
        );
    }

    #[test]
    fn wasi_fs_fault_errors_and_short_io_are_observable() {
        let directory = tempdir().unwrap();
        let eio = directory.path().join("eio.wasm");
        let enospc = directory.path().join("enospc.wasm");
        let short = directory.path().join("short.wasm");
        fs::write(&eio, wat::parse_str(WASI_FS_EIO_READ).unwrap()).unwrap();
        fs::write(&enospc, wat::parse_str(WASI_FS_ENOSPC_WRITE).unwrap()).unwrap();
        fs::write(&short, wat::parse_str(WASI_FS_SHORT_WRITE).unwrap()).unwrap();

        let patina = env!("CARGO_BIN_EXE_cargo-patina");
        for (module, seed, flag, value, marker) in [
            (
                &eio,
                "1",
                "--fs-error-permille",
                "1000",
                "WASI_FS_FAULT_RESULT eio",
            ),
            (
                &enospc,
                "2",
                "--fs-error-permille",
                "1000",
                "WASI_FS_FAULT_RESULT enospc",
            ),
            (
                &short,
                "5",
                "--fs-short-permille",
                "1000",
                "WASI_FS_FAULT_RESULT short_write",
            ),
        ] {
            let output = invoke_unchecked(
                patina,
                directory.path(),
                &[
                    "run",
                    module.to_str().unwrap(),
                    "--seed",
                    seed,
                    "--preopen",
                    "/fs:rw",
                    flag,
                    value,
                ],
            );
            assert!(
                output.status.success(),
                "WASI fs fault module failed with {}\nstdout:\n{}\nstderr:\n{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                String::from_utf8_lossy(&output.stdout).contains(marker),
                "missing marker {marker}:\n{}",
                String::from_utf8_lossy(&output.stdout)
            );
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                stderr.contains("PATINA_FS_FAULT_REPORT") && stderr.contains("vacuous=0"),
                "WASI fs fault run should be non-vacuous:\n{stderr}"
            );
        }
    }
}
