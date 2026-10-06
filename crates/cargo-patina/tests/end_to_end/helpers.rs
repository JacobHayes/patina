//! Shared e2e fixtures, process results, reports, and campaign checkpoints.

use super::*;

// The guest reads the monotonic clock either side of ONE eligible filesystem
// operation and exits 70 unless virtual time advanced by at least the configured
// latency. This is the observation `--fs-latency-nanos` exists to produce, seen
// from inside the guest rather than from a host-side report.
pub(super) const WASI_FS_LATENCY: &str = r#"(module
  (import "wasi_snapshot_preview1" "clock_time_get"
    (func $clock_time_get (param i32 i64 i32) (result i32)))
  (import "wasi_snapshot_preview1" "path_filestat_get"
    (func $path_filestat_get (param i32 i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "file")
  (data (i32.const 128) "WASI_FS_FAULT_RESULT latency\n")
  (func $print
    (i32.store (i32.const 64) (i32.const 128))
    (i32.store (i32.const 68) (i32.const 29))
    (drop (call $fd_write (i32.const 1) (i32.const 64) (i32.const 1) (i32.const 80))))
  (func (export "_start")
    (local $before i64) (local $after i64)
    (drop (call $clock_time_get (i32.const 1) (i64.const 0) (i32.const 200)))
    (local.set $before (i64.load (i32.const 200)))
    (drop (call $path_filestat_get
      (i32.const 3) (i32.const 0) (i32.const 0) (i32.const 4) (i32.const 100)))
    (drop (call $clock_time_get (i32.const 1) (i64.const 0) (i32.const 208)))
    (local.set $after (i64.load (i32.const 208)))
    (if (i64.lt_u (i64.sub (local.get $after) (local.get $before)) (i64.const 1000000))
      (then (call $proc_exit (i32.const 70))))
    (call $print)))"#;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn active_toolchain_binary(name: &str) -> PathBuf {
    let sysroot = Command::new("rustc")
        .args(["--print", "sysroot"])
        .output()
        .unwrap_or_else(|error| panic!("failed to query rustc sysroot: {error}"));
    assert!(
        sysroot.status.success(),
        "rustc --print sysroot failed:\n{}",
        String::from_utf8_lossy(&sysroot.stderr)
    );
    let sysroot = String::from_utf8_lossy(&sysroot.stdout).trim().to_owned();
    let binary = Path::new(&sysroot).join("bin").join(name);
    assert!(
        binary.is_file(),
        "active toolchain has no {name} binary at {}",
        binary.display()
    );
    binary
}

// Write a minimal plain Cargo package (no Patina dependency) with a single
// binary that prints `body`. Such a package integrates no runtime, so `run`/
// `replay` must build it shim-linked and run it under the native pre-run gate —
// never fall through to a toothless cargo-family `cargo run`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn write_plain_package(root: &Path, name: &str, main: &str) {
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        format!("[package]\nname = \"{name}\"\nversion = \"0.0.0\"\nedition = \"2021\"\n"),
    )
    .unwrap();
    fs::write(root.join("src/main.rs"), main).unwrap();
}

// A custom `#[global_allocator]` is SUPPORTED — it audits clean and runs
// deterministically, with no flags. This is the support regression for the
// tikv-jemallocator blocker: the shim's synchronization interposers register each
// lock in host-libc-backed tables (never the guest allocator), and an allocator's
// own `os_unfair_lock` runs natively during the bootstrap window / reentrantly
// under a held spinlock, so the allocator's init cannot re-enter the shim and
// deadlock. The fixture's allocator takes an interposed `os_unfair_lock` from
// INSIDE the global-allocator path (mimicking jemalloc's `malloc_mutex`), which is
// the exact reentrancy that used to deadlock: pre-fix, the shim's lock-table
// registration allocated through this very allocator; the RED proof is the real
// tikv-jemallocator MRE hanging/aborting when the fix is reverted (see the shim
// crate). macOS-specific (`os_unfair_lock`).
#[cfg(target_os = "macos")]
pub(super) const CUSTOM_ALLOCATOR_SOURCE: &str = r#"use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicU32, Ordering};

// `os_unfair_lock` is a bare `u32` (OS_UNFAIR_LOCK_INIT == 0), interposed by the
// shim. This allocator guards its one-time setup with it — reached from inside the
// global-allocator path, exactly like jemalloc's `malloc_mutex` during init.
unsafe extern "C" {
    fn os_unfair_lock_lock(lock: *mut u32);
    fn os_unfair_lock_unlock(lock: *mut u32);
}

struct LockingAlloc { lock: UnsafeCell<u32>, ready: AtomicU32 }
unsafe impl Sync for LockingAlloc {}

unsafe impl GlobalAlloc for LockingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if self.ready.load(Ordering::Acquire) == 0 {
            unsafe { os_unfair_lock_lock(self.lock.get()) };
            self.ready.store(1, Ordering::Release);
            unsafe { os_unfair_lock_unlock(self.lock.get()) };
        }
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) { unsafe { System.dealloc(ptr, layout) } }
}

#[global_allocator]
static GLOBAL: LockingAlloc = LockingAlloc { lock: UnsafeCell::new(0), ready: AtomicU32::new(0) };

fn main() { let v: Vec<u8> = vec![1, 2, 3]; println!("CUSTOM_ALLOC_OK len={}", v.len()); }
"#;

// `build --target wasi` compiles a Cargo package for `wasm32-wasip1`, and the
// resulting module composes with `audit` and `run` inferred from its magic
// bytes. Requires the wasm32-wasip1 target (installed in CI and by the
// validate/smoke scripts' preflight).
pub(super) fn campaign_gen_lines(text: &str) -> String {
    text.lines()
        .filter(|line| line.starts_with("PATINA_CAMPAIGN_GEN"))
        .collect::<Vec<_>>()
        .join("\n")
}

pub(super) fn campaign_state_without_invocations(path: &Path) -> serde_json::Value {
    let mut value: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    value.as_object_mut().unwrap().remove("invocations");
    value
}

pub(super) fn campaign_json_stdout(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "campaign JSON stdout was not a single object: {error}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

/// Build the planted-liveness-bug guest (`testbeds/liveness-campaign`) into
/// `output`, staging its Cargo build under this test build's target directory.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn build_liveness_guest(output: &Path) {
    let workspace = native_workspace();
    let fixture = workspace.join("testbeds/liveness-campaign");
    let target = common::guest_target_dir("liveness-campaign");
    invoke_in_with_env(
        workspace,
        &[
            "build",
            fixture.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
            "--release",
        ],
        &[("CARGO_TARGET_DIR", target.to_str().unwrap())],
    );
}

// Class pairing: build/run artifact discovery must use Cargo's target directory,
// not assume package/target (build caches and CARGO_TARGET_DIR redirect it).
pub(super) fn fixture_target_directory(package: &Path) -> std::path::PathBuf {
    let output = Command::new("cargo")
        .current_dir(package)
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    metadata["target_directory"]
        .as_str()
        .expect("Cargo target_directory")
        .into()
}

pub(super) fn wasm32_wasip1_installed() -> bool {
    Command::new("rustc")
        .args(["--print", "target-libdir", "--target", "wasm32-wasip1"])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

// The single `PATINA_SDK_REPORT` line from a run's stderr (emitted by the runtime
// at `Context::finish`, which the in-process wasip1 host drives).
pub(super) fn sdk_report_line(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr)
        .lines()
        .find(|line| line.starts_with("PATINA_SDK_REPORT "))
        .unwrap_or_default()
        .to_string()
}

// The first stdout line containing `needle` (the build-on-the-fly identity note
// and the guest's own output share stdout).
pub(super) fn stdout_line_with(output: &Output, needle: &str) -> String {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find(|line| line.contains(needle))
        .unwrap_or_default()
        .to_string()
}

// `linkat` (hard links) and `fdopendir` (the openat-traversal `remove_dir_all`
// uses) are strong-def'd by the shim: the audit is clean (no unsupported-import
// note, no allowances), the guest runs deterministically, same-seed double runs
// are byte-identical, and a recorded run replays byte-identically. Before this
// wave the audit refused the binary outright ("unsupported native imports:
// _fdopendir _linkat"), which is the RED evidence this test's fix clears.
/// The calibration busy-wait, in the pure-`Instant` shape that needs no x86
/// counter — the loop `fastant`'s pre-`main` constructor runs to measure the
/// timestamp counter against the OS clock, minus the `rdtsc`. Before
/// advance-on-spin this guest hung forever at 100% CPU: virtual time only moved
/// through a recorded sleep and the loop issues none, so `elapsed` was 0 on
/// every iteration and the exit condition was unreachable.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) const CALIBRATION_SPIN_SOURCE: &str = r#"
use std::time::Instant;

fn main() {
    let start = Instant::now();
    let mut reads: u64 = 0;
    loop {
        let elapsed = start.elapsed().as_nanos() as u64;
        reads += 1;
        if elapsed > 10_000_000 {
            println!("CALIBRATION elapsed_ns={elapsed} reads={reads}");
            // Derive a rate the way a calibrating crate does: both sides of the
            // ratio counted off the same clock.
            let ticks = Instant::now().duration_since(start).as_nanos() as u64;
            println!("CALIBRATION hz={}", ticks * 1_000_000_000 / elapsed);
            return;
        }
    }
}
"#;

// A single-process loopback TCP echo: a listener thread reads a fixed 16-byte
// payload and answers with its checksum; main streams the payload as eight
// 2-byte segments and prints a deterministic result line. Exercises the SimNet
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) const FS_FAULT_SOURCE: &str = r#"
use std::env;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};

fn raw(error: std::io::Error) -> i32 {
    error.raw_os_error().unwrap_or(-1)
}

fn expect_errno(label: &str, error: std::io::Error, expected: i32) {
    let errno = raw(error);
    assert_eq!(errno, expected, "{label} errno");
    println!("NATIVE_FS_FAULT_RESULT mode={label} errno={errno}");
}

fn main() {
    let mode = env::args().nth(1).expect("mode");
    match mode.as_str() {
        "eio_read" => {
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open("/fault-eio")
                .expect("open");
            file.write_all(b"abcdef").expect("setup write");
            file.seek(SeekFrom::Start(0)).expect("seek");
            let mut buf = [0u8; 6];
            match file.read(&mut buf) {
                Err(error) => expect_errno("eio_read", error, 5),
                Ok(read) => panic!("expected EIO read, got {read}"),
            }
        }
        "enospc_write" => {
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open("/fault-enospc")
                .expect("open");
            match file.write(b"abcdef") {
                Err(error) => expect_errno("enospc_write", error, 28),
                Ok(written) => panic!("expected ENOSPC write, wrote {written}"),
            }
        }
        "short_write" => {
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open("/fault-short-write")
                .expect("open");
            let written = file.write(b"abcdef").expect("short write");
            assert!((1..6).contains(&written), "written={written}");
            println!("NATIVE_FS_FAULT_RESULT mode=short_write written={written}");
        }
        "latency" => {
            // Virtual time observed from inside the guest, either side of one
            // eligible filesystem operation.
            std::fs::write("/fault-latency", b"abc").expect("setup write");
            let before = std::time::Instant::now();
            let meta = std::fs::metadata("/fault-latency").expect("metadata");
            let elapsed = before.elapsed().as_nanos();
            assert_eq!(meta.len(), 3);
            println!("NATIVE_FS_FAULT_RESULT mode=latency elapsed_nanos={elapsed}");
        }
        "short_read" => {
            std::fs::write("/fault-short-read", b"abcdef").expect("setup write_all");
            let mut file = OpenOptions::new()
                .read(true)
                .open("/fault-short-read")
                .expect("open read");
            let mut buf = [0u8; 6];
            let read = file.read(&mut buf).expect("short read");
            assert!((1..6).contains(&read), "read={read}");
            println!("NATIVE_FS_FAULT_RESULT mode=short_read read={read}");
        }
        other => panic!("unknown mode {other}"),
    }
}
"#;

// A planted escape: a program that references two uninterposed blocking
// primitives (the Mach `semaphore_wait`/`semaphore_signal`, in the
// `unmanaged-sync` class) directly. Taking their addresses forces the undefined
// imports without a host call, and they are operations the deterministic runtime
// does not model — exactly the escape class the pre-run gate exists to catch.
// (os_unfair_lock is now interposed and accepted, so the still-uninterposed Mach
// semaphore is the blocking representative for the gate-mechanics test.)
#[cfg(target_os = "macos")]
pub(super) const PLANTED_ESCAPE_SOURCE: &str = r#"
unsafe extern "C" {
    fn semaphore_wait(s: u32) -> i32;
    fn semaphore_signal(s: u32) -> i32;
}
fn main() {
    let ptrs: &[*const ()] = &[semaphore_wait as *const (), semaphore_signal as *const ()];
    let mut acc = 0usize;
    for p in ptrs {
        acc ^= *p as usize;
    }
    std::hint::black_box(acc);
    println!("planted escape ran");
}
"#;

pub(super) fn invoke_unchecked_clean_env(
    executable: &str,
    fixture: &Path,
    arguments: &[&str],
    envs: &[(&str, &str)],
) -> Output {
    let mut command = Command::new(executable);
    command.current_dir(fixture).args(arguments);
    for name in [
        "PATINA_SEED",
        "PATINA_RECORD",
        "PATINA_BUDGET",
        "PATINA_PARAM",
        "PATINA_BUGGIFY",
        "PATINA_BUGGIFY_AFTER_SETUP",
        "PATINA_BUGGIFY_ACTIVATION_PERMILLE",
        "PATINA_BUGGIFY_CUTOFF_NANOS",
        "PATINA_HARNESS",
        "PATINA_FUEL",
        "PATINA_ARG",
        "PATINA_ENV",
        "PATINA_PREOPEN",
        "PATINA_KIND",
        "PATINA_RUNTIME",
        "PATINA_ALL",
        "PATINA_EXERCISED",
        "PATINA_GENERATIONS",
    ] {
        command.env_remove(name);
    }
    for (name, value) in envs {
        command.env(name, value);
    }
    command.output().unwrap()
}

pub(super) fn result_line(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find(|line| line.starts_with("PATINA_RESULT"))
        .unwrap_or_else(|| {
            panic!(
                "missing PATINA_RESULT in stdout:\n{}",
                String::from_utf8_lossy(&output.stdout)
            )
        })
        .to_owned()
}

pub(super) fn create_fixture(path: &Path) {
    fs::create_dir_all(path.join("src")).unwrap();
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let runtime_path = workspace.join("crates/patina-runtime");
    let runtime_path = runtime_path.to_string_lossy().replace('\\', "\\\\");
    let abi_path = workspace.join("crates/patina-abi");
    let abi_path = abi_path.to_string_lossy().replace('\\', "\\\\");
    fs::write(
        path.join("Cargo.toml"),
        format!(
            "[package]\nname = \"patina-e2e-fixture\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[dependencies]\npatina-dst-runtime = {{ path = \"{runtime_path}\" }}\npatina-dst-abi = {{ path = \"{abi_path}\" }}\n"
        ),
    )
    .unwrap();
    fs::write(
        path.join("src/main.rs"),
        r#"use patina_dst_abi::ClockKind;
use patina_dst_runtime::RuntimeError;

fn scenario() -> Result<String, RuntimeError> {
    patina_dst_runtime::run(|context| {
        let prefix = context.entropy_bytes(8)?;
        let suffix = context.entropy_bytes(8)?;
        context.write_file("/state/value", &suffix)?;
        context.sleep_for(10)?;
        let stored = context.read_file("/state/value")?;
        let time = context.now(ClockKind::Monotonic)?;
        let wall = context.now(ClockKind::Realtime)?;
        Ok(format!("PATINA_RESULT seed={} prefix={prefix:?} suffix={stored:?} time={time} wall={wall} host={} zone={:?} cfg={}", context.root_seed(), context.hostname(), context.param("zone"), cfg!(all(patina, dst))))
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", scenario()?);
    Ok(())
}


#[cfg(test)]
mod tests {
    #[test]
    fn deterministic_scenario_runs_under_cargo_patina_test() {
        assert!(super::scenario().unwrap().starts_with("PATINA_RESULT"));
    }
}
"#,
    )
    .unwrap();
}

// ---- Cooperative-SUT (buggify) SDK, end to end -------------------------------
//
// A whole package depending on the `patina` crate's default-feature SDK, built
// and run through native-build/native-run. Verifies that buggify fires
// deterministically, emits `PATINA_SDK_REPORT`, records and replays
// byte-identically without re-supplying `--buggify`, and that a duplicate label
// aborts with the fatal marker.

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn sdk_fixture_package_name(root: &Path) -> String {
    let mut hash = DefaultHasher::new();
    root.hash(&mut hash);
    format!("buggify-sdk-fixture-{:016x}", hash.finish())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn write_sdk_fixture(root: &Path, main: &str) {
    fs::create_dir_all(root.join("src")).unwrap();
    let package_name = sdk_fixture_package_name(root);
    let patina_path = native_workspace().join("crates/patina");
    let patina_path = patina_path.to_string_lossy().replace('\\', "\\\\");
    fs::write(
        root.join("Cargo.toml"),
        format!(
            "[package]\nname = \"{package_name}\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[dependencies]\npatina-dst = {{ path = \"{patina_path}\" }}\n"
        ),
    )
    .unwrap();
    fs::write(root.join("src/main.rs"), main).unwrap();
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn assert_sites_join_for_sdk_report(
    package: &Path,
    stderr: &str,
    expected_labels: &[&str],
) {
    let report_path = package.join("sdk-report.stderr");
    fs::write(&report_path, stderr).unwrap();
    let joined = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        package,
        &[
            "sites",
            "--no-cache",
            "--exercised",
            report_path.to_str().unwrap(),
            "--all",
            "--format",
            "json",
        ],
    );
    assert!(
        joined.status.success(),
        "sites --exercised failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&joined.stdout),
        String::from_utf8_lossy(&joined.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&joined.stdout).unwrap_or_else(|error| {
        panic!(
            "sites --exercised did not emit JSON: {error}\nstdout:\n{}",
            String::from_utf8_lossy(&joined.stdout)
        )
    });
    assert_eq!(json["schema"], "patina.sites/v1");
    assert_eq!(json["unmatched_runtime_labels"], 0, "{json:#}");
    assert_eq!(
        json["totals"]["exercised"]["unmatched_runtime_labels"], 0,
        "{json:#}"
    );
    for label in expected_labels {
        let row = json["sites"]
            .as_array()
            .unwrap()
            .iter()
            .find(|site| site["label"].as_str() == Some(label))
            .unwrap_or_else(|| panic!("missing static site for label {label}: {json:#}"));
        assert!(
            row.get("exercised").is_some(),
            "label {label} did not join an exercised row: {json:#}"
        );
    }
}

// A guest that reuses the same label at two different call sites: a fatal
// duplicate, aborting with the marker. With literal labels the link-time site
// table catches it at install, before the first evaluation.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) const BUGGIFY_DUP_MAIN: &str = r#"
fn main() {
    let _ = patina_dst::buggify!("same-label");
    let _ = patina_dst::buggify!("same-label");
    println!("unreachable");
}
"#;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn assert_native_harness_prerun_refusal(
    name: &str,
    exact: &str,
    source: &str,
    category: &str,
) {
    let directory = tempdir().unwrap();
    let root = directory.path();
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        format!("[package]\nname = {name:?}\nversion = \"0.1.0\"\nedition = \"2021\"\n"),
    )
    .unwrap();
    fs::write(root.join("src/lib.rs"), source).unwrap();
    let native = Command::new("cargo")
        .args(["test", "--quiet"])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(native.status.success(), "{native:?}");
    let patina = env!("CARGO_BIN_EXE_cargo-patina");
    let staged =
        fixture_target_directory(root).join(format!("patina/dst/{name}/lib/{name}/{exact}"));
    fs::create_dir_all(&staged).unwrap();
    let trace = staged.join("seed-0.patina");
    // File existence is not evidence that THIS run produced a trace.
    fs::write(&trace, b"stale trace canary").unwrap();
    let run = invoke_unchecked(
        patina,
        root,
        &[
            "test",
            ".",
            "--harness-target",
            name,
            "--exact",
            exact,
            "--seed",
            "0",
            "--format",
            "json",
        ],
    );
    assert_eq!(run.status.code(), Some(2), "{run:?}");
    let result: serde_json::Value = serde_json::from_slice(&run.stdout).unwrap();
    assert_eq!(result["verb"], "test");
    assert!(result["trace"].is_null(), "{result}");
    // Skipping the recording attempt must not touch a previous attempt's file;
    // and that file must not masquerade as facts in this attempt's receipt.
    assert_eq!(fs::read(&trace).unwrap(), b"stale trace canary");
    let refused = invoke_unchecked(
        patina,
        root,
        &[
            "run",
            staged.join("guest").to_str().unwrap(),
            "--format",
            "json",
        ],
    );
    assert_eq!(refused.status.code(), Some(2));
    let receipt: serde_json::Value = serde_json::from_slice(&refused.stdout).unwrap();
    assert_eq!(receipt["refusal"]["class"], "native_prerun_audit");
    assert!(receipt["guest_exit"].is_null());
    assert!(receipt["trace"].is_null());
    let audit = invoke_unchecked(
        patina,
        root,
        &[
            "audit",
            staged.join("guest").to_str().unwrap(),
            "--format",
            "json",
        ],
    );
    assert_eq!(audit.status.code(), Some(2), "{audit:?}");
    let result: serde_json::Value = serde_json::from_slice(&audit.stdout).unwrap();
    assert!(
        result["finding_details"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["category"] == category),
        "{result}"
    );
}

// ---- patina-dst-harness (shim-backed configure-then-run harness) --------------
//
// Validation gates for USAGE-MODES.md usage mode 2 (startup Option B, deferred
// init). A harness binary depends on `patina-dst-harness` and is built and run
// through `cargo patina run --harness`; ordinary `std` effects in the application
// closure are interposed by the native shim, and the harness's `HarnessBuilder`
// overlay flows through the same `RuntimeConfig` fields the CLI env path sets.
// Gate 7 (SDK dependency-lightness) belongs to the facade builder; gate 8
// (explicit-context separateness) is out of scope here — the explicit `Context`
// API lives in `patina-dst-runtime` and is exercised by `create_fixture`'s
// `patina_dst::run` scenarios, which never install the shim's global context.

/// Write a harness fixture crate at `dir` whose `main.rs` is `main_rs`, with a
/// path dependency on the workspace `patina-dst-harness`. Modeled on
/// `create_fixture`, but the dependency is the harness crate, not the SDK.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn write_harness_fixture(dir: &Path, name: &str, main_rs: &str) {
    fs::create_dir_all(dir.join("src")).unwrap();
    let harness_path = native_workspace().join("crates/patina-harness");
    let harness_path = harness_path.to_string_lossy().replace('\\', "\\\\");
    fs::write(
        dir.join("Cargo.toml"),
        format!(
            "[package]\nname = \"{name}\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[dependencies]\npatina-dst-harness = {{ path = \"{harness_path}\" }}\n"
        ),
    )
    .unwrap();
    fs::write(dir.join("src/main.rs"), main_rs).unwrap();
}

/// Build a harness fixture into `out` through `cargo patina build`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn build_harness_bin(dir: &Path, out: &Path) {
    invoke(
        native_workspace(),
        &[
            "build",
            dir.join("Cargo.toml").to_str().unwrap(),
            "--output",
            out.to_str().unwrap(),
        ],
    );
}

// ---------------------------------------------------------------------------
// WASI depth (coverage-depth arc, wave D): fuel + per-import hostcall counts.
// ---------------------------------------------------------------------------

// A wasip1 guest whose hostcall mix is fixed by the module text and whose work
// (and therefore fuel) is driven by one deterministic random byte, so depth
// varies across seeds while staying exactly reproducible for any one seed.
pub(super) const WASI_DEPTH_MODULE: &str = r#"(module
    (import "wasi_snapshot_preview1" "random_get"
        (func $random (param i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "clock_time_get"
        (func $clock (param i32 i64 i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_write"
        (func $write (param i32 i32 i32 i32) (result i32)))
    (memory (export "memory") 1)
    (data (i32.const 128) "DEPTH_GUEST ok\n")
    (func (export "_start")
        (local $n i32)
        (drop (call $random (i32.const 64) (i32.const 1)))
        (local.set $n (i32.and (i32.load8_u (i32.const 64)) (i32.const 63)))
        (block $done (loop $spin
            (br_if $done (i32.eqz (local.get $n)))
            (local.set $n (i32.sub (local.get $n) (i32.const 1)))
            (br $spin)))
        (drop (call $clock (i32.const 0) (i64.const 0) (i32.const 72)))
        (i32.store (i32.const 0) (i32.const 128))
        (i32.store (i32.const 4) (i32.const 15))
        (drop (call $write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 16)))))"#;

pub(super) fn campaign_depth_meta(out_dir: &Path) -> serde_json::Value {
    let path = out_dir.join("depth").join("meta.json");
    assert!(
        path.is_file(),
        "campaign depth store is missing at {}",
        path.display()
    );
    serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap()
}

// ---- campaign forwards the native `run` invocation shape ---------------------
//
// A campaign spawns child `cargo patina run` processes. `--harness` and the
// pre-run gate surface (`--allow`, `--allow-unsupported-symbols`) are host/build
// facts, not seed-derived knobs: without them every generation of an affected
// guest is refused IDENTICALLY, so the campaign is not a sweep that reports
// failures, it is a sweep that never ran the guest at all. Each gate below is
// red-before/green-after in one test: the same guest, same generations, with and
// without the flag.

/// Run a campaign and return its output, without asserting success.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn campaign_run(out: &Path, guest: &Path, extra: &[&str]) -> Output {
    let mut args = vec![
        "campaign",
        guest.to_str().unwrap(),
        "--gens",
        "2",
        "--progress-every",
        "1",
        "--out-dir",
        out.to_str().unwrap(),
        "--format",
        "json",
    ];
    args.extend_from_slice(extra);
    invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        native_workspace(),
        &args,
    )
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn build_facts_guest(directory: &Path, name: &str, source: &str) -> PathBuf {
    let path = directory.join(format!("{name}.rs"));
    fs::write(&path, source).unwrap();
    let binary = directory.join(name);
    invoke(
        native_workspace(),
        &[
            "build",
            path.to_str().unwrap(),
            "--output",
            binary.to_str().unwrap(),
        ],
    );
    binary
}
