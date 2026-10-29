//! Shared e2e fixtures, process results, reports, and campaign checkpoints.

use super::*;

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
// binary whose `main.rs` is `main`.
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

// The single `PATINA_SDK_REPORT` line from a run's stderr (emitted by the runtime
// at `Context::finish`).
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

/// A store that fails closed after a failed writeback and re-reads its log
/// from the disk, the way a real kernel lets it: `posix_fadvise(DONTNEED)`
/// drops the clean pages, so the re-read sees what the disk holds, not what
/// the failed writeback dropped. One mode per volume writeback a test fails
/// (`--fs-error-at`): `fsync` fails the commit's `fsync`, `sync` fails a
/// `sync(2)`, which reports nothing. Each prints what the guest saw.
#[cfg(target_os = "linux")]
pub(super) const WRITEBACK_SOURCE: &str = r#"
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;

unsafe extern "C" {
    fn posix_fadvise(fd: i32, offset: i64, len: i64, advice: i32) -> i32;
    fn syncfs(fd: i32) -> i32;
    fn sync();
    fn sync_file_range(fd: i32, offset: i64, nbytes: i64, flags: u32) -> i32;
}

const PAGE: usize = 4096;
const POSIX_FADV_DONTNEED: i32 = 4;
const SYNC_FILE_RANGE_WAIT_BEFORE: u32 = 1;

fn errno_of(result: i32) -> i32 {
    if result == 0 { 0 } else { std::io::Error::last_os_error().raw_os_error().unwrap_or(-1) }
}

fn fsync_errno(file: &File) -> i32 {
    match file.sync_all() {
        Ok(()) => 0,
        Err(error) => error.raw_os_error().unwrap_or(-1),
    }
}

/// What the log's first page reads after its clean pages are dropped.
fn reread() -> &'static str {
    let mut log = File::open("/log").expect("reopen");
    assert_eq!(unsafe { posix_fadvise(log.as_raw_fd(), 0, 0, POSIX_FADV_DONTNEED) }, 0);
    let mut page = vec![0u8; PAGE];
    log.read_exact(&mut page).expect("reread");
    match page[0] {
        b'a' => "durable",
        b'b' => "dropped-write",
        _ => "other",
    }
}

fn main() {
    let mode = env::args().nth(1).expect("mode");
    let mut log = OpenOptions::new()
        .read(true).write(true).create(true).truncate(true)
        .open("/log").expect("open");
    log.write_all(&[b'a'; PAGE]).expect("write");
    assert_eq!(fsync_errno(&log), 0, "the first commit");
    let watcher = File::open("/log").expect("watcher");
    log.write_all_at(&[b'b'; PAGE], 0).expect("overwrite");
    let line = match mode.as_str() {
        "fsync" => {
            let failed = fsync_errno(&log);
            let retried = fsync_errno(&log);
            let waited = [0, 1].map(|_| errno_of(unsafe {
                sync_file_range(watcher.as_raw_fd(), 0, 0, SYNC_FILE_RANGE_WAIT_BEFORE)
            }));
            let syncfs = [0, 1].map(|_| errno_of(unsafe { syncfs(watcher.as_raw_fd()) }));
            format!("fsync={failed},{retried} wait={},{} syncfs={},{}",
                waited[0], waited[1], syncfs[0], syncfs[1])
        }
        "sync" => {
            unsafe { sync() };
            let later = File::open("/log").expect("opened after the failure");
            let fsync = [fsync_errno(&later), fsync_errno(&later)];
            let syncfs = [0, 1].map(|_| errno_of(unsafe { syncfs(log.as_raw_fd()) }));
            format!("fsync={},{} syncfs={},{}", fsync[0], fsync[1], syncfs[0], syncfs[1])
        }
        other => panic!("unknown mode {other}"),
    };
    println!("NATIVE_WRITEBACK {line} reread={}", reread());
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
    // Neither a flag default nor a control-plane variable from the caller's
    // environment may reach the invocation under test.
    for (name, _) in env::vars_os() {
        if name.to_string_lossy().starts_with("PATINA_") {
            command.env_remove(name);
        }
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

// ---- Cooperative-SUT (buggify) SDK, end to end -------------------------------
//
// A whole package depending on the `patina` crate's default-feature SDK, built
// and run through native-build/native-run. Verifies that buggify fires
// deterministically, reports its sites, records and replays
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
pub(super) fn assert_sites_join_for_campaign(
    package: &Path,
    binary: &Path,
    expected_labels: &[&str],
) {
    let directory = tempdir().unwrap();
    let out = directory.path().join("campaign");
    // The guest's unreached `reachable!` fails the campaign's coverage gate;
    // only the sites store it leaves behind matters here.
    invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        native_workspace(),
        &[
            "campaign",
            binary.to_str().unwrap(),
            "--gens",
            "1",
            "--buggify",
            "--out-dir",
            out.to_str().unwrap(),
        ],
    );
    let joined = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        package,
        &[
            "sites",
            "--no-cache",
            "--exercised",
            out.to_str().unwrap(),
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
// through `cargo patina run`; ordinary `std` effects in the application
// closure are interposed by the native shim, and the harness's `HarnessBuilder`
// overlay flows through the same `RuntimeConfig` fields the CLI env path sets.

/// Write a harness fixture crate at `dir` whose `main.rs` is `main_rs`, with a
/// path dependency on the workspace `patina-dst-harness`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn write_harness_fixture(dir: &Path, name: &str, main_rs: &str) {
    fs::create_dir_all(dir.join("src")).unwrap();
    let harness_path = native_workspace().join("crates/patina-harness");
    let harness_path = harness_path.to_string_lossy().replace('\\', "\\\\");
    let sdk_path = native_workspace().join("crates/patina");
    let sdk_path = sdk_path.to_string_lossy().replace('\\', "\\\\");
    fs::write(
        dir.join("Cargo.toml"),
        format!(
            "[package]\nname = \"{name}\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[dependencies]\npatina-dst-harness = {{ path = \"{harness_path}\" }}\npatina-dst = {{ path = \"{sdk_path}\" }}\n"
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

// ---- campaign forwards the native `run` invocation shape ---------------------
//
// A campaign spawns child `cargo patina run` processes. The
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

/// The `sha256:` identity of the `cargo-patina` under test, as a recording or
/// a campaign names it: the SHA-256 of its linker build ID, or of its bytes
/// when it carries none.
pub(super) fn supervisor_identity() -> String {
    use object::Object;
    let bytes = fs::read(env!("CARGO_BIN_EXE_cargo-patina")).unwrap();
    let file = object::File::parse(&*bytes).unwrap();
    let id = match file.build_id() {
        Ok(Some(id)) => Some(id.to_vec()),
        _ => file.mach_uuid().ok().flatten().map(|id| id.to_vec()),
    };
    let digest = match id {
        Some(id) => Sha256::new()
            .chain_update(b"cargo-patina build id\0")
            .chain_update(&id)
            .finalize(),
        None => Sha256::digest(&bytes),
    };
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("sha256:{hex}")
}
