use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output};

use tempfile::tempdir;

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
        &["wasi-run", module.to_str().unwrap(), "--preopen", "/rw:rw"],
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
        &["wasi-run", module.to_str().unwrap(), "--preopen", "/ro:ro"],
    );
    assert_eq!(ro.status.code(), Some(69));
}

#[test]
fn separate_processes_repeat_record_and_replay() {
    let directory = tempdir().unwrap();
    let fixture = directory.path().join("fixture");
    create_fixture(&fixture);

    let first = invoke(&fixture, &["run", "--seed", "123"]);
    let repeated = invoke(&fixture, &["run", "--seed", "123"]);
    let different = invoke(&fixture, &["run", "--seed", "124"]);
    let first_result = result_line(&first);
    assert_eq!(result_line(&repeated), first_result);
    assert!(first_result.contains("cfg=true"));
    assert_ne!(result_line(&different), first_result);
    let parameterized = invoke(&fixture, &["run", "--seed", "123", "--param", "zone=a"]);
    assert!(result_line(&parameterized).contains("zone=Some(\"a\")"));

    let budgeted = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        &fixture,
        &["run", "--seed", "123", "--budget", "1"],
    );
    assert!(!budgeted.status.success());
    assert!(String::from_utf8_lossy(&budgeted.stderr).contains("StepBudgetExceeded"));

    let trace = directory.path().join("run.patina");
    let recorded = invoke(
        &fixture,
        &["run", "--seed", "123", "--record", trace.to_str().unwrap()],
    );
    assert!(trace.is_file());
    let replayed = invoke(&fixture, &["run", "--replay", trace.to_str().unwrap()]);
    assert_eq!(result_line(&recorded), result_line(&replayed));
    assert_eq!(result_line(&replayed), first_result);

    let branched = invoke(
        &fixture,
        &[
            "run",
            "--branch",
            trace.to_str().unwrap(),
            "--from",
            "1",
            "--branch-seed",
            "999",
            "--branch-id",
            "branch-999",
        ],
    );
    assert_ne!(result_line(&branched), first_result);
    let replayed_branch = invoke(
        &fixture,
        &[
            "run",
            "--replay",
            trace.to_str().unwrap(),
            "--timeline",
            "branch-999",
        ],
    );
    assert_eq!(result_line(&replayed_branch), result_line(&branched));

    invoke(&fixture, &["test", "--seed", "123"]);
    let alias = invoke_with(
        env!("CARGO_BIN_EXE_cargo-dst"),
        &fixture,
        &["run", "--seed", "123"],
    );
    assert_eq!(result_line(&alias), first_result);

    writeln!(
        OpenOptions::new()
            .append(true)
            .open(fixture.join("src/main.rs"))
            .unwrap(),
        "// changed after recording"
    )
    .unwrap();
    let incompatible = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        &fixture,
        &["run", "--replay", trace.to_str().unwrap()],
    );
    assert!(!incompatible.status.success());
    let stderr = String::from_utf8_lossy(&incompatible.stderr);
    assert!(
        stderr.contains("FingerprintMismatch") || stderr.contains("fingerprint mismatch"),
        "missing fingerprint diagnostic in stderr:\n{stderr}"
    );
}

// Whole Cargo-package `native-build`: a package with a path dependency and a
// build script builds under Patina control, passes the strict audit, and
// records/replays byte-identically, while multi-bin ambiguity and an
// off-allowlist binary fail closed. `native-build` builds the `patina-native-shim`
// staticlib from the surrounding Patina workspace, so it runs with the workspace
// as its working directory while the fixture is addressed by absolute path.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_build_package_audits_records_and_fails_closed() {
    let directory = tempdir().unwrap();
    let package = directory.path().join("pkg");
    create_package_fixture(directory.path());
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();

    // The clean binary builds through the package's own `cargo build`, with the
    // shim link args isolated to the final binary by the explicit host --target
    // (the build script's file I/O proves it did not leak onto host artifacts).
    let clean = package.join("clean-bin");
    let built = invoke_in(
        workspace,
        &[
            "native-build",
            package.to_str().unwrap(),
            "--bin",
            "patina-native-pkg-fixture",
            "--output",
            clean.to_str().unwrap(),
        ],
    );
    assert!(
        String::from_utf8_lossy(&built.stdout).contains("PATINA_NATIVE_BUILD"),
        "missing build marker:\n{}",
        String::from_utf8_lossy(&built.stdout)
    );
    assert!(clean.is_file());

    // The produced binary passes the same strict audit as a single-source
    // binary, with the shim control-plane symbols allowed per audited binary.
    // Under the host-alias doctrine the trace-fd and baton vehicles are resolved
    // at runtime through the `dlsym` primitive, so their names never reach the
    // guest import table. macOS collapses to the single `dlsym` residue; Linux
    // reaches the resolver through `-Wl,--wrap=dlsym` (leaving `dlsym` as the
    // residue) and additionally keeps `pthread_create` as the wrap-contained
    // managed thread-creation vehicle.
    let control_plane: &[&str] = if cfg!(target_os = "macos") {
        &["dlsym"]
    } else {
        &["dlsym", "pthread_create"]
    };
    let mut audit_args = vec!["native-audit", clean.to_str().unwrap()];
    for symbol in control_plane {
        audit_args.push("--allow");
        audit_args.push(symbol);
    }
    invoke_in(workspace, &audit_args);

    // The package binary runs under native-run with cross-process seed stability,
    // seed variation, and byte-identical record/replay through the supervisor.
    let seeded = package_result(&invoke_in(
        workspace,
        &["native-run", clean.to_str().unwrap(), "--seed", "5"],
    ));
    let repeated = package_result(&invoke_in(
        workspace,
        &["native-run", clean.to_str().unwrap(), "--seed", "5"],
    ));
    let other = package_result(&invoke_in(
        workspace,
        &["native-run", clean.to_str().unwrap(), "--seed", "6"],
    ));
    assert_eq!(seeded, repeated);
    assert_ne!(seeded, other);
    assert!(
        seeded.contains("built=1"),
        "build-script env missing: {seeded}"
    );
    assert!(
        seeded.contains("stored=hello from greeter"),
        "path dependency output missing: {seeded}"
    );

    let trace = directory.path().join("pkg.patina");
    let recorded = package_result(&invoke_in(
        workspace,
        &[
            "native-run",
            clean.to_str().unwrap(),
            "--seed",
            "5",
            "--record",
            trace.to_str().unwrap(),
            "--fingerprint",
            "native-pkg-v1",
        ],
    ));
    let replayed = package_result(&invoke_in(
        workspace,
        &[
            "native-run",
            clean.to_str().unwrap(),
            "--replay",
            trace.to_str().unwrap(),
            "--fingerprint",
            "native-pkg-v1",
        ],
    ));
    assert_eq!(recorded, seeded);
    assert_eq!(replayed, seeded);

    // Multiple binary targets with no --bin selection fails with a clear message
    // rather than guessing.
    let ambiguous = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &["native-build", package.to_str().unwrap()],
    );
    assert!(!ambiguous.status.success());
    let ambiguous_stderr = String::from_utf8_lossy(&ambiguous.stderr);
    assert!(
        ambiguous_stderr.contains("multiple binary targets") && ambiguous_stderr.contains("--bin"),
        "missing ambiguity diagnostic:\n{ambiguous_stderr}"
    );

    // A binary whose build product imports an off-allowlist symbol builds, but
    // fails the audit with the existing category diagnostic.
    let leaky = package.join("leaky-bin");
    invoke_in(
        workspace,
        &[
            "native-build",
            package.to_str().unwrap(),
            "--bin",
            "leaky",
            "--output",
            leaky.to_str().unwrap(),
        ],
    );
    let denied = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &["native-audit", leaky.to_str().unwrap()],
    );
    assert!(!denied.status.success());
    assert!(
        String::from_utf8_lossy(&denied.stderr).contains("process"),
        "missing process-category diagnostic:\n{}",
        String::from_utf8_lossy(&denied.stderr)
    );
}

fn invoke(fixture: &Path, arguments: &[&str]) -> Output {
    invoke_with(env!("CARGO_BIN_EXE_cargo-patina"), fixture, arguments)
}

fn native_workspace() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
}

// Two threads communicating over `std::sync::mpsc` with `recv_timeout`: on macOS
// this drives std's Darwin thread `Parker` (`park`/`park_timeout` on a
// libdispatch semaphore), on Linux the futex Parker. The interposed dispatch
// semaphore routes the wait through the deterministic scheduler and virtual
// clock, so both the delivery/timeout interleaving and the timeout count are a
// function of the seed alone — byte-identical across repeated runs and exactly
// reproduced by record/replay — never of host wall-clock timing.
const RECV_TIMEOUT_SOURCE: &str = r#"
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

fn main() {
    let (tx, rx) = mpsc::channel::<u64>();
    let producer = thread::spawn(move || {
        for i in 0..5 {
            thread::sleep(Duration::from_millis(10));
            tx.send(i).unwrap();
        }
    });
    let mut delivered = Vec::new();
    let mut timeouts = 0u32;
    loop {
        match rx.recv_timeout(Duration::from_millis(7)) {
            Ok(v) => delivered.push(v),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                timeouts += 1;
                if delivered.len() == 5 {
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    producer.join().unwrap();
    println!("delivered={:?} timeouts={}", delivered, timeouts);
}
"#;

// Part A: `recv_timeout` across two threads is byte-identical across >=3 runs at
// multiple seeds and exactly reproduced by record/replay. Before the fix the
// Parker blocked a real host thread on a libdispatch semaphore and read host
// time for its timeout, escaping the scheduler entirely.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_recv_timeout_is_deterministic_across_seeds_and_replay() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("recv_timeout.rs");
    fs::write(&source, RECV_TIMEOUT_SOURCE).unwrap();
    let workspace = native_workspace();
    let bin = directory.path().join("recv-timeout");
    invoke_in(
        workspace,
        &[
            "native-build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );

    for seed in ["1", "5", "9"] {
        let first = invoke_in(
            workspace,
            &["native-run", bin.to_str().unwrap(), "--seed", seed],
        );
        let baseline = String::from_utf8_lossy(&first.stdout).into_owned();
        assert!(
            baseline.contains("delivered="),
            "unexpected recv_timeout output at seed {seed}: {baseline}"
        );
        for _ in 0..2 {
            let again = invoke_in(
                workspace,
                &["native-run", bin.to_str().unwrap(), "--seed", seed],
            );
            assert_eq!(
                baseline,
                String::from_utf8_lossy(&again.stdout),
                "recv_timeout output is not byte-identical across runs at seed {seed}"
            );
        }
    }

    let trace = directory.path().join("recv.patina");
    let recorded = invoke_in(
        workspace,
        &[
            "native-run",
            bin.to_str().unwrap(),
            "--seed",
            "9",
            "--record",
            trace.to_str().unwrap(),
            "--fingerprint",
            "recv-timeout",
        ],
    );
    let replayed = invoke_in(
        workspace,
        &[
            "native-run",
            bin.to_str().unwrap(),
            "--replay",
            trace.to_str().unwrap(),
            "--fingerprint",
            "recv-timeout",
        ],
    );
    assert_eq!(
        String::from_utf8_lossy(&recorded.stdout),
        String::from_utf8_lossy(&replayed.stdout),
        "record and strict replay diverged"
    );
}

// A guest that reads a file the supervisor mounted into the deterministic
// filesystem. Used to exercise `--mount` composing with `--record`/`--replay`,
// which hands the child TWO inherited descriptors at once.
const MOUNT_READER_SOURCE: &str = r#"
use std::fs;

fn main() {
    let contents = fs::read_to_string("/data.txt").expect("read mounted file");
    print!("{contents}");
}
"#;

// Regression: `--mount` + `--record`/`--replay` installs two inherited
// descriptors — the trace channel (fd 3) and the filesystem image (fd 4). The
// image temp file can be allocated on fd 3, so installing the trace there first
// used to clobber the still-unread image source, crashing the guest by signal
// (buggy-smoke never tripped it: it carries only the single trace fd). The
// descriptor-relocation fix (F_DUPFD every source above the target range before
// installing) must let both compose. Asserts a clean record AND replay that see
// the mounted content.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_mount_composes_with_record_and_replay_two_inherited_descriptors() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("read_mount.rs");
    fs::write(&source, MOUNT_READER_SOURCE).unwrap();
    let workspace = native_workspace();
    let bin = directory.path().join("read-mount");
    invoke_in(
        workspace,
        &[
            "native-build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );

    let mount = directory.path().join("corpus");
    fs::create_dir(&mount).unwrap();
    fs::write(mount.join("data.txt"), "MOUNTED-CONTENT\n").unwrap();

    let trace = directory.path().join("mount.patina");
    let recorded = invoke_in(
        workspace,
        &[
            "native-run",
            bin.to_str().unwrap(),
            "--seed",
            "0",
            "--mount",
            mount.to_str().unwrap(),
            "--record",
            trace.to_str().unwrap(),
            "--fingerprint",
            "read-mount",
        ],
    );
    assert_eq!(
        String::from_utf8_lossy(&recorded.stdout),
        "MOUNTED-CONTENT\n",
        "record mode with --mount did not see the mounted file"
    );

    // Replay carries both descriptors too, and must re-supply --mount so the
    // image hash folded into the fingerprint still matches.
    let replayed = invoke_in(
        workspace,
        &[
            "native-run",
            bin.to_str().unwrap(),
            "--replay",
            trace.to_str().unwrap(),
            "--mount",
            mount.to_str().unwrap(),
            "--fingerprint",
            "read-mount",
        ],
    );
    assert_eq!(
        String::from_utf8_lossy(&replayed.stdout),
        "MOUNTED-CONTENT\n",
        "strict replay with --mount diverged from the recorded run"
    );

    // A DIFFERENT corpus at replay hashes to a different image, so the hash
    // folded into the fingerprint no longer matches and replay must fail closed —
    // and say WHY (the specific fingerprint mismatch), not abort mutely with the
    // generic "no runtime installed" line.
    let other_mount = directory.path().join("corpus-other");
    fs::create_dir(&other_mount).unwrap();
    fs::write(other_mount.join("data.txt"), "DIFFERENT-CONTENT\n").unwrap();
    let cross = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &[
            "native-run",
            bin.to_str().unwrap(),
            "--replay",
            trace.to_str().unwrap(),
            "--mount",
            other_mount.to_str().unwrap(),
            "--fingerprint",
            "read-mount",
        ],
    );
    let cross_stderr = String::from_utf8_lossy(&cross.stderr);
    assert!(
        !cross.status.success(),
        "replay against a different --mount corpus must fail closed:\nstderr:\n{cross_stderr}"
    );
    assert!(
        cross_stderr.contains("failed to initialize")
            && cross_stderr.contains("fingerprint mismatch"),
        "cross-corpus replay must name the fingerprint mismatch, not abort mutely:\nstderr:\n{cross_stderr}"
    );
}

// A guest that opens the SAME file twice and takes an advisory `flock` on each
// descriptor. The interposed `flock` keys on the deterministic-fs inode, so the
// second `LOCK_EX | LOCK_NB` must report EWOULDBLOCK (-1) — the contention redb's
// open surfaces as `DatabaseAlreadyOpen` — rather than both succeeding as a naive
// always-0 stub would. Closing the first descriptor releases the lock, so a
// third opener then acquires it, proving release-on-close.
const FLOCK_CONTENTION_SOURCE: &str = r#"
use std::fs::{File, OpenOptions};
use std::os::unix::io::AsRawFd;

unsafe extern "C" {
    fn flock(fd: i32, operation: i32) -> i32;
}
const LOCK_EX: i32 = 2;
const LOCK_NB: i32 = 4;

fn try_lock(file: &File) -> i32 {
    unsafe { flock(file.as_raw_fd(), LOCK_EX | LOCK_NB) }
}

fn main() {
    let first = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open("/lock.db")
        .unwrap();
    let first_lock = try_lock(&first);
    let second = File::open("/lock.db").unwrap();
    let second_lock = try_lock(&second);
    drop(first);
    let third = File::open("/lock.db").unwrap();
    let third_lock = try_lock(&third);
    println!("FLOCK first={first_lock} second={second_lock} third={third_lock}");
}
"#;

// The per-inode advisory-lock table: a second open of the same path contends the
// first's `LOCK_EX`, and closing the first releases it. A single-opener redb path
// still acquires cleanly (covered by the redb rung); this is the can-fail half.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_flock_contends_on_a_second_open_and_releases_on_close() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("flock.rs");
    fs::write(&source, FLOCK_CONTENTION_SOURCE).unwrap();
    let workspace = native_workspace();
    let bin = directory.path().join("flock");
    invoke_in(
        workspace,
        &[
            "native-build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );
    let run = invoke_in(
        workspace,
        &["native-run", bin.to_str().unwrap(), "--seed", "1"],
    );
    let stdout = String::from_utf8_lossy(&run.stdout);
    assert!(
        stdout.contains("FLOCK first=0 second=-1 third=0"),
        "per-inode flock must contend the second open and release on close:\nstdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&run.stderr),
    );
}

// A guest that touches the deterministic filesystem, so its first effect
// boundary routes through `ensure_runtime` (a guest that only writes stdout is
// captured without a runtime check and would never observe a failed init). The
// fault-config conflict is resolved at runtime init, before this body runs, so
// under a conflicting replay the filesystem write never executes — the boundary
// aborts with the runtime's diagnostic first.
const FS_TOUCH_SOURCE: &str = r#"
use std::fs;

fn main() {
    fs::write("/probe", b"x").unwrap();
    println!("TOUCH_ok");
}
"#;

// Supplying a fault knob at replay that conflicts with the trace's recorded
// (authoritative) configuration must fail closed — and the shim must surface the
// runtime's specific "fault knobs conflict" diagnostic, not abort with the
// generic "no runtime installed" line.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_replay_fault_knob_conflict_names_the_conflict() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("fs_touch.rs");
    fs::write(&source, FS_TOUCH_SOURCE).unwrap();
    let workspace = native_workspace();
    let bin = directory.path().join("fs-touch");
    invoke_in(
        workspace,
        &[
            "native-build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );

    let trace = directory.path().join("faults.patina");
    invoke_in(
        workspace,
        &[
            "native-run",
            bin.to_str().unwrap(),
            "--seed",
            "0",
            "--record",
            trace.to_str().unwrap(),
            "--fingerprint",
            "trivial-faults",
            "--net-latency-nanos",
            "1000",
        ],
    );

    // Same fingerprint, but a DIFFERENT net-latency knob than the recording: the
    // trace is authoritative, so replay must reject the conflicting knob.
    let conflict = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &[
            "native-run",
            bin.to_str().unwrap(),
            "--replay",
            trace.to_str().unwrap(),
            "--fingerprint",
            "trivial-faults",
            "--net-latency-nanos",
            "2000",
        ],
    );
    let conflict_stderr = String::from_utf8_lossy(&conflict.stderr);
    assert!(
        !conflict.status.success(),
        "a conflicting replay fault knob must fail closed:\nstderr:\n{conflict_stderr}"
    );
    assert!(
        conflict_stderr.contains("failed to initialize")
            && conflict_stderr.contains("fault knobs conflict"),
        "the conflict must be named, not aborted mutely:\nstderr:\n{conflict_stderr}"
    );
}

// Two threads contending on a std::sync::RwLock. On the toolchain in use std's
// queue-based RwLock takes its contended `write()` path through
// lock_contended → thread::park → dispatch_semaphore_wait — i.e. the interposed
// Darwin Parker. Each thread holds the write lock across a scheduling point, so
// the other writers PARK on it; the acquisition order is therefore chosen by
// DetScheduler. The total is schedule-invariant (correctly locked, no lost
// updates), the order is byte-identical per seed, and the winning thread order
// varies across seeds — this is the load-bearing piece for reaching a
// lock-contention race (e.g. rung 1's lost-update) deterministically.
const RWLOCK_CONTENTION_SOURCE: &str = r#"
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

fn main() {
    let log = Arc::new(RwLock::new(Vec::<u32>::new()));
    let mut handles = Vec::new();
    for id in 0..3u32 {
        let log = Arc::clone(&log);
        handles.push(thread::spawn(move || {
            for _ in 0..4 {
                let mut g = log.write().unwrap();
                g.push(id);
                thread::sleep(Duration::from_nanos(1));
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let final_log = log.read().unwrap();
    let sum: u32 = final_log.iter().sum();
    println!("RWLOCK_RESULT len={} sum={} order={:?}", final_log.len(), sum, &*final_log);
}
"#;

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_rwlock_contention_is_seed_deterministic_and_varies_across_seeds() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("rwlock.rs");
    fs::write(&source, RWLOCK_CONTENTION_SOURCE).unwrap();
    let workspace = native_workspace();
    let bin = directory.path().join("rwlock");
    invoke_in(
        workspace,
        &[
            "native-build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );

    let mut outputs = std::collections::BTreeSet::new();
    for seed in ["1", "2", "3", "4", "5", "6"] {
        let first = invoke_in(
            workspace,
            &["native-run", bin.to_str().unwrap(), "--seed", seed],
        );
        let baseline = String::from_utf8_lossy(&first.stdout).into_owned();
        // Schedule-invariant total (correctly locked, no lost updates).
        assert!(
            baseline.contains("RWLOCK_RESULT len=12 sum=12"),
            "unexpected rwlock output at seed {seed}: {baseline}"
        );
        for _ in 0..2 {
            let again = invoke_in(
                workspace,
                &["native-run", bin.to_str().unwrap(), "--seed", seed],
            );
            assert_eq!(
                baseline,
                String::from_utf8_lossy(&again.stdout),
                "rwlock contention order is not byte-identical across runs at seed {seed}"
            );
        }
        outputs.insert(baseline);
    }
    // The acquisition order is scheduler-controlled, so it must actually vary
    // across seeds — a fixed order would mean the schedule isn't seed-driven.
    assert!(
        outputs.len() >= 2,
        "rwlock acquisition order did not vary across seeds: {outputs:?}"
    );

    let trace = directory.path().join("rwlock.patina");
    let recorded = invoke_in(
        workspace,
        &[
            "native-run",
            bin.to_str().unwrap(),
            "--seed",
            "3",
            "--record",
            trace.to_str().unwrap(),
            "--fingerprint",
            "rwlock-contention",
        ],
    );
    let replayed = invoke_in(
        workspace,
        &[
            "native-run",
            bin.to_str().unwrap(),
            "--replay",
            trace.to_str().unwrap(),
            "--fingerprint",
            "rwlock-contention",
        ],
    );
    assert_eq!(
        String::from_utf8_lossy(&recorded.stdout),
        String::from_utf8_lossy(&replayed.stdout),
        "rwlock record and strict replay diverged"
    );
}

// Two threads incrementing a shared counter through the atomics-only
// `std::sync::RwLock` fast path — the buggy-smoke `lost-update` shape. Reads no
// argv/env, so it audits clean without `--allow-unsupported-symbols`.
const YIELD_POINTS_SOURCE: &str = r#"
use std::sync::{Arc, RwLock};
use std::thread;

fn main() {
    let cell = Arc::new(RwLock::new(0u64));
    let handles: Vec<_> = (0..2)
        .map(|_| {
            let cell = Arc::clone(&cell);
            thread::spawn(move || {
                for _ in 0..50 {
                    let current = *cell.read().unwrap();
                    *cell.write().unwrap() = current + 1;
                }
            })
        })
        .collect();
    for handle in handles {
        handle.join().unwrap();
    }
    println!("YP_RESULT total={}", *cell.read().unwrap());
}
"#;

// A `--yield-points` binary schedules under a denser policy than a plain build,
// so their traces are different guests. `native-run` folds the yield-point
// marker into the compatibility fingerprint, so a trace recorded from an
// instrumented binary must fail closed when replayed against a plain one (and
// the reverse), never produce a silently different run. The instrumented binary
// replays its own trace exactly.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_yield_points_trace_fails_closed_against_plain_binary() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("yp.rs");
    fs::write(&source, YIELD_POINTS_SOURCE).unwrap();
    let workspace = native_workspace();
    let plain = directory.path().join("plain");
    let instrumented = directory.path().join("instrumented");
    invoke_in(
        workspace,
        &[
            "native-build",
            source.to_str().unwrap(),
            "--output",
            plain.to_str().unwrap(),
        ],
    );
    invoke_in(
        workspace,
        &[
            "native-build",
            source.to_str().unwrap(),
            "--output",
            instrumented.to_str().unwrap(),
            "--yield-points",
        ],
    );

    let yp_trace = directory.path().join("yp.patina");
    invoke_in(
        workspace,
        &[
            "native-run",
            instrumented.to_str().unwrap(),
            "--seed",
            "3",
            "--record",
            yp_trace.to_str().unwrap(),
        ],
    );

    // The instrumented binary replays its own trace exactly.
    let self_replay = invoke_in(
        workspace,
        &[
            "native-run",
            instrumented.to_str().unwrap(),
            "--replay",
            yp_trace.to_str().unwrap(),
        ],
    );
    assert!(
        self_replay.status.success(),
        "an instrumented binary must replay its own yield-points trace"
    );

    // The plain binary must refuse the yield-points trace: the fingerprint suffix
    // makes the policies incompatible, so replay fails closed rather than running
    // a silently different schedule.
    let rejected = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &[
            "native-run",
            plain.to_str().unwrap(),
            "--replay",
            yp_trace.to_str().unwrap(),
        ],
    );
    let rejected_stderr = String::from_utf8_lossy(&rejected.stderr);
    assert!(
        !rejected.status.success(),
        "a yield-points trace must not replay against a plain binary; got success\nstdout:\n{}\nstderr:\n{rejected_stderr}",
        String::from_utf8_lossy(&rejected.stdout),
    );
    // Fail-closed, but say WHY: the shim surfaces the runtime's fingerprint
    // mismatch instead of the generic "no runtime installed" abort.
    assert!(
        rejected_stderr.contains("failed to initialize")
            && rejected_stderr.contains("fingerprint mismatch"),
        "cross-replay rejection must name the fingerprint mismatch:\nstderr:\n{rejected_stderr}"
    );

    // And the reverse: a plain trace must not replay against the instrumented
    // binary.
    let plain_trace = directory.path().join("plain.patina");
    invoke_in(
        workspace,
        &[
            "native-run",
            plain.to_str().unwrap(),
            "--seed",
            "3",
            "--record",
            plain_trace.to_str().unwrap(),
        ],
    );
    let rejected_reverse = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &[
            "native-run",
            instrumented.to_str().unwrap(),
            "--replay",
            plain_trace.to_str().unwrap(),
        ],
    );
    let rejected_reverse_stderr = String::from_utf8_lossy(&rejected_reverse.stderr);
    assert!(
        !rejected_reverse.status.success(),
        "a plain trace must not replay against a yield-points binary:\nstderr:\n{rejected_reverse_stderr}"
    );
    assert!(
        rejected_reverse_stderr.contains("failed to initialize")
            && rejected_reverse_stderr.contains("fingerprint mismatch"),
        "reverse cross-replay rejection must name the fingerprint mismatch:\nstderr:\n{rejected_reverse_stderr}"
    );
}

// A worker that uses `mpsc::recv_timeout` initializes a thread-local `Thread`
// handle whose destructor runs at pthread exit. Under `--yield-points` that
// destructor is instrumented std code monomorphized into the guest crate, so it
// runs the yield hook AFTER `thread_finish` completed the task — the regression
// that aborted with "scheduler task 2 does not exist" on the raft harness. The
// program itself is trivial and must run to completion, deterministically.
const YIELD_TEARDOWN_SOURCE: &str = r#"
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

fn main() {
    let handle = thread::spawn(|| {
        let (_tx, rx) = mpsc::channel::<u8>();
        let _ = rx.recv_timeout(Duration::from_millis(5));
    });
    handle.join().unwrap();
    println!("TEARDOWN_ok");
}
"#;

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_yield_points_survive_thread_local_teardown() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("teardown.rs");
    fs::write(&source, YIELD_TEARDOWN_SOURCE).unwrap();
    let workspace = native_workspace();
    let bin = directory.path().join("teardown");
    invoke_in(
        workspace,
        &[
            "native-build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
            "--yield-points",
        ],
    );

    // Before the fix this aborted at thread exit; it must now run to completion.
    let first = invoke_in(
        workspace,
        &["native-run", bin.to_str().unwrap(), "--seed", "1"],
    );
    let baseline = String::from_utf8_lossy(&first.stdout).into_owned();
    assert!(
        baseline.contains("TEARDOWN_ok"),
        "yield-points teardown run did not complete: {baseline}\nstderr:\n{}",
        String::from_utf8_lossy(&first.stderr)
    );

    // Deterministic across repeats and exactly replayable.
    for _ in 0..2 {
        let again = invoke_in(
            workspace,
            &["native-run", bin.to_str().unwrap(), "--seed", "1"],
        );
        assert_eq!(
            baseline,
            String::from_utf8_lossy(&again.stdout),
            "yield-points teardown output is not byte-identical across runs"
        );
    }
    let trace = directory.path().join("teardown.patina");
    invoke_in(
        workspace,
        &[
            "native-run",
            bin.to_str().unwrap(),
            "--seed",
            "1",
            "--record",
            trace.to_str().unwrap(),
        ],
    );
    let replayed = invoke_in(
        workspace,
        &[
            "native-run",
            bin.to_str().unwrap(),
            "--replay",
            trace.to_str().unwrap(),
        ],
    );
    assert!(
        String::from_utf8_lossy(&replayed.stdout).contains("TEARDOWN_ok"),
        "replay of the yield-points teardown trace did not complete"
    );
}

// One uninterposed symbol per escape class in a single guest. Taking each as a
// pointer forces the undefined import, so the pre-run gate must refuse the whole
// binary before it runs. This is the gate-level per-class proof: if any class's
// end-to-end detection path rots (a symbol dropped from the deny lists, or the
// gate stops enumerating it), the corresponding label vanishes and the test
// fails. Two classes have no plantable member here and are covered elsewhere:
// `environment` (getenv/setenv/... are all interposed, so no shim-linked binary
// can import an uninterposed one) and `unmanaged-thread` (pthread_create is
// interposed; the C `escape_probe` in validate-native-shim.sh imports it and
// native-audit rejects it as `unmanaged-thread`).
//
// The `process` representative is `kill`, deliberately NOT a spawn-family symbol
// (`fork`/`posix_spawn*`/`waitpid`/...): those are now shim-*defined* deny-traps
// (they abort deterministically if reached), so they no longer appear as imports
// and could not exercise the gate. `kill` stays uninterposed — the process class
// is a deterministic-runtime non-goal — so it remains an undefined import the
// gate must flag as `process`.
#[cfg(target_os = "macos")]
const ESCAPE_CLASSES_SOURCE: &str = r#"
unsafe extern "C" {
    fn link(a: *const u8, b: *const u8) -> i32;
    fn gethostbyname(name: *const u8) -> *mut u8;
    fn select(n: i32, r: *mut u8, w: *mut u8, e: *mut u8, t: *mut u8) -> i32;
    fn os_unfair_lock_lock(lock: *mut u8);
    fn time(t: *mut i64) -> i64;
    fn arc4random() -> u32;
    fn kill(pid: i32, sig: i32) -> i32;
    fn dlopen(path: *const u8, mode: i32) -> *mut u8;
    fn shm_open(name: *const u8, oflag: i32) -> i32;
    fn setitimer(which: i32, nv: *const u8, ov: *mut u8) -> i32;
    fn syscall(number: i64) -> i64;
}
fn main() {
    let ptrs: &[*const ()] = &[
        link as *const (), gethostbyname as *const (), select as *const (),
        os_unfair_lock_lock as *const (), time as *const (), arc4random as *const (),
        kill as *const (), dlopen as *const (), shm_open as *const (),
        setitimer as *const (), syscall as *const (),
    ];
    let mut acc = 0usize;
    for p in ptrs { acc ^= *p as usize; }
    std::process::exit((acc & 1) as i32);
}
"#;

// Gate-level per-class detection: native-run refuses a guest reaching one
// uninterposed symbol of each class, naming every class. Demonstrably able to
// fail — it depends on the run being refused with each label present.
#[cfg(target_os = "macos")]
#[test]
fn native_run_prerun_gate_refuses_every_escape_class() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("escape_classes.rs");
    fs::write(&source, ESCAPE_CLASSES_SOURCE).unwrap();
    let workspace = native_workspace();
    let bin = directory.path().join("escape-classes");
    invoke_in(
        workspace,
        &[
            "native-build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );

    let refused = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &["native-run", bin.to_str().unwrap(), "--seed", "1"],
    );
    assert!(
        !refused.status.success(),
        "the gate must refuse a guest reaching uninterposed escape-class symbols"
    );
    let stderr = String::from_utf8_lossy(&refused.stderr);
    for class in [
        "(filesystem)",
        "(network)",
        "(wait-multiplex)",
        "(unmanaged-sync)",
        "(time)",
        "(entropy)",
        "(process)",
        "(dynamic-loading)",
        "(shared-memory-ipc)",
        "(signals-timers)",
        "(direct-syscall)",
    ] {
        assert!(
            stderr.contains(class),
            "the gate denial must name the {class} class:\n{stderr}"
        );
    }
    assert!(
        !String::from_utf8_lossy(&refused.stdout).contains("escape"),
        "the guest must not run"
    );
}

// A planted escape: a program that reaches an uninterposed blocking primitive
// (`os_unfair_lock`, in the `unmanaged-sync` class) directly. Uncontended the
// lock returns without a syscall, so the guest runs, but the calls are host
// operations the deterministic runtime does not model — exactly the escape
// class the pre-run gate exists to catch.
#[cfg(target_os = "macos")]
const PLANTED_ESCAPE_SOURCE: &str = r#"
#[repr(C)]
struct OsUnfairLock(u32);
unsafe extern "C" {
    fn os_unfair_lock_lock(lock: *mut OsUnfairLock);
    fn os_unfair_lock_unlock(lock: *mut OsUnfairLock);
}
fn main() {
    let mut lock = OsUnfairLock(0);
    unsafe {
        os_unfair_lock_lock(&mut lock);
        os_unfair_lock_unlock(&mut lock);
    }
    println!("planted escape ran");
}
"#;

// Part B: the pre-run default-deny gate refuses to run a binary reaching an
// uninterposed blocking symbol (naming and categorizing it), the escape hatch
// downgrades it to a loud warning and runs, and a partial allow list still fails
// closed on the remaining symbol. This gate is demonstrably able to fail: the
// first assertion depends on the run being rejected.
#[cfg(target_os = "macos")]
#[test]
fn native_run_prerun_gate_blocks_and_flags_uninterposed_blocking_symbol() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("planted_escape.rs");
    fs::write(&source, PLANTED_ESCAPE_SOURCE).unwrap();
    let workspace = native_workspace();
    let bin = directory.path().join("planted-escape");
    invoke_in(
        workspace,
        &[
            "native-build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );
    let exe = env!("CARGO_BIN_EXE_cargo-patina");

    // (1) Default-deny: refuses to run, names and categorizes the symbols, and
    // the guest never executes.
    let denied = invoke_unchecked(
        exe,
        workspace,
        &["native-run", bin.to_str().unwrap(), "--seed", "1"],
    );
    assert!(
        !denied.status.success(),
        "the pre-run gate must refuse the planted escape"
    );
    let denied_err = String::from_utf8_lossy(&denied.stderr);
    assert!(
        denied_err.contains("os_unfair_lock_lock") && denied_err.contains("unmanaged-sync"),
        "denial must name and categorize the symbol:\n{denied_err}"
    );
    assert!(
        !String::from_utf8_lossy(&denied.stdout).contains("planted escape ran"),
        "the guest must not run when the gate denies it"
    );

    // (2) Escape hatch: downgrades to a prominent warning and runs.
    let allowed = invoke_unchecked(
        exe,
        workspace,
        &[
            "native-run",
            bin.to_str().unwrap(),
            "--seed",
            "1",
            "--allow-unsupported-symbols",
            "all",
        ],
    );
    assert!(
        allowed.status.success(),
        "the escape hatch must let the guest run:\n{}",
        String::from_utf8_lossy(&allowed.stderr)
    );
    assert!(
        String::from_utf8_lossy(&allowed.stdout).contains("planted escape ran"),
        "the guest must run under the escape hatch"
    );
    assert!(
        String::from_utf8_lossy(&allowed.stderr).contains("WARNING"),
        "the escape hatch must warn prominently"
    );

    // (3) A partial allow list still fails closed on the un-allowed symbol.
    let partial = invoke_unchecked(
        exe,
        workspace,
        &[
            "native-run",
            bin.to_str().unwrap(),
            "--seed",
            "1",
            "--allow-unsupported-symbols",
            "os_unfair_lock_lock",
        ],
    );
    assert!(
        !partial.status.success(),
        "a partial allow list must still fail closed"
    );
    assert!(
        String::from_utf8_lossy(&partial.stderr).contains("os_unfair_lock_unlock"),
        "the remaining un-allowed symbol must be named"
    );
}

// A guest that actually CALLS a process-spawn symbol under Patina. Once the shim
// deny-trap stubs (task #15 shim portion) land, `fork` is shim-*defined* — so the
// pre-run audit passes (it is no longer an import), the guest runs, and the call
// aborts deterministically with the deny-trap diagnostic. This is the can-fail
// proof for the deny-trap disposition: distinct from the pre-run gate (which
// refuses a guest that merely *imports* an uninterposed spawn symbol), this
// asserts the *runtime* guard fires for a guest that reaches one.
#[cfg(target_os = "macos")]
const PLANTED_SPAWN_SOURCE: &str = r#"
unsafe extern "C" {
    fn fork() -> i32;
}
fn main() {
    println!("before spawn");
    unsafe {
        fork();
    }
    println!("after spawn");
}
"#;

// `fork` is now shim-defined (a deny-trap in `c/patina_posix.c`), so the pre-run
// gate passes this binary (fork is no longer an import) and the runtime deny-trap
// is what fires when the guest reaches fork — the distinct guarantee this proves.
#[cfg(target_os = "macos")]
#[test]
fn native_run_deny_trap_aborts_a_guest_that_actually_spawns() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("planted_spawn.rs");
    fs::write(&source, PLANTED_SPAWN_SOURCE).unwrap();
    let workspace = native_workspace();
    let bin = directory.path().join("planted-spawn");
    invoke_in(
        workspace,
        &[
            "native-build",
            source.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );

    let ran = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &["native-run", bin.to_str().unwrap(), "--seed", "1"],
    );
    // The audit passes (fork is shim-defined, not an import), the guest starts,
    // and the fork() call aborts deterministically.
    assert!(
        !ran.status.success(),
        "a guest that reaches fork must abort under the deny-trap"
    );
    let stderr = String::from_utf8_lossy(&ran.stderr);
    assert!(
        stderr.contains("process spawn reached under patina: fork"),
        "the deny-trap must name the reached spawn symbol:\n{stderr}"
    );
    let stdout = String::from_utf8_lossy(&ran.stdout);
    assert!(
        stdout.contains("before spawn"),
        "the guest must run up to the spawn attempt"
    );
    assert!(
        !stdout.contains("after spawn"),
        "the guest must not continue past the deny-trap"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn invoke_in(directory: &Path, arguments: &[&str]) -> Output {
    invoke_with(env!("CARGO_BIN_EXE_cargo-patina"), directory, arguments)
}

// Schedule reduction end to end: record a three-task run whose failure depends
// on the interleaving (task b runs before task a completes), then minimize it
// with a replay oracle. The oracle accepts a candidate only when the replayed
// program itself exits with the failure's exact code and marker, so a candidate
// whose rewritten schedule merely breaks replay is rejected rather than
// mistaken for the failure. The minimized trace must still replay to the same
// failure with no more context switches than the original.
#[cfg(unix)]
#[test]
fn minimize_canonicalizes_a_recorded_schedule_via_replay_oracle() {
    let directory = tempdir().unwrap();
    let fixture = directory.path().join("fixture");
    create_schedule_fixture(&fixture);

    let trace = directory.path().join("sched.patina");
    let mut original = None;
    for seed in 0..32u64 {
        let seed_string = seed.to_string();
        let recorded = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            &fixture,
            &[
                "run",
                "--seed",
                &seed_string,
                "--record",
                trace.to_str().unwrap(),
            ],
        );
        if recorded.status.code() == Some(3) {
            original = Some(schedule_line(&recorded));
            break;
        }
    }
    let original = original.expect("no seed in 0..32 interleaved b before a completed");
    assert!(original.contains("interleaved=true"));
    let original_switches = switch_count(&original);

    let oracle = directory.path().join("oracle.sh");
    fs::write(
        &oracle,
        format!(
            "#!/bin/sh\nout=$(\"{}\" run --replay \"$PATINA_MINIMIZE_TRACE\" 2>/dev/null)\ncode=$?\nif [ \"$code\" -eq 3 ] && printf '%s' \"$out\" | grep -q 'interleaved=true'; then\n  exit 1\nfi\nexit 0\n",
            env!("CARGO_BIN_EXE_cargo-patina")
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&oracle, fs::Permissions::from_mode(0o755)).unwrap();
    }

    let minimized_path = directory.path().join("sched-min.patina");
    let minimized = invoke(
        &fixture,
        &[
            "minimize",
            trace.to_str().unwrap(),
            "--output",
            minimized_path.to_str().unwrap(),
            "--",
            oracle.to_str().unwrap(),
        ],
    );
    assert!(
        String::from_utf8_lossy(&minimized.stdout).contains("PATINA_MINIMIZE_COMPLETE"),
        "missing completion line:\n{}",
        String::from_utf8_lossy(&minimized.stdout)
    );

    let replayed = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        &fixture,
        &["run", "--replay", minimized_path.to_str().unwrap()],
    );
    assert_eq!(
        replayed.status.code(),
        Some(3),
        "minimized trace no longer reproduces the failure:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&replayed.stdout),
        String::from_utf8_lossy(&replayed.stderr)
    );
    let reduced = schedule_line(&replayed);
    assert!(reduced.contains("interleaved=true"));
    assert!(
        switch_count(&reduced) <= original_switches,
        "schedule reduction increased context switches: {original} -> {reduced}"
    );
}

#[cfg(unix)]
fn schedule_line(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find(|line| line.starts_with("PATINA_SCHED_RESULT"))
        .unwrap_or_else(|| {
            panic!(
                "missing PATINA_SCHED_RESULT in stdout:\n{}",
                String::from_utf8_lossy(&output.stdout)
            )
        })
        .to_owned()
}

#[cfg(unix)]
fn switch_count(line: &str) -> u64 {
    line.split("switches=")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| panic!("missing switches= in {line}"))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn package_result(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find(|line| line.starts_with("NATIVE_PKG_RESULT"))
        .unwrap_or_else(|| {
            panic!(
                "missing NATIVE_PKG_RESULT in stdout:\n{}",
                String::from_utf8_lossy(&output.stdout)
            )
        })
        .to_owned()
}

fn invoke_with(executable: &str, fixture: &Path, arguments: &[&str]) -> Output {
    let output = invoke_unchecked(executable, fixture, arguments);
    assert!(
        output.status.success(),
        "command failed with {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn invoke_unchecked(executable: &str, fixture: &Path, arguments: &[&str]) -> Output {
    Command::new(executable)
        .current_dir(fixture)
        .args(arguments)
        .output()
        .unwrap()
}

fn result_line(output: &Output) -> String {
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

// Build a self-contained fixture: an ordinary-`std` package with a path
// dependency (`greeter`), a build script (whose output the binary reads back,
// and whose host-side file I/O proves the shim link args do not leak onto build
// scripts), a clean binary that audits and replays, and a second binary that
// imports an off-allowlist process symbol.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn create_package_fixture(root: &Path) {
    let greeter = root.join("greeter");
    fs::create_dir_all(greeter.join("src")).unwrap();
    fs::write(
        greeter.join("Cargo.toml"),
        "[package]\nname = \"greeter\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    fs::write(
        greeter.join("src/lib.rs"),
        "pub fn greeting() -> String {\n    format!(\"hello from {}\", \"greeter\")\n}\n",
    )
    .unwrap();

    let package = root.join("pkg");
    fs::create_dir_all(package.join("src/bin")).unwrap();
    fs::write(
        package.join("Cargo.toml"),
        "[package]\nname = \"patina-native-pkg-fixture\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[dependencies]\ngreeter = { path = \"../greeter\" }\n",
    )
    .unwrap();
    fs::write(
        package.join("build.rs"),
        r#"fn main() {
    // Runs on the host. If the shim link args leaked onto this build script, its
    // file I/O would route into an uninitialized Patina runtime and abort; the
    // explicit host --target keeps them off host artifacts.
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    std::fs::read(std::path::Path::new(&manifest).join("Cargo.toml")).unwrap();
    println!("cargo:rustc-env=PKG_BUILT=1");
    println!("cargo:rerun-if-changed=build.rs");
}
"#,
    )
    .unwrap();
    fs::write(
        package.join("src/main.rs"),
        r#"use std::hash::{BuildHasher, Hasher};

fn main() {
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write(greeter::greeting().as_bytes());
    let hash = hasher.finish();
    std::fs::create_dir("/state").unwrap();
    std::fs::write("/state/value", greeter::greeting().as_bytes()).unwrap();
    let stored = std::fs::read_to_string("/state/value").unwrap();
    std::fs::remove_file("/state/value").unwrap();
    std::fs::remove_dir("/state").unwrap();
    println!(
        "NATIVE_PKG_RESULT built={} hash={hash:016x} stored={stored}",
        env!("PKG_BUILT")
    );
}
"#,
    )
    .unwrap();
    fs::write(
        package.join("src/bin/leaky.rs"),
        r#"// Imports an uninterposed process-class libc symbol (`kill`) that the native
// audit denies as "process". The spawn family (fork/posix_spawn*/waitpid/...) is
// now shim-defined (deny-traps), so a `Command::spawn` would leave no process
// *import* to flag; this reaches for a still-uninterposed member of the class
// instead. Taking its address forces the undefined import. Building succeeds; the
// audit must reject the product with the "process" category.
unsafe extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}
fn main() {
    let reached = kill as *const ();
    std::process::exit((reached as usize & 1) as i32);
}
"#,
    )
    .unwrap();
}

// A fixture that drives the explicit scheduler API: three tasks of four rounds
// each, selected by recorded `SchedulerNext` decisions. The schedule-dependent
// failure — task b selected before task a has completed — exits the process
// with code 3 so a replay oracle can demand the exact failure rather than any
// nonzero exit.
#[cfg(unix)]
fn create_schedule_fixture(path: &Path) {
    fs::create_dir_all(path.join("src")).unwrap();
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let patina_path = workspace.join("crates/patina");
    let patina_path = patina_path.to_string_lossy().replace('\\', "\\\\");
    fs::write(
        path.join("Cargo.toml"),
        format!(
            "[package]\nname = \"patina-sched-fixture\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[dependencies]\npatina = {{ path = \"{patina_path}\", features = [\"runtime\"] }}\n"
        ),
    )
    .unwrap();
    fs::write(
        path.join("src/main.rs"),
        r#"use std::collections::BTreeMap;

use patina::RuntimeError;

fn scenario() -> Result<(String, bool), RuntimeError> {
    patina::run(|context| {
        let a = context.task_spawn("a")?;
        let b = context.task_spawn("b")?;
        let c = context.task_spawn("c")?;
        let mut remaining = BTreeMap::from([(a, 4_u32), (b, 4), (c, 4)]);
        let mut order = Vec::new();
        let mut interleaved = false;
        while let Some(task) = context.scheduler_next()? {
            order.push(task.0);
            if task == b && remaining.contains_key(&a) {
                interleaved = true;
            }
            let rounds = remaining.get_mut(&task).expect("selected task is live");
            *rounds -= 1;
            if *rounds == 0 {
                remaining.remove(&task);
                context.task_complete(task)?;
            } else {
                context.task_yield(task)?;
            }
        }
        let switches = order.windows(2).filter(|pair| pair[0] != pair[1]).count();
        let line = format!(
            "PATINA_SCHED_RESULT seed={} order={order:?} switches={switches} interleaved={interleaved}",
            context.root_seed()
        );
        Ok((line, interleaved))
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (line, interleaved) = scenario()?;
    println!("{line}");
    if interleaved {
        std::process::exit(3);
    }
    Ok(())
}
"#,
    )
    .unwrap();
}

fn create_fixture(path: &Path) {
    fs::create_dir_all(path.join("src")).unwrap();
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let patina_path = workspace.join("crates/patina");
    let patina_path = patina_path.to_string_lossy().replace('\\', "\\\\");
    fs::write(
        path.join("Cargo.toml"),
        format!(
            "[package]\nname = \"patina-e2e-fixture\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[dependencies]\npatina = {{ path = \"{patina_path}\", features = [\"runtime\"] }}\n"
        ),
    )
    .unwrap();
    fs::write(
        path.join("src/main.rs"),
        r#"use patina::{ClockKind, RuntimeError};

fn scenario() -> Result<String, RuntimeError> {
    patina::run(|context| {
        let prefix = context.entropy_bytes(8)?;
        let suffix = context.entropy_bytes(8)?;
        context.write_file("/state/value", &suffix)?;
        context.sleep_for(10)?;
        let stored = context.read_file("/state/value")?;
        let time = context.now(ClockKind::Monotonic)?;
        Ok(format!("PATINA_RESULT seed={} prefix={prefix:?} suffix={stored:?} time={time} zone={:?} cfg={}", context.root_seed(), context.param("zone"), cfg!(all(patina, dst))))
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
fn write_sdk_fixture(root: &Path, main: &str) {
    fs::create_dir_all(root.join("src")).unwrap();
    let patina_path = native_workspace().join("crates/patina");
    let patina_path = patina_path.to_string_lossy().replace('\\', "\\\\");
    fs::write(
        root.join("Cargo.toml"),
        format!(
            "[package]\nname = \"buggify-sdk-fixture\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[dependencies]\npatina = {{ path = \"{patina_path}\" }}\n"
        ),
    )
    .unwrap();
    fs::write(root.join("src/main.rs"), main).unwrap();
}

// A guest whose buggify sites all activate and always fire under
// `--buggify=1000 --buggify-activation-permille 1000`, so the outcome is
// deterministic without hunting for a firing seed.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const BUGGIFY_SDK_MAIN: &str = r#"
fn main() {
    patina::lifecycle::setup_complete();
    let mut fired = 0u32;
    let knob = patina::buggify_knob!("batch", 10_i64, 1, 100);
    for i in 0..8 {
        patina::reachable!("loop-body");
        if patina::buggify!("early-return") {
            fired += 1;
        }
        patina::sometimes!(i == 3, "index-is-three");
    }
    patina::always!(fired <= 8, "fired-in-bounds");
    println!("RESULT knob={knob} fired={fired} rng={}", patina::rng());
}
"#;

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_buggify_sdk_reports_records_and_replays() {
    let directory = tempdir().unwrap();
    let pkg = directory.path().join("pkg");
    write_sdk_fixture(&pkg, BUGGIFY_SDK_MAIN);
    let workspace = native_workspace();
    let bin = directory.path().join("buggify-sdk");
    invoke_in(
        workspace,
        &[
            "native-build",
            pkg.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );

    // Seeded run with every site active and always firing.
    let flags = ["--buggify=1000", "--buggify-activation-permille", "1000"];
    let seeded = invoke_in(
        workspace,
        &[
            &["native-run", bin.to_str().unwrap(), "--seed", "4"][..],
            &flags[..],
        ]
        .concat(),
    );
    let stdout = String::from_utf8_lossy(&seeded.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&seeded.stderr).into_owned();
    assert!(
        stdout.contains("fired=8"),
        "all sites should fire: {stdout}"
    );
    assert!(
        stderr.contains("PATINA_SDK_REPORT enabled=1"),
        "expected SDK report: {stderr}"
    );
    assert!(
        stderr.contains("total_firings=") && !stderr.contains("total_firings=0"),
        "expected nonzero firings: {stderr}"
    );

    // Record, then replay WITHOUT re-supplying --buggify: byte-identical stdout.
    let trace = directory.path().join("buggify.patina");
    let recorded = invoke_in(
        workspace,
        &[
            &["native-run", bin.to_str().unwrap(), "--seed", "4"][..],
            &flags[..],
            &["--record", trace.to_str().unwrap()][..],
        ]
        .concat(),
    );
    let replayed = invoke_in(
        workspace,
        &[
            "native-run",
            bin.to_str().unwrap(),
            "--replay",
            trace.to_str().unwrap(),
        ],
    );
    assert_eq!(
        String::from_utf8_lossy(&recorded.stdout),
        String::from_utf8_lossy(&replayed.stdout),
        "record/replay stdout diverged"
    );
}

// A guest that reuses the same label at two different call sites: a fatal
// duplicate, aborting with the marker.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const BUGGIFY_DUP_MAIN: &str = r#"
fn main() {
    let _ = patina::buggify!("same-label");
    let _ = patina::buggify!("same-label");
    println!("unreachable");
}
"#;

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_buggify_duplicate_label_aborts_with_marker() {
    let directory = tempdir().unwrap();
    let pkg = directory.path().join("dup");
    write_sdk_fixture(&pkg, BUGGIFY_DUP_MAIN);
    let workspace = native_workspace();
    let bin = directory.path().join("buggify-dup");
    invoke_in(
        workspace,
        &[
            "native-build",
            pkg.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );
    let output = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &["native-run", bin.to_str().unwrap(), "--seed", "1"],
    );
    assert!(!output.status.success(), "duplicate label must abort");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("PATINA_BUGGIFY_DUPLICATE_LABEL label=same-label"),
        "expected duplicate-label marker: {stderr}"
    );
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("unreachable"),
        "guest ran past the duplicate label"
    );
}

// A guest that never calls setup_complete; under --buggify-after-setup this is a
// declared-but-never-called harness bug that must fail loudly.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const BUGGIFY_NO_SETUP_MAIN: &str = r#"
fn main() {
    for _ in 0..5 {
        let _ = patina::buggify!("gated");
    }
    println!("guest-finished");
}
"#;

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_buggify_after_setup_never_called_fails_loudly() {
    let directory = tempdir().unwrap();
    let pkg = directory.path().join("nosetup");
    write_sdk_fixture(&pkg, BUGGIFY_NO_SETUP_MAIN);
    let workspace = native_workspace();
    let bin = directory.path().join("buggify-nosetup");
    invoke_in(
        workspace,
        &[
            "native-build",
            pkg.to_str().unwrap(),
            "--output",
            bin.to_str().unwrap(),
        ],
    );

    // With the gate declared but never reached: fatal marker + nonzero exit,
    // even though buggify itself injected no fault.
    let gated = invoke_unchecked(
        env!("CARGO_BIN_EXE_cargo-patina"),
        workspace,
        &[
            "native-run",
            bin.to_str().unwrap(),
            "--seed",
            "1",
            "--buggify",
            "--buggify-after-setup",
        ],
    );
    assert!(
        !gated.status.success(),
        "declared-but-never-called must fail"
    );
    assert!(
        String::from_utf8_lossy(&gated.stderr).contains("PATINA_BUGGIFY_SETUP_NEVER_CALLED"),
        "expected never-called marker: {}",
        String::from_utf8_lossy(&gated.stderr)
    );

    // Same guest WITHOUT the gate declaration runs clean.
    let plain = invoke_in(
        workspace,
        &[
            "native-run",
            bin.to_str().unwrap(),
            "--seed",
            "1",
            "--buggify",
        ],
    );
    assert!(
        String::from_utf8_lossy(&plain.stdout).contains("guest-finished"),
        "ungated run should finish cleanly"
    );
}
