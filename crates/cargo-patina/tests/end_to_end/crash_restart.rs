//! Native filesystem crash/restart, torn images, and namespace durability.

#[cfg(test)]
mod tests {
    use super::super::*;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const NATIVE_CRASH_RESTART_CANARY_SOURCE: &str = r#"
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::process;

extern "C" fn incarnation0_atexit() {
    println!("CANARY atexit0_should_not_run");
}

unsafe extern "C" {
    fn read(fd: i32, buf: *mut core::ffi::c_void, count: usize) -> isize;
    fn atexit(cb: extern "C" fn()) -> i32;
}

fn read_file(path: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    File::open(path).unwrap().read_to_end(&mut bytes).unwrap();
    bytes
}

fn main() {
    let pid = process::id();
    if let Ok(first) = File::open("/pid0") {
        use std::os::fd::AsRawFd;
        println!("CANARY restart_first_fd={}", first.as_raw_fd());
        drop(first);
        let pid0 = String::from_utf8(read_file("/pid0")).unwrap();
        println!("CANARY incarnation=1 pid0={pid0} pid1={pid}");
        println!("CANARY A={:?}", String::from_utf8_lossy(&read_file("/a")));
        println!("CANARY B={:?}", String::from_utf8_lossy(&read_file("/b")));
        let mut stale = File::open("/stale").unwrap();
        let raw: i32 = String::from_utf8(read_file("/fd")).unwrap().parse().unwrap();
        let mut buf = [0_u8; 1];
        let stale_result = unsafe { read(raw, buf.as_mut_ptr().cast(), 1) };
        println!("CANARY stale_fd_result={stale_result}");
        let fresh = File::open("/a").unwrap();
        println!("CANARY later_fresh_fd={}", fresh.as_raw_fd());
        stale.seek(SeekFrom::Start(0)).unwrap();
        return;
    }

    unsafe { atexit(incarnation0_atexit); }
    let mut pid_file = OpenOptions::new().create(true).truncate(true).write(true).open("/pid0").unwrap();
    write!(pid_file, "{pid}").unwrap();
    pid_file.sync_all().unwrap();
    File::open("/").unwrap().sync_all().unwrap();

    let mut a = OpenOptions::new().create(true).truncate(true).read(true).write(true).open("/a").unwrap();
    a.write_all(b"A-synced").unwrap();
    a.sync_all().unwrap();
    File::open("/").unwrap().sync_all().unwrap();
    use std::os::fd::AsRawFd;
    let mut fd_file = OpenOptions::new().create(true).truncate(true).write(true).open("/fd").unwrap();
    write!(fd_file, "{}", a.as_raw_fd()).unwrap();
    fd_file.sync_all().unwrap();
    let mut stale = OpenOptions::new().create(true).truncate(true).write(true).open("/stale").unwrap();
    stale.write_all(b"held").unwrap();
    stale.sync_all().unwrap();
    File::open("/").unwrap().sync_all().unwrap();

    let mut b = OpenOptions::new().create(true).truncate(true).write(true).open("/b").unwrap();
    b.write_all(b"B-stable!!").unwrap();
    b.sync_all().unwrap();
    File::open("/").unwrap().sync_all().unwrap();
    b.seek(SeekFrom::Start(0)).unwrap();
    println!("CANARY before_trigger pid={pid}");
    b.write_all(b"B-volatile").unwrap();
    println!("CANARY after_trigger_should_not_print");
}
"#;

    /// Build the crash-restart canary into `directory`.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn build_crash_restart_canary(directory: &Path) -> PathBuf {
        let source = directory.join("crash_restart.rs");
        fs::write(&source, NATIVE_CRASH_RESTART_CANARY_SOURCE).unwrap();
        let bin = directory.join("crash_restart");
        invoke(
            native_workspace(),
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );
        bin
    }

    /// The canary's crash selector: the unsynced overwrite of `/b`, its sixth write.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const CANARY_CRASH_SELECTOR: &str = "write:6";

    /// Record the canary's crash-restart run at seed 11 into `trace`.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn record_crash_restart_canary(bin: &Path, trace: &Path) -> Output {
        invoke(
            native_workspace(),
            &[
                "run",
                bin.to_str().unwrap(),
                "--seed",
                "11",
                "--fs-crash-at",
                CANARY_CRASH_SELECTOR,
                "--record",
                trace.to_str().unwrap(),
            ],
        )
    }

    /// The `operations=` count on a run's one `PATINA_FS_CRASH_RESTART` line: how
    /// many operations incarnation 0 completed before its crash.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn crash_restart_operations(stderr: &[u8]) -> String {
        let stderr = String::from_utf8_lossy(stderr);
        let lines: Vec<&str> = stderr
            .lines()
            .filter(|line| line.starts_with("PATINA_FS_CRASH_RESTART "))
            .collect();
        assert_eq!(lines.len(), 1, "expected one restart line:\n{stderr}");
        lines[0]
            .split(' ')
            .find_map(|field| field.strip_prefix("operations="))
            .unwrap_or_else(|| panic!("restart line carries no operations=: {}", lines[0]))
            .to_owned()
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_fs_crash_at_restarts_fresh_incarnation() {
        let directory = tempdir().unwrap();
        let workspace = native_workspace();
        let bin = build_crash_restart_canary(directory.path());
        let output = invoke(
            workspace,
            &[
                "run",
                bin.to_str().unwrap(),
                "--seed",
                "11",
                "--fs-crash-at",
                "write:6",
            ],
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stdout.contains("CANARY before_trigger"),
            "{stdout}\n{stderr}"
        );
        assert!(
            !stdout.contains("after_trigger_should_not_print"),
            "{stdout}"
        );
        assert!(!stdout.contains("atexit0_should_not_run"), "{stdout}");
        assert!(
            stdout.contains("CANARY incarnation=1"),
            "{stdout}\n{stderr}"
        );
        assert!(stdout.contains("CANARY A=\"A-synced\""), "{stdout}");
        assert!(stdout.contains("CANARY B=\"B-stable!!\""), "{stdout}");
        assert!(!stdout.contains("B-volatile"), "{stdout}");
        assert!(stdout.contains("CANARY stale_fd_result=-1"), "{stdout}");
        assert!(stdout.contains("CANARY restart_first_fd=3"), "{stdout}");
        assert!(
            stderr.matches("PATINA_FS_CRASH_RESTART").count() == 1,
            "{stderr}"
        );
        let json = invoke(
            workspace,
            &[
                "run",
                bin.to_str().unwrap(),
                "--seed",
                "11",
                "--fs-crash-at",
                "write:6",
                "--format",
                "json",
            ],
        );
        let envelope: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap_or_else(|error| {
        panic!(
            "native crash-restart --format json did not emit JSON: {error}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&json.stdout),
            String::from_utf8_lossy(&json.stderr)
        )
    });
        let crash = &envelope["crash_restart"];
        assert_eq!(crash["selector"]["op"], "write");
        assert_eq!(crash["selector"]["ordinal"], 6);
        assert_eq!(crash["reached"], true);
        assert_eq!(crash["crash_count"], 1);
        assert_eq!(crash["restart_count"], 1);
        assert_eq!(crash["incarnations"][0]["id"], 0);
        assert_eq!(crash["incarnations"][1]["id"], 1);
        assert_ne!(
            crash["incarnations"][0]["host_pid"],
            crash["incarnations"][1]["host_pid"]
        );
        assert!(
            crash["handoff_digest"]
                .as_str()
                .unwrap()
                .starts_with("sha256:")
        );
        assert!(
            crash["snapshot_digest"]
                .as_str()
                .unwrap()
                .starts_with("sha256:")
        );
        assert_eq!(crash["terminal_outcome"]["kind"], "completed_after_restart");
        let json_guest_stdout = envelope["stdout"].as_str().unwrap();
        assert!(json_guest_stdout.contains("CANARY incarnation=1"));
        assert!(!json_guest_stdout.contains("after_trigger_should_not_print"));
        assert!(!json_guest_stdout.contains("atexit0_should_not_run"));

        let unreached = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            workspace,
            &[
                "run",
                bin.to_str().unwrap(),
                "--seed",
                "11",
                "--fs-crash-at",
                "write:99",
            ],
        );
        assert!(
            !unreached.status.success(),
            "unreached selector unexpectedly passed"
        );
        assert!(
            String::from_utf8_lossy(&unreached.stderr)
                .contains("PATINA_FS_CRASH_SELECTOR_UNREACHED"),
            "{}",
            String::from_utf8_lossy(&unreached.stderr)
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_fs_crash_restart_record_replays_both_incarnations() {
        let directory = tempdir().unwrap();
        let bin = build_crash_restart_canary(directory.path());
        let trace = directory.path().join("crash-restart.patina");
        let recorded = record_crash_restart_canary(&bin, &trace);
        let replayed = invoke(
            native_workspace(),
            &["replay", bin.to_str().unwrap(), trace.to_str().unwrap()],
        );

        let recorded_stdout = String::from_utf8_lossy(&recorded.stdout);
        assert!(
            recorded_stdout.contains("CANARY incarnation=1"),
            "{recorded_stdout}"
        );
        assert_eq!(
            recorded_stdout,
            String::from_utf8_lossy(&replayed.stdout),
            "the replay's guest output differs from the recording's"
        );
        assert_eq!(
            crash_restart_operations(&recorded.stderr),
            crash_restart_operations(&replayed.stderr),
            "the replay crashed at a different point than the recording"
        );
        let bundle: serde_json::Value = serde_json::from_slice(&fs::read(&trace).unwrap()).unwrap();
        let lifecycle: Vec<&str> = bundle["timelines"][0]["lifecycle"]
            .as_array()
            .unwrap()
            .iter()
            .map(|marker| marker["kind"].as_str().unwrap())
            .collect();
        assert_eq!(lifecycle, ["start", "crash", "restart", "start", "end"]);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_fs_crash_restart_records_are_byte_identical() {
        let directory = tempdir().unwrap();
        let bin = build_crash_restart_canary(directory.path());
        let first = directory.path().join("first.patina");
        let second = directory.path().join("second.patina");
        record_crash_restart_canary(&bin, &first);
        record_crash_restart_canary(&bin, &second);
        assert!(
            fs::read(&first).unwrap() == fs::read(&second).unwrap(),
            "two records of one seeded crash-restart run produced different traces"
        );
    }

    /// Rewrite `trace` through `edit` into `tampered.patina` beside it. Traces are
    /// compact JSON, so an edit here is exactly a hand-altered artifact.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn tamper_trace(trace: &Path, edit: impl FnOnce(&mut serde_json::Value)) -> PathBuf {
        let mut bundle: serde_json::Value =
            serde_json::from_slice(&fs::read(trace).unwrap()).unwrap();
        edit(&mut bundle);
        let tampered = trace.with_file_name("tampered.patina");
        fs::write(&tampered, serde_json::to_vec(&bundle).unwrap()).unwrap();
        tampered
    }

    /// Replay `trace` against `bin`, expecting a named crash-replay divergence, and
    /// return the replay's stderr.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn replay_crash_divergence(bin: &Path, trace: &Path) -> String {
        let replayed = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            native_workspace(),
            &["replay", bin.to_str().unwrap(), trace.to_str().unwrap()],
        );
        let stderr = String::from_utf8_lossy(&replayed.stderr).into_owned();
        assert!(
            !replayed.status.success(),
            "the divergent trace replayed:\n{stderr}"
        );
        assert!(
            stderr.contains("PATINA_FS_CRASH_REPLAY_DIVERGENCE"),
            "missing the named divergence:\n{stderr}"
        );
        assert!(
            !String::from_utf8_lossy(&replayed.stdout).contains("CANARY incarnation=1"),
            "incarnation 1 ran after a divergence at or before the crash"
        );
        stderr
    }

    /// A well-formed digest no recovered filesystem has.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const FORGED_SNAPSHOT_DIGEST: &str =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000";

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_fs_crash_restart_replay_refuses_a_forged_handoff_digest() {
        let directory = tempdir().unwrap();
        let bin = build_crash_restart_canary(directory.path());
        let trace = directory.path().join("crash-restart.patina");
        record_crash_restart_canary(&bin, &trace);

        // Forge the digest on both the Crash and the Restart marker, so the trace
        // stays structurally valid and only the handed-over state disagrees.
        let tampered = tamper_trace(&trace, |bundle| {
            let mut forged = 0;
            for marker in bundle["timelines"][0]["lifecycle"].as_array_mut().unwrap() {
                if let Some(digest) = marker.get_mut("snapshot_digest") {
                    *digest = FORGED_SNAPSHOT_DIGEST.into();
                    forged += 1;
                }
            }
            assert_eq!(forged, 2, "expected a Crash and a Restart marker");
        });
        let stderr = replay_crash_divergence(&bin, &tampered);
        assert!(stderr.contains(FORGED_SNAPSHOT_DIGEST), "{stderr}");
    }

    /// The canary's fifth write, the durable `B-stable!!`: a successful write one
    /// before the recorded crash selector.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const CANARY_EARLIER_WRITE_ORDINAL: u64 = 5;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_fs_crash_restart_replay_refuses_a_crash_at_a_different_operation() {
        let directory = tempdir().unwrap();
        let bin = build_crash_restart_canary(directory.path());
        let trace = directory.path().join("crash-restart.patina");
        record_crash_restart_canary(&bin, &trace);

        // Move the recorded selector one write earlier: incarnation 0's replayed
        // operations still match, but its crash now comes before the recorded one.
        let tampered = tamper_trace(&trace, |bundle| {
            bundle["metadata"]["faults"]["crash_at"]["ordinal"] =
                CANARY_EARLIER_WRITE_ORDINAL.into();
        });
        let stderr = replay_crash_divergence(&bin, &tampered);
        assert!(
            stderr.contains("the recorded crash followed operation"),
            "{stderr}"
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_fs_crash_restart_replay_refuses_a_crash_the_recording_never_had() {
        let directory = tempdir().unwrap();
        let bin = build_crash_restart_canary(directory.path());
        let trace = directory.path().join("no-crash.patina");
        invoke(
            native_workspace(),
            &[
                "run",
                bin.to_str().unwrap(),
                "--seed",
                "11",
                "--record",
                trace.to_str().unwrap(),
            ],
        );

        // Claim the crash-free recording was made with the canary's selector: its
        // replay crashes where the recording kept running.
        let tampered = tamper_trace(&trace, |bundle| {
            bundle["metadata"]["faults"]["crash_at"] =
                serde_json::json!({"op": "write", "ordinal": 6});
        });
        let stderr = replay_crash_divergence(&bin, &tampered);
        assert!(
            stderr.contains("the recorded run never crashed"),
            "{stderr}"
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_fs_crash_restart_replay_refuses_a_divergence_in_the_restarted_incarnation() {
        let directory = tempdir().unwrap();
        let bin = build_crash_restart_canary(directory.path());
        let trace = directory.path().join("crash-restart.patina");
        record_crash_restart_canary(&bin, &trace);

        // Alter the outcome of incarnation 1's first operation (its look-up of
        // `/pid0`); only a replay of incarnation 1's own segment can notice. The
        // diverged operation fails in the guest and the runtime reports the
        // unconsumed remainder of the segment.
        let tampered = tamper_trace(&trace, |bundle| {
            let first_restarted = bundle["timelines"][0]["decisions"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|event| event["incarnation"] == 1)
                .expect("incarnation 1 recorded operations");
            let len = &mut first_restarted["outcome"]["value"]["len"];
            *len = (len.as_u64().expect("a metadata outcome") + 1).into();
        });
        let replayed = invoke_unchecked(
            env!("CARGO_BIN_EXE_cargo-patina"),
            native_workspace(),
            &["replay", bin.to_str().unwrap(), tampered.to_str().unwrap()],
        );
        let stderr = String::from_utf8_lossy(&replayed.stderr);
        assert!(
            !replayed.status.success(),
            "a tampered incarnation 1 replayed:\n{stderr}"
        );
        assert!(
            stderr.contains("PATINA_FS_CRASH_RESTART ") && stderr.contains("replay consumed"),
            "incarnation 1 did not replay its segment past the restart:\n{stderr}"
        );
        assert!(
            !String::from_utf8_lossy(&replayed.stdout).contains("CANARY incarnation=1"),
            "incarnation 1 ran past its diverged operation"
        );
    }

    /// A seed whose swarm draw deselects the canary's one fault class, the crash
    /// (the run's `PATINA_SWARM_REPORT` says `class=crash|0`, asserted below).
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const SWARM_DROPS_CRASH_SEED: &str = "1";

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_fs_crash_restart_swarm_dropped_crash_records_and_replays_one_incarnation() {
        let directory = tempdir().unwrap();
        let bin = build_crash_restart_canary(directory.path());
        let trace = directory.path().join("swarm.patina");
        let recorded = invoke(
            native_workspace(),
            &[
                "run",
                bin.to_str().unwrap(),
                "--seed",
                SWARM_DROPS_CRASH_SEED,
                "--fs-crash-at",
                CANARY_CRASH_SELECTOR,
                "--swarm",
                "--record",
                trace.to_str().unwrap(),
            ],
        );
        let recorded_stderr = String::from_utf8_lossy(&recorded.stderr);
        assert!(
            recorded_stderr.contains("class=crash|0"),
            "the seed no longer deselects the crash class:\n{recorded_stderr}"
        );
        let bundle: serde_json::Value = serde_json::from_slice(&fs::read(&trace).unwrap()).unwrap();
        let lifecycle: Vec<&str> = bundle["timelines"][0]["lifecycle"]
            .as_array()
            .unwrap()
            .iter()
            .map(|marker| marker["kind"].as_str().unwrap())
            .collect();
        assert_eq!(lifecycle, ["start", "end"]);
        let replayed = invoke(
            native_workspace(),
            &["replay", bin.to_str().unwrap(), trace.to_str().unwrap()],
        );
        assert_eq!(
            String::from_utf8_lossy(&recorded.stdout),
            String::from_utf8_lossy(&replayed.stdout)
        );
    }

    // A guest that establishes a durable 16-byte baseline, then issues one UNSYNCED
    // positional overwrite. `--fs-crash-at write:2` fires right after that pwrite,
    // so it is the final write eligible for a sub-block (byte-granularity) tear. The
    // guest reopens cold and prints the recovered image. Under whole-block tearing
    // the overwrite reverts wholesale (all 'A'); under byte tearing it survives
    // partially (an 'B' prefix, an 'A' suffix) -- an image a block model can never
    // produce.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const TORN_GRANULARITY_SOURCE: &str = r#"
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::FileExt;

fn main() {
    let path = "/f";
    if let Ok(mut f) = File::open(path) {
        let mut buf = Vec::new();
        let _ = f.read_to_end(&mut buf);
        println!("recovered={buf:?}");
        return;
    }
    {
        let f = OpenOptions::new().create(true).write(true).open(path).unwrap();
        f.write_all_at(&[b'A'; 16], 0).unwrap();
        f.sync_all().unwrap();
        File::open("/").unwrap().sync_all().unwrap();
    }
    {
        let f = OpenOptions::new().write(true).open(path).unwrap();
        let _ = f.write_all_at(&[b'B'; 16], 0);
    }
    let mut buf = Vec::new();
    if let Ok(mut f) = File::open(path) {
        let _ = f.read_to_end(&mut buf);
    }
    println!("recovered={buf:?}");
}
"#;

    // `--fs-torn-granularity byte` must actually reach the guest's crash filesystem.
    // This FAILED before the structural fix: the shim pre-installed a default-policy
    // (whole-block) CrashFs via `with_filesystem`, so `RuntimeBuilder::build` never
    // consumed `config.faults.torn_granularity` and every crash ran as block. With
    // the runtime now the single choke point that builds the CrashFs from the fault
    // config, block and byte produce different guest-visible recovered images.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_fs_torn_granularity_byte_reaches_the_guest() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("torn.rs");
        fs::write(&source, TORN_GRANULARITY_SOURCE).unwrap();
        let workspace = native_workspace();
        let bin = directory.path().join("torn");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );

        let run = |gran: &str| {
            let output = invoke(
                workspace,
                &[
                    "run",
                    bin.to_str().unwrap(),
                    "--seed",
                    "1",
                    "--fs-crash-at",
                    "write:2",
                    "--fs-torn-granularity",
                    gran,
                ],
            );
            String::from_utf8_lossy(&output.stdout).into_owned()
        };

        let block = run("block");
        let byte = run("byte");
        // Block granularity reverts the unsynced overwrite wholesale to the durable
        // baseline; byte granularity keeps a live prefix, so the images differ.
        assert!(
            block.contains(
                "recovered=[65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65]"
            ),
            "block granularity should revert wholesale to the durable baseline: {block}"
        );
        assert_ne!(
            block, byte,
            "--fs-torn-granularity byte did not reach the guest (byte tearing == block)"
        );
        assert!(
            byte.contains("66") && byte.contains("65"),
            "byte granularity should leave a partial live/durable mix: {byte}"
        );
    }

    // The seeded crash-decision stream must be LIVE per `--seed` (the shim used to
    // pin the CrashFs to seed 0, so every seed produced the same crash image), and
    // still deterministic: identical seed reproduces the identical torn image.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_fs_crash_image_is_seed_live_and_deterministic() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("torn.rs");
        fs::write(&source, TORN_GRANULARITY_SOURCE).unwrap();
        let workspace = native_workspace();
        let bin = directory.path().join("torn");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );

        let run = |seed: &str| {
            let output = invoke(
                workspace,
                &[
                    "run",
                    bin.to_str().unwrap(),
                    "--seed",
                    seed,
                    "--fs-crash-at",
                    "write:2",
                    "--fs-torn-granularity",
                    "byte",
                ],
            );
            String::from_utf8_lossy(&output.stdout).into_owned()
        };

        let images: Vec<String> = ["1", "2", "3"].iter().map(|seed| run(seed)).collect();
        // Seed liveness: the seeded tear point varies, so not every seed yields the
        // same recovered image.
        assert!(
            images.iter().any(|image| *image != images[0]),
            "crash image did not vary across seeds (seed stream is pinned): {images:?}"
        );
        // Determinism: each seed reproduces its image byte-identically on re-run.
        for seed in ["1", "2", "3"] {
            assert_eq!(
                run(seed),
                run(seed),
                "crash image is not deterministic for seed {seed}"
            );
        }
    }

    // A native guest that follows the parent-directory fsync pattern for namespace
    // durability: write tmp, fsync file, rename, open parent directory read-only,
    // fstat it, fsync it, then recover. Without the parent fsync, a crash after the
    // rename can lose the destination; with the parent fsync, a crash after the dir
    // fsync preserves it. This is the SlateDB local-object-store pattern that used
    // to be impossible because File::open(parent_dir) returned EISDIR under Patina.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const NAMESPACE_DURABILITY_SOURCE: &str = r#"
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};

fn report(final_path: &str) {
    let mut contents = String::new();
    match File::open(final_path) {
        Ok(mut file) => {
            file.read_to_string(&mut contents).unwrap();
            println!("NS_RESULT present {contents}");
        }
        Err(error) => println!("NS_RESULT missing {:?}", error.kind()),
    }
}

fn main() {
    let with_dir_fsync = env::args().any(|arg| arg == "--dir-fsync");
    let marker = "/tmp/patina-ns.started";
    let tmp = "/tmp/patina-ns.tmp";
    let final_path = "/tmp/patina-ns.final";
    if File::open(marker).is_ok() {
        report(final_path);
        return;
    }
    let _ = fs::remove_file(tmp);
    let _ = fs::remove_file(final_path);
    let mut marker_file = OpenOptions::new().create(true).truncate(true).write(true).open(marker).unwrap();
    marker_file.write_all(b"started").unwrap();
    marker_file.sync_all().unwrap();
    File::open("/tmp").unwrap().sync_all().unwrap();

    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(tmp)
        .unwrap();
    file.write_all(b"stable").unwrap();
    file.sync_all().unwrap();
    fs::rename(tmp, final_path).unwrap();

    if with_dir_fsync {
        let dir = File::open("/tmp").unwrap();
        println!("dir_is_dir={}", dir.metadata().unwrap().is_dir());
        dir.sync_all().unwrap();
    }
    drop(file);

    report(final_path);
}
"#;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_directory_fsync_guards_namespace_durability_and_replays() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("namespace.rs");
        fs::write(&source, NAMESPACE_DURABILITY_SOURCE).unwrap();
        let workspace = native_workspace();
        let bin = directory.path().join("namespace");
        invoke(
            workspace,
            &[
                "build",
                source.to_str().unwrap(),
                "--output",
                bin.to_str().unwrap(),
            ],
        );

        let run_stdout = |args: &[&str]| -> String {
            String::from_utf8_lossy(&invoke(workspace, args).stdout).into_owned()
        };
        let bin_str = bin.to_str().unwrap();

        // RED detector: without the parent-directory fsync, a crash after the rename
        // (the file close immediately after rename) loses the destination. Same seed
        // repeats byte-identically.
        let lost_args = ["run", bin_str, "--seed", "5", "--fs-crash-at", "close:1"];
        let lost_a = run_stdout(&lost_args);
        let lost_b = run_stdout(&lost_args);
        assert_eq!(lost_a, lost_b, "same-seed namespace crash outcome changed");
        assert!(
            lost_a.contains("NS_RESULT missing"),
            "missing parent fsync should be able to lose the rename:\n{lost_a}"
        );

        // Guarded green: the same workload with parent-dir fsync survives a crash
        // immediately after the directory fsync.
        let guarded = run_stdout(&[
            "run",
            bin_str,
            "--seed",
            "5",
            "--fs-crash-at",
            "sync:4",
            "--",
            "--dir-fsync",
        ]);
        assert!(
            guarded.contains("dir_is_dir=true"),
            "fstat did not report a directory before the modeled crash:\n{guarded}"
        );
        assert!(
            guarded.contains("NS_RESULT present stable"),
            "parent dir fsync should preserve the rename:\n{guarded}"
        );

        // A dir-fsync-bearing trace records and replays byte-identically.
        let trace = directory.path().join("namespace.patina");
        let recorded = invoke(
            workspace,
            &[
                "run",
                bin_str,
                "--seed",
                "5",
                "--record",
                trace.to_str().unwrap(),
                "--fingerprint",
                "namespace-dir-fsync",
                "--",
                "--dir-fsync",
            ],
        );
        let replayed = invoke(
            workspace,
            &[
                "replay",
                bin_str,
                trace.to_str().unwrap(),
                "--fingerprint",
                "namespace-dir-fsync",
            ],
        );
        assert_eq!(
            String::from_utf8_lossy(&recorded.stdout),
            String::from_utf8_lossy(&replayed.stdout),
            "directory-fsync trace replay diverged"
        );
    }
}
