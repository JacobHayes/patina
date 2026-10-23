//! Native filesystem crash/restart, torn images, and namespace durability.

#[cfg(test)]
mod tests {
    use super::super::*;
    use common::native::{Guest, assert_success};

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
    /// The canary's crash selector: the unsynced overwrite of `/b`, its sixth write.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const CANARY_CRASH_SELECTOR: &str = "write:6";

    /// The canary's fifth write, the durable `B-stable!!`: a successful write one
    /// before the recorded crash selector.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const CANARY_EARLIER_WRITE_ORDINAL: u64 = 5;

    /// A seed whose swarm draw deselects the canary's one fault class, the crash
    /// (the run's `PATINA_SWARM_REPORT` says `class=crash|0`, asserted below).
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const SWARM_DROPS_CRASH_SEED: &str = "1";

    /// A well-formed digest no recovered filesystem has.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const FORGED_SNAPSHOT_DIGEST: &str =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000";

    /// Build the single-file guest `source` as `name` into a scratch directory.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn build_guest(name: &str, source: &str) -> Guest {
        let dir = tempdir().unwrap();
        let binary = build_facts_guest(dir.path(), name, source);
        Guest { dir, binary }
    }

    /// The lifecycle marker kinds of a trace's main timeline, in order.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn lifecycle(trace: &Path) -> Vec<String> {
        let bundle: serde_json::Value = serde_json::from_slice(&fs::read(trace).unwrap()).unwrap();
        bundle["timelines"][0]["lifecycle"]
            .as_array()
            .unwrap()
            .iter()
            .map(|marker| marker["kind"].as_str().unwrap().to_owned())
            .collect()
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

    /// Replay `trace` against the canary, expecting a named crash-replay
    /// divergence, and return the replay's stderr.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn replay_crash_divergence(canary: &Guest, trace: &Path) -> String {
        let replayed = canary.command("replay", &[trace.to_str().unwrap()]);
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

    /// A crash point restarts the guest as a fresh incarnation over the durable
    /// image: synced bytes survive, the unsynced overwrite and incarnation 0's
    /// exit handlers do not, and a held descriptor is stale. The seeded run
    /// records and replays both incarnations, the envelope describes the
    /// restart, an unreached selector fails, and a replay refuses a trace whose
    /// crash point, handed-over state or restarted incarnation was altered.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_fs_crash_restarts_a_fresh_incarnation_and_its_replay_refuses_divergence() {
        let canary = build_guest("crash_restart", NATIVE_CRASH_RESTART_CANARY_SOURCE);
        let crash = ["--fs-crash-at", CANARY_CRASH_SELECTOR];
        let (output, trace) = canary.assert_recorded(11, &crash);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        for expected in [
            "CANARY before_trigger",
            "CANARY incarnation=1",
            "CANARY A=\"A-synced\"",
            "CANARY B=\"B-stable!!\"",
            "CANARY stale_fd_result=-1",
            "CANARY restart_first_fd=3",
        ] {
            assert!(
                stdout.contains(expected),
                "missing {expected}:\n{stdout}\n{stderr}"
            );
        }
        for absent in [
            "after_trigger_should_not_print",
            "atexit0_should_not_run",
            "B-volatile",
        ] {
            assert!(!stdout.contains(absent), "unexpected {absent}:\n{stdout}");
        }
        assert_eq!(
            stderr.matches("PATINA_FS_CRASH_RESTART").count(),
            1,
            "{stderr}"
        );
        assert_eq!(
            lifecycle(&trace),
            ["start", "crash", "restart", "start", "end"]
        );

        let json = assert_success(canary.command(
            "run",
            &[
                "--seed",
                "11",
                "--fs-crash-at",
                CANARY_CRASH_SELECTOR,
                "--format",
                "json",
            ],
        ));
        let envelope: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
        let crash_restart = &envelope["crash_restart"];
        assert_eq!(crash_restart["selector"]["op"], "write");
        assert_eq!(crash_restart["selector"]["ordinal"], 6);
        assert_eq!(crash_restart["reached"], true);
        assert_eq!(crash_restart["crash_count"], 1);
        assert_eq!(crash_restart["restart_count"], 1);
        assert_eq!(crash_restart["incarnations"][0]["id"], 0);
        assert_eq!(crash_restart["incarnations"][1]["id"], 1);
        assert_ne!(
            crash_restart["incarnations"][0]["host_pid"],
            crash_restart["incarnations"][1]["host_pid"]
        );
        for digest in ["handoff_digest", "snapshot_digest"] {
            assert!(
                crash_restart[digest]
                    .as_str()
                    .unwrap()
                    .starts_with("sha256:"),
                "{envelope:#}"
            );
        }
        assert_eq!(
            crash_restart["terminal_outcome"]["kind"],
            "completed_after_restart"
        );
        let json_stdout = envelope["stdout"].as_str().unwrap();
        assert!(json_stdout.contains("CANARY incarnation=1"), "{envelope:#}");
        assert!(
            !json_stdout.contains("after_trigger_should_not_print"),
            "{envelope:#}"
        );
        assert!(
            !json_stdout.contains("atexit0_should_not_run"),
            "{envelope:#}"
        );

        let unreached = canary.command("run", &["--seed", "11", "--fs-crash-at", "write:99"]);
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

        // Forge the digest on both the Crash and the Restart marker, so the trace
        // stays structurally valid and only the handed-over state disagrees.
        let forged = tamper_trace(&trace, |bundle| {
            let mut forged = 0;
            for marker in bundle["timelines"][0]["lifecycle"].as_array_mut().unwrap() {
                if let Some(digest) = marker.get_mut("snapshot_digest") {
                    *digest = FORGED_SNAPSHOT_DIGEST.into();
                    forged += 1;
                }
            }
            assert_eq!(forged, 2, "expected a Crash and a Restart marker");
        });
        let stderr = replay_crash_divergence(&canary, &forged);
        assert!(stderr.contains(FORGED_SNAPSHOT_DIGEST), "{stderr}");

        // Move the recorded selector one write earlier: incarnation 0's replayed
        // operations still match, but its crash now comes before the recorded one.
        let earlier = tamper_trace(&trace, |bundle| {
            bundle["metadata"]["faults"]["crash_at"]["ordinal"] =
                CANARY_EARLIER_WRITE_ORDINAL.into();
        });
        let stderr = replay_crash_divergence(&canary, &earlier);
        assert!(
            stderr.contains("the recorded crash followed operation"),
            "{stderr}"
        );

        // Alter the outcome of incarnation 1's first operation (its open of
        // `/pid0`); only a replay of incarnation 1's own segment can notice. The
        // diverged operation fails in the guest and the runtime reports the
        // unconsumed remainder of the segment.
        let restarted = tamper_trace(&trace, |bundle| {
            let first_restarted = bundle["timelines"][0]["decisions"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|event| event["incarnation"] == 1)
                .expect("incarnation 1 recorded operations");
            let handle = &mut first_restarted["outcome"]["value"];
            *handle = (handle.as_u64().expect("a handle outcome") + 1).into();
        });
        let replayed = canary.command("replay", &[restarted.to_str().unwrap()]);
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

        // Claim a crash-free recording was made with the canary's selector: its
        // replay crashes where the recording kept running.
        let crash_free = canary.dir.path().join("crash-free.patina");
        assert_success(canary.command(
            "run",
            &["--seed", "11", "--record", crash_free.to_str().unwrap()],
        ));
        let never = tamper_trace(&crash_free, |bundle| {
            bundle["metadata"]["faults"]["crash_at"] =
                serde_json::json!({"op": "write", "ordinal": 6});
        });
        let stderr = replay_crash_divergence(&canary, &never);
        assert!(
            stderr.contains("the recorded run never crashed"),
            "{stderr}"
        );

        // A swarm draw that deselects the crash records and replays one incarnation.
        let swarm = canary.dir.path().join("swarm.patina");
        let recorded = assert_success(canary.command(
            "run",
            &[
                "--seed",
                SWARM_DROPS_CRASH_SEED,
                "--fs-crash-at",
                CANARY_CRASH_SELECTOR,
                "--swarm",
                "--record",
                swarm.to_str().unwrap(),
            ],
        ));
        assert!(
            String::from_utf8_lossy(&recorded.stderr).contains("class=crash|0"),
            "the seed no longer deselects the crash class:\n{}",
            String::from_utf8_lossy(&recorded.stderr)
        );
        assert_eq!(lifecycle(&swarm), ["start", "end"]);
        let replayed = assert_success(canary.command("replay", &[swarm.to_str().unwrap()]));
        assert_eq!(recorded.stdout, replayed.stdout);
    }

    /// A guest that reports, in each incarnation, its first entropy draw and
    /// its realtime, and in incarnation 1 the last realtime incarnation 0 read
    /// and the timestamp it left on the file it wrote that reading to.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const NATIVE_INCARNATION_STREAMS_SOURCE: &str = r#"
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

unsafe extern "C" {
    fn getentropy(buf: *mut core::ffi::c_void, len: usize) -> i32;
}

fn now_nanos() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
}

fn report(incarnation: u32) {
    let mut bytes = [0_u8; 16];
    assert_eq!(unsafe { getentropy(bytes.as_mut_ptr().cast(), bytes.len()) }, 0);
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    println!("STREAMS incarnation={incarnation} entropy={hex} realtime={}", now_nanos());
}

fn main() {
    if let Ok(previous) = fs::read_to_string("/last-realtime") {
        let stamped = fs::metadata("/last-realtime").unwrap().modified().unwrap();
        let stamped = stamped.duration_since(UNIX_EPOCH).unwrap().as_nanos();
        println!("STREAMS previous_realtime={previous} previous_stamp={stamped}");
        report(1);
        return;
    }
    report(0);
    // Run on for a while, so incarnation 0's clock gets well past the boot.
    std::thread::sleep(Duration::from_secs(5));
    let mut last = OpenOptions::new().create(true).truncate(true).write(true).open("/last-realtime").unwrap();
    write!(last, "{}", now_nanos()).unwrap();
    last.sync_all().unwrap();
    File::open("/").unwrap().sync_all().unwrap();
    // The crash selector: this second write.
    OpenOptions::new().create(true).write(true).open("/trigger").unwrap().write_all(b"x").unwrap();
}
"#;
    /// The `STREAMS` lines of a run's output, each as its `key=value` fields.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn streams_report(stdout: &[u8]) -> Vec<BTreeMap<String, String>> {
        String::from_utf8_lossy(stdout)
            .lines()
            .filter_map(|line| line.strip_prefix("STREAMS "))
            .map(|fields| {
                fields
                    .split(' ')
                    .map(|field| {
                        let (key, value) = field.split_once('=').expect("key=value field");
                        (key.to_owned(), value.to_owned())
                    })
                    .collect()
            })
            .collect()
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_restarted_incarnation_draws_fresh_streams_and_carries_realtime_forward() {
        let guest = build_guest("incarnation_streams", NATIVE_INCARNATION_STREAMS_SOURCE);
        let seeded = guest.assert_run_success(11, &["--fs-crash-at", "write:2"]);
        let report = streams_report(&seeded.stdout);
        let [first, previous, restarted] = report.as_slice() else {
            panic!(
                "expected incarnation 0's report, then incarnation 1's two:\n{}",
                String::from_utf8_lossy(&seeded.stdout)
            );
        };
        let nanos =
            |fields: &BTreeMap<String, String>, key: &str| -> u128 { fields[key].parse().unwrap() };

        assert_ne!(
            first["entropy"], restarted["entropy"],
            "incarnation 1 repeated incarnation 0's entropy"
        );
        let restarted_realtime = nanos(restarted, "realtime");
        assert!(
            restarted_realtime >= nanos(previous, "previous_realtime")
                && restarted_realtime >= nanos(previous, "previous_stamp"),
            "realtime ran backwards across the restart: {report:?}"
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
    // `--fs-torn-granularity byte` must reach the guest's crash filesystem (the
    // runtime is the single choke point that builds the CrashFs from the fault
    // config), and the seeded crash-decision stream must be live per `--seed`
    // while one seed reproduces its torn image.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_fs_torn_image_follows_the_granularity_and_the_seed() {
        let guest = build_guest("torn", TORN_GRANULARITY_SOURCE);
        let crash = |seed: &str, granularity: &str| {
            let output = assert_success(guest.command(
                "run",
                &[
                    "--seed",
                    seed,
                    "--fs-crash-at",
                    "write:2",
                    "--fs-torn-granularity",
                    granularity,
                ],
            ));
            String::from_utf8_lossy(&output.stdout).into_owned()
        };

        // Block granularity reverts the unsynced overwrite wholesale to the durable
        // baseline; byte granularity keeps a live prefix, so the images differ.
        let block = crash("1", "block");
        assert!(
            block.contains(
                "recovered=[65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65]"
            ),
            "block granularity should revert wholesale to the durable baseline: {block}"
        );
        let byte_flags = ["--fs-crash-at", "write:2", "--fs-torn-granularity", "byte"];
        let byte =
            String::from_utf8_lossy(&guest.assert_run_success(1, &byte_flags).stdout).into_owned();
        assert_ne!(
            block, byte,
            "--fs-torn-granularity byte did not reach the guest (byte tearing == block)"
        );
        assert!(
            byte.contains("66") && byte.contains("65"),
            "byte granularity should leave a partial live/durable mix: {byte}"
        );
        assert!(
            ["2", "3"].iter().any(|seed| crash(seed, "byte") != byte),
            "crash image did not vary across seeds (seed stream is pinned)"
        );
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
        let guest = build_guest("namespace", NAMESPACE_DURABILITY_SOURCE);
        let stdout = |output: Output| String::from_utf8_lossy(&output.stdout).into_owned();

        // Without the parent-directory fsync, a crash after the rename (the file
        // close immediately after it) loses the destination.
        let lost = stdout(assert_success(
            guest.command("run", &["--seed", "5", "--fs-crash-at", "close:1"]),
        ));
        assert!(
            lost.contains("NS_RESULT missing"),
            "missing parent fsync should be able to lose the rename:\n{lost}"
        );

        // The same workload with the parent-dir fsync survives a crash immediately
        // after the directory fsync, and its recording replays flag-free.
        let trace = guest.dir.path().join("namespace.patina");
        let guarded = stdout(assert_success(guest.command(
            "run",
            &[
                "--seed",
                "5",
                "--fs-crash-at",
                "sync:4",
                "--record",
                trace.to_str().unwrap(),
                "--",
                "--dir-fsync",
            ],
        )));
        assert!(
            guarded.contains("dir_is_dir=true"),
            "fstat did not report a directory before the modeled crash:\n{guarded}"
        );
        assert!(
            guarded.contains("NS_RESULT present stable"),
            "parent dir fsync should preserve the rename:\n{guarded}"
        );
        let replayed = stdout(assert_success(
            guest.command("replay", &[trace.to_str().unwrap()]),
        ));
        assert_eq!(guarded, replayed, "directory-fsync trace replay diverged");
    }

    /// The `--format json` envelope of a run that may fail.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn run_envelope(guest: &Guest, arguments: &[&str]) -> serde_json::Value {
        let output = guest.command("run", arguments);
        serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "no JSON envelope: {error}\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        })
    }

    // A log fsynced record by record around one removal step: a temp directory
    // holding a file, created and removed as a dropped `TempDir` does. The
    // `early-exit` step instead exits at once, with a status patina once used
    // for a failed crash, before any crash point.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const REMOVAL_THEN_CRASH_SOURCE: &str = r#"
use std::fs::{self, File, OpenOptions};
use std::io::Write;

unsafe extern "C" {
    fn _exit(status: i32) -> !;
}

fn append(log: &mut File, n: u32) {
    log.write_all(format!("record {n}\n").as_bytes()).unwrap();
    log.sync_all().unwrap();
}

fn main() {
    let step = std::env::args().nth(1).unwrap_or_default();
    if step == "early-exit" {
        unsafe { _exit(113) }
    }
    if let Ok(log) = fs::read_to_string("log") {
        println!("RESTARTED records={}", log.lines().count());
        return;
    }
    let mut log = OpenOptions::new().create(true).append(true).open("log").unwrap();
    for n in 0..5 { append(&mut log, n); }
    if step == "remove-dir" {
        fs::create_dir("scratch").unwrap();
        File::create("scratch/f").unwrap();
        fs::remove_dir_all("scratch").unwrap();
    }
    for n in 5..10 { append(&mut log, n); }
    println!("NO_CRASH");
}
"#;

    /// The removal guest, built once and shared by the tests that crash it.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn removal_guest() -> Guest {
        let binary = super::super::run_facts::shared_guest("crash-removal", |dir| {
            build_facts_guest(dir, "removal", REMOVAL_THEN_CRASH_SOURCE)
        });
        Guest {
            dir: tempdir().unwrap(),
            binary,
        }
    }

    /// A crash point after a removal still fires: the run crashes at the eighth
    /// fsync and restarts holding the eight records fsynced by then. Whether a
    /// crash was attempted never rests on the guest's exit status: a guest that
    /// exits before its crash point is a run that exited without a crash,
    /// whatever status it chose.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_fs_crash_after_a_removal_restarts_and_an_early_exit_attempts_none() {
        let guest = removal_guest();
        let crash = [
            "--seed",
            "1",
            "--fs-crash-at",
            "sync:8",
            "--format",
            "json",
            "--",
        ];
        let envelope = run_envelope(&guest, &[&crash[..], &["remove-dir"][..]].concat());
        let crash_restart = &envelope["crash_restart"];
        assert_eq!(crash_restart["reached"], true, "{envelope:#}");
        assert_eq!(
            crash_restart["terminal_outcome"]["kind"], "completed_after_restart",
            "{envelope:#}"
        );
        let stdout = envelope["stdout"].as_str().unwrap();
        assert!(stdout.contains("RESTARTED records=8"), "{stdout}");

        let envelope = run_envelope(&guest, &[&crash[..], &["early-exit"][..]].concat());
        let crash_restart = &envelope["crash_restart"];
        assert_eq!(crash_restart["attempted"], false, "{envelope:#}");
        assert_eq!(
            crash_restart["terminal_outcome"]["kind"], "exited_without_crash",
            "{envelope:#}"
        );
        assert!(envelope["refusal"].is_null(), "{envelope:#}");
    }

    /// A crash whose handoff cannot be written at all (the supervisor's file
    /// size limit is zero) is still reported as a failed crash attempt,
    /// whether the write fails with `SIGXFSZ` ignored, or `SIGXFSZ` kills the
    /// incarnation mid-handoff or, for a record, in its trace flush.
    #[cfg(target_os = "linux")]
    #[test]
    fn native_fs_crash_with_an_unwritable_handoff_is_an_infra_refusal() {
        let guest = removal_guest();
        let trace = guest.dir.path().join("unwritable.patina");
        for (xfsz, record) in [("trap '' XFSZ;", false), ("", false), ("", true)] {
            let case = format!("{xfsz:?} record={record}");
            let mut arguments = vec![
                "run",
                guest.binary.to_str().unwrap(),
                "--seed",
                "1",
                "--fs-crash-at",
                "sync:8",
                "--format",
                "json",
            ];
            if record {
                arguments.extend(["--record", trace.to_str().unwrap()]);
            }
            let output = Command::new("bash")
                .current_dir(native_workspace())
                .args([
                    "-c",
                    &format!("ulimit -f 0; {xfsz} exec \"$0\" \"$@\""),
                    env!("CARGO_BIN_EXE_cargo-patina"),
                ])
                .args(&arguments)
                .output()
                .unwrap();
            let envelope: serde_json::Value = serde_json::from_slice(&output.stdout)
                .unwrap_or_else(|error| {
                    panic!(
                        "{case}: no JSON envelope: {error}\nstderr:\n{}",
                        String::from_utf8_lossy(&output.stderr)
                    )
                });
            assert_eq!(
                envelope["refusal"]["class"], "fs_crash_failed",
                "{case}: {envelope:#}"
            );
            let crash = &envelope["crash_restart"];
            assert_eq!(crash["attempted"], true, "{case}: {envelope:#}");
            assert_eq!(crash["reached"], false, "{case}: {envelope:#}");
            assert_eq!(
                crash["terminal_outcome"]["kind"], "crash_failed",
                "{case}: {envelope:#}"
            );
        }
    }

    // A fsynced file one block past the restart snapshot's 64 MiB field limit:
    // the crash at that fsync cannot export the recovered image. With `readv`,
    // the crash point is instead the write-back a vectored read makes between
    // its segments: the first segment copies into a shared view of the file
    // the second reads.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const UNEXPORTABLE_CRASH_SOURCE: &str = r#"
use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;

#[repr(C)]
struct Iov {
    base: *mut c_void,
    len: usize,
}

unsafe extern "C" {
    fn mmap(addr: *mut c_void, len: usize, prot: i32, flags: i32, fd: i32, offset: i64) -> *mut c_void;
    fn readv(fd: i32, iov: *const Iov, count: i32) -> isize;
}

fn vectored_read_through_a_shared_view() {
    let mut big = OpenOptions::new().create(true).read(true).write(true).open("/big").unwrap();
    big.write_all(&vec![7_u8; (64 << 20) + 4096]).unwrap();
    big.sync_all().unwrap();
    let mut file = OpenOptions::new().create(true).read(true).write(true).open("/small").unwrap();
    file.write_all(b"ABCD").unwrap();
    let view = unsafe { mmap(std::ptr::null_mut(), 4096, 3, 1, file.as_raw_fd(), 0) };
    assert_ne!(view as isize, -1);
    file.seek(SeekFrom::Start(0)).unwrap();
    let mut tail = [0_u8; 1];
    let segments = [
        Iov { base: unsafe { view.cast::<u8>().add(2) }.cast(), len: 1 },
        Iov { base: tail.as_mut_ptr().cast(), len: 1 },
    ];
    let read = unsafe { readv(file.as_raw_fd(), segments.as_ptr(), 2) };
    println!("READV_RETURNED {read}");
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("readv") {
        vectored_read_through_a_shared_view();
        return;
    }
    if File::open("/big").is_ok() {
        println!("RESTARTED");
        return;
    }
    let mut big = File::create("/big").unwrap();
    big.write_all(&vec![7_u8; (64 << 20) + 4096]).unwrap();
    let synced = big.sync_all();
    println!("SYNC_RETURNED {synced:?}");
}
"#;

    /// A crash point reached but not carried out fails closed: the run is an
    /// infra refusal naming the driver error, the crash is attempted and not
    /// reached, and the guest is never handed an errno for it, even from inside
    /// a vectored read.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_fs_crash_that_cannot_be_exported_is_an_infra_refusal() {
        let guest = build_guest("unexportable", UNEXPORTABLE_CRASH_SOURCE);
        let envelope = run_envelope(
            &guest,
            &["--seed", "1", "--fs-crash-at", "sync:1", "--format", "json"],
        );
        let stdout = envelope["stdout"].as_str().unwrap();
        assert!(!stdout.contains("SYNC_RETURNED"), "{envelope:#}");
        assert!(!stdout.contains("RESTARTED"), "{envelope:#}");
        assert_eq!(envelope["result"], "infra", "{envelope:#}");
        assert_eq!(
            envelope["refusal"]["class"], "fs_crash_failed",
            "{envelope:#}"
        );
        let refusal = envelope["refusal"]["message"].as_str().unwrap();
        assert!(refusal.contains("sync:1"), "{refusal}");
        let crash = &envelope["crash_restart"];
        assert_eq!(crash["attempted"], true, "{envelope:#}");
        assert_eq!(crash["reached"], false, "{envelope:#}");
        assert_eq!(
            crash["terminal_outcome"]["kind"], "crash_failed",
            "{envelope:#}"
        );

        #[cfg(target_os = "linux")]
        {
            let envelope = run_envelope(
                &guest,
                &[
                    "--seed",
                    "1",
                    "--fs-crash-at",
                    "write:3",
                    "--format",
                    "json",
                    "--",
                    "readv",
                ],
            );
            let stdout = envelope["stdout"].as_str().unwrap();
            assert!(!stdout.contains("READV_RETURNED"), "{envelope:#}");
            assert_eq!(
                envelope["refusal"]["class"], "fs_crash_failed",
                "{envelope:#}"
            );
            let refusal = envelope["refusal"]["message"].as_str().unwrap();
            assert!(refusal.contains("write:3"), "{refusal}");
            assert_eq!(
                envelope["crash_restart"]["terminal_outcome"]["kind"], "crash_failed",
                "{envelope:#}"
            );
        }
    }
}
