//! Native crash/restart: crash placement, crash kinds, namespace durability.

#[cfg(test)]
mod tests {
    use super::super::*;
    use common::native::{
        Guest, assert_success, crash_flag, crash_permille_for, crash_point_index, crash_seeds,
    };
    use patina_dst_abi::Operation;
    use std::collections::BTreeSet;

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

    /// Where to crash a guest: the rate, and `count` seeds that each crash it
    /// right after the `nth` operation `matches` selects in a crash-free
    /// recording of `guest_args`.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn crash_after(
        guest: &Guest,
        guest_args: &[&str],
        nth: usize,
        matches: impl Fn(&Operation) -> bool,
        count: usize,
    ) -> (String, Vec<String>) {
        static RECORDINGS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let recording = RECORDINGS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let trace = guest
            .dir
            .path()
            .join(format!("crash-free-{recording}.patina"));
        let mut args = vec!["--seed", "0", "--record", trace.to_str().unwrap(), "--"];
        args.extend_from_slice(guest_args);
        // The guest's verdict is beside the point: only its operations matter.
        let recorded = guest.command("run", &args);
        assert!(
            trace.exists(),
            "no crash-free recording:\n{}",
            String::from_utf8_lossy(&recorded.stderr)
        );
        let index = crash_point_index(&trace, nth, matches);
        let permille = crash_permille_for(index);
        let seeds = crash_seeds(permille, index, count)
            .into_iter()
            .map(|seed| seed.to_string())
            .collect();
        (permille.to_string(), seeds)
    }

    /// Whether `operation` writes exactly `bytes`.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn writes(operation: &Operation, bytes: &[u8]) -> bool {
        matches!(
            operation,
            Operation::FsWrite { bytes: written, .. } | Operation::FsWriteAt { bytes: written, .. }
                if written == bytes
        )
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
            stderr.contains("PATINA_CRASH_REPLAY_DIVERGENCE"),
            "missing the named divergence:\n{stderr}"
        );
        assert!(
            !String::from_utf8_lossy(&replayed.stdout).contains("CANARY incarnation=1"),
            "incarnation 1 ran after a divergence at or before the crash"
        );
        stderr
    }

    /// A crash restarts the guest as a fresh incarnation over the image the
    /// crash leaves: synced bytes survive, incarnation 0's exit handlers and
    /// everything after the crash point do not, and a held descriptor is
    /// stale. A process crash keeps the unsynced overwrite; a machine crash may
    /// keep it or the synced bytes before it. The run records and replays both
    /// incarnations, the envelope describes the restart, a rate whose draw
    /// never hits runs one incarnation, and a replay refuses a trace whose
    /// handed-over state or restarted incarnation was altered.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_crash_restarts_a_fresh_incarnation_and_its_replay_refuses_divergence() {
        let canary = build_guest("crash_restart", NATIVE_CRASH_RESTART_CANARY_SOURCE);
        let (permille, seeds) = crash_after(&canary, &[], 0, |op| writes(op, b"B-volatile"), 2);
        let crash = |kind: &'static str| [crash_flag(kind), &permille];
        let seed: u64 = seeds[0].parse().unwrap();
        let (output, trace) = canary.assert_recorded(seed, &crash("process"));
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        for expected in [
            "CANARY before_trigger",
            "CANARY incarnation=1",
            "CANARY A=\"A-synced\"",
            "CANARY B=\"B-volatile\"",
            "CANARY stale_fd_result=-1",
            "CANARY restart_first_fd=3",
        ] {
            assert!(
                stdout.contains(expected),
                "missing {expected}:\n{stdout}\n{stderr}"
            );
        }
        for absent in ["after_trigger_should_not_print", "atexit0_should_not_run"] {
            assert!(!stdout.contains(absent), "unexpected {absent}:\n{stdout}");
        }
        assert_eq!(
            stderr.matches("PATINA_CRASH_RESTART").count(),
            1,
            "{stderr}"
        );
        assert_eq!(
            lifecycle(&trace),
            ["start", "crash", "restart", "start", "end"]
        );

        // A machine crash keeps the synced bytes, and of the unsynced
        // overwrite either all or none: never a mix within the one block.
        for seed in &seeds {
            let machine = assert_success(
                canary.command("run", &[&["--seed", seed][..], &crash("machine")].concat()),
            );
            let stdout = String::from_utf8_lossy(&machine.stdout);
            assert!(stdout.contains("CANARY A=\"A-synced\""), "{stdout}");
            assert!(
                stdout.contains("CANARY B=\"B-stable!!\"")
                    || stdout.contains("CANARY B=\"B-volatile\""),
                "{stdout}"
            );
        }

        let json = assert_success(
            canary.command(
                "run",
                &[
                    &["--seed", &seeds[0]][..],
                    &crash("process"),
                    &["--format", "json"],
                ]
                .concat(),
            ),
        );
        let envelope: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
        let crash_restart = &envelope["crash_restart"];
        assert_eq!(crash_restart["crash_kind"], "process");
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

        // A rate whose draw never hits in this run: one incarnation, no crash.
        let quiet = crash_seeds(1, 4096, 1)[0].to_string();
        let json = assert_success(canary.command(
            "run",
            &[
                "--seed",
                &quiet,
                "--machine-crash-permille",
                "1",
                "--format",
                "json",
            ],
        ));
        let envelope: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
        assert_eq!(
            envelope["crash_restart"]["attempted"], false,
            "{envelope:#}"
        );
        assert_eq!(
            envelope["crash_restart"]["terminal_outcome"]["kind"], "exited_without_crash",
            "{envelope:#}"
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

        // Alter the outcome of incarnation 1's first operation (its open of
        // `/pid0`); only a replay of incarnation 1's own segment can notice. The
        // diverged operation fails in the guest and the runtime reports the
        // unconsumed remainder of the segment.
        let first_restarted = patina_dst_trace::TraceBundle::load(&trace)
            .unwrap()
            .timelines[0]
            .decisions
            .iter()
            .position(|event| event.incarnation == 1)
            .expect("incarnation 1 recorded operations");
        let restarted = tamper_trace(&trace, |bundle| {
            let decision = &mut bundle["timelines"][0]["decisions"][first_restarted];
            let handle = &mut decision[1]["value"];
            *handle = (handle.as_u64().expect("a handle outcome") + 1).into();
        });
        let replayed = canary.command("replay", &[restarted.to_str().unwrap()]);
        let stderr = String::from_utf8_lossy(&replayed.stderr);
        assert!(
            !replayed.status.success(),
            "a tampered incarnation 1 replayed:\n{stderr}"
        );
        assert!(
            stderr.contains("PATINA_CRASH_RESTART ") && stderr.contains("replay consumed"),
            "incarnation 1 did not replay its segment past the restart:\n{stderr}"
        );

        // A swarm draw that deselects the crash records and replays one incarnation.
        let swarm = canary.dir.path().join("swarm.patina");
        let recorded = assert_success(
            canary.command(
                "run",
                &[
                    &["--seed", "1"][..],
                    &crash("machine"),
                    &["--swarm", "--record", swarm.to_str().unwrap()],
                ]
                .concat(),
            ),
        );
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
    // The crash follows this write.
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
        let (permille, seeds) = crash_after(&guest, &[], 0, |op| writes(op, b"x"), 1);
        let seed: u64 = seeds[0].parse().unwrap();
        let seeded = guest.assert_run_success(seed, &["--machine-crash-permille", &permille]);
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

    // A guest that establishes a durable 16-byte baseline, then issues one
    // UNSYNCED positional overwrite, after which the run crashes. The guest
    // reopens cold and prints the recovered image.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const UNSYNCED_OVERWRITE_SOURCE: &str = r#"
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::FileExt;

fn main() {
    let path = "/f";
    if let Ok(mut f) = File::open(path) {
        let mut buf = Vec::new();
        let _ = f.read_to_end(&mut buf);
        println!("recovered={}", String::from_utf8_lossy(&buf));
        return;
    }
    {
        let f = OpenOptions::new().create(true).write(true).open(path).unwrap();
        f.write_all_at(&[b'A'; 16], 0).unwrap();
        f.sync_all().unwrap();
        File::open("/").unwrap().sync_all().unwrap();
    }
    if std::env::args().any(|arg| arg == "--dsync") {
        // Every write through an `O_DSYNC` description is durable on return;
        // the crash lands on the next file's creation.
        use std::os::unix::fs::OpenOptionsExt;
        #[cfg(target_os = "linux")]
        const O_DSYNC: i32 = 0o10000;
        #[cfg(target_os = "macos")]
        const O_DSYNC: i32 = 0x0040_0000;
        let f = OpenOptions::new().write(true).custom_flags(O_DSYNC).open(path).unwrap();
        f.write_all_at(&[b'B'; 16], 0).unwrap();
        let _ = OpenOptions::new().create(true).write(true).open("/g");
        println!("not_crashed");
        return;
    }
    let f = OpenOptions::new().read(true).write(true).open(path).unwrap();
    if std::env::args().any(|arg| arg == "--mapped") {
        // The overwrite through a shared view sits in the page cache until a
        // write-back; the crash lands on the next file's creation.
        unsafe extern "C" {
            fn mmap(addr: *mut u8, len: usize, prot: i32, flags: i32, fd: i32, offset: i64) -> *mut u8;
        }
        const PROT_READ_WRITE: i32 = 3;
        const MAP_SHARED: i32 = 1;
        use std::os::fd::AsRawFd;
        let view = unsafe { mmap(std::ptr::null_mut(), 16, PROT_READ_WRITE, MAP_SHARED, f.as_raw_fd(), 0) };
        assert_ne!(view as isize, -1);
        unsafe { std::ptr::write_bytes(view, b'B', 16) };
        let _ = OpenOptions::new().create(true).write(true).open("/g");
    } else {
        let _ = f.write_all_at(&[b'B'; 16], 0);
    }
    println!("not_crashed");
}
"#;
    /// What survives a crash right after an unsynced overwrite is the crash
    /// kind's to decide, through the runtime's one crash-filesystem choke
    /// point: a process crash keeps the overwrite every time, and a machine
    /// crash keeps it or the durable baseline, each for some seed, while one
    /// seed reproduces its image.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_crash_kind_decides_what_an_unsynced_overwrite_leaves() {
        let guest = build_guest("overwrite", UNSYNCED_OVERWRITE_SOURCE);
        let (permille, seeds) = crash_after(&guest, &[], 0, |op| writes(op, &[b'B'; 16]), 8);
        let recovered = |seed: &str, kind: &str| {
            let output = assert_success(
                guest.command("run", &["--seed", seed, crash_flag(kind), &permille]),
            );
            let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
            assert!(!stdout.contains("not_crashed"), "{stdout}");
            stdout
        };
        let (overwrite, baseline) = (
            format!("recovered={}", "B".repeat(16)),
            format!("recovered={}", "A".repeat(16)),
        );
        let mut machine = BTreeSet::new();
        for seed in &seeds {
            assert!(recovered(seed, "process").contains(&overwrite));
            let image = recovered(seed, "machine");
            assert_eq!(
                image,
                recovered(seed, "machine"),
                "seed {seed} did not reproduce"
            );
            machine.insert(if image.contains(&overwrite) {
                "overwrite"
            } else {
                assert!(image.contains(&baseline), "{image}");
                "baseline"
            });
        }
        assert_eq!(machine, BTreeSet::from(["baseline", "overwrite"]));
    }

    /// A process crash keeps what a store through a shared view left in the
    /// page cache with no write-back yet, and a machine crash loses it with
    /// the other unsynced writes.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_crash_kind_decides_what_an_unwritten_mapped_store_leaves() {
        let guest = build_guest("mapped", UNSYNCED_OVERWRITE_SOURCE);
        let creates_g =
            |op: &Operation| matches!(op, Operation::FsOpen { path, .. } if path == "/g");
        let (permille, seeds) = crash_after(&guest, &["--mapped"], 0, creates_g, 1);
        let recovered = |kind: &str| {
            let output = assert_success(guest.command(
                "run",
                &[
                    "--seed",
                    &seeds[0],
                    crash_flag(kind),
                    &permille,
                    "--",
                    "--mapped",
                ],
            ));
            String::from_utf8_lossy(&output.stdout).into_owned()
        };
        let process = recovered("process");
        assert!(
            process.contains(&format!("recovered={}", "B".repeat(16))),
            "{process}"
        );
        let machine = recovered("machine");
        assert!(
            machine.contains(&format!("recovered={}", "A".repeat(16))),
            "{machine}"
        );
    }

    /// A write through an `O_DSYNC` description is durable when it returns,
    /// as `generic_write_sync` makes it: a machine crash after it keeps the
    /// overwrite for every seed, where an unsynced one loses it for some.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_crash_keeps_a_write_through_an_o_dsync_description() {
        let guest = build_guest("dsync", UNSYNCED_OVERWRITE_SOURCE);
        let creates_g =
            |op: &Operation| matches!(op, Operation::FsOpen { path, .. } if path == "/g");
        let (permille, seeds) = crash_after(&guest, &["--dsync"], 0, creates_g, 8);
        for seed in &seeds {
            let output = assert_success(guest.command(
                "run",
                &[
                    "--seed",
                    seed,
                    crash_flag("machine"),
                    &permille,
                    "--",
                    "--dsync",
                ],
            ));
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                stdout.contains(&format!("recovered={}", "B".repeat(16))),
                "seed {seed}: {stdout}"
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
    /// Without the parent-directory fsync, a machine crash right after the
    /// rename can lose the destination; with it, a crash right after the
    /// directory fsync never does, under either kind, and its recording replays.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_directory_fsync_guards_namespace_durability_and_replays() {
        let guest = build_guest("namespace", NAMESPACE_DURABILITY_SOURCE);
        let stdout = |output: Output| String::from_utf8_lossy(&output.stdout).into_owned();
        let renamed = |op: &Operation| matches!(op, Operation::FsRename { .. });

        let (permille, seeds) = crash_after(&guest, &[], 0, renamed, 8);
        let lost = seeds.iter().any(|seed| {
            stdout(assert_success(guest.command(
                "run",
                &["--seed", seed, "--machine-crash-permille", &permille],
            )))
            .contains("NS_RESULT missing")
        });
        assert!(lost, "no machine crash lost the unsynced rename");

        // The crash follows the directory fsync, the sync after the rename.
        let renamed_yet = std::cell::Cell::new(false);
        let (permille, seeds) = crash_after(
            &guest,
            &["--dir-fsync"],
            0,
            |op| {
                renamed_yet.set(renamed_yet.get() || renamed(op));
                renamed_yet.get() && is_sync(op)
            },
            4,
        );
        for seed in &seeds {
            for kind in ["process", "machine"] {
                let guarded = stdout(assert_success(guest.command(
                    "run",
                    &[
                        "--seed",
                        seed,
                        crash_flag(kind),
                        &permille,
                        "--",
                        "--dir-fsync",
                    ],
                )));
                assert!(guarded.contains("dir_is_dir=true"), "{guarded}");
                assert!(
                    guarded.contains("NS_RESULT present stable"),
                    "parent dir fsync should preserve the rename:\n{guarded}"
                );
            }
        }
        let trace = guest.dir.path().join("namespace.patina");
        let recorded = stdout(assert_success(guest.command(
            "run",
            &[
                "--seed",
                &seeds[0],
                "--machine-crash-permille",
                &permille,
                "--record",
                trace.to_str().unwrap(),
                "--",
                "--dir-fsync",
            ],
        )));
        let replayed = stdout(assert_success(
            guest.command("replay", &[trace.to_str().unwrap()]),
        ));
        assert_eq!(recorded, replayed, "directory-fsync trace replay diverged");
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

    /// A crash right after a sync following a removal still fires: the run
    /// crashes at the eighth fsync and a process crash restarts holding the
    /// eight records fsynced by then. Whether a crash was attempted never rests
    /// on the guest's exit status: a guest that exits before any crash point is
    /// a run that exited without a crash, whatever status it chose.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_crash_after_a_removal_restarts_and_an_early_exit_attempts_none() {
        let guest = removal_guest();
        let (permille, seeds) = crash_after(&guest, &["remove-dir"], 7, is_sync, 1);
        let crash = [
            "--seed",
            &seeds[0],
            "--process-crash-permille",
            &permille,
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

    /// Whether `operation` is an fsync.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn is_sync(operation: &Operation) -> bool {
        matches!(operation, Operation::FsSync { .. })
    }

    /// A crash whose handoff cannot be written at all (the supervisor's file
    /// size limit is zero) is still reported as a failed crash attempt,
    /// whether the write fails with `SIGXFSZ` ignored, or `SIGXFSZ` kills the
    /// incarnation mid-handoff or, for a record, in its trace flush.
    #[cfg(target_os = "linux")]
    #[test]
    fn native_crash_with_an_unwritable_handoff_is_an_infra_refusal() {
        let guest = removal_guest();
        let (permille, seeds) = crash_after(&guest, &[], 7, is_sync, 1);
        let trace = guest.dir.path().join("unwritable.patina");
        for (xfsz, record) in [("trap '' XFSZ;", false), ("", false), ("", true)] {
            let case = format!("{xfsz:?} record={record}");
            let mut arguments = vec![
                "run",
                guest.binary.to_str().unwrap(),
                "--seed",
                &seeds[0],
                "--machine-crash-permille",
                &permille,
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
                envelope["refusal"]["class"], "crash_failed",
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

    // A fsynced file, its name made durable, one block past the restart
    // snapshot's 64 MiB field limit (or, with `small`, a file of one block): a
    // crash at that fsync cannot
    // export the recovered image. With `readv`, the crash point is instead the
    // write-back a vectored read makes between its segments: the first segment
    // copies into a shared view of the file the second reads.
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

fn big_len() -> usize {
    if std::env::args().any(|arg| arg == "small") { 4096 } else { (64 << 20) + 4096 }
}

fn vectored_read_through_a_shared_view() {
    let mut big = OpenOptions::new().create(true).read(true).write(true).open("/big").unwrap();
    File::open("/").unwrap().sync_all().unwrap();
    big.write_all(&vec![7_u8; big_len()]).unwrap();
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
    File::open("/").unwrap().sync_all().unwrap();
    big.write_all(&vec![7_u8; big_len()]).unwrap();
    let synced = big.sync_all();
    println!("SYNC_RETURNED {synced:?}");
}
"#;

    /// A crash reached but not carried out fails closed: the run is an infra
    /// refusal, the crash is attempted and not reached, and the guest is never
    /// handed an errno for it, even from inside a vectored read. Where to crash
    /// is found on the one-block variant, whose operations are the same.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_crash_that_cannot_be_exported_is_an_infra_refusal() {
        let guest = build_guest("unexportable", UNEXPORTABLE_CRASH_SOURCE);
        // The file's fsync, after its directory's.
        let (permille, seeds) = crash_after(&guest, &["main", "small"], 1, is_sync, 1);
        let envelope = run_envelope(
            &guest,
            &[
                "--seed",
                &seeds[0],
                "--machine-crash-permille",
                &permille,
                "--format",
                "json",
            ],
        );
        let stdout = envelope["stdout"].as_str().unwrap();
        assert!(!stdout.contains("SYNC_RETURNED"), "{envelope:#}");
        assert!(!stdout.contains("RESTARTED"), "{envelope:#}");
        assert_eq!(envelope["result"], "infra", "{envelope:#}");
        assert_eq!(envelope["refusal"]["class"], "crash_failed", "{envelope:#}");
        let crash = &envelope["crash_restart"];
        assert_eq!(crash["attempted"], true, "{envelope:#}");
        assert_eq!(crash["reached"], false, "{envelope:#}");
        assert_eq!(
            crash["terminal_outcome"]["kind"], "crash_failed",
            "{envelope:#}"
        );

        #[cfg(target_os = "linux")]
        {
            let (permille, seeds) = crash_after(
                &guest,
                &["readv", "small"],
                0,
                |op| matches!(op, Operation::FsWriteBackAt { .. }),
                1,
            );
            let envelope = run_envelope(
                &guest,
                &[
                    "--seed",
                    &seeds[0],
                    "--machine-crash-permille",
                    &permille,
                    "--format",
                    "json",
                    "--",
                    "readv",
                ],
            );
            let stdout = envelope["stdout"].as_str().unwrap();
            assert!(!stdout.contains("READV_RETURNED"), "{envelope:#}");
            assert_eq!(envelope["refusal"]["class"], "crash_failed", "{envelope:#}");
            assert_eq!(
                envelope["crash_restart"]["terminal_outcome"]["kind"], "crash_failed",
                "{envelope:#}"
            );
        }
    }

    /// A log the guest acks record by record into a ledger it fsyncs after
    /// each ack, and whose creation it makes durable first. A restarted
    /// incarnation reports `LOST` and exits 3 when the ledger holds more acks
    /// than the log holds records. Without `--fsync-log` the log's records are
    /// never written back, so a machine crash loses records the ledger acked:
    /// the bug a crash plane exists to find, and nothing short of a crash can
    /// show. Each incarnation
    /// first draws entropy until a low byte: draws a trace reducer can delete,
    /// since a later draw's answer ends the loop as well.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const ACKED_LOG_SOURCE: &str = r#"
use std::fs::{self, File, OpenOptions};
use std::io::Write;

fn sync_dir(path: &str) {
    File::open(path).unwrap().sync_all().unwrap();
}

fn lines(path: &str) -> usize {
    fs::read_to_string(path).map_or(0, |text| text.matches('\n').count())
}

unsafe extern "C" {
    fn getentropy(buf: *mut core::ffi::c_void, len: usize) -> i32;
}

fn draw_until_low() {
    loop {
        let mut byte = [0_u8; 1];
        assert_eq!(unsafe { getentropy(byte.as_mut_ptr().cast(), 1) }, 0);
        if byte[0] < 8 {
            return;
        }
    }
}

fn main() {
    draw_until_low();
    if fs::metadata("/acked").is_ok() {
        let (acked, logged) = (lines("/acked"), lines("/data/log"));
        if logged < acked {
            println!("LOST acked={acked} logged={logged}");
            std::process::exit(3);
        }
        println!("RESTARTED acked={acked} logged={logged}");
        return;
    }
    let mut ledger = OpenOptions::new().create(true).append(true).open("/acked").unwrap();
    sync_dir("/");
    fs::create_dir("/data").unwrap();
    let mut log = OpenOptions::new().create(true).append(true).open("/data/log").unwrap();
    sync_dir("/data");
    let fsync_log = std::env::args().any(|arg| arg == "--fsync-log");
    for record in 0..8 {
        writeln!(log, "record {record}").unwrap();
        if fsync_log {
            log.sync_all().unwrap();
        }
        writeln!(ledger, "{record}").unwrap();
        ledger.sync_all().unwrap();
    }
}
"#;

    /// A campaign drawing the crash plane crashes and restarts generations at
    /// drawn rates: it catches log records lost to a missing fsync (red)
    /// and passes the fixed guest (green); and `minimize` reduces a crash
    /// generation's fault knobs, keeping the crash it needs and recording a
    /// two-incarnation trace.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_campaign_crash_plane_catches_an_unsynced_log() {
        let guest = build_guest("acked_log", ACKED_LOG_SOURCE);
        let spec = guest.dir.path().join("spec.json");
        fs::write(
            &spec,
            r#"{"faults": ["crash"], "classify": {"exit_codes": {"VIOLATION": [3]}}}"#,
        )
        .unwrap();
        let campaign = |name: &str, guest_args: &[&str]| {
            let out = guest.dir.path().join(name);
            let mut args = vec![
                "--gens",
                "16",
                "--spec",
                spec.to_str().unwrap(),
                "--out-dir",
                out.to_str().unwrap(),
                "--format",
                "json",
                "--",
            ];
            args.extend_from_slice(guest_args);
            let envelope = campaign_json_stdout(&guest.command("campaign", &args));
            (out, envelope)
        };
        let classes = |envelope: &serde_json::Value| -> BTreeMap<String, u64> {
            envelope["classes"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(class, count)| (class.clone(), count.as_u64().unwrap()))
                .filter(|(_, count)| *count > 0)
                .collect()
        };

        let (red, envelope) = campaign("red", &[]);
        let red_classes = classes(&envelope);
        assert!(red_classes.contains_key("VIOLATION"), "{envelope:#}");
        assert!(
            red_classes
                .keys()
                .all(|class| class == "OK" || class == "VIOLATION"),
            "{envelope:#}"
        );
        let (_, envelope) = campaign("green", &["--fsync-log"]);
        assert_eq!(
            classes(&envelope).into_keys().collect::<Vec<_>>(),
            ["OK"],
            "{envelope:#}"
        );

        let violation = envelope_generation(&red, "VIOLATION");
        let reduced = assert_success(
            invoke_with_deadline(
                env!("CARGO_BIN_EXE_cargo-patina"),
                native_workspace(),
                &[
                    "minimize",
                    "--generation",
                    &violation,
                    "--out-dir",
                    red.to_str().unwrap(),
                    "--marker",
                    "LOST",
                ],
                Duration::from_secs(120),
            )
            .expect("minimize exceeded 120s"),
        );
        let stdout = String::from_utf8_lossy(&reduced.stdout).into_owned();
        let complete = stdout
            .lines()
            .find_map(|line| line.strip_prefix("PATINA_MINIMIZE_GENERATION_COMPLETE "))
            .unwrap_or_else(|| panic!("no completion line:\n{stdout}"));
        let field = |key: &str| -> String {
            complete
                .split(' ')
                .find_map(|field| field.strip_prefix(&format!("{key}=")))
                .unwrap_or_else(|| panic!("no {key} in {complete}"))
                .to_owned()
        };
        assert!(
            stdout.contains("--machine-crash-permille"),
            "the reduction dropped the crash it needs:\n{stdout}"
        );
        assert_eq!(
            lifecycle(Path::new(&field("output"))),
            ["start", "crash", "restart", "start", "end"]
        );
        let (before, after): (u64, u64) = (
            field("knobs_before").parse().unwrap(),
            field("knobs_after").parse().unwrap(),
        );
        assert!(after < before, "the fault knobs did not shrink:\n{stdout}");
    }

    /// The first generation of a campaign out-dir classed `class`.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn envelope_generation(out: &Path, class: &str) -> String {
        let state: serde_json::Value =
            serde_json::from_slice(&fs::read(out.join("campaign-state.json")).unwrap()).unwrap();
        state["notable_runs"]
            .as_array()
            .unwrap()
            .iter()
            .find(|run| run["class"] == class)
            .unwrap_or_else(|| panic!("no {class} generation in {state:#}"))["generation"]
            .to_string()
    }
}
