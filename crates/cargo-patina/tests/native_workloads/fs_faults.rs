//! Calls under filesystem faults: a fault reaches only the guest's own
//! operations, never the kernel's internal reads (a page cache filling, an
//! inode's size, the path walk).

use super::*;

/// A mapped file's page cache is the whole file whatever the filesystem faults
/// do to the guest's own I/O: it is sized from the file's size and filled by a
/// read no fault reaches. So every page of a `MAP_SHARED` view is backed and
/// holds the file's bytes, `mmap` answers no injected errno, and the reload
/// after an in-process crash is whole too. RED before: a short injected read
/// sized the page cache to the bytes it returned, so the first store past them
/// was `SIGBUS`, and an injected error failed `mmap` with `EIO`. Class pairing:
/// the shim's `clippy.toml` keeps the faulted content reads out of everything
/// but the guest's own read funnels.
#[test]
fn a_mapped_file_is_whole_under_filesystem_faults() {
    let g = Guest::assert_build("mmap_short_read_probe.rs");
    for mode in [&[][..], &["--env", "MMAP_SHORT_READ_MODE=crash"]] {
        for faults in [
            ["--fs-short-permille", "1000"],
            ["--fs-error-permille", "500"],
        ] {
            let flags = [&faults[..], mode].concat();
            let out = g.assert_seeded_record_replay_identity(1, &flags);
            assert_eq!(
                assert_unique_line_payload(&out, "NATIVE_MMAP_SHORT_READ "),
                "pages_written=64",
                "{flags:?}"
            );
        }
    }
}

/// What `inode_read_fault_probe.rs` prints for each call Linux answers from
/// in-memory inode and file state: a 4096-byte file read from offset 1000, and
/// every other call succeeding (`copy_file_range` copies nothing from the end
/// of its source and refuses an overlap within one file).
#[cfg(target_os = "linux")]
const INODE_READ_ANSWERS: [(&str, &str); 9] = [
    ("fionread", "3096"),
    ("fioqsize", "4096"),
    ("lock_end", "0"),
    ("fchdir", "0"),
    ("copy_file_range", "at_end=0 overlap=EINVAL"),
    ("name_to_handle_at", "0"),
    ("utimensat_fd", "0"),
    ("fchown_file", "0"),
    ("fchown_fifo", "0"),
];

/// A call the kernel answers from the in-memory inode gets Linux's answer
/// under filesystem faults, and the shim's inode read inside it draws no
/// fault. The probe never calls `fstat` itself, so a run whose fault report
/// attributes an injected error to `fd_metadata` has a shim step that read
/// the inode through the guest's `fstat`. That attribution is what judges
/// `utimensat` and `fchown`, whose own attribute write can fail and is
/// retried. Each call runs alone so a failure names its site; the whole probe
/// then repeats and replays under the same faults. RED before: each site read
/// the inode through the faulted `fstat`, so the calls that do no I/O failed
/// with `EIO` and every site drew `fd_metadata` faults.
#[cfg(target_os = "linux")]
#[test]
fn in_memory_inode_reads_answer_under_filesystem_faults() {
    let g = Guest::assert_build("inode_read_fault_probe.rs");
    let faults = ["--fs-error-permille", "500", "--fs-short-permille", "1000"];
    for (site, expected) in INODE_READ_ANSWERS {
        let env = format!("INODE_READ_SITE={site}");
        let run = ["--seed", "1", "--env", &env, "--format", "json"];
        let output = g.command("run", &[&faults[..], &run].concat());
        assert!(
            output.status.success(),
            "{site}: {}: {}{}",
            output.status,
            text(&output.stdout),
            text(&output.stderr)
        );
        let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let stdout = envelope["stdout"].as_str().unwrap();
        let prefix = format!("NATIVE_INODE_READ {site} ");
        assert_eq!(
            assert_unique_line_payload(stdout.as_bytes(), &prefix),
            expected,
            "{site}"
        );
        let errors = &envelope["fault_reports"]["fs"]["errors_by_op"];
        assert!(errors.is_object(), "{site}: {envelope:#}");
        assert_eq!(errors.get("fd_metadata"), None, "{site}: {errors}");
    }
    let out = g.assert_seeded_record_replay_identity(1, &faults);
    for (site, expected) in INODE_READ_ANSWERS {
        let prefix = format!("NATIVE_INODE_READ {site} ");
        assert_eq!(assert_unique_line_payload(&out, &prefix), expected);
    }
}

/// What `path_walk_fault_probe.rs` prints in its `lookups` mode for each call
/// that is nothing but a path walk through `..` and `.`: Linux's answer
/// (`/tmp` is a directory that exists, `/tmp/absent` does not).
#[cfg(target_os = "linux")]
const PATH_WALK_ANSWERS: [(&str, &str); 4] = [
    ("statfs", "0"),
    ("inotify_add_watch", "1"),
    ("realpath", "/tmp"),
    ("missing", "errno2"),
];

/// The path walk is the kernel's own lookups, so no filesystem fault reaches
/// it; only the call's own operation draws one. Under certain filesystem
/// errors a call that is only a walk gets Linux's answer, and an `open` and a
/// `mkdir` through a walk fail on their own operations, with no injected
/// error landing on a lookup. Under a partial rate, the same rounds of `open`,
/// `stat` and `mkdir` spelled directly and through `..`, `.` and a symlink
/// draw the same fault stream, so they get the same answers under one seed,
/// and each spelling replays. RED before: every lookup of the walk drew a
/// `metadata` fault (and a symlink a `read_link` one), so the walk-only calls
/// failed with `EIO`, the fault report charged errors to `metadata`, and a
/// longer spelling shifted every later call's draw.
#[cfg(target_os = "linux")]
#[test]
fn the_path_walk_draws_no_filesystem_fault() {
    let g = Guest::assert_build("path_walk_fault_probe.rs");
    let run = [
        "--fs-error-permille",
        "1000",
        "--seed",
        "1",
        "--env",
        "PATH_WALK_MODE=lookups",
        "--format",
        "json",
    ];
    let output = g.command("run", &run);
    assert!(
        output.status.success(),
        "{}: {}{}",
        output.status,
        text(&output.stdout),
        text(&output.stderr)
    );
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let stdout = envelope["stdout"].as_str().unwrap();
    for (call, expected) in PATH_WALK_ANSWERS {
        let prefix = format!("NATIVE_PATH_WALK {call} ");
        assert_eq!(
            assert_unique_line_payload(stdout.as_bytes(), &prefix),
            expected,
            "{call}"
        );
    }
    let injected = [libc::EIO, libc::ENOSPC, libc::EINTR].map(|errno| format!("errno{errno}"));
    for call in ["open", "mkdir"] {
        let prefix = format!("NATIVE_PATH_WALK {call} ");
        let answer = assert_unique_line_payload(stdout.as_bytes(), &prefix);
        assert!(
            injected.iter().any(|errno| errno == answer),
            "{call}: {answer}"
        );
    }
    let errors = &envelope["fault_reports"]["fs"]["errors_by_op"];
    assert_eq!(
        errors,
        &serde_json::json!({"open": 1, "create_directory": 1}),
        "{envelope:#}"
    );
    let faults = ["--fs-error-permille", "500"];
    let answers = ["plain", "walked"].map(|mode| {
        let env = format!("PATH_WALK_MODE={mode}");
        let out =
            g.assert_seeded_record_replay_identity(1, &[&faults[..], &["--env", &env]].concat());
        assert_unique_line_payload(&out, "NATIVE_PATH_WALK rounds ").to_owned()
    });
    let [plain, walked] = &answers;
    assert_eq!(plain, walked);
    let answers: Vec<&str> = plain.split(',').collect();
    assert!(
        answers.contains(&"0") && answers.iter().any(|answer| answer.starts_with("errno")),
        "the rate must fail some calls and pass others: {plain}"
    );
}

/// Calls that do no filesystem I/O answer from memory in Linux (an inode's
/// size, a lock table, the descriptor table, the working directory), so no
/// filesystem fault reaches one: `fault_plane_probe.rs` gets the same answers
/// with every filesystem operation faulted as with none, and the faulted run
/// draws no fault at all. Run with and without `--cwd`, whose directory the
/// run installs before the guest starts. A regression pin for the fixes that
/// moved each of these reads off the guest's faulted queries; the
/// `Bookkeeping` view, which keeps the shim's internal modules off them by
/// type, is not what it checks. RED with any one row's fix reverted:
/// `FIONREAD`, a `SEEK_END` lock, `mmap`, `cachestat` and `fchdir` read the
/// size or mode through the guest's faulted `fstat`; the first `getcwd`
/// opened `/` through a faulted open; `open` at `RLIMIT_NOFILE` reached the
/// driver before it found no number free; and `--cwd` refused the run.
#[cfg(target_os = "linux")]
#[test]
fn calls_without_filesystem_io_draw_no_filesystem_fault() {
    let g = Guest::assert_build("fault_plane_probe.rs");
    for cwd in [&[][..], &["--cwd", "/tmp"]] {
        let [calm, faulted] = ["0", "1000"].map(|permille| {
            let rates = [
                "--fs-error-permille",
                permille,
                "--fs-short-permille",
                permille,
            ];
            let run = [&rates[..], &["--seed", "1", "--format", "json"], cwd].concat();
            let output = g.command("run", &run);
            assert!(
                output.status.success(),
                "{cwd:?} at {permille}: {}: {}{}",
                output.status,
                text(&output.stdout),
                text(&output.stderr)
            );
            let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            // The run reports no filesystem fault plane when no operation
            // was eligible for a fault.
            let eligible = envelope["fault_reports"]["fs"]["eligible_ops"].as_u64();
            assert_eq!(eligible.unwrap_or(0), 0, "{cwd:?}: {envelope:#}");
            let stdout = envelope["stdout"].as_str().unwrap();
            stdout
                .lines()
                .filter(|line| line.starts_with("NATIVE_FAULT_PLANE "))
                .map(str::to_owned)
                .collect::<Vec<_>>()
        });
        assert!(!calm.is_empty(), "{cwd:?}: the probe printed no rows");
        assert_eq!(calm, faulted, "{cwd:?}");
    }
}
