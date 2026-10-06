//! Tests for filesystem crash injection and restart images.

use crate::builder::RuntimeBuilder;
use crate::config::RuntimeConfig;
use crate::fs_crash::CrashOp;
use crate::{Context, RuntimeError, TornGranularity};
use patina_dst_abi::{OpenFlags, SeekWhence};

use patina_dst_fs_crash::CrashFs;

use patina_dst_fs_mem::MemFs;

use tempfile::tempdir;

#[test]
fn crash_filesystem_record_and_replay_restore_the_synced_checkpoint() {
    fn exercise(context: &mut Context) -> Result<Vec<u8>, RuntimeError> {
        let fd = context.fs_open("/state", OpenFlags::create_truncate_write())?;
        context.fs_write(fd, b"stable")?;
        context.fs_sync(fd)?;
        let dir = context.fs_open("/", OpenFlags::read_only())?;
        context.fs_sync(dir)?;
        context.fs_close(dir)?;
        context.fs_write(fd, b"-volatile")?;
        context.fs_crash()?;
        // A crash rolls back DATA; it cannot invalidate the guest's own
        // descriptor (see `patina-dst-fs-crash`: no power loss reaches into
        // a running process to close its files, and an `EBADF` here would
        // ask the guest to tolerate an impossible failure). Probe with a
        // read-only op so the check itself does not perturb the image the
        // record/replay comparison below depends on.
        assert!(context.fs_fd_metadata(fd).is_ok());
        context.read_file("/state")
    }

    let directory = tempdir().unwrap();
    let trace = directory.path().join("crash.patina");
    let config = RuntimeConfig::record(71, &trace, "crash-v1");
    let mut record = RuntimeBuilder::new(config)
        .with_default_drivers()
        .with_filesystem(CrashFs::default())
        .build()
        .unwrap();
    assert_eq!(exercise(&mut record).unwrap(), b"stable");
    record.finish().unwrap();

    let config = RuntimeConfig::replay(&trace, "crash-v1");
    let mut replay = RuntimeBuilder::new(config)
        .with_default_drivers()
        .with_filesystem(CrashFs::default())
        .build()
        .unwrap();
    assert_eq!(exercise(&mut replay).unwrap(), b"stable");
    replay.finish().unwrap();
}

#[test]
fn crash_torn_writes_record_and_replay_reproduce_the_same_image() {
    fn crash_fs() -> CrashFs {
        CrashFs::builder()
            .seed(9)
            .torn_write_granularity(2)
            .torn_write_probability(0.5)
            .build()
            .unwrap()
    }

    fn exercise(context: &mut Context) -> Result<Vec<u8>, RuntimeError> {
        let fd = context.fs_open("/log", OpenFlags::create_truncate_write())?;
        context.fs_write(fd, b"AAAAAAAA")?;
        context.fs_sync(fd)?;
        let dir = context.fs_open("/", OpenFlags::read_only())?;
        context.fs_sync(dir)?;
        context.fs_close(dir)?;
        context.fs_seek(fd, 0, SeekWhence::Start)?;
        context.fs_write(fd, b"BBBBBBBB")?;
        context.fs_crash()?;
        // The pre-crash handle stays live across the crash; only the bytes
        // roll back. Probed read-only so the check does not perturb the
        // torn image this test compares across record and replay.
        assert!(context.fs_fd_metadata(fd).is_ok());
        context.read_file("/log")
    }

    let directory = tempdir().unwrap();
    let trace = directory.path().join("torn.patina");
    let config = RuntimeConfig::record(3, &trace, "crash-torn-v1");
    let mut record = RuntimeBuilder::new(config)
        .with_default_drivers()
        .with_filesystem(crash_fs())
        .build()
        .unwrap();
    let recorded = exercise(&mut record).unwrap();
    record.finish().unwrap();

    // The seeded tear is a real per-block mix, not a whole-image outcome.
    assert_eq!(recorded.len(), 8);
    assert!(
        recorded
            .chunks(2)
            .all(|block| block == b"AA" || block == b"BB")
    );
    assert!(recorded.chunks(2).any(|block| block == b"AA"));
    assert!(recorded.chunks(2).any(|block| block == b"BB"));

    let config = RuntimeConfig::replay(&trace, "crash-torn-v1");
    let mut replay = RuntimeBuilder::new(config)
        .with_default_drivers()
        .with_filesystem(crash_fs())
        .build()
        .unwrap();
    assert_eq!(exercise(&mut replay).unwrap(), recorded);
    replay.finish().unwrap();
}

// Structural guard for the "parsed fault knob silently ignored because a
// pre-installed filesystem bypassed the config" gap class: an explicit
// filesystem MUST NOT coexist with config-driven crash knobs. `build` fails
// closed instead of dropping them. (The historical bug installed a default
// CrashFs and let `--fs-torn-granularity byte` be silently ignored.)
#[test]
fn explicit_filesystem_with_crash_knobs_fails_closed() {
    // `Context` is not `Debug`, so assert on the Result shape directly.
    // Explicit filesystem + a crash point -> refuse.
    let result = RuntimeBuilder::new(RuntimeConfig::seeded(1).with_crash_at(CrashOp::Write, 1))
        .with_default_drivers()
        .with_filesystem(CrashFs::default())
        .build();
    assert!(matches!(result, Err(RuntimeError::Config(_))));

    // Explicit filesystem + a non-default torn granularity -> refuse, even
    // with no crash point, because the granularity would be dropped.
    let result = RuntimeBuilder::new(
        RuntimeConfig::seeded(1).with_fs_torn_granularity(TornGranularity::Byte),
    )
    .with_default_drivers()
    .with_filesystem(CrashFs::default())
    .build();
    assert!(matches!(result, Err(RuntimeError::Config(_))));

    // An explicit filesystem with NO crash knobs is still fine (tests /
    // embedders that drive `fs_crash` manually).
    assert!(
        RuntimeBuilder::new(RuntimeConfig::seeded(1))
            .with_default_drivers()
            .with_filesystem(CrashFs::default())
            .build()
            .is_ok()
    );

    // Supplying both a base image and an explicit filesystem is ambiguous.
    let result = RuntimeBuilder::new(RuntimeConfig::seeded(1))
        .with_default_drivers()
        .with_filesystem(MemFs::new())
        .with_fs_image(MemFs::new())
        .build();
    assert!(matches!(result, Err(RuntimeError::Config(_))));
}

#[test]
fn fs_crash_at_counts_only_successful_boundaries() {
    let mut context = Context::from_config(
        RuntimeConfig::seeded(1)
            .with_crash_at(CrashOp::Open, 1)
            .require_crash_selector_reached(),
    )
    .unwrap();
    let bad = context
        .fs_open("/missing", OpenFlags::read_only())
        .expect_err("failed open must not trigger crash");
    assert!(matches!(bad, RuntimeError::Effect(_)));
    let error = context.finish().unwrap_err();
    match error {
        RuntimeError::CrashSelectorUnreached { counts, .. } => {
            assert_eq!(counts.open, 0);
        }
        other => panic!("expected unreached crash selector, got {other}"),
    }
}

#[test]
fn restarted_incarnation_never_fires_the_crash_selector() {
    let mut context = Context::from_config(
        RuntimeConfig::seeded(1)
            .with_crash_at(CrashOp::Open, 1)
            .with_incarnation(1),
    )
    .unwrap();
    context
        .fs_open("/", OpenFlags::read_only())
        .expect("incarnation 1 starts after the selector fired");
    context.finish().unwrap();
}

// The single choke point builds the crash filesystem from the fault config:
// a base image + `--fs-crash-at` + `--fs-torn-granularity byte` yields a
// sub-block partial tear, while the default (block) granularity reverts the
// final write wholesale. This is the runtime-level guarantee the shim relies
// on instead of constructing the CrashFs itself.
#[test]
fn fs_image_choke_point_honors_configured_torn_granularity() {
    fn recovered_image(granularity: TornGranularity) -> Vec<u8> {
        let mut config = RuntimeConfig::seeded(1).with_crash_at(CrashOp::Write, 2);
        if granularity == TornGranularity::Byte {
            config = config.with_fs_torn_granularity(TornGranularity::Byte);
        }
        let mut context = RuntimeBuilder::new(config)
            .with_default_drivers()
            .with_fs_image(MemFs::new())
            .build()
            .unwrap();
        // Durable baseline, then one unsynced overwrite (crash fires after
        // this second write), then read the recovered image.
        let fd = context
            .fs_open("/f", OpenFlags::create_truncate_write())
            .unwrap();
        context.fs_write_at(fd, 0, &[b'A'; 16]).unwrap(); // write 1
        context.fs_sync(fd).unwrap();
        let dir = context.fs_open("/", OpenFlags::read_only()).unwrap();
        context.fs_sync(dir).unwrap();
        context.fs_close(dir).unwrap();
        let _ = context.fs_write_at(fd, 0, &[b'B'; 16]); // write 2 -> crash
        context.read_file("/f").unwrap_or_default()
    }

    let block = recovered_image(TornGranularity::Block);
    let byte = recovered_image(TornGranularity::Byte);
    assert_eq!(
        block,
        vec![b'A'; 16],
        "block granularity should revert wholesale"
    );
    assert_ne!(
        byte, block,
        "byte granularity should not match the block revert"
    );
    assert!(
        byte.contains(&b'B') && byte.contains(&b'A'),
        "byte granularity should leave a partial live/durable mix: {byte:?}"
    );
}

// Regression for two bugs the shim/WASI paths hit, both via
// `with_default_drivers` WITHOUT `with_fs_image` (exactly what
// `Context::from_config` — the WASI `wasi-run` path — does), knob-free:
//   (a) the choke point used `MemFs::default()` as the base, which is
//       ROOTLESS (no `/`), so every path op (create_dir/open) failed with
//       NotFound; it must use `MemFs::new()`.
//   (b) a bare `MemFs` cannot crash — `crash()` returns `InvalidState`
//       (errno 13) — so imperative `fs_crash()` callers broke; the base must
//       be wrapped in a `CrashFs`.
// This single test exercises both: a rooted directory/file op AND a manual
// crash with no `--fs-crash-at` configured.
#[test]
fn context_from_config_filesystem_is_rooted_and_crashable() {
    let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
    // (a) Rooted: create a directory and a file under `/`, write, sync.
    context.fs_create_directory("/state", 0o777).unwrap();
    let root = context.fs_open("/", OpenFlags::read_only()).unwrap();
    context.fs_sync(root).unwrap();
    context.fs_close(root).unwrap();
    let fd = context
        .fs_open("/state/value", OpenFlags::create_truncate_write())
        .unwrap();
    context.fs_write_at(fd, 0, b"durable").unwrap();
    context.fs_sync(fd).unwrap();
    let state = context.fs_open("/state", OpenFlags::read_only()).unwrap();
    context.fs_sync(state).unwrap();
    context.fs_close(state).unwrap();
    context.fs_write_at(fd, 0, b"volatile").unwrap(); // unsynced overwrite
    // (b) Crashable: an imperative crash with NO crash_at must succeed and
    // drop the unsynced overwrite back to the durable bytes.
    context
        .fs_crash()
        .expect("imperative fs_crash must succeed");
    assert_eq!(context.read_file("/state/value").unwrap(), b"durable");
}
