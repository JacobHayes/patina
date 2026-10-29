//! Tests for crash points, crash kinds and restart images.

use crate::builder::RuntimeBuilder;
use crate::config::RuntimeConfig;
use crate::crash::{CrashArm, Incarnation, RESTART_DOWNTIME_NANOS};
use crate::{
    Context, DEFAULT_BOOT_ORIGIN_NANOS, DEFAULT_REALTIME_EPOCH_NANOS, EntropyWait, RuntimeError,
};
use patina_dst_abi::{ClockKind, CrashKind, OpenFlags, SeekWhence};
use std::num::NonZeroU64;

use patina_dst_fs_crash::CrashFs;

use patina_dst_fs_mem::MemFs;

use tempfile::tempdir;

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
// CrashFs and let a crash knob be silently ignored.)
#[test]
fn explicit_filesystem_with_crash_knobs_fails_closed() {
    // `Context` is not `Debug`, so assert on the Result shape directly.
    // Explicit filesystem + a crash rate -> refuse.
    let result = RuntimeBuilder::new(
        RuntimeConfig::seeded(1)
            .with_crash_permille(1)
            .with_crash_supervisor(),
    )
    .with_default_drivers()
    .with_filesystem(CrashFs::default())
    .build();
    assert!(matches!(result, Err(RuntimeError::Config(_))));

    // Explicit filesystem + a non-default crash kind -> refuse, even with no
    // crash rate, because the kind would be dropped.
    let result = RuntimeBuilder::new(RuntimeConfig::seeded(1).with_crash_kind(CrashKind::Process))
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

/// A supervised run that crashes at every crash point.
fn certain_crash(seed: u64, kind: CrashKind) -> RuntimeConfig {
    RuntimeConfig::seeded(seed)
        .with_crash_permille(1000)
        .with_crash_kind(kind)
        .with_crash_supervisor()
}

/// Only a completed crash point can be where the run crashes: a failed
/// operation and one with no effect a crash could cut short (a read-only
/// open) never are, and the first that is crashes.
#[test]
fn a_crash_follows_the_first_successful_crash_point() {
    let mut context = Context::from_config(certain_crash(1, CrashKind::Machine)).unwrap();
    let missing = context.fs_remove_file("/missing").err();
    assert!(
        !matches!(missing, Some(RuntimeError::InjectedCrash(_))),
        "a failed crash point crashed: {missing:?}"
    );
    context
        .fs_open("/", OpenFlags::read_only())
        .expect("a read-only open is no crash point");
    match context.fs_open("/f", OpenFlags::create_truncate_write()) {
        Err(RuntimeError::InjectedCrash(crash)) => {
            assert_eq!(crash.kind, CrashKind::Machine);
            assert_eq!(crash.consumed.operations, 3);
        }
        other => panic!("expected the crash at the creating open, got {other:?}"),
    }
}

/// A run crashes at most once, in incarnation 0: a restarted incarnation
/// takes no crash, and a live run with a crash rate but no supervisor to boot
/// the next incarnation is refused.
#[test]
fn only_a_supervised_first_incarnation_crashes() {
    let mut context = Context::from_config(
        certain_crash(1, CrashKind::Machine)
            .with_incarnation(restarted(DEFAULT_REALTIME_EPOCH_NANOS)),
    )
    .unwrap();
    context
        .fs_open("/f", OpenFlags::create_truncate_write())
        .expect("incarnation 1 boots after the run's crash");
    context.finish().unwrap();

    assert!(matches!(
        Context::from_config(RuntimeConfig::seeded(1).with_crash_permille(1000)),
        Err(RuntimeError::Config(_))
    ));
}

/// The image a crash hands over: from the same pre-crash run, a process
/// crash keeps an unsynced overwrite (the page cache survives), and a machine
/// crash keeps the synced bytes and, block by block, either the overwrite or
/// what was durable before it, varying across seeds.
#[test]
fn the_crash_kind_decides_the_restart_image() {
    fn restart_image(seed: u64, kind: CrashKind) -> Vec<u8> {
        let mut context = Context::from_config(RuntimeConfig::seeded(seed)).unwrap();
        let fd = context
            .fs_open("/f", OpenFlags::create_truncate_write())
            .unwrap();
        context.fs_write_at(fd, 0, &[b'A'; 16]).unwrap();
        context.fs_sync(fd).unwrap();
        let dir = context.fs_open("/", OpenFlags::read_only()).unwrap();
        context.fs_sync(dir).unwrap();
        context.fs_close(dir).unwrap();
        // Armed now, so the overwrite is the crash point.
        context.crash = CrashArm::arm(true, true, false, 1000, kind, seed);
        let crash = match context.fs_write_at(fd, 0, &[b'B'; 16]) {
            Err(RuntimeError::InjectedCrash(crash)) => crash,
            other => panic!("expected the crash at the overwrite, got {other:?}"),
        };
        crash.snapshot.into_memfs().contents("/f").unwrap()
    }

    let mut machine = std::collections::BTreeSet::new();
    for seed in 0..16 {
        assert_eq!(restart_image(seed, CrashKind::Process), [b'B'; 16]);
        machine.insert(restart_image(seed, CrashKind::Machine));
    }
    assert_eq!(
        machine,
        [vec![b'A'; 16], vec![b'B'; 16]].into(),
        "a machine crash must keep the overwrite or the durable bytes, each for some seed"
    );
}

// Regression for two bugs the shim paths hit, both via
// `with_default_drivers` WITHOUT `with_fs_image` (exactly what
// `Context::from_config` does), knob-free:
//   (a) the choke point used `MemFs::default()` as the base, which is
//       ROOTLESS (no `/`), so every path op (create_dir/open) failed with
//       NotFound; it must use `MemFs::new()`.
//   (b) a bare `MemFs` cannot crash — `crash()` returns `InvalidState`
//       (errno 13) — so imperative `fs_crash()` callers broke; the base must
//       be wrapped in a `CrashFs`.
// This single test exercises both: a rooted directory/file op AND a manual
// crash with no crash knob configured.
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
    // (b) Crashable: an imperative crash with no crash knob must succeed and
    // drop the unsynced overwrite back to the durable bytes.
    context
        .fs_crash()
        .expect("imperative fs_crash must succeed");
    assert_eq!(context.read_file("/state/value").unwrap(), b"durable");
}

/// Incarnation 1, booting after a crash whose clock had reached
/// `previous_realtime_nanos`.
fn restarted(previous_realtime_nanos: u64) -> Incarnation {
    Incarnation::Restarted {
        id: NonZeroU64::MIN,
        previous_realtime_nanos,
    }
}

/// The first `len` entropy bytes a fresh context of `incarnation` draws at `seed`.
fn first_entropy(seed: u64, incarnation: Incarnation) -> Vec<u8> {
    let mut context =
        Context::from_config(RuntimeConfig::seeded(seed).with_incarnation(incarnation)).unwrap();
    let bytes = context.entropy_bytes(32, EntropyWait::UntilReady).unwrap();
    context.finish().unwrap();
    bytes
}

#[test]
fn a_restarted_incarnation_draws_its_own_streams_from_the_run_seed() {
    let first = first_entropy(11, Incarnation::First);
    let restart = first_entropy(11, restarted(DEFAULT_REALTIME_EPOCH_NANOS));
    assert_ne!(
        restart, first,
        "incarnation 1 must not repeat incarnation 0's entropy"
    );
    // Both still come from the run's seed: a different seed gives different
    // streams.
    assert_ne!(
        restart,
        first_entropy(12, restarted(DEFAULT_REALTIME_EPOCH_NANOS))
    );
}

#[test]
fn a_restarted_incarnation_boots_after_the_crashed_one_and_replays_identically() {
    // Incarnation 0 reads realtime, runs on for a while, stamps a file, and
    // crashes after its second write.
    let mut first = Context::from_config(RuntimeConfig::seeded(5)).unwrap();
    let fd = first
        .fs_open("/f", OpenFlags::create_truncate_write())
        .unwrap();
    first.fs_write(fd, b"one").unwrap();
    first.sleep_for(3_000_000_000).unwrap();
    let last_read = first.now(ClockKind::Realtime).unwrap();
    let stamped = first.fs_time_unrecorded().unwrap();
    first.crash = CrashArm::arm(true, true, false, 1000, CrashKind::Machine, 5);
    let crash = match first.fs_write(fd, b"two") {
        Err(RuntimeError::InjectedCrash(crash)) => crash,
        other => panic!("expected the injected crash, got {other:?}"),
    };
    assert!(crash.realtime_nanos >= last_read.max(stamped));

    let directory = tempdir().unwrap();
    let trace = directory.path().join("restart.patina");
    let boot = |config: RuntimeConfig| {
        let mut context =
            Context::from_config(config.with_incarnation(restarted(crash.realtime_nanos))).unwrap();
        let realtime = context.now(ClockKind::Realtime).unwrap();
        let monotonic = context.now(ClockKind::Monotonic).unwrap();
        let fd = context
            .fs_open("/g", OpenFlags::create_truncate_write())
            .unwrap();
        context.fs_write(fd, b"after").unwrap();
        // Unrecorded, so a replay answers it from its own clock and image
        // rather than from the trace.
        let modified = context.fs_fd_metadata_unrecorded(fd).unwrap().mtime_nanos;
        context.finish().unwrap();
        (realtime, monotonic, modified)
    };
    let (realtime, monotonic, modified) = boot(RuntimeConfig::record(5, &trace, "restart-v1"));
    // Realtime carries on from the crash after a downtime; monotonic time is
    // per boot and starts again at the boot origin.
    assert!(
        realtime > crash.realtime_nanos,
        "realtime ran backwards across the restart: {} ns at the crash, {realtime} ns after",
        crash.realtime_nanos
    );
    let downtime = realtime - crash.realtime_nanos;
    assert!(
        RESTART_DOWNTIME_NANOS.contains(&downtime),
        "downtime {downtime} ns is outside {RESTART_DOWNTIME_NANOS:?}"
    );
    assert!(modified > i128::from(crash.realtime_nanos));
    assert_eq!(monotonic, DEFAULT_BOOT_ORIGIN_NANOS);
    // A replay of the restarted incarnation, handed the same predecessor
    // realtime, reads and stamps exactly what the recording did.
    assert_eq!(
        boot(RuntimeConfig::replay(&trace, "restart-v1")),
        (realtime, monotonic, modified)
    );
}
