//! The virtual realtime epoch: the default every default-driver run starts on,
//! the explicit override, and its record/replay contract (recorded into the
//! trace, authoritative on replay).

use patina_dst_abi::ClockKind;
use patina_dst_runtime::{
    Context, DEFAULT_REALTIME_EPOCH_NANOS, ENV_REALTIME_EPOCH_NANOS, RuntimeBuilder, RuntimeConfig,
    RuntimeError,
};
use patina_dst_time_virtual::VirtualClock;
use patina_dst_trace::TraceBundle;
use tempfile::tempdir;

/// A non-default epoch: 2001-09-09T01:46:40Z.
const EPOCH: u64 = 1_000_000_000_000_000_000;
const STEP: u64 = 5_000;

/// The record/replay workload: advance, read realtime (recorded), create a
/// directory (stamped from realtime WITHOUT a recorded read).
fn workload(context: &mut Context) -> u64 {
    context.sleep_until(ClockKind::Monotonic, STEP).unwrap();
    let realtime = context.now(ClockKind::Realtime).unwrap();
    context.fs_create_directory("/d", 0o755).unwrap();
    realtime
}

fn record(config: RuntimeConfig) -> u64 {
    let mut context = Context::from_config(config).unwrap();
    let realtime = workload(&mut context);
    context.finish().unwrap();
    realtime
}

fn assert_config_refusal(result: Result<Context, RuntimeError>) {
    match result {
        Err(RuntimeError::Config(_)) => {}
        Err(other) => panic!("expected a configuration refusal, got {other:?}"),
        Ok(_) => panic!("expected a configuration refusal, got a runtime"),
    }
}

#[test]
fn a_default_runtime_reads_the_default_epoch_at_monotonic_zero() {
    let mut context = Context::from_config(RuntimeConfig::seeded(0)).unwrap();
    assert_eq!(context.now(ClockKind::Monotonic).unwrap(), 0);
    assert_eq!(
        context.now(ClockKind::Realtime).unwrap(),
        DEFAULT_REALTIME_EPOCH_NANOS
    );
    // The filesystem stamps from the same clock.
    context.fs_create_directory("/d", 0o755).unwrap();
    assert_eq!(
        context.fs_metadata("/d").unwrap().btime_nanos,
        DEFAULT_REALTIME_EPOCH_NANOS
    );
    assert_eq!(
        RuntimeConfig::seeded(0).realtime_epoch_nanos(),
        DEFAULT_REALTIME_EPOCH_NANOS
    );
    context.finish().unwrap();
}

#[test]
fn a_configured_epoch_overrides_the_default_directly_and_through_the_control_plane() {
    let mut direct =
        Context::from_config(RuntimeConfig::seeded(0).with_realtime_epoch_nanos(EPOCH)).unwrap();
    assert_eq!(direct.now(ClockKind::Realtime).unwrap(), EPOCH);
    direct.finish().unwrap();

    let value = EPOCH.to_string();
    let config = RuntimeConfig::seeded(0)
        .apply_realtime_epoch_env(|name| (name == ENV_REALTIME_EPOCH_NANOS).then(|| value.clone()))
        .unwrap();
    assert_eq!(config.realtime_epoch_nanos(), EPOCH);
    let mut via_env = Context::from_config(config).unwrap();
    via_env.sleep_until(ClockKind::Monotonic, STEP).unwrap();
    assert_eq!(via_env.now(ClockKind::Realtime).unwrap(), EPOCH + STEP);
    via_env.finish().unwrap();

    // Absent leaves the default; malformed fails closed.
    let unset = RuntimeConfig::seeded(0)
        .apply_realtime_epoch_env(|_| None)
        .unwrap();
    assert_eq!(unset.realtime_epoch_nanos(), DEFAULT_REALTIME_EPOCH_NANOS);
    for bad in ["", "-1", "2026-07-22T23:00:09Z", "18446744073709551616"] {
        let error = RuntimeConfig::seeded(0)
            .apply_realtime_epoch_env(|name| (name == ENV_REALTIME_EPOCH_NANOS).then(|| bad.into()))
            .expect_err(bad);
        assert!(matches!(error, RuntimeError::Config(_)), "{bad:?}: {error}");
    }
}

#[test]
fn replay_reproduces_a_recorded_non_default_epoch_without_resupplying_it() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("epoch.patina");
    let recorded =
        record(RuntimeConfig::record(3, &path, "epoch-v1").with_realtime_epoch_nanos(EPOCH));
    assert_eq!(recorded, EPOCH + STEP);
    let bundle = TraceBundle::load(&path).unwrap();
    assert_eq!(bundle.metadata.realtime_epoch_nanos, EPOCH);

    // Flag-free replay: the recorded read comes back from the trace, and the
    // clock the filesystem stamps from runs on the recorded epoch — an
    // unrecorded read, so only the adopted epoch can make it match.
    let mut replay = Context::from_config(RuntimeConfig::replay(&path, "epoch-v1")).unwrap();
    assert_eq!(workload(&mut replay), recorded);
    assert_eq!(replay.fs_time_unrecorded().unwrap(), EPOCH + STEP);
    replay.finish().unwrap();

    // A branch inherits the parent's epoch the same way.
    let mut branch =
        Context::from_config(RuntimeConfig::branch(&path, "main", 1, "b1", 9, "epoch-v1")).unwrap();
    assert_eq!(branch.fs_time_unrecorded().unwrap(), EPOCH);
    drop(branch);

    // A matching explicit epoch is accepted; a conflicting one is refused.
    let matching = RuntimeConfig::replay(&path, "epoch-v1").with_realtime_epoch_nanos(EPOCH);
    let mut matching = Context::from_config(matching).unwrap();
    workload(&mut matching);
    matching.finish().unwrap();
    let conflicting = RuntimeConfig::replay(&path, "epoch-v1")
        .with_realtime_epoch_nanos(DEFAULT_REALTIME_EPOCH_NANOS);
    assert_config_refusal(Context::from_config(conflicting));
}

#[test]
fn a_default_epoch_run_records_the_default_epoch() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("default.patina");
    let recorded = record(RuntimeConfig::record(3, &path, "epoch-v1"));
    assert_eq!(recorded, DEFAULT_REALTIME_EPOCH_NANOS + STEP);
    let bundle = TraceBundle::load(&path).unwrap();
    assert_eq!(
        bundle.metadata.realtime_epoch_nanos,
        DEFAULT_REALTIME_EPOCH_NANOS
    );
}

#[test]
fn an_installed_clock_owns_its_epoch_and_is_reconciled_like_a_configured_one() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("clock.patina");

    // The trace records the epoch the installed clock really runs on.
    let mut context = RuntimeBuilder::new(RuntimeConfig::record(3, &path, "epoch-v1"))
        .with_default_drivers()
        .with_clock(VirtualClock::new(EPOCH))
        .build()
        .unwrap();
    workload(&mut context);
    context.finish().unwrap();
    assert_eq!(
        TraceBundle::load(&path)
            .unwrap()
            .metadata
            .realtime_epoch_nanos,
        EPOCH
    );

    // A configured epoch the installed clock would ignore is refused, and a
    // matching one is not...
    let with_clock = |config: RuntimeConfig, clock: VirtualClock| {
        RuntimeBuilder::new(config)
            .with_default_drivers()
            .with_clock(clock)
            .build()
    };
    assert_config_refusal(with_clock(
        RuntimeConfig::seeded(0).with_realtime_epoch_nanos(7),
        VirtualClock::new(EPOCH),
    ));
    with_clock(
        RuntimeConfig::seeded(0).with_realtime_epoch_nanos(EPOCH),
        VirtualClock::new(EPOCH),
    )
    .unwrap();
    // ...and so is replaying the trace on a clock with another epoch, while a
    // clock on the recorded epoch replays.
    assert_config_refusal(with_clock(
        RuntimeConfig::replay(&path, "epoch-v1"),
        VirtualClock::default(),
    ));
    let mut replay = with_clock(
        RuntimeConfig::replay(&path, "epoch-v1"),
        VirtualClock::new(EPOCH),
    )
    .unwrap();
    workload(&mut replay);
    replay.finish().unwrap();
}
