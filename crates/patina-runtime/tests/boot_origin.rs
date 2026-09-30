//! Class detector: translating uptime must not translate elapsed execution,
//! fault windows, CPU charges or deadline ordering. Native boot_origin.c is
//! the ABI-level pairing; realtime_epoch.rs covers epoch reconciliation.
use patina_dst_abi::ClockKind;
use patina_dst_runtime::{
    BuggifyConfig, Context, DEFAULT_BOOT_ORIGIN_NANOS, DEFAULT_REALTIME_EPOCH_NANOS,
    LivenessConfig, RuntimeBuilder, RuntimeConfig, RuntimeError, SiteOutcome,
};
use patina_dst_time_virtual::VirtualClock;
use patina_dst_trace::TraceBundle;

fn workload(ctx: &mut Context) -> (u64, u64) {
    let start = ctx.now(ClockKind::Monotonic).unwrap();
    let real = ctx.now(ClockKind::Realtime).unwrap();
    assert_eq!(real - start, DEFAULT_REALTIME_EPOCH_NANOS);
    let cpu = ctx.cpu_time_nanos();
    assert_eq!(
        ctx.buggify_evaluate("fault", "origin-test", None).unwrap(),
        SiteOutcome::Fire
    );
    ctx.sleep_until(ClockKind::Monotonic, 1).unwrap();
    assert_eq!(ctx.now(ClockKind::Monotonic).unwrap(), start);
    ctx.sleep_until(ClockKind::Realtime, real + 7).unwrap();
    assert_eq!(ctx.now(ClockKind::Monotonic).unwrap(), start + 7);
    ctx.sleep_for(13).unwrap();
    assert_eq!(
        ctx.buggify_evaluate("fault", "origin-test", None).unwrap(),
        SiteOutcome::Ok
    );
    assert!(ctx.buggify_diagnostics().cutoff_reached);
    assert_eq!(ctx.cpu_time_nanos(), cpu, "sleep is not CPU time");
    let before_spin = ctx.now(ClockKind::Monotonic).unwrap();
    while ctx.now(ClockKind::Monotonic).unwrap() == before_spin {}
    let elapsed = ctx.now(ClockKind::Monotonic).unwrap() - start;
    let charge = ctx.cpu_time_nanos() - cpu;
    assert_eq!(elapsed, 20 + charge);
    assert!(charge > 0);
    (elapsed, charge)
}

fn faults(config: RuntimeConfig) -> RuntimeConfig {
    config.with_buggify(BuggifyConfig {
        enabled: true,
        activation_permille: 1000,
        fire_permille: 1000,
        cutoff_nanos: 20,
        after_setup: false,
    })
}

#[test]
fn uptime_translation_preserves_elapsed_fault_windows_and_cpu_accounting() {
    let mut results = Vec::new();
    for origin in [DEFAULT_BOOT_ORIGIN_NANOS, 98_765_432_109_876] {
        let mut ctx = Context::from_config(faults(
            RuntimeConfig::seeded(3).with_boot_origin_nanos(origin),
        ))
        .unwrap();
        assert_eq!(ctx.monotonic_now_unrecorded().unwrap(), origin);
        results.push(workload(&mut ctx));
        ctx.finish().unwrap();
    }
    assert_eq!(results[0], results[1]);
}

#[test]
fn recorded_origin_is_authoritative_for_replay_branch_and_installed_clocks() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("origin.patina");
    let origin = DEFAULT_BOOT_ORIGIN_NANOS + 987_654_321;
    let mut record = Context::from_config(faults(
        RuntimeConfig::record(3, &path, "origin+buggify").with_boot_origin_nanos(origin),
    ))
    .unwrap();
    let expected = workload(&mut record);
    record.finish().unwrap();
    assert_eq!(
        TraceBundle::load(&path).unwrap().metadata.boot_origin_nanos,
        origin
    );
    let mut replay = Context::from_config(RuntimeConfig::replay(&path, "origin+buggify")).unwrap();
    assert_eq!(replay.monotonic_now_unrecorded().unwrap(), origin);
    assert_eq!(workload(&mut replay), expected);
    replay.finish().unwrap();
    for config in [
        RuntimeConfig::replay(&path, "origin+buggify").with_boot_origin_nanos(origin + 1),
        RuntimeConfig::seeded(1).with_boot_origin_nanos(0),
        RuntimeConfig::seeded(1).with_boot_origin_nanos(u64::MAX),
    ] {
        assert!(matches!(
            Context::from_config(config),
            Err(RuntimeError::Config(_))
        ));
    }
    assert!(
        RuntimeBuilder::new(RuntimeConfig::replay(&path, "origin+buggify"))
            .with_default_drivers()
            .with_clock(VirtualClock::default())
            .build()
            .is_err()
    );
    let mut branch = Context::from_config(RuntimeConfig::branch(
        &path,
        "main",
        1,
        "branch",
        3,
        "origin+buggify",
    ))
    .unwrap();
    assert_eq!(branch.monotonic_now_unrecorded().unwrap(), origin);
    assert_eq!(workload(&mut branch), expected);
    branch.finish().unwrap();

    let custom_path = dir.path().join("custom.patina");
    let mut custom = RuntimeBuilder::new(RuntimeConfig::record(3, &custom_path, "custom"))
        .with_default_drivers()
        .with_clock(VirtualClock::at(origin, DEFAULT_REALTIME_EPOCH_NANOS))
        .build()
        .unwrap();
    assert_eq!(custom.now(ClockKind::Monotonic).unwrap(), origin);
    custom.finish().unwrap();
    assert_eq!(
        TraceBundle::load(&custom_path)
            .unwrap()
            .metadata
            .boot_origin_nanos,
        origin
    );
    assert!(
        RuntimeBuilder::new(RuntimeConfig::seeded(1).with_boot_origin_nanos(origin + 1))
            .with_clock(VirtualClock::at(origin, DEFAULT_REALTIME_EPOCH_NANOS))
            .build()
            .is_err()
    );
}

// Class pairing: translation invariance above, extended to the signed clock
// boundary. Refuse both an invalid uptime and a valid uptime with invalid wall time.
#[test]
fn boot_origin_signed_bounds_apply_to_config_installed_clocks_and_replay() {
    let max = i64::MAX as u64;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bounds.patina");
    let mut record = Context::from_config(RuntimeConfig::record(1, &path, "bounds")).unwrap();
    record.now(ClockKind::Monotonic).unwrap();
    record.finish().unwrap();
    let mut bundle = TraceBundle::load(&path).unwrap();
    for (origin, epoch) in [
        (0, 0),
        (max + 1, 0),
        (u64::MAX - 1, 0),
        (max, 1),
        (1, u64::MAX),
    ] {
        assert!(matches!(
            Context::from_config(
                RuntimeConfig::seeded(1)
                    .with_boot_origin_nanos(origin)
                    .with_realtime_epoch_nanos(epoch)
            ),
            Err(RuntimeError::Config(_))
        ));
        assert!(
            RuntimeBuilder::new(RuntimeConfig::seeded(1))
                .with_default_drivers()
                .with_clock(VirtualClock::at(origin, epoch))
                .build()
                .is_err()
        );
        bundle.metadata.boot_origin_nanos = origin;
        bundle.metadata.realtime_epoch_nanos = epoch;
        bundle.write_atomic(&path).unwrap();
        for config in [
            RuntimeConfig::replay(&path, "bounds"),
            RuntimeConfig::branch(&path, "main", 1, "branch", 1, "bounds"),
        ] {
            assert!(matches!(
                Context::from_config(config),
                Err(RuntimeError::Config(_))
            ));
        }
    }
    // Inclusive bound, using the installed clock's epoch, not the unused default.
    let mut ctx = RuntimeBuilder::new(RuntimeConfig::seeded(1))
        .with_default_drivers()
        .with_clock(VirtualClock::at(max, 0))
        .build()
        .unwrap();
    assert_eq!(ctx.now(ClockKind::Realtime).unwrap(), max);
}

#[test]
fn relative_sleep_saturates_at_the_deadline_limit() {
    let mut ctx = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
    ctx.sleep_for(u64::MAX).unwrap();
    assert_eq!(ctx.now(ClockKind::Monotonic).unwrap(), u64::MAX);
    ctx.finish().unwrap();
}

#[test]
fn convergence_window_is_run_relative_but_diagnostics_are_absolute() {
    for origin in [DEFAULT_BOOT_ORIGIN_NANOS, DEFAULT_BOOT_ORIGIN_NANOS * 2] {
        let mut ctx = Context::from_config(
            RuntimeConfig::seeded(3)
                .with_boot_origin_nanos(origin)
                .with_liveness(LivenessConfig {
                    no_progress_budget_nanos: None,
                    converge_budget_nanos: Some(10),
                    heal_after_nanos: Some(100),
                }),
        )
        .unwrap();
        for _ in 0..10 {
            ctx.sleep_for(5).unwrap();
        }
        assert!(ctx.run_facts().get("runtime_findings").is_none());
        let error = loop {
            if let Err(error) = ctx.sleep_for(5) {
                break error;
            }
        };
        assert!(matches!(error, RuntimeError::Liveness { .. }));
        let facts = ctx.run_facts();
        let finding = &facts["runtime_findings"][0];
        assert_eq!(
            finding["last_fault_vtime_ns"].as_u64().unwrap(),
            origin + 100
        );
        assert!(finding["vtime_ns"].as_u64().unwrap() > origin + 110);
    }
}
