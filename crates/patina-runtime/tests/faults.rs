//! End-to-end coverage for the seed-driven fault-injection knobs, each with a
//! case that MUST exhibit the fault and a control that MUST stay clean, so no
//! knob is vacuously "working".

use std::collections::BTreeSet;

use patina_dst_abi::{ClockKind, ErrorCode, OpenFlags, SendDisposition};
use patina_dst_driver_api::{
    ClockFaultReport, CustomOpFaultReport, DnsFaultReport, EntropyFaultReport, FsFaultReport,
    NetFaultReport,
};
use patina_dst_runtime::{Context, CrashOp, RuntimeConfig, TornGranularity};
use tempfile::tempdir;

fn sync_directory(context: &mut Context, path: &str) {
    // Do not close the directory fd here: several tests pin `--fs-crash-at
    // close:1` to the subsequent file close, so adding an earlier close would
    // move the planted crash point away from the data-durability assertion.
    let dir = context.fs_open(path, OpenFlags::read_only()).unwrap();
    context.fs_sync(dir).unwrap();
}

/// Append `records` framed with a trailing marker to a write-ahead log without
/// syncing, mirroring a missing-fsync commit protocol, then return how many
/// bytes survive a reopen. The write handle is closed before the reopen so a
/// crash pinned to that close lands between the append and the verify.
fn write_wal_and_reopen(seed: u64, crash: Option<CrashOp>) -> usize {
    let mut config = RuntimeConfig::seeded(seed);
    if let Some(op) = crash {
        config = config.with_crash_at(op, 1);
    }
    let mut context = Context::from_config(config).unwrap();
    let fd = context
        .fs_open("/commit.log", OpenFlags::create_truncate_write())
        .unwrap();
    context.fs_write(fd, b"durable-record-0001").unwrap();
    // Make the namespace entry durable but do NOT fsync the file data: the
    // record is announced durable but never flushed.
    sync_directory(&mut context, "/");
    context.fs_close(fd).unwrap();

    let fd = context
        .fs_open("/commit.log", OpenFlags::read_only())
        .unwrap();
    let bytes = context.fs_read(fd, 4096).unwrap();
    context.fs_close(fd).unwrap();
    context.finish().unwrap();
    bytes.len()
}

#[test]
fn crash_at_close_drops_unsynced_records_but_clean_run_keeps_them() {
    // MUST trip: an injected crash at the first close drops the unsynced write,
    // so the reopened log is empty — the lost-durable-records failure.
    assert_eq!(write_wal_and_reopen(0, Some(CrashOp::Close)), 0);
    // MUST stay clean: with no crash configured the record survives intact.
    assert_eq!(write_wal_and_reopen(0, None), 19);
}

#[test]
fn crash_injection_replays_self_contained_without_re_supplying_flags() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("crash.patina");

    let recorded = {
        let mut context = Context::from_config(
            RuntimeConfig::record(0, &path, "fault-v1").with_crash_at(CrashOp::Close, 1),
        )
        .unwrap();
        let fd = context
            .fs_open("/commit.log", OpenFlags::create_truncate_write())
            .unwrap();
        context.fs_write(fd, b"durable-record-0001").unwrap();
        sync_directory(&mut context, "/");
        context.fs_close(fd).unwrap();
        let fd = context
            .fs_open("/commit.log", OpenFlags::read_only())
            .unwrap();
        let bytes = context.fs_read(fd, 4096).unwrap();
        context.fs_close(fd).unwrap();
        context.finish().unwrap();
        bytes.len()
    };
    assert_eq!(
        recorded, 0,
        "the recorded run must observe the dropped record"
    );

    // Replay supplies NO crash flag: the trace's recorded fault configuration is
    // authoritative, so the injected FsCrash reproduces the loss byte-identically
    // from the metadata alone.
    let mut replay = Context::from_config(RuntimeConfig::replay(&path, "fault-v1")).unwrap();
    let fd = replay
        .fs_open("/commit.log", OpenFlags::create_truncate_write())
        .unwrap();
    replay.fs_write(fd, b"durable-record-0001").unwrap();
    sync_directory(&mut replay, "/");
    replay.fs_close(fd).unwrap();
    let fd = replay
        .fs_open("/commit.log", OpenFlags::read_only())
        .unwrap();
    assert_eq!(replay.fs_read(fd, 4096).unwrap().len(), 0);
    replay.fs_close(fd).unwrap();
    replay.finish().unwrap();
}

#[test]
fn replay_with_matching_flags_is_still_accepted() {
    // Explicitly re-supplying the SAME knobs the recording used remains valid —
    // they match the authoritative trace configuration and are adopted.
    let directory = tempdir().unwrap();
    let path = directory.path().join("crash-match.patina");
    {
        let mut context = Context::from_config(
            RuntimeConfig::record(0, &path, "fault-v1").with_crash_at(CrashOp::Close, 1),
        )
        .unwrap();
        let fd = context
            .fs_open("/commit.log", OpenFlags::create_truncate_write())
            .unwrap();
        context.fs_write(fd, b"durable-record-0001").unwrap();
        sync_directory(&mut context, "/");
        context.fs_close(fd).unwrap();
        let fd = context
            .fs_open("/commit.log", OpenFlags::read_only())
            .unwrap();
        context.fs_read(fd, 4096).unwrap();
        context.fs_close(fd).unwrap();
        context.finish().unwrap();
    }
    let mut replay = Context::from_config(
        RuntimeConfig::replay(&path, "fault-v1").with_crash_at(CrashOp::Close, 1),
    )
    .unwrap();
    let fd = replay
        .fs_open("/commit.log", OpenFlags::create_truncate_write())
        .unwrap();
    replay.fs_write(fd, b"durable-record-0001").unwrap();
    sync_directory(&mut replay, "/");
    replay.fs_close(fd).unwrap();
    let fd = replay
        .fs_open("/commit.log", OpenFlags::read_only())
        .unwrap();
    assert_eq!(replay.fs_read(fd, 4096).unwrap().len(), 0);
    replay.fs_close(fd).unwrap();
    replay.finish().unwrap();
}

#[test]
fn replay_with_a_different_crash_point_fails_closed() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("crash-mismatch.patina");

    // Record a crash pinned to the first close.
    {
        let mut context = Context::from_config(
            RuntimeConfig::record(0, &path, "fault-v1").with_crash_at(CrashOp::Close, 1),
        )
        .unwrap();
        let fd = context
            .fs_open("/commit.log", OpenFlags::create_truncate_write())
            .unwrap();
        context.fs_write(fd, b"durable-record-0001").unwrap();
        sync_directory(&mut context, "/");
        context.fs_close(fd).unwrap();
        let fd = context
            .fs_open("/commit.log", OpenFlags::read_only())
            .unwrap();
        context.fs_read(fd, 4096).unwrap();
        context.fs_close(fd).unwrap();
        context.finish().unwrap();
    }

    // Replay explicitly supplying a DIFFERENT crash point (second close). The
    // trace's stored configuration is authoritative, so the conflicting flag is
    // rejected fail-closed as the runtime is built — before any operation runs —
    // rather than silently running a different fault schedule.
    let conflicting = Context::from_config(
        RuntimeConfig::replay(&path, "fault-v1").with_crash_at(CrashOp::Close, 2),
    );
    assert!(
        conflicting.is_err(),
        "replay with a conflicting crash point must fail closed, got a runtime"
    );
}

#[test]
fn byte_granularity_crash_records_a_torn_image_and_replays_self_contained() {
    // A byte-granularity crash records the torn (partial) final-write image, and
    // a flag-free replay reproduces the same bytes from the trace metadata alone
    // — the sub-block model round-tripping through record/replay.
    let directory = tempdir().unwrap();
    let path = directory.path().join("torn.patina");

    // Durable baseline, then an unsynced overwrite crashed part-way through.
    // The crash fires right after the second write, invalidating that handle, so
    // the stale fd is not closed — the modeled process restarts and reopens.
    fn drive(context: &mut Context) -> Vec<u8> {
        let fd = context
            .fs_open("/db", OpenFlags::create_truncate_write())
            .unwrap();
        context.fs_write(fd, &[b'A'; 4096]).unwrap();
        context.fs_sync(fd).unwrap();
        sync_directory(context, "/");
        // The final unsynced write; the injected crash fires immediately after.
        context.fs_write(fd, &[b'B'; 4096]).unwrap();
        let fd = context.fs_open("/db", OpenFlags::read_only()).unwrap();
        let bytes = context.fs_read(fd, 8192).unwrap();
        context.fs_close(fd).unwrap();
        bytes
    }

    let recorded = {
        let mut context = Context::from_config(
            RuntimeConfig::record(7, &path, "fault-v1")
                .with_crash_at(CrashOp::Write, 2)
                .with_fs_torn_granularity(TornGranularity::Byte),
        )
        .unwrap();
        let bytes = drive(&mut context);
        context.finish().unwrap();
        bytes
    };
    // The reconstructed image is a genuine partial tear: some live 'B' bytes
    // survived and some durable 'A' bytes remain, so it differs from BOTH the
    // durable baseline and the fully-applied write.
    assert!(recorded.contains(&b'B'), "no live prefix survived");
    assert!(recorded.contains(&b'A'), "no durable suffix remained");
    assert_ne!(recorded, vec![b'A'; 4096]);
    assert_ne!(recorded, vec![b'B'; 4096]);

    // Flag-free replay reproduces the torn image byte-for-byte from the trace.
    let mut replay = Context::from_config(RuntimeConfig::replay(&path, "fault-v1")).unwrap();
    let replayed = drive(&mut replay);
    replay.finish().unwrap();
    assert_eq!(
        replayed, recorded,
        "flag-free replay did not reproduce the torn image"
    );
}

/// Sleep for `duration`, returning the virtual monotonic time afterward.
fn elapsed_after_sleep(config: RuntimeConfig, duration: u64) -> u64 {
    let mut context = Context::from_config(config).unwrap();
    context.sleep_for(duration).unwrap();
    let elapsed = context.now(ClockKind::Monotonic).unwrap();
    context.finish().unwrap();
    elapsed
}

#[test]
fn sleep_jitter_inflates_elapsed_time_deterministically() {
    // Control: no jitter advances the clock by exactly the requested duration.
    assert_eq!(elapsed_after_sleep(RuntimeConfig::seeded(1), 1_000), 1_000);

    // MUST inflate: injected jitter in [500, 1500] pushes elapsed into
    // [1500, 2500], strictly past the nominal budget.
    let jittered = elapsed_after_sleep(
        RuntimeConfig::seeded(1).with_sleep_jitter_nanos(500, 1_500),
        1_000,
    );
    assert!(
        (1_500..=2_500).contains(&jittered),
        "jittered elapsed {jittered} out of expected range"
    );
    // Deterministic per seed.
    let again = elapsed_after_sleep(
        RuntimeConfig::seeded(1).with_sleep_jitter_nanos(500, 1_500),
        1_000,
    );
    assert_eq!(jittered, again);

    // Varies across seeds, proving the draw is genuinely seed-driven.
    let distinct: BTreeSet<u64> = (0..16)
        .map(|seed| {
            elapsed_after_sleep(
                RuntimeConfig::seeded(seed).with_sleep_jitter_nanos(500, 1_500),
                1_000,
            )
        })
        .collect();
    assert!(distinct.len() > 1, "sleep jitter never varied across seeds");
}

#[test]
fn net_drop_loses_datagrams_and_clean_run_delivers() {
    // MUST drop: certain drop reports the send as written but delivers nothing.
    let mut context =
        Context::from_config(RuntimeConfig::seeded(0).with_net_drop_permille(1000)).unwrap();
    let tx = context.net_bind("tx").unwrap();
    let rx = context.net_bind("rx").unwrap();
    let report = context.net_send(tx, "rx", b"payload").unwrap();
    assert_eq!(report.disposition, SendDisposition::DroppedByFault);
    assert!(context.net_recv(rx).unwrap().is_none());
    context.finish().unwrap();

    // Control: with no drop configured the datagram is delivered.
    let mut context = Context::from_config(RuntimeConfig::seeded(0)).unwrap();
    let tx = context.net_bind("tx").unwrap();
    let rx = context.net_bind("rx").unwrap();
    let report = context.net_send(tx, "rx", b"payload").unwrap();
    assert_eq!(report.disposition, SendDisposition::Queued);
    assert_eq!(
        context
            .net_recv(rx)
            .unwrap()
            .expect("datagram delivered")
            .bytes,
        b"payload"
    );
    context.finish().unwrap();
}

#[test]
fn net_jitter_reorders_datagrams_relative_to_send_order() {
    // A seed sweep must contain at least one reordering, and each configuration
    // reproduces exactly, proving the SimNet reorder knob threads through the
    // runtime config.
    fn delivered_order(seed: u64) -> Vec<u32> {
        let mut context =
            Context::from_config(RuntimeConfig::seeded(seed).with_net_jitter_nanos(0, 1_000))
                .unwrap();
        let tx = context.net_bind("tx").unwrap();
        let rx = context.net_bind("rx").unwrap();
        for seq in 0..8u32 {
            context.net_send(tx, "rx", &seq.to_le_bytes()).unwrap();
        }
        // Advance the virtual clock past the largest possible delivery so every
        // surviving datagram is deliverable, then drain in delivery order.
        context.sleep_for(10_000).unwrap();
        let mut order = Vec::new();
        while let Some(datagram) = context.net_recv(rx).unwrap() {
            order.push(u32::from_le_bytes(datagram.bytes.try_into().unwrap()));
        }
        context.finish().unwrap();
        order
    }

    let in_order: Vec<u32> = (0..8).collect();
    assert_eq!(
        delivered_order(3),
        delivered_order(3),
        "must reproduce per seed"
    );
    assert!(
        (0..16).any(|seed| delivered_order(seed) != in_order),
        "net jitter never reordered across seeds"
    );
}

#[test]
fn net_faults_delay_the_tcp_stream_without_losing_data() {
    // Establish one loopback stream and push a segment, returning whether it was
    // readable at the send instant (t=0) and after advancing the virtual clock.
    fn stream_once<F: Fn(RuntimeConfig) -> RuntimeConfig>(configure: F) -> (bool, Vec<u8>) {
        let mut context = Context::from_config(configure(RuntimeConfig::seeded(4))).unwrap();
        let listener = context.net_tcp_listen("server", 8).unwrap();
        let client = context.net_tcp_connect("client", "server").unwrap();
        let server = context.net_tcp_accept(listener).unwrap().unwrap().socket;
        context.net_tcp_send(client, b"hello").unwrap();
        let at_send = context.net_tcp_recv(server, 64).unwrap();
        let mut delivered = at_send.clone().unwrap_or_default();
        // Advance well past the bounded retransmit + jitter ceiling.
        context.sleep_for(1_000_000_000).unwrap();
        if let Some(bytes) = context.net_tcp_recv(server, 64).unwrap() {
            delivered.extend_from_slice(&bytes);
        }
        context.finish().unwrap();
        (at_send.is_some(), delivered)
    }

    // Control: no fault knobs -> the stream delivers immediately and intact.
    let (clean_ready, clean_bytes) = stream_once(|config| config);
    assert!(
        clean_ready,
        "without faults a TCP segment is readable at once"
    );
    assert_eq!(clean_bytes, b"hello");

    // Base latency: net latency now lives in the net fault config and applies to
    // TCP segments as well as datagrams, so the segment is NOT readable at the
    // send instant and then arrives once virtual time advances.
    let (latency_ready, latency_bytes) =
        stream_once(|config| config.with_net_latency_nanos(50_000));
    assert!(
        !latency_ready,
        "net base latency must delay TCP delivery — the latency knob is inert on the stream path otherwise"
    );
    assert_eq!(latency_bytes, b"hello", "TCP latency must never lose data");

    // Jitter: the fault reaches the TCP path through the runtime, so the segment
    // is NOT readable at the send instant, yet the reliable stream never loses
    // it once the clock advances.
    let (jitter_ready, jitter_bytes) =
        stream_once(|config| config.with_net_jitter_nanos(1, 50_000));
    assert!(
        !jitter_ready,
        "net jitter must delay TCP delivery — the fault knob is inert on the stream path otherwise"
    );
    assert_eq!(jitter_bytes, b"hello", "TCP jitter must never lose data");

    // Drop: a reliable stream retransmits, so a dropped segment is delayed, not
    // lost — the TCP contract the datagram drop knob would otherwise violate.
    let (drop_ready, drop_bytes) = stream_once(|config| config.with_net_drop_permille(1000));
    assert!(
        !drop_ready,
        "a dropped TCP segment is retransmitted (delayed)"
    );
    assert_eq!(drop_bytes, b"hello", "TCP drop must never lose data");
}

/// Open a file, write, sync and read it back — five fault-eligible filesystem
/// operations plus one ineligible close — reporting the virtual monotonic time
/// afterwards and the run's filesystem fault report.
fn fs_ops_elapsed_and_report(config: RuntimeConfig) -> (u64, Option<FsFaultReport>) {
    let mut context = Context::from_config(config).unwrap();
    let fd = context
        .fs_open("/latency.log", OpenFlags::create_truncate_write())
        .unwrap();
    context.fs_write(fd, b"record").unwrap();
    context.fs_sync(fd).unwrap();
    context.fs_set_len(fd, 6).unwrap();
    context.fs_metadata("/latency.log").unwrap();
    context.fs_close(fd).unwrap();
    let elapsed = context.now(ClockKind::Monotonic).unwrap();
    let report = context.fs_fault_report();
    context.finish().unwrap();
    (elapsed, report)
}

/// Five eligible operations: open, write, sync, set_len, metadata. `close` is
/// outside the eligible set, so it is deliberately not counted.
const ELIGIBLE_FS_OPS: u64 = 5;

#[test]
fn fs_latency_delays_every_eligible_operation_and_never_the_ineligible_ones() {
    // Control: with no fs fault knob the clock never moves and no report exists
    // at all, so a knob-free run is unchanged.
    let (clean_elapsed, clean_report) = fs_ops_elapsed_and_report(RuntimeConfig::seeded(1));
    assert_eq!(clean_elapsed, 0);
    assert!(clean_report.is_none());

    // MUST delay: a fixed 1_000ns latency delays each of the five eligible ops
    // and nothing else, so elapsed is exactly five microseconds' worth. An
    // eligible-op miscount or a delayed `close` both show up here.
    let (elapsed, report) =
        fs_ops_elapsed_and_report(RuntimeConfig::seeded(1).with_fs_latency_nanos(1_000, 1_000));
    assert_eq!(elapsed, ELIGIBLE_FS_OPS * 1_000);
    let report = report.expect("a live fs latency knob must report");
    assert_eq!(report.latency_applied, ELIGIBLE_FS_OPS);
    assert_eq!(report.eligible_ops, ELIGIBLE_FS_OPS);
    assert!(report.latency_vacuity_diagnosable);
    assert!(
        !report.is_vacuous(),
        "a latency knob that delayed every eligible op is not vacuous: {report:?}"
    );
}

#[test]
fn fs_latency_is_seed_deterministic_and_seed_varying() {
    let elapsed_for = |seed: u64| {
        fs_ops_elapsed_and_report(RuntimeConfig::seeded(seed).with_fs_latency_nanos(500, 1_500)).0
    };
    // Deterministic per seed, and every draw lands inside the configured range.
    let first = elapsed_for(7);
    assert_eq!(first, elapsed_for(7));
    assert!((ELIGIBLE_FS_OPS * 500..=ELIGIBLE_FS_OPS * 1_500).contains(&first));

    // Genuinely seed-driven rather than a fixed offset.
    let distinct: BTreeSet<u64> = (0..16).map(elapsed_for).collect();
    assert!(distinct.len() > 1, "fs latency never varied across seeds");
}

#[test]
fn a_decision_free_fs_latency_range_perturbs_nothing_and_is_not_diagnosed_vacuous() {
    // A `0..0` range applies no delay by construction. That is an inert knob,
    // not an inert code path, so the vacuity diagnostic must stay silent —
    // otherwise the warning fires on healthy runs and stops meaning anything.
    let (elapsed, report) =
        fs_ops_elapsed_and_report(RuntimeConfig::seeded(1).with_fs_latency_nanos(0, 0));
    assert_eq!(elapsed, 0);
    let report = report.expect("a live knob still reports");
    assert_eq!(report.latency_applied, 0);
    assert!(!report.latency_vacuity_diagnosable);
    assert!(!report.is_vacuous());
}

#[test]
fn fs_latency_replays_self_contained_without_re_supplying_flags() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("fs-latency.patina");
    let (recorded_elapsed, recorded_report) = fs_ops_elapsed_and_report(
        RuntimeConfig::record(11, &path, "patina-test").with_fs_latency_nanos(400, 900),
    );
    assert!(recorded_elapsed >= ELIGIBLE_FS_OPS * 400);
    assert_eq!(
        recorded_report.expect("report").latency_applied,
        ELIGIBLE_FS_OPS
    );

    // A flag-free replay restores the latency configuration from the trace and
    // reproduces the identical virtual-time profile.
    let (replayed_elapsed, _) =
        fs_ops_elapsed_and_report(RuntimeConfig::replay(&path, "patina-test"));
    assert_eq!(recorded_elapsed, replayed_elapsed);
}

/// Resolve `name` under `config`, returning the outcome and the virtual monotonic
/// time afterwards (so an injected resolution latency is observable).
fn resolve_once(
    config: RuntimeConfig,
    name: &str,
) -> (Result<String, String>, u64, Option<DnsFaultReport>) {
    let mut context = Context::from_config(config).unwrap();
    let outcome = context.dns_resolve(name).map_err(|error| error.to_string());
    let elapsed = context.now(ClockKind::Monotonic).unwrap();
    let report = context.dns_fault_report();
    context.finish().unwrap();
    (outcome, elapsed, report)
}

fn with_entry(config: RuntimeConfig) -> RuntimeConfig {
    config.with_dns_entry("db.internal", "10.0.0.5").unwrap()
}

#[test]
fn dns_resolves_the_host_table_and_nxdomains_everything_else() {
    // A defined name resolves; an undefined one is NXDOMAIN as SEMANTICS — no
    // knob is set, and the failure is deterministic.
    let (resolved, _, report) = resolve_once(with_entry(RuntimeConfig::seeded(1)), "db.internal");
    assert_eq!(resolved.unwrap(), "10.0.0.5");
    assert!(report.is_none(), "no DNS knob was live, so no report");

    let (missing, _, _) = resolve_once(with_entry(RuntimeConfig::seeded(1)), "absent.internal");
    assert!(
        missing.unwrap_err().contains("no virtual DNS entry"),
        "an undefined name must be NXDOMAIN"
    );

    // Built-ins resolve without the table and are never fault-eligible.
    for (name, expected) in [("localhost", "127.0.0.1"), ("10.0.0.7", "10.0.0.7")] {
        let (builtin, _, _) = resolve_once(
            with_entry(RuntimeConfig::seeded(1).with_dns_fail_permille(1000)),
            name,
        );
        assert_eq!(builtin.unwrap(), expected, "{name} must resolve locally");
    }
}

#[test]
fn the_dns_failure_knob_fires_only_on_defined_names_and_is_reported() {
    // MUST fail: a certain failure rate turns a DEFINED name's resolution into
    // an injected error, and the report proves it was applied.
    let (failed, _, report) = resolve_once(
        with_entry(RuntimeConfig::seeded(4).with_dns_fail_permille(1000)),
        "db.internal",
    );
    assert!(
        failed.unwrap_err().contains("injected DNS failure"),
        "a certain failure rate must fail a defined name"
    );
    let report = report.expect("a live knob reports");
    assert_eq!(report.resolutions, 1);
    assert_eq!(report.failures_injected, 1);

    // An UNDEFINED name is not fault-eligible: it was already NXDOMAIN, so the
    // knob had no opportunity and the run records none. Counting it would let a
    // workload that never resolves a real name look like the knob was exercised.
    let (_, _, absent_report) = resolve_once(
        with_entry(RuntimeConfig::seeded(4).with_dns_fail_permille(1000)),
        "absent.internal",
    );
    assert_eq!(absent_report.expect("live knob").resolutions, 0);
}

#[test]
fn dns_latency_delays_an_eligible_resolution_and_is_seed_driven() {
    // Control: no knob, no virtual time spent resolving.
    let (_, clean, _) = resolve_once(with_entry(RuntimeConfig::seeded(2)), "db.internal");
    assert_eq!(clean, 0);

    let (resolved, elapsed, report) = resolve_once(
        with_entry(RuntimeConfig::seeded(2).with_dns_latency_nanos(5_000, 5_000)),
        "db.internal",
    );
    assert_eq!(resolved.unwrap(), "10.0.0.5");
    assert_eq!(elapsed, 5_000);
    assert_eq!(report.expect("live knob").latency_applied, 1);

    // Seed-driven over a range, not a fixed offset.
    let spread: BTreeSet<u64> = (0..16)
        .map(|seed| {
            resolve_once(
                with_entry(RuntimeConfig::seeded(seed).with_dns_latency_nanos(1_000, 9_000)),
                "db.internal",
            )
            .1
        })
        .collect();
    assert!(spread.len() > 1, "DNS latency never varied across seeds");
}

#[test]
fn a_dns_knob_that_never_fired_over_eligible_traffic_is_diagnosed_vacuous() {
    // The detector: a live knob, enough eligible resolutions for the configured
    // rate to be expected to fire repeatedly, and ZERO applications. Built by
    // hand here because a correctly wired knob cannot produce it — which is
    // exactly why the class needs its own pinned shape.
    let inert = DnsFaultReport {
        resolutions: 40,
        fail_vacuity_diagnosable: true,
        failures_injected: 0,
        ..DnsFaultReport::default()
    };
    assert!(inert.is_vacuous());

    // A knob that DID fire over the same traffic is not vacuous.
    let live = DnsFaultReport {
        resolutions: 40,
        fail_vacuity_diagnosable: true,
        failures_injected: 3,
        ..DnsFaultReport::default()
    };
    assert!(!live.is_vacuous());

    // And a low rate that ordinarily draws zero is not diagnosable at all, so a
    // healthy run never trips the warning.
    let (_, _, sparse) = resolve_once(
        with_entry(RuntimeConfig::seeded(9).with_dns_fail_permille(1)),
        "db.internal",
    );
    let sparse = sparse.expect("live knob");
    assert!(!sparse.fail_vacuity_diagnosable);
    assert!(!sparse.is_vacuous());
}

#[test]
fn dns_resolution_replays_self_contained_without_re_supplying_the_table() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("dns.patina");
    let (recorded, recorded_elapsed, _) = resolve_once(
        with_entry(RuntimeConfig::record(6, &path, "patina-test").with_dns_latency_nanos(300, 700)),
        "db.internal",
    );
    assert_eq!(recorded.unwrap(), "10.0.0.5");

    // Flag-free: no --dns-entry, no knobs. The trace restores both.
    let (replayed, replayed_elapsed, _) =
        resolve_once(RuntimeConfig::replay(&path, "patina-test"), "db.internal");
    assert_eq!(replayed.unwrap(), "10.0.0.5");
    assert_eq!(recorded_elapsed, replayed_elapsed);

    // A conflicting table at replay fails closed rather than silently resolving
    // something the recording never did.
    let conflicting = RuntimeConfig::replay(&path, "patina-test")
        .with_dns_entry("db.internal", "10.0.0.6")
        .unwrap();
    assert!(Context::from_config(conflicting).is_err());
}

#[test]
fn a_malformed_dns_entry_fails_closed_at_configuration_time() {
    assert!(
        RuntimeConfig::seeded(1)
            .with_dns_entry("db.internal", "not-an-ip")
            .is_err()
    );
    assert!(
        RuntimeConfig::seeded(1)
            .with_dns_entry("", "10.0.0.5")
            .is_err()
    );
    // A name that would resolve without the table cannot be redefined by it.
    assert!(
        RuntimeConfig::seeded(1)
            .with_dns_entry("localhost", "10.0.0.5")
            .is_err()
    );
}

// ---------------------------------------------------------------------------
// Entropy-request failure injection
// ---------------------------------------------------------------------------

fn entropy_once(
    config: RuntimeConfig,
    len: usize,
) -> (Result<Vec<u8>, String>, Option<EntropyFaultReport>) {
    let mut context = Context::from_config(config).unwrap();
    let outcome = context
        .entropy_bytes(len)
        .map_err(|error| error.to_string());
    let report = context.entropy_fault_report();
    context.finish().unwrap();
    (outcome, report)
}

#[test]
fn entropy_bytes_resolves_without_a_knob_and_reports_nothing() {
    let (bytes, report) = entropy_once(RuntimeConfig::seeded(1), 16);
    assert_eq!(bytes.unwrap().len(), 16);
    assert!(report.is_none(), "no entropy knob was live, so no report");
}

#[test]
fn the_entropy_failure_knob_fires_and_is_reported() {
    // MUST fail: a certain failure rate turns a request into an injected error,
    // and the report proves it was applied.
    let (failed, report) = entropy_once(
        RuntimeConfig::seeded(4).with_entropy_fail_permille(1000),
        16,
    );
    assert!(
        failed.unwrap_err().contains("injected entropy failure"),
        "a certain failure rate must fail every request"
    );
    let report = report.expect("a live knob reports");
    assert_eq!(report.requests, 1);
    assert_eq!(report.failures_injected, 1);
}

#[test]
fn an_entropy_knob_that_never_fired_over_eligible_traffic_is_diagnosed_vacuous() {
    // The detector: a live knob, enough eligible requests for the configured
    // rate to be expected to fire repeatedly, and ZERO applications. Built by
    // hand here because a correctly wired knob cannot produce it.
    let inert = EntropyFaultReport {
        requests: 40,
        fail_vacuity_diagnosable: true,
        failures_injected: 0,
    };
    assert!(inert.is_vacuous());

    // A knob that DID fire over the same traffic is not vacuous.
    let live = EntropyFaultReport {
        requests: 40,
        fail_vacuity_diagnosable: true,
        failures_injected: 3,
    };
    assert!(!live.is_vacuous());

    // And a low rate that ordinarily draws zero is not diagnosable at all, so a
    // healthy run never trips the warning.
    let (_, sparse) = entropy_once(RuntimeConfig::seeded(9).with_entropy_fail_permille(1), 16);
    let sparse = sparse.expect("live knob");
    assert!(!sparse.fail_vacuity_diagnosable);
    assert!(!sparse.is_vacuous());
}

#[test]
fn arming_the_entropy_fault_knob_does_not_perturb_a_request_it_does_not_fire_on() {
    // The §1.2-style guarantee: the fault decision draws from its own
    // domain-separated stream, never from the entropy stream itself. Find a
    // seed where a live knob does not fire on the first request, then check the
    // returned bytes equal the knob-absent baseline for that SAME seed — a
    // shared decision stream would perturb them.
    let seed = (0..64)
        .find(|&seed| {
            let (_, report) = entropy_once(
                RuntimeConfig::seeded(seed).with_entropy_fail_permille(500),
                16,
            );
            report.expect("live knob").failures_injected == 0
        })
        .expect("some seed in range must not fire at rate 500");
    let baseline = entropy_once(RuntimeConfig::seeded(seed), 16).0.unwrap();
    let armed = entropy_once(
        RuntimeConfig::seeded(seed).with_entropy_fail_permille(500),
        16,
    )
    .0
    .unwrap();
    assert_eq!(baseline, armed);
}

#[test]
fn entropy_failure_replays_self_contained_without_re_supplying_the_flag() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("entropy.patina");
    let (recorded, recorded_report) = entropy_once(
        RuntimeConfig::record(4, &path, "patina-test").with_entropy_fail_permille(1000),
        16,
    );
    let recorded_message = recorded.unwrap_err();
    assert!(recorded_message.contains("injected entropy failure"));
    assert_eq!(recorded_report.expect("report").failures_injected, 1);

    // Flag-free: no --entropy-fail-permille. The trace restores it.
    let (replayed, _) = entropy_once(RuntimeConfig::replay(&path, "patina-test"), 16);
    assert_eq!(replayed.unwrap_err(), recorded_message);

    // A conflicting knob at replay fails closed rather than silently running a
    // different fault schedule.
    let conflicting = RuntimeConfig::replay(&path, "patina-test").with_entropy_fail_permille(1);
    assert!(Context::from_config(conflicting).is_err());
}

// ---------------------------------------------------------------------------
// Realtime-epoch jump injection
// ---------------------------------------------------------------------------

/// Read `ClockKind::Realtime` once, after advancing the monotonic clock (and
/// therefore, at epoch 0, the true realtime value) to `advance_to`.
fn realtime_once(config: RuntimeConfig, advance_to: u64) -> (u64, Option<ClockFaultReport>) {
    let mut context = Context::from_config(config).unwrap();
    if advance_to > 0 {
        context
            .sleep_until(ClockKind::Monotonic, advance_to)
            .unwrap();
    }
    let value = context.now(ClockKind::Realtime).unwrap();
    let report = context.clock_fault_report();
    context.finish().unwrap();
    (value, report)
}

#[test]
fn realtime_now_resolves_without_a_knob_and_reports_nothing() {
    let (value, report) = realtime_once(RuntimeConfig::seeded(1), 1_000_000);
    assert_eq!(
        value, 1_000_000,
        "no jump knob was live, so the true epoch is untouched"
    );
    assert!(
        report.is_none(),
        "no epoch-jump knob was live, so no report"
    );
}

#[test]
fn the_epoch_jump_knob_fires_and_is_reported() {
    // MUST perturb: some seed in range must draw a nonzero offset at a healthy
    // true epoch, and the report proves it was applied.
    let seed = (0..64)
        .find(|&seed| {
            realtime_once(
                RuntimeConfig::seeded(seed).with_epoch_jump_nanos(1_000),
                1_000_000,
            )
            .0 != 1_000_000
        })
        .expect("some seed in range must draw a nonzero offset");
    let (value, report) = realtime_once(
        RuntimeConfig::seeded(seed).with_epoch_jump_nanos(1_000),
        1_000_000,
    );
    assert_ne!(value, 1_000_000, "the knob must have perturbed this read");
    let report = report.expect("a live knob reports");
    assert_eq!(report.reads, 1);
    assert_eq!(report.jumps_applied, 1);
}

#[test]
fn an_epoch_jump_knob_that_never_applied_over_eligible_reads_is_diagnosed_vacuous() {
    // The detector: a live knob, enough eligible reads for the configured range
    // to be expected to apply repeatedly, and ZERO applications. Built by hand
    // here because a correctly wired knob cannot produce it.
    let inert = ClockFaultReport {
        reads: 40,
        jump_vacuity_diagnosable: true,
        jumps_applied: 0,
    };
    assert!(inert.is_vacuous());

    // A knob that DID apply over the same traffic is not vacuous.
    let live = ClockFaultReport {
        reads: 40,
        jump_vacuity_diagnosable: true,
        jumps_applied: 3,
    };
    assert!(!live.is_vacuous());

    // `hi == 0` (the off default) never diagnoses: a report is not even emitted.
    let (_, off) = realtime_once(RuntimeConfig::seeded(0), 1_000_000);
    assert!(off.is_none());
}

#[test]
fn arming_the_epoch_jump_knob_does_not_perturb_monotonic_reads() {
    // The clock-plane scope boundary: the jump knob touches ONLY
    // `ClockKind::Realtime`. Monotonic drives timers and the liveness
    // watchdog, so it must read identically whether or not the knob is armed.
    let mut baseline = Context::from_config(RuntimeConfig::seeded(7)).unwrap();
    baseline
        .sleep_until(ClockKind::Monotonic, 1_000_000)
        .unwrap();
    let baseline_monotonic = baseline.now(ClockKind::Monotonic).unwrap();
    baseline.finish().unwrap();

    let mut armed =
        Context::from_config(RuntimeConfig::seeded(7).with_epoch_jump_nanos(u64::MAX)).unwrap();
    armed.sleep_until(ClockKind::Monotonic, 1_000_000).unwrap();
    let armed_monotonic = armed.now(ClockKind::Monotonic).unwrap();
    let report = armed.clock_fault_report();
    armed.finish().unwrap();

    assert_eq!(baseline_monotonic, armed_monotonic);
    // The knob was live but this Context never read Realtime, so it drew
    // nothing at all: the report must show zero eligible reads.
    assert_eq!(report.expect("live knob").reads, 0);
}

#[test]
fn epoch_jump_replays_self_contained_without_re_supplying_the_flag() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("epoch-jump.patina");

    let mut recorded = Context::from_config(
        RuntimeConfig::record(4, &path, "patina-test").with_epoch_jump_nanos(1_000_000),
    )
    .unwrap();
    recorded
        .sleep_until(ClockKind::Monotonic, 10_000_000)
        .unwrap();
    let recorded_value = recorded.now(ClockKind::Realtime).unwrap();
    recorded.finish().unwrap();

    // Flag-free: no --epoch-jump-nanos. The trace restores it, and replay
    // reproduces the SAME recorded (already-perturbed) value with no redraw.
    let mut replayed = Context::from_config(RuntimeConfig::replay(&path, "patina-test")).unwrap();
    replayed
        .sleep_until(ClockKind::Monotonic, 10_000_000)
        .unwrap();
    let replayed_value = replayed.now(ClockKind::Realtime).unwrap();
    replayed.finish().unwrap();
    assert_eq!(replayed_value, recorded_value);

    // A conflicting knob at replay fails closed rather than silently running a
    // different fault schedule.
    let conflicting = RuntimeConfig::replay(&path, "patina-test").with_epoch_jump_nanos(1);
    assert!(Context::from_config(conflicting).is_err());
}

#[test]
fn epoch_jump_can_regress_a_read_below_an_earlier_one_at_the_same_true_time() {
    // The bug class this knob exists for: two adjacent reads of the SAME true
    // realtime value (no sleep between them) can still disagree, because each
    // draws its own independent offset — proving the signed draw actually goes
    // negative, not just that it can be positive.
    let seed = (0..256)
        .find(|&seed| {
            let mut context =
                Context::from_config(RuntimeConfig::seeded(seed).with_epoch_jump_nanos(1_000_000))
                    .unwrap();
            context
                .sleep_until(ClockKind::Monotonic, 10_000_000)
                .unwrap();
            let first = context.now(ClockKind::Realtime).unwrap();
            let second = context.now(ClockKind::Realtime).unwrap();
            context.finish().unwrap();
            second < first
        })
        .expect("some seed in range must draw a smaller offset on the second read");

    let mut context =
        Context::from_config(RuntimeConfig::seeded(seed).with_epoch_jump_nanos(1_000_000)).unwrap();
    context
        .sleep_until(ClockKind::Monotonic, 10_000_000)
        .unwrap();
    let first = context.now(ClockKind::Realtime).unwrap();
    let second = context.now(ClockKind::Realtime).unwrap();
    assert!(
        second < first,
        "wall time must be able to regress between adjacent reads: {first} then {second}"
    );
    let report = context.clock_fault_report().expect("live knob");
    assert_eq!(report.reads, 2);
    assert_eq!(report.jumps_applied, 2);
    context.finish().unwrap();
}

#[test]
fn epoch_jump_saturates_at_zero_rather_than_wrapping_negative() {
    // Find a seed whose draw, at a healthy true epoch, is negative (the
    // perturbed read is strictly below the true value) — then, for that SAME
    // seed, at true epoch 0, the negative draw would go below zero, and the
    // knob must clamp there rather than wrap a `u64`.
    let hi = 1_000;
    let seed = (0..64)
        .find(|&seed| {
            realtime_once(
                RuntimeConfig::seeded(seed).with_epoch_jump_nanos(hi),
                1_000_000,
            )
            .0 < 1_000_000
        })
        .expect("some seed in range must draw a negative offset");

    let (at_zero, report) = realtime_once(RuntimeConfig::seeded(seed).with_epoch_jump_nanos(hi), 0);
    assert_eq!(
        at_zero, 0,
        "a negative draw at true epoch 0 must saturate, not wrap"
    );
    assert_eq!(
        report.expect("live knob").jumps_applied,
        0,
        "clamped-to-unchanged is not a counted application"
    );
}

// ---------------------------------------------------------------------------
// Wave E: connection-level network faults, duplication, partitions, buffers
// ---------------------------------------------------------------------------

/// Establish one loopback stream, exchange a payload both ways, and report what
/// the guest observed: whether the connect succeeded, whether the send and the
/// receive succeeded, and the run's network fault report.
fn stream_exchange(config: RuntimeConfig) -> (Result<(), ErrorCode>, Option<NetFaultReport>) {
    let mut context = Context::from_config(config).unwrap();
    let listener = context.net_tcp_listen("server", 8).unwrap();
    let outcome = (|| {
        let client = context
            .net_tcp_connect("client", "server")
            .map_err(error_code)?;
        let server = context
            .net_tcp_accept(listener)
            .map_err(error_code)?
            .expect("a connected stream is pending")
            .socket;
        context.net_tcp_send(client, b"ping").map_err(error_code)?;
        context
            .net_tcp_recv(server, 64)
            .map_err(error_code)?
            .expect("the segment is deliverable at once without delay knobs");
        Ok(())
    })();
    let report = context.net_fault_report();
    context.finish().unwrap();
    (outcome, report)
}

/// The ABI error code behind a runtime effect failure, so a test can assert the
/// guest saw ECONNREFUSED/ECONNRESET rather than merely "an error".
fn error_code(error: patina_dst_runtime::RuntimeError) -> ErrorCode {
    match error {
        patina_dst_runtime::RuntimeError::Effect(effect) => effect.code,
        other => panic!("expected an effect error, got {other:?}"),
    }
}

#[test]
fn the_connect_refusal_knob_is_guest_observable_and_reported() {
    // Control: no knob, the exchange completes and no report exists at all.
    let (clean, clean_report) = stream_exchange(RuntimeConfig::seeded(3));
    assert_eq!(clean, Ok(()));
    assert!(clean_report.is_none());

    // MUST refuse: the guest's connect fails with ConnectionRefused — the
    // startup-race failure a service must retry through.
    let (refused, report) =
        stream_exchange(RuntimeConfig::seeded(3).with_net_connect_refuse_permille(1000));
    assert_eq!(refused, Err(ErrorCode::ConnectionRefused));
    let report = report.expect("a live connect-refusal knob must report");
    assert_eq!(report.connect_ops, 1);
    assert_eq!(report.connects_refused, 1);
    assert!(!report.is_vacuous());
}

#[test]
fn the_reset_knob_is_guest_observable_and_reported() {
    let (reset, report) = stream_exchange(RuntimeConfig::seeded(3).with_net_reset_permille(1000));
    assert_eq!(reset, Err(ErrorCode::ConnectionReset));
    let report = report.expect("a live reset knob must report");
    assert_eq!(report.resets_injected, 1);
    assert!(!report.is_vacuous());
}

#[test]
fn the_duplication_knob_delivers_a_datagram_twice() {
    // Control: exactly one delivery without the knob.
    assert_eq!(datagram_deliveries(RuntimeConfig::seeded(2)), 1);
    // MUST duplicate: the receiver observes the same payload twice, which is the
    // at-least-once hazard a non-idempotent handler mishandles.
    assert_eq!(
        datagram_deliveries(RuntimeConfig::seeded(2).with_net_duplicate_permille(1000)),
        2
    );
}

/// Send one datagram and count how many copies the receiver observes.
fn datagram_deliveries(config: RuntimeConfig) -> usize {
    let mut context = Context::from_config(config).unwrap();
    let tx = context.net_bind("tx").unwrap();
    let rx = context.net_bind("rx").unwrap();
    context.net_send(tx, "rx", b"once?").unwrap();
    context.sleep_for(1_000_000).unwrap();
    let mut delivered = 0;
    while let Some(datagram) = context.net_recv(rx).unwrap() {
        assert_eq!(datagram.bytes, b"once?");
        delivered += 1;
    }
    context.finish().unwrap();
    delivered
}

#[test]
fn a_partition_blocks_traffic_and_an_unused_one_is_diagnosed_vacuous() {
    // MUST block: a partitioned datagram never reaches the peer.
    let mut context =
        Context::from_config(RuntimeConfig::seeded(1).with_net_partition("tx", "rx")).unwrap();
    let tx = context.net_bind("tx").unwrap();
    let rx = context.net_bind("rx").unwrap();
    for _ in 0..8 {
        assert_eq!(
            context.net_send(tx, "rx", b"blocked").unwrap().disposition,
            SendDisposition::DroppedByPartition
        );
    }
    assert!(context.net_recv(rx).unwrap().is_none());
    let report = context.net_fault_report().expect("a partition reports");
    assert_eq!(report.partition_blocks, 8);
    assert!(!report.is_vacuous());
    context.finish().unwrap();

    // MUST diagnose: a partition spelled for addresses this run never uses
    // blocks nothing, so a clean pass would otherwise read as "tested under
    // partition". This is the operator-typo signature.
    let mut context = Context::from_config(
        RuntimeConfig::seeded(1).with_net_partition("typo-left", "typo-right"),
    )
    .unwrap();
    let tx = context.net_bind("tx").unwrap();
    context.net_bind("rx").unwrap();
    for _ in 0..8 {
        context.net_send(tx, "rx", b"through").unwrap();
    }
    let report = context.net_fault_report().expect("a partition reports");
    assert_eq!(report.partition_blocks, 0);
    assert!(report.partition_vacuity_diagnosable);
    assert!(report.is_vacuous());
    context.finish().unwrap();
}

#[test]
fn the_tcp_buffer_knob_makes_backpressure_reachable() {
    // Control: the default buffer swallows the whole payload in one send.
    assert_eq!(first_send_accepted(RuntimeConfig::seeded(1), 4096), 4096);
    // MUST bind: a small buffer forces the would-block/partial-send path a guest
    // must handle, which is unreachable at the default size.
    assert_eq!(
        first_send_accepted(RuntimeConfig::seeded(1).with_net_tcp_buffer_bytes(64), 4096),
        64
    );
}

/// The byte count the first `tcp_send` of `len` bytes accepts.
fn first_send_accepted(config: RuntimeConfig, len: usize) -> usize {
    let mut context = Context::from_config(config).unwrap();
    let listener = context.net_tcp_listen("server", 1).unwrap();
    let client = context.net_tcp_connect("client", "server").unwrap();
    context.net_tcp_accept(listener).unwrap().unwrap();
    let accepted = context.net_tcp_send(client, &vec![7u8; len]).unwrap();
    context.finish().unwrap();
    accepted
}

#[test]
fn the_new_net_knobs_are_seed_deterministic_and_seed_varying() {
    // Same seed, same outcome; across seeds the fault lands in different places,
    // so each knob is genuinely seed-driven rather than a fixed decision.
    let refusals = |seed: u64| {
        connect_attempts(RuntimeConfig::seeded(seed).with_net_connect_refuse_permille(500))
    };
    for seed in 0..8 {
        assert_eq!(refusals(seed), refusals(seed), "seed {seed}");
    }
    assert!((0..16).map(refusals).collect::<BTreeSet<_>>().len() > 1);

    let duplicates = |seed: u64| {
        let mut context =
            Context::from_config(RuntimeConfig::seeded(seed).with_net_duplicate_permille(500))
                .unwrap();
        let tx = context.net_bind("tx").unwrap();
        context.net_bind("rx").unwrap();
        let copies: Vec<usize> = (0..24)
            .map(|index| context.net_send(tx, "rx", &[index as u8]).unwrap().copies)
            .collect();
        context.finish().unwrap();
        copies
    };
    for seed in 0..8 {
        assert_eq!(duplicates(seed), duplicates(seed), "seed {seed}");
    }
    assert!((0..16).map(duplicates).collect::<BTreeSet<_>>().len() > 1);
}

/// Which of 16 connects to one listener succeeded.
fn connect_attempts(config: RuntimeConfig) -> Vec<bool> {
    let mut context = Context::from_config(config).unwrap();
    context.net_tcp_listen("server", 64).unwrap();
    let outcomes = (0..16)
        .map(|index| {
            context
                .net_tcp_connect(&format!("client-{index}"), "server")
                .is_ok()
        })
        .collect();
    context.finish().unwrap();
    outcomes
}

#[test]
fn connection_faults_replay_self_contained_without_re_supplying_flags() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("connect.patina");
    let (recorded, _) = stream_exchange(
        RuntimeConfig::record(5, &path, "patina-test").with_net_connect_refuse_permille(1000),
    );
    assert_eq!(recorded, Err(ErrorCode::ConnectionRefused));

    // Flag-free: the recorded outcome stream reproduces the injected refusal.
    let (replayed, _) = stream_exchange(RuntimeConfig::replay(&path, "patina-test"));
    assert_eq!(replayed, Err(ErrorCode::ConnectionRefused));

    // Re-supplying a DIFFERENT rate fails closed rather than running a schedule
    // the recording never took.
    let conflicting =
        RuntimeConfig::replay(&path, "patina-test").with_net_connect_refuse_permille(250);
    assert!(Context::from_config(conflicting).is_err());
}

#[test]
fn arming_a_new_net_knob_does_not_perturb_another_domains_stream() {
    // The §1.2 guarantee, asserted where it would actually break: the jitter
    // draws of a datagram workload are identical whether or not the TCP-only
    // knobs are ARMED (not merely left at their defaults). A shared decision
    // stream would shift every delivery deadline here.
    let baseline =
        datagram_delivery_times(RuntimeConfig::seeded(9).with_net_jitter_nanos(1, 1_000));
    let with_tcp_knobs_armed = datagram_delivery_times(
        RuntimeConfig::seeded(9)
            .with_net_jitter_nanos(1, 1_000)
            .with_net_connect_refuse_permille(500)
            .with_net_reset_permille(500),
    );
    assert_eq!(baseline, with_tcp_knobs_armed);
    assert!(
        baseline.iter().any(|nanos| *nanos > 0),
        "the control must actually have drawn jitter, or this proves nothing"
    );
}

/// The delivery deadline of each of eight jittered datagrams, i.e. the exact
/// sequence of draws the net fault stream produced.
fn datagram_delivery_times(config: RuntimeConfig) -> Vec<u64> {
    let mut context = Context::from_config(config).unwrap();
    let tx = context.net_bind("tx").unwrap();
    context.net_bind("rx").unwrap();
    let times = (0..8)
        .flat_map(|index| {
            context
                .net_send(tx, "rx", &[index as u8])
                .unwrap()
                .delivery_nanos
        })
        .collect();
    context.finish().unwrap();
    times
}

// ---------------------------------------------------------------------------
// Custom-operation failure injection (docs/arcs/custom-ops.md, Wave B)
// ---------------------------------------------------------------------------

/// Run `count` custom operations under one context and report, per operation,
/// whether the guest got its declared failure instead of the real result, plus
/// the run's custom-op fault report. `eligible` is the guest's declaration that
/// the operation has a failure shape.
///
/// The `perform` closure bumps a counter rather than doing I/O, so "did the
/// wrapped effect run?" is answered directly rather than inferred.
fn custom_ops(
    config: RuntimeConfig,
    label: &str,
    count: usize,
    eligible: bool,
) -> (Vec<bool>, usize, Option<CustomOpFaultReport>) {
    let mut context = Context::from_config(config).unwrap();
    let mut performed = 0;
    let mut failed = Vec::new();
    for index in 0..count {
        let value: String = if eligible {
            context
                .custom_op_faultable(
                    label,
                    &index,
                    || "FAILED".to_string(),
                    || {
                        performed += 1;
                        "ok".to_string()
                    },
                )
                .unwrap()
        } else {
            context
                .custom_op(label, &index, || {
                    performed += 1;
                    "ok".to_string()
                })
                .unwrap()
        };
        failed.push(value == "FAILED");
    }
    let report = context.custom_op_fault_report();
    context.finish().unwrap();
    (failed, performed, report)
}

#[test]
fn a_custom_op_without_the_knob_performs_and_reports_nothing() {
    let (failed, performed, report) = custom_ops(RuntimeConfig::seeded(1), "s3.get", 4, true);
    assert_eq!(failed, vec![false; 4], "no knob is live, so nothing fails");
    assert_eq!(performed, 4);
    assert!(report.is_none(), "no custom-op knob was live, so no report");
}

#[test]
fn the_custom_op_failure_knob_fires_and_never_runs_perform() {
    // MUST fail: a certain rate hands back the guest's declared failure for
    // every eligible operation, and `perform` does not run at all — the fault
    // replaces the effect rather than discarding its result.
    let (failed, performed, report) = custom_ops(
        RuntimeConfig::seeded(4).with_custom_op_fail_permille(1000),
        "s3.get",
        4,
        true,
    );
    assert_eq!(failed, vec![true; 4]);
    assert_eq!(performed, 0, "a faulted operation must not perform");
    let report = report.expect("a live knob reports");
    assert_eq!(report.eligible_ops, 4);
    assert_eq!(report.faults_injected, 4);
    assert!(!report.is_vacuous());
}

#[test]
fn an_op_that_declares_no_failure_shape_is_never_faulted() {
    // The control: the same certain rate over the same label, with the guest
    // declaring nothing. Eligibility is the guest's call, so the knob passes it
    // by — and the plane says so by counting zero opportunities, which is
    // vacuous rather than quietly clean.
    let (failed, performed, report) = custom_ops(
        RuntimeConfig::seeded(4).with_custom_op_fail_permille(1000),
        "s3.get",
        4,
        false,
    );
    assert_eq!(failed, vec![false; 4]);
    assert_eq!(performed, 4);
    let report = report.expect("a live knob reports");
    assert_eq!(report.eligible_ops, 0);
    assert_eq!(report.faults_injected, 0);
    assert!(
        report.is_vacuous(),
        "an armed knob with nothing eligible is a coverage failure, not a clean run"
    );
}

#[test]
fn an_armed_run_that_reaches_no_custom_op_at_all_is_vacuous() {
    // The other half of the honesty rule: a guest with no declarations at all
    // (here, no custom operations at all) plus the knob is vacuous too. That is
    // stricter than every other plane, where zero traffic simply means nothing
    // to fault — and deliberately so, because a fault-eligible custom op exists
    // only if the guest wrote one.
    let context =
        Context::from_config(RuntimeConfig::seeded(4).with_custom_op_fail_permille(500)).unwrap();
    let report = context.custom_op_fault_report().expect("live knob");
    context.finish().unwrap();
    assert_eq!(report.eligible_ops, 0);
    assert!(report.is_vacuous());

    // RED twin: the same report shape with the knob unarmed produces no report
    // at all, so an unarmed run can never trip the class.
    let context = Context::from_config(RuntimeConfig::seeded(4)).unwrap();
    assert!(context.custom_op_fault_report().is_none());
    context.finish().unwrap();
}

#[test]
fn a_custom_op_knob_that_never_fired_over_eligible_ops_is_diagnosed_vacuous() {
    // Built by hand: a correctly wired knob cannot produce this, which is what
    // makes it a detector rather than an assertion about today's behavior.
    let inert = CustomOpFaultReport {
        eligible_ops: 40,
        fail_vacuity_diagnosable: true,
        faults_injected: 0,
    };
    assert!(inert.is_vacuous());
    let live = CustomOpFaultReport {
        eligible_ops: 40,
        fail_vacuity_diagnosable: true,
        faults_injected: 3,
    };
    assert!(!live.is_vacuous());

    // A rate too low to be expected to fire is not diagnosable, so a healthy
    // sparse run never trips the warning.
    let (_, _, sparse) = custom_ops(
        RuntimeConfig::seeded(9).with_custom_op_fail_permille(1),
        "s3.get",
        1,
        true,
    );
    let sparse = sparse.expect("live knob");
    assert!(!sparse.fail_vacuity_diagnosable);
    assert!(!sparse.is_vacuous());
}

#[test]
fn custom_op_fault_streams_are_domain_separated_per_label() {
    // Two labels under one seed and one rate must not draw the same pattern: a
    // shared coin would make arming a fault on one operation class shift the
    // other's decisions, and would make a campaign's per-class coverage a lie.
    let pattern = |label: &str| {
        custom_ops(
            RuntimeConfig::seeded(7).with_custom_op_fail_permille(500),
            label,
            24,
            true,
        )
        .0
    };
    let left = pattern("s3.get");
    let right = pattern("kms.decrypt");
    assert_ne!(left, right, "two labels must not share a coin");
    // ... and each label's own pattern is stable across runs at the same seed.
    assert_eq!(left, pattern("s3.get"));

    // A different seed explores a different pattern.
    let other_seed = custom_ops(
        RuntimeConfig::seeded(8).with_custom_op_fail_permille(500),
        "s3.get",
        24,
        true,
    )
    .0;
    assert_ne!(left, other_seed, "seed variation must change the schedule");
}

#[test]
fn custom_op_faults_replay_self_contained_without_re_supplying_the_flag() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("custom-op-fault.patina");
    let (recorded, performed, report) = custom_ops(
        RuntimeConfig::record(4, &path, "patina-test").with_custom_op_fail_permille(500),
        "s3.get",
        24,
        true,
    );
    let report = report.expect("live knob");
    assert!(
        report.faults_injected > 0 && report.faults_injected < 24,
        "the fixture needs a MIX of faulted and performed ops: {report:?}"
    );
    assert_eq!(performed, 24 - report.faults_injected as usize);

    // Flag-free replay: the trace restores the knob, and every faulted operation
    // replays as the same fault at the same position.
    let (replayed, replay_performed, _) = custom_ops(
        RuntimeConfig::replay(&path, "patina-test"),
        "s3.get",
        24,
        true,
    );
    assert_eq!(replayed, recorded);
    assert_eq!(
        replay_performed, 0,
        "replay reproduces every operation from the recording, faulted or not"
    );

    // The trace is the authority: a conflicting knob at replay fails closed
    // rather than silently running a different fault schedule.
    let conflicting = RuntimeConfig::replay(&path, "patina-test").with_custom_op_fail_permille(1);
    assert!(Context::from_config(conflicting).is_err());
}

#[test]
fn a_recorded_fault_replays_without_consulting_eligibility() {
    // The trace is authoritative, so the replay never redraws — but a call site
    // that dropped its failure declaration has no value to return for a
    // recorded fault, and is refused by name rather than handed something
    // invented.
    let directory = tempdir().unwrap();
    let path = directory.path().join("custom-op-fault-drop.patina");
    let (recorded, _, _) = custom_ops(
        RuntimeConfig::record(4, &path, "patina-test").with_custom_op_fail_permille(1000),
        "s3.get",
        1,
        true,
    );
    assert_eq!(recorded, vec![true]);

    let mut context = Context::from_config(RuntimeConfig::replay(&path, "patina-test")).unwrap();
    let error = context
        .custom_op::<String, usize>("s3.get", &0, || "ok".to_string())
        .expect_err("a recorded fault needs a declared failure shape");
    assert!(
        error.to_string().contains("s3.get") && error.to_string().contains("declares no failure"),
        "{error}"
    );
}
