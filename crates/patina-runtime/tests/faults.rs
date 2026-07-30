//! End-to-end coverage for the seed-driven fault-injection knobs, each with a
//! case that MUST exhibit the fault and a control that MUST stay clean, so no
//! knob is vacuously "working".

use std::collections::BTreeSet;

use patina_dst_abi::{ClockKind, OpenFlags, SendDisposition};
use patina_dst_runtime::{Context, CrashOp, RuntimeConfig, TornGranularity};
use tempfile::tempdir;

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
    // No fs_sync: the record is announced durable but never flushed.
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
