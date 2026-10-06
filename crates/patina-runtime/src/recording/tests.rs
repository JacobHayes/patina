//! Tests for trace transport, recording lifecycle, effect reconciliation, and outcome decoding.

use crate::builder::RuntimeBuilder;
use crate::config::RuntimeConfig;
use crate::fs_crash::CrashOp;
use crate::recording::TraceTransport;
use crate::reports::fs_fault_report_line;
use crate::{
    Context, DEFAULT_BOOT_ORIGIN_NANOS, ENV_FS_ERROR_PERMILLE, FACTS_SCHEMA, FactsSink,
    RuntimeError,
};
use patina_dst_abi::{ClockKind, OpenFlags, Operation};

use patina_dst_time_virtual::VirtualClock;
use patina_dst_trace::{TraceBundle, TraceError};
use std::ffi::OsString;
use std::fs;
use tempfile::tempdir;

use crate::filesystem::tests::WrongHandleFs;

use crate::tests::exercise;

/// The facts channel is sourced from the same structs the report lines are
/// formatted from. Red before the channel existed: the document is absent
/// while `PATINA_FS_FAULT_REPORT` reports the very same numbers.
#[test]
fn a_run_writes_its_fault_planes_to_the_facts_channel() {
    let directory = tempdir().unwrap();
    let facts = directory.path().join("facts.json");
    let config = RuntimeConfig::seeded(9)
        .with_facts_path(&facts)
        .apply_fault_env(|name| (name == ENV_FS_ERROR_PERMILLE).then(|| "300".to_string()))
        .unwrap();
    let mut context = Context::from_config(config).unwrap();
    for index in 0..40u32 {
        let _ = context.write_file(&format!("/entry-{index}"), b"payload");
    }
    // The structured plane and the printed line must agree, so capture the
    // report the line is built from before finalization consumes the context.
    let report = context.fs_fault_report().expect("fs faults are modeled");
    let line = fs_fault_report_line(&report);
    context.finish().unwrap();

    let bytes = std::fs::read(&facts).expect("the facts channel was written");
    let document: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(document["schema"], FACTS_SCHEMA);
    let plane = &document["fault_reports"]["fs"];
    assert_eq!(plane["eligible_ops"], report.eligible_ops);
    assert_eq!(plane["errors_injected"], report.errors_injected);
    assert_eq!(plane["vacuous"], report.is_vacuous());
    assert!(
        report.errors_injected > 0,
        "the knob must have fired for this to prove anything: {line}"
    );
    // The breakdown the scalar cannot express reaches the document too.
    assert_eq!(
        plane["errors_by_op"]
            .as_object()
            .unwrap()
            .values()
            .map(|value| value.as_u64().unwrap())
            .sum::<u64>(),
        report.errors_injected
    );
}

/// Same seed, same document — byte for byte. The envelope built from it
/// inherits that determinism.
#[test]
fn the_facts_document_repeats_byte_identically() {
    let directory = tempdir().unwrap();
    let write_once = |name: &str| {
        let facts = directory.path().join(name);
        let config = RuntimeConfig::seeded(3)
            .with_facts_path(&facts)
            .apply_fault_env(|name| (name == ENV_FS_ERROR_PERMILLE).then(|| "250".to_string()))
            .unwrap();
        let mut context = Context::from_config(config).unwrap();
        for index in 0..20u32 {
            let _ = context.write_file(&format!("/entry-{index}"), b"payload");
        }
        context.finish().unwrap();
        std::fs::read(&facts).unwrap()
    };
    assert_eq!(write_once("first.json"), write_once("second.json"));
}

/// A run nobody asked facts of writes nothing and is otherwise unchanged.
#[test]
fn no_channel_means_no_document() {
    let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
    context.write_file("/data", b"payload").unwrap();
    // The facts are still computable on demand; only the emission is opt-in.
    let facts = context.run_facts();
    assert_eq!(facts["schema"], FACTS_SCHEMA);
    context.finish().unwrap();
}

/// Two live destinations would silently drop one document.
#[test]
fn a_path_and_a_sink_together_are_refused() {
    struct Discard;
    impl FactsSink for Discard {
        fn write_facts(&mut self, _bytes: &[u8]) -> std::io::Result<()> {
            Ok(())
        }
    }
    let built = RuntimeBuilder::new(RuntimeConfig::seeded(1).with_facts_path("/facts.json"))
        .with_default_drivers()
        .with_facts_sink(Discard)
        .build();
    let Err(error) = built else {
        panic!("both destinations must be refused");
    };
    assert!(
        error.to_string().contains("use exactly one"),
        "unexpected error: {error}"
    );
}

#[derive(Clone, Default)]
struct SharedTransport {
    bytes: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
}

impl SharedTransport {
    fn stored(&self) -> Vec<u8> {
        self.bytes.lock().unwrap().clone()
    }
}

impl TraceTransport for SharedTransport {
    fn read_bundle(&mut self) -> std::io::Result<Vec<u8>> {
        Ok(self.stored())
    }

    fn write_bundle(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        *self.bytes.lock().unwrap() = bytes.to_vec();
        Ok(())
    }
}

// Class pairing: tests/boot_origin.rs signed startup bounds.
#[test]
fn trace_transport_rejects_out_of_range_startup_clocks() {
    let transport = SharedTransport::default();
    RuntimeBuilder::new(RuntimeConfig::record_transport(1, "bounds"))
        .with_default_drivers()
        .with_trace_transport(transport.clone())
        .build()
        .unwrap()
        .finish()
        .unwrap();
    let mut bundle: TraceBundle = serde_json::from_slice(&transport.stored()).unwrap();
    for (origin, epoch) in [(i64::MAX as u64 + 1, 0), (1, i64::MAX as u64)] {
        bundle.metadata.boot_origin_nanos = origin;
        bundle.metadata.realtime_epoch_nanos = epoch;
        let mut invalid = SharedTransport::default();
        invalid.write_bundle(&bundle.to_bytes().unwrap()).unwrap();
        assert!(matches!(
            RuntimeBuilder::new(RuntimeConfig::replay_transport_timeline("main", "bounds"))
                .with_default_drivers()
                .with_trace_transport(invalid)
                .build(),
            Err(RuntimeError::Config(_))
        ));
    }
}

#[test]
fn trace_transport_records_and_replays_without_paths() {
    let transport = SharedTransport::default();
    let origin = DEFAULT_BOOT_ORIGIN_NANOS + 321;
    let mut record = RuntimeBuilder::new(
        RuntimeConfig::record_transport(99, "fixture-v1").with_boot_origin_nanos(origin),
    )
    .with_default_drivers()
    .with_trace_transport(transport.clone())
    .build()
    .unwrap();
    let expected = exercise(&mut record).unwrap();
    record.finish().unwrap();
    assert!(!transport.stored().is_empty());

    let mut replay = RuntimeBuilder::new(RuntimeConfig::replay_transport_timeline(
        "main",
        "fixture-v1",
    ))
    .with_default_drivers()
    .with_trace_transport(transport.clone())
    .build()
    .unwrap();
    assert_eq!(replay.root_seed(), 99);
    assert_eq!(replay.monotonic_now_unrecorded().unwrap(), origin);
    assert_eq!(exercise(&mut replay).unwrap(), expected);
    replay.finish().unwrap();

    let unconsumed = RuntimeBuilder::new(RuntimeConfig::replay_transport_timeline(
        "main",
        "fixture-v1",
    ))
    .with_default_drivers()
    .with_trace_transport(transport)
    .build()
    .unwrap();
    assert!(matches!(
        unconsumed.finish(),
        Err(RuntimeError::Trace(TraceError::UnconsumedEvents { .. }))
    ));
}

#[test]
fn crash_writes_the_incarnation_recording_ending_with_the_trigger() {
    let transport = SharedTransport::default();
    let mut record = RuntimeBuilder::new(
        RuntimeConfig::record_transport(3, "fixture-v1").with_crash_at(CrashOp::Open, 1),
    )
    .with_default_drivers()
    .with_trace_transport(transport.clone())
    .build()
    .unwrap();
    let trigger = Operation::FsOpen {
        path: "/".into(),
        flags: OpenFlags::read_only(),
    };
    let crash = record.fs_open("/", OpenFlags::read_only()).unwrap_err();
    assert!(matches!(crash, RuntimeError::InjectedFsCrash(_)));
    let recorded = TraceBundle::from_slice(&transport.stored()).unwrap();
    let last = recorded.timelines[0]
        .decisions
        .last()
        .map(|event| &event.operation);
    assert_eq!(last, Some(&trigger));
}

#[test]
fn trace_transport_configuration_fails_loudly() {
    assert!(matches!(
        RuntimeBuilder::new(RuntimeConfig::record_transport(1, "fixture-v1"))
            .with_default_drivers()
            .build(),
        Err(RuntimeError::Config(_))
    ));
    assert!(matches!(
        RuntimeBuilder::new(RuntimeConfig::seeded(1))
            .with_default_drivers()
            .with_trace_transport(SharedTransport::default())
            .build(),
        Err(RuntimeError::Config(_))
    ));
}

#[test]
fn replay_rejects_changed_operations_and_unconsumed_events() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("run.patina");
    let mut record = Context::from_config(RuntimeConfig::record(1, &path, "fixture-v1")).unwrap();
    record.entropy_bytes(4).unwrap();
    record.finish().unwrap();

    let mut changed = Context::from_config(RuntimeConfig::replay(&path, "fixture-v1")).unwrap();
    assert!(matches!(
        changed.entropy_bytes(5),
        Err(RuntimeError::Trace(TraceError::OperationMismatch { .. }))
    ));

    let untouched = Context::from_config(RuntimeConfig::replay(&path, "fixture-v1")).unwrap();
    assert!(matches!(
        untouched.finish(),
        Err(RuntimeError::Trace(TraceError::UnconsumedEvents { .. }))
    ));
}

#[test]
fn record_mode_rejects_concurrent_and_existing_trace_writers() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("run.patina");
    let first = Context::from_config(RuntimeConfig::record(1, &path, "fixture-v1")).unwrap();
    assert!(matches!(
        Context::from_config(RuntimeConfig::record(1, &path, "fixture-v1")),
        Err(RuntimeError::Config(message)) if message.contains("another Patina recorder")
    ));
    drop(first);

    Context::from_config(RuntimeConfig::record(1, &path, "fixture-v1"))
        .unwrap()
        .finish()
        .unwrap();
    assert!(matches!(
        Context::from_config(RuntimeConfig::record(1, &path, "fixture-v1")),
        Err(RuntimeError::Config(message)) if message.contains("refusing to overwrite")
    ));

    let branch = |id: &str| RuntimeConfig::branch(&path, "main", 0, id, 2, "fixture-v1");
    let first = Context::from_config(branch("first")).unwrap();
    assert!(matches!(
        Context::from_config(branch("second")),
        Err(RuntimeError::Config(message)) if message.contains("another Patina recorder")
    ));
    first.finish().unwrap();

    // A released reservation leaves nothing beside the trace.
    let entries: Vec<_> = fs::read_dir(directory.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(entries, [OsString::from("run.patina")]);
}

#[test]
fn replay_rejects_a_changed_fingerprint() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("run.patina");
    Context::from_config(RuntimeConfig::record(1, &path, "fixture-v1"))
        .unwrap()
        .finish()
        .unwrap();
    assert!(matches!(
        Context::from_config(RuntimeConfig::replay(&path, "fixture-v2")),
        Err(RuntimeError::Trace(TraceError::FingerprintMismatch { .. }))
    ));
}

#[test]
fn branch_replays_the_prefix_and_uses_a_new_seed_for_the_suffix() {
    fn two_decisions(context: &mut Context) -> Result<(Vec<u8>, Vec<u8>), RuntimeError> {
        Ok((context.entropy_bytes(8)?, context.entropy_bytes(8)?))
    }

    let directory = tempdir().unwrap();
    let path = directory.path().join("branches.patina");
    let mut record = Context::from_config(RuntimeConfig::record(7, &path, "branches-v1")).unwrap();
    let main = two_decisions(&mut record).unwrap();
    record.finish().unwrap();

    let mut branch = Context::from_config(RuntimeConfig::branch(
        &path,
        "main",
        1,
        "branch-99",
        99,
        "branches-v1",
    ))
    .unwrap();
    let branched = two_decisions(&mut branch).unwrap();
    branch.finish().unwrap();
    assert_eq!(branched.0, main.0, "the prefix must replay exactly");
    assert_ne!(branched.1, main.1, "the suffix must use the branch seed");

    let mut replay = Context::from_config(RuntimeConfig::replay_timeline(
        &path,
        "branch-99",
        "branches-v1",
    ))
    .unwrap();
    assert_eq!(two_decisions(&mut replay).unwrap(), branched);
    replay.finish().unwrap();
}

#[test]
fn step_budget_stops_before_an_unrecorded_boundary_operation() {
    let mut context = Context::from_config(RuntimeConfig::seeded(1).with_step_budget(2)).unwrap();
    context.entropy_bytes(1).unwrap();
    context.now(ClockKind::Monotonic).unwrap();
    assert_eq!(context.steps(), 2);
    assert!(matches!(
        context.entropy_bytes(1),
        Err(RuntimeError::StepBudgetExceeded { budget: 2 })
    ));
    assert_eq!(context.steps(), 2);
}

#[test]
fn a_step_budget_abort_under_record_leaves_a_loadable_truncated_trace() {
    // The artifact that would explain a wedge is exactly the one a budget
    // abort used to destroy: `finish` is never reached in the interposed
    // families, so the pre-created trace file stayed empty.
    let directory = tempdir().unwrap();
    let path = directory.path().join("budget.patina");
    let mut context =
        Context::from_config(RuntimeConfig::record(4, &path, "budget-v1").with_step_budget(6))
            .unwrap();
    context.write_file("/a", b"one").unwrap();
    context.write_file("/b", b"two").unwrap();
    let error = context
        .write_file("/c", b"three")
        .expect_err("the budget must stop the run");
    assert!(matches!(
        error,
        RuntimeError::StepBudgetExceeded { budget: 6 }
    ));

    // The trace exists, loads, and carries the operations up to the abort —
    // truncated but structurally valid.
    let bundle = TraceBundle::load(&path).expect("the truncated trace must load");
    let events = &bundle.timelines[0].decisions;
    assert_eq!(
        events.len(),
        6,
        "every op performed before the stop is kept"
    );
    assert!(
        events
            .iter()
            .any(|event| matches!(&event.operation, Operation::FsWrite { .. }))
    );
    // `finish` must not write a second bundle over the flushed one.
    context.finish().unwrap();
    assert_eq!(
        TraceBundle::load(&path).unwrap().timelines,
        bundle.timelines
    );
}

#[test]
fn replay_compares_deterministic_driver_outcomes() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("run.patina");
    let mut record = Context::from_config(RuntimeConfig::record(1, &path, "fixture-v1")).unwrap();
    record
        .fs_open("/value", OpenFlags::create_truncate_write())
        .unwrap();
    record.finish().unwrap();

    // The explicit clock must run on the recorded (default) epoch; one on
    // any other epoch is refused up front, before any outcome is compared.
    let mut replay = RuntimeBuilder::new(RuntimeConfig::replay(&path, "fixture-v1"))
        .with_clock(VirtualClock::default())
        .with_filesystem(WrongHandleFs)
        .build()
        .unwrap();
    assert!(matches!(
        replay.fs_open("/value", OpenFlags::create_truncate_write()),
        Err(RuntimeError::Trace(TraceError::OutcomeMismatch { .. }))
    ));
}
