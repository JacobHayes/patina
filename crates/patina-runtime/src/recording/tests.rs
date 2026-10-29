//! Tests for trace transport, recording lifecycle, effect reconciliation, and outcome decoding.

use crate::EntropyWait;
use crate::builder::RuntimeBuilder;
use crate::config::RuntimeConfig;
use crate::recording::TraceTransport;
use crate::reports::fs_fault_report_line;
use crate::{
    Context, DEFAULT_BOOT_ORIGIN_NANOS, ENV_FS_ERROR_PERMILLE, FACTS_SCHEMA, RuntimeError,
};
use patina_dst_abi::{ClockKind, OpenFlags, Operation};

use crate::VirtualClock;
use patina_dst_trace::{TraceBundle, TraceError};
use std::ffi::OsString;
use std::fs;
use tempfile::tempdir;

use crate::filesystem::tests::WrongHandleFs;

use crate::tests::{exercise, with_facts_file};

/// The facts channel is sourced from the same structs the report lines are
/// formatted from. Red before the channel existed: the document is absent
/// while `PATINA_FS_FAULT_REPORT` reports the very same numbers.
#[test]
fn a_run_writes_its_fault_planes_to_the_facts_channel() {
    let directory = tempdir().unwrap();
    let facts = directory.path().join("facts.json");
    let config = RuntimeConfig::seeded(9)
        .apply_fault_env(|name| (name == ENV_FS_ERROR_PERMILLE).then(|| "300".to_string()))
        .unwrap();
    let mut context = with_facts_file(config, &facts);
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

#[test]
fn trace_transport_records_and_replays_without_paths() {
    let transport = SharedTransport::default();
    let origin = DEFAULT_BOOT_ORIGIN_NANOS + 321;
    let mut record = RuntimeBuilder::new(
        RuntimeConfig::record_transport(99, "fixture-v1").with_boot_origin_nanos(origin),
    )
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
        RuntimeConfig::record_transport(3, "fixture-v1")
            .with_machine_crash_permille(1000)
            .with_crash_supervisor(),
    )
    .with_trace_transport(transport.clone())
    .build()
    .unwrap();
    let trigger = Operation::FsOpen {
        path: "/f".into(),
        flags: OpenFlags::create_truncate_write(),
    };
    let crash = record
        .fs_open("/f", OpenFlags::create_truncate_write())
        .unwrap_err();
    assert!(matches!(crash, RuntimeError::InjectedCrash(_)));
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
        RuntimeBuilder::new(RuntimeConfig::record_transport(1, "fixture-v1")).build(),
        Err(RuntimeError::Config(_))
    ));
    assert!(matches!(
        RuntimeBuilder::new(RuntimeConfig::seeded(1))
            .with_trace_transport(SharedTransport::default())
            .build(),
        Err(RuntimeError::Config(_))
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
fn branch_replays_the_prefix_and_uses_a_new_seed_for_the_suffix() {
    fn two_decisions(context: &mut Context) -> Result<(Vec<u8>, Vec<u8>), RuntimeError> {
        Ok((
            context.entropy_bytes(8, EntropyWait::UntilReady)?,
            context.entropy_bytes(8, EntropyWait::UntilReady)?,
        ))
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
    // The refused operation is not counted: the budget stops before it.
    assert_eq!(context.steps(), 6);

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

/// A replay that leaves its trace says so on the facts channel, as the trace
/// layer's typed divergence kind; a replay that follows its trace does not.
/// The channel is the supervisor's evidence of divergence because the guest
/// cannot write it, unlike any line of the run's text.
#[test]
fn a_replay_divergence_reaches_the_facts_channel_as_its_kind() {
    let directory = tempdir().unwrap();
    let trace = directory.path().join("run.patina");
    let mut record = Context::from_config(RuntimeConfig::record(4, &trace, "fp")).unwrap();
    record.write_file("/a", b"payload").unwrap();
    record.write_file("/b", b"payload").unwrap();
    record.finish().unwrap();

    let replay = |name: &str, paths: &[&str]| -> serde_json::Value {
        let facts = directory.path().join(name);
        let mut replay = with_facts_file(RuntimeConfig::replay(&trace, "fp"), &facts);
        for path in paths {
            let _ = replay.write_file(path, b"payload");
        }
        let _ = replay.finish();
        last_facts(&facts)
    };
    assert!(
        replay("followed.json", &["/a", "/b"])
            .get("replay_divergence")
            .is_none()
    );
    for (paths, kind) in [
        (&["/a"][..], "unconsumed_events"),
        (&["/a", "/c"][..], "operation_mismatch"),
        (&["/a", "/b", "/c"][..], "trace_exhausted"),
    ] {
        let name = format!("{kind}.json");
        assert_eq!(replay(&name, paths)["replay_divergence"], kind, "{paths:?}");
    }
}

/// A divergence the runtime finds itself, outside the trace layer, reaches the
/// facts channel the same way: here the time model, where the replay charged a
/// call the recording did not and so derives a different monotonic time.
#[test]
fn a_time_model_divergence_reaches_the_facts_channel() {
    use patina_dst_abi::{ChargeClass, ChargeCounts};
    let directory = tempdir().unwrap();
    let trace = directory.path().join("clock.patina");
    let mut record = Context::from_config(RuntimeConfig::record(4, &trace, "fp")).unwrap();
    record.now(ClockKind::Monotonic).unwrap();
    record.finish().unwrap();

    let facts = directory.path().join("facts.json");
    let mut replay = with_facts_file(RuntimeConfig::replay(&trace, "fp"), &facts);
    let mut counts = ChargeCounts::new();
    counts.count(ChargeClass::Clock);
    replay.charge_calls(None, counts).unwrap();
    assert!(matches!(
        replay.now(ClockKind::Monotonic),
        Err(RuntimeError::TimeModel { .. })
    ));
    let document = last_facts(&facts);
    assert_eq!(document["replay_divergence"], "time_model_mismatch");
}

/// The last complete document the run appended to its facts channel.
fn last_facts(path: &std::path::Path) -> serde_json::Value {
    let text = fs::read_to_string(path).unwrap();
    serde_json::from_str(
        text.lines()
            .rev()
            .find(|line| !line.trim().is_empty())
            .unwrap(),
    )
    .unwrap()
}
