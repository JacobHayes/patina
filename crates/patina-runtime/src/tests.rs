//! Tests spanning runtime modules and crate entry points.

use crate::config::RuntimeConfig;
use crate::{Context, RuntimeError, run_with_context};
use patina_dst_abi::{ClockKind, EffectError, ErrorCode, TaskId};

use patina_dst_trace::TraceBundle;
use std::env;
use tempfile::tempdir;

pub(super) fn exercise(context: &mut Context) -> Result<Vec<u8>, RuntimeError> {
    let entropy = context.entropy_bytes(12)?;
    context.write_file("/state/value", &entropy)?;
    assert_eq!(context.read_file("/state/value")?, entropy);
    let start = context.now(ClockKind::Monotonic)?;
    context.sleep_for(250)?;
    assert_eq!(context.now(ClockKind::Monotonic)? - start, 250);
    Ok(entropy)
}

#[test]
fn same_seed_repeats_and_different_seed_varies() {
    let mut first = Context::from_config(RuntimeConfig::seeded(7)).unwrap();
    let first_result = exercise(&mut first).unwrap();
    first.finish().unwrap();

    let mut second = Context::from_config(RuntimeConfig::seeded(7)).unwrap();
    let second_result = exercise(&mut second).unwrap();
    second.finish().unwrap();

    let mut different = Context::from_config(RuntimeConfig::seeded(8)).unwrap();
    let different_result = exercise(&mut different).unwrap();
    different.finish().unwrap();

    assert_eq!(first_result, second_result);
    assert_ne!(first_result, different_result);
}

#[test]
fn record_and_replay_cover_all_initial_effects() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("run.patina");
    let mut record = Context::from_config(RuntimeConfig::record(99, &path, "fixture-v1")).unwrap();
    let expected = exercise(&mut record).unwrap();
    record.finish().unwrap();

    let mut replay = Context::from_config(RuntimeConfig::replay(&path, "fixture-v1")).unwrap();
    assert_eq!(replay.root_seed(), 99);
    assert_eq!(exercise(&mut replay).unwrap(), expected);
    replay.finish().unwrap();
}

#[test]
fn record_and_replay_cross_scheduler_network_clock_and_filesystem() {
    fn simulation(context: &mut Context) -> Result<(TaskId, Vec<u8>), RuntimeError> {
        let first = context.task_spawn("first")?;
        context.task_spawn("second")?;
        let selected = context.scheduler_next()?.expect("tasks are runnable");
        context.task_yield(selected)?;

        let left = context.net_bind("left")?;
        let right = context.net_bind("right")?;
        context.net_send(left, "right", b"packet")?;
        let packet = context
            .net_recv(right)?
            .expect("zero-latency packet is ready");
        context.write_file("/state/packet", &packet.bytes)?;
        context.net_close(left)?;
        context.net_close(right)?;
        assert_eq!(first, TaskId(1));
        Ok((selected, context.read_file("/state/packet")?))
    }

    let directory = tempdir().unwrap();
    let path = directory.path().join("simulation.patina");
    let mut record =
        Context::from_config(RuntimeConfig::record(77, &path, "simulation-v1")).unwrap();
    let expected = simulation(&mut record).unwrap();
    record.finish().unwrap();

    let mut replay = Context::from_config(RuntimeConfig::replay(&path, "simulation-v1")).unwrap();
    assert_eq!(simulation(&mut replay).unwrap(), expected);
    replay.finish().unwrap();
}

#[test]
fn run_with_context_finalizes_recording_when_the_application_returns_an_error() {
    // The explicit-context `run` path always finalizes: a recorded run whose
    // closure fails still flushes the trace and surfaces the closure error.
    let directory = tempdir().unwrap();
    let trace = directory.path().join("failed-run.patina");
    let context = Context::from_config(RuntimeConfig::record(5, &trace, "fixture-v1")).unwrap();
    let result = run_with_context(context, |_| {
        Err::<(), _>(EffectError::new(ErrorCode::Denied, "application failed").into())
    });
    assert!(matches!(result, Err(RuntimeError::Effect(_))));
    assert!(trace.is_file());
}

/// A process that dies without unwinding — an abort, a kill, `exit`, a
/// panic=abort guest, a runtime held in a global — runs no destructor, so
/// the claim on a trace path has to be one the kernel releases. Red while
/// the claim was a sentinel file that only `Drop` removed: the path stayed
/// refused as "another Patina recorder may be active" forever. The child is
/// this test re-executed; it reserves the path and aborts.
#[cfg(unix)]
#[test]
fn a_recorder_that_dies_without_unwinding_leaves_its_path_recordable() {
    use std::os::unix::process::ExitStatusExt;
    const CHILD_TRACE: &str = "PATINA_TEST_ABORTING_RECORDER_TRACE";
    const SIGABRT: i32 = 6;
    if let Some(trace) = env::var_os(CHILD_TRACE) {
        let _recorder = Context::from_config(RuntimeConfig::record(1, trace, "fp")).unwrap();
        std::process::abort();
    }
    let directory = tempdir().unwrap();
    let trace = directory.path().join("aborted.patina");
    let status = std::process::Command::new(env::current_exe().unwrap())
        .args([
            "--exact",
            "tests::a_recorder_that_dies_without_unwinding_leaves_its_path_recordable",
            "--nocapture",
        ])
        .env(CHILD_TRACE, &trace)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert_eq!(
        status.signal(),
        Some(SIGABRT),
        "the child must abort while holding the reservation: {status}"
    );
    assert!(!trace.exists(), "the aborted recorder wrote no trace");
    let lock_file = directory.path().join(".aborted.patina.lock");
    assert!(
        lock_file.exists(),
        "the aborted recorder left its lock file"
    );

    let recorder = Context::from_config(RuntimeConfig::record(2, &trace, "fp")).unwrap();
    recorder.finish().unwrap();
    TraceBundle::load(&trace).unwrap();
    assert!(!lock_file.exists());
}
