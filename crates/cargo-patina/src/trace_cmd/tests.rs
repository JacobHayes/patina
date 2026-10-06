//! Regression tests for trace_cmd.

use super::*;
use patina_dst_abi::{ClockKind, Fd, Operation, Outcome, TaskId};
use patina_dst_trace::{RunMetadata, TraceBundle, TraceEvent};

pub(super) fn bundle_with(events: Vec<(Operation, Outcome)>) -> TraceBundle {
    let decisions = events
        .into_iter()
        .enumerate()
        .map(|(i, (operation, outcome))| TraceEvent::new(i as u64, operation, outcome))
        .collect();
    TraceBundle::new(RunMetadata::new(7, "fp-test", 0, "patina"), decisions)
}

pub(super) fn sample_flat() -> FlatTrace {
    let bundle = bundle_with(vec![
        (
            Operation::ClockNow {
                clock: ClockKind::Monotonic,
            },
            Outcome::U64(10),
        ),
        (
            Operation::TaskSpawn {
                label: "worker".into(),
            },
            Outcome::Task(TaskId(1)),
        ),
        (
            Operation::SchedulerNext,
            Outcome::OptionalTask(Some(TaskId(1))),
        ),
        (Operation::FsSync { fd: Fd(3) }, Outcome::Unit),
        (Operation::TaskComplete { task: TaskId(1) }, Outcome::Unit),
    ]);
    let raw = serde_json::to_value(&bundle).unwrap();
    trace_view::flatten(&bundle, &raw, "main").unwrap()
}
