//! Argument parsing regression tests.

use super::*;
use crate::tests::{parse_error, strings};
use crate::{trace_cmd, trace_view};
use std::path::PathBuf;

#[test]
fn parses_trace_subcommands_and_events_filters() {
    match parse(strings(&[
        "trace",
        "events",
        "--kind",
        "fs_write,network",
        "--task",
        "main",
        "--task=2",
        "--seq",
        "2..5",
        "--first",
        "3",
        "run.patina",
    ]))
    .unwrap()
    {
        ParseResult::Trace(trace_cmd::TraceInvocation::Events(events)) => {
            assert_eq!(events.path, PathBuf::from("run.patina"));
            assert!(events.filters.op_kinds.contains("fs_write"));
            assert!(
                events
                    .filters
                    .categories
                    .contains(&trace_view::Category::Net)
            );
            assert!(events.filters.tasks.contains(&trace_view::LaneKey::Main));
            assert!(events.filters.tasks.contains(&trace_view::LaneKey::Task(2)));
            assert_eq!(events.filters.seq, Some((2, 5)));
            assert_eq!(events.filters.first, Some(3));
        }
        _ => panic!("expected trace events"),
    }

    assert!(
        parse_error(&[
            "trace",
            "events",
            "--first",
            "1",
            "--last",
            "1",
            "run.patina",
        ])
        .contains("--first")
    );
    match parse(strings(&[
        "trace",
        "diff",
        "a.patina",
        "--context",
        "0",
        "b.patina",
    ]))
    .unwrap()
    {
        ParseResult::Trace(trace_cmd::TraceInvocation::Diff(diff)) => {
            assert_eq!(diff.a, PathBuf::from("a.patina"));
            assert_eq!(diff.b, PathBuf::from("b.patina"));
            assert_eq!(diff.context, 0);
        }
        _ => panic!("expected trace diff"),
    }

    assert!(parse_error(&["trace", "info", "--kind", "fs_write", "run.patina"]).contains("--kind"));
}
