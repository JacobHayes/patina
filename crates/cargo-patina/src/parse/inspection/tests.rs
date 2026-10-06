//! Argument parsing regression tests.

use super::*;
use crate::tests::{parse_error, strings};
use crate::{trace_cmd, trace_view};
use std::path::PathBuf;

#[test]
fn parses_trace_subcommands_and_events_filters() {
    match parse(strings(&[
        "trace",
        "info",
        "--timeline",
        "b1",
        "run.patina",
    ]))
    .unwrap()
    {
        ParseResult::Trace(trace_cmd::TraceInvocation::Info(info)) => {
            assert_eq!(info.path, PathBuf::from("run.patina"));
            assert_eq!(info.timeline, "b1");
        }
        _ => panic!("expected trace info"),
    }

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
            assert_eq!(events.timeline, "main");
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
        parse_error(&["trace", "events", "--kind", "nope", "run.patina"])
            .contains("unknown --kind token")
    );
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
        .contains("mutually exclusive")
    );
    match parse(strings(&["trace", "stats", "run.patina", "--timeline=b2"])).unwrap() {
        ParseResult::Trace(trace_cmd::TraceInvocation::Stats(stats)) => {
            assert_eq!(stats.path, PathBuf::from("run.patina"));
            assert_eq!(stats.timeline, "b2");
        }
        _ => panic!("expected trace stats"),
    }

    match parse(strings(&[
        "trace",
        "diff",
        "a.patina",
        "--context",
        "0",
        "b.patina",
        "--timeline",
        "main",
    ]))
    .unwrap()
    {
        ParseResult::Trace(trace_cmd::TraceInvocation::Diff(diff)) => {
            assert_eq!(diff.a, PathBuf::from("a.patina"));
            assert_eq!(diff.b, PathBuf::from("b.patina"));
            assert_eq!(diff.context, 0);
            assert_eq!(diff.timeline, "main");
        }
        _ => panic!("expected trace diff"),
    }

    assert!(
        parse_error(&["trace", "info", "--kind", "fs_write", "run.patina"])
            .contains("does not accept --kind")
    );
    assert!(
        parse_error(&["trace", "stats", "--first", "1", "run.patina"])
            .contains("does not accept --first")
    );
    assert!(parse_error(&["trace", "diff", "a.patina"]).contains("second trace"));
}
