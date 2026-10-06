//! Regression tests for summary.

use super::*;
use patina_dst_abi::{Fd, OpenFlags};

/// An `fs_open` line has to SAY what the open asked for. The flag word and
/// the creation mode live inside the nested `flags` object, where the
/// generic scalar scan cannot see them, so both are rendered explicitly —
/// and a mode is only readable in octal. RED before the nested branch: an
/// `fs_open` rendered `path=…` and nothing else, so a reader could not tell
/// a path-only directory handle (which charges nothing and cannot be read)
/// from a read-only open of the same directory.
#[test]
fn an_fs_open_renders_its_flag_word_and_its_creation_mode() {
    let render = |flags: OpenFlags| {
        let operation = Operation::FsOpen {
            path: "/d".into(),
            flags,
        };
        summarize(
            operation_kind(&operation),
            &serde_json::to_value(&operation).unwrap(),
            &serde_json::to_value(Outcome::Handle(Fd(3))).unwrap(),
        )
    };

    let creating = render(OpenFlags {
        mode: 0o644,
        ..OpenFlags::create_truncate_write()
    });
    assert!(
        creating.contains("flags=write|create|truncate"),
        "the flag word must be rendered: {creating}"
    );
    assert!(
        creating.contains("mode=0o644"),
        "a creation mode is only readable in octal: {creating}"
    );

    // A non-creating open reads no third argument, so there is no mode to
    // show — rendering `mode=0o0` would be an argument the kernel never
    // looked at.
    let reading = render(OpenFlags::read_only());
    assert!(reading.contains("flags=read"), "{reading}");
    assert!(!reading.contains("mode="), "{reading}");

    // The two directory opens are distinguishable in the trace.
    let location = render(OpenFlags::path_only());
    assert!(location.contains("flags=path_only"), "{location}");
    assert!(!location.contains("read"), "{location}");
}
