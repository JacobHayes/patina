//! Argument parsing regression tests.

use super::*;
use crate::tests::{strings, wasi_invocation};
use crate::{ArtifactRef, Mode};
use patina_dst_wasi_host::{DEFAULT_WASM_FUEL, MountPolicy};
use std::path::PathBuf;

#[test]
fn parses_wasi_run_record_and_branch_modes() {
    let invocation = parse_wasi_run(strings(&[
        "module.wasm",
        "--seed",
        "7",
        "--record",
        "run.patina",
        "--arg",
        "one",
        "--env",
        "MODE=test",
        "--socket",
        "4=node-a->node-b",
        "--socket",
        "5=node-b->node-a",
        "--preopen",
        "/data:ro",
        "--max-memory-pages",
        "128",
        "--max-descriptors",
        "32",
        "--max-preopens",
        "4",
        "--max-path-bytes",
        "512",
        "--max-io-bytes",
        "4096",
        "--max-iovecs",
        "16",
    ]))
    .unwrap();
    assert_eq!(
        invocation.module,
        ArtifactRef::Prebuilt(PathBuf::from("module.wasm"))
    );
    assert_eq!(invocation.fuel, DEFAULT_WASM_FUEL);
    assert_eq!(invocation.arguments, ["one"]);
    assert_eq!(invocation.environment["MODE"], "test");
    assert_eq!(invocation.sockets.len(), 2);
    assert_eq!(invocation.sockets[0].fd, 4);
    assert_eq!(invocation.preopens.len(), 1);
    assert_eq!(invocation.preopens[0].guest_path, "/data");
    assert_eq!(invocation.preopens[0].policy, MountPolicy::ReadOnly);
    assert_eq!(invocation.resource_limits.max_memory_pages, Some(128));
    assert_eq!(invocation.resource_limits.max_descriptors, Some(32));
    assert_eq!(invocation.resource_limits.max_preopens, Some(4));
    assert_eq!(invocation.resource_limits.max_path_bytes, Some(512));
    assert_eq!(invocation.resource_limits.max_io_bytes, Some(4096));
    assert_eq!(invocation.resource_limits.max_iovecs, Some(16));
    assert_eq!(
        invocation.mode,
        Mode::Record {
            seed: 7,
            path: "run.patina".into()
        }
    );

    // Replaying and branching a WASI trace is the `replay` verb's job now:
    // the trace is a positional and the flags are semantic-free.
    let module = ArtifactRef::Prebuilt(PathBuf::from("module.wasm"));
    let branched = parse_wasi_replay(
        module.clone(),
        "run.patina".into(),
        strings(&[
            "--branch",
            "--from",
            "3",
            "--branch-seed",
            "8",
            "--branch-id",
            "wasi-branch",
        ]),
    )
    .unwrap();
    assert_eq!(
        branched.mode,
        Mode::Branch {
            path: "run.patina".into(),
            parent: "main".into(),
            from_sequence: 3,
            branch_seed: 8,
            branch_id: "wasi-branch".into(),
        }
    );

    // Strict replay of a named timeline, and the recorded host inputs
    // (`--socket`) still re-supplied as genuine host state.
    let replayed = parse_wasi_replay(
        module,
        "run.patina".into(),
        strings(&["--timeline", "wasi-branch", "--socket", "4=node-a->node-b"]),
    )
    .unwrap();
    assert_eq!(
        replayed.mode,
        Mode::Replay {
            path: "run.patina".into(),
            timeline: "wasi-branch".into(),
        }
    );
    assert_eq!(replayed.sockets.len(), 1);
    // A semantic flag on WASI replay is refused: the trace is authoritative.
    assert!(
        parse_wasi_replay(
            ArtifactRef::Prebuilt(PathBuf::from("module.wasm")),
            "run.patina".into(),
            strings(&["--fs-crash-at", "close:1"]),
        )
        .is_err()
    );
}

#[test]
fn parses_wasi_preopen_policy_forms_and_limits() {
    let invocation = wasi_invocation(&[
        "wasi-run",
        "module.wasm",
        "--fuel",
        "99",
        "--preopen",
        "/default",
        "--preopen",
        "/readonly:ro",
        "--preopen",
        "/readwrite:rw",
        "--max-memory-pages",
        "2",
        "--max-descriptors",
        "3",
        "--max-preopens",
        "4",
        "--max-path-bytes",
        "5",
        "--max-io-bytes",
        "6",
        "--max-iovecs",
        "7",
    ]);
    assert_eq!(invocation.fuel, 99);
    assert_eq!(invocation.resource_limits.fuel, Some(99));
    assert_eq!(invocation.preopens.len(), 3);
    assert_eq!(invocation.preopens[0].guest_path, "/default");
    assert_eq!(invocation.preopens[0].policy, MountPolicy::ReadWrite);
    assert_eq!(invocation.preopens[1].guest_path, "/readonly");
    assert_eq!(invocation.preopens[1].policy, MountPolicy::ReadOnly);
    assert_eq!(invocation.preopens[2].guest_path, "/readwrite");
    assert_eq!(invocation.preopens[2].policy, MountPolicy::ReadWrite);
    assert_eq!(invocation.resource_limits.max_memory_pages, Some(2));
    assert_eq!(invocation.resource_limits.max_descriptors, Some(3));
    assert_eq!(invocation.resource_limits.max_preopens, Some(4));
    assert_eq!(invocation.resource_limits.max_path_bytes, Some(5));
    assert_eq!(invocation.resource_limits.max_io_bytes, Some(6));
    assert_eq!(invocation.resource_limits.max_iovecs, Some(7));
}

#[test]
fn rejects_missing_and_duplicate_wasi_option_values() {
    // Value-GRAMMAR rejection is covered generically by
    // `registry_value_grammars_match_the_parsers`; what stays here are the
    // non-grammar shapes: a required-value flag with no value at all, and a
    // repeated non-repeatable flag.
    assert!(parse_wasi_run(strings(&["module.wasm", "--preopen"])).is_err());
    assert!(
        parse_wasi_run(strings(&[
            "module.wasm",
            "--max-iovecs",
            "1",
            "--max-iovecs",
            "2",
        ]))
        .is_err()
    );
}
