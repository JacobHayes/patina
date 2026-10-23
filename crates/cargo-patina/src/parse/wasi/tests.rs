//! Argument parsing regression tests.

use super::*;
use crate::tests::strings;
use crate::{ArtifactRef, Mode};
use patina_dst_wasi_host::MountPolicy;
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
        "--preopen",
        "/default",
        "--preopen",
        "/readwrite:rw",
        "--fuel",
        "99",
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
    assert_eq!(invocation.fuel, 99);
    assert_eq!(invocation.resource_limits.fuel, Some(99));
    assert_eq!(invocation.arguments, ["one"]);
    assert_eq!(invocation.environment["MODE"], "test");
    assert_eq!(invocation.sockets.len(), 2);
    assert_eq!(invocation.sockets[0].fd, 4);
    // A preopen's policy defaults to read-write.
    let preopens: Vec<_> = invocation
        .preopens
        .iter()
        .map(|preopen| (preopen.guest_path.as_str(), preopen.policy))
        .collect();
    assert_eq!(
        preopens,
        [
            ("/data", MountPolicy::ReadOnly),
            ("/default", MountPolicy::ReadWrite),
            ("/readwrite", MountPolicy::ReadWrite),
        ]
    );
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
