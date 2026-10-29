//! Execution verb registry rows.

use super::*;

// ===========================================================================
// The verb registry
// ===========================================================================

pub(super) const RUN: Verb = Verb {
    name: "run",
    summary: "Build (on the fly) and/or run an artifact under the deterministic runtime.",
    synopsis: &[
        "cargo patina run <BINARY> [--seed N | --record PATH] [--env K=V]... [--budget N] [--coverage-out PATH] [--fingerprint STR] [--mount HOST_DIR] [FAULT OPTIONS] [BUGGIFY/SCHEDULE/LIVENESS OPTIONS] [--allow SYMBOL]... [-- PROGRAM ARGS]",
        "cargo patina run <SOURCE.rs|DIR|Cargo.toml> [--release] [RUN OPTIONS]   (builds on the fly, then runs)",
    ],
    prose: "\
`run` is source-first with artifacts accepted uniformly. A built artifact \
(recognized by its leading magic bytes) is used as-is; a <SOURCE.rs|DIR|Cargo.toml> \
is built on the fly through the same pipeline as `build` and its product is run \
(a one-line PATINA_BUILD_ON_RUN note reports the built artifact and its hash).\n\
\n\
`run <BINARY>` runs a shim-linked native binary under a pre-run default-deny audit: every externally resolved symbol must \
be interposed or known-safe, and any unsupported symbol on the \
blocking/time/scheduling/effect surface hard-errors. --allow SYMBOL adds a \
known-safe symbol; --allow-unsupported-symbols <all|name,...> downgrades matching \
denials to a loud warning (an instruction-class finding matches by its own \
`instruction@.text+OFF` name or by the containing symbol its provenance names).\n\
\n\
A `patina-dst-harness` (configure-then-run) binary is recognised by the marker it \
embeds and defers runtime installation on its own; no flag is needed on `run` or \
`replay`. Reproduce a recorded run with \
`cargo patina replay`.",
    families: &[fam(Family::Sole, "`run`", None)],
    groups: &[
        Group {
            title: "Patina options",
            families: SOLE,
            flags: &[
                f(
                    "--seed",
                    None,
                    Value::Required("U64", Kind::U64),
                    "Deterministic root seed (default 0).",
                    false,
                ),
                f(
                    "--record",
                    None,
                    Value::Required("PATH", Kind::Path),
                    "Record boundary operations and outcomes to PATH.",
                    false,
                ),
                f(
                    "--budget",
                    None,
                    Value::Required("STEPS", Kind::U64),
                    "Maximum boundary operations before explicit failure.",
                    false,
                ),
                f(
                    "--realtime-epoch",
                    None,
                    Value::Required("RFC3339", Kind::UtcTimestamp),
                    "Realtime at monotonic zero, as an RFC 3339 UTC timestamp (default 2026-07-22T23:00:09Z). Guest-start realtime adds the boot origin (default uptime 12345.678901234s); recorded and restored on replay.",
                    false,
                ),
                f(
                    "--hostname",
                    None,
                    Value::Required("NAME", Kind::Hostname),
                    "The node name the guest's virtual kernel reports through uname/gethostname (default patina; at most 64 bytes, no NUL; recorded and restored on replay).",
                    false,
                ),
            ],
        },
        Group {
            title: "Source-first selection (building a source/package on the fly)",
            families: SOLE,
            flags: SOURCE_SELECT,
        },
        Group {
            title: "Build profile (source-first)",
            families: SOLE,
            flags: &[f(
                "--release",
                None,
                Value::None,
                "Build the on-the-fly guest in release mode (default debug; debug is the bug-finding profile — see the debug-vs-release note).",
                false,
            )],
        },
        Group {
            title: "Fault options (seed-driven, default off)",
            families: SOLE,
            flags: FAULT_FLAGS,
        },
        Group {
            title: "DNS options",
            families: SOLE,
            flags: DNS_FLAGS,
        },
        Group {
            title: "Native run options",
            families: SOLE,
            flags: &[
                CPUS_FLAG,
                PARAM_FLAG,
                f(
                    "--mount",
                    None,
                    Value::Required("HOST_DIR", Kind::Path),
                    "Capture a host directory read-only (contents, modes and mtimes) into the guest filesystem at `/`.",
                    false,
                ),
                f(
                    "--coverage-out",
                    None,
                    Value::Required("PATH", Kind::Path),
                    "Write a patina.covmap/v1 edge-counter map (requires an --instrument build).",
                    false,
                ),
                f(
                    "--env",
                    None,
                    Value::Required("K=V", Kind::KeyValue),
                    "Set a deterministic native guest environment variable (recorded and restored on replay).",
                    true,
                ),
                f(
                    "--cwd",
                    None,
                    Value::Required("PATH", Kind::Str),
                    "The guest's initial working directory: an absolute path in the deterministic filesystem that must exist as a directory (default `/`; recorded and restored on replay).",
                    false,
                ),
                // The label a RECORDING carries: the supervisor composes it (base
                // label plus the `+buggify`/`+pct`/`+swarm` components the run
                // really armed), the runtime writes it into the trace, and replay
                // recomputes and compares it. A seeded run writes no trace and the
                // runtime never even reads `PATINA_RT_FINGERPRINT` in seeded mode, so
                // a label supplied there could not be checked by anything —
                // declared dependent on `--record` so it is refused rather than
                // silently discarded.
                needs(
                    f(
                        "--fingerprint",
                        None,
                        Value::Required("STR", Kind::Str),
                        "Compatibility label written into the recorded trace; requires --record (default patina-native).",
                        false,
                    ),
                    "--record",
                ),
                ALLOW_FLAG,
                ALLOW_UNSUPPORTED_FLAG,
                ALLOW_RANDOMIZED_LAYOUT_FLAG,
            ],
        },
        Group {
            title: "Scheduling options",
            families: SOLE,
            flags: NATIVE_SCHEDULE_FLAGS,
        },
        Group {
            title: "Buggify options",
            families: SOLE,
            flags: BUGGIFY_FLAGS,
        },
        Group {
            title: "Native compute liveness (host-time terminal bound)",
            families: SOLE,
            flags: &[COMPUTE_WATCHDOG_FLAG],
        },
        Group {
            title: "Liveness options",
            families: SOLE,
            flags: LIVENESS_FLAGS_OPTIONAL,
        },
    ],
    refusals: NO_REFUSALS,
};

pub(super) const TEST: Verb = Verb {
    name: "test",
    summary: "Run one libtest test of a source package shim-linked, across seeds.",
    synopsis: &[
        "cargo patina test <DIR|Cargo.toml> --harness-target NAME --exact MOD::test [--seed N | --seeds N] [--release] [--budget N] [--instrument] [FAULT/BUGGIFY/SCHEDULE/LIVENESS OPTIONS]",
    ],
    prose: "\
Patina rebuilds the requested Cargo libtest target shim-linked with `cargo rustc`, stages \
the harness under target/patina/dst, and runs only the `--exact` test with \
`--test-threads=1`. `--seeds N` sweeps 0..N (default 20); `--seed N` runs one \
seed. Qualify a shared target name as lib:NAME, bin:NAME, or test:NAME; \
--package selects a workspace member. Staging is keyed on the resolved kind/name. \
On the first failure Patina re-runs that seed with --record, except pre-run \
audit/import refusals (nothing executed). A `test` repro is always printed; \
the JSON `trace` field and a `replay` command come only from the recorded \
child's readable-trace receipt.",
    families: &[fam(Family::Sole, "`test`", None)],
    groups: &[
        Group {
            title: "Patina options",
            families: SOLE,
            flags: &[
                f(
                    "--seed",
                    None,
                    Value::Required("U64", Kind::U64),
                    "Run exactly this seed instead of a sweep.",
                    false,
                ),
                f(
                    "--budget",
                    None,
                    Value::Required("STEPS", Kind::U64),
                    "Maximum boundary operations before explicit failure.",
                    false,
                ),
                f(
                    "--realtime-epoch",
                    None,
                    Value::Required("RFC3339", Kind::UtcTimestamp),
                    "Realtime at monotonic zero, as an RFC 3339 UTC timestamp (default 2026-07-22T23:00:09Z). Guest-start realtime adds the boot origin (default uptime 12345.678901234s); recorded and restored on replay.",
                    false,
                ),
                f(
                    "--hostname",
                    None,
                    Value::Required("NAME", Kind::Hostname),
                    "The node name the guest's virtual kernel reports through uname/gethostname (default patina; at most 64 bytes, no NUL; recorded and restored on replay).",
                    false,
                ),
                PARAM_FLAG,
            ],
        },
        Group {
            title: "Libtest harness selection",
            families: SOLE,
            flags: &[
                f(
                    "--harness-target",
                    None,
                    Value::Required("NAME", Kind::Symbol),
                    "Cargo libtest target to rebuild shim-linked. Use NAME when unique, or lib:NAME, bin:NAME, test:NAME to disambiguate target kinds; --package selects the workspace member. Required.",
                    false,
                ),
                f(
                    "--exact",
                    None,
                    Value::Required("MOD::test", Kind::Symbol),
                    "Exact libtest filter to run inside the shim-linked harness. Required.",
                    false,
                ),
                f(
                    "--seeds",
                    None,
                    Value::Required("N", Kind::PositiveU64),
                    "Run seeds 0..N (default 20; mutually exclusive with --seed).",
                    false,
                ),
                f(
                    "--package",
                    Some("-p"),
                    Value::Required("NAME", Kind::Str),
                    "Select a workspace member before building the native libtest harness.",
                    false,
                ),
                f(
                    "--features",
                    None,
                    Value::Required("FEATURES", Kind::Str),
                    "Space- or comma-separated Cargo features to enable when building the native libtest harness (forwarded to `cargo rustc --features`).",
                    false,
                ),
                f(
                    "--release",
                    None,
                    Value::None,
                    "Build the native libtest harness in release mode (default debug).",
                    false,
                ),
                f(
                    "--instrument",
                    None,
                    Value::None,
                    "Build the native libtest harness with edge hooks: edge counters, and the scheduling points --yield-stride asks for.",
                    false,
                ),
            ],
        },
        Group {
            title: "Fault options (seed-driven, default off)",
            families: SOLE,
            flags: FAULT_FLAGS,
        },
        Group {
            title: "DNS options",
            families: SOLE,
            flags: DNS_FLAGS,
        },
        Group {
            title: "Buggify options",
            families: SOLE,
            flags: BUGGIFY_FLAGS,
        },
        Group {
            title: "Native scheduling options",
            families: SOLE,
            flags: NATIVE_SCHEDULE_FLAGS,
        },
        Group {
            title: "Native compute liveness (host-time terminal bound)",
            families: SOLE,
            flags: &[COMPUTE_WATCHDOG_FLAG],
        },
        Group {
            title: "Virtual machine",
            families: SOLE,
            flags: &[Flag {
                doc: "The number of CPUs every seed's guest sees (default 4, at most 1024), re-emitted onto each seed's child run.",
                ..CPUS_FLAG
            }],
        },
        Group {
            title: "Native address layout",
            families: SOLE,
            flags: &[Flag {
                doc: "Run every seed, and its record-on-failure retry, with the host's address-space randomization, for a host that forbids turning it off; each seed's determinism is qualified and the replay repro carries the flag.",
                ..ALLOW_RANDOMIZED_LAYOUT_FLAG
            }],
        },
        Group {
            title: "Liveness options",
            families: SOLE,
            flags: LIVENESS_FLAGS_OPTIONAL,
        },
    ],
    refusals: NO_REFUSALS,
};

pub(super) const BUILD: Verb = Verb {
    name: "build",
    summary: "Build a guest linked against the native shim.",
    synopsis: &[
        "cargo patina build <SOURCE.rs> --output <PATH> [--edition YEAR] [--release] [--instrument] [-- RUSTC OPTIONS]",
        "cargo patina build <DIR|Cargo.toml> [--output <PATH>] [--package NAME] [--bin NAME] [--release] [--instrument]",
        "cargo patina build <GO PACKAGE DIR> --go --output <PATH> [--release] [-- GO BUILD OPTIONS]",
    ],
    prose: "\
`build` packages the native linked-shim target: it \
builds the patina-dst-native-shim staticlib, compiles the embedded POSIX C layer, \
injects cfg(patina)/cfg(dst), and links the shim below the user program. A `.rs` \
path builds a single source directly; a directory or Cargo.toml drives the \
package's own cargo build under Patina control. Select the member with --package \
and the binary with --bin; --output copies the built binary out.\n\
\n\
`--instrument` adds a SanitizerCoverage hook at every edge of every crate \
compiled from source. The hook keeps edge counters, so --coverage-out, `cargo \
patina coverage` and `campaign --guided` work, and it takes the scheduling \
points the run asks for: `run --yield-stride N` puts one every N edges a thread \
executes (1 = every edge, the densest), which makes atomics-only race windows \
schedulable. The default stride, 0, adds none and costs only the counters. The \
stride is a run setting recorded in the trace, so one binary serves both and a \
replay takes the recorded stride. An instrumented binary's traces carry \
`+instrumented` in their fingerprint and never cross-replay with a plain one.\n\
\n\
`--go` builds the Go main package in DIR (Linux): `go build` in cgo mode, linked \
externally with the shim, so goroutine threads start through the shim's \
pthread_create. A pure-Go package needs no source change. Patina sets -ldflags \
and -o; other `go build` options follow `--`. `--release` builds the shim in \
release mode; --instrument is Rust-only.",
    families: &[fam(Family::Sole, "`build`", None)],
    groups: &[Group {
        title: "Build options",
        families: SOLE,
        flags: &[
            f(
                "--output",
                Some("-o"),
                Value::Required("PATH", Kind::Path),
                "Copy the built binary out to PATH (required for a single .rs source).",
                false,
            ),
            f(
                "--edition",
                None,
                Value::Required("YEAR", Kind::Str),
                "Rust edition for a single-source build (default 2024).",
                false,
            ),
            f(
                "--release",
                None,
                Value::None,
                "Build in release mode.",
                false,
            ),
            f(
                "--instrument",
                None,
                Value::None,
                "Edge hooks at every edge: edge counters, and the scheduling points run --yield-stride asks for.",
                false,
            ),
            f(
                "--package",
                Some("-p"),
                Value::Required("NAME", Kind::Str),
                "Select a workspace member.",
                false,
            ),
            f(
                "--bin",
                None,
                Value::Required("NAME", Kind::Str),
                "Select the binary when the package defines more than one.",
                false,
            ),
            f(
                "--go",
                None,
                Value::None,
                "Build the path as a Go main package, cgo mode, externally linked with the shim (Linux).",
                false,
            ),
        ],
    }],
    refusals: NO_REFUSALS,
};

pub(super) const AUDIT: Verb = Verb {
    name: "audit",
    summary: "Report the true post-interposition residual effect surface of a binary.",
    synopsis: &[
        "cargo patina audit <SOURCE.rs|DIR|Cargo.toml> [--package NAME] [--bin NAME] [--allow SYMBOL]...   (builds shim-linked, then audits)",
        "cargo patina audit <ARTIFACT> [--allow SYMBOL]... [--raw]   (a prebuilt binary; must be `cargo patina build`-linked unless --raw)",
    ],
    prose: "\
`audit` is source-first: only a shim-linked binary shows the true \
post-interposition residual, so auditing a source/package links the shim first and \
the report is the handful of effect-surface symbols that genuinely escape. A stock \
`cargo build` binary lists every libc call the shim would interpose as an \
unsupported import — the opposite of the truth — so `audit <prebuilt>` fails closed \
unless the binary was produced by `cargo patina build`. `--raw` overrides that gate \
and runs the full audit anyway under a loud banner.",
    families: &[fam(Family::Sole, "`audit`", None)],
    groups: &[
        Group {
            title: "Audit options",
            families: SOLE,
            flags: &[
                ALLOW_FLAG,
                f(
                    "--raw",
                    None,
                    Value::None,
                    "Audit a non-Patina-built binary anyway (import findings are pre-interposition).",
                    false,
                ),
            ],
        },
        Group {
            title: "Source-first selection",
            families: SOLE,
            flags: SOURCE_SELECT,
        },
    ],
    refusals: NO_REFUSALS,
};

pub(super) const REPLAY: Verb = Verb {
    name: "replay",
    summary: "Reproduce a recorded run of an artifact, source, or package.",
    synopsis: &["cargo patina replay <ARTIFACT|SOURCE.rs|DIR|Cargo.toml> <TRACE> [REPLAY OPTIONS]"],
    prose: "\
`replay <ARTIFACT|SOURCE|PKG> <TRACE>` replays a native binary (or a \
source/package built on the fly) under the native supervisor. It restores every recorded semantic input (seed, fault knobs, buggify, \
realtime epoch, boot origin, hostname, native CPU count, guest argv, and native `--env` values) from the trace — the trace is authoritative \
— so replay exposes no semantic flags; any re-supplied value must match the \
recording or the replay is refused.\n\
\n\
Only host/build inputs the trace cannot carry stay as flags: replay accepts \
only --fingerprint, --mount, --coverage-out, --compute-watchdog-ms, the \
--allow/--allow-unsupported-symbols audit surface, and a --cpus that must match the recording's.",
    families: &[fam(Family::Sole, "`replay`", None)],
    groups: &[Group {
        title: "Replay options (host/build facts the trace cannot carry)",
        families: SOLE,
        flags: &[
            COMPUTE_WATCHDOG_FLAG,
            f(
                "--fingerprint",
                None,
                Value::Required("STR", Kind::Str),
                "Compatibility fingerprint label (default patina-native).",
                false,
            ),
            f(
                "--mount",
                None,
                Value::Required("HOST_DIR", Kind::Path),
                "Re-supply the host corpus whose hash (contents, then modes and mtimes) the fingerprint verifies.",
                false,
            ),
            f(
                "--coverage-out",
                None,
                Value::Required("PATH", Kind::Path),
                "Write a patina.covmap/v1 edge-counter map for the replayed native run.",
                false,
            ),
            ALLOW_FLAG,
            ALLOW_UNSUPPORTED_FLAG,
            Flag {
                doc: "Replay a trace recorded with --allow-randomized-address-layout, keeping the host's address-space randomization; required exactly when the recording used it.",
                ..ALLOW_RANDOMIZED_LAYOUT_FLAG
            },
            Flag {
                doc: "The trace's CPU count, which replay restores without it; a count that differs from the recording's is refused.",
                ..CPUS_FLAG
            },
        ],
    }],
    refusals: &[
        // Every semantic input is recorded in the trace and restored from it, so
        // re-supplying one could only diverge the replay. Declared by reference
        // to the shared slices: a knob added to FAULT_FLAGS or BUGGIFY_FLAGS is
        // refused here the day it is added, with no second list to remember.
        Refusal {
            families: SOLE,
            flags: &[FAULT_FLAGS, DNS_FLAGS, BUGGIFY_FLAGS, NATIVE_SCHEDULE_FLAGS],
            names: &[
                "--seed",
                "--record",
                "--env",
                "--param",
                "--cwd",
                "--realtime-epoch",
                "--hostname",
            ],
            message: "replay restores run semantics from the trace and does not accept {flag}; the trace is authoritative",
        },
    ],
};
