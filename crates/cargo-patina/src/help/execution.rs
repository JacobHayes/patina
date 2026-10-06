//! Execution verb registry rows.

use super::*;

// ===========================================================================
// The verb registry
// ===========================================================================

pub(super) const RUN: Verb = Verb {
    name: "run",
    summary: "Build (on the fly) and/or run an artifact under the deterministic runtime.",
    synopsis: &[
        "cargo patina run [--seed N | --record PATH] [FAULT/BUGGIFY OPTIONS] [--budget N] [--param K=V]... [CARGO OPTIONS] [-- PROGRAM OPTIONS]",
        "cargo patina run <MODULE.wasm> [--seed N | --record PATH] [--fuel N] [--budget N] [--arg VALUE]... [--env K=V]... [--preopen GUEST[:ro|:rw]]... [FAULT OPTIONS] [BUGGIFY/LIVENESS OPTIONS]",
        "cargo patina run <BINARY> [--seed N | --record PATH] [--env K=V]... [--budget N] [--coverage-out PATH] [--fingerprint STR] [--mount HOST_DIR] [--harness] [FAULT OPTIONS] [BUGGIFY/SCHEDULE/LIVENESS OPTIONS] [--allow SYMBOL]... [-- PROGRAM ARGS]",
        "cargo patina run <SOURCE.rs|DIR|Cargo.toml> [--target native|wasi] [--release] [RUN OPTIONS]   (builds on the fly, then runs)",
    ],
    prose: "\
`run` is source-first with artifacts accepted uniformly. A built artifact \
(recognized by its leading magic bytes) is used as-is; a <SOURCE.rs|DIR|Cargo.toml> \
is built on the fly through the same pipeline as `build` and its product is run \
(a one-line PATINA_BUILD_ON_RUN note reports the built artifact and its hash). A \
`run` with a directory, a Cargo.toml, or no artifact and no --target stays the \
Cargo package family (the same seed/record/param/budget machinery as `test`); \
--target opts a source/package into build-then-run.\n\
\n\
`run <MODULE.wasm>` runs under WASI; `run <BINARY>` runs a shim-linked native \
binary under a pre-run default-deny audit: every externally resolved symbol must \
be interposed or known-safe, and any unsupported symbol on the \
blocking/time/scheduling/effect surface hard-errors. --allow SYMBOL adds a \
known-safe symbol; --allow-unsupported-symbols <all|name,...> downgrades matching \
denials to a loud warning (an instruction-class finding matches by its own \
`instruction@.text+OFF` name or by the containing symbol its provenance names).\n\
\n\
`--harness` marks a patina-dst-harness (configure-then-run) binary: it defers \
runtime installation so the harness installs and configures the context itself. \
Supply it on both the record `run` and the `replay`. Reproduce a recorded run with \
`cargo patina replay`.",
    families: &[
        fam(Family::Cargo, "`run`", None),
        fam(Family::Wasi, "`run` of a WASI module", None),
        fam(Family::Native, "`run` of a native binary", None),
    ],
    groups: &[
        Group {
            title: "Patina options (run/test)",
            families: &[Family::Cargo, Family::Wasi, Family::Native],
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
                // wasip1 has no hostname surface at all, so the WASI family is
                // absent and `run <MODULE.wasm> --hostname` is refused rather
                // than accepted as a knob that could never be observed.
                only(
                    f(
                        "--hostname",
                        None,
                        Value::Required("NAME", Kind::Hostname),
                        "The node name the guest's virtual kernel reports through uname/gethostname (default patina; at most 64 bytes, no NUL; recorded and restored on replay).",
                        false,
                    ),
                    &[Family::Cargo, Family::Native],
                ),
                only(
                    f(
                        "--param",
                        None,
                        Value::Required("K=V", Kind::KeyValue),
                        "Typed-builder parameter exposed through Context (cargo family).",
                        true,
                    ),
                    &[Family::Cargo],
                ),
            ],
        },
        Group {
            title: "Source-first selection (building a source/package on the fly)",
            families: &[Family::Wasi, Family::Native],
            flags: SOURCE_SELECT,
        },
        Group {
            title: "Build profile (source-first)",
            families: &[Family::Wasi, Family::Native],
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
            families: &[Family::Cargo, Family::Wasi, Family::Native],
            flags: FAULT_FLAGS,
        },
        Group {
            // wasip1 has no resolution surface, so the WASI family is absent
            // here and `run <MODULE.wasm> --dns-entry` is refused.
            title: "DNS options (no wasip1 resolution surface, so not under --target wasi)",
            families: &[Family::Cargo, Family::Native],
            flags: DNS_FLAGS,
        },
        Group {
            title: "Native run options (run <BINARY>)",
            families: &[Family::Native],
            flags: &[
                HARNESS_FLAG,
                f(
                    "--mount",
                    None,
                    Value::Required("HOST_DIR", Kind::Path),
                    "Capture a host directory read-only into the guest filesystem at `/`.",
                    false,
                ),
                f(
                    "--coverage-out",
                    None,
                    Value::Required("PATH", Kind::Path),
                    "Write a patina.covmap/v1 edge-counter map (requires a --yield-points or --coverage-points build).",
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
                // runtime never even reads `PATINA_FINGERPRINT` in seeded mode, so
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
            ],
        },
        Group {
            title: "Native scheduling options (run <BINARY>)",
            families: &[Family::Native],
            flags: NATIVE_SCHEDULE_FLAGS,
        },
        Group {
            title: "Buggify options",
            families: &[Family::Cargo, Family::Wasi, Family::Native],
            flags: BUGGIFY_FLAGS,
        },
        Group {
            title: "Native compute liveness (host-time terminal bound)",
            families: &[Family::Native],
            flags: &[COMPUTE_WATCHDOG_FLAG],
        },
        Group {
            title: "Liveness options (run <MODULE.wasm> & run <BINARY>)",
            families: &[Family::Wasi, Family::Native],
            flags: LIVENESS_FLAGS_OPTIONAL,
        },
        Group {
            title: "WASI run options (run <MODULE.wasm>)",
            families: &[Family::Wasi],
            flags: WASI_HOST_FLAGS,
        },
    ],
    refusals: NO_REFUSALS,
};

pub(super) const TEST: Verb = Verb {
    name: "test",
    summary: "Run tests under Patina: Cargo-family by default, or a shim-linked native libtest harness for a source package.",
    synopsis: &[
        "cargo patina test [--seed N | --record PATH] [FAULT/BUGGIFY OPTIONS] [--budget N] [--param K=V]... [CARGO OPTIONS] [-- PROGRAM OPTIONS]",
        "cargo patina test <DIR|Cargo.toml> --harness-target NAME --exact MOD::test [--seed N | --seeds N] [--release] [--budget N] [--yield-points] [FAULT/BUGGIFY/SCHEDULE/LIVENESS OPTIONS]",
    ],
    prose: "\
With no source positional, `test` is the Cargo package family: the seed/record \
machinery, seed-driven fault knobs, and typed --param values, with every \
unrecognized option forwarded to Cargo. Reproducing a recording is the `replay` \
verb's job, so the Cargo-family form carries no replay/branch/timeline flags. A \
--record run captures its seed and fault knobs into the trace metadata so \
`replay` restores them.\n\
\n\
A directory or Cargo.toml positional selects native harness mode: Patina rebuilds \
the requested Cargo libtest target shim-linked with `cargo rustc`, stages \
the harness under target/patina/dst, and runs only the `--exact` test with \
`--test-threads=1`. `--seeds N` sweeps 0..N (default 20); `--seed N` runs one \
seed. Qualify a shared target name as lib:NAME, bin:NAME, or test:NAME; \
--package selects a workspace member. Staging is keyed on the resolved kind/name. \
On the first failure Patina re-runs that seed with --record, except pre-run \
audit/import refusals (nothing executed). A `test` repro is always printed; \
the JSON `trace` field and a `replay` command come only from the recorded \
child's readable-trace receipt.",
    families: &[
        fam(Family::Cargo, "`test`", None),
        fam(Family::Harness, "`test` native harness mode", None),
    ],
    groups: &[
        Group {
            title: "Patina options (Cargo-family run/test)",
            families: &[Family::Cargo, Family::Harness],
            flags: &[
                f(
                    "--seed",
                    None,
                    Value::Required("U64", Kind::U64),
                    "Deterministic root seed (default 0). In native harness mode, run exactly this seed instead of a sweep.",
                    false,
                ),
                only(
                    f(
                        "--record",
                        None,
                        Value::Required("PATH", Kind::Path),
                        "Record boundary operations and outcomes to PATH (Cargo-family form; native harness mode records failures automatically).",
                        false,
                    ),
                    &[Family::Cargo],
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
                only(
                    f(
                        "--param",
                        None,
                        Value::Required("K=V", Kind::KeyValue),
                        "Typed-builder parameter exposed through Context (Cargo-family form).",
                        true,
                    ),
                    &[Family::Cargo],
                ),
            ],
        },
        Group {
            title: "Native libtest harness selection (test <DIR|Cargo.toml>)",
            families: &[Family::Harness],
            flags: &[
                f(
                    "--harness-target",
                    None,
                    Value::Required("NAME", Kind::Symbol),
                    "Cargo libtest target to rebuild shim-linked. Use NAME when unique, or lib:NAME, bin:NAME, test:NAME to disambiguate target kinds; --package selects the workspace member. Required in native harness mode.",
                    false,
                ),
                f(
                    "--exact",
                    None,
                    Value::Required("MOD::test", Kind::Symbol),
                    "Exact libtest filter to run inside the shim-linked harness. Required in native harness mode.",
                    false,
                ),
                f(
                    "--seeds",
                    None,
                    Value::Required("N", Kind::PositiveU64),
                    "Run seeds 0..N in native harness mode (default 20; mutually exclusive with --seed).",
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
                    "--all-features",
                    None,
                    Value::None,
                    "Build the native libtest harness with every package feature enabled.",
                    false,
                ),
                f(
                    "--no-default-features",
                    None,
                    Value::None,
                    "Build the native libtest harness without the package's default features.",
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
                    "--yield-points",
                    None,
                    Value::None,
                    "Instrument the native libtest harness with deterministic yield points.",
                    false,
                ),
                f(
                    "--coverage-points",
                    None,
                    Value::Optional("STRIDE", Kind::PositiveU64),
                    "Edge counters at every basic block; bare = no added scheduling points, =N = one every N blocks. Excludes --yield-points.",
                    false,
                ),
            ],
        },
        Group {
            title: "Fault options (seed-driven, default off)",
            families: &[Family::Cargo, Family::Harness],
            flags: FAULT_FLAGS,
        },
        Group {
            title: "DNS options",
            families: &[Family::Cargo, Family::Harness],
            flags: DNS_FLAGS,
        },
        Group {
            title: "Buggify options",
            families: &[Family::Cargo, Family::Harness],
            flags: BUGGIFY_FLAGS,
        },
        Group {
            title: "Native scheduling options (native harness mode)",
            families: &[Family::Harness],
            flags: NATIVE_SCHEDULE_FLAGS,
        },
        Group {
            title: "Native compute liveness (host-time terminal bound)",
            families: &[Family::Harness],
            flags: &[COMPUTE_WATCHDOG_FLAG],
        },
        Group {
            title: "Liveness options (native harness mode)",
            families: &[Family::Harness],
            flags: LIVENESS_FLAGS_OPTIONAL,
        },
    ],
    refusals: NO_REFUSALS,
};

pub(super) const BUILD: Verb = Verb {
    name: "build",
    summary: "Build the native linked-shim target (default) or a wasm32-wasip1 package.",
    synopsis: &[
        "cargo patina build <SOURCE.rs> --output <PATH> [--edition YEAR] [--release] [--yield-points | --coverage-points[=STRIDE]] [-- RUSTC OPTIONS]",
        "cargo patina build <DIR|Cargo.toml> [--output <PATH>] [--package NAME] [--bin NAME] [--release] [--yield-points | --coverage-points[=STRIDE]]",
        "cargo patina build <DIR|Cargo.toml> --target wasi [--output PATH] [--package NAME] [--bin NAME] [--release]",
    ],
    prose: "\
`build` (default --target native) packages the native linked-shim target: it \
builds the patina-dst-native-shim staticlib, compiles the embedded POSIX C layer, \
injects cfg(patina)/cfg(dst), and links the shim below the user program. A `.rs` \
path builds a single source directly; a directory or Cargo.toml drives the \
package's own cargo build under Patina control. Select the member with --package \
and the binary with --bin; --output copies the built binary out.\n\
\n\
`--yield-points` instruments the native guest with deterministic cooperative \
preemption (a hook at every basic block routes into the scheduler), making \
atomics-only race windows schedulable. It is the densest and by far the most \
expensive mode: every basic block pays a scheduler round trip.\n\
\n\
`--coverage-points` splits the two things --yield-points bundles. Bare, it emits \
the SAME edge counters (so --coverage-out, `cargo patina coverage`, and `campaign \
--guided` all work) with NO scheduler hook, at counter cost. `--coverage-points=N` \
adds a scheduling point every N basic blocks a thread executes, bounding the \
blocks between preemption opportunities by N at 1/N of the --yield-points cost. \
The stride is compiled into the binary and recovered from it at run time, so it \
is part of the compatibility fingerprint (`+covpoints:N`) and a trace never \
cross-replays against a different stride or against --yield-points. The sampling \
countdown is per-thread, so the sampled sites are a pure function of the seed. \
The two flags are mutually exclusive. Both are native-only and rejected under \
--target wasi (wasip1 has no threads to preempt). `build --target wasi` compiles a \
Cargo package for wasm32-wasip1 and is package-only (a single .rs source is \
native-only).",
    families: &[
        fam(Family::Native, "`build`", None),
        fam(
            Family::Wasi,
            "`build --target wasi`",
            Some(
                "wasip1 has no threads to preempt and takes its edition from the package's Cargo.toml",
            ),
        ),
    ],
    groups: &[Group {
        title: "Build options",
        families: &[Family::Native, Family::Wasi],
        flags: &[
            f(
                "--output",
                Some("-o"),
                Value::Required("PATH", Kind::Path),
                "Copy the built binary out to PATH (required for a single .rs source).",
                false,
            ),
            only(
                f(
                    "--edition",
                    None,
                    Value::Required("YEAR", Kind::Str),
                    "Rust edition for a single-source build (default 2024).",
                    false,
                ),
                &[Family::Native],
            ),
            f(
                "--release",
                None,
                Value::None,
                "Build in release mode.",
                false,
            ),
            only(
                f(
                    "--yield-points",
                    None,
                    Value::None,
                    "Instrument deterministic cooperative preemption (native only).",
                    false,
                ),
                &[Family::Native],
            ),
            only(
                f(
                    "--coverage-points",
                    None,
                    Value::Optional("STRIDE", Kind::PositiveU64),
                    "Edge counters at every basic block; bare = no added scheduling points, =N = one every N blocks. Excludes --yield-points.",
                    false,
                ),
                &[Family::Native],
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
            TARGET_FLAG,
        ],
    }],
    refusals: NO_REFUSALS,
};

pub(super) const AUDIT: Verb = Verb {
    name: "audit",
    summary: "Report the true post-interposition residual effect surface of a binary.",
    synopsis: &[
        "cargo patina audit <SOURCE.rs|DIR|Cargo.toml> [--package NAME] [--bin NAME] [--target native|wasi] [--allow SYMBOL]...   (builds shim-linked, then audits)",
        "cargo patina audit <ARTIFACT> [--allow SYMBOL]... [--raw]   (a prebuilt binary; must be `cargo patina build`-linked unless --raw)",
    ],
    prose: "\
`audit` is source-first: only a shim-linked binary shows the true \
post-interposition residual, so auditing a source/package links the shim first and \
the report is the handful of effect-surface symbols that genuinely escape. A stock \
`cargo build` binary lists every libc call the shim would interpose as an \
unsupported import — the opposite of the truth — so `audit <prebuilt>` fails closed \
unless the binary was produced by `cargo patina build`. `--raw` overrides that gate \
and runs the full audit anyway under a loud banner. A WASI module lists its imports \
and takes no --allow (the allow list is native-only).",
    families: &[
        fam(Family::Native, "`audit` of a native binary", None),
        fam(
            Family::Wasi,
            "`audit` of a WASI module",
            Some(
                "a module's imports are read from the module itself; the allow list is native-only",
            ),
        ),
    ],
    groups: &[
        Group {
            title: "Audit options",
            families: &[Family::Native],
            flags: &[
                Flag {
                    doc: "Treat SYMBOL as known-safe (native only).",
                    ..ALLOW_FLAG
                },
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
            families: &[Family::Native, Family::Wasi],
            flags: SOURCE_SELECT,
        },
    ],
    refusals: NO_REFUSALS,
};

pub(super) const REPLAY: Verb = Verb {
    name: "replay",
    summary: "Reproduce a recorded run; routes by the same inference as `run`.",
    synopsis: &[
        "cargo patina replay <ARTIFACT|SOURCE.rs|DIR|Cargo.toml> <TRACE> [--target native|wasi] [REPLAY OPTIONS]",
    ],
    prose: "\
`replay <ARTIFACT|SOURCE|PKG> <TRACE>` is the sole replay entry point for all three \
families: a wasm module replays under WASI, a native binary under the native \
supervisor, and a directory/Cargo.toml (no --target) under the Cargo package \
family. Each restores every recorded semantic input (seed, fault knobs, buggify, \
realtime epoch, boot origin, hostname, guest argv, and native `--env` values) from the trace — the trace is authoritative \
— so replay exposes no semantic flags; any re-supplied value must match the \
recording or the replay is refused.\n\
\n\
Only host/build inputs the trace cannot carry stay as flags. The Cargo and WASI \
families carry the timeline/branch controls (--timeline, and --branch --from \
--branch-seed --branch-id [--parent]); WASI re-takes its host environment \
(--fuel/--env/--socket/--preopen and resource limits). Native traces restore \
`run --env` values from metadata and reject re-supplied native `--env`; native \
traces are single-timeline (native runs cannot branch), so native replay accepts \
only --fingerprint, --mount, --coverage-out, --harness, --compute-watchdog-ms, and the \
--allow/--allow-unsupported-symbols audit surface.",
    families: &[
        fam(Family::Cargo, "`replay` of a Cargo package", None),
        fam(Family::Wasi, "`replay` of a WASI module", None),
        fam(Family::Native, "`replay` of a native binary", None),
    ],
    groups: &[
        Group {
            title: "Native replay options (host/build facts the trace cannot carry)",
            families: &[Family::Native],
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
                    "Re-supply the host corpus whose hash the fingerprint verifies.",
                    false,
                ),
                f(
                    "--coverage-out",
                    None,
                    Value::Required("PATH", Kind::Path),
                    "Write a patina.covmap/v1 edge-counter map for the replayed native run.",
                    false,
                ),
                Flag {
                    doc: "Replay a patina-dst-harness binary (defers runtime init).",
                    ..HARNESS_FLAG
                },
                ALLOW_FLAG,
                ALLOW_UNSUPPORTED_FLAG,
            ],
        },
        Group {
            title: "Timeline/branch replay (Cargo package & WASI families)",
            families: &[Family::Cargo, Family::Wasi],
            flags: REPLAY_TIMELINE_FLAGS,
        },
        Group {
            title: "WASI host environment (re-supplied and fingerprint-checked)",
            families: &[Family::Wasi],
            flags: WASI_HOST_FLAGS,
        },
        Group {
            title: "Family selection",
            families: &[Family::Wasi, Family::Native],
            flags: &[TARGET_FLAG],
        },
    ],
    refusals: &[
        // Every semantic input is recorded in the trace and restored from it, so
        // re-supplying one could only diverge the replay. Declared by reference
        // to the shared slices: a knob added to FAULT_FLAGS or BUGGIFY_FLAGS is
        // refused here the day it is added, with no second list to remember.
        Refusal {
            families: &[Family::Cargo, Family::Wasi, Family::Native],
            flags: &[FAULT_FLAGS, DNS_FLAGS, BUGGIFY_FLAGS, NATIVE_SCHEDULE_FLAGS],
            names: &[
                "--seed",
                "--record",
                "--env",
                "--cwd",
                "--realtime-epoch",
                "--hostname",
            ],
            message: "replay restores run semantics from the trace and does not accept {flag}; the trace is authoritative",
        },
        // Native traces are single-timeline and a native run cannot branch.
        Refusal {
            families: &[Family::Native],
            flags: &[REPLAY_TIMELINE_FLAGS],
            names: &[],
            message: "{flag} is not supported for native replay: native traces are single-timeline and native runs cannot branch; branch/timeline replay is the Cargo package and WASI families",
        },
    ],
};
