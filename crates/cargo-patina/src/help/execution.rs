//! Execution verb registry rows.

use super::*;

// ===========================================================================
// The verb registry
// ===========================================================================

pub(super) const RUN: Verb = Verb {
    name: "run",
    summary: "Build (on the fly) and/or run an artifact under the deterministic runtime.",
    synopsis: &[
        "patina run <BINARY> [--seed N | --record PATH] [--env K=V]... [--budget N] [--coverage-out PATH] [--mount HOST_DIR[:GUEST_DIR]] [FAULT OPTIONS] [BUGGIFY/SCHEDULE/LIVENESS OPTIONS] [--allow SYMBOL|all]... [-- PROGRAM ARGS]",
        "patina run <SOURCE.rs|DIR|Cargo.toml> [--release] [--no-instrument] [RUN OPTIONS]   (builds on the fly, then runs)",
    ],
    prose: "\
`run` is source-first with artifacts accepted uniformly. A built artifact \
(recognized by its leading magic bytes) is used as-is; a <SOURCE.rs|DIR|Cargo.toml> \
is built on the fly through the same pipeline as `build` and its product is run \
(a one-line PATINA_BUILD_ON_RUN note reports the built artifact and its hash). \
On Linux a source is built instrumented, so its computation costs virtual \
time, unless --no-instrument asks for a plain build; on macOS it is built \
plain. A built artifact is whatever it was \
built as. The result names which (`build`: instrumented, go, python or plain), \
and a plain one is noted on stderr.\n\
\n\
`run <BINARY>` runs a shim-linked native binary under a pre-run default-deny audit: every externally resolved symbol must \
be interposed or known-safe, and any unsupported symbol on the \
blocking/time/scheduling/effect surface hard-errors. --allow SYMBOL admits \
one (an instruction-class finding matches by its own `instruction@.text+OFF` \
name or by the containing symbol its provenance names, and is admitted with a \
loud warning); --allow all admits every one that way.\n\
\n\
Reproduce a recorded run with `patina replay`.",
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
                    "Record boundary operations and outcomes to PATH. A recording that outgrows the trace budget (4000000 events or 256 MiB) is dropped: the result says so (trace_incomplete) and the run's outcome is unchanged.",
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
            title: "Build (source-first)",
            families: SOLE,
            flags: &[
                f(
                    "--release",
                    None,
                    Value::None,
                    "Build the on-the-fly guest in release mode (default debug; debug is the bug-finding profile — see the debug-vs-release note).",
                    false,
                ),
                f(
                    "--no-instrument",
                    None,
                    Value::None,
                    NO_INSTRUMENT_HELP,
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
            title: "Native run options",
            families: SOLE,
            flags: &[
                CPUS_FLAG,
                PARAM_FLAG,
                f(
                    "--mount",
                    None,
                    Value::Required("HOST_DIR[:GUEST_DIR]", Kind::Path),
                    "Capture a host directory read-only (contents, modes, mtimes and the hard links among its names) into the guest filesystem at GUEST_DIR, `/` unless one is named; `--mount $PWD:$PWD` keeps absolute host paths working.",
                    false,
                ),
                f(
                    "--coverage-out",
                    None,
                    Value::Required("PATH", Kind::Path),
                    "Write a patina.covmap/v1 edge-counter map (requires an instrumented build, the Linux default, or a Go guest).",
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
                f(
                    "--stdin",
                    None,
                    Value::Required("HOST_FILE", Kind::Path),
                    "The guest's standard input, as `< HOST_FILE`: descriptor 0 is an unlinked read-only regular file holding its bytes (at most 4 MiB), whose reads fault as any file's do (recorded and restored on replay; default an empty pipe).",
                    false,
                ),
                ALLOW_FLAG,
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
            flags: LIVENESS_FLAGS,
        },
    ],
    refusals: NO_REFUSALS,
};

pub(super) const TEST: Verb = Verb {
    name: "test",
    summary: "Run a Cargo project's own test suite under the deterministic runtime, one run per test.",
    synopsis: &[
        "patina test [DIR|Cargo.toml] [TESTNAME] [--exact] [--skip PATTERN]... [-p NAME]... [--workspace] [--lib] [--bin NAME]... [--bins] [--test NAME]... [--tests] [--skip-target NAME]... [--seed N | --seeds N] [--jobs N] [RUN OPTIONS]",
        "patina test [DIR|Cargo.toml] --no-run [SELECTION]   (build and stage the test targets; print each guest's path)",
    ],
    prose: "\
`test` builds each selected Cargo test target once, linked with the runtime, \
asks the built harness for its tests (`--list`), and runs every test in a \
simulated world of its own: one `patina run` per test and seed, `--jobs` at a \
time. Selection follows `cargo test`: the package in or above the current \
directory (or the one DIR names), `-p`/`--workspace` for workspace members, \
`--lib`/`--bin`/`--bins`/`--test`/`--tests` for targets (default: the library, \
binaries and integration tests), and a trailing TESTNAME that filters by \
substring, or matches exactly with `--exact`; a filter that matches nothing is \
an error. `--skip PATTERN` leaves tests out as libtest's own `--skip` does, and \
`--skip-target NAME` leaves out a whole target. Doc tests are not run. `#[ignore]`d tests are skipped unless \
`--include-ignored`; `#[should_panic]` is libtest's own.\n\
\n\
Each test ends in one outcome; the run exits 1 if any test is a finding, \
else 2 if any test could not be run (unsupported, timeout, internal, error), \
else 0. `--accept-unsupported TEXT` keeps an `unsupported` test whose stop \
names TEXT from raising the exit status; it is still reported as unsupported, \
never as passed. Every test that did not pass is listed with the command that \
reruns it alone on its seed; a finding is run again recorded, and a replay \
command printed. `--format json` prints one patina.test/v1 document.\n\
\n\
The staged guest of each target is target/patina/dst/<PACKAGE>/<KIND>/<TARGET>/guest; \
`--no-run` builds and prints those paths without running anything.",
    families: &[fam(Family::Sole, "`test`", None)],
    groups: &[
        Group {
            title: "Test selection (as `cargo test`)",
            families: SOLE,
            flags: &[
                f(
                    "--package",
                    Some("-p"),
                    Value::Required("NAME", Kind::Str),
                    "Test this workspace member (repeatable; default: the package of DIR, or the workspace's default members).",
                    true,
                ),
                f(
                    "--workspace",
                    None,
                    Value::None,
                    "Test every workspace member.",
                    false,
                ),
                f(
                    "--lib",
                    None,
                    Value::None,
                    "Test the package's library.",
                    false,
                ),
                f(
                    "--bin",
                    None,
                    Value::Required("NAME", Kind::Str),
                    "Test the named binary (repeatable).",
                    true,
                ),
                f("--bins", None, Value::None, "Test every binary.", false),
                f(
                    "--test",
                    None,
                    Value::Required("NAME", Kind::Str),
                    "Test the named integration test target (repeatable).",
                    true,
                ),
                f(
                    "--tests",
                    None,
                    Value::None,
                    "Test every integration test target.",
                    false,
                ),
                f(
                    "--skip-target",
                    None,
                    Value::Required("NAME", Kind::Str),
                    "Leave out the selected target NAME (a library, binary or integration test of that name; repeatable). A NAME that is not selected is an error.",
                    true,
                ),
                f(
                    "--skip",
                    None,
                    Value::Required("PATTERN", Kind::Str),
                    "libtest's --skip: do not run a test whose path contains PATTERN (with --exact, equals it; repeatable).",
                    true,
                ),
                f(
                    "--exact",
                    None,
                    Value::None,
                    "Match TESTNAME and every --skip exactly against the test's path within its target, not as a substring.",
                    false,
                ),
                f(
                    "--include-ignored",
                    None,
                    Value::None,
                    "Run `#[ignore]`d tests too.",
                    false,
                ),
                f(
                    "--features",
                    None,
                    Value::Required("FEATURES", Kind::Str),
                    "Space- or comma-separated Cargo features to enable (forwarded to Cargo).",
                    false,
                ),
                f(
                    "--all-features",
                    None,
                    Value::None,
                    "Enable every feature of the selected packages.",
                    false,
                ),
                f(
                    "--no-default-features",
                    None,
                    Value::None,
                    "Do not enable the default feature.",
                    false,
                ),
                f(
                    "--release",
                    None,
                    Value::None,
                    "Build the test targets with the `bench` profile, which inherits `release` (default: the `test` profile).",
                    false,
                ),
                f(
                    "--no-instrument",
                    None,
                    Value::None,
                    NO_INSTRUMENT_HELP,
                    false,
                ),
                f(
                    "--no-run",
                    None,
                    Value::None,
                    "Build and stage the selected test targets, print each staged guest's path, and run nothing.",
                    false,
                ),
            ],
        },
        Group {
            title: "Seeds and running",
            families: SOLE,
            flags: &[
                f(
                    "--seed",
                    None,
                    Value::Required("U64", Kind::U64),
                    "Run every test on this seed (default 0).",
                    false,
                ),
                f(
                    "--seeds",
                    None,
                    Value::Required("N", Kind::PositiveU64),
                    "Run every test on seeds 0..N, stopping a test at its first seed that does not pass (mutually exclusive with --seed).",
                    false,
                ),
                f(
                    "--jobs",
                    Some("-j"),
                    Value::Required("N", Kind::PositiveU64),
                    "Run at most N tests at a time, each in its own process (default: half the CPUs this process may use, at least 1).",
                    false,
                ),
                f(
                    "--timeout-secs",
                    None,
                    Value::Required("N", Kind::U64),
                    "Stop a test's run after N seconds of host time and report it as `timeout` (default 300; 0 waits forever).",
                    false,
                ),
                f(
                    "--accept-unsupported",
                    None,
                    Value::Required("TEXT", Kind::Symbol),
                    "Do not let an `unsupported` test whose stop names TEXT (as the summary prints it, e.g. `process spawn`) raise the exit status; it is still reported as unsupported (repeatable).",
                    true,
                ),
                f(
                    "--budget",
                    None,
                    Value::Required("STEPS", Kind::U64),
                    "Maximum boundary operations of each test's run before explicit failure.",
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
                f(
                    "--env",
                    None,
                    Value::Required("K=V", Kind::KeyValue),
                    "Set a deterministic guest environment variable in every test's run (recorded and restored on replay).",
                    true,
                ),
                f(
                    "--mount",
                    None,
                    Value::Required("HOST_DIR[:GUEST_DIR]", Kind::Path),
                    "Capture a host directory read-only into every test's filesystem at GUEST_DIR, `/` unless one is named: at `/` a test's relative paths resolve (its working directory is `/`); at the package's own path (`--mount $PWD:$PWD`) its absolute ones (`env!(\"CARGO_MANIFEST_DIR\")`) do.",
                    false,
                ),
                Flag {
                    doc: "The number of CPUs every test's guest sees (default 4, at most 1024).",
                    ..CPUS_FLAG
                },
                Flag {
                    doc: "Run every test, and its record-on-failure retry, with the host's address-space randomization, for a host that forbids turning it off; each run's determinism is qualified, and so is its replay.",
                    ..ALLOW_RANDOMIZED_LAYOUT_FLAG
                },
            ],
        },
        Group {
            title: "Fault options (seed-driven, default off; applied to every test)",
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
            title: "Liveness options",
            families: SOLE,
            flags: LIVENESS_FLAGS,
        },
    ],
    refusals: NO_REFUSALS,
};

pub(super) const BUILD: Verb = Verb {
    name: "build",
    summary: "Build a guest linked against the native shim.",
    synopsis: &[
        "patina build <SOURCE.rs> --output <PATH> [--edition YEAR] [--release] [--no-instrument] [-- RUSTC OPTIONS]",
        "patina build <DIR|Cargo.toml> [--output <PATH>] [--package NAME] [--bin NAME] [--release] [--no-instrument]",
        "patina build <GO PACKAGE DIR> --go [--go-test] --output <PATH> [--release] [-- GO BUILD OPTIONS]",
        "patina build <SCRIPT.py|DIR> --python --output <PATH> [--python-path DIR]... [--python-source TARBALL|DIR] [--release]",
    ],
    prose: "\
`build` packages the native linked-shim target: it \
builds the patina-dst-native-shim staticlib, compiles the embedded POSIX C layer, \
injects cfg(patina)/cfg(dst), and links the shim below the user program. A `.rs` \
path builds a single source directly; a directory or Cargo.toml drives the \
package's own cargo build under Patina control. Select the member with --package \
and the binary with --bin; --output copies the built binary out.\n\
\n\
On Linux a Rust build is instrumented: a SanitizerCoverage hook at every edge of every \
crate compiled from source meters the computation, so it costs virtual time \
and a run that computes without end stops deterministically \
(timeout/compute_bound, --compute-watchdog-ms) on every host. The hook also \
keeps edge counters, so --coverage-out, `cargo patina coverage` and `campaign \
--guided` work, and it takes the scheduling points the run asks for: `run \
--yield-stride N` puts one every N edges a thread executes (1 = every edge, \
the densest), which makes atomics-only race windows schedulable. The default \
stride, 0, adds none. The stride is a run setting recorded in the trace, so \
one binary serves both and a replay takes the recorded stride. \
`--no-instrument` builds plain: faster compute (an instrumented tight loop runs \
up to about 3x slower), but its computation is not metered, so a run that \
computes without end stops only at the host-time backstop, an inconclusive \
timeout. A run reports which it ran (`build` in its result). An instrumented \
binary's traces carry `+instrumented` in their fingerprint and never \
cross-replay with a plain one. On macOS every Rust/C build is plain \
(--no-instrument asks for that default): Mach-O linking keeps instrumented dead \
code and its imports alive, which the default-deny audit would refuse.\n\
\n\
`--go` builds the Go main package in DIR (Linux): `go build` in cgo mode, linked \
externally with the shim, so goroutine threads start through the shim's \
pthread_create. A pure-Go package needs no source change. Patina sets -ldflags \
and -o and adds the `patina` build tag, which selects the Go SDK's (`go/patina`) \
shim-backed sites; other `go build` options follow `--`. `--release` builds the shim in \
release mode; --no-instrument is Rust-only. Every Go guest keeps Go's own 8-bit \
edge counters, so --coverage-out, `patina coverage` and `campaign \
--guided` work on it; it has no edge hook, so `run --yield-stride` is refused. \
`--go-test` builds the package's test binary (`go test -c`) instead of a main \
package, so a package's own tests run as a guest: give `go test` flags such as \
`-test.run` and `-test.v` to `run` after `--`.\n\
\n\
`--python` builds a Python application (Linux): a script, run as its module, or a \
directory, run as its `__main__.py`. Patina builds CPython (the pinned release, \
fetched once and checked against its digest, or the --python-source tarball or \
tree) statically by its own recipe, caches it, and freezes the standard library, \
the application and each --python-path root (a virtualenv's site-packages, say; \
earlier roots shadow later ones) into the executable, so the interpreter imports \
nothing from a filesystem and runs isolated from the environment. Pure-Python \
modules only: an extension module refuses the build, and package data is not \
carried. Arguments after `--` on `run` reach the program as `sys.argv[1:]`.",
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
                "--no-instrument",
                None,
                Value::None,
                NO_INSTRUMENT_HELP,
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
            needs(
                f(
                    "--go-test",
                    None,
                    Value::None,
                    "Build the Go package's test binary (`go test -c`) instead of a main package.",
                    false,
                ),
                "--go",
            ),
            f(
                "--python",
                None,
                Value::None,
                "Build the path as a Python application frozen into a statically built CPython.",
                false,
            ),
            needs(
                f(
                    "--python-path",
                    None,
                    Value::Required("DIR", Kind::Path),
                    "Freeze the modules under DIR too (a site-packages directory, say); repeatable.",
                    true,
                ),
                "--python",
            ),
            needs(
                f(
                    "--python-source",
                    None,
                    Value::Required("TARBALL|DIR", Kind::Path),
                    "Build CPython from this source tarball or tree instead of the pinned release.",
                    false,
                ),
                "--python",
            ),
        ],
    }],
    refusals: NO_REFUSALS,
};

pub(super) const AUDIT: Verb = Verb {
    name: "audit",
    summary: "Report the true post-interposition residual effect surface of a binary.",
    synopsis: &[
        "patina audit <SOURCE.rs|DIR|Cargo.toml> [--package NAME] [--bin NAME] [--allow SYMBOL]...   (builds shim-linked, then audits)",
        "patina audit <ARTIFACT> [--allow SYMBOL]... [--raw]   (a prebuilt binary; must be `patina build`-linked unless --raw)",
    ],
    prose: "\
`audit` is source-first: only a shim-linked binary shows the true \
post-interposition residual, so auditing a source/package links the shim first and \
the report is the handful of effect-surface symbols that genuinely escape. A stock \
`cargo build` binary lists every libc call the shim would interpose as an \
unsupported import — the opposite of the truth — so `audit <prebuilt>` fails closed \
unless the binary was produced by `patina build`. `--raw` overrides that gate \
and runs the full audit anyway under a loud banner.",
    families: &[fam(Family::Sole, "`audit`", None)],
    groups: &[
        Group {
            title: "Audit options",
            families: SOLE,
            flags: &[
                Flag {
                    value: Value::Required("SYMBOL", Kind::Symbol),
                    doc: "Leave SYMBOL out of the findings, as `run --allow SYMBOL` admits it (repeatable).",
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
            families: SOLE,
            flags: SOURCE_SELECT,
        },
    ],
    refusals: NO_REFUSALS,
};

pub(super) const REPLAY: Verb = Verb {
    name: "replay",
    summary: "Reproduce a recorded run of an artifact, source, or package.",
    synopsis: &["patina replay <ARTIFACT|SOURCE.rs|DIR|Cargo.toml> <TRACE> [REPLAY OPTIONS]"],
    prose: "\
`replay <ARTIFACT|SOURCE|PKG> <TRACE>` replays a native binary (or a \
source/package built on the fly) under the native supervisor. It restores every recorded input (seed, fault knobs, buggify, \
realtime epoch, boot origin, hostname, CPU count, standard input, address layout, guest argv, and `--env` values) from the trace — the trace is authoritative \
— so replay takes none of them as flags.\n\
\n\
Only host inputs the trace cannot carry stay as flags: the --mount corpus, \
--coverage-out, and the --allow audit surface.",
    families: &[fam(Family::Sole, "`replay`", None)],
    groups: &[Group {
        title: "Replay options (host/build facts the trace cannot carry)",
        families: SOLE,
        flags: &[
            f(
                "--mount",
                None,
                Value::Required("HOST_DIR[:GUEST_DIR]", Kind::Path),
                "Re-supply the host corpus, at the guest directory it was recorded at, whose hash (contents and guest paths, then modes and mtimes) the fingerprint verifies.",
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
                "--cpus",
                "--stdin",
                "--allow-randomized-address-layout",
                "--compute-watchdog-ms",
            ],
            message: "replay restores run semantics from the trace and does not accept {flag}; the trace is authoritative",
        },
    ],
};
