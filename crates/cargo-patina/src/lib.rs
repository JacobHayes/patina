//! Process-level implementation behind the `cargo-patina` binary.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use patina_dst_fs_mem::{FsImage, FsImageEntry};
use patina_dst_minimize::{
    MinimizeError, Scenario, minimize_all, minimize_branch_tree, minimize_main, minimize_timeline,
    reduce_scenario, reduce_schedule,
};
use patina_dst_runtime::{
    Context, ENV_BRANCH_FROM, ENV_BRANCH_ID, ENV_BRANCH_SEED, ENV_BUGGIFY, ENV_BUGGIFY_ACTIVATION,
    ENV_BUGGIFY_AFTER_SETUP, ENV_BUGGIFY_CUTOFF, ENV_CONVERGE_WITHIN, ENV_FINGERPRINT,
    ENV_FS_CRASH_AT, ENV_FS_IMAGE_FD, ENV_FS_TORN_GRANULARITY, ENV_GUEST_ARGV, ENV_HEAL_AFTER,
    ENV_LIVENESS_WATCHDOG, ENV_MODE, ENV_NET_DROP_PERMILLE, ENV_NET_JITTER, ENV_NET_LATENCY,
    ENV_PARAMS_JSON, ENV_PARENT_TIMELINE, ENV_SCHED_PCT, ENV_SCHED_PCT_STEPS, ENV_SCHED_STARVE,
    ENV_SCHED_STARVE_MAX_LEN, ENV_SCHED_STARVE_WINDOW, ENV_SEED, ENV_SLEEP_JITTER, ENV_STEP_BUDGET,
    ENV_SWARM, ENV_TIMELINE, ENV_TRACE, ENV_TRACE_FD, RuntimeConfig,
};
use patina_dst_target::{
    NativeAudit, NativeEscape, TargetError, WASI_PREVIEW1_TARGET, WasiAudit,
    shim_control_plane_symbols,
};
use patina_dst_trace::TraceBundle;
use patina_dst_wasi_host::{
    DEFAULT_WASM_FUEL, MountPolicy, Preview1Host, ResourceLimits, execute_preview1_with_fuel,
};
use sha2::{Digest, Sha256};

// Additive output-side modules: HTML timeline rendering and the machine-readable
// `--output json` envelope. Both are read-only consumers of trace/runtime
// semantics — they never record, replay, or mutate a trace — so rendering or
// emitting an envelope cannot perturb replay hashes.
mod campaign;
mod output;
mod render;

const PATINA_CFG_FLAGS: &str = "--cfg patina --cfg dst";

// The native link recipe is packaged into `cargo patina` so `native-build` can
// reproduce it without the source tree: the POSIX shim C layer and its header
// are embedded, compiled below the user program, and linked against the
// `patina-dst-native-shim` staticlib. The C text is sourced from the shim crate
// itself (its `pub const`s) rather than an `include_str!` across the crate
// boundary, so there is a single copy of the C that cannot drift and both
// crates package cleanly for publish.
const PATINA_POSIX_C: &str = patina_dst_native_shim::POSIX_C_SOURCE;
const PATINA_NATIVE_H: &str = patina_dst_native_shim::NATIVE_HEADER;
/// Build-time deterministic-preemption hook, linked only under `--yield-points`.
const PATINA_YIELD_C: &str = include_str!("../c/patina_yield.c");
/// Marker string the `--yield-points` hook embeds; `native-run` looks for it in
/// the binary to fold yield-point scheduling into the compatibility fingerprint.
const PATINA_YIELD_MARKER: &[u8] = b"PATINA_YIELD_POINTS_V1";
/// Fingerprint suffix distinguishing a yield-point binary's schedule policy from
/// a plain one, so their recorded traces never cross-replay.
const PATINA_YIELD_FINGERPRINT_SUFFIX: &str = "+yieldpoints";
const NATIVE_SHIM_STATICLIB: &str = "libpatina_dst_native_shim.a";
const DEFAULT_NATIVE_EDITION: &str = "2024";
const DEFAULT_NATIVE_FINGERPRINT: &str = "patina-native";
/// The fixed, machine-independent `argv[0]` every native guest sees. `native-run`
/// resolves the guest binary to an absolute host path (tempdir-specific,
/// machine-specific) to exec it, so passing that path through as `argv[0]` would
/// leak a non-portable string into the guest's `std::env::args().next()` — a
/// latent cross-machine determinism surface. The supervisor is the sole exec-er,
/// so it stamps this stable name as `argv[0]` instead; guests read their own
/// arguments from `argv[1..]` (all in-repo guests `.skip(1)`), so nothing that
/// observes real program arguments is affected.
const NATIVE_GUEST_ARGV0: &str = "patina-guest";
/// Inherited descriptor `native-run` hands the child for the trace control
/// plane (`PATINA_TRACE_FD`), matching the supervisor channel the shim reads.
const PATINA_TRACE_CHANNEL_FD: i32 = 3;
/// Inherited descriptor `native-run` hands the child carrying an encoded
/// `FsImage` (`PATINA_FS_IMAGE_FD`) when `--mount` captures a host directory
/// into the guest filesystem. Distinct from the trace channel so both may be
/// installed at once.
const PATINA_FS_IMAGE_CHANNEL_FD: i32 = 4;

const HELP: &str = "Patina deterministic Cargo runner

Usage:
  cargo patina run [--seed N | --record PATH] [FAULT OPTIONS] [--budget N] [--param K=V]... [CARGO OPTIONS] [-- PROGRAM OPTIONS]
  cargo patina run <MODULE.wasm> [--seed N | --record PATH] [--fuel N] [--arg VALUE]... [--env K=V]... [--socket FD=BIND->PEER]... [--preopen GUEST[:ro|:rw]]... [--fs-crash-at SPEC] [--fs-torn-granularity block|byte] [--net-jitter-nanos MIN..MAX] [--net-drop-permille N]
  cargo patina run <BINARY> [--seed N | --record PATH] [--fingerprint STR] [--mount HOST_DIR] [--net-latency-nanos N] [FAULT OPTIONS] [--buggify[=PERMILLE]] [--buggify-activation-permille N] [--buggify-cutoff-nanos N] [--buggify-after-setup] [--liveness-watchdog[=NANOS]] [--converge-within[=NANOS]] [--heal-after NANOS] [--allow SYMBOL]... [--allow-unsupported-symbols <all|name,...>] [-- PROGRAM ARGS]
  cargo patina run <SOURCE.rs|DIR|Cargo.toml> [--target native|wasi] [RUN OPTIONS]   (builds on the fly, then runs)
  cargo patina test [--seed N | --record PATH] [FAULT OPTIONS] [--budget N] [--param K=V]... [CARGO OPTIONS] [-- PROGRAM OPTIONS]
  cargo patina explore run <ARTIFACT|SOURCE.rs|DIR|Cargo.toml> [--target native|wasi] [--seeds N] [--start N] [RUN OPTIONS]
  cargo patina explore test [--seeds N] [--start N] [PATINA/CARGO OPTIONS]
  cargo patina campaign <ARTIFACT|SOURCE.rs|DIR|Cargo.toml> [--gens N] [--out DIR] [--spec FILE.json] [--seed-base N] [--buggify] [--swarm] [--pct] [--faults] [--liveness-watchdog N] [--converge-within N] [--report] [-- GUEST ARGS]
  cargo patina campaign --selftest
  cargo patina build <SOURCE.rs> --output <PATH> [--edition YEAR] [--release] [--yield-points] [-- RUSTC OPTIONS]
  cargo patina build <DIR|Cargo.toml> [--output <PATH>] [--package NAME] [--bin NAME] [--release] [--yield-points]
  cargo patina build <DIR|Cargo.toml> --target wasi [--output PATH] [--package NAME] [--bin NAME] [--release]
  cargo patina audit <ARTIFACT|SOURCE.rs|DIR|Cargo.toml> [--target native|wasi] [--allow SYMBOL]...
  cargo patina replay <ARTIFACT|SOURCE.rs|DIR|Cargo.toml> <TRACE> [--target native|wasi] [REPLAY OPTIONS]
  cargo patina minimize <TRACE> --output <PATH> [--timeline ID] [--prune-branches] -- <ORACLE> [ARGS]...
  cargo patina minimize --scenario --seed <U64> [--param K=V]... [--seed-budget N] -- <ORACLE> [ARGS]...

`replay <ARTIFACT|SOURCE|PKG> <TRACE>` routes by the same inference as `run`: a
WebAssembly module replays under WASI, a native binary under the native
supervisor, and a directory/Cargo.toml (no `--target`) under the Cargo package
family. Each restores its recorded semantics from the trace, so replay is
flag-free (seed, fault knobs, and — for WASI — the `--arg` guest argv are
restored; any re-supplied value must match the recording or the replay is
refused). The Cargo and WASI families also carry the timeline/branch controls:
`replay <PKG|MODULE.wasm> <TRACE> [--timeline ID]` replays a named timeline
(default `main`), and `replay <PKG|MODULE.wasm> <TRACE> --branch --from N
--branch-seed S --branch-id ID [--parent ID]` replays the parent prefix then
appends a new branch timeline. Native traces are single-timeline (native runs
cannot branch), so native replay accepts only `--fingerprint`, `--mount`, and
the `--allow`/`--allow-unsupported-symbols` audit surface.

`run`, `audit`, and `replay` are source-first with artifacts accepted uniformly.
A built artifact (recognized by its leading magic bytes — `\\0asm` for a WASI
module, Mach-O/ELF for a native binary) is used as-is. A `<SOURCE.rs|DIR|
Cargo.toml>` argument is built on the fly through the same pipeline as `build`
(honoring `--target`, default native) and its product is used; a one-line
`PATINA_BUILD_ON_RUN` note reports the built artifact and its content hash so an
implicit rebuild never silently changes what ran. `replay` judges a rebuilt
binary against the trace with the usual fail-closed machinery (fingerprint +
operation mismatch). A `run` with a directory, a `Cargo.toml`, or no artifact and
no `--target` stays the Cargo package family (the same seed/record/replay/branch
machinery as `test`); `--target` opts a source/package argument into build-then-
run. `build` defaults to `--target native`.

Patina options (run/test):
      --seed <U64>       Deterministic root seed (default: 0)
      --record <PATH>    Record boundary operations and outcomes
      --budget <STEPS>   Maximum boundary operations before explicit failure
      --param <K=V>      Typed-builder parameter exposed through Context
  -h, --help             Print help
  -V, --version          Print version

Output options (all verbs; stripped before routing, never reach the guest):
      --format <human|json>  Default human. `json` prints one machine-readable
                             result envelope (schema \"patina.result/v1\") on
                             stdout: result (ok|violation|failure|error),
                             exit_code, family, artifact, fingerprint, seed,
                             trace {path, format_version, timelines, event_count,
                             metadata}, findings, markers, and captured
                             stdout/stderr. Human output is unchanged by default.
                             (`--output` is the build/minimize artifact path.)
      --render <OUT.html>    For a run/replay with a trace (record or replay),
                             write a self-contained HTML timeline (per-task lanes,
                             scheduling/sleep/net/fs/crash events) to OUT.html.
      --report <OUT.html>    Like --render but only when the run fails; the HTML
                             leads with a failure summary (what fired, exit code,
                             the result/violation lines).

Fault options (run/test and run <MODULE.wasm>; seed-driven, default off):
      --fs-crash-at <SPEC>           open|write|sync|close[:N] (bare = :1)
      --fs-torn-granularity <G>      block (default) or byte
      --sleep-jitter-nanos <MIN..MAX>  extra seeded latency per guest sleep
                                     (also honored on run <MODULE.wasm> at the
                                     wasip1 host's sleep entry, incl. poll_oneoff)
      --net-jitter-nanos <MIN..MAX>  seeded per-datagram delivery jitter
      --net-drop-permille <N>        drop datagrams at N per-mille (0..=1000)

Reproducing a recording — strict or branch-append — is the `replay` verb's job,
so `run`/`test` carry no replay/branch/timeline flags. A `--record` run captures
its seed, fault knobs, and (for WASI) guest argv into the trace metadata, so
`replay` restores them and gets its root seed from the trace. All unrecognized
`run`/`test` options are forwarded to Cargo.

`minimize <TRACE>` shrinks a recorded trace. It chooses the strategy from the
bundle: an unbranched main timeline or a leaf `--timeline ID` is delta-debugged
directly, while a branched bundle or a non-leaf timeline is shrunk under the
branch-tree policy that never touches an inherited replay prefix.
`--prune-branches` also drops whole branch subtrees the failure does not need.
The oracle runs once per candidate with the candidate written to
`$PATINA_MINIMIZE_TRACE`; a non-zero exit means the failure is still present.

`minimize --scenario` shrinks experiment inputs instead of a trace: it drops and
shrinks `--param` values and canonicalizes `--seed` toward zero, bounded by
`--seed-budget`. Each candidate re-runs the oracle as a fresh seeded child that
receives the candidate through the usual `PATINA_SEED`/`PATINA_PARAMS_JSON`
environment protocol; a non-zero exit means the failure is still present.

`build` (default `--target native`) packages the native linked-shim target: it
builds the `patina-dst-native-shim` staticlib, compiles the embedded POSIX C layer,
injects `cfg(patina)`/`cfg(dst)`, and links the shim below the user program with
`rustc`. On Linux it also links `-Wl,--wrap=dlsym` so the shim reaches the real
glibc resolver through `__real_dlsym` (its host-alias table) while guest `dlsym`
stays neutered; thread creation is interposed by a plain strong `pthread_create`
def whose real vehicle is resolved through that same table, so no
`--wrap=pthread_create` is needed (and none is used — glibc ships its own
`__wrap_pthread_create` in libgcc's x86 split-stack support, which a wrap would
clash with). macOS needs neither flag.
A `.rs` path builds that single source directly. A directory (or `Cargo.toml`)
path instead drives the package's own `cargo build` under Patina control: the
same cfg flags and shim link arguments are injected through
`CARGO_ENCODED_RUSTFLAGS`, and an explicit host `--target` keeps them off build
scripts and proc macros (which link for the host). Select the member with
`--package` in a workspace and the binary with `--bin` when the package defines
more than one; `--output` copies the built binary out (otherwise its Cargo
artifact path is reported). The `patina-dst-native-shim` staticlib is built from the
surrounding Patina workspace, so run `build` from within it.
`build --target wasi` instead compiles a Cargo package for `wasm32-wasip1`; it is
package-only (a single `.rs` source is native-only) and `--yield-points` is
rejected (wasip1 has no threads to preempt).
`--yield-points` additionally instruments the native guest with deterministic
cooperative preemption: LLVM SanitizerCoverage emits a hook at every basic block
(reaching loop backedges) that routes into the scheduler, so a race window that
lives entirely in atomics-only code — a `std::sync::RwLock` read-modify-write,
say — becomes reachable by the seeded scheduler instead of running to completion
uninterrupted. It is off by default and touches only the Patina build; a plain
native build is unaffected. `run` detects a yield-point binary and folds
it into the compatibility fingerprint so its traces never cross-replay with a
plain binary.
`run <BINARY>` executes such a binary under the deterministic runtime; for
`--record` (and for the `replay` subcommand) it opens the trace on the host and
hands the child an inherited `PATINA_TRACE_FD` descriptor so a fully interposed
program never recurses into the deterministic filesystem while finalizing its
trace. Before
the guest runs it applies a pre-run default-deny audit: every externally
resolved symbol must be interposed or known-safe (the shim's own control-plane
vehicle is allowed automatically), and any unsupported symbol on the
blocking/time/scheduling/effect surface hard-errors with the names listed.
`--allow SYMBOL` adds a known-safe symbol; `--allow-unsupported-symbols
<all|name,...>` downgrades matching denials to a loud warning (recorded beside a
`--record` trace) for programs that carry unsupported surface the scenario never
reaches.

WASI options:
      --preopen <GUEST[:ro|:rw]>  Preopen an absolute guest path (repeatable;
                                  default policy: rw). The first explicit
                                  preopen replaces the implicit rw `/` root.
      --max-memory-pages <N>      Maximum guest memory pages (64 KiB each)
      --max-descriptors <N>       Maximum open WASI descriptors
      --max-preopens <N>          Maximum configured preopened directories
      --max-path-bytes <N>        Maximum bytes in a single guest path
      --max-io-bytes <N>          Maximum bytes in one WASI I/O operation
      --max-iovecs <N>            Maximum iovec entries in one WASI operation

Native filesystem options (run <BINARY>):
      --mount <HOST_DIR>          Capture a host directory read-only into the
                                  guest filesystem, mounted at the guest root
                                  `/`. The supervisor walks it into a
                                  deterministic in-memory image (sorted; host
                                  readdir order never leaks) and streams it to
                                  the guest, which never touches the host FS.
                                  Symlinks are preserved as inert (not followed).
                                  The image hash folds into the run fingerprint
                                  so replay rejects a different corpus.

Native fault options (run <BINARY>; seed-driven, default off):
      --fs-crash-at <SPEC>        Inject a filesystem crash after the Nth boundary
                                  op: open|write|sync|close[:N] (bare = :1). The
                                  filesystem becomes a CrashFs and unsynced data
                                  is dropped, exposing missing-fsync durability
                                  bugs.
      --fs-torn-granularity <G>   Torn-write granularity for --fs-crash-at:
                                  block (default, whole-block revert) or byte
                                  (the final unsynced write may survive
                                  partially at sub-block byte granularity,
                                  modeling a torn in-flight page).
      --sleep-jitter-nanos <MIN..MAX>
                                  Add seeded latency drawn from [MIN, MAX] to
                                  every guest sleep, inflating virtual elapsed
                                  time past wall-clock deadline assumptions.
      --net-jitter-nanos <MIN..MAX>
                                  Add seeded per-datagram delivery jitter drawn
                                  from [MIN, MAX], reordering datagrams relative
                                  to send order.
      --net-drop-permille <N>     Drop datagrams with probability N per-mille
                                  (0..=1000).
      --buggify[=<PERMILLE>]      Enable cooperative-SUT (buggify) fault
                                  injection. PERMILLE is the per-evaluation
                                  firing probability for an active site
                                  (default 250 = 25%).
      --buggify-activation-permille <N>
                                  Fraction of buggify sites made active this run
                                  (default 250 = 25%). Implies --buggify.
      --buggify-cutoff-nanos <N>  Virtual-time cutoff after which buggify stops
                                  firing (default 300000000000 = 300s). Implies
                                  --buggify.
      --buggify-after-setup       Declare that the guest calls
                                  patina_dst::lifecycle::setup_complete(); buggify
                                  stays inert until it does. If the guest never
                                  calls it, the run fails loudly. Implies
                                  --buggify.

Fault and buggify knobs are seeded by the run seed. A --record run captures its
full configuration — fault knobs, buggify, and the guest arguments after `--` —
into the trace metadata. Enabling buggify folds a +buggify component into the run
fingerprint, so a buggify trace never cross-replays with a non-buggify build.

Reproduce a recorded run with `cargo patina replay <ARTIFACT|SOURCE|PKG>
<TRACE>`, the sole replay entry point for all three families: it restores every
semantic input (seed, fault knobs, and buggify — for both the native and WASI
families) from the trace — the trace is authoritative — and exposes no semantic
flags. For native the guest
arguments are restored from the trace, so a run recorded with non-default
`-- ARGS` replays without re-passing them (a `--` section is allowed only if
byte-identical to the recording, or the replay is refused up front); for WASI the
recorded `--arg` guest argv is restored the same way and a re-supplied `--arg`
must match. Only host/build inputs the trace cannot carry stay as flags: native
takes --fingerprint/--mount/--allow[-unsupported-symbols]; WASI re-takes its host
environment (--fuel/--env/--socket/--preopen and resource limits), whose match is
verified through the compatibility fingerprint. The native guest always sees a
fixed, machine-independent `argv[0]` (`patina-guest`), never the host binary
path, so traces are portable across machines.
";

#[derive(Clone, Debug, PartialEq, Eq)]
enum Mode {
    Seeded {
        seed: u64,
    },
    Record {
        seed: u64,
        path: PathBuf,
    },
    Replay {
        path: PathBuf,
        timeline: String,
    },
    Branch {
        path: PathBuf,
        parent: String,
        from_sequence: u64,
        branch_seed: u64,
        branch_id: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct WasiInvocation {
    module: ArtifactRef,
    mode: Mode,
    fuel: u64,
    arguments: Vec<String>,
    environment: BTreeMap<String, String>,
    sockets: Vec<WasiSocketConfig>,
    preopens: Vec<WasiPreopenConfig>,
    resource_limits: WasiResourceLimitOverrides,
    /// Seed-driven fault-injection knobs applied to the in-process runtime before
    /// `Context::from_config`, so a WASI guest's filesystem and datagram sockets
    /// see the same seeded crash/jitter/drop drivers the native family does.
    /// Recorded into the trace metadata on `--record`; restored from the trace on
    /// `replay`, so a WASI replay is flag-free. `--sleep-jitter-nanos` is carried
    /// here too: the wasip1 host applies it at its single guest-facing sleep entry
    /// (`Preview1Host::sleep_until`, also covering `poll_oneoff` clock timeouts).
    faults: NativeFaults,
    /// Cooperative-SUT (buggify) knobs applied to the in-process runtime through
    /// the same `apply_buggify_env` accessor the native family feeds over its
    /// control plane. `None` unless `--buggify` was passed. Recorded into the
    /// trace metadata on `--record` and restored from the trace on `replay`, so a
    /// WASI buggify replay is flag-free, exactly like the fault knobs.
    buggify: Option<NativeBuggify>,
    /// Liveness-watchdog knobs applied to the in-process runtime through the shared
    /// `apply_liveness_env` accessor. Schedule-invariant, so recorded into the
    /// trace metadata (informational) but never fingerprinted.
    liveness: NativeLiveness,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct WasiPreopenConfig {
    guest_path: String,
    policy: MountPolicy,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct WasiResourceLimitOverrides {
    fuel: Option<u64>,
    max_memory_pages: Option<u32>,
    max_iovecs: Option<usize>,
    max_io_bytes: Option<usize>,
    max_descriptors: Option<usize>,
    max_preopens: Option<usize>,
    max_path_bytes: Option<usize>,
}

impl WasiResourceLimitOverrides {
    fn to_host_limits(&self) -> ResourceLimits {
        let mut limits = ResourceLimits::default();
        if let Some(fuel) = self.fuel {
            limits.fuel = fuel;
        }
        if let Some(max_memory_pages) = self.max_memory_pages {
            limits.max_memory_pages = max_memory_pages;
        }
        if let Some(max_iovecs) = self.max_iovecs {
            limits.max_iovecs = max_iovecs;
        }
        if let Some(max_io_bytes) = self.max_io_bytes {
            limits.max_io_bytes = max_io_bytes;
        }
        if let Some(max_descriptors) = self.max_descriptors {
            limits.max_descriptors = max_descriptors;
        }
        if let Some(max_preopens) = self.max_preopens {
            limits.max_preopens = max_preopens;
        }
        if let Some(max_path_bytes) = self.max_path_bytes {
            limits.max_path_bytes = max_path_bytes;
        }
        limits
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct WasiSocketConfig {
    fd: u32,
    bind: String,
    peer: String,
}

struct NativeAuditInvocation {
    binary: ArtifactRef,
    allow: BTreeSet<String>,
}

/// A `minimize` request: either shrinking a recorded trace bundle or reducing
/// the experiment inputs (seed and parameters) that trigger a failure.
enum MinimizeInvocation {
    Trace(TraceMinimize),
    Scenario(ScenarioMinimize),
}

struct TraceMinimize {
    trace: PathBuf,
    output: PathBuf,
    timeline: Option<String>,
    prune: bool,
    oracle: Vec<OsString>,
}

/// Default number of candidate seeds tried when reducing a scenario's seed.
const DEFAULT_SEED_BUDGET: u64 = 256;

struct ScenarioMinimize {
    seed: u64,
    params: BTreeMap<String, String>,
    seed_budget: u64,
    oracle: Vec<OsString>,
}

#[derive(Clone)]
struct Invocation {
    cargo_command: String,
    cargo_args: Vec<OsString>,
    mode: Mode,
    step_budget: Option<u64>,
    params: BTreeMap<String, String>,
    /// Seed-driven fault-injection knobs forwarded to the guest through the
    /// `PATINA_*` control plane (the same knobs the native and WASI families
    /// accept). Recorded into the trace metadata on `--record`; restored from the
    /// trace on the `replay` verb, so a cargo-family replay is flag-free. Default
    /// (all `None`) leaves faults off.
    faults: NativeFaults,
    /// Working directory the cargo subprocess runs in, or `None` to inherit the
    /// caller's. Set by the cargo-family `replay` verb from its `<pkg>` positional
    /// so a replay can run from anywhere while its fingerprint (which walks the
    /// package's own source tree) still matches the recording.
    working_dir: Option<PathBuf>,
}

struct ExploreInvocation {
    target: ExploreTarget,
    start_seed: u64,
    seed_count: u64,
}

/// What `explore` sweeps across seeds. The Cargo package family re-runs the whole
/// `run`/`test` command per seed (each cargo invocation is cheap next to the
/// build it caches). The native and WASI families instead build the artifact
/// once and run that SAME artifact across every seed, so a source/package is
/// never rebuilt per seed.
enum ExploreTarget {
    Cargo(Invocation),
    Wasi(WasiInvocation),
    Native(NativeRunInvocation),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct NativeBuildInvocation {
    target: NativeBuildTarget,
    output: Option<PathBuf>,
    release: bool,
    /// Instrument the guest with deterministic yield points (LLVM
    /// SanitizerCoverage → `patina_sched_yield`) so atomics-only race windows are
    /// schedulable. Off by default; native builds never see it.
    yield_points: bool,
}

/// What `build` compiles for the native target: a single Rust source linked
/// directly with `rustc`, or a whole Cargo package driven through its own
/// `cargo build`.
#[derive(Clone, Debug, PartialEq, Eq)]
enum NativeBuildTarget {
    Source {
        source: PathBuf,
        edition: String,
        rustc_args: Vec<OsString>,
    },
    Package {
        manifest: PathBuf,
        package: Option<String>,
        bin: Option<String>,
    },
}

/// What `build --target wasi` compiles: a Cargo package for `wasm32-wasip1`.
/// WASI is package-only (a single `.rs` source is native-only).
#[derive(Clone, Debug, PartialEq, Eq)]
struct WasiBuildInvocation {
    manifest: PathBuf,
    package: Option<String>,
    bin: Option<String>,
    release: bool,
    /// When set, the produced `.wasm` is copied here; otherwise its Cargo
    /// artifact path is reported.
    output: Option<PathBuf>,
}

/// A build-on-the-fly request captured at parse time and executed by the shared
/// build pipeline just before a run/audit/replay consumes its product. Carries
/// the user's original source argument (`origin`) so a WASI guest's `argv[0]`
/// and diagnostics name the source rather than a throwaway temp path.
#[derive(Clone, Debug, PartialEq, Eq)]
struct BuildSpec {
    origin: PathBuf,
    kind: BuildSpecKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum BuildSpecKind {
    Native(NativeBuildInvocation),
    Wasi(WasiBuildInvocation),
}

/// A run/audit/replay artifact argument: either an already-built file used
/// directly (build-once-run-many stays first-class), or a source/package built
/// on the fly through the shared build pipeline before use. Resolved to a
/// concrete path — building if needed — at execute time by [`resolve_artifact`].
#[derive(Clone, Debug, PartialEq, Eq)]
enum ArtifactRef {
    Prebuilt(PathBuf),
    Build(Box<BuildSpec>),
}

#[derive(Clone)]
enum NativeRunMode {
    Seeded {
        seed: u64,
    },
    Record {
        seed: u64,
        path: PathBuf,
        fingerprint: String,
    },
    Replay {
        path: PathBuf,
        fingerprint: String,
    },
}

#[derive(Clone)]
struct NativeRunInvocation {
    binary: ArtifactRef,
    mode: NativeRunMode,
    program_args: Vec<OsString>,
    net_latency_nanos: Option<u64>,
    /// Fault-injection knobs forwarded to the guest through the `PATINA_*`
    /// control plane. Each is a validated raw value stored verbatim; the runtime
    /// re-parses it identically on record and replay, so a mismatched flag on
    /// replay fails closed like any other operation divergence.
    faults: NativeFaults,
    /// Cooperative-SUT (buggify) knobs, or `None` when `--buggify` was not
    /// passed. Presence enables buggify and folds `+buggify` into the run
    /// fingerprint.
    buggify: Option<NativeBuggify>,
    /// Exploration scheduling-policy (PCT / starvation) and swarm knobs. Enabling
    /// a non-default policy or swarm folds `+pct`/`+starve`/`+swarm` into the run
    /// fingerprint.
    schedule: NativeSchedule,
    /// Liveness-watchdog knobs forwarded to the guest through the control plane.
    /// Schedule-invariant: recorded (informational) but NOT fingerprinted.
    liveness: NativeLiveness,
    /// Extra symbols to treat as known-safe in the pre-run audit gate, beyond
    /// the baked shim control-plane vehicle. Mirrors `native-audit --allow`.
    allow: BTreeSet<String>,
    /// How the pre-run gate treats symbols that are neither interposed nor
    /// known-safe.
    allow_unsupported: UnsupportedPolicy,
    /// Host directory to capture read-only into the guest filesystem, mounted at
    /// the guest root `/`. When set, the supervisor (which is not interposed)
    /// walks the tree into a deterministic `FsImage`, streams it to the guest
    /// over an inherited descriptor, and the shim rebuilds it as the
    /// deterministic filesystem. The image hash is folded into the run
    /// fingerprint so replay rejects a different corpus.
    mount: Option<PathBuf>,
}

/// Seed-driven fault-injection knobs for `native-run`, all default-off. Stored
/// as validated raw strings so the exact protocol text reaches the guest.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct NativeFaults {
    /// Filesystem crash point, e.g. `close:1`, `write:3`, `sync:2`, `open:1`.
    fs_crash_at: Option<String>,
    /// Torn-write granularity for an injected crash: `block` (default) or
    /// `byte` (sub-block tearing of the final unsynced write). Only meaningful
    /// alongside `fs_crash_at`.
    fs_torn_granularity: Option<String>,
    /// Seeded sleep-latency range `MIN..MAX` nanoseconds.
    sleep_jitter_nanos: Option<String>,
    /// Seeded per-datagram delivery-jitter range `MIN..MAX` nanoseconds.
    net_jitter_nanos: Option<String>,
    /// Seeded datagram drop probability in per-mille (0..=1000).
    net_drop_permille: Option<String>,
}

/// Cooperative-SUT (buggify) knobs for `native-run`, forwarded to the guest as
/// validated raw strings through the `PATINA_BUGGIFY*` control plane. Presence
/// of the enclosing `Option` means `--buggify` was passed (buggify enabled).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct NativeBuggify {
    /// Per-evaluation firing probability in per-mille from `--buggify[=permille]`.
    fire_permille: Option<String>,
    /// Per-run site activation probability from `--buggify-activation-permille`.
    activation_permille: Option<String>,
    /// Damage-control cutoff in virtual nanoseconds from `--buggify-cutoff-nanos`.
    cutoff_nanos: Option<String>,
    /// `--buggify-after-setup`: declare that the guest calls
    /// `setup_complete()`, gating buggify off until it does.
    after_setup: bool,
}

/// Exploration scheduling-policy and swarm knobs for `native-run`, forwarded to
/// the guest as validated raw strings through the `PATINA_SCHED_*`/`PATINA_SWARM`
/// control plane. Each is default-off; enabling a non-default policy or swarm
/// folds a fingerprint component so a policy trace never cross-replays with a
/// plain build.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct NativeSchedule {
    /// PCT bug depth `d` from `--sched-pct[=D]`. `Some("")` = bare `--sched-pct`
    /// (default depth); `Some("N")` = explicit depth. `None` = PCT off.
    pct: Option<String>,
    /// Expected schedule length from `--sched-pct-steps N`. Inert without `pct`.
    pct_steps: Option<String>,
    /// Starvation interval count from `--starve[=N]`. `Some("")` = bare `--starve`
    /// (default count). `None` = starvation off.
    starve: Option<String>,
    /// Maximum starvation-interval length from `--starve-max-len N`. Inert
    /// without `starve`.
    starve_max_len: Option<String>,
    /// Starvation start window from `--starve-window N`. Inert without `starve`.
    starve_window: Option<String>,
    /// `--swarm`: apply a seed-derived subset of the enabled fault classes.
    swarm: bool,
}

/// Liveness-watchdog knobs, forwarded to the guest/runtime as validated raw
/// strings through the `PATINA_LIVENESS_*`/`PATINA_CONVERGE_*`/`PATINA_HEAL_*`
/// control plane. Default-off. Deliberately kept SEPARATE from [`NativeSchedule`]
/// because the watchdog is schedule-invariant: enabling it folds NO fingerprint
/// component (it only adds a possible violation report), so a watchdog trace
/// replays against any build.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct NativeLiveness {
    /// `--liveness-watchdog[=NANOS]`: generic no-progress budget. `Some("")` = bare
    /// (runtime default budget); `Some("N")` = explicit budget. `None` = off.
    watchdog: Option<String>,
    /// `--converge-within[=NANOS]`: heal-then-converge budget. `Some("")` = bare
    /// (runtime default); `Some("N")` = explicit. `None` = off.
    converge: Option<String>,
    /// `--heal-after=NANOS`: explicit override for the converge arm-time. Inert
    /// without `converge`.
    heal_after: Option<String>,
}

impl NativeLiveness {
    fn is_enabled(&self) -> bool {
        self.watchdog.is_some() || self.converge.is_some()
    }
}

/// The escape hatch for `native-run`'s pre-run default-deny gate. By default an
/// unsupported symbol on the blocking/effect surface is a hard error before the
/// guest runs; the operator can downgrade specific symbols (or all) to a loud
/// warning for programs that carry unsupported surface never reached by the
/// scenario under test.
#[derive(Clone, Debug, PartialEq, Eq)]
enum UnsupportedPolicy {
    /// Default: any unsupported symbol is a hard error (fail closed).
    Deny,
    /// `--allow-unsupported-symbols all`: downgrade every unsupported symbol.
    All,
    /// `--allow-unsupported-symbols a,b,c`: downgrade only the listed symbols;
    /// anything else still hard-errors.
    Only(BTreeSet<String>),
}

pub fn entrypoint() -> Result<i32, CliError> {
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    // Strip the cross-cutting output flags (`--output`, `--render`, `--report`)
    // once, globally, before any per-verb routing — the same pre-pass shape as
    // `extract_target`. They are patina-level flags, so they never reach the
    // guest (anything after `--` is left in place).
    let (options, arguments) = output::extract(arguments)?;
    let is_json = options.is_json();
    output::install(options);
    let result = dispatch(arguments);
    // Under `--output json` a CLI-side failure becomes a JSON error envelope
    // rather than the bare `cargo-patina: {error}` stderr line, so an agent always
    // parses one machine-readable object.
    match result {
        Err(error) if is_json => {
            output::emit_simple("cli", "error", 2, Some(error.to_string()));
            Ok(2)
        }
        other => other,
    }
}

fn dispatch(arguments: Vec<OsString>) -> Result<i32, CliError> {
    match parse(arguments)? {
        ParseResult::Help => {
            print!("{HELP}");
            Ok(0)
        }
        ParseResult::Version => {
            println!("cargo-patina {}", env!("CARGO_PKG_VERSION"));
            Ok(0)
        }
        ParseResult::Run(invocation) => execute(invocation),
        ParseResult::Campaign(invocation) => campaign::execute(invocation),
        ParseResult::Explore(invocation) => execute_explore(invocation),
        ParseResult::WasiBuild(invocation) => execute_wasi_build(invocation),
        ParseResult::WasiAudit(artifact) => execute_wasi_audit(artifact),
        ParseResult::WasiRun(invocation) => execute_wasi_run(invocation),
        ParseResult::NativeAudit(invocation) => execute_native_audit(invocation),
        ParseResult::NativeBuild(invocation) => execute_native_build(invocation),
        ParseResult::NativeRun(invocation) => execute_native_run(invocation),
        ParseResult::Minimize(invocation) => execute_minimize(invocation),
    }
}

enum ParseResult {
    Help,
    Version,
    Run(Invocation),
    Campaign(campaign::CampaignInvocation),
    Explore(ExploreInvocation),
    WasiBuild(WasiBuildInvocation),
    WasiAudit(ArtifactRef),
    WasiRun(WasiInvocation),
    NativeAudit(NativeAuditInvocation),
    NativeBuild(NativeBuildInvocation),
    NativeRun(NativeRunInvocation),
    Minimize(MinimizeInvocation),
}

fn parse(mut arguments: Vec<OsString>) -> Result<ParseResult, CliError> {
    // `cargo patina ...` invokes this binary with a leading `patina` argument.
    if arguments.first().and_then(|value| value.to_str()) == Some("patina") {
        arguments.remove(0);
    }
    if arguments.is_empty() {
        return Err(CliError::usage(
            "missing command (expected run, test, campaign, explore, build, audit, replay, or minimize)",
        ));
    }
    match arguments.first().and_then(|value| value.to_str()) {
        Some("campaign") => {
            arguments.remove(0);
            campaign::parse(arguments).map(ParseResult::Campaign)
        }
        Some("explore") => {
            arguments.remove(0);
            parse_explore(arguments).map(ParseResult::Explore)
        }
        Some("build") => {
            arguments.remove(0);
            parse_build(arguments)
        }
        Some("audit") => {
            arguments.remove(0);
            parse_audit(arguments)
        }
        Some("run") => {
            arguments.remove(0);
            parse_run(arguments)
        }
        Some("test") => {
            arguments.remove(0);
            parse_cargo("test".to_string(), arguments)
        }
        Some("replay") => {
            arguments.remove(0);
            // `replay` is the sole replay entry point for all three families,
            // routed by the same artifact inference as `run`: it restores each
            // family's semantic config (seed, fault knobs, buggify, guest argv)
            // from the trace and exposes no semantic flags.
            parse_replay(arguments)
        }
        Some("minimize") => {
            arguments.remove(0);
            parse_minimize(arguments).map(ParseResult::Minimize)
        }
        Some("-h" | "--help") => Ok(ParseResult::Help),
        Some("-V" | "--version") => Ok(ParseResult::Version),
        _ => Err(CliError::usage(format!(
            "unsupported command {:?}; expected run, test, campaign, explore, build, audit, replay, or minimize",
            arguments[0].to_string_lossy()
        ))),
    }
}

/// A compiled artifact's target family, inferred from its leading magic bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ArtifactFamily {
    /// A WebAssembly module (`\0asm` preamble) → the WASI runner/audit path.
    Wasm,
    /// A native executable (Mach-O or ELF magic) → the native runner/audit path.
    Native,
}

/// Classify a compiled artifact by its leading magic bytes. Pure and
/// filesystem-free so it is unit-testable on byte slices; returns `None` for
/// anything that is neither a WebAssembly module nor a native Mach-O/ELF image
/// (a `Cargo.toml`, a shell script, an empty file, ...).
fn detect_artifact_family(bytes: &[u8]) -> Option<ArtifactFamily> {
    // WebAssembly: the four-byte `\0asm` preamble.
    if bytes.starts_with(b"\0asm") {
        return Some(ArtifactFamily::Wasm);
    }
    // ELF: 0x7F 'E' 'L' 'F'.
    if bytes.starts_with(&[0x7f, b'E', b'L', b'F']) {
        return Some(ArtifactFamily::Native);
    }
    // Mach-O: thin 32/64-bit in either byte order, plus universal ("fat")
    // archives. Each four-byte magic is matched exactly.
    const MACH_O_MAGICS: [[u8; 4]; 6] = [
        [0xfe, 0xed, 0xfa, 0xce], // MH_MAGIC (32-bit)
        [0xce, 0xfa, 0xed, 0xfe], // MH_CIGAM (32-bit, byte-swapped)
        [0xfe, 0xed, 0xfa, 0xcf], // MH_MAGIC_64 (64-bit)
        [0xcf, 0xfa, 0xed, 0xfe], // MH_CIGAM_64 (64-bit, byte-swapped)
        [0xca, 0xfe, 0xba, 0xbe], // FAT_MAGIC (universal)
        [0xbe, 0xba, 0xfe, 0xca], // FAT_CIGAM (universal, byte-swapped)
    ];
    if MACH_O_MAGICS.iter().any(|magic| bytes.starts_with(magic)) {
        return Some(ArtifactFamily::Native);
    }
    None
}

/// Read the leading magic bytes of `path` and classify it with
/// [`detect_artifact_family`]. Only a short prefix is read, so a multi-megabyte
/// native binary is not slurped merely to route it.
fn artifact_family(path: &Path) -> Result<Option<ArtifactFamily>, CliError> {
    use std::io::Read;
    let mut file = fs::File::open(path).map_err(|error| {
        CliError(format!(
            "failed to open artifact {}: {error}",
            path.display()
        ))
    })?;
    let mut prefix = [0u8; 8];
    let read = file.read(&mut prefix).map_err(|error| {
        CliError(format!(
            "failed to read artifact {}: {error}",
            path.display()
        ))
    })?;
    Ok(detect_artifact_family(&prefix[..read]))
}

/// Extract a `--target native|wasi` selector from the leading (pre-`--`) region
/// of an argument list, returning it plus the arguments with the selector
/// removed. A `--target` after a `--` separator is left in place — there it is a
/// rustc/cargo flag, not Patina's family selector.
fn extract_target(arguments: Vec<OsString>) -> Result<(Option<String>, Vec<OsString>), CliError> {
    let mut target: Option<String> = None;
    let mut rest: Vec<OsString> = Vec::new();
    let mut iterator = arguments.into_iter();
    let mut after_separator = false;
    while let Some(argument) = iterator.next() {
        if after_separator {
            rest.push(argument);
            continue;
        }
        if argument == "--" {
            after_separator = true;
            rest.push(argument);
            continue;
        }
        match argument.to_str() {
            Some("--target") => {
                let value = iterator
                    .next()
                    .and_then(|value| value.into_string().ok())
                    .ok_or_else(|| CliError::usage("--target requires native or wasi"))?;
                set_once(&mut target, value, "--target")?;
            }
            Some(value) if value.starts_with("--target=") => {
                set_once(
                    &mut target,
                    value["--target=".len()..].to_string(),
                    "--target",
                )?;
            }
            _ => rest.push(argument),
        }
    }
    Ok((target, rest))
}

/// Map a `--target` value to its artifact family.
fn target_family(target: &str) -> Result<ArtifactFamily, CliError> {
    match target {
        "native" => Ok(ArtifactFamily::Native),
        "wasi" => Ok(ArtifactFamily::Wasm),
        other => Err(CliError::usage(format!(
            "--target must be native or wasi; got {other:?}"
        ))),
    }
}

/// How a run/audit/replay positional argument classifies. The single shared
/// resolution step (unit-tested via [`classify_arg`]) decides between using an
/// already-built artifact directly and building a source/package on the fly.
enum ArgKind {
    /// An existing file with WebAssembly or native Mach-O/ELF magic.
    Artifact(ArtifactFamily),
    /// A single `.rs` source (built native).
    SourceFile(PathBuf),
    /// A directory or `Cargo.toml` (a Cargo package), resolved to its manifest.
    SourcePackage(PathBuf),
    /// A leading flag, or a plain non-source file: neither artifact nor source.
    Other,
}

/// Classify a run/audit/replay positional argument. A built artifact is
/// recognized by leading magic bytes (used directly); a `.rs`, directory, or
/// `Cargo.toml` is a source/package to build; everything else is `Other`.
fn classify_arg(raw: &OsStr) -> Result<ArgKind, CliError> {
    if raw.to_str().is_some_and(|value| value.starts_with('-')) {
        return Ok(ArgKind::Other);
    }
    let path = Path::new(raw);
    if path.is_dir() {
        return Ok(ArgKind::SourcePackage(native_manifest_path(path)));
    }
    if path.is_file() {
        if let Some(family) = artifact_family(path)? {
            return Ok(ArgKind::Artifact(family));
        }
    }
    if path.file_name() == Some(OsStr::new("Cargo.toml")) {
        return Ok(ArgKind::SourcePackage(path.to_path_buf()));
    }
    if path.extension().and_then(OsStr::to_str) == Some("rs") {
        return Ok(ArgKind::SourceFile(path.to_path_buf()));
    }
    Ok(ArgKind::Other)
}

/// Build spec for a single-source native build on the fly (defaults: current
/// edition, debug, no yield points, no extra rustc args).
fn native_source_spec(source: PathBuf) -> BuildSpec {
    BuildSpec {
        origin: source.clone(),
        kind: BuildSpecKind::Native(NativeBuildInvocation {
            target: NativeBuildTarget::Source {
                source,
                edition: DEFAULT_NATIVE_EDITION.to_string(),
                rustc_args: Vec::new(),
            },
            output: None,
            release: false,
            yield_points: false,
        }),
    }
}

/// Build spec for a native Cargo-package build on the fly. Binary selection is
/// automatic (fails closed on ambiguity, like the `build` verb).
fn native_package_spec(origin: PathBuf, manifest: PathBuf) -> BuildSpec {
    BuildSpec {
        origin,
        kind: BuildSpecKind::Native(NativeBuildInvocation {
            target: NativeBuildTarget::Package {
                manifest,
                package: None,
                bin: None,
            },
            output: None,
            release: false,
            yield_points: false,
        }),
    }
}

/// Build spec for a WASI Cargo-package build on the fly.
fn wasi_package_spec(origin: PathBuf, manifest: PathBuf) -> BuildSpec {
    BuildSpec {
        origin,
        kind: BuildSpecKind::Wasi(WasiBuildInvocation {
            manifest,
            package: None,
            bin: None,
            release: false,
            output: None,
        }),
    }
}

/// Resolve a run/audit/replay positional to an [`ArtifactRef`], honoring
/// `--target` (default native) and building a source/package on the fly. When
/// `cargo_family` is true (only `run`), a directory/`Cargo.toml` with no
/// `--target` is NOT built — it stays the explicit-API Cargo package family and
/// this returns `None` so the caller falls through to `parse_cargo`.
fn resolve_positional(
    raw: &OsStr,
    target: Option<&str>,
    cargo_family: bool,
) -> Result<Option<(ArtifactFamily, ArtifactRef)>, CliError> {
    match classify_arg(raw)? {
        ArgKind::Artifact(family) => {
            if let Some(target) = target {
                let requested = target_family(target)?;
                if requested != family {
                    return Err(CliError::usage(format!(
                        "--target {target} does not match {}, an already-built {} artifact",
                        Path::new(raw).display(),
                        family_label(family)
                    )));
                }
            }
            Ok(Some((family, ArtifactRef::Prebuilt(PathBuf::from(raw)))))
        }
        ArgKind::SourceFile(source) => {
            let family = match target {
                Some(target) => target_family(target)?,
                None => ArtifactFamily::Native,
            };
            if family == ArtifactFamily::Wasm {
                return Err(CliError::usage(
                    "build --target wasi compiles a Cargo package; a single .rs source is native-only",
                ));
            }
            Ok(Some((
                family,
                ArtifactRef::Build(Box::new(native_source_spec(source))),
            )))
        }
        ArgKind::SourcePackage(manifest) => match target {
            None if cargo_family => Ok(None),
            None => Ok(Some((
                ArtifactFamily::Native,
                ArtifactRef::Build(Box::new(native_package_spec(PathBuf::from(raw), manifest))),
            ))),
            Some(target) => {
                let family = target_family(target)?;
                let spec = match family {
                    ArtifactFamily::Native => native_package_spec(PathBuf::from(raw), manifest),
                    ArtifactFamily::Wasm => wasi_package_spec(PathBuf::from(raw), manifest),
                };
                Ok(Some((family, ArtifactRef::Build(Box::new(spec)))))
            }
        },
        ArgKind::Other => {
            if target.is_some() {
                return Err(CliError::usage(format!(
                    "--target requires a source or package to build; {} is neither a .rs source, a directory, nor a Cargo.toml",
                    Path::new(raw).display()
                )));
            }
            Ok(None)
        }
    }
}

fn family_label(family: ArtifactFamily) -> &'static str {
    match family {
        ArtifactFamily::Wasm => "WebAssembly",
        ArtifactFamily::Native => "native",
    }
}

/// Route `run`: source-first with artifacts accepted uniformly. A built
/// artifact runs as-is (family from magic); a `.rs`/dir/`Cargo.toml` with
/// `--target` (or a lone `.rs`) builds on the fly then runs; a dir/`Cargo.toml`
/// with no `--target`, a leading flag, or no artifact is the Cargo package
/// family — the same machinery as `test`.
fn parse_run(arguments: Vec<OsString>) -> Result<ParseResult, CliError> {
    let (target, rest) = extract_target(arguments)?;
    let Some(first) = rest.first() else {
        if target.is_some() {
            return Err(CliError::usage(
                "--target requires a source or package to build; `run` with no artifact is the Cargo package family",
            ));
        }
        return parse_cargo("run".to_string(), rest);
    };
    match resolve_positional(first, target.as_deref(), true)? {
        Some((ArtifactFamily::Wasm, module)) => {
            parse_wasi_run_from(module, rest[1..].to_vec()).map(ParseResult::WasiRun)
        }
        Some((ArtifactFamily::Native, binary)) => {
            parse_native_run_from(binary, rest[1..].to_vec()).map(ParseResult::NativeRun)
        }
        // Cargo package family: forward the whole argument list (including the
        // positional dir/Cargo.toml, which Cargo interprets) to `parse_cargo`.
        None => parse_cargo("run".to_string(), rest),
    }
}

/// Route `audit`: source-first, artifacts accepted. A native binary (built or
/// built-on-the-fly) goes to the symbol audit; a WASI module lists its imports
/// (and takes no `--allow`, which is native-only). A dir/`Cargo.toml` with no
/// `--target` builds native (audit has no Cargo package family).
fn parse_audit(arguments: Vec<OsString>) -> Result<ParseResult, CliError> {
    let (target, rest) = extract_target(arguments)?;
    let Some(first) = rest.first() else {
        return Err(CliError::usage("audit requires an artifact or source path"));
    };
    let (family, artifact) = resolve_positional(first, target.as_deref(), false)?
        .ok_or_else(|| {
            CliError::usage(format!(
                "audit target {} is neither a WebAssembly module, a native binary, nor a source/package to build",
                Path::new(first).display()
            ))
        })?;
    let flags = rest[1..].to_vec();
    match family {
        ArtifactFamily::Native => {
            parse_native_audit_from(artifact, flags).map(ParseResult::NativeAudit)
        }
        ArtifactFamily::Wasm => {
            if flags.iter().any(|argument| argument == "--allow") {
                return Err(CliError::usage(
                    "audit of a WASI module takes no --allow (the allow list is native-only)",
                ));
            }
            if !flags.is_empty() {
                return Err(CliError::usage(
                    "audit of a WASI module takes only the module path",
                ));
            }
            Ok(ParseResult::WasiAudit(artifact))
        }
    }
}

/// Route `build`: extract `--target` (default `native`) and dispatch to the
/// native or WASI package builder. The rest of the argument vector is handed to
/// the per-target parser unchanged, so each target keeps its exact flag set.
fn parse_build(arguments: Vec<OsString>) -> Result<ParseResult, CliError> {
    let (target, rest) = extract_target(arguments)?;
    match target.as_deref().unwrap_or("native") {
        "native" => parse_native_build(rest).map(ParseResult::NativeBuild),
        "wasi" => parse_wasi_build(rest).map(ParseResult::WasiBuild),
        other => Err(CliError::usage(format!(
            "build --target must be native or wasi; got {other:?}"
        ))),
    }
}

/// Parse `build --target wasi <DIR|Cargo.toml> [--package NAME] [--bin NAME]
/// [--release] [--output PATH]`. WASI is package-only: a single `.rs` source is
/// native-only, and `--yield-points` is meaningless without threads.
fn parse_wasi_build(mut arguments: Vec<OsString>) -> Result<WasiBuildInvocation, CliError> {
    if arguments.is_empty() {
        return Err(CliError::usage(
            "build --target wasi requires a Cargo package (a directory or Cargo.toml)",
        ));
    }
    let package_path = PathBuf::from(arguments.remove(0));
    if package_path.extension().and_then(OsStr::to_str) == Some("rs") {
        return Err(CliError::usage(
            "build --target wasi compiles a Cargo package; a single .rs source is native-only",
        ));
    }
    let manifest = native_manifest_path(&package_path);
    let mut package = None;
    let mut bin = None;
    let mut release = false;
    let mut output = None;
    let mut index = 0;
    while index < arguments.len() {
        let option = arguments[index]
            .to_str()
            .ok_or_else(|| CliError::usage("build --target wasi options must be valid UTF-8"))?;
        match option {
            "--package" | "-p" => {
                index += 1;
                let value = utf8_argument(&arguments, index, "--package")?;
                set_once(&mut package, value.to_string(), "--package")?;
            }
            "--bin" => {
                index += 1;
                let value = utf8_argument(&arguments, index, "--bin")?;
                set_once(&mut bin, value.to_string(), "--bin")?;
            }
            "--release" => release = true,
            "--output" | "-o" => {
                index += 1;
                let value = arguments
                    .get(index)
                    .ok_or_else(|| CliError::usage("--output requires a path"))?;
                set_once(&mut output, PathBuf::from(value), "--output")?;
            }
            "--yield-points" => {
                return Err(CliError::usage(
                    "--yield-points has no effect with --target wasi: wasip1 has no threads to preempt",
                ));
            }
            _ => {
                return Err(CliError::usage(format!(
                    "unsupported build --target wasi option {option:?}"
                )));
            }
        }
        index += 1;
    }
    Ok(WasiBuildInvocation {
        manifest,
        package,
        bin,
        release,
        output,
    })
}

/// Parse the Cargo package family (`run`/`test` with no diverting artifact): the
/// seed/record machinery, seed-driven fault knobs, and typed `--param`s,
/// forwarding every unrecognized option to Cargo. Replaying a recording — strict
/// or branch-append — is the `replay` verb's job (see [`parse_cargo_replay`]), so
/// `run`/`test` carry no replay/branch/timeline flags.
fn parse_cargo(command: String, arguments: Vec<OsString>) -> Result<ParseResult, CliError> {
    let mut seed = None;
    let mut record = None;
    let mut step_budget = None;
    let mut params = BTreeMap::new();
    let mut faults = NativeFaults::default();
    let mut cargo_args = Vec::new();
    let mut index = 0;
    let mut passthrough = false;
    while index < arguments.len() {
        let argument = &arguments[index];
        if passthrough {
            cargo_args.push(argument.clone());
            index += 1;
            continue;
        }
        if argument == "--" {
            passthrough = true;
            cargo_args.push(argument.clone());
            index += 1;
            continue;
        }

        let text = argument.to_str();
        if matches!(text, Some("-h" | "--help")) {
            return Ok(ParseResult::Help);
        }
        if matches!(text, Some("-V" | "--version")) {
            return Ok(ParseResult::Version);
        }
        if let Some(value) = text.and_then(|value| value.strip_prefix("--seed=")) {
            set_once(&mut seed, parse_u64("--seed", value)?, "--seed")?;
        } else if text == Some("--seed") {
            index += 1;
            let value = arguments
                .get(index)
                .and_then(|value| value.to_str())
                .ok_or_else(|| CliError::usage("--seed requires a UTF-8 value"))?;
            set_once(&mut seed, parse_u64("--seed", value)?, "--seed")?;
        } else if let Some(value) = text.and_then(|value| value.strip_prefix("--record=")) {
            set_once(&mut record, PathBuf::from(value), "--record")?;
        } else if text == Some("--record") {
            index += 1;
            let value = arguments
                .get(index)
                .ok_or_else(|| CliError::usage("--record requires a path"))?;
            set_once(&mut record, PathBuf::from(value), "--record")?;
        } else if text == Some("--budget") {
            index += 1;
            let value = utf8_argument(&arguments, index, "--budget")?;
            set_once(&mut step_budget, parse_u64("--budget", value)?, "--budget")?;
        } else if text == Some("--param") {
            index += 1;
            let value = utf8_argument(&arguments, index, "--param")?;
            let (key, value) = value
                .split_once('=')
                .ok_or_else(|| CliError::usage("--param requires KEY=VALUE"))?;
            if key.is_empty() || params.insert(key.into(), value.into()).is_some() {
                return Err(CliError::usage("--param keys must be non-empty and unique"));
            }
        } else if text.is_some_and(|option| FAULT_FLAGS.contains(&option)) {
            let option = text.expect("checked Some above");
            index += 1;
            let value = utf8_argument(&arguments, index, option)?;
            apply_fault_flag(&mut faults, option, value)?;
        } else {
            cargo_args.push(argument.clone());
        }
        index += 1;
    }

    let seed = seed.unwrap_or(0);
    let mode = match record {
        Some(path) => Mode::Record { seed, path },
        None => Mode::Seeded { seed },
    };

    Ok(ParseResult::Run(Invocation {
        cargo_command: command,
        cargo_args,
        mode,
        step_budget,
        params,
        faults,
        working_dir: None,
    }))
}

/// Parse the cargo-family `replay <pkg> <trace>` verb. The `<pkg>` positional
/// (already resolved to its package directory) selects the workspace; the
/// `<trace>` positional replaces the old `--replay`/`--branch` PATH. Two shapes:
///
/// * strict replay — `replay <pkg> <trace> [--timeline ID]` — reproduces a
///   recorded timeline (default `main`);
/// * branch-append — `replay <pkg> <trace> --branch --from N --branch-seed S
///   --branch-id ID [--parent ID]` — replays the parent prefix then records a new
///   branch timeline (today's `--branch` semantics).
///
/// Cargo selectors (`-p NAME`, `--example NAME`, a `-- ARGS` tail, ...) that are
/// not replay controls are forwarded to Cargo verbatim and folded into the
/// compatibility fingerprint exactly as on the recording, so they must match the
/// recorded run (a mismatch fails closed on the fingerprint). Fault knobs are
/// never accepted here: the trace's recorded fault configuration is authoritative
/// and restored by the runtime, so replay is flag-free.
fn parse_cargo_replay(
    package_dir: PathBuf,
    trace: PathBuf,
    arguments: Vec<OsString>,
) -> Result<ParseResult, CliError> {
    let mut branch = false;
    let mut timeline = None;
    let mut branch_from = None;
    let mut branch_seed = None;
    let mut branch_id = None;
    let mut parent = None;
    let mut cargo_args = Vec::new();
    let mut index = 0;
    let mut passthrough = false;
    while index < arguments.len() {
        let argument = &arguments[index];
        if passthrough {
            cargo_args.push(argument.clone());
            index += 1;
            continue;
        }
        if argument == "--" {
            passthrough = true;
            cargo_args.push(argument.clone());
            index += 1;
            continue;
        }
        match argument.to_str() {
            Some("--branch") => branch = true,
            Some("--timeline") => {
                index += 1;
                let value = utf8_argument(&arguments, index, "--timeline")?;
                set_once(&mut timeline, value.to_string(), "--timeline")?;
            }
            Some("--from") => {
                index += 1;
                let value = utf8_argument(&arguments, index, "--from")?;
                set_once(&mut branch_from, parse_u64("--from", value)?, "--from")?;
            }
            Some("--branch-seed") => {
                index += 1;
                let value = utf8_argument(&arguments, index, "--branch-seed")?;
                set_once(
                    &mut branch_seed,
                    parse_u64("--branch-seed", value)?,
                    "--branch-seed",
                )?;
            }
            Some("--branch-id") => {
                index += 1;
                let value = utf8_argument(&arguments, index, "--branch-id")?;
                set_once(&mut branch_id, value.to_string(), "--branch-id")?;
            }
            Some("--parent") => {
                index += 1;
                let value = utf8_argument(&arguments, index, "--parent")?;
                set_once(&mut parent, value.to_string(), "--parent")?;
            }
            // Any other flag or value is a Cargo selector, forwarded verbatim so
            // it hashes into the fingerprint exactly as it did on the recording.
            _ => cargo_args.push(argument.clone()),
        }
        index += 1;
    }

    let mode = if branch {
        if timeline.is_some() {
            return Err(CliError::usage(
                "--timeline selects a timeline to replay and is not valid with --branch",
            ));
        }
        Mode::Branch {
            path: trace,
            parent: parent.unwrap_or_else(|| "main".into()),
            from_sequence: branch_from
                .ok_or_else(|| CliError::usage("replay --branch requires --from"))?,
            branch_seed: branch_seed
                .ok_or_else(|| CliError::usage("replay --branch requires --branch-seed"))?,
            branch_id: branch_id
                .ok_or_else(|| CliError::usage("replay --branch requires --branch-id"))?,
        }
    } else {
        if branch_from.is_some() || branch_seed.is_some() || branch_id.is_some() || parent.is_some()
        {
            return Err(CliError::usage(
                "--from/--branch-seed/--branch-id/--parent require --branch",
            ));
        }
        Mode::Replay {
            path: trace,
            timeline: timeline.unwrap_or_else(|| "main".into()),
        }
    };

    Ok(ParseResult::Run(Invocation {
        // A recording is produced by `run`; its fingerprint hashes the cargo
        // subcommand, so replaying reproduces the `run` program under the runtime.
        cargo_command: "run".to_string(),
        cargo_args,
        mode,
        step_budget: None,
        params: BTreeMap::new(),
        faults: NativeFaults::default(),
        working_dir: Some(package_dir),
    }))
}

/// Thin wrapper: treat the leading argument as an already-built module. Used by
/// unit tests; `run` routing calls [`parse_wasi_run_from`] with a resolved ref.
#[cfg(test)]
fn parse_wasi_run(mut arguments: Vec<OsString>) -> Result<WasiInvocation, CliError> {
    if arguments.is_empty() {
        return Err(CliError::usage(
            "run of a WASI module requires a .wasm path",
        ));
    }
    let module = ArtifactRef::Prebuilt(PathBuf::from(arguments.remove(0)));
    parse_wasi_run_from(module, arguments)
}

/// Parse the flags of a WASI `run` given an already-resolved module reference
/// The host-supplied inputs a WASI run/replay shares: fuel, guest argv, guest
/// environment, datagram sockets, preopens, and resource-limit overrides. These
/// are genuine host inputs (not recorded semantic state — except `--arg`, which
/// becomes the recorded guest argv), so both `run` and `replay` accept them and
/// they feed the WASI compatibility fingerprint.
#[derive(Default)]
struct WasiHostInputs {
    fuel: Option<u64>,
    arguments: Vec<String>,
    environment: BTreeMap<String, String>,
    sockets: Vec<WasiSocketConfig>,
    preopens: Vec<WasiPreopenConfig>,
    resource_limits: WasiResourceLimitOverrides,
    socket_fds: BTreeSet<u32>,
}

/// Apply one WASI host-input flag (`value` already fetched) to `inputs`,
/// returning `true` when `option` is a host-input flag and `false` otherwise.
/// Shared by [`parse_wasi_run_from`] and [`parse_wasi_replay`] so the two verbs
/// parse the guest environment identically.
fn apply_wasi_host_input(
    inputs: &mut WasiHostInputs,
    option: &str,
    value: &OsStr,
) -> Result<bool, CliError> {
    let utf8 = |name: &str| {
        value
            .to_str()
            .ok_or_else(|| CliError::usage(format!("{name} requires UTF-8")))
    };
    match option {
        "--fuel" => {
            let parsed = parse_u64("--fuel", utf8("--fuel")?)?;
            set_once(&mut inputs.fuel, parsed, "--fuel")?;
            set_once(&mut inputs.resource_limits.fuel, parsed, "--fuel")?;
        }
        "--arg" => inputs.arguments.push(utf8("--arg")?.into()),
        "--socket" => {
            let value = utf8("--socket")?;
            let (fd, route) = value
                .split_once('=')
                .ok_or_else(|| CliError::usage("--socket requires FD=BIND->PEER"))?;
            let fd = fd
                .parse::<u32>()
                .map_err(|_| CliError::usage("--socket FD must be an unsigned 32-bit integer"))?;
            let (bind, peer) = route
                .split_once("->")
                .ok_or_else(|| CliError::usage("--socket requires FD=BIND->PEER"))?;
            if fd <= 3 || bind.is_empty() || peer.is_empty() || !inputs.socket_fds.insert(fd) {
                return Err(CliError::usage(
                    "--socket requires a unique FD above 3 and non-empty addresses",
                ));
            }
            inputs.sockets.push(WasiSocketConfig {
                fd,
                bind: bind.into(),
                peer: peer.into(),
            });
        }
        "--env" => {
            let value = utf8("--env")?;
            let (key, value) = value
                .split_once('=')
                .ok_or_else(|| CliError::usage("--env requires KEY=VALUE"))?;
            if key.is_empty()
                || inputs
                    .environment
                    .insert(key.into(), value.into())
                    .is_some()
            {
                return Err(CliError::usage("--env keys must be non-empty and unique"));
            }
        }
        "--preopen" => inputs
            .preopens
            .push(parse_wasi_preopen(utf8("--preopen")?)?),
        "--max-memory-pages" => set_once(
            &mut inputs.resource_limits.max_memory_pages,
            parse_u32("--max-memory-pages", utf8("--max-memory-pages")?)?,
            "--max-memory-pages",
        )?,
        "--max-descriptors" => set_once(
            &mut inputs.resource_limits.max_descriptors,
            parse_usize("--max-descriptors", utf8("--max-descriptors")?)?,
            "--max-descriptors",
        )?,
        "--max-preopens" => set_once(
            &mut inputs.resource_limits.max_preopens,
            parse_usize("--max-preopens", utf8("--max-preopens")?)?,
            "--max-preopens",
        )?,
        "--max-path-bytes" => set_once(
            &mut inputs.resource_limits.max_path_bytes,
            parse_usize("--max-path-bytes", utf8("--max-path-bytes")?)?,
            "--max-path-bytes",
        )?,
        "--max-io-bytes" => set_once(
            &mut inputs.resource_limits.max_io_bytes,
            parse_usize("--max-io-bytes", utf8("--max-io-bytes")?)?,
            "--max-io-bytes",
        )?,
        "--max-iovecs" => set_once(
            &mut inputs.resource_limits.max_iovecs,
            parse_usize("--max-iovecs", utf8("--max-iovecs")?)?,
            "--max-iovecs",
        )?,
        _ => return Ok(false),
    }
    Ok(true)
}

/// Assemble a [`WasiInvocation`] from a parsed mode, the shared host inputs, and
/// the fault knobs. Shared tail of [`parse_wasi_run_from`] and
/// [`parse_wasi_replay`].
fn wasi_invocation_from(
    module: ArtifactRef,
    mode: Mode,
    inputs: WasiHostInputs,
    faults: NativeFaults,
    buggify: Option<NativeBuggify>,
    liveness: NativeLiveness,
) -> WasiInvocation {
    WasiInvocation {
        module,
        mode,
        fuel: inputs.fuel.unwrap_or(DEFAULT_WASM_FUEL),
        arguments: inputs.arguments,
        environment: inputs.environment,
        sockets: inputs.sockets,
        preopens: inputs.preopens,
        resource_limits: inputs.resource_limits,
        faults,
        buggify,
        liveness,
    }
}

/// (an existing `.wasm` or a build-on-the-fly spec). `run` produces a seeded or
/// `--record` run: replaying a recording is the `replay` verb's job, so the
/// replay/branch/timeline flags live there, not here. The seed-driven fault knobs
/// (including `--sleep-jitter-nanos`, now honored at the wasip1 host's sleep
/// entry) and the cooperative-SUT (buggify) knobs are accepted and recorded
/// exactly as on the native family.
fn parse_wasi_run_from(
    module: ArtifactRef,
    arguments: Vec<OsString>,
) -> Result<WasiInvocation, CliError> {
    let mut seed = None;
    let mut record = None;
    let mut faults = NativeFaults::default();
    let mut buggify: Option<NativeBuggify> = None;
    let mut liveness = NativeLiveness::default();
    let mut inputs = WasiHostInputs::default();
    let mut index = 0;
    while index < arguments.len() {
        let name = arguments[index]
            .to_str()
            .ok_or_else(|| CliError::usage("run options must be valid UTF-8"))?
            .to_string();
        index += 1;
        // Valueless cooperative-SUT flags consume no following argument, so they
        // are handled before the eager value fetch below (which requires one).
        match name.as_str() {
            "--liveness-watchdog" => {
                liveness.watchdog = Some(String::new());
                continue;
            }
            other if other.starts_with("--liveness-watchdog=") => {
                let nanos = &other["--liveness-watchdog=".len()..];
                parse_u64("--liveness-watchdog", nanos)?;
                liveness.watchdog = Some(nanos.to_string());
                continue;
            }
            "--converge-within" => {
                liveness.converge = Some(String::new());
                continue;
            }
            other if other.starts_with("--converge-within=") => {
                let nanos = &other["--converge-within=".len()..];
                parse_u64("--converge-within", nanos)?;
                liveness.converge = Some(nanos.to_string());
                continue;
            }
            other if other.starts_with("--heal-after=") => {
                let nanos = &other["--heal-after=".len()..];
                parse_u64("--heal-after", nanos)?;
                liveness.heal_after = Some(nanos.to_string());
                continue;
            }
            "--buggify" => {
                buggify.get_or_insert_with(NativeBuggify::default);
                continue;
            }
            "--buggify-after-setup" => {
                buggify
                    .get_or_insert_with(NativeBuggify::default)
                    .after_setup = true;
                continue;
            }
            other if other.starts_with("--buggify=") => {
                let permille = parse_u64("--buggify", &other["--buggify=".len()..])?;
                if permille > 1000 {
                    return Err(CliError::usage(
                        "--buggify permille must be within [0, 1000]",
                    ));
                }
                set_once(
                    &mut buggify
                        .get_or_insert_with(NativeBuggify::default)
                        .fire_permille,
                    permille.to_string(),
                    "--buggify",
                )?;
                continue;
            }
            _ => {}
        }
        let value = arguments
            .get(index)
            .ok_or_else(|| CliError::usage(format!("{name} requires a value")))?;
        match name.as_str() {
            "--seed" => set_once(
                &mut seed,
                parse_u64(
                    "--seed",
                    value
                        .to_str()
                        .ok_or_else(|| CliError::usage("--seed requires a UTF-8 value"))?,
                )?,
                "--seed",
            )?,
            "--record" => set_once(&mut record, PathBuf::from(value), "--record")?,
            "--buggify-activation-permille" => {
                let permille = parse_u64(
                    "--buggify-activation-permille",
                    value.to_str().ok_or_else(|| {
                        CliError::usage("--buggify-activation-permille requires UTF-8")
                    })?,
                )?;
                if permille > 1000 {
                    return Err(CliError::usage(
                        "--buggify-activation-permille must be within [0, 1000]",
                    ));
                }
                set_once(
                    &mut buggify
                        .get_or_insert_with(NativeBuggify::default)
                        .activation_permille,
                    permille.to_string(),
                    "--buggify-activation-permille",
                )?;
            }
            "--buggify-cutoff-nanos" => {
                let nanos = parse_u64(
                    "--buggify-cutoff-nanos",
                    value
                        .to_str()
                        .ok_or_else(|| CliError::usage("--buggify-cutoff-nanos requires UTF-8"))?,
                )?;
                set_once(
                    &mut buggify
                        .get_or_insert_with(NativeBuggify::default)
                        .cutoff_nanos,
                    nanos.to_string(),
                    "--buggify-cutoff-nanos",
                )?;
            }
            "--heal-after" => {
                let nanos = value
                    .to_str()
                    .ok_or_else(|| CliError::usage("--heal-after requires UTF-8"))?;
                parse_u64("--heal-after", nanos)?;
                liveness.heal_after = Some(nanos.to_string());
            }
            option if FAULT_FLAGS.contains(&option) => {
                let value = value
                    .to_str()
                    .ok_or_else(|| CliError::usage(format!("{option} requires UTF-8")))?;
                apply_fault_flag(&mut faults, option, value)?;
            }
            option => {
                if !apply_wasi_host_input(&mut inputs, option, value)? {
                    return Err(CliError::usage(format!(
                        "unsupported option {option:?} for `run` of a WASI module"
                    )));
                }
            }
        }
        index += 1;
    }
    let mode = match record {
        Some(path) => Mode::Record {
            seed: seed.unwrap_or(0),
            path,
        },
        None => Mode::Seeded {
            seed: seed.unwrap_or(0),
        },
    };
    Ok(wasi_invocation_from(
        module, mode, inputs, faults, buggify, liveness,
    ))
}

/// Parse the WASI `replay <MODULE.wasm> <TRACE>` verb given an already-resolved
/// module reference and trace path. Flag-free for semantics: the seed and fault
/// knobs are restored from the trace, and `--arg` values (the recorded guest
/// argv) are restored and conflict-checked at execution. Only genuine host inputs
/// stay as flags (`--fuel`/`--env`/`--socket`/`--preopen`/resource limits), plus
/// the timeline selector and branch controls that the WASI runtime supports:
///
/// * strict replay — `replay <mod.wasm> <trace> [--timeline ID]`;
/// * branch-append — `replay <mod.wasm> <trace> --branch --from N --branch-seed S
///   --branch-id ID [--parent ID]`.
fn parse_wasi_replay(
    module: ArtifactRef,
    trace: PathBuf,
    arguments: Vec<OsString>,
) -> Result<WasiInvocation, CliError> {
    let mut inputs = WasiHostInputs::default();
    let mut branch = false;
    let mut timeline = None;
    let mut branch_from = None;
    let mut branch_seed = None;
    let mut branch_id = None;
    let mut parent = None;
    let mut index = 0;
    while index < arguments.len() {
        let option = arguments[index]
            .to_str()
            .ok_or_else(|| CliError::usage("replay options must be valid UTF-8"))?
            .to_string();
        match option.as_str() {
            "--branch" => branch = true,
            "--timeline" => {
                index += 1;
                let value = utf8_argument(&arguments, index, "--timeline")?;
                set_once(&mut timeline, value.to_string(), "--timeline")?;
            }
            "--from" => {
                index += 1;
                let value = utf8_argument(&arguments, index, "--from")?;
                set_once(&mut branch_from, parse_u64("--from", value)?, "--from")?;
            }
            "--branch-seed" => {
                index += 1;
                let value = utf8_argument(&arguments, index, "--branch-seed")?;
                set_once(
                    &mut branch_seed,
                    parse_u64("--branch-seed", value)?,
                    "--branch-seed",
                )?;
            }
            "--branch-id" => {
                index += 1;
                let value = utf8_argument(&arguments, index, "--branch-id")?;
                set_once(&mut branch_id, value.to_string(), "--branch-id")?;
            }
            "--parent" => {
                index += 1;
                let value = utf8_argument(&arguments, index, "--parent")?;
                set_once(&mut parent, value.to_string(), "--parent")?;
            }
            // Semantic inputs are restored from the trace, never re-supplied. The
            // cooperative-SUT (buggify) configuration is likewise authoritative in
            // the trace metadata and reconciled by `Context::from_config`, so its
            // knobs are rejected here exactly as on the native replay path.
            other
                if other == "--seed"
                    || other == "--record"
                    || FAULT_FLAGS.contains(&other)
                    || other == "--buggify"
                    || other == "--buggify-after-setup"
                    || other == "--buggify-activation-permille"
                    || other == "--buggify-cutoff-nanos"
                    || other.starts_with("--buggify=") =>
            {
                return Err(CliError::usage(format!(
                    "replay restores run semantics from the trace and does not accept {other}; \
the trace is authoritative"
                )));
            }
            _ => {
                index += 1;
                let value = arguments
                    .get(index)
                    .ok_or_else(|| CliError::usage(format!("{option} requires a value")))?;
                if !apply_wasi_host_input(&mut inputs, &option, value)? {
                    return Err(CliError::usage(format!(
                        "unsupported option {option:?} for `replay` of a WASI module"
                    )));
                }
            }
        }
        index += 1;
    }
    let mode = if branch {
        if timeline.is_some() {
            return Err(CliError::usage(
                "--timeline selects a timeline to replay and is not valid with --branch",
            ));
        }
        Mode::Branch {
            path: trace,
            parent: parent.unwrap_or_else(|| "main".into()),
            from_sequence: branch_from
                .ok_or_else(|| CliError::usage("replay --branch requires --from"))?,
            branch_seed: branch_seed
                .ok_or_else(|| CliError::usage("replay --branch requires --branch-seed"))?,
            branch_id: branch_id
                .ok_or_else(|| CliError::usage("replay --branch requires --branch-id"))?,
        }
    } else {
        if branch_from.is_some() || branch_seed.is_some() || branch_id.is_some() || parent.is_some()
        {
            return Err(CliError::usage(
                "--from/--branch-seed/--branch-id/--parent require --branch",
            ));
        }
        Mode::Replay {
            path: trace,
            timeline: timeline.unwrap_or_else(|| "main".into()),
        }
    };
    Ok(wasi_invocation_from(
        module,
        mode,
        inputs,
        NativeFaults::default(),
        None,
        NativeLiveness::default(),
    ))
}

fn parse_explore(arguments: Vec<OsString>) -> Result<ExploreInvocation, CliError> {
    let mut forwarded = Vec::new();
    let mut seeds = None;
    let mut start = None;
    let mut index = 0;
    while index < arguments.len() {
        if arguments[index] == "--" {
            forwarded.extend(arguments[index..].iter().cloned());
            break;
        }
        let name = arguments[index].to_string_lossy();
        let (option, inline) = name
            .split_once('=')
            .map_or((name.as_ref(), None), |(name, value)| (name, Some(value)));
        if matches!(option, "--seeds" | "--start") {
            let value = if let Some(value) = inline {
                value
            } else {
                index += 1;
                arguments
                    .get(index)
                    .and_then(|value| value.to_str())
                    .ok_or_else(|| CliError::usage(format!("{option} requires a value")))?
            };
            let value = parse_u64(option, value)?;
            if option == "--seeds" {
                set_once(&mut seeds, value, option)?;
            } else {
                set_once(&mut start, value, option)?;
            }
        } else {
            forwarded.push(arguments[index].clone());
        }
        index += 1;
    }
    // `explore run <artifact|src>` sweeps the native or WASI families; `explore
    // run`/`test` with no diverting artifact stays the Cargo package family. Every
    // family must be in a plain seeded mode — record/replay/branch pin a single
    // run and have nothing to sweep.
    let (target, mode_seed) = match parse(forwarded)? {
        ParseResult::Run(invocation) => {
            let seed = explore_seed_of(&invocation.mode)?;
            (ExploreTarget::Cargo(invocation), seed)
        }
        ParseResult::WasiRun(invocation) => {
            let seed = explore_seed_of(&invocation.mode)?;
            (ExploreTarget::Wasi(invocation), seed)
        }
        ParseResult::NativeRun(invocation) => {
            let seed = explore_native_seed_of(&invocation.mode)?;
            (ExploreTarget::Native(invocation), seed)
        }
        _ => {
            return Err(CliError::usage(
                "explore requires a `run <artifact|source>`/`test` command",
            ));
        }
    };
    let seed_count = seeds.unwrap_or(100);
    if seed_count == 0 || seed_count > 1_000_000 {
        return Err(CliError::usage("--seeds must be between 1 and 1000000"));
    }
    let start_seed = start.unwrap_or(mode_seed);
    start_seed
        .checked_add(seed_count - 1)
        .ok_or_else(|| CliError::usage("exploration seed range overflows u64"))?;
    Ok(ExploreInvocation {
        target,
        start_seed,
        seed_count,
    })
}

/// The seed of a plain seeded [`Mode`], rejecting record/replay/branch which pin
/// a single run.
fn explore_seed_of(mode: &Mode) -> Result<u64, CliError> {
    match mode {
        Mode::Seeded { seed } => Ok(*seed),
        _ => Err(CliError::usage(
            "explore does not accept record, replay, or branch mode",
        )),
    }
}

/// The seed of a plain seeded [`NativeRunMode`], rejecting record/replay.
fn explore_native_seed_of(mode: &NativeRunMode) -> Result<u64, CliError> {
    match mode {
        NativeRunMode::Seeded { seed } => Ok(*seed),
        _ => Err(CliError::usage(
            "explore does not accept record or replay mode",
        )),
    }
}

/// Thin wrapper: treat the leading argument as an already-built binary. Used by
/// unit tests; `audit` routing calls [`parse_native_audit_from`].
#[cfg(test)]
fn parse_native_audit(mut arguments: Vec<OsString>) -> Result<NativeAuditInvocation, CliError> {
    if arguments.is_empty() {
        return Err(CliError::usage(
            "audit of a native binary requires a binary path",
        ));
    }
    let binary = ArtifactRef::Prebuilt(PathBuf::from(arguments.remove(0)));
    parse_native_audit_from(binary, arguments)
}

/// Parse the `--allow` flags of a native `audit` given an already-resolved
/// binary reference (an existing binary or a build-on-the-fly spec).
fn parse_native_audit_from(
    binary: ArtifactRef,
    arguments: Vec<OsString>,
) -> Result<NativeAuditInvocation, CliError> {
    let mut allow = BTreeSet::new();
    let mut index = 0;
    while index < arguments.len() {
        if arguments[index] != "--allow" {
            return Err(CliError::usage(format!(
                "unsupported option {:?} for `audit` of a native binary",
                arguments[index]
            )));
        }
        let symbol = arguments
            .get(index + 1)
            .and_then(|value| value.to_str())
            .ok_or_else(|| CliError::usage("--allow requires a UTF-8 symbol"))?;
        if symbol.is_empty() {
            return Err(CliError::usage("--allow symbol must not be empty"));
        }
        allow.insert(symbol.into());
        index += 2;
    }
    Ok(NativeAuditInvocation { binary, allow })
}

fn split_trailing_args(arguments: &mut Vec<OsString>) -> Vec<OsString> {
    match arguments.iter().position(|argument| argument == "--") {
        Some(index) => {
            let trailing = arguments.split_off(index + 1);
            arguments.pop();
            trailing
        }
        None => Vec::new(),
    }
}

fn parse_native_build(mut arguments: Vec<OsString>) -> Result<NativeBuildInvocation, CliError> {
    let rustc_args = split_trailing_args(&mut arguments);
    if arguments.is_empty() {
        return Err(CliError::usage(
            "build requires a Rust source path or a Cargo package",
        ));
    }
    let path = PathBuf::from(arguments.remove(0));
    let mut output = None;
    let mut edition = None;
    let mut release = false;
    let mut package = None;
    let mut bin = None;
    let mut yield_points = false;
    let mut index = 0;
    while index < arguments.len() {
        let option = arguments[index]
            .to_str()
            .ok_or_else(|| CliError::usage("build options must be valid UTF-8"))?;
        match option {
            "--output" | "-o" => {
                index += 1;
                let path = arguments
                    .get(index)
                    .ok_or_else(|| CliError::usage("--output requires a path"))?;
                set_once(&mut output, PathBuf::from(path), "--output")?;
            }
            "--edition" => {
                index += 1;
                let value = utf8_argument(&arguments, index, "--edition")?;
                set_once(&mut edition, value.to_string(), "--edition")?;
            }
            "--release" => {
                release = true;
            }
            "--yield-points" => {
                yield_points = true;
            }
            "--package" | "-p" => {
                index += 1;
                let value = utf8_argument(&arguments, index, "--package")?;
                set_once(&mut package, value.to_string(), "--package")?;
            }
            "--bin" => {
                index += 1;
                let value = utf8_argument(&arguments, index, "--bin")?;
                set_once(&mut bin, value.to_string(), "--bin")?;
            }
            _ => {
                return Err(CliError::usage(format!(
                    "unsupported build option {option:?}"
                )));
            }
        }
        index += 1;
    }

    if is_native_package_path(&path) {
        if let Some(rustc_arg) = rustc_args.first() {
            return Err(CliError::usage(format!(
                "trailing rustc options ({rustc_arg:?}) apply to a single-source build, not package builds"
            )));
        }
        if edition.is_some() {
            return Err(CliError::usage(
                "--edition applies to a single-source build; a package's edition comes from its Cargo.toml",
            ));
        }
        Ok(NativeBuildInvocation {
            target: NativeBuildTarget::Package {
                manifest: native_manifest_path(&path),
                package,
                bin,
            },
            output,
            release,
            yield_points,
        })
    } else {
        if package.is_some() || bin.is_some() {
            return Err(CliError::usage(
                "--package and --bin apply to a Cargo-package build, not a single source file",
            ));
        }
        let output = output.ok_or_else(|| CliError::usage("build requires --output <PATH>"))?;
        Ok(NativeBuildInvocation {
            target: NativeBuildTarget::Source {
                source: path,
                edition: edition.unwrap_or_else(|| DEFAULT_NATIVE_EDITION.to_string()),
                rustc_args,
            },
            output: Some(output),
            release,
            yield_points,
        })
    }
}

/// Classify a `native-build` path by shape (no filesystem access, so parsing
/// stays pure): a `.rs` file is a single source, and anything else — a
/// directory or a `Cargo.toml` — is a Cargo package. Existence is checked when
/// the build runs.
fn is_native_package_path(path: &Path) -> bool {
    if path.file_name() == Some(OsStr::new("Cargo.toml")) {
        return true;
    }
    path.extension().and_then(OsStr::to_str) != Some("rs")
}

/// Resolve a package path to its `Cargo.toml`: a manifest path is used as-is, a
/// directory gets `Cargo.toml` appended.
fn native_manifest_path(path: &Path) -> PathBuf {
    if path.file_name() == Some(OsStr::new("Cargo.toml")) {
        path.to_path_buf()
    } else {
        path.join("Cargo.toml")
    }
}

/// Validate a `--fs-crash-at` value (`close`, `close:1`, `write:3`, ...) so a
/// malformed knob is rejected before the guest is built and spawned. The runtime
/// re-parses the same grammar; this keeps the failure early and legible.
fn validate_crash_at(value: &str) -> Result<(), CliError> {
    let (op, ordinal) = value.split_once(':').unwrap_or((value, "1"));
    if !matches!(op, "open" | "write" | "sync" | "close") {
        return Err(CliError::usage(format!(
            "--fs-crash-at op must be open, write, sync, or close; got {op:?}"
        )));
    }
    match ordinal.parse::<u64>() {
        Ok(0) | Err(_) => Err(CliError::usage(format!(
            "--fs-crash-at ordinal must be a positive integer; got {value:?}"
        ))),
        Ok(_) => Ok(()),
    }
}

/// Validate an inclusive `MIN..MAX` nanosecond range flag.
fn validate_nanos_range(name: &str, value: &str) -> Result<(), CliError> {
    let (min, max) = value.split_once("..").ok_or_else(|| {
        CliError::usage(format!("{name} must be a MIN..MAX range; got {value:?}"))
    })?;
    let min = parse_u64(name, min)?;
    let max = parse_u64(name, max)?;
    if min > max {
        return Err(CliError::usage(format!(
            "{name} requires MIN <= MAX; got {value:?}"
        )));
    }
    Ok(())
}

/// The seed-driven fault-injection flags shared by every run family. Kept as a
/// single list so `run`/`test`/`replay` routing can detect a fault knob without
/// re-listing the names, and so a knob added here is offered everywhere at once.
const FAULT_FLAGS: &[&str] = &[
    "--fs-crash-at",
    "--fs-torn-granularity",
    "--sleep-jitter-nanos",
    "--net-jitter-nanos",
    "--net-drop-permille",
];

/// Validate and store a single fault-injection knob into `faults`. Returns `true`
/// when `option` is one of the [`FAULT_FLAGS`] (having consumed `value`), `false`
/// when it is not a fault flag at all. Shared by the WASI and cargo-family run
/// parsers so every family validates the fault protocol identically; the value is
/// stored verbatim so the runtime re-parses the exact same text on record and
/// replay.
fn apply_fault_flag(
    faults: &mut NativeFaults,
    option: &str,
    value: &str,
) -> Result<bool, CliError> {
    match option {
        "--fs-crash-at" => {
            validate_crash_at(value)?;
            set_once(&mut faults.fs_crash_at, value.to_string(), "--fs-crash-at")?;
        }
        "--fs-torn-granularity" => {
            if value != "block" && value != "byte" {
                return Err(CliError::usage(format!(
                    "--fs-torn-granularity must be block or byte; got {value:?}"
                )));
            }
            set_once(
                &mut faults.fs_torn_granularity,
                value.to_string(),
                "--fs-torn-granularity",
            )?;
        }
        "--sleep-jitter-nanos" => {
            validate_nanos_range("--sleep-jitter-nanos", value)?;
            set_once(
                &mut faults.sleep_jitter_nanos,
                value.to_string(),
                "--sleep-jitter-nanos",
            )?;
        }
        "--net-jitter-nanos" => {
            validate_nanos_range("--net-jitter-nanos", value)?;
            set_once(
                &mut faults.net_jitter_nanos,
                value.to_string(),
                "--net-jitter-nanos",
            )?;
        }
        "--net-drop-permille" => {
            let permille = parse_u64("--net-drop-permille", value)?;
            if permille > 1000 {
                return Err(CliError::usage(
                    "--net-drop-permille must be within [0, 1000]",
                ));
            }
            set_once(
                &mut faults.net_drop_permille,
                permille.to_string(),
                "--net-drop-permille",
            )?;
        }
        _ => return Ok(false),
    }
    Ok(true)
}

/// The `PATINA_*` control-plane variables carrying a [`NativeFaults`] to the
/// guest, paired with each set knob's raw value. Used by the WASI in-process
/// runtime (via [`RuntimeConfig::apply_fault_env`]) and by the cargo-family
/// subprocess (as real environment variables), so both apply the identical
/// protocol the native shim reads.
fn fault_env_pairs(faults: &NativeFaults) -> Vec<(&'static str, String)> {
    let mut pairs = Vec::new();
    if let Some(value) = &faults.fs_crash_at {
        pairs.push((ENV_FS_CRASH_AT, value.clone()));
    }
    if let Some(value) = &faults.fs_torn_granularity {
        pairs.push((ENV_FS_TORN_GRANULARITY, value.clone()));
    }
    if let Some(value) = &faults.sleep_jitter_nanos {
        pairs.push((ENV_SLEEP_JITTER, value.clone()));
    }
    if let Some(value) = &faults.net_jitter_nanos {
        pairs.push((ENV_NET_JITTER, value.clone()));
    }
    if let Some(value) = &faults.net_drop_permille {
        pairs.push((ENV_NET_DROP_PERMILLE, value.clone()));
    }
    pairs
}

/// The cooperative-SUT (buggify) control-plane pairs for the in-process WASI
/// runtime, mirroring the env vars the native family forwards to its subprocess.
/// Presence of `PATINA_BUGGIFY` (its value, possibly empty, being the firing
/// per-mille) enables buggify; the optional knobs follow.
fn buggify_env_pairs(buggify: &NativeBuggify) -> Vec<(&'static str, String)> {
    let mut pairs = vec![(
        ENV_BUGGIFY,
        buggify.fire_permille.clone().unwrap_or_default(),
    )];
    if let Some(value) = &buggify.activation_permille {
        pairs.push((ENV_BUGGIFY_ACTIVATION, value.clone()));
    }
    if let Some(value) = &buggify.cutoff_nanos {
        pairs.push((ENV_BUGGIFY_CUTOFF, value.clone()));
    }
    if buggify.after_setup {
        pairs.push((ENV_BUGGIFY_AFTER_SETUP, "1".to_string()));
    }
    pairs
}

/// The exploration scheduling-policy and swarm control-plane pairs. Presence of
/// `PATINA_SCHED_PCT` enables PCT (its value, possibly empty, being the bug
/// depth); `PATINA_SCHED_STARVE` enables starvation; `PATINA_SWARM` enables
/// swarm fault-class selection. Mirrors [`fault_env_pairs`] so the native family
/// forwards them to the subprocess and the WASI/Cargo families to the in-process
/// runtime through the same protocol.
fn schedule_env_pairs(schedule: &NativeSchedule) -> Vec<(&'static str, String)> {
    let mut pairs = Vec::new();
    if let Some(depth) = &schedule.pct {
        pairs.push((ENV_SCHED_PCT, depth.clone()));
        if let Some(steps) = &schedule.pct_steps {
            pairs.push((ENV_SCHED_PCT_STEPS, steps.clone()));
        }
    }
    if let Some(count) = &schedule.starve {
        pairs.push((ENV_SCHED_STARVE, count.clone()));
        if let Some(len) = &schedule.starve_max_len {
            pairs.push((ENV_SCHED_STARVE_MAX_LEN, len.clone()));
        }
        if let Some(window) = &schedule.starve_window {
            pairs.push((ENV_SCHED_STARVE_WINDOW, window.clone()));
        }
    }
    if schedule.swarm {
        pairs.push((ENV_SWARM, "1".to_string()));
    }
    pairs
}

/// The liveness-watchdog control-plane pairs, mirroring [`schedule_env_pairs`] so
/// the native family forwards them to the subprocess and the WASI/Cargo families
/// to the in-process runtime through the same `apply_liveness_env` protocol.
fn liveness_env_pairs(liveness: &NativeLiveness) -> Vec<(&'static str, String)> {
    let mut pairs = Vec::new();
    if let Some(budget) = &liveness.watchdog {
        pairs.push((ENV_LIVENESS_WATCHDOG, budget.clone()));
    }
    if let Some(budget) = &liveness.converge {
        pairs.push((ENV_CONVERGE_WITHIN, budget.clone()));
        if let Some(heal_after) = &liveness.heal_after {
            pairs.push((ENV_HEAL_AFTER, heal_after.clone()));
        }
    }
    pairs
}

/// Parse a single liveness-watchdog flag into `liveness`, returning `true` when
/// `option` was one (advancing `index` past any separate value). Shared by every
/// `run` family so `--liveness-watchdog`, `--converge-within`, and `--heal-after`
/// parse identically. A supplied budget is validated as an unsigned integer.
fn parse_liveness_flag(
    option: &str,
    arguments: &[OsString],
    index: &mut usize,
    liveness: &mut NativeLiveness,
) -> Result<bool, CliError> {
    match option {
        "--liveness-watchdog" => liveness.watchdog = Some(String::new()),
        value if value.starts_with("--liveness-watchdog=") => {
            let nanos = &value["--liveness-watchdog=".len()..];
            parse_u64("--liveness-watchdog", nanos)?;
            liveness.watchdog = Some(nanos.to_string());
        }
        "--converge-within" => liveness.converge = Some(String::new()),
        value if value.starts_with("--converge-within=") => {
            let nanos = &value["--converge-within=".len()..];
            parse_u64("--converge-within", nanos)?;
            liveness.converge = Some(nanos.to_string());
        }
        "--heal-after" => {
            *index += 1;
            let value = utf8_argument(arguments, *index, "--heal-after")?;
            parse_u64("--heal-after", value)?;
            liveness.heal_after = Some(value.to_string());
        }
        value if value.starts_with("--heal-after=") => {
            let nanos = &value["--heal-after=".len()..];
            parse_u64("--heal-after", nanos)?;
            liveness.heal_after = Some(nanos.to_string());
        }
        _ => return Ok(false),
    }
    Ok(true)
}

/// Thin wrapper: treat the leading argument as an already-built binary. Used by
/// unit tests; `run` routing calls [`parse_native_run_from`] with a resolved ref.
#[cfg(test)]
fn parse_native_run(mut arguments: Vec<OsString>) -> Result<NativeRunInvocation, CliError> {
    // The binary is the first token, ahead of any `--` guest-args separator.
    if arguments.is_empty() || arguments[0] == "--" {
        return Err(CliError::usage(
            "run of a native binary requires a binary path",
        ));
    }
    let binary = ArtifactRef::Prebuilt(PathBuf::from(arguments.remove(0)));
    parse_native_run_from(binary, arguments)
}

/// Parse the flags of a native `run` given an already-resolved binary reference
/// (an existing binary or a build-on-the-fly spec). A trailing `-- ARGS` section
/// is the guest argument vector.
fn parse_native_run_from(
    binary: ArtifactRef,
    mut arguments: Vec<OsString>,
) -> Result<NativeRunInvocation, CliError> {
    let program_args = split_trailing_args(&mut arguments);
    let mut seed = None;
    let mut record = None;
    let mut fingerprint = None;
    let mut net_latency_nanos = None;
    let mut faults = NativeFaults::default();
    let mut buggify: Option<NativeBuggify> = None;
    let mut schedule = NativeSchedule::default();
    let mut liveness = NativeLiveness::default();
    let mut allow = BTreeSet::new();
    let mut allow_unsupported: Option<UnsupportedPolicy> = None;
    let mut mount = None;
    let mut index = 0;
    while index < arguments.len() {
        let option = arguments[index]
            .to_str()
            .ok_or_else(|| CliError::usage("run options must be valid UTF-8"))?;
        match option {
            "--allow" => {
                index += 1;
                let symbol = utf8_argument(&arguments, index, "--allow")?;
                if symbol.is_empty() {
                    return Err(CliError::usage("--allow symbol must not be empty"));
                }
                allow.insert(symbol.to_string());
            }
            "--allow-unsupported-symbols" => {
                index += 1;
                let value = utf8_argument(&arguments, index, "--allow-unsupported-symbols")?;
                let policy = if value == "all" {
                    UnsupportedPolicy::All
                } else {
                    let symbols: BTreeSet<String> = value
                        .split(',')
                        .map(str::trim)
                        .filter(|part| !part.is_empty())
                        .map(str::to_owned)
                        .collect();
                    if symbols.is_empty() {
                        return Err(CliError::usage(
                            "--allow-unsupported-symbols requires `all` or a comma-separated symbol list",
                        ));
                    }
                    UnsupportedPolicy::Only(symbols)
                };
                set_once(
                    &mut allow_unsupported,
                    policy,
                    "--allow-unsupported-symbols",
                )?;
            }
            "--seed" => {
                index += 1;
                let value = utf8_argument(&arguments, index, "--seed")?;
                set_once(&mut seed, parse_u64("--seed", value)?, "--seed")?;
            }
            "--net-latency-nanos" => {
                index += 1;
                let value = utf8_argument(&arguments, index, "--net-latency-nanos")?;
                set_once(
                    &mut net_latency_nanos,
                    parse_u64("--net-latency-nanos", value)?,
                    "--net-latency-nanos",
                )?;
            }
            "--mount" => {
                index += 1;
                let path = arguments
                    .get(index)
                    .ok_or_else(|| CliError::usage("--mount requires a host directory path"))?;
                set_once(&mut mount, PathBuf::from(path), "--mount")?;
            }
            "--fs-crash-at" => {
                index += 1;
                let value = utf8_argument(&arguments, index, "--fs-crash-at")?;
                validate_crash_at(value)?;
                set_once(&mut faults.fs_crash_at, value.to_string(), "--fs-crash-at")?;
            }
            "--fs-torn-granularity" => {
                index += 1;
                let value = utf8_argument(&arguments, index, "--fs-torn-granularity")?;
                if value != "block" && value != "byte" {
                    return Err(CliError::usage(format!(
                        "--fs-torn-granularity must be block or byte; got {value:?}"
                    )));
                }
                set_once(
                    &mut faults.fs_torn_granularity,
                    value.to_string(),
                    "--fs-torn-granularity",
                )?;
            }
            "--sleep-jitter-nanos" => {
                index += 1;
                let value = utf8_argument(&arguments, index, "--sleep-jitter-nanos")?;
                validate_nanos_range("--sleep-jitter-nanos", value)?;
                set_once(
                    &mut faults.sleep_jitter_nanos,
                    value.to_string(),
                    "--sleep-jitter-nanos",
                )?;
            }
            "--net-jitter-nanos" => {
                index += 1;
                let value = utf8_argument(&arguments, index, "--net-jitter-nanos")?;
                validate_nanos_range("--net-jitter-nanos", value)?;
                set_once(
                    &mut faults.net_jitter_nanos,
                    value.to_string(),
                    "--net-jitter-nanos",
                )?;
            }
            "--net-drop-permille" => {
                index += 1;
                let value = utf8_argument(&arguments, index, "--net-drop-permille")?;
                let permille = parse_u64("--net-drop-permille", value)?;
                if permille > 1000 {
                    return Err(CliError::usage(
                        "--net-drop-permille must be within [0, 1000]",
                    ));
                }
                set_once(
                    &mut faults.net_drop_permille,
                    permille.to_string(),
                    "--net-drop-permille",
                )?;
            }
            "--buggify" => {
                buggify.get_or_insert_with(NativeBuggify::default);
            }
            value if value.starts_with("--buggify=") => {
                let permille = parse_u64("--buggify", &value["--buggify=".len()..])?;
                if permille > 1000 {
                    return Err(CliError::usage(
                        "--buggify permille must be within [0, 1000]",
                    ));
                }
                let entry = buggify.get_or_insert_with(NativeBuggify::default);
                set_once(&mut entry.fire_permille, permille.to_string(), "--buggify")?;
            }
            "--buggify-activation-permille" => {
                index += 1;
                let value = utf8_argument(&arguments, index, "--buggify-activation-permille")?;
                let permille = parse_u64("--buggify-activation-permille", value)?;
                if permille > 1000 {
                    return Err(CliError::usage(
                        "--buggify-activation-permille must be within [0, 1000]",
                    ));
                }
                let entry = buggify.get_or_insert_with(NativeBuggify::default);
                set_once(
                    &mut entry.activation_permille,
                    permille.to_string(),
                    "--buggify-activation-permille",
                )?;
            }
            "--buggify-cutoff-nanos" => {
                index += 1;
                let value = utf8_argument(&arguments, index, "--buggify-cutoff-nanos")?;
                let nanos = parse_u64("--buggify-cutoff-nanos", value)?;
                let entry = buggify.get_or_insert_with(NativeBuggify::default);
                set_once(
                    &mut entry.cutoff_nanos,
                    nanos.to_string(),
                    "--buggify-cutoff-nanos",
                )?;
            }
            "--buggify-after-setup" => {
                buggify
                    .get_or_insert_with(NativeBuggify::default)
                    .after_setup = true;
            }
            "--sched-pct" => {
                set_once(&mut schedule.pct, String::new(), "--sched-pct")?;
            }
            value if value.starts_with("--sched-pct=") => {
                let depth = &value["--sched-pct=".len()..];
                let parsed = parse_u64("--sched-pct", depth)?;
                if parsed < 1 {
                    return Err(CliError::usage("--sched-pct bug depth must be >= 1"));
                }
                set_once(&mut schedule.pct, parsed.to_string(), "--sched-pct")?;
            }
            "--sched-pct-steps" => {
                index += 1;
                let value = utf8_argument(&arguments, index, "--sched-pct-steps")?;
                let steps = parse_u64("--sched-pct-steps", value)?;
                if steps < 1 {
                    return Err(CliError::usage("--sched-pct-steps must be >= 1"));
                }
                set_once(
                    &mut schedule.pct_steps,
                    steps.to_string(),
                    "--sched-pct-steps",
                )?;
            }
            "--starve" => {
                set_once(&mut schedule.starve, String::new(), "--starve")?;
            }
            value if value.starts_with("--starve=") => {
                let count = &value["--starve=".len()..];
                let parsed = parse_u64("--starve", count)?;
                if parsed < 1 {
                    return Err(CliError::usage("--starve interval count must be >= 1"));
                }
                set_once(&mut schedule.starve, parsed.to_string(), "--starve")?;
            }
            "--starve-max-len" => {
                index += 1;
                let value = utf8_argument(&arguments, index, "--starve-max-len")?;
                let len = parse_u64("--starve-max-len", value)?;
                if len < 1 {
                    return Err(CliError::usage("--starve-max-len must be >= 1"));
                }
                set_once(
                    &mut schedule.starve_max_len,
                    len.to_string(),
                    "--starve-max-len",
                )?;
            }
            "--starve-window" => {
                index += 1;
                let value = utf8_argument(&arguments, index, "--starve-window")?;
                let window = parse_u64("--starve-window", value)?;
                if window < 1 {
                    return Err(CliError::usage("--starve-window must be >= 1"));
                }
                set_once(
                    &mut schedule.starve_window,
                    window.to_string(),
                    "--starve-window",
                )?;
            }
            "--swarm" => {
                schedule.swarm = true;
            }
            "--record" => {
                index += 1;
                let path = arguments
                    .get(index)
                    .ok_or_else(|| CliError::usage("--record requires a path"))?;
                set_once(&mut record, PathBuf::from(path), "--record")?;
            }
            "--fingerprint" => {
                index += 1;
                let value = utf8_argument(&arguments, index, "--fingerprint")?;
                set_once(&mut fingerprint, value.to_string(), "--fingerprint")?;
            }
            other => {
                if !parse_liveness_flag(other, &arguments, &mut index, &mut liveness)? {
                    return Err(CliError::usage(format!(
                        "unsupported option {option:?} for `run` of a native binary"
                    )));
                }
            }
        }
        index += 1;
    }
    // Dependent knobs are inert without their parent policy; reject rather than
    // silently ignore, so a mistyped sweep flag fails loudly.
    if schedule.pct.is_none() && (schedule.pct_steps.is_some()) {
        return Err(CliError::usage("--sched-pct-steps requires --sched-pct"));
    }
    if schedule.starve.is_none()
        && (schedule.starve_max_len.is_some() || schedule.starve_window.is_some())
    {
        return Err(CliError::usage(
            "--starve-max-len and --starve-window require --starve",
        ));
    }
    if liveness.converge.is_none() && liveness.heal_after.is_some() {
        return Err(CliError::usage("--heal-after requires --converge-within"));
    }
    let fingerprint = fingerprint.unwrap_or_else(|| DEFAULT_NATIVE_FINGERPRINT.to_string());
    let mode = if let Some(path) = record {
        NativeRunMode::Record {
            seed: seed.unwrap_or(0),
            path,
            fingerprint,
        }
    } else {
        NativeRunMode::Seeded {
            seed: seed.unwrap_or(0),
        }
    };
    Ok(NativeRunInvocation {
        binary,
        mode,
        program_args,
        net_latency_nanos,
        faults,
        buggify,
        schedule,
        liveness,
        allow,
        allow_unsupported: allow_unsupported.unwrap_or(UnsupportedPolicy::Deny),
        mount,
    })
}

/// Route `replay <ARTIFACT|SOURCE|PKG> <TRACE>` by the same artifact inference as
/// `run`: a WebAssembly module replays under WASI, a native binary under the
/// native supervisor, and a directory/`Cargo.toml` (no `--target`) under the
/// Cargo package family. Each restores its recorded semantic config from the
/// trace and exposes only that family's genuine host inputs. The two positionals
/// (artifact/source/package, then trace) always lead; per-family flags and any
/// `--` section follow and are handled by the family parser.
fn parse_replay(arguments: Vec<OsString>) -> Result<ParseResult, CliError> {
    // `replay` is source-first like `run`/`audit`: the artifact may be built or a
    // source/package built on the fly (honoring `--target`). A rebuilt binary is
    // judged against the trace by the fail-closed machinery (fingerprint +
    // operation-mismatch), so no special-casing.
    let (target, mut rest) = extract_target(arguments)?;
    if rest.is_empty() || rest[0] == "--" {
        return Err(CliError::usage(
            "replay requires an artifact/source/package path and a trace path",
        ));
    }
    let origin = rest.remove(0);
    if rest.is_empty() || rest[0] == "--" {
        return Err(CliError::usage("replay requires a trace path"));
    }
    let trace = PathBuf::from(rest.remove(0));
    let flags = rest;
    match resolve_positional(&origin, target.as_deref(), true)? {
        Some((ArtifactFamily::Wasm, module)) => {
            parse_wasi_replay(module, trace, flags).map(ParseResult::WasiRun)
        }
        Some((ArtifactFamily::Native, binary)) => {
            parse_native_replay(binary, trace, flags).map(ParseResult::NativeRun)
        }
        // No diverting artifact and no `--target`: the Cargo package family. The
        // origin must name a package (a directory or a `Cargo.toml`); its
        // directory selects the workspace for the replay.
        None => {
            let package_dir = cargo_package_dir(&origin)?;
            parse_cargo_replay(package_dir, trace, flags)
        }
    }
}

/// Resolve a cargo-family `replay` positional to its package directory. The
/// origin must be a directory or a `Cargo.toml` (the shapes `resolve_positional`
/// classifies as the Cargo package family); anything else is neither an artifact
/// nor a package and is rejected naming the offending path.
fn cargo_package_dir(origin: &OsStr) -> Result<PathBuf, CliError> {
    match classify_arg(origin)? {
        ArgKind::SourcePackage(manifest) => Ok(manifest
            .parent()
            .map(Path::to_path_buf)
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| PathBuf::from("."))),
        _ => Err(CliError::usage(format!(
            "replay target {} is neither a WASI module, a native binary, nor a Cargo package (a directory or Cargo.toml)",
            Path::new(origin).display()
        ))),
    }
}

/// Parse the native `replay <BINARY> <TRACE> [--fingerprint STR] [--mount
/// HOST_DIR] [--allow SYMBOL]... [--allow-unsupported-symbols <all|name,...>]
/// [-- GUEST ARGS]` given an already-resolved binary reference and trace path.
///
/// Native replay restores every semantic input from the trace itself — seed,
/// fault knobs, buggify, and the guest arguments — so it exposes NO semantic
/// flags (not `--seed`, not `--fs-*`, not `--buggify*`). The only flags are
/// host/build facts the trace cannot carry: `--fingerprint` (the compatibility
/// fingerprint), `--mount` (re-supply the host corpus whose hash the fingerprint
/// verifies), and `--allow`/`--allow-unsupported-symbols` (the machine-local
/// pre-run audit surface). An optional trailing `--` section is accepted only for
/// script compatibility and must match the recorded arguments byte-for-byte
/// (enforced downstream by `reconcile_replay_argv`); for a trace recorded before
/// argv capture the `--` section is used as-is. Native traces are single-timeline
/// and native runs cannot branch, so `--timeline`/`--branch` are not accepted.
fn parse_native_replay(
    binary: ArtifactRef,
    trace: PathBuf,
    mut arguments: Vec<OsString>,
) -> Result<NativeRunInvocation, CliError> {
    let program_args = split_trailing_args(&mut arguments);
    let mut fingerprint = None;
    let mut allow = BTreeSet::new();
    let mut allow_unsupported: Option<UnsupportedPolicy> = None;
    let mut mount = None;
    let mut index = 0;
    while index < arguments.len() {
        let option = arguments[index]
            .to_str()
            .ok_or_else(|| CliError::usage("replay options must be valid UTF-8"))?;
        match option {
            "--fingerprint" => {
                index += 1;
                let value = utf8_argument(&arguments, index, "--fingerprint")?;
                set_once(&mut fingerprint, value.to_string(), "--fingerprint")?;
            }
            // `--mount` re-supplies the host corpus, a host input the trace cannot
            // carry: only its hash is recorded (folded into the fingerprint, which
            // still rejects a wrong corpus). So, like `--fingerprint`, it is a
            // host/build input rather than a semantic knob restored from metadata.
            "--mount" => {
                index += 1;
                let path = arguments
                    .get(index)
                    .ok_or_else(|| CliError::usage("--mount requires a host directory path"))?;
                set_once(&mut mount, PathBuf::from(path), "--mount")?;
            }
            "--allow" => {
                index += 1;
                let symbol = utf8_argument(&arguments, index, "--allow")?;
                if symbol.is_empty() {
                    return Err(CliError::usage("--allow symbol must not be empty"));
                }
                allow.insert(symbol.to_string());
            }
            "--allow-unsupported-symbols" => {
                index += 1;
                let value = utf8_argument(&arguments, index, "--allow-unsupported-symbols")?;
                let policy = if value == "all" {
                    UnsupportedPolicy::All
                } else {
                    let symbols: BTreeSet<String> = value
                        .split(',')
                        .map(str::trim)
                        .filter(|part| !part.is_empty())
                        .map(str::to_owned)
                        .collect();
                    if symbols.is_empty() {
                        return Err(CliError::usage(
                            "--allow-unsupported-symbols requires `all` or a comma-separated symbol list",
                        ));
                    }
                    UnsupportedPolicy::Only(symbols)
                };
                set_once(
                    &mut allow_unsupported,
                    policy,
                    "--allow-unsupported-symbols",
                )?;
            }
            // Branch and timeline replay are the explicit-API (Cargo) and WASI
            // families' capability; native traces are single-timeline and a
            // native run cannot branch, so name the family that can.
            "--branch" | "--timeline" | "--from" | "--branch-seed" | "--branch-id" | "--parent" => {
                return Err(CliError::usage(format!(
                    "{option} is not supported for native replay: native traces are single-timeline \
and native runs cannot branch; branch/timeline replay is the Cargo package and WASI families"
                )));
            }
            // Semantic inputs are restored from the trace, never re-supplied.
            // Name the offending flag so the operator is not left guessing why a
            // knob was rejected; the trace is authoritative for all of these.
            "--seed"
            | "--record"
            | "--net-latency-nanos"
            | "--fs-crash-at"
            | "--fs-torn-granularity"
            | "--sleep-jitter-nanos"
            | "--net-jitter-nanos"
            | "--net-drop-permille"
            | "--buggify"
            | "--buggify-activation-permille"
            | "--buggify-cutoff-nanos"
            | "--buggify-after-setup"
            | "--sched-pct"
            | "--sched-pct-steps"
            | "--starve"
            | "--starve-max-len"
            | "--starve-window"
            | "--swarm" => {
                return Err(CliError::usage(format!(
                    "replay restores run semantics from the trace and does not accept {option}; \
the trace is authoritative"
                )));
            }
            other
                if other.starts_with("--buggify=")
                    || other.starts_with("--sched-pct=")
                    || other.starts_with("--starve=") =>
            {
                return Err(CliError::usage(
                    "replay restores run semantics from the trace and does not accept this flag; the \
trace is authoritative",
                ));
            }
            _ => {
                return Err(CliError::usage(format!(
                    "unsupported replay option {option:?}"
                )));
            }
        }
        index += 1;
    }
    let fingerprint = fingerprint.unwrap_or_else(|| DEFAULT_NATIVE_FINGERPRINT.to_string());
    Ok(NativeRunInvocation {
        binary,
        mode: NativeRunMode::Replay {
            path: trace,
            fingerprint,
        },
        program_args,
        net_latency_nanos: None,
        faults: NativeFaults::default(),
        buggify: None,
        // Replay restores the scheduling policy and swarm selection from the
        // trace metadata; the run path reconstructs the fingerprint suffix from
        // the trace (see `native_schedule_from_trace`), so nothing is supplied.
        schedule: NativeSchedule::default(),
        // Liveness is schedule-invariant and informational-only in the trace, so a
        // replay does not re-supply or reconcile it.
        liveness: NativeLiveness::default(),
        allow,
        allow_unsupported: allow_unsupported.unwrap_or(UnsupportedPolicy::Deny),
        mount,
    })
}

fn parse_minimize(mut arguments: Vec<OsString>) -> Result<MinimizeInvocation, CliError> {
    let delimiter = arguments
        .iter()
        .position(|argument| argument == "--")
        .ok_or_else(|| CliError::usage("minimize requires `-- <ORACLE> [ARGS]...`"))?;
    let oracle = arguments.split_off(delimiter + 1);
    arguments.pop();
    if oracle.is_empty() {
        return Err(CliError::usage(
            "minimize requires an oracle command after `--`",
        ));
    }
    if arguments.iter().any(|argument| argument == "--scenario") {
        parse_minimize_scenario(arguments, oracle).map(MinimizeInvocation::Scenario)
    } else {
        parse_minimize_trace(arguments, oracle).map(MinimizeInvocation::Trace)
    }
}

fn parse_minimize_trace(
    mut arguments: Vec<OsString>,
    oracle: Vec<OsString>,
) -> Result<TraceMinimize, CliError> {
    if arguments.is_empty() {
        return Err(CliError::usage("minimize requires a trace path"));
    }
    let trace = PathBuf::from(arguments.remove(0));
    let mut output = None;
    let mut timeline = None;
    let mut prune = false;
    let mut index = 0;
    while index < arguments.len() {
        let option = arguments[index]
            .to_str()
            .ok_or_else(|| CliError::usage("minimize options must be valid UTF-8"))?;
        match option {
            "--output" => {
                index += 1;
                let path = arguments
                    .get(index)
                    .ok_or_else(|| CliError::usage("--output requires a path"))?;
                set_once(&mut output, PathBuf::from(path), "--output")?;
            }
            "--timeline" => {
                index += 1;
                let value = utf8_argument(&arguments, index, "--timeline")?;
                set_once(&mut timeline, value.into(), "--timeline")?;
            }
            "--prune-branches" => {
                prune = true;
            }
            _ => {
                return Err(CliError::usage(format!(
                    "unsupported minimize option {option:?}"
                )));
            }
        }
        index += 1;
    }
    if prune && timeline.is_some() {
        return Err(CliError::usage(
            "--prune-branches operates on the whole branch forest and cannot be combined with --timeline",
        ));
    }
    let output = output.ok_or_else(|| CliError::usage("minimize requires --output <PATH>"))?;
    Ok(TraceMinimize {
        trace,
        output,
        timeline,
        prune,
        oracle,
    })
}

fn parse_minimize_scenario(
    arguments: Vec<OsString>,
    oracle: Vec<OsString>,
) -> Result<ScenarioMinimize, CliError> {
    let mut seed = None;
    let mut seed_budget = None;
    let mut params = BTreeMap::new();
    let mut index = 0;
    while index < arguments.len() {
        let option = arguments[index]
            .to_str()
            .ok_or_else(|| CliError::usage("minimize options must be valid UTF-8"))?;
        match option {
            "--scenario" => {}
            "--seed" => {
                index += 1;
                let value = utf8_argument(&arguments, index, "--seed")?;
                set_once(&mut seed, parse_u64("--seed", value)?, "--seed")?;
            }
            "--seed-budget" => {
                index += 1;
                let value = utf8_argument(&arguments, index, "--seed-budget")?;
                set_once(
                    &mut seed_budget,
                    parse_u64("--seed-budget", value)?,
                    "--seed-budget",
                )?;
            }
            "--param" => {
                index += 1;
                let value = utf8_argument(&arguments, index, "--param")?;
                let (key, param_value) = value
                    .split_once('=')
                    .ok_or_else(|| CliError::usage("--param requires KEY=VALUE"))?;
                if key.is_empty() || params.insert(key.into(), param_value.into()).is_some() {
                    return Err(CliError::usage("--param keys must be non-empty and unique"));
                }
            }
            "--output" | "--timeline" | "--prune-branches" => {
                return Err(CliError::usage(format!(
                    "minimize --scenario reduces experiment inputs and does not accept {option}"
                )));
            }
            _ => {
                return Err(CliError::usage(format!(
                    "unsupported minimize option {option:?}"
                )));
            }
        }
        index += 1;
    }
    let seed = seed.ok_or_else(|| CliError::usage("minimize --scenario requires --seed <U64>"))?;
    Ok(ScenarioMinimize {
        seed,
        params,
        seed_budget: seed_budget.unwrap_or(DEFAULT_SEED_BUDGET),
        oracle,
    })
}

fn utf8_argument<'a>(
    arguments: &'a [OsString],
    index: usize,
    name: &str,
) -> Result<&'a str, CliError> {
    arguments
        .get(index)
        .and_then(|value| value.to_str())
        .ok_or_else(|| CliError::usage(format!("{name} requires a UTF-8 value")))
}

fn set_once<T>(slot: &mut Option<T>, value: T, name: &str) -> Result<(), CliError> {
    if slot.replace(value).is_some() {
        return Err(CliError::usage(format!(
            "{name} was provided more than once"
        )));
    }
    Ok(())
}

fn parse_u64(name: &str, value: &str) -> Result<u64, CliError> {
    value
        .parse()
        .map_err(|_| CliError::usage(format!("{name} must be an unsigned 64-bit integer")))
}

fn parse_u32(name: &str, value: &str) -> Result<u32, CliError> {
    value
        .parse()
        .map_err(|_| CliError::usage(format!("{name} must be an unsigned 32-bit integer")))
}

fn parse_usize(name: &str, value: &str) -> Result<usize, CliError> {
    value
        .parse()
        .map_err(|_| CliError::usage(format!("{name} must be a non-negative integer")))
}

fn parse_wasi_preopen(value: &str) -> Result<WasiPreopenConfig, CliError> {
    let (guest_path, policy) = match value.rsplit_once(':') {
        Some((guest_path, "ro")) => (guest_path, MountPolicy::ReadOnly),
        Some((guest_path, "rw")) => (guest_path, MountPolicy::ReadWrite),
        Some(_) => {
            return Err(CliError::usage(
                "--preopen requires GUEST, GUEST:ro, or GUEST:rw",
            ));
        }
        None => (value, MountPolicy::ReadWrite),
    };
    if guest_path.is_empty() {
        return Err(CliError::usage("--preopen guest path must not be empty"));
    }
    Ok(WasiPreopenConfig {
        guest_path: normalize_cli_preopen_path(guest_path),
        policy,
    })
}

fn normalize_cli_preopen_path(path: &str) -> String {
    if !path.starts_with('/') || path.contains('\0') {
        return path.to_owned();
    }
    let mut components = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => return path.to_owned(),
            component => components.push(component),
        }
    }
    if components.is_empty() {
        "/".to_owned()
    } else {
        format!("/{}", components.join("/"))
    }
}

fn execute_wasi_run(invocation: WasiInvocation) -> Result<i32, CliError> {
    let mut invocation = invocation;
    let resolved = resolve_artifact(invocation.module.clone())?;
    let bytes = fs::read(&resolved.path).map_err(|error| {
        CliError(format!(
            "failed to read WebAssembly module {}: {error}",
            resolved.path.display()
        ))
    })?;
    // A replay/branch restores the recorded guest argv from the trace so the run
    // reproduces without the `--arg` values being re-passed. Any `--arg` the
    // operator did supply must match the recording byte-for-byte or the replay is
    // refused up front, naming both — the same authoritative-trace contract the
    // native family enforces. The restored argv is folded into the WASI
    // fingerprint below exactly as it was at record time. A pre-argv trace keeps
    // today's contract: the supplied `--arg` values are used as-is.
    if let Some(trace) = replay_trace_path(&invocation.mode) {
        invocation.arguments = reconcile_wasi_replay_argv(trace, &invocation.arguments)?;
    }
    // Buggify presence folds into the fingerprint exactly as `+buggify` does on
    // the native path, so a buggify trace and a plain trace of the same module are
    // never cross-replayable. On a flag-free replay the operator passes no
    // `--buggify`, so the trace metadata is authoritative — mirror the native
    // `trace_has_buggify` reconciliation so the recomputed fingerprint matches.
    let buggify_enabled = invocation.buggify.is_some()
        || replay_trace_path(&invocation.mode).is_some_and(trace_has_buggify);
    let fingerprint = wasi_compatibility_fingerprint(&bytes, &invocation, buggify_enabled);
    let mut config = match &invocation.mode {
        Mode::Seeded { seed } => RuntimeConfig::seeded(*seed),
        Mode::Record { seed, path } => RuntimeConfig::record(*seed, path.clone(), &fingerprint),
        Mode::Replay { path, timeline } => {
            RuntimeConfig::replay_timeline(path.clone(), timeline.clone(), &fingerprint)
        }
        Mode::Branch {
            path,
            parent,
            from_sequence,
            branch_seed,
            branch_id,
        } => RuntimeConfig::branch(
            path.clone(),
            parent.clone(),
            *from_sequence,
            branch_id.clone(),
            *branch_seed,
            &fingerprint,
        ),
    };
    // On a seeded or `--record` run the operator's fault knobs configure the
    // in-process drivers (and, on record, are captured into the trace metadata
    // via the runtime's record path). On replay/branch the config carries no
    // faults: the runtime restores the trace's authoritative fault configuration
    // during `Context::from_config`, so a flag-free replay rebuilds the same
    // CrashFs/SimNet the recording used.
    if matches!(invocation.mode, Mode::Seeded { .. } | Mode::Record { .. }) {
        let pairs = fault_env_pairs(&invocation.faults);
        config = config
            .apply_fault_env(|name| {
                pairs
                    .iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| value.clone())
            })
            .map_err(|error| CliError(error.to_string()))?;
        // Cooperative-SUT (buggify) knobs configure the same in-process runtime
        // through the shared `apply_buggify_env` accessor. On `--record` the
        // runtime captures the resulting `BuggifyConfigRecord` into the trace
        // metadata; on replay/branch the config carries no buggify and the runtime
        // restores it from the trace during `Context::from_config`, exactly as the
        // faults above — so a WASI buggify replay is flag-free.
        if let Some(buggify) = &invocation.buggify {
            let pairs = buggify_env_pairs(buggify);
            config = config
                .apply_buggify_env(|name| {
                    pairs
                        .iter()
                        .find(|(key, _)| *key == name)
                        .map(|(_, value)| value.clone())
                })
                .map_err(|error| CliError(error.to_string()))?;
        }
        // Liveness-watchdog knobs configure the same in-process runtime. The
        // watchdog is schedule-invariant, so on `--record` its config is recorded
        // (informational metadata) but not fingerprinted; a WASI guest that wedges
        // into a pure-sleep churn trips a deterministic PATINA_LIVENESS.
        if invocation.liveness.is_enabled() {
            let pairs = liveness_env_pairs(&invocation.liveness);
            config = config
                .apply_liveness_env(|name| {
                    pairs
                        .iter()
                        .find(|(key, _)| *key == name)
                        .map(|(_, value)| value.clone())
                })
                .map_err(|error| CliError(error.to_string()))?;
        }
    }
    // Record the guest argv (the `--arg` values) into the trace metadata so a
    // later `replay` restores them flag-free. Always recorded on `--record`, even
    // when empty, so a zero-argument run reproduces zero arguments rather than
    // inheriting whatever the replay command line supplies.
    if matches!(invocation.mode, Mode::Record { .. }) {
        config = config.with_guest_argv(Some(invocation.arguments.clone()));
    }
    let context = Context::from_config(config).map_err(|error| CliError(error.to_string()))?;
    let host = configured_wasi_host(&invocation, &resolved.display, context)?;
    let execution = execute_preview1_with_fuel(&bytes, host, invocation.fuel)
        .map_err(|error| CliError(error.to_string()))?;
    let (trace_path, seed, timeline) = match &invocation.mode {
        Mode::Seeded { seed } => (None, Some(*seed), "main".to_string()),
        Mode::Record { seed, path } => (Some(path.clone()), Some(*seed), "main".to_string()),
        Mode::Replay { path, timeline } => (Some(path.clone()), None, timeline.clone()),
        Mode::Branch {
            path, branch_id, ..
        } => (Some(path.clone()), None, branch_id.clone()),
    };
    let artifact = resolved.display.display().to_string();
    output::finalize_inprocess(
        output::RunReport {
            verb: "run",
            family: "wasi",
            artifact: &artifact,
            trace_path,
            timeline: &timeline,
            fingerprint: Some(fingerprint),
            seed,
        },
        execution.exit_code,
        execution.stdout,
        execution.stderr,
    )
}

/// The trace path a replay/branch mode reads its recorded guest argv from, or
/// `None` for a seeded/record run.
fn replay_trace_path(mode: &Mode) -> Option<&Path> {
    match mode {
        Mode::Replay { path, .. } | Mode::Branch { path, .. } => Some(path),
        Mode::Seeded { .. } | Mode::Record { .. } => None,
    }
}

/// Restore the recorded guest argv from a WASI trace, reconciling it with any
/// `--arg` values the operator also supplied on the replay. The trace is
/// authoritative: with no `--arg` the recorded argv is adopted verbatim; supplied
/// values must match the recording exactly or the replay is refused up front,
/// naming both. A trace recorded before argv capture (`guest_argv` absent) keeps
/// the historical contract — the supplied `--arg` values are used as-is.
fn reconcile_wasi_replay_argv(trace: &Path, supplied: &[String]) -> Result<Vec<String>, CliError> {
    let bundle = TraceBundle::load(trace)
        .map_err(|error| CliError(format!("failed to load trace {}: {error}", trace.display())))?;
    match bundle.metadata.guest_argv {
        Some(recorded) => {
            if !supplied.is_empty() && supplied != recorded.as_slice() {
                return Err(CliError(format!(
                    "replay --arg values {supplied:?} conflict with the trace's recorded guest \
arguments {recorded:?}; the trace is authoritative, so omit --arg (or supply matching values)"
                )));
            }
            Ok(recorded)
        }
        None => Ok(supplied.to_vec()),
    }
}

fn configured_wasi_host(
    invocation: &WasiInvocation,
    argv0: &Path,
    context: Context,
) -> Result<Preview1Host, CliError> {
    let mut host = Preview1Host::new(context)
        .with_resource_limits(invocation.resource_limits.to_host_limits())
        .with_argument(argv0.to_string_lossy().into_owned());
    for preopen in &invocation.preopens {
        host = host
            .with_preopen(&preopen.guest_path, preopen.policy)
            .map_err(|error| CliError(error.to_string()))?;
    }
    for argument in &invocation.arguments {
        host = host.with_argument(argument.clone());
    }
    for (key, value) in &invocation.environment {
        host = host.with_environment(key.clone(), value.clone());
    }
    for socket in &invocation.sockets {
        host = host
            .with_datagram_socket(socket.fd, &socket.bind, socket.peer.clone())
            .map_err(|error| CliError(error.to_string()))?;
    }
    Ok(host)
}

fn wasi_compatibility_fingerprint(
    bytes: &[u8],
    invocation: &WasiInvocation,
    buggify_enabled: bool,
) -> String {
    let mut hasher = Sha256::new();
    hash_bytes(&mut hasher, b"patina-wasi-execution-v1");
    hash_bytes(&mut hasher, env!("CARGO_PKG_VERSION").as_bytes());
    hash_bytes(&mut hasher, bytes);
    // Each section is domain-tagged and count-prefixed so fields cannot
    // migrate between sections (`--arg k --arg v` must not fingerprint like
    // `--env k=v`).
    hash_bytes(&mut hasher, b"wasi-arguments-v1");
    hash_bytes(
        &mut hasher,
        &(invocation.arguments.len() as u64).to_le_bytes(),
    );
    for argument in &invocation.arguments {
        hash_bytes(&mut hasher, argument.as_bytes());
    }
    hash_bytes(&mut hasher, b"wasi-environment-v1");
    hash_bytes(
        &mut hasher,
        &(invocation.environment.len() as u64).to_le_bytes(),
    );
    for (key, value) in &invocation.environment {
        hash_bytes(&mut hasher, key.as_bytes());
        hash_bytes(&mut hasher, value.as_bytes());
    }
    hash_bytes(&mut hasher, b"wasi-sockets-v1");
    hash_bytes(
        &mut hasher,
        &(invocation.sockets.len() as u64).to_le_bytes(),
    );
    for socket in &invocation.sockets {
        hash_bytes(&mut hasher, &socket.fd.to_le_bytes());
        hash_bytes(&mut hasher, socket.bind.as_bytes());
        hash_bytes(&mut hasher, socket.peer.as_bytes());
    }
    hash_wasi_preopens(&mut hasher, &invocation.preopens);
    hash_wasi_limit_overrides(&mut hasher, &invocation.resource_limits);
    // Buggify presence is folded in only when enabled, so a plain (non-buggify)
    // run fingerprints identically to before this component existed — mirroring
    // the native `+buggify` suffix, which is likewise appended only when on. The
    // specific knobs live in the trace metadata and are reconciled by the runtime;
    // the fingerprint carries only the boolean, which is all a flag-free replay
    // can recover from `trace_has_buggify`.
    if buggify_enabled {
        hash_bytes(&mut hasher, b"wasi-buggify-v1");
    }
    format!("sha256:{}", hex(&hasher.finalize()))
}

fn hash_wasi_preopens(hasher: &mut Sha256, preopens: &[WasiPreopenConfig]) {
    if preopens.is_empty() {
        return;
    }
    // Preopens are hashed in configuration order: descriptor numbers are
    // assigned in `with_preopen` call order, so a reordered preopen list is a
    // semantically different guest environment and must change the
    // fingerprint rather than fail later with a boundary-operation mismatch.
    hash_bytes(hasher, b"wasi-preopens-v1");
    hash_bytes(hasher, &(preopens.len() as u64).to_le_bytes());
    for preopen in preopens {
        hash_bytes(hasher, preopen.guest_path.as_bytes());
        hash_bytes(hasher, mount_policy_name(preopen.policy).as_bytes());
    }
}

fn hash_wasi_limit_overrides(hasher: &mut Sha256, limits: &WasiResourceLimitOverrides) {
    if limits == &WasiResourceLimitOverrides::default() {
        return;
    }
    hash_bytes(hasher, b"wasi-resource-limits-v1");
    if let Some(value) = limits.fuel {
        hash_bytes(hasher, b"fuel");
        hash_bytes(hasher, &value.to_le_bytes());
    }
    if let Some(value) = limits.max_memory_pages {
        hash_bytes(hasher, b"max-memory-pages");
        hash_bytes(hasher, &value.to_le_bytes());
    }
    if let Some(value) = limits.max_iovecs {
        hash_bytes(hasher, b"max-iovecs");
        hash_bytes(hasher, &(value as u64).to_le_bytes());
    }
    if let Some(value) = limits.max_io_bytes {
        hash_bytes(hasher, b"max-io-bytes");
        hash_bytes(hasher, &(value as u64).to_le_bytes());
    }
    if let Some(value) = limits.max_descriptors {
        hash_bytes(hasher, b"max-descriptors");
        hash_bytes(hasher, &(value as u64).to_le_bytes());
    }
    if let Some(value) = limits.max_preopens {
        hash_bytes(hasher, b"max-preopens");
        hash_bytes(hasher, &(value as u64).to_le_bytes());
    }
    if let Some(value) = limits.max_path_bytes {
        hash_bytes(hasher, b"max-path-bytes");
        hash_bytes(hasher, &(value as u64).to_le_bytes());
    }
}

fn mount_policy_name(policy: MountPolicy) -> &'static str {
    match policy {
        MountPolicy::ReadOnly => "ro",
        MountPolicy::ReadWrite => "rw",
    }
}

/// The `build --target wasi` verb: build the package and report the module path.
fn execute_wasi_build(invocation: WasiBuildInvocation) -> Result<i32, CliError> {
    let path = run_wasi_build(&invocation, None)?;
    if output::options().is_json() {
        output::emit_build("wasi", &path);
    } else {
        println!("PATINA_WASI_BUILD output={}", path.display());
    }
    Ok(0)
}

/// Build a Cargo package for `wasm32-wasip1` and return the produced `.wasm`.
/// Shared by the `build --target wasi` verb and build-on-the-fly. A `forced`
/// output (or the invocation's `output`) receives a copy of the module.
fn run_wasi_build(
    invocation: &WasiBuildInvocation,
    forced_output: Option<&Path>,
) -> Result<PathBuf, CliError> {
    if !invocation.manifest.is_file() {
        return Err(CliError(format!(
            "no Cargo manifest at {}",
            invocation.manifest.display()
        )));
    }
    let selected = select_native_package_bin(
        &invocation.manifest,
        invocation.package.as_deref(),
        invocation.bin.as_deref(),
    )?;
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let mut command = Command::new(&cargo);
    command
        .arg("build")
        .arg("--manifest-path")
        .arg(&invocation.manifest)
        .arg("--package")
        .arg(&selected.package)
        .arg("--bin")
        .arg(&selected.bin)
        .arg("--target")
        .arg(WASI_PREVIEW1_TARGET)
        .arg("--message-format=json-render-diagnostics")
        .env("RUSTFLAGS", patina_rustflags())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    if invocation.release {
        command.arg("--release");
    }
    let built = command
        .output()
        .map_err(|error| CliError(format!("failed to run WASI cargo build: {error}")))?;
    if !built.status.success() {
        return Err(CliError(format!(
            "building the WASI package {:?} failed",
            selected.bin
        )));
    }
    let module = native_build_executable(&built.stdout, &selected.bin)?;
    match forced_output.or(invocation.output.as_deref()) {
        Some(destination) => {
            fs::copy(&module, destination).map_err(|error| {
                CliError(format!(
                    "failed to copy built module {} to {}: {error}",
                    module.display(),
                    destination.display()
                ))
            })?;
            Ok(destination.to_path_buf())
        }
        None => Ok(module),
    }
}

fn execute_wasi_audit(artifact: ArtifactRef) -> Result<i32, CliError> {
    let resolved = resolve_artifact(artifact)?;
    let bytes = fs::read(&resolved.path).map_err(|error| {
        CliError(format!(
            "failed to read WebAssembly module {}: {error}",
            resolved.path.display()
        ))
    })?;
    let audit = WasiAudit::audit(&bytes).map_err(|error| CliError(error.to_string()))?;
    let findings: Vec<String> = audit
        .imports
        .iter()
        .map(|import| format!("{}::{}", import.module, import.name))
        .collect();
    if output::options().is_json() {
        output::emit_audit(
            "audit",
            "wasi",
            &resolved.display.display().to_string(),
            findings,
            0,
        );
    } else {
        for finding in &findings {
            println!("{finding}");
        }
    }
    Ok(0)
}

/// A resolved run/audit/replay artifact: the concrete path to consume, a display
/// path (the source argument when built on the fly, so a WASI guest's `argv[0]`
/// and diagnostics name the source rather than a throwaway temp path), and an
/// optional workspace that must outlive its use.
struct ResolvedArtifact {
    path: PathBuf,
    display: PathBuf,
    _workspace: Option<tempfile::TempDir>,
}

/// The single shared resolution step: an already-built artifact is used
/// directly; a source/package is built on the fly through the shared build
/// pipeline (printing a one-line identity note) and its product used.
fn resolve_artifact(artifact: ArtifactRef) -> Result<ResolvedArtifact, CliError> {
    match artifact {
        ArtifactRef::Prebuilt(path) => Ok(ResolvedArtifact {
            display: path.clone(),
            path,
            _workspace: None,
        }),
        ArtifactRef::Build(spec) => build_on_the_fly(*spec),
    }
}

/// Build a source/package on the fly and return its artifact. Prints a one-line
/// identity note (`PATINA_BUILD_ON_RUN`) naming the source, the built artifact,
/// and its content hash, so an implicit rebuild never silently changes what ran.
fn build_on_the_fly(spec: BuildSpec) -> Result<ResolvedArtifact, CliError> {
    let workspace = tempfile::tempdir()
        .map_err(|error| CliError(format!("failed to create build workspace: {error}")))?;
    let (path, target_label) = match spec.kind {
        BuildSpecKind::Native(mut invocation) => {
            invocation.output = Some(workspace.path().join("patina-run-artifact"));
            (run_native_build(invocation)?, "native")
        }
        BuildSpecKind::Wasi(invocation) => {
            let output = workspace.path().join("patina-run-artifact.wasm");
            (run_wasi_build(&invocation, Some(&output))?, "wasi")
        }
    };
    let bytes = fs::read(&path).map_err(|error| {
        CliError(format!(
            "failed to read the built artifact {}: {error}",
            path.display()
        ))
    })?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    // Route this on-the-fly build note to stderr under `--output json` so stdout
    // stays a single clean JSON envelope; human output keeps it on stdout.
    let build_note = format!(
        "PATINA_BUILD_ON_RUN target={target_label} source={} artifact={} sha256={}",
        spec.origin.display(),
        path.display(),
        hex(&hasher.finalize())
    );
    if output::options().is_json() {
        eprintln!("{build_note}");
    } else {
        println!("{build_note}");
    }
    Ok(ResolvedArtifact {
        path,
        display: spec.origin,
        _workspace: Some(workspace),
    })
}

fn execute_explore(exploration: ExploreInvocation) -> Result<i32, CliError> {
    // Explore drives many child runs and reports once, so per-seed run
    // finalization (capture/envelope/render) is suppressed here: each child
    // streams normally and this verb emits a single campaign-level envelope.
    output::suppress_run_finalize();
    let start = exploration.start_seed;
    let count = exploration.seed_count;
    // The native and WASI families build the artifact once, then run that SAME
    // built artifact across every seed — a source/package is never rebuilt per
    // seed. The resolved artifact (and its build workspace) is held for the whole
    // sweep so the built file outlives every run. The Cargo family instead re-runs
    // the whole command per seed (cargo caches the build).
    let prebuilt = match &exploration.target {
        ExploreTarget::Cargo(_) => None,
        ExploreTarget::Wasi(invocation) => Some(resolve_artifact(invocation.module.clone())?),
        ExploreTarget::Native(invocation) => Some(resolve_artifact(invocation.binary.clone())?),
    };
    let seed_at = |offset: u64| {
        start
            .checked_add(offset)
            .expect("exploration range was validated")
    };
    for offset in 0..count {
        let seed = seed_at(offset);
        let exit = match &exploration.target {
            ExploreTarget::Cargo(invocation) => {
                let mut invocation = invocation.clone();
                invocation.mode = Mode::Seeded { seed };
                execute(invocation)?
            }
            ExploreTarget::Wasi(invocation) => {
                let mut invocation = invocation.clone();
                invocation.module = ArtifactRef::Prebuilt(
                    prebuilt
                        .as_ref()
                        .expect("wasi explore resolved")
                        .path
                        .clone(),
                );
                invocation.mode = Mode::Seeded { seed };
                execute_wasi_run(invocation)?
            }
            ExploreTarget::Native(invocation) => {
                let mut invocation = invocation.clone();
                invocation.binary = ArtifactRef::Prebuilt(
                    prebuilt
                        .as_ref()
                        .expect("native explore resolved")
                        .path
                        .clone(),
                );
                invocation.mode = NativeRunMode::Seeded { seed };
                execute_native_run(invocation)?
            }
        };
        if exit != 0 {
            eprintln!("PATINA_EXPLORE_FAILURE seed={seed} exit={exit}");
            output::emit_simple(
                "explore",
                "failure",
                exit,
                Some(format!("seed {seed} exited {exit}")),
            );
            return Ok(exit);
        }
    }
    if output::options().is_json() {
        output::emit_simple(
            "explore",
            "ok",
            0,
            Some(format!("start={start} seeds={count}")),
        );
    } else {
        println!("PATINA_EXPLORE_COMPLETE start={start} seeds={count}");
    }
    Ok(0)
}

fn execute_native_audit(invocation: NativeAuditInvocation) -> Result<i32, CliError> {
    let resolved = resolve_artifact(invocation.binary)?;
    let bytes = fs::read(&resolved.path).map_err(|error| {
        CliError(format!(
            "failed to read native binary {}: {error}",
            resolved.path.display()
        ))
    })?;
    let audit = NativeAudit::audit(&bytes, &invocation.allow)
        .map_err(|error| CliError(error.to_string()))?;
    let findings: Vec<String> = audit.imports.iter().map(ToString::to_string).collect();
    if output::options().is_json() {
        output::emit_audit(
            "audit",
            "native",
            &resolved.path.display().to_string(),
            findings,
            0,
        );
    } else {
        for finding in &findings {
            println!("{finding}");
        }
    }
    Ok(0)
}

fn link_arg(path: &Path) -> OsString {
    let mut arg = OsString::from("link-arg=");
    arg.push(path);
    arg
}

/// Build the `patina-dst-native-shim` staticlib and return its path. The shim's
/// Rust boundary is produced by Cargo; the C POSIX layer and header are packaged
/// into this binary and compiled at link time by [`execute_native_build`].
fn build_native_shim(release: bool) -> Result<PathBuf, CliError> {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let mut command = Command::new(&cargo);
    command.arg("build").arg("-p").arg("patina-dst-native-shim");
    if release {
        command.arg("--release");
    }
    let status = command
        .status()
        .map_err(|error| CliError(format!("failed to build patina-dst-native-shim: {error}")))?;
    if !status.success() {
        return Err(CliError(
            "building the patina-dst-native-shim staticlib failed".into(),
        ));
    }
    let target_dir = match env::var_os("CARGO_TARGET_DIR") {
        Some(dir) => PathBuf::from(dir),
        None => workspace_root(&[])?.join("target"),
    };
    let profile = if release { "release" } else { "debug" };
    let staticlib = target_dir.join(profile).join(NATIVE_SHIM_STATICLIB);
    if !staticlib.exists() {
        return Err(CliError(format!(
            "expected the shim staticlib at {} after building it",
            staticlib.display()
        )));
    }
    Ok(staticlib)
}

/// The `build` (native) verb: build and report the artifact path.
fn execute_native_build(invocation: NativeBuildInvocation) -> Result<i32, CliError> {
    let path = run_native_build(invocation)?;
    if output::options().is_json() {
        output::emit_build("native", &path);
    } else {
        println!("PATINA_NATIVE_BUILD output={}", path.display());
    }
    Ok(0)
}

/// Run the native build pipeline and return the produced artifact path. Shared
/// by the `build` verb and build-on-the-fly (`run`/`audit`/`replay` of a
/// source): both go through exactly this code.
fn run_native_build(invocation: NativeBuildInvocation) -> Result<PathBuf, CliError> {
    let staticlib = build_native_shim(invocation.release)?;

    // Materialize the embedded POSIX shim layer and compile it below the user
    // program, matching the flags the deterministic linked target requires. The
    // workspace outlives both build paths so the object stays valid for linking.
    let workdir = tempfile::tempdir()
        .map_err(|error| CliError(format!("failed to create native build workspace: {error}")))?;
    let object = compile_posix_object(workdir.path())?;
    // The yield-point hook object is compiled and linked only under
    // `--yield-points`; a plain build never references SanitizerCoverage symbols.
    let yield_object = if invocation.yield_points {
        // Surface the instrumentation prominently: this binary is not a plain
        // build — it carries LLVM SanitizerCoverage yield points wired to the
        // deterministic scheduler, and `native-run` will schedule it under a
        // distinct (denser) policy recorded in its fingerprint.
        let yield_note = format!(
            "PATINA_NATIVE_BUILD_YIELD_POINTS instrumentation=llvm-sancov-trace-pc-guard \
scheduler-hook=patina_sched_yield fingerprint-suffix={PATINA_YIELD_FINGERPRINT_SUFFIX}"
        );
        if output::options().is_json() {
            eprintln!("{yield_note}");
        } else {
            println!("{yield_note}");
        }
        Some(compile_yield_object(workdir.path())?)
    } else {
        None
    };

    match invocation.target {
        NativeBuildTarget::Source {
            source,
            edition,
            rustc_args,
        } => build_native_source(
            &source,
            invocation
                .output
                .as_deref()
                .expect("single-source native-build requires --output"),
            &edition,
            &object,
            &staticlib,
            yield_object.as_deref(),
            &rustc_args,
        ),
        NativeBuildTarget::Package {
            manifest,
            package,
            bin,
        } => build_native_package(
            &manifest,
            package.as_deref(),
            bin.as_deref(),
            invocation.output.as_deref(),
            invocation.release,
            &object,
            &staticlib,
            yield_object.as_deref(),
        ),
    }
}

/// Stage and compile the `--yield-points` hook object. Compiled without the
/// SanitizerCoverage flags themselves, so the hook (and thus `patina_sched_yield`
/// it calls) is never itself instrumented and cannot recurse.
fn compile_yield_object(workdir: &Path) -> Result<PathBuf, CliError> {
    let c_source = workdir.join("patina_yield.c");
    fs::write(&c_source, PATINA_YIELD_C)
        .map_err(|error| CliError(format!("failed to stage the yield-point hook: {error}")))?;
    let object = workdir.join("patina_yield.o");
    let cc = env::var_os("CC").unwrap_or_else(|| OsString::from("cc"));
    let cc_status = Command::new(&cc)
        .args([
            "-std=c11",
            "-fno-stack-protector",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-c",
        ])
        .arg(&c_source)
        .arg("-o")
        .arg(&object)
        .status()
        .map_err(|error| CliError(format!("failed to run C compiler {cc:?}: {error}")))?;
    if !cc_status.success() {
        return Err(CliError(
            "compiling the Patina yield-point hook failed".into(),
        ));
    }
    Ok(object)
}

/// The rustc flags that turn on LLVM SanitizerCoverage trace-pc-guard
/// instrumentation at basic-block granularity (level 3 reaches loop backedges),
/// so `__sanitizer_cov_trace_pc_guard` — routed to `patina_sched_yield` by the
/// linked hook — fires inside hot loops, not only at function entry. `-Cpasses`
/// and `-Cllvm-args` are stable rustc codegen flags, so this needs no nightly
/// toolchain and no `RUSTC_BOOTSTRAP`. The only version coupling is to LLVM's
/// internal pass name (`sancov-module`) and coverage cl::opts, which are stable
/// across the LLVM releases rustc ships but are not a rustc stability guarantee.
fn sancov_rustc_flags() -> [&'static str; 6] {
    [
        "-C",
        "passes=sancov-module",
        "-C",
        "llvm-args=-sanitizer-coverage-level=3",
        "-C",
        "llvm-args=-sanitizer-coverage-trace-pc-guard",
    ]
}

/// Stage the embedded POSIX shim C layer in `workdir` and compile it to an
/// object below the user program. Shared by the single-source and package build
/// paths.
fn compile_posix_object(workdir: &Path) -> Result<PathBuf, CliError> {
    fs::write(workdir.join("patina_native.h"), PATINA_NATIVE_H)
        .map_err(|error| CliError(format!("failed to stage the shim header: {error}")))?;
    let c_source = workdir.join("patina_posix.c");
    fs::write(&c_source, PATINA_POSIX_C)
        .map_err(|error| CliError(format!("failed to stage the shim C layer: {error}")))?;
    let object = workdir.join("patina_posix.o");
    let cc = env::var_os("CC").unwrap_or_else(|| OsString::from("cc"));
    let cc_status = Command::new(&cc)
        .args([
            "-std=c11",
            "-D_POSIX_C_SOURCE=200809L",
            "-fno-stack-protector",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-c",
        ])
        .arg("-I")
        .arg(workdir)
        .arg(&c_source)
        .arg("-o")
        .arg(&object)
        .status()
        .map_err(|error| CliError(format!("failed to run C compiler {cc:?}: {error}")))?;
    if !cc_status.success() {
        return Err(CliError(
            "compiling the Patina POSIX shim layer failed".into(),
        ));
    }
    Ok(object)
}

/// Add the platform-specific shim link arguments a native binary needs to
/// `configure`. On Linux the shim interposes thread creation with a plain strong
/// `pthread_create` def and reaches the real glibc creator through its host-alias
/// table (`dlsym(RTLD_NEXT, ...)`), so no link-time wrap is needed — and none is
/// used: gcc ships its own `__wrap_pthread_create` in libgcc's x86 split-stack
/// support, so `-Wl,--wrap=pthread_create` would `multiple definition`-clash at
/// link. macOS uses `pthread_create_suspended_np`. The shim objects also land
/// after the toolchain's own `-lc`, and glibc's `atexit` lives in
/// `libc_nonshared.a` (reached through the `libc.so` linker script); GNU ld scans
/// archives in a single pass, so libc must be scanned again after the shim
/// objects introduce their references.
fn push_platform_link_args(mut configure: impl FnMut(&str)) {
    #[cfg(target_os = "linux")]
    {
        // Wrap `dlsym` so the shim's host-alias table can reach the real glibc
        // resolver through `__real_dlsym` while guest/std references to `dlsym`
        // still bind to the shim's neutering `__wrap_dlsym` interposer. This is
        // the Linux half of the host-alias doctrine: `dlsym(RTLD_NEXT, ...)`
        // resolves the trace-fd I/O, baton-semaphore, and host-thread-creation
        // vehicles at runtime, so `__read`/`__write`/`sem_*`/`pthread_create` no
        // longer appear in the guest import table.
        configure("link-arg=-Wl,--wrap=dlsym");
        configure("link-arg=-lc");
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = &mut configure;
    }
}

/// Compile a single Rust source, injecting cfg(patina)/cfg(dst) and linking the
/// POSIX object and shim staticlib below it. Built native for the host, so the
/// host OS selects the link recipe.
fn build_native_source(
    source: &Path,
    output: &Path,
    edition: &str,
    object: &Path,
    staticlib: &Path,
    yield_object: Option<&Path>,
    rustc_args: &[OsString],
) -> Result<PathBuf, CliError> {
    let rustc = env::var_os("RUSTC").unwrap_or_else(|| OsString::from("rustc"));
    let mut command = Command::new(&rustc);
    command
        .arg("--edition")
        .arg(edition)
        // `patina_shim` marks a shim-linked build: the `patina` crate's SDK
        // resolves its buggify FFI only under this cfg, so a plain/WASI/`run`
        // build (which also sets `patina`/`dst`) never references the shim
        // symbols and never fails to link.
        .args(["--cfg", "patina", "--cfg", "dst", "--cfg", "patina_shim"])
        .arg("-C")
        .arg(link_arg(object))
        .arg("-C")
        .arg(link_arg(staticlib));
    if let Some(yield_object) = yield_object {
        // SanitizerCoverage is driven entirely through stable `-C` codegen flags
        // (no `RUSTC_BOOTSTRAP`); the hook object below resolves the emitted
        // callbacks.
        command
            .args(sancov_rustc_flags())
            .arg("-C")
            .arg(link_arg(yield_object));
    }
    push_platform_link_args(|arg| {
        command.arg("-C").arg(arg);
    });
    command.arg(source).arg("-o").arg(output).args(rustc_args);
    let status = command
        .status()
        .map_err(|error| CliError(format!("failed to run rustc {rustc:?}: {error}")))?;
    if !status.success() {
        return Err(CliError("linking the native Patina program failed".into()));
    }
    Ok(output.to_path_buf())
}

/// Drive a Cargo package's own `cargo build` under Patina control. The cfg
/// flags and shim link arguments are injected through `CARGO_ENCODED_RUSTFLAGS`,
/// and an explicit host `--target` isolates them to the final binary: rustc
/// records link arguments only at the binary link step (rlib compilation
/// ignores them), and building for an explicit target keeps them off build
/// scripts and proc macros, which Cargo compiles for the host without these
/// flags.
#[allow(clippy::too_many_arguments)]
fn build_native_package(
    manifest: &Path,
    package: Option<&str>,
    bin: Option<&str>,
    output: Option<&Path>,
    release: bool,
    object: &Path,
    staticlib: &Path,
    yield_object: Option<&Path>,
) -> Result<PathBuf, CliError> {
    if !manifest.is_file() {
        return Err(CliError(format!(
            "no Cargo manifest at {}",
            manifest.display()
        )));
    }
    let selected = select_native_package_bin(manifest, package, bin)?;
    let host_target = host_target_triple()?;
    let rustflags = native_package_rustflags(object, staticlib, yield_object);

    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let mut command = Command::new(&cargo);
    command
        .arg("build")
        .arg("--manifest-path")
        .arg(manifest)
        .arg("--package")
        .arg(&selected.package)
        .arg("--bin")
        .arg(&selected.bin)
        .arg("--target")
        .arg(&host_target)
        .arg("--message-format=json-render-diagnostics")
        .env_remove("RUSTFLAGS")
        .env("CARGO_ENCODED_RUSTFLAGS", rustflags)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    // The SanitizerCoverage flags carried in the encoded rustflags are stable
    // `-C` codegen options, so no `RUSTC_BOOTSTRAP` is needed. They apply to every
    // crate Cargo compiles from source in this invocation (guest + its
    // path/registry deps); the precompiled std is untouched, so only guest code
    // gains yield points.
    if release {
        command.arg("--release");
    }
    let built = command
        .output()
        .map_err(|error| CliError(format!("failed to run cargo build: {error}")))?;
    if !built.status.success() {
        return Err(CliError(format!(
            "building the native Patina package {:?} failed",
            selected.bin
        )));
    }
    let executable = native_build_executable(&built.stdout, &selected.bin)?;
    let final_path = if let Some(destination) = output {
        fs::copy(&executable, destination).map_err(|error| {
            CliError(format!(
                "failed to copy built binary {} to {}: {error}",
                executable.display(),
                destination.display()
            ))
        })?;
        destination.to_path_buf()
    } else {
        executable
    };
    Ok(final_path)
}

/// The package and binary a package `native-build` resolves to.
struct SelectedNativeBin {
    package: String,
    bin: String,
}

/// Resolve which package and which binary target `native-build` should compile,
/// failing closed on ambiguity rather than guessing. `cargo metadata` enumerates
/// the workspace members and their targets without touching the network for a
/// path-only graph.
fn select_native_package_bin(
    manifest: &Path,
    package: Option<&str>,
    bin: Option<&str>,
) -> Result<SelectedNativeBin, CliError> {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let output = Command::new(&cargo)
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .arg("--manifest-path")
        .arg(manifest)
        .output()
        .map_err(|error| CliError(format!("failed to run cargo metadata: {error}")))?;
    if !output.status.success() {
        return Err(CliError(format!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let metadata: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| CliError(format!("failed to parse cargo metadata: {error}")))?;
    let packages = metadata
        .get("packages")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| CliError("cargo metadata reported no packages".into()))?;

    let selected = if let Some(name) = package {
        packages
            .iter()
            .find(|entry| entry.get("name").and_then(serde_json::Value::as_str) == Some(name))
            .ok_or_else(|| {
                CliError(format!(
                    "package {name:?} is not a member of {}",
                    manifest.display()
                ))
            })?
    } else {
        // With no --package, select the package defined by exactly this manifest
        // so a member of a larger workspace resolves unambiguously.
        let wanted = fs::canonicalize(manifest).unwrap_or_else(|_| manifest.to_path_buf());
        let mut matches = packages.iter().filter(|entry| {
            entry
                .get("manifest_path")
                .and_then(serde_json::Value::as_str)
                .map(|path| fs::canonicalize(path).unwrap_or_else(|_| PathBuf::from(path)))
                == Some(wanted.clone())
        });
        matches.next().ok_or_else(|| {
            CliError(format!(
                "{} defines no package (a virtual workspace); select a member with --package",
                manifest.display()
            ))
        })?
    };

    let package_name = selected
        .get("name")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| CliError("cargo metadata package has no name".into()))?
        .to_string();
    let mut binaries = selected
        .get("targets")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter(|target| {
            target
                .get("kind")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
                .any(|kind| kind.as_str() == Some("bin"))
        })
        .filter_map(|target| {
            target
                .get("name")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .collect::<Vec<_>>();
    binaries.sort();

    let chosen = if let Some(name) = bin {
        if !binaries.iter().any(|candidate| candidate == name) {
            return Err(CliError(format!(
                "package {package_name:?} has no binary target {name:?}; available: {}",
                binaries.join(", ")
            )));
        }
        name.to_string()
    } else {
        match binaries.as_slice() {
            [single] => single.clone(),
            [] => {
                return Err(CliError(format!(
                    "package {package_name:?} has no binary targets to build"
                )));
            }
            multiple => {
                return Err(CliError(format!(
                    "package {package_name:?} has multiple binary targets ({}); select one with --bin",
                    multiple.join(", ")
                )));
            }
        }
    };
    Ok(SelectedNativeBin {
        package: package_name,
        bin: chosen,
    })
}

/// Locate the executable Cargo emitted for `bin` from its JSON build output.
fn native_build_executable(stdout: &[u8], bin: &str) -> Result<PathBuf, CliError> {
    for line in stdout.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        let Ok(message) = serde_json::from_slice::<serde_json::Value>(line) else {
            continue;
        };
        if message.get("reason").and_then(serde_json::Value::as_str) != Some("compiler-artifact") {
            continue;
        }
        let Some(executable) = message
            .get("executable")
            .and_then(serde_json::Value::as_str)
        else {
            continue;
        };
        let is_target_bin = message.get("target").is_some_and(|target| {
            target.get("name").and_then(serde_json::Value::as_str) == Some(bin)
        });
        if is_target_bin {
            return Ok(PathBuf::from(executable));
        }
    }
    Err(CliError(format!(
        "cargo build did not report an executable artifact for binary {bin:?}"
    )))
}

/// Query rustc for the host target triple so the package build isolates its
/// link arguments to host artifacts.
fn host_target_triple() -> Result<String, CliError> {
    let output = Command::new("rustc")
        .arg("-vV")
        .output()
        .map_err(|error| CliError(format!("failed to query rustc host target: {error}")))?;
    if !output.status.success() {
        return Err(CliError(format!(
            "rustc -vV failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .map(str::to_owned)
        .ok_or_else(|| CliError("rustc -vV did not report a host target triple".into()))
}

/// Build the `CARGO_ENCODED_RUSTFLAGS` value for a package build: cfg(patina)/
/// cfg(dst) plus the shim link arguments, encoded with the `0x1f` unit
/// separator so link-argument paths that contain spaces survive intact. Any
/// pre-existing `RUSTFLAGS` are preserved ahead of the injected flags, matching
/// how `cargo patina run` layers its cfgs onto the user's flags.
fn native_package_rustflags(
    object: &Path,
    staticlib: &Path,
    yield_object: Option<&Path>,
) -> OsString {
    let mut tokens: Vec<OsString> = Vec::new();
    if let Some(existing) = env::var_os("RUSTFLAGS") {
        for part in existing.to_string_lossy().split_whitespace() {
            tokens.push(OsString::from(part));
        }
    }
    tokens.push(OsString::from("--cfg"));
    tokens.push(OsString::from("patina"));
    tokens.push(OsString::from("--cfg"));
    tokens.push(OsString::from("dst"));
    // Shim-linked build marker; see `compile_single_source` for why the SDK's
    // buggify FFI is gated on `patina_shim` rather than `patina`.
    tokens.push(OsString::from("--cfg"));
    tokens.push(OsString::from("patina_shim"));
    tokens.push(OsString::from("-C"));
    tokens.push(link_arg(object));
    tokens.push(OsString::from("-C"));
    tokens.push(link_arg(staticlib));
    if let Some(yield_object) = yield_object {
        for flag in sancov_rustc_flags() {
            tokens.push(OsString::from(flag));
        }
        tokens.push(OsString::from("-C"));
        tokens.push(link_arg(yield_object));
    }
    push_platform_link_args(|arg| {
        tokens.push(OsString::from("-C"));
        tokens.push(OsString::from(arg));
    });
    let mut encoded = OsString::new();
    for (index, token) in tokens.iter().enumerate() {
        if index > 0 {
            encoded.push("\u{1f}");
        }
        encoded.push(token);
    }
    encoded
}

#[cfg(unix)]
/// Does `policy` downgrade the denied import `escape` from a hard error to a
/// warning? Matches the raw import name and its underscore-stripped alias so an
/// operator can pass either `_os_unfair_lock_lock` or `os_unfair_lock_lock`.
fn policy_downgrades(policy: &UnsupportedPolicy, escape: &NativeEscape) -> bool {
    match policy {
        UnsupportedPolicy::Deny => false,
        UnsupportedPolicy::All => true,
        UnsupportedPolicy::Only(symbols) => {
            symbols.contains(&escape.symbol)
                || symbols.contains(escape.symbol.trim_start_matches('_'))
        }
    }
}

/// Pre-run default-deny gate for `native-run`. Audits the guest binary against
/// the baked shim control-plane vehicle plus any operator `--allow`, then
/// applies the `--allow-unsupported-symbols` policy. Returns the symbols that
/// were downgraded to warnings (empty when the binary audits clean), or a hard
/// error listing the symbols that remain unsupported.
/// Whether `binary` was built with `--yield-points`, detected by the hook's
/// embedded marker. This classification is load-bearing: it selects the
/// `+yieldpoints` compatibility-fingerprint suffix, so a false negative silently
/// records under — or cross-replays against — the wrong schedule policy. A read
/// failure is therefore NOT treated as "not instrumented" (a silent fail-open
/// that, under memory pressure, let an ENOMEM whole-file read misclassify an
/// instrumented binary as plain and bypass the fingerprint gate); it fails
/// closed with the underlying error. The scan streams the image in a bounded
/// window rather than allocating the whole (large, instrumented) binary, so the
/// detection itself never adds the memory pressure it must survive; a marker
/// straddling a chunk boundary is caught by carrying the trailing overlap.
fn binary_has_yield_points(binary: &Path) -> Result<bool, CliError> {
    use std::io::Read;

    let mut file = fs::File::open(binary).map_err(|error| {
        CliError(format!(
            "failed to open {} to detect yield-point instrumentation: {error}",
            binary.display()
        ))
    })?;
    let marker = PATINA_YIELD_MARKER;
    let overlap = marker.len() - 1;
    let mut window: Vec<u8> = Vec::with_capacity(overlap + 64 * 1024);
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut chunk).map_err(|error| {
            CliError(format!(
                "failed to read {} to detect yield-point instrumentation: {error}",
                binary.display()
            ))
        })?;
        if read == 0 {
            return Ok(false);
        }
        window.extend_from_slice(&chunk[..read]);
        if window.windows(marker.len()).any(|w| w == marker) {
            return Ok(true);
        }
        // Retain only the trailing `overlap` bytes so a marker split across the
        // next chunk boundary is still found without unbounded growth.
        if window.len() > overlap {
            window.drain(..window.len() - overlap);
        }
    }
}

/// Append the yield-point policy suffix to a base fingerprint when the binary is
/// yield-instrumented, leaving a plain binary's fingerprint untouched.
fn yield_point_fingerprint(base: &str, yield_points: bool) -> String {
    if yield_points {
        format!("{base}{PATINA_YIELD_FINGERPRINT_SUFFIX}")
    } else {
        base.to_string()
    }
}

/// The compatibility fingerprint for a native run: the base fingerprint, then
/// the yield-point policy suffix, the mounted-corpus suffix, and the
/// cooperative-SUT (buggify) suffix. Folding the filesystem image hash in means
/// a trace recorded against one corpus fails closed on replay against a
/// different one, exactly like a schedule-policy mismatch. The `+buggify`
/// suffix means a buggify trace never cross-replays with a non-buggify build,
/// even though the per-site knobs live in (reconciled) metadata.
fn native_run_fingerprint(
    base: &str,
    yield_points: bool,
    image_hash: Option<&str>,
    buggify: bool,
    policy: &SchedulePolicyFingerprint,
) -> String {
    let mut fingerprint = yield_point_fingerprint(base, yield_points);
    if let Some(hash) = image_hash {
        fingerprint.push_str("+fsimg:");
        fingerprint.push_str(hash);
    }
    if buggify {
        fingerprint.push_str("+buggify");
    }
    // Exploration-policy suffixes, in a fixed order so the fingerprint is stable.
    // Each folds only when active, so a plain run fingerprints exactly as before
    // these components existed — mirroring the conditional `+buggify` suffix.
    if policy.pct {
        fingerprint.push_str("+pct");
    }
    if policy.starvation {
        fingerprint.push_str("+starve");
    }
    if policy.swarm {
        fingerprint.push_str("+swarm");
    }
    fingerprint
}

/// The exploration-policy fingerprint components of a native run. On a fresh run
/// these come from the CLI flags; on replay they are reconstructed from the trace
/// metadata (see [`native_policy_from_trace`]), so replay is self-contained and a
/// policy trace never cross-replays with a plain build.
#[derive(Clone, Copy, Debug, Default)]
struct SchedulePolicyFingerprint {
    pct: bool,
    starvation: bool,
    swarm: bool,
}

impl SchedulePolicyFingerprint {
    fn from_schedule(schedule: &NativeSchedule) -> Self {
        Self {
            pct: schedule.pct.is_some(),
            starvation: schedule.starve.is_some(),
            swarm: schedule.swarm,
        }
    }
}

/// Whether a recorded trace carries buggify metadata. Used at replay so the
/// `+buggify` fingerprint component is reconstructed from the trace itself,
/// keeping replay self-contained (the operator need not re-pass `--buggify`).
/// A read/parse failure reports `false`; the runtime surfaces any genuine error.
fn trace_has_buggify(path: &Path) -> bool {
    patina_dst_trace::TraceBundle::load(path)
        .map(|bundle| bundle.metadata.buggify.is_some())
        .unwrap_or(false)
}

/// Reconstruct the exploration-policy fingerprint components from a recorded
/// trace's metadata, so a flag-free replay recomputes the same fingerprint the
/// record run folded (`+pct`/`+starve`/`+swarm`) and a cross-policy replay fails
/// closed. A read/parse failure reports the inert default; the runtime surfaces
/// any genuine error.
fn native_policy_from_trace(path: &Path) -> SchedulePolicyFingerprint {
    patina_dst_trace::TraceBundle::load(path)
        .map(|bundle| SchedulePolicyFingerprint {
            pct: bundle
                .metadata
                .schedule_policy
                .as_ref()
                .is_some_and(|policy| policy.pct.is_some()),
            starvation: bundle
                .metadata
                .schedule_policy
                .as_ref()
                .is_some_and(|policy| policy.starvation.is_some()),
            swarm: bundle.metadata.swarm.is_some(),
        })
        .unwrap_or_default()
}

/// An encoded filesystem image held open in a temporary file, ready to be
/// duplicated onto the guest's inherited image descriptor, plus its content
/// hash for the run fingerprint.
struct FsImageCapture {
    file: fs::File,
    hash: String,
}

/// Capture `host_dir` into a deterministic [`FsImage`], encode it, and write the
/// bytes to a rewound anonymous temporary file the child reads over its
/// inherited image descriptor. The supervisor runs uninterposed, so reading the
/// host tree here is sound; the guest only ever sees the rebuilt image.
fn build_fs_image_file(host_dir: &Path) -> Result<FsImageCapture, CliError> {
    use std::io::{Seek, SeekFrom, Write};

    let root = fs::canonicalize(host_dir).map_err(|error| {
        CliError(format!(
            "failed to resolve --mount directory {}: {error}",
            host_dir.display()
        ))
    })?;
    if !root.is_dir() {
        return Err(CliError(format!(
            "--mount target is not a directory: {}",
            root.display()
        )));
    }
    let mut entries = Vec::new();
    collect_fs_entries(&root, "", &mut entries)?;
    let image = FsImage::new(entries);
    let bytes = image.encode();

    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let hash = hasher
        .finalize()
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();

    let mut file = tempfile::tempfile().map_err(|error| {
        CliError(format!(
            "failed to create filesystem image scratch file: {error}"
        ))
    })?;
    file.write_all(&bytes)
        .map_err(|error| CliError(format!("failed to write filesystem image: {error}")))?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| CliError(format!("failed to rewind filesystem image: {error}")))?;
    Ok(FsImageCapture { file, hash })
}

/// Recursively collect `host_dir`'s contents as [`FsImageEntry`] values, mapping
/// the mount root to the guest root `/`. Symlinks are captured verbatim (their
/// target string, never followed), directories are recorded and descended, and
/// regular files carry their bytes. `FsImage::new` sorts the result, so the host
/// `readdir` order never leaks into the deterministic image.
fn collect_fs_entries(
    host_dir: &Path,
    guest_prefix: &str,
    entries: &mut Vec<FsImageEntry>,
) -> Result<(), CliError> {
    let listing = fs::read_dir(host_dir).map_err(|error| {
        CliError(format!(
            "failed to read --mount directory {}: {error}",
            host_dir.display()
        ))
    })?;
    for entry in listing {
        let entry = entry.map_err(|error| {
            CliError(format!(
                "failed to read entry under {}: {error}",
                host_dir.display()
            ))
        })?;
        let host_path = entry.path();
        let name = entry.file_name().into_string().map_err(|_| {
            CliError(format!(
                "--mount directory contains a non-UTF-8 name under {}",
                host_dir.display()
            ))
        })?;
        let guest_path = format!("{guest_prefix}/{name}");
        // Classify without following symlinks so a symlink stays a symlink in
        // the image, matching how a default ripgrep walk lstat's and skips it.
        let metadata = fs::symlink_metadata(&host_path).map_err(|error| {
            CliError(format!("failed to stat {}: {error}", host_path.display()))
        })?;
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            let target = fs::read_link(&host_path)
                .map_err(|error| {
                    CliError(format!(
                        "failed to read symlink {}: {error}",
                        host_path.display()
                    ))
                })?
                .into_os_string()
                .into_string()
                .map_err(|_| {
                    CliError(format!(
                        "symlink {} has a non-UTF-8 target",
                        host_path.display()
                    ))
                })?;
            entries.push(FsImageEntry::Symlink {
                path: guest_path,
                target,
            });
        } else if file_type.is_dir() {
            entries.push(FsImageEntry::Directory {
                path: guest_path.clone(),
            });
            collect_fs_entries(&host_path, &guest_path, entries)?;
        } else if file_type.is_file() {
            let contents = fs::read(&host_path).map_err(|error| {
                CliError(format!("failed to read {}: {error}", host_path.display()))
            })?;
            entries.push(FsImageEntry::File {
                path: guest_path,
                contents,
            });
        }
        // Anything else (sockets, devices, fifos) is skipped: a search corpus
        // has none, and the in-memory filesystem cannot model them.
    }
    Ok(())
}

fn native_prerun_gate(
    binary: &Path,
    allow: &BTreeSet<String>,
    policy: &UnsupportedPolicy,
) -> Result<Vec<NativeEscape>, CliError> {
    let bytes = fs::read(binary).map_err(|error| {
        CliError(format!(
            "failed to read native program {} for the pre-run audit: {error}",
            binary.display()
        ))
    })?;
    let mut effective = shim_control_plane_symbols();
    effective.extend(allow.iter().cloned());
    let denied = match NativeAudit::audit(&bytes, &effective) {
        Ok(_) => return Ok(Vec::new()),
        Err(TargetError::UnsupportedNativeImports(denied)) => denied,
        // A binary we cannot even parse/format-check must never run.
        Err(other) => {
            return Err(CliError(format!(
                "refusing to run {}: {other}",
                binary.display()
            )));
        }
    };

    let (downgraded, blocked): (Vec<_>, Vec<_>) = denied
        .into_iter()
        .partition(|escape| policy_downgrades(policy, escape));

    if !blocked.is_empty() {
        let mut message = format!(
            "refusing to run {}: {} symbol(s) on the blocking/time/scheduling/effect surface are \
neither interposed by the deterministic runtime nor known-safe (default-deny). Interpose them, or \
pass --allow-unsupported-symbols <all|name,name,...> to run anyway with a warning:",
            binary.display(),
            blocked.len()
        );
        for escape in &blocked {
            message.push_str(&format!("\n  {} ({})", escape.symbol, escape.category));
        }
        return Err(CliError(message));
    }

    if !downgraded.is_empty() {
        eprintln!(
            "patina: WARNING: running {} with {} UNSUPPORTED symbol(s) downgraded from error by \
--allow-unsupported-symbols:",
            binary.display(),
            downgraded.len()
        );
        for escape in &downgraded {
            eprintln!("patina:   {} ({})", escape.symbol, escape.category);
        }
        eprintln!(
            "patina: these host symbols are NOT interposed by the deterministic runtime; if the \
guest reaches them at run time it can block, read host time, or otherwise escape the scheduler. \
This run's determinism is NOT guaranteed and any \"deterministic\" claim on it is qualified."
        );
    }

    Ok(downgraded)
}

/// Record the downgraded-symbol caveat next to a recorded trace so a later
/// reader of the artifact sees that the run was not an unconditional
/// determinism claim.
fn write_unsupported_sidecar(trace: &Path, downgraded: &[NativeEscape]) -> Result<(), CliError> {
    if downgraded.is_empty() {
        return Ok(());
    }
    let sidecar = {
        let mut name = trace.as_os_str().to_owned();
        name.push(".unsupported-symbols");
        PathBuf::from(name)
    };
    let mut contents = String::from(
        "# This trace was recorded with --allow-unsupported-symbols. The symbols\n\
# below are NOT interposed by the deterministic runtime; the run's determinism\n\
# is qualified. Symbol (category):\n",
    );
    for escape in downgraded {
        contents.push_str(&format!("{} ({})\n", escape.symbol, escape.category));
    }
    fs::write(&sidecar, contents).map_err(|error| {
        CliError(format!(
            "failed to write unsupported-symbols sidecar {}: {error}",
            sidecar.display()
        ))
    })
}

/// Encode the guest program arguments (`argv[1..]`) as the JSON string array the
/// runtime records into the trace metadata. Recording requires UTF-8 arguments
/// (the trace bundle is UTF-8 JSON); a non-UTF-8 argument fails closed here,
/// before the guest runs, rather than corrupting the trace.
fn encode_guest_argv(program_args: &[OsString]) -> Result<String, CliError> {
    let mut argv = Vec::with_capacity(program_args.len());
    for argument in program_args {
        let text = argument.to_str().ok_or_else(|| {
            CliError(format!(
                "cannot record the guest argument {argument:?}: --record requires UTF-8 guest \
arguments so they round-trip through the trace metadata"
            ))
        })?;
        argv.push(text.to_owned());
    }
    serde_json::to_string(&argv)
        .map_err(|error| CliError(format!("failed to encode guest arguments: {error}")))
}

/// Reconcile the guest arguments for a replay against the trace's recorded argv.
///
/// The trace records the `argv[1..]` it ran with, so a bare replay (no `--`
/// section) reproduces them and the operator need not re-pass the arguments —
/// fixing the incident where a divergent default argv caused a confusing mid-run
/// operation mismatch. If a `--` section IS supplied it must match the recording
/// byte-for-byte, otherwise the replay is refused UPFRONT naming both the
/// recorded and the passed arguments (a parse-time error, never a mid-run
/// divergence). A trace recorded before argv capture carries no recorded argv, so
/// the arguments are taken from the command line exactly as before — no new error
/// for old traces.
fn reconcile_replay_argv(trace: &Path, passed: &[OsString]) -> Result<Vec<OsString>, CliError> {
    let bundle = TraceBundle::load(trace).map_err(|error| {
        CliError(format!(
            "failed to read trace {} for guest-argument restoration: {error}",
            trace.display()
        ))
    })?;
    let Some(recorded) = bundle.metadata.guest_argv else {
        // Pre-argv trace: honor the historical contract (arguments from the
        // command line, and their absence behaves exactly as today).
        return Ok(passed.to_vec());
    };
    let recorded_os: Vec<OsString> = recorded.iter().map(OsString::from).collect();
    if passed.is_empty() || passed == recorded_os.as_slice() {
        Ok(recorded_os)
    } else {
        Err(CliError(format!(
            "replay guest-argument mismatch for {}: the trace recorded {recorded:?}, but the \
command line passed {passed:?} after `--`. Omit the `--` section to replay the recorded arguments, \
or pass them byte-for-byte identically.",
            trace.display()
        )))
    }
}

fn execute_native_run(invocation: NativeRunInvocation) -> Result<i32, CliError> {
    use std::os::unix::io::AsRawFd;
    use std::os::unix::process::CommandExt;

    // A non-interposed host descriptor duplicated into the child for the trace
    // control plane. Declared here (rather than pulling in `libc`) mirroring the
    // shim's own non-interposed host descriptor aliases. `fcntl` clears
    // close-on-exec so the descriptor survives the exec into the child.
    unsafe extern "C" {
        fn dup2(oldfd: i32, newfd: i32) -> i32;
        fn fcntl(fd: i32, cmd: i32, arg: i32) -> i32;
    }
    // F_SETFD with flags 0 clears FD_CLOEXEC on macOS and Linux; FD_CLOEXEC is 1.
    // F_DUPFD (0) duplicates to the lowest free descriptor at or above its arg.
    const F_SETFD: i32 = 2;
    const F_DUPFD: i32 = 0;
    const FD_CLOEXEC: i32 = 1;

    // Source-first: an artifact runs as-is; a source/package is built on the fly
    // first (`resolved` holds the build workspace alive for the whole run). For
    // replay, the rebuilt binary is judged against the trace by the fingerprint
    // and operation-mismatch machinery below — no special-casing.
    let resolved = resolve_artifact(invocation.binary.clone())?;
    let binary = fs::canonicalize(&resolved.path).map_err(|error| {
        CliError(format!(
            "failed to resolve native program {}: {error}",
            resolved.path.display()
        ))
    })?;

    // Pre-run default-deny gate. Before the guest executes, enumerate every
    // externally-resolved symbol it can reach and hard-error, listing names, if
    // any on the blocking/time/scheduling/effect surface is neither interposed
    // nor known-safe. This is what makes a missed interposer (the class the
    // macOS dispatch-semaphore Parker escape belonged to) structurally
    // impossible to run silently: an unmodeled blocking symbol is an import the
    // shim does not define, so it surfaces here as a denial rather than blocking
    // a host thread outside the scheduler. `--allow-unsupported-symbols`
    // downgrades matching denials to a loud warning for programs that carry
    // unsupported surface the scenario never reaches.
    let downgraded = native_prerun_gate(&binary, &invocation.allow, &invocation.allow_unsupported)?;

    // A binary built with `--yield-points` schedules under a different (denser)
    // policy, so its recorded traces must not cross-replay with a plain binary.
    // Detect the linked hook's marker and fold it into the compatibility
    // fingerprint; the same binary is inspected on record and replay, so the
    // suffix is applied consistently and a policy mismatch is rejected.
    let yield_points = binary_has_yield_points(&binary)?;

    // Starvation intervals reorder real thread execution adversarially. A guest
    // whose synchronization is INTERPOSED (mutex/condvar/futex) is always safe —
    // every wait is a scheduling boundary the aging guarantee can act on. But a
    // guest with an *invisible atomic spinlock* (e.g. std's queue `RwLock`/`Parker`
    // fast path) held across an interposed boundary can wedge: the adversarial
    // deferral schedules the spinner while the lock holder is starved, and the
    // spinner's atomics-only loop offers no boundary for aging to force the holder
    // — the exact cooperative-scheduling limitation the vacuous-schedule warning
    // flags. `--yield-points` closes it (loop backedges become boundaries), so
    // starvation there is always liveness-safe. Warn loudly when starvation is
    // enabled on a non-instrumented binary rather than risk a silent hang.
    if invocation.schedule.starve.is_some() && !yield_points {
        eprintln!(
            "PATINA WARNING: starvation intervals (--starve) are enabled on a binary that was NOT \
built with `--yield-points`. Starvation is liveness-safe for guests whose synchronization is \
interposed (mutex/condvar/futex), but a guest with an invisible atomic spinlock (e.g. std's queue \
RwLock/Parker fast path) held across a boundary can WEDGE under adversarial deferral — the same \
atomics-only window the vacuous-schedule diagnostic flags as unreachable. Rebuild with \
`cargo patina build --yield-points` to make those windows schedulable so starvation stays \
liveness-safe."
        );
    }

    // Capture the mounted host directory into a deterministic filesystem image.
    // The supervisor is not interposed, so it may read the host tree freely; the
    // encoded image travels to the guest over an inherited descriptor and the
    // shim rebuilds it, so the fully interposed guest never touches the host
    // filesystem. The image hash folds into the fingerprint below so a replay
    // against a different corpus is rejected exactly like any incompatibility.
    let image_file = match &invocation.mount {
        Some(host_dir) => Some(build_fs_image_file(host_dir)?),
        None => None,
    };
    let image_hash = image_file.as_ref().map(|image| image.hash.clone());

    // Restore the guest arguments for a replay from the trace's recorded argv, so
    // a bare replay reproduces them without the `--` section being re-passed; a
    // mismatched `--` section is refused upfront (see `reconcile_replay_argv`).
    // For seeded/record runs the arguments are the ones supplied on the command
    // line, unchanged.
    let program_args = match &invocation.mode {
        NativeRunMode::Replay { path, .. } => {
            reconcile_replay_argv(path, &invocation.program_args)?
        }
        NativeRunMode::Seeded { .. } | NativeRunMode::Record { .. } => {
            invocation.program_args.clone()
        }
    };

    let mut command = Command::new(&binary);
    // Stamp a fixed, machine-independent `argv[0]`: the guest is exec'd from an
    // absolute host path, but that path must not leak into the guest's
    // `std::env::args()` as a non-portable string. The guest's own arguments live
    // in `argv[1..]`.
    command
        .args(&program_args)
        .arg0(NATIVE_GUEST_ARGV0)
        .env_clear();
    if image_file.is_some() {
        command.env(ENV_FS_IMAGE_FD, PATINA_FS_IMAGE_CHANNEL_FD.to_string());
    }
    if let Some(latency) = invocation.net_latency_nanos {
        command.env(ENV_NET_LATENCY, latency.to_string());
    }
    // Forward whatever fault knobs the operator supplied to the guest. On record
    // and seeded runs these configure the faults and are recorded into the trace
    // metadata. On replay they are OPTIONAL: the trace's recorded configuration
    // is authoritative, so an operator who supplies none replays the faults from
    // the trace alone, while conflicting knobs fail closed in the runtime.
    if let Some(value) = &invocation.faults.fs_crash_at {
        command.env(ENV_FS_CRASH_AT, value);
    }
    if let Some(value) = &invocation.faults.fs_torn_granularity {
        command.env(ENV_FS_TORN_GRANULARITY, value);
    }
    if let Some(value) = &invocation.faults.sleep_jitter_nanos {
        command.env(ENV_SLEEP_JITTER, value);
    }
    if let Some(value) = &invocation.faults.net_jitter_nanos {
        command.env(ENV_NET_JITTER, value);
    }
    if let Some(value) = &invocation.faults.net_drop_permille {
        command.env(ENV_NET_DROP_PERMILLE, value);
    }
    // Forward the cooperative-SUT (buggify) knobs. Presence of `PATINA_BUGGIFY`
    // enables buggify; its value (if any) is the firing per-mille. Like the fault
    // knobs, these are recorded into the trace metadata and are OPTIONAL on
    // replay (the trace is authoritative; a conflicting knob fails closed).
    if let Some(buggify) = &invocation.buggify {
        command.env(ENV_BUGGIFY, buggify.fire_permille.as_deref().unwrap_or(""));
        if let Some(value) = &buggify.activation_permille {
            command.env(ENV_BUGGIFY_ACTIVATION, value);
        }
        if let Some(value) = &buggify.cutoff_nanos {
            command.env(ENV_BUGGIFY_CUTOFF, value);
        }
        if buggify.after_setup {
            command.env(ENV_BUGGIFY_AFTER_SETUP, "1");
        }
    }
    // Forward the exploration scheduling-policy (PCT / starvation) and swarm
    // knobs through the same control plane. Recorded into the trace metadata and
    // OPTIONAL on replay (the trace is authoritative; the fingerprint suffix
    // rejects a cross-policy replay).
    for (name, value) in schedule_env_pairs(&invocation.schedule) {
        command.env(name, value);
    }
    // Forward the liveness-watchdog knobs through the same control plane. The
    // watchdog is schedule-invariant: recorded (informational) but not
    // fingerprinted, so a watchdog trace replays against any build.
    for (name, value) in liveness_env_pairs(&invocation.liveness) {
        command.env(name, value);
    }

    // Hold the trace file open until the child has been spawned so its
    // descriptor is still valid when `pre_exec` duplicates it.
    let trace_file = match &invocation.mode {
        NativeRunMode::Seeded { seed } => {
            command
                .env(ENV_MODE, "seeded")
                .env(ENV_SEED, seed.to_string());
            None
        }
        NativeRunMode::Record {
            seed,
            path,
            fingerprint,
        } => {
            let file = fs::File::create(path).map_err(|error| {
                CliError(format!(
                    "failed to create trace {}: {error}",
                    path.display()
                ))
            })?;
            command
                .env(ENV_MODE, "record")
                .env(ENV_SEED, seed.to_string())
                .env(
                    ENV_FINGERPRINT,
                    native_run_fingerprint(
                        fingerprint,
                        yield_points,
                        image_hash.as_deref(),
                        invocation.buggify.is_some(),
                        &SchedulePolicyFingerprint::from_schedule(&invocation.schedule),
                    ),
                )
                .env(ENV_TRACE_FD, PATINA_TRACE_CHANNEL_FD.to_string())
                // Record the guest arguments into the trace metadata so a later
                // `replay` restores them without the `--` section being
                // re-passed. Always forwarded (even when empty) so a
                // zero-argument run records `[]` — distinct from an old trace's
                // absent field, so replaying it reproduces zero arguments rather
                // than inheriting whatever the command line supplies.
                .env(ENV_GUEST_ARGV, encode_guest_argv(&program_args)?);
            // Qualify the recorded artifact: a run that downgraded unsupported
            // symbols is not an unconditional determinism claim. Record the
            // downgraded surface in a sidecar next to the trace so the caveat
            // travels with it.
            write_unsupported_sidecar(path, &downgraded)?;
            Some(file)
        }
        NativeRunMode::Replay { path, fingerprint } => {
            let file = fs::File::open(path).map_err(|error| {
                CliError(format!("failed to open trace {}: {error}", path.display()))
            })?;
            // Reconstruct the `+buggify` and `+pct`/`+starve`/`+swarm` fingerprint
            // components from the trace so replay is self-contained; a policy
            // trace replayed against a plain build still fails closed on the
            // fingerprint.
            let buggify = invocation.buggify.is_some() || trace_has_buggify(path);
            let policy = native_policy_from_trace(path);
            command
                .env(ENV_MODE, "replay")
                .env(
                    ENV_FINGERPRINT,
                    native_run_fingerprint(
                        fingerprint,
                        yield_points,
                        image_hash.as_deref(),
                        buggify,
                        &policy,
                    ),
                )
                .env(ENV_TRACE_FD, PATINA_TRACE_CHANNEL_FD.to_string());
            Some(file)
        }
    };

    // Install every inherited descriptor the shim reads at a fixed number: the
    // trace channel (record/replay) and the filesystem image (`--mount`). Both
    // are duplicated with close-on-exec cleared so they survive the exec.
    let mut inherited: Vec<(std::os::unix::io::RawFd, i32)> = Vec::new();
    if let Some(file) = &trace_file {
        inherited.push((file.as_raw_fd(), PATINA_TRACE_CHANNEL_FD));
    }
    if let Some(image) = &image_file {
        inherited.push((image.file.as_raw_fd(), PATINA_FS_IMAGE_CHANNEL_FD));
    }
    if !inherited.is_empty() {
        // SAFETY: `dup2` and `fcntl` are async-signal-safe, so they are sound to
        // call between fork and exec, and the closure allocates nothing (it
        // iterates a Vec moved in from the parent and uses a fixed-size stack
        // array). Installing the descriptors naively is unsafe: a source file
        // can already sit on another pair's target number (e.g. the image temp
        // file landing on fd 3, the trace target), and writing that target first
        // would clobber the still-unread source. So first relocate every source
        // to a fresh high descriptor with F_DUPFD (which picks the lowest free
        // fd at or above 10, never aliasing a target or another source), then
        // install each at its fixed target with close-on-exec cleared so it
        // survives the exec, marking the scratch copies close-on-exec so they do
        // not leak into the guest. `inherited` holds at most two entries (trace,
        // image).
        unsafe {
            command.pre_exec(move || {
                let mut scratch = [-1_i32; 2];
                for (index, (source_fd, _target)) in inherited.iter().enumerate() {
                    let high = fcntl(*source_fd, F_DUPFD, 10);
                    if high < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    scratch[index] = high;
                }
                for (index, (_source, target_fd)) in inherited.iter().enumerate() {
                    if dup2(scratch[index], *target_fd) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    if fcntl(*target_fd, F_SETFD, 0) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    if fcntl(scratch[index], F_SETFD, FD_CLOEXEC) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
    }

    // Starvation stall backstop (diagnostic, NOT a liveness guarantee; armed only
    // when starvation is enabled, so it has zero effect on any other mode). The
    // scheduler's aging bounds starvation for interposed synchronization, but a
    // guest spinning inside a std-internal atomic critical section — which is NOT
    // yield-point instrumented, so cooperative scheduling has no edge to preempt
    // it while the lock holder is starved — can livelock. A hung generation
    // silently eats a sweep slot, so the supervisor (uninterposed, real
    // wall-clock) converts an already-hung run into a LOUD named fatal with a
    // distinct nonzero exit so sweeps classify STARVATION_STALL instead of
    // hanging. The threshold is deliberately generous (default 60 real seconds,
    // `PATINA_STARVATION_STALL_SECS` override) so it is unreachable on any healthy
    // run; it never touches the recorded operation stream of a run that completes.
    // The kill-able wait loop mirrors `output::execute_command`'s capture
    // semantics (piped when the JSON envelope / render wants guest output,
    // inherited otherwise) so `--starve` composes with `--format json`.
    let captured = if invocation.schedule.starve.is_some() {
        let stall_secs: u64 = std::env::var("PATINA_STARVATION_STALL_SECS")
            .ok()
            .and_then(|value| value.trim().parse().ok())
            .filter(|value| *value > 0)
            .unwrap_or(60);
        let capture = output::capture_active();
        if capture {
            command.stdout(Stdio::piped()).stderr(Stdio::piped());
        }
        let mut child = command.spawn().map_err(|error| {
            CliError(format!(
                "failed to run native program {}: {error}",
                binary.display()
            ))
        })?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(stall_secs);
        loop {
            match child.try_wait() {
                Ok(Some(_status)) => break,
                Ok(None) => {
                    if std::time::Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        eprintln!(
                            "patina: starvation stall — no scheduler progress in {stall_secs}s under \
--starve; the guest is likely spinning inside an uninstrumented atomic critical section (std is not \
yield-point instrumented, so cooperative scheduling cannot preempt a spinner while the lock holder \
is starved). This is the documented starvation limitation, not a liveness guarantee — see \
IMPLEMENTATION.md \"Slice 7: exploration tier\". Killed with a nonzero exit."
                        );
                        drop(trace_file);
                        drop(image_file);
                        return Ok(STARVATION_STALL_EXIT);
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                Err(error) => {
                    return Err(CliError(format!(
                        "failed while waiting on native program {}: {error}",
                        binary.display()
                    )));
                }
            }
        }
        let output = child.wait_with_output().map_err(|error| {
            CliError(format!(
                "failed while waiting on native program {}: {error}",
                binary.display()
            ))
        })?;
        output::Captured {
            exit_code: exit_code(output.status)?,
            stdout: output.stdout,
            stderr: output.stderr,
            captured: capture,
        }
    } else {
        output::execute_command(&mut command)?
    };
    drop(trace_file);
    drop(image_file);
    let (trace_path, seed) = match &invocation.mode {
        NativeRunMode::Seeded { seed } => (None, Some(*seed)),
        NativeRunMode::Record { seed, path, .. } => (Some(path.clone()), Some(*seed)),
        NativeRunMode::Replay { path, .. } => (Some(path.clone()), None),
    };
    let fingerprint = match &invocation.mode {
        NativeRunMode::Seeded { .. } => None,
        NativeRunMode::Record { fingerprint, .. } | NativeRunMode::Replay { fingerprint, .. } => {
            Some(fingerprint.clone())
        }
    };
    let artifact = binary.display().to_string();
    output::finalize_run(
        output::RunReport {
            verb: "run",
            family: "native",
            artifact: &artifact,
            trace_path,
            timeline: "main",
            fingerprint,
            seed,
        },
        captured,
    )
}

/// Distinct exit code the supervisor returns when the starvation stall backstop
/// kills a hung `--starve` run, so a sweep can classify `STARVATION_STALL` rather
/// than treat the run as an ordinary crash.
const STARVATION_STALL_EXIT: i32 = 111;

#[cfg(not(unix))]
fn execute_native_run(_invocation: NativeRunInvocation) -> Result<i32, CliError> {
    Err(CliError(
        "native-run requires a Unix host for the PATINA_TRACE_FD supervisor channel".into(),
    ))
}

fn execute_minimize(invocation: MinimizeInvocation) -> Result<i32, CliError> {
    match invocation {
        MinimizeInvocation::Trace(trace) => execute_minimize_trace(trace),
        MinimizeInvocation::Scenario(scenario) => execute_minimize_scenario(scenario),
    }
}

fn execute_minimize_trace(invocation: TraceMinimize) -> Result<i32, CliError> {
    let original = TraceBundle::load(&invocation.trace).map_err(|error| {
        CliError(format!(
            "failed to load trace {}: {error}",
            invocation.trace.display()
        ))
    })?;

    // Pick the strategy automatically: a leaf timeline (or an unbranched main)
    // uses the strict suffix path; a non-leaf target or a branched bundle uses
    // the non-leaf branch-tree policy so shrinking never invalidates an
    // inherited replay prefix. `--prune-branches` additionally drops whole
    // branch subtrees the failure does not need.
    let target_has_children = invocation.timeline.as_deref().is_some_and(|id| {
        original
            .timelines
            .iter()
            .any(|timeline| timeline.parent.as_deref() == Some(id))
    });
    let whole_bundle = invocation.prune
        || target_has_children
        || (invocation.timeline.is_none() && original.timelines.len() > 1);
    let before = minimize_event_count(&original, invocation.timeline.as_deref(), whole_bundle);

    let mut calls = 0_u64;
    let mut oracle = |candidate: &TraceBundle| -> io::Result<bool> {
        calls += 1;
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("candidate.patina");
        candidate.write_atomic(&path).map_err(io::Error::other)?;
        let status = Command::new(&invocation.oracle[0])
            .args(&invocation.oracle[1..])
            .env("PATINA_MINIMIZE_TRACE", &path)
            .status()?;
        Ok(!status.success())
    };
    // Compose deletion with schedule canonicalization. `--prune-branches` runs
    // the full pipeline (prune, then shrink and reduce_schedule to a joint fixed
    // point). Every other strategy interleaves its delete reducer with
    // reduce_schedule to the same joint fixed point, so a rewritten schedule that
    // unblocks a deletion (or vice versa) is exploited while each pass stays
    // failure-preserving.
    let minimized = if invocation.prune {
        minimize_all(&original, &mut oracle)
    } else {
        let mut joint = || -> Result<TraceBundle, MinimizeError<io::Error>> {
            let mut current = original.clone();
            loop {
                let before = current.clone();
                current = if whole_bundle {
                    minimize_branch_tree(&current, &mut oracle)?
                } else if let Some(timeline) = invocation.timeline.as_deref() {
                    minimize_timeline(&current, timeline, &mut oracle)?
                } else {
                    minimize_main(&current, &mut oracle)?
                };
                current = reduce_schedule(&current, &mut oracle)?;
                if current == before {
                    return Ok(current);
                }
            }
        };
        joint()
    }
    .map_err(|error| CliError(format!("trace minimization failed: {error}")))?;

    let after = minimize_event_count(&minimized, invocation.timeline.as_deref(), whole_bundle);
    minimized
        .write_atomic(&invocation.output)
        .map_err(|error| {
            CliError(format!(
                "failed to write minimized trace {}: {error}",
                invocation.output.display()
            ))
        })?;
    if output::options().is_json() {
        output::emit_simple(
            "minimize",
            "ok",
            0,
            Some(format!(
                "before={before} after={after} oracle_runs={calls} output={}",
                invocation.output.display()
            )),
        );
    } else {
        println!(
            "PATINA_MINIMIZE_COMPLETE before={before} after={after} oracle_runs={calls} output={}",
            invocation.output.display()
        );
    }
    Ok(0)
}

/// Count the decisions the reported before/after totals should cover: every
/// timeline for a whole-bundle run, one named timeline, or the main timeline.
fn minimize_event_count(bundle: &TraceBundle, timeline: Option<&str>, whole_bundle: bool) -> usize {
    if whole_bundle {
        return bundle
            .timelines
            .iter()
            .map(|timeline| timeline.decisions.len())
            .sum();
    }
    timeline
        .map_or_else(
            || bundle.timelines.first(),
            |id| bundle.timelines.iter().find(|timeline| timeline.id == id),
        )
        .map(|timeline| timeline.decisions.len())
        .unwrap_or(0)
}

fn execute_minimize_scenario(invocation: ScenarioMinimize) -> Result<i32, CliError> {
    let mut base = Scenario::new(invocation.seed);
    base.params = invocation.params;
    let mut calls = 0_u64;
    // Each candidate runs the oracle as a fresh seeded child, handing it the
    // seed and parameters through the same PATINA_* environment protocol a
    // recorded run uses. A non-zero exit means the failure still reproduces.
    let mut oracle = |candidate: &Scenario| -> io::Result<bool> {
        calls += 1;
        let mut command = Command::new(&invocation.oracle[0]);
        command
            .args(&invocation.oracle[1..])
            .env(ENV_MODE, "seeded")
            .env(ENV_SEED, candidate.seed.to_string())
            .env_remove(ENV_PARAMS_JSON);
        if !candidate.params.is_empty() {
            let params = serde_json::to_string(&candidate.params).map_err(io::Error::other)?;
            command.env(ENV_PARAMS_JSON, params);
        }
        let status = command.status()?;
        Ok(!status.success())
    };
    let reduced = reduce_scenario(&base, &mut oracle, invocation.seed_budget)
        .map_err(|error| CliError(format!("scenario minimization failed: {error}")))?;
    let params = reduced
        .params
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join(",");
    if output::options().is_json() {
        output::emit_simple(
            "minimize",
            "ok",
            0,
            Some(format!(
                "seed={} params=[{params}] oracle_runs={calls}",
                reduced.seed
            )),
        );
    } else {
        println!(
            "PATINA_MINIMIZE_SCENARIO_COMPLETE seed={} params=[{params}] oracle_runs={calls}",
            reduced.seed
        );
    }
    Ok(0)
}

fn execute(invocation: Invocation) -> Result<i32, CliError> {
    let workspace = workspace_root_in(invocation.working_dir.as_deref(), &invocation.cargo_args)?;
    ensure_lockfile(&workspace)?;
    let fingerprint = compatibility_fingerprint(&workspace, &invocation)?;
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let mut command = Command::new(cargo);
    // The cargo-family `replay` verb runs from anywhere: run cargo in the
    // package's directory so its build and workspace resolution match the
    // recording (whose fingerprint walks that same source tree), without adding a
    // `--manifest-path` to the arguments, which would perturb the fingerprint.
    if let Some(working_dir) = &invocation.working_dir {
        command.current_dir(working_dir);
    }
    command
        .arg(&invocation.cargo_command)
        .args(&invocation.cargo_args)
        .env("RUSTFLAGS", patina_rustflags())
        .env(ENV_FINGERPRINT, fingerprint.clone())
        .env_remove(ENV_MODE)
        .env_remove(ENV_SEED)
        .env_remove(ENV_TRACE)
        .env_remove(ENV_TIMELINE)
        .env_remove(ENV_BRANCH_FROM)
        .env_remove(ENV_BRANCH_SEED)
        .env_remove(ENV_BRANCH_ID)
        .env_remove(ENV_PARENT_TIMELINE)
        .env_remove(ENV_STEP_BUDGET)
        .env_remove(ENV_PARAMS_JSON)
        // Scrub the fault-injection control plane so only the flags this
        // invocation parsed reach the child; an ambient `PATINA_FS_CRASH_AT` (or
        // any sibling) in the caller's environment must never silently perturb a
        // run that requested no faults.
        .env_remove(ENV_FS_CRASH_AT)
        .env_remove(ENV_FS_TORN_GRANULARITY)
        .env_remove(ENV_SLEEP_JITTER)
        .env_remove(ENV_NET_JITTER)
        .env_remove(ENV_NET_DROP_PERMILLE);
    // Forward this run's fault knobs. On a `--record` run the child's runtime
    // captures them into the trace metadata; on the `replay` verb none are set
    // (the trace is authoritative and the runtime restores them), so replay is
    // flag-free.
    for (name, value) in fault_env_pairs(&invocation.faults) {
        command.env(name, value);
    }
    if let Some(budget) = invocation.step_budget {
        command.env(ENV_STEP_BUDGET, budget.to_string());
    }
    if !invocation.params.is_empty() {
        command.env(
            ENV_PARAMS_JSON,
            serde_json::to_string(&invocation.params)
                .map_err(|error| CliError(format!("failed to encode parameters: {error}")))?,
        );
    }

    match &invocation.mode {
        Mode::Seeded { seed } => {
            command
                .env(ENV_MODE, "seeded")
                .env(ENV_SEED, seed.to_string());
        }
        Mode::Record { seed, path } => {
            command
                .env(ENV_MODE, "record")
                .env(ENV_SEED, seed.to_string())
                .env(ENV_TRACE, path);
        }
        Mode::Replay { path, timeline } => {
            command
                .env(ENV_MODE, "replay")
                .env(ENV_TRACE, path)
                .env(ENV_TIMELINE, timeline);
        }
        Mode::Branch {
            path,
            parent,
            from_sequence,
            branch_seed,
            branch_id,
        } => {
            command
                .env(ENV_MODE, "branch")
                .env(ENV_TRACE, path)
                .env(ENV_PARENT_TIMELINE, parent)
                .env(ENV_BRANCH_FROM, from_sequence.to_string())
                .env(ENV_BRANCH_SEED, branch_seed.to_string())
                .env(ENV_BRANCH_ID, branch_id);
        }
    }
    if invocation.cargo_command == "test" {
        command.env("RUST_TEST_THREADS", "1");
    }

    let captured = output::execute_command(&mut command)?;
    let (trace_path, seed, timeline) = match &invocation.mode {
        Mode::Seeded { seed } => (None, Some(*seed), "main".to_string()),
        Mode::Record { seed, path } => (Some(path.clone()), Some(*seed), "main".to_string()),
        Mode::Replay { path, timeline } => (Some(path.clone()), None, timeline.clone()),
        Mode::Branch {
            path, branch_id, ..
        } => (Some(path.clone()), None, branch_id.clone()),
    };
    let artifact = format!("cargo {}", invocation.cargo_command);
    output::finalize_run(
        output::RunReport {
            verb: &invocation.cargo_command,
            family: "cargo",
            artifact: &artifact,
            trace_path,
            timeline: &timeline,
            fingerprint: Some(fingerprint),
            seed,
        },
        captured,
    )
}

fn workspace_root(cargo_args: &[OsString]) -> Result<PathBuf, CliError> {
    workspace_root_in(None, cargo_args)
}

/// Locate the Cargo workspace root, optionally resolving from `working_dir`
/// (the cargo-family `replay` verb's package directory) rather than the inherited
/// current directory. An explicit `--manifest-path` in `cargo_args` still wins.
fn workspace_root_in(
    working_dir: Option<&Path>,
    cargo_args: &[OsString],
) -> Result<PathBuf, CliError> {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let mut command = Command::new(cargo);
    command.args(["locate-project", "--workspace", "--message-format", "plain"]);
    if let Some(working_dir) = working_dir {
        command.current_dir(working_dir);
    }
    if let Some(path) = manifest_path(cargo_args)? {
        command.arg("--manifest-path").arg(path);
    }
    let output = command
        .output()
        .map_err(|error| CliError(format!("failed to locate Cargo workspace: {error}")))?;
    if !output.status.success() {
        return Err(CliError(format!(
            "cargo locate-project failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let manifest = String::from_utf8(output.stdout)
        .map_err(|_| CliError("cargo locate-project returned a non-UTF-8 path".into()))?;
    let manifest = PathBuf::from(manifest.trim());
    manifest.parent().map(Path::to_path_buf).ok_or_else(|| {
        CliError(format!(
            "workspace manifest has no parent: {}",
            manifest.display()
        ))
    })
}

fn manifest_path(arguments: &[OsString]) -> Result<Option<&OsStr>, CliError> {
    let mut index = 0;
    while index < arguments.len() {
        if arguments[index] == "--" {
            break;
        }
        if arguments[index] == "--manifest-path" {
            return arguments
                .get(index + 1)
                .map(|value| Some(value.as_os_str()))
                .ok_or_else(|| CliError::usage("--manifest-path requires a path"));
        }
        if let Some(value) = arguments[index]
            .to_str()
            .and_then(|value| value.strip_prefix("--manifest-path="))
        {
            return Ok(Some(OsStr::new(value)));
        }
        index += 1;
    }
    Ok(None)
}

fn patina_rustflags() -> OsString {
    let mut flags = env::var_os("RUSTFLAGS").unwrap_or_default();
    if !flags.is_empty() {
        flags.push(" ");
    }
    flags.push(PATINA_CFG_FLAGS);
    flags
}

/// Materialize `Cargo.lock` before the fingerprint is computed. The lockfile is
/// a fingerprint input, but a fresh workspace has none until the first build
/// writes one. Recording would then hash the pre-build state, while replay —
/// run after the build materialized the lockfile — hashes a file the recording
/// never saw and aborts with a spurious `FingerprintMismatch`. Generating it up
/// front (only when absent, so an existing lockfile's pins are never disturbed)
/// makes the record- and replay-time fingerprints observe the same lockfile.
fn ensure_lockfile(workspace: &Path) -> Result<(), CliError> {
    if workspace.join("Cargo.lock").exists() {
        return Ok(());
    }
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let status = Command::new(cargo)
        .arg("generate-lockfile")
        .arg("--manifest-path")
        .arg(workspace.join("Cargo.toml"))
        .status()
        .map_err(|error| CliError(format!("failed to materialize Cargo.lock: {error}")))?;
    if !status.success() {
        return Err(CliError(
            "cargo generate-lockfile failed to materialize Cargo.lock".into(),
        ));
    }
    Ok(())
}

fn compatibility_fingerprint(
    workspace: &Path,
    invocation: &Invocation,
) -> Result<String, CliError> {
    let mut hasher = Sha256::new();
    hash_bytes(&mut hasher, b"patina-fingerprint-v1");
    hash_bytes(&mut hasher, env!("CARGO_PKG_VERSION").as_bytes());

    let rustc = Command::new("rustc")
        .arg("-vV")
        .output()
        .map_err(|error| CliError(format!("failed to query rustc identity: {error}")))?;
    if !rustc.status.success() {
        return Err(CliError(format!(
            "rustc -vV failed: {}",
            String::from_utf8_lossy(&rustc.stderr).trim()
        )));
    }
    hash_bytes(&mut hasher, &rustc.stdout);
    hash_bytes(&mut hasher, invocation.cargo_command.as_bytes());
    hash_os(&mut hasher, &patina_rustflags());
    for argument in &invocation.cargo_args {
        hash_os(&mut hasher, argument);
    }
    for (key, value) in &invocation.params {
        hash_bytes(&mut hasher, key.as_bytes());
        hash_bytes(&mut hasher, value.as_bytes());
    }

    let mut inputs = Vec::new();
    collect_inputs(workspace, workspace, &mut inputs)?;
    inputs.sort();
    for relative in inputs {
        hash_os(&mut hasher, relative.as_os_str());
        let contents = fs::read(workspace.join(&relative)).map_err(|error| {
            CliError(format!(
                "failed to read fingerprint input {}: {error}",
                workspace.join(&relative).display()
            ))
        })?;
        hash_bytes(&mut hasher, &contents);
    }

    Ok(format!("sha256:{}", hex(&hasher.finalize())))
}

fn collect_inputs(
    root: &Path,
    directory: &Path,
    inputs: &mut Vec<PathBuf>,
) -> Result<(), CliError> {
    let entries = fs::read_dir(directory).map_err(|error| {
        CliError(format!(
            "failed to read workspace directory {}: {error}",
            directory.display()
        ))
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            CliError(format!(
                "failed to inspect workspace directory {}: {error}",
                directory.display()
            ))
        })?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|error| CliError(format!("failed to inspect {}: {error}", path.display())))?;
        if file_type.is_dir() {
            if matches!(entry.file_name().to_str(), Some("target" | ".git" | ".jj")) {
                continue;
            }
            collect_inputs(root, &path, inputs)?;
        } else if file_type.is_file() && is_fingerprint_input(&path) {
            let relative = path.strip_prefix(root).map_err(|error| {
                CliError(format!(
                    "failed to make {} relative to {}: {error}",
                    path.display(),
                    root.display()
                ))
            })?;
            inputs.push(relative.to_path_buf());
        }
    }
    Ok(())
}

fn is_fingerprint_input(path: &Path) -> bool {
    path.file_name() == Some(OsStr::new("Cargo.lock"))
        || matches!(
            path.extension().and_then(|value| value.to_str()),
            Some("rs" | "toml")
        )
}

fn hash_bytes(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

#[cfg(unix)]
fn hash_os(hasher: &mut Sha256, value: &OsStr) {
    use std::os::unix::ffi::OsStrExt;
    hash_bytes(hasher, value.as_bytes());
}

#[cfg(windows)]
fn hash_os(hasher: &mut Sha256, value: &OsStr) {
    use std::os::windows::ffi::OsStrExt;
    let bytes = value
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    hash_bytes(hasher, &bytes);
}

fn hex(bytes: &[u8]) -> String {
    use fmt::Write;
    bytes.iter().fold(String::new(), |mut output, byte| {
        write!(output, "{byte:02x}").expect("writing to a String cannot fail");
        output
    })
}

fn exit_code(status: ExitStatus) -> Result<i32, CliError> {
    status
        .code()
        .ok_or_else(|| CliError("Cargo process terminated by a signal".into()))
}

#[derive(Debug)]
pub struct CliError(String);

impl CliError {
    fn usage(message: impl Into<String>) -> Self {
        Self(format!("{}\n\n{HELP}", message.into()))
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CliError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    fn invocation(values: &[&str]) -> Invocation {
        match parse(strings(values)).unwrap() {
            ParseResult::Run(value) => value,
            _ => panic!("expected invocation"),
        }
    }

    // `run`/`audit`/`build` infer their target from artifact magic bytes at the
    // routing layer (covered by the e2e suite with real artifacts and by
    // `detects_artifact_family_from_magic` below). These helpers exercise the
    // per-target parsers directly, so the first element is a readable label the
    // helper drops before parsing.
    fn wasi_invocation(values: &[&str]) -> WasiInvocation {
        parse_wasi_run(strings(&values[1..])).unwrap()
    }

    fn native_run(values: &[&str]) -> NativeRunInvocation {
        parse_native_run(strings(&values[1..])).unwrap()
    }

    #[test]
    fn native_run_parses_fault_knobs() {
        let parsed = native_run(&[
            "native-run",
            "bin",
            "--fs-crash-at",
            "close:1",
            "--fs-torn-granularity",
            "byte",
            "--sleep-jitter-nanos",
            "500..1500",
            "--net-jitter-nanos",
            "0..1000",
            "--net-drop-permille",
            "250",
        ]);
        assert_eq!(parsed.faults.fs_crash_at.as_deref(), Some("close:1"));
        assert_eq!(parsed.faults.fs_torn_granularity.as_deref(), Some("byte"));
        assert_eq!(
            parsed.faults.sleep_jitter_nanos.as_deref(),
            Some("500..1500")
        );
        assert_eq!(parsed.faults.net_jitter_nanos.as_deref(), Some("0..1000"));
        assert_eq!(parsed.faults.net_drop_permille.as_deref(), Some("250"));
    }

    #[test]
    fn native_run_defaults_leave_fault_knobs_off() {
        let parsed = native_run(&["native-run", "bin"]);
        assert_eq!(parsed.faults, NativeFaults::default());
    }

    #[test]
    fn native_run_rejects_malformed_fault_knobs() {
        for bad in [
            &["native-run", "bin", "--fs-crash-at", "flush:1"][..],
            &["native-run", "bin", "--fs-crash-at", "close:0"][..],
            &["native-run", "bin", "--fs-torn-granularity", "page"][..],
            &["native-run", "bin", "--sleep-jitter-nanos", "1500..500"][..],
            &["native-run", "bin", "--net-jitter-nanos", "10"][..],
            &["native-run", "bin", "--net-drop-permille", "1001"][..],
        ] {
            assert!(
                parse_native_run(strings(&bad[1..])).is_err(),
                "expected rejection for {bad:?}"
            );
        }
    }

    #[test]
    fn strips_cargo_plugin_name_and_forwards_unknown_arguments() {
        let parsed = invocation(&[
            "patina",
            "run",
            "--seed",
            "42",
            "--budget",
            "100",
            "--param",
            "zone=a",
            "--release",
            "--example=demo",
        ]);
        assert_eq!(parsed.cargo_command, "run");
        assert_eq!(parsed.mode, Mode::Seeded { seed: 42 });
        assert_eq!(parsed.step_budget, Some(100));
        assert_eq!(parsed.params.get("zone").map(String::as_str), Some("a"));
        assert_eq!(parsed.cargo_args, strings(&["--release", "--example=demo"]));
    }

    #[test]
    fn does_not_consume_program_arguments_after_separator() {
        let parsed = invocation(&["run", "--seed=1", "--", "--seed", "application"]);
        assert_eq!(parsed.mode, Mode::Seeded { seed: 1 });
        assert_eq!(parsed.cargo_args, strings(&["--", "--seed", "application"]));
    }

    #[test]
    fn parses_record_and_replay_and_rejects_conflicts() {
        assert_eq!(
            invocation(&["test", "--record", "run.patina"]).mode,
            Mode::Record {
                seed: 0,
                path: "run.patina".into()
            }
        );
        // Replaying a Cargo-family recording is the `replay` verb's job. The `.`
        // package positional routes to the Cargo family (the crate directory the
        // test runs in) and the trace positional replaces the old `--replay` PATH.
        let replayed = invocation(&["replay", ".", "run.patina"]);
        assert_eq!(
            replayed.mode,
            Mode::Replay {
                path: "run.patina".into(),
                timeline: "main".into(),
            }
        );
        // A recording is produced by `run`, so replay reproduces the `run`
        // program under the runtime; its package directory is threaded through.
        assert_eq!(replayed.cargo_command, "run");
        assert!(replayed.working_dir.is_some());
        assert_eq!(
            invocation(&[
                "replay",
                ".",
                "run.patina",
                "--branch",
                "--from",
                "4",
                "--branch-seed",
                "99",
                "--branch-id",
                "branch-99",
                "--parent",
                "main",
            ])
            .mode,
            Mode::Branch {
                path: "run.patina".into(),
                parent: "main".into(),
                from_sequence: 4,
                branch_seed: 99,
                branch_id: "branch-99".into(),
            }
        );
        // `--timeline` selects a timeline to replay and cannot combine with the
        // branch controls; branch controls without `--branch` are also rejected.
        assert!(
            parse(strings(&[
                "replay",
                ".",
                "run.patina",
                "--branch",
                "--from",
                "1",
                "--branch-seed",
                "2",
                "--branch-id",
                "b",
                "--timeline",
                "x",
            ]))
            .is_err()
        );
        assert!(parse(strings(&["replay", ".", "run.patina", "--from", "1"])).is_err());
        // `run`/`test` no longer parse the replay/branch flags: an unknown flag is
        // forwarded to Cargo, leaving the Patina mode plainly seeded.
        assert_eq!(
            invocation(&["test", "--seed", "1"]).mode,
            Mode::Seeded { seed: 1 }
        );
    }

    #[test]
    fn parses_bounded_seed_exploration() {
        match parse(strings(&[
            "explore",
            "test",
            "--seeds=3",
            "--start",
            "5",
            "--release",
        ]))
        .unwrap()
        {
            ParseResult::Explore(exploration) => {
                assert_eq!(exploration.start_seed, 5);
                assert_eq!(exploration.seed_count, 3);
                match exploration.target {
                    ExploreTarget::Cargo(invocation) => {
                        assert_eq!(invocation.cargo_command, "test");
                        assert_eq!(invocation.cargo_args, strings(&["--release"]));
                    }
                    _ => panic!("expected a Cargo explore target"),
                }
            }
            _ => panic!("expected exploration"),
        }
        assert!(parse(strings(&["explore", "test", "--seeds", "0"])).is_err());
        assert!(parse(strings(&["explore", "test", "--record", "run.patina"])).is_err());
    }

    #[test]
    fn cargo_family_parses_fault_knobs_and_explore_run_wasi() {
        // The Cargo family accepts the seed-driven fault knobs on run/test.
        let parsed = invocation(&[
            "run",
            "--fs-crash-at",
            "close:2",
            "--net-drop-permille",
            "300",
            "--",
            "app-arg",
        ]);
        assert_eq!(parsed.faults.fs_crash_at.as_deref(), Some("close:2"));
        assert_eq!(parsed.faults.net_drop_permille.as_deref(), Some("300"));
        // The `--` tail is forwarded to Cargo, unaffected by fault parsing.
        assert_eq!(parsed.cargo_args, strings(&["--", "app-arg"]));

        // `explore run <MODULE.wasm>` sweeps the WASI family (build once, run the
        // same artifact across seeds). The module is recognized by magic bytes at
        // execution; here a real `.wasm` file exercises the routing.
        let directory = tempfile::tempdir().unwrap();
        let module = directory.path().join("m.wasm");
        std::fs::write(&module, b"\0asm\x01\0\0\0").unwrap();
        match parse(strings(&[
            "explore",
            "run",
            module.to_str().unwrap(),
            "--seeds",
            "4",
            "--start",
            "2",
        ]))
        .unwrap()
        {
            ParseResult::Explore(exploration) => {
                assert_eq!(exploration.start_seed, 2);
                assert_eq!(exploration.seed_count, 4);
                assert!(matches!(exploration.target, ExploreTarget::Wasi(_)));
            }
            _ => panic!("expected a WASI exploration"),
        }
    }

    fn trace_invocation(values: &[&str]) -> TraceMinimize {
        match parse(strings(values)).unwrap() {
            ParseResult::Minimize(MinimizeInvocation::Trace(invocation)) => invocation,
            _ => panic!("expected trace minimization"),
        }
    }

    fn scenario_invocation(values: &[&str]) -> ScenarioMinimize {
        match parse(strings(values)).unwrap() {
            ParseResult::Minimize(MinimizeInvocation::Scenario(invocation)) => invocation,
            _ => panic!("expected scenario minimization"),
        }
    }

    fn clock_event(sequence: u64, value: u64) -> patina_dst_trace::TraceEvent {
        patina_dst_trace::TraceEvent {
            sequence,
            operation: patina_dst_abi::Operation::ClockNow {
                clock: patina_dst_abi::ClockKind::Monotonic,
            },
            outcome: patina_dst_abi::Outcome::U64(value),
        }
    }

    #[test]
    fn parses_trace_minimization_with_an_external_oracle() {
        let invocation = trace_invocation(&[
            "minimize",
            "failure.patina",
            "--output",
            "small.patina",
            "--timeline",
            "failure",
            "--",
            "./oracle",
            "--exact",
        ]);
        assert_eq!(invocation.trace, PathBuf::from("failure.patina"));
        assert_eq!(invocation.output, PathBuf::from("small.patina"));
        assert_eq!(invocation.timeline.as_deref(), Some("failure"));
        assert!(!invocation.prune);
        assert_eq!(invocation.oracle, strings(&["./oracle", "--exact"]));
        assert!(parse(strings(&["minimize", "failure.patina"])).is_err());
    }

    #[test]
    fn executes_trace_minimization_with_an_external_oracle() {
        use patina_dst_abi::Outcome;
        use patina_dst_trace::RunMetadata;

        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("input.patina");
        let output = directory.path().join("output.patina");
        let decisions = (0..6)
            .map(|sequence| clock_event(sequence, if sequence == 4 { 999 } else { sequence }))
            .collect();
        TraceBundle::new(RunMetadata::new(1, "fixture"), decisions)
            .write_atomic(&input)
            .unwrap();
        execute_minimize_trace(TraceMinimize {
            trace: input,
            output: output.clone(),
            timeline: None,
            prune: false,
            oracle: strings(&[
                "sh",
                "-c",
                "grep -q 999 \"$PATINA_MINIMIZE_TRACE\" && exit 1; exit 0",
            ]),
        })
        .unwrap();
        let minimized = TraceBundle::load(output).unwrap();
        assert_eq!(minimized.timelines[0].decisions.len(), 1);
        assert_eq!(
            minimized.timelines[0].decisions[0].outcome,
            Outcome::U64(999)
        );
    }

    fn branched_input(path: &Path) {
        use patina_dst_trace::{RunMetadata, Timeline};
        // main -> keeper (holds the 999 marker plus a removable suffix) and
        // main -> disposable (dead weight the oracle never needs).
        let mut bundle = TraceBundle::new(RunMetadata::new(1, "fixture"), vec![clock_event(0, 0)]);
        bundle.timelines.push(Timeline {
            id: "keeper".into(),
            parent: Some("main".into()),
            from_sequence: Some(1),
            branch_seed: Some(7),
            decisions: vec![clock_event(1, 999), clock_event(2, 2), clock_event(3, 3)],
        });
        bundle.timelines.push(Timeline {
            id: "disposable".into(),
            parent: Some("main".into()),
            from_sequence: Some(1),
            branch_seed: Some(8),
            decisions: vec![clock_event(1, 11), clock_event(2, 12)],
        });
        bundle.write_atomic(path).unwrap();
    }

    #[test]
    fn executes_non_leaf_branch_tree_minimization_automatically() {
        use patina_dst_abi::Outcome;

        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("input.patina");
        let output = directory.path().join("output.patina");
        branched_input(&input);

        // A branched bundle with no --timeline automatically uses the branch-tree
        // policy: each timeline's safe suffix shrinks, but no subtree is dropped.
        execute_minimize_trace(TraceMinimize {
            trace: input,
            output: output.clone(),
            timeline: None,
            prune: false,
            oracle: strings(&[
                "sh",
                "-c",
                "grep -q 999 \"$PATINA_MINIMIZE_TRACE\" && exit 1; exit 0",
            ]),
        })
        .unwrap();

        let minimized = TraceBundle::load(output).unwrap();
        let ids: Vec<&str> = minimized.timelines.iter().map(|t| t.id.as_str()).collect();
        assert_eq!(ids, vec!["main", "keeper", "disposable"]);
        assert_eq!(minimized.timelines[1].decisions.len(), 1);
        assert_eq!(
            minimized.timelines[1].decisions[0].outcome,
            Outcome::U64(999)
        );
        minimized.validate().unwrap();
    }

    #[test]
    fn parses_branch_pruning_and_rejects_timeline_combo() {
        let invocation = trace_invocation(&[
            "minimize",
            "failure.patina",
            "--output",
            "small.patina",
            "--prune-branches",
            "--",
            "./oracle",
        ]);
        assert!(invocation.prune);
        assert_eq!(invocation.timeline, None);
        // --prune-branches and --timeline are mutually exclusive.
        assert!(
            parse(strings(&[
                "minimize",
                "failure.patina",
                "--output",
                "small.patina",
                "--prune-branches",
                "--timeline",
                "leaf",
                "--",
                "./oracle",
            ]))
            .is_err()
        );
    }

    #[test]
    fn executes_branch_pruning_dropping_and_shrinking() {
        use patina_dst_abi::Outcome;

        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("input.patina");
        let output = directory.path().join("output.patina");
        branched_input(&input);

        execute_minimize_trace(TraceMinimize {
            trace: input,
            output: output.clone(),
            timeline: None,
            prune: true,
            oracle: strings(&[
                "sh",
                "-c",
                "grep -q 999 \"$PATINA_MINIMIZE_TRACE\" && exit 1; exit 0",
            ]),
        })
        .unwrap();

        let minimized = TraceBundle::load(output).unwrap();
        let ids: Vec<&str> = minimized.timelines.iter().map(|t| t.id.as_str()).collect();
        assert_eq!(ids, vec!["main", "keeper"]);
        assert_eq!(minimized.timelines[1].decisions.len(), 1);
        assert_eq!(
            minimized.timelines[1].decisions[0].outcome,
            Outcome::U64(999)
        );
    }

    #[test]
    fn parses_scenario_minimization_with_seed_and_params() {
        let invocation = scenario_invocation(&[
            "minimize",
            "--scenario",
            "--seed",
            "12",
            "--param",
            "zone=a",
            "--seed-budget",
            "16",
            "--",
            "./oracle",
            "--flag",
        ]);
        assert_eq!(invocation.seed, 12);
        assert_eq!(invocation.seed_budget, 16);
        assert_eq!(invocation.params.get("zone").map(String::as_str), Some("a"));
        assert_eq!(invocation.oracle, strings(&["./oracle", "--flag"]));
        // --scenario requires a seed and an oracle after `--`.
        assert!(parse(strings(&["minimize", "--scenario", "--", "./oracle"])).is_err());
        assert!(parse(strings(&["minimize", "--scenario", "--seed", "1"])).is_err());
        // trace-only options are rejected in scenario mode.
        assert!(
            parse(strings(&[
                "minimize",
                "--scenario",
                "--seed",
                "1",
                "--timeline",
                "leaf",
                "--",
                "./oracle",
            ]))
            .is_err()
        );
    }

    #[test]
    fn executes_scenario_minimization_shrinking_seed_and_params() {
        let invocation = scenario_invocation(&[
            "minimize",
            "--scenario",
            "--seed",
            "9",
            "--param",
            "keep=1",
            "--param",
            "drop=5",
            "--seed-budget",
            "64",
            "--",
            "sh",
            "-c",
            // Failure needs seed >= 3 and the `keep` parameter present, read from
            // the PATINA_* environment protocol.
            "test \"$PATINA_SEED\" -ge 3 \
             && printf '%s' \"$PATINA_PARAMS_JSON\" | grep -q '\"keep\"' && exit 1; exit 0",
        ]);
        // Smoke-check the scenario reducer runs end-to-end through the oracle.
        assert_eq!(execute_minimize_scenario(invocation).unwrap(), 0);
    }

    #[test]
    fn detects_artifact_family_from_magic() {
        // WebAssembly preamble.
        assert_eq!(
            detect_artifact_family(b"\0asm\x01\0\0\0"),
            Some(ArtifactFamily::Wasm)
        );
        // ELF.
        assert_eq!(
            detect_artifact_family(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]),
            Some(ArtifactFamily::Native)
        );
        // Mach-O thin (both byte orders) and universal ("fat").
        for magic in [
            [0xfe, 0xed, 0xfa, 0xce],
            [0xce, 0xfa, 0xed, 0xfe],
            [0xfe, 0xed, 0xfa, 0xcf],
            [0xcf, 0xfa, 0xed, 0xfe],
            [0xca, 0xfe, 0xba, 0xbe],
            [0xbe, 0xba, 0xfe, 0xca],
        ] {
            assert_eq!(
                detect_artifact_family(&magic),
                Some(ArtifactFamily::Native),
                "Mach-O magic {magic:02x?} should classify as native"
            );
        }
        // Unrecognized: a Cargo.toml, a too-short buffer, an empty buffer.
        assert_eq!(detect_artifact_family(b"[package]\nname = \"x\"\n"), None);
        assert_eq!(detect_artifact_family(b"\0as"), None);
        assert_eq!(detect_artifact_family(b""), None);
    }

    #[test]
    fn extracts_target_selector() {
        let (target, rest) =
            extract_target(strings(&["src.rs", "--target", "wasi", "--release"])).unwrap();
        assert_eq!(target.as_deref(), Some("wasi"));
        assert_eq!(rest, strings(&["src.rs", "--release"]));

        let (target, rest) = extract_target(strings(&["pkg", "--target=native"])).unwrap();
        assert_eq!(target.as_deref(), Some("native"));
        assert_eq!(rest, strings(&["pkg"]));

        // A `--target` past `--` is a rustc/cargo flag, left in place.
        let (target, rest) = extract_target(strings(&["src.rs", "--", "--target", "x86"])).unwrap();
        assert_eq!(target, None);
        assert_eq!(rest, strings(&["src.rs", "--", "--target", "x86"]));

        assert_eq!(target_family("native").unwrap(), ArtifactFamily::Native);
        assert_eq!(target_family("wasi").unwrap(), ArtifactFamily::Wasm);
        assert!(target_family("riscv").is_err());
    }

    #[test]
    fn classifies_and_resolves_positional_arguments() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();

        // A native (ELF) magic file is a built artifact.
        let elf = root.join("bin");
        fs::write(&elf, [0x7f, b'E', b'L', b'F', 2, 1, 1, 0]).unwrap();
        assert!(matches!(
            classify_arg(elf.as_os_str()).unwrap(),
            ArgKind::Artifact(ArtifactFamily::Native)
        ));
        // A WebAssembly magic file is a built artifact.
        let wasm = root.join("mod.wasm");
        fs::write(&wasm, b"\0asm\x01\0\0\0").unwrap();
        assert!(matches!(
            classify_arg(wasm.as_os_str()).unwrap(),
            ArgKind::Artifact(ArtifactFamily::Wasm)
        ));
        // A `.rs` source, a package directory, and a Cargo.toml are sources.
        let source = root.join("main.rs");
        fs::write(&source, "fn main() {}").unwrap();
        assert!(matches!(
            classify_arg(source.as_os_str()).unwrap(),
            ArgKind::SourceFile(_)
        ));
        let pkg = root.join("pkg");
        fs::create_dir(&pkg).unwrap();
        fs::write(pkg.join("Cargo.toml"), "[package]").unwrap();
        match classify_arg(pkg.as_os_str()).unwrap() {
            ArgKind::SourcePackage(manifest) => assert_eq!(manifest, pkg.join("Cargo.toml")),
            _ => panic!("expected a source package"),
        }
        assert!(matches!(
            classify_arg(pkg.join("Cargo.toml").as_os_str()).unwrap(),
            ArgKind::SourcePackage(_)
        ));
        // A leading flag and a plain non-source file are neither.
        assert!(matches!(
            classify_arg(OsStr::new("--seed")).unwrap(),
            ArgKind::Other
        ));
        let plain = root.join("notes.txt");
        fs::write(&plain, "hello").unwrap();
        assert!(matches!(
            classify_arg(plain.as_os_str()).unwrap(),
            ArgKind::Other
        ));

        // Resolution: a lone `.rs` builds native; `--target wasi` on a `.rs`
        // errors (native-only); a prebuilt artifact with a mismatched --target
        // errors.
        let (family, artifact) = resolve_positional(source.as_os_str(), None, false)
            .unwrap()
            .unwrap();
        assert_eq!(family, ArtifactFamily::Native);
        assert!(matches!(artifact, ArtifactRef::Build(_)));
        assert!(resolve_positional(source.as_os_str(), Some("wasi"), false).is_err());
        assert!(resolve_positional(wasm.as_os_str(), Some("native"), false).is_err());

        // A package directory: cargo family (None) under `run` with no --target;
        // a native build under `audit`/`replay` (cargo_family = false).
        assert!(
            resolve_positional(pkg.as_os_str(), None, true)
                .unwrap()
                .is_none()
        );
        let (family, artifact) = resolve_positional(pkg.as_os_str(), None, false)
            .unwrap()
            .unwrap();
        assert_eq!(family, ArtifactFamily::Native);
        assert!(matches!(artifact, ArtifactRef::Build(_)));
        let (family, _) = resolve_positional(pkg.as_os_str(), Some("wasi"), true)
            .unwrap()
            .unwrap();
        assert_eq!(family, ArtifactFamily::Wasm);
    }

    #[test]
    fn parses_build_wasi_target_and_native_audit() {
        // `build --target wasi <package>` resolves a manifest-scoped package
        // build; a `.rs` source, `--yield-points`, and an unknown target rejected.
        match parse_build(strings(&["pkg", "--target", "wasi", "--release"])).unwrap() {
            ParseResult::WasiBuild(invocation) => {
                assert_eq!(invocation.manifest, PathBuf::from("pkg/Cargo.toml"));
                assert!(invocation.release);
                assert_eq!(invocation.package, None);
                assert_eq!(invocation.bin, None);
                assert_eq!(invocation.output, None);
            }
            _ => panic!("expected a WASI build"),
        }
        assert!(parse_build(strings(&["probe.rs", "--target", "wasi"])).is_err());
        assert!(parse_build(strings(&["pkg", "--target", "wasi", "--yield-points"])).is_err());
        assert!(parse_build(strings(&["pkg", "--target", "riscv"])).is_err());

        // Native audit parsing (routing to it by artifact magic is covered by e2e).
        let audit = parse_native_audit(strings(&[
            "probe",
            "--allow",
            "write",
            "--allow",
            "clock_gettime",
        ]))
        .unwrap();
        assert_eq!(audit.binary, ArtifactRef::Prebuilt(PathBuf::from("probe")));
        assert!(audit.allow.contains("write"));
        assert!(audit.allow.contains("clock_gettime"));
    }

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
    fn rejects_malformed_wasi_preopens_and_limits() {
        assert!(parse_wasi_run(strings(&["module.wasm", "--preopen"])).is_err());
        assert!(parse_wasi_run(strings(&["module.wasm", "--preopen", ":ro"])).is_err());
        assert!(parse_wasi_run(strings(&["module.wasm", "--preopen", "/data:rx"])).is_err());
        assert!(
            parse_wasi_run(strings(&[
                "module.wasm",
                "--max-memory-pages",
                "4294967296"
            ]))
            .is_err()
        );
        assert!(parse_wasi_run(strings(&["module.wasm", "--max-descriptors", "-1"])).is_err());
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

    #[test]
    fn wasi_host_configuration_errors_are_cli_errors() {
        let invalid = wasi_invocation(&["wasi-run", "module.wasm", "--preopen", "relative"]);
        let error = configured_wasi_host(
            &invalid,
            Path::new("module.wasm"),
            Context::from_config(RuntimeConfig::seeded(0)).unwrap(),
        )
        .err()
        .unwrap()
        .to_string();
        assert!(error.contains("invalid WASI preopen"));

        let overlapping = wasi_invocation(&[
            "wasi-run",
            "module.wasm",
            "--preopen",
            "/data",
            "--preopen",
            "/data/inner",
        ]);
        let error = configured_wasi_host(
            &overlapping,
            Path::new("module.wasm"),
            Context::from_config(RuntimeConfig::seeded(0)).unwrap(),
        )
        .err()
        .unwrap()
        .to_string();
        assert!(error.contains("overlaps the configured mount"));

        let too_many = wasi_invocation(&[
            "wasi-run",
            "module.wasm",
            "--max-preopens",
            "1",
            "--preopen",
            "/first",
            "--preopen",
            "/second",
        ]);
        let error = configured_wasi_host(
            &too_many,
            Path::new("module.wasm"),
            Context::from_config(RuntimeConfig::seeded(0)).unwrap(),
        )
        .err()
        .unwrap()
        .to_string();
        assert!(error.contains("configured limit of 1"));
    }

    #[test]
    fn wasi_fingerprint_separates_arguments_from_environment() {
        let module = b"module";
        let arguments = wasi_invocation(&["wasi-run", "module.wasm", "--arg", "k", "--arg", "v"]);
        let environment = wasi_invocation(&["wasi-run", "module.wasm", "--env", "k=v"]);
        assert_ne!(
            wasi_compatibility_fingerprint(module, &arguments, false),
            wasi_compatibility_fingerprint(module, &environment, false)
        );
    }

    #[test]
    fn wasi_fingerprint_covers_preopens_and_resource_limits() {
        let module = b"module";
        let ordered = wasi_invocation(&[
            "wasi-run",
            "module.wasm",
            "--preopen",
            "/beta:ro",
            "--preopen",
            "/alpha:rw",
            "--max-io-bytes",
            "64",
        ]);
        let reordered = wasi_invocation(&[
            "wasi-run",
            "module.wasm",
            "--preopen",
            "/alpha:rw",
            "--preopen",
            "/beta:ro",
            "--max-io-bytes",
            "64",
        ]);
        // Reordering preopens changes descriptor assignment, so it must
        // change the fingerprint.
        assert_ne!(
            wasi_compatibility_fingerprint(module, &ordered, false),
            wasi_compatibility_fingerprint(module, &reordered, false)
        );

        let changed_preopen = wasi_invocation(&[
            "wasi-run",
            "module.wasm",
            "--preopen",
            "/alpha:ro",
            "--preopen",
            "/beta:ro",
            "--max-io-bytes",
            "64",
        ]);
        assert_ne!(
            wasi_compatibility_fingerprint(module, &ordered, false),
            wasi_compatibility_fingerprint(module, &changed_preopen, false)
        );

        let changed_limit = wasi_invocation(&[
            "wasi-run",
            "module.wasm",
            "--preopen",
            "/beta:ro",
            "--preopen",
            "/alpha:rw",
            "--max-io-bytes",
            "65",
        ]);
        assert_ne!(
            wasi_compatibility_fingerprint(module, &ordered, false),
            wasi_compatibility_fingerprint(module, &changed_limit, false)
        );
    }

    fn native_build_invocation(values: &[&str]) -> NativeBuildInvocation {
        // The first element is a readable label; `build` routing lives in
        // `parse_build`, exercised separately.
        parse_native_build(strings(&values[1..])).unwrap()
    }

    #[test]
    fn parses_native_build_with_output_edition_and_forwarded_rustc_args() {
        let invocation = native_build_invocation(&[
            "native-build",
            "probe.rs",
            "--output",
            "probe",
            "--edition",
            "2021",
            "--release",
            "--",
            "-C",
            "opt-level=2",
        ]);
        assert_eq!(invocation.output.as_deref(), Some(Path::new("probe")));
        assert!(invocation.release);
        match invocation.target {
            NativeBuildTarget::Source {
                source,
                edition,
                rustc_args,
            } => {
                assert_eq!(source, PathBuf::from("probe.rs"));
                assert_eq!(edition, "2021");
                assert_eq!(rustc_args, strings(&["-C", "opt-level=2"]));
            }
            NativeBuildTarget::Package { .. } => panic!("expected a single-source target"),
        }
        // The default edition applies and --output is required.
        let invocation =
            native_build_invocation(&["native-build", "probe.rs", "--output", "probe", "--"]);
        assert!(!invocation.release);
        match invocation.target {
            NativeBuildTarget::Source {
                edition,
                rustc_args,
                ..
            } => {
                assert_eq!(edition, DEFAULT_NATIVE_EDITION);
                assert!(rustc_args.is_empty());
            }
            NativeBuildTarget::Package { .. } => panic!("expected a single-source target"),
        }
        assert!(parse_native_build(strings(&["probe.rs"])).is_err());
        assert!(parse_native_build(strings(&["--output", "probe"])).is_err());
        // Package-only options are rejected for a single source.
        assert!(
            parse_native_build(strings(&["probe.rs", "--output", "probe", "--bin", "x"])).is_err()
        );
    }

    #[test]
    fn yield_points_flag_and_fingerprint_suffix() {
        // Off by default on both target shapes.
        assert!(
            !native_build_invocation(&["native-build", "probe.rs", "--output", "p"]).yield_points
        );
        assert!(!native_build_invocation(&["native-build", "pkg", "--output", "p"]).yield_points);
        // `--yield-points` sets it on a single source and on a package.
        assert!(
            native_build_invocation(&[
                "native-build",
                "probe.rs",
                "--output",
                "p",
                "--yield-points",
            ])
            .yield_points
        );
        assert!(
            native_build_invocation(&["native-build", "pkg", "--output", "p", "--yield-points"])
                .yield_points
        );
        // The fingerprint gains the policy suffix only for a yield-point binary,
        // so a plain binary's traces stay compatible and cross-config replay is
        // rejected.
        assert_eq!(
            yield_point_fingerprint(DEFAULT_NATIVE_FINGERPRINT, false),
            DEFAULT_NATIVE_FINGERPRINT
        );
        assert_eq!(
            yield_point_fingerprint(DEFAULT_NATIVE_FINGERPRINT, true),
            format!("{DEFAULT_NATIVE_FINGERPRINT}{PATINA_YIELD_FINGERPRINT_SUFFIX}")
        );
    }

    // The yield-point classification is load-bearing for the compatibility
    // fingerprint, so its detector must (a) find the marker even when it straddles
    // the streaming chunk boundary, (b) report a clean absence as `Ok(false)`, and
    // (c) FAIL CLOSED on an unreadable image rather than silently reporting "not
    // instrumented" — the fail-open that let a memory-pressure read failure
    // misclassify an instrumented binary as plain and bypass the fingerprint gate.
    #[test]
    fn yield_point_detection_streams_and_fails_closed() {
        let dir = tempfile::tempdir().unwrap();

        // Absent marker -> Ok(false).
        let plain = dir.path().join("plain.bin");
        fs::write(&plain, vec![0u8; 200_000]).unwrap();
        assert_eq!(binary_has_yield_points(&plain).ok(), Some(false));

        // Marker present, and deliberately positioned to straddle the 64 KiB
        // streaming boundary so the trailing-overlap carry is exercised.
        let boundary = 64 * 1024 - (PATINA_YIELD_MARKER.len() / 2);
        let mut image = vec![0u8; 200_000];
        image[boundary..boundary + PATINA_YIELD_MARKER.len()].copy_from_slice(PATINA_YIELD_MARKER);
        let instrumented = dir.path().join("instrumented.bin");
        fs::write(&instrumented, &image).unwrap();
        assert_eq!(binary_has_yield_points(&instrumented).ok(), Some(true));

        // An unreadable image is a hard error, never a silent `false`.
        let missing = dir.path().join("does-not-exist.bin");
        let error = binary_has_yield_points(&missing).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("detect yield-point instrumentation"),
            "read failure must fail closed with a named error, got: {error}"
        );
    }

    #[test]
    fn parses_native_build_for_cargo_packages() {
        // A directory and an explicit Cargo.toml both resolve to a manifest path.
        let invocation = native_build_invocation(&[
            "native-build",
            "pkg",
            "--package",
            "demo",
            "--bin",
            "app",
            "--output",
            "out",
            "--release",
        ]);
        assert_eq!(invocation.output.as_deref(), Some(Path::new("out")));
        assert!(invocation.release);
        match invocation.target {
            NativeBuildTarget::Package {
                manifest,
                package,
                bin,
            } => {
                assert_eq!(manifest, PathBuf::from("pkg/Cargo.toml"));
                assert_eq!(package.as_deref(), Some("demo"));
                assert_eq!(bin.as_deref(), Some("app"));
            }
            NativeBuildTarget::Source { .. } => panic!("expected a package target"),
        }

        // --output is optional for packages; a Cargo.toml path is used as-is.
        let invocation = native_build_invocation(&["native-build", "pkg/Cargo.toml"]);
        assert!(invocation.output.is_none());
        match invocation.target {
            NativeBuildTarget::Package {
                manifest,
                package,
                bin,
            } => {
                assert_eq!(manifest, PathBuf::from("pkg/Cargo.toml"));
                assert_eq!(package, None);
                assert_eq!(bin, None);
            }
            NativeBuildTarget::Source { .. } => panic!("expected a package target"),
        }

        // Single-source options are rejected for a package.
        assert!(parse_native_build(strings(&["pkg", "--edition", "2021"])).is_err());
        assert!(parse_native_build(strings(&["pkg", "--", "-C", "opt-level=2"])).is_err());
    }

    #[test]
    fn parses_native_run_modes_and_rejects_conflicts() {
        let seeded = native_run(&["native-run", "probe", "--seed", "9", "--", "one"]);
        assert_eq!(seeded.binary, ArtifactRef::Prebuilt(PathBuf::from("probe")));
        assert!(matches!(seeded.mode, NativeRunMode::Seeded { seed: 9 }));
        assert_eq!(seeded.program_args, strings(&["one"]));

        let recorded = native_run(&[
            "native-run",
            "probe",
            "--record",
            "run.patina",
            "--seed",
            "5",
            "--fingerprint",
            "native-v1",
        ]);
        match recorded.mode {
            NativeRunMode::Record {
                seed,
                path,
                fingerprint,
            } => {
                assert_eq!(seed, 5);
                assert_eq!(path, PathBuf::from("run.patina"));
                assert_eq!(fingerprint, "native-v1");
            }
            _ => panic!("expected record mode"),
        }
        // `run <BINARY>` has no `--replay` flag: replay is the sole domain of the
        // `replay` subcommand, so the native runner rejects it as an unknown option.
        assert!(parse_native_run(strings(&["probe", "--replay", "run.patina"])).is_err());
        assert!(parse_native_run(Vec::new()).is_err());

        // `replay <bin> <trace>` parses into replay mode, restoring seed/faults/
        // buggify/argv from the trace and defaulting the fingerprint. `replay` is
        // source-first, so the binary is classified by magic: use a real file
        // carrying native (ELF) magic as the prebuilt artifact.
        let directory = tempfile::tempdir().unwrap();
        let probe = directory.path().join("probe");
        fs::write(&probe, [0x7f, b'E', b'L', b'F', 2, 1, 1, 0]).unwrap();
        let probe = probe.to_str().unwrap();
        match parse(strings(&["replay", probe, "run.patina"])).unwrap() {
            ParseResult::NativeRun(invocation) => {
                assert_eq!(
                    invocation.binary,
                    ArtifactRef::Prebuilt(PathBuf::from(probe))
                );
                match invocation.mode {
                    NativeRunMode::Replay { path, fingerprint } => {
                        assert_eq!(path, PathBuf::from("run.patina"));
                        assert_eq!(fingerprint, DEFAULT_NATIVE_FINGERPRINT);
                    }
                    _ => panic!("expected replay mode"),
                }
            }
            _ => panic!("expected native-run invocation from replay"),
        }
        // `replay` accepts host/build inputs the trace cannot carry ...
        assert!(
            parse(strings(&[
                "replay",
                probe,
                "run.patina",
                "--fingerprint",
                "fp"
            ]))
            .is_ok()
        );
        assert!(
            parse(strings(&[
                "replay",
                probe,
                "run.patina",
                "--mount",
                "corpus"
            ]))
            .is_ok()
        );
        // ... but rejects semantic knobs (the trace is authoritative) and a
        // missing trace path.
        assert!(
            parse(strings(&[
                "replay",
                probe,
                "run.patina",
                "--net-latency-nanos",
                "5"
            ]))
            .is_err()
        );
        assert!(parse(strings(&["replay", probe, "run.patina", "--seed", "1"])).is_err());
        assert!(parse(strings(&["replay", probe])).is_err());
    }

    #[test]
    fn parses_manifest_path_for_fingerprinting() {
        assert_eq!(
            manifest_path(&strings(&["--manifest-path", "nested/Cargo.toml"]))
                .unwrap()
                .unwrap(),
            OsStr::new("nested/Cargo.toml")
        );
    }
}
