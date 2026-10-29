//! Process-level implementation behind the `cargo-patina` binary.
//!
//! Internal crate: the `cargo patina` CLI — verb parsing (`build`, `run`,
//! `test`, `audit`, `replay`, `campaign`, `minimize`, `sites`, `trace`), artifact
//! resolution (a shim-linked native binary, or a source built into one),
//! build orchestration, the supervisor protocol that hands the `PATINA_*`
//! control plane to a guest, and result rendering (`--format json`,
//! `--render`). The user-facing contract is `cargo patina <verb> --help` (and
//! `--help --format json` for the machine-readable registry), not this crate's
//! API. See [ARCHITECTURE.md] for how the CLI drives the runtime.
//!
//! [ARCHITECTURE.md]: https://github.com/JacobHayes/patina/blob/main/ARCHITECTURE.md

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

use patina_dst_runtime::FaultKnob;
use patina_dst_trace::remove_dead_scratch;
use sha2::{Digest, Sha256};

// Additive output-side modules: HTML timeline rendering and the machine-readable
// `--output json` envelope. Both are read-only consumers of trace/runtime
// semantics — they never record, replay, or mutate a trace — so rendering or
// emitting an envelope cannot perturb replay hashes.
mod allocator_routing;
mod audit;
mod aux_store;
mod campaign;
mod cli;
mod coverage;
#[cfg(unix)]
mod crash_restart;
mod go_build;
mod guided;
mod harness;
mod help;
mod lifeline;
mod minimize;
mod native_build;
mod native_run;
mod output;
mod parse;
mod render;
mod rollup;
mod run_cache;
mod sdk_report;
mod seal;
mod shim_build;
mod shim_cache;
mod sites;
mod supervisor_identity;
mod syscalls;
mod trace_cmd;
mod trace_view;
mod values;

use audit::execute_native_audit;
use harness::execute_native_harness;
use native_build::{
    binary_instrumented, execute_native_build, instrumentation_fingerprint, resolve_artifact,
};
use native_run::{TRACE_CHANNEL_UNAVAILABLE, execute_native_run};
use parse::{ParseResult, current_verb, locate_positionals, parse};
use shim_build::lock_target_dir;

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
// Native supervisor descriptors are inherited at their already-open fd numbers;
// the child discovers them from `PATINA_RT_TRACE_FD` / `PATINA_RT_FS_IMAGE_FD`. Keeping
// the actual numbers avoids a macOS fork/exec edge where pre-exec
// relocation onto fixed low fds could still leave those fds closed after exec.
#[cfg(unix)]
const F_GETFD: i32 = 1;
#[cfg(unix)]
const F_SETFD: i32 = 2;
#[cfg(unix)]
const FD_CLOEXEC: i32 = 1;

#[cfg(unix)]
unsafe extern "C" {
    // Darwin arm64 passes anonymous arguments on the stack. A fixed-arity
    // declaration would place F_SETFD's argument in the wrong location.
    fn fcntl(fd: i32, cmd: i32, ...) -> i32;
}

// The one shared binding must satisfy the real C-variadic ABI, including on
// Darwin arm64. A fixed-arity declaration cannot inhabit this function type.
#[cfg(unix)]
const _: unsafe extern "C" fn(i32, i32, ...) -> i32 = fcntl;

#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn prctl(option: std::ffi::c_int, ...) -> std::ffi::c_int;
}

#[cfg(target_os = "linux")]
const _: unsafe extern "C" fn(std::ffi::c_int, ...) -> std::ffi::c_int = prctl;

struct NativeAuditInvocation {
    binary: ArtifactRef,
    allow: BTreeSet<String>,
    /// Audit a prebuilt native binary even when it is not shim-linked. Without
    /// it, `execute_native_audit` fails closed on a stock `cargo build` output
    /// (whose imports are unsatisfied libc calls, not the post-interposition
    /// residual). With it, the full audit runs anyway under a loud banner
    /// marking the import findings as pre-interposition.
    raw: bool,
}

struct NativeHarnessInvocation {
    origin: PathBuf,
    manifest: PathBuf,
    package: Option<String>,
    harness_target: String,
    exact: String,
    seeds: HarnessSeeds,
    release: bool,
    /// Cargo features (`--features`) forwarded verbatim to the harness build.
    features: HarnessFeatures,
    /// `--instrument`: build the native libtest harness with edge hooks (edge
    /// counters, and the scheduling points `--yield-stride` asks for).
    instrument: bool,
    /// Boundary-operation budget forwarded to each seed's child `run`.
    step_budget: Option<u64>,
    /// The `--realtime-epoch` timestamp, re-emitted verbatim onto each seed's
    /// child `run`.
    realtime_epoch: Option<String>,
    /// The `--hostname` name, re-emitted verbatim onto each seed's child `run`.
    hostname: Option<String>,
    /// The `--cpus` count, re-emitted onto each seed's child `run`.
    cpus: Option<u32>,
    /// The `--param` run parameters, re-emitted onto each seed's child `run`.
    params: BTreeMap<String, String>,
    /// Every fault knob this invocation set, re-emitted onto each seed's child
    /// `run` command line by [`knob_flag_pairs`].
    knobs: KnobValues,
    buggify: Option<NativeBuggify>,
    schedule: NativeSchedule,
    liveness: NativeLiveness,
    /// `--allow-randomized-address-layout`, re-emitted onto each seed's child
    /// `run` and onto the replay repro.
    allow_randomized_layout: bool,
}

/// Cargo feature selection for a native libtest harness build.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct HarnessFeatures {
    features: Option<String>,
}

impl HarnessFeatures {
    /// The `cargo rustc` arguments that reproduce this selection.
    fn cargo_args(&self) -> Vec<OsString> {
        let mut args = Vec::new();
        if let Some(features) = &self.features {
            args.push(OsString::from("--features"));
            args.push(OsString::from(features));
        }
        args
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HarnessSeeds {
    One(u64),
    Range(u64),
}

impl HarnessSeeds {
    fn iter(self) -> Box<dyn Iterator<Item = u64>> {
        match self {
            HarnessSeeds::One(seed) => Box::new(std::iter::once(seed)),
            HarnessSeeds::Range(count) => Box::new(0..count),
        }
    }

    fn label(self) -> String {
        match self {
            HarnessSeeds::One(seed) => format!("seed {seed}"),
            HarnessSeeds::Range(count) => format!("seeds 0..{count}"),
        }
    }

    fn contains(self, seed: u64) -> String {
        match self {
            HarnessSeeds::One(_) => format!("seed {seed}"),
            HarnessSeeds::Range(count) => format!("seed {seed} of 0..{count}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct NativeBuildInvocation {
    target: NativeBuildTarget,
    output: Option<PathBuf>,
    release: bool,
    /// `--instrument`: SanitizerCoverage edge hooks in every crate compiled
    /// from source, which keep edge counters and take the scheduling points a
    /// run's `--yield-stride` asks for. Off by default; plain native builds are
    /// unchanged.
    instrument: bool,
}

/// What `build` compiles for the native target: a single Rust source linked
/// directly with `rustc`, a whole Cargo package driven through its own
/// `cargo build`, or a Go main package driven through `go build`.
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
    /// A Go main package (`--go`): built by `go build` in cgo mode and linked
    /// externally with the shim ([`go_build`]).
    Go {
        package_dir: PathBuf,
        go_args: Vec<OsString>,
    },
}

/// A build-on-the-fly request captured at parse time and executed by the shared
/// build pipeline just before a run/audit/replay consumes its product. Carries
/// the user's original source argument (`origin`) so diagnostics name the source
/// rather than a throwaway temp path.
#[derive(Clone, Debug, PartialEq, Eq)]
struct BuildSpec {
    origin: PathBuf,
    build: NativeBuildInvocation,
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
    /// Deterministic guest environment values injected by native `run --env`.
    /// Recorded into trace metadata on `--record` and restored by replay.
    environment: BTreeMap<String, String>,
    /// Run parameters (`run --param`), forwarded as [`ENV_PARAMS_JSON`] and read
    /// by the guest through `patina_dst::param`. Recorded into trace metadata
    /// on `--record` and restored by replay.
    params: BTreeMap<String, String>,
    /// The guest's initial working directory (`run --cwd`), an absolute path in
    /// the deterministic filesystem; `None` is `/`. Recorded into trace
    /// metadata on `--record` and restored by replay like the environment.
    cwd: Option<String>,
    /// Maximum boundary operations before the run fails explicitly (`--budget`),
    /// forwarded over the control plane: the `RuntimeConfig::step_budget` the
    /// runtime enforces.
    step_budget: Option<u64>,
    /// The run's virtual realtime epoch in Unix-time nanoseconds
    /// (`--realtime-epoch`), forwarded as [`ENV_REALTIME_EPOCH_NANOS`]; `None`
    /// leaves the runtime default. Recorded into trace metadata on `--record`
    /// and restored by replay like the working directory.
    realtime_epoch_nanos: Option<u64>,
    /// The guest's node name (`--hostname`), forwarded as
    /// [`ENV_GUEST_HOSTNAME`] for the shim's `uname`/`gethostname`; `None`
    /// leaves the runtime default. Recorded and restored like the epoch.
    hostname: Option<String>,
    /// The guest's virtual CPU count (`--cpus`), forwarded as
    /// [`ENV_GUEST_CPUS`]; `None` leaves the runtime default. Recorded and
    /// restored like the node name; on replay a count is checked against the
    /// trace's and the trace's is what the guest gets.
    cpus: Option<u32>,
    /// Fault-injection knobs forwarded to the guest through the `PATINA_*`
    /// control plane. Each is a validated raw value stored verbatim; the runtime
    /// re-parses it identically on record and replay, so a mismatched flag on
    /// replay fails closed like any other operation divergence. The repeatable
    /// knobs (`--dns-entry`, `--net-partition`) ride the same table: they are
    /// semantic configuration, recorded into the trace and restored on replay, so
    /// `replay` refuses a re-supplied set.
    knobs: KnobValues,
    /// Cooperative-SUT (buggify) knobs, or `None` when `--buggify` was not
    /// passed. Presence enables buggify and folds `+buggify` into the run
    /// fingerprint.
    buggify: Option<NativeBuggify>,
    /// Exploration scheduling-policy (PCT) and swarm knobs. Enabling
    /// a non-default policy, swarm or a yield stride folds
    /// `+pct`/`+swarm`/`+yieldstride` into the run fingerprint.
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
    /// Host path where `run --coverage-out` writes the native yield-point edge
    /// counter map. The supervisor creates the file and passes its descriptor via
    /// `PATINA_RT_COVERAGE_FD`, so the shim never opens it through the deterministic
    /// filesystem. Native yield-point binaries only.
    coverage_out: Option<PathBuf>,
    /// Host directory to capture read-only into the guest filesystem, mounted at
    /// the guest root `/`. When set, the supervisor (which is not interposed)
    /// walks the tree into a deterministic `FsImage`, streams it to the guest
    /// over an inherited descriptor, and the shim rebuilds it as the
    /// deterministic filesystem. The image hash is folded into the run
    /// fingerprint so replay rejects a different corpus.
    mount: Option<PathBuf>,
    /// `--allow-randomized-address-layout`: launch the guest with the host's
    /// address-space randomization and inherited stack limit instead of the
    /// fixed layout, qualifying the run's determinism. Recorded into the trace;
    /// a replay must pass it exactly when the recording did.
    allow_randomized_layout: bool,
}

/// Every fault knob an invocation set, keyed by [`FaultKnob`] and stored as the
/// exact text the operator typed so the runtime re-parses the same protocol
/// string on record and on replay.
///
/// One store for both plumbing shapes: a [`Plumbing::Scalar`] knob holds at most
/// one value, a [`Plumbing::Repeatable`] one holds the whole set in CLI order.
/// Every family's plumbing — the native subprocess environment, the cargo
/// subprocess environment and its scrub list, and the native harness's
/// re-emitted `run` command line — iterates
/// [`FaultKnob::ALL`], so a knob added to the registry cannot be forwarded by one
/// family and silently dropped by another. There is no per-knob field, accessor
/// or forwarding row to forget: the CLI builds its knob rows from ALL through
/// an exhaustive grammar match, and everything else follows from it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct KnobValues(BTreeMap<FaultKnob, Vec<String>>);

impl KnobValues {
    /// The raw CLI texts supplied for one knob, empty when it was not set.
    fn get(&self, knob: FaultKnob) -> &[String] {
        self.0.get(&knob).map_or(&[], Vec::as_slice)
    }
}

/// Cooperative-SUT (buggify) knobs for `native-run`, forwarded to the guest as
/// validated raw strings through the `PATINA_RT_BUGGIFY*` control plane. Presence
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
/// the guest as validated raw strings through the `PATINA_SCHED_*`/`PATINA_RT_SWARM`
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
    /// `--swarm`: apply a seed-derived subset of the enabled fault classes.
    swarm: bool,
    /// `--yield-stride N`: an instrumented guest takes a scheduling point every
    /// Nth edge a thread executes; 0 (the default) takes none.
    yield_stride: u32,
}

/// Liveness-watchdog knobs, forwarded to the guest/runtime as validated raw
/// strings through the `PATINA_LIVENESS_*`/`PATINA_CONVERGE_*`/`PATINA_HEAL_*`
/// control plane. Virtual-time controls default off; the native compute bound
/// defaults to the shim's 10 seconds. Kept SEPARATE from [`NativeSchedule`]
/// because the watchdog is schedule-invariant: enabling it folds NO fingerprint
/// component (it only adds a possible violation report), so a watchdog trace
/// replays against any build.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct NativeLiveness {
    /// Native-only host-time terminal bound; never a schedule input.
    compute_watchdog_ms: Option<String>,
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

/// The compiler-driver arguments that route Rust's allocator entry points
/// through the arena router of the engine sealed from the shim archive
/// `staticlib`, for a link `cargo patina build` does not drive (the test
/// suites' C and C++ guests): the routing object is compiled into `dir` with
/// `cc`.
#[doc(hidden)]
pub fn shim_allocator_linker_args(staticlib: &Path, dir: &Path) -> Result<Vec<OsString>, CliError> {
    let routing = allocator_routing::AllocatorRouting::read(staticlib)?;
    let Some(defines) = routing.defines() else {
        return Ok(Vec::new());
    };
    let source = dir.join("patina_allocator_routing.S");
    let object = dir.join("patina_allocator_routing.o");
    fs::write(&source, allocator_routing::PATINA_ALLOCATOR_ROUTING_S)
        .map_err(|error| CliError(format!("staging {}: {error}", source.display())))?;
    let status = Command::new(env::var_os("CC").unwrap_or_else(|| "cc".into()))
        .args(&defines)
        .arg("-c")
        .arg(&source)
        .arg("-o")
        .arg(&object)
        .status()
        .map_err(|error| CliError(format!("compiling the allocator routing: {error}")))?;
    if !status.success() {
        return Err(CliError(
            "compiling the allocator routing failed".to_owned(),
        ));
    }
    Ok(routing.linker_args(&object))
}

/// Seal the shim archive `staticlib` with the C seams object `posix` into
/// `dir`, as `cargo patina build` seals it, for a link it does not drive:
/// returns the façade and the engine objects, which a guest links in place of
/// the two. Always seals afresh, replacing a previous seal in `dir`
/// atomically. Refuses an engine the seal's gate refuses.
#[doc(hidden)]
pub fn seal_shim(staticlib: &Path, posix: &Path, dir: &Path) -> Result<[PathBuf; 2], CliError> {
    let routing = allocator_routing::AllocatorRouting::read(staticlib)?;
    fs::create_dir_all(dir).map_err(|error| CliError(format!("{}: {error}", dir.display())))?;
    let stale = dir.join(seal::FACADE);
    if let Err(error) = fs::remove_file(&stale)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        return Err(CliError(format!("{}: {error}", stale.display())));
    }
    let sealed = seal::seal(staticlib, posix, &routing, dir)?;
    Ok([sealed.facade, sealed.engine])
}

pub fn entrypoint() -> Result<i32, CliError> {
    // A Go guest's build runs this executable as its `-toolexec` wrapper
    // around every Go tool; that role is not a verb, and it skips the
    // supervisor setup a run needs.
    let mut raw = env::args_os().skip(1);
    if raw.next().as_deref() == Some(OsStr::new(go_build::TOOLEXEC_ROLE)) {
        return go_build::run_as_toolexec(raw.collect());
    }
    lifeline::watch()?;
    supervisor_identity::establish()?;
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    // Strip the cross-cutting output flags (`--format`, `--render`,
    // `--report`) once, globally, before any per-verb routing —
    // the same pre-pass shape as `extract_target`. They are patina-level flags,
    // so they never reach the guest (anything after `--` is left in place).
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
        ParseResult::Help(topic) => {
            // `--help --format json` (the output pre-pass already stripped and
            // installed the format) emits the machine-readable registry scoped to
            // the same topic: the compact index for the overview, one verb's full
            // detail for a verb. The human form prints the focused section. Both
            // exit 0.
            if output::options().is_json() {
                print!("{}", help::render_json(topic));
            } else {
                print!("{}", help::render(topic));
            }
            Ok(0)
        }
        ParseResult::Version => {
            println!("cargo-patina {}", env!("CARGO_PKG_VERSION"));
            println!(
                "virtual Linux kernel: {} (pinned: Ubuntu 24.04's GA kernel)",
                patina_dst_syscalls::VIRTUAL_ABI
            );
            Ok(0)
        }
        ParseResult::Campaign(invocation) => campaign::execute(invocation),
        ParseResult::Coverage(invocation) => coverage::execute(invocation),
        ParseResult::Sites(options) => sites::execute(options),
        ParseResult::Syscalls(invocation) => syscalls::execute(invocation),
        ParseResult::NativeAudit(invocation) => execute_native_audit(invocation),
        ParseResult::NativeBuild(invocation) => execute_native_build(invocation),
        ParseResult::NativeRun(invocation) => execute_native_run(invocation),
        ParseResult::NativeHarness(invocation) => execute_native_harness(invocation),
        ParseResult::Minimize(invocation) => minimize::execute(invocation),
        ParseResult::Trace(invocation) => trace_cmd::execute(invocation),
    }
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
    /// A usage error: the specific message, then the offending verb's synopsis
    /// lines (or the compact top-level list before a verb is resolved) and a
    /// `--help` pointer — never the whole help wall.
    fn usage(message: impl Into<String>) -> Self {
        Self(format!(
            "{}\n\n{}",
            message.into(),
            help::usage_synopsis(current_verb())
        ))
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CliError {}

#[cfg(test)]
mod tests;

#[cfg(all(test, unix))]
use native_run::{NativeChildStatus, native_child_status};
#[cfg(test)]
use patina_dst_trace::create_scratch;
