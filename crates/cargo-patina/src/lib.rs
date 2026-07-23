//! Process-level implementation shared by `cargo-patina` and `cargo-dst`.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use patina_minimize::{
    MinimizeError, Scenario, minimize_all, minimize_branch_tree, minimize_main, minimize_timeline,
    reduce_scenario, reduce_schedule,
};
use patina_runtime::{
    Context, ENV_BRANCH_FROM, ENV_BRANCH_ID, ENV_BRANCH_SEED, ENV_FINGERPRINT, ENV_MODE,
    ENV_NET_LATENCY, ENV_PARAMS_JSON, ENV_PARENT_TIMELINE, ENV_SEED, ENV_STEP_BUDGET, ENV_TIMELINE,
    ENV_TRACE, ENV_TRACE_FD, RuntimeConfig,
};
use patina_target::{NativeAudit, WASI_PREVIEW1_TARGET, WasiAudit};
use patina_trace::TraceBundle;
use patina_wasi_host::{
    DEFAULT_WASM_FUEL, MountPolicy, Preview1Host, ResourceLimits, execute_preview1_with_fuel,
};
use sha2::{Digest, Sha256};

const PATINA_CFG_FLAGS: &str = "--cfg patina --cfg dst";

// The native link recipe is packaged into `cargo patina` so `native-build` can
// reproduce it without the source tree: the POSIX shim C layer and its header
// are embedded, compiled below the user program, and linked against the
// `patina-native-shim` staticlib.
const PATINA_POSIX_C: &str = include_str!("../../patina-native-shim/c/patina_posix.c");
const PATINA_NATIVE_H: &str = include_str!("../../patina-native-shim/include/patina_native.h");
const NATIVE_SHIM_STATICLIB: &str = "libpatina_native_shim.a";
const DEFAULT_NATIVE_EDITION: &str = "2024";
const DEFAULT_NATIVE_FINGERPRINT: &str = "patina-native";
/// Inherited descriptor `native-run` hands the child for the trace control
/// plane (`PATINA_TRACE_FD`), matching the supervisor channel the shim reads.
const PATINA_TRACE_CHANNEL_FD: i32 = 3;

const HELP: &str = "Patina deterministic Cargo runner

Usage:
  cargo patina <run|test> [PATINA OPTIONS] [CARGO OPTIONS] [-- PROGRAM OPTIONS]
  cargo patina explore <run|test> [--seeds N] [--start N] [PATINA/CARGO OPTIONS]
  cargo patina wasi-build [CARGO BUILD OPTIONS]
  cargo patina wasi-audit <MODULE.wasm>
  cargo patina wasi-run <MODULE.wasm> [PATINA OPTIONS] [--fuel N] [--arg VALUE] [--env K=V] [--socket FD=BIND->PEER] [--preopen GUEST[:ro|:rw]]...
  cargo patina native-audit <BINARY> [--allow SYMBOL]...
  cargo patina native-build <SOURCE.rs> --output <PATH> [--edition YEAR] [--release] [-- RUSTC OPTIONS]
  cargo patina native-build <DIR|Cargo.toml> [--output <PATH>] [--package NAME] [--bin NAME] [--release]
  cargo patina native-run <BINARY> [--seed N | --record PATH | --replay PATH] [--fingerprint STR] [--net-latency-nanos N] [-- PROGRAM ARGS]
  cargo patina minimize <TRACE> --output <PATH> [--timeline ID] [--prune-branches] -- <ORACLE> [ARGS]...
  cargo patina minimize --scenario --seed <U64> [--param K=V]... [--seed-budget N] -- <ORACLE> [ARGS]...
  cargo dst    <run|test> [PATINA OPTIONS] [CARGO OPTIONS] [-- PROGRAM OPTIONS]

Patina options:
      --seed <U64>       Deterministic root seed (default: 0)
      --record <PATH>    Record boundary operations and outcomes
      --replay <PATH>    Strictly replay a recorded trace
      --timeline <ID>    Replay a named timeline (default: main)
      --branch <PATH>    Replay a prefix and append a branch timeline
      --from <SEQUENCE>  Number of parent events in the exact branch prefix
      --branch-seed <N>  Root seed for branch suffix decisions
      --branch-id <ID>   New timeline identifier
      --parent <ID>      Parent timeline (default: main)
      --budget <STEPS>   Maximum boundary operations before explicit failure
      --param <K=V>      Typed-builder parameter exposed through Context
  -h, --help             Print help
  -V, --version          Print version

`--record`, `--replay`, and `--branch` are mutually exclusive. Replay gets its
root seed from the trace. All unrecognized options are forwarded to Cargo.

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

`native-build` packages the native linked-shim target: it builds the
`patina-native-shim` staticlib, compiles the embedded POSIX C layer, injects
`cfg(patina)`/`cfg(dst)`, and links the shim below the user program with `rustc`.
On Linux it also links `-Wl,--wrap=pthread_create` so the shim interposes thread
creation without dynamic loading; macOS needs no such flag.
A `.rs` path builds that single source directly. A directory (or `Cargo.toml`)
path instead drives the package's own `cargo build` under Patina control: the
same cfg flags and shim link arguments are injected through
`CARGO_ENCODED_RUSTFLAGS`, and an explicit host `--target` keeps them off build
scripts and proc macros (which link for the host). Select the member with
`--package` in a workspace and the binary with `--bin` when the package defines
more than one; `--output` copies the built binary out (otherwise its Cargo
artifact path is reported). The `patina-native-shim` staticlib is built from the
surrounding Patina workspace, so run `native-build` from within it.
`native-run` executes such a binary under the deterministic runtime; for
`--record`/`--replay` it opens the trace on the host and hands the child an
inherited `PATINA_TRACE_FD` descriptor so a fully interposed program never
recurses into the deterministic filesystem while finalizing its trace.

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
    module: PathBuf,
    mode: Mode,
    fuel: u64,
    arguments: Vec<String>,
    environment: BTreeMap<String, String>,
    sockets: Vec<WasiSocketConfig>,
    preopens: Vec<WasiPreopenConfig>,
    resource_limits: WasiResourceLimitOverrides,
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
    binary: PathBuf,
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
}

struct ExploreInvocation {
    invocation: Invocation,
    start_seed: u64,
    seed_count: u64,
}

struct NativeBuildInvocation {
    target: NativeBuildTarget,
    output: Option<PathBuf>,
    release: bool,
}

/// What `native-build` compiles: a single Rust source linked directly with
/// `rustc`, or a whole Cargo package driven through its own `cargo build`.
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

struct NativeRunInvocation {
    binary: PathBuf,
    mode: NativeRunMode,
    program_args: Vec<OsString>,
    net_latency_nanos: Option<u64>,
}

pub fn entrypoint() -> Result<i32, CliError> {
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
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
        ParseResult::Explore(invocation) => execute_explore(invocation),
        ParseResult::WasiBuild(arguments) => execute_wasi_build(arguments),
        ParseResult::WasiAudit(path) => execute_wasi_audit(&path),
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
    Explore(ExploreInvocation),
    WasiBuild(Vec<OsString>),
    WasiAudit(PathBuf),
    WasiRun(WasiInvocation),
    NativeAudit(NativeAuditInvocation),
    NativeBuild(NativeBuildInvocation),
    NativeRun(NativeRunInvocation),
    Minimize(MinimizeInvocation),
}

fn parse(mut arguments: Vec<OsString>) -> Result<ParseResult, CliError> {
    if matches!(
        arguments.first().and_then(|value| value.to_str()),
        Some("patina" | "dst")
    ) {
        arguments.remove(0);
    }
    if arguments.is_empty() {
        return Err(CliError::usage(
            "missing command (expected run, test, explore, wasi-build, wasi-audit, wasi-run, native-audit, native-build, native-run, or minimize)",
        ));
    }
    if arguments.first() == Some(&OsString::from("explore")) {
        arguments.remove(0);
        return parse_explore(arguments).map(ParseResult::Explore);
    }
    if arguments.first() == Some(&OsString::from("wasi-build")) {
        arguments.remove(0);
        return Ok(ParseResult::WasiBuild(arguments));
    }
    if arguments.first() == Some(&OsString::from("wasi-audit")) {
        arguments.remove(0);
        if arguments.len() != 1 {
            return Err(CliError::usage(
                "wasi-audit requires exactly one .wasm path",
            ));
        }
        return Ok(ParseResult::WasiAudit(PathBuf::from(arguments.remove(0))));
    }
    if arguments.first() == Some(&OsString::from("wasi-run")) {
        arguments.remove(0);
        return parse_wasi_run(arguments).map(ParseResult::WasiRun);
    }
    if arguments.first() == Some(&OsString::from("native-audit")) {
        arguments.remove(0);
        return parse_native_audit(arguments).map(ParseResult::NativeAudit);
    }
    if arguments.first() == Some(&OsString::from("native-build")) {
        arguments.remove(0);
        return parse_native_build(arguments).map(ParseResult::NativeBuild);
    }
    if arguments.first() == Some(&OsString::from("native-run")) {
        arguments.remove(0);
        return parse_native_run(arguments).map(ParseResult::NativeRun);
    }
    if arguments.first() == Some(&OsString::from("minimize")) {
        arguments.remove(0);
        return parse_minimize(arguments).map(ParseResult::Minimize);
    }
    if matches!(
        arguments.first().and_then(|value| value.to_str()),
        Some("-h" | "--help")
    ) {
        return Ok(ParseResult::Help);
    }
    if matches!(
        arguments.first().and_then(|value| value.to_str()),
        Some("-V" | "--version")
    ) {
        return Ok(ParseResult::Version);
    }

    let command = arguments
        .remove(0)
        .into_string()
        .map_err(|_| CliError::usage("Cargo command is not valid UTF-8 (expected run or test)"))?;
    if command != "run" && command != "test" {
        return Err(CliError::usage(format!(
            "unsupported Cargo command {command:?}; expected run or test"
        )));
    }

    let mut seed = None;
    let mut record = None;
    let mut replay = None;
    let mut timeline = None;
    let mut branch = None;
    let mut branch_from = None;
    let mut branch_seed = None;
    let mut branch_id = None;
    let mut parent = None;
    let mut step_budget = None;
    let mut params = BTreeMap::new();
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
        } else if let Some(value) = text.and_then(|value| value.strip_prefix("--replay=")) {
            set_once(&mut replay, PathBuf::from(value), "--replay")?;
        } else if text == Some("--replay") {
            index += 1;
            let value = arguments
                .get(index)
                .ok_or_else(|| CliError::usage("--replay requires a path"))?;
            set_once(&mut replay, PathBuf::from(value), "--replay")?;
        } else if text == Some("--timeline") {
            index += 1;
            let value = utf8_argument(&arguments, index, "--timeline")?;
            set_once(&mut timeline, value.into(), "--timeline")?;
        } else if text == Some("--branch") {
            index += 1;
            let value = arguments
                .get(index)
                .ok_or_else(|| CliError::usage("--branch requires a path"))?;
            set_once(&mut branch, PathBuf::from(value), "--branch")?;
        } else if text == Some("--from") {
            index += 1;
            let value = utf8_argument(&arguments, index, "--from")?;
            set_once(&mut branch_from, parse_u64("--from", value)?, "--from")?;
        } else if text == Some("--branch-seed") {
            index += 1;
            let value = utf8_argument(&arguments, index, "--branch-seed")?;
            set_once(
                &mut branch_seed,
                parse_u64("--branch-seed", value)?,
                "--branch-seed",
            )?;
        } else if text == Some("--branch-id") {
            index += 1;
            let value = utf8_argument(&arguments, index, "--branch-id")?;
            set_once(&mut branch_id, value.into(), "--branch-id")?;
        } else if text == Some("--parent") {
            index += 1;
            let value = utf8_argument(&arguments, index, "--parent")?;
            set_once(&mut parent, value.into(), "--parent")?;
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
        } else {
            cargo_args.push(argument.clone());
        }
        index += 1;
    }

    let selected_modes = usize::from(record.is_some())
        + usize::from(replay.is_some())
        + usize::from(branch.is_some());
    if selected_modes > 1 {
        return Err(CliError::usage(
            "--record, --replay, and --branch are mutually exclusive",
        ));
    }
    if (replay.is_some() || branch.is_some()) && seed.is_some() {
        return Err(CliError::usage(
            "--seed cannot be combined with --replay or --branch",
        ));
    }
    let seed = seed.unwrap_or(0);
    let mode = if let Some(path) = record {
        reject_branch_only_options(&timeline, &branch_from, &branch_seed, &branch_id, &parent)?;
        Mode::Record { seed, path }
    } else if let Some(path) = replay {
        if branch_from.is_some() || branch_seed.is_some() || branch_id.is_some() || parent.is_some()
        {
            return Err(CliError::usage(
                "branch options require --branch, not --replay",
            ));
        }
        Mode::Replay {
            path,
            timeline: timeline.unwrap_or_else(|| "main".into()),
        }
    } else if let Some(path) = branch {
        if timeline.is_some() {
            return Err(CliError::usage("--timeline is only valid with --replay"));
        }
        Mode::Branch {
            path,
            parent: parent.unwrap_or_else(|| "main".into()),
            from_sequence: branch_from
                .ok_or_else(|| CliError::usage("--branch requires --from"))?,
            branch_seed: branch_seed
                .ok_or_else(|| CliError::usage("--branch requires --branch-seed"))?,
            branch_id: branch_id.ok_or_else(|| CliError::usage("--branch requires --branch-id"))?,
        }
    } else {
        reject_branch_only_options(&timeline, &branch_from, &branch_seed, &branch_id, &parent)?;
        Mode::Seeded { seed }
    };

    Ok(ParseResult::Run(Invocation {
        cargo_command: command,
        cargo_args,
        mode,
        step_budget,
        params,
    }))
}

fn parse_wasi_run(mut arguments: Vec<OsString>) -> Result<WasiInvocation, CliError> {
    if arguments.is_empty() {
        return Err(CliError::usage("wasi-run requires a .wasm path"));
    }
    let module = PathBuf::from(arguments.remove(0));
    let mut seed = None;
    let mut record = None;
    let mut replay = None;
    let mut branch = None;
    let mut timeline = None;
    let mut branch_from = None;
    let mut branch_seed = None;
    let mut branch_id = None;
    let mut parent = None;
    let mut fuel = None;
    let mut guest_arguments = Vec::new();
    let mut guest_environment = BTreeMap::new();
    let mut guest_sockets = Vec::new();
    let mut guest_preopens = Vec::new();
    let mut resource_limits = WasiResourceLimitOverrides::default();
    let mut socket_fds = BTreeSet::new();
    let mut index = 0;
    while index < arguments.len() {
        let name = arguments[index].to_string_lossy();
        index += 1;
        let value = arguments
            .get(index)
            .ok_or_else(|| CliError::usage(format!("{name} requires a value")))?;
        match name.as_ref() {
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
            "--replay" => set_once(&mut replay, PathBuf::from(value), "--replay")?,
            "--branch" => set_once(&mut branch, PathBuf::from(value), "--branch")?,
            "--from" => set_once(
                &mut branch_from,
                parse_u64(
                    "--from",
                    value
                        .to_str()
                        .ok_or_else(|| CliError::usage("--from requires UTF-8"))?,
                )?,
                "--from",
            )?,
            "--branch-seed" => set_once(
                &mut branch_seed,
                parse_u64(
                    "--branch-seed",
                    value
                        .to_str()
                        .ok_or_else(|| CliError::usage("--branch-seed requires UTF-8"))?,
                )?,
                "--branch-seed",
            )?,
            "--branch-id" => set_once(
                &mut branch_id,
                value
                    .to_str()
                    .ok_or_else(|| CliError::usage("--branch-id requires UTF-8"))?
                    .into(),
                "--branch-id",
            )?,
            "--parent" => set_once(
                &mut parent,
                value
                    .to_str()
                    .ok_or_else(|| CliError::usage("--parent requires UTF-8"))?
                    .into(),
                "--parent",
            )?,
            "--timeline" => set_once(
                &mut timeline,
                value
                    .to_str()
                    .ok_or_else(|| CliError::usage("--timeline requires UTF-8"))?
                    .into(),
                "--timeline",
            )?,
            "--fuel" => {
                let parsed = parse_u64(
                    "--fuel",
                    value
                        .to_str()
                        .ok_or_else(|| CliError::usage("--fuel requires UTF-8"))?,
                )?;
                set_once(&mut fuel, parsed, "--fuel")?;
                set_once(&mut resource_limits.fuel, parsed, "--fuel")?;
            }
            "--arg" => guest_arguments.push(
                value
                    .to_str()
                    .ok_or_else(|| CliError::usage("--arg requires UTF-8"))?
                    .into(),
            ),
            "--socket" => {
                let value = value
                    .to_str()
                    .ok_or_else(|| CliError::usage("--socket requires UTF-8"))?;
                let (fd, route) = value
                    .split_once('=')
                    .ok_or_else(|| CliError::usage("--socket requires FD=BIND->PEER"))?;
                let fd = fd.parse::<u32>().map_err(|_| {
                    CliError::usage("--socket FD must be an unsigned 32-bit integer")
                })?;
                let (bind, peer) = route
                    .split_once("->")
                    .ok_or_else(|| CliError::usage("--socket requires FD=BIND->PEER"))?;
                if fd <= 3 || bind.is_empty() || peer.is_empty() || !socket_fds.insert(fd) {
                    return Err(CliError::usage(
                        "--socket requires a unique FD above 3 and non-empty addresses",
                    ));
                }
                guest_sockets.push(WasiSocketConfig {
                    fd,
                    bind: bind.into(),
                    peer: peer.into(),
                });
            }
            "--env" => {
                let value = value
                    .to_str()
                    .ok_or_else(|| CliError::usage("--env requires UTF-8"))?;
                let (key, value) = value
                    .split_once('=')
                    .ok_or_else(|| CliError::usage("--env requires KEY=VALUE"))?;
                if key.is_empty() || guest_environment.insert(key.into(), value.into()).is_some() {
                    return Err(CliError::usage("--env keys must be non-empty and unique"));
                }
            }
            "--preopen" => {
                let value = value
                    .to_str()
                    .ok_or_else(|| CliError::usage("--preopen requires UTF-8"))?;
                guest_preopens.push(parse_wasi_preopen(value)?);
            }
            "--max-memory-pages" => {
                let value = value
                    .to_str()
                    .ok_or_else(|| CliError::usage("--max-memory-pages requires UTF-8"))?;
                set_once(
                    &mut resource_limits.max_memory_pages,
                    parse_u32("--max-memory-pages", value)?,
                    "--max-memory-pages",
                )?;
            }
            "--max-descriptors" => {
                let value = value
                    .to_str()
                    .ok_or_else(|| CliError::usage("--max-descriptors requires UTF-8"))?;
                set_once(
                    &mut resource_limits.max_descriptors,
                    parse_usize("--max-descriptors", value)?,
                    "--max-descriptors",
                )?;
            }
            "--max-preopens" => {
                let value = value
                    .to_str()
                    .ok_or_else(|| CliError::usage("--max-preopens requires UTF-8"))?;
                set_once(
                    &mut resource_limits.max_preopens,
                    parse_usize("--max-preopens", value)?,
                    "--max-preopens",
                )?;
            }
            "--max-path-bytes" => {
                let value = value
                    .to_str()
                    .ok_or_else(|| CliError::usage("--max-path-bytes requires UTF-8"))?;
                set_once(
                    &mut resource_limits.max_path_bytes,
                    parse_usize("--max-path-bytes", value)?,
                    "--max-path-bytes",
                )?;
            }
            "--max-io-bytes" => {
                let value = value
                    .to_str()
                    .ok_or_else(|| CliError::usage("--max-io-bytes requires UTF-8"))?;
                set_once(
                    &mut resource_limits.max_io_bytes,
                    parse_usize("--max-io-bytes", value)?,
                    "--max-io-bytes",
                )?;
            }
            "--max-iovecs" => {
                let value = value
                    .to_str()
                    .ok_or_else(|| CliError::usage("--max-iovecs requires UTF-8"))?;
                set_once(
                    &mut resource_limits.max_iovecs,
                    parse_usize("--max-iovecs", value)?,
                    "--max-iovecs",
                )?;
            }
            _ => {
                return Err(CliError::usage(format!(
                    "unsupported wasi-run option {name:?}"
                )));
            }
        }
        index += 1;
    }
    let mode_count = usize::from(record.is_some())
        + usize::from(replay.is_some())
        + usize::from(branch.is_some());
    if mode_count > 1 {
        return Err(CliError::usage(
            "wasi-run --record, --replay, and --branch are mutually exclusive",
        ));
    }
    if replay.is_some() && seed.is_some() {
        return Err(CliError::usage(
            "wasi-run --seed cannot be combined with --replay",
        ));
    }
    let mode = if let Some(path) = record {
        reject_branch_only_options(&timeline, &branch_from, &branch_seed, &branch_id, &parent)?;
        Mode::Record {
            seed: seed.unwrap_or(0),
            path,
        }
    } else if let Some(path) = replay {
        if branch_from.is_some() || branch_seed.is_some() || branch_id.is_some() || parent.is_some()
        {
            return Err(CliError::usage("branch options require wasi-run --branch"));
        }
        Mode::Replay {
            path,
            timeline: timeline.unwrap_or_else(|| "main".into()),
        }
    } else if let Some(path) = branch {
        if seed.is_some() || timeline.is_some() {
            return Err(CliError::usage(
                "wasi-run --branch does not accept --seed or --timeline",
            ));
        }
        Mode::Branch {
            path,
            parent: parent.unwrap_or_else(|| "main".into()),
            from_sequence: branch_from
                .ok_or_else(|| CliError::usage("wasi-run --branch requires --from"))?,
            branch_seed: branch_seed
                .ok_or_else(|| CliError::usage("wasi-run --branch requires --branch-seed"))?,
            branch_id: branch_id
                .ok_or_else(|| CliError::usage("wasi-run --branch requires --branch-id"))?,
        }
    } else {
        reject_branch_only_options(&timeline, &branch_from, &branch_seed, &branch_id, &parent)?;
        Mode::Seeded {
            seed: seed.unwrap_or(0),
        }
    };
    Ok(WasiInvocation {
        module,
        mode,
        fuel: fuel.unwrap_or(DEFAULT_WASM_FUEL),
        arguments: guest_arguments,
        environment: guest_environment,
        sockets: guest_sockets,
        preopens: guest_preopens,
        resource_limits,
    })
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
    let invocation = match parse(forwarded)? {
        ParseResult::Run(invocation) => invocation,
        _ => {
            return Err(CliError::usage(
                "explore requires a Cargo run or test command",
            ));
        }
    };
    let mode_seed = match &invocation.mode {
        Mode::Seeded { seed } => *seed,
        _ => {
            return Err(CliError::usage(
                "explore does not accept record, replay, or branch mode",
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
        invocation,
        start_seed,
        seed_count,
    })
}

fn parse_native_audit(mut arguments: Vec<OsString>) -> Result<NativeAuditInvocation, CliError> {
    if arguments.is_empty() {
        return Err(CliError::usage("native-audit requires a binary path"));
    }
    let binary = PathBuf::from(arguments.remove(0));
    let mut allow = BTreeSet::new();
    let mut index = 0;
    while index < arguments.len() {
        if arguments[index] != "--allow" {
            return Err(CliError::usage(format!(
                "unsupported native-audit option {:?}",
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
            "native-build requires a Rust source path or a Cargo package",
        ));
    }
    let path = PathBuf::from(arguments.remove(0));
    let mut output = None;
    let mut edition = None;
    let mut release = false;
    let mut package = None;
    let mut bin = None;
    let mut index = 0;
    while index < arguments.len() {
        let option = arguments[index]
            .to_str()
            .ok_or_else(|| CliError::usage("native-build options must be valid UTF-8"))?;
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
                    "unsupported native-build option {option:?}"
                )));
            }
        }
        index += 1;
    }

    if is_native_package_path(&path) {
        if let Some(rustc_arg) = rustc_args.first() {
            return Err(CliError::usage(format!(
                "trailing rustc options ({rustc_arg:?}) apply to single-source native-build, not package builds"
            )));
        }
        if edition.is_some() {
            return Err(CliError::usage(
                "--edition applies to single-source native-build; a package's edition comes from its Cargo.toml",
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
        })
    } else {
        if package.is_some() || bin.is_some() {
            return Err(CliError::usage(
                "--package and --bin apply to Cargo-package native-build, not a single source file",
            ));
        }
        let output =
            output.ok_or_else(|| CliError::usage("native-build requires --output <PATH>"))?;
        Ok(NativeBuildInvocation {
            target: NativeBuildTarget::Source {
                source: path,
                edition: edition.unwrap_or_else(|| DEFAULT_NATIVE_EDITION.to_string()),
                rustc_args,
            },
            output: Some(output),
            release,
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

fn parse_native_run(mut arguments: Vec<OsString>) -> Result<NativeRunInvocation, CliError> {
    let program_args = split_trailing_args(&mut arguments);
    if arguments.is_empty() {
        return Err(CliError::usage("native-run requires a binary path"));
    }
    let binary = PathBuf::from(arguments.remove(0));
    let mut seed = None;
    let mut record = None;
    let mut replay = None;
    let mut fingerprint = None;
    let mut net_latency_nanos = None;
    let mut index = 0;
    while index < arguments.len() {
        let option = arguments[index]
            .to_str()
            .ok_or_else(|| CliError::usage("native-run options must be valid UTF-8"))?;
        match option {
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
            "--record" => {
                index += 1;
                let path = arguments
                    .get(index)
                    .ok_or_else(|| CliError::usage("--record requires a path"))?;
                set_once(&mut record, PathBuf::from(path), "--record")?;
            }
            "--replay" => {
                index += 1;
                let path = arguments
                    .get(index)
                    .ok_or_else(|| CliError::usage("--replay requires a path"))?;
                set_once(&mut replay, PathBuf::from(path), "--replay")?;
            }
            "--fingerprint" => {
                index += 1;
                let value = utf8_argument(&arguments, index, "--fingerprint")?;
                set_once(&mut fingerprint, value.to_string(), "--fingerprint")?;
            }
            _ => {
                return Err(CliError::usage(format!(
                    "unsupported native-run option {option:?}"
                )));
            }
        }
        index += 1;
    }
    if record.is_some() && replay.is_some() {
        return Err(CliError::usage(
            "--record and --replay are mutually exclusive",
        ));
    }
    let fingerprint = fingerprint.unwrap_or_else(|| DEFAULT_NATIVE_FINGERPRINT.to_string());
    let mode = if let Some(path) = record {
        NativeRunMode::Record {
            seed: seed.unwrap_or(0),
            path,
            fingerprint,
        }
    } else if let Some(path) = replay {
        if seed.is_some() {
            return Err(CliError::usage(
                "--seed cannot be combined with --replay; replay takes its seed from the trace",
            ));
        }
        NativeRunMode::Replay { path, fingerprint }
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

fn reject_branch_only_options(
    timeline: &Option<String>,
    branch_from: &Option<u64>,
    branch_seed: &Option<u64>,
    branch_id: &Option<String>,
    parent: &Option<String>,
) -> Result<(), CliError> {
    if timeline.is_some()
        || branch_from.is_some()
        || branch_seed.is_some()
        || branch_id.is_some()
        || parent.is_some()
    {
        return Err(CliError::usage(
            "timeline/branch options require --replay or --branch",
        ));
    }
    Ok(())
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
    let bytes = fs::read(&invocation.module).map_err(|error| {
        CliError(format!(
            "failed to read WebAssembly module {}: {error}",
            invocation.module.display()
        ))
    })?;
    let fingerprint = wasi_compatibility_fingerprint(&bytes, &invocation);
    let config = match &invocation.mode {
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
    let context = Context::from_config(config).map_err(|error| CliError(error.to_string()))?;
    let host = configured_wasi_host(&invocation, context)?;
    let execution = execute_preview1_with_fuel(&bytes, host, invocation.fuel)
        .map_err(|error| CliError(error.to_string()))?;
    std::io::stdout()
        .write_all(&execution.stdout)
        .map_err(|error| CliError(format!("failed to write captured WASI stdout: {error}")))?;
    std::io::stderr()
        .write_all(&execution.stderr)
        .map_err(|error| CliError(format!("failed to write captured WASI stderr: {error}")))?;
    Ok(execution.exit_code)
}

fn configured_wasi_host(
    invocation: &WasiInvocation,
    context: Context,
) -> Result<Preview1Host, CliError> {
    let mut host = Preview1Host::new(context)
        .with_resource_limits(invocation.resource_limits.to_host_limits())
        .with_argument(invocation.module.to_string_lossy().into_owned());
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

fn wasi_compatibility_fingerprint(bytes: &[u8], invocation: &WasiInvocation) -> String {
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

fn execute_wasi_build(arguments: Vec<OsString>) -> Result<i32, CliError> {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let status = Command::new(cargo)
        .arg("build")
        .arg("--target")
        .arg(WASI_PREVIEW1_TARGET)
        .args(arguments)
        .env("RUSTFLAGS", patina_rustflags())
        .status()
        .map_err(|error| CliError(format!("failed to execute WASI Cargo build: {error}")))?;
    exit_code(status)
}

fn execute_wasi_audit(path: &Path) -> Result<i32, CliError> {
    let bytes = fs::read(path).map_err(|error| {
        CliError(format!(
            "failed to read WebAssembly module {}: {error}",
            path.display()
        ))
    })?;
    let audit = WasiAudit::audit(&bytes).map_err(|error| CliError(error.to_string()))?;
    for import in audit.imports {
        println!("{}::{}", import.module, import.name);
    }
    Ok(0)
}

fn execute_explore(exploration: ExploreInvocation) -> Result<i32, CliError> {
    for offset in 0..exploration.seed_count {
        let seed = exploration
            .start_seed
            .checked_add(offset)
            .expect("exploration range was validated");
        let mut invocation = exploration.invocation.clone();
        invocation.mode = Mode::Seeded { seed };
        let exit = execute(invocation)?;
        if exit != 0 {
            eprintln!("PATINA_EXPLORE_FAILURE seed={seed} exit={exit}");
            return Ok(exit);
        }
    }
    println!(
        "PATINA_EXPLORE_COMPLETE start={} seeds={}",
        exploration.start_seed, exploration.seed_count
    );
    Ok(0)
}

fn execute_native_audit(invocation: NativeAuditInvocation) -> Result<i32, CliError> {
    let bytes = fs::read(&invocation.binary).map_err(|error| {
        CliError(format!(
            "failed to read native binary {}: {error}",
            invocation.binary.display()
        ))
    })?;
    let audit = NativeAudit::audit(&bytes, &invocation.allow)
        .map_err(|error| CliError(error.to_string()))?;
    for import in audit.imports {
        println!("{import}");
    }
    Ok(0)
}

fn link_arg(path: &Path) -> OsString {
    let mut arg = OsString::from("link-arg=");
    arg.push(path);
    arg
}

/// Build the `patina-native-shim` staticlib and return its path. The shim's
/// Rust boundary is produced by Cargo; the C POSIX layer and header are packaged
/// into this binary and compiled at link time by [`execute_native_build`].
fn build_native_shim(release: bool) -> Result<PathBuf, CliError> {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let mut command = Command::new(&cargo);
    command.arg("build").arg("-p").arg("patina-native-shim");
    if release {
        command.arg("--release");
    }
    let status = command
        .status()
        .map_err(|error| CliError(format!("failed to build patina-native-shim: {error}")))?;
    if !status.success() {
        return Err(CliError(
            "building the patina-native-shim staticlib failed".into(),
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

fn execute_native_build(invocation: NativeBuildInvocation) -> Result<i32, CliError> {
    let staticlib = build_native_shim(invocation.release)?;

    // Materialize the embedded POSIX shim layer and compile it below the user
    // program, matching the flags the deterministic linked target requires. The
    // workspace outlives both build paths so the object stays valid for linking.
    let workdir = tempfile::tempdir()
        .map_err(|error| CliError(format!("failed to create native build workspace: {error}")))?;
    let object = compile_posix_object(workdir.path())?;

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
        ),
    }
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
/// `configure`. On Linux the shim interposes thread creation by wrapping
/// `pthread_create` at link time, because glibc has no suspended-create variant
/// and dynamic loading (`dlsym`) stays denied by the audit on every platform;
/// macOS uses `pthread_create_suspended_np` and needs no wrapping. The shim
/// objects also land after the toolchain's own `-lc`, and glibc's `atexit`
/// lives in `libc_nonshared.a` (reached through the `libc.so` linker script);
/// GNU ld scans archives in a single pass, so libc must be scanned again after
/// the shim objects introduce their references.
fn push_platform_link_args(mut configure: impl FnMut(&str)) {
    #[cfg(target_os = "linux")]
    {
        configure("link-arg=-Wl,--wrap=pthread_create");
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
    rustc_args: &[OsString],
) -> Result<i32, CliError> {
    let rustc = env::var_os("RUSTC").unwrap_or_else(|| OsString::from("rustc"));
    let mut command = Command::new(&rustc);
    command
        .arg("--edition")
        .arg(edition)
        .args(["--cfg", "patina", "--cfg", "dst"])
        .arg("-C")
        .arg(link_arg(object))
        .arg("-C")
        .arg(link_arg(staticlib));
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
    println!("PATINA_NATIVE_BUILD output={}", output.display());
    Ok(0)
}

/// Drive a Cargo package's own `cargo build` under Patina control. The cfg
/// flags and shim link arguments are injected through `CARGO_ENCODED_RUSTFLAGS`,
/// and an explicit host `--target` isolates them to the final binary: rustc
/// records link arguments only at the binary link step (rlib compilation
/// ignores them), and building for an explicit target keeps them off build
/// scripts and proc macros, which Cargo compiles for the host without these
/// flags.
fn build_native_package(
    manifest: &Path,
    package: Option<&str>,
    bin: Option<&str>,
    output: Option<&Path>,
    release: bool,
    object: &Path,
    staticlib: &Path,
) -> Result<i32, CliError> {
    if !manifest.is_file() {
        return Err(CliError(format!(
            "no Cargo manifest at {}",
            manifest.display()
        )));
    }
    let selected = select_native_package_bin(manifest, package, bin)?;
    let host_target = host_target_triple()?;
    let rustflags = native_package_rustflags(object, staticlib);

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
    println!("PATINA_NATIVE_BUILD output={}", final_path.display());
    Ok(0)
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
fn native_package_rustflags(object: &Path, staticlib: &Path) -> OsString {
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
    tokens.push(OsString::from("-C"));
    tokens.push(link_arg(object));
    tokens.push(OsString::from("-C"));
    tokens.push(link_arg(staticlib));
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
    // F_SETFD with flags 0 clears FD_CLOEXEC on macOS and Linux.
    const F_SETFD: i32 = 2;

    let binary = fs::canonicalize(&invocation.binary).map_err(|error| {
        CliError(format!(
            "failed to resolve native program {}: {error}",
            invocation.binary.display()
        ))
    })?;
    let mut command = Command::new(&binary);
    command.args(&invocation.program_args).env_clear();
    if let Some(latency) = invocation.net_latency_nanos {
        command.env(ENV_NET_LATENCY, latency.to_string());
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
                .env(ENV_FINGERPRINT, fingerprint)
                .env(ENV_TRACE_FD, PATINA_TRACE_CHANNEL_FD.to_string());
            Some(file)
        }
        NativeRunMode::Replay { path, fingerprint } => {
            let file = fs::File::open(path).map_err(|error| {
                CliError(format!("failed to open trace {}: {error}", path.display()))
            })?;
            command
                .env(ENV_MODE, "replay")
                .env(ENV_FINGERPRINT, fingerprint)
                .env(ENV_TRACE_FD, PATINA_TRACE_CHANNEL_FD.to_string());
            Some(file)
        }
    };

    if let Some(file) = &trace_file {
        let source_fd = file.as_raw_fd();
        // SAFETY: `dup2` and `fcntl` are async-signal-safe, so they are sound to
        // call between fork and exec. This installs the trace descriptor at the
        // well-known number the shim reads. `dup2` normally clears close-on-exec
        // on the new descriptor, but when the source already sits at the target
        // number it is a no-op that leaves the flag set, so clear it explicitly;
        // otherwise the descriptor would close at exec and the child's trace
        // write would hit a bad descriptor.
        unsafe {
            command.pre_exec(move || {
                if dup2(source_fd, PATINA_TRACE_CHANNEL_FD) < 0 {
                    return Err(io::Error::last_os_error());
                }
                if fcntl(PATINA_TRACE_CHANNEL_FD, F_SETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    let status = command.status().map_err(|error| {
        CliError(format!(
            "failed to run native program {}: {error}",
            binary.display()
        ))
    })?;
    drop(trace_file);
    exit_code(status)
}

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
    println!(
        "PATINA_MINIMIZE_COMPLETE before={before} after={after} oracle_runs={calls} output={}",
        invocation.output.display()
    );
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
    println!(
        "PATINA_MINIMIZE_SCENARIO_COMPLETE seed={} params=[{params}] oracle_runs={calls}",
        reduced.seed
    );
    Ok(0)
}

fn execute(invocation: Invocation) -> Result<i32, CliError> {
    let workspace = workspace_root(&invocation.cargo_args)?;
    ensure_lockfile(&workspace)?;
    let fingerprint = compatibility_fingerprint(&workspace, &invocation)?;
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let mut command = Command::new(cargo);
    command
        .arg(&invocation.cargo_command)
        .args(&invocation.cargo_args)
        .env("RUSTFLAGS", patina_rustflags())
        .env(ENV_FINGERPRINT, fingerprint)
        .env_remove(ENV_MODE)
        .env_remove(ENV_SEED)
        .env_remove(ENV_TRACE)
        .env_remove(ENV_TIMELINE)
        .env_remove(ENV_BRANCH_FROM)
        .env_remove(ENV_BRANCH_SEED)
        .env_remove(ENV_BRANCH_ID)
        .env_remove(ENV_PARENT_TIMELINE)
        .env_remove(ENV_STEP_BUDGET)
        .env_remove(ENV_PARAMS_JSON);
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

    let status = command
        .status()
        .map_err(|error| CliError(format!("failed to execute Cargo: {error}")))?;
    exit_code(status)
}

fn workspace_root(cargo_args: &[OsString]) -> Result<PathBuf, CliError> {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let mut command = Command::new(cargo);
    command.args(["locate-project", "--workspace", "--message-format", "plain"]);
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

    fn wasi_invocation(values: &[&str]) -> WasiInvocation {
        match parse(strings(values)).unwrap() {
            ParseResult::WasiRun(value) => value,
            _ => panic!("expected wasi-run invocation"),
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
            invocation(&["dst", "test", "--record", "run.patina"]).mode,
            Mode::Record {
                seed: 0,
                path: "run.patina".into()
            }
        );
        assert_eq!(
            invocation(&["test", "--replay=run.patina"]).mode,
            Mode::Replay {
                path: "run.patina".into(),
                timeline: "main".into(),
            }
        );
        assert_eq!(
            invocation(&[
                "run",
                "--branch",
                "run.patina",
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
        assert!(parse(strings(&["test", "--record", "a", "--replay", "b"])).is_err());
        assert!(parse(strings(&["test", "--seed", "1", "--replay", "a"])).is_err());
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
                assert_eq!(exploration.invocation.cargo_command, "test");
                assert_eq!(exploration.invocation.cargo_args, strings(&["--release"]));
            }
            _ => panic!("expected exploration"),
        }
        assert!(parse(strings(&["explore", "test", "--seeds", "0"])).is_err());
        assert!(parse(strings(&["explore", "test", "--record", "run.patina"])).is_err());
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

    fn clock_event(sequence: u64, value: u64) -> patina_trace::TraceEvent {
        patina_trace::TraceEvent {
            sequence,
            operation: patina_abi::Operation::ClockNow {
                clock: patina_abi::ClockKind::Monotonic,
            },
            outcome: patina_abi::Outcome::U64(value),
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
        use patina_abi::Outcome;
        use patina_trace::RunMetadata;

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
        use patina_trace::{RunMetadata, Timeline};
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
        use patina_abi::Outcome;

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
        use patina_abi::Outcome;

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
    fn parses_wasi_build_and_audit_commands() {
        match parse(strings(&["wasi-build", "--release"])).unwrap() {
            ParseResult::WasiBuild(arguments) => assert_eq!(arguments, strings(&["--release"])),
            _ => panic!("expected wasi-build"),
        }
        match parse(strings(&["wasi-audit", "module.wasm"])).unwrap() {
            ParseResult::WasiAudit(path) => assert_eq!(path, PathBuf::from("module.wasm")),
            _ => panic!("expected wasi-audit"),
        }
        match parse(strings(&[
            "native-audit",
            "probe",
            "--allow",
            "write",
            "--allow",
            "clock_gettime",
        ]))
        .unwrap()
        {
            ParseResult::NativeAudit(invocation) => {
                assert_eq!(invocation.binary, PathBuf::from("probe"));
                assert!(invocation.allow.contains("write"));
                assert!(invocation.allow.contains("clock_gettime"));
            }
            _ => panic!("expected native-audit"),
        }
        match parse(strings(&[
            "wasi-run",
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
        .unwrap()
        {
            ParseResult::WasiRun(invocation) => {
                assert_eq!(invocation.module, PathBuf::from("module.wasm"));
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
            }
            _ => panic!("expected wasi-run"),
        }
        match parse(strings(&[
            "wasi-run",
            "module.wasm",
            "--branch",
            "run.patina",
            "--from",
            "3",
            "--branch-seed",
            "8",
            "--branch-id",
            "wasi-branch",
        ]))
        .unwrap()
        {
            ParseResult::WasiRun(invocation) => assert_eq!(
                invocation.mode,
                Mode::Branch {
                    path: "run.patina".into(),
                    parent: "main".into(),
                    from_sequence: 3,
                    branch_seed: 8,
                    branch_id: "wasi-branch".into(),
                }
            ),
            _ => panic!("expected wasi branch"),
        }
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
        assert!(parse(strings(&["wasi-run", "module.wasm", "--preopen"])).is_err());
        assert!(parse(strings(&["wasi-run", "module.wasm", "--preopen", ":ro"])).is_err());
        assert!(
            parse(strings(&[
                "wasi-run",
                "module.wasm",
                "--preopen",
                "/data:rx"
            ]))
            .is_err()
        );
        assert!(
            parse(strings(&[
                "wasi-run",
                "module.wasm",
                "--max-memory-pages",
                "4294967296"
            ]))
            .is_err()
        );
        assert!(
            parse(strings(&[
                "wasi-run",
                "module.wasm",
                "--max-descriptors",
                "-1"
            ]))
            .is_err()
        );
        assert!(
            parse(strings(&[
                "wasi-run",
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
            wasi_compatibility_fingerprint(module, &arguments),
            wasi_compatibility_fingerprint(module, &environment)
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
            wasi_compatibility_fingerprint(module, &ordered),
            wasi_compatibility_fingerprint(module, &reordered)
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
            wasi_compatibility_fingerprint(module, &ordered),
            wasi_compatibility_fingerprint(module, &changed_preopen)
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
            wasi_compatibility_fingerprint(module, &ordered),
            wasi_compatibility_fingerprint(module, &changed_limit)
        );
    }

    fn native_build_invocation(values: &[&str]) -> NativeBuildInvocation {
        match parse(strings(values)).unwrap() {
            ParseResult::NativeBuild(invocation) => invocation,
            _ => panic!("expected native-build"),
        }
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
        assert!(parse(strings(&["native-build", "probe.rs"])).is_err());
        assert!(parse(strings(&["native-build", "--output", "probe"])).is_err());
        // Package-only options are rejected for a single source.
        assert!(
            parse(strings(&[
                "native-build",
                "probe.rs",
                "--output",
                "probe",
                "--bin",
                "x"
            ]))
            .is_err()
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
        assert!(parse(strings(&["native-build", "pkg", "--edition", "2021"])).is_err());
        assert!(parse(strings(&["native-build", "pkg", "--", "-C", "opt-level=2"])).is_err());
    }

    #[test]
    fn parses_native_run_modes_and_rejects_conflicts() {
        match parse(strings(&[
            "native-run",
            "probe",
            "--seed",
            "9",
            "--",
            "one",
        ]))
        .unwrap()
        {
            ParseResult::NativeRun(invocation) => {
                assert_eq!(invocation.binary, PathBuf::from("probe"));
                assert!(matches!(invocation.mode, NativeRunMode::Seeded { seed: 9 }));
                assert_eq!(invocation.program_args, strings(&["one"]));
            }
            _ => panic!("expected native-run"),
        }
        match parse(strings(&[
            "native-run",
            "probe",
            "--record",
            "run.patina",
            "--seed",
            "5",
            "--fingerprint",
            "native-v1",
        ]))
        .unwrap()
        {
            ParseResult::NativeRun(invocation) => match invocation.mode {
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
            },
            _ => panic!("expected native-run"),
        }
        match parse(strings(&["native-run", "probe", "--replay", "run.patina"])).unwrap() {
            ParseResult::NativeRun(invocation) => match invocation.mode {
                NativeRunMode::Replay { path, fingerprint } => {
                    assert_eq!(path, PathBuf::from("run.patina"));
                    assert_eq!(fingerprint, DEFAULT_NATIVE_FINGERPRINT);
                }
                _ => panic!("expected replay mode"),
            },
            _ => panic!("expected native-run"),
        }
        // record/replay are mutually exclusive and replay takes its seed from the trace.
        assert!(
            parse(strings(&[
                "native-run",
                "probe",
                "--record",
                "a",
                "--replay",
                "b"
            ]))
            .is_err()
        );
        assert!(
            parse(strings(&[
                "native-run",
                "probe",
                "--replay",
                "a",
                "--seed",
                "1"
            ]))
            .is_err()
        );
        assert!(parse(strings(&["native-run"])).is_err());
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
