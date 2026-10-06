//! WASI run, build, audit, and compatibility fingerprints.

use crate::native_build::{
    native_build_executable, resolve_artifact, select_native_package_bin, trace_has_buggify,
};
use crate::parse::{buggify_env_pairs, knob_env_pairs, liveness_env_pairs};
use crate::shim_build::lock_target_dir;
use crate::{
    ArtifactRef, CliError, Mode, WasiBuildInvocation, WasiInvocation, WasiPreopenConfig,
    WasiResourceLimitOverrides, hash_bytes, hex, output, patina_rustflags, read_facts_channel,
};
use patina_dst_runtime::{Context, FaultKnob, RuntimeConfig};
use patina_dst_target::{WASI_PREVIEW1_TARGET, WasiAudit};
use patina_dst_trace::TraceBundle;
use patina_dst_wasi_host::{MountPolicy, Preview1Host, execute_preview1_with_fuel};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::{env, fs};

pub(super) fn execute_wasi_run(invocation: WasiInvocation) -> Result<i32, CliError> {
    let mut invocation = invocation;
    if !invocation.knobs.get(FaultKnob::FsCrashAt).is_empty() {
        return Err(CliError::usage(
            "WASI --fs-crash-at crash-restart is not implemented; refusing rather than using the old rollback-and-continue model",
        ));
    }
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
        || replay_trace_path(&invocation.mode).is_some_and(|path| {
            TraceBundle::load(path).is_ok_and(|bundle| trace_has_buggify(&bundle))
        });
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
    if let Some(budget) = invocation.step_budget {
        config = config.with_step_budget(budget);
    }
    // The realtime epoch configures the in-process clock on a seeded or
    // `--record` run and is recorded into the trace; replay carries none and
    // the runtime restores the recorded one.
    if let Some(nanos) = invocation.realtime_epoch_nanos {
        config = config.with_realtime_epoch_nanos(nanos);
    }
    if matches!(invocation.mode, Mode::Seeded { .. } | Mode::Record { .. }) {
        let pairs = knob_env_pairs(&invocation.knobs)?;
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
    // A WASI guest runs in THIS process, so the report knobs come straight from
    // the supervisor's environment — but through the same table and parser the
    // native and cargo families use, and resolved once for both the runtime's own
    // reports and the depth line this function appends below.
    let reports = patina_dst_runtime::ReportConfig::default().applied(|name| env::var(name).ok());
    config = config.with_reports(reports);
    // The structured run-facts channel. A WASI guest's runtime lives in THIS
    // process, which is not interposed, so the plain path channel is enough — no
    // descriptor hand-off is needed.
    let facts_file = if output::facts_active() {
        Some(tempfile::NamedTempFile::new().map_err(|error| {
            CliError(format!("failed to create the run-facts channel: {error}"))
        })?)
    } else {
        None
    };
    if let Some(file) = &facts_file {
        config = config.with_facts_path(file.path());
    }
    let context = Context::from_config(config).map_err(|error| CliError(error.to_string()))?;
    let host = configured_wasi_host(&invocation, &resolved.display, context)?;
    let (trace_path, seed, timeline) = match &invocation.mode {
        Mode::Seeded { seed } => (None, Some(*seed), "main".to_string()),
        Mode::Record { seed, path } => (Some(path.clone()), Some(*seed), "main".to_string()),
        Mode::Replay { path, timeline } => (Some(path.clone()), None, timeline.clone()),
        Mode::Branch {
            path, branch_id, ..
        } => (Some(path.clone()), None, branch_id.clone()),
    };
    let artifact = resolved.display.display().to_string();
    let mut execution = match execute_preview1_with_fuel(&bytes, host, invocation.fuel) {
        Ok(execution) => execution,
        Err(error) => {
            // A guest TRAP is an outcome of the guest, not a failure to run it:
            // an `always!` violation, an `unreachable`, a memory-cap trap. It
            // gets a real run envelope, so the verdicts the guest drained before
            // trapping survive and a campaign classifies the generation on them
            // instead of filing it as harness noise (docs/arcs/outcome-channel.md,
            // Wave B residue). Every OTHER failure — an audit refusal, an
            // engine/link error, a host finalization error — is patina or the
            // module failing and stays a `CliError`.
            let (trap, stdout, mut stderr) = match error.guest_trap() {
                Ok(trap) => trap,
                Err(other) => return Err(CliError(other.to_string())),
            };
            // The trap itself stays loud: it rides the run's own stderr, so it
            // reaches the human stream, the envelope's `stderr`, and a campaign's
            // captured output through one channel.
            stderr.extend_from_slice(format!("patina: wasm trap: {trap}\n").as_bytes());
            // No `depth`: the engine's fuel meter and hostcall counters are only
            // available from a finished `WasiExecution`, and an absent report must
            // never read as zero. `facts` is whatever the runtime managed to write
            // before the trap — absent stays absent.
            let facts = read_facts_channel(facts_file.as_ref().map(tempfile::NamedTempFile::path))?;
            return output::finalize_inprocess(
                output::RunReport {
                    verb: "run",
                    family: "wasi",
                    artifact: &artifact,
                    trace_path,
                    timeline: &timeline,
                    fingerprint: Some(fingerprint),
                    seed,
                    coverage: None,
                    depth: None,
                    crash_restart: None,
                    facts,
                },
                WASI_TRAP_EXIT,
                stdout,
                stderr,
            );
        }
    };
    // WASI depth (fuel + hostcall counts) rides the run's own stderr, exactly as
    // the native family's `PATINA_COVERAGE_REPORT` rides the child's — so the
    // human stream, the envelope's `markers`, and a campaign's captured child
    // output all read the same line. Appending happens after the guest and its
    // trace are finalized, so no recorded byte or fingerprint is affected.
    let depth = wasi_depth_report(&execution);
    if reports.enabled(patina_dst_runtime::Report::Depth) {
        execution
            .stderr
            .extend_from_slice(depth.marker_line().as_bytes());
        execution.stderr.push(b'\n');
    }
    let facts = read_facts_channel(facts_file.as_ref().map(tempfile::NamedTempFile::path))?;
    output::finalize_inprocess(
        output::RunReport {
            verb: "run",
            family: "wasi",
            artifact: &artifact,
            trace_path,
            timeline: &timeline,
            fingerprint: Some(fingerprint),
            seed,
            coverage: None,
            depth: Some(depth),
            crash_restart: None,
            facts,
        },
        execution.exit_code,
        execution.stdout,
        execution.stderr,
    )
}

/// Build the run envelope's `depth` object from a finished WASI execution. The
/// values come straight from the engine's fuel meter and the host's per-import
/// counters, both deterministic functions of the executed instruction stream.
fn wasi_depth_report(execution: &patina_dst_wasi_host::WasiExecution) -> output::DepthReport {
    output::DepthReport {
        family: "wasi".to_string(),
        fuel_consumed: execution.fuel_consumed,
        hostcalls: execution
            .hostcalls
            .iter()
            .map(|(name, count)| ((*name).to_string(), *count))
            .collect(),
    }
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
pub(super) fn execute_wasi_build(invocation: WasiBuildInvocation) -> Result<i32, CliError> {
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
pub(super) fn run_wasi_build(
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
        None,
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
    let _lock = lock_target_dir(&selected.target_dir)?;
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

pub(super) fn execute_wasi_audit(artifact: ArtifactRef) -> Result<i32, CliError> {
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

/// Exit code for a WASI guest that trapped. A wasm trap carries no exit status
/// and no signal, so the run reports the ordinary "the guest failed" code rather
/// than borrowing a signal-death code (`134`) it did not die from — the envelope's
/// `verdicts[]` and `stderr` carry what actually happened.
const WASI_TRAP_EXIT: i32 = 1;

#[cfg(test)]
mod tests {
    use super::*;
    use patina_dst_runtime::{Context, FaultKnob, Plumbing, RuntimeConfig};
    use std::ffi::OsString;
    use std::path::Path;

    use crate::help;

    use crate::parse::{knob_env_pairs, parse_wasi_run, repeatable_payload};
    use crate::tests::{knob_sample, wasi_invocation};

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

    #[test]
    fn wasi_run_forwards_every_registered_fault_knob() {
        // WASI's `run` has no child process to re-emit onto — it applies fault
        // knobs to the in-process runtime through `knob_env_pairs` — but the same
        // silent-drop class applies: a knob the registry gives the WASI family
        // that `parse_wasi_run`/`knob_env_pairs` fails to carry through to the
        // control-plane pairs would leave that family's faults inert with nothing
        // to notice, the shape the historical `--net-partition` bug had for WASI.
        // Driven off `FaultKnob::ALL` and the registry's own family list (never a
        // hand-kept one), so a future knob is covered the day it is registered,
        // and the DNS knobs (which WASI's parser refuses outright) are skipped
        // because the registry says so, not because this test hard-codes it.
        let registered: Vec<FaultKnob> = FaultKnob::ALL
            .iter()
            .copied()
            .filter(|knob| {
                help::verb("run")
                    .expect("registered verb")
                    .family_flags(help::Family::Wasi)
                    .any(|flag| flag.name == knob.meta().flag)
            })
            .collect();
        assert!(
            !registered.is_empty(),
            "no fault knobs registered for the WASI family — the filter is wrong"
        );
        let mut tokens: Vec<OsString> = vec![OsString::from("guest.wasm")];
        for knob in &registered {
            tokens.push(OsString::from(knob.meta().flag));
            tokens.push(OsString::from(knob_sample(*knob)));
        }
        let invocation = parse_wasi_run(tokens).expect("wasi run parse");
        let pairs = knob_env_pairs(&invocation.knobs).expect("encode");
        for knob in &registered {
            let meta = knob.meta();
            let expected = match meta.plumbing {
                Plumbing::Scalar => knob_sample(*knob).to_string(),
                Plumbing::Repeatable(_) => {
                    repeatable_payload(*knob, &[knob_sample(*knob).to_string()])
                        .expect("every repeatable knob encodes its sample")
                }
            };
            assert!(
                pairs.contains(&(meta.env, expected.clone())),
                "WASI run dropped {} on the way to {}: {pairs:?}",
                meta.flag,
                meta.env
            );
        }
    }
}
