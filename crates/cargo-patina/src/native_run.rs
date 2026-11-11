//! Native pre-run gates, trace channels, and child execution.

use crate::audit::{native_escape_summary, push_native_escape_provenance_lines};
use crate::crash_restart::{
    IncarnationLaunch, append_native_infra_marker, crash_restart_plan, supervise_crash_restart,
};
use crate::native_build::{
    IMAGE_FINGERPRINT_COMPONENT, binary_build_kind, binary_instrumentation,
    instrumentation_fingerprint, native_run_fingerprint, resolve_artifact,
};
use crate::output;
use crate::parse::{buggify_env_pairs, knob_env_pairs, liveness_env_pairs, schedule_env_pairs};
use crate::run_cache::Image;
use crate::{
    CliError, DEFAULT_NATIVE_FINGERPRINT, NATIVE_GUEST_ARGV0, NativeRunInvocation, NativeRunMode,
    UnsupportedPolicy, coverage,
};
use crate::{F_GETFD, F_SETFD, FD_CLOEXEC, fcntl};
use patina_dst_abi::RunClass;
use patina_dst_fs_mem::{FsImage, FsImageEntry};
use patina_dst_runtime::{
    ENV_COVERAGE_FD, ENV_FINGERPRINT, ENV_FS_IMAGE_FD, ENV_GUEST_ARGV, ENV_GUEST_CPUS,
    ENV_GUEST_CWD, ENV_GUEST_ENV, ENV_GUEST_HOSTNAME, ENV_GUEST_STDIN_FD, ENV_INITIAL_STACK,
    ENV_MODE, ENV_PARAMS_JSON, ENV_REALTIME_EPOCH_NANOS, ENV_SEED, ENV_STEP_BUDGET, ENV_TRACE_FD,
    GUEST_STDIN_MAX_BYTES, NATIVE_INITIAL_STACK_TRAILER_SLOTS,
};
use patina_dst_target::{
    NativeAudit, NativeEscape, TargetError, native_binary_has_sud_marker,
    native_binary_has_tsc_marker, native_binary_is_shim_linked, native_deny_trap_armed,
    native_escape_is_sud_manageable, native_escape_is_tsc_manageable, render_compat_mode_note,
    render_cpu_nondeterminism_note, render_thread_pointer_note, render_tsc_managed_note,
};
use patina_dst_trace::{
    TraceBundle, TraceError, create_scratch, parse_abandoned_trace_marker, remove_dead_scratch,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::{env, fs, io};

mod child;
mod fs_image;
mod gate;
mod identity;
mod layout;
mod trace;

/// Name prefix of the envp slots reserved for the shim's startup map.
const ENVP_SLOT_PREFIX: &str = "_PATINA_ENVP_SLOT_";

pub(super) use child::NATIVE_CRASH_RESTART_EXIT;
use child::encode_guest_argv;
use child::reconcile_replay_argv;
use child::wait_native_child_once;
#[cfg(test)]
pub(super) use child::{NativeChildStatus, native_child_status};
use fs_image::{FsImageHash, build_fs_image_file, recorded_image_hash};

/// `--stdin HOST_FILE`'s bytes: at most [`GUEST_STDIN_MAX_BYTES`], since
/// the trace records them whole.
fn read_guest_stdin(path: &Path) -> Result<Vec<u8>, CliError> {
    use std::io::Read;

    let failed = |error: std::io::Error| {
        CliError(format!(
            "failed to read --stdin {}: {error}",
            path.display()
        ))
    };
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(failed)?
        .take(GUEST_STDIN_MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(failed)?;
    if bytes.len() > GUEST_STDIN_MAX_BYTES {
        return Err(CliError(format!(
            "--stdin {} holds more than {GUEST_STDIN_MAX_BYTES} bytes, the most a trace records",
            path.display()
        )));
    }
    Ok(bytes)
}

/// `bytes` in a rewound scratch file, the descriptor the guest inherits.
fn stage_guest_stdin(bytes: &[u8]) -> Result<fs::File, CliError> {
    use std::io::{Seek, SeekFrom, Write};

    let scratch = |error: std::io::Error| {
        CliError(format!(
            "failed to stage --stdin in a scratch file: {error}"
        ))
    };
    let mut file = tempfile::tempfile().map_err(scratch)?;
    file.write_all(bytes).map_err(scratch)?;
    file.seek(SeekFrom::Start(0)).map_err(scratch)?;
    Ok(file)
}

/// The fingerprint hash (`<contents>.<metadata>`) a run's `--mount` folds
/// into its trace, for a caller that pins a corpus across runs (a campaign
/// and its continuations).
pub(crate) fn mount_corpus_hash(mount: &crate::mount::Mount) -> Result<String, CliError> {
    Ok(build_fs_image_file(mount)?.hash)
}
pub(super) use gate::emit_native_deny_trap_note;
use gate::native_prerun_gate;
pub(super) use gate::target_has_sud;
use identity::{guest_trace_channel, native_identity, native_identity_refusal};
use trace::NativeTraceSink;
pub(crate) use trace::TRACE_CHANNEL_UNAVAILABLE;
use trace::TraceCommitFailure;
use trace::write_unsupported_sidecar;

pub(super) fn execute_native_run(mut invocation: NativeRunInvocation) -> Result<i32, CliError> {
    use std::os::unix::io::AsRawFd;
    use std::os::unix::process::CommandExt;

    // A page (`--render`) is drawn from a trace. A run asked for
    // one without `--record` records into a scratch directory that goes away
    // with the run.
    let scratch_trace = match &invocation.mode {
        NativeRunMode::Seeded { seed } if output::options().render.is_some() => {
            let directory = tempfile::tempdir().map_err(|error| {
                CliError(format!(
                    "failed to create a scratch directory for the page's trace: {error}"
                ))
            })?;
            invocation.mode = NativeRunMode::Record {
                seed: *seed,
                path: directory.path().join("run.patina"),
            };
            Some(directory)
        }
        _ => None,
    };

    // Source-first: an artifact runs as-is; a source/package is built on the fly
    // first (`resolved` holds the build workspace alive for the whole run). For
    // replay, the rebuilt binary is judged against the trace's build identity
    // below, exactly like a prebuilt one — no special-casing.
    let resolved = resolve_artifact(invocation.binary.clone())?;
    let binary = fs::canonicalize(&resolved.path).map_err(|error| {
        CliError(format!(
            "failed to resolve native program {}: {error}",
            resolved.path.display()
        ))
    })?;
    // The executable's bytes, mapped once: the build identity and the pre-run
    // gate both judge exactly these.
    let image = fs::File::open(&binary)
        .and_then(|file| Image::map(&file))
        .map_err(|error| {
            CliError(format!(
                "failed to read native program {}: {error}",
                binary.display()
            ))
        })?;

    // A replay reads its trace once: the build identity, the guest arguments,
    // the fingerprint components and the crash-restart plan all come from this
    // one load.
    // The envelope's trace facts come from this load too.
    let replay_trace = match &invocation.mode {
        NativeRunMode::Replay { path, .. } => Some(TraceBundle::load(path).map_err(|error| {
            CliError(format!("failed to read trace {}: {error}", path.display()))
        })?),
        NativeRunMode::Seeded { .. } | NativeRunMode::Record { .. } => None,
    };
    // A trace recorded with the host's randomized address layout replays with
    // it: the qualification the recording carried is the replay's too.
    if replay_trace.as_ref().is_some_and(|bundle| {
        bundle.metadata.address_layout == Some(patina_dst_trace::AddressLayout::Randomized)
    }) {
        invocation.allow_randomized_layout = true;
    }
    let mut trace_facts = match (&invocation.mode, &replay_trace) {
        (NativeRunMode::Replay { path, .. }, Some(bundle)) => {
            Some(output::TraceFacts::of(path, bundle, "main"))
        }
        _ => None,
    };

    // A replay restores the recorded environment; a new run of a Go guest
    // gets the settings its runtime needs under Patina.
    if replay_trace.is_none() {
        let metered = image.remember("go-meter", || {
            Ok::<_, CliError>(crate::go_build::carries_meter(image.bytes()))
        })?;
        crate::go_build::apply_go_guest_defaults(metered, &mut invocation.environment);
    }

    // The build identity a recording stores and a replay must match. A replay
    // against another build is refused here, by component, before the guest
    // starts: past this point it could only fail as an operation mismatch at
    // some later boundary, or not fail at all.
    // The images the loader maps beside the executable. The gate judges every
    // reference by the image it binds to, and a recording names each image, so
    // a replay against a different libc is refused like one against a
    // different executable.
    let load_set = crate::load_set::discover(&binary, image.bytes())?;
    let identity = match &invocation.mode {
        NativeRunMode::Seeded { .. } => None,
        NativeRunMode::Record { .. } | NativeRunMode::Replay { .. } => {
            Some(native_identity(&image, &load_set)?)
        }
    };
    if let (NativeRunMode::Replay { path, .. }, Some(bundle), Some(identity)) =
        (&invocation.mode, &replay_trace, &identity)
        && let Some(message) =
            native_identity_refusal(path, bundle.metadata.native.as_ref(), identity)
    {
        // The trace belongs to another build: the request's, judged before
        // any guest runs.
        return Ok(output::report_prerun_stop(
            &binary,
            RunClass::Error,
            output::Stop::new(output::TRACE_MISMATCH_STOP, message),
        ));
    }
    // The CPU count the guest's virtual machine has: on replay the trace's;
    // otherwise the flag's, or the runtime default.
    let guest_cpus = match &replay_trace {
        Some(bundle) => Some(bundle.metadata.cpus),
        None => invocation.cpus,
    };
    // Pre-run default-deny gate. Before the guest executes, enumerate every
    // externally-resolved symbol it can reach and hard-error, listing names, if
    // any on the blocking/time/scheduling/effect surface is neither interposed
    // nor known-safe. This is what makes a missed interposer (the class the
    // macOS dispatch-semaphore Parker escape belonged to) structurally
    // impossible to run silently: an unmodeled blocking symbol is an import the
    // shim does not define, so it surfaces here as a denial rather than blocking
    // a host thread outside the scheduler. `--allow`
    // downgrades matching denials to a loud warning for programs that carry
    // unsupported surface the scenario never reaches.
    let downgraded = match native_prerun_gate(
        &binary,
        &image,
        &load_set,
        &invocation.allow,
        &invocation.allow_unsupported,
    ) {
        Ok(downgraded) => downgraded,
        // The binary links something patina does not model: the refusal
        // names each symbol and where it is reached from, and no guest runs.
        Err(gate::GateRefusal::Unsupported(message)) => {
            return Ok(output::report_prerun_stop(
                &binary,
                RunClass::Unsupported,
                output::Stop::new(output::PRERUN_AUDIT_STOP, message),
            ));
        }
        Err(gate::GateRefusal::Error(error)) => return Err(error),
    };
    if invocation.allow_randomized_layout {
        eprintln!("patina: WARNING: {}", layout::RANDOMIZED_QUALIFICATION);
    }

    // An instrumented binary carries the edge hook (counters and a stride to
    // honour); a Go guest carries counters only. Detect the linked markers: they
    // decide whether there are counters to write and a stride to honour, and the
    // edge hook folds into the compatibility fingerprint, so a trace never
    // cross-replays between an instrumented binary and a plain one.
    let instrumented = image.remember("instrumentation", || {
        Ok::<_, CliError>(binary_instrumentation(image.bytes()))
    })?;
    // A prebuilt binary is whatever it was built as: say so when its
    // computation is not metered, since then a run that computes without end
    // stops only at the host-time backstop.
    let build_kind = image.remember("build-kind", || {
        Ok::<_, CliError>(binary_build_kind(image.bytes()))
    })?;
    // Only where a metered build is the default is a plain one worth a note:
    // on macOS every Rust/C build is plain.
    if build_kind == crate::native_build::BuildKind::Plain
        && crate::native_build::INSTRUMENT_BY_DEFAULT
        && !output::options().is_json()
    {
        eprintln!(
            "patina: note: {} is a plain build: its computation is not metered, so a run that \
computes without end stops only at the host-time backstop, an inconclusive timeout; {} to \
meter it",
            binary.display(),
            crate::native_build::METER_HINT
        );
    }
    if invocation.coverage_out.is_some() && !instrumented.edge_counters {
        return Err(CliError::usage(
            "--coverage-out requires a native binary with edge counters: an instrumented build (the default; not --no-instrument) or a Go guest",
        ));
    }
    if invocation.schedule.yield_stride != 0 && !instrumented.yield_hook {
        return Err(CliError::usage(format!(
            "--yield-stride {} takes its scheduling points at the edge hooks of an instrumented \
build; {} was built with --no-instrument (or is a Go or Python guest), so the stride would be inert",
            invocation.schedule.yield_stride,
            binary.display()
        )));
    }

    // Capture the mounted host directory into a deterministic filesystem image.
    // The supervisor is not interposed, so it may read the host tree freely; the
    // encoded image travels to the guest over an inherited descriptor and the
    // shim rebuilds it, so the fully interposed guest never touches the host
    // filesystem. The image hash folds into the fingerprint below so a replay
    // against a different corpus is rejected exactly like any incompatibility.
    let image_file = match &invocation.mount {
        Some(mount) => Some(build_fs_image_file(mount)?),
        None => None,
    };
    let image_hash = image_file.as_ref().map(|image| image.hash.clone());
    // A supplied standard input travels the same way: read here (a FIFO or a
    // terminal too, once), held in a scratch file every incarnation reads
    // from the start, and recorded by the runtime into the trace, from which
    // a replay restores it.
    let stdin_file = match &invocation.stdin {
        Some(path) => Some(stage_guest_stdin(&read_guest_stdin(path)?)?),
        None => None,
    };
    // A replay against another corpus would only fail as a fingerprint
    // mismatch inside the guest; refuse it here and say which half differs.
    // The recorded hash is read where this replay's fingerprint puts its
    // own, so it is compared only when the fingerprints differ in nothing
    // else.
    if let (NativeRunMode::Replay { .. }, Some(bundle), Some(current), Some(host_dir)) = (
        &invocation.mode,
        &replay_trace,
        &image_hash,
        &invocation.mount,
    ) {
        let head = instrumentation_fingerprint(DEFAULT_NATIVE_FINGERPRINT, instrumented);
        if let Some(recorded) = recorded_image_hash(&bundle.metadata.fingerprint, &head)
            && let Some(mismatch) = FsImageHash::mismatch(recorded, current)
        {
            let message = format!(
                "--mount {host_dir} is not the corpus this trace recorded: {}. Replay against \
                 the recorded corpus (trace {IMAGE_FINGERPRINT_COMPONENT}{recorded}, this corpus \
                 {IMAGE_FINGERPRINT_COMPONENT}{current})",
                mismatch.describe()
            );
            let mut stop = output::Stop::new(output::TRACE_MISMATCH_STOP, message);
            stop.mismatch = Some(mismatch.input());
            return Ok(output::report_prerun_stop(&binary, RunClass::Error, stop));
        }
    }
    let coverage_file = match &invocation.coverage_out {
        Some(path) => Some(fs::File::create(path).map_err(|error| {
            CliError(format!(
                "failed to create coverage map {}: {error}",
                path.display()
            ))
        })?),
        None => None,
    };
    // The structured run-facts channel. A native guest is FULLY interposed, so
    // the document cannot travel over a path — it rides an inherited host
    // descriptor the shim writes through its private host aliases, exactly like
    // the trace bundle and the coverage map. Every run carries it, whatever its
    // output format: the run's result is judged from these facts, and a
    // verdict the guest reported must fail a run nobody asked JSON of.
    let facts_file =
        Some(tempfile::tempfile().map_err(|error| {
            CliError(format!("failed to create the run-facts channel: {error}"))
        })?);
    // Patina's end-of-run reports (and their warnings): kept apart from the guest's stderr, shown on `--verbose` and
    // carried in the envelope, so they are never mistaken for the guest's words.
    let reports_file = tempfile::tempfile()
        .map_err(|error| CliError(format!("failed to create the reports channel: {error}")))?;
    // The stop pipe: where the shim says why it is ending the run, just before
    // it does. A pipe rather than the facts file, so no file size limit, full
    // disk or `SIGXFSZ` can lose the one record that keeps patina's own stop
    // from reading as the guest's crash.
    let (mut stop_reader, stop_writer) =
        io::pipe().map_err(|error| CliError(format!("failed to create the stop pipe: {error}")))?;

    // Restore the guest arguments for a replay from the trace's recorded argv, so
    // a bare replay reproduces them without the `--` section being re-passed; a
    // mismatched `--` section is refused upfront (see `reconcile_replay_argv`).
    // For seeded/record runs the arguments are the ones supplied on the command
    // line, unchanged.
    let program_args = match (&invocation.mode, &replay_trace) {
        (NativeRunMode::Replay { path, .. }, Some(bundle)) => {
            reconcile_replay_argv(path, bundle, &invocation.program_args)?
        }
        _ => invocation.program_args.clone(),
    };

    // What a record or replay tells the guest about its mode, identical for
    // every incarnation of the run.
    let mode_env: Vec<(&str, String)> = match &invocation.mode {
        NativeRunMode::Seeded { seed } => {
            vec![(ENV_MODE, "seeded".into()), (ENV_SEED, seed.to_string())]
        }
        NativeRunMode::Record { seed, .. } => vec![
            (ENV_MODE, "record".into()),
            (ENV_SEED, seed.to_string()),
            (
                ENV_FINGERPRINT,
                native_run_fingerprint(
                    DEFAULT_NATIVE_FINGERPRINT,
                    instrumented,
                    image_hash.as_deref(),
                ),
            ),
            // Record the guest arguments into the trace metadata so a later
            // `replay` restores them without the `--` section being re-passed.
            // Always forwarded (even when empty) so a zero-argument run records
            // `[]`, and replaying it reproduces zero arguments.
            (ENV_GUEST_ARGV, encode_guest_argv(&program_args)?),
        ],
        NativeRunMode::Replay { .. } => {
            let bundle = replay_trace
                .as_ref()
                .expect("a native replay loads its trace first");
            vec![
                (ENV_MODE, "replay".into()),
                // Startup effects (notably AT_RANDOM) happen before the shim
                // can read the trace. They need the same seed as the runtime.
                (ENV_SEED, bundle.metadata.root_seed.to_string()),
                (
                    ENV_FINGERPRINT,
                    native_run_fingerprint(
                        DEFAULT_NATIVE_FINGERPRINT,
                        instrumented,
                        image_hash.as_deref(),
                    ),
                ),
            ]
        }
    };

    // The shim publishes the deterministic map into the ORIGINAL stack envp.
    // Reserve room for its entries plus a disjoint copy of the platform trailer
    // (ELF auxv / Darwin apple vector); libc/dyld keep the original trailer.
    // Replay restores its map from metadata, not the normally empty CLI map.
    let startup_env_entries = if let Some(bundle) = &replay_trace {
        bundle.metadata.guest_env.as_ref().map_or(0, BTreeMap::len)
    } else {
        invocation.environment.len()
    };
    // The run's own inputs as the control plane carries them: its environment
    // map and its arguments, the same size in every mode, so the fixed address
    // layout can reserve room for them beside the rest of the control plane.
    // Run parameters are not among them: they ride the control plane's own
    // reservation, which the padding evens out.
    let guest_payload = {
        let environment = replay_trace
            .as_ref()
            .and_then(|bundle| bundle.metadata.guest_env.as_ref())
            .unwrap_or(&invocation.environment);
        let arguments: Vec<_> = program_args
            .iter()
            .map(|argument| argument.to_string_lossy())
            .collect();
        serde_json::to_string(environment).map_or(0, |json| json.len())
            + serde_json::to_string(&arguments).map_or(0, |json| json.len())
    };

    // A replaying guest reads the trace the supervisor hands it, so it reads
    // the recording without its build identity.
    let replay_channel = replay_trace.as_ref().map(guest_trace_channel).transpose()?;
    let crash_restart_plan = crash_restart_plan(&invocation, replay_trace)?;
    // Every incarnation of the run is launched from this one description; only
    // its descriptors (trace channel, base filesystem, crash handoff) differ. A
    // run without a crash rate is the single incarnation 0. Returns the
    // command and the descriptors it inherits: the shim reads only the ones the
    // control plane names, and they stay inheritable for the child's lifetime.
    let incarnation_command = |launch: IncarnationLaunch<'_>| -> Result<
        (Command, Vec<std::os::unix::io::RawFd>),
        CliError,
    > {
        let mut command = Command::new(&binary);
        let mut fds = Vec::new();
        // Stamp a fixed, machine-independent `argv[0]`: the guest is exec'd from
        // an absolute host path, but that path must not leak into the guest's
        // `std::env::args()` as a non-portable string. The guest's own arguments
        // live in `argv[1..]`.
        command
            .args(&program_args)
            .arg0(NATIVE_GUEST_ARGV0)
            .env_clear();
        // These inert entries cannot configure the loader (unlike baking the
        // guest's real names, e.g. LD_PRELOAD, into exec's environment). The
        // shim checks actual trailer size before writing, failing closed if a
        // future platform needs more than this reservation. Padding is not
        // control-plane state and is never snapshotted or exposed to the guest.
        command.env(ENV_INITIAL_STACK, "1");
        for slot in 0..startup_env_entries + NATIVE_INITIAL_STACK_TRAILER_SLOTS {
            command.env(format!("{ENVP_SLOT_PREFIX}{slot}"), "");
        }
        if let Some(file) = &coverage_file {
            command.env(ENV_COVERAGE_FD, file.as_raw_fd().to_string());
            fds.push(file.as_raw_fd());
        }
        if let Some(file) = &facts_file {
            command.env(
                patina_dst_runtime::ENV_FACTS_FD,
                file.as_raw_fd().to_string(),
            );
            fds.push(file.as_raw_fd());
        }
        command.env(
            patina_dst_runtime::ENV_STOP_FD,
            stop_writer.as_raw_fd().to_string(),
        );
        fds.push(stop_writer.as_raw_fd());
        command.env(
            patina_dst_runtime::ENV_REPORTS_FD,
            reports_file.as_raw_fd().to_string(),
        );
        fds.push(reports_file.as_raw_fd());
        if !invocation.environment.is_empty() {
            let encoded = serde_json::to_string(&invocation.environment).map_err(|error| {
                CliError(format!(
                    "failed to encode native guest environment: {error}"
                ))
            })?;
            command.env(ENV_GUEST_ENV, encoded);
        }
        if !invocation.params.is_empty() {
            let encoded = serde_json::to_string(&invocation.params).map_err(|error| {
                CliError(format!("failed to encode run parameters: {error}"))
            })?;
            command.env(ENV_PARAMS_JSON, encoded);
        }
        if let Some(cwd) = &invocation.cwd {
            command.env(ENV_GUEST_CWD, cwd);
        }
        if let Some(nanos) = invocation.realtime_epoch_nanos {
            command.env(ENV_REALTIME_EPOCH_NANOS, nanos.to_string());
        }
        if let Some(hostname) = &invocation.hostname {
            command.env(ENV_GUEST_HOSTNAME, hostname);
        }
        if let Some(cpus) = guest_cpus {
            command.env(ENV_GUEST_CPUS, cpus.to_string());
        }
        // The boundary-operation budget is a supervisor-side bound, not recorded
        // run semantics, so it is supplied per invocation on every family alike.
        if let Some(budget) = invocation.step_budget {
            command.env(ENV_STEP_BUDGET, budget.to_string());
        }
        // Forward whatever fault knobs the operator supplied to the guest (its
        // environment is cleared above). On record and seeded runs these configure
        // the faults and are recorded into the trace metadata. Native replay
        // does not accept semantic re-supply; the trace's recorded configuration
        // is authoritative and restored by the runtime.
        for (name, value) in knob_env_pairs(&invocation.knobs)? {
            command.env(name, value);
        }
        // Forward the cooperative-SUT (buggify) knobs. Presence of
        // `PATINA_RT_BUGGIFY` enables buggify; its value (if any) is the firing
        // per-mille. Like the fault knobs, these are recorded into trace metadata
        // and restored from the trace on native replay, rather than re-supplied
        // as semantic flags.
        if let Some(buggify) = &invocation.buggify {
            for (name, value) in buggify_env_pairs(buggify) {
                command.env(name, value);
            }
        }
        // Forward the exploration scheduling-policy (PCT) and swarm
        // knobs through the same control plane. Recorded into the trace metadata
        // and restored from the trace on native replay; the fingerprint suffix
        // rejects a cross-policy replay.
        for (name, value) in schedule_env_pairs(&invocation.schedule) {
            command.env(name, value);
        }
        // Forward the liveness-watchdog knobs through the same control plane. The
        // watchdog is schedule-invariant: recorded but not fingerprinted, and a
        // replay adopts the recorded one.
        for (name, value) in liveness_env_pairs(&invocation.liveness) {
            command.env(name, value);
        }
        for (name, value) in &mode_env {
            command.env(name, value);
        }
        command.env(
            patina_dst_runtime::ENV_INCARNATION,
            launch.incarnation.to_string(),
        );
        if let Some(file) = launch.trace {
            command.env(ENV_TRACE_FD, file.as_raw_fd().to_string());
            fds.push(file.as_raw_fd());
        }
        if let Some((file, key)) = launch.handoff {
            command
                .env(
                    patina_dst_runtime::ENV_HANDOFF_FD,
                    file.as_raw_fd().to_string(),
                )
                .env(patina_dst_runtime::ENV_HANDOFF_KEY, key);
            fds.push(file.as_raw_fd());
        }
        if let Some(kind) = launch.replayed_crash {
            command.env(patina_dst_runtime::ENV_REPLAY_CRASH_KIND, kind.name());
        }
        if let Some(pipe) = launch.crash_report {
            command.env(
                patina_dst_runtime::ENV_CRASH_REPORT_FD,
                pipe.as_raw_fd().to_string(),
            );
            fds.push(pipe.as_raw_fd());
        }
        // A restarted incarnation boots from the recovered filesystem instead of
        // the run's base image, and carries realtime on from the crashed one.
        match (launch.restart, &image_file) {
            (Some(restart), _) => {
                command
                    .env(
                        patina_dst_runtime::ENV_RESTART_SNAPSHOT_FD,
                        restart.snapshot.as_raw_fd().to_string(),
                    )
                    .env(
                        patina_dst_runtime::ENV_RESTART_REALTIME_NANOS,
                        restart.previous_realtime_nanos.to_string(),
                    )
                    .env(patina_dst_runtime::ENV_RESTART_FAULTS, restart.faults);
                fds.push(restart.snapshot.as_raw_fd());
            }
            (None, Some(image)) => {
                command.env(ENV_FS_IMAGE_FD, image.file.as_raw_fd().to_string());
                fds.push(image.file.as_raw_fd());
            }
            (None, None) => {}
        }
        if let Some(file) = &stdin_file {
            use std::io::{Seek, SeekFrom};
            (&*file).seek(SeekFrom::Start(0)).map_err(|error| {
                CliError(format!("failed to rewind the --stdin scratch file: {error}"))
            })?;
            command.env(ENV_GUEST_STDIN_FD, file.as_raw_fd().to_string());
            fds.push(file.as_raw_fd());
        }
        layout::pin(
            &mut command,
            NATIVE_GUEST_ARGV0,
            ENVP_SLOT_PREFIX,
            guest_payload,
            invocation.allow_randomized_layout,
        )?;
        Ok((command, fds))
    };

    // Record mode writes to a sibling temporary file first; the supervisor
    // validates and renames it to the requested path only after the run ends.
    let mut trace_sink = match &invocation.mode {
        NativeRunMode::Record { path, .. } => Some(NativeTraceSink::create(path)?),
        NativeRunMode::Seeded { .. } | NativeRunMode::Replay { .. } => None,
    };

    output::progress::emit(
        "run_started",
        match &invocation.mode {
            NativeRunMode::Seeded { seed } | NativeRunMode::Record { seed, .. } => {
                serde_json::json!({ "artifact": binary.to_string_lossy(), "seed": seed })
            }
            NativeRunMode::Replay { path, .. } => serde_json::json!({
                "artifact": binary.to_string_lossy(),
                "trace": path.to_string_lossy(),
            }),
        },
    );
    let mut crash_restart = None;
    let mut captured = if let Some(plan) = &crash_restart_plan {
        let run = supervise_crash_restart(plan, |launch| {
            let (mut command, fds) = incarnation_command(launch)?;
            wait_native_child_once(&mut command, &binary, &fds)
        })?;
        if let (Some(sink), Some(bytes)) = (trace_sink.as_mut(), &run.trace) {
            sink.write_all(bytes)?;
        }
        crash_restart = Some(run.report);
        run.captured
    } else {
        // Hold the trace channel open until the child exits so the inherited
        // descriptor named by `PATINA_RT_TRACE_FD` stays valid.
        let replay_trace_file = replay_channel;
        let trace = trace_sink
            .as_ref()
            .map(NativeTraceSink::file)
            .or(replay_trace_file.as_ref());
        let (mut command, inherited_fds) = incarnation_command(IncarnationLaunch {
            incarnation: 0,
            trace,
            handoff: None,
            replayed_crash: None,
            crash_report: None,
            restart: None,
        })?;
        wait_native_child_once(&mut command, &binary, &inherited_fds)?.0
    };
    let mut committed_record_trace = None;
    let mut trace_finalization_error: Option<(PathBuf, String)> = None;
    let mut channel_unavailable: Option<i32> = None;
    // The recording is lost for a reason of patina's own, as opposed to a
    // truncated trace a guest that died mid-record leaves behind.
    let mut trace_lost: Option<String> = None;
    // The recording the run was asked for is not at its path, whatever the
    // reason: a fact of the run beside its class.
    let mut trace_incomplete: Option<output::TraceIncomplete> = None;
    if let Some(sink) = trace_sink {
        // The supervisor stamps the build identity as it commits the trace, so
        // a recording replays against its own build whatever the recorder
        // linked into the guest knows about identities.
        let identity = identity
            .as_ref()
            .expect("a recording computes its build identity");
        match sink.commit(identity) {
            Ok((path, bundle)) => {
                if let Err(error) = write_unsupported_sidecar(&path, &downgraded) {
                    let _ = fs::remove_file(&path);
                    return Err(error);
                }
                trace_facts = Some(output::TraceFacts::of(&path, &bundle, "main"));
                committed_record_trace = Some(path);
            }
            Err(failure) => {
                let path = match &invocation.mode {
                    NativeRunMode::Record { path, .. } => path.clone(),
                    NativeRunMode::Seeded { .. } | NativeRunMode::Replay { .. } => PathBuf::new(),
                };
                // A trace that is missing for an unexplained reason fails the
                // run: a clean exit code alongside no bundle would report a
                // recording that does not exist. A trace the recorder
                // deliberately abandoned after the guest finished is different
                // in kind — the guest's own status is the run's answer, and
                // overriding it here would manufacture a failure out of a
                // completed run (and bury the real status of one that failed
                // for a genuine reason). Either way the `PATINA_INFRA
                // trace=incomplete` marker below says the artifact is missing
                // and why, so nothing is silent.
                let guest_clean = captured.exit_code == 0 && captured.signal.is_none();
                if matches!(failure, TraceCommitFailure::Unavailable(_)) {
                    channel_unavailable = Some(captured.exit_code);
                    trace_lost = Some(failure.reason().to_string());
                } else if matches!(failure, TraceCommitFailure::Broken(_)) && guest_clean {
                    trace_lost = Some(failure.reason().to_string());
                }
                trace_incomplete = Some(output::TraceIncomplete {
                    reason: failure.kind(),
                    detail: failure.reason().to_string(),
                });
                trace_finalization_error = Some((path, failure.reason().to_string()));
            }
        }
    }
    append_native_infra_marker(
        &mut captured,
        trace_finalization_error
            .as_ref()
            .map(|(path, reason)| (path.as_path(), reason.as_str())),
        channel_unavailable,
    );
    drop(image_file);
    drop(coverage_file);
    // Read the facts document back off the inherited descriptor. The child wrote
    // through the same open file description, so the offset is at the end —
    // rewind before reading.
    let mut channel_defect: Option<String> = None;
    let mut facts = match facts_file {
        Some(mut file) => {
            use std::io::{Read, Seek};
            file.rewind().map_err(|error| {
                CliError(format!("failed to rewind the run-facts channel: {error}"))
            })?;
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).map_err(|error| {
                CliError(format!("failed to read the run-facts channel: {error}"))
            })?;
            // A channel patina cannot read is patina's own defect: the run
            // is judged `internal`, not waved through as an error of the
            // request, and not judged from half the evidence.
            match output::parse_facts(&bytes) {
                Ok(facts) => facts,
                Err(error) => {
                    channel_defect = Some(error.to_string());
                    None
                }
            }
        }
        None => None,
    };
    let reports = {
        use std::io::{Read, Seek};
        let mut file = reports_file;
        let mut bytes = Vec::new();
        file.rewind()
            .and_then(|()| file.read_to_end(&mut bytes))
            .map_err(|error| CliError(format!("failed to read the reports channel: {error}")))?;
        String::from_utf8_lossy(&bytes).into_owned()
    };
    // The shim's stop record, if it ended the run. Every incarnation has
    // exited and this was the last other holder of the write end, so the read
    // ends at what they wrote.
    drop(stop_writer);
    let stop = {
        use std::io::Read;
        let mut bytes = Vec::new();
        stop_reader
            .read_to_end(&mut bytes)
            .map_err(|error| CliError(format!("failed to read the stop pipe: {error}")))?;
        match output::parse_stop(&bytes) {
            Ok(stop) => stop,
            Err(error) => {
                channel_defect.get_or_insert(error.to_string());
                output::StopChannel::default()
            }
        }
    };
    let runtime_started = stop.started;
    if let Some(mut stop) = stop.stop {
        // A compute stop's sampled PC, named from the executable that ran.
        let location = stop
            .get("yield_point_delta")
            .and_then(serde_json::Value::as_i64)
            .and_then(|delta| crate::coverage::locate(image.bytes(), delta));
        if let (Some(location), serde_json::Value::Object(record)) = (location, &mut stop) {
            record.insert("location".into(), output::location_json(&location));
        }
        let document = facts.get_or_insert_with(
            || serde_json::json!({ "schema": patina_dst_runtime::FACTS_SCHEMA }),
        );
        if let serde_json::Value::Object(root) = document {
            root.insert("stop".into(), stop);
        }
    }
    let coverage = if let Some(path) = &invocation.coverage_out {
        let len = fs::metadata(path)
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        if captured.exit_code == 0 || len > 0 {
            Some(coverage::coverage_summary_from_map(path)?)
        } else {
            None
        }
    } else {
        None
    };
    let (trace_path, seed) = match &invocation.mode {
        NativeRunMode::Seeded { seed } => (None, Some(*seed)),
        NativeRunMode::Record { seed, .. } => (committed_record_trace.clone(), Some(*seed)),
        NativeRunMode::Replay { path, .. } => (Some(path.clone()), None),
    };
    let fingerprint = match &invocation.mode {
        NativeRunMode::Seeded { .. } => None,
        NativeRunMode::Record { .. } if scratch_trace.is_some() => None,
        NativeRunMode::Record { .. } | NativeRunMode::Replay { .. } => {
            Some(DEFAULT_NATIVE_FINGERPRINT.to_string())
        }
    };
    let artifact = resolved.display.display().to_string();
    // How to see this run again, should it not end clean: the replay of its
    // recording when it has one to keep (a replay names itself, so a
    // recording and its replay say the same), else the same `run`.
    let reproduce = match (&trace_path, seed) {
        (Some(trace), _) if scratch_trace.is_none() => Some(format!(
            "patina replay {} {}",
            crate::cli::shell_quote(resolved.display.as_os_str()),
            crate::cli::shell_quote(trace.as_os_str()),
        )),
        (_, Some(seed)) => output::run_again_command(seed),
        (_, None) => None,
    };
    let mut qualifications = Vec::new();
    if invocation.allow_randomized_layout {
        qualifications.push(output::Qualification {
            kind: "randomized_address_layout",
            detail: layout::RANDOMIZED_QUALIFICATION.into(),
        });
    }
    if !downgraded.is_empty() {
        qualifications.push(output::Qualification {
            kind: "unsupported_symbols",
            detail: downgraded
                .iter()
                .map(native_escape_summary)
                .collect::<Vec<_>>()
                .join("; "),
        });
    }
    let exit = output::finalize_run(
        output::RunReport {
            verb: "run",
            artifact: &artifact,
            trace_path,
            trace_scratch: scratch_trace.is_some(),
            trace_facts,
            timeline: "main",
            fingerprint,
            build: Some(build_kind.as_str()),
            seed,
            coverage: coverage.clone(),
            crash_restart,
            facts,
            reports,
            runtime_started,
            channel_defect,
            trace_lost,
            trace_incomplete,
            qualifications,
            rust_program: crate::native_build::started_by_rust_runtime(image.bytes()),
            reproduce,
            mount: invocation.mount.clone(),
        },
        captured,
    )?;
    if let Some(coverage) = coverage
        && !output::options().is_json()
        && let Some(path) = coverage.map_path
    {
        eprintln!(
            "PATINA_COVERAGE map={} edges={}/{} covered_permille={}",
            path.display(),
            coverage.edges_covered,
            coverage.edges_total,
            coverage.covered_permille,
        );
    }
    Ok(exit)
}
