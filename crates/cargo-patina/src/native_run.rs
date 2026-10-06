//! Native pre-run gates, trace channels, and child execution.

use crate::audit::{native_escape_summary, push_native_escape_provenance_lines};
#[cfg(unix)]
use crate::crash_restart::{
    IncarnationLaunch, append_native_infra_marker, crash_restart_plan, supervise_crash_restart,
};
use crate::native_build::{
    SchedulePolicyFingerprint, binary_instrumentation, native_policy_from_trace,
    native_run_fingerprint, resolve_artifact, trace_has_buggify,
};
use crate::output;
use crate::parse::{knob_env_pairs, knob_env_vars, liveness_env_pairs, schedule_env_pairs};
use crate::{
    CliError, NATIVE_GUEST_ARGV0, NativeRunInvocation, NativeRunMode, UnsupportedPolicy, coverage,
};
#[cfg(unix)]
use crate::{F_GETFD, F_SETFD, FD_CLOEXEC, fcntl};
use patina_dst_fs_mem::{FsImage, FsImageEntry};
use patina_dst_runtime::{
    ENV_BUGGIFY, ENV_BUGGIFY_ACTIVATION, ENV_BUGGIFY_AFTER_SETUP, ENV_BUGGIFY_CUTOFF,
    ENV_COVERAGE_FD, ENV_DEFER_INIT, ENV_FINGERPRINT, ENV_FS_IMAGE_FD, ENV_GUEST_ARGV,
    ENV_GUEST_CWD, ENV_GUEST_ENV, ENV_GUEST_HOSTNAME, ENV_INITIAL_STACK, ENV_MODE,
    ENV_REALTIME_EPOCH_NANOS, ENV_SEED, ENV_STEP_BUDGET, ENV_TRACE_FD,
    NATIVE_INITIAL_STACK_TRAILER_SLOTS,
};
use patina_dst_target::{
    NativeAudit, NativeEscape, TargetError, native_binary_has_sud_marker,
    native_binary_has_tsc_marker, native_binary_is_shim_linked, native_deny_trap_armed,
    native_escape_is_sud_manageable, native_escape_is_tsc_manageable, render_compat_mode_note,
    render_cpu_nondeterminism_note, render_thread_pointer_note, render_tsc_managed_note,
    shim_control_plane_symbols,
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
mod trace;

pub(super) use child::NATIVE_FS_CRASH_RESTART_EXIT;
#[cfg(unix)]
pub(super) use child::NativeChildStatus;
use child::encode_guest_argv;
#[cfg(unix)]
pub(super) use child::native_child_status;
use child::reconcile_replay_argv;
#[cfg(unix)]
use child::spawn_native_child;
#[cfg(unix)]
use child::wait_native_child_once;
use fs_image::build_fs_image_file;
pub(super) use gate::effective_native_allow;
pub(super) use gate::emit_native_deny_trap_note;
use gate::native_prerun_gate;
pub(super) use gate::target_has_sud;
use trace::NativeTraceSink;
pub(crate) use trace::TRACE_CHANNEL_UNAVAILABLE;
use trace::TraceCommitFailure;
use trace::write_unsupported_sidecar;

#[cfg(unix)]
pub(super) fn execute_native_run(invocation: NativeRunInvocation) -> Result<i32, CliError> {
    use std::os::unix::io::AsRawFd;
    use std::os::unix::process::CommandExt;

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
    let downgraded =
        match native_prerun_gate(&binary, &invocation.allow, &invocation.allow_unsupported) {
            Ok(downgraded) => downgraded,
            Err(error) if output::facts_active() => {
                output::emit_native_prerun_refusal(&binary, error.to_string());
                return Ok(2);
            }
            Err(error) => return Err(error),
        };

    // A binary built with `--yield-points` schedules under a different (denser)
    // policy, so its recorded traces must not cross-replay with a plain binary.
    // Detect the linked hook's marker and fold it into the compatibility
    // fingerprint; the same binary is inspected on record and replay, so the
    // suffix is applied consistently and a policy mismatch is rejected.
    let instrumentation = binary_instrumentation(&binary)?;
    if invocation.coverage_out.is_some() && !instrumentation.has_coverage() {
        return Err(CliError::usage(
            "--coverage-out requires a native binary built with `cargo patina build --yield-points` or `--coverage-points`; coverage rides the SanitizerCoverage edge counters",
        ));
    }

    // Starvation intervals reorder real thread execution adversarially. A guest
    // whose synchronization is INTERPOSED (mutex/condvar/futex) is always safe —
    // every wait is a scheduling boundary the aging guarantee can act on. But a
    // guest with an *invisible atomic spinlock* (e.g. std's queue `RwLock`/`Parker`
    // fast path) held across an interposed boundary can wedge: the adversarial
    // deferral schedules the spinner while the lock holder is starved, and the
    // spinner's atomics-only loop offers no boundary for aging to force the holder
    // — the exact cooperative-scheduling limitation the vacuous-schedule warning
    // flags. `--yield-points` closes it (loop backedges become boundaries), so
    // starvation there is always liveness-safe; `--coverage-points=N` closes it
    // too, one boundary every N basic blocks, which bounds the aging delay by N
    // blocks rather than eliminating it. Warn loudly when starvation is enabled
    // on a binary with neither rather than risk a silent hang.
    if invocation.schedule.starve.is_some() && !instrumentation.preempts_inside_atomics() {
        eprintln!(
            "PATINA WARNING: starvation intervals (--starve) are enabled on a binary built \
WITHOUT a mode that makes an atomics-only window schedulable (`--yield-points`, or \
`--coverage-points=N`). Starvation is liveness-safe for guests whose synchronization is \
interposed (mutex/condvar/futex), but a guest with an invisible atomic spinlock (e.g. std's queue \
RwLock/Parker fast path) held across a boundary can WEDGE under adversarial deferral — the same \
atomics-only window the vacuous-schedule diagnostic flags as unreachable. Rebuild with \
`cargo patina build --yield-points` (a boundary at every basic block) or `--coverage-points=N` \
(one every N basic blocks, far cheaper) to make those windows schedulable so starvation stays \
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
    // the trace bundle and the coverage map.
    let facts_file = if output::facts_active() {
        Some(tempfile::tempfile().map_err(|error| {
            CliError(format!("failed to create the run-facts channel: {error}"))
        })?)
    } else {
        None
    };

    // A replay reads its trace once: the guest arguments, the fingerprint
    // components and the crash-restart plan all come from this one load.
    let replay_trace = match &invocation.mode {
        NativeRunMode::Replay { path, .. } => Some(TraceBundle::load(path).map_err(|error| {
            CliError(format!("failed to read trace {}: {error}", path.display()))
        })?),
        NativeRunMode::Seeded { .. } | NativeRunMode::Record { .. } => None,
    };

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
        NativeRunMode::Record {
            seed, fingerprint, ..
        } => vec![
            (ENV_MODE, "record".into()),
            (ENV_SEED, seed.to_string()),
            (
                ENV_FINGERPRINT,
                native_run_fingerprint(
                    fingerprint,
                    instrumentation,
                    image_hash.as_deref(),
                    invocation.buggify.is_some(),
                    &SchedulePolicyFingerprint::from_schedule(&invocation.schedule),
                ),
            ),
            // Record the guest arguments into the trace metadata so a later
            // `replay` restores them without the `--` section being re-passed.
            // Always forwarded (even when empty) so a zero-argument run records
            // `[]` — distinct from an old trace's absent field, so replaying it
            // reproduces zero arguments rather than inheriting whatever the
            // command line supplies.
            (ENV_GUEST_ARGV, encode_guest_argv(&program_args)?),
        ],
        NativeRunMode::Replay { fingerprint, .. } => {
            // Reconstruct the `+buggify` and `+pct`/`+starve`/`+swarm`
            // fingerprint components from the trace so replay is self-contained;
            // a policy trace replayed against a plain build still fails closed on
            // the fingerprint.
            let bundle = replay_trace
                .as_ref()
                .expect("a native replay loads its trace first");
            let buggify = invocation.buggify.is_some() || trace_has_buggify(bundle);
            let policy = native_policy_from_trace(bundle);
            vec![
                (ENV_MODE, "replay".into()),
                // Startup effects (notably AT_RANDOM) happen before the shim
                // can read the trace. They need the same seed as the runtime.
                (ENV_SEED, bundle.metadata.root_seed.to_string()),
                (
                    ENV_FINGERPRINT,
                    native_run_fingerprint(
                        fingerprint,
                        instrumentation,
                        image_hash.as_deref(),
                        buggify,
                        &policy,
                    ),
                ),
            ]
        }
    };

    // The shim publishes the deterministic map into the ORIGINAL stack envp.
    // Reserve room for its entries plus a disjoint copy of the platform trailer
    // (ELF auxv / Darwin apple vector); libc/dyld keep the original trailer.
    // Replay restores its map from metadata, not the normally empty CLI map.
    // A deferred harness starts empty and later replaces environ at installation.
    let startup_env_entries = if invocation.harness {
        0
    } else if let Some(bundle) = &replay_trace {
        bundle.metadata.guest_env.as_ref().map_or(0, BTreeMap::len)
    } else {
        invocation.environment.len()
    };

    let crash_restart_plan = crash_restart_plan(&invocation, replay_trace)?;
    if crash_restart_plan.is_some() && invocation.schedule.starve.is_some() {
        return Err(CliError::usage(
            "native --fs-crash-at crash-restart with --starve is not implemented; refusing rather than mixing the restart supervisor with the starvation stall backstop",
        ));
    }

    // Every incarnation of the run is launched from this one description; only
    // its descriptors (trace channel, base filesystem, crash handoff) differ. A
    // run without a crash selector is the single incarnation 0. Returns the
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
            command.env(format!("_PATINA_ENVP_SLOT_{slot}"), "");
        }
        // A `patina-dst-harness` binary (usage mode 2) defers runtime
        // installation to its `run`/`run_with` call: tell the packaged
        // constructor to capture/scrub the control plane and register
        // finalization but NOT install the runtime. Applies uniformly to
        // seeded/record and replay so the harness owns installation on every
        // path. An interposed effect before the harness installs fails closed.
        if invocation.harness {
            command.env(ENV_DEFER_INIT, "1");
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
        // The guest's environment is cleared above, so every end-of-run report
        // knob the operator set has to be forwarded explicitly or it never
        // reaches the guest at all. Driven by `Report::ALL` rather than a
        // hand-kept list, so a report added to the runtime is silenceable on
        // native the day it exists.
        if let Some(value) = env::var_os("PATINA_COMPUTE_WATCHDOG_MS") {
            command.env("PATINA_COMPUTE_WATCHDOG_MS", value);
        }
        for report in patina_dst_runtime::Report::ALL {
            if let Some(value) = env::var_os(report.env()) {
                command.env(report.env(), value);
            }
        }
        if !invocation.environment.is_empty() {
            let encoded = serde_json::to_string(&invocation.environment).map_err(|error| {
                CliError(format!(
                    "failed to encode native guest environment: {error}"
                ))
            })?;
            command.env(ENV_GUEST_ENV, encoded);
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
        // The boundary-operation budget is a supervisor-side bound, not recorded
        // run semantics, so it is supplied per invocation on every family alike.
        if let Some(budget) = invocation.step_budget {
            command.env(ENV_STEP_BUDGET, budget.to_string());
        }
        // Forward whatever fault knobs the operator supplied to the guest,
        // scrubbing every knob's variable first so an ambient value cannot leak
        // into a run that set none. On record and seeded runs these configure
        // the faults and are recorded into the trace metadata. Native replay
        // does not accept semantic re-supply; the trace's recorded configuration
        // is authoritative and restored by the runtime.
        for variable in knob_env_vars() {
            command.env_remove(variable);
        }
        for (name, value) in knob_env_pairs(&invocation.knobs)? {
            command.env(name, value);
        }
        // Forward the cooperative-SUT (buggify) knobs. Presence of
        // `PATINA_BUGGIFY` enables buggify; its value (if any) is the firing
        // per-mille. Like the fault knobs, these are recorded into trace metadata
        // and restored from the trace on native replay, rather than re-supplied
        // as semantic flags.
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
        // knobs through the same control plane. Recorded into the trace metadata
        // and restored from the trace on native replay; the fingerprint suffix
        // rejects a cross-policy replay.
        for (name, value) in schedule_env_pairs(&invocation.schedule) {
            command.env(name, value);
        }
        // Forward the liveness-watchdog knobs through the same control plane. The
        // watchdog is schedule-invariant: recorded (informational) but not
        // fingerprinted, so a watchdog trace replays against any build.
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
        // A restarted incarnation boots from the recovered filesystem instead of
        // the run's base image.
        match (launch.restart_snapshot, &image_file) {
            (Some(file), _) => {
                command.env(
                    patina_dst_runtime::ENV_RESTART_SNAPSHOT_FD,
                    file.as_raw_fd().to_string(),
                );
                fds.push(file.as_raw_fd());
            }
            (None, Some(image)) => {
                command.env(ENV_FS_IMAGE_FD, image.file.as_raw_fd().to_string());
                fds.push(image.file.as_raw_fd());
            }
            (None, None) => {}
        }
        Ok((command, fds))
    };

    // Record mode writes to a sibling temporary file first; the supervisor
    // validates and renames it to the requested path only after the run ends.
    let mut trace_sink = match &invocation.mode {
        NativeRunMode::Record { path, .. } => Some(NativeTraceSink::create(path)?),
        NativeRunMode::Seeded { .. } | NativeRunMode::Replay { .. } => None,
    };

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
        // descriptor named by `PATINA_TRACE_FD` stays valid.
        let replay_trace_file = match &invocation.mode {
            NativeRunMode::Replay { path, .. } => Some(fs::File::open(path).map_err(|error| {
                CliError(format!("failed to open trace {}: {error}", path.display()))
            })?),
            NativeRunMode::Seeded { .. } | NativeRunMode::Record { .. } => None,
        };
        let trace = trace_sink
            .as_ref()
            .map(NativeTraceSink::file)
            .or(replay_trace_file.as_ref());
        let (mut command, inherited_fds) = incarnation_command(IncarnationLaunch {
            incarnation: 0,
            trace,
            handoff: None,
            restart_snapshot: None,
        })?;
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
        // `PATINA_STARVATION_STALL_SECS` override) so a healthy run normally finishes
        // far inside it — a 10,000-iteration `turso_stress` generation takes about
        // 30 s — though a busy enough host can still cross it; it never touches the
        // recorded operation stream of a run that completes.
        // It is an ELAPSED-TIME deadline, not a progress detector: the supervisor
        // cannot see the scheduler's decision counter, so it cannot separate a wedge
        // from a run that is merely slower than the deadline. That is exactly why a
        // campaign files exit 111 under a class that is NOT counted as a bug found
        // (`CampaignClass::is_finding`), and why the counter is the signal to publish
        // if the two ever need telling apart from the outside.
        if invocation.schedule.starve.is_some() {
            let stall_secs: u64 = std::env::var("PATINA_STARVATION_STALL_SECS")
                .ok()
                .and_then(|value| value.trim().parse().ok())
                .filter(|value| *value > 0)
                .unwrap_or(60);
            let capture = output::capture_active();
            if capture {
                command.stdout(Stdio::piped()).stderr(Stdio::piped());
            }
            let (mut child, inherited_guard) =
                spawn_native_child(&mut command, &binary, &inherited_fds)?;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(stall_secs);
            loop {
                match child.try_wait() {
                    Ok(Some(_status)) => break,
                    Ok(None) => {
                        if std::time::Instant::now() >= deadline {
                            let _ = child.kill();
                            let _ = child.wait();
                            eprintln!(
                                "patina: starvation stall — the run did not finish within {stall_secs}s \
    under --starve. What this backstop measures is elapsed wall clock, not scheduler progress: the \
    supervisor cannot see the decision counter, so it cannot tell a guest spinning inside an \
    uninstrumented atomic critical section (std carries no yield point, so cooperative scheduling \
    cannot preempt a spinner while the lock holder is starved — the documented starvation limitation, \
    and the likely cause) from a run that is merely slower than this deadline. Not a liveness \
    guarantee, and not a verdict on the guest — see IMPLEMENTATION.md \"Slice 7: exploration tier\". \
    Killed with a nonzero exit."
                            );
                            inherited_guard.restore()?;
                            drop(trace_sink);
                            drop(replay_trace_file);
                            drop(image_file);
                            drop(coverage_file);
                            drop(facts_file);
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
            inherited_guard.restore()?;
            let NativeChildStatus {
                exit_code,
                signal,
                core,
            } = native_child_status(output.status);
            output::Captured {
                exit_code,
                stdout: output.stdout,
                stderr: output.stderr,
                captured: capture,
                signal,
                core,
            }
        } else {
            wait_native_child_once(&mut command, &binary, &inherited_fds)?.0
        }
    };
    let mut committed_record_trace = None;
    let mut trace_finalization_error: Option<(PathBuf, String)> = None;
    let mut channel_unavailable: Option<i32> = None;
    if let Some(sink) = trace_sink {
        match sink.commit() {
            Ok(path) => {
                if let Err(error) = write_unsupported_sidecar(&path, &downgraded) {
                    let _ = fs::remove_file(&path);
                    return Err(error);
                }
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
                if matches!(
                    failure,
                    TraceCommitFailure::Broken(_) | TraceCommitFailure::Unavailable(_)
                ) && captured.exit_code == 0
                {
                    // The guest's own status is preserved for the classifier on
                    // the `guest_exit_code=` of the channel line below; this
                    // status is patina's, and says the artifact is missing.
                    channel_unavailable =
                        matches!(failure, TraceCommitFailure::Unavailable(_)).then_some(0);
                    captured.exit_code = 2;
                } else if matches!(failure, TraceCommitFailure::Unavailable(_)) {
                    channel_unavailable = Some(captured.exit_code);
                }
                trace_finalization_error = Some((path, failure.reason().to_string()));
            }
        }
    }
    let native_signal = captured.signal;
    append_native_infra_marker(
        &mut captured,
        native_signal,
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
    let facts = match facts_file {
        Some(mut file) => {
            use std::io::{Read, Seek};
            file.rewind().map_err(|error| {
                CliError(format!("failed to rewind the run-facts channel: {error}"))
            })?;
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).map_err(|error| {
                CliError(format!("failed to read the run-facts channel: {error}"))
            })?;
            output::parse_facts(&bytes)?
        }
        None => None,
    };
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
        NativeRunMode::Record { fingerprint, .. } | NativeRunMode::Replay { fingerprint, .. } => {
            Some(fingerprint.clone())
        }
    };
    let artifact = resolved.display.display().to_string();
    let exit = output::finalize_run(
        output::RunReport {
            verb: "run",
            family: "native",
            artifact: &artifact,
            trace_path,
            timeline: "main",
            fingerprint,
            seed,
            coverage: coverage.clone(),
            depth: None,
            crash_restart,
            facts,
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

/// Distinct exit code the supervisor returns when the starvation stall backstop
/// kills a hung `--starve` run, so a sweep can classify `STARVATION_STALL` rather
/// than treat the run as an ordinary crash.
pub(super) const STARVATION_STALL_EXIT: i32 = 111;

#[cfg(not(unix))]
pub(super) fn execute_native_run(_invocation: NativeRunInvocation) -> Result<i32, CliError> {
    Err(CliError(
        "native-run requires a Unix host for the PATINA_TRACE_FD supervisor channel".into(),
    ))
}
