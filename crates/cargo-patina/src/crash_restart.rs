//! Native crash-restart plans, incarnation supervision, and handoffs.

use crate::native_run::{NATIVE_CRASH_RESTART_EXIT, TRACE_CHANNEL_UNAVAILABLE};
use crate::{CliError, NativeRunInvocation, NativeRunMode, hex, output};
use patina_dst_runtime::{CrashKind, FaultKnob, RuntimeError};
use patina_dst_trace::{
    CrashReport, CrashRestartSegments, HandoffSealKey, IncarnationHandoff, Sha256Digest,
    TraceBundle, abandoned_trace_marker, resource_limit_infra_line,
};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

/// How a crashing run is supervised: what its crash takes down, the seed its
/// handoff seal key derives from, and what each incarnation's trace channel
/// carries.
#[cfg(unix)]
pub(super) struct CrashRestartPlan {
    kind: CrashKind,
    seed: u64,
    trace: CrashRestartTrace,
}

#[cfg(unix)]
enum CrashRestartTrace {
    /// A seeded run has no trace channel.
    Seeded,
    /// Each incarnation records its own linear trace; the supervisor joins
    /// them into the run's one crash-restart trace.
    Record,
    /// Each incarnation replays its own segment of the recorded trace.
    Replay(Box<CrashRestartSegments>),
}

/// The crash-restart plan for a native run, or `None` when the run takes no
/// crash. A seeded or record run is supervised when `--crash-permille` gives
/// it a crash rate, whether or not a crash then lands; a replay is
/// supervised when its trace records a crash, and replays that crash where
/// the recording took it, never drawing one of its own.
#[cfg(unix)]
pub(super) fn crash_restart_plan(
    invocation: &NativeRunInvocation,
    replay_trace: Option<TraceBundle>,
) -> Result<Option<CrashRestartPlan>, CliError> {
    let (seed, trace) = match (&invocation.mode, replay_trace) {
        (NativeRunMode::Replay { path, .. }, Some(bundle)) => {
            return crash_restart_replay_plan(path, bundle);
        }
        (NativeRunMode::Replay { .. }, None) => {
            unreachable!("a native replay loads its trace before planning")
        }
        (NativeRunMode::Seeded { seed }, _) => (*seed, CrashRestartTrace::Seeded),
        (NativeRunMode::Record { seed, .. }, _) => (*seed, CrashRestartTrace::Record),
    };
    let Some(permille) = invocation.knobs.get(FaultKnob::CrashPermille).first() else {
        return Ok(None);
    };
    let permille: u16 = permille.parse().map_err(|_| {
        CliError::usage(format!(
            "--crash-permille expects 0..=1000, got {permille:?}"
        ))
    })?;
    if permille == 0 {
        return Ok(None);
    }
    let kind = match invocation.knobs.get(FaultKnob::CrashKind).first() {
        None => CrashKind::default(),
        Some(text) => CrashKind::parse(text).ok_or_else(|| {
            CliError::usage(format!(
                "--crash-kind expects process or machine, got {text:?}"
            ))
        })?,
    };
    Ok(Some(CrashRestartPlan { kind, seed, trace }))
}

#[cfg(unix)]
fn crash_restart_replay_plan(
    path: &Path,
    bundle: TraceBundle,
) -> Result<Option<CrashRestartPlan>, CliError> {
    let segments = bundle
        .crash_restart_segments()
        .map_err(|error| CliError(format!("failed to load trace {}: {error}", path.display())))?;
    let Some(segments) = segments else {
        return Ok(None);
    };
    let kind = bundle.metadata.faults.crash_kind;
    Ok(Some(CrashRestartPlan {
        kind,
        seed: bundle.metadata.root_seed,
        trace: CrashRestartTrace::Replay(Box::new(segments)),
    }))
}

/// The descriptors one incarnation is launched with. Everything else about the
/// launch is common to the run.
#[cfg(unix)]
pub(super) struct IncarnationLaunch<'a> {
    pub(super) incarnation: u64,
    /// The incarnation's trace channel, for a record or replay.
    pub(super) trace: Option<&'a fs::File>,
    /// Incarnation 0's crash handoff channel and its seal key (hex).
    pub(super) handoff: Option<(&'a fs::File, &'a str)>,
    /// Incarnation 0's crash-report pipe (`ENV_CRASH_REPORT_FD`).
    pub(super) crash_report: Option<&'a std::io::PipeWriter>,
    /// What a restarted incarnation boots from, from the crashed one's handoff.
    pub(super) restart: Option<RestartBoot<'a>>,
}

/// What a restarted incarnation boots from: the recovered filesystem, in place
/// of the run's base image, and the realtime the crashed incarnation's clock
/// had reached, which its own realtime carries on from.
#[cfg(unix)]
pub(super) struct RestartBoot<'a> {
    pub(super) snapshot: &'a fs::File,
    pub(super) previous_realtime_nanos: u64,
}

/// A supervised crash-restart run: its merged guest output and status, the
/// `crash_restart` envelope field, and, for a record, the trace bytes to
/// commit.
#[cfg(unix)]
pub(super) struct CrashRestartRun {
    pub(super) captured: output::Captured,
    pub(super) report: serde_json::Value,
    pub(super) trace: Option<Vec<u8>>,
}

/// A replay that departed from the recording at or before the crash: incarnation
/// 1 never runs, and the run keeps incarnation 0's output and envelope, with
/// the named divergence as its last stderr line and a failing status.
#[cfg(unix)]
fn crash_replay_divergence(
    mut first: output::Captured,
    first_host_pid: u32,
    kind: CrashKind,
    reached: bool,
    detail: &str,
) -> CrashRestartRun {
    append_supervisor_line(
        &mut first,
        &format!(
            "PATINA_CRASH_REPLAY_DIVERGENCE kind={} {detail}",
            kind.name()
        ),
    );
    if first.exit_code == 0 || first.exit_code == NATIVE_CRASH_RESTART_EXIT {
        first.exit_code = 2;
    }
    let report = serde_json::json!({
        "crash_kind": kind.name(),
        "attempted": reached,
        "reached": reached,
        "crash_count": u8::from(reached),
        "restart_count": 0,
        "incarnations": [{"id": 0, "host_pid": first_host_pid}],
        "terminal_outcome": {"kind": output::CRASH_REPLAY_DIVERGED, "exit_code": first.exit_code, "signal": first.signal},
    });
    CrashRestartRun {
        captured: first,
        report,
        trace: None,
    }
}

/// Incarnation 0 reached its crash point and could not carry out the crash:
/// patina's failure, so the run is an infra refusal naming `reason`, with the
/// crash attempted and not reached, and incarnation 1 never runs.
#[cfg(unix)]
fn crash_failed(
    mut first: output::Captured,
    first_host_pid: u32,
    kind: CrashKind,
    reason: &str,
    trace: Option<Vec<u8>>,
) -> CrashRestartRun {
    let error = RuntimeError::CrashFailed {
        reason: reason.to_owned(),
    };
    append_supervisor_line(&mut first, &error.to_string());
    if first.exit_code == 0 {
        first.exit_code = 2;
    }
    let report = serde_json::json!({
        "crash_kind": kind.name(),
        "attempted": true,
        "reached": false,
        "crash_count": 0,
        "restart_count": 0,
        "incarnations": [{"id": 0, "host_pid": first_host_pid}],
        "terminal_outcome": {"kind": "crash_failed", "exit_code": first.exit_code, "signal": first.signal},
    });
    CrashRestartRun {
        captured: first,
        report,
        trace,
    }
}

/// Everything incarnation 0 wrote to its crash-report pipe.
#[cfg(unix)]
fn read_crash_reports(mut reader: std::io::PipeReader) -> Result<Vec<u8>, CliError> {
    use std::io::Read;

    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .map_err(|error| CliError(format!("failed to read the crash-report pipe: {error}")))?;
    Ok(bytes)
}

/// Whether incarnation 0 attempted its crash, decided from its crash reports
/// alone: `None` when no crash landed, `Some(Ok(()))`
/// when it handed over, and `Some(Err(reason))` when the crash failed. An
/// attempt with no outcome (the incarnation died in the handoff), and bytes
/// that are not whole reports, are failed crashes too.
#[cfg(unix)]
fn crash_attempt(bytes: Vec<u8>, first: &output::Captured) -> Option<Result<(), String>> {
    let Some(reports) = CrashReport::decode_all(&bytes) else {
        return Some(Err(format!(
            "the crash-report pipe holds {} bytes that are not whole reports",
            bytes.len()
        )));
    };
    match reports.as_slice() {
        [] => None,
        [CrashReport::Attempting, CrashReport::HandedOver] => Some(Ok(())),
        [CrashReport::Attempting, CrashReport::Failed(reason)] => Some(Err(reason.clone())),
        [CrashReport::Attempting] => Some(Err(match first.signal {
            Some(signal) => format!(
                "incarnation 0 was killed by signal {signal} before reporting how its crash ended"
            ),
            None => format!(
                "incarnation 0 exited with status {} before reporting how its crash ended",
                first.exit_code
            ),
        })),
        reports => Some(Err(format!(
            "incarnation 0 reported its crash out of order: {reports:?}"
        ))),
    }
}

/// What a record's incarnation 0 wrote to its trace channel, for a run that
/// ends with that incarnation.
#[cfg(unix)]
fn read_record_segment(
    trace: &CrashRestartTrace,
    channel: Option<&fs::File>,
) -> Result<Option<Vec<u8>>, CliError> {
    match (trace, channel) {
        (CrashRestartTrace::Record, Some(file)) => {
            read_scratch_file(file, "incarnation 0 trace channel").map(Some)
        }
        _ => Ok(None),
    }
}

/// Supervise incarnation 0 until its crash, verify the handoff, and run
/// incarnation 1 from the recovered filesystem.
///
/// A record gives each incarnation its own trace channel and joins the two
/// segments with the handoff's snapshot digest. A replay gives each
/// incarnation its recorded segment, and refuses by name when the replayed
/// crash comes at a different point, or hands over a different filesystem,
/// than the recorded one: the recovered filesystem is re-derived by the
/// replay, never read from the trace.
#[cfg(unix)]
pub(super) fn supervise_crash_restart(
    plan: &CrashRestartPlan,
    mut launch: impl FnMut(IncarnationLaunch<'_>) -> Result<(output::Captured, u32), CliError>,
) -> Result<CrashRestartRun, CliError> {
    let kind = plan.kind;
    let key = crash_handoff_key(plan.seed, kind);
    let key_hex = hex(&key);
    let handoff = scratch_file("crash-restart handoff channel", &[])?;
    let crashed_trace = match &plan.trace {
        CrashRestartTrace::Seeded => None,
        CrashRestartTrace::Record => Some(scratch_file("incarnation 0 trace channel", &[])?),
        CrashRestartTrace::Replay(segments) => Some(scratch_file(
            "incarnation 0 trace channel",
            &segments.crashed.to_bytes().map_err(|error| {
                CliError(format!("failed to encode incarnation 0's trace: {error}"))
            })?,
        )?),
    };
    let (report_reader, report_writer) = std::io::pipe()
        .map_err(|error| CliError(format!("failed to create the crash-report pipe: {error}")))?;
    let (first, first_host_pid) = launch(IncarnationLaunch {
        incarnation: 0,
        trace: crashed_trace.as_ref(),
        handoff: Some((&handoff, &key_hex)),
        crash_report: Some(&report_writer),
        restart: None,
    })?;
    // Incarnation 0 has exited: with the supervisor's own write end closed,
    // the pipe holds everything it reported.
    drop(report_writer);
    let attempt = crash_attempt(read_crash_reports(report_reader)?, &first);
    let recorded_crash = match &plan.trace {
        CrashRestartTrace::Replay(segments) => Some(segments),
        CrashRestartTrace::Seeded | CrashRestartTrace::Record => None,
    };

    if let Some(Err(reason)) = &attempt {
        let trace = read_record_segment(&plan.trace, crashed_trace.as_ref())?;
        return Ok(crash_failed(first, first_host_pid, kind, reason, trace));
    }
    if attempt.is_none() {
        if recorded_crash.is_some() {
            let detail = format!(
                "incarnation 0 exited with status {} before the recorded crash",
                first.exit_code
            );
            return Ok(crash_replay_divergence(
                first,
                first_host_pid,
                kind,
                false,
                &detail,
            ));
        }
        let report = serde_json::json!({
            "crash_kind": kind.name(),
            "attempted": false,
            "reached": false,
            "crash_count": 0,
            "restart_count": 0,
            "incarnations": [{"id": 0, "host_pid": first_host_pid}],
            "terminal_outcome": {"kind": "exited_without_crash", "exit_code": first.exit_code, "signal": first.signal},
        });
        let trace = read_record_segment(&plan.trace, crashed_trace.as_ref())?;
        return Ok(CrashRestartRun {
            captured: first,
            report,
            trace,
        });
    }

    let handoff_bytes = read_scratch_file(&handoff, "crash-restart handoff channel")?;
    let handoff_digest = Sha256Digest(Sha256::digest(&handoff_bytes).into());
    let verified = IncarnationHandoff::open(&handoff_bytes, &HandoffSealKey::from_bytes(key))
        .map_err(|error| CliError(format!("PATINA_CRASH_INVALID_HANDOFF {error}")))?;
    if verified.from_incarnation != 0 || verified.to_incarnation != 1 {
        return Err(CliError(format!(
            "PATINA_CRASH_INVALID_HANDOFF expected 0->1 restart, got {}->{}",
            verified.from_incarnation, verified.to_incarnation
        )));
    }
    if verified.kind != kind {
        return Err(CliError(format!(
            "PATINA_CRASH_INVALID_HANDOFF crash kind mismatch: expected {}, got {}",
            kind.name(),
            verified.kind.name()
        )));
    }
    let snapshot_digest = Sha256Digest(verified.snapshot_digest);

    let restarted_trace = match recorded_crash {
        None if matches!(plan.trace, CrashRestartTrace::Record) => {
            Some(scratch_file("incarnation 1 trace channel", &[])?)
        }
        None => None,
        Some(segments) => {
            let recorded_operations = segments.crashed.timelines[0].decisions.len() as u64;
            if verified.consumed.operations != recorded_operations {
                let detail = format!(
                    "the replay crashed after {} operations; the recorded crash followed operation {recorded_operations}",
                    verified.consumed.operations
                );
                return Ok(crash_replay_divergence(
                    first,
                    first_host_pid,
                    kind,
                    true,
                    &detail,
                ));
            }
            let recorded_digest = segments.snapshot_digest;
            if snapshot_digest != recorded_digest {
                let detail = format!(
                    "the replay handed incarnation 1 a recovered filesystem with digest {snapshot_digest}; the recording handed over {recorded_digest}"
                );
                return Ok(crash_replay_divergence(
                    first,
                    first_host_pid,
                    kind,
                    true,
                    &detail,
                ));
            }
            Some(scratch_file(
                "incarnation 1 trace channel",
                &segments.restarted.to_bytes().map_err(|error| {
                    CliError(format!("failed to encode incarnation 1's trace: {error}"))
                })?,
            )?)
        }
    };

    let snapshot = scratch_file("restart snapshot channel", &verified.snapshot_bytes)?;
    let (second, second_host_pid) = launch(IncarnationLaunch {
        incarnation: 1,
        trace: restarted_trace.as_ref(),
        handoff: None,
        crash_report: None,
        restart: Some(RestartBoot {
            snapshot: &snapshot,
            previous_realtime_nanos: verified.realtime_nanos,
        }),
    })?;

    let terminal_kind = if second.exit_code == 0 && second.signal.is_none() {
        "completed_after_restart"
    } else {
        "restart_child_failed"
    };
    let report = serde_json::json!({
        "crash_kind": kind.name(),
        "attempted": true,
        "reached": true,
        "crash_count": 1,
        "restart_count": 1,
        "incarnations": [
            {"id": verified.from_incarnation, "host_pid": first_host_pid},
            {"id": verified.to_incarnation, "host_pid": second_host_pid}
        ],
        "handoff_digest": handoff_digest.to_string(),
        "snapshot_digest": snapshot_digest.to_string(),
        "consumed": {
            "operations": verified.consumed.operations,
            "lifecycle_order": verified.consumed.lifecycle_order
        },
        "terminal_outcome": {"kind": terminal_kind, "exit_code": second.exit_code, "signal": second.signal},
    });
    let mut captured = first;
    captured.stdout.extend_from_slice(&second.stdout);
    captured.stderr.extend_from_slice(&second.stderr);
    append_supervisor_line(
        &mut captured,
        &format!(
            "PATINA_CRASH_RESTART kind={} host_pid0={first_host_pid} host_pid1={second_host_pid} incarnation0=0 incarnation1=1 operations={} result=restarted",
            kind.name(),
            verified.consumed.operations
        ),
    );
    captured.exit_code = second.exit_code;
    captured.signal = second.signal;
    captured.core = second.core;
    let trace = match (&plan.trace, &crashed_trace, &restarted_trace) {
        (CrashRestartTrace::Record, Some(crashed), Some(restarted)) => {
            Some(join_recorded_incarnations(
                read_scratch_file(crashed, "incarnation 0 trace channel")?,
                &verified,
                read_scratch_file(restarted, "incarnation 1 trace channel")?,
                &mut captured,
            )?)
        }
        _ => None,
    };
    Ok(CrashRestartRun {
        captured,
        report,
        trace,
    })
}

/// The recorded run's one trace: incarnation 0's segment, the crash, and
/// incarnation 1's segment. A segment that is not a bundle (empty, truncated,
/// or an abandoned-trace marker) means the run's trace was lost, and its bytes
/// are what the trace channel carries, so the commit reports the loss exactly
/// as it would for a run that never restarted. A joined trace over the size
/// budget is abandoned, with its `PATINA_INFRA` line in the run's stderr.
#[cfg(unix)]
fn join_recorded_incarnations(
    crashed: Vec<u8>,
    handoff: &patina_dst_trace::VerifiedIncarnationHandoff,
    restarted: Vec<u8>,
    captured: &mut output::Captured,
) -> Result<Vec<u8>, CliError> {
    let Ok(crashed_bundle) = TraceBundle::from_slice(&crashed) else {
        return Ok(crashed);
    };
    let recorded_operations = crashed_bundle.timelines[0].decisions.len() as u64;
    if recorded_operations != handoff.consumed.operations {
        return Err(CliError(format!(
            "PATINA_CRASH_INVALID_HANDOFF incarnation 0 recorded {recorded_operations} operations but its handoff consumed {}",
            handoff.consumed.operations
        )));
    }
    let Ok(restarted_bundle) = TraceBundle::from_slice(&restarted) else {
        return Ok(restarted);
    };
    let joined = CrashRestartSegments {
        crashed: crashed_bundle,
        snapshot_digest: Sha256Digest(handoff.snapshot_digest),
        restarted: restarted_bundle,
    }
    .join()
    .map_err(|error| CliError(format!("failed to join the crash-restart trace: {error}")))?;
    match joined.to_bytes() {
        Ok(bytes) => Ok(bytes),
        Err(error) if error.is_resource_limit() => {
            append_supervisor_line(captured, resource_limit_infra_line(&error).trim_end());
            Ok(abandoned_trace_marker("resource-limit", &error.to_string()))
        }
        Err(error) => Err(CliError(format!(
            "failed to encode the crash-restart trace: {error}"
        ))),
    }
}

/// An anonymous host file holding `contents`, rewound for the child to read.
#[cfg(unix)]
pub(crate) fn scratch_file(purpose: &str, contents: &[u8]) -> Result<fs::File, CliError> {
    use std::io::{Seek, Write};

    let mut file = tempfile::tempfile()
        .map_err(|error| CliError(format!("failed to create the {purpose}: {error}")))?;
    file.write_all(contents)
        .and_then(|()| file.rewind())
        .map_err(|error| CliError(format!("failed to fill the {purpose}: {error}")))?;
    Ok(file)
}

/// Everything a child wrote into a scratch channel.
#[cfg(unix)]
fn read_scratch_file(file: &fs::File, purpose: &str) -> Result<Vec<u8>, CliError> {
    use std::io::{Read, Seek};

    let mut file = file;
    let mut bytes = Vec::new();
    file.rewind()
        .and_then(|()| file.read_to_end(&mut bytes))
        .map_err(|error| CliError(format!("failed to read the {purpose}: {error}")))?;
    Ok(bytes)
}

/// A supervisor line in the run's stderr: appended to captured output, or
/// printed where the guest's own stderr went.
#[cfg(unix)]
fn append_supervisor_line(captured: &mut output::Captured, line: &str) {
    if captured.captured {
        output::end_guest_line(&mut captured.stderr);
        captured.stderr.extend_from_slice(line.as_bytes());
        captured.stderr.push(b'\n');
    } else {
        eprintln!("{line}");
    }
}

/// The handoff seal key: a function of the run's seed and crash kind, so the
/// record and the replay of one run derive the same key.
#[cfg(unix)]
fn crash_handoff_key(seed: u64, kind: CrashKind) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"patina-native-crash-restart-handoff-key/v2");
    hasher.update(seed.to_le_bytes());
    hasher.update(kind.name().as_bytes());
    hasher.finalize().into()
}

/// Append the supervisor's human `PATINA_INFRA native_run` line to the run's
/// stderr: the guest's death signal and any trace the run left incomplete.
#[cfg(unix)]
pub(super) fn append_native_infra_marker(
    captured: &mut output::Captured,
    signal: Option<i32>,
    trace_error: Option<(&Path, &str)>,
    channel_unavailable: Option<i32>,
) {
    if signal.is_none() && trace_error.is_none() {
        return;
    }
    let mut line = String::from("PATINA_INFRA native_run");
    if let Some(signal) = signal {
        line.push_str(&format!(" signal={signal}"));
    }
    if let Some((path, reason)) = trace_error {
        line.push_str(&format!(
            " trace=incomplete trace_path={:?} reason={:?}",
            path.display().to_string(),
            reason
        ));
    }
    line.push('\n');
    // A channel failure is patina's own operational condition, not a finding, so
    // it says so in the attributable form the envelope reads: one stable
    // sentence (the refusal class keys on it, so every such generation dedups
    // onto ONE signature instead of one per scratch path) carrying the status
    // the GUEST itself reached, which stays the run's answer when it has one.
    if let Some(guest_exit_code) = channel_unavailable {
        line.push_str(&format!(
            "{TRACE_CHANNEL_UNAVAILABLE} guest_exit_code={guest_exit_code} — the trace could \
not be written, so this generation has no replay artifact; the guest's own verdict stands.\n"
        ));
    }
    if captured.captured {
        output::end_guest_line(&mut captured.stderr);
        captured.stderr.extend_from_slice(line.as_bytes());
    } else {
        eprint!("{line}");
    }
}
