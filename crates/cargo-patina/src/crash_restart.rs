//! Native crash-restart plans, incarnation supervision, and handoffs.

use crate::native_run::{NATIVE_FS_CRASH_RESTART_EXIT, TRACE_CHANNEL_UNAVAILABLE};
use crate::{CliError, NativeRunInvocation, NativeRunMode, hex, output};
use patina_dst_runtime::{CrashPoint, FaultKnob};
use patina_dst_trace::{
    CrashRestartSegments, HandoffSealKey, IncarnationHandoff, Sha256Digest, TraceBundle,
    abandoned_trace_marker, resource_limit_infra_line,
};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

/// How a `--fs-crash-at` run is supervised: the one crash selector, the seed
/// its handoff seal key derives from, and what each incarnation's trace
/// channel carries.
#[cfg(unix)]
pub(super) struct CrashRestartPlan {
    selector: CrashPoint,
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
    /// `restarted` is `None` when the recorded run never crashed.
    Replay {
        crashed: Box<TraceBundle>,
        restarted: Option<(Sha256Digest, Box<TraceBundle>)>,
    },
}

/// The crash-restart plan for a native run, or `None` when the run has no
/// crash selector. Seeded and record runs take the selector from
/// `--fs-crash-at`; a replay takes it, and the incarnations it replays, from
/// its already-loaded trace.
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
    let Some(text) = invocation.knobs.get(FaultKnob::FsCrashAt).first() else {
        return Ok(None);
    };
    let selector = CrashPoint::parse(text).map_err(|error| CliError::usage(error.to_string()))?;
    Ok(Some(CrashRestartPlan {
        selector,
        seed,
        trace,
    }))
}

#[cfg(unix)]
fn crash_restart_replay_plan(
    path: &Path,
    bundle: TraceBundle,
) -> Result<Option<CrashRestartPlan>, CliError> {
    let segments = bundle
        .crash_restart_segments()
        .map_err(|error| CliError(format!("failed to load trace {}: {error}", path.display())))?;
    let selector = bundle
        .metadata
        .faults
        .as_ref()
        .and_then(|faults| faults.crash_at);
    let Some(selector) = selector else {
        if segments.is_some() {
            return Err(CliError(format!(
                "trace {} records a crash-restart lifecycle but no --fs-crash-at selector",
                path.display()
            )));
        }
        return Ok(None);
    };
    let seed = bundle.metadata.root_seed;
    let trace = match segments {
        Some(segments) => CrashRestartTrace::Replay {
            crashed: Box::new(segments.crashed),
            restarted: Some((segments.snapshot_digest, Box::new(segments.restarted))),
        },
        None => CrashRestartTrace::Replay {
            crashed: Box::new(bundle),
            restarted: None,
        },
    };
    Ok(Some(CrashRestartPlan {
        selector: selector.into(),
        seed,
        trace,
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
    /// The recovered filesystem a restarted incarnation boots from, in place of
    /// the run's base image.
    pub(super) restart_snapshot: Option<&'a fs::File>,
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
    selector: CrashPoint,
    reached: bool,
    detail: &str,
) -> CrashRestartRun {
    append_supervisor_line(
        &mut first,
        &format!("PATINA_FS_CRASH_REPLAY_DIVERGENCE selector={selector} {detail}"),
    );
    if first.exit_code == 0 || first.exit_code == NATIVE_FS_CRASH_RESTART_EXIT {
        first.exit_code = 2;
    }
    let report = serde_json::json!({
        "selector": selector_json(selector),
        "reached": reached,
        "crash_count": u8::from(reached),
        "restart_count": 0,
        "incarnations": [{"id": 0, "host_pid": first_host_pid}],
        "terminal_outcome": {"kind": "replay_diverged", "exit_code": first.exit_code, "signal": first.signal},
    });
    CrashRestartRun {
        captured: first,
        report,
        trace: None,
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
    let selector = plan.selector;
    let key = crash_handoff_key(plan.seed, selector);
    let key_hex = hex(&key);
    let handoff = scratch_file("crash-restart handoff channel", &[])?;
    let crashed_trace = match &plan.trace {
        CrashRestartTrace::Seeded => None,
        CrashRestartTrace::Record => Some(scratch_file("incarnation 0 trace channel", &[])?),
        CrashRestartTrace::Replay { crashed, .. } => Some(scratch_file(
            "incarnation 0 trace channel",
            &crashed.to_bytes().map_err(|error| {
                CliError(format!("failed to encode incarnation 0's trace: {error}"))
            })?,
        )?),
    };
    let (first, first_host_pid) = launch(IncarnationLaunch {
        incarnation: 0,
        trace: crashed_trace.as_ref(),
        handoff: Some((&handoff, &key_hex)),
        restart_snapshot: None,
    })?;
    let recorded_crash = match &plan.trace {
        CrashRestartTrace::Replay { crashed, restarted } => Some((crashed, restarted.as_ref())),
        CrashRestartTrace::Seeded | CrashRestartTrace::Record => None,
    };

    if first.exit_code != NATIVE_FS_CRASH_RESTART_EXIT {
        if let Some((_, Some(_))) = recorded_crash {
            let detail = format!(
                "incarnation 0 exited with status {} before the recorded crash",
                first.exit_code
            );
            return Ok(crash_replay_divergence(
                first,
                first_host_pid,
                selector,
                false,
                &detail,
            ));
        }
        let report = serde_json::json!({
            "selector": selector_json(selector),
            "reached": false,
            "crash_count": 0,
            "restart_count": 0,
            "incarnations": [{"id": 0, "host_pid": first_host_pid}],
            "terminal_outcome": {"kind": "exited_without_crash", "exit_code": first.exit_code, "signal": first.signal},
        });
        let trace = match (&plan.trace, &crashed_trace) {
            (CrashRestartTrace::Record, Some(file)) => {
                Some(read_scratch_file(file, "incarnation 0 trace channel")?)
            }
            _ => None,
        };
        return Ok(CrashRestartRun {
            captured: first,
            report,
            trace,
        });
    }

    let handoff_bytes = read_scratch_file(&handoff, "crash-restart handoff channel")?;
    let handoff_digest = Sha256Digest(Sha256::digest(&handoff_bytes).into());
    let verified = IncarnationHandoff::open(&handoff_bytes, &HandoffSealKey::from_bytes(key))
        .map_err(|error| CliError(format!("PATINA_FS_CRASH_INVALID_HANDOFF {error}")))?;
    if verified.from_incarnation != 0 || verified.to_incarnation != 1 {
        return Err(CliError(format!(
            "PATINA_FS_CRASH_INVALID_HANDOFF expected 0->1 restart, got {}->{}",
            verified.from_incarnation, verified.to_incarnation
        )));
    }
    let handed_selector = CrashPoint::from(verified.selector);
    if handed_selector != selector {
        return Err(CliError(format!(
            "PATINA_FS_CRASH_INVALID_HANDOFF selector mismatch: expected {selector}, got {handed_selector}"
        )));
    }
    let snapshot_digest = Sha256Digest(verified.snapshot_digest);

    let restarted_trace = match recorded_crash {
        None if matches!(plan.trace, CrashRestartTrace::Record) => {
            Some(scratch_file("incarnation 1 trace channel", &[])?)
        }
        None => None,
        Some((_, None)) => {
            let detail = format!(
                "the recorded run never crashed, but the replay crashed after {} operations",
                verified.consumed.operations
            );
            return Ok(crash_replay_divergence(
                first,
                first_host_pid,
                selector,
                true,
                &detail,
            ));
        }
        Some((crashed, Some((recorded_digest, restarted)))) => {
            let recorded_operations = crashed.timelines[0].decisions.len() as u64;
            if verified.consumed.operations != recorded_operations {
                let detail = format!(
                    "the replay crashed after {} operations; the recorded crash followed operation {recorded_operations}",
                    verified.consumed.operations
                );
                return Ok(crash_replay_divergence(
                    first,
                    first_host_pid,
                    selector,
                    true,
                    &detail,
                ));
            }
            if snapshot_digest != *recorded_digest {
                let detail = format!(
                    "the replay handed incarnation 1 a recovered filesystem with digest {snapshot_digest}; the recording handed over {recorded_digest}"
                );
                return Ok(crash_replay_divergence(
                    first,
                    first_host_pid,
                    selector,
                    true,
                    &detail,
                ));
            }
            Some(scratch_file(
                "incarnation 1 trace channel",
                &restarted.to_bytes().map_err(|error| {
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
        restart_snapshot: Some(&snapshot),
    })?;

    let terminal_kind = if second.exit_code == 0 && second.signal.is_none() {
        "completed_after_restart"
    } else {
        "restart_child_failed"
    };
    let report = serde_json::json!({
        "selector": selector_json(selector),
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
            "PATINA_FS_CRASH_RESTART selector={selector} host_pid0={first_host_pid} host_pid1={second_host_pid} incarnation0=0 incarnation1=1 operations={} result=restarted",
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
            "PATINA_FS_CRASH_INVALID_HANDOFF incarnation 0 recorded {recorded_operations} operations but its handoff consumed {}",
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
fn scratch_file(purpose: &str, contents: &[u8]) -> Result<fs::File, CliError> {
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
        captured.stderr.extend_from_slice(line.as_bytes());
        captured.stderr.push(b'\n');
    } else {
        eprintln!("{line}");
    }
}

/// The handoff seal key: a function of the run's seed and crash selector, so
/// the record and the replay of one run derive the same key.
#[cfg(unix)]
fn crash_handoff_key(seed: u64, selector: CrashPoint) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"patina-native-crash-restart-handoff-key/v1");
    hasher.update(seed.to_le_bytes());
    hasher.update(selector.to_string().as_bytes());
    hasher.finalize().into()
}

#[cfg(unix)]
fn selector_json(selector: CrashPoint) -> serde_json::Value {
    serde_json::json!({
        "op": selector.op.to_string(),
        "ordinal": selector.ordinal,
        "text": selector.to_string(),
    })
}

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
        captured.stderr.extend_from_slice(line.as_bytes());
    } else {
        eprint!("{line}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use patina_dst_trace::{
        CrashRestartSegments, HandoffSealKey, IncarnationHandoff, Sha256Digest, TraceBundle,
    };
    use std::path::Path;

    /// A verb may not redeclare a global flag. The global output/config switches
    /// are stripped by a pre-pass BEFORE any verb routing, so a verb that
    /// registers the same name can never be reached — and if the two declare
    /// different arities, the pre-pass also eats the following token.
    ///
    /// This is a shipped bug pinned as a class: `campaign --report` was
    /// documented and unreachable, because the global `--report OUT.html`
    /// consumed both it and whatever came next.
    #[cfg(unix)]
    #[test]
    fn crash_restart_replay_plan_refuses_a_crash_lifecycle_without_a_selector() {
        let metadata = patina_dst_trace::RunMetadata::new(7, "fingerprint", 0, "patina");
        assert!(
            metadata.faults.is_none(),
            "the fixture must carry no selector"
        );
        let joined = CrashRestartSegments {
            crashed: TraceBundle::linear(metadata.clone(), 0, Vec::new()),
            snapshot_digest: Sha256Digest([0; 32]),
            restarted: TraceBundle::linear(metadata, 1, Vec::new()),
        }
        .join()
        .unwrap();
        let error = crash_restart_replay_plan(Path::new("joined.patina"), joined)
            .err()
            .expect("a crash lifecycle without a selector must be refused");
        assert!(
            error
                .0
                .contains("crash-restart lifecycle but no --fs-crash-at selector"),
            "{}",
            error.0
        );
    }

    #[test]
    fn corrupt_crash_restart_handoff_is_refused_by_codec_not_env_hook() {
        let key = HandoffSealKey::from_bytes([3; 32]);
        let handoff = IncarnationHandoff {
            compatibility_fingerprint: "fp".into(),
            from_incarnation: 0,
            to_incarnation: 1,
            selector: patina_dst_trace::CrashPointRecord {
                op: patina_dst_trace::FaultCrashOp::Write,
                ordinal: 6,
            },
            consumed: patina_dst_trace::HandoffConsumedState {
                operations: 12,
                lifecycle_order: 12,
            },
            snapshot: patina_dst_fs_mem::MemFs::new().export_snapshot(),
        };
        let mut encoded = handoff.seal(&key).unwrap();
        assert!(IncarnationHandoff::open(&encoded, &key).is_ok());
        *encoded.last_mut().unwrap() ^= 0xff;
        let error = IncarnationHandoff::open(&encoded, &key).unwrap_err();
        assert!(error.to_string().contains("seal mismatch"));
    }
}
