//! Trace transport, recording lifecycle, effect reconciliation, and outcome decoding.

use crate::liveness::SPIN_RESCUE_CLOCK_OPS;
use crate::{Context, RuntimeError, facts};

use crate::reports::{
    emit_clock_fault_report, emit_customop_fault_report, emit_dns_fault_report,
    emit_entropy_fault_report, emit_fs_fault_report, emit_liveness_report, emit_net_fault_report,
    emit_schedule_policy_report, emit_schedule_report, emit_sdk_report, emit_swarm_report,
};
use crate::schedule::classify_yield_divergence;
use patina_dst_abi::{
    Datagram, EffectError, ErrorCode, Fd, FsDirectoryEntry, FsMetadata, Operation, Outcome,
    SendReport, SocketId, TaskId, TcpAccepted,
};
use patina_dst_trace::{
    BranchSession, Recorder, Replayer, abandoned_trace_marker, lock_exclusive, path_names,
    resource_limit_infra_line,
};
use std::ffi::OsString;
use std::fs;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

pub(super) const READ_CHUNK_SIZE: usize = 4096;

pub(super) const MAX_READ_FILE_BYTES: usize = 64 * 1024 * 1024;

/// Byte-level trace channel supplied by an embedder when the runtime must not
/// open trace files itself (for example inside a fully interposed native
/// process whose ambient file symbols route back into Patina).
pub trait TraceTransport: Send {
    /// Read the complete serialized trace bundle for replay.
    fn read_bundle(&mut self) -> std::io::Result<Vec<u8>>;
    /// Deliver the complete serialized trace bundle at record finalization.
    fn write_bundle(&mut self, bytes: &[u8]) -> std::io::Result<()>;
    /// Export a borrowed prefix at an asynchronous native stop. Embedders that
    /// share a guest allocator must override this with allocation-free I/O.
    fn write_prefix(&mut self, recorder: &Recorder) -> std::io::Result<()> {
        let mut bytes = Vec::new();
        recorder
            .write_prefix(&mut bytes)
            .map_err(std::io::Error::other)?;
        self.write_bundle(&bytes)
    }
}

pub(super) enum Execution {
    Seeded,
    Record {
        recorder: Recorder,
        sink: RecordSink,
    },
    Replay(Replayer),
    Branch {
        // Boxed: a `BranchSession` is by far the largest variant payload, and
        // branch runs are the rare path, so keeping it out of line avoids
        // inflating every `Execution` (clippy::large_enum_variant).
        session: Box<BranchSession>,
        _reservation: RecordReservation,
    },
}

pub(super) enum RecordSink {
    Path {
        path: PathBuf,
        _reservation: RecordReservation,
    },
    Transport(Box<dyn TraceTransport>),
}

/// One recorder's claim on a trace path: an exclusive advisory lock on
/// `.<trace>.lock` beside it, held for the recorder's life. The kernel releases
/// the lock when the recorder dies without unwinding, so a crashed recording
/// never locks its path; a lock file left behind by one is unlocked and taken
/// over by the next recorder.
pub(super) struct RecordReservation {
    lock_path: PathBuf,
    _lock: File,
}

impl RecordReservation {
    pub(super) fn acquire(trace_path: &Path) -> Result<Self, RuntimeError> {
        let reservation = Self::acquire_lock(trace_path)?;
        if trace_path.exists() {
            return Err(RuntimeError::Config(format!(
                "refusing to overwrite existing trace {}",
                trace_path.display()
            )));
        }
        Ok(reservation)
    }

    pub(super) fn acquire_branch(trace_path: &Path) -> Result<Self, RuntimeError> {
        if !trace_path.is_file() {
            return Err(RuntimeError::Config(format!(
                "cannot branch from missing trace {}",
                trace_path.display()
            )));
        }
        Self::acquire_lock(trace_path)
    }

    fn acquire_lock(trace_path: &Path) -> Result<Self, RuntimeError> {
        let parent = trace_path
            .parent()
            .filter(|value| !value.as_os_str().is_empty());
        if let Some(parent) = parent {
            fs::create_dir_all(parent).map_err(|source| RuntimeError::Io {
                action: format!("create trace directory {}", parent.display()),
                source,
            })?;
        }
        let lock_path = record_lock_path(trace_path)?;
        let io_error = |source| RuntimeError::Io {
            action: format!(
                "reserve trace {} using {}",
                trace_path.display(),
                lock_path.display()
            ),
            source,
        };
        loop {
            let lock = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .open(&lock_path)
                .map_err(io_error)?;
            match lock_exclusive(&lock, false) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    return Err(RuntimeError::Config(format!(
                        "refusing to record trace {}: another Patina recorder holds {}",
                        trace_path.display(),
                        lock_path.display()
                    )));
                }
                Err(error) => return Err(io_error(error)),
            }
            // A releasing recorder unlinks the lock file before closing it, so a
            // lock won on a descriptor opened before that unlink guards a name
            // no other recorder opens; take the file the name holds now instead.
            if path_names(&lock_path, &lock).map_err(io_error)? {
                return Ok(Self {
                    lock_path,
                    _lock: lock,
                });
            }
        }
    }
}

impl Drop for RecordReservation {
    /// Unlink the lock file while still holding its lock, which is released
    /// when `_lock` closes after this.
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_path);
    }
}

pub(super) enum FilesystemExpected {
    Execute(Option<(u64, Outcome)>),
    Captured(Outcome),
}

fn record_lock_path(trace_path: &Path) -> Result<PathBuf, RuntimeError> {
    let file_name = trace_path.file_name().ok_or_else(|| {
        RuntimeError::Config(format!(
            "trace path has no file name: {}",
            trace_path.display()
        ))
    })?;
    let mut lock_name = OsString::from(".");
    lock_name.push(file_name);
    lock_name.push(".lock");
    Ok(trace_path.with_file_name(lock_name))
}

fn invalid_outcome(operation: &Operation, outcome: Outcome) -> RuntimeError {
    RuntimeError::InvalidOutcome {
        operation: Box::new(operation.clone()),
        outcome: Box::new(outcome),
    }
}

pub(super) fn decode_unit(operation: &Operation, outcome: Outcome) -> Result<(), RuntimeError> {
    match outcome {
        Outcome::Unit => Ok(()),
        Outcome::Error(error) => Err(error.into()),
        other => Err(invalid_outcome(operation, other)),
    }
}

pub(super) fn decode_handle(operation: &Operation, outcome: Outcome) -> Result<Fd, RuntimeError> {
    match outcome {
        Outcome::Handle(fd) => Ok(fd),
        Outcome::Error(error) => Err(error.into()),
        other => Err(invalid_outcome(operation, other)),
    }
}

pub(super) fn decode_bytes(
    operation: &Operation,
    outcome: Outcome,
) -> Result<Vec<u8>, RuntimeError> {
    match outcome {
        Outcome::Bytes(bytes) => Ok(bytes),
        Outcome::Error(error) => Err(error.into()),
        other => Err(invalid_outcome(operation, other)),
    }
}

pub(super) fn decode_string(
    operation: &Operation,
    outcome: Outcome,
) -> Result<String, RuntimeError> {
    let bytes = decode_bytes(operation, outcome)?;
    String::from_utf8(bytes).map_err(|error| {
        EffectError::new(
            ErrorCode::InvalidInput,
            format!("filesystem read_link target is not UTF-8: {error}"),
        )
        .into()
    })
}

pub(super) fn decode_u64(operation: &Operation, outcome: Outcome) -> Result<u64, RuntimeError> {
    match outcome {
        Outcome::U64(value) => Ok(value),
        Outcome::Error(error) => Err(error.into()),
        other => Err(invalid_outcome(operation, other)),
    }
}

pub(super) fn decode_usize(operation: &Operation, outcome: Outcome) -> Result<usize, RuntimeError> {
    match outcome {
        Outcome::Usize(value) => Ok(value),
        Outcome::Error(error) => Err(error.into()),
        other => Err(invalid_outcome(operation, other)),
    }
}

pub(super) fn decode_metadata(
    operation: &Operation,
    outcome: Outcome,
) -> Result<FsMetadata, RuntimeError> {
    match outcome {
        Outcome::Metadata(metadata) => Ok(metadata),
        Outcome::Error(error) => Err(error.into()),
        other => Err(invalid_outcome(operation, other)),
    }
}

pub(super) fn decode_directory_entries(
    operation: &Operation,
    outcome: Outcome,
) -> Result<Vec<FsDirectoryEntry>, RuntimeError> {
    match outcome {
        Outcome::DirectoryEntries(entries) => Ok(entries),
        Outcome::Error(error) => Err(error.into()),
        other => Err(invalid_outcome(operation, other)),
    }
}

pub(super) fn decode_task(operation: &Operation, outcome: Outcome) -> Result<TaskId, RuntimeError> {
    match outcome {
        Outcome::Task(task) => Ok(task),
        Outcome::Error(error) => Err(error.into()),
        other => Err(invalid_outcome(operation, other)),
    }
}

pub(super) fn decode_optional_task(
    operation: &Operation,
    outcome: Outcome,
) -> Result<Option<TaskId>, RuntimeError> {
    match outcome {
        Outcome::OptionalTask(task) => Ok(task),
        Outcome::Error(error) => Err(error.into()),
        other => Err(invalid_outcome(operation, other)),
    }
}

pub(super) fn decode_socket(
    operation: &Operation,
    outcome: Outcome,
) -> Result<SocketId, RuntimeError> {
    match outcome {
        Outcome::Socket(socket) => Ok(socket),
        Outcome::Error(error) => Err(error.into()),
        other => Err(invalid_outcome(operation, other)),
    }
}

pub(super) fn decode_send_report(
    operation: &Operation,
    outcome: Outcome,
) -> Result<SendReport, RuntimeError> {
    match outcome {
        Outcome::SendReport(report) => Ok(report),
        Outcome::Error(error) => Err(error.into()),
        other => Err(invalid_outcome(operation, other)),
    }
}

pub(super) fn decode_optional_u64(
    operation: &Operation,
    outcome: Outcome,
) -> Result<Option<u64>, RuntimeError> {
    match outcome {
        Outcome::OptionalU64(value) => Ok(value),
        Outcome::Error(error) => Err(error.into()),
        other => Err(invalid_outcome(operation, other)),
    }
}

pub(super) fn decode_datagram(
    operation: &Operation,
    outcome: Outcome,
) -> Result<Option<Datagram>, RuntimeError> {
    match outcome {
        Outcome::Datagram(datagram) => Ok(datagram),
        Outcome::Error(error) => Err(error.into()),
        other => Err(invalid_outcome(operation, other)),
    }
}

pub(super) fn decode_tcp_accepted(
    operation: &Operation,
    outcome: Outcome,
) -> Result<Option<TcpAccepted>, RuntimeError> {
    match outcome {
        Outcome::TcpAccepted(accepted) => Ok(accepted),
        Outcome::Error(error) => Err(error.into()),
        other => Err(invalid_outcome(operation, other)),
    }
}

pub(super) fn decode_optional_bytes(
    operation: &Operation,
    outcome: Outcome,
) -> Result<Option<Vec<u8>>, RuntimeError> {
    match outcome {
        Outcome::OptionalBytes(bytes) => Ok(bytes),
        Outcome::Error(error) => Err(error.into()),
        other => Err(invalid_outcome(operation, other)),
    }
}

impl Context {
    pub(super) fn execution_fingerprint(&self) -> &str {
        &self.compatibility_fingerprint
    }

    /// This run's structured facts document ([`patina.runfacts/v1`](FACTS_SCHEMA)):
    /// the per-plane fault accounting and the runtime-detected findings, built
    /// from the very same report structs the `PATINA_*_REPORT` stderr lines are
    /// formatted from.
    ///
    /// A plane is present exactly when its human line would have had something to
    /// say (the plane saw at least one opportunity) — absent means the feature
    /// did not fire, never "zero". Deliberately independent of
    /// [`ReportConfig`]: silencing a printed diagnostic must not blind the
    /// structured channel.
    pub fn run_facts(&self) -> serde_json::Value {
        let mut planes = serde_json::Map::new();
        if let Some(report) = self.fs_fault_report().filter(|r| r.eligible_ops > 0) {
            planes.insert("fs".into(), facts::fs_plane(&report));
        }
        if let Some(report) = self.dns_fault_report().filter(|r| r.resolutions > 0) {
            planes.insert("dns".into(), facts::dns_plane(&report));
        }
        if let Some(report) = self
            .net_fault_report()
            .filter(patina_dst_driver_api::NetFaultReport::had_opportunities)
        {
            planes.insert("net".into(), facts::net_plane(&report));
        }
        if let Some(report) = self.entropy_fault_report().filter(|r| r.requests > 0) {
            planes.insert("entropy".into(), facts::entropy_plane(&report));
        }
        if let Some(report) = self.clock_fault_report().filter(|r| r.reads > 0) {
            planes.insert("clock".into(), facts::clock_plane(&report));
        }
        // No `had opportunities` filter, unlike every plane above: zero eligible
        // custom operations is the plane's most important finding, not a reason
        // to omit it.
        if let Some(report) = self.custom_op_fault_report() {
            planes.insert("custom_op".into(), facts::custom_op_plane(&report));
        }
        if let Some(swarm) = self.swarm.as_ref() {
            planes.insert("swarm".into(), facts::swarm_plane(swarm));
        }
        let schedule = self.schedule.diagnostics();
        if schedule.had_concurrency() {
            planes.insert("schedule".into(), facts::schedule_plane(&schedule));
        }

        let mut findings = Vec::new();
        if let Some(violation) = self.liveness.violation.as_ref() {
            findings.push(facts::liveness_finding(violation));
        }
        if let Some(vtime) = self.spin.churn_vtime_nanos {
            findings.push(facts::frozen_clock_churn_finding(
                vtime,
                self.spin.rescues,
                self.spin.advanced_nanos,
                SPIN_RESCUE_CLOCK_OPS,
            ));
        }
        if !schedule.vacuous.is_empty() {
            findings.push(facts::vacuous_schedule_finding(&schedule));
        }
        if let Some(report) = self.scheduler.as_ref().and_then(|s| s.policy_report()) {
            if report.starve_vacuous > 0 {
                findings.push(facts::vacuous_starvation_finding(report.starve_vacuous));
            }
        }
        facts::document(planes, findings)
    }

    /// Write the facts document to the installed channel, at most once per run.
    /// A write failure is loud and classifiable (`PATINA_INFRA`) rather than
    /// silent — a consumer that asked for the structured channel must never read
    /// a missing document as "nothing happened".
    pub(super) fn emit_facts(&mut self) {
        if self.facts_emitted || self.facts.is_none() {
            return;
        }
        self.facts_emitted = true;
        let document = self.run_facts();
        let mut bytes = match serde_json::to_vec(&document) {
            Ok(bytes) => bytes,
            Err(error) => {
                eprintln!("PATINA_INFRA run_facts serialize_failed reason={error:?}");
                return;
            }
        };
        bytes.push(b'\n');
        if let Some(output) = self.facts.as_mut() {
            if let Err(error) = output.write(&bytes) {
                eprintln!("PATINA_INFRA run_facts write_failed reason={error:?}");
            }
        }
    }

    /// Finalize the run: emit the end-of-run diagnostics (schedule, buggify,
    /// liveness, net-fault), enforce end-of-run oracles, and — in record mode —
    /// write the trace. Consumes the context; [`run`]/[`run_with`] call this
    /// automatically, on error paths too.
    pub fn finish(mut self) -> Result<(), RuntimeError> {
        if let Some(stop) = self.replay_compute_stop_due() {
            return Err(self.stop_compute_bound(stop.task));
        }
        // A custom operation still open at the end of the run means its `begin`
        // was never closed out — on the record pass the trace is missing an event
        // the guest logically performed, and on replay a recorded result was
        // consumed and dropped. Either way the trace no longer describes the run,
        // so say so here instead of letting it fail as an unexplained mismatch on
        // some later replay.
        if let Some(pending) = self.custom_op.take() {
            return Err(RuntimeError::CustomOp {
                detail: format!(
                    "the run ended with custom op {:?} still open: its `begin` was never closed by \
a recorded result or a replay fetch",
                    pending.label
                ),
                label: pending.label,
            });
        }
        if self.require_crash_selector_reached && !self.crash_fired {
            if let Some(selector) = self.crash_at {
                return Err(RuntimeError::CrashSelectorUnreached {
                    selector,
                    counts: self.crash_counts,
                });
            }
        }
        // Any runtime diagnostic no embedder drained. The shim and the WASI host
        // drain after each SDK entry point so the lines interleave with guest
        // output; an in-process (cargo-family) guest has no embedder, and this is
        // where its verdicts reach stderr. Drained, so nothing can print twice.
        // Deliberately not gated by `ReportConfig`: a verdict is the run's
        // result, not a diagnostic, and a suppressible result is a silent hole.
        for line in self.take_pending_diagnostics() {
            eprintln!("{line}");
        }
        emit_schedule_report(self.reports, &self.schedule.diagnostics());
        // Swarm selection diagnostic. Default-on for every masked run so which
        // classes this generation actually carried is never left to inference
        // from an absent knob effect.
        if let Some(swarm) = self.swarm.as_ref() {
            emit_swarm_report(self.reports, swarm);
        }
        // Exploration-policy diagnostic (PCT / starvation). Populated from live
        // selection, so it reflects a record/seeded run; a replay reports the
        // inert default because recorded selections bypass the policy.
        if let Some(report) = self.scheduler.as_ref().and_then(|s| s.policy_report()) {
            emit_schedule_policy_report(self.reports, &report);
        }
        // Filesystem fault-injection diagnostic. Default-on so a run configured
        // with fs fault knobs that never actually perturb eligible I/O is never a
        // false green.
        if let Some(report) = self.fs_fault_report() {
            emit_fs_fault_report(self.reports, &report);
        }
        // DNS fault-injection diagnostic, on the same default-on terms.
        if let Some(report) = self.dns_fault_report() {
            emit_dns_fault_report(self.reports, &report);
        }
        // Network fault-injection diagnostic. Default-on so a run configured with
        // net fault knobs that never actually perturbed any send (the knobs being
        // silently inert on the exercised code path) is never a false green.
        if let Some(report) = self.net_fault_report() {
            emit_net_fault_report(self.reports, &report);
        }
        // Entropy fault-injection diagnostic, on the same default-on terms.
        if let Some(report) = self.entropy_fault_report() {
            emit_entropy_fault_report(self.reports, &report);
        }
        // Clock (epoch-jump) fault-injection diagnostic, on the same
        // default-on terms.
        if let Some(report) = self.clock_fault_report() {
            emit_clock_fault_report(self.reports, &report);
        }
        // Custom-op fault-injection diagnostic, on the same default-on terms.
        if let Some(report) = self.custom_op_fault_report() {
            emit_customop_fault_report(self.reports, &report);
        }
        // Liveness-watchdog diagnostic: prove the watchdog was actually armed and
        // ran to a clean finish (it did NOT fire — a fired watchdog aborts before
        // finish()). Default-on so "watchdog enabled, run OK" is never silently
        // vacuous; suppressed by a false-y PATINA_LIVENESS_REPORT.
        if self.liveness.active {
            emit_liveness_report(self.reports, &self.liveness);
        }
        // Cooperative-SUT diagnostic + metadata. Computed before the execution is
        // consumed so the record sink can fold in the run's realized active-site
        // set and knob picks.
        let buggify_diag = self.buggify_diagnostics();
        emit_sdk_report(self.reports, &buggify_diag);
        // The structured parallel of every line emitted above, from the same
        // structs. Written before the trace so a trace-write failure still
        // leaves the run's facts on the channel.
        self.emit_facts();
        let buggify_record = self.buggify.to_record();
        // A runtime-initiated stop already wrote the recording out (a truncated
        // but valid trace, see `flush_recording`); the transport is append-only,
        // so writing a second bundle would corrupt it. Nothing is recorded after
        // such a stop, so the flushed snapshot is the complete artifact.
        if self.recording_flushed {
            return Ok(());
        }
        match self.execution {
            Execution::Seeded => Ok(()),
            Execution::Record { mut recorder, sink } => match sink {
                RecordSink::Path { path, _reservation } => {
                    recorder.set_buggify(buggify_record);
                    recorder.finish(path).map_err(Into::into)
                }
                RecordSink::Transport(mut transport) => {
                    recorder.set_buggify(buggify_record);
                    let bytes = recorder.into_bundle()?.to_bytes()?;
                    transport
                        .write_bundle(&bytes)
                        .map_err(|source| RuntimeError::Io {
                            action: "write trace bundle to trace transport".into(),
                            source,
                        })
                }
            },
            Execution::Replay(replayer) => replayer.finish().map_err(Into::into),
            Execution::Branch {
                session,
                _reservation,
            } => session.finish().map_err(Into::into),
        }
    }

    /// Write the recording as it stands, WITHOUT consuming the context, so a
    /// runtime-initiated stop leaves a truncated-but-valid trace instead of the
    /// empty file the supervisor pre-created. Native internal stops use the
    /// private host-abort vehicle, skipping both guest-abort finalization and
    /// atexit shutdown. This explicit flush preserves the evidence explaining
    /// a runtime-initiated stop. At most one write per run
    /// ([`Context::recording_flushed`]): the native transport is append-only.
    ///
    /// Scoped to stops the RUNTIME initiates (step-budget exhaustion,
    /// frozen-clock churn, the crash that ends an incarnation), not arbitrary
    /// shim failures or panics. Explicit Linux guest `abort()` separately
    /// finalizes a healthy context; other internal fatalities leave the trace
    /// incomplete.
    pub(super) fn flush_recording(&mut self) {
        if self.recording_flushed || !matches!(self.execution, Execution::Record { .. }) {
            return;
        }
        self.recording_flushed = true;
        let buggify_record = self.buggify.to_record();
        let Execution::Record { recorder, sink } = &mut self.execution else {
            unreachable!("execution was checked to be Record");
        };
        recorder.set_buggify(buggify_record);
        let bundle = match recorder.to_bundle() {
            Ok(bundle) => bundle,
            // The recorder already abandoned this trace for outgrowing its
            // budget, so it holds nothing to flush. Report it in the same
            // greppable form `patina_shutdown` uses — this stop aborts and
            // never reaches that reporting — and leave the supervisor the
            // marker on the transport, so an abandoned trace still reads as
            // abandoned rather than as the empty file a mid-run death leaves.
            Err(error) if error.is_resource_limit() => {
                eprint!("{}", resource_limit_infra_line(&error));
                if let RecordSink::Transport(transport) = sink {
                    let _ = transport.write_bundle(&abandoned_trace_marker(
                        "resource-limit",
                        &error.to_string(),
                    ));
                }
                return;
            }
            Err(error) => {
                eprintln!(
                    "PATINA_INFRA truncated_trace write_failed reason={:?}",
                    format!("snapshot truncated trace: {error}")
                );
                return;
            }
        };
        let result = match sink {
            RecordSink::Path { path, .. } => bundle
                .write_atomic(&*path)
                .map_err(|error| format!("write truncated trace to {}: {error}", path.display())),
            RecordSink::Transport(transport) => bundle
                .to_bytes()
                .map_err(|error| format!("serialize truncated trace: {error}"))
                .and_then(|bytes| {
                    transport
                        .write_bundle(&bytes)
                        .map_err(|error| format!("write truncated trace to transport: {error}"))
                }),
        };
        if let Err(reason) = result {
            eprintln!("PATINA_INFRA truncated_trace write_failed reason={reason:?}");
        }
    }

    pub(super) fn replay_expected(
        &mut self,
        operation: &Operation,
    ) -> Result<Option<(u64, Outcome)>, RuntimeError> {
        if self.step_budget.is_some_and(|budget| self.steps >= budget) {
            if let Some(stop) = self.replay_compute_stop_due() {
                return Err(self.stop_compute_bound(stop.task));
            }
            // Preserve the artifacts before the stop: the interposed families
            // abort without reaching `finish`, and a budget abort is precisely
            // the case where the partial trace is the evidence (see
            // [`Context::flush_recording`]).
            self.emit_facts();
            self.flush_recording();
            return Err(RuntimeError::StepBudgetExceeded {
                budget: self.step_budget.expect("budget was checked"),
            });
        }
        self.steps += 1;
        self.liveness_track(operation)?;
        self.spin_track(operation)?;
        match &mut self.execution {
            Execution::Replay(replayer) => {
                let sequence = replayer.consumed();
                match replayer.expect(operation) {
                    Ok(outcome) => Ok(Some((sequence, outcome))),
                    Err(error) => Err(classify_yield_divergence(&self.schedule, replayer, error)),
                }
            }
            Execution::Branch { session, .. } => {
                session.expect_prefix(operation).map_err(Into::into)
            }
            _ => Ok(None),
        }
    }

    pub(super) fn complete(&mut self, operation: Operation, actual: Outcome) -> Outcome {
        match &mut self.execution {
            Execution::Record { recorder, .. } => {
                recorder.observe(operation, actual.clone());
            }
            Execution::Branch { session, .. } => {
                session.observe(operation, actual.clone());
            }
            _ => {}
        }
        actual
    }

    pub(super) fn reconcile(
        &mut self,
        operation: Operation,
        expected: Option<(u64, Outcome)>,
        actual: Outcome,
    ) -> Result<Outcome, RuntimeError> {
        if let Some((sequence, recorded)) = expected {
            match &self.execution {
                Execution::Replay(replayer) => {
                    replayer.compare_outcome(sequence, &recorded, &actual)?;
                }
                Execution::Branch { session, .. } => {
                    session.compare_outcome(sequence, &recorded, &actual)?;
                }
                _ => {}
            }
            Ok(recorded)
        } else {
            Ok(self.complete(operation, actual))
        }
    }
}

#[cfg(test)]
mod tests;
