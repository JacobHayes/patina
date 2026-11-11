//! Trace transport, recording lifecycle, effect reconciliation, and outcome decoding.

use crate::{Context, RuntimeError, facts};

use crate::reports::{
    emit_clock_fault_report, emit_dns_fault_report, emit_entropy_fault_report,
    emit_fs_fault_report, emit_liveness_report, emit_net_fault_report, emit_schedule_policy_report,
    emit_schedule_report, emit_sdk_report, emit_swarm_report,
};
use crate::schedule::classify_yield_divergence;
use patina_dst_abi::{
    Datagram, EffectError, ErrorCode, Fd, FsDirectoryEntry, FsMetadata, Operation, Outcome,
    SendReport, SocketId, TaskId, TcpAccepted,
};
use patina_dst_trace::{Recorder, Replayer, abandoned_trace_marker, resource_limit_infra_line};
use std::fs;
use std::path::PathBuf;

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
        transport: Box<dyn TraceTransport>,
    },
    Replay(Replayer),
}

/// The transport a path constructor names ([`RuntimeConfig::record`],
/// [`RuntimeConfig::replay`]): the trace file itself.
///
/// [`RuntimeConfig::record`]: crate::RuntimeConfig::record
/// [`RuntimeConfig::replay`]: crate::RuntimeConfig::replay
pub(super) struct FileTransport(pub(super) PathBuf);

impl TraceTransport for FileTransport {
    fn read_bundle(&mut self) -> std::io::Result<Vec<u8>> {
        fs::read(&self.0)
    }

    fn write_bundle(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        if let Some(parent) = self.0.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&self.0, bytes)
    }
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
    /// did not fire, never "zero".
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
        if self.compute_budget_fired {
            findings.push(facts::compute_budget_finding(
                self.charges.running,
                self.busy.compute_nanos,
                self.busy.compute_budget_nanos,
            ));
        }
        if !schedule.vacuous.is_empty() {
            findings.push(facts::vacuous_schedule_finding(&schedule));
        }
        let mut document = facts::document(planes, findings);
        if let serde_json::Value::Object(root) = &mut document {
            root.insert("context".into(), self.facts_context.into());
            if !self.verdicts.is_empty() {
                root.insert("verdicts".into(), facts::verdicts(&self.verdicts));
            }
            let sdk = self.buggify_diagnostics();
            if sdk.enabled || sdk.sites_registered > 0 || !sdk.declared_sites.is_empty() {
                root.insert("sdk".into(), facts::sdk(&sdk));
            }
            if let Some(report) = self
                .scheduler
                .policy_report()
                .filter(crate::scheduler::SchedulePolicyReport::is_active)
            {
                root.insert("schedule_policy".into(), facts::schedule_policy(&report));
            }
            root.insert("cpu_charges".into(), self.charges.facts());
            if let Some(kind) = self.replay_divergence {
                root.insert("replay_divergence".into(), kind.into());
            }
            if self.executable_unavailable {
                root.insert("executable_unavailable".into(), true.into());
            }
            if !self.missing_paths.is_empty() {
                root.insert("missing_paths".into(), self.missing_paths.clone().into());
            }
        }
        document
    }

    /// Note that the replay diverged from its trace, as the typed
    /// [`patina_dst_trace::TraceError::replay_divergence`] kind, and write the
    /// facts document now: the divergence usually ends the process before
    /// [`Context::finish`] (a native shim fatal aborts), and the facts channel
    /// is the one place the supervisor learns of it that the guest cannot
    /// write. The first divergence is the one reported; a run's facts are its
    /// state at that point.
    pub(super) fn note_replay_divergence(&mut self, divergence: Option<&'static str>) {
        if let Some(kind) = divergence {
            self.replay_divergence.get_or_insert(kind);
            self.emit_facts();
        }
    }

    /// Note that the guest looked for its own executable's file (a native
    /// guest's `/proc/self/exe` or `/proc/self/maps`), which the model does
    /// not provide: what reads it, a backtrace's symbolizer, found nothing.
    /// Carried on the facts channel as `executable_unavailable`.
    pub fn note_executable_unavailable(&mut self) {
        self.executable_unavailable = true;
    }

    /// Note that the guest opened or stat'ed the absolute `path` and it was
    /// not there. Carried on the facts channel as `missing_paths` (distinct,
    /// first seen first, at most [`MISSING_PATHS_MAX`]), so the supervisor
    /// can tell, after the run and outside it, whether the guest looked for a
    /// host file the simulated filesystem was never given. Nothing here or in
    /// the guest learns whether the host has it.
    pub fn note_missing_path(&mut self, path: &str) {
        if path.starts_with('/')
            && self.missing_paths.len() < crate::MISSING_PATHS_MAX
            && !self.missing_paths.iter().any(|seen| seen == path)
        {
            self.missing_paths.push(path.to_owned());
        }
    }

    /// Hand back a runtime-detected error, first noting it on the facts channel
    /// when, on a replay, it reports a divergence
    /// ([`RuntimeError::replay_divergence`]). The route for every replay
    /// cross-check the runtime makes itself rather than the trace layer (the
    /// time model, a recorded compute stop); a record or seeded run notes
    /// nothing, since there is no recording to diverge from.
    pub(super) fn diverged(&mut self, error: RuntimeError) -> RuntimeError {
        if matches!(self.execution, Execution::Replay(_)) {
            self.note_replay_divergence(error.replay_divergence());
        }
        error
    }

    /// Append the facts document, as the run stands now, to the installed
    /// channel. Called at every point after which the process may die without
    /// reaching [`Context::finish`] (a liveness or compute stop, a replay
    /// divergence, a verdict) and again at finish; each document is complete,
    /// so the reader takes this context's last one. A compute-bound stop seals
    /// the channel: its terminal document is the run's last word. A write failure is loud and classifiable (`PATINA_INFRA`) rather than
    /// silent — a consumer that asked for the structured channel must never read
    /// a missing document as "nothing happened".
    pub(super) fn emit_facts(&mut self) {
        if self.facts_sealed || self.facts.is_none() {
            return;
        }
        let document = self.run_facts();
        let mut bytes = match serde_json::to_vec(&document) {
            Ok(bytes) => bytes,
            Err(error) => {
                crate::reports::diagnostic!(
                    "PATINA_INFRA run_facts serialize_failed reason={error:?}"
                );
                return;
            }
        };
        bytes.push(b'\n');
        if let Some(output) = self.facts.as_mut()
            && let Err(error) = output.write_facts(&bytes)
        {
            crate::reports::diagnostic!("PATINA_INFRA run_facts write_failed reason={error:?}");
        }
    }

    /// Finalize the run: emit the end-of-run diagnostics (schedule, buggify,
    /// liveness, net-fault), enforce end-of-run oracles, and — in record mode —
    /// write the trace. Consumes the context.
    pub fn finish(mut self) -> Result<(), RuntimeError> {
        if let Some(stop) = self.replay_compute_stop_due() {
            {
                let error = self.stop_compute_bound(stop.task);
                return Err(self.diverged(error));
            }
        }
        // Any runtime diagnostic no embedder drained. The shim
        // drains after each SDK entry point so the lines interleave with guest
        // output; this catches what a direct context's caller left. Drained, so
        // nothing can print twice.
        for line in self.take_pending_diagnostics() {
            crate::reports::diagnostic!("{line}");
        }
        emit_schedule_report(&self.schedule.diagnostics());
        // Swarm selection diagnostic. Default-on for every masked run so which
        // classes this generation actually carried is never left to inference
        // from an absent knob effect.
        if let Some(swarm) = self.swarm.as_ref() {
            emit_swarm_report(swarm);
        }
        // Exploration-policy diagnostic (PCT). Populated from live
        // selection, so it reflects a record/seeded run; a replay reports the
        // inert default because recorded selections bypass the policy.
        if let Some(report) = self.scheduler.policy_report() {
            emit_schedule_policy_report(&report);
        }
        // Filesystem fault-injection diagnostic. Default-on so a run configured
        // with fs fault knobs that never actually perturb eligible I/O is never a
        // false green.
        if let Some(report) = self.fs_fault_report() {
            emit_fs_fault_report(&report);
        }
        // DNS fault-injection diagnostic, on the same default-on terms.
        if let Some(report) = self.dns_fault_report() {
            emit_dns_fault_report(&report);
        }
        // Network fault-injection diagnostic. Default-on so a run configured with
        // net fault knobs that never actually perturbed any send (the knobs being
        // silently inert on the exercised code path) is never a false green.
        if let Some(report) = self.net_fault_report() {
            emit_net_fault_report(&report);
        }
        // Entropy fault-injection diagnostic, on the same default-on terms.
        if let Some(report) = self.entropy_fault_report() {
            emit_entropy_fault_report(&report);
        }
        // Clock (epoch-jump) fault-injection diagnostic, on the same
        // default-on terms.
        if let Some(report) = self.clock_fault_report() {
            emit_clock_fault_report(&report);
        }
        // Liveness-watchdog diagnostic: prove the watchdog was actually armed and
        // ran to a clean finish (it did NOT fire — a fired watchdog aborts before
        // finish()), so "watchdog enabled, run OK" is never silently vacuous.
        if self.liveness.active {
            emit_liveness_report(&self.liveness);
        }
        // Cooperative-SUT diagnostic + metadata. Computed before the execution is
        // consumed so the record sink can fold in the run's realized active-site
        // set and knob picks.
        let buggify_diag = self.buggify_diagnostics();
        emit_sdk_report(&buggify_diag);
        // A replay that ends with recorded operations left over diverged. The
        // execution's own finish below refuses it too, but only after the facts
        // are written, so the divergence is noted here first.
        let incomplete = match &self.execution {
            Execution::Replay(replayer) => replayer.check_complete().err(),
            _ => None,
        };
        if let Some(error) = incomplete {
            self.note_replay_divergence(error.replay_divergence());
        }
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
            Execution::Record {
                mut recorder,
                mut transport,
            } => {
                recorder.set_buggify(buggify_record);
                let bytes = recorder.into_bundle()?.to_bytes()?;
                transport
                    .write_bundle(&bytes)
                    .map_err(|source| RuntimeError::Io {
                        action: "write trace bundle to trace transport".into(),
                        source,
                    })
            }
            Execution::Replay(replayer) => replayer.finish().map_err(Into::into),
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
    /// Scoped to stops the RUNTIME initiates (step-budget exhaustion, a
    /// liveness stop, the compute budget, the crash that ends an incarnation), not arbitrary
    /// shim failures or panics. Explicit Linux guest `abort()` separately
    /// finalizes a healthy context; other internal fatalities leave the trace
    /// incomplete.
    pub(super) fn flush_recording(&mut self) {
        if self.recording_flushed || !matches!(self.execution, Execution::Record { .. }) {
            return;
        }
        self.recording_flushed = true;
        let buggify_record = self.buggify.to_record();
        let Execution::Record {
            recorder,
            transport,
        } = &mut self.execution
        else {
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
                crate::reports::write_diagnostic(format_args!(
                    "{}",
                    resource_limit_infra_line(&error)
                ));
                let _ = transport.write_bundle(&abandoned_trace_marker(
                    "resource-limit",
                    &error.to_string(),
                ));
                return;
            }
            Err(error) => {
                crate::reports::diagnostic!(
                    "PATINA_INFRA truncated_trace write_failed reason={:?}",
                    format!("snapshot truncated trace: {error}")
                );
                return;
            }
        };
        let result = bundle
            .to_bytes()
            .map_err(|error| format!("serialize truncated trace: {error}"))
            .and_then(|bytes| {
                transport
                    .write_bundle(&bytes)
                    .map_err(|error| format!("write truncated trace to transport: {error}"))
            });
        if let Err(reason) = result {
            crate::reports::diagnostic!(
                "PATINA_INFRA truncated_trace write_failed reason={reason:?}"
            );
        }
    }

    pub(super) fn replay_expected(
        &mut self,
        operation: &Operation,
    ) -> Result<Option<(u64, Outcome)>, RuntimeError> {
        if self.step_budget.is_some_and(|budget| self.steps >= budget) {
            if let Some(stop) = self.replay_compute_stop_due() {
                {
                    let error = self.stop_compute_bound(stop.task);
                    return Err(self.diverged(error));
                }
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
        self.track_begin(operation)?;
        let expected = match &mut self.execution {
            Execution::Replay(replayer) => {
                let sequence = replayer.consumed();
                match replayer.expect(operation) {
                    Ok(outcome) => Ok(Some((sequence, outcome))),
                    Err(error) => Err((
                        error.replay_divergence(),
                        classify_yield_divergence(&self.schedule, replayer, error),
                    )),
                }
            }
            _ => Ok(None),
        };
        expected.map_err(|(divergence, error)| {
            self.note_replay_divergence(divergence);
            error
        })
    }

    pub(super) fn complete(&mut self, operation: Operation, actual: Outcome) -> Outcome {
        if let Execution::Record { recorder, .. } = &mut self.execution {
            recorder.observe(operation, actual.clone());
        }
        actual
    }

    /// Settle a completed operation: compare a replayed outcome with the
    /// recording's, or record a live one, then take the crash the operation
    /// may be the point of ([`Context::crash_after`]).
    pub(super) fn reconcile(
        &mut self,
        operation: Operation,
        expected: Option<(u64, Outcome)>,
        actual: Outcome,
    ) -> Result<Outcome, RuntimeError> {
        let class = operation.effect_class();
        let poll = operation.is_poll();
        let outcome = self.settle(operation, expected, actual)?;
        self.crash_after(class.is_crash_point(poll, &outcome))?;
        Ok(outcome)
    }

    fn settle(
        &mut self,
        operation: Operation,
        expected: Option<(u64, Outcome)>,
        actual: Outcome,
    ) -> Result<Outcome, RuntimeError> {
        if let Some((sequence, recorded)) = expected {
            let compared = match &self.execution {
                Execution::Replay(replayer) => {
                    replayer.compare_outcome(sequence, &recorded, &actual)
                }
                _ => Ok(()),
            };
            if let Err(error) = compared {
                self.note_replay_divergence(error.replay_divergence());
                return Err(error.into());
            }
            self.track_outcome(&operation, &recorded)?;
            self.escalate_due()?;
            Ok(recorded)
        } else {
            self.track_outcome(&operation, &actual)?;
            let outcome = self.complete(operation, actual);
            // An empty poll that completes a streak is escalated once it is
            // recorded, so the escalation's own expiries follow it.
            self.escalate_due()?;
            Ok(outcome)
        }
    }
}

#[cfg(test)]
mod tests;
