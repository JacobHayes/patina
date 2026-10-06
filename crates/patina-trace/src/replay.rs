//! Strict recorded-operation and outcome reconciliation.

use std::collections::BTreeMap;
use std::path::Path;

use patina_dst_abi::{Operation, Outcome, TaskId};

use crate::{
    BuggifyConfigRecord, ComputeStop, DnsConfigRecord, FaultConfigRecord, MAIN_TIMELINE,
    RunMetadata, SchedulePolicyRecord, SwarmConfigRecord, TraceBundle, TraceError, TraceEvent,
};

pub struct Replayer {
    pub(super) metadata: RunMetadata,
    pub(super) decisions: Vec<TraceEvent>,
    pub(super) next: usize,
}

impl Replayer {
    pub fn open(path: impl AsRef<Path>, expected_fingerprint: &str) -> Result<Self, TraceError> {
        Self::open_timeline(path, expected_fingerprint, MAIN_TIMELINE)
    }

    pub fn open_timeline(
        path: impl AsRef<Path>,
        expected_fingerprint: &str,
        timeline: &str,
    ) -> Result<Self, TraceError> {
        Self::from_bundle(TraceBundle::load(path)?, expected_fingerprint, timeline)
    }

    /// Build a replayer from an already-loaded bundle.
    pub fn from_bundle(
        bundle: TraceBundle,
        expected_fingerprint: &str,
        timeline: &str,
    ) -> Result<Self, TraceError> {
        if bundle.metadata.fingerprint != expected_fingerprint {
            return Err(TraceError::FingerprintMismatch {
                expected: expected_fingerprint.into(),
                recorded: bundle.metadata.fingerprint,
            });
        }
        let decisions = bundle.resolved_timeline(timeline)?;
        if let Some(stop) = bundle.metadata.compute_stop {
            if stop.steps != decisions.len() as u64 || stop.task.0 == 0 {
                return Err(TraceError::Invalid(
                    "compute stop must name a task at the end of its exact prefix".into(),
                ));
            }
        }
        let execution_seed = bundle
            .timelines
            .iter()
            .find(|candidate| candidate.id == timeline)
            .and_then(|candidate| candidate.branch_seed)
            .unwrap_or(bundle.metadata.root_seed);
        let mut metadata = bundle.metadata;
        metadata.root_seed = execution_seed;
        Ok(Self {
            metadata,
            decisions,
            next: 0,
        })
    }

    pub const fn root_seed(&self) -> u64 {
        self.metadata.root_seed
    }

    /// The recorded fault-injection configuration, authoritative on replay.
    /// `None` for a pre-format-4 trace that carried no such metadata.
    pub const fn fault_config(&self) -> Option<&FaultConfigRecord> {
        self.metadata.faults.as_ref()
    }

    /// The recorded cooperative-SUT (buggify) configuration, authoritative on
    /// replay. `None` for a trace recorded without buggify.
    pub const fn buggify_config(&self) -> Option<&BuggifyConfigRecord> {
        self.metadata.buggify.as_ref()
    }

    /// The recorded exploration scheduling policy, authoritative on replay.
    /// `None` for a trace recorded under the default uniform policy.
    pub const fn schedule_policy(&self) -> Option<&SchedulePolicyRecord> {
        self.metadata.schedule_policy.as_ref()
    }

    /// The recorded swarm fault-class selection. `None` when swarm was disabled.
    pub const fn swarm_config(&self) -> Option<&SwarmConfigRecord> {
        self.metadata.swarm.as_ref()
    }

    /// The recorded guest program arguments (`argv[1..]`). `None` for a trace
    /// recorded before argv capture; `Some` (possibly empty) otherwise.
    pub fn guest_argv(&self) -> Option<&[String]> {
        self.metadata.guest_argv.as_deref()
    }

    /// Deterministic guest environment values recorded into the trace.
    /// `None` for a trace recorded before env capture or with no supplied values.
    pub fn guest_env(&self) -> Option<&BTreeMap<String, String>> {
        self.metadata.guest_env.as_ref()
    }

    /// The guest's initial working directory recorded into the trace. `None`
    /// for a run that started at `/` or a trace recorded before cwd capture.
    pub fn guest_cwd(&self) -> Option<&str> {
        self.metadata.guest_cwd.as_deref()
    }

    /// The DNS host table recorded into the trace, authoritative on replay.
    /// `None` for a trace recorded without one.
    pub const fn dns_config(&self) -> Option<&DnsConfigRecord> {
        self.metadata.dns.as_ref()
    }

    /// Whether the trace was recorded under syscall-user-dispatch. `Some(true)`
    /// when it was; `None` otherwise (see [`RunMetadata::sud`]).
    pub const fn compute_stop(&self) -> Option<ComputeStop> {
        self.metadata.compute_stop
    }

    pub const fn sud(&self) -> Option<bool> {
        self.metadata.sud
    }

    /// Whether the trace was recorded with the timestamp-counter trap armed, or
    /// `None` otherwise (see [`RunMetadata::tsc`]).
    pub const fn tsc(&self) -> Option<bool> {
        self.metadata.tsc
    }

    /// The virtual realtime epoch the trace was recorded on (see
    /// [`RunMetadata::realtime_epoch_nanos`]).
    pub const fn realtime_epoch_nanos(&self) -> u64 {
        self.metadata.realtime_epoch_nanos
    }

    pub const fn boot_origin_nanos(&self) -> u64 {
        self.metadata.boot_origin_nanos
    }

    /// The node name the trace was recorded under (see
    /// [`RunMetadata::hostname`]).
    pub fn hostname(&self) -> &str {
        &self.metadata.hostname
    }

    pub fn expect(&mut self, operation: &Operation) -> Result<Outcome, TraceError> {
        let event = self
            .decisions
            .get(self.next)
            .ok_or_else(|| TraceError::ReplayExhausted {
                sequence: self.next as u64,
                actual: operation.clone(),
            })?;
        if &event.operation != operation {
            return Err(TraceError::OperationMismatch {
                sequence: event.sequence,
                expected: Box::new(event.operation.clone()),
                actual: Box::new(operation.clone()),
            });
        }
        self.next += 1;
        Ok(event.outcome.clone())
    }

    pub fn compare_outcome(
        &self,
        sequence: u64,
        recorded: &Outcome,
        actual: &Outcome,
    ) -> Result<(), TraceError> {
        if recorded != actual {
            return Err(TraceError::OutcomeMismatch {
                sequence,
                recorded: Box::new(recorded.clone()),
                actual: Box::new(actual.clone()),
            });
        }
        Ok(())
    }

    pub const fn consumed(&self) -> u64 {
        self.next as u64
    }

    pub fn total(&self) -> usize {
        self.decisions.len()
    }

    /// How many `TaskYield` operations the full recorded timeline holds for
    /// `task`. Divergence diagnostics use this to report record-vs-replay yield
    /// accounting instead of a bare "trace ended" cursor position.
    pub fn recorded_yields_for(&self, task: TaskId) -> usize {
        self.decisions
            .iter()
            .filter(|event| event.operation == Operation::TaskYield { task })
            .count()
    }

    pub fn finish(self) -> Result<(), TraceError> {
        if self.next != self.decisions.len() {
            return Err(TraceError::UnconsumedEvents {
                consumed: self.next,
                total: self.decisions.len(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::operation;
    use crate::{Recorder, RunMetadata, TraceError};
    use patina_dst_abi::{Operation, Outcome};
    use tempfile::tempdir;

    #[test]
    fn rejects_fingerprint_operation_and_trailing_event_mismatches() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("run.patina");
        let mut recorder = Recorder::new(RunMetadata::new(7, "fingerprint", 0, "patina"));
        recorder.observe(operation(), Outcome::U64(10));
        recorder.finish(&path).unwrap();

        assert!(matches!(
            Replayer::open(&path, "changed"),
            Err(TraceError::FingerprintMismatch { .. })
        ));

        let mut replay = Replayer::open(&path, "fingerprint").unwrap();
        let mismatch = replay
            .expect(&Operation::EntropyFill { len: 1 })
            .unwrap_err();
        assert!(matches!(mismatch, TraceError::OperationMismatch { .. }));

        let replay = Replayer::open(&path, "fingerprint").unwrap();
        assert!(matches!(
            replay.finish(),
            Err(TraceError::UnconsumedEvents { .. })
        ));
    }
}
