//! Parent-prefix replay and deterministic branch suffix recording.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use patina_dst_abi::{Operation, Outcome};

use crate::lifecycle::linear_lifecycle_from_start_and_incarnation;
use crate::recorder::*;
use crate::{
    BuggifyConfigRecord, DnsConfigRecord, FaultConfigRecord, MAX_TRACE_BYTES, Replayer,
    SchedulePolicyRecord, SwarmConfigRecord, Timeline, TraceBundle, TraceError, TraceEvent,
};

/// Replays an exact parent prefix and records a new deterministic suffix.
pub struct BranchSession {
    path: PathBuf,
    bundle: TraceBundle,
    parent: String,
    branch_id: String,
    branch_seed: u64,
    from_sequence: u64,
    prefix: Replayer,
    suffix: Vec<TraceEvent>,
    suffix_next_order: u64,
    suffix_incarnation: u64,
    /// Bounds the branch's OWN suffix the way [`Recorder`]'s ledger bounds a
    /// recording. The inherited parent bundle is already bounded by the load-
    /// time byte limit, and budgeting the suffix alone keeps the in-flight
    /// total a strict under-estimate of the written file, so a branch that
    /// would have fit is never abandoned.
    ledger: EventLedger,
}

impl BranchSession {
    pub fn open(
        path: impl AsRef<Path>,
        expected_fingerprint: &str,
        parent: &str,
        from_sequence: u64,
        branch_id: impl Into<String>,
        branch_seed: u64,
    ) -> Result<Self, TraceError> {
        let path = path.as_ref().to_path_buf();
        let bundle = TraceBundle::load(&path)?;
        if bundle.metadata.compute_stop.is_some() {
            return Err(TraceError::Invalid(
                "branching a compute-stop trace is not supported".into(),
            ));
        }
        if bundle.metadata.fingerprint != expected_fingerprint {
            return Err(TraceError::FingerprintMismatch {
                expected: expected_fingerprint.into(),
                recorded: bundle.metadata.fingerprint.clone(),
            });
        }
        let branch_id = branch_id.into();
        if branch_id.is_empty()
            || bundle
                .timelines
                .iter()
                .any(|timeline| timeline.id == branch_id)
        {
            return Err(TraceError::DuplicateTimeline(branch_id));
        }
        let mut prefix_decisions = bundle.resolved_timeline(parent)?;
        if from_sequence > prefix_decisions.len() as u64 {
            return Err(TraceError::Invalid(format!(
                "branch sequence {from_sequence} exceeds parent timeline length {}",
                prefix_decisions.len()
            )));
        }
        prefix_decisions.truncate(from_sequence as usize);
        let suffix_next_order = prefix_decisions
            .last()
            .map(|event| event.order.saturating_add(2))
            .unwrap_or(1);
        let suffix_incarnation = prefix_decisions
            .last()
            .map(|event| event.incarnation)
            .unwrap_or(0);
        let prefix = Replayer {
            metadata: bundle.metadata.clone(),
            decisions: prefix_decisions,
            next: 0,
        };
        Ok(Self {
            path,
            bundle,
            parent: parent.into(),
            branch_id,
            branch_seed,
            from_sequence,
            prefix,
            suffix: Vec::new(),
            suffix_next_order,
            suffix_incarnation,
            ledger: EventLedger::new(MAX_TRACE_BYTES),
        })
    }

    /// The parent trace's recorded fault-injection configuration, inherited by
    /// the branch so its replayed prefix uses the same fault drivers. `None` for
    /// a pre-format-4 parent trace.
    pub const fn fault_config(&self) -> Option<&FaultConfigRecord> {
        self.bundle.metadata.faults.as_ref()
    }

    /// The parent trace's recorded cooperative-SUT (buggify) configuration,
    /// inherited by the branch. `None` for a parent trace recorded without
    /// buggify.
    pub const fn buggify_config(&self) -> Option<&BuggifyConfigRecord> {
        self.bundle.metadata.buggify.as_ref()
    }

    /// The parent trace's recorded exploration scheduling policy, inherited by
    /// the branch. `None` for a parent trace recorded under the default policy.
    pub const fn schedule_policy(&self) -> Option<&SchedulePolicyRecord> {
        self.bundle.metadata.schedule_policy.as_ref()
    }

    /// The parent trace's recorded swarm fault-class selection. `None` when the
    /// parent was recorded without swarm.
    pub const fn swarm_config(&self) -> Option<&SwarmConfigRecord> {
        self.bundle.metadata.swarm.as_ref()
    }

    /// Deterministic guest environment values inherited from the parent trace.
    /// `None` for a trace recorded before env capture or with no supplied values.
    pub fn guest_env(&self) -> Option<&BTreeMap<String, String>> {
        self.bundle.metadata.guest_env.as_ref()
    }

    /// The guest's initial working directory inherited from the parent trace.
    pub fn guest_cwd(&self) -> Option<&str> {
        self.bundle.metadata.guest_cwd.as_deref()
    }

    /// The virtual realtime epoch inherited from the parent trace.
    pub const fn realtime_epoch_nanos(&self) -> u64 {
        self.bundle.metadata.realtime_epoch_nanos
    }

    pub const fn boot_origin_nanos(&self) -> u64 {
        self.bundle.metadata.boot_origin_nanos
    }

    /// The node name inherited from the parent trace.
    pub fn hostname(&self) -> &str {
        &self.bundle.metadata.hostname
    }

    /// The DNS host table inherited from the parent trace.
    pub const fn dns_config(&self) -> Option<&DnsConfigRecord> {
        self.bundle.metadata.dns.as_ref()
    }

    pub fn expect_prefix(
        &mut self,
        operation: &Operation,
    ) -> Result<Option<(u64, Outcome)>, TraceError> {
        if self.prefix.consumed() as usize == self.prefix.total() {
            return Ok(None);
        }
        let sequence = self.prefix.consumed();
        Ok(Some((sequence, self.prefix.expect(operation)?)))
    }

    pub fn compare_outcome(
        &self,
        sequence: u64,
        recorded: &Outcome,
        actual: &Outcome,
    ) -> Result<(), TraceError> {
        self.prefix.compare_outcome(sequence, recorded, actual)
    }

    pub fn observe(&mut self, operation: Operation, outcome: Outcome) {
        if self.ledger.overflowed() {
            return;
        }
        let mut event = TraceEvent::new(
            self.from_sequence + self.suffix.len() as u64,
            operation,
            outcome,
        );
        event.order = self
            .suffix_next_order
            .saturating_add(self.suffix.len() as u64);
        event.incarnation = self.suffix_incarnation;
        if self.ledger.admit(&event, &self.branch_id) {
            self.suffix.push(event);
        } else {
            self.suffix = Vec::new();
        }
    }

    pub fn finish(self) -> Result<(), TraceError> {
        // Prefix reconciliation first: a divergence from the parent trace is a
        // real finding and stays loud, ahead of the graceful budget refusal.
        self.prefix.finish()?;
        if let Some(error) = self.ledger.overflow_error() {
            return Err(error);
        }
        let mut bundle = self.bundle;
        let lifecycle = linear_lifecycle_from_start_and_incarnation(
            self.suffix_next_order.saturating_sub(1),
            self.suffix_incarnation,
            &self.suffix,
        );
        bundle.timelines.push(Timeline {
            id: self.branch_id,
            parent: Some(self.parent),
            from_sequence: Some(self.from_sequence),
            branch_seed: Some(self.branch_seed),
            lifecycle,
            decisions: self.suffix,
        });
        bundle.write_atomic(self.path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::operation;
    use crate::{LifecycleEvent, LifecycleEventKind, Recorder, RunMetadata, TraceBundle};
    use patina_dst_abi::{Operation, Outcome};
    use tempfile::tempdir;

    #[test]
    fn branches_replay_an_exact_prefix_and_append_a_suffix() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("run.patina");
        let mut recorder = Recorder::new(RunMetadata::new(7, "fingerprint", 0, "patina"));
        recorder.observe(operation(), Outcome::U64(10));
        recorder.observe(Operation::EntropyFill { len: 1 }, Outcome::Bytes(vec![1]));
        recorder.finish(&path).unwrap();

        let mut branch =
            BranchSession::open(&path, "fingerprint", "main", 1, "branch-1", 99).unwrap();
        assert_eq!(
            branch.expect_prefix(&operation()).unwrap().unwrap().1,
            Outcome::U64(10)
        );
        assert_eq!(
            branch
                .expect_prefix(&Operation::EntropyFill { len: 1 })
                .unwrap(),
            None
        );
        branch.observe(Operation::EntropyFill { len: 1 }, Outcome::Bytes(vec![9]));
        branch.finish().unwrap();

        let bundle = TraceBundle::load(&path).unwrap();
        assert_eq!(bundle.timelines.len(), 2);
        let resolved = bundle.resolved_timeline("branch-1").unwrap();
        assert_eq!(resolved[0].outcome, Outcome::U64(10));
        assert_eq!(resolved[1].outcome, Outcome::Bytes(vec![9]));
        assert_eq!(resolved[0].order, 1);
        assert_eq!(resolved[1].order, 3);
        assert_eq!(resolved[0].incarnation, 0);
        assert_eq!(resolved[1].incarnation, 0);
        let lifecycle = bundle.resolved_lifecycle("branch-1").unwrap();
        assert_eq!(
            lifecycle,
            vec![
                LifecycleEvent {
                    order: 0,
                    kind: LifecycleEventKind::Start { incarnation: 0 },
                },
                LifecycleEvent {
                    order: 4,
                    kind: LifecycleEventKind::End { incarnation: 0 },
                },
            ],
            "resolved branch lifecycle continues the inherited incarnation instead of duplicating Start(0)"
        );
        assert_eq!(bundle.timelines[1].lifecycle[0].order, 2);
        assert_eq!(
            bundle.timelines[1].lifecycle[0].kind,
            LifecycleEventKind::Start { incarnation: 0 }
        );
        assert_eq!(bundle.timelines[1].branch_seed, Some(99));
    }
}
