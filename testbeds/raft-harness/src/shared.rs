//! State each node thread publishes for the driver and the invariant checker.
//!
//! Node threads never share their `RawNode` (it is neither `Sync` nor safe to
//! touch off-thread); instead every node owns one `Arc<Mutex<NodeObservation>>`
//! that it overwrites at the end of each tick, plus a shared leadership log used
//! to police the single-leader-per-term invariant. All raft messages still flow
//! over UDP — these structures carry only observations, never raft traffic.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};

/// One applied log entry, recorded in commit order for cross-node comparison.
#[derive(Clone, PartialEq, Eq)]
pub struct AppliedEntry {
    pub index: u64,
    pub term: u64,
    pub data: Vec<u8>,
}

/// A snapshot of a node's externally observable state.
#[derive(Clone, Default)]
pub struct NodeObservation {
    pub alive: bool,
    pub is_leader: bool,
    pub term: u64,
    pub leader_id: u64,
    pub applied_index: u64,
    pub committed_index: u64,
    /// Unique client-proposal ids this node has applied (empty/no-op entries and
    /// any other non-client entries are excluded).
    pub applied_ids: BTreeSet<u64>,
    /// Every applied entry in commit order (content + order = the log-matching
    /// witness). Small in this harness; cloned wholesale under the lock.
    pub applied: Vec<AppliedEntry>,
}

impl NodeObservation {
    /// SHA-256 over this node's applied entries truncated to `len`, matching the
    /// `RAFT_RESULT applied_hash` format (64 lowercase hex chars).
    pub fn applied_hash_prefix(&self, len: usize) -> String {
        let mut hasher = Sha256::new();
        for entry in self.applied.iter().take(len) {
            hasher.update(entry.index.to_le_bytes());
            hasher.update(entry.term.to_le_bytes());
            hasher.update((entry.data.len() as u64).to_le_bytes());
            hasher.update(&entry.data);
        }
        hex(&hasher.finalize())
    }
}

/// Shared handle to one node's observation slot.
pub type ObservationHandle = Arc<Mutex<NodeObservation>>;

/// Accumulated record of which node claimed leadership in which term. Nodes
/// append themselves whenever they observe their own leader role; the checker
/// flags any term claimed by more than one distinct id.
#[derive(Clone, Default)]
pub struct LeadershipLog {
    pub leaders_by_term: BTreeMap<u64, BTreeSet<u64>>,
}

impl LeadershipLog {
    pub fn record(&mut self, term: u64, node_id: u64) {
        self.leaders_by_term.entry(term).or_default().insert(node_id);
    }

    /// The first term (if any) with two or more distinct leaders.
    pub fn conflicting_term(&self) -> Option<(u64, Vec<u64>)> {
        self.leaders_by_term
            .iter()
            .find(|(_, ids)| ids.len() > 1)
            .map(|(term, ids)| (*term, ids.iter().copied().collect()))
    }
}

pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_leader_per_term_is_accepted() {
        let mut log = LeadershipLog::default();
        log.record(1, 2);
        log.record(1, 2); // same node re-observing itself is fine
        log.record(2, 3);
        assert!(log.conflicting_term().is_none());
    }

    #[test]
    fn two_leaders_in_a_term_are_flagged() {
        let mut log = LeadershipLog::default();
        log.record(4, 1);
        log.record(4, 2);
        let (term, ids) = log.conflicting_term().expect("conflict detected");
        assert_eq!(term, 4);
        assert_eq!(ids, vec![1, 2]);
    }

    #[test]
    fn applied_hash_reflects_content() {
        let view = NodeObservation {
            applied: vec![
                AppliedEntry { index: 1, term: 1, data: vec![7] },
                AppliedEntry { index: 2, term: 1, data: vec![9] },
            ],
            ..Default::default()
        };
        let full = view.applied_hash_prefix(2);
        let prefix = view.applied_hash_prefix(1);
        assert_eq!(full.len(), 64);
        assert_ne!(full, prefix, "different prefix lengths must hash differently");
    }
}
