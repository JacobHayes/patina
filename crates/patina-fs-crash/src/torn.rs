//! Seeded crash decisions and block torn-write merging.

use std::collections::BTreeSet;

use patina_dst_fs_mem::{BLOCK_SIZE, BlockState, FileData, data::same_block};

use crate::CrashFs;

/// The bytes of `start..end`, zeros past the file's end: what a crash merge
/// compares.
fn bytes_of(data: &FileData, start: u64, end: u64) -> Vec<u8> {
    let mut bytes = data.read(start, (end - start) as usize);
    bytes.resize((end - start) as usize, 0);
    bytes
}

/// The torn blocks (of `granularity` bytes, below `blocks`) that can differ
/// between `baseline` and `current`, in order: those overlapping a 4 KiB block
/// where either holds written bytes that the other does not hold alike. A
/// hole and an unwritten block both read as zeros, so nothing else can.
fn candidate_blocks(
    baseline: &FileData,
    current: &FileData,
    granularity: u64,
    blocks: u64,
) -> Vec<u64> {
    let mut changed: BTreeSet<u64> = BTreeSet::new();
    let mut differs = |one: &FileData, other: &FileData| {
        for (index, block) in one.written() {
            let same = match other.block(index) {
                BlockState::Written(theirs) => same_block(block, theirs),
                BlockState::Hole | BlockState::Unwritten => block.iter().all(|byte| *byte == 0),
            };
            if !same {
                changed.insert(index);
            }
        }
    };
    differs(baseline, current);
    differs(current, baseline);
    let mut torn: Vec<u64> = Vec::new();
    for index in changed {
        let first = index * BLOCK_SIZE / granularity;
        let last = ((index + 1) * BLOCK_SIZE).div_ceil(granularity).min(blocks);
        for block in first.max(torn.last().map_or(0, |last| last + 1))..last {
            torn.push(block);
        }
    }
    torn
}

impl CrashFs {
    /// Draw a Bernoulli decision, consuming the seeded stream only when the
    /// probability is strictly interior so extreme knobs stay decision-free
    /// and identical across record and replay.
    pub(super) fn decide(&mut self, probability: f64) -> bool {
        if probability <= 0.0 {
            return false;
        }
        if probability >= 1.0 {
            return true;
        }
        let bits = self.rng.next_u64() >> 11;
        (bits as f64) / ((1u64 << 53) as f64) < probability
    }

    /// Merge durable `baseline` and live `current` at block granularity,
    /// tearing modified blocks back to the baseline per the seeded policy.
    ///
    /// A block is modified when its BYTES differ; a change of allocation alone
    /// (a reservation, a punched hole over zeros) is metadata the live image
    /// keeps, so it draws no decision. Only blocks that hold written data on
    /// either side can differ, so the merge visits those and nothing else: a
    /// sparse file costs its written blocks, whatever its length. Unchanged
    /// blocks are shared storage and compare by identity.
    pub(super) fn torn_merge(&mut self, baseline: &FileData, current: &FileData) -> FileData {
        let granularity = self.policy.torn_write_granularity as u64;
        let max_len = baseline.len().max(current.len());
        let blocks = max_len.div_ceil(granularity);
        let mut result = current.clone();
        // The tail block dictates the reconstructed length: an unchanged or
        // persisted tail keeps the live length. A reverted tail falls back to
        // the durable length, or, for a file that grew, to the end of its last
        // persisted block past it: an append whose last block reverted keeps
        // the blocks before it that persisted.
        let mut tail_reverted = false;
        let mut persisted_end = baseline.len();
        for block in candidate_blocks(baseline, current, granularity, blocks) {
            let start = block * granularity;
            let end = ((block + 1) * granularity).min(max_len);
            if bytes_of(baseline, start, end) == bytes_of(current, start, end) {
                continue;
            }
            // Persisted, the live bytes are already there; else the block
            // reverts to the durable bytes whole.
            let reverted = self.decide(self.policy.torn_write_probability);
            if reverted {
                result.overlay(baseline, start, end);
            } else {
                persisted_end = persisted_end.max(end.min(current.len()));
            }
            if block + 1 == blocks {
                tail_reverted = reverted;
            }
        }
        let len = if tail_reverted {
            persisted_end
        } else {
            current.len()
        };
        result.clip(len);
        result
    }
}

#[cfg(test)]
mod tests;
