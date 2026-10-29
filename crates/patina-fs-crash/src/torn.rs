//! Seeded crash decisions and in-place block tearing.

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

    /// The bytes a crash leaves of a file the last commit recorded as `base`
    /// and the cache holds as `current`: `base`, except that each block below
    /// `limit` the commit had written and the cache has since overwritten in
    /// place keeps its old bytes or takes the new ones whole, per the seeded
    /// policy, as a disk that writes whole sectors leaves it. A block
    /// `freed` since the commit (punched or zeroed) is not overwritten in
    /// place either: a write there lands on a new block. A block
    /// allocated since the commit is not on disk (delayed allocation), and
    /// a punched, zeroed or reserved range is an extent change the commit
    /// did not record, so neither draws a decision. Only blocks holding written data on
    /// either side can differ, so a sparse file costs its written blocks,
    /// whatever its length.
    pub(super) fn torn_in_place(
        &mut self,
        base: &FileData,
        current: &FileData,
        limit: u64,
        freed: &BTreeSet<u64>,
    ) -> FileData {
        let granularity = self.policy.torn_write_granularity as u64;
        let blocks = limit.div_ceil(granularity);
        let mut result = base.clone();
        for block in candidate_blocks(base, current, granularity, blocks) {
            let start = block * granularity;
            let end = ((block + 1) * granularity).min(limit);
            let index = start / BLOCK_SIZE;
            if !base.is_written(index)
                || !current.is_written(index)
                || freed.contains(&index)
                || bytes_of(base, start, end) == bytes_of(current, start, end)
            {
                continue;
            }
            if !self.decide(self.policy.torn_write_probability) {
                result.overlay(current, start, end);
            }
        }
        result
    }
}

#[cfg(test)]
mod tests;
