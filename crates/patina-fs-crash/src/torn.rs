//! Seeded crash decisions and block or byte torn-write merging.

use std::collections::BTreeSet;

use patina_dst_fs_mem::{BLOCK_SIZE, BlockState, FileData, data::same_block};

use crate::CrashFs;

/// Granularity at which a torn write reverts on crash.
///
/// [`TornGranularity::Block`] (the default) reverts a modified block all-or-
/// nothing, so a torn block is byte-identical to either the durable baseline or
/// the live image. [`TornGranularity::Byte`] additionally lets the single most
/// recent unsynced write survive at sub-block byte granularity: a seeded cut
/// inside the write's differing bytes keeps a prefix from the live image and
/// reverts the suffix to the durable baseline, so the affected block differs
/// from *both* endpoints — the torn-page image a whole-block model can never
/// produce.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TornGranularity {
    /// Whole-block revert: a torn block is entirely durable or entirely live.
    #[default]
    Block,
    /// Sub-block tearing of the final unsynced write at byte granularity.
    Byte,
}

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
    ///
    /// `partial_region`, when set, is the `[start, end)` byte range of the final
    /// unsynced write to this file under [`TornGranularity::Byte`]. A torn block
    /// overlapping that region keeps a seeded prefix of the live bytes and
    /// reverts the rest, so the block differs from both the durable and the
    /// fully-applied image. Every other torn block reverts wholesale, exactly as
    /// in the whole-block model.
    pub(super) fn torn_merge(
        &mut self,
        baseline: &FileData,
        current: &FileData,
        partial_region: Option<(u64, u64)>,
    ) -> FileData {
        let granularity = self.policy.torn_write_granularity as u64;
        let max_len = baseline.len().max(current.len());
        let blocks = max_len.div_ceil(granularity);
        let mut result = current.clone();
        // The tail block dictates the reconstructed length: a persisted or
        // partially-torn tail keeps the live length (a partial tear models an
        // in-place page whose size already reached disk), a wholly-reverted tail
        // falls back to the durable length.
        let mut tail_reverted = false;
        for block in candidate_blocks(baseline, current, granularity, blocks) {
            let start = block * granularity;
            let end = ((block + 1) * granularity).min(max_len);
            if bytes_of(baseline, start, end) == bytes_of(current, start, end) {
                continue;
            }
            let mut reverted = false;
            if !self.decide(self.policy.torn_write_probability) {
                // Persisted: the live bytes are already there.
            } else if let Some(cut) = partial_region
                .and_then(|(rs, re)| self.partial_cut(start, end, rs, re, baseline, current))
            {
                // Sub-block tear: keep the live prefix, revert the suffix.
                result.overlay(baseline, cut, end);
            } else {
                result.overlay(baseline, start, end);
                reverted = true;
            }
            if block + 1 == blocks {
                tail_reverted = reverted;
            }
        }
        result.clip(if tail_reverted {
            baseline.len()
        } else {
            current.len()
        });
        result
    }

    /// Choose a seeded byte cut inside the intersection of block `[start, end)`,
    /// the final-write `[region_start, region_end)`, and the bytes that actually
    /// differ between `baseline` and `current`. Returns the absolute cut so that
    /// `[start, cut)` takes the live bytes and `[cut, end)` reverts to durable,
    /// guaranteeing at least one differing byte on each side (so the block
    /// differs from both endpoints). Returns `None` when the overlap has fewer
    /// than two differing bytes and no partial split is possible.
    fn partial_cut(
        &mut self,
        start: u64,
        end: u64,
        region_start: u64,
        region_end: u64,
        baseline: &FileData,
        current: &FileData,
    ) -> Option<u64> {
        let lo = start.max(region_start);
        let hi = end.min(region_end);
        if lo >= hi {
            return None;
        }
        let (durable, live) = (bytes_of(baseline, lo, hi), bytes_of(current, lo, hi));
        let differs = |index: &usize| durable[*index] != live[*index];
        let first_diff = (0..durable.len()).find(differs)? as u64 + lo;
        let last_diff = (0..durable.len()).rev().find(differs)? as u64 + lo;
        if last_diff <= first_diff {
            return None;
        }
        // Cut lands in `[first_diff + 1, last_diff]`: the live prefix keeps
        // `first_diff` (differs from durable) and the durable suffix keeps
        // `last_diff` (differs from live).
        let span = last_diff - first_diff;
        Some(first_diff + 1 + self.rng.next_u64() % span)
    }
}

#[cfg(test)]
mod tests;
