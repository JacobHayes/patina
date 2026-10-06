//! A regular file's bytes as the volume stores them: its length, the blocks it
//! has written, and the unwritten extents a reservation left.
//!
//! The volume's block is 4 KiB — the `st_blksize` the stat family reports, the
//! `f_bsize` of the statfs profile, ext4's default block and the page size of
//! both supported architectures' pinned kernels — so one stored block is one
//! filesystem block and one page. A block is in one of three states, as an
//! ext4 extent is:
//!
//! * **written** — it holds bytes (zeros included: writing zeros allocates);
//! * **unwritten** — allocated by `fallocate` but never written: it counts in
//!   `st_blocks` and reads as zeros, and `SEEK_DATA` passes over it (6.8's
//!   `iomap_seek_data` treats an unwritten extent with no cached page as a
//!   hole, on ext4 and XFS alike);
//! * **a hole** — nothing stored; it reads as zeros and holds no block.
//!
//! A hole costs nothing, so a file of any length costs what it has written: a
//! 100 GiB file with a few bytes at its end holds one block. A written block
//! is one allocation of a power of two bytes, up to a block, that covers its
//! last written byte (the rest of the block reads as zeros), so a small file
//! costs about its bytes, not a whole block. Written blocks are shared (`Arc`)
//! between clones and copied on the first write after one, so a crash model's
//! durable baseline or a restart snapshot costs the blocks that changed since,
//! not the file.
//!
//! Invariants: no written block lies wholly past the length, and every stored
//! byte past the length or past the last byte written is zero; unwritten
//! extents are disjoint, never adjacent (merged), never overlap a written
//! block, and may lie past the length (a `FALLOC_FL_KEEP_SIZE` reservation).

mod blocks;

use std::collections::BTreeMap;
use std::sync::Arc;

use blocks::Blocks;

/// The volume's block, in bytes.
pub const BLOCK_SIZE: u64 = 4096;
const BLOCK: usize = BLOCK_SIZE as usize;
/// `st_blocks` counts 512-byte units.
const SECTORS_PER_BLOCK: u64 = BLOCK_SIZE / 512;

/// One written block: a power of two bytes (at most a block) covering its last
/// written byte; the rest of the block reads as zeros.
pub type Block = Arc<[u8]>;

/// A block of `old`'s bytes with `head` at `within`: `end` (`within` plus the
/// head's length) rounded up to a power of two, and at least double `old`, so
/// appends within a block copy it a logarithmic number of times.
fn grown(old: &[u8], within: usize, head: &[u8]) -> Block {
    let end = within + head.len();
    if old.is_empty() && within == 0 && end == BLOCK {
        return Arc::from(head);
    }
    let size = end.next_power_of_two().max(old.len() * 2).min(BLOCK);
    let mut block: Block = Arc::from(&ZEROS[..size]);
    let bytes = Arc::get_mut(&mut block).expect("a new block is unshared");
    bytes[..old.len()].copy_from_slice(old);
    bytes[within..end].copy_from_slice(head);
    block
}

/// A block of zeros, the fill a new written block starts from.
static ZEROS: [u8; BLOCK] = [0; BLOCK];

/// Whether two written blocks read the same: equal where both store bytes,
/// and zero where only one does.
pub fn same_block(a: &Block, b: &Block) -> bool {
    if Arc::ptr_eq(a, b) {
        return true;
    }
    let common = a.len().min(b.len());
    a[..common] == b[..common]
        && a[common..].iter().all(|byte| *byte == 0)
        && b[common..].iter().all(|byte| *byte == 0)
}

/// What one block of a file is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockState<'a> {
    Hole,
    Unwritten,
    Written(&'a Block),
}

/// A regular file's (or a symlink's) bytes. See the module docs.
#[derive(Clone, Debug, Default)]
pub struct FileData {
    len: u64,
    written: Blocks,
    /// Unwritten extents: first block index to one past the last.
    unwritten: BTreeMap<u64, u64>,
    /// The blocks `unwritten` covers.
    unwritten_blocks: u64,
}

/// Equal when they read the same and hold the same blocks in the same states.
impl PartialEq for FileData {
    fn eq(&self, other: &Self) -> bool {
        self.len == other.len
            && self.unwritten == other.unwritten
            && self.written.len() == other.written.len()
            && self
                .written
                .iter()
                .zip(other.written.iter())
                .all(|((i, a), (j, b))| i == j && same_block(a, b))
    }
}

impl Eq for FileData {}

fn block_of(offset: u64) -> u64 {
    offset / BLOCK_SIZE
}

/// The first block index at or past `offset`.
fn blocks_to(offset: u64) -> u64 {
    offset.div_ceil(BLOCK_SIZE)
}

impl FileData {
    /// A file holding `bytes` written from offset 0.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut data = Self::default();
        data.write(0, bytes);
        data
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The storage the file holds, in the 512-byte units `st_blocks` counts:
    /// its written and unwritten blocks, a reservation past the end included.
    pub fn sectors(&self) -> u64 {
        (self.written.len() + self.unwritten_blocks) * SECTORS_PER_BLOCK
    }

    /// Whether block `index` holds written bytes.
    pub fn is_written(&self, index: u64) -> bool {
        self.written.contains(index)
    }

    pub fn block(&self, index: u64) -> BlockState<'_> {
        if let Some(block) = self.written.get(index) {
            BlockState::Written(block)
        } else if self.is_unwritten(index) {
            BlockState::Unwritten
        } else {
            BlockState::Hole
        }
    }

    fn is_unwritten(&self, index: u64) -> bool {
        self.unwritten
            .range(..=index)
            .next_back()
            .is_some_and(|(_, &end)| index < end)
    }

    /// The written blocks, by index.
    pub fn written(&self) -> impl Iterator<Item = (u64, &Block)> {
        self.written.iter()
    }

    /// The unwritten extents as `(first, end)` block indices.
    pub fn unwritten(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.unwritten.iter().map(|(first, end)| (*first, *end))
    }

    /// The bytes in `offset..offset + max_len`, clipped to the length: holes
    /// and unwritten blocks read as zeros.
    pub fn read(&self, offset: u64, max_len: usize) -> Vec<u8> {
        let end = offset.saturating_add(max_len as u64).min(self.len);
        if offset >= end {
            return Vec::new();
        }
        let mut out = Vec::with_capacity((end - offset) as usize);
        self.read_into(offset, end, &mut out);
        out
    }

    /// Append the bytes of `offset..end` (within the length) to `out`.
    fn read_into(&self, offset: u64, end: u64, out: &mut Vec<u8>) {
        let base = out.len();
        let size = (end - offset) as usize;
        let index = block_of(offset);
        if block_of(end - 1) == index {
            if let Some(block) = self.written.get(index) {
                let from = (offset - index * BLOCK_SIZE) as usize;
                let to = (from + size).min(block.len());
                if from < to {
                    out.extend_from_slice(&block[from..to]);
                }
            }
            out.resize(base + size, 0);
            return;
        }
        // Contiguous written blocks are copied slice by slice and the gaps
        // between them filled once, so nothing is zeroed and then overwritten.
        for (index, block) in self.written.range(index, blocks_to(end)) {
            let start = index * BLOCK_SIZE;
            let from = (offset.max(start) - start) as usize;
            let to = ((end.min(start + BLOCK_SIZE) - start) as usize).min(block.len());
            if from < to {
                let at = base + (start + from as u64 - offset) as usize;
                if out.len() != at {
                    out.resize(at, 0);
                }
                out.extend_from_slice(&block[from..to]);
            }
        }
        out.resize(base + size, 0);
    }

    /// Every byte of the file.
    pub fn to_vec(&self) -> Vec<u8> {
        self.read(0, usize::try_from(self.len).unwrap_or(usize::MAX))
    }

    /// Write `bytes` at `offset`, growing the length to cover them: a block a
    /// write touches is written from then on, the rest of a block that was a
    /// hole or unwritten reading as zeros.
    pub fn write(&mut self, offset: u64, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        if self.unwritten_blocks != 0 {
            // Every block the write touches is written from now on, and an
            // unwritten extent never overlaps a written block.
            let end = offset.saturating_add(bytes.len() as u64);
            self.remove_unwritten(block_of(offset), blocks_to(end));
        }
        let mut position = offset;
        let mut rest = bytes;
        while !rest.is_empty() {
            let index = block_of(position);
            let within = (position % BLOCK_SIZE) as usize;
            let (head, tail) = rest.split_at((BLOCK - within).min(rest.len()));
            let end = within + head.len();
            // One lookup per block; a block is copied only when a clone
            // still shares it, and reallocated only to grow.
            self.written.update(index, |slot| match slot {
                Some(block) if block.len() >= end => {
                    Arc::make_mut(block)[within..end].copy_from_slice(head);
                }
                Some(block) => *block = grown(block, within, head),
                None => *slot = Some(grown(&[], within, head)),
            });
            position += head.len() as u64;
            rest = tail;
        }
        self.len = self.len.max(position);
    }

    /// `truncate`: the length becomes `len`. Growing leaves a hole (and keeps
    /// a reservation past the old end); any other length frees every block
    /// past the new end, a reservation included (`ext4_truncate` and
    /// `shmem_setattr` alike, host-checked on ext4, XFS and tmpfs), and zeroes
    /// the tail of the block the end falls in.
    pub fn set_len(&mut self, len: u64) {
        if len > self.len {
            self.len = len;
            return;
        }
        self.len = len;
        let keep = blocks_to(len);
        self.written.remove_range(keep, u64::MAX);
        self.remove_unwritten(keep, u64::MAX);
        self.zero_tail(len);
    }

    /// Zero the bytes of the block `len` falls in from `len` on, copying the
    /// block (and a shared leaf) only when one of them is not zero already.
    fn zero_tail(&mut self, len: u64) {
        let (index, within) = (block_of(len), (len % BLOCK_SIZE) as usize);
        let dirty = within != 0
            && self.written.get(index).is_some_and(|block| {
                block[within.min(block.len())..]
                    .iter()
                    .any(|byte| *byte != 0)
            });
        if dirty && let Some(block) = self.written.get_mut(index) {
            Arc::make_mut(block)[within..].fill(0);
        }
    }

    /// `fallocate` mode 0 or `FALLOC_FL_KEEP_SIZE` over `offset..end`: every
    /// block the range touches that is a hole becomes unwritten; written
    /// blocks keep their bytes. The length is the caller's.
    pub fn reserve(&mut self, offset: u64, end: u64) {
        let (first, last) = (block_of(offset), blocks_to(end));
        let mut gap = first;
        let written: Vec<u64> = self.written.range(first, last).map(|(i, _)| i).collect();
        for index in written {
            if gap < index {
                self.insert_unwritten(gap, index);
            }
            gap = index + 1;
        }
        if gap < last {
            self.insert_unwritten(gap, last);
        }
    }

    /// `FALLOC_FL_PUNCH_HOLE` over `offset..end`: the whole blocks inside the
    /// range become holes, and the written bytes of the partial blocks at its
    /// edges inside it are zeroed (a partial block that is unwritten or a hole
    /// stays as it is).
    pub fn punch(&mut self, offset: u64, end: u64) {
        if offset >= end {
            return;
        }
        let (first, last) = (blocks_to(offset), block_of(end));
        if first < last {
            self.remove_written(first, last);
            self.remove_unwritten(first, last);
        }
        self.zero_partial(offset, end);
    }

    /// `FALLOC_FL_ZERO_RANGE` over `offset..end` (`ext4_zero_range`): every
    /// block the range touches is allocated, its whole blocks become
    /// unwritten (written ones are converted, their bytes dropped), and the
    /// written bytes of its partial edge blocks inside it are zeroed. The
    /// length is the caller's.
    pub fn zero_range(&mut self, offset: u64, end: u64) {
        if offset >= end {
            return;
        }
        self.reserve(offset, end);
        let (first, last) = (blocks_to(offset), block_of(end));
        if first < last {
            self.remove_written(first, last);
            self.insert_unwritten(first, last);
        }
        self.zero_partial(offset, end);
    }

    /// Zero the written bytes of `offset..end` in the blocks it covers only in
    /// part.
    fn zero_partial(&mut self, offset: u64, end: u64) {
        for index in [block_of(offset), block_of(end - 1)] {
            let start = index * BLOCK_SIZE;
            if offset <= start && start + BLOCK_SIZE <= end {
                continue;
            }
            if let Some(block) = self.written.get_mut(index) {
                let from = (offset.max(start) - start) as usize;
                let to = ((end.min(start + BLOCK_SIZE) - start) as usize).min(block.len());
                if from < to {
                    Arc::make_mut(block)[from..to].fill(0);
                }
            }
        }
    }

    /// `SEEK_DATA`: the first offset at or past `offset` in a written block,
    /// or `None` when there is none before the end.
    pub fn seek_data(&self, offset: u64) -> Option<u64> {
        if offset >= self.len {
            return None;
        }
        let (index, _) = self.written.range(block_of(offset), u64::MAX).next()?;
        let position = offset.max(index * BLOCK_SIZE);
        (position < self.len).then_some(position)
    }

    /// `SEEK_HOLE`: the first offset at or past `offset` outside a written
    /// block, the end counting as one; `None` at or past the end.
    pub fn seek_hole(&self, offset: u64) -> Option<u64> {
        if offset >= self.len {
            return None;
        }
        let mut index = block_of(offset);
        for (written, _) in self.written.range(index, u64::MAX) {
            if written != index {
                break;
            }
            index += 1;
        }
        Some(offset.max(index.saturating_mul(BLOCK_SIZE)).min(self.len))
    }

    /// Take `source`'s bytes over `offset..end`, as a crash merge reverts a
    /// range to its durable image. A block the range covers whole takes
    /// `source`'s block as it is (written, unwritten or a hole, its storage
    /// shared); a block it covers in part takes `source`'s bytes there and is
    /// written if either side's block is. The length is untouched: see
    /// [`FileData::clip`].
    pub fn overlay(&mut self, source: &FileData, offset: u64, end: u64) {
        if offset >= end {
            return;
        }
        for index in block_of(offset)..blocks_to(end) {
            let start = index * BLOCK_SIZE;
            if offset <= start && start + BLOCK_SIZE <= end {
                self.remove_unwritten(index, index + 1);
                match source.block(index) {
                    BlockState::Hole => {
                        self.written.remove(index);
                    }
                    BlockState::Unwritten => {
                        self.written.remove(index);
                        self.insert_unwritten(index, index + 1);
                    }
                    BlockState::Written(block) => {
                        self.written.insert(index, Arc::clone(block));
                    }
                }
                continue;
            }
            if !self.is_written(index) && !source.is_written(index) {
                continue;
            }
            let (from, to) = (offset.max(start), end.min(start + BLOCK_SIZE));
            let mut bytes = source.read(from, (to - from) as usize);
            bytes.resize((to - from) as usize, 0);
            let length = self.len;
            self.write(from, &bytes);
            self.len = length;
        }
    }

    /// Set the length to `len` as a crash merge settles it: the written
    /// blocks past it go and the bytes past it are zeroed, a reservation
    /// stays.
    pub fn clip(&mut self, len: u64) {
        self.len = len;
        self.written.remove_range(blocks_to(len), u64::MAX);
        self.zero_tail(len);
    }

    fn remove_written(&mut self, first: u64, end: u64) {
        self.written.remove_range(first, end);
    }

    /// Cover `first..end` with an unwritten extent, merging the extents it
    /// overlaps or touches. The caller guarantees no written block inside.
    fn insert_unwritten(&mut self, first: u64, end: u64) {
        let (mut low, mut high) = (first, end);
        let mut removed = 0;
        // Extents are disjoint and never touch, so the ones to merge are the
        // last few starting at or before `high`, back to the first that ends
        // before `low`.
        while let Some((&start, &extent_end)) = self.unwritten.range(..=high).next_back() {
            if extent_end < low {
                break;
            }
            self.unwritten.remove(&start);
            removed += extent_end - start;
            low = low.min(start);
            high = high.max(extent_end);
        }
        self.unwritten.insert(low, high);
        self.unwritten_blocks += (high - low) - removed;
    }

    /// Uncover `first..end`, splitting the extents that straddle it.
    fn remove_unwritten(&mut self, first: u64, end: u64) {
        if self.unwritten_blocks == 0 {
            return;
        }
        while let Some((&start, &extent_end)) = self.unwritten.range(..end).next_back() {
            if extent_end <= first {
                break;
            }
            self.unwritten.remove(&start);
            self.unwritten_blocks -= extent_end - start;
            if end < extent_end {
                self.unwritten.insert(end, extent_end);
                self.unwritten_blocks += extent_end - end;
            }
            if start < first {
                // The kept head ends at `first`: the next look finds it and
                // stops.
                self.unwritten.insert(start, first);
                self.unwritten_blocks += first - start;
            }
        }
    }
}

/// The stored form a restart snapshot carries: runs of consecutive written
/// blocks and the unwritten extents, so a hole costs nothing there either.
impl FileData {
    /// The written blocks as runs of consecutive blocks, each its first index
    /// and its byte length, clipped to the length (a whole number of blocks
    /// but for the run that holds the end), from the block map alone.
    pub fn run_lengths(&self) -> Vec<(u64, u64)> {
        let mut runs: Vec<(u64, u64)> = Vec::new();
        for (index, _) in self.written.iter() {
            match runs.last_mut() {
                Some((first, count)) if *first + *count == index => *count += 1,
                _ => runs.push((index, 1)),
            }
        }
        for (first, count) in &mut runs {
            *count = (*count * BLOCK_SIZE).min(self.len - *first * BLOCK_SIZE);
        }
        runs
    }

    /// Append the bytes of the run of `len` bytes starting at block `first`
    /// (one of [`FileData::run_lengths`]) to `out`.
    pub fn append_run(&self, first: u64, len: u64, out: &mut Vec<u8>) {
        let start = first * BLOCK_SIZE;
        self.read_into(start, start + len, out);
    }

    /// Rebuild contents from runs of bytes (as [`FileData::run_lengths`] and
    /// [`FileData::append_run`] give them) and [`FileData::unwritten`], or
    /// `None` when they are not the canonical form of any file: runs out of order, touching or empty, a run not
    /// clipped to the length, an unwritten extent empty, out of order,
    /// touching another or overlapping a written block.
    pub fn from_stored(
        len: u64,
        runs: &[(u64, Vec<u8>)],
        unwritten: &[(u64, u64)],
    ) -> Option<Self> {
        let mut data = Self::default();
        let mut next_free = 0;
        for (first, bytes) in runs {
            let start = first.checked_mul(BLOCK_SIZE)?;
            let count = (bytes.len() as u64).div_ceil(BLOCK_SIZE);
            let canonical = count.checked_mul(BLOCK_SIZE)?.min(len.checked_sub(start)?);
            if bytes.is_empty() || *first < next_free || bytes.len() as u64 != canonical {
                return None;
            }
            data.write(start, bytes);
            next_free = first + count + 1;
        }
        data.len = len;
        let mut previous_end = None;
        for &(first, end) in unwritten {
            if first >= end
                || end > u64::MAX / BLOCK_SIZE
                || previous_end.is_some_and(|previous| first <= previous)
                || data.written.range(first, end).next().is_some()
            {
                return None;
            }
            data.insert_unwritten(first, end);
            previous_end = Some(end);
        }
        Some(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A file with a written block, a hole, a reservation and a short final
    /// block: `x` at 4090..4100 (blocks 0 and 1), a hole at block 2, block 3
    /// unwritten, `y` at 16384..16390 (block 4), and 8 blocks reserved past
    /// the end.
    fn shaped() -> FileData {
        let mut data = FileData::default();
        data.write(4090, b"xxxxxxxxxx");
        data.write(16384, b"yyyyyy");
        data.reserve(3 * BLOCK_SIZE, 4 * BLOCK_SIZE);
        data.reserve(5 * BLOCK_SIZE, 13 * BLOCK_SIZE);
        data
    }

    #[test]
    fn reads_see_holes_and_reservations_as_zeros_across_every_boundary() {
        let data = shaped();
        assert_eq!(data.len(), 16390);
        assert_eq!(data.sectors(), (3 + 1 + 8) * SECTORS_PER_BLOCK);
        let mut expected = vec![0u8; 16390];
        expected[4090..4100].fill(b'x');
        expected[16384..].fill(b'y');
        assert_eq!(data.to_vec(), expected);
        for (offset, len) in [
            (0, 5000),
            (4095, 2),
            (4100, 12290),
            (16383, 100),
            (20000, 5),
        ] {
            let end = (offset + len).min(expected.len());
            let want = expected.get(offset..end).unwrap_or_default();
            assert_eq!(data.read(offset as u64, len), want, "{offset}+{len}");
        }
    }

    #[test]
    fn a_clone_shares_blocks_until_one_side_writes() {
        let original = shaped();
        let mut copy = original.clone();
        copy.write(4095, b"Z");
        copy.set_len(4096);
        assert_eq!(original, shaped());
        assert_eq!(copy.to_vec()[4090..], *b"xxxxxZ");
        assert_ne!(copy, original);
    }

    #[test]
    fn the_stored_form_round_trips_and_only_its_canonical_form_decodes() {
        let data = shaped();
        let runs: Vec<(u64, Vec<u8>)> = data
            .run_lengths()
            .into_iter()
            .map(|(first, len)| {
                let mut bytes = Vec::new();
                data.append_run(first, len, &mut bytes);
                (first, bytes)
            })
            .collect();
        let unwritten: Vec<(u64, u64)> = data.unwritten().collect();
        // A run is whole blocks but for the one that holds the end.
        assert_eq!(
            runs.iter()
                .map(|(first, run)| (*first, run.len()))
                .collect::<Vec<_>>(),
            [(0, 8192), (4, 6)]
        );
        assert_eq!(unwritten, [(3, 4), (5, 13)]);
        assert_eq!(
            FileData::from_stored(data.len(), &runs, &unwritten),
            Some(data)
        );
        let block = |len| vec![1u8; len];
        type Stored = (&'static str, u64, Vec<(u64, Vec<u8>)>, Vec<(u64, u64)>);
        let malformed: &[Stored] = &[
            ("an empty run", 100, vec![(0, vec![])], vec![]),
            (
                "a run not clipped to the length",
                100,
                vec![(0, block(4096))],
                vec![],
            ),
            (
                "a short run before the end",
                9000,
                vec![(0, block(100))],
                vec![],
            ),
            ("a run past the end", 100, vec![(1, block(1))], vec![]),
            (
                "touching runs",
                16384,
                vec![(0, block(4096)), (1, block(4096))],
                vec![],
            ),
            (
                "runs out of order",
                16384,
                vec![(2, block(4096)), (0, block(4096))],
                vec![],
            ),
            ("an empty extent", 0, vec![], vec![(3, 3)]),
            ("touching extents", 0, vec![], vec![(1, 2), (2, 3)]),
            (
                "a reservation over a written block",
                4096,
                vec![(0, block(4096))],
                vec![(0, 1)],
            ),
        ];
        for (name, len, runs, unwritten) in malformed {
            assert_eq!(FileData::from_stored(*len, runs, unwritten), None, "{name}");
        }
    }
}
