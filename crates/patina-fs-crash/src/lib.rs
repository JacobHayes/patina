//! Deterministic crash/restart semantics for the in-memory filesystem.
//!
//! `CrashFs` keeps a live working image and a durable baseline. Ordinary
//! effects mutate the live image. Durability is reached incrementally: a file
//! `sync` stages that file's fsynced content, `sync_directory` commits the
//! namespace operations of one directory, and `checkpoint` makes the entire
//! live image durable. `crash` recomputes the post-crash image from the
//! durable baseline plus seeded torn-write and lost-entry decisions, then
//! invalidates every open handle so a modeled process restart begins from a
//! clean descriptor table.
//!
//! ## Models
//!
//! - **Torn writes**: on crash, blocks modified since their last durability
//!   point may fail to persist and revert to the durable bytes. The tear
//!   decision is drawn per block of `torn_write_granularity` bytes from a
//!   seeded [`SplitMix64`] stream with `torn_write_probability`. The default
//!   [`TornGranularity::Block`] policy tears whole blocks all-or-nothing, so a
//!   torn block is either entirely the durable image or entirely the live one —
//!   the model that only ever yields crash-consistent block prefixes. Under
//!   [`TornGranularity::Byte`] the single most recent unsynced write may instead
//!   survive *partially*: a seeded cut point inside the differing region keeps a
//!   prefix of the write and reverts the suffix to the durable bytes, modeling a
//!   torn in-flight page whose header and body disagree. Every other unsynced
//!   block still tears wholesale, so a byte-granularity crash reproduces the
//!   realistic "clean prefix plus one torn final page" geometry.
//! - **Rename atomicity**: with `model_rename_atomicity(true)` a rename is a
//!   single all-or-nothing namespace change across a crash. With it disabled a
//!   crash can land between the destination link and source unlink, exposing
//!   duplicated or lost entries. A rename has two governing directories — the
//!   destination parent (link side) and the source parent (unlink side) — and
//!   is fully durable only when both are fsynced; fsyncing one leaves the other
//!   side subject to its seeded loss decision.
//! - **Directory durability**: with `model_directory_durability(true)` a
//!   creation, unlink, or rename that has not been committed by a
//!   `sync_directory` of the governing directory may be lost on crash per
//!   `directory_loss_probability` — the classic "you must fsync the directory"
//!   bug class.
//!
//! Files, directories, and symlinks are all carried through the durable
//! baseline and recomputed on crash with the same namespace-durability rules,
//! so a symlink is never silently dropped. Per-entry timestamps captured at the
//! last durability point are restored on reconstruction. Hard links are
//! modeled at the data level — each surviving name keeps the shared content —
//! but inode identity (shared `nlink`) is not preserved across a crash.
//!
//! All decisions are a deterministic function of the configured seed and the
//! exact operation sequence, so identical seeds reproduce identical post-crash
//! images. This lets crash outcomes round-trip through record/replay: the
//! `crash` operation records no observable value, but every later read or
//! metadata query reflects the same seeded decisions and is compared during
//! replay.

use std::collections::{BTreeMap, BTreeSet};

use patina_dst_abi::{
    EffectError, ErrorCode, Fd, FsDirectoryEntry, FsEntryKind, FsMetadata, OpenFlags, SeekWhence,
};
use patina_dst_driver_api::{DriverResult, FsDriver};
use patina_dst_fs_mem::MemFs;
use patina_dst_rng_seeded::SplitMix64;

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

/// Tuning for the seeded crash-consistency decision policies.
#[derive(Clone, Debug)]
struct CrashPolicy {
    torn_write_granularity: usize,
    torn_write_probability: f64,
    torn_granularity: TornGranularity,
    model_rename_atomicity: bool,
    model_directory_durability: bool,
    directory_loss_probability: f64,
}

impl Default for CrashPolicy {
    fn default() -> Self {
        Self {
            torn_write_granularity: 4096,
            torn_write_probability: 1.0,
            torn_granularity: TornGranularity::Block,
            model_rename_atomicity: true,
            model_directory_durability: false,
            directory_loss_probability: 0.0,
        }
    }
}

/// A namespace mutation observed since the last durable baseline. Every entry
/// carries its kind so files, directories, and symlinks are tracked in the same
/// journal and none is silently dropped across a crash.
#[derive(Clone, Debug)]
enum PendingKind {
    Create {
        path: String,
        kind: FsEntryKind,
    },
    Remove {
        path: String,
        kind: FsEntryKind,
    },
    Rename {
        from: String,
        to: String,
        kind: FsEntryKind,
    },
}

#[derive(Clone, Debug)]
struct PendingOp {
    kind: PendingKind,
    /// Whether the governing directory of the create (or a rename's link) side
    /// has been made durable by a `sync_directory`.
    committed: bool,
    /// Whether the source parent directory of a rename has been made durable.
    /// Only meaningful for [`PendingKind::Rename`]; a rename is fully durable
    /// only when both its link and unlink sides are committed.
    source_committed: bool,
}

/// A durable filesystem baseline captured at a durability point: the directory
/// set, file contents, symlink targets, and per-entry timestamps.
#[derive(Clone, Default)]
struct Baseline {
    dirs: BTreeSet<String>,
    files: BTreeMap<String, Vec<u8>>,
    symlinks: BTreeMap<String, String>,
    times: BTreeMap<String, (u64, u64)>,
}

/// A configurable crash-consistency filesystem model.
///
/// Construct one with [`CrashFs::builder`] to select the torn-write,
/// rename-atomicity, and directory-durability models, or use
/// [`CrashFs::default`] for the conservative whole-file model where fsynced
/// data survives, namespace changes are durable, and unsynced data is lost.
pub struct CrashFs {
    live: MemFs,
    /// The durable baseline: entries, contents, symlink targets, and times.
    durable: Baseline,
    /// Per-file content made durable by an explicit file `sync`.
    staged_content: BTreeMap<String, Vec<u8>>,
    /// Namespace operations since the baseline, in observation order.
    pending: Vec<PendingOp>,
    /// Live descriptor-to-path map used to attribute `sync` calls.
    open_paths: BTreeMap<Fd, String>,
    /// The single most recent unsynced write as `(path, offset, len)`. Under
    /// [`TornGranularity::Byte`] this is the region eligible for a sub-block
    /// partial tear on crash; `None` before any write and after a durability
    /// point clears the pending set.
    last_write: Option<(String, usize, usize)>,
    policy: CrashPolicy,
    rng: SplitMix64,
    crashes: u64,
}

/// Builds a [`CrashFs`] with typed, code-first crash semantics.
pub struct CrashFsBuilder {
    filesystem: MemFs,
    seed: u64,
    policy: CrashPolicy,
}

impl CrashFsBuilder {
    fn new() -> Self {
        Self {
            filesystem: MemFs::new(),
            seed: 0,
            policy: CrashPolicy::default(),
        }
    }

    /// Use `filesystem` as the initial durable image.
    pub fn filesystem(mut self, filesystem: MemFs) -> Self {
        self.filesystem = filesystem;
        self
    }

    /// Seed the deterministic crash-decision policy.
    pub fn seed(mut self, seed: u64) -> Self {
        self.seed = seed;
        self
    }

    /// Set the torn-write block size in bytes. Must be at least one.
    pub fn torn_write_granularity(mut self, bytes: usize) -> Self {
        self.policy.torn_write_granularity = bytes;
        self
    }

    /// Probability in `[0, 1]` that a modified block reverts on crash.
    pub fn torn_write_probability(mut self, probability: f64) -> Self {
        self.policy.torn_write_probability = probability;
        self
    }

    /// Select whole-block or sub-block byte-granularity tearing of the final
    /// unsynced write. See [`TornGranularity`].
    pub fn torn_granularity(mut self, granularity: TornGranularity) -> Self {
        self.policy.torn_granularity = granularity;
        self
    }

    /// Keep renames atomic across a crash when `true`.
    pub fn model_rename_atomicity(mut self, atomic: bool) -> Self {
        self.policy.model_rename_atomicity = atomic;
        self
    }

    /// Model loss of directory entries not made durable by `sync_directory`.
    pub fn model_directory_durability(mut self, enabled: bool) -> Self {
        self.policy.model_directory_durability = enabled;
        self
    }

    /// Probability in `[0, 1]` that an uncommitted namespace change is lost.
    pub fn directory_loss_probability(mut self, probability: f64) -> Self {
        self.policy.directory_loss_probability = probability;
        self
    }

    /// Validate the configuration and build the model. Fails closed on any
    /// out-of-range knob rather than silently clamping.
    pub fn build(self) -> DriverResult<CrashFs> {
        if self.policy.torn_write_granularity == 0 {
            return Err(EffectError::new(
                ErrorCode::InvalidInput,
                "torn_write_granularity must be at least 1 byte",
            ));
        }
        if !(0.0..=1.0).contains(&self.policy.torn_write_probability) {
            return Err(EffectError::new(
                ErrorCode::InvalidInput,
                "torn_write_probability must be within [0, 1]",
            ));
        }
        if !(0.0..=1.0).contains(&self.policy.directory_loss_probability) {
            return Err(EffectError::new(
                ErrorCode::InvalidInput,
                "directory_loss_probability must be within [0, 1]",
            ));
        }
        Ok(CrashFs::with_policy(
            self.filesystem,
            self.policy,
            self.seed,
        ))
    }
}

impl std::fmt::Debug for CrashFs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CrashFs")
            .field("policy", &self.policy)
            .field("pending", &self.pending.len())
            .field("crashes", &self.crashes)
            .finish_non_exhaustive()
    }
}

impl CrashFs {
    pub fn new(filesystem: MemFs) -> Self {
        Self::with_policy(filesystem, CrashPolicy::default(), 0)
    }

    /// Start a typed builder for the crash-consistency models.
    pub fn builder() -> CrashFsBuilder {
        CrashFsBuilder::new()
    }

    fn with_policy(mut filesystem: MemFs, policy: CrashPolicy, seed: u64) -> Self {
        let durable = enumerate(&mut filesystem);
        Self {
            live: filesystem,
            durable,
            staged_content: BTreeMap::new(),
            pending: Vec::new(),
            open_paths: BTreeMap::new(),
            last_write: None,
            policy,
            rng: SplitMix64::new(seed),
            crashes: 0,
        }
    }

    /// Make the entire live image durable as one deterministic checkpoint.
    pub fn checkpoint(&mut self) {
        self.durable = enumerate(&mut self.live);
        self.staged_content.clear();
        self.pending.clear();
        self.last_write = None;
    }

    /// Commit the namespace operations of one directory, modeling a directory
    /// fsync. After this, the directory's creations, unlinks, and renames
    /// survive a crash even under the directory-durability model.
    pub fn sync_directory(&mut self, path: &str) -> DriverResult<()> {
        let path = normalize_entry_path(path)?;
        if !matches!(self.live.metadata(&path)?.kind, FsEntryKind::Directory) {
            return Err(EffectError::new(
                ErrorCode::NotDirectory,
                format!("virtual filesystem path is not a directory: {path}"),
            ));
        }
        // Committing a directory makes durable exactly the namespace changes it
        // governs. A rename has two governing directories: the destination
        // parent (its link side, tracked by `committed`) and the source parent
        // (its unlink side, tracked by `source_committed`). Only fsyncing both
        // makes the whole rename durable.
        for op in &mut self.pending {
            match &op.kind {
                PendingKind::Create { path: entry, .. }
                | PendingKind::Remove { path: entry, .. } => {
                    if parent_path(entry) == path {
                        op.committed = true;
                    }
                }
                PendingKind::Rename { from, to, .. } => {
                    if parent_path(to) == path {
                        op.committed = true;
                    }
                    if parent_path(from) == path {
                        op.source_committed = true;
                    }
                }
            }
        }
        Ok(())
    }

    pub fn crash_count(&self) -> u64 {
        self.crashes
    }

    pub fn contents(&self, path: &str) -> DriverResult<&[u8]> {
        self.live.contents(path)
    }

    /// Draw a Bernoulli decision, consuming the seeded stream only when the
    /// probability is strictly interior so extreme knobs stay decision-free
    /// and identical across record and replay.
    fn decide(&mut self, probability: f64) -> bool {
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
    /// `partial_region`, when set, is the `[start, end)` byte range of the final
    /// unsynced write to this file under [`TornGranularity::Byte`]. A torn block
    /// overlapping that region keeps a seeded prefix of the live bytes and
    /// reverts the rest, so the block differs from both the durable and the
    /// fully-applied image. Every other torn block reverts wholesale, exactly as
    /// in the whole-block model.
    fn torn_merge(
        &mut self,
        baseline: &[u8],
        current: &[u8],
        partial_region: Option<(usize, usize)>,
    ) -> Vec<u8> {
        let granularity = self.policy.torn_write_granularity;
        let max_len = baseline.len().max(current.len());
        if max_len == 0 {
            return Vec::new();
        }
        let blocks = max_len.div_ceil(granularity);
        let mut result = vec![0u8; max_len];
        // The tail block dictates the reconstructed length: a persisted or
        // partially-torn tail keeps the live length (a partial tear models an
        // in-place page whose size already reached disk), a wholly-reverted tail
        // falls back to the durable length.
        let mut tail_reverted = false;
        for block in 0..blocks {
            let start = block * granularity;
            let end = ((block + 1) * granularity).min(max_len);
            let same =
                (start..end).all(|index| byte_at(baseline, index) == byte_at(current, index));
            let persist = if same {
                true
            } else {
                !self.decide(self.policy.torn_write_probability)
            };
            let mut reverted = false;
            if persist {
                copy_range(&mut result, current, start, end);
            } else if let Some(cut) = partial_region
                .and_then(|(rs, re)| self.partial_cut(start, end, rs, re, baseline, current))
            {
                // Sub-block tear: keep the live prefix, revert the suffix.
                copy_range(&mut result, current, start, cut);
                copy_range(&mut result, baseline, cut, end);
            } else {
                copy_range(&mut result, baseline, start, end);
                reverted = true;
            }
            if block + 1 == blocks {
                tail_reverted = reverted;
            }
        }
        let final_len = if tail_reverted {
            baseline.len()
        } else {
            current.len()
        };
        result.truncate(final_len);
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
        start: usize,
        end: usize,
        region_start: usize,
        region_end: usize,
        baseline: &[u8],
        current: &[u8],
    ) -> Option<usize> {
        let lo = start.max(region_start);
        let hi = end.min(region_end);
        if lo >= hi {
            return None;
        }
        let mut first_diff = None;
        let mut last_diff = None;
        for index in lo..hi {
            if byte_at(baseline, index) != byte_at(current, index) {
                first_diff.get_or_insert(index);
                last_diff = Some(index);
            }
        }
        let (first_diff, last_diff) = (first_diff?, last_diff?);
        if last_diff <= first_diff {
            return None;
        }
        // Cut lands in `[first_diff + 1, last_diff]`: the live prefix keeps
        // `first_diff` (differs from durable) and the durable suffix keeps
        // `last_diff` (differs from live).
        let span = (last_diff - first_diff) as u64;
        let cut = first_diff + 1 + (self.rng.next_u64() % span) as usize;
        Some(cut)
    }

    fn recompute_after_crash(&mut self) -> DriverResult<()> {
        let pending = self.pending.clone();
        let mut dirs = self.durable.dirs.clone();
        let mut files: BTreeSet<String> = self.durable.files.keys().cloned().collect();
        let mut symlinks: BTreeSet<String> = self.durable.symlinks.keys().cloned().collect();

        for op in &pending {
            match &op.kind {
                PendingKind::Create { path, kind } => {
                    let survive = self.entry_survives(op.committed);
                    let set = survival_set(*kind, &mut dirs, &mut files, &mut symlinks);
                    if survive {
                        set.insert(path.clone());
                    } else {
                        set.remove(path);
                    }
                }
                PendingKind::Remove { path, kind } => {
                    // A surviving unlink persists the removal; a lost unlink
                    // resurrects the durable entry.
                    let persist = self.entry_survives(op.committed);
                    let set = survival_set(*kind, &mut dirs, &mut files, &mut symlinks);
                    if persist {
                        set.remove(path);
                    } else {
                        set.insert(path.clone());
                    }
                }
                PendingKind::Rename { from, to, kind } => {
                    if self.policy.model_rename_atomicity || *kind == FsEntryKind::Directory {
                        // Atomic (or directory) renames are all-or-nothing and
                        // fully durable only when both governing directories are
                        // committed; otherwise a single seeded decision applies.
                        if self.entry_survives(op.committed && op.source_committed) {
                            rewrite_prefix(&mut dirs, from, to);
                            rewrite_prefix(&mut files, from, to);
                            rewrite_prefix(&mut symlinks, from, to);
                        }
                    } else {
                        // Non-atomic: the destination link and the source unlink
                        // are governed by their own directories and fail
                        // independently, so a crash can leave both names or
                        // neither. Draw the link side first, then the unlink
                        // side, for a stable decision order.
                        let link_new = self.entry_survives(op.committed);
                        let unlink_old = self.entry_survives(op.source_committed);
                        let set = survival_set(*kind, &mut dirs, &mut files, &mut symlinks);
                        if unlink_old {
                            set.remove(from);
                        }
                        if link_new {
                            set.insert(to.clone());
                        }
                    }
                }
            }
        }

        // The final unsynced write is eligible for a sub-block partial tear
        // under the byte-granularity policy; every other block still tears
        // wholesale. Captured before the merge loop borrows the rng.
        let final_write = match self.policy.torn_granularity {
            TornGranularity::Byte => self.last_write.clone(),
            TornGranularity::Block => None,
        };
        let mut file_contents: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        for path in &files {
            let baseline = self
                .staged_content
                .get(path)
                .or_else(|| self.durable.files.get(path))
                .cloned()
                .unwrap_or_default();
            let partial_region = match &final_write {
                Some((write_path, offset, len)) if write_path == path => {
                    Some((*offset, offset.saturating_add(*len)))
                }
                _ => None,
            };
            let content = match self.live.contents(path) {
                Ok(current) => {
                    let current = current.to_vec();
                    self.torn_merge(&baseline, &current, partial_region)
                }
                Err(_) => baseline,
            };
            file_contents.insert(path.clone(), content);
        }
        let mut symlink_targets: BTreeMap<String, String> = BTreeMap::new();
        for path in &symlinks {
            // A symlink's target is metadata, not torn data: keep the live
            // target if still present, else the durable baseline target.
            let target = self
                .live
                .read_link(path)
                .ok()
                .or_else(|| self.durable.symlinks.get(path).cloned())
                .unwrap_or_default();
            symlink_targets.insert(path.clone(), target);
        }

        let mut next = MemFs::new();
        for (path, bytes) in &file_contents {
            next = next.with_file(path, bytes.clone())?;
        }
        for dir in &dirs {
            if dir != "/" {
                ensure_parents(&mut next, dir)?;
                if next.metadata(dir).is_err() {
                    next.create_directory(dir)?;
                }
            }
        }
        for (path, target) in &symlink_targets {
            ensure_parents(&mut next, path)?;
            next.symlink(target, path)?;
        }
        // Restore durable timestamps for the surviving baseline entries so
        // crash reconstruction does not silently reset metadata to zero.
        for (path, (atime, mtime)) in &self.durable.times {
            if next.metadata(path).is_ok() {
                next.set_times_by_path(path, Some(*atime), Some(*mtime))?;
            }
        }

        self.durable = enumerate(&mut next);
        self.live = next;
        self.staged_content.clear();
        self.pending.clear();
        self.open_paths.clear();
        self.last_write = None;
        Ok(())
    }

    /// Decide whether an uncommitted namespace change survives a crash. When a
    /// directory fsync committed it, or the directory-durability model is off,
    /// it survives without consuming the decision stream.
    fn entry_survives(&mut self, committed: bool) -> bool {
        if committed || !self.policy.model_directory_durability {
            return true;
        }
        !self.decide(self.policy.directory_loss_probability)
    }

    /// Record a namespace mutation in the pending journal, initially uncommitted
    /// on both governing-directory sides.
    fn journal(&mut self, kind: PendingKind) {
        self.pending.push(PendingOp {
            kind,
            committed: false,
            source_committed: false,
        });
    }
}

impl Default for CrashFs {
    fn default() -> Self {
        Self::new(MemFs::new())
    }
}

impl FsDriver for CrashFs {
    fn open(&mut self, path: &str, flags: OpenFlags) -> DriverResult<Fd> {
        let existed = self
            .live
            .metadata(path)
            .map(|metadata| matches!(metadata.kind, FsEntryKind::File))
            .unwrap_or(false);
        let fd = self.live.open(path, flags)?;
        let normalized = normalize_path(path).expect("open normalized the path already");
        if flags.create && !existed {
            self.journal(PendingKind::Create {
                path: normalized.clone(),
                kind: FsEntryKind::File,
            });
        }
        self.open_paths.insert(fd, normalized);
        Ok(fd)
    }

    fn read(&mut self, fd: Fd, max_len: usize) -> DriverResult<Vec<u8>> {
        self.live.read(fd, max_len)
    }

    fn write(&mut self, fd: Fd, bytes: &[u8]) -> DriverResult<usize> {
        // Capture the write offset before the cursor advances so the byte-
        // granularity crash model knows which bytes the final write touched.
        // Positional writes (`write_at`) reach this method after the driver's
        // default seek-to-offset, so their target offset is recorded too.
        let offset = self.live.seek(fd, 0, SeekWhence::Current).ok();
        let written = self.live.write(fd, bytes)?;
        if let (Some(offset), Some(path)) = (offset, self.open_paths.get(&fd).cloned()) {
            self.last_write = Some((path, offset as usize, written));
        }
        Ok(written)
    }

    fn close(&mut self, fd: Fd) -> DriverResult<()> {
        self.live.close(fd)?;
        self.open_paths.remove(&fd);
        Ok(())
    }

    fn seek(&mut self, fd: Fd, offset: i64, whence: SeekWhence) -> DriverResult<u64> {
        self.live.seek(fd, offset, whence)
    }

    fn dup(&mut self, fd: Fd) -> DriverResult<Fd> {
        let duplicate = self.live.dup(fd)?;
        if let Some(path) = self.open_paths.get(&fd).cloned() {
            self.open_paths.insert(duplicate, path);
        }
        Ok(duplicate)
    }

    fn metadata(&mut self, path: &str) -> DriverResult<FsMetadata> {
        self.live.metadata(path)
    }

    fn fd_metadata(&mut self, fd: Fd) -> DriverResult<FsMetadata> {
        self.live.fd_metadata(fd)
    }

    fn create_directory(&mut self, path: &str) -> DriverResult<()> {
        self.live.create_directory(path)?;
        let normalized = normalize_entry_path(path).expect("create normalized the path already");
        self.journal(PendingKind::Create {
            path: normalized,
            kind: FsEntryKind::Directory,
        });
        Ok(())
    }

    fn remove_file(&mut self, path: &str) -> DriverResult<()> {
        // A symlink is removed through this call too, so capture the kind before
        // it disappears to journal the correct survival set.
        let kind = self
            .live
            .metadata(path)
            .map(|metadata| metadata.kind)
            .unwrap_or(FsEntryKind::File);
        self.live.remove_file(path)?;
        let normalized = normalize_entry_path(path).expect("remove normalized the path already");
        self.journal(PendingKind::Remove {
            path: normalized,
            kind,
        });
        Ok(())
    }

    fn sync(&mut self, fd: Fd) -> DriverResult<()> {
        self.live.sync(fd)?;
        if let Some(path) = self.open_paths.get(&fd).cloned() {
            if let Ok(bytes) = self.live.contents(&path) {
                self.staged_content.insert(path, bytes.to_vec());
            }
        }
        Ok(())
    }

    fn set_len(&mut self, fd: Fd, len: u64) -> DriverResult<()> {
        self.live.set_len(fd, len)
    }

    fn read_directory(&mut self, path: &str) -> DriverResult<Vec<FsDirectoryEntry>> {
        self.live.read_directory(path)
    }

    fn remove_directory(&mut self, path: &str) -> DriverResult<()> {
        self.live.remove_directory(path)?;
        let normalized =
            normalize_entry_path(path).expect("remove_directory normalized the path already");
        self.journal(PendingKind::Remove {
            path: normalized,
            kind: FsEntryKind::Directory,
        });
        Ok(())
    }

    fn rename(&mut self, from: &str, to: &str) -> DriverResult<()> {
        self.live.rename(from, to)?;
        let from = normalize_entry_path(from).expect("rename normalized the source already");
        let to = normalize_entry_path(to).expect("rename normalized the destination already");
        let kind = self.live.metadata(&to)?.kind;

        // Carry durable data along the rename so a plain rename does not tear
        // its unmodified bytes, while the durable baseline still holds the old
        // name for the rolled-back case. Symlinks carry no content.
        match kind {
            FsEntryKind::Directory => {
                let prefix = format!("{from}/");
                let moved: Vec<String> = self
                    .staged_content
                    .keys()
                    .filter(|key| key.starts_with(&prefix))
                    .cloned()
                    .collect();
                for key in moved {
                    let bytes = self.staged_content.remove(&key).expect("key was listed");
                    self.staged_content
                        .insert(format!("{to}{}", &key[from.len()..]), bytes);
                }
            }
            FsEntryKind::File => {
                if let Some(bytes) = self
                    .staged_content
                    .remove(&from)
                    .or_else(|| self.durable.files.get(&from).cloned())
                {
                    self.staged_content.insert(to.clone(), bytes);
                }
            }
            FsEntryKind::Symlink => {}
        }

        let prefix = format!("{from}/");
        for path in self.open_paths.values_mut() {
            if *path == from {
                path.clone_from(&to);
            } else if path.starts_with(&prefix) {
                *path = format!("{to}{}", &path[from.len()..]);
            }
        }

        self.journal(PendingKind::Rename { from, to, kind });
        Ok(())
    }

    fn set_times(
        &mut self,
        fd: Fd,
        atime_nanos: Option<u64>,
        mtime_nanos: Option<u64>,
    ) -> DriverResult<()> {
        self.live.set_times(fd, atime_nanos, mtime_nanos)
    }

    fn set_times_by_path(
        &mut self,
        path: &str,
        atime_nanos: Option<u64>,
        mtime_nanos: Option<u64>,
    ) -> DriverResult<()> {
        self.live.set_times_by_path(path, atime_nanos, mtime_nanos)
    }

    fn link(&mut self, from: &str, to: &str) -> DriverResult<()> {
        self.live.link(from, to)?;
        // The new name is a fresh namespace entry; its kind follows the source
        // (a hard link to a file, or a copied symlink per MemFs semantics).
        let to_norm = normalize_entry_path(to).expect("link normalized the destination already");
        let kind = self
            .live
            .metadata(to)
            .map(|metadata| metadata.kind)
            .unwrap_or(FsEntryKind::File);
        self.journal(PendingKind::Create {
            path: to_norm,
            kind,
        });
        Ok(())
    }

    fn symlink(&mut self, target: &str, link_path: &str) -> DriverResult<()> {
        self.live.symlink(target, link_path)?;
        let normalized =
            normalize_entry_path(link_path).expect("symlink normalized the path already");
        self.journal(PendingKind::Create {
            path: normalized,
            kind: FsEntryKind::Symlink,
        });
        Ok(())
    }

    fn read_link(&mut self, path: &str) -> DriverResult<String> {
        self.live.read_link(path)
    }

    fn crash(&mut self) -> DriverResult<()> {
        let crashes = self.crashes.checked_add(1).ok_or_else(|| {
            EffectError::new(
                ErrorCode::InvalidState,
                "filesystem crash counter exhausted",
            )
        })?;
        self.recompute_after_crash()?;
        self.crashes = crashes;
        Ok(())
    }
}

fn byte_at(bytes: &[u8], index: usize) -> u8 {
    bytes.get(index).copied().unwrap_or(0)
}

/// Copy `source[start..end]` (zero-filled past its end) into `result[start..end]`.
fn copy_range(result: &mut [u8], source: &[u8], start: usize, end: usize) {
    for (offset, slot) in result[start..end].iter_mut().enumerate() {
        *slot = byte_at(source, start + offset);
    }
}

/// Select the survival set matching an entry kind, so files, directories, and
/// symlinks each apply their namespace decisions to the right table.
fn survival_set<'a>(
    kind: FsEntryKind,
    dirs: &'a mut BTreeSet<String>,
    files: &'a mut BTreeSet<String>,
    symlinks: &'a mut BTreeSet<String>,
) -> &'a mut BTreeSet<String> {
    match kind {
        FsEntryKind::Directory => dirs,
        FsEntryKind::File => files,
        FsEntryKind::Symlink => symlinks,
    }
}

/// Create every missing ancestor directory of `path` in `fs`, so a rebuilt
/// symlink or directory always has a parent to hang from.
fn ensure_parents(fs: &mut MemFs, path: &str) -> DriverResult<()> {
    let mut ancestors = Vec::new();
    let mut parent = parent_path(path);
    while parent != "/" {
        ancestors.push(parent.to_owned());
        parent = parent_path(parent);
    }
    for dir in ancestors.into_iter().rev() {
        if fs.metadata(&dir).is_err() {
            fs.create_directory(&dir)?;
        }
    }
    Ok(())
}

/// Move every entry rooted at `from` to be rooted at `to`.
fn rewrite_prefix(set: &mut BTreeSet<String>, from: &str, to: &str) {
    let prefix = format!("{from}/");
    let moved: Vec<String> = set
        .iter()
        .filter(|path| *path == from || path.starts_with(&prefix))
        .cloned()
        .collect();
    for path in moved {
        set.remove(&path);
        let rewritten = if path == from {
            to.to_owned()
        } else {
            format!("{to}{}", &path[from.len()..])
        };
        set.insert(rewritten);
    }
}

/// Snapshot a filesystem into a durable baseline: directories, file contents,
/// symlink targets, and per-entry timestamps. Every entry kind is captured so
/// none is silently lost across a crash.
fn enumerate(fs: &mut MemFs) -> Baseline {
    let mut baseline = Baseline::default();
    baseline.dirs.insert("/".to_owned());
    if let Ok(metadata) = fs.metadata("/") {
        baseline
            .times
            .insert("/".to_owned(), (metadata.atime_nanos, metadata.mtime_nanos));
    }
    let mut stack = vec!["/".to_owned()];
    while let Some(dir) = stack.pop() {
        let entries = fs.read_directory(&dir).unwrap_or_default();
        for entry in entries {
            let child = child_path(&dir, &entry.name);
            if let Ok(metadata) = fs.metadata(&child) {
                baseline
                    .times
                    .insert(child.clone(), (metadata.atime_nanos, metadata.mtime_nanos));
            }
            match entry.kind {
                FsEntryKind::Directory => {
                    baseline.dirs.insert(child.clone());
                    stack.push(child);
                }
                FsEntryKind::File => {
                    let content = fs.contents(&child).map(<[u8]>::to_vec).unwrap_or_default();
                    baseline.files.insert(child, content);
                }
                FsEntryKind::Symlink => {
                    let target = fs.read_link(&child).unwrap_or_default();
                    baseline.symlinks.insert(child, target);
                }
            }
        }
    }
    baseline
}

fn child_path(dir: &str, name: &str) -> String {
    if dir == "/" {
        format!("/{name}")
    } else {
        format!("{dir}/{name}")
    }
}

fn parent_path(path: &str) -> &str {
    let parent = path.rsplit_once('/').map_or("/", |(parent, _)| parent);
    if parent.is_empty() { "/" } else { parent }
}

fn normalize_path(path: &str) -> DriverResult<String> {
    if !path.starts_with('/') {
        return Err(EffectError::new(
            ErrorCode::InvalidInput,
            format!("virtual filesystem path must be absolute: {path:?}"),
        ));
    }
    if path.contains('\0') {
        return Err(EffectError::new(
            ErrorCode::InvalidInput,
            "virtual filesystem path contains NUL",
        ));
    }
    let mut components = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                return Err(EffectError::new(
                    ErrorCode::InvalidInput,
                    format!("parent traversal is not supported: {path:?}"),
                ));
            }
            value => components.push(value),
        }
    }
    if components.is_empty() {
        return Err(EffectError::new(
            ErrorCode::InvalidInput,
            "the virtual filesystem root is not a file",
        ));
    }
    Ok(format!("/{}", components.join("/")))
}

fn normalize_entry_path(path: &str) -> DriverResult<String> {
    if path == "/" || path.chars().all(|character| character == '/') {
        return Ok("/".into());
    }
    normalize_path(path)
}

#[cfg(test)]
mod tests {
    use patina_dst_abi::{ErrorCode, OpenFlags};

    use super::*;

    fn write_only() -> OpenFlags {
        OpenFlags {
            read: false,
            write: true,
            create: false,
            truncate: false,
            append: false,
            exclusive: false,
        }
    }

    fn write(fs: &mut CrashFs, path: &str, bytes: &[u8]) -> Fd {
        let fd = fs.open(path, OpenFlags::create_truncate_write()).unwrap();
        fs.write(fd, bytes).unwrap();
        fd
    }

    #[test]
    fn positional_write_is_crash_losable_exactly_like_a_cursor_write() {
        // A page-oriented database writes every page through pwrite (write_at),
        // so a positional write MUST be as crash-losable as a cursor write --
        // otherwise the crash campaign would silently miss its real durability
        // boundary. write_at rides the default seek/write/seek path, so CrashFs
        // journals it through the same live-vs-durable model. This is the
        // load-bearing guarantee for the whole positional-I/O rung.
        const OFFSET: u64 = 1024;

        // Unsynced positional write is dropped: after a durable zero baseline,
        // a pwrite that is never fsynced reverts on crash.
        let mut fs = CrashFs::default();
        let fd = fs.open("/db", OpenFlags::create_truncate_write()).unwrap();
        fs.set_len(fd, 4096).unwrap();
        fs.sync(fd).unwrap(); // durable baseline: 4096 zero bytes
        fs.write_at(fd, OFFSET, b"positional").unwrap();
        fs.crash().unwrap();
        let after = fs.contents("/db").unwrap();
        assert!(
            !after
                .windows(b"positional".len())
                .any(|w| w == b"positional"),
            "an unsynced positional write survived a crash"
        );

        // A positional write that IS fsynced survives byte-for-byte.
        let mut fs = CrashFs::default();
        let fd = fs.open("/db", OpenFlags::create_truncate_write()).unwrap();
        fs.set_len(fd, 4096).unwrap();
        fs.write_at(fd, OFFSET, b"positional").unwrap();
        fs.sync(fd).unwrap();
        fs.crash().unwrap();
        let after = fs.contents("/db").unwrap();
        let start = OFFSET as usize;
        assert_eq!(
            &after[start..start + b"positional".len()],
            b"positional",
            "a synced positional write did not survive a crash"
        );

        // A positional read reaches the written bytes WITHOUT disturbing the
        // shared cursor -- the property that makes positional I/O sound under
        // concurrency (no crash involved).
        let mut fs = CrashFs::default();
        let read_write = OpenFlags {
            read: true,
            write: true,
            create: true,
            truncate: true,
            append: false,
            exclusive: false,
        };
        let fd = fs.open("/db", read_write).unwrap();
        fs.set_len(fd, 4096).unwrap();
        fs.write_at(fd, OFFSET, b"positional").unwrap();
        fs.seek(fd, 0, SeekWhence::Start).unwrap();
        let positional = fs.read_at(fd, OFFSET, b"positional".len()).unwrap();
        assert_eq!(positional, b"positional");
        let cursor_pos = fs.seek(fd, 0, SeekWhence::Current).unwrap();
        assert_eq!(cursor_pos, 0, "read_at disturbed the shared cursor");
    }

    #[test]
    fn crash_discards_unsynchronized_data_and_open_handles() {
        let mut fs = CrashFs::default();
        let fd = write(&mut fs, "/volatile", b"lost");
        fs.crash().unwrap();
        assert_eq!(fs.crash_count(), 1);
        // The entry is durable metadata by default, but its unsynced bytes are
        // discarded, leaving an empty file.
        assert!(fs.contents("/volatile").unwrap().is_empty());
        assert_eq!(
            fs.write(fd, b"stale").unwrap_err().code,
            ErrorCode::InvalidHandle
        );
    }

    #[test]
    fn sync_persists_a_checkpoint_and_later_changes_are_lost() {
        let mut fs = CrashFs::default();
        let fd = write(&mut fs, "/state", b"stable");
        fs.sync(fd).unwrap();
        fs.write(fd, b"-volatile").unwrap();
        fs.crash().unwrap();
        assert_eq!(fs.contents("/state").unwrap(), b"stable");
    }

    #[test]
    fn a_mounted_image_is_durable_and_composes_with_crash_injection() {
        // This is the `native-run --mount` composition with `--fs-crash-at`: the
        // shim builds `CrashFs::new(FsImage::into_memfs())`, so a mounted corpus
        // is the durable baseline while unsynced guest writes still drop on a
        // crash exactly as with an empty filesystem. `CrashFs::new` here uses the
        // same default policy as `CrashFs::default()` (torn-write probability 1),
        // so the mount does not change crash behavior.
        let image = patina_dst_fs_mem::FsImage::new(vec![patina_dst_fs_mem::FsImageEntry::File {
            path: "/corpus/data.txt".into(),
            contents: b"mounted-and-durable".to_vec(),
        }]);
        let mounted = image.into_memfs().unwrap();
        let mut fs = CrashFs::new(mounted);

        // A new guest write without an fsync.
        let _volatile = write(&mut fs, "/scratch/out.txt", b"never-synced");
        fs.crash().unwrap();

        // The mounted (durable) content survives the crash byte-for-byte.
        assert_eq!(
            fs.contents("/corpus/data.txt").unwrap(),
            b"mounted-and-durable"
        );
        // The unsynced guest write is dropped, just as against an empty FS.
        assert!(fs.contents("/scratch/out.txt").unwrap().is_empty());
    }

    #[test]
    fn restart_keeps_synced_data_loses_unsynced_and_reopens_cleanly() {
        let mut fs = CrashFs::default();
        let durable = write(&mut fs, "/keep", b"durable");
        fs.sync(durable).unwrap();
        let volatile = write(&mut fs, "/lose", b"volatile");
        fs.crash().unwrap();

        // Handles from before the crash are stale after restart.
        assert_eq!(
            fs.read(durable, 4).unwrap_err().code,
            ErrorCode::InvalidHandle
        );
        assert_eq!(
            fs.write(volatile, b"x").unwrap_err().code,
            ErrorCode::InvalidHandle
        );

        assert_eq!(fs.contents("/keep").unwrap(), b"durable");
        assert!(fs.contents("/lose").unwrap().is_empty());

        // The restarted process can open durable state through fresh handles.
        let reopened = fs.open("/keep", OpenFlags::read_only()).unwrap();
        assert_eq!(fs.read(reopened, 16).unwrap(), b"durable");
    }

    fn torn_after_crash(seed: u64) -> Vec<u8> {
        let mut fs = CrashFs::builder()
            .seed(seed)
            .torn_write_granularity(2)
            .torn_write_probability(0.5)
            .build()
            .unwrap();
        let fd = write(&mut fs, "/f", b"AAAAAAAA");
        fs.close(fd).unwrap();
        fs.checkpoint();
        let fd = fs.open("/f", write_only()).unwrap();
        fs.write(fd, b"BBBBBBBB").unwrap();
        fs.crash().unwrap();
        fs.contents("/f").unwrap().to_vec()
    }

    #[test]
    fn torn_writes_are_deterministic_per_seed_and_vary_across_seeds() {
        // The same seed reproduces the same tear exactly.
        for seed in 0..8 {
            assert_eq!(torn_after_crash(seed), torn_after_crash(seed));
        }
        // Every result is a per-block mix of the durable and live bytes.
        for seed in 0..8 {
            let torn = torn_after_crash(seed);
            assert_eq!(torn.len(), 8);
            assert!(torn.chunks(2).all(|block| block == b"AA" || block == b"BB"));
        }
        // Some seeds tear differently from seed 0.
        let baseline = torn_after_crash(0);
        assert!(
            (0..64).any(|seed| torn_after_crash(seed) != baseline),
            "torn writes never varied across seeds"
        );
    }

    #[test]
    fn torn_write_probability_extremes_are_decision_free() {
        // Probability 0 keeps every modified block; probability 1 reverts them.
        let mut kept = CrashFs::builder()
            .torn_write_probability(0.0)
            .torn_write_granularity(2)
            .build()
            .unwrap();
        let fd = write(&mut kept, "/f", b"AAAA");
        kept.close(fd).unwrap();
        kept.checkpoint();
        let fd = kept.open("/f", write_only()).unwrap();
        kept.write(fd, b"BBBB").unwrap();
        kept.crash().unwrap();
        assert_eq!(kept.contents("/f").unwrap(), b"BBBB");

        let mut reverted = CrashFs::builder()
            .torn_write_probability(1.0)
            .torn_write_granularity(2)
            .build()
            .unwrap();
        let fd = write(&mut reverted, "/f", b"AAAA");
        reverted.close(fd).unwrap();
        reverted.checkpoint();
        let fd = reverted.open("/f", write_only()).unwrap();
        reverted.write(fd, b"BBBB").unwrap();
        reverted.crash().unwrap();
        assert_eq!(reverted.contents("/f").unwrap(), b"AAAA");
    }

    fn byte_torn_final_write(seed: u64) -> Vec<u8> {
        // Durable "AAAA...", then a single unsynced overwrite with "BBBB..."
        // that a byte-granularity crash may tear part-way through.
        let mut fs = CrashFs::builder()
            .seed(seed)
            .torn_granularity(TornGranularity::Byte)
            .build()
            .unwrap();
        let fd = write(&mut fs, "/f", b"AAAAAAAA");
        fs.close(fd).unwrap();
        fs.checkpoint();
        let fd = fs.open("/f", write_only()).unwrap();
        fs.write(fd, b"BBBBBBBB").unwrap();
        fs.crash().unwrap();
        fs.contents("/f").unwrap().to_vec()
    }

    #[test]
    fn byte_granularity_tears_the_final_write_into_a_partial_image() {
        // The load-bearing property for the sub-block crash campaign: the final
        // unsynced write survives PARTIALLY, so the reconstructed image differs
        // from BOTH the durable baseline and the fully-applied write -- the torn
        // page a whole-block model can never produce.
        for seed in 0..32 {
            let torn = byte_torn_final_write(seed);
            assert_eq!(torn.len(), 8);
            assert_ne!(
                torn, b"AAAAAAAA",
                "seed {seed} reverted wholesale (durable)"
            );
            assert_ne!(torn, b"BBBBBBBB", "seed {seed} applied wholesale (live)");
            // The surviving prefix is live bytes, the reverted suffix is durable.
            let cut = torn.iter().take_while(|&&byte| byte == b'B').count();
            assert!(
                (1..8).contains(&cut),
                "seed {seed} cut {cut} is not a strict interior split: {torn:?}"
            );
            assert!(
                torn[cut..].iter().all(|&byte| byte == b'A'),
                "seed {seed} suffix is not the durable image: {torn:?}"
            );
        }
    }

    #[test]
    fn byte_torn_final_write_is_deterministic_per_seed_and_varies() {
        for seed in 0..8 {
            assert_eq!(byte_torn_final_write(seed), byte_torn_final_write(seed));
        }
        let baseline = byte_torn_final_write(0);
        assert!(
            (0..64).any(|seed| byte_torn_final_write(seed) != baseline),
            "byte-granularity tear geometry never varied across seeds"
        );
    }

    #[test]
    fn block_granularity_leaves_the_final_write_whole() {
        // The default whole-block policy is unchanged: with certain tearing the
        // single unsynced overwrite reverts entirely to the durable image, never
        // a partial mix. This is the behavior every pre-existing trace relies on.
        for seed in 0..32 {
            let mut fs = CrashFs::builder()
                .seed(seed)
                .torn_granularity(TornGranularity::Block)
                .build()
                .unwrap();
            let fd = write(&mut fs, "/f", b"AAAAAAAA");
            fs.close(fd).unwrap();
            fs.checkpoint();
            let fd = fs.open("/f", write_only()).unwrap();
            fs.write(fd, b"BBBBBBBB").unwrap();
            fs.crash().unwrap();
            assert_eq!(
                fs.contents("/f").unwrap(),
                b"AAAAAAAA",
                "whole-block tear produced a non-durable image at seed {seed}"
            );
        }
    }

    #[test]
    fn byte_granularity_tears_only_the_final_write_not_earlier_ones() {
        // An earlier unsynced write to a different page reverts wholesale, while
        // the final write's page tears partially -- the "clean prefix plus one
        // torn final page" geometry the sub-block crash hunt needs.
        let mut fs = CrashFs::builder()
            .seed(11)
            .torn_write_granularity(4)
            .torn_granularity(TornGranularity::Byte)
            .build()
            .unwrap();
        // Durable baseline: two 4-byte pages of zeros.
        let fd = fs.open("/db", OpenFlags::create_truncate_write()).unwrap();
        fs.set_len(fd, 8).unwrap();
        fs.sync(fd).unwrap();
        // First (earlier) write to page 0, then the final write to page 1.
        fs.write_at(fd, 0, b"XXXX").unwrap();
        fs.write_at(fd, 4, b"YYYY").unwrap();
        fs.crash().unwrap();
        let after = fs.contents("/db").unwrap();
        assert_eq!(after.len(), 8);
        // Page 0 (the earlier write) reverted wholesale to durable zeros.
        assert_eq!(
            &after[0..4],
            &[0, 0, 0, 0],
            "earlier write did not revert wholesale"
        );
        // Page 1 (the final write) tore partially: at least one live 'Y' survived
        // and at least one durable zero remains.
        assert!(
            after[4..8].contains(&b'Y'),
            "final write left no surviving prefix: {after:?}"
        );
        assert!(
            after[4..8].contains(&0),
            "final write applied wholesale instead of tearing: {after:?}"
        );
    }

    fn rename_outcome(atomic: bool, seed: u64) -> (bool, bool) {
        let mut fs = CrashFs::builder()
            .seed(seed)
            .model_rename_atomicity(atomic)
            .model_directory_durability(true)
            .directory_loss_probability(0.5)
            .build()
            .unwrap();
        let fd = write(&mut fs, "/a", b"data");
        fs.close(fd).unwrap();
        fs.checkpoint();
        fs.rename("/a", "/b").unwrap();
        fs.crash().unwrap();
        let from = fs.metadata("/a").is_ok();
        let to = fs.metadata("/b").is_ok();
        (from, to)
    }

    #[test]
    fn atomic_rename_is_all_or_nothing_across_a_crash() {
        for seed in 0..64 {
            let (from, to) = rename_outcome(true, seed);
            assert!(
                from != to,
                "atomic rename left both or neither name at seed {seed}: from={from} to={to}"
            );
        }
    }

    #[test]
    fn non_atomic_rename_can_duplicate_or_lose_the_entry() {
        // The two-step rename can leave a state atomic rename never produces:
        // both names present (duplicate) or neither (lost).
        let observed_non_atomic = (0..64)
            .any(|seed| matches!(rename_outcome(false, seed), (true, true) | (false, false)));
        assert!(
            observed_non_atomic,
            "non-atomic rename never exposed a torn intermediate state"
        );
    }

    #[test]
    fn directory_entry_loss_requires_a_directory_fsync() {
        let mut base = MemFs::new();
        base.create_directory("/d").unwrap();

        // Without a directory fsync the created entry can be lost on crash.
        let mut fs = CrashFs::builder()
            .filesystem(base.clone())
            .model_directory_durability(true)
            .directory_loss_probability(1.0)
            .build()
            .unwrap();
        let fd = write(&mut fs, "/d/f", b"x");
        fs.sync(fd).unwrap();
        fs.close(fd).unwrap();
        fs.crash().unwrap();
        assert_eq!(fs.metadata("/d").unwrap().kind, FsEntryKind::Directory);
        assert_eq!(fs.metadata("/d/f").unwrap_err().code, ErrorCode::NotFound);

        // Fsyncing the parent directory commits the entry so it survives.
        let mut fs = CrashFs::builder()
            .filesystem(base)
            .model_directory_durability(true)
            .directory_loss_probability(1.0)
            .build()
            .unwrap();
        let fd = write(&mut fs, "/d/f", b"x");
        fs.sync(fd).unwrap();
        fs.close(fd).unwrap();
        fs.sync_directory("/d").unwrap();
        fs.crash().unwrap();
        assert_eq!(fs.contents("/d/f").unwrap(), b"x");
    }

    #[test]
    fn sync_directory_rejects_non_directories() {
        let mut fs = CrashFs::default();
        let fd = write(&mut fs, "/file", b"x");
        fs.close(fd).unwrap();
        assert_eq!(
            fs.sync_directory("/file").unwrap_err().code,
            ErrorCode::NotDirectory
        );
        assert_eq!(
            fs.sync_directory("/missing").unwrap_err().code,
            ErrorCode::NotFound
        );
    }

    #[test]
    fn builder_rejects_invalid_configuration() {
        assert_eq!(
            CrashFs::builder()
                .torn_write_granularity(0)
                .build()
                .unwrap_err()
                .code,
            ErrorCode::InvalidInput
        );
        assert_eq!(
            CrashFs::builder()
                .torn_write_probability(1.5)
                .build()
                .unwrap_err()
                .code,
            ErrorCode::InvalidInput
        );
        assert_eq!(
            CrashFs::builder()
                .directory_loss_probability(-0.1)
                .build()
                .unwrap_err()
                .code,
            ErrorCode::InvalidInput
        );
        assert!(
            CrashFs::builder()
                .torn_write_probability(f64::NAN)
                .build()
                .is_err()
        );
    }

    #[test]
    fn checkpoint_persists_namespace_operations() {
        let mut fs = CrashFs::default();
        let fd = write(&mut fs, "/before", b"value");
        fs.close(fd).unwrap();
        fs.checkpoint();
        // A committed rename after the checkpoint survives; unsynced content
        // written afterwards does not.
        fs.rename("/before", "/after").unwrap();
        fs.checkpoint();
        fs.crash().unwrap();
        assert_eq!(fs.contents("/after").unwrap(), b"value");
        assert_eq!(
            fs.metadata("/before").unwrap_err().code,
            ErrorCode::NotFound
        );
    }

    // --- Finding 2: symlinks are modeled, not silently dropped on crash. ---

    #[test]
    fn symlink_and_read_link_work_through_crashfs_before_and_after_crash() {
        let mut base = MemFs::new();
        base.create_directory("/d").unwrap();
        let mut fs = CrashFs::builder().filesystem(base).build().unwrap();
        fs.symlink("/target", "/d/link").unwrap();
        assert_eq!(fs.read_link("/d/link").unwrap(), "/target");
        assert_eq!(fs.metadata("/d/link").unwrap().kind, FsEntryKind::Symlink);

        // Default model keeps namespace entries durable, so the symlink and its
        // verbatim target survive the crash rather than being silently dropped.
        fs.crash().unwrap();
        assert_eq!(fs.read_link("/d/link").unwrap(), "/target");
        assert_eq!(fs.metadata("/d/link").unwrap().kind, FsEntryKind::Symlink);
    }

    #[test]
    fn seed_image_symlink_survives_crash() {
        let mut base = MemFs::new();
        base.symlink("/etc/target", "/link").unwrap();
        let mut fs = CrashFs::new(base);
        assert_eq!(fs.read_link("/link").unwrap(), "/etc/target");
        fs.crash().unwrap();
        assert_eq!(fs.read_link("/link").unwrap(), "/etc/target");
    }

    fn symlink_after_crash(sync_dir: bool, probability: f64, seed: u64) -> Option<String> {
        let mut base = MemFs::new();
        base.create_directory("/d").unwrap();
        let mut fs = CrashFs::builder()
            .filesystem(base)
            .seed(seed)
            .model_directory_durability(true)
            .directory_loss_probability(probability)
            .build()
            .unwrap();
        fs.symlink("/target", "/d/link").unwrap();
        if sync_dir {
            fs.sync_directory("/d").unwrap();
        }
        fs.crash().unwrap();
        fs.read_link("/d/link").ok()
    }

    #[test]
    fn symlink_survives_crash_when_parent_directory_is_fsynced() {
        // Even with certain loss configured, an fsynced directory commits the
        // symlink so it survives.
        assert_eq!(
            symlink_after_crash(true, 1.0, 7),
            Some("/target".to_owned())
        );
    }

    #[test]
    fn symlink_is_lost_without_directory_fsync() {
        // Without the directory fsync and certain loss, the symlink is dropped
        // by the seeded policy (deterministically), not silently.
        assert_eq!(symlink_after_crash(false, 1.0, 7), None);
    }

    #[test]
    fn symlink_loss_is_deterministic_per_seed_and_varies() {
        for seed in 0..8 {
            assert_eq!(
                symlink_after_crash(false, 0.5, seed),
                symlink_after_crash(false, 0.5, seed)
            );
        }
        let outcomes: Vec<bool> = (0..32)
            .map(|seed| symlink_after_crash(false, 0.5, seed).is_some())
            .collect();
        assert!(
            outcomes.iter().any(|kept| *kept) && outcomes.iter().any(|kept| !*kept),
            "seeded symlink loss never varied across seeds"
        );
    }

    // --- Finding 8: rename durability is governed by both parent directories. ---

    fn rename_two_sided(
        atomic: bool,
        sync_dest: bool,
        sync_source: bool,
        seed: u64,
    ) -> (bool, bool) {
        let mut base = MemFs::new();
        base.create_directory("/src").unwrap();
        base.create_directory("/dst").unwrap();
        let mut fs = CrashFs::builder()
            .filesystem(base)
            .seed(seed)
            .model_rename_atomicity(atomic)
            .model_directory_durability(true)
            .directory_loss_probability(0.5)
            .build()
            .unwrap();
        let fd = write(&mut fs, "/src/a", b"data");
        fs.close(fd).unwrap();
        fs.checkpoint();
        fs.rename("/src/a", "/dst/b").unwrap();
        if sync_dest {
            fs.sync_directory("/dst").unwrap();
        }
        if sync_source {
            fs.sync_directory("/src").unwrap();
        }
        fs.crash().unwrap();
        (fs.metadata("/src/a").is_ok(), fs.metadata("/dst/b").is_ok())
    }

    #[test]
    fn non_atomic_rename_only_dest_fsync_leaves_unlink_side_losable() {
        // Fsyncing only the destination parent makes the new link durable, but
        // the source unlink is still subject to loss, so the old name can
        // survive (duplicated) for some seeds. The new name is always present.
        let mut saw_duplicate = false;
        for seed in 0..64 {
            let (from, to) = rename_two_sided(false, true, false, seed);
            assert!(to, "destination link should be durable at seed {seed}");
            saw_duplicate |= from;
        }
        assert!(
            saw_duplicate,
            "only-destination fsync never left the unlink side losable"
        );
    }

    #[test]
    fn non_atomic_rename_only_source_fsync_leaves_link_side_losable() {
        // Fsyncing only the source parent makes the unlink durable, but the new
        // link is still subject to loss, so the destination can be missing
        // (data lost) for some seeds. The old name is always gone.
        let mut saw_lost = false;
        for seed in 0..64 {
            let (from, to) = rename_two_sided(false, false, true, seed);
            assert!(!from, "source unlink should be durable at seed {seed}");
            saw_lost |= !to;
        }
        assert!(
            saw_lost,
            "only-source fsync never left the link side losable"
        );
    }

    #[test]
    fn rename_with_both_parents_fsynced_is_fully_durable() {
        for atomic in [true, false] {
            for seed in 0..64 {
                assert_eq!(
                    rename_two_sided(atomic, true, true, seed),
                    (false, true),
                    "both-parent fsync should fully commit the rename (atomic={atomic})"
                );
            }
        }
    }

    #[test]
    fn atomic_rename_stays_all_or_nothing_under_partial_dir_sync() {
        // Atomic rename is never torn: partial directory sync leaves it subject
        // to a single all-or-nothing decision, never both or neither name.
        for (sync_dest, sync_source) in [(true, false), (false, true), (false, false)] {
            for seed in 0..64 {
                let (from, to) = rename_two_sided(true, sync_dest, sync_source, seed);
                assert!(
                    from != to,
                    "atomic rename produced a torn state at seed {seed}: from={from} to={to}"
                );
            }
        }
    }

    #[test]
    fn hard_link_names_and_durable_timestamps_survive_crash() {
        let mut fs = CrashFs::default();
        let fd = write(&mut fs, "/a", b"data");
        fs.close(fd).unwrap();
        fs.link("/a", "/b").unwrap();
        assert_eq!(fs.contents("/b").unwrap(), b"data");
        fs.set_times_by_path("/a", Some(111), Some(222)).unwrap();
        fs.checkpoint();
        fs.crash().unwrap();

        // Both names keep their content and durable timestamps across the crash.
        assert_eq!(fs.contents("/a").unwrap(), b"data");
        assert_eq!(fs.contents("/b").unwrap(), b"data");
        let metadata = fs.metadata("/a").unwrap();
        assert_eq!((metadata.atime_nanos, metadata.mtime_nanos), (111, 222));
    }
}
