//! Deterministic storage-crash rollback semantics for the in-memory filesystem.
//!
//! `CrashFs` keeps a live working image and a durable baseline. Ordinary
//! effects mutate the live image. Durability is reached incrementally: a file
//! `sync` stages that file's fsynced content, syncing a directory fd commits the
//! namespace operations of that directory, and `checkpoint` makes the entire
//! live image durable. `crash` recomputes the post-crash image from the
//! durable baseline plus seeded torn-write and lost-entry decisions, while
//! preserving the running process's open handles. This is an in-process storage
//! rollback model, not a whole-process power cut or restart.
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
//! Files, directories, symlinks, and named pipes are all carried through the
//! durable baseline and recomputed on crash with the same namespace-durability
//! rules, so a symlink is never silently dropped. A FIFO's NAME is durable
//! namespace state; the bytes in flight through one are process state, so a
//! crash drops them exactly as a real one does. Per-entry timestamps captured at the
//! last durability point are restored on reconstruction. Hard-link groups are
//! reconstructed as one inode per surviving source inode, so shared `nlink`
//! identity survives crash recovery.
//!
//! - **Open descriptors survive.** A crash rebuilds the image, but it never
//!   invalidates a descriptor the guest is holding: an open file description is
//!   the process's own object, and no power loss reaches into a running process
//!   to close its files. The handle table moves onto the rebuilt image. Paths
//!   whose full parent chain survived keep resolving after the crash; lost
//!   parent directories are not implicitly resurrected.
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
use patina_dst_fs_mem::{FsSnapshot, MemFs};
use patina_dst_rng_seeded::SplitMix64;

/// The creation modes crash reconstruction rebuilds entries at before restoring
/// their recorded permission bits. Nothing is judged against them: every
/// surviving entry's real mode is written back from the live image or the
/// durable baseline immediately afterwards.
const RECONSTRUCTION_FILE_MODE: u32 = 0o666;
const RECONSTRUCTION_DIRECTORY_MODE: u32 = 0o777;

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
            model_directory_durability: true,
            directory_loss_probability: 1.0,
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

/// A file name captured in the durable baseline.
#[derive(Clone, Debug)]
struct BaselineFile {
    inode: u64,
    contents: Vec<u8>,
}

/// A durable filesystem baseline captured at a durability point: the directory
/// set, file contents, file inode identity, symlink targets, and per-entry
/// timestamps.
#[derive(Clone, Default)]
struct Baseline {
    dirs: BTreeSet<String>,
    files: BTreeMap<String, BaselineFile>,
    symlinks: BTreeMap<String, String>,
    /// Named pipes, by path, with their inode identity. A FIFO's NAME is
    /// durable namespace state like any other, and its INODE is what a second
    /// hard link names, so the two names come back as one node; the bytes in
    /// flight through it are process state, so nothing here holds them and a
    /// crash simply drops them, exactly as a real one does.
    fifos: BTreeMap<String, u64>,
    times: BTreeMap<String, (u64, u64)>,
    /// Permission bits, by path, for every entry that owns a mode (files,
    /// directories and FIFOs; a symlink leaf has none). A mode is durable
    /// metadata like a symlink's target — a crash reverts a lost entry, never a
    /// surviving entry's bits to a per-kind constant.
    modes: BTreeMap<String, u32>,
}

/// A configurable crash-consistency filesystem model.
///
/// Construct one with [`CrashFs::builder`] to select the torn-write,
/// rename-atomicity, and directory-durability models, or use
/// [`CrashFs::default`] for the conservative crash model where fsynced file
/// data survives, fsynced parent directories make namespace changes durable,
/// and unsynced data or namespace changes are lost.
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

    fn with_policy(filesystem: MemFs, policy: CrashPolicy, seed: u64) -> Self {
        let durable = enumerate(&filesystem);
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
        self.durable = enumerate(&self.live);
        self.staged_content.clear();
        self.pending.clear();
        self.last_write = None;
    }

    /// Apply this model's crash recovery and export the reconstructed durable
    /// image as a restart snapshot. The exported image has no open descriptors;
    /// a fresh incarnation starts with a clean descriptor table.
    pub fn crash_and_snapshot(&mut self) -> DriverResult<FsSnapshot> {
        self.crash()?;
        Ok(self.live.export_snapshot())
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
        let mut fifos: BTreeSet<String> = self.durable.fifos.keys().cloned().collect();

        for op in &pending {
            match &op.kind {
                PendingKind::Create { path, kind } => {
                    let survive = self.entry_survives(op.committed);
                    let set = survival_set(*kind, &mut dirs, &mut files, &mut symlinks, &mut fifos);
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
                    let set = survival_set(*kind, &mut dirs, &mut files, &mut symlinks, &mut fifos);
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
                            rewrite_prefix(&mut fifos, from, to);
                        }
                    } else {
                        // Non-atomic: the destination link and the source unlink
                        // are governed by their own directories and fail
                        // independently, so a crash can leave both names or
                        // neither. Draw the link side first, then the unlink
                        // side, for a stable decision order.
                        let link_new = self.entry_survives(op.committed);
                        let unlink_old = self.entry_survives(op.source_committed);
                        let set =
                            survival_set(*kind, &mut dirs, &mut files, &mut symlinks, &mut fifos);
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

        // A crash cannot invalidate a descriptor the guest is still holding.
        // An open file description is the PROCESS's object; power loss reaches
        // the disk, not the caller's descriptor table, so no real storage
        // failure turns a valid fd into `EBADF`. A name can only be pinned back
        // into the rebuilt namespace when its full parent chain survived; the
        // crash model must not silently resurrect lost directories to make a
        // child fit.
        let mut resurrected: BTreeSet<String> = BTreeSet::new();
        for (path, kind) in self.live.open_entries() {
            let fresh = survival_set(kind, &mut dirs, &mut files, &mut symlinks, &mut fifos)
                .insert(path.clone());
            if fresh && kind == FsEntryKind::File {
                resurrected.insert(path);
            }
        }
        prune_to_surviving_parents(&mut dirs, &mut files, &mut symlinks, &mut fifos);

        let mut durable_content_by_inode: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        for file in self.durable.files.values() {
            durable_content_by_inode
                .entry(file.inode)
                .or_insert_with(|| file.contents.clone());
        }
        let mut staged_content_by_inode: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        let staged_content: Vec<(String, Vec<u8>)> = self
            .staged_content
            .iter()
            .map(|(path, bytes)| (path.clone(), bytes.clone()))
            .collect();
        for (path, bytes) in staged_content {
            if let Some(inode) = self.file_source_inode(&path) {
                staged_content_by_inode.insert(inode, bytes);
            }
        }

        // The final unsynced write is eligible for a sub-block partial tear
        // under the byte-granularity policy; every other block still tears
        // wholesale. Captured before the merge loop borrows the rng.
        let last_write = self.last_write.clone();
        let final_write = match self.policy.torn_granularity {
            TornGranularity::Byte => last_write.as_ref().and_then(|(path, offset, len)| {
                self.file_source_inode(path)
                    .map(|inode| (inode, *offset, offset.saturating_add(*len)))
            }),
            TornGranularity::Block => None,
        };
        let mut file_contents_by_inode: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        let mut file_paths_by_inode: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();
        for path in &files {
            let source_inode = self.file_source_inode(path).ok_or_else(|| {
                EffectError::new(
                    ErrorCode::InvalidState,
                    format!("surviving file has no source inode: {path}"),
                )
            })?;
            let baseline = staged_content_by_inode
                .get(&source_inode)
                .or_else(|| durable_content_by_inode.get(&source_inode))
                .cloned()
                .unwrap_or_default();
            let partial_region = match final_write {
                Some((inode, start, end)) if inode == source_inode => Some((start, end)),
                _ => None,
            };
            let content = if resurrected.contains(path) {
                // Only open-descriptor pinning put this name back: the crash
                // decided its creation did not survive, so nothing it ever held
                // is durable. The name exists for the descriptor's sake; the
                // contents are the durable baseline (empty for a lost create).
                baseline
            } else {
                match self.live.contents(path) {
                    Ok(current) => {
                        let current = current.to_vec();
                        self.torn_merge(&baseline, &current, partial_region)
                    }
                    Err(_) => baseline,
                }
            };
            file_contents_by_inode
                .entry(source_inode)
                .or_insert(content);
            file_paths_by_inode
                .entry(source_inode)
                .or_default()
                .insert(path.clone());
        }
        let mut symlink_targets: BTreeMap<String, String> = BTreeMap::new();
        for path in &symlinks {
            // A symlink's target is metadata, not torn data: keep the live
            // target if still present, else the durable baseline target.
            let target = self
                .live
                .symlink_target(path)
                .map(str::to_owned)
                .or_else(|| self.durable.symlinks.get(path).cloned())
                .unwrap_or_default();
            symlink_targets.insert(path.clone(), target);
        }

        let mut next = MemFs::new();
        for dir in &dirs {
            if dir != "/" && next.metadata(dir).is_err() {
                next.create_directory(dir, RECONSTRUCTION_DIRECTORY_MODE)?;
            }
        }
        for (source_inode, paths) in &file_paths_by_inode {
            let first = paths.iter().next().expect("file group is non-empty");
            let bytes = file_contents_by_inode
                .get(source_inode)
                .expect("file group has content")
                .clone();
            next = next.with_file(first, bytes)?;
            for path in paths.iter().skip(1) {
                next.link(first, path)?;
            }
        }
        for (path, target) in &symlink_targets {
            next.symlink(target, path)?;
        }
        // A FIFO's name is what survives; its buffered bytes never were durable.
        // Names that share an inode are ONE node — a hard link to a FIFO is the
        // same pipe — so they are grouped exactly as a file's links are.
        let mut fifo_paths_by_inode: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();
        for path in &fifos {
            let source_inode = self.fifo_source_inode(path).ok_or_else(|| {
                EffectError::new(
                    ErrorCode::InvalidState,
                    format!("surviving fifo has no source inode: {path}"),
                )
            })?;
            fifo_paths_by_inode
                .entry(source_inode)
                .or_default()
                .insert(path.clone());
        }
        for paths in fifo_paths_by_inode.values() {
            let first = paths.iter().next().expect("fifo group is non-empty");
            next.make_fifo(first, RECONSTRUCTION_FILE_MODE)?;
            for path in paths.iter().skip(1) {
                next.link(first, path)?;
            }
        }
        // Restore durable timestamps for the surviving baseline entries so
        // crash reconstruction does not silently reset metadata to zero.
        for (path, (atime, mtime)) in &self.durable.times {
            if next.metadata(path).is_ok() {
                next.set_times_by_path(path, Some(*atime), Some(*mtime))?;
            }
        }
        // Permission bits last, and deepest name first. A mode is metadata like
        // a symlink's target — the live value if the entry is still there, else
        // the durable baseline — and rebuilding at a per-kind constant would
        // silently revert a `chmod`, or a `0o400` creation mode, that a real
        // crash has no way to undo. Restrictive modes are written from the
        // leaves up so a directory clamped to `0o500` cannot lock the walk out
        // of the names beneath it.
        let mut restored_modes: BTreeMap<String, u32> = BTreeMap::new();
        for path in next.paths_with_modes() {
            let mode = self
                .live
                .entry_metadata(&path)
                .ok()
                .map(|metadata| metadata.mode)
                .or_else(|| self.durable.modes.get(&path).copied());
            if let Some(mode) = mode {
                restored_modes.insert(path, mode);
            }
        }
        for (path, mode) in restored_modes.iter().rev() {
            next.set_mode(path, *mode)?;
        }

        self.durable = enumerate(&next);
        // Descriptors survive the crash (see the pinning comment above), so the
        // handle table and the descriptor-to-path map both move across: a `sync`
        // on an fd opened before the crash must still be attributed to its file.
        next.adopt_handles(&self.live);
        self.live = next;
        self.staged_content.clear();
        self.pending.clear();
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

    /// The inode a surviving FIFO name belongs to: the live one if the entry is
    /// still there, else the durable baseline's. The mirror of
    /// [`CrashFs::file_source_inode`], and for the same reason — two names of
    /// one node must come back as one node.
    fn fifo_source_inode(&mut self, path: &str) -> Option<u64> {
        self.live
            .entry_metadata(path)
            .ok()
            .filter(|metadata| metadata.kind == FsEntryKind::Fifo)
            .map(|metadata| metadata.ino)
            .or_else(|| self.durable.fifos.get(path).copied())
    }

    fn file_source_inode(&mut self, path: &str) -> Option<u64> {
        self.live
            .entry_metadata(path)
            .ok()
            .filter(|metadata| metadata.kind == FsEntryKind::File)
            .map(|metadata| metadata.ino)
            .or_else(|| self.durable.files.get(path).map(|file| file.inode))
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
        let normalized = normalize_entry_path(path).expect("open normalized the path already");
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
        let written = self.live.write(fd, bytes)?;
        // Capture the actual byte range after the filesystem has applied open
        // mode semantics. In particular, O_APPEND chooses EOF at write time, so
        // the pre-write cursor can be stale after intervening writes or crash
        // reconstruction.
        if let (Ok(end), Some(path)) = (
            self.live.seek(fd, 0, SeekWhence::Current),
            self.open_paths.get(&fd).cloned(),
        ) {
            if let Some(start) = usize::try_from(end)
                .ok()
                .and_then(|end| end.checked_sub(written))
            {
                self.last_write = Some((path, start, written));
            }
        }
        Ok(written)
    }

    fn write_at(&mut self, fd: Fd, offset: u64, bytes: &[u8]) -> DriverResult<usize> {
        let written = self.live.write_at(fd, offset, bytes)?;
        if let (Ok(offset), Some(path)) =
            (usize::try_from(offset), self.open_paths.get(&fd).cloned())
        {
            self.last_write = Some((path, offset, written));
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

    /// Reading an inode's live metadata touches no crash state: it is the same
    /// query `fd_metadata` is, addressed by node instead of by descriptor.
    fn inode_metadata(&mut self, ino: u64) -> DriverResult<FsMetadata> {
        self.live.inode_metadata(ino)
    }

    /// A mode is durable metadata wherever it is named from; the crash model
    /// reads it back off the live image at reconstruction, exactly as it does
    /// for the path- and descriptor-named spellings.
    fn set_inode_mode(&mut self, ino: u64, mode: u32) -> DriverResult<()> {
        self.live.set_inode_mode(ino, mode)
    }

    /// An inode reference is a descriptor's hold on a node, and a descriptor is
    /// the process's object: no crash state is touched by taking or dropping
    /// one. The rebuilt image carries the reference across a restart with the
    /// descriptor itself (see `MemFs::adopt_handles`).
    fn retain_inode(&mut self, ino: u64) -> DriverResult<()> {
        self.live.retain_inode(ino)
    }

    fn release_inode(&mut self, ino: u64) -> DriverResult<()> {
        self.live.release_inode(ino)
    }

    fn create_directory(&mut self, path: &str, mode: u32) -> DriverResult<()> {
        self.live.create_directory(path, mode)?;
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
            match self.live.metadata(&path)?.kind {
                FsEntryKind::File => {
                    if let Ok(bytes) = self.live.contents(&path) {
                        self.staged_content.insert(path, bytes.to_vec());
                    }
                }
                FsEntryKind::Directory => self.sync_directory(&path)?,
                // Neither a symlink's target nor a FIFO's buffer is file data
                // this model stages: there is nothing to make durable.
                FsEntryKind::Symlink | FsEntryKind::Fifo => {}
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

    fn read_directory_fd(&mut self, fd: Fd) -> DriverResult<Vec<FsDirectoryEntry>> {
        self.live.read_directory_fd(fd)
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
                if let Some(bytes) = self.staged_content.remove(&from).or_else(|| {
                    self.durable
                        .files
                        .get(&from)
                        .map(|file| file.contents.clone())
                }) {
                    self.staged_content.insert(to.clone(), bytes);
                }
            }
            FsEntryKind::Symlink | FsEntryKind::Fifo => {}
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

    /// A FIFO creation is a NAME appearing, exactly like a symlink's: the
    /// namespace-durability journal holds it, and a crash before the parent
    /// directory is fsynced can lose it.
    fn make_fifo(&mut self, path: &str, mode: u32) -> DriverResult<()> {
        self.live.make_fifo(path, mode)?;
        let normalized = normalize_entry_path(path).expect("make_fifo normalized the path already");
        self.journal(PendingKind::Create {
            path: normalized,
            kind: FsEntryKind::Fifo,
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

    /// A mode change is metadata on an existing entry, like `set_times`: the
    /// live image takes it and no name appears or disappears, so there is
    /// nothing for the namespace-durability journal to hold.
    fn set_mode(&mut self, path: &str, mode: u32) -> DriverResult<()> {
        self.live.set_mode(path, mode)
    }

    fn set_fd_mode(&mut self, fd: Fd, mode: u32) -> DriverResult<()> {
        self.live.set_fd_mode(fd, mode)
    }

    fn fd_path(&mut self, fd: Fd) -> DriverResult<String> {
        self.live.fd_path(fd)
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

    fn crash_and_export_restart_snapshot(&mut self) -> DriverResult<Vec<u8>> {
        Ok(self.crash_and_snapshot()?.encode()?)
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

/// Select the survival set matching an entry kind, so files, directories,
/// symlinks, and named pipes each apply their namespace decisions to the right
/// table.
fn survival_set<'a>(
    kind: FsEntryKind,
    dirs: &'a mut BTreeSet<String>,
    files: &'a mut BTreeSet<String>,
    symlinks: &'a mut BTreeSet<String>,
    fifos: &'a mut BTreeSet<String>,
) -> &'a mut BTreeSet<String> {
    match kind {
        FsEntryKind::Directory => dirs,
        FsEntryKind::File => files,
        FsEntryKind::Symlink => symlinks,
        FsEntryKind::Fifo => fifos,
    }
}

/// Remove entries whose parent directories did not survive the crash. A child
/// name is not independently meaningful without its full parent chain, and
/// reconstruction must not create implicit ancestor directories just to make a
/// selected child fit.
fn prune_to_surviving_parents(
    dirs: &mut BTreeSet<String>,
    files: &mut BTreeSet<String>,
    symlinks: &mut BTreeSet<String>,
    fifos: &mut BTreeSet<String>,
) {
    let selected_dirs = dirs.clone();
    dirs.retain(|path| path == "/" || full_parent_chain_survives(path, &selected_dirs));
    files.retain(|path| full_parent_chain_survives(path, dirs));
    symlinks.retain(|path| full_parent_chain_survives(path, dirs));
    fifos.retain(|path| full_parent_chain_survives(path, dirs));
}

fn full_parent_chain_survives(path: &str, dirs: &BTreeSet<String>) -> bool {
    let mut parent = parent_path(path);
    while parent != "/" {
        if !dirs.contains(parent) {
            return false;
        }
        parent = parent_path(parent);
    }
    dirs.contains("/")
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
/// symlink targets, permission bits, and per-entry timestamps. Every entry kind
/// is captured so none is silently lost across a crash.
///
/// The image is read through [`MemFs::inventory`], the storage layer's own
/// unenforced view. A crash journal is not a process: it must see a `0o000`
/// directory's children, or a mode change would quietly delete data on the next
/// crash.
fn enumerate(fs: &MemFs) -> Baseline {
    let mut baseline = Baseline::default();
    baseline.dirs.insert("/".to_owned());
    for (path, metadata) in fs.inventory() {
        baseline
            .times
            .insert(path.clone(), (metadata.atime_nanos, metadata.mtime_nanos));
        // A symlink leaf has no mode of its own; every other kind does.
        if metadata.kind != FsEntryKind::Symlink {
            baseline.modes.insert(path.clone(), metadata.mode);
        }
        match metadata.kind {
            FsEntryKind::Directory => {
                baseline.dirs.insert(path);
            }
            FsEntryKind::File => {
                let contents = fs.contents(&path).map(<[u8]>::to_vec).unwrap_or_default();
                baseline.files.insert(
                    path,
                    BaselineFile {
                        inode: metadata.ino,
                        contents,
                    },
                );
            }
            FsEntryKind::Symlink => {
                let target = fs.symlink_target(&path).unwrap_or_default().to_owned();
                baseline.symlinks.insert(path, target);
            }
            FsEntryKind::Fifo => {
                baseline.fifos.insert(path, metadata.ino);
            }
        }
    }
    baseline
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
            path_only: false,
            mode: patina_dst_abi::CREATE_MODE_UNUSED,
        }
    }

    fn append_write() -> OpenFlags {
        OpenFlags {
            append: true,
            ..write_only()
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
        // boundary. CrashFs overrides write_at so an append-mode descriptor
        // cannot redirect the explicit offset; the write is still journaled
        // through the same live-vs-durable model. This is the
        // load-bearing guarantee for the whole positional-I/O rung.
        const OFFSET: u64 = 1024;

        // Unsynced positional write is dropped: after a durable zero baseline,
        // a pwrite that is never fsynced reverts on crash.
        let mut fs = CrashFs::default();
        let fd = fs.open("/db", OpenFlags::create_truncate_write()).unwrap();
        fs.set_len(fd, 4096).unwrap();
        fs.sync(fd).unwrap(); // durable baseline: 4096 zero bytes
        fs.sync_directory("/").unwrap(); // durable namespace entry
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
        fs.sync_directory("/").unwrap();
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
            path_only: false,
            mode: patina_dst_abi::DEFAULT_FILE_CREATE_MODE,
        };
        let fd = fs.open("/db", read_write).unwrap();
        fs.set_len(fd, 4096).unwrap();
        fs.write_at(fd, OFFSET, b"positional").unwrap();
        fs.seek(fd, 0, SeekWhence::Start).unwrap();
        let positional = fs.read_at(fd, OFFSET, b"positional".len()).unwrap();
        assert_eq!(positional, b"positional");
        let cursor_pos = fs.seek(fd, 0, SeekWhence::Current).unwrap();
        assert_eq!(cursor_pos, 0, "read_at disturbed the shared cursor");

        fs.seek(fd, 1, SeekWhence::Start).unwrap();
        fs.write_at(fd, OFFSET + 32, b"X").unwrap();
        fs.write(fd, b"Y").unwrap();
        let after = fs.contents("/db").unwrap();
        assert_eq!(after[1], b'Y', "write_at moved the shared cursor");
        assert_eq!(after[OFFSET as usize + 32], b'X');
    }

    #[test]
    fn crash_discards_unsynchronized_data_but_not_open_handles() {
        let mut fs = CrashFs::default();
        let fd = write(&mut fs, "/volatile", b"lost");
        // Fsync the parent directory to make only the namespace entry durable;
        // the unsynced bytes are still discarded, leaving an empty file.
        fs.sync_directory("/").unwrap();
        fs.crash().unwrap();
        assert_eq!(fs.crash_count(), 1);
        assert!(fs.contents("/volatile").unwrap().is_empty());
        // The DATA is gone; the descriptor is not. A write through it lands on
        // the rebuilt file rather than reporting the guest's own fd invalid.
        // The cursor is process state and survives with the fd, so the write
        // lands where the guest left off (past the rolled-back bytes).
        fs.seek(fd, 0, SeekWhence::Start).unwrap();
        assert_eq!(fs.write(fd, b"stale").unwrap(), 5);
        assert_eq!(fs.contents("/volatile").unwrap(), b"stale");
    }

    #[test]
    fn append_handle_survives_crash_and_appends_at_rebuilt_eof() {
        let initial = MemFs::new().with_file("/log", b"stable").unwrap();
        let mut fs = CrashFs::new(initial);
        let fd = fs.open("/log", append_write()).unwrap();

        fs.write(fd, b"-volatile").unwrap();
        fs.crash().unwrap();
        assert_eq!(fs.contents("/log").unwrap(), b"stable");

        fs.write(fd, b"-after").unwrap();
        assert_eq!(fs.contents("/log").unwrap(), b"stable-after");
    }

    #[test]
    fn byte_torn_append_uses_actual_eof_region_after_intervening_writes() {
        let initial = MemFs::new().with_file("/log", b"stable").unwrap();
        let mut fs = CrashFs::builder()
            .filesystem(initial)
            .torn_granularity(TornGranularity::Byte)
            .torn_write_granularity(4096)
            .torn_write_probability(1.0)
            .build()
            .unwrap();
        let append = fs.open("/log", append_write()).unwrap();

        let regular = fs.open("/log", write_only()).unwrap();
        fs.seek(regular, 0, SeekWhence::End).unwrap();
        fs.write(regular, b"-intervening").unwrap();
        fs.sync(regular).unwrap();
        fs.close(regular).unwrap();

        fs.write(append, b"-tail").unwrap();
        fs.crash().unwrap();
        let after = fs.contents("/log").unwrap();
        let full = b"stable-intervening-tail";
        assert_eq!(after.len(), full.len());
        assert!(after.starts_with(b"stable-intervening-"));
        assert_ne!(after, full);
    }

    #[test]
    fn crash_and_snapshot_exports_recovered_image_without_handles() {
        let mut fs = CrashFs::default();
        let fd = fs
            .open("/state", OpenFlags::create_truncate_write())
            .unwrap();
        fs.write(fd, b"stable").unwrap();
        fs.sync(fd).unwrap();
        fs.sync_directory("/").unwrap();
        fs.write(fd, b"-volatile").unwrap();

        let snapshot = fs.crash_and_snapshot().unwrap();
        let encoded = snapshot.encode().unwrap();
        assert_eq!(
            FsSnapshot::decode(&encoded).unwrap().encode().unwrap(),
            encoded
        );
        let mut imported = snapshot.into_memfs();
        assert_eq!(imported.contents("/state").unwrap(), b"stable");
        assert_eq!(
            imported.read(fd, 1).unwrap_err().code,
            ErrorCode::InvalidHandle
        );
        assert_eq!(
            imported.open("/state", OpenFlags::read_only()).unwrap(),
            Fd(3)
        );
    }

    #[test]
    fn crash_and_snapshot_preserves_hard_link_inode_identity() {
        let mut base = MemFs::new().with_file("/a", b"stable").unwrap();
        base.link("/a", "/b").unwrap();
        let mut fs = CrashFs::new(base);
        let fd = fs.open("/a", write_only()).unwrap();
        fs.write(fd, b"volatile").unwrap();

        let snapshot = fs.crash_and_snapshot().unwrap();
        let mut imported = snapshot.into_memfs();
        let a = imported.metadata("/a").unwrap();
        let b = imported.metadata("/b").unwrap();
        assert_eq!(a.ino, b.ino);
        assert_eq!(a.nlink, 2);
        assert_eq!(b.nlink, 2);
        assert_eq!(imported.contents("/a").unwrap(), b"stable");
        assert_eq!(imported.contents("/b").unwrap(), b"stable");
    }

    #[test]
    fn crash_prunes_children_whose_parent_chain_was_lost() {
        let mut fs = CrashFs::builder()
            .model_directory_durability(true)
            .directory_loss_probability(1.0)
            .build()
            .unwrap();
        fs.create_directory("/parent", 0o777).unwrap();
        fs.create_directory("/parent/child", 0o777).unwrap();
        let fd = write(&mut fs, "/parent/child/file", b"data");
        fs.close(fd).unwrap();
        fs.symlink("file", "/parent/child/link").unwrap();
        fs.sync_directory("/parent").unwrap();
        fs.sync_directory("/parent/child").unwrap();

        fs.crash().unwrap();
        assert_eq!(
            fs.metadata("/parent").unwrap_err().code,
            ErrorCode::NotFound
        );
        assert_eq!(
            fs.metadata("/parent/child").unwrap_err().code,
            ErrorCode::NotFound
        );
        assert_eq!(
            fs.metadata("/parent/child/file").unwrap_err().code,
            ErrorCode::NotFound
        );
        assert_eq!(
            fs.metadata("/parent/child/link").unwrap_err().code,
            ErrorCode::NotFound
        );
    }

    #[test]
    fn sync_persists_a_checkpoint_and_later_changes_are_lost() {
        let mut fs = CrashFs::default();
        let fd = write(&mut fs, "/state", b"stable");
        fs.sync(fd).unwrap();
        fs.sync_directory("/").unwrap();
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

        // A new guest write without an fsync, with the descriptor closed before
        // the crash — an fd still open across a crash pins its name (see
        // `a_crash_lost_create_keeps_its_open_descriptor_and_loses_its_data`),
        // and this case is about the namespace, not the descriptor table.
        let volatile = write(&mut fs, "/scratch/out.txt", b"never-synced");
        fs.close(volatile).unwrap();
        fs.crash().unwrap();

        // The mounted (durable) content survives the crash byte-for-byte.
        assert_eq!(
            fs.contents("/corpus/data.txt").unwrap(),
            b"mounted-and-durable"
        );
        // The unsynced guest write's namespace entry was never made durable.
        assert_eq!(
            fs.metadata("/scratch/out.txt").unwrap_err().code,
            ErrorCode::NotFound
        );
    }

    #[test]
    fn a_crash_keeps_synced_data_loses_unsynced_and_leaves_handles_usable() {
        let mut fs = CrashFs::default();
        let durable = write(&mut fs, "/keep", b"durable");
        fs.sync(durable).unwrap();
        fs.sync_directory("/").unwrap();
        let volatile = write(&mut fs, "/lose", b"volatile");
        fs.sync_directory("/").unwrap();
        fs.crash().unwrap();

        assert_eq!(fs.contents("/keep").unwrap(), b"durable");
        assert!(fs.contents("/lose").unwrap().is_empty());

        // Handles from before the crash still name their files. A crash rolls
        // back bytes; it cannot invalidate the guest's descriptor table, and
        // reporting `InvalidHandle` here would surface as an impossible `EBADF`.
        fs.seek(durable, 0, SeekWhence::Start).unwrap();
        assert_eq!(fs.write(durable, b"D").unwrap(), 1);
        assert_eq!(fs.contents("/keep").unwrap(), b"Durable");
        fs.seek(volatile, 0, SeekWhence::Start).unwrap();
        assert_eq!(fs.write(volatile, b"x").unwrap(), 1);
        assert_eq!(fs.contents("/lose").unwrap(), b"x");

        // A fresh open gets its own descriptor number and sees the live bytes.
        let reopened = fs.open("/keep", OpenFlags::read_only()).unwrap();
        assert_ne!(reopened, durable);
        assert_eq!(fs.read(reopened, 16).unwrap(), b"Durable");
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
        fs.sync_directory("/").unwrap();
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
    fn directory_fd_sync_commits_namespace_operations() {
        let mut base = MemFs::new();
        base.create_directory("/d", 0o777).unwrap();
        let mut fs = CrashFs::builder()
            .filesystem(base)
            .model_directory_durability(true)
            .directory_loss_probability(1.0)
            .build()
            .unwrap();
        let fd = write(&mut fs, "/d/f", b"x");
        fs.sync(fd).unwrap();
        fs.close(fd).unwrap();
        let dir = fs.open("/d", OpenFlags::read_only()).unwrap();
        assert_eq!(fs.fd_metadata(dir).unwrap().kind, FsEntryKind::Directory);
        fs.sync(dir).unwrap();
        fs.close(dir).unwrap();
        fs.crash().unwrap();
        assert_eq!(fs.contents("/d/f").unwrap(), b"x");
    }

    #[test]
    fn directory_entry_loss_requires_a_directory_fsync() {
        let mut base = MemFs::new();
        base.create_directory("/d", 0o777).unwrap();

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
        base.create_directory("/d", 0o777).unwrap();
        let mut fs = CrashFs::builder().filesystem(base).build().unwrap();
        fs.symlink("/target", "/d/link").unwrap();
        assert_eq!(fs.read_link("/d/link").unwrap(), "/target");
        assert_eq!(fs.metadata("/d/link").unwrap().kind, FsEntryKind::Symlink);

        // Fsyncing the parent directory makes the symlink and its verbatim target
        // survive the crash rather than being silently dropped.
        fs.sync_directory("/d").unwrap();
        fs.crash().unwrap();
        assert_eq!(fs.read_link("/d/link").unwrap(), "/target");
        assert_eq!(fs.metadata("/d/link").unwrap().kind, FsEntryKind::Symlink);
    }

    // --- Named pipes: the NAME is durable namespace state, the bytes are not. ---

    #[test]
    fn fifo_name_and_mode_survive_a_crash_once_the_parent_is_fsynced() {
        let mut base = MemFs::new();
        base.create_directory("/d", 0o777).unwrap();
        let mut fs = CrashFs::builder().filesystem(base).build().unwrap();
        fs.make_fifo("/d/pipe", 0o666).unwrap();
        assert_eq!(fs.metadata("/d/pipe").unwrap().kind, FsEntryKind::Fifo);
        fs.set_mode("/d/pipe", 0o640).unwrap();

        // Fsyncing the parent commits the name; reconstruction must rebuild it
        // as a FIFO with the mode it had, not as a regular file.
        fs.sync_directory("/d").unwrap();
        fs.crash().unwrap();
        let metadata = fs.metadata("/d/pipe").unwrap();
        assert_eq!(metadata.kind, FsEntryKind::Fifo);
        assert_eq!(metadata.mode, 0o640);
        // And it is still listed as a FIFO by its parent.
        assert_eq!(
            fs.read_directory("/d").unwrap(),
            vec![patina_dst_abi::FsDirectoryEntry {
                name: "pipe".into(),
                kind: FsEntryKind::Fifo,
            }]
        );
    }

    /// A mode is durable metadata like a symlink's target. RED before crash
    /// reconstruction restored permission bits: the rebuilt image created every
    /// file at `0o644` and every directory at `0o755`, so a `chmod` — or a
    /// creation mode a real crash has no way to undo — silently reverted.
    #[test]
    fn modes_survive_a_crash_for_every_kind_that_owns_one() {
        let mut base = MemFs::new();
        base.create_directory("/d", 0o777).unwrap();
        let mut fs = CrashFs::builder().filesystem(base).build().unwrap();
        let fd = fs
            .open(
                "/d/file",
                OpenFlags {
                    path_only: false,
                    mode: 0o604,
                    ..OpenFlags::create_truncate_write()
                },
            )
            .unwrap();
        fs.write(fd, b"bytes").unwrap();
        fs.sync(fd).unwrap();
        fs.close(fd).unwrap();
        fs.create_directory("/d/sub", 0o700).unwrap();
        fs.make_fifo("/d/pipe", 0o660).unwrap();
        fs.sync_directory("/d").unwrap();
        fs.sync_directory("/d/sub").unwrap();

        fs.crash().unwrap();
        assert_eq!(fs.metadata("/d/file").unwrap().mode, 0o604);
        assert_eq!(fs.metadata("/d/sub").unwrap().mode, 0o700);
        assert_eq!(fs.metadata("/d/pipe").unwrap().mode, 0o640);
        assert_eq!(fs.metadata("/d").unwrap().mode, 0o755);
    }

    /// A directory clamped so tightly that the reconstruction walk could not
    /// see inside it still comes back with every child intact: permission bits
    /// are written from the leaves up, after the namespace is rebuilt.
    #[test]
    fn a_restrictive_directory_mode_survives_without_hiding_its_children() {
        let mut base = MemFs::new();
        base.create_directory("/d", 0o777).unwrap();
        let mut fs = CrashFs::builder().filesystem(base).build().unwrap();
        fs.create_directory("/d/vault", 0o777).unwrap();
        let fd = fs
            .open("/d/vault/secret", OpenFlags::create_truncate_write())
            .unwrap();
        fs.write(fd, b"inner").unwrap();
        fs.sync(fd).unwrap();
        fs.close(fd).unwrap();
        fs.sync_directory("/d").unwrap();
        fs.sync_directory("/d/vault").unwrap();
        fs.set_mode("/d/vault", 0o000).unwrap();

        fs.crash().unwrap();
        assert_eq!(fs.metadata("/d/vault").unwrap().mode, 0o000);
        // The child is there; only the mode keeps the guest out of it, which is
        // an `EACCES` and never a `NotFound`.
        assert_eq!(
            fs.metadata("/d/vault/secret").unwrap_err().code,
            ErrorCode::Denied
        );
        fs.set_mode("/d/vault", 0o755).unwrap();
        assert_eq!(fs.contents("/d/vault/secret").unwrap(), b"inner");
    }

    /// Two names for one FIFO are one node, and a crash must not split them
    /// into two pipes. The file path already grouped by inode; the FIFO path
    /// now does too.
    #[test]
    fn hard_linked_fifos_come_back_from_a_crash_as_one_node() {
        let mut base = MemFs::new();
        base.create_directory("/d", 0o777).unwrap();
        let mut fs = CrashFs::builder().filesystem(base).build().unwrap();
        fs.make_fifo("/d/pipe", 0o666).unwrap();
        fs.link("/d/pipe", "/d/alias").unwrap();
        fs.sync_directory("/d").unwrap();

        fs.crash().unwrap();
        let first = fs.metadata("/d/pipe").unwrap();
        let second = fs.metadata("/d/alias").unwrap();
        assert_eq!(first.kind, FsEntryKind::Fifo);
        assert_eq!(second.kind, FsEntryKind::Fifo);
        assert_eq!(first.ino, second.ino);
        assert_eq!(first.nlink, 2);
    }

    #[test]
    fn an_unsynced_fifo_creation_is_lost_like_any_other_name() {
        let mut base = MemFs::new();
        base.create_directory("/d", 0o777).unwrap();
        let mut fs = CrashFs::builder()
            .filesystem(base)
            .seed(7)
            .model_directory_durability(true)
            .directory_loss_probability(1.0)
            .build()
            .unwrap();
        fs.make_fifo("/d/pipe", 0o666).unwrap();
        fs.crash().unwrap();
        assert_eq!(
            fs.metadata("/d/pipe").unwrap_err().code,
            ErrorCode::NotFound,
            "an uncommitted FIFO creation is namespace state a crash can lose"
        );
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
        base.create_directory("/d", 0o777).unwrap();
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
        base.create_directory("/src", 0o777).unwrap();
        base.create_directory("/dst", 0o777).unwrap();
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

    /// A crash must never hand the guest `EBADF` for a descriptor it is still
    /// holding: real storage cannot invalidate a caller's fd, so a guest is
    /// right not to tolerate one, and a simulator that produces one is testing
    /// against an impossible world.
    #[test]
    fn descriptors_opened_before_a_crash_stay_usable_after_it() {
        let mut fs = CrashFs::default();
        let fd = write(&mut fs, "/a", b"durable");
        fs.sync(fd).unwrap();
        fs.checkpoint();
        // A second, unsynced write is what the crash rolls back.
        fs.write(fd, b"-lost").unwrap();
        fs.crash().unwrap();

        // Every operation on the pre-crash fd resolves; none reports
        // `InvalidHandle` (which the POSIX boundary renders as `EBADF`).
        fs.fd_metadata(fd).expect("fd_metadata after crash");
        fs.seek(fd, 0, SeekWhence::Start).expect("seek after crash");
        fs.sync(fd).expect("sync after crash");
        fs.close(fd).expect("close after crash");
    }

    /// A file whose creation did not survive still comes back as a NAME for the
    /// descriptor that is open on it — with its data rolled all the way back.
    #[test]
    fn a_crash_lost_create_keeps_its_open_descriptor_and_loses_its_data() {
        let mut fs = CrashFs::builder()
            .model_directory_durability(true)
            .directory_loss_probability(1.0)
            .build()
            .unwrap();
        let fd = write(&mut fs, "/fresh", b"never-durable");
        fs.crash().unwrap();

        assert_eq!(
            fs.contents("/fresh").unwrap(),
            b"",
            "a lost create keeps no data"
        );
        let metadata = fs.fd_metadata(fd).expect("the fd stays valid");
        assert_eq!(metadata.len, 0);
        // And it is still writable, so the guest recovers by rewriting.
        assert_eq!(fs.write(fd, b"again").unwrap(), 5);
    }

    /// A descriptor on an entry whose last NAME is gone crosses a crash like any
    /// other: a crash reaches the disk, not the process's descriptor table. The
    /// journal enumerates names and this node has none, so it is re-bound to a
    /// fresh anonymous node carrying what the descriptor last held — and never
    /// to a number the rebuilt image gave some unrelated entry.
    ///
    /// RED before inode lifetime: `remove_file` refused an open file outright,
    /// so this state was unreachable; with descriptions still keyed by path, the
    /// adopted description would have named an entry the rebuilt image does not
    /// have.
    #[test]
    fn a_descriptor_on_an_unlinked_entry_survives_a_crash_without_capturing_another_node() {
        // Directory durability off, so the unlink itself is not the variable
        // under test: this is about what a descriptor on a NAMELESS node means.
        let mut fs = CrashFs::builder()
            .model_directory_durability(false)
            .build()
            .unwrap();
        let kept = write(&mut fs, "/kept", b"durable");
        fs.sync(kept).unwrap();
        let doomed = write(&mut fs, "/doomed", b"anonymous");
        fs.sync(doomed).unwrap();
        fs.checkpoint();
        fs.remove_file("/doomed").unwrap();
        let anonymous_ino = fs.fd_metadata(doomed).unwrap().ino;
        let kept_ino = fs.fd_metadata(kept).unwrap().ino;
        assert_ne!(anonymous_ino, kept_ino);

        fs.crash().unwrap();

        // The named entry comes back at its name; the anonymous one comes back
        // only behind its descriptor, and the two are still different nodes.
        assert_eq!(fs.contents("/kept").unwrap(), b"durable");
        assert_eq!(
            fs.metadata("/doomed").unwrap_err().code,
            ErrorCode::NotFound,
            "an unlinked name is not resurrected by its descriptor"
        );
        let after = fs.fd_metadata(doomed).expect("the descriptor stays valid");
        assert_eq!(after.nlink, 0, "still no name");
        assert_ne!(
            after.ino,
            fs.fd_metadata(kept).unwrap().ino,
            "the anonymous descriptor must not capture another entry's node"
        );
        assert_eq!(after.len, 9, "and still holds what it last wrote");
        // The descriptor is write-only (it was minted by `File::create`), and it
        // still is: a crash cannot change what a descriptor was opened for.
        assert_eq!(fs.write(doomed, b"!").unwrap(), 1);
        assert_eq!(fs.fd_metadata(doomed).unwrap().len, 10);
    }

    /// A post-crash `open` must not reuse a descriptor number the guest still
    /// believes is live: aliasing two files onto one fd is a corruption the
    /// guest can neither see nor defend against.
    #[test]
    fn a_post_crash_open_never_reuses_a_live_descriptor_number() {
        let mut fs = CrashFs::default();
        let held = write(&mut fs, "/a", b"data");
        fs.sync(held).unwrap();
        fs.checkpoint();
        fs.crash().unwrap();

        let fresh = fs.open("/a", OpenFlags::create_truncate_write()).unwrap();
        assert_ne!(fresh, held);
    }
}
