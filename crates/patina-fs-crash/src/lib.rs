//! Deterministic storage-crash rollback semantics for the in-memory filesystem.
//!
//! `CrashFs` keeps a live working image and a durable baseline. Ordinary
//! effects mutate the live image. Durability is reached incrementally: a file
//! `sync` stages that file's fsynced content, syncing a directory fd commits the
//! namespace operations of that directory, and `checkpoint` makes the entire
//! live image durable. `crash` recomputes the post-crash image from the
//! durable baseline plus seeded torn-write and lost-entry decisions, while
//! preserving the running process's open handles. That is an in-process storage
//! rollback; a crash restart exports the image a fresh incarnation boots from
//! instead ([`CrashFs::crash_and_snapshot`]).
//!
//! ## Models
//!
//! - **Torn writes**: on crash, blocks modified since their last durability
//!   point may fail to persist and revert to the durable bytes. The tear
//!   decision is drawn per block of `torn_write_granularity` bytes from a
//!   seeded [`SplitMix64`] stream with `torn_write_probability`, and a block
//!   tears all-or-nothing: a torn block is either entirely the durable image or
//!   entirely the live one, as a disk that writes whole sectors leaves it. The
//!   decisions are independent, so any subset of the unsynced blocks can be
//!   what reached the disk.
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
//!   bug class. A lost change changes nothing: a lost unlink leaves the name
//!   holding the node it removed, so the name comes back only where the crash
//!   kept it (its durable entry, or a creation that survived), and a lost
//!   creation leaves whatever the name held before it. A temp file whose
//!   creation was lost too stays gone; a reused journal name whose unlink and
//!   re-creation were both lost holds the first journal.
//! - **Writeback errors**: an `fsync`, `sync` or `syncfs` that failed writing
//!   dirty pages back ([`FsDriver::fail_writeback`],
//!   [`FsDriver::fail_writeback_all`]) leaves them clean but not on disk, so
//!   no later `fsync` or `sync` makes them durable, and a crash or a
//!   `DONTNEED` ([`FsDriver::drop_cache`]) reverts them; the error reaches each
//!   open file description once per check (see [`writeback`]).
//!
//! Files, directories, symlinks, named pipes, socket nodes and whiteouts are all
//! carried through the durable baseline and recomputed on crash with the same
//! namespace-durability rules, so no kind is silently dropped. A FIFO's NAME is
//! durable namespace state; the bytes in flight through one are process state,
//! so a crash drops them exactly as a real one does. Timestamps are restored
//! from the last durability point (an fsync of the node, or the baseline).
//! Permission bits and extended attributes are taken to be durable the moment
//! they change, and belong to the node, not the name: a rebuilt name whose
//! node the live image still holds (through any name, or only a descriptor)
//! gets that node's live mode and attributes, and only a node the live image
//! no longer holds gets what was last recorded for it (its removal's record,
//! else the baseline's). Every name of one node therefore restores the same
//! metadata, and a name is matched to the baseline by node identity, never by
//! the name alone. Hard-link groups — of any
//! non-directory kind, a symlink's included — are reconstructed as one inode
//! per surviving source inode, so shared `nlink` identity survives crash
//! recovery.
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

use patina_dst_abi::{CrashKind, EffectError, ErrorCode, Fd};
use patina_dst_driver_api::DriverResult;
#[cfg(doc)]
use patina_dst_driver_api::FsDriver;
use patina_dst_fs_mem::{FileData, FsSnapshot, MemFs};
use patina_dst_rng_seeded::SplitMix64;

mod baseline;
mod driver;
mod namespace;
mod recovery;
mod torn;
mod writeback;

use baseline::{Baseline, DurableTimes, enumerate};
use namespace::PendingOp;

/// Tuning for the seeded crash-consistency decision policies.
#[derive(Clone, Debug)]
struct CrashPolicy {
    torn_write_granularity: usize,
    torn_write_probability: f64,
    model_rename_atomicity: bool,
    model_directory_durability: bool,
    directory_loss_probability: f64,
}

impl Default for CrashPolicy {
    fn default() -> Self {
        Self {
            torn_write_granularity: 4096,
            torn_write_probability: 1.0,
            model_rename_atomicity: true,
            model_directory_durability: true,
            directory_loss_probability: 1.0,
        }
    }
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
    /// File content made durable by an explicit file `sync`, by inode: the
    /// bytes belong to the node, whatever later happens to any of its names.
    staged_content: BTreeMap<u64, FileData>,
    /// Fsynced timestamps belong to the inode, not any one hard-link name.
    staged_times: BTreeMap<u64, DurableTimes>,
    /// Namespace operations since the baseline, in observation order.
    pending: Vec<PendingOp>,
    /// Live descriptor-to-path map used to attribute `sync` calls.
    open_paths: BTreeMap<Fd, String>,
    /// The 4096-byte pages of each named file written since its last
    /// durability point, by inode: `cachestat`'s dirty pages. Anonymous
    /// files are no part of the durable image and have none.
    dirty: BTreeMap<u64, BTreeSet<u64>>,
    /// The 4096-byte pages of each named file a writeback error dropped, by
    /// inode: clean in the cache, but the disk never got them (see
    /// [`writeback`]).
    lost: BTreeMap<u64, BTreeSet<u64>>,
    /// The writeback errors recorded against each named file's mapping, by
    /// inode (see [`writeback`]).
    file_errors: BTreeMap<u64, writeback::ErrSeq>,
    /// The writeback errors recorded against the filesystem (`s_wb_err`).
    filesystem_errors: writeback::ErrSeq,
    /// What each open file description last saw of those, by description.
    samples: BTreeMap<u64, writeback::Samples>,
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

impl Default for CrashFs {
    fn default() -> Self {
        Self::new(MemFs::new())
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
            staged_times: BTreeMap::new(),
            pending: Vec::new(),
            open_paths: BTreeMap::new(),
            dirty: BTreeMap::new(),
            lost: BTreeMap::new(),
            file_errors: BTreeMap::new(),
            filesystem_errors: writeback::ErrSeq::default(),
            samples: BTreeMap::new(),
            policy,
            rng: SplitMix64::new(seed),
            crashes: 0,
        }
    }

    /// Make the entire live image durable as one deterministic checkpoint:
    /// every dirty page is written back, and the pages a writeback error
    /// dropped are not (they are clean).
    pub fn checkpoint(&mut self) {
        let durable: BTreeMap<u64, FileData> = self
            .lost
            .keys()
            .map(|ino| (*ino, self.durable_content(*ino)))
            .collect();
        self.durable = enumerate(&self.live);
        let mut files = std::mem::take(&mut self.durable.files);
        for file in files.values_mut() {
            if let Some(durable) = durable.get(&file.inode) {
                file.contents = self.written_back(file.inode, durable, &file.contents);
            }
        }
        self.durable.files = files;
        self.staged_content.clear();
        self.staged_times.clear();
        self.pending.clear();
        self.dirty.clear();
    }

    /// Export the image a fresh incarnation boots from after a crash of
    /// `kind`. A process crash leaves the kernel's page cache in place, so the
    /// image is the live one, synced or not. A machine crash applies this
    /// model's recovery first, so the image is what the disk held. Either way
    /// the image has no open descriptors: a fresh incarnation starts with a
    /// clean descriptor table, and a file only a descriptor held is gone.
    pub fn crash_and_snapshot(&mut self, kind: CrashKind) -> DriverResult<FsSnapshot> {
        if kind == CrashKind::Machine {
            let crashes = self.crashes.checked_add(1).ok_or_else(|| {
                EffectError::new(
                    ErrorCode::InvalidState,
                    "filesystem crash counter exhausted",
                )
            })?;
            // The process dies with the machine: no descriptor keeps a name.
            self.recompute_after_crash(false)?;
            self.crashes = crashes;
        }
        Ok(self.live.export_snapshot())
    }

    pub fn crash_count(&self) -> u64 {
        self.crashes
    }

    pub fn contents(&self, path: &str) -> DriverResult<Vec<u8>> {
        self.live.contents(path)
    }
}

#[cfg(test)]
mod tests;
