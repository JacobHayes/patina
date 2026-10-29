//! Deterministic storage-crash semantics for the in-memory filesystem,
//! modelled on ext4 (`data=ordered`, delayed allocation, `auto_da_alloc`,
//! `commit=5`).
//!
//! `CrashFs` keeps a live working image (the page cache and in-memory
//! metadata) and the last COMMITTED journal transaction. Ordinary effects
//! mutate the live image and join the running transaction. A machine crash
//! rolls the namespace and every inode's metadata back to the last commit,
//! atomically: a crash never exposes a subset or a reordering of metadata
//! changes, so a rename is always all-or-nothing.
//!
//! ## Commit points
//!
//! The running transaction commits, carrying every metadata change on the
//! volume since the previous commit, when:
//!
//! - an `fsync` names an inode with a change in it (a new inode, its link,
//!   size, extents, times, mode or attributes, or a directory an entry was
//!   added to or removed from). `fdatasync` reaches this driver as the same
//!   call, so it commits under the same rule;
//! - `sync` or `syncfs` runs;
//! - five virtual seconds have passed since the transaction's first change
//!   (jbd2's `commit=5`), observed at the next filesystem operation or at the
//!   crash itself.
//!
//! A directory needs no fsync of its own for an entry to survive: the commit
//! an `fsync` of the new file forces carries its directory entry, and so does
//! the next periodic commit. A crash before either loses it.
//!
//! ## Data
//!
//! - **Delayed allocation.** Written bytes reach the disk only at writeback:
//!   an `fsync`, `sync`/`syncfs`, or `auto_da_alloc` (below). Writeback
//!   advances the size the next commit records (`i_disksize`) to the bytes
//!   it wrote, so a file a crash keeps is the prefix the last commit before
//!   it recorded, and a fresh file nothing wrote back yet comes back empty.
//!   An append within the block the recorded size ends in allocates nothing,
//!   so its size is recorded at once and its bytes there can read as zeros.
//! - **`data=ordered`.** Blocks a committed transaction allocated were
//!   written before its commit record, so committed data is never stale.
//! - **In-place overwrites tear.** An unsynced overwrite of a block the last
//!   commit already had written survives per block as either the old or the
//!   new bytes. The decision is drawn per block of `torn_write_granularity`
//!   bytes (4096 by default; 512 for a 512e device) from a seeded
//!   [`SplitMix64`] stream with `torn_write_probability` the chance a block
//!   keeps its old bytes. A block truncated, punched or zeroed away since the
//!   commit was freed, so a write there is not in place: its old bytes come
//!   back whole.
//! - **`auto_da_alloc`.** A rename over an existing name writes the source
//!   file's delayed allocations back, and so does closing a file truncated to
//!   zero, so the commit that carries the rename or the truncation carries
//!   those bytes too; an in-place overwrite stays unsynced.
//! - **Writeback errors**: an `fsync`, `sync` or `syncfs` that failed writing
//!   dirty pages back ([`FsDriver::fail_writeback`],
//!   [`FsDriver::fail_writeback_all`]) leaves them clean but not on disk, so
//!   no later `fsync` or `sync` makes them durable, and a crash or a
//!   `DONTNEED` ([`FsDriver::drop_cache`]) reverts them; the error reaches each
//!   open file description once per check (see [`writeback`]). An `fsync`
//!   that reports one does not commit.
//!
//! Files, directories, symlinks, named pipes, socket nodes and whiteouts are
//! all carried through the committed image, so no kind is silently dropped. A
//! FIFO's NAME is metadata; the bytes in flight through one are process
//! state, so a crash drops them exactly as a real one does. Timestamps,
//! permission bits and extended attributes are inode metadata and roll back
//! with the rest. Hard-link groups — of any non-directory kind, a symlink's
//! included — come back as one inode each, so shared `nlink` identity
//! survives.
//!
//! - **Open descriptors survive an in-place crash.** [`FsDriver::crash`]
//!   rebuilds the image under a process that lives on, and never invalidates a
//!   descriptor it holds: an open file description is the process's own
//!   object. A name an open descriptor holds whose full parent chain
//!   survived is pinned back, with the bytes the commit recorded for its
//!   node (none, for a lost creation). A crash restart instead exports the
//!   image a fresh incarnation boots from ([`CrashFs::crash_and_snapshot`]);
//!   a process crash leaves the page cache, so that image is the live one.
//!
//! All decisions are a deterministic function of the configured seed, the
//! virtual clock and the exact operation sequence, so identical seeds
//! reproduce identical post-crash images and crash outcomes round-trip
//! through record/replay.
//!
//! `O_DIRECT` is not modelled: the in-memory image has no direct-I/O path.

use std::collections::{BTreeMap, BTreeSet};

use patina_dst_abi::{CrashKind, EffectError, ErrorCode, Fd, FsClock};
use patina_dst_driver_api::DriverResult;
#[cfg(doc)]
use patina_dst_driver_api::FsDriver;
use patina_dst_fs_mem::{FileData, FsSnapshot, MemFs};
use patina_dst_rng_seeded::SplitMix64;

mod baseline;
mod driver;
mod journal;
mod recovery;
mod torn;
mod writeback;

use baseline::{Baseline, enumerate};

/// How long a running transaction stays open before jbd2 commits it
/// (ext4's default `commit=5`), in virtual nanoseconds.
const COMMIT_INTERVAL_NANOS: u64 = 5_000_000_000;

/// Tuning for the seeded torn-write decisions.
#[derive(Clone, Debug)]
struct CrashPolicy {
    torn_write_granularity: usize,
    torn_write_probability: f64,
}

impl Default for CrashPolicy {
    fn default() -> Self {
        Self {
            torn_write_granularity: 4096,
            torn_write_probability: 1.0,
        }
    }
}

/// An ext4-like crash-consistency filesystem model.
///
/// Construct one with [`CrashFs::builder`] to tune the torn-write model, or
/// use [`CrashFs::default`], where every unsynced in-place overwrite keeps
/// its old bytes.
pub struct CrashFs {
    live: MemFs,
    /// The last committed transaction: the namespace, every inode's metadata,
    /// and each file's bytes up to the size the commit recorded.
    committed: Baseline,
    /// The committed image's file bytes, by inode.
    committed_data: BTreeMap<u64, FileData>,
    /// The bytes written back since the last commit, by inode, at the size
    /// the next commit records for it (`i_disksize`).
    written: BTreeMap<u64, FileData>,
    /// The shortest length each inode was truncated to since the last commit:
    /// its blocks past that were freed, so no write lands on them in place.
    shrunk: BTreeMap<u64, u64>,
    /// The whole blocks of each inode punched or zeroed since the last
    /// commit: freed, so a write there since lands on a new block.
    freed: BTreeMap<u64, BTreeSet<u64>>,
    /// The inodes with a change in the running transaction.
    journaled: BTreeSet<u64>,
    /// When the running transaction took its first change, in virtual
    /// realtime nanoseconds; `None` while it is empty.
    opened: Option<u64>,
    /// The latest virtual realtime an operation carried: when a writeback
    /// with no clock of its own joins the running transaction.
    now: u64,
    /// Files truncated to zero whose close writes their data back
    /// (`auto_da_alloc`'s `EXT4_STATE_DA_ALLOC_CLOSE`), by inode.
    flush_on_close: BTreeSet<u64>,
    /// The descriptors open on a named file or directory (not an anonymous
    /// file): the ones whose writes are disk data.
    named: BTreeSet<Fd>,
    /// The 4096-byte pages of each named file written since its last
    /// writeback, by inode: `cachestat`'s dirty pages. Anonymous files are no
    /// part of the durable image and have none.
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

    /// Use `filesystem` as the initial, committed image.
    pub fn filesystem(mut self, filesystem: MemFs) -> Self {
        self.filesystem = filesystem;
        self
    }

    /// Seed the deterministic crash-decision policy.
    pub fn seed(mut self, seed: u64) -> Self {
        self.seed = seed;
        self
    }

    /// Set the torn-write block size in bytes (4096 by default; 512 models a
    /// 512e device). Must be at least one.
    pub fn torn_write_granularity(mut self, bytes: usize) -> Self {
        self.policy.torn_write_granularity = bytes;
        self
    }

    /// Probability in `[0, 1]` that a block overwritten in place since the
    /// last commit keeps its old bytes across a crash.
    pub fn torn_write_probability(mut self, probability: f64) -> Self {
        self.policy.torn_write_probability = probability;
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
            .field("journaled", &self.journaled.len())
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
        let committed = enumerate(&filesystem);
        Self {
            live: filesystem,
            committed_data: journal::data_by_inode(&committed),
            committed,
            written: BTreeMap::new(),
            shrunk: BTreeMap::new(),
            freed: BTreeMap::new(),
            journaled: BTreeSet::new(),
            opened: None,
            now: 0,
            flush_on_close: BTreeSet::new(),
            named: BTreeSet::new(),
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

    /// `sync(2)`: write every named file's dirty pages back (the pages a
    /// writeback error dropped stay as the disk has them: they are clean),
    /// then commit.
    pub fn checkpoint(&mut self) {
        for (path, metadata) in self.live.inventory() {
            if let Ok(current) = self.live.file_data(&path) {
                let current = current.clone();
                self.write_back(metadata.ino, &current);
            }
        }
        self.commit();
    }

    /// Export the image a fresh incarnation boots from after a crash of
    /// `kind` at `clock`. A process crash leaves the kernel's page cache in
    /// place, so the image is the live one, synced or not. A machine crash
    /// rolls back to the last commit first (one falls due at `clock` if the
    /// running transaction is old enough), so the image is what the disk
    /// held. Either way the image has no open descriptors: a fresh
    /// incarnation starts with a clean descriptor table, and a file only a
    /// descriptor held is gone.
    pub fn crash_and_snapshot(
        &mut self,
        clock: FsClock,
        kind: CrashKind,
    ) -> DriverResult<FsSnapshot> {
        if kind == CrashKind::Machine {
            let crashes = self.crashes.checked_add(1).ok_or_else(|| {
                EffectError::new(
                    ErrorCode::InvalidState,
                    "filesystem crash counter exhausted",
                )
            })?;
            // The process dies with the machine: no descriptor keeps a name.
            self.recompute_after_crash(clock, false)?;
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
