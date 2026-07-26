//! File-backed raft `Storage`.
//!
//! Reads are delegated to raft's own `MemStorage` (an `Arc<RwLock<..>>` with all
//! the subtle first-index / compaction / bounds behaviour already correct), and
//! every durable mutation is mirrored to three files under a per-node directory:
//!
//! ```text
//!   <dir>/hardstate.bin   whole-file prost HardState, replaced atomically
//!   <dir>/snapshot.bin    whole-file prost Snapshot,  replaced atomically
//!   <dir>/entries.log     length-prefixed prost Entry records (see wire.rs)
//! ```
//!
//! The log is rewritten in full from the authoritative in-memory entries on
//! every persist. That is O(n) but keeps the format dead simple and makes raft
//! log truncation (a conflicting suffix append) correct for free — exactly the
//! property the later crash-injection phase needs when it replays `entries.log`.
//! `load` reconstructs a `MemStorage` from these files, so a crash-restart under
//! Patina resumes from whatever bytes survived the injected fault.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use raft::prelude::{ConfState, Entry, HardState, Snapshot};
use raft::storage::MemStorage;
use raft::{GetEntriesContext, RaftState, Storage};

use crate::wire;

const HARD_STATE_FILE: &str = "hardstate.bin";
const SNAPSHOT_FILE: &str = "snapshot.bin";
const ENTRIES_FILE: &str = "entries.log";

/// A `Storage` whose durable state lives in files but whose reads run against an
/// in-memory `MemStorage` kept in lock-step with those files.
pub struct FileStorage {
    inner: MemStorage,
    dir: PathBuf,
}

impl FileStorage {
    /// Open a node's storage: reconstruct from existing files if any are
    /// present, otherwise create a fresh cluster member seeded with
    /// `conf_state` (the static 3-voter membership) and write its initial files.
    pub fn open(dir: impl AsRef<Path>, conf_state: ConfState) -> io::Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)?;
        let has_state = dir.join(HARD_STATE_FILE).exists() || dir.join(ENTRIES_FILE).exists();
        if has_state {
            Self::load(dir, conf_state)
        } else {
            Self::create_fresh(dir, conf_state)
        }
    }

    fn create_fresh(dir: PathBuf, conf_state: ConfState) -> io::Result<Self> {
        let inner = MemStorage::new_with_conf_state(conf_state);
        let storage = FileStorage { inner, dir };
        storage.persist_entries()?;
        storage.persist_hard_state()?;
        Ok(storage)
    }

    fn load(dir: PathBuf, default_conf: ConfState) -> io::Result<Self> {
        let inner = MemStorage::new();
        let snapshot_path = dir.join(SNAPSHOT_FILE);
        if snapshot_path.exists() {
            let snapshot = wire::decode_snapshot(&fs::read(&snapshot_path)?).map_err(decode_err)?;
            if !snapshot.is_empty() {
                inner.wl().apply_snapshot(snapshot).map_err(raft_err)?;
            } else {
                inner.initialize_with_conf_state(default_conf);
            }
        } else {
            // No snapshot survived: raft still needs to know the voter set to
            // count quorums, so seed it from the known static membership.
            inner.initialize_with_conf_state(default_conf);
        }

        let entries_path = dir.join(ENTRIES_FILE);
        if entries_path.exists() {
            let entries = wire::decode_entry_log(&fs::read(&entries_path)?).map_err(other_err)?;
            if !entries.is_empty() {
                inner.wl().append(&entries).map_err(raft_err)?;
            }
        }

        let hard_state_path = dir.join(HARD_STATE_FILE);
        if hard_state_path.exists() {
            let hard_state =
                wire::decode_hard_state(&fs::read(&hard_state_path)?).map_err(decode_err)?;
            inner.wl().set_hardstate(hard_state);
        }

        Ok(FileStorage { inner, dir })
    }

    /// Append entries to the log and rewrite `entries.log` from the resulting
    /// in-memory state (which handles any conflicting-suffix truncation).
    pub fn append(&mut self, entries: &[Entry]) -> io::Result<()> {
        self.inner.wl().append(entries).map_err(raft_err)?;
        self.persist_entries()
    }

    /// Replace the persisted `HardState`.
    pub fn set_hard_state(&mut self, hard_state: HardState) -> io::Result<()> {
        self.inner.wl().set_hardstate(hard_state);
        self.persist_hard_state()
    }

    /// Update only the committed index of the `HardState` (the `LightReady`
    /// commit advance) and re-persist it.
    pub fn set_commit(&mut self, commit: u64) -> io::Result<()> {
        self.inner.wl().mut_hard_state().set_commit(commit);
        self.persist_hard_state()
    }

    /// Install a snapshot: apply it to the in-memory store, then rewrite all
    /// three files since a snapshot moves the log offset and conf state.
    pub fn apply_snapshot(&mut self, snapshot: Snapshot) -> io::Result<()> {
        self.write_atomic(SNAPSHOT_FILE, &wire::encode(&snapshot))?;
        self.inner.wl().apply_snapshot(snapshot).map_err(raft_err)?;
        self.persist_entries()?;
        self.persist_hard_state()
    }

    fn persist_entries(&self) -> io::Result<()> {
        let first = self.inner.first_index().map_err(raft_err)?;
        let last = self.inner.last_index().map_err(raft_err)?;
        let entries = if last >= first {
            self.inner
                .entries(first, last + 1, None, GetEntriesContext::empty(false))
                .map_err(raft_err)?
        } else {
            Vec::new()
        };
        self.write_atomic(ENTRIES_FILE, &wire::encode_entry_log(&entries))
    }

    fn persist_hard_state(&self) -> io::Result<()> {
        let hard_state = self.inner.rl().hard_state().clone();
        self.write_atomic(HARD_STATE_FILE, &wire::encode(&hard_state))
    }

    /// Write `bytes` to `name` durably: stage a temp file, fsync it, rename it
    /// over the target, then fsync the directory. These explicit sync points are
    /// the fault boundaries the crash-injection phase will interpose on.
    fn write_atomic(&self, name: &str, bytes: &[u8]) -> io::Result<()> {
        let target = self.dir.join(name);
        let temp = self.dir.join(format!("{name}.tmp"));
        {
            let mut file = File::create(&temp)?;
            file.write_all(bytes)?;
            file.flush()?;
            file.sync_all()?;
        }
        fs::rename(&temp, &target)?;
        // Fsync the directory so the rename itself is durable. Not every
        // platform permits this; a failure here is non-fatal for the harness.
        if let Ok(dir) = File::open(&self.dir) {
            let _ = dir.sync_all();
        }
        Ok(())
    }
}

impl Storage for FileStorage {
    fn initial_state(&self) -> raft::Result<RaftState> {
        self.inner.initial_state()
    }

    fn entries(
        &self,
        low: u64,
        high: u64,
        max_size: impl Into<Option<u64>>,
        context: GetEntriesContext,
    ) -> raft::Result<Vec<Entry>> {
        self.inner.entries(low, high, max_size, context)
    }

    fn term(&self, idx: u64) -> raft::Result<u64> {
        self.inner.term(idx)
    }

    fn first_index(&self) -> raft::Result<u64> {
        self.inner.first_index()
    }

    fn last_index(&self) -> raft::Result<u64> {
        self.inner.last_index()
    }

    fn snapshot(&self, request_index: u64, to: u64) -> raft::Result<Snapshot> {
        self.inner.snapshot(request_index, to)
    }
}

fn raft_err(error: raft::Error) -> io::Error {
    io::Error::other(format!("raft storage error: {error}"))
}

fn decode_err(error: prost::DecodeError) -> io::Error {
    io::Error::other(format!("prost decode error: {error}"))
}

fn other_err(error: String) -> io::Error {
    io::Error::other(error)
}
