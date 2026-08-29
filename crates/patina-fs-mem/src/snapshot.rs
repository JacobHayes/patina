//! Restart snapshots for [`MemFs`].
//!
//! Unlike [`crate::FsImage`], which is an input-only mount/corpus format,
//! [`FsSnapshot`] captures a live deterministic filesystem image for a fresh
//! incarnation: namespace, file contents, hard-link identity, metadata, and the
//! inode allocator state. It deliberately excludes open descriptors and other
//! process-local state.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use patina_dst_abi::{EffectError, ErrorCode};

use crate::{EntryMetadata, Inode, InodeId, MODE_MASK, MemFs, normalize_entry_path, parent_path};

/// Magic prefix identifying an encoded [`FsSnapshot`] stream.
const MAGIC: &[u8; 8] = b"PATFSSNP";
/// Wire-format version. Bump on any incompatible layout change.
///
/// Version 4 makes a FIFO an inode-backed name like a regular file's: the fifo
/// section carries an inode id instead of a private metadata record, so a hard
/// link to a FIFO is a second name for the same node across a restart, and the
/// mode, timestamps and link count live where every other inode's do.
const VERSION: u32 = 4;

/// Deliberately conservative structural bounds for a restart handoff. The
/// decoder checks them before allocating from untrusted bytes, so corrupt
/// handoffs fail closed instead of exhausting memory.
const MAX_SNAPSHOT_BYTES: usize = 128 * 1024 * 1024;
const MAX_ENTRIES: u64 = 1_000_000;
const MAX_FIELD_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PATH_BYTES: u64 = 4096;

/// A canonical, versioned snapshot of a [`MemFs`] suitable for constructing a
/// fresh incarnation's filesystem.
#[derive(Clone)]
pub struct FsSnapshot {
    filesystem: MemFs,
}

impl fmt::Debug for FsSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FsSnapshot")
            .field("directories", &self.filesystem.directories.len())
            .field("files", &self.filesystem.files.len())
            .field("inodes", &self.filesystem.inodes.len())
            .field("symlinks", &self.filesystem.symlinks.len())
            .field("fifos", &self.filesystem.fifos.len())
            .field("next_inode", &self.filesystem.next_inode)
            .finish()
    }
}

impl FsSnapshot {
    pub(crate) fn from_memfs(filesystem: &MemFs) -> Self {
        let mut filesystem = filesystem.clone();
        filesystem.handles.clear();
        filesystem.descriptions.clear();
        filesystem.next_fd = 3;
        filesystem.next_description = 1;
        Self { filesystem }
    }

    /// Encode this snapshot into its canonical wire format.
    ///
    /// Encoding fails before allocating the output buffer if the in-memory image
    /// would exceed the snapshot handoff bounds. This keeps the encoder honest
    /// with the decoder: it cannot produce a byte stream Patina would reject for
    /// size or field-length limits.
    pub fn encode(&self) -> Result<Vec<u8>, FsSnapshotError> {
        let encoded_len = self.preflight_encode()?;
        let mut bytes = Vec::with_capacity(encoded_len);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        bytes.extend_from_slice(&self.filesystem.next_inode.to_le_bytes());
        bytes.extend_from_slice(&(self.filesystem.directories.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&(self.filesystem.inodes.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&(self.filesystem.files.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&(self.filesystem.symlinks.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&(self.filesystem.fifos.len() as u64).to_le_bytes());

        for (path, metadata) in &self.filesystem.directories {
            encode_path(&mut bytes, path);
            encode_metadata(&mut bytes, metadata);
        }
        for (inode_id, inode) in &self.filesystem.inodes {
            bytes.extend_from_slice(&inode_id.to_le_bytes());
            bytes.extend_from_slice(&(inode.links as u64).to_le_bytes());
            bytes.extend_from_slice(&inode.atime_nanos.to_le_bytes());
            bytes.extend_from_slice(&inode.mtime_nanos.to_le_bytes());
            bytes.extend_from_slice(&inode.mode.to_le_bytes());
            encode_field(&mut bytes, &inode.contents);
        }
        for (path, inode_id) in &self.filesystem.files {
            encode_path(&mut bytes, path);
            bytes.extend_from_slice(&inode_id.to_le_bytes());
        }
        for (path, target) in &self.filesystem.symlinks {
            encode_path(&mut bytes, path);
            encode_field(&mut bytes, target.as_bytes());
            let metadata = self
                .filesystem
                .symlink_metadata
                .get(path)
                .expect("symlink has metadata");
            encode_metadata(&mut bytes, metadata);
        }
        for (path, inode_id) in &self.filesystem.fifos {
            encode_path(&mut bytes, path);
            bytes.extend_from_slice(&inode_id.to_le_bytes());
        }
        debug_assert_eq!(bytes.len(), encoded_len);
        Ok(bytes)
    }

    fn preflight_encode(&self) -> Result<usize, FsSnapshotError> {
        validate_snapshot_state(
            self.filesystem.next_inode,
            &self.filesystem.directories,
            &self.filesystem.inodes,
            &self.filesystem.files,
            &self.filesystem.symlinks,
            &self.filesystem.symlink_metadata,
            &self.filesystem.fifos,
        )?;

        preflight_count(self.filesystem.directories.len(), "directory count")?;
        preflight_count(self.filesystem.inodes.len(), "inode count")?;
        preflight_count(self.filesystem.files.len(), "file count")?;
        preflight_count(self.filesystem.symlinks.len(), "symlink count")?;
        preflight_count(self.filesystem.fifos.len(), "fifo count")?;

        let mut total = MAGIC.len() + 4 + 8 + 8 + 8 + 8 + 8 + 8;
        for path in self.filesystem.directories.keys() {
            add_path_len(&mut total, path)?;
            add_len(&mut total, METADATA_BYTES)?;
        }
        for inode in self.filesystem.inodes.values() {
            add_len(&mut total, 8 + 8 + 8 + 8 + 4)?;
            add_field_len(&mut total, inode.contents.len(), "field length")?;
        }
        for path in self.filesystem.files.keys() {
            add_path_len(&mut total, path)?;
            add_len(&mut total, 8)?;
        }
        for (path, target) in &self.filesystem.symlinks {
            add_path_len(&mut total, path)?;
            add_field_len(&mut total, target.len(), "field length")?;
            add_len(&mut total, METADATA_BYTES)?;
        }
        for path in self.filesystem.fifos.keys() {
            add_path_len(&mut total, path)?;
            add_len(&mut total, 8)?;
        }
        Ok(total)
    }

    /// Decode a stream produced by [`FsSnapshot::encode`]. The decoder validates
    /// structure, ordering, identity, and bounds before constructing a fresh
    /// [`MemFs`] with no open descriptors.
    pub fn decode(bytes: &[u8]) -> Result<Self, FsSnapshotError> {
        if bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err(FsSnapshotError::LimitExceeded("snapshot byte length"));
        }
        let mut reader = Reader::new(bytes);
        if reader.take(MAGIC.len())? != MAGIC {
            return Err(FsSnapshotError::BadMagic);
        }
        let version = reader.take_u32()?;
        if version != VERSION {
            return Err(FsSnapshotError::UnsupportedVersion(version));
        }
        let next_inode = reader.take_u64()?;
        let directory_count = reader.take_count("directory count")?;
        let inode_count = reader.take_count("inode count")?;
        let file_count = reader.take_count("file count")?;
        let symlink_count = reader.take_count("symlink count")?;
        let fifo_count = reader.take_count("fifo count")?;

        let mut directories = BTreeMap::new();
        let mut previous_path = None;
        for _ in 0..directory_count {
            let path = reader.take_path(true)?;
            require_strict_path_order(previous_path.as_deref(), &path)?;
            previous_path = Some(path.clone());
            let metadata = reader.take_metadata()?;
            directories.insert(path, metadata);
        }

        let mut inodes = BTreeMap::new();
        let mut previous_inode = None;
        for _ in 0..inode_count {
            let inode_id = reader.take_u64()?;
            if inode_id == 0 || previous_inode.is_some_and(|previous| inode_id <= previous) {
                return Err(FsSnapshotError::Malformed(
                    "inodes are not strictly sorted by positive id",
                ));
            }
            previous_inode = Some(inode_id);
            let links = reader.take_u64()?;
            let links = u32::try_from(links)
                .map_err(|_| FsSnapshotError::Malformed("inode link count overflows u32"))?;
            if links == 0 {
                return Err(FsSnapshotError::Malformed("inode has zero links"));
            }
            let atime_nanos = reader.take_u64()?;
            let mtime_nanos = reader.take_u64()?;
            let mode = reader.take_mode()?;
            let contents = reader.take_field()?;
            inodes.insert(
                inode_id,
                Inode {
                    contents,
                    links,
                    atime_nanos,
                    mtime_nanos,
                    mode,
                },
            );
        }

        let mut files = BTreeMap::new();
        previous_path = None;
        for _ in 0..file_count {
            let path = reader.take_path(false)?;
            require_strict_path_order(previous_path.as_deref(), &path)?;
            previous_path = Some(path.clone());
            let inode_id = reader.take_u64()?;
            if !inodes.contains_key(&inode_id) {
                return Err(FsSnapshotError::Malformed(
                    "file references an unknown inode",
                ));
            }
            files.insert(path, inode_id);
        }

        let mut symlinks = BTreeMap::new();
        let mut symlink_metadata = BTreeMap::new();
        previous_path = None;
        for _ in 0..symlink_count {
            let path = reader.take_path(false)?;
            require_strict_path_order(previous_path.as_deref(), &path)?;
            previous_path = Some(path.clone());
            let target = reader.take_string("symlink target")?;
            if target.contains('\0') {
                return Err(FsSnapshotError::Malformed("symlink target contains NUL"));
            }
            let metadata = reader.take_metadata()?;
            symlinks.insert(path.clone(), target);
            symlink_metadata.insert(path, metadata);
        }

        let mut fifos = BTreeMap::new();
        previous_path = None;
        for _ in 0..fifo_count {
            let path = reader.take_path(false)?;
            require_strict_path_order(previous_path.as_deref(), &path)?;
            previous_path = Some(path.clone());
            let inode_id = reader.take_u64()?;
            if !inodes.contains_key(&inode_id) {
                return Err(FsSnapshotError::Malformed(
                    "fifo references an unknown inode",
                ));
            }
            fifos.insert(path, inode_id);
        }

        if !reader.is_empty() {
            return Err(FsSnapshotError::Malformed("trailing bytes after snapshot"));
        }

        validate_snapshot_state(
            next_inode,
            &directories,
            &inodes,
            &files,
            &symlinks,
            &symlink_metadata,
            &fifos,
        )?;

        Ok(Self {
            filesystem: MemFs {
                files,
                inodes,
                symlinks,
                symlink_metadata,
                fifos,
                directories,
                handles: BTreeMap::new(),
                descriptions: BTreeMap::new(),
                next_fd: 3,
                next_description: 1,
                next_inode,
            },
        })
    }

    /// Reconstruct the captured image as a fresh [`MemFs`] with no descriptors.
    pub fn into_memfs(&self) -> MemFs {
        self.filesystem.clone()
    }
}

fn validate_snapshot_state(
    next_inode: InodeId,
    directories: &BTreeMap<String, EntryMetadata>,
    inodes: &BTreeMap<InodeId, Inode>,
    files: &BTreeMap<String, InodeId>,
    symlinks: &BTreeMap<String, String>,
    symlink_metadata: &BTreeMap<String, EntryMetadata>,
    fifos: &BTreeMap<String, InodeId>,
) -> Result<(), FsSnapshotError> {
    if !directories.contains_key("/") {
        return Err(FsSnapshotError::Malformed("root directory is missing"));
    }

    let mut paths = BTreeSet::new();
    let mut metadata_ids = BTreeSet::new();
    let mut max_inode = 0;

    for (path, metadata) in directories {
        validate_entry_path(path, true)?;
        insert_unique_path(&mut paths, path)?;
        insert_unique_inode(&mut metadata_ids, metadata.ino)?;
        max_inode = max_inode.max(metadata.ino);
        if path != "/" {
            require_parent_directory(path, directories)?;
        }
    }
    for path in files.keys() {
        validate_entry_path(path, false)?;
        insert_unique_path(&mut paths, path)?;
        require_parent_directory(path, directories)?;
    }
    for inode_id in inodes.keys().copied() {
        insert_unique_inode(&mut metadata_ids, inode_id)?;
        max_inode = max_inode.max(inode_id);
    }
    for (path, target) in symlinks {
        validate_entry_path(path, false)?;
        insert_unique_path(&mut paths, path)?;
        require_parent_directory(path, directories)?;
        if target.contains('\0') {
            return Err(FsSnapshotError::Malformed("symlink target contains NUL"));
        }
        let metadata = symlink_metadata
            .get(path)
            .ok_or(FsSnapshotError::Malformed("symlink metadata is missing"))?;
        insert_unique_inode(&mut metadata_ids, metadata.ino)?;
        max_inode = max_inode.max(metadata.ino);
    }
    if symlink_metadata.len() != symlinks.len() {
        return Err(FsSnapshotError::Malformed("orphan symlink metadata entry"));
    }
    for path in fifos.keys() {
        validate_entry_path(path, false)?;
        insert_unique_path(&mut paths, path)?;
        require_parent_directory(path, directories)?;
    }
    // An inode is one KIND. A node named by both a file and a fifo would make
    // `metadata_for_path` answer two different kinds for one identity, so the
    // decoder refuses it rather than letting the name tables disagree.
    for inode_id in fifos.values() {
        if files.values().any(|file| file == inode_id) {
            return Err(FsSnapshotError::Malformed(
                "inode is named as both a file and a fifo",
            ));
        }
    }
    // A FIFO holds no filesystem bytes: its inode exists for identity, the link
    // count and the mode. Contents there would be state no reader can ever see.
    for inode_id in fifos.values() {
        if inodes
            .get(inode_id)
            .is_some_and(|inode| !inode.contents.is_empty())
        {
            return Err(FsSnapshotError::Malformed("fifo inode carries contents"));
        }
    }

    let mut actual_links: BTreeMap<InodeId, u32> = BTreeMap::new();
    for inode_id in files.values().chain(fifos.values()).copied() {
        *actual_links.entry(inode_id).or_default() += 1;
    }
    for (inode_id, inode) in inodes {
        let actual = actual_links.get(inode_id).copied().unwrap_or(0);
        if actual == 0 {
            return Err(FsSnapshotError::Malformed("inode has no file names"));
        }
        if actual != inode.links {
            return Err(FsSnapshotError::Malformed("inode link count mismatch"));
        }
    }
    if actual_links.len() != inodes.len() {
        return Err(FsSnapshotError::Malformed(
            "file references an unknown inode",
        ));
    }

    if next_inode == u64::MAX {
        return Err(FsSnapshotError::Malformed(
            "next inode allocator state is exhausted",
        ));
    }
    if next_inode == 0 || next_inode <= max_inode {
        return Err(FsSnapshotError::Malformed(
            "next inode allocator state does not advance past existing metadata",
        ));
    }

    Ok(())
}

fn require_parent_directory(
    path: &str,
    directories: &BTreeMap<String, EntryMetadata>,
) -> Result<(), FsSnapshotError> {
    let parent = parent_path(path);
    if directories.contains_key(parent) {
        Ok(())
    } else {
        Err(FsSnapshotError::Malformed(
            "entry parent directory is missing",
        ))
    }
}

fn insert_unique_path(paths: &mut BTreeSet<String>, path: &str) -> Result<(), FsSnapshotError> {
    if paths.insert(path.to_owned()) {
        Ok(())
    } else {
        Err(FsSnapshotError::Malformed(
            "path appears in more than one section",
        ))
    }
}

fn insert_unique_inode(ids: &mut BTreeSet<InodeId>, id: InodeId) -> Result<(), FsSnapshotError> {
    if id == 0 {
        return Err(FsSnapshotError::Malformed("metadata inode id is zero"));
    }
    if ids.insert(id) {
        Ok(())
    } else {
        Err(FsSnapshotError::Malformed(
            "metadata inode id is duplicated",
        ))
    }
}

fn require_strict_path_order(previous: Option<&str>, path: &str) -> Result<(), FsSnapshotError> {
    if previous.is_some_and(|previous| path <= previous) {
        Err(FsSnapshotError::Malformed(
            "paths are not strictly sorted (unsorted or duplicate)",
        ))
    } else {
        Ok(())
    }
}

fn validate_entry_path(path: &str, allow_root: bool) -> Result<(), FsSnapshotError> {
    if !path.starts_with('/') {
        return Err(FsSnapshotError::Malformed("entry path is not absolute"));
    }
    if path.contains('\0') {
        return Err(FsSnapshotError::Malformed("entry path contains NUL"));
    }
    if path == "/" {
        return if allow_root {
            Ok(())
        } else {
            Err(FsSnapshotError::Malformed(
                "root path is only valid as a directory",
            ))
        };
    }
    if path.chars().all(|character| character == '/') {
        return Err(FsSnapshotError::Malformed(
            "entry path is non-canonical root",
        ));
    }
    if normalize_entry_path(path).as_deref() != Ok(path) {
        return Err(FsSnapshotError::Malformed("entry path is not canonical"));
    }
    Ok(())
}

fn preflight_count(count: usize, name: &'static str) -> Result<(), FsSnapshotError> {
    let count = u64::try_from(count).map_err(|_| FsSnapshotError::LimitExceeded(name))?;
    if count > MAX_ENTRIES {
        return Err(FsSnapshotError::LimitExceeded(name));
    }
    Ok(())
}

fn add_len(total: &mut usize, len: usize) -> Result<(), FsSnapshotError> {
    *total = total
        .checked_add(len)
        .ok_or(FsSnapshotError::LimitExceeded("snapshot byte length"))?;
    if *total > MAX_SNAPSHOT_BYTES {
        return Err(FsSnapshotError::LimitExceeded("snapshot byte length"));
    }
    Ok(())
}

fn add_field_len(
    total: &mut usize,
    len: usize,
    limit: &'static str,
) -> Result<(), FsSnapshotError> {
    let len_u64 = u64::try_from(len).map_err(|_| FsSnapshotError::LimitExceeded(limit))?;
    if len_u64 > MAX_FIELD_BYTES {
        return Err(FsSnapshotError::LimitExceeded(limit));
    }
    add_len(total, 8)?;
    add_len(total, len)
}

fn add_path_len(total: &mut usize, path: &str) -> Result<(), FsSnapshotError> {
    let len =
        u64::try_from(path.len()).map_err(|_| FsSnapshotError::LimitExceeded("path length"))?;
    if len > MAX_PATH_BYTES {
        return Err(FsSnapshotError::LimitExceeded("path length"));
    }
    add_len(total, 8)?;
    add_len(total, path.len())
}

fn encode_metadata(bytes: &mut Vec<u8>, metadata: &EntryMetadata) {
    bytes.extend_from_slice(&metadata.ino.to_le_bytes());
    bytes.extend_from_slice(&metadata.atime_nanos.to_le_bytes());
    bytes.extend_from_slice(&metadata.mtime_nanos.to_le_bytes());
    bytes.extend_from_slice(&metadata.mode.to_le_bytes());
}

/// The encoded size of one [`EntryMetadata`]: inode id, both timestamps, mode.
const METADATA_BYTES: usize = 8 + 8 + 8 + 4;

fn encode_path(bytes: &mut Vec<u8>, path: &str) {
    encode_field(bytes, path.as_bytes());
}

fn encode_field(bytes: &mut Vec<u8>, field: &[u8]) {
    bytes.extend_from_slice(&(field.len() as u64).to_le_bytes());
    bytes.extend_from_slice(field);
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], FsSnapshotError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(FsSnapshotError::Truncated)?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or(FsSnapshotError::Truncated)?;
        self.offset = end;
        Ok(slice)
    }

    fn take_u32(&mut self) -> Result<u32, FsSnapshotError> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes(bytes.try_into().expect("4 bytes")))
    }

    fn take_u64(&mut self) -> Result<u64, FsSnapshotError> {
        let bytes = self.take(8)?;
        Ok(u64::from_le_bytes(bytes.try_into().expect("8 bytes")))
    }

    fn take_count(&mut self, name: &'static str) -> Result<u64, FsSnapshotError> {
        let count = self.take_u64()?;
        if count > MAX_ENTRIES {
            return Err(FsSnapshotError::LimitExceeded(name));
        }
        Ok(count)
    }

    fn take_field(&mut self) -> Result<Vec<u8>, FsSnapshotError> {
        let len = self.take_u64()?;
        if len > MAX_FIELD_BYTES {
            return Err(FsSnapshotError::LimitExceeded("field length"));
        }
        let len =
            usize::try_from(len).map_err(|_| FsSnapshotError::LimitExceeded("field length"))?;
        Ok(self.take(len)?.to_vec())
    }

    fn take_string(&mut self, field: &'static str) -> Result<String, FsSnapshotError> {
        String::from_utf8(self.take_field()?).map_err(|_| FsSnapshotError::Malformed(field))
    }

    fn take_path(&mut self, allow_root: bool) -> Result<String, FsSnapshotError> {
        let len = self.take_u64()?;
        if len > MAX_PATH_BYTES {
            return Err(FsSnapshotError::LimitExceeded("path length"));
        }
        let len =
            usize::try_from(len).map_err(|_| FsSnapshotError::LimitExceeded("path length"))?;
        let path = String::from_utf8(self.take(len)?.to_vec())
            .map_err(|_| FsSnapshotError::Malformed("path is not UTF-8"))?;
        validate_entry_path(&path, allow_root)?;
        Ok(path)
    }

    fn take_metadata(&mut self) -> Result<EntryMetadata, FsSnapshotError> {
        Ok(EntryMetadata {
            ino: self.take_u64()?,
            atime_nanos: self.take_u64()?,
            mtime_nanos: self.take_u64()?,
            mode: self.take_mode()?,
        })
    }

    /// Permission bits, rejected rather than masked when they carry anything
    /// outside `0o7777`: a snapshot that disagrees with the model about what a
    /// mode IS must not be silently reinterpreted.
    fn take_mode(&mut self) -> Result<u32, FsSnapshotError> {
        let mode = self.take_u32()?;
        if mode & !MODE_MASK != 0 {
            return Err(FsSnapshotError::Malformed(
                "mode carries bits outside the permission mask",
            ));
        }
        Ok(mode)
    }
}

/// A failure decoding an [`FsSnapshot`] stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FsSnapshotError {
    BadMagic,
    UnsupportedVersion(u32),
    Truncated,
    LimitExceeded(&'static str),
    Malformed(&'static str),
}

impl fmt::Display for FsSnapshotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FsSnapshotError::BadMagic => {
                write!(formatter, "not a Patina filesystem snapshot (bad magic)")
            }
            FsSnapshotError::UnsupportedVersion(version) => {
                write!(
                    formatter,
                    "unsupported filesystem snapshot version {version}"
                )
            }
            FsSnapshotError::Truncated => write!(formatter, "filesystem snapshot is truncated"),
            FsSnapshotError::LimitExceeded(limit) => {
                write!(formatter, "filesystem snapshot exceeds {limit} limit")
            }
            FsSnapshotError::Malformed(reason) => {
                write!(formatter, "malformed filesystem snapshot: {reason}")
            }
        }
    }
}

impl std::error::Error for FsSnapshotError {}

impl From<FsSnapshotError> for EffectError {
    fn from(error: FsSnapshotError) -> Self {
        EffectError::new(ErrorCode::InvalidInput, error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use patina_dst_abi::{Fd, FsEntryKind, OpenFlags, SeekWhence};
    use patina_dst_driver_api::FsDriver;

    use super::*;

    fn read_write() -> OpenFlags {
        OpenFlags {
            read: true,
            write: true,
            create: false,
            truncate: false,
            append: false,
            exclusive: false,
            mode: patina_dst_abi::CREATE_MODE_UNUSED,
        }
    }

    fn fixture() -> MemFs {
        let mut fs = MemFs::new();
        fs.create_directory("/state", 0o777).unwrap();
        fs.make_fifo("/state/pipe", 0o666).unwrap();
        fs.create_directory("/state/empty", 0o777).unwrap();
        fs.set_times_by_path("/state", Some(10), Some(20)).unwrap();
        let fd = fs
            .open("/state/log", OpenFlags::create_truncate_write())
            .unwrap();
        fs.write(fd, b"stable").unwrap();
        fs.set_times(fd, Some(30), Some(40)).unwrap();
        fs.close(fd).unwrap();
        fs.link("/state/log", "/state/log.link").unwrap();
        fs.symlink("../state/log", "/state/log.sym").unwrap();
        fs.set_times_by_path("/state/log.sym", Some(50), Some(60))
            .unwrap();
        fs
    }

    fn hand_encode(
        next_inode: u64,
        directories: &[(&str, u64, u64, u64)],
        inodes: &[(u64, u64, u64, u64, &[u8])],
        files: &[(&str, u64)],
        symlinks: &[(&str, &str, u64, u64, u64)],
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        bytes.extend_from_slice(&next_inode.to_le_bytes());
        bytes.extend_from_slice(&(directories.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&(inodes.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&(files.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&(symlinks.len() as u64).to_le_bytes());
        // Every hand-encoded case below probes namespace structure, so none of
        // them plants a FIFO; the section is still written (empty) because the
        // decoder reads its count unconditionally.
        bytes.extend_from_slice(&0u64.to_le_bytes());
        // Modes are not part of the hand-encoded tuples: every case below
        // probes structure (ordering, identity, bounds), so each entry carries
        // its ordinary creation mode.
        for (path, ino, atime, mtime) in directories {
            encode_path(&mut bytes, path);
            bytes.extend_from_slice(&ino.to_le_bytes());
            bytes.extend_from_slice(&atime.to_le_bytes());
            bytes.extend_from_slice(&mtime.to_le_bytes());
            bytes.extend_from_slice(&crate::DIRECTORY_MODE.to_le_bytes());
        }
        for (ino, links, atime, mtime, contents) in inodes {
            bytes.extend_from_slice(&ino.to_le_bytes());
            bytes.extend_from_slice(&links.to_le_bytes());
            bytes.extend_from_slice(&atime.to_le_bytes());
            bytes.extend_from_slice(&mtime.to_le_bytes());
            bytes.extend_from_slice(&crate::FILE_MODE.to_le_bytes());
            encode_field(&mut bytes, contents);
        }
        for (path, ino) in files {
            encode_path(&mut bytes, path);
            bytes.extend_from_slice(&ino.to_le_bytes());
        }
        for (path, target, ino, atime, mtime) in symlinks {
            encode_path(&mut bytes, path);
            encode_field(&mut bytes, target.as_bytes());
            bytes.extend_from_slice(&ino.to_le_bytes());
            bytes.extend_from_slice(&atime.to_le_bytes());
            bytes.extend_from_slice(&mtime.to_le_bytes());
            bytes.extend_from_slice(&crate::SYMLINK_MODE.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn snapshot_round_trip_is_canonical_and_excludes_handles() {
        let mut fs = fixture();
        let open = fs.open("/state/log", read_write()).unwrap();
        fs.seek(open, 3, SeekWhence::Start).unwrap();
        let encoded = fs.export_snapshot().encode().unwrap();
        let snapshot = FsSnapshot::decode(&encoded).unwrap();
        assert_eq!(snapshot.encode().unwrap(), encoded);

        let mut imported = MemFs::import_snapshot(&snapshot);
        assert_eq!(
            imported.read(Fd(3), 1).unwrap_err().code,
            ErrorCode::InvalidHandle
        );
        let fd = imported.open("/state/log", OpenFlags::read_only()).unwrap();
        assert_eq!(fd, Fd(3), "restart snapshot carried an old fd allocator");
        assert_eq!(imported.read(fd, 64).unwrap(), b"stable");
        assert_eq!(imported.export_snapshot().encode().unwrap(), encoded);
    }

    #[test]
    fn snapshot_preserves_hard_links_timestamps_and_inode_allocator() {
        let mut fs = fixture();
        let gap = fs
            .open("/removed", OpenFlags::create_truncate_write())
            .unwrap();
        fs.close(gap).unwrap();
        fs.remove_file("/removed").unwrap();
        let expected_next_inode = fs.next_inode;
        let mut imported = FsSnapshot::decode(&fs.export_snapshot().encode().unwrap())
            .unwrap()
            .into_memfs();

        let log = imported.metadata("/state/log").unwrap();
        let link = imported.metadata("/state/log.link").unwrap();
        assert_eq!(log.kind, FsEntryKind::File);
        assert_eq!(log.ino, link.ino);
        assert_eq!(log.nlink, 2);
        assert_eq!((log.atime_nanos, log.mtime_nanos), (30, 40));
        assert_eq!(imported.contents("/state/log.link").unwrap(), b"stable");

        let directory = imported.metadata("/state").unwrap();
        assert_eq!(directory.kind, FsEntryKind::Directory);
        assert_eq!((directory.atime_nanos, directory.mtime_nanos), (10, 20));
        let symlink = imported.metadata("/state/log.sym").unwrap();
        assert_eq!(symlink.kind, FsEntryKind::Symlink);
        assert_eq!((symlink.atime_nanos, symlink.mtime_nanos), (50, 60));
        assert_eq!(
            imported.read_link("/state/log.sym").unwrap(),
            "../state/log"
        );

        let fd = imported
            .open("/new", OpenFlags::create_truncate_write())
            .unwrap();
        assert_eq!(imported.metadata("/new").unwrap().ino, expected_next_inode);
        imported.close(fd).unwrap();
    }

    #[test]
    fn decode_rejects_bad_magic_version_truncation_and_limits() {
        assert_eq!(
            FsSnapshot::decode(b"NOTFSSNP").unwrap_err(),
            FsSnapshotError::BadMagic
        );

        let mut unsupported = fixture().export_snapshot().encode().unwrap();
        unsupported[MAGIC.len()..MAGIC.len() + 4].copy_from_slice(&99u32.to_le_bytes());
        assert_eq!(
            FsSnapshot::decode(&unsupported).unwrap_err(),
            FsSnapshotError::UnsupportedVersion(99)
        );

        let encoded = fixture().export_snapshot().encode().unwrap();
        for len in 0..encoded.len() {
            assert!(
                FsSnapshot::decode(&encoded[..len]).is_err(),
                "truncated snapshot of len {len} decoded successfully"
            );
        }

        let mut too_many = encoded.clone();
        let directory_count_offset = MAGIC.len() + 4 + 8;
        too_many[directory_count_offset..directory_count_offset + 8]
            .copy_from_slice(&(MAX_ENTRIES + 1).to_le_bytes());
        assert_eq!(
            FsSnapshot::decode(&too_many).unwrap_err(),
            FsSnapshotError::LimitExceeded("directory count")
        );
    }

    #[test]
    fn encode_preflight_rejects_bounded_outputs_before_allocating_bytes() {
        let mut total = MAX_SNAPSHOT_BYTES - 4;
        assert_eq!(
            add_len(&mut total, 5).unwrap_err(),
            FsSnapshotError::LimitExceeded("snapshot byte length")
        );

        let mut total = 0;
        assert_eq!(
            add_field_len(&mut total, (MAX_FIELD_BYTES as usize) + 1, "field length").unwrap_err(),
            FsSnapshotError::LimitExceeded("field length")
        );

        let mut fs = MemFs::new();
        let path = format!("/{}", "a".repeat(MAX_PATH_BYTES as usize + 1));
        fs.create_directory(&path, 0o777).unwrap();
        assert_eq!(
            fs.export_snapshot().encode().unwrap_err(),
            FsSnapshotError::LimitExceeded("path length")
        );
    }

    #[test]
    fn decode_rejects_exhausted_inode_allocator_and_valid_decode_can_allocate() {
        let root = ("/", 1, 0, 0);
        assert_eq!(
            FsSnapshot::decode(&hand_encode(u64::MAX, &[root], &[], &[], &[])).unwrap_err(),
            FsSnapshotError::Malformed("next inode allocator state is exhausted")
        );

        let mut imported = FsSnapshot::decode(&hand_encode(2, &[root], &[], &[], &[]))
            .unwrap()
            .into_memfs();
        let fd = imported
            .open("/allocated", OpenFlags::create_truncate_write())
            .unwrap();
        imported.close(fd).unwrap();
        assert_eq!(imported.metadata("/allocated").unwrap().ino, 2);
    }

    #[test]
    fn decode_rejects_noncanonical_ordering_duplicates_and_inconsistent_inodes() {
        let root = ("/", 1, 0, 0);
        let a = ("/a", 2, 0, 0);
        let b = ("/b", 3, 0, 0);
        let inode = (4, 1, 0, 0, b"x" as &[u8]);

        // Unsorted paths in one section.
        assert!(matches!(
            FsSnapshot::decode(&hand_encode(
                5,
                &[root, b, a],
                &[inode],
                &[("/a/f", 4)],
                &[]
            )),
            Err(FsSnapshotError::Malformed(
                "paths are not strictly sorted (unsorted or duplicate)"
            ))
        ));
        // Duplicate path within a section.
        assert!(matches!(
            FsSnapshot::decode(&hand_encode(5, &[root, a, a], &[], &[], &[])),
            Err(FsSnapshotError::Malformed(
                "paths are not strictly sorted (unsorted or duplicate)"
            ))
        ));
        // Same path across two sections.
        assert!(matches!(
            FsSnapshot::decode(&hand_encode(5, &[root, a], &[inode], &[("/a", 4)], &[])),
            Err(FsSnapshotError::Malformed(
                "path appears in more than one section"
            ))
        ));
        // Non-canonical path.
        assert!(matches!(
            FsSnapshot::decode(&hand_encode(5, &[root, ("/a//b", 2, 0, 0)], &[], &[], &[])),
            Err(FsSnapshotError::Malformed("entry path is not canonical"))
        ));
        // Missing parent directory.
        assert!(matches!(
            FsSnapshot::decode(&hand_encode(
                5,
                &[root],
                &[inode],
                &[("/missing/file", 4)],
                &[]
            )),
            Err(FsSnapshotError::Malformed(
                "entry parent directory is missing"
            ))
        ));
        // File references unknown inode.
        assert!(matches!(
            FsSnapshot::decode(&hand_encode(5, &[root], &[], &[("/file", 4)], &[])),
            Err(FsSnapshotError::Malformed(
                "file references an unknown inode"
            ))
        ));
        // Inode link count does not match names.
        assert!(matches!(
            FsSnapshot::decode(&hand_encode(
                5,
                &[root],
                &[(4, 2, 0, 0, b"x")],
                &[("/file", 4)],
                &[]
            )),
            Err(FsSnapshotError::Malformed("inode link count mismatch"))
        ));
        // Duplicate metadata/inode id across sections.
        assert!(matches!(
            FsSnapshot::decode(&hand_encode(
                5,
                &[root],
                &[inode],
                &[("/file", 4)],
                &[("/sym", "x", 4, 0, 0)]
            )),
            Err(FsSnapshotError::Malformed(
                "metadata inode id is duplicated"
            ))
        ));
        // Allocator state would reuse an existing metadata id.
        assert!(matches!(
            FsSnapshot::decode(&hand_encode(4, &[root], &[inode], &[("/file", 4)], &[])),
            Err(FsSnapshotError::Malformed(
                "next inode allocator state does not advance past existing metadata"
            ))
        ));
    }
}
