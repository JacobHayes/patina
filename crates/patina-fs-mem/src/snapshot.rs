//! Restart snapshots for [`MemFs`].
//!
//! Unlike [`crate::FsImage`], which is an input-only mount/corpus format,
//! [`FsSnapshot`] captures a live deterministic filesystem image for a fresh
//! incarnation: namespace, file contents, hard-link identity, metadata,
//! extended attributes, and the inode allocator state. It deliberately excludes
//! open descriptors and other process-local state.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use patina_dst_abi::{EffectError, ErrorCode};

use crate::Times;
use crate::{EntryMetadata, Inode, InodeId, MODE_MASK, MemFs, normalize_entry_path, parent_path};
use patina_dst_abi::FsEntryKind;

/// Magic prefix identifying an encoded [`FsSnapshot`] stream.
const MAGIC: &[u8; 8] = b"PATFSSNP";
/// Wire-format version. Bump on any incompatible layout change.
///
/// Version 6 makes every non-directory name one section naming an inode that
/// carries its own KIND — a regular file, a symlink (whose target is its
/// contents), a FIFO, a socket node or a whiteout — so a hard link to any of
/// them is a second name for one node across a restart, and adds the extended
/// attributes, by the node they belong to. Version 5 kept symlinks as
/// per-path records and FIFOs as a section of their own.
const VERSION: u32 = 6;

/// Deliberately conservative structural bounds for a restart handoff. The
/// decoder checks them before allocating from untrusted bytes, so corrupt
/// handoffs fail closed instead of exhausting memory.
const MAX_SNAPSHOT_BYTES: usize = 128 * 1024 * 1024;
const MAX_ENTRIES: u64 = 1_000_000;
const MAX_FIELD_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PATH_BYTES: u64 = 4096;
/// `XATTR_NAME_MAX` and `XATTR_SIZE_MAX`: what one extended attribute can be.
const MAX_XATTR_NAME_BYTES: usize = 255;
const MAX_XATTR_VALUE_BYTES: usize = 65536;

/// The wire code of an inode's kind. A directory is never an inode-table node.
fn kind_code(kind: FsEntryKind) -> u8 {
    match kind {
        FsEntryKind::File => 0,
        FsEntryKind::Symlink => 1,
        FsEntryKind::Fifo => 2,
        FsEntryKind::Socket => 3,
        FsEntryKind::CharDevice => 4,
        FsEntryKind::Directory => unreachable!("a directory is not an inode-table node"),
    }
}

fn kind_from_code(code: u8) -> Result<FsEntryKind, FsSnapshotError> {
    match code {
        0 => Ok(FsEntryKind::File),
        1 => Ok(FsEntryKind::Symlink),
        2 => Ok(FsEntryKind::Fifo),
        3 => Ok(FsEntryKind::Socket),
        4 => Ok(FsEntryKind::CharDevice),
        _ => Err(FsSnapshotError::Malformed("inode kind is unknown")),
    }
}

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
            .field("names", &self.filesystem.names.len())
            .field("inodes", &self.filesystem.inodes.len())
            .field("xattrs", &self.filesystem.xattrs.len())
            .field("next_inode", &self.filesystem.next_inode)
            .finish()
    }
}

impl FsSnapshot {
    pub(crate) fn from_memfs(filesystem: &MemFs) -> Self {
        let mut filesystem = filesystem.clone();
        // Descriptors do not cross a restart, and neither does a node only a
        // descriptor was keeping alive: a snapshot is a NAMESPACE, and an
        // unlinked-but-open entry has no name to write down.
        filesystem.forget_open_state();
        Self { filesystem }
    }

    fn xattr_entries(&self) -> impl Iterator<Item = (InodeId, &String, &Vec<u8>)> {
        self.filesystem.xattrs.iter().flat_map(|(ino, attributes)| {
            attributes
                .iter()
                .map(move |(name, value)| (*ino, name, value))
        })
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
        bytes.extend_from_slice(&(self.filesystem.names.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&(self.xattr_entries().count() as u64).to_le_bytes());

        for (path, metadata) in &self.filesystem.directories {
            encode_path(&mut bytes, path);
            encode_metadata(&mut bytes, metadata);
        }
        for (inode_id, inode) in &self.filesystem.inodes {
            bytes.extend_from_slice(&inode_id.to_le_bytes());
            bytes.push(kind_code(inode.kind));
            bytes.extend_from_slice(&(inode.links as u64).to_le_bytes());
            encode_times(&mut bytes, &inode.times);
            bytes.extend_from_slice(&inode.mode.to_le_bytes());
            encode_field(&mut bytes, &inode.contents);
        }
        for (path, inode_id) in &self.filesystem.names {
            encode_path(&mut bytes, path);
            bytes.extend_from_slice(&inode_id.to_le_bytes());
        }
        for (ino, name, value) in self.xattr_entries() {
            bytes.extend_from_slice(&ino.to_le_bytes());
            encode_field(&mut bytes, name.as_bytes());
            encode_field(&mut bytes, value);
        }
        debug_assert_eq!(bytes.len(), encoded_len);
        Ok(bytes)
    }

    fn preflight_encode(&self) -> Result<usize, FsSnapshotError> {
        validate_snapshot_state(
            self.filesystem.next_inode,
            &self.filesystem.directories,
            &self.filesystem.inodes,
            &self.filesystem.names,
            &self.filesystem.xattrs,
        )?;

        preflight_count(self.filesystem.directories.len(), "directory count")?;
        preflight_count(self.filesystem.inodes.len(), "inode count")?;
        preflight_count(self.filesystem.names.len(), "name count")?;
        preflight_count(self.xattr_entries().count(), "xattr count")?;

        let mut total = MAGIC.len() + 4 + 8 + 8 + 8 + 8 + 8;
        for path in self.filesystem.directories.keys() {
            add_path_len(&mut total, path)?;
            add_len(&mut total, METADATA_BYTES)?;
        }
        for inode in self.filesystem.inodes.values() {
            add_len(&mut total, 8 + 1 + 8 + TIMES_BYTES + 4)?;
            add_field_len(&mut total, inode.contents.len(), "field length")?;
        }
        for path in self.filesystem.names.keys() {
            add_path_len(&mut total, path)?;
            add_len(&mut total, 8)?;
        }
        for (_, name, value) in self.xattr_entries() {
            add_len(&mut total, 8)?;
            add_field_len(&mut total, name.len(), "field length")?;
            add_field_len(&mut total, value.len(), "field length")?;
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
        let name_count = reader.take_count("name count")?;
        let xattr_count = reader.take_count("xattr count")?;

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
            let kind = kind_from_code(reader.take(1)?[0])?;
            let links = reader.take_u64()?;
            let links = u32::try_from(links)
                .map_err(|_| FsSnapshotError::Malformed("inode link count overflows u32"))?;
            if links == 0 {
                return Err(FsSnapshotError::Malformed("inode has zero links"));
            }
            let times = reader.take_times()?;
            let mode = reader.take_mode()?;
            let contents = reader.take_field()?;
            inodes.insert(
                inode_id,
                Inode {
                    kind,
                    contents,
                    links,
                    openers: 0,
                    times,
                    mode,
                },
            );
        }

        let mut names = BTreeMap::new();
        previous_path = None;
        for _ in 0..name_count {
            let path = reader.take_path(false)?;
            require_strict_path_order(previous_path.as_deref(), &path)?;
            previous_path = Some(path.clone());
            let inode_id = reader.take_u64()?;
            names.insert(path, inode_id);
        }

        let mut xattrs: BTreeMap<InodeId, BTreeMap<String, Vec<u8>>> = BTreeMap::new();
        let mut previous_key: Option<(InodeId, String)> = None;
        for _ in 0..xattr_count {
            let ino = reader.take_u64()?;
            let name = reader.take_string("xattr name is not UTF-8")?;
            let value = reader.take_field()?;
            let key = (ino, name.clone());
            if previous_key
                .as_ref()
                .is_some_and(|previous| key <= *previous)
            {
                return Err(FsSnapshotError::Malformed(
                    "xattrs are not strictly sorted by node and name",
                ));
            }
            previous_key = Some(key);
            xattrs.entry(ino).or_default().insert(name, value);
        }

        if !reader.is_empty() {
            return Err(FsSnapshotError::Malformed("trailing bytes after snapshot"));
        }

        validate_snapshot_state(next_inode, &directories, &inodes, &names, &xattrs)?;

        Ok(Self {
            filesystem: MemFs {
                names,
                inodes,
                directories,
                xattrs,
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
    names: &BTreeMap<String, InodeId>,
    xattrs: &BTreeMap<InodeId, BTreeMap<String, Vec<u8>>>,
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
    for (path, inode_id) in names {
        validate_entry_path(path, false)?;
        insert_unique_path(&mut paths, path)?;
        require_parent_directory(path, directories)?;
        if !inodes.contains_key(inode_id) {
            return Err(FsSnapshotError::Malformed(
                "name references an unknown inode",
            ));
        }
    }
    for (inode_id, inode) in inodes {
        insert_unique_inode(&mut metadata_ids, *inode_id)?;
        max_inode = max_inode.max(*inode_id);
        match inode.kind {
            // A symlink's contents are its target: a path string, never NUL.
            FsEntryKind::Symlink => {
                if std::str::from_utf8(&inode.contents).is_err() || inode.contents.contains(&0) {
                    return Err(FsSnapshotError::Malformed(
                        "symlink target is not a NUL-free string",
                    ));
                }
            }
            // A FIFO, a socket node or a whiteout holds no filesystem bytes:
            // its inode exists for identity, the link count and the mode.
            // Contents there would be state no reader can ever see.
            FsEntryKind::Fifo | FsEntryKind::Socket | FsEntryKind::CharDevice => {
                if !inode.contents.is_empty() {
                    return Err(FsSnapshotError::Malformed(
                        "a node without bytes carries contents",
                    ));
                }
            }
            FsEntryKind::File => {}
            FsEntryKind::Directory => {
                return Err(FsSnapshotError::Malformed("inode kind is unknown"));
            }
        }
    }

    let mut actual_links: BTreeMap<InodeId, u32> = BTreeMap::new();
    for inode_id in names.values().copied() {
        *actual_links.entry(inode_id).or_default() += 1;
    }
    for (inode_id, inode) in inodes {
        let actual = actual_links.get(inode_id).copied().unwrap_or(0);
        if actual == 0 {
            return Err(FsSnapshotError::Malformed("inode has no names"));
        }
        if actual != inode.links {
            return Err(FsSnapshotError::Malformed("inode link count mismatch"));
        }
    }

    for (ino, attributes) in xattrs {
        if !metadata_ids.contains(ino) {
            return Err(FsSnapshotError::Malformed("xattr names an unknown node"));
        }
        if attributes.is_empty() {
            return Err(FsSnapshotError::Malformed("node has an empty xattr set"));
        }
        for (name, value) in attributes {
            if name.is_empty() || name.len() > MAX_XATTR_NAME_BYTES || name.contains('\0') {
                return Err(FsSnapshotError::Malformed("xattr name is out of range"));
            }
            if value.len() > MAX_XATTR_VALUE_BYTES {
                return Err(FsSnapshotError::Malformed("xattr value is too large"));
            }
        }
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

fn encode_times(bytes: &mut Vec<u8>, times: &Times) {
    bytes.extend_from_slice(&times.atime_nanos.to_le_bytes());
    bytes.extend_from_slice(&times.mtime_nanos.to_le_bytes());
    bytes.extend_from_slice(&times.ctime_nanos.to_le_bytes());
    bytes.extend_from_slice(&times.btime_nanos.to_le_bytes());
}

fn encode_metadata(bytes: &mut Vec<u8>, metadata: &EntryMetadata) {
    bytes.extend_from_slice(&metadata.ino.to_le_bytes());
    encode_times(bytes, &metadata.times);
    bytes.extend_from_slice(&metadata.mode.to_le_bytes());
}

/// The encoded size of the four timestamps.
const TIMES_BYTES: usize = 4 * 8;
/// The encoded size of one [`EntryMetadata`]: inode id, four timestamps, mode.
const METADATA_BYTES: usize = 8 + TIMES_BYTES + 4;

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

    fn take_times(&mut self) -> Result<Times, FsSnapshotError> {
        Ok(Times {
            atime_nanos: self.take_u64()?,
            mtime_nanos: self.take_u64()?,
            ctime_nanos: self.take_u64()?,
            btime_nanos: self.take_u64()?,
        })
    }

    fn take_metadata(&mut self) -> Result<EntryMetadata, FsSnapshotError> {
        Ok(EntryMetadata {
            ino: self.take_u64()?,
            times: self.take_times()?,
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
    use patina_dst_abi::{Fd, FsClock, FsEntryKind, OpenFlags, SeekWhence};
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
            path_only: false,
            mode: patina_dst_abi::CREATE_MODE_UNUSED,
        }
    }

    fn fixture() -> MemFs {
        let mut fs = MemFs::new();
        fs.create_directory(FsClock::EPOCH, "/state", 0o777)
            .unwrap();
        fs.make_fifo(FsClock::EPOCH, "/state/pipe", 0o666).unwrap();
        fs.create_directory(FsClock::EPOCH, "/state/empty", 0o777)
            .unwrap();
        let fd = fs
            .open(
                FsClock::EPOCH,
                "/state/log",
                OpenFlags::create_truncate_write(),
            )
            .unwrap();
        fs.write(FsClock::EPOCH, fd, b"stable").unwrap();
        fs.set_times(FsClock::EPOCH, fd, Some(30), Some(40))
            .unwrap();
        fs.close(fd).unwrap();
        fs.link(FsClock::EPOCH, "/state/log", "/state/log.link")
            .unwrap();
        fs.symlink(FsClock::EPOCH, "../state/log", "/state/log.sym")
            .unwrap();
        fs.set_times_by_path(FsClock::EPOCH, "/state/log.sym", Some(50), Some(60))
            .unwrap();
        // Last: every name created above stamped the directory's mtime/ctime.
        fs.set_times_by_path(FsClock::EPOCH, "/state", Some(10), Some(20))
            .unwrap();
        fs
    }

    /// A hand-built v6 stream. Every case below probes namespace structure,
    /// so each inode is a regular file at its ordinary creation mode, each
    /// directory at its own, change and birth times are zero, and no node
    /// carries attributes.
    fn hand_encode(
        next_inode: u64,
        directories: &[(&str, u64, u64, u64)],
        inodes: &[(u64, u64, u64, u64, &[u8])],
        names: &[(&str, u64)],
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        bytes.extend_from_slice(&next_inode.to_le_bytes());
        bytes.extend_from_slice(&(directories.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&(inodes.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&(names.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        for (path, ino, atime, mtime) in directories {
            encode_path(&mut bytes, path);
            bytes.extend_from_slice(&ino.to_le_bytes());
            bytes.extend_from_slice(&atime.to_le_bytes());
            bytes.extend_from_slice(&mtime.to_le_bytes());
            bytes.extend_from_slice(&[0u8; 16]);
            bytes.extend_from_slice(&crate::DIRECTORY_MODE.to_le_bytes());
        }
        for (ino, links, atime, mtime, contents) in inodes {
            bytes.extend_from_slice(&ino.to_le_bytes());
            bytes.push(kind_code(FsEntryKind::File));
            bytes.extend_from_slice(&links.to_le_bytes());
            bytes.extend_from_slice(&atime.to_le_bytes());
            bytes.extend_from_slice(&mtime.to_le_bytes());
            bytes.extend_from_slice(&[0u8; 16]);
            bytes.extend_from_slice(&crate::FILE_MODE.to_le_bytes());
            encode_field(&mut bytes, contents);
        }
        for (path, ino) in names {
            encode_path(&mut bytes, path);
            bytes.extend_from_slice(&ino.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn snapshot_round_trip_is_canonical_and_excludes_handles() {
        let mut fs = fixture();
        let open = fs.open(FsClock::EPOCH, "/state/log", read_write()).unwrap();
        fs.seek(open, 3, SeekWhence::Start).unwrap();
        let encoded = fs.export_snapshot().encode().unwrap();
        let snapshot = FsSnapshot::decode(&encoded).unwrap();
        assert_eq!(snapshot.encode().unwrap(), encoded);

        let mut imported = MemFs::import_snapshot(&snapshot);
        assert_eq!(
            imported.read(FsClock::EPOCH, Fd(3), 1).unwrap_err().code,
            ErrorCode::InvalidHandle
        );
        let fd = imported
            .open(FsClock::EPOCH, "/state/log", OpenFlags::read_only())
            .unwrap();
        assert_eq!(fd, Fd(3), "restart snapshot carried an old fd allocator");
        // A read under `noatime` is the one read that leaves the image
        // byte-identical; under the default `relatime` it would stamp `atime`
        // (the file's mtime is newer than its atime), which is the point of
        // the model, not a snapshot defect.
        let noatime = FsClock {
            now_nanos: 0,
            atime: patina_dst_abi::AtimePolicy::NoAtime,
        };
        assert_eq!(imported.read(noatime, fd, 64).unwrap(), b"stable");
        assert_eq!(imported.export_snapshot().encode().unwrap(), encoded);
    }

    #[test]
    fn snapshot_preserves_hard_links_timestamps_and_inode_allocator() {
        let mut fs = fixture();
        let gap = fs
            .open(
                FsClock::EPOCH,
                "/removed",
                OpenFlags::create_truncate_write(),
            )
            .unwrap();
        fs.close(gap).unwrap();
        fs.remove_file(FsClock::EPOCH, "/removed").unwrap();
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
            imported
                .read_link(FsClock::EPOCH, "/state/log.sym")
                .unwrap(),
            "../state/log"
        );

        let fd = imported
            .open(FsClock::EPOCH, "/new", OpenFlags::create_truncate_write())
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
        fs.create_directory(FsClock::EPOCH, &path, 0o777).unwrap();
        assert_eq!(
            fs.export_snapshot().encode().unwrap_err(),
            FsSnapshotError::LimitExceeded("path length")
        );
    }

    #[test]
    fn decode_rejects_exhausted_inode_allocator_and_valid_decode_can_allocate() {
        let root = ("/", 1, 0, 0);
        assert_eq!(
            FsSnapshot::decode(&hand_encode(u64::MAX, &[root], &[], &[])).unwrap_err(),
            FsSnapshotError::Malformed("next inode allocator state is exhausted")
        );

        let mut imported = FsSnapshot::decode(&hand_encode(2, &[root], &[], &[]))
            .unwrap()
            .into_memfs();
        let fd = imported
            .open(
                FsClock::EPOCH,
                "/allocated",
                OpenFlags::create_truncate_write(),
            )
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
            FsSnapshot::decode(&hand_encode(5, &[root, b, a], &[inode], &[("/a/f", 4)])),
            Err(FsSnapshotError::Malformed(
                "paths are not strictly sorted (unsorted or duplicate)"
            ))
        ));
        // Duplicate path within a section.
        assert!(matches!(
            FsSnapshot::decode(&hand_encode(5, &[root, a, a], &[], &[])),
            Err(FsSnapshotError::Malformed(
                "paths are not strictly sorted (unsorted or duplicate)"
            ))
        ));
        // Same path across two sections.
        assert!(matches!(
            FsSnapshot::decode(&hand_encode(5, &[root, a], &[inode], &[("/a", 4)])),
            Err(FsSnapshotError::Malformed(
                "path appears in more than one section"
            ))
        ));
        // Non-canonical path.
        assert!(matches!(
            FsSnapshot::decode(&hand_encode(5, &[root, ("/a//b", 2, 0, 0)], &[], &[])),
            Err(FsSnapshotError::Malformed("entry path is not canonical"))
        ));
        // Missing parent directory.
        assert!(matches!(
            FsSnapshot::decode(&hand_encode(5, &[root], &[inode], &[("/missing/file", 4)])),
            Err(FsSnapshotError::Malformed(
                "entry parent directory is missing"
            ))
        ));
        // A name references an unknown inode.
        assert!(matches!(
            FsSnapshot::decode(&hand_encode(5, &[root], &[], &[("/file", 4)])),
            Err(FsSnapshotError::Malformed(
                "name references an unknown inode"
            ))
        ));
        // Inode link count does not match names.
        assert!(matches!(
            FsSnapshot::decode(&hand_encode(
                5,
                &[root],
                &[(4, 2, 0, 0, b"x")],
                &[("/file", 4)],
            )),
            Err(FsSnapshotError::Malformed("inode link count mismatch"))
        ));
        // Duplicate metadata/inode id across sections.
        assert!(matches!(
            FsSnapshot::decode(&hand_encode(
                5,
                &[root, ("/d", 4, 0, 0)],
                &[inode],
                &[("/file", 4)],
            )),
            Err(FsSnapshotError::Malformed(
                "metadata inode id is duplicated"
            ))
        ));
        // Allocator state would reuse an existing metadata id.
        assert!(matches!(
            FsSnapshot::decode(&hand_encode(4, &[root], &[inode], &[("/file", 4)])),
            Err(FsSnapshotError::Malformed(
                "next inode allocator state does not advance past existing metadata"
            ))
        ));
    }
}
