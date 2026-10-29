//! A deterministic, self-describing wire format for a read-only filesystem tree.
//!
//! An [`FsImage`] is an ordered set of directory, file, and symlink entries,
//! each with the metadata a guest can observe of it (permission bits and
//! modification time), that encodes to a byte stream and decodes back
//! identically. It exists so a
//! non-interposed supervisor process (which may freely read the host
//! filesystem) can capture a directory tree, hand the encoded bytes to a fully
//! interposed guest over an inherited descriptor, and have the guest rebuild the
//! tree as a [`MemFs`] without ever touching the host filesystem itself.
//!
//! The format is byte-for-byte a pure function of the entry set and their
//! sorted order, so an image built from a deterministic corpus is identical
//! across runs and machines and can be hashed to fingerprint the corpus a trace
//! was recorded against. Symlinks are preserved verbatim (target string, no
//! following), matching [`MemFs`]'s inert no-follow symlink model.
//!
//! The image also encodes in two halves ([`FsImage::encode_contents`],
//! [`FsImage::encode_metadata`]), so a corpus hashed by halves can be said to
//! differ from a recorded one in its contents or only in its metadata.

use std::fmt;

use patina_dst_abi::{DEFAULT_DIRECTORY_CREATE_MODE, DEFAULT_UMASK, FsClock};
use patina_dst_driver_api::{DriverResult, FsDriver};

use crate::{DIRECTORY_MODE, FILE_MODE, MODE_MASK, MemFs};

/// Magic prefix identifying an encoded [`FsImage`] stream.
const MAGIC: &[u8; 8] = b"PATFSIMG";
/// Wire-format version. Bump on any incompatible layout change.
const VERSION: u32 = 2;

const KIND_DIRECTORY: u8 = 0;
const KIND_FILE: u8 = 1;
const KIND_SYMLINK: u8 = 2;

/// One entry in an [`FsImage`]: an absolute guest path plus its kind,
/// payload and metadata. File contents and symlink targets travel verbatim;
/// directories carry no payload. `mode` is the permission bits (`0o7777`), which
/// a symlink does not have; `mtime_nanos` is the modification time in
/// nanoseconds since the Unix epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FsImageEntry {
    Directory {
        path: String,
        mode: u32,
        mtime_nanos: i128,
    },
    File {
        path: String,
        contents: Vec<u8>,
        mode: u32,
        mtime_nanos: i128,
    },
    Symlink {
        path: String,
        target: String,
        mtime_nanos: i128,
    },
}

impl FsImageEntry {
    /// A directory as an image builder's `mkdir` makes one: `0o755`, at the
    /// epoch.
    pub fn directory(path: impl Into<String>) -> Self {
        FsImageEntry::Directory {
            path: path.into(),
            mode: DIRECTORY_MODE,
            mtime_nanos: 0,
        }
    }

    /// A file as an image builder writes one: `0o644`, at the epoch.
    pub fn file(path: impl Into<String>, contents: impl Into<Vec<u8>>) -> Self {
        FsImageEntry::File {
            path: path.into(),
            contents: contents.into(),
            mode: FILE_MODE,
            mtime_nanos: 0,
        }
    }

    /// A symlink to `target`, at the epoch.
    pub fn symlink(path: impl Into<String>, target: impl Into<String>) -> Self {
        FsImageEntry::Symlink {
            path: path.into(),
            target: target.into(),
            mtime_nanos: 0,
        }
    }

    fn path(&self) -> &str {
        match self {
            FsImageEntry::Directory { path, .. }
            | FsImageEntry::File { path, .. }
            | FsImageEntry::Symlink { path, .. } => path,
        }
    }

    /// The permission bits, or `None` for a symlink.
    fn mode(&self) -> Option<u32> {
        match self {
            FsImageEntry::Directory { mode, .. } | FsImageEntry::File { mode, .. } => Some(*mode),
            FsImageEntry::Symlink { .. } => None,
        }
    }

    fn mtime_nanos(&self) -> i128 {
        match self {
            FsImageEntry::Directory { mtime_nanos, .. }
            | FsImageEntry::File { mtime_nanos, .. }
            | FsImageEntry::Symlink { mtime_nanos, .. } => *mtime_nanos,
        }
    }

    /// The kind byte and the payload: what the content half of the image is.
    fn content(&self) -> (u8, &[u8]) {
        match self {
            FsImageEntry::Directory { .. } => (KIND_DIRECTORY, &[]),
            FsImageEntry::File { contents, .. } => (KIND_FILE, contents),
            FsImageEntry::Symlink { target, .. } => (KIND_SYMLINK, target.as_bytes()),
        }
    }
}

/// An ordered, deterministic snapshot of a read-only filesystem tree.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FsImage {
    entries: Vec<FsImageEntry>,
}

impl FsImage {
    /// Build an image from entries in an arbitrary order. Entries are sorted by
    /// path so the encoded bytes are a pure function of the set, independent of
    /// discovery order (host `readdir` order must never leak into the image).
    pub fn new(mut entries: Vec<FsImageEntry>) -> Self {
        entries.sort_by(|left, right| left.path().cmp(right.path()));
        Self { entries }
    }

    pub fn entries(&self) -> &[FsImageEntry] {
        &self.entries
    }

    /// Encode to the self-describing wire format. Deterministic: identical
    /// entry sets always produce identical bytes. Each entry is its kind, path
    /// and payload, then its permission bits (directories and files only) and
    /// its modification time.
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        bytes.extend_from_slice(&(self.entries.len() as u64).to_le_bytes());
        for entry in &self.entries {
            let (kind, payload) = entry.content();
            bytes.push(kind);
            encode_field(&mut bytes, entry.path().as_bytes());
            encode_field(&mut bytes, payload);
            if let Some(mode) = entry.mode() {
                bytes.extend_from_slice(&mode.to_le_bytes());
            }
            bytes.extend_from_slice(&entry.mtime_nanos().to_le_bytes());
        }
        bytes
    }

    /// The tree's contents alone: every entry's kind, path and payload, and
    /// nothing of its metadata. Together with [`FsImage::encode_metadata`] it
    /// determines [`FsImage::encode`].
    pub fn encode_contents(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for entry in &self.entries {
            let (kind, payload) = entry.content();
            bytes.push(kind);
            encode_field(&mut bytes, entry.path().as_bytes());
            encode_field(&mut bytes, payload);
        }
        bytes
    }

    /// The tree's metadata alone: every entry's path, permission bits (a
    /// symlink's, which it has none of, as `u32::MAX`) and modification time.
    pub fn encode_metadata(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for entry in &self.entries {
            encode_field(&mut bytes, entry.path().as_bytes());
            bytes.extend_from_slice(&entry.mode().unwrap_or(u32::MAX).to_le_bytes());
            bytes.extend_from_slice(&entry.mtime_nanos().to_le_bytes());
        }
        bytes
    }

    /// Decode a stream produced by [`FsImage::encode`]. Rejects a truncated or
    /// malformed stream rather than silently producing a partial tree.
    pub fn decode(bytes: &[u8]) -> Result<Self, FsImageError> {
        let mut reader = Reader::new(bytes);
        let magic = reader.take(MAGIC.len())?;
        if magic != MAGIC {
            return Err(FsImageError::BadMagic);
        }
        let version = reader.take_u32()?;
        if version != VERSION {
            return Err(FsImageError::UnsupportedVersion(version));
        }
        let count = reader.take_u64()?;
        let mut entries = Vec::with_capacity(count.min(4096) as usize);
        for _ in 0..count {
            let kind = reader.take_u8()?;
            let path = reader.take_string()?;
            let payload = reader.take_field()?;
            let entry = match kind {
                KIND_DIRECTORY => {
                    if !payload.is_empty() {
                        return Err(FsImageError::Malformed("directory carries a payload"));
                    }
                    FsImageEntry::Directory {
                        path,
                        mode: reader.take_mode()?,
                        mtime_nanos: reader.take_i128()?,
                    }
                }
                KIND_FILE => FsImageEntry::File {
                    path,
                    contents: payload,
                    mode: reader.take_mode()?,
                    mtime_nanos: reader.take_i128()?,
                },
                KIND_SYMLINK => FsImageEntry::Symlink {
                    path,
                    target: String::from_utf8(payload)
                        .map_err(|_| FsImageError::Malformed("symlink target is not UTF-8"))?,
                    mtime_nanos: reader.take_i128()?,
                },
                other => return Err(FsImageError::UnknownKind(other)),
            };
            entries.push(entry);
        }
        if !reader.is_empty() {
            return Err(FsImageError::Malformed("trailing bytes after final entry"));
        }
        // Fail closed: the decoder never trusts its input. Every entry path must
        // be a clean absolute path with no `.`/`..`/empty components (no root
        // escape), and the whole list must be strictly ascending by path — which
        // simultaneously rejects duplicates and any non-canonical ordering. A
        // corrupt or adversarial image errors loudly here rather than rebuilding
        // a silently different filesystem.
        validate_decoded(&entries)?;
        Ok(Self { entries })
    }

    /// Rebuild the tree as a fresh [`MemFs`]. Ancestor directories are created
    /// top-down on demand, so an image whose intermediate directories are
    /// implicit still yields a walkable tree; directory entries additionally
    /// preserve empty directories that carry no files. Once the whole tree
    /// exists, each entry takes its captured metadata, so adding a child does
    /// not restamp its directory and a directory without search permission
    /// does not stop its children being seeded.
    pub fn into_memfs(&self) -> DriverResult<MemFs> {
        self.into_memfs_with(Ok)
    }

    /// [`FsImage::into_memfs`] with `setup` run on the rebuilt tree before
    /// its captured metadata is applied: what setup adds (a directory the
    /// system image always has) is made as the tree's own entries were, and
    /// the captured metadata is the last word on every entry the image holds,
    /// whatever setup did to it.
    pub fn into_memfs_with(
        &self,
        setup: impl FnOnce(MemFs) -> DriverResult<MemFs>,
    ) -> DriverResult<MemFs> {
        let mut fs = MemFs::new();
        // Entries are already sorted by path, so every parent precedes its
        // children; `ensure_directory` is defensive against implicit parents.
        for entry in &self.entries {
            match entry {
                FsImageEntry::Directory { path, .. } => ensure_directory(&mut fs, path)?,
                FsImageEntry::File { path, contents, .. } => {
                    if let Some(parent) = parent_of(path) {
                        ensure_directory(&mut fs, parent)?;
                    }
                    fs = fs.with_file(path, contents.clone())?;
                }
                FsImageEntry::Symlink { path, target, .. } => {
                    if let Some(parent) = parent_of(path) {
                        ensure_directory(&mut fs, parent)?;
                    }
                    fs.symlink(FsClock::EPOCH, target, path)?;
                }
            }
        }
        let mut fs = setup(fs)?;
        for entry in &self.entries {
            fs.seed_metadata(entry.path(), entry.mode(), entry.mtime_nanos())?;
        }
        Ok(fs)
    }
}

/// Reject a decoded entry list that is not a clean, strictly-ascending set of
/// well-formed absolute paths. Called on every `decode`, never on the trusted
/// encoder path.
fn validate_decoded(entries: &[FsImageEntry]) -> Result<(), FsImageError> {
    let mut previous: Option<&str> = None;
    for entry in entries {
        let path = entry.path();
        validate_entry_path(path)?;
        if let Some(previous) = previous
            && path <= previous
        {
            return Err(FsImageError::Malformed(
                "entries are not strictly sorted by path (unsorted or duplicate)",
            ));
        }
        previous = Some(path);
    }
    Ok(())
}

/// A well-formed image entry path: absolute, NUL-free, with at least one
/// component and no empty / `.` / `..` component (so it can never escape or
/// alias the mount root).
fn validate_entry_path(path: &str) -> Result<(), FsImageError> {
    if !path.starts_with('/') {
        return Err(FsImageError::Malformed("entry path is not absolute"));
    }
    if path.contains('\0') {
        return Err(FsImageError::Malformed("entry path contains NUL"));
    }
    let mut components = 0;
    for component in path.split('/').skip(1) {
        match component {
            "" => return Err(FsImageError::Malformed("entry path has an empty component")),
            "." | ".." => {
                return Err(FsImageError::Malformed(
                    "entry path has a `.` or `..` component",
                ));
            }
            _ => components += 1,
        }
    }
    if components == 0 {
        return Err(FsImageError::Malformed("entry path is the root"));
    }
    Ok(())
}

/// Create `path` and every missing ancestor directory, top-down, treating an
/// already-present directory as success. The virtual root `/` always exists.
fn ensure_directory(fs: &mut MemFs, path: &str) -> DriverResult<()> {
    if path == "/" || path.is_empty() {
        return Ok(());
    }
    if let Some(parent) = parent_of(path) {
        ensure_directory(fs, parent)?;
    }
    // A mount image's directories are the ordinary `mkdir(0o777)` an image
    // builder would have run under the default umask: `0o755`.
    match fs.create_directory(
        FsClock::EPOCH,
        path,
        DEFAULT_DIRECTORY_CREATE_MODE & !DEFAULT_UMASK,
    ) {
        Ok(()) => Ok(()),
        // An entry that already exists as a directory is the desired state; a
        // repeated create in a full tree walk is expected.
        Err(error) if error.code == patina_dst_abi::ErrorCode::AlreadyExists => Ok(()),
        Err(error) => Err(error),
    }
}

/// Parent of an absolute path, or `None` for the root itself.
fn parent_of(path: &str) -> Option<&str> {
    if path == "/" {
        return None;
    }
    match path.rfind('/') {
        Some(0) => Some("/"),
        Some(index) => Some(&path[..index]),
        None => None,
    }
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
        self.offset >= self.bytes.len()
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], FsImageError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(FsImageError::Truncated)?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or(FsImageError::Truncated)?;
        self.offset = end;
        Ok(slice)
    }

    fn take_u8(&mut self) -> Result<u8, FsImageError> {
        Ok(self.take(1)?[0])
    }

    fn take_u32(&mut self) -> Result<u32, FsImageError> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes(bytes.try_into().expect("4 bytes")))
    }

    fn take_u64(&mut self) -> Result<u64, FsImageError> {
        let bytes = self.take(8)?;
        Ok(u64::from_le_bytes(bytes.try_into().expect("8 bytes")))
    }

    fn take_i128(&mut self) -> Result<i128, FsImageError> {
        let bytes = self.take(16)?;
        Ok(i128::from_le_bytes(bytes.try_into().expect("16 bytes")))
    }

    /// Permission bits: nothing outside `0o7777`.
    fn take_mode(&mut self) -> Result<u32, FsImageError> {
        let mode = self.take_u32()?;
        if mode & !MODE_MASK != 0 {
            return Err(FsImageError::Malformed("mode has bits outside 0o7777"));
        }
        Ok(mode)
    }

    fn take_field(&mut self) -> Result<Vec<u8>, FsImageError> {
        let len = self.take_u64()?;
        Ok(self.take(len as usize)?.to_vec())
    }

    fn take_string(&mut self) -> Result<String, FsImageError> {
        let field = self.take_field()?;
        String::from_utf8(field).map_err(|_| FsImageError::Malformed("path is not UTF-8"))
    }
}

/// A failure decoding an [`FsImage`] stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FsImageError {
    BadMagic,
    UnsupportedVersion(u32),
    UnknownKind(u8),
    Truncated,
    Malformed(&'static str),
}

impl fmt::Display for FsImageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FsImageError::BadMagic => {
                write!(formatter, "not a Patina filesystem image (bad magic)")
            }
            FsImageError::UnsupportedVersion(version) => {
                write!(formatter, "unsupported filesystem image version {version}")
            }
            FsImageError::UnknownKind(kind) => {
                write!(formatter, "unknown filesystem image entry kind {kind}")
            }
            FsImageError::Truncated => write!(formatter, "filesystem image is truncated"),
            FsImageError::Malformed(reason) => {
                write!(formatter, "malformed filesystem image: {reason}")
            }
        }
    }
}

impl std::error::Error for FsImageError {}

#[cfg(test)]
mod tests {
    use patina_dst_abi::{FsClock, FsEntryKind, OpenFlags};

    use super::*;

    fn sample() -> FsImage {
        FsImage::new(vec![
            FsImageEntry::file("/docs/guide/intro.txt", "PATINA_MARKER here"),
            FsImageEntry::directory("/data/empty"),
            FsImageEntry::symlink("/link_to_readme", "README"),
            FsImageEntry::file("/README", "top level"),
        ])
    }

    /// Hand-encode a raw stream with the given entries so the decoder sees input
    /// the trusted `FsImage::new` sorter would never produce. Directories and
    /// files carry `mode`; every entry is at the epoch.
    fn hand_encode_with_mode(entries: &[(u8, &str, &[u8])], mode: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        bytes.extend_from_slice(&(entries.len() as u64).to_le_bytes());
        for (kind, path, payload) in entries {
            bytes.push(*kind);
            encode_field(&mut bytes, path.as_bytes());
            encode_field(&mut bytes, payload);
            if *kind != KIND_SYMLINK {
                bytes.extend_from_slice(&mode.to_le_bytes());
            }
            bytes.extend_from_slice(&0i128.to_le_bytes());
        }
        bytes
    }

    fn hand_encode(entries: &[(u8, &str, &[u8])]) -> Vec<u8> {
        hand_encode_with_mode(entries, FILE_MODE)
    }

    #[test]
    fn decode_fails_closed_on_adversarial_images() {
        assert_eq!(
            FsImage::decode(b"NOTMAGIC____").unwrap_err(),
            FsImageError::BadMagic
        );
        let mut truncated = sample().encode();
        truncated.truncate(truncated.len() - 3);
        assert!(matches!(
            FsImage::decode(&truncated),
            Err(FsImageError::Truncated | FsImageError::Malformed(_))
        ));
        // Root escape via `..`.
        assert!(matches!(
            FsImage::decode(&hand_encode(&[(KIND_FILE, "/../escape", b"x")])),
            Err(FsImageError::Malformed(_))
        ));
        // Relative (non-absolute) path.
        assert!(matches!(
            FsImage::decode(&hand_encode(&[(KIND_FILE, "relative", b"x")])),
            Err(FsImageError::Malformed(_))
        ));
    }

    /// The same entry set discovered in two host readdir orders yields
    /// byte-identical images that decode to what was encoded and enumerate
    /// sorted in the guest.
    #[test]
    fn images_round_trip_independent_of_host_order_and_list_sorted() {
        let forward = vec![
            FsImageEntry::file("/src/a.rs", "fn a"),
            FsImageEntry::file("/src/b.rs", "fn b"),
            FsImageEntry::file("/src/c.rs", "fn c"),
            FsImageEntry::directory("/src"),
        ];
        let mut shuffled = forward.clone();
        shuffled.rotate_left(2);
        shuffled.reverse();

        let image_a = FsImage::new(forward);
        let image_b = FsImage::new(shuffled);
        assert_eq!(image_a.encode(), image_b.encode());
        let decoded = FsImage::decode(&image_a.encode()).unwrap();
        assert_eq!(decoded, image_a);

        let mut fs = decoded.into_memfs().unwrap();
        let names: Vec<_> = fs
            .read_directory(FsClock::EPOCH, "/src")
            .unwrap()
            .into_iter()
            .map(|entry| entry.name)
            .collect();
        assert_eq!(names, vec!["a.rs", "b.rs", "c.rs"]);
    }

    const SECOND: i128 = 1_000_000_000;

    /// Captured entries survive the round trip and the rebuild: a file reads
    /// its contents, a symlink is listed inert with its target, an empty
    /// directory survives, each entry reads back its own bits and mtime (its
    /// other times derived from it), a directory keeps its mtime although
    /// children were added after it, and a directory without search
    /// permission still has its children seeded.
    #[test]
    fn into_memfs_gives_each_entry_its_captured_mode_and_mtime() {
        let (dir_time, file_time, link_time) = (
            1_704_067_200 * SECOND,
            1_704_153_600 * SECOND + 5,
            -631_152_000 * SECOND,
        );
        let image = FsImage::new(vec![
            FsImageEntry::Directory {
                path: "/dir".into(),
                mode: 0o750,
                mtime_nanos: dir_time,
            },
            FsImageEntry::File {
                path: "/dir/run.sh".into(),
                contents: b"#!/bin/sh".to_vec(),
                mode: 0o4755,
                mtime_nanos: file_time,
            },
            FsImageEntry::Symlink {
                path: "/dir/link".into(),
                target: "run.sh".into(),
                mtime_nanos: link_time,
            },
            FsImageEntry::directory("/empty"),
            FsImageEntry::Directory {
                path: "/locked".into(),
                mode: 0o000,
                mtime_nanos: dir_time,
            },
            FsImageEntry::File {
                path: "/locked/secret".into(),
                contents: Vec::new(),
                mode: 0o600,
                mtime_nanos: file_time,
            },
        ]);
        let mut fs = FsImage::decode(&image.encode())
            .unwrap()
            .into_memfs()
            .unwrap();
        for (path, mode, mtime) in [
            ("/dir", Some(0o750), dir_time),
            ("/dir/run.sh", Some(0o4755), file_time),
            ("/dir/link", None, link_time),
            ("/locked", Some(0o000), dir_time),
        ] {
            let metadata = fs.metadata(path).unwrap();
            if let Some(mode) = mode {
                assert_eq!(metadata.mode, mode, "{path}");
            }
            assert_eq!(metadata.mtime_nanos, mtime, "{path}");
            assert_eq!(metadata.atime_nanos, mtime, "{path}");
            assert_eq!(metadata.ctime_nanos, mtime, "{path}");
            assert_eq!(metadata.btime_nanos, mtime, "{path}");
        }
        assert_eq!(fs.metadata("/dir/link").unwrap().kind, FsEntryKind::Symlink);
        assert_eq!(fs.read_link(FsClock::EPOCH, "/dir/link").unwrap(), "run.sh");
        let fd = fs
            .open(FsClock::EPOCH, "/dir/run.sh", OpenFlags::read_only())
            .unwrap();
        assert_eq!(fs.read(FsClock::EPOCH, fd, 64).unwrap(), b"#!/bin/sh");
        let listed: Vec<_> = fs
            .read_directory(FsClock::EPOCH, "/dir")
            .unwrap()
            .into_iter()
            .map(|entry| (entry.name, entry.kind))
            .collect();
        assert!(listed.contains(&("link".to_string(), FsEntryKind::Symlink)));
        assert!(
            fs.read_directory(FsClock::EPOCH, "/empty")
                .unwrap()
                .is_empty()
        );
        // Behind a directory without search permission: read without the
        // guards a guest's lookup runs.
        let secret = fs.leaf("/locked/secret").unwrap();
        assert_eq!((secret.mode, secret.times.mtime_nanos), (0o600, file_time));
    }
}
