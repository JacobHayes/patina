//! A deterministic, self-describing wire format for a read-only filesystem tree.
//!
//! An [`FsImage`] is an ordered set of directory, file, and symlink entries that
//! encodes to a byte stream and decodes back identically. It exists so a
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

use std::fmt;

use patina_driver_api::{DriverResult, FsDriver};

use crate::MemFs;

/// Magic prefix identifying an encoded [`FsImage`] stream.
const MAGIC: &[u8; 8] = b"PATFSIMG";
/// Wire-format version. Bump on any incompatible layout change.
const VERSION: u32 = 1;

const KIND_DIRECTORY: u8 = 0;
const KIND_FILE: u8 = 1;
const KIND_SYMLINK: u8 = 2;

/// One entry in an [`FsImage`]: an absolute guest path plus its kind and
/// payload. File contents and symlink targets travel verbatim; directories
/// carry no payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FsImageEntry {
    Directory { path: String },
    File { path: String, contents: Vec<u8> },
    Symlink { path: String, target: String },
}

impl FsImageEntry {
    fn path(&self) -> &str {
        match self {
            FsImageEntry::Directory { path }
            | FsImageEntry::File { path, .. }
            | FsImageEntry::Symlink { path, .. } => path,
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
    /// entry sets always produce identical bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        bytes.extend_from_slice(&(self.entries.len() as u64).to_le_bytes());
        for entry in &self.entries {
            match entry {
                FsImageEntry::Directory { path } => {
                    bytes.push(KIND_DIRECTORY);
                    encode_field(&mut bytes, path.as_bytes());
                    encode_field(&mut bytes, &[]);
                }
                FsImageEntry::File { path, contents } => {
                    bytes.push(KIND_FILE);
                    encode_field(&mut bytes, path.as_bytes());
                    encode_field(&mut bytes, contents);
                }
                FsImageEntry::Symlink { path, target } => {
                    bytes.push(KIND_SYMLINK);
                    encode_field(&mut bytes, path.as_bytes());
                    encode_field(&mut bytes, target.as_bytes());
                }
            }
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
                    FsImageEntry::Directory { path }
                }
                KIND_FILE => FsImageEntry::File {
                    path,
                    contents: payload,
                },
                KIND_SYMLINK => FsImageEntry::Symlink {
                    path,
                    target: String::from_utf8(payload)
                        .map_err(|_| FsImageError::Malformed("symlink target is not UTF-8"))?,
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
    /// preserve empty directories that carry no files.
    pub fn into_memfs(&self) -> DriverResult<MemFs> {
        let mut fs = MemFs::new();
        // Entries are already sorted by path, so every parent precedes its
        // children; `ensure_directory` is defensive against implicit parents.
        for entry in &self.entries {
            match entry {
                FsImageEntry::Directory { path } => ensure_directory(&mut fs, path)?,
                FsImageEntry::File { path, contents } => {
                    if let Some(parent) = parent_of(path) {
                        ensure_directory(&mut fs, parent)?;
                    }
                    fs = fs.with_file(path, contents.clone())?;
                }
                FsImageEntry::Symlink { path, target } => {
                    if let Some(parent) = parent_of(path) {
                        ensure_directory(&mut fs, parent)?;
                    }
                    fs.symlink(target, path)?;
                }
            }
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
        if let Some(previous) = previous {
            if path <= previous {
                return Err(FsImageError::Malformed(
                    "entries are not strictly sorted by path (unsorted or duplicate)",
                ));
            }
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
    match fs.create_directory(path) {
        Ok(()) => Ok(()),
        // An entry that already exists as a directory is the desired state; a
        // repeated create in a full tree walk is expected.
        Err(error) if error.code == patina_abi::ErrorCode::AlreadyExists => Ok(()),
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
    use patina_abi::{FsEntryKind, OpenFlags};

    use super::*;

    fn sample() -> FsImage {
        FsImage::new(vec![
            FsImageEntry::File {
                path: "/docs/guide/intro.txt".into(),
                contents: b"PATINA_MARKER here".to_vec(),
            },
            FsImageEntry::Directory {
                path: "/data/empty".into(),
            },
            FsImageEntry::Symlink {
                path: "/link_to_readme".into(),
                target: "README".into(),
            },
            FsImageEntry::File {
                path: "/README".into(),
                contents: b"top level".to_vec(),
            },
        ])
    }

    #[test]
    fn encode_decode_round_trips_and_is_order_independent() {
        let image = sample();
        let decoded = FsImage::decode(&image.encode()).unwrap();
        assert_eq!(image, decoded);

        // A differently-ordered construction yields byte-identical output.
        let reordered = FsImage::new({
            let mut entries = image.entries().to_vec();
            entries.reverse();
            entries
        });
        assert_eq!(image.encode(), reordered.encode());
    }

    #[test]
    fn into_memfs_rebuilds_files_dirs_and_inert_symlinks() {
        let mut fs = sample().into_memfs().unwrap();

        let fd = fs.open("/README", OpenFlags::read_only()).unwrap();
        assert_eq!(fs.read(fd, 64).unwrap(), b"top level");

        let root: Vec<_> = fs
            .read_directory("/")
            .unwrap()
            .into_iter()
            .map(|entry| (entry.name, entry.kind))
            .collect();
        // Symlink is listed as a symlink (inert, not followed), matching how a
        // default `rg` walk skips it.
        assert!(root.contains(&("link_to_readme".to_string(), FsEntryKind::Symlink)));
        assert!(root.contains(&("README".to_string(), FsEntryKind::File)));
        // Empty directory survives.
        assert_eq!(fs.read_link("/link_to_readme").unwrap(), "README");
        let empty = fs.read_directory("/data/empty").unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    fn decode_rejects_corruption() {
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
    }

    /// Hand-encode a raw stream with the given entries so the decoder sees input
    /// the trusted `FsImage::new` sorter would never produce.
    fn hand_encode(entries: &[(u8, &str, &[u8])]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        bytes.extend_from_slice(&(entries.len() as u64).to_le_bytes());
        for (kind, path, payload) in entries {
            bytes.push(*kind);
            encode_field(&mut bytes, path.as_bytes());
            encode_field(&mut bytes, payload);
        }
        bytes
    }

    #[test]
    fn decode_fails_closed_on_adversarial_images() {
        // Unsorted.
        assert_eq!(
            FsImage::decode(&hand_encode(&[
                (KIND_FILE, "/b", b"x"),
                (KIND_FILE, "/a", b"y"),
            ]))
            .unwrap_err(),
            FsImageError::Malformed(
                "entries are not strictly sorted by path (unsorted or duplicate)"
            )
        );
        // Duplicate path.
        assert_eq!(
            FsImage::decode(&hand_encode(&[
                (KIND_FILE, "/a", b"x"),
                (KIND_FILE, "/a", b"y"),
            ]))
            .unwrap_err(),
            FsImageError::Malformed(
                "entries are not strictly sorted by path (unsorted or duplicate)"
            )
        );
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
        // Empty component (`//`).
        assert!(matches!(
            FsImage::decode(&hand_encode(&[(KIND_FILE, "/a//b", b"x")])),
            Err(FsImageError::Malformed(_))
        ));
    }

    #[test]
    fn readdir_order_is_sorted_and_host_order_independent() {
        // Same entry set discovered in two different (host readdir) orders must
        // yield byte-identical images and identically sorted guest enumeration.
        let forward = vec![
            FsImageEntry::File {
                path: "/src/a.rs".into(),
                contents: b"fn a".to_vec(),
            },
            FsImageEntry::File {
                path: "/src/b.rs".into(),
                contents: b"fn b".to_vec(),
            },
            FsImageEntry::File {
                path: "/src/c.rs".into(),
                contents: b"fn c".to_vec(),
            },
            FsImageEntry::Directory {
                path: "/src".into(),
            },
        ];
        let mut shuffled = forward.clone();
        shuffled.rotate_left(2);
        shuffled.reverse();

        let image_a = FsImage::new(forward);
        let image_b = FsImage::new(shuffled);
        assert_eq!(image_a.encode(), image_b.encode());

        let mut fs = FsImage::decode(&image_a.encode())
            .unwrap()
            .into_memfs()
            .unwrap();
        let names: Vec<_> = fs
            .read_directory("/src")
            .unwrap()
            .into_iter()
            .map(|entry| entry.name)
            .collect();
        assert_eq!(names, vec!["a.rs", "b.rs", "c.rs"]);
    }
}
