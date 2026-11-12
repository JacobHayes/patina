//! Deterministic filesystem-image capture.

use super::*;
use crate::mount::Mount;
use std::os::unix::fs::MetadataExt;

/// An encoded filesystem image held open in an anonymous file, ready to be
/// duplicated onto the guest's inherited image descriptor, plus its hash for
/// the run fingerprint: [`FsImageHash`]'s two halves.
pub(crate) struct FsImageCapture {
    pub(crate) file: fs::File,
    pub(crate) hash: String,
}

/// An image's fingerprint hash, `<contents>.<metadata>`: a digest of its
/// paths, kinds and bytes, then of its modes and mtimes, so a replay against a
/// corpus that differs can say which half moved.
pub(crate) struct FsImageHash;

impl FsImageHash {
    fn of(image: &FsImage) -> String {
        let mut contents = HashWriter(Sha256::new());
        let mut metadata = HashWriter(Sha256::new());
        image
            .encode_contents_to(&mut contents)
            .and_then(|()| image.encode_metadata_to(&mut metadata))
            .expect("hashing does not fail");
        format!("{}.{}", short_digest(contents.0), short_digest(metadata.0))
    }

    /// Why a corpus hashing to `current` is not the one a trace recorded as
    /// `recorded`, or `None` when it is.
    pub(crate) fn mismatch(recorded: &str, current: &str) -> Option<MountMismatch> {
        if recorded == current {
            return None;
        }
        let contents = |hash: &str| {
            hash.split_once('.')
                .map(|(contents, _)| contents.to_owned())
        };
        Some(match (contents(recorded), contents(current)) {
            (Some(recorded), Some(current)) if recorded == current => MountMismatch::Metadata,
            _ => MountMismatch::Contents,
        })
    }
}

/// How a re-supplied `--mount` corpus differs from the recorded one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MountMismatch {
    /// Its paths, kinds, bytes or symlink targets.
    Contents,
    /// Only its file modes or modification times: the contents match.
    Metadata,
}

impl MountMismatch {
    /// The input that differs, as the refusal names it (`refusal.mismatch`).
    pub(crate) fn input(self) -> &'static str {
        match self {
            MountMismatch::Contents => "mount_contents",
            MountMismatch::Metadata => "mount_metadata",
        }
    }

    pub(crate) fn describe(self) -> &'static str {
        match self {
            MountMismatch::Contents => {
                "its contents differ (a path, an entry's kind, a file's bytes or a symlink's target)"
            }
            MountMismatch::Metadata => {
                "its contents match but its metadata differs (a mode or a modification time; a fresh \
                 checkout or copy restamps mtimes)"
            }
        }
    }
}

/// The image hash a recorded fingerprint carries where this run's puts one:
/// right after `head` (the base and instrumentation parts), before the policy
/// suffix the runtime appends. `None` when the recorded fingerprint is not this run's head followed
/// by some image hash (it differs elsewhere too, or recorded no corpus).
pub(crate) fn recorded_image_hash<'a>(recorded: &'a str, head: &str) -> Option<&'a str> {
    let rest = recorded
        .strip_prefix(head)?
        .strip_prefix(IMAGE_FINGERPRINT_COMPONENT)?;
    let hash = rest.split('+').next().unwrap_or_default();
    (!hash.is_empty()).then_some(hash)
}

/// A hash fed as bytes are written to it, so an image half is hashed without
/// being held.
struct HashWriter(Sha256);

impl std::io::Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn short_digest(hash: Sha256) -> String {
    hash.finalize()
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Capture `mount`'s host directory into a deterministic [`FsImage`] at its
/// guest directory, encode it, and write the bytes to a rewound anonymous file
/// ([`image_scratch`]) the child reads over its inherited image descriptor. The
/// supervisor runs uninterposed, so reading the host tree here is sound; the
/// guest only ever sees the rebuilt image.
pub(super) fn build_fs_image_file(mount: &Mount) -> Result<FsImageCapture, CliError> {
    use std::io::{Seek, SeekFrom};

    let root = mount.canonical()?.host;
    if !root.is_dir() {
        return Err(CliError(format!(
            "--mount target is not a directory: {}",
            root.display()
        )));
    }
    check_mount_size(mount)?;
    let mut entries = Vec::new();
    mount_point_entries(&root, mount.guest_prefix(), &mut entries)?;
    collect_fs_entries(&root, mount.guest_prefix(), &mut entries)?;
    let image = FsImage::new(link_shared_files(entries));
    let hash = FsImageHash::of(&image);

    let file = image_scratch().map_err(|error| {
        CliError(format!(
            "failed to create filesystem image scratch file: {error}"
        ))
    })?;
    // Streamed: the encoded image is as large as the corpus.
    let write_error = |error| CliError(format!("failed to write filesystem image: {error}"));
    let mut writer = std::io::BufWriter::new(file);
    image.encode_to(&mut writer).map_err(write_error)?;
    let mut file = writer
        .into_inner()
        .map_err(|error| write_error(error.into_error()))?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| CliError(format!("failed to rewind filesystem image: {error}")))?;
    Ok(FsImageCapture { file, hash })
}

/// The most file bytes a mount captures. Every run holds its whole corpus in
/// memory, the supervisor's encoded image and the guest's filesystem, so a
/// tree past this is refused before a byte is read.
pub(crate) const MOUNT_LIMIT_BYTES: u64 = 1 << 30;

/// Refuse a mount whose regular files hold more than [`MOUNT_LIMIT_BYTES`],
/// naming its largest entries, from their metadata alone.
pub(crate) fn check_mount_size(mount: &Mount) -> Result<(), CliError> {
    let root = mount.canonical()?.host;
    let mut sizes: Vec<(u64, PathBuf)> = Vec::new();
    for entry in fs::read_dir(&root).map_err(|error| {
        CliError(format!(
            "failed to read --mount directory {}: {error}",
            root.display()
        ))
    })? {
        let path = entry
            .map_err(|error| {
                CliError(format!(
                    "failed to read entry under {}: {error}",
                    root.display()
                ))
            })?
            .path();
        sizes.push((tree_bytes(&path)?, path));
    }
    let total: u64 = sizes.iter().map(|(bytes, _)| bytes).sum();
    if total <= MOUNT_LIMIT_BYTES {
        return Ok(());
    }
    sizes.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    let largest: Vec<String> = sizes
        .iter()
        .take(3)
        .map(|(bytes, path)| format!("{} ({})", path.display(), gib(*bytes)))
        .collect();
    Err(CliError::usage(format!(
        "--mount {} holds {} of files, more than the {} a run captures into memory; its \
         largest entries: {}. Mount the subdirectory the guest reads instead \
         (--mount HOST_DIR/SUB:GUEST_DIR/SUB)",
        root.display(),
        gib(total),
        gib(MOUNT_LIMIT_BYTES),
        largest.join(", ")
    )))
}

fn gib(bytes: u64) -> String {
    format!("{:.1} GiB", bytes as f64 / f64::from(1u32 << 30))
}

/// The bytes of every regular file at or under `path`, symlinks not followed.
fn tree_bytes(path: &Path) -> Result<u64, CliError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| CliError(format!("failed to stat {}: {error}", path.display())))?;
    if metadata.is_file() {
        return Ok(metadata.len());
    }
    if !metadata.is_dir() {
        return Ok(0);
    }
    let mut total = 0u64;
    for entry in fs::read_dir(path)
        .map_err(|error| CliError(format!("failed to read {}: {error}", path.display())))?
    {
        let entry = entry.map_err(|error| {
            CliError(format!(
                "failed to read entry under {}: {error}",
                path.display()
            ))
        })?;
        total = total.saturating_add(tree_bytes(&entry.path())?);
    }
    Ok(total)
}

/// The directories a mount below the guest root stands on: each ancestor of
/// the guest directory as an image builder's `mkdir` makes one, then the
/// mount point itself with the host directory's own mode and mtime. A mount
/// at `/` adds none, so its image is exactly the corpus's entries.
fn mount_point_entries(
    root: &Path,
    guest_prefix: &str,
    entries: &mut Vec<CapturedEntry>,
) -> Result<(), CliError> {
    if guest_prefix.is_empty() {
        return Ok(());
    }
    let mut ancestor = String::new();
    let parts: Vec<&str> = guest_prefix[1..].split('/').collect();
    for part in &parts[..parts.len() - 1] {
        ancestor.push('/');
        ancestor.push_str(part);
        entries.push(CapturedEntry {
            entry: FsImageEntry::directory(ancestor.clone()),
            inode: None,
        });
    }
    let metadata = fs::metadata(root)
        .map_err(|error| CliError(format!("failed to stat {}: {error}", root.display())))?;
    entries.push(CapturedEntry {
        entry: FsImageEntry::Directory {
            path: guest_prefix.to_owned(),
            mode: metadata.mode() & 0o7777,
            mtime_nanos: i128::from(metadata.mtime()) * 1_000_000_000
                + i128::from(metadata.mtime_nsec()),
        },
        inode: None,
    });
    Ok(())
}

/// Where the encoded image waits for the child: anonymous memory on Linux,
/// where a disk-backed scratch file would put every run's whole corpus
/// through the filesystem's write path; elsewhere an anonymous temporary file.
#[cfg(target_os = "linux")]
fn image_scratch() -> std::io::Result<fs::File> {
    use std::os::fd::FromRawFd;
    // SAFETY: a NUL-terminated name and a flag the kernel defines.
    let fd = unsafe { libc::memfd_create(c"patina-fs-image".as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fd` was just created and nothing else owns it.
    Ok(unsafe { fs::File::from_raw_fd(fd) })
}

#[cfg(not(target_os = "linux"))]
fn image_scratch() -> std::io::Result<fs::File> {
    tempfile::tempfile()
}

/// Recursively collect `host_dir`'s contents as [`FsImageEntry`] values, mapping
/// the mount root to the guest directory `guest_prefix` (`""` for `/`). Symlinks are captured verbatim (their
/// target string, never followed), directories are recorded and descended, and
/// regular files carry their bytes. Each entry carries what a guest can observe
/// of it: its permission bits (not a symlink's, which has none) and its
/// modification time, read without following a symlink. Ownership is not
/// captured: every entry belongs to the guest's own identity. `FsImage::new`
/// sorts the result, so the host `readdir` order never leaks into the
/// deterministic image.
///
/// A regular file with more than one host name is captured as a file with an
/// inode key, so [`link_shared_files`] can turn its other names inside the
/// mount into hard links. Names outside the mount are not seen: such a file
/// arrives with one name.
fn collect_fs_entries(
    host_dir: &Path,
    guest_prefix: &str,
    entries: &mut Vec<CapturedEntry>,
) -> Result<(), CliError> {
    let listing = fs::read_dir(host_dir).map_err(|error| {
        CliError(format!(
            "failed to read --mount directory {}: {error}",
            host_dir.display()
        ))
    })?;
    for entry in listing {
        let entry = entry.map_err(|error| {
            CliError(format!(
                "failed to read entry under {}: {error}",
                host_dir.display()
            ))
        })?;
        let host_path = entry.path();
        let name = entry.file_name().into_string().map_err(|_| {
            CliError(format!(
                "--mount directory contains a non-UTF-8 name under {}",
                host_dir.display()
            ))
        })?;
        let guest_path = format!("{guest_prefix}/{name}");
        // Classify without following symlinks so a symlink stays a symlink in
        // the image, matching how a default recursive file-walk lstat's and skips it.
        let metadata = fs::symlink_metadata(&host_path).map_err(|error| {
            CliError(format!("failed to stat {}: {error}", host_path.display()))
        })?;
        let file_type = metadata.file_type();
        let mode = metadata.mode() & 0o7777;
        let mtime_nanos =
            i128::from(metadata.mtime()) * 1_000_000_000 + i128::from(metadata.mtime_nsec());
        if file_type.is_symlink() {
            let target = fs::read_link(&host_path)
                .map_err(|error| {
                    CliError(format!(
                        "failed to read symlink {}: {error}",
                        host_path.display()
                    ))
                })?
                .into_os_string()
                .into_string()
                .map_err(|_| {
                    CliError(format!(
                        "symlink {} has a non-UTF-8 target",
                        host_path.display()
                    ))
                })?;
            entries.push(CapturedEntry {
                entry: FsImageEntry::Symlink {
                    path: guest_path,
                    target,
                    mtime_nanos,
                },
                inode: None,
            });
        } else if file_type.is_dir() {
            entries.push(CapturedEntry {
                entry: FsImageEntry::Directory {
                    path: guest_path.clone(),
                    mode,
                    mtime_nanos,
                },
                inode: None,
            });
            collect_fs_entries(&host_path, &guest_path, entries)?;
        } else if file_type.is_file() {
            let contents = fs::read(&host_path).map_err(|error| {
                CliError(format!("failed to read {}: {error}", host_path.display()))
            })?;
            let inode = (metadata.nlink() > 1).then(|| (metadata.dev(), metadata.ino()));
            entries.push(CapturedEntry {
                entry: FsImageEntry::File {
                    path: guest_path,
                    contents,
                    mode,
                    mtime_nanos,
                },
                inode,
            });
        }
        // Anything else (sockets, devices, fifos) is skipped: a search corpus
        // has none, and the in-memory filesystem cannot model them.
    }
    Ok(())
}

/// One captured entry, with the host `(device, inode)` of a regular file
/// that has more than one name.
struct CapturedEntry {
    entry: FsImageEntry,
    inode: Option<(u64, u64)>,
}

/// Give every group of captured names that share a host inode one node in the
/// image: the group's first path in sorted order keeps the file entry, and each
/// other name becomes a hard link to it. The choice depends only on the paths,
/// never on `readdir` order.
fn link_shared_files(captured: Vec<CapturedEntry>) -> Vec<FsImageEntry> {
    use std::collections::BTreeMap;

    let mut first: BTreeMap<(u64, u64), String> = BTreeMap::new();
    for captured in &captured {
        if let (Some(inode), FsImageEntry::File { path, .. }) = (captured.inode, &captured.entry) {
            first
                .entry(inode)
                .and_modify(|kept| {
                    if path < kept {
                        kept.clone_from(path);
                    }
                })
                .or_insert_with(|| path.clone());
        }
    }
    captured
        .into_iter()
        .map(|captured| match (captured.inode, captured.entry) {
            (Some(inode), FsImageEntry::File { path, .. }) if first[&inode] != path => {
                FsImageEntry::HardLink {
                    target: first[&inode].clone(),
                    path,
                }
            }
            (_, entry) => entry,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mismatch_names_the_half_that_moved() {
        let base = FsImage::new(vec![FsImageEntry::file("/a", "x")]);
        let restamped = FsImage::new(vec![FsImageEntry::File {
            path: "/a".into(),
            contents: b"x".to_vec(),
            mode: 0o644,
            mtime_nanos: 1,
        }]);
        let edited = FsImage::new(vec![FsImageEntry::file("/a", "y")]);
        let hash = FsImageHash::of(&base);
        assert_eq!(FsImageHash::mismatch(&hash, &hash), None);
        assert_eq!(
            FsImageHash::mismatch(&hash, &FsImageHash::of(&restamped)),
            Some(MountMismatch::Metadata)
        );
        assert_eq!(
            FsImageHash::mismatch(&hash, &FsImageHash::of(&edited)),
            Some(MountMismatch::Contents)
        );
    }

    /// Names that share a host inode inside the mount capture as one file and
    /// hard links to it, whichever name readdir returns first; a file whose
    /// other name is outside the mount captures as a plain file.
    #[test]
    fn shared_inodes_capture_as_hard_links() {
        let scratch = tempfile::tempdir().unwrap();
        let mount = scratch.path().join("mount");
        fs::create_dir_all(mount.join("sub")).unwrap();
        fs::write(mount.join("sub/z"), "shared").unwrap();
        fs::hard_link(mount.join("sub/z"), mount.join("a")).unwrap();
        fs::hard_link(mount.join("sub/z"), mount.join("m")).unwrap();
        fs::write(mount.join("inside"), "half").unwrap();
        fs::hard_link(mount.join("inside"), scratch.path().join("outside")).unwrap();

        let mut captured = Vec::new();
        collect_fs_entries(&mount, "", &mut captured).unwrap();
        let image = FsImage::new(link_shared_files(captured));
        let kinds: Vec<(&str, Option<&str>)> = image
            .entries()
            .iter()
            .filter_map(|entry| match entry {
                FsImageEntry::File { path, .. } => Some((path.as_str(), None)),
                FsImageEntry::HardLink { path, target } => {
                    Some((path.as_str(), Some(target.as_str())))
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            kinds,
            vec![
                ("/a", None),
                ("/inside", None),
                ("/m", Some("/a")),
                ("/sub/z", Some("/a"))
            ]
        );
        use patina_dst_driver_api::FsDriver as _;
        let mut fs = FsImage::decode(&image.encode())
            .unwrap()
            .into_memfs()
            .unwrap();
        assert_eq!(fs.metadata("/sub/z").unwrap().nlink, 3);
        assert_eq!(fs.metadata("/inside").unwrap().nlink, 1);
    }

    /// The hash is the component right after the run's own head, a `+fsimg:` in
    /// the label notwithstanding, and ends where the runtime's policy suffix
    /// begins; a fingerprint that differs in the head carries none this run can
    /// compare.
    #[test]
    fn the_image_hash_is_read_where_the_fingerprint_puts_it() {
        for label in ["label+fsimg:custom", "a+fsimg:b+fsimg:c", "base"] {
            let head = instrumentation_fingerprint(label, Default::default());
            for policy in ["", "+buggify", "+pct+swarm+yieldstride"] {
                let recorded = format!(
                    "{}{policy}",
                    native_run_fingerprint(label, Default::default(), Some("aa.bb"))
                );
                assert_eq!(
                    recorded_image_hash(&recorded, &head),
                    Some("aa.bb"),
                    "{label} {policy}"
                );
                let other = instrumentation_fingerprint("other", Default::default());
                assert_eq!(recorded_image_hash(&recorded, &other), None);
                assert_eq!(recorded_image_hash(&format!("{head}{policy}"), &head), None);
            }
        }
    }
}
