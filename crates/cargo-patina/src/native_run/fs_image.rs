//! Deterministic filesystem-image capture.

use super::*;
use std::os::unix::fs::MetadataExt;

/// An encoded filesystem image held open in a temporary file, ready to be
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
        format!(
            "{}.{}",
            short_digest(&image.encode_contents()),
            short_digest(&image.encode_metadata())
        )
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
/// suffix the runtime appends. A `+fsimg:` in the user's own label is never taken
/// for it. `None` when the recorded fingerprint is not this run's head followed
/// by some image hash (it differs elsewhere too, or recorded no corpus).
pub(crate) fn recorded_image_hash<'a>(recorded: &'a str, head: &str) -> Option<&'a str> {
    let rest = recorded
        .strip_prefix(head)?
        .strip_prefix(IMAGE_FINGERPRINT_COMPONENT)?;
    let hash = rest.split('+').next().unwrap_or_default();
    (!hash.is_empty()).then_some(hash)
}

fn short_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Capture `host_dir` into a deterministic [`FsImage`], encode it, and write the
/// bytes to a rewound anonymous temporary file the child reads over its
/// inherited image descriptor. The supervisor runs uninterposed, so reading the
/// host tree here is sound; the guest only ever sees the rebuilt image.
pub(super) fn build_fs_image_file(host_dir: &Path) -> Result<FsImageCapture, CliError> {
    use std::io::{Seek, SeekFrom, Write};

    let root = fs::canonicalize(host_dir).map_err(|error| {
        CliError(format!(
            "failed to resolve --mount directory {}: {error}",
            host_dir.display()
        ))
    })?;
    if !root.is_dir() {
        return Err(CliError(format!(
            "--mount target is not a directory: {}",
            root.display()
        )));
    }
    let mut entries = Vec::new();
    collect_fs_entries(&root, "", &mut entries)?;
    let image = FsImage::new(entries);
    let bytes = image.encode();
    let hash = FsImageHash::of(&image);

    let mut file = tempfile::tempfile().map_err(|error| {
        CliError(format!(
            "failed to create filesystem image scratch file: {error}"
        ))
    })?;
    file.write_all(&bytes)
        .map_err(|error| CliError(format!("failed to write filesystem image: {error}")))?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| CliError(format!("failed to rewind filesystem image: {error}")))?;
    Ok(FsImageCapture { file, hash })
}

/// Recursively collect `host_dir`'s contents as [`FsImageEntry`] values, mapping
/// the mount root to the guest root `/`. Symlinks are captured verbatim (their
/// target string, never followed), directories are recorded and descended, and
/// regular files carry their bytes. Each entry carries what a guest can observe
/// of it: its permission bits (not a symlink's, which has none) and its
/// modification time, read without following a symlink. Ownership is not
/// captured: every entry belongs to the guest's own identity. `FsImage::new`
/// sorts the result, so the host `readdir` order never leaks into the
/// deterministic image.
fn collect_fs_entries(
    host_dir: &Path,
    guest_prefix: &str,
    entries: &mut Vec<FsImageEntry>,
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
            entries.push(FsImageEntry::Symlink {
                path: guest_path,
                target,
                mtime_nanos,
            });
        } else if file_type.is_dir() {
            entries.push(FsImageEntry::Directory {
                path: guest_path.clone(),
                mode,
                mtime_nanos,
            });
            collect_fs_entries(&host_path, &guest_path, entries)?;
        } else if file_type.is_file() {
            let contents = fs::read(&host_path).map_err(|error| {
                CliError(format!("failed to read {}: {error}", host_path.display()))
            })?;
            entries.push(FsImageEntry::File {
                path: guest_path,
                contents,
                mode,
                mtime_nanos,
            });
        }
        // Anything else (sockets, devices, fifos) is skipped: a search corpus
        // has none, and the in-memory filesystem cannot model them.
    }
    Ok(())
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
