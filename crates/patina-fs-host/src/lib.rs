//! Explicit, allowlisted, read-only host filesystem capture.
//!
//! The driver maps one virtual mount to one canonical host directory. It is
//! intended for `RuntimeBuilder::with_captured_filesystem`: record mode may
//! read the allowlisted host tree, while replay returns trace outcomes without
//! touching the host. Symlink and parent traversal escapes are rejected.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use patina_dst_abi::{
    EffectError, ErrorCode, Fd, FsDirectoryEntry, FsEntryKind, FsMetadata, OpenFlags, SeekWhence,
};
use patina_dst_driver_api::{DriverResult, FsDriver};

const MAX_CAPTURE_READ: usize = 16 * 1024 * 1024;

pub struct HostCaptureFs {
    virtual_mount: String,
    host_root: PathBuf,
    handles: BTreeMap<Fd, File>,
    next_fd: u64,
}

impl HostCaptureFs {
    pub fn new(virtual_mount: &str, host_root: impl AsRef<Path>) -> DriverResult<Self> {
        let virtual_mount = normalize_virtual_path(virtual_mount, true)?;
        let host_root = fs::canonicalize(host_root.as_ref())
            .map_err(|error| host_error("canonicalize capture root", error))?;
        if !host_root.is_dir() {
            return Err(EffectError::new(
                ErrorCode::NotDirectory,
                format!("capture root is not a directory: {}", host_root.display()),
            ));
        }
        Ok(Self {
            virtual_mount,
            host_root,
            handles: BTreeMap::new(),
            next_fd: 3,
        })
    }

    pub fn virtual_mount(&self) -> &str {
        &self.virtual_mount
    }

    pub fn host_root(&self) -> &Path {
        &self.host_root
    }

    fn resolve_existing(&self, virtual_path: &str) -> DriverResult<PathBuf> {
        let virtual_path = normalize_virtual_path(virtual_path, true)?;
        let relative = if self.virtual_mount == "/" {
            virtual_path.trim_start_matches('/')
        } else if virtual_path == self.virtual_mount {
            ""
        } else {
            virtual_path
                .strip_prefix(&format!("{}/", self.virtual_mount))
                .ok_or_else(|| {
                    EffectError::new(
                        ErrorCode::Denied,
                        format!(
                            "virtual path {virtual_path} is outside capture mount {}",
                            self.virtual_mount
                        ),
                    )
                })?
        };
        let candidate = fs::canonicalize(self.host_root.join(relative))
            .map_err(|error| host_error("resolve captured path", error))?;
        if !candidate.starts_with(&self.host_root) {
            return Err(EffectError::new(
                ErrorCode::Denied,
                format!("captured path escapes allowlisted root: {virtual_path}"),
            ));
        }
        Ok(candidate)
    }

    fn allocate_fd(&mut self, file: File) -> DriverResult<Fd> {
        let fd = Fd(self.next_fd);
        self.next_fd = self.next_fd.checked_add(1).ok_or_else(|| {
            EffectError::new(ErrorCode::InvalidHandle, "capture handles exhausted")
        })?;
        self.handles.insert(fd, file);
        Ok(fd)
    }
}

impl FsDriver for HostCaptureFs {
    fn open(&mut self, path: &str, flags: OpenFlags) -> DriverResult<Fd> {
        if !flags.read
            || flags.write
            || flags.create
            || flags.truncate
            || flags.append
            || flags.exclusive
        {
            return Err(EffectError::new(
                ErrorCode::Denied,
                "host capture permits read-only opens",
            ));
        }
        let path = self.resolve_existing(path)?;
        if path.is_dir() {
            return Err(EffectError::new(
                ErrorCode::IsDirectory,
                format!("captured path is a directory: {}", path.display()),
            ));
        }
        let file = File::open(&path).map_err(|error| host_error("open captured file", error))?;
        self.allocate_fd(file)
    }

    fn read(&mut self, fd: Fd, max_len: usize) -> DriverResult<Vec<u8>> {
        if max_len > MAX_CAPTURE_READ {
            return Err(EffectError::new(
                ErrorCode::InvalidInput,
                format!("capture read exceeds {MAX_CAPTURE_READ} bytes"),
            ));
        }
        let file = self.handles.get_mut(&fd).ok_or_else(|| invalid_fd(fd))?;
        let mut bytes = vec![0; max_len];
        let count = file
            .read(&mut bytes)
            .map_err(|error| host_error("read captured file", error))?;
        bytes.truncate(count);
        Ok(bytes)
    }

    fn write(&mut self, _fd: Fd, _bytes: &[u8]) -> DriverResult<usize> {
        Err(EffectError::new(
            ErrorCode::Denied,
            "host capture filesystem is read-only",
        ))
    }

    fn close(&mut self, fd: Fd) -> DriverResult<()> {
        self.handles
            .remove(&fd)
            .map(|_| ())
            .ok_or_else(|| invalid_fd(fd))
    }

    fn seek(&mut self, fd: Fd, offset: i64, whence: SeekWhence) -> DriverResult<u64> {
        let file = self.handles.get_mut(&fd).ok_or_else(|| invalid_fd(fd))?;
        let position = match whence {
            SeekWhence::Start => {
                let offset = u64::try_from(offset).map_err(|_| {
                    EffectError::new(ErrorCode::InvalidInput, "negative start-relative seek")
                })?;
                SeekFrom::Start(offset)
            }
            SeekWhence::Current => SeekFrom::Current(offset),
            SeekWhence::End => SeekFrom::End(offset),
        };
        file.seek(position)
            .map_err(|error| host_error("seek captured file", error))
    }

    fn metadata(&mut self, path: &str) -> DriverResult<FsMetadata> {
        let path = self.resolve_existing(path)?;
        let metadata =
            fs::metadata(&path).map_err(|error| host_error("read captured metadata", error))?;
        metadata_from_host(&metadata)
    }

    fn fd_metadata(&mut self, fd: Fd) -> DriverResult<FsMetadata> {
        let file = self.handles.get(&fd).ok_or_else(|| invalid_fd(fd))?;
        let metadata = file
            .metadata()
            .map_err(|error| host_error("read captured descriptor metadata", error))?;
        metadata_from_host(&metadata)
    }

    fn read_directory(&mut self, path: &str) -> DriverResult<Vec<FsDirectoryEntry>> {
        let path = self.resolve_existing(path)?;
        if !path.is_dir() {
            return Err(EffectError::new(
                ErrorCode::NotDirectory,
                format!("captured path is not a directory: {}", path.display()),
            ));
        }
        let mut entries = BTreeMap::new();
        for entry in
            fs::read_dir(&path).map_err(|error| host_error("read captured directory", error))?
        {
            let entry =
                entry.map_err(|error| host_error("read captured directory entry", error))?;
            let name = entry.file_name().into_string().map_err(|_| {
                EffectError::new(
                    ErrorCode::InvalidInput,
                    "captured directory contains a non-UTF-8 name",
                )
            })?;
            let resolved = fs::canonicalize(entry.path())
                .map_err(|error| host_error("resolve captured directory entry", error))?;
            if !resolved.starts_with(&self.host_root) {
                return Err(EffectError::new(
                    ErrorCode::Denied,
                    format!("captured directory entry escapes allowlisted root: {name}"),
                ));
            }
            let metadata = fs::metadata(&resolved)
                .map_err(|error| host_error("read captured directory metadata", error))?;
            entries.insert(name, metadata_from_host(&metadata)?.kind);
        }
        Ok(entries
            .into_iter()
            .map(|(name, kind)| FsDirectoryEntry { name, kind })
            .collect())
    }
}

fn metadata_from_host(metadata: &fs::Metadata) -> DriverResult<FsMetadata> {
    let kind = if metadata.is_file() {
        FsEntryKind::File
    } else if metadata.is_dir() {
        FsEntryKind::Directory
    } else {
        return Err(EffectError::new(
            ErrorCode::Denied,
            "captured host entry is neither a regular file nor a directory",
        ));
    };
    Ok(FsMetadata {
        kind,
        len: metadata.len(),
        ino: 0,
        nlink: 1,
        atime_nanos: 0,
        mtime_nanos: 0,
    })
}

fn normalize_virtual_path(path: &str, allow_root: bool) -> DriverResult<String> {
    if !path.starts_with('/') || path.contains('\0') {
        return Err(EffectError::new(
            ErrorCode::InvalidInput,
            format!("capture path must be an absolute NUL-free path: {path:?}"),
        ));
    }
    let mut components = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                return Err(EffectError::new(
                    ErrorCode::Denied,
                    format!("capture path contains parent traversal: {path:?}"),
                ));
            }
            value => components.push(value),
        }
    }
    if components.is_empty() {
        return allow_root.then(|| "/".into()).ok_or_else(|| {
            EffectError::new(ErrorCode::InvalidInput, "capture path refers to root")
        });
    }
    Ok(format!("/{}", components.join("/")))
}

fn invalid_fd(fd: Fd) -> EffectError {
    EffectError::new(
        ErrorCode::InvalidHandle,
        format!("capture file handle {} is not open", fd.0),
    )
}

fn host_error(action: &str, error: std::io::Error) -> EffectError {
    let code = match error.kind() {
        std::io::ErrorKind::NotFound => ErrorCode::NotFound,
        std::io::ErrorKind::PermissionDenied => ErrorCode::Denied,
        std::io::ErrorKind::AlreadyExists => ErrorCode::AlreadyExists,
        std::io::ErrorKind::InvalidInput => ErrorCode::InvalidInput,
        _ => ErrorCode::InvalidState,
    };
    EffectError::new(code, format!("failed to {action}: {error}"))
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn captures_only_read_only_files_under_the_allowlisted_root() {
        let root = tempdir().unwrap();
        fs::create_dir(root.path().join("nested")).unwrap();
        File::create(root.path().join("nested/value"))
            .unwrap()
            .write_all(b"captured")
            .unwrap();
        let mut capture = HostCaptureFs::new("/fixtures", root.path()).unwrap();
        let fd = capture
            .open("/fixtures/nested/value", OpenFlags::read_only())
            .unwrap();
        assert_eq!(capture.read(fd, 99).unwrap(), b"captured");
        assert_eq!(capture.fd_metadata(fd).unwrap().len, 8);
        capture.close(fd).unwrap();
        assert_eq!(capture.read_directory("/fixtures/nested").unwrap().len(), 1);
        assert_eq!(
            capture
                .open("/outside", OpenFlags::read_only())
                .unwrap_err()
                .code,
            ErrorCode::Denied
        );
        assert_eq!(
            capture
                .open("/fixtures/../outside", OpenFlags::read_only())
                .unwrap_err()
                .code,
            ErrorCode::Denied
        );
    }

    #[test]
    fn rejects_symlinks_that_escape_the_capture_root() {
        let root = tempdir().unwrap();
        let outside = tempdir().unwrap();
        fs::write(outside.path().join("secret"), b"host").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(outside.path().join("secret"), root.path().join("escape"))
            .unwrap();
        #[cfg(unix)]
        {
            let mut capture = HostCaptureFs::new("/fixtures", root.path()).unwrap();
            assert_eq!(
                capture
                    .open("/fixtures/escape", OpenFlags::read_only())
                    .unwrap_err()
                    .code,
                ErrorCode::Denied
            );
        }
    }
}
