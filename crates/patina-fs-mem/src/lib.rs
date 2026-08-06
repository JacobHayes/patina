//! A small deterministic in-memory filesystem driver.

pub mod image;

pub use image::{FsImage, FsImageEntry, FsImageError};

use std::collections::BTreeMap;

use patina_dst_abi::{
    EffectError, ErrorCode, Fd, FsDirectoryEntry, FsEntryKind, FsMetadata, OpenFlags, SeekWhence,
};
use patina_dst_driver_api::{DriverResult, FsDriver};

type InodeId = u64;
type DescriptionId = u64;

#[derive(Clone, Debug)]
struct Description {
    path: String,
    cursor: usize,
    readable: bool,
    writable: bool,
    kind: FsEntryKind,
    /// Number of fds referencing this open-file description.
    fds: u32,
}

#[derive(Clone, Debug)]
struct Inode {
    contents: Vec<u8>,
    links: u32,
    atime_nanos: u64,
    mtime_nanos: u64,
}

#[derive(Clone, Copy, Debug)]
struct EntryMetadata {
    ino: InodeId,
    atime_nanos: u64,
    mtime_nanos: u64,
}

/// A deterministic in-memory filesystem keyed by normalized absolute paths.
///
/// It models regular files, hard links, inert symlink leaves, directories,
/// cursors, and basic metadata. MemFs has no clock, so access and modification
/// times are not auto-updated by reads or writes; timestamps change only through
/// explicit `set_times` calls.
#[derive(Clone, Default)]
pub struct MemFs {
    files: BTreeMap<String, InodeId>,
    inodes: BTreeMap<InodeId, Inode>,
    symlinks: BTreeMap<String, String>,
    symlink_metadata: BTreeMap<String, EntryMetadata>,
    directories: BTreeMap<String, EntryMetadata>,
    handles: BTreeMap<Fd, DescriptionId>,
    descriptions: BTreeMap<DescriptionId, Description>,
    next_fd: u64,
    next_description: DescriptionId,
    next_inode: InodeId,
}

impl MemFs {
    pub fn new() -> Self {
        let mut filesystem = Self {
            next_fd: 3,
            next_description: 1,
            next_inode: 1,
            ..Self::default()
        };
        let root = filesystem.allocate_entry_metadata();
        filesystem.directories.insert("/".into(), root);
        let tmp = filesystem.allocate_entry_metadata();
        filesystem.directories.insert("/tmp".into(), tmp);
        filesystem
    }

    pub fn with_file(mut self, path: &str, contents: impl Into<Vec<u8>>) -> DriverResult<Self> {
        let path = normalize_path(path)?;
        self.insert_parent_directories(&path);
        let inode = self.allocate_inode(contents.into());
        self.files.insert(path, inode);
        Ok(self)
    }

    pub fn contents(&self, path: &str) -> DriverResult<&[u8]> {
        let path = normalize_path(path)?;
        self.ensure_no_intermediate_symlink(&path)?;
        let inode = self.file_inode(&path)?;
        Ok(self
            .inodes
            .get(&inode)
            .expect("file path references an inode")
            .contents
            .as_slice())
    }

    /// Clone persistent filesystem state without carrying open handles across
    /// a modeled process restart.
    pub fn persistent_snapshot(&self) -> Self {
        let mut snapshot = self.clone();
        snapshot.handles.clear();
        snapshot.descriptions.clear();
        snapshot
    }

    fn allocate_entry_metadata(&mut self) -> EntryMetadata {
        let ino = self.next_inode;
        self.next_inode = self.next_inode.checked_add(1).expect("inode IDs exhausted");
        EntryMetadata {
            ino,
            atime_nanos: 0,
            mtime_nanos: 0,
        }
    }

    fn allocate_inode(&mut self, contents: Vec<u8>) -> InodeId {
        let inode = self.next_inode;
        self.next_inode = self.next_inode.checked_add(1).expect("inode IDs exhausted");
        self.inodes.insert(
            inode,
            Inode {
                contents,
                links: 1,
                atime_nanos: 0,
                mtime_nanos: 0,
            },
        );
        inode
    }

    fn description_mut(&mut self, fd: Fd) -> DriverResult<&mut Description> {
        let id = *self.handles.get(&fd).ok_or_else(|| invalid_fd(fd))?;
        Ok(self
            .descriptions
            .get_mut(&id)
            .expect("handle references a description"))
    }

    fn description(&self, fd: Fd) -> DriverResult<&Description> {
        let id = *self.handles.get(&fd).ok_or_else(|| invalid_fd(fd))?;
        Ok(self
            .descriptions
            .get(&id)
            .expect("handle references a description"))
    }

    fn allocate_handle(
        &mut self,
        path: String,
        cursor: usize,
        readable: bool,
        writable: bool,
        kind: FsEntryKind,
    ) -> DriverResult<Fd> {
        let fd = Fd(self.next_fd);
        self.next_fd = self.next_fd.checked_add(1).ok_or_else(|| {
            EffectError::new(ErrorCode::InvalidHandle, "virtual file handles exhausted")
        })?;
        let description = self.next_description;
        self.next_description = self.next_description.checked_add(1).ok_or_else(|| {
            EffectError::new(
                ErrorCode::InvalidHandle,
                "virtual file descriptions exhausted",
            )
        })?;
        self.descriptions.insert(
            description,
            Description {
                path,
                cursor,
                readable,
                writable,
                kind,
                fds: 1,
            },
        );
        self.handles.insert(fd, description);
        Ok(fd)
    }

    fn file_inode(&self, path: &str) -> DriverResult<InodeId> {
        self.files.get(path).copied().ok_or_else(|| not_found(path))
    }

    fn handle_inode(&self, fd: Fd) -> DriverResult<InodeId> {
        let description = self.description(fd)?;
        self.file_inode(&description.path)
    }

    fn decrement_inode_link(&mut self, inode: InodeId) {
        let entry = self.inodes.get_mut(&inode).expect("inode was checked");
        entry.links -= 1;
        if entry.links == 0 {
            self.inodes.remove(&inode);
        }
    }

    fn path_exists(&self, path: &str) -> bool {
        self.directories.contains_key(path)
            || self.files.contains_key(path)
            || self.symlinks.contains_key(path)
    }

    fn ensure_no_intermediate_symlink(&self, path: &str) -> DriverResult<()> {
        let mut current = String::new();
        for component in path
            .trim_start_matches('/')
            .split('/')
            .filter(|component| !component.is_empty())
        {
            current.push('/');
            current.push_str(component);
            if current != path && self.symlinks.contains_key(&current) {
                return Err(EffectError::new(
                    ErrorCode::Denied,
                    format!(
                        "virtual symlink cannot be traversed as an intermediate component: {current}"
                    ),
                ));
            }
        }
        Ok(())
    }

    fn insert_parent_directories(&mut self, path: &str) {
        let mut parents = Vec::new();
        let mut parent = parent_path(path);
        while parent != "/" {
            if !self.directories.contains_key(parent) {
                parents.push(parent.to_owned());
            }
            parent = parent_path(parent);
        }
        for parent in parents.into_iter().rev() {
            let metadata = self.allocate_entry_metadata();
            self.directories.insert(parent, metadata);
        }
        if !self.directories.contains_key("/") {
            let metadata = self.allocate_entry_metadata();
            self.directories.insert("/".into(), metadata);
        }
    }

    fn set_times_on_metadata(
        atime_nanos: &mut u64,
        mtime_nanos: &mut u64,
        atime: Option<u64>,
        mtime: Option<u64>,
    ) {
        if let Some(value) = atime {
            *atime_nanos = value;
        }
        if let Some(value) = mtime {
            *mtime_nanos = value;
        }
    }
}

impl FsDriver for MemFs {
    fn open(&mut self, path: &str, flags: OpenFlags) -> DriverResult<Fd> {
        let path = normalize_entry_path(path)?;
        self.ensure_no_intermediate_symlink(&path)?;
        if !flags.read && !flags.write {
            return Err(EffectError::new(
                ErrorCode::InvalidInput,
                "open requires read or write access",
            ));
        }
        if (flags.create || flags.truncate || flags.append || flags.exclusive) && !flags.write {
            return Err(EffectError::new(
                ErrorCode::InvalidInput,
                "create, truncate, append, and exclusive flags require write access",
            ));
        }
        if flags.exclusive && !flags.create {
            return Err(EffectError::new(
                ErrorCode::InvalidInput,
                "exclusive open requires create",
            ));
        }
        if self.directories.contains_key(&path) {
            if flags.write || flags.create || flags.truncate || flags.append || flags.exclusive {
                return Err(EffectError::new(
                    ErrorCode::IsDirectory,
                    format!("virtual filesystem path is a directory: {path}"),
                ));
            }
            return self.allocate_handle(path, 0, true, false, FsEntryKind::Directory);
        }
        if self.symlinks.contains_key(&path) {
            return Err(EffectError::new(
                ErrorCode::InvalidInput,
                format!("virtual symlink cannot be opened without host-level follow: {path}"),
            ));
        }

        if !self.files.contains_key(&path) {
            if flags.create {
                self.insert_parent_directories(&path);
                let inode = self.allocate_inode(Vec::new());
                self.files.insert(path.clone(), inode);
            } else {
                return Err(not_found(&path));
            }
        } else if flags.exclusive {
            return Err(EffectError::new(
                ErrorCode::AlreadyExists,
                format!("virtual filesystem entry already exists: {path}"),
            ));
        } else if flags.truncate {
            let inode = self.file_inode(&path)?;
            self.inodes
                .get_mut(&inode)
                .expect("file path references an inode")
                .contents
                .clear();
        }

        let cursor = if flags.append {
            let inode = self.file_inode(&path)?;
            self.inodes
                .get(&inode)
                .expect("file path references an inode")
                .contents
                .len()
        } else {
            0
        };
        self.allocate_handle(path, cursor, flags.read, flags.write, FsEntryKind::File)
    }

    fn read(&mut self, fd: Fd, max_len: usize) -> DriverResult<Vec<u8>> {
        let description = self.description(fd)?;
        if !description.readable {
            return Err(EffectError::new(
                ErrorCode::NotReadable,
                format!("virtual file handle {} is not readable", fd.0),
            ));
        }
        if description.kind == FsEntryKind::Directory {
            return Err(EffectError::new(
                ErrorCode::IsDirectory,
                format!("virtual file handle {} references a directory", fd.0),
            ));
        }
        let path = description.path.clone();
        let start = description.cursor;
        let inode = self.file_inode(&path)?;
        let file = &self
            .inodes
            .get(&inode)
            .expect("open handle references a file")
            .contents;
        let end = start.saturating_add(max_len).min(file.len());
        let bytes = file[start..end].to_vec();
        self.description_mut(fd)?.cursor = end;
        Ok(bytes)
    }

    fn write(&mut self, fd: Fd, bytes: &[u8]) -> DriverResult<usize> {
        let description = self.description(fd)?;
        if !description.writable {
            return Err(EffectError::new(
                ErrorCode::NotWritable,
                format!("virtual file handle {} is not writable", fd.0),
            ));
        }
        if description.kind == FsEntryKind::Directory {
            return Err(EffectError::new(
                ErrorCode::IsDirectory,
                format!("virtual file handle {} references a directory", fd.0),
            ));
        }
        let path = description.path.clone();
        let start = description.cursor;
        let end = start.checked_add(bytes.len()).ok_or_else(|| {
            EffectError::new(ErrorCode::InvalidInput, "virtual file size overflowed")
        })?;
        let inode = self.file_inode(&path)?;
        let file = &mut self
            .inodes
            .get_mut(&inode)
            .expect("open handle references a file")
            .contents;
        if file.len() < end {
            file.resize(end, 0);
        }
        file[start..end].copy_from_slice(bytes);
        self.description_mut(fd)?.cursor = end;
        Ok(bytes.len())
    }

    fn close(&mut self, fd: Fd) -> DriverResult<()> {
        let id = self.handles.remove(&fd).ok_or_else(|| invalid_fd(fd))?;
        let description = self
            .descriptions
            .get_mut(&id)
            .expect("handle references a description");
        description.fds -= 1;
        if description.fds == 0 {
            self.descriptions.remove(&id);
        }
        Ok(())
    }

    fn dup(&mut self, fd: Fd) -> DriverResult<Fd> {
        let id = *self.handles.get(&fd).ok_or_else(|| invalid_fd(fd))?;
        let duplicate = Fd(self.next_fd);
        // Reserve the descriptor number before touching the refcount so an
        // exhausted `next_fd` fails without leaking a description reference.
        self.next_fd = self.next_fd.checked_add(1).ok_or_else(|| {
            EffectError::new(ErrorCode::InvalidHandle, "virtual file handles exhausted")
        })?;
        self.descriptions
            .get_mut(&id)
            .expect("handle references a description")
            .fds += 1;
        self.handles.insert(duplicate, id);
        Ok(duplicate)
    }

    fn seek(&mut self, fd: Fd, offset: i64, whence: SeekWhence) -> DriverResult<u64> {
        let description = self.description(fd)?;
        if description.kind == FsEntryKind::Directory {
            return Err(EffectError::new(
                ErrorCode::InvalidInput,
                format!("virtual directory handle {} cannot be seeked", fd.0),
            ));
        }
        let path = description.path.clone();
        let cursor = description.cursor;
        let inode = self.file_inode(&path)?;
        let base = match whence {
            SeekWhence::Start => 0,
            SeekWhence::Current => cursor,
            SeekWhence::End => self
                .inodes
                .get(&inode)
                .expect("open handle references a file")
                .contents
                .len(),
        };
        let position = i128::try_from(base).expect("usize fits in i128") + i128::from(offset);
        let position = usize::try_from(position).map_err(|_| {
            EffectError::new(
                ErrorCode::InvalidInput,
                format!("virtual seek before start or beyond addressable range: {position}"),
            )
        })?;
        self.description_mut(fd)?.cursor = position;
        u64::try_from(position).map_err(|_| {
            EffectError::new(
                ErrorCode::InvalidInput,
                "virtual seek position does not fit in u64",
            )
        })
    }

    fn metadata(&mut self, path: &str) -> DriverResult<FsMetadata> {
        let path = normalize_entry_path(path)?;
        self.ensure_no_intermediate_symlink(&path)?;
        self.metadata_for_path(&path)
    }

    fn fd_metadata(&mut self, fd: Fd) -> DriverResult<FsMetadata> {
        let path = self.description(fd)?.path.clone();
        self.metadata_for_path(&path)
    }

    fn create_directory(&mut self, path: &str) -> DriverResult<()> {
        let path = normalize_entry_path(path)?;
        self.ensure_no_intermediate_symlink(&path)?;
        if self.path_exists(&path) {
            return Err(EffectError::new(
                ErrorCode::AlreadyExists,
                format!("virtual filesystem entry already exists: {path}"),
            ));
        }
        let parent = parent_path(&path);
        if !self.directories.contains_key(parent) {
            return Err(EffectError::new(
                ErrorCode::NotFound,
                format!("virtual parent directory does not exist: {parent}"),
            ));
        }
        let metadata = self.allocate_entry_metadata();
        self.directories.insert(path, metadata);
        Ok(())
    }

    fn remove_file(&mut self, path: &str) -> DriverResult<()> {
        let path = normalize_entry_path(path)?;
        self.ensure_no_intermediate_symlink(&path)?;
        if self.directories.contains_key(&path) {
            return Err(EffectError::new(
                ErrorCode::IsDirectory,
                format!("virtual filesystem path is a directory: {path}"),
            ));
        }
        if self.symlinks.remove(&path).is_some() {
            self.symlink_metadata.remove(&path);
            return Ok(());
        }
        let inode = self.file_inode(&path)?;
        // MemFs deliberately denies unlink-while-open through any hard-link name
        // for the same inode instead of modeling POSIX anonymous open files.
        if self
            .handles
            .values()
            .filter_map(|id| self.descriptions.get(id))
            .filter_map(|description| self.files.get(&description.path))
            .any(|open_inode| *open_inode == inode)
        {
            return Err(EffectError::new(
                ErrorCode::InvalidState,
                format!("cannot remove open virtual file: {path}"),
            ));
        }
        self.files.remove(&path).expect("file was checked");
        self.decrement_inode_link(inode);
        Ok(())
    }

    fn sync(&mut self, fd: Fd) -> DriverResult<()> {
        self.description(fd).map(|_| ())
    }

    fn set_len(&mut self, fd: Fd, len: u64) -> DriverResult<()> {
        let description = self.description(fd)?;
        if !description.writable {
            return Err(EffectError::new(
                ErrorCode::NotWritable,
                format!("virtual file handle {} is not writable", fd.0),
            ));
        }
        let len = usize::try_from(len).map_err(|_| {
            EffectError::new(
                ErrorCode::InvalidInput,
                "virtual file length exceeds the addressable range",
            )
        })?;
        let inode = self.handle_inode(fd)?;
        self.inodes
            .get_mut(&inode)
            .expect("open handle references a file")
            .contents
            .resize(len, 0);
        Ok(())
    }

    fn set_times(
        &mut self,
        fd: Fd,
        atime_nanos: Option<u64>,
        mtime_nanos: Option<u64>,
    ) -> DriverResult<()> {
        let inode = self.handle_inode(fd)?;
        let inode = self
            .inodes
            .get_mut(&inode)
            .expect("open handle references a file");
        Self::set_times_on_metadata(
            &mut inode.atime_nanos,
            &mut inode.mtime_nanos,
            atime_nanos,
            mtime_nanos,
        );
        Ok(())
    }

    fn set_times_by_path(
        &mut self,
        path: &str,
        atime_nanos: Option<u64>,
        mtime_nanos: Option<u64>,
    ) -> DriverResult<()> {
        let path = normalize_entry_path(path)?;
        self.ensure_no_intermediate_symlink(&path)?;
        if let Some(inode) = self.files.get(&path).copied() {
            let inode = self
                .inodes
                .get_mut(&inode)
                .expect("file path references an inode");
            Self::set_times_on_metadata(
                &mut inode.atime_nanos,
                &mut inode.mtime_nanos,
                atime_nanos,
                mtime_nanos,
            );
            return Ok(());
        }
        if let Some(times) = self.directories.get_mut(&path) {
            Self::set_times_on_metadata(
                &mut times.atime_nanos,
                &mut times.mtime_nanos,
                atime_nanos,
                mtime_nanos,
            );
            return Ok(());
        }
        if let Some(metadata) = self.symlink_metadata.get_mut(&path) {
            Self::set_times_on_metadata(
                &mut metadata.atime_nanos,
                &mut metadata.mtime_nanos,
                atime_nanos,
                mtime_nanos,
            );
            return Ok(());
        }
        Err(not_found(&path))
    }

    fn read_directory(&mut self, path: &str) -> DriverResult<Vec<FsDirectoryEntry>> {
        let path = normalize_entry_path(path)?;
        self.ensure_no_intermediate_symlink(&path)?;
        if self.files.contains_key(&path) || self.symlinks.contains_key(&path) {
            return Err(EffectError::new(
                ErrorCode::NotDirectory,
                format!("virtual filesystem path is not a directory: {path}"),
            ));
        }
        if !self.directories.contains_key(&path) {
            return Err(not_found(&path));
        }
        let prefix = if path == "/" {
            "/".to_owned()
        } else {
            format!("{path}/")
        };
        let mut entries = BTreeMap::new();
        for directory in self.directories.keys() {
            if let Some(relative) = directory.strip_prefix(&prefix) {
                if !relative.is_empty() && !relative.contains('/') {
                    entries.insert(relative.to_owned(), FsEntryKind::Directory);
                }
            }
        }
        for file in self.files.keys() {
            if let Some(relative) = file.strip_prefix(&prefix) {
                if !relative.is_empty() && !relative.contains('/') {
                    entries.insert(relative.to_owned(), FsEntryKind::File);
                }
            }
        }
        for symlink in self.symlinks.keys() {
            if let Some(relative) = symlink.strip_prefix(&prefix) {
                if !relative.is_empty() && !relative.contains('/') {
                    entries.insert(relative.to_owned(), FsEntryKind::Symlink);
                }
            }
        }
        Ok(entries
            .into_iter()
            .map(|(name, kind)| FsDirectoryEntry { name, kind })
            .collect())
    }

    fn remove_directory(&mut self, path: &str) -> DriverResult<()> {
        let path = normalize_entry_path(path)?;
        self.ensure_no_intermediate_symlink(&path)?;
        if path == "/" {
            return Err(EffectError::new(
                ErrorCode::Denied,
                "cannot remove the virtual filesystem root",
            ));
        }
        if self.files.contains_key(&path) || self.symlinks.contains_key(&path) {
            return Err(EffectError::new(
                ErrorCode::NotDirectory,
                format!("virtual filesystem path is not a directory: {path}"),
            ));
        }
        if !self.directories.contains_key(&path) {
            return Err(not_found(&path));
        }
        let prefix = format!("{path}/");
        if self
            .directories
            .keys()
            .any(|candidate| candidate.starts_with(&prefix))
            || self
                .files
                .keys()
                .any(|candidate| candidate.starts_with(&prefix))
            || self
                .symlinks
                .keys()
                .any(|candidate| candidate.starts_with(&prefix))
        {
            return Err(EffectError::new(
                ErrorCode::DirectoryNotEmpty,
                format!("virtual directory is not empty: {path}"),
            ));
        }
        self.directories.remove(&path);
        Ok(())
    }

    fn rename(&mut self, from: &str, to: &str) -> DriverResult<()> {
        let from = normalize_entry_path(from)?;
        let to = normalize_entry_path(to)?;
        self.ensure_no_intermediate_symlink(&from)?;
        self.ensure_no_intermediate_symlink(&to)?;
        if from == "/" || to == "/" || to.starts_with(&format!("{from}/")) {
            return Err(EffectError::new(
                ErrorCode::InvalidInput,
                format!("invalid virtual rename from {from} to {to}"),
            ));
        }
        if !self.directories.contains_key(parent_path(&to)) {
            return Err(not_found(parent_path(&to)));
        }
        if let Some(inode) = self.files.remove(&from) {
            if self.directories.contains_key(&to) {
                self.files.insert(from, inode);
                return Err(EffectError::new(
                    ErrorCode::IsDirectory,
                    format!("virtual rename destination is a directory: {to}"),
                ));
            }
            if let Some(replaced) = self.files.remove(&to) {
                self.decrement_inode_link(replaced);
            }
            self.symlinks.remove(&to);
            self.symlink_metadata.remove(&to);
            self.files.insert(to.clone(), inode);
            for description in self
                .descriptions
                .values_mut()
                .filter(|description| description.path == from)
            {
                description.path.clone_from(&to);
            }
            return Ok(());
        }
        if let Some(target) = self.symlinks.remove(&from) {
            let metadata = self
                .symlink_metadata
                .remove(&from)
                .expect("symlink metadata exists");
            if self.directories.contains_key(&to) {
                self.symlinks.insert(from.clone(), target);
                self.symlink_metadata.insert(from, metadata);
                return Err(EffectError::new(
                    ErrorCode::IsDirectory,
                    format!("virtual rename destination is a directory: {to}"),
                ));
            }
            if let Some(replaced) = self.files.remove(&to) {
                self.decrement_inode_link(replaced);
            }
            self.symlinks.remove(&to);
            self.symlink_metadata.remove(&to);
            self.symlinks.insert(to.clone(), target);
            self.symlink_metadata.insert(to, metadata);
            return Ok(());
        }
        if !self.directories.contains_key(&from) {
            return Err(not_found(&from));
        }
        if self.path_exists(&to) {
            return Err(EffectError::new(
                ErrorCode::AlreadyExists,
                format!("virtual rename destination already exists: {to}"),
            ));
        }
        let prefix = format!("{from}/");
        let moved_directories = self
            .directories
            .keys()
            .filter(|path| **path == from || path.starts_with(&prefix))
            .cloned()
            .collect::<Vec<_>>();
        let moved_files = self
            .files
            .keys()
            .filter(|path| path.starts_with(&prefix))
            .cloned()
            .collect::<Vec<_>>();
        let moved_symlinks = self
            .symlinks
            .keys()
            .filter(|path| path.starts_with(&prefix))
            .cloned()
            .collect::<Vec<_>>();
        for path in moved_directories {
            let times = self
                .directories
                .remove(&path)
                .expect("directory was enumerated");
            self.directories
                .insert(format!("{to}{}", &path[from.len()..]), times);
        }
        for path in moved_files {
            let inode = self.files.remove(&path).expect("file was enumerated");
            self.files
                .insert(format!("{to}{}", &path[from.len()..]), inode);
        }
        for path in moved_symlinks {
            let target = self.symlinks.remove(&path).expect("symlink was enumerated");
            let metadata = self
                .symlink_metadata
                .remove(&path)
                .expect("symlink metadata exists");
            let moved = format!("{to}{}", &path[from.len()..]);
            self.symlinks.insert(moved.clone(), target);
            self.symlink_metadata.insert(moved, metadata);
        }
        for description in self
            .descriptions
            .values_mut()
            .filter(|description| description.path == from || description.path.starts_with(&prefix))
        {
            description.path = if description.path == from {
                to.clone()
            } else {
                format!("{to}{}", &description.path[from.len()..])
            };
        }
        Ok(())
    }

    fn link(&mut self, from: &str, to: &str) -> DriverResult<()> {
        let from = normalize_entry_path(from)?;
        let to = normalize_entry_path(to)?;
        self.ensure_no_intermediate_symlink(&from)?;
        self.ensure_no_intermediate_symlink(&to)?;
        if self.path_exists(&to) {
            return Err(EffectError::new(
                ErrorCode::AlreadyExists,
                format!("virtual filesystem entry already exists: {to}"),
            ));
        }
        if !self.directories.contains_key(parent_path(&to)) {
            return Err(not_found(parent_path(&to)));
        }
        if self.directories.contains_key(&from) {
            return Err(EffectError::new(
                ErrorCode::Denied,
                format!("virtual directory hard links are not supported: {from}"),
            ));
        }
        if let Some(target) = self.symlinks.get(&from).cloned() {
            self.symlinks.insert(to.clone(), target);
            let metadata = self.allocate_entry_metadata();
            self.symlink_metadata.insert(to, metadata);
            return Ok(());
        }
        let inode = self.file_inode(&from)?;
        self.inodes
            .get_mut(&inode)
            .expect("file path references an inode")
            .links += 1;
        self.files.insert(to, inode);
        Ok(())
    }

    fn symlink(&mut self, target: &str, link_path: &str) -> DriverResult<()> {
        if target.contains('\0') {
            return Err(EffectError::new(
                ErrorCode::InvalidInput,
                "virtual symlink target contains NUL",
            ));
        }
        let link_path = normalize_entry_path(link_path)?;
        self.ensure_no_intermediate_symlink(&link_path)?;
        if self.path_exists(&link_path) {
            return Err(EffectError::new(
                ErrorCode::AlreadyExists,
                format!("virtual filesystem entry already exists: {link_path}"),
            ));
        }
        if !self.directories.contains_key(parent_path(&link_path)) {
            return Err(not_found(parent_path(&link_path)));
        }
        self.symlinks.insert(link_path.clone(), target.into());
        let metadata = self.allocate_entry_metadata();
        self.symlink_metadata.insert(link_path, metadata);
        Ok(())
    }

    fn read_link(&mut self, path: &str) -> DriverResult<String> {
        let path = normalize_entry_path(path)?;
        self.ensure_no_intermediate_symlink(&path)?;
        self.symlinks
            .get(&path)
            .cloned()
            .ok_or_else(|| not_found(&path))
    }
}

impl MemFs {
    fn metadata_for_path(&self, path: &str) -> DriverResult<FsMetadata> {
        if let Some(inode_id) = self.files.get(path) {
            let inode = self
                .inodes
                .get(inode_id)
                .expect("file path references an inode");
            return Ok(FsMetadata {
                kind: FsEntryKind::File,
                len: inode.contents.len() as u64,
                ino: *inode_id,
                nlink: inode.links,
                atime_nanos: inode.atime_nanos,
                mtime_nanos: inode.mtime_nanos,
            });
        }
        if let Some(metadata) = self.directories.get(path) {
            return Ok(FsMetadata {
                kind: FsEntryKind::Directory,
                len: 0,
                ino: metadata.ino,
                nlink: 1,
                atime_nanos: metadata.atime_nanos,
                mtime_nanos: metadata.mtime_nanos,
            });
        }
        if let Some(target) = self.symlinks.get(path) {
            let metadata = self
                .symlink_metadata
                .get(path)
                .copied()
                .expect("symlink metadata exists");
            return Ok(FsMetadata {
                kind: FsEntryKind::Symlink,
                len: target.len() as u64,
                ino: metadata.ino,
                nlink: 1,
                atime_nanos: metadata.atime_nanos,
                mtime_nanos: metadata.mtime_nanos,
            });
        }
        Err(not_found(path))
    }
}

fn normalize_path(path: &str) -> DriverResult<String> {
    if !path.starts_with('/') {
        return Err(EffectError::new(
            ErrorCode::InvalidInput,
            format!("virtual filesystem path must be absolute: {path:?}"),
        ));
    }
    if path.contains('\0') {
        return Err(EffectError::new(
            ErrorCode::InvalidInput,
            "virtual filesystem path contains NUL",
        ));
    }

    let mut components = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                return Err(EffectError::new(
                    ErrorCode::InvalidInput,
                    format!("parent traversal is not supported: {path:?}"),
                ));
            }
            value => components.push(value),
        }
    }
    if components.is_empty() {
        return Err(EffectError::new(
            ErrorCode::InvalidInput,
            "the virtual filesystem root is not a file",
        ));
    }
    Ok(format!("/{}", components.join("/")))
}

fn normalize_entry_path(path: &str) -> DriverResult<String> {
    if path == "/" || path.chars().all(|character| character == '/') {
        return Ok("/".into());
    }
    normalize_path(path)
}

fn parent_path(path: &str) -> &str {
    let parent = path.rsplit_once('/').map_or("/", |(parent, _)| parent);
    if parent.is_empty() { "/" } else { parent }
}

fn invalid_fd(fd: Fd) -> EffectError {
    EffectError::new(
        ErrorCode::InvalidHandle,
        format!("virtual file handle {} is not open", fd.0),
    )
}

fn not_found(path: &str) -> EffectError {
    EffectError::new(
        ErrorCode::NotFound,
        format!("virtual file does not exist: {path}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_seeds_root_and_tmp_directories() {
        let mut fs = MemFs::new();
        assert_eq!(fs.metadata("/").unwrap().kind, FsEntryKind::Directory);
        assert_eq!(fs.metadata("/tmp").unwrap().kind, FsEntryKind::Directory);
    }

    #[test]
    fn read_only_directory_open_supports_fstat_fsync_and_close_only() {
        let mut fs = MemFs::new();
        fs.create_directory("/state").unwrap();
        let fd = fs.open("/state", OpenFlags::read_only()).unwrap();
        assert_eq!(fs.fd_metadata(fd).unwrap().kind, FsEntryKind::Directory);
        fs.sync(fd).unwrap();
        assert_eq!(fs.read(fd, 1).unwrap_err().code, ErrorCode::IsDirectory);
        assert_eq!(fs.write(fd, b"x").unwrap_err().code, ErrorCode::NotWritable);
        assert_eq!(
            fs.seek(fd, 0, SeekWhence::Start).unwrap_err().code,
            ErrorCode::InvalidInput
        );
        fs.close(fd).unwrap();

        let write_dir = OpenFlags {
            read: true,
            write: true,
            create: false,
            truncate: false,
            append: false,
            exclusive: false,
        };
        assert_eq!(
            fs.open("/state", write_dir).unwrap_err().code,
            ErrorCode::IsDirectory
        );
    }

    #[test]
    fn writes_reads_and_truncates_files() {
        let mut fs = MemFs::new();
        let write_fd = fs
            .open("/state/value", OpenFlags::create_truncate_write())
            .unwrap();
        assert_eq!(fs.write(write_fd, b"patina").unwrap(), 6);
        fs.close(write_fd).unwrap();

        let read_fd = fs.open("/state//./value", OpenFlags::read_only()).unwrap();
        assert_eq!(fs.read(read_fd, 3).unwrap(), b"pat");
        assert_eq!(fs.read(read_fd, 99).unwrap(), b"ina");
        assert!(fs.read(read_fd, 1).unwrap().is_empty());
        fs.close(read_fd).unwrap();
        assert_eq!(fs.contents("/state/value").unwrap(), b"patina");

        let truncate_fd = fs
            .open("/state/value", OpenFlags::create_truncate_write())
            .unwrap();
        fs.close(truncate_fd).unwrap();
        assert!(fs.contents("/state/value").unwrap().is_empty());
    }

    #[test]
    fn directories_metadata_seek_append_and_remove_are_deterministic() {
        let mut fs = MemFs::new();
        fs.create_directory("/state").unwrap();
        assert_eq!(fs.metadata("/state").unwrap().kind, FsEntryKind::Directory);
        let fd = fs
            .open(
                "/state/value",
                OpenFlags {
                    read: true,
                    write: true,
                    create: true,
                    truncate: false,
                    append: false,
                    exclusive: true,
                },
            )
            .unwrap();
        fs.write(fd, b"patina").unwrap();
        assert_eq!(fs.seek(fd, -3, SeekWhence::End).unwrap(), 3);
        assert_eq!(fs.read(fd, 3).unwrap(), b"ina");
        assert_eq!(fs.fd_metadata(fd).unwrap().len, 6);
        fs.close(fd).unwrap();

        let append = fs
            .open(
                "/state/value",
                OpenFlags {
                    read: false,
                    write: true,
                    create: false,
                    truncate: false,
                    append: true,
                    exclusive: false,
                },
            )
            .unwrap();
        fs.write(append, b"!").unwrap();
        fs.close(append).unwrap();
        assert_eq!(fs.contents("/state/value").unwrap(), b"patina!");
        fs.remove_file("/state/value").unwrap();
        assert_eq!(
            fs.metadata("/state/value").unwrap_err().code,
            ErrorCode::NotFound
        );
    }

    #[test]
    fn missing_and_closed_handles_fail_explicitly() {
        let mut fs = MemFs::new();
        let missing = fs.open("/missing", OpenFlags::read_only()).unwrap_err();
        assert_eq!(missing.code, ErrorCode::NotFound);

        let fd = fs
            .open("/value", OpenFlags::create_truncate_write())
            .unwrap();
        fs.close(fd).unwrap();
        let closed = fs.write(fd, b"no").unwrap_err();
        assert_eq!(closed.code, ErrorCode::InvalidHandle);
    }

    #[test]
    fn dup_shares_cursor_and_is_deterministically_numbered() {
        let mut fs = MemFs::new();
        let write = fs
            .open("/value", OpenFlags::create_truncate_write())
            .unwrap();
        fs.write(write, b"abcdef").unwrap();
        fs.close(write).unwrap();

        let first = fs.open("/value", OpenFlags::read_only()).unwrap();
        let second = fs.dup(first).unwrap();
        assert_eq!(second, Fd(first.0 + 1));
        assert_eq!(fs.read(first, 3).unwrap(), b"abc");
        assert_eq!(fs.read(second, 3).unwrap(), b"def");
        fs.seek(second, 1, SeekWhence::Start).unwrap();
        assert_eq!(fs.read(first, 2).unwrap(), b"bc");
    }

    #[test]
    fn close_of_one_duplicate_keeps_the_description() {
        let mut fs = MemFs::new().with_file("/value", b"abc").unwrap();
        let first = fs.open("/value", OpenFlags::read_only()).unwrap();
        let second = fs.dup(first).unwrap();
        fs.close(first).unwrap();
        assert_eq!(fs.read(second, 1).unwrap(), b"a");
        fs.close(second).unwrap();
        let error = fs.read(second, 1).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidHandle);
        assert_eq!(
            error.message,
            format!("virtual file handle {} is not open", second.0)
        );
    }

    #[test]
    fn dup_of_unknown_fd_is_invalid_handle() {
        let mut fs = MemFs::new();
        let error = fs.dup(Fd(99)).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidHandle);
        assert_eq!(error.message, "virtual file handle 99 is not open");
    }

    #[test]
    fn unlink_while_open_through_a_duplicate_is_denied() {
        let mut fs = MemFs::new().with_file("/value", b"abc").unwrap();
        let first = fs.open("/value", OpenFlags::read_only()).unwrap();
        let second = fs.dup(first).unwrap();
        fs.close(first).unwrap();
        let error = fs.remove_file("/value").unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidState);
        assert_eq!(error.message, "cannot remove open virtual file: /value");
        fs.close(second).unwrap();
    }

    #[test]
    fn persistent_snapshot_drops_descriptions() {
        let mut fs = MemFs::new().with_file("/value", b"abc").unwrap();
        let first = fs.open("/value", OpenFlags::read_only()).unwrap();
        let second = fs.dup(first).unwrap();
        let mut snapshot = fs.persistent_snapshot();
        assert_eq!(
            snapshot.read(first, 1).unwrap_err().code,
            ErrorCode::InvalidHandle
        );
        assert_eq!(
            snapshot.read(second, 1).unwrap_err().code,
            ErrorCode::InvalidHandle
        );
    }

    #[test]
    fn access_modes_and_unsafe_paths_are_rejected() {
        let mut fs = MemFs::new().with_file("/value", b"x").unwrap();
        let read_fd = fs.open("/value", OpenFlags::read_only()).unwrap();
        assert_eq!(
            fs.write(read_fd, b"no").unwrap_err().code,
            ErrorCode::NotWritable
        );
        assert_eq!(
            fs.open("../host", OpenFlags::read_only()).unwrap_err().code,
            ErrorCode::InvalidInput
        );
        assert_eq!(
            fs.open("/safe/../host", OpenFlags::read_only())
                .unwrap_err()
                .code,
            ErrorCode::InvalidInput
        );
    }

    #[test]
    fn hard_links_share_inodes_and_drop_after_last_name() {
        let mut fs = MemFs::new().with_file("/a", b"abc").unwrap();
        fs.link("/a", "/b").unwrap();
        let a_metadata = fs.metadata("/a").unwrap();
        let b_metadata = fs.metadata("/b").unwrap();
        assert_eq!(a_metadata.ino, b_metadata.ino);
        assert_eq!(a_metadata.nlink, 2);
        assert_eq!(b_metadata.nlink, 2);
        let write = fs
            .open(
                "/a",
                OpenFlags {
                    read: false,
                    write: true,
                    create: false,
                    truncate: false,
                    append: true,
                    exclusive: false,
                },
            )
            .unwrap();
        fs.write(write, b"!").unwrap();
        fs.close(write).unwrap();
        assert_eq!(fs.contents("/b").unwrap(), b"abc!");
        fs.remove_file("/a").unwrap();
        assert_eq!(fs.contents("/b").unwrap(), b"abc!");
        let survivor = fs.metadata("/b").unwrap();
        assert_eq!(survivor.ino, b_metadata.ino);
        assert_eq!(survivor.nlink, 1);
        fs.remove_file("/b").unwrap();
        assert_eq!(fs.metadata("/b").unwrap_err().code, ErrorCode::NotFound);
    }

    #[test]
    fn hard_link_removal_is_denied_while_any_inode_name_is_open() {
        let mut fs = MemFs::new().with_file("/a", b"abc").unwrap();
        fs.link("/a", "/b").unwrap();
        let fd = fs.open("/a", OpenFlags::read_only()).unwrap();
        assert_eq!(
            fs.remove_file("/b").unwrap_err().code,
            ErrorCode::InvalidState
        );
        fs.close(fd).unwrap();
        fs.remove_file("/b").unwrap();
    }

    #[test]
    fn symlinks_store_verbatim_targets_and_are_listed() {
        let mut fs = MemFs::new();
        fs.create_directory("/state").unwrap();
        fs.symlink("../missing", "/state/link").unwrap();
        assert_eq!(fs.read_link("/state/link").unwrap(), "../missing");
        let metadata = fs.metadata("/state/link").unwrap();
        assert_eq!(metadata.kind, FsEntryKind::Symlink);
        assert_eq!(metadata.len, 10);
        assert_eq!(
            fs.read_directory("/state").unwrap(),
            vec![FsDirectoryEntry {
                name: "link".into(),
                kind: FsEntryKind::Symlink,
            }]
        );
        assert_eq!(
            fs.open("/state/link/x", OpenFlags::read_only())
                .unwrap_err()
                .code,
            ErrorCode::Denied
        );
        fs.remove_file("/state/link").unwrap();
        assert_eq!(
            fs.read_link("/state/link").unwrap_err().code,
            ErrorCode::NotFound
        );
    }

    #[test]
    fn explicit_timestamp_updates_are_reflected_in_metadata() {
        let mut fs = MemFs::new().with_file("/value", b"x").unwrap();
        let fd = fs.open("/value", OpenFlags::read_only()).unwrap();
        fs.set_times(fd, Some(10), Some(20)).unwrap();
        assert_eq!(fs.fd_metadata(fd).unwrap().atime_nanos, 10);
        assert_eq!(fs.metadata("/value").unwrap().mtime_nanos, 20);
        fs.close(fd).unwrap();
        fs.create_directory("/state").unwrap();
        let state_ino = fs.metadata("/state").unwrap().ino;
        fs.symlink("missing", "/state/link").unwrap();
        let link_metadata = fs.metadata("/state/link").unwrap();
        assert_ne!(state_ino, link_metadata.ino);
        assert_eq!(link_metadata.nlink, 1);
        fs.set_times_by_path("/state", Some(30), None).unwrap();
        fs.set_times_by_path("/state/link", None, Some(40)).unwrap();
        assert_eq!(fs.metadata("/state").unwrap().atime_nanos, 30);
        assert_eq!(fs.metadata("/state/link").unwrap().mtime_nanos, 40);
    }
}
