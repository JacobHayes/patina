//! A small deterministic in-memory filesystem driver.

pub mod image;
pub mod snapshot;

pub use image::{FsImage, FsImageEntry, FsImageError};
pub use snapshot::{FsSnapshot, FsSnapshotError};

use std::collections::BTreeMap;

use patina_dst_abi::{
    EffectError, ErrorCode, Fd, FsDirectoryEntry, FsEntryKind, FsMetadata, OpenFlags, SeekWhence,
};
use patina_dst_driver_api::{DriverResult, FsDriver};

type InodeId = u64;
type DescriptionId = u64;

/// The permission mask a mode is stored under (`setuid`/`setgid`/sticky plus
/// the three triads); the file-type bits live in [`FsEntryKind`].
pub const MODE_MASK: u32 = 0o7777;
/// The fixed umask this filesystem models, applied to the POSIX creation modes.
pub const UMASK: u32 = 0o022;
/// A newly created regular file: `0o666 & !UMASK`.
pub const FILE_MODE: u32 = 0o666 & !UMASK;
/// A newly created directory: `0o777 & !UMASK`.
pub const DIRECTORY_MODE: u32 = 0o777 & !UMASK;
/// A symlink leaf. Linux ignores a symlink's own mode entirely and reports the
/// conventional `0o777`; nothing here consults it.
pub const SYMLINK_MODE: u32 = 0o777;

/// Owner-triad permission bits, as POSIX spells them.
const READ: u32 = 0o4;
const WRITE: u32 = 0o2;
const SEARCH: u32 = 0o1;

/// Does the single modeled (owning, non-root) identity hold every bit in `want`?
fn owner_allows(mode: u32, want: u32) -> bool {
    ((mode >> 6) & 0o7) & want == want
}

#[derive(Clone, Debug)]
struct Description {
    path: String,
    cursor: usize,
    readable: bool,
    writable: bool,
    append: bool,
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
    /// POSIX permission bits (`0o7777`), without the file-type bits.
    mode: u32,
}

#[derive(Clone, Copy, Debug)]
struct EntryMetadata {
    ino: InodeId,
    atime_nanos: u64,
    mtime_nanos: u64,
    /// POSIX permission bits (`0o7777`), without the file-type bits.
    mode: u32,
}

/// A deterministic in-memory filesystem keyed by normalized absolute paths.
///
/// It models regular files, hard links, inert symlink leaves, named pipes
/// (`mkfifo` — the NAME and its mode; the bytes belong to the openers' pipe
/// channel, not to the filesystem), directories, cursors, basic metadata, and
/// POSIX permission bits. MemFs has no clock, so
/// access and modification times are not auto-updated by reads or writes;
/// timestamps change only through explicit `set_times` calls.
///
/// # Permissions
///
/// Every entry carries a mode. New files are `0o644` and new directories
/// `0o755` — the POSIX creation modes `0o666`/`0o777` under the fixed `0o022`
/// umask this filesystem models — and symlink leaves are the conventional
/// `0o777`. The guest is a single non-root identity (uid/gid 1000, the value the
/// native shim's `getuid` reports) and owns every entry, so enforcement reads
/// the OWNER triad: read needs `r`, write needs `w`, resolving a path through a
/// directory needs `x` on that directory, listing one needs `r`, and creating,
/// removing, or renaming a name inside one needs `w` and `x`. There is no
/// root-bypass identity, so a mode change is always enforced.
#[derive(Clone, Default)]
pub struct MemFs {
    files: BTreeMap<String, InodeId>,
    inodes: BTreeMap<InodeId, Inode>,
    symlinks: BTreeMap<String, String>,
    symlink_metadata: BTreeMap<String, EntryMetadata>,
    /// Named pipes, by path. A FIFO is a NAME and a mode and nothing else: the
    /// bytes that flow through it are not filesystem state, so no inode and no
    /// contents hang off one here.
    fifos: BTreeMap<String, EntryMetadata>,
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
        let root = filesystem.allocate_entry_metadata(DIRECTORY_MODE);
        filesystem.directories.insert("/".into(), root);
        let tmp = filesystem.allocate_entry_metadata(DIRECTORY_MODE);
        filesystem.directories.insert("/tmp".into(), tmp);
        filesystem
    }

    pub fn with_file(mut self, path: &str, contents: impl Into<Vec<u8>>) -> DriverResult<Self> {
        let path = normalize_path(path)?;
        self.insert_parent_directories(&path);
        let inode = self.allocate_inode(contents.into(), FILE_MODE);
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
        snapshot.next_fd = 3;
        snapshot.next_description = 1;
        snapshot
    }

    /// Export a canonical, versioned restart snapshot. Open descriptors and
    /// descriptions are deliberately omitted; inode identity, timestamps, names,
    /// contents, and future inode allocation state are preserved.
    pub fn export_snapshot(&self) -> FsSnapshot {
        FsSnapshot::from_memfs(self)
    }

    /// Import a restart snapshot as a fresh filesystem image with no descriptors.
    pub fn import_snapshot(snapshot: &FsSnapshot) -> Self {
        snapshot.into_memfs()
    }

    /// The paths a live descriptor currently names, with the entry kind each was
    /// opened as, deduplicated and in path order.
    ///
    /// A crash model reads this to keep the guest's descriptors meaningful
    /// across a rebuilt image: see [`MemFs::adopt_handles`].
    pub fn open_entries(&self) -> BTreeMap<String, FsEntryKind> {
        self.handles
            .values()
            .filter_map(|id| self.descriptions.get(id))
            .map(|description| (description.path.clone(), description.kind))
            .collect()
    }

    /// Carry `previous`'s open descriptor table onto this image.
    ///
    /// A crash model rebuilds the post-crash filesystem as a fresh [`MemFs`];
    /// without this the guest's still-open descriptors would all become
    /// unknown handles, and every later read/write/close on one would fail
    /// `InvalidHandle` — `EBADF` at the POSIX boundary. No real storage failure
    /// does that: a descriptor is the process's own object, and power loss
    /// cannot reach into a running process and close its files. Injecting
    /// `EBADF` would test the guest against an impossible world, so the table
    /// moves across intact.
    ///
    /// Descriptor and description IDs advance past the previous image's, so a
    /// post-crash `open` can never hand back a number the guest still believes
    /// is live.
    pub fn adopt_handles(&mut self, previous: &Self) {
        self.handles.clone_from(&previous.handles);
        self.descriptions.clone_from(&previous.descriptions);
        self.next_fd = self.next_fd.max(previous.next_fd);
        self.next_description = self.next_description.max(previous.next_description);
    }

    fn allocate_entry_metadata(&mut self, mode: u32) -> EntryMetadata {
        let ino = self.next_inode;
        self.next_inode = self.next_inode.checked_add(1).expect("inode IDs exhausted");
        EntryMetadata {
            ino,
            atime_nanos: 0,
            mtime_nanos: 0,
            mode: mode & MODE_MASK,
        }
    }

    fn allocate_inode(&mut self, contents: Vec<u8>, mode: u32) -> InodeId {
        let inode = self.next_inode;
        self.next_inode = self.next_inode.checked_add(1).expect("inode IDs exhausted");
        self.inodes.insert(
            inode,
            Inode {
                contents,
                links: 1,
                atime_nanos: 0,
                mtime_nanos: 0,
                mode: mode & MODE_MASK,
            },
        );
        inode
    }

    /// The permission bits of an existing entry, or `None` when nothing is
    /// there. Symlink leaves answer [`SYMLINK_MODE`]: Linux never consults a
    /// link's own mode.
    fn entry_mode(&self, path: &str) -> Option<u32> {
        if let Some(inode) = self.files.get(path) {
            return Some(
                self.inodes
                    .get(inode)
                    .expect("file references an inode")
                    .mode,
            );
        }
        if let Some(metadata) = self.directories.get(path) {
            return Some(metadata.mode);
        }
        if let Some(metadata) = self.fifos.get(path) {
            return Some(metadata.mode);
        }
        self.symlinks.get(path).map(|_| SYMLINK_MODE)
    }

    /// Resolving a path walks every directory ABOVE the final component, and
    /// each of those needs `x`. Checked before existence, as the kernel does:
    /// an unsearchable directory answers `EACCES`, never "not found", so the
    /// names behind it cannot be probed through the error code.
    fn check_search_path(&self, path: &str) -> DriverResult<()> {
        if path != "/" {
            if let Some(root) = self.directories.get("/") {
                if !owner_allows(root.mode, SEARCH) {
                    return Err(denied("/", "search"));
                }
            }
        }
        let mut current = String::new();
        for component in path
            .trim_start_matches('/')
            .split('/')
            .filter(|component| !component.is_empty())
        {
            current.push('/');
            current.push_str(component);
            if current.len() >= path.len() {
                // The final component is the entry itself, not a directory the
                // resolution passes THROUGH.
                break;
            }
            if let Some(metadata) = self.directories.get(&current) {
                if !owner_allows(metadata.mode, SEARCH) {
                    return Err(denied(&current, "search"));
                }
            }
        }
        Ok(())
    }

    /// Creating, removing, or renaming a NAME inside a directory is a write to
    /// that directory: `w` and `x` both.
    fn check_directory_write(&self, directory: &str) -> DriverResult<()> {
        if let Some(metadata) = self.directories.get(directory) {
            if !owner_allows(metadata.mode, WRITE | SEARCH) {
                return Err(denied(directory, "modify"));
            }
        }
        Ok(())
    }

    /// The guard every path-taking entry point runs first: no symlink in the
    /// interior, then `x` on every directory above the final component.
    fn resolve_guard(&self, path: &str) -> DriverResult<()> {
        self.ensure_no_intermediate_symlink(path)?;
        self.check_search_path(path)
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
        append: bool,
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
                append,
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
            || self.fifos.contains_key(path)
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
            let metadata = self.allocate_entry_metadata(DIRECTORY_MODE);
            self.directories.insert(parent, metadata);
        }
        if !self.directories.contains_key("/") {
            let metadata = self.allocate_entry_metadata(DIRECTORY_MODE);
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
        self.resolve_guard(&path)?;
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
        if let Some(metadata) = self.directories.get(&path).copied() {
            if flags.write || flags.create || flags.truncate || flags.append || flags.exclusive {
                return Err(EffectError::new(
                    ErrorCode::IsDirectory,
                    format!("virtual filesystem path is a directory: {path}"),
                ));
            }
            // A directory descriptor is a handle on the node, so `x` (search) is
            // what it costs. The `r` a listing needs is charged at
            // `read_directory`, which is also where a descriptor opened
            // `O_PATH` — indistinguishable here, since a path-only open is not
            // part of the driver's flag vocabulary — would pay it.
            if !owner_allows(metadata.mode, SEARCH) {
                return Err(denied(&path, "open"));
            }
            return self.allocate_handle(path, 0, true, false, false, FsEntryKind::Directory);
        }
        if let Some(metadata) = self.fifos.get(&path).copied() {
            // The permission decision belongs HERE — one enforcement point for
            // every kind — even though the descriptor itself is not a filesystem
            // descriptor. Opening a FIFO for reading needs `r` and for writing
            // needs `w`, exactly as a regular file does.
            if flags.exclusive {
                return Err(EffectError::new(
                    ErrorCode::AlreadyExists,
                    format!("virtual filesystem entry already exists: {path}"),
                ));
            }
            if flags.read && !owner_allows(metadata.mode, READ) {
                return Err(denied(&path, "read"));
            }
            if flags.write && !owner_allows(metadata.mode, WRITE) {
                return Err(denied(&path, "write"));
            }
            // A FIFO carries no filesystem bytes, so there is no filesystem
            // description to hand back: the caller opens the pipe the FIFO's
            // openers share. The permission and existence answers above are the
            // part that IS filesystem state, and they have been given.
            return Err(EffectError::new(
                ErrorCode::InvalidInput,
                format!(
                    "virtual named pipe is opened through the pipe boundary, not as a filesystem descriptor: {path}"
                ),
            ));
        }
        if self.symlinks.contains_key(&path) {
            return Err(EffectError::new(
                ErrorCode::InvalidInput,
                format!("virtual symlink cannot be opened without host-level follow: {path}"),
            ));
        }

        if !self.files.contains_key(&path) {
            if flags.create {
                self.check_directory_write(parent_path(&path))?;
                self.insert_parent_directories(&path);
                let inode = self.allocate_inode(Vec::new(), FILE_MODE);
                self.files.insert(path.clone(), inode);
            } else {
                return Err(not_found(&path));
            }
        } else if flags.exclusive {
            return Err(EffectError::new(
                ErrorCode::AlreadyExists,
                format!("virtual filesystem entry already exists: {path}"),
            ));
        } else {
            let mode = self
                .entry_mode(&path)
                .expect("the file was found in this branch");
            if flags.read && !owner_allows(mode, READ) {
                return Err(denied(&path, "read"));
            }
            if flags.write && !owner_allows(mode, WRITE) {
                return Err(denied(&path, "write"));
            }
            if flags.truncate {
                let inode = self.file_inode(&path)?;
                self.inodes
                    .get_mut(&inode)
                    .expect("file path references an inode")
                    .contents
                    .clear();
            }
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
        self.allocate_handle(
            path,
            cursor,
            flags.read,
            flags.write,
            flags.append,
            FsEntryKind::File,
        )
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
        let cursor = description.cursor;
        let append = description.append;
        let inode = self.file_inode(&path)?;
        let file = &mut self
            .inodes
            .get_mut(&inode)
            .expect("open handle references a file")
            .contents;
        let start = if append { file.len() } else { cursor };
        let end = start.checked_add(bytes.len()).ok_or_else(|| {
            EffectError::new(ErrorCode::InvalidInput, "virtual file size overflowed")
        })?;
        if file.len() < end {
            file.resize(end, 0);
        }
        file[start..end].copy_from_slice(bytes);
        self.description_mut(fd)?.cursor = end;
        Ok(bytes.len())
    }

    fn write_at(&mut self, fd: Fd, offset: u64, bytes: &[u8]) -> DriverResult<usize> {
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
        let start = usize::try_from(offset).map_err(|_| {
            EffectError::new(
                ErrorCode::InvalidInput,
                "virtual write offset exceeds the addressable range",
            )
        })?;
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
        self.resolve_guard(&path)?;
        self.metadata_for_path(&path)
    }

    fn fd_metadata(&mut self, fd: Fd) -> DriverResult<FsMetadata> {
        let path = self.description(fd)?.path.clone();
        self.metadata_for_path(&path)
    }

    fn create_directory(&mut self, path: &str) -> DriverResult<()> {
        let path = normalize_entry_path(path)?;
        self.resolve_guard(&path)?;
        self.check_directory_write(parent_path(&path))?;
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
        let metadata = self.allocate_entry_metadata(DIRECTORY_MODE);
        self.directories.insert(path, metadata);
        Ok(())
    }

    fn make_fifo(&mut self, path: &str, mode: u32) -> DriverResult<()> {
        let path = normalize_entry_path(path)?;
        self.resolve_guard(&path)?;
        self.check_directory_write(parent_path(&path))?;
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
        // The caller's mode IS honored here (unlike `open`'s and `mkdir`'s,
        // which this boundary does not carry) with the modeled umask applied,
        // exactly as the kernel applies the process umask to `mkfifo`.
        let metadata = self.allocate_entry_metadata(mode & !UMASK);
        self.fifos.insert(path, metadata);
        Ok(())
    }

    fn remove_file(&mut self, path: &str) -> DriverResult<()> {
        let path = normalize_entry_path(path)?;
        self.resolve_guard(&path)?;
        self.check_directory_write(parent_path(&path))?;
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
        // A FIFO name goes away on unlink whatever is open on it: the openers
        // hold the pipe, not the name, so nothing is lost by unlinking one and
        // the kernel does not refuse it either.
        if self.fifos.remove(&path).is_some() {
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
        self.resolve_guard(&path)?;
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
        if let Some(metadata) = self.fifos.get_mut(&path) {
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
        self.resolve_guard(&path)?;
        if self.files.contains_key(&path)
            || self.symlinks.contains_key(&path)
            || self.fifos.contains_key(&path)
        {
            return Err(EffectError::new(
                ErrorCode::NotDirectory,
                format!("virtual filesystem path is not a directory: {path}"),
            ));
        }
        let Some(metadata) = self.directories.get(&path).copied() else {
            return Err(not_found(&path));
        };
        // Listing a directory reads it, so `r` is what it costs — separately
        // from the `x` that resolving a path THROUGH it costs.
        if !owner_allows(metadata.mode, READ) {
            return Err(denied(&path, "list"));
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
        for fifo in self.fifos.keys() {
            if let Some(relative) = fifo.strip_prefix(&prefix) {
                if !relative.is_empty() && !relative.contains('/') {
                    entries.insert(relative.to_owned(), FsEntryKind::Fifo);
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
        self.resolve_guard(&path)?;
        self.check_directory_write(parent_path(&path))?;
        if path == "/" {
            return Err(EffectError::new(
                ErrorCode::Denied,
                "cannot remove the virtual filesystem root",
            ));
        }
        if self.files.contains_key(&path)
            || self.symlinks.contains_key(&path)
            || self.fifos.contains_key(&path)
        {
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
            || self
                .fifos
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
        self.resolve_guard(&from)?;
        self.resolve_guard(&to)?;
        self.check_directory_write(parent_path(&from))?;
        self.check_directory_write(parent_path(&to))?;
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
            self.fifos.remove(&to);
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
            self.fifos.remove(&to);
            self.symlinks.insert(to.clone(), target);
            self.symlink_metadata.insert(to, metadata);
            return Ok(());
        }
        // A FIFO renames like any other leaf: the NAME moves and the entry keeps
        // its inode identity and mode. Anything already open on it holds the
        // pipe, not the name, so nothing about the transfer changes.
        if let Some(metadata) = self.fifos.remove(&from) {
            if self.directories.contains_key(&to) {
                self.fifos.insert(from, metadata);
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
            self.fifos.remove(&to);
            self.fifos.insert(to, metadata);
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
        self.resolve_guard(&from)?;
        self.resolve_guard(&to)?;
        self.check_directory_write(parent_path(&to))?;
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
            let metadata = self.allocate_entry_metadata(SYMLINK_MODE);
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
        self.resolve_guard(&link_path)?;
        self.check_directory_write(parent_path(&link_path))?;
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
        let metadata = self.allocate_entry_metadata(SYMLINK_MODE);
        self.symlink_metadata.insert(link_path, metadata);
        Ok(())
    }

    fn read_link(&mut self, path: &str) -> DriverResult<String> {
        let path = normalize_entry_path(path)?;
        self.resolve_guard(&path)?;
        self.symlinks
            .get(&path)
            .cloned()
            .ok_or_else(|| not_found(&path))
    }

    /// `chmod` / `fchmodat`. Changing a mode is an OWNER right, not a
    /// permission-bit right, and the single modeled identity owns every entry —
    /// so only REACHING the entry is checked, never the entry's own bits.
    ///
    /// A symlink leaf has no mode of its own here (Linux ignores one too), so
    /// naming a link fails closed rather than silently recording a mode nothing
    /// will ever read. `chmod`'s follow-the-link spelling resolves above this
    /// boundary and arrives naming the target.
    fn set_mode(&mut self, path: &str, mode: u32) -> DriverResult<()> {
        let path = normalize_entry_path(path)?;
        self.resolve_guard(&path)?;
        if self.symlinks.contains_key(&path) {
            return Err(EffectError::new(
                ErrorCode::Denied,
                format!("virtual symlink has no mode of its own: {path}"),
            ));
        }
        self.apply_mode(&path, mode)
    }

    fn set_fd_mode(&mut self, fd: Fd, mode: u32) -> DriverResult<()> {
        let path = self.description(fd)?.path.clone();
        self.apply_mode(&path, mode)
    }

    /// The path this descriptor's NODE currently has — see
    /// [`FsDriver::fd_path`]. A description is bound to the node, and every
    /// rename that moves the node rewrites the descriptions that reference it,
    /// so this answers where the node IS rather than the name it was opened
    /// under.
    fn fd_path(&mut self, fd: Fd) -> DriverResult<String> {
        Ok(self.description(fd)?.path.clone())
    }
}

impl MemFs {
    /// Write `mode`'s permission bits onto the entry `path` names.
    fn apply_mode(&mut self, path: &str, mode: u32) -> DriverResult<()> {
        let mode = mode & MODE_MASK;
        if let Some(inode) = self.files.get(path).copied() {
            self.inodes
                .get_mut(&inode)
                .expect("file path references an inode")
                .mode = mode;
            return Ok(());
        }
        if let Some(metadata) = self.directories.get_mut(path) {
            metadata.mode = mode;
            return Ok(());
        }
        if let Some(metadata) = self.fifos.get_mut(path) {
            metadata.mode = mode;
            return Ok(());
        }
        Err(not_found(path))
    }

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
                mode: inode.mode,
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
                mode: metadata.mode,
            });
        }
        if let Some(metadata) = self.fifos.get(path) {
            return Ok(FsMetadata {
                kind: FsEntryKind::Fifo,
                len: 0,
                ino: metadata.ino,
                nlink: 1,
                atime_nanos: metadata.atime_nanos,
                mtime_nanos: metadata.mtime_nanos,
                mode: metadata.mode,
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
                mode: SYMLINK_MODE,
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

/// A permission refusal. [`ErrorCode::Denied`] is the code the POSIX boundary
/// renders as `EACCES`, so a guest reads it as `PermissionDenied` — the answer
/// that has to stay distinguishable from "not found" and from a sandbox's own
/// confinement refusal.
fn denied(path: &str, action: &str) -> EffectError {
    EffectError::new(
        ErrorCode::Denied,
        format!("virtual filesystem permissions do not allow {action}: {path}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RED before the mode model: every entry reported one fabricated constant,
    /// `set_mode` did not exist, and nothing was ever refused for permissions —
    /// so a guest could not tell a genuine `EACCES` from "missing".
    #[test]
    fn modes_default_to_the_umasked_creation_modes_and_chmod_changes_them() {
        let mut fs = MemFs::new();
        fs.create_directory("/perm").unwrap();
        let fd = fs
            .open("/perm/file", OpenFlags::create_truncate_write())
            .unwrap();
        fs.close(fd).unwrap();
        fs.symlink("/perm/file", "/perm/link").unwrap();

        assert_eq!(fs.metadata("/perm").unwrap().mode, 0o755);
        assert_eq!(fs.metadata("/perm/file").unwrap().mode, 0o644);
        assert_eq!(fs.metadata("/").unwrap().mode, 0o755);
        // Linux gives a symlink no mode of its own; it always reads 0o777 and
        // cannot be changed.
        assert_eq!(fs.metadata("/perm/link").unwrap().mode, 0o777);
        assert_eq!(
            fs.set_mode("/perm/link", 0o600).unwrap_err().code,
            ErrorCode::Denied
        );

        fs.set_mode("/perm/file", 0o600).unwrap();
        assert_eq!(fs.metadata("/perm/file").unwrap().mode, 0o600);
        // Only the permission bits are stored; file-type bits are the kind's.
        fs.set_mode("/perm/file", 0o100_644).unwrap();
        assert_eq!(fs.metadata("/perm/file").unwrap().mode, 0o644);
    }

    #[test]
    fn file_modes_are_enforced_for_read_and_write() {
        let mut fs = MemFs::new();
        let fd = fs
            .open("/tmp/data", OpenFlags::create_truncate_write())
            .unwrap();
        fs.write(fd, b"bytes").unwrap();
        fs.close(fd).unwrap();

        fs.set_mode("/tmp/data", 0o000).unwrap();
        assert_eq!(
            fs.open("/tmp/data", OpenFlags::read_only())
                .unwrap_err()
                .code,
            ErrorCode::Denied,
            "a 0o000 file must be denied, not reported missing"
        );
        assert_eq!(
            fs.open("/tmp/data", OpenFlags::create_truncate_write())
                .unwrap_err()
                .code,
            ErrorCode::Denied
        );

        fs.set_mode("/tmp/data", 0o400).unwrap();
        let fd = fs.open("/tmp/data", OpenFlags::read_only()).unwrap();
        assert_eq!(fs.read(fd, 8).unwrap(), b"bytes");
        fs.close(fd).unwrap();
        assert_eq!(
            fs.open("/tmp/data", OpenFlags::create_truncate_write())
                .unwrap_err()
                .code,
            ErrorCode::Denied,
            "a read-only mode must not be openable for write"
        );
        // A descriptor opened while the mode allowed it keeps working: the
        // check belongs to `open`, not to every later read (POSIX).
        let fd = fs.open("/tmp/data", OpenFlags::read_only()).unwrap();
        fs.set_mode("/tmp/data", 0o000).unwrap();
        assert_eq!(fs.read(fd, 8).unwrap(), b"bytes");
        fs.close(fd).unwrap();
    }

    #[test]
    fn directory_modes_gate_search_listing_and_name_creation() {
        let mut fs = MemFs::new();
        fs.create_directory("/gate").unwrap();
        let fd = fs
            .open("/gate/inner", OpenFlags::create_truncate_write())
            .unwrap();
        fs.close(fd).unwrap();

        // No `x`: nothing resolves THROUGH it, and the refusal is a permission
        // one even though the name behind it exists.
        fs.set_mode("/gate", 0o000).unwrap();
        assert_eq!(
            fs.open("/gate/inner", OpenFlags::read_only())
                .unwrap_err()
                .code,
            ErrorCode::Denied
        );
        assert_eq!(
            fs.metadata("/gate/inner").unwrap_err().code,
            ErrorCode::Denied
        );
        assert_eq!(
            fs.read_directory("/gate").unwrap_err().code,
            ErrorCode::Denied
        );
        // Same refusal for a name that does NOT exist, so the error cannot be
        // used to probe what is behind an unsearchable directory.
        assert_eq!(
            fs.metadata("/gate/absent").unwrap_err().code,
            ErrorCode::Denied
        );

        // `r-x`: listing and traversal work, creating a name does not.
        fs.set_mode("/gate", 0o500).unwrap();
        assert_eq!(fs.read_directory("/gate").unwrap().len(), 1);
        let opened = fs
            .open("/gate/inner", OpenFlags::read_only())
            .expect("search + read bits allow the open");
        fs.close(opened).unwrap();
        assert_eq!(
            fs.open("/gate/new", OpenFlags::create_truncate_write())
                .unwrap_err()
                .code,
            ErrorCode::Denied
        );
        assert_eq!(
            fs.create_directory("/gate/sub").unwrap_err().code,
            ErrorCode::Denied
        );
        assert_eq!(
            fs.remove_file("/gate/inner").unwrap_err().code,
            ErrorCode::Denied
        );
        assert_eq!(
            fs.rename("/gate/inner", "/gate/moved").unwrap_err().code,
            ErrorCode::Denied
        );
        assert_eq!(
            fs.symlink("/gate/inner", "/gate/link").unwrap_err().code,
            ErrorCode::Denied
        );

        // `--x`: traversal only. The entry behind it is reachable, the listing
        // is not — the distinction a search-only directory exists to make.
        fs.set_mode("/gate", 0o100).unwrap();
        let opened = fs
            .open("/gate/inner", OpenFlags::read_only())
            .expect("search alone is enough to resolve through");
        fs.close(opened).unwrap();
        assert_eq!(
            fs.read_directory("/gate").unwrap_err().code,
            ErrorCode::Denied
        );

        fs.set_mode("/gate", 0o755).unwrap();
        fs.remove_file("/gate/inner").unwrap();
    }

    /// RED before node-identity resolution: `*at` resolution replayed the name a
    /// descriptor was opened under, so a renamed directory detached its
    /// descriptor and a symlink planted at the vacated name captured every later
    /// resolution through it.
    /// A plain `O_WRONLY`: write access with no creation, truncation, or append.
    fn write_only() -> OpenFlags {
        OpenFlags {
            read: false,
            write: true,
            create: false,
            truncate: false,
            append: false,
            exclusive: false,
        }
    }

    #[test]
    fn fifos_carry_the_umasked_creation_mode_and_report_their_own_kind() {
        let mut fs = MemFs::new();
        fs.make_fifo("/tmp/pipe", 0o666).unwrap();
        let metadata = fs.metadata("/tmp/pipe").unwrap();
        assert_eq!(metadata.kind, FsEntryKind::Fifo);
        // The caller's mode IS honored here, under the modeled umask.
        assert_eq!(metadata.mode, 0o644);
        // A FIFO's bytes are never filesystem state, so it has no length.
        assert_eq!(metadata.len, 0);
        assert_eq!(metadata.nlink, 1);
        assert_ne!(metadata.ino, 0);

        fs.make_fifo("/tmp/strict", 0o777).unwrap();
        assert_eq!(fs.metadata("/tmp/strict").unwrap().mode, 0o755);
        // A mode change reaches a FIFO like any other entry.
        fs.set_mode("/tmp/strict", 0o600).unwrap();
        assert_eq!(fs.metadata("/tmp/strict").unwrap().mode, 0o600);

        assert_eq!(
            fs.make_fifo("/tmp/pipe", 0o666).unwrap_err().code,
            ErrorCode::AlreadyExists
        );
        // Creating a name needs `w` and `x` on the directory, as for any kind.
        fs.create_directory("/tmp/locked").unwrap();
        fs.set_mode("/tmp/locked", 0o500).unwrap();
        assert_eq!(
            fs.make_fifo("/tmp/locked/pipe", 0o666).unwrap_err().code,
            ErrorCode::Denied
        );
    }

    #[test]
    fn opening_a_fifo_enforces_its_mode_and_then_defers_to_the_pipe_boundary() {
        let mut fs = MemFs::new();
        fs.make_fifo("/tmp/pipe", 0o666).unwrap();
        // Permitted: the driver has nothing to hand back, because the bytes are
        // not filesystem state — but it says so with `InvalidInput`, never with
        // a permission or existence error.
        assert_eq!(
            fs.open("/tmp/pipe", OpenFlags::read_only())
                .unwrap_err()
                .code,
            ErrorCode::InvalidInput
        );
        assert_eq!(
            fs.open("/tmp/pipe", write_only()).unwrap_err().code,
            ErrorCode::InvalidInput
        );

        // Denied: the permission decision belongs to the ONE enforcement point,
        // and it has to stay distinguishable from "not found".
        fs.set_mode("/tmp/pipe", 0o000).unwrap();
        assert_eq!(
            fs.open("/tmp/pipe", OpenFlags::read_only())
                .unwrap_err()
                .code,
            ErrorCode::Denied,
            "a 0o000 FIFO must not be openable for reading"
        );
        assert_eq!(
            fs.open("/tmp/pipe", write_only()).unwrap_err().code,
            ErrorCode::Denied
        );
        fs.set_mode("/tmp/pipe", 0o400).unwrap();
        assert_eq!(
            fs.open("/tmp/pipe", OpenFlags::read_only())
                .unwrap_err()
                .code,
            ErrorCode::InvalidInput
        );
        assert_eq!(
            fs.open("/tmp/pipe", write_only()).unwrap_err().code,
            ErrorCode::Denied,
            "a read-only FIFO must not be openable for writing"
        );
        // An unsearchable parent hides it exactly as it hides a file.
        fs.create_directory("/tmp/gate").unwrap();
        fs.make_fifo("/tmp/gate/pipe", 0o666).unwrap();
        fs.set_mode("/tmp/gate", 0o000).unwrap();
        assert_eq!(
            fs.metadata("/tmp/gate/pipe").unwrap_err().code,
            ErrorCode::Denied
        );
    }

    #[test]
    fn a_fifo_lists_renames_and_unlinks_like_any_other_entry() {
        let mut fs = MemFs::new();
        fs.make_fifo("/tmp/pipe", 0o666).unwrap();
        let listed = fs.read_directory("/tmp").unwrap();
        assert_eq!(
            listed,
            vec![FsDirectoryEntry {
                name: "pipe".into(),
                kind: FsEntryKind::Fifo,
            }]
        );
        assert_eq!(
            fs.read_directory("/tmp/pipe").unwrap_err().code,
            ErrorCode::NotDirectory
        );
        assert_eq!(
            fs.remove_directory("/tmp/pipe").unwrap_err().code,
            ErrorCode::NotDirectory
        );

        // The swap a sandbox race plants: a FIFO over a regular file, and back.
        let fd = fs
            .open("/tmp/file", OpenFlags::create_truncate_write())
            .unwrap();
        fs.write(fd, b"public").unwrap();
        fs.close(fd).unwrap();
        let ino = fs.metadata("/tmp/pipe").unwrap().ino;
        fs.rename("/tmp/pipe", "/tmp/file").unwrap();
        let replaced = fs.metadata("/tmp/file").unwrap();
        assert_eq!(replaced.kind, FsEntryKind::Fifo);
        assert_eq!(replaced.ino, ino, "a renamed FIFO keeps its identity");
        assert_eq!(
            fs.metadata("/tmp/pipe").unwrap_err().code,
            ErrorCode::NotFound
        );
        let fd = fs
            .open("/tmp/regular", OpenFlags::create_truncate_write())
            .unwrap();
        fs.close(fd).unwrap();
        fs.rename("/tmp/regular", "/tmp/file").unwrap();
        assert_eq!(fs.metadata("/tmp/file").unwrap().kind, FsEntryKind::File);

        // Unlink is unconditional: nothing filesystem-side is holding a FIFO
        // open, because what an opener holds is the pipe.
        fs.make_fifo("/tmp/gone", 0o666).unwrap();
        fs.remove_file("/tmp/gone").unwrap();
        assert_eq!(
            fs.metadata("/tmp/gone").unwrap_err().code,
            ErrorCode::NotFound
        );
    }

    #[test]
    fn fifos_survive_a_restart_snapshot_with_their_mode_and_identity() {
        let mut fs = MemFs::new();
        fs.make_fifo("/tmp/pipe", 0o666).unwrap();
        fs.set_mode("/tmp/pipe", 0o640).unwrap();
        let before = fs.metadata("/tmp/pipe").unwrap();

        let encoded = fs.export_snapshot().encode().unwrap();
        let mut restored = MemFs::import_snapshot(&crate::FsSnapshot::decode(&encoded).unwrap());
        let after = restored.metadata("/tmp/pipe").unwrap();
        assert_eq!(after.kind, FsEntryKind::Fifo);
        assert_eq!(after.mode, 0o640);
        assert_eq!(after.ino, before.ino);
        assert_eq!(restored.export_snapshot().encode().unwrap(), encoded);
    }

    #[test]
    fn a_descriptor_follows_its_node_through_a_rename() {
        let mut fs = MemFs::new();
        fs.create_directory("/pinned").unwrap();
        let fd = fs
            .open("/pinned/file", OpenFlags::create_truncate_write())
            .unwrap();
        fs.close(fd).unwrap();

        let dir = fs.open("/pinned", OpenFlags::read_only()).unwrap();
        assert_eq!(fs.fd_path(dir).unwrap(), "/pinned");

        fs.rename("/pinned", "/moved").unwrap();
        assert_eq!(
            fs.fd_path(dir).unwrap(),
            "/moved",
            "the descriptor names an inode, so it moved with the directory"
        );

        // Planting a symlink at the vacated name must not recapture it.
        fs.symlink("/elsewhere", "/pinned").unwrap();
        assert_eq!(fs.fd_path(dir).unwrap(), "/moved");

        // An ancestor rename moves it too.
        fs.create_directory("/outer").unwrap();
        fs.rename("/moved", "/outer/inner").unwrap();
        assert_eq!(fs.fd_path(dir).unwrap(), "/outer/inner");
        fs.rename("/outer", "/renamed-outer").unwrap();
        assert_eq!(fs.fd_path(dir).unwrap(), "/renamed-outer/inner");
    }

    #[test]
    fn modes_survive_a_restart_snapshot() {
        let mut fs = MemFs::new();
        fs.create_directory("/state").unwrap();
        let fd = fs
            .open("/state/file", OpenFlags::create_truncate_write())
            .unwrap();
        fs.close(fd).unwrap();
        fs.set_mode("/state/file", 0o600).unwrap();
        fs.set_mode("/state", 0o700).unwrap();

        let encoded = fs.export_snapshot().encode().unwrap();
        let mut restarted =
            MemFs::import_snapshot(&FsSnapshot::decode(&encoded).expect("snapshot decodes"));
        assert_eq!(restarted.metadata("/state/file").unwrap().mode, 0o600);
        assert_eq!(restarted.metadata("/state").unwrap().mode, 0o700);
    }

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
    fn append_descriptions_use_current_eof_and_write_at_stays_positional() {
        let mut fs = MemFs::new().with_file("/log", b"head").unwrap();
        let append = fs
            .open(
                "/log",
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
        let duplicate = fs.dup(append).unwrap();

        let regular = fs
            .open(
                "/log",
                OpenFlags {
                    read: false,
                    write: true,
                    create: false,
                    truncate: false,
                    append: false,
                    exclusive: false,
                },
            )
            .unwrap();
        fs.seek(regular, 0, SeekWhence::End).unwrap();
        fs.write(regular, b"-intervening").unwrap();
        fs.close(regular).unwrap();

        fs.seek(append, 0, SeekWhence::Start).unwrap();
        fs.write(append, b"-a").unwrap();
        fs.write(duplicate, b"-d").unwrap();
        fs.write_at(append, 1, b"EA").unwrap();
        fs.write(append, b"-tail").unwrap();

        assert_eq!(fs.contents("/log").unwrap(), b"hEAd-intervening-a-d-tail");
    }

    #[test]
    fn positional_write_does_not_move_the_shared_cursor() {
        let mut fs = MemFs::new().with_file("/value", b"abcde").unwrap();
        let fd = fs
            .open(
                "/value",
                OpenFlags {
                    read: true,
                    write: true,
                    create: false,
                    truncate: false,
                    append: false,
                    exclusive: false,
                },
            )
            .unwrap();
        fs.seek(fd, 2, SeekWhence::Start).unwrap();
        fs.write_at(fd, 0, b"X").unwrap();
        fs.write(fd, b"Y").unwrap();

        assert_eq!(fs.contents("/value").unwrap(), b"XbYde");
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
