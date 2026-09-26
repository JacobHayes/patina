//! A small deterministic in-memory filesystem driver.

pub mod image;
pub mod snapshot;

pub use image::{FsImage, FsImageEntry, FsImageError};
pub use snapshot::{FsSnapshot, FsSnapshotError};

use std::collections::{BTreeMap, BTreeSet};

use patina_dst_abi::{
    AtimePolicy, EffectError, ErrorCode, Fd, FsClock, FsDirectoryEntry, FsEntryKind, FsMetadata,
    FsNode, OpenFlags, SeekWhence, XattrTarget,
};
use patina_dst_driver_api::{DriverResult, FsDriver, XattrNamespace, xattr_permission};

type InodeId = u64;
type DescriptionId = u64;

/// The permission mask a mode is stored under (`setuid`/`setgid`/sticky plus
/// the three triads); the file-type bits live in [`FsEntryKind`].
pub const MODE_MASK: u32 = 0o7777;
/// The mode a regular file in the initial image carries (`0o666` under the
/// default `0o022` umask), and the mode a legacy snapshot without per-entry
/// modes reloads a file at. Not applied to any creating call: the umask is
/// process state the layer above the driver applies.
pub const FILE_MODE: u32 = 0o644;
/// The mode the initial image's directories carry (`0o777` under the default
/// `0o022` umask); see [`FILE_MODE`].
pub const DIRECTORY_MODE: u32 = 0o755;
/// A symlink leaf. Linux ignores a symlink's own mode entirely and reports the
/// conventional `0o777`; nothing here consults it.
pub const SYMLINK_MODE: u32 = 0o777;

/// The `relatime` refresh window: an access time at least this old is updated
/// by the next read even when it is newer than `mtime`/`ctime` (Linux's
/// `relatime_need_update`, 24 hours).
const RELATIME_REFRESH_NANOS: u64 = 24 * 60 * 60 * 1_000_000_000;

/// The four timestamps every entry carries, stamped by the kernel's rules from
/// the [`FsClock`] each operation is handed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Times {
    atime_nanos: u64,
    mtime_nanos: u64,
    ctime_nanos: u64,
    btime_nanos: u64,
}

impl Times {
    /// A freshly created entry: all four at `now`.
    fn created(clock: FsClock) -> Self {
        let now = clock.now_nanos;
        Self {
            atime_nanos: now,
            mtime_nanos: now,
            ctime_nanos: now,
            btime_nanos: now,
        }
    }

    /// The entry's DATA changed (a write, a truncation, an allocation; for a
    /// directory, a name appeared or disappeared): `mtime` and `ctime`.
    fn data_changed(&mut self, clock: FsClock) {
        self.mtime_nanos = clock.now_nanos;
        self.ctime_nanos = clock.now_nanos;
    }

    /// The entry's METADATA changed (mode, link count, name, explicit times):
    /// `ctime` only.
    fn metadata_changed(&mut self, clock: FsClock) {
        self.ctime_nanos = clock.now_nanos;
    }

    /// The entry was READ: `atime`, under the clock's policy. `relatime` is
    /// Linux's `relatime_need_update` — an access time not newer than `mtime`
    /// or `ctime`, or at least a day old, is refreshed; otherwise a read leaves
    /// it alone — and no policy rewrites an access time that already reads
    /// `now`.
    fn accessed(&mut self, clock: FsClock) {
        let now = clock.now_nanos;
        let due = match clock.atime {
            AtimePolicy::NoAtime => false,
            AtimePolicy::Strict => true,
            AtimePolicy::Relatime => {
                self.mtime_nanos >= self.atime_nanos
                    || self.ctime_nanos >= self.atime_nanos
                    || now.saturating_sub(self.atime_nanos) >= RELATIME_REFRESH_NANOS
            }
        };
        if due && self.atime_nanos != now {
            self.atime_nanos = now;
        }
    }

    /// `utimensat`: `None` leaves a time alone. Any change stamps `ctime`.
    fn set(&mut self, clock: FsClock, atime: Option<u64>, mtime: Option<u64>) {
        if atime.is_none() && mtime.is_none() {
            return;
        }
        if let Some(value) = atime {
            self.atime_nanos = value;
        }
        if let Some(value) = mtime {
            self.mtime_nanos = value;
        }
        self.metadata_changed(clock);
    }
}

/// Owner-triad permission bits, as POSIX spells them.
const READ: u32 = 0o4;
const WRITE: u32 = 0o2;
const SEARCH: u32 = 0o1;

/// Does the single modeled (owning, non-root) identity hold every bit in `want`?
fn owner_allows(mode: u32, want: u32) -> bool {
    ((mode >> 6) & 0o7) & want == want
}

/// What an open DECIDED the description may do. Bundled because the decision is
/// one thing — the flags the open was granted — and every caller passes it whole.
#[derive(Clone, Copy, Debug)]
struct Access {
    readable: bool,
    writable: bool,
    append: bool,
    /// `O_PATH`: the description names a LOCATION and never the file behind it.
    path_only: bool,
}

impl Access {
    /// The `O_PATH` grant: nothing but resolution, `fstat`, `dup` and `close`.
    const LOCATION: Self = Self {
        readable: false,
        writable: false,
        append: false,
        path_only: true,
    };

    fn from_flags(flags: OpenFlags) -> Self {
        Self {
            readable: flags.read,
            writable: flags.write,
            append: flags.append,
            path_only: flags.path_only,
        }
    }
}

#[derive(Clone, Debug)]
struct Description {
    /// The NODE this description is open on, never the name it was opened
    /// under. A rename moves the descriptor with its node, an unlink cannot
    /// detach it, and the node outlives its last name for as long as this
    /// description holds a reference on it. A directory description names the
    /// directory's `ino`, which is drawn from the same counter and is therefore
    /// never confusable with a file's.
    node: InodeId,
    cursor: usize,
    readable: bool,
    writable: bool,
    append: bool,
    /// `O_PATH`: the description names a LOCATION and never the file behind it,
    /// so everything that touches the file through the descriptor is refused
    /// (`read`, `write`, `seek`, `fsync`, `fchmod`, directory iteration) while
    /// `fstat`, `*at` resolution, `dup` and `close` work.
    path_only: bool,
    kind: FsEntryKind,
    /// Number of fds referencing this open-file description.
    fds: u32,
}

#[derive(Clone, Debug)]
struct Inode {
    /// What the node IS. It lives here rather than being read off the name
    /// tables because a node with no names left is still a node: an `fstat`
    /// through a descriptor on an unlinked entry has to answer `S_IFIFO` or
    /// `S_IFREG` with nothing left to look it up by.
    kind: FsEntryKind,
    /// A regular file's bytes, or a symlink's target; empty for every other
    /// kind.
    contents: Vec<u8>,
    /// Names referencing this node — POSIX `st_nlink`.
    links: u32,
    /// Open descriptions (and pipe endpoints) referencing it. A real kernel
    /// keeps an inode alive while ANY reference exists, so the node is freed
    /// only when its last name AND its last descriptor are gone; until then an
    /// unlinked-but-open entry answers `fstat`, reads, writes and `fchmod` from
    /// the live node rather than from a copy taken when it was opened.
    openers: u32,
    times: Times,
    /// POSIX permission bits (`0o7777`), without the file-type bits.
    mode: u32,
    /// The `F_SEAL_*` set of an anonymous file (`memfd_create`), the one kind
    /// of node that can be sealed; `None` for every named node.
    seals: Option<u32>,
    /// The huge page size of a hugetlbfs file (`MFD_HUGETLB`), 0 for every
    /// other node. The machine reserves no huge pages: such a file has no
    /// write method, sizes in whole huge pages, allocates nothing, and reads
    /// as a hole.
    huge_page: u64,
}

use patina_dst_abi::seals::{
    F_ALL_SEALS, F_SEAL_EXEC, F_SEAL_FUTURE_WRITE, F_SEAL_GROW, F_SEAL_SEAL, F_SEAL_SHRINK,
    F_SEAL_WRITE,
};

impl Inode {
    /// A write reaching `end`: a hugetlbfs file has no write method
    /// (`vfs_write`'s `FMODE_CAN_WRITE`), then the node's seals
    /// (`shmem_write_begin`): a write seal refuses every write, a grow seal one
    /// past the end.
    fn check_write_seals(&self, end: usize) -> DriverResult<()> {
        if self.huge_page != 0 {
            return Err(EffectError::new(
                ErrorCode::InvalidInput,
                "a hugetlbfs file has no write method",
            ));
        }
        let seals = self.seals.unwrap_or(0);
        if seals & (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE) != 0
            || (seals & F_SEAL_GROW != 0 && end > self.contents.len())
        {
            return Err(sealed());
        }
        Ok(())
    }

    /// A length change to `len`: a hugetlbfs file sizes in whole huge pages
    /// (`hugetlbfs_setattr`), then the node's seals (`shmem_setattr`).
    fn check_resize_seals(&self, len: usize) -> DriverResult<()> {
        if self.huge_page != 0 && len as u64 % self.huge_page != 0 {
            return Err(EffectError::new(
                ErrorCode::InvalidInput,
                "a hugetlbfs file sizes in whole huge pages",
            ));
        }
        let seals = self.seals.unwrap_or(0);
        let current = self.contents.len();
        if (len < current && seals & F_SEAL_SHRINK != 0)
            || (len > current && seals & F_SEAL_GROW != 0)
        {
            return Err(sealed());
        }
        Ok(())
    }
}

fn sealed() -> EffectError {
    EffectError::new(
        ErrorCode::NotPermitted,
        "the virtual file is sealed against this change",
    )
}

#[derive(Clone, Copy, Debug)]
struct EntryMetadata {
    ino: InodeId,
    times: Times,
    /// POSIX permission bits (`0o7777`), without the file-type bits.
    mode: u32,
}

/// A deterministic in-memory filesystem keyed by normalized absolute paths.
///
/// It models regular files, hard links, inert symlink leaves, named pipes
/// (`mkfifo` — the NAME and its inode; the bytes belong to the openers' pipe
/// channel, not to the filesystem), socket nodes and whiteouts (`mknod`),
/// directories, cursors, basic metadata, POSIX permission bits, and extended
/// attributes. Every non-directory NAME names an inode whose kind lives on the
/// node, so a hard link to any of them — a symlink included — is a second name
/// for the same node. MemFs has no clock of its own: every reading or mutating
/// operation is handed the runtime's virtual clock ([`FsClock`]) and stamps
/// `atime`/`mtime`/`ctime`/`btime` by the kernel's rules — creation sets all
/// four, a data change `mtime`+`ctime`, a metadata change `ctime`, a read
/// `atime` under the clock's `relatime`/`strictatime`/`noatime` policy — so the
/// times a guest reads back are a pure function of the run.
///
/// # Permissions
///
/// Every entry carries a mode. A creating call brings its own: `open`'s third
/// argument, `mkdir`'s, and `mkfifo`'s all cross this boundary and are stored
/// VERBATIM (masked to the permission bits). The process umask is applied
/// above this boundary, where a kernel applies it — by the native shim's
/// `umask` state or the WASI host's fixed `0o022` — so what arrives here is
/// what the kernel would store, and a caller asking for `0o400` gets `0o400`.
/// An `open` of an EXISTING entry never touches its mode. Symlink leaves are
/// the conventional `0o777`. The guest is a single non-root identity (uid/gid 1000, the value the
/// native shim's `getuid` reports) and owns every entry, so enforcement reads
/// the OWNER triad: read needs `r`, write needs `w`, resolving a path through a
/// directory needs `x` on that directory, listing one needs `r`, and creating,
/// removing, or renaming a name inside one needs `w` and `x`. There is no
/// root-bypass identity, so a mode change is always enforced.
///
/// # Extended attributes
///
/// Attributes belong to the NODE (so they follow hard links and renames) and
/// are judged by the kernel's namespace rules for an unprivileged caller
/// (`xattr_permission`, `cap_inode_setxattr`): `user.*` exists only on regular
/// files and directories (on anything else a write is `EPERM` and a read
/// `ENODATA`) and is charged against the mode's `r`/`w` bits; `trusted.*` needs
/// `CAP_SYS_ADMIN` (`EPERM` to write, `ENODATA` to read, never listed);
/// `security.*` can be read and listed but not written (`EPERM`); `system.*`
/// has no handler here (`EOPNOTSUPP`, a volume mounted without ACLs), and
/// neither has a name outside the four namespaces.
#[derive(Clone, Default)]
pub struct MemFs {
    /// Every non-directory name, by path: the node it names. The node says what
    /// the entry is — a regular file, a symlink (its contents are the target),
    /// a FIFO, a socket node or a whiteout.
    names: BTreeMap<String, InodeId>,
    inodes: BTreeMap<InodeId, Inode>,
    directories: BTreeMap<String, EntryMetadata>,
    /// Extended attributes, by the node they belong to (a directory's by its
    /// `ino`). A node without attributes has no entry.
    xattrs: BTreeMap<InodeId, BTreeMap<String, Vec<u8>>>,
    handles: BTreeMap<Fd, DescriptionId>,
    descriptions: BTreeMap<DescriptionId, Description>,
    next_fd: u64,
    next_description: DescriptionId,
    next_inode: InodeId,
}

/// `setxattr(2)`'s flags: the name must be new / must exist.
pub const XATTR_CREATE: u32 = 1;
pub const XATTR_REPLACE: u32 = 2;

/// Is an attribute access a read or a write (`MAY_READ`/`MAY_WRITE`)?
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum XattrAccess {
    Read,
    Write,
}

impl MemFs {
    pub fn new() -> Self {
        let mut filesystem = Self {
            next_fd: 3,
            next_description: 1,
            next_inode: 1,
            ..Self::default()
        };
        let root = filesystem.allocate_entry_metadata(FsClock::EPOCH, DIRECTORY_MODE);
        filesystem.directories.insert("/".into(), root);
        let tmp = filesystem.allocate_entry_metadata(FsClock::EPOCH, DIRECTORY_MODE);
        filesystem.directories.insert("/tmp".into(), tmp);
        filesystem
    }

    /// Seed a file into the initial image. It is stamped at the epoch, like the
    /// image's directories: nothing in the run created it.
    pub fn with_file(mut self, path: &str, contents: impl Into<Vec<u8>>) -> DriverResult<Self> {
        let path = normalize_path(path)?;
        self.insert_parent_directories(FsClock::EPOCH, &path);
        let inode = self.allocate_inode(
            FsClock::EPOCH,
            FsEntryKind::File,
            contents.into(),
            FILE_MODE,
        );
        self.names.insert(path, inode);
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

    /// The bytes of the regular file `fd` is open on, whatever names it has
    /// now (none, once unlinked).
    pub fn fd_contents(&self, fd: Fd) -> DriverResult<&[u8]> {
        let node = self.description(fd)?.node;
        self.inodes
            .get(&node)
            .filter(|inode| inode.kind == FsEntryKind::File)
            .map(|inode| inode.contents.as_slice())
            .ok_or_else(|| {
                EffectError::new(
                    ErrorCode::InvalidInput,
                    format!("virtual descriptor is not open on a regular file: {fd:?}"),
                )
            })
    }

    /// Clone persistent filesystem state without carrying open handles across
    /// a modeled process restart.
    pub fn persistent_snapshot(&self) -> Self {
        let mut snapshot = self.clone();
        snapshot.forget_open_state();
        snapshot
    }

    /// Export a canonical, versioned restart snapshot. Open descriptors and
    /// descriptions are deliberately omitted; inode identity, timestamps, names,
    /// contents, extended attributes, and future inode allocation state are
    /// preserved.
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
    /// A node whose last name is already gone contributes nothing: there is no
    /// name to pin back into a rebuilt namespace, and the node itself crosses
    /// with the descriptor through [`MemFs::adopt_handles`].
    pub fn open_entries(&self) -> BTreeMap<String, FsEntryKind> {
        self.handles
            .values()
            .filter_map(|id| self.descriptions.get(id))
            .filter_map(|description| {
                self.node_path(description.node, description.kind)
                    .map(|path| (path, description.kind))
            })
            .collect()
    }

    /// Every entry in the image with its metadata, in path order, WITHOUT
    /// permission enforcement.
    ///
    /// A crash model is the storage layer, not the guest. Permission bits gate a
    /// PROCESS's access; a power cut does not consult them, and neither does the
    /// journal that decides what survived one. Walking the enforced
    /// `read_directory`/`metadata` here would make a `0o000` directory look
    /// EMPTY and silently drop every child beneath it on the next crash — a
    /// mode change quietly deleting data.
    pub fn inventory(&self) -> Vec<(String, FsMetadata)> {
        let mut paths: BTreeSet<&String> = self.directories.keys().collect();
        paths.extend(self.names.keys());
        paths
            .into_iter()
            .map(|path| {
                let metadata = self
                    .metadata_for_path(path)
                    .expect("an enumerated path has metadata");
                (path.clone(), metadata)
            })
            .collect()
    }

    /// The metadata of one entry WITHOUT permission enforcement — the storage
    /// layer's own view, for the same reason [`MemFs::inventory`] has one.
    pub fn entry_metadata(&self, path: &str) -> DriverResult<FsMetadata> {
        let path = normalize_entry_path(path)?;
        self.metadata_for_path(&path)
    }

    /// A symlink's stored target WITHOUT permission enforcement.
    pub fn symlink_target(&self, path: &str) -> Option<&str> {
        let path = normalize_entry_path(path).ok()?;
        let inode = self
            .leaf(&path)
            .filter(|inode| inode.kind == FsEntryKind::Symlink)?;
        std::str::from_utf8(&inode.contents).ok()
    }

    /// The extended attributes of the entry at `path` WITHOUT permission
    /// enforcement — the storage layer's own view, for a crash model carrying
    /// them onto a rebuilt image.
    pub fn entry_xattrs(&self, path: &str) -> BTreeMap<String, Vec<u8>> {
        normalize_entry_path(path)
            .ok()
            .and_then(|path| self.node_id(&path))
            .and_then(|ino| self.xattrs.get(&ino).cloned())
            .unwrap_or_default()
    }

    /// Write the extended attributes of the entry at `path` back verbatim —
    /// the storage layer's own setter, the mirror of [`MemFs::entry_xattrs`]
    /// for a rebuild. It stamps nothing.
    pub fn restore_xattrs(
        &mut self,
        path: &str,
        xattrs: BTreeMap<String, Vec<u8>>,
    ) -> DriverResult<()> {
        let path = normalize_entry_path(path)?;
        let ino = self.node_id(&path).ok_or_else(|| not_found(&path))?;
        if xattrs.is_empty() {
            self.xattrs.remove(&ino);
        } else {
            self.xattrs.insert(ino, xattrs);
        }
        Ok(())
    }

    /// Write all four timestamps of the entry at `path` back verbatim — the
    /// storage layer's own setter, for a crash model rebuilding an image from
    /// its durable baseline. Unlike the guest-facing `set_times` it stamps
    /// nothing (a rebuild is not an inode change) and it restores the birth
    /// time, which no guest-facing call can set.
    pub fn restore_times(
        &mut self,
        path: &str,
        atime_nanos: u64,
        mtime_nanos: u64,
        ctime_nanos: u64,
        btime_nanos: u64,
    ) -> DriverResult<()> {
        let path = normalize_entry_path(path)?;
        let times = self.times_mut(&path).ok_or_else(|| not_found(&path))?;
        *times = Times {
            atime_nanos,
            mtime_nanos,
            ctime_nanos,
            btime_nanos,
        };
        Ok(())
    }

    /// Write permission bits back onto the entry at `path` WITHOUT stamping
    /// `ctime` or enforcing the search path: the storage-layer mirror of
    /// [`MemFs::restore_times`], for the same rebuild.
    pub fn restore_mode(&mut self, path: &str, mode: u32) -> DriverResult<()> {
        let path = normalize_entry_path(path)?;
        let mode = mode & MODE_MASK;
        if let Some(inode) = self.names.get(&path).copied() {
            self.inodes
                .get_mut(&inode)
                .expect("name references an inode")
                .mode = mode;
            return Ok(());
        }
        if let Some(metadata) = self.directories.get_mut(&path) {
            metadata.mode = mode;
            return Ok(());
        }
        Err(not_found(&path))
    }

    /// Every path that OWNS a mode — every entry but a symlink — in path
    /// order. A symlink leaf is excluded: Linux ignores a link's own mode and
    /// this filesystem has none to set.
    ///
    /// A crash model reads this to write permission bits back onto a
    /// reconstructed image without inventing a per-kind constant.
    pub fn paths_with_modes(&self) -> Vec<String> {
        let mut paths: BTreeSet<&String> = self.directories.keys().collect();
        paths.extend(
            self.names
                .iter()
                .filter(|(_, ino)| self.kind_of(**ino) != Some(FsEntryKind::Symlink))
                .map(|(path, _)| path),
        );
        paths.into_iter().cloned().collect()
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
    /// A description names a NODE, and this image minted its own inode numbers,
    /// so every description is re-bound to the node its name has HERE. A
    /// description whose name did not come back — an entry unlinked while open,
    /// whose node no crash can reach because the journal enumerates names — is
    /// re-bound to a fresh node carrying the bytes the descriptor last saw: the
    /// descriptor is the process's object either way, and a number reused by an
    /// unrelated entry would be far worse than an anonymous one.
    pub fn adopt_handles(&mut self, previous: &Self) {
        self.handles.clone_from(&previous.handles);
        self.descriptions.clone_from(&previous.descriptions);
        self.next_fd = self.next_fd.max(previous.next_fd);
        self.next_description = self.next_description.max(previous.next_description);
        let mut rebound: BTreeMap<InodeId, InodeId> = BTreeMap::new();
        // Per DESCRIPTION, not per descriptor: a `dup`ed pair is two fds on one
        // description, which is one reference on the node.
        let descriptions: BTreeSet<DescriptionId> = self.handles.values().copied().collect();
        for id in descriptions {
            let description = self
                .descriptions
                .get(&id)
                .expect("handle references a description");
            let (node, kind) = (description.node, description.kind);
            let carried = match rebound.get(&node).copied() {
                Some(carried) => carried,
                None => {
                    let carried = previous
                        .node_path(node, kind)
                        .and_then(|path| self.node_at(&path, kind))
                        .unwrap_or_else(|| self.carry_anonymous_node(previous, node, kind));
                    rebound.insert(node, carried);
                    carried
                }
            };
            self.descriptions
                .get_mut(&id)
                .expect("handle references a description")
                .node = carried;
            if let Some(inode) = self.inodes.get_mut(&carried) {
                inode.openers += 1;
            }
        }
    }

    /// The node the entry at `path` has in THIS image, if it has one of `kind`.
    fn node_at(&self, path: &str, kind: FsEntryKind) -> Option<InodeId> {
        match kind {
            FsEntryKind::Directory => self.directories.get(path).map(|metadata| metadata.ino),
            _ => self
                .names
                .get(path)
                .copied()
                .filter(|ino| self.kind_of(*ino) == Some(kind)),
        }
    }

    /// Mint a nameless node for a descriptor whose entry this image does not
    /// have, carrying the previous image's contents and metadata. A directory
    /// has no inode-table entry to carry, so it gets a fresh unused id that
    /// names nothing — which is the point: a stale descriptor must never be
    /// captured by an unrelated entry that happens to reuse the number.
    fn carry_anonymous_node(
        &mut self,
        previous: &Self,
        node: InodeId,
        kind: FsEntryKind,
    ) -> InodeId {
        let fresh = self.next_inode;
        self.next_inode = self.next_inode.checked_add(1).expect("inode IDs exhausted");
        if kind != FsEntryKind::Directory {
            if let Some(inode) = previous.inodes.get(&node) {
                let mut carried = inode.clone();
                carried.links = 0;
                carried.openers = 0;
                self.inodes.insert(fresh, carried);
            }
        }
        fresh
    }

    /// Drop every descriptor and every node only a descriptor was holding — the
    /// image as a fresh incarnation inherits it. An anonymous node is exactly
    /// what a restart cannot carry: nothing names it.
    fn forget_open_state(&mut self) {
        self.handles.clear();
        self.descriptions.clear();
        self.next_fd = 3;
        self.next_description = 1;
        for inode in self.inodes.values_mut() {
            inode.openers = 0;
        }
        self.inodes.retain(|_, inode| inode.links > 0);
        let directories: BTreeSet<InodeId> = self
            .directories
            .values()
            .map(|metadata| metadata.ino)
            .collect();
        let inodes = &self.inodes;
        self.xattrs
            .retain(|ino, _| inodes.contains_key(ino) || directories.contains(ino));
    }

    fn allocate_entry_metadata(&mut self, clock: FsClock, mode: u32) -> EntryMetadata {
        let ino = self.next_inode;
        self.next_inode = self.next_inode.checked_add(1).expect("inode IDs exhausted");
        EntryMetadata {
            ino,
            times: Times::created(clock),
            mode: mode & MODE_MASK,
        }
    }

    fn allocate_inode(
        &mut self,
        clock: FsClock,
        kind: FsEntryKind,
        contents: Vec<u8>,
        mode: u32,
    ) -> InodeId {
        let inode = self.next_inode;
        self.next_inode = self.next_inode.checked_add(1).expect("inode IDs exhausted");
        self.inodes.insert(
            inode,
            Inode {
                kind,
                contents,
                links: 1,
                openers: 0,
                times: Times::created(clock),
                mode: mode & MODE_MASK,
                seals: None,
                huge_page: 0,
            },
        );
        inode
    }

    /// A name appeared in or disappeared from `directory`: its `mtime` and
    /// `ctime`, as every namespace operation stamps its parent.
    fn stamp_directory(&mut self, clock: FsClock, directory: &str) {
        if let Some(metadata) = self.directories.get_mut(directory) {
            metadata.times.data_changed(clock);
        }
    }

    /// The node a non-directory name refers to.
    fn leaf(&self, path: &str) -> Option<&Inode> {
        self.names.get(path).and_then(|ino| self.inodes.get(ino))
    }

    fn kind_of(&self, ino: InodeId) -> Option<FsEntryKind> {
        self.inodes.get(&ino).map(|inode| inode.kind)
    }

    /// The kind of the non-directory entry at `path`.
    fn leaf_kind(&self, path: &str) -> Option<FsEntryKind> {
        self.leaf(path).map(|inode| inode.kind)
    }

    /// The node id of the entry at `path`, whatever its kind (a directory's
    /// `ino` included).
    fn node_id(&self, path: &str) -> Option<InodeId> {
        self.names
            .get(path)
            .copied()
            .or_else(|| self.directories.get(path).map(|metadata| metadata.ino))
    }

    /// The timestamps of the entry at `path`, whatever its kind.
    fn times_mut(&mut self, path: &str) -> Option<&mut Times> {
        if let Some(inode) = self.names.get(path).copied() {
            return self.inodes.get_mut(&inode).map(|inode| &mut inode.times);
        }
        self.directories
            .get_mut(path)
            .map(|metadata| &mut metadata.times)
    }

    /// `2 + subdirectories`: a directory's link count is its own `.`, its
    /// parent's name for it, and every child's `..`.
    fn directory_links(&self, path: &str) -> u32 {
        let prefix = if path == "/" {
            "/".to_owned()
        } else {
            format!("{path}/")
        };
        let children = self
            .directories
            .keys()
            .filter(|candidate| {
                candidate
                    .strip_prefix(&prefix)
                    .is_some_and(|relative| !relative.is_empty() && !relative.contains('/'))
            })
            .count();
        2 + u32::try_from(children).unwrap_or(u32::MAX - 2)
    }

    /// The permission bits of an existing entry, or `None` when nothing is
    /// there. Symlink leaves answer [`SYMLINK_MODE`]: Linux never consults a
    /// link's own mode.
    fn entry_mode(&self, path: &str) -> Option<u32> {
        if let Some(inode) = self.leaf(path) {
            return Some(inode.mode);
        }
        self.directories.get(path).map(|metadata| metadata.mode)
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
            } else if self.names.contains_key(&current) {
                // A component resolved THROUGH a non-directory is `ENOTDIR`,
                // never "not found": the name is there, it just cannot be
                // walked into. (An intermediate symlink is refused before this
                // walk; a missing component is the entry lookup's `NotFound`.)
                return Err(EffectError::new(
                    ErrorCode::NotDirectory,
                    format!("virtual filesystem path component is not a directory: {current}"),
                ));
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

    /// Mint a descriptor on `node`, taking the node's open reference with it.
    fn allocate_handle(
        &mut self,
        node: InodeId,
        cursor: usize,
        access: Access,
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
                node,
                cursor,
                readable: access.readable,
                writable: access.writable,
                append: access.append,
                path_only: access.path_only,
                kind,
                fds: 1,
            },
        );
        self.handles.insert(fd, description);
        // A descriptor is a reference on the node (a directory's metadata is not
        // in the inode table, so it has none to take).
        if let Some(inode) = self.inodes.get_mut(&node) {
            inode.openers += 1;
        }
        Ok(fd)
    }

    /// The node a regular-file name refers to; any other entry, or none, is
    /// `NotFound` to a caller that asked for a file.
    fn file_inode(&self, path: &str) -> DriverResult<InodeId> {
        self.names
            .get(path)
            .copied()
            .filter(|ino| self.kind_of(*ino) == Some(FsEntryKind::File))
            .ok_or_else(|| not_found(path))
    }

    /// The node an open descriptor holds. A directory description names an ino
    /// the inode table does not hold, so it is refused here rather than read as
    /// a file.
    fn handle_inode(&self, fd: Fd) -> DriverResult<InodeId> {
        let description = self.description(fd)?;
        if !self.inodes.contains_key(&description.node) {
            return Err(EffectError::new(
                ErrorCode::IsDirectory,
                format!("virtual file handle {} references a directory", fd.0),
            ));
        }
        Ok(description.node)
    }

    /// Drop one NAME's reference to a node, releasing it if that was its last
    /// reference of either kind.
    fn drop_name(&mut self, clock: FsClock, inode: InodeId) {
        let entry = self.inodes.get_mut(&inode).expect("inode was checked");
        entry.links -= 1;
        // The link count is inode metadata: `ctime` moves, on a node that may
        // live on behind a descriptor.
        entry.times.metadata_changed(clock);
        self.release_if_unreferenced(inode);
    }

    /// Free a node once NOTHING references it — no name and no descriptor. This
    /// is the whole of inode lifetime: a kernel drops the on-disk inode when
    /// `i_nlink` and `i_count` both reach zero, and until then an unlinked entry
    /// stays fully alive behind every descriptor that holds it. Its attributes
    /// go with it.
    fn release_if_unreferenced(&mut self, inode: InodeId) {
        let Some(entry) = self.inodes.get(&inode) else {
            return;
        };
        if entry.links == 0 && entry.openers == 0 {
            self.inodes.remove(&inode);
            self.xattrs.remove(&inode);
        }
    }

    /// Remove the directory at `path` (which the caller checked is empty),
    /// its attributes with it.
    fn drop_directory(&mut self, path: &str) {
        if let Some(metadata) = self.directories.remove(path) {
            self.xattrs.remove(&metadata.ino);
        }
    }

    /// The path a live node currently has, or `None` when its last name is gone.
    /// A node with several names (hard links) answers the first in path order,
    /// deterministically; every name of one node reports identical metadata.
    fn node_path(&self, node: InodeId, kind: FsEntryKind) -> Option<String> {
        if kind == FsEntryKind::Directory {
            return self
                .directories
                .iter()
                .find_map(|(path, metadata)| (metadata.ino == node).then(|| path.clone()));
        }
        self.names
            .iter()
            .find_map(|(path, inode)| (*inode == node).then(|| path.clone()))
    }

    /// Metadata straight off a node, with no name involved — what a descriptor
    /// on an unlinked entry answers. A regular file's length is its bytes, a
    /// symlink's its target's; every other node holds none.
    fn metadata_for_inode(&self, node: InodeId) -> DriverResult<FsMetadata> {
        let inode = self.inodes.get(&node).ok_or_else(|| {
            EffectError::new(
                ErrorCode::NotFound,
                format!("no virtual filesystem node {node}"),
            )
        })?;
        Ok(FsMetadata {
            kind: inode.kind,
            len: match inode.kind {
                FsEntryKind::File | FsEntryKind::Symlink => inode.contents.len() as u64,
                FsEntryKind::Directory
                | FsEntryKind::Fifo
                | FsEntryKind::Socket
                | FsEntryKind::CharDevice => 0,
            },
            ino: node,
            nlink: inode.links,
            atime_nanos: inode.times.atime_nanos,
            mtime_nanos: inode.times.mtime_nanos,
            ctime_nanos: inode.times.ctime_nanos,
            btime_nanos: inode.times.btime_nanos,
            mode: inode.mode,
        })
    }

    /// Does directory `path` hold any entry?
    fn has_children(&self, path: &str) -> bool {
        let prefix = format!("{path}/");
        let under = |candidate: &String| candidate.starts_with(&prefix);
        self.directories.keys().any(under) || self.names.keys().any(under)
    }

    fn path_exists(&self, path: &str) -> bool {
        self.directories.contains_key(path) || self.names.contains_key(path)
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
            if current != path && self.leaf_kind(&current) == Some(FsEntryKind::Symlink) {
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

    fn insert_parent_directories(&mut self, clock: FsClock, path: &str) {
        let mut parents = Vec::new();
        let mut parent = parent_path(path);
        while parent != "/" {
            if !self.directories.contains_key(parent) {
                parents.push(parent.to_owned());
            }
            parent = parent_path(parent);
        }
        for parent in parents.into_iter().rev() {
            let metadata = self.allocate_entry_metadata(clock, DIRECTORY_MODE);
            self.directories.insert(parent, metadata);
        }
        if !self.directories.contains_key("/") {
            let metadata = self.allocate_entry_metadata(clock, DIRECTORY_MODE);
            self.directories.insert("/".into(), metadata);
        }
    }

    /// The checks every creating call runs on the NAME: resolvable, the parent
    /// writable, the name free, the parent a directory.
    fn check_new_name(&self, path: &str) -> DriverResult<()> {
        self.resolve_guard(path)?;
        self.check_directory_write(parent_path(path))?;
        if self.path_exists(path) {
            return Err(EffectError::new(
                ErrorCode::AlreadyExists,
                format!("virtual filesystem entry already exists: {path}"),
            ));
        }
        let parent = parent_path(path);
        if !self.directories.contains_key(parent) {
            return Err(EffectError::new(
                ErrorCode::NotFound,
                format!("virtual parent directory does not exist: {parent}"),
            ));
        }
        Ok(())
    }

    /// The node an attribute operation names, and its kind and mode.
    fn xattr_node(&self, target: &XattrTarget) -> DriverResult<(InodeId, FsEntryKind, u32)> {
        match target {
            XattrTarget::Path(path) => {
                let path = normalize_entry_path(path)?;
                self.resolve_guard(&path)?;
                let metadata = self.metadata_for_path(&path)?;
                Ok((metadata.ino, metadata.kind, metadata.mode))
            }
            XattrTarget::Fd(fd) => {
                let description = self.description(*fd)?;
                if description.path_only {
                    return Err(EffectError::new(
                        ErrorCode::InvalidHandle,
                        format!("virtual handle {} names a location", fd.0),
                    ));
                }
                let (node, kind) = (description.node, description.kind);
                let metadata = if kind == FsEntryKind::Directory {
                    let path = self
                        .node_path(node, kind)
                        .ok_or_else(|| not_found("<removed directory>"))?;
                    self.metadata_for_path(&path)?
                } else {
                    self.metadata_for_inode(node)?
                };
                Ok((node, metadata.kind, metadata.mode))
            }
            XattrTarget::Inode(ino) => {
                let metadata = self.metadata_for_inode(*ino)?;
                Ok((*ino, metadata.kind, metadata.mode))
            }
        }
    }

    /// The kernel's judgment of the access ([`xattr_permission`], one judge for
    /// every filesystem), then the handler lookup `xattr_resolve_name` does
    /// here: a name in no namespace, or in `system.*` (no ACL handler on this
    /// volume), has none, and a namespace prefix alone names nothing.
    fn check_xattr(
        kind: FsEntryKind,
        mode: u32,
        name: &str,
        access: XattrAccess,
    ) -> DriverResult<XattrNamespace> {
        let file_or_directory = matches!(kind, FsEntryKind::File | FsEntryKind::Directory);
        let namespace =
            xattr_permission(file_or_directory, mode, name, access == XattrAccess::Write).map_err(
                |code| match code {
                    ErrorCode::Denied => denied(name, "access the extended attribute"),
                    code => EffectError::new(
                        code,
                        format!(
                            "virtual extended attribute {name} is not available to this caller"
                        ),
                    ),
                },
            )?;
        if matches!(namespace, XattrNamespace::System | XattrNamespace::Unknown) {
            return Err(EffectError::new(
                ErrorCode::Unsupported,
                format!("no virtual extended attribute handler for {name}"),
            ));
        }
        let suffix = name.split_once('.').map_or("", |(_, suffix)| suffix);
        if suffix.is_empty() {
            return Err(EffectError::new(
                ErrorCode::InvalidInput,
                format!("virtual extended attribute name has no suffix: {name}"),
            ));
        }
        Ok(namespace)
    }
}

impl FsDriver for MemFs {
    fn open(&mut self, clock: FsClock, path: &str, flags: OpenFlags) -> DriverResult<Fd> {
        let path = normalize_entry_path(path)?;
        self.resolve_guard(&path)?;
        if flags.path_only {
            // `O_PATH` names a location. The kernel ignores the access mode and
            // every creating flag under it, so a caller that sets one is asking
            // for two different descriptors at once.
            if flags.read
                || flags.write
                || flags.create
                || flags.truncate
                || flags.append
                || flags.exclusive
            {
                return Err(EffectError::new(
                    ErrorCode::InvalidInput,
                    "a path-only open carries no access mode and creates nothing",
                ));
            }
        } else if !flags.read && !flags.write {
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
            // The two directory opens cost different things, which is the whole
            // reason `O_PATH` is in this vocabulary. An `O_PATH` open never
            // opens the entry: Linux charges nothing on it, only the `x` walk of
            // the prefix that `resolve_guard` has already done, and the
            // descriptor can resolve and `fstat` but not iterate. A plain
            // `O_RDONLY|O_DIRECTORY` open DOES open it for reading and costs
            // `r` — charged here, once, so a later `chmod` cannot retroactively
            // break a walk already in progress.
            if !flags.path_only && !owner_allows(metadata.mode, READ) {
                return Err(denied(&path, "list"));
            }
            // A plain directory open is a READ of the directory; a path-only
            // one opens nothing at all.
            let access = if flags.path_only {
                Access::LOCATION
            } else {
                Access {
                    readable: true,
                    writable: false,
                    append: false,
                    path_only: false,
                }
            };
            return self.allocate_handle(metadata.ino, 0, access, FsEntryKind::Directory);
        }
        if let Some(inode) = self.names.get(&path).copied() {
            let (kind, mode) = {
                let node = self.inodes.get(&inode).expect("name references an inode");
                (node.kind, node.mode)
            };
            match kind {
                FsEntryKind::Symlink => {
                    return Err(EffectError::new(
                        ErrorCode::InvalidInput,
                        format!(
                            "virtual symlink cannot be opened without host-level follow: {path}"
                        ),
                    ));
                }
                // `O_PATH` is the one open of a FIFO, a socket node or a
                // whiteout that never reaches past the name: it names the entry
                // without opening it, so there is no rendezvous, no permission
                // on the entry to charge, and the descriptor IS a filesystem
                // descriptor — the only kind of handle this filesystem can hold
                // on one.
                FsEntryKind::Fifo | FsEntryKind::Socket | FsEntryKind::CharDevice => {
                    if flags.path_only {
                        return self.allocate_handle(inode, 0, Access::LOCATION, kind);
                    }
                    // The permission decision belongs HERE — one enforcement
                    // point for every kind — even though no filesystem
                    // descriptor comes back: opening for reading needs `r` and
                    // for writing `w`, exactly as a regular file does.
                    if flags.exclusive {
                        return Err(EffectError::new(
                            ErrorCode::AlreadyExists,
                            format!("virtual filesystem entry already exists: {path}"),
                        ));
                    }
                    if flags.read && !owner_allows(mode, READ) {
                        return Err(denied(&path, "read"));
                    }
                    if flags.write && !owner_allows(mode, WRITE) {
                        return Err(denied(&path, "write"));
                    }
                    // A FIFO carries no filesystem bytes, so there is no
                    // filesystem description to hand back: the caller opens the
                    // pipe the FIFO's openers share. A socket node or a whiteout
                    // has nothing behind it at all, and the caller answers the
                    // `ENXIO` the kernel's open does. The permission and
                    // existence answers above are the part that IS filesystem
                    // state, and they have been given.
                    return Err(EffectError::new(
                        ErrorCode::InvalidInput,
                        format!(
                            "virtual {kind:?} node is not opened as a filesystem descriptor: {path}"
                        ),
                    ));
                }
                FsEntryKind::File | FsEntryKind::Directory => {}
            }
        }

        if !self.names.contains_key(&path) {
            // A path-only open creates nothing, so a missing name is missing.
            if flags.create {
                self.check_directory_write(parent_path(&path))?;
                self.insert_parent_directories(clock, &path);
                // The caller's own creation mode — `open`'s third argument, which
                // the kernel reads only on the branch that actually creates the
                // entry, already under the caller's umask.
                let inode = self.allocate_inode(clock, FsEntryKind::File, Vec::new(), flags.mode);
                self.names.insert(path.clone(), inode);
                self.stamp_directory(clock, parent_path(&path));
            } else {
                return Err(not_found(&path));
            }
        } else if flags.exclusive {
            return Err(EffectError::new(
                ErrorCode::AlreadyExists,
                format!("virtual filesystem entry already exists: {path}"),
            ));
        } else if !flags.path_only {
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
                // `O_TRUNC` is a truncation: `mtime`/`ctime` move even when the
                // file was already empty (`handle_truncate` → `do_truncate`).
                let inode = self.file_inode(&path)?;
                let inode = self
                    .inodes
                    .get_mut(&inode)
                    .expect("file path references an inode");
                inode.contents.clear();
                inode.times.data_changed(clock);
            }
        }

        let node = self.file_inode(&path)?;
        let cursor = if flags.append {
            self.inodes
                .get(&node)
                .expect("file path references an inode")
                .contents
                .len()
        } else {
            0
        };
        self.allocate_handle(node, cursor, Access::from_flags(flags), FsEntryKind::File)
    }

    fn read(&mut self, clock: FsClock, fd: Fd, max_len: usize) -> DriverResult<Vec<u8>> {
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
        let start = description.cursor;
        let inode = self.handle_inode(fd)?;
        let inode = self
            .inodes
            .get_mut(&inode)
            .expect("open handle references a file");
        let file = &inode.contents;
        let end = start.saturating_add(max_len).min(file.len());
        let bytes = file[start.min(end)..end].to_vec();
        if max_len != 0 {
            inode.times.accessed(clock);
        }
        self.description_mut(fd)?.cursor = start + bytes.len();
        Ok(bytes)
    }

    fn write(&mut self, clock: FsClock, fd: Fd, bytes: &[u8]) -> DriverResult<usize> {
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
        if bytes.is_empty() {
            return Ok(0);
        }
        let cursor = description.cursor;
        let append = description.append;
        let inode = self.handle_inode(fd)?;
        let inode = self
            .inodes
            .get_mut(&inode)
            .expect("open handle references a file");
        let start = if append { inode.contents.len() } else { cursor };
        let end = start.checked_add(bytes.len()).ok_or_else(|| {
            EffectError::new(ErrorCode::InvalidInput, "virtual file size overflowed")
        })?;
        inode.check_write_seals(end)?;
        let file = &mut inode.contents;
        if file.len() < end {
            Self::resize_contents(file, end)?;
        }
        file[start..end].copy_from_slice(bytes);
        inode.times.data_changed(clock);
        self.description_mut(fd)?.cursor = end;
        Ok(bytes.len())
    }

    fn write_at(
        &mut self,
        clock: FsClock,
        fd: Fd,
        offset: u64,
        bytes: &[u8],
    ) -> DriverResult<usize> {
        self.write_node_at(clock, fd, offset, bytes, true)
    }

    /// The page cache's write-back: what a shared mapping stored. A write
    /// seal does not refuse it — a mapping writable before the seal keeps
    /// writing the file.
    fn write_back_at(
        &mut self,
        clock: FsClock,
        fd: Fd,
        offset: u64,
        bytes: &[u8],
    ) -> DriverResult<usize> {
        self.write_node_at(clock, fd, offset, bytes, false)
    }

    fn close(&mut self, fd: Fd) -> DriverResult<()> {
        let id = self.handles.remove(&fd).ok_or_else(|| invalid_fd(fd))?;
        let description = self
            .descriptions
            .get_mut(&id)
            .expect("handle references a description");
        description.fds -= 1;
        if description.fds == 0 {
            // The LAST descriptor on the description drops the description's
            // reference to the node; if its last name went first, this is where
            // the node itself is finally freed.
            let node = description.node;
            self.descriptions.remove(&id);
            if let Some(inode) = self.inodes.get_mut(&node) {
                inode.openers -= 1;
            }
            self.release_if_unreferenced(node);
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
        if description.kind == FsEntryKind::Directory || description.path_only {
            return Err(EffectError::new(
                ErrorCode::InvalidInput,
                format!(
                    "virtual handle {} names a location and cannot be seeked",
                    fd.0
                ),
            ));
        }
        let cursor = description.cursor;
        let inode = self.handle_inode(fd)?;
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

    /// `fstat`. A descriptor answers from its NODE, so an entry whose last name
    /// was unlinked while it stayed open reports its live mode, size and link
    /// count rather than a copy taken when it was opened.
    fn fd_metadata(&mut self, fd: Fd) -> DriverResult<FsMetadata> {
        let description = self.description(fd)?;
        let (node, kind) = (description.node, description.kind);
        if kind == FsEntryKind::Directory {
            let path = self
                .node_path(node, kind)
                .ok_or_else(|| not_found("<removed directory>"))?;
            return self.metadata_for_path(&path);
        }
        self.metadata_for_inode(node)
    }

    /// The LIVE metadata of the entry an inode names — what `fstat` on a FIFO
    /// descriptor reads, since the pipe endpoint holds a node and no filesystem
    /// handle. Any of the node's names answers identically (a mode, a link count
    /// and a timestamp belong to the inode, not to a name), so the first in path
    /// order is taken for determinism. A node with no names left is `NotFound`:
    /// the filesystem has nothing to say about an inode only a descriptor holds.
    fn inode_metadata(&mut self, ino: u64) -> DriverResult<FsMetadata> {
        self.metadata_for_inode(ino)
    }

    /// `fchmod` on a node, for the descriptor class the filesystem holds no
    /// handle for. It reaches an unlinked node exactly as `inode_metadata` does.
    fn set_inode_mode(&mut self, clock: FsClock, ino: u64, mode: u32) -> DriverResult<()> {
        let inode = self.inodes.get_mut(&ino).ok_or_else(|| {
            EffectError::new(
                ErrorCode::NotFound,
                format!("no virtual filesystem node {ino}"),
            )
        })?;
        inode.mode = mode & MODE_MASK;
        inode.times.metadata_changed(clock);
        Ok(())
    }

    /// Take a descriptor's reference on a node the filesystem hands back no
    /// handle for — the FIFO endpoint whose bytes belong to the openers' pipe.
    fn retain_inode(&mut self, ino: u64) -> DriverResult<()> {
        let inode = self.inodes.get_mut(&ino).ok_or_else(|| {
            EffectError::new(
                ErrorCode::NotFound,
                format!("no virtual filesystem node {ino}"),
            )
        })?;
        inode.openers += 1;
        Ok(())
    }

    fn release_inode(&mut self, ino: u64) -> DriverResult<()> {
        let inode = self.inodes.get_mut(&ino).ok_or_else(|| {
            EffectError::new(
                ErrorCode::NotFound,
                format!("no virtual filesystem node {ino}"),
            )
        })?;
        if inode.openers == 0 {
            return Err(EffectError::new(
                ErrorCode::InvalidState,
                format!("virtual filesystem node {ino} holds no descriptor reference"),
            ));
        }
        inode.openers -= 1;
        self.release_if_unreferenced(ino);
        Ok(())
    }

    fn create_directory(&mut self, clock: FsClock, path: &str, mode: u32) -> DriverResult<()> {
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
        // `mkdir`'s mode argument, already under the caller's umask.
        let metadata = self.allocate_entry_metadata(clock, mode);
        self.directories.insert(path.clone(), metadata);
        self.stamp_directory(clock, parent_path(&path));
        Ok(())
    }

    fn make_fifo(&mut self, clock: FsClock, path: &str, mode: u32) -> DriverResult<()> {
        // A FIFO is an inode with no bytes: hard links, the link count, the
        // mode and the identity the openers' pipe channel is keyed by all live
        // there, exactly as they do for a regular file.
        self.make_node(clock, path, FsNode::Fifo, mode)
    }

    /// `mknod`: a new name for a fresh node with no bytes, at the mode the
    /// caller asked for (already under its umask). The name and the parent's
    /// `w`+`x` are judged first, then the privilege a device other than the
    /// whiteout needs, which the one modeled identity does not have.
    fn make_node(
        &mut self,
        clock: FsClock,
        path: &str,
        node: FsNode,
        mode: u32,
    ) -> DriverResult<()> {
        let path = normalize_entry_path(path)?;
        self.check_new_name(&path)?;
        let kind = node.kind().ok_or_else(|| {
            EffectError::new(
                ErrorCode::NotPermitted,
                format!("a device node needs CAP_MKNOD: {path}"),
            )
        })?;
        let inode = self.allocate_inode(clock, kind, Vec::new(), mode);
        self.names.insert(path.clone(), inode);
        self.stamp_directory(clock, parent_path(&path));
        Ok(())
    }

    /// `renameat2(RENAME_WHITEOUT)`: the rename, then a whiteout (a 0:0
    /// character device, mode 0) at the name it vacated, in one call. A rename
    /// between two names of one node changes nothing, whiteout included.
    fn rename_whiteout(&mut self, clock: FsClock, from: &str, to: &str) -> DriverResult<()> {
        self.rename(clock, from, to)?;
        let from = normalize_entry_path(from)?;
        if self.path_exists(&from) {
            return Ok(());
        }
        let inode = self.allocate_inode(clock, FsEntryKind::CharDevice, Vec::new(), 0);
        self.names.insert(from, inode);
        Ok(())
    }

    fn remove_file(&mut self, clock: FsClock, path: &str) -> DriverResult<()> {
        let path = normalize_entry_path(path)?;
        self.resolve_guard(&path)?;
        self.check_directory_write(parent_path(&path))?;
        if self.directories.contains_key(&path) {
            return Err(EffectError::new(
                ErrorCode::IsDirectory,
                format!("virtual filesystem path is a directory: {path}"),
            ));
        }
        // Unlink removes the NAME, never the node. Whatever still holds the node
        // — another name, or an open descriptor — keeps it alive, and the last
        // reference of either kind is what frees it. A FIFO name goes the same
        // way whatever is open on it: the openers hold the pipe, not the name.
        let inode = self.names.remove(&path).ok_or_else(|| not_found(&path))?;
        self.drop_name(clock, inode);
        self.stamp_directory(clock, parent_path(&path));
        Ok(())
    }

    fn sync(&mut self, fd: Fd) -> DriverResult<()> {
        let description = self.description(fd)?;
        if description.path_only {
            return Err(EffectError::new(
                ErrorCode::InvalidHandle,
                format!(
                    "virtual handle {} names a location and cannot be synced",
                    fd.0
                ),
            ));
        }
        Ok(())
    }

    /// `ftruncate`. The kernel's refusals (`do_sys_ftruncate`): a path-only
    /// descriptor is `EBADF`; a directory, or any descriptor not open for
    /// writing, is `EINVAL` — not `EBADF` (the number is valid) and not
    /// `EISDIR` (that is the by-NAME answer). `mtime`/`ctime` move even when
    /// the length does not.
    fn set_len(&mut self, clock: FsClock, fd: Fd, len: u64) -> DriverResult<()> {
        let description = self.description(fd)?;
        if description.kind == FsEntryKind::Directory {
            return Err(EffectError::new(
                ErrorCode::InvalidInput,
                format!("virtual file handle {} references a directory", fd.0),
            ));
        }
        if description.path_only {
            return Err(EffectError::new(
                ErrorCode::InvalidHandle,
                format!(
                    "virtual handle {} names a location and cannot be truncated",
                    fd.0
                ),
            ));
        }
        if !description.writable {
            return Err(EffectError::new(
                ErrorCode::InvalidInput,
                format!("virtual file handle {} is not open for writing", fd.0),
            ));
        }
        let inode = self.handle_inode(fd)?;
        let target = usize::try_from(len).unwrap_or(usize::MAX);
        self.inodes
            .get(&inode)
            .expect("open handle references a file")
            .check_resize_seals(target)?;
        Self::truncate_inode(self.inodes.get_mut(&inode), clock, len)
    }

    /// `truncate(2)`: `EISDIR` for a directory, `EINVAL` for any other
    /// non-regular entry (a FIFO, a socket node, a whiteout, or a symlink the
    /// caller declined to follow), `EACCES` without `w`.
    fn set_len_by_path(&mut self, clock: FsClock, path: &str, len: u64) -> DriverResult<()> {
        let path = normalize_entry_path(path)?;
        self.resolve_guard(&path)?;
        if self.directories.contains_key(&path) {
            return Err(EffectError::new(
                ErrorCode::IsDirectory,
                format!("virtual filesystem path is a directory: {path}"),
            ));
        }
        if self
            .leaf_kind(&path)
            .is_some_and(|kind| kind != FsEntryKind::File)
        {
            return Err(EffectError::new(
                ErrorCode::InvalidInput,
                format!("virtual filesystem entry is not a regular file: {path}"),
            ));
        }
        let inode = self.file_inode(&path)?;
        let mode = self
            .inodes
            .get(&inode)
            .expect("file path references an inode")
            .mode;
        if !owner_allows(mode, WRITE) {
            return Err(denied(&path, "write"));
        }
        Self::truncate_inode(self.inodes.get_mut(&inode), clock, len)
    }

    /// `fallocate`: the kernel's refusals in its order (`EBADF` for a
    /// descriptor not open for writing or a path-only one, `EISDIR` for a
    /// directory), then the range change, then `mtime`/`ctime`.
    fn allocate(
        &mut self,
        clock: FsClock,
        fd: Fd,
        offset: u64,
        len: u64,
        zero: bool,
        keep_size: bool,
    ) -> DriverResult<()> {
        let description = self.description(fd)?;
        if description.path_only || !description.writable {
            return Err(EffectError::new(
                ErrorCode::NotWritable,
                format!("virtual file handle {} is not open for writing", fd.0),
            ));
        }
        if description.kind == FsEntryKind::Directory {
            return Err(EffectError::new(
                ErrorCode::IsDirectory,
                format!("virtual file handle {} references a directory", fd.0),
            ));
        }
        let end = offset.checked_add(len).ok_or_else(|| {
            EffectError::new(
                ErrorCode::InvalidInput,
                "virtual allocation range overflowed",
            )
        })?;
        let (start, end) = (usize::try_from(offset), usize::try_from(end));
        let (Ok(start), Ok(end)) = (start, end) else {
            return Err(EffectError::new(
                ErrorCode::InvalidInput,
                "virtual allocation range exceeds the addressable range",
            ));
        };
        let inode = self.handle_inode(fd)?;
        let inode = self
            .inodes
            .get_mut(&inode)
            .expect("open handle references a file");
        // `hugetlbfs_fallocate` with no huge page to allocate: a hole punch has
        // nothing to free, an allocation fails.
        if inode.huge_page != 0 {
            if zero {
                return Ok(());
            }
            return Err(EffectError::new(
                ErrorCode::NoSpace,
                "no huge page is reserved to allocate",
            ));
        }
        // `shmem_fallocate`: punching needs no write seal, growing no grow seal.
        let seals = inode.seals.unwrap_or(0);
        if (zero && seals & (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE) != 0)
            || (!keep_size && end > inode.contents.len() && seals & F_SEAL_GROW != 0)
        {
            return Err(sealed());
        }
        let file = &mut inode.contents;
        if !keep_size && end > file.len() {
            Self::resize_contents(file, end)?;
        }
        if zero {
            let end = end.min(file.len());
            if start < end {
                file[start..end].fill(0);
            }
        }
        inode.times.data_changed(clock);
        Ok(())
    }

    fn set_times(
        &mut self,
        clock: FsClock,
        fd: Fd,
        atime_nanos: Option<u64>,
        mtime_nanos: Option<u64>,
    ) -> DriverResult<()> {
        let description = self.description(fd)?;
        if description.path_only {
            return Err(EffectError::new(
                ErrorCode::InvalidHandle,
                format!("virtual handle {} names a location and has no times", fd.0),
            ));
        }
        let (node, kind) = (description.node, description.kind);
        if kind == FsEntryKind::Directory {
            let path = self
                .node_path(node, kind)
                .ok_or_else(|| not_found("<removed directory>"))?;
            let times = self.times_mut(&path).expect("a named directory has times");
            times.set(clock, atime_nanos, mtime_nanos);
            return Ok(());
        }
        let inode = self.inodes.get_mut(&node).ok_or_else(|| invalid_fd(fd))?;
        inode.times.set(clock, atime_nanos, mtime_nanos);
        Ok(())
    }

    fn set_inode_times(
        &mut self,
        clock: FsClock,
        ino: u64,
        atime_nanos: Option<u64>,
        mtime_nanos: Option<u64>,
    ) -> DriverResult<()> {
        let times = if let Some(inode) = self.inodes.get_mut(&ino) {
            &mut inode.times
        } else {
            &mut self
                .directories
                .values_mut()
                .find(|entry| entry.ino == ino)
                .ok_or_else(|| not_found("<inode>"))?
                .times
        };
        times.set(clock, atime_nanos, mtime_nanos);
        Ok(())
    }

    fn set_times_by_path(
        &mut self,
        clock: FsClock,
        path: &str,
        atime_nanos: Option<u64>,
        mtime_nanos: Option<u64>,
    ) -> DriverResult<()> {
        let path = normalize_entry_path(path)?;
        self.resolve_guard(&path)?;
        let times = self.times_mut(&path).ok_or_else(|| not_found(&path))?;
        times.set(clock, atime_nanos, mtime_nanos);
        Ok(())
    }

    fn read_directory(
        &mut self,
        clock: FsClock,
        path: &str,
    ) -> DriverResult<Vec<FsDirectoryEntry>> {
        let path = normalize_entry_path(path)?;
        self.resolve_guard(&path)?;
        if self.names.contains_key(&path) {
            return Err(EffectError::new(
                ErrorCode::NotDirectory,
                format!("virtual filesystem path is not a directory: {path}"),
            ));
        }
        let Some(metadata) = self.directories.get(&path).copied() else {
            return Err(not_found(&path));
        };
        // The fused path form is `opendir`+`readdir` in one call, so it charges
        // the `r` the open inside it would have charged. The descriptor form
        // ([`FsDriver::read_directory_fd`]) charges nothing: its `r` was paid
        // when the descriptor was opened.
        if !owner_allows(metadata.mode, READ) {
            return Err(denied(&path, "list"));
        }
        self.directories
            .get_mut(&path)
            .expect("directory was checked")
            .times
            .accessed(clock);
        self.list_directory(&path)
    }

    fn read_directory_fd(&mut self, clock: FsClock, fd: Fd) -> DriverResult<Vec<FsDirectoryEntry>> {
        let description = self.description(fd)?;
        if description.kind != FsEntryKind::Directory {
            return Err(EffectError::new(
                ErrorCode::NotDirectory,
                format!(
                    "virtual file handle {} does not reference a directory",
                    fd.0
                ),
            ));
        }
        if !description.readable {
            // An `O_PATH` directory descriptor: it names the location and never
            // opened it, so there is nothing to iterate however permissive the
            // directory's own bits are.
            return Err(EffectError::new(
                ErrorCode::NotReadable,
                format!(
                    "virtual directory handle {} was not opened for reading",
                    fd.0
                ),
            ));
        }
        let path = self
            .node_path(description.node, FsEntryKind::Directory)
            .ok_or_else(|| not_found("<removed directory>"))?;
        // Reached through the descriptor, the listing itself is unenforced: the
        // access was charged at open, and a `chmod` afterwards cannot reach back
        // into a walk already under way.
        self.directories
            .get_mut(&path)
            .expect("the node has a name")
            .times
            .accessed(clock);
        let mut listing = self.dot_entries(&path).to_vec();
        listing.extend(self.list_directory(&path)?);
        Ok(listing)
    }

    fn remove_directory(&mut self, clock: FsClock, path: &str) -> DriverResult<()> {
        let path = normalize_entry_path(path)?;
        self.resolve_guard(&path)?;
        self.check_directory_write(parent_path(&path))?;
        if path == "/" {
            return Err(EffectError::new(
                ErrorCode::Denied,
                "cannot remove the virtual filesystem root",
            ));
        }
        if self.names.contains_key(&path) {
            return Err(EffectError::new(
                ErrorCode::NotDirectory,
                format!("virtual filesystem path is not a directory: {path}"),
            ));
        }
        if !self.directories.contains_key(&path) {
            return Err(not_found(&path));
        }
        if self.has_children(&path) {
            return Err(EffectError::new(
                ErrorCode::DirectoryNotEmpty,
                format!("virtual directory is not empty: {path}"),
            ));
        }
        self.drop_directory(&path);
        self.stamp_directory(clock, parent_path(&path));
        Ok(())
    }

    /// `rename`. A name moves onto a free name or replaces what is there: a
    /// non-directory replaces a non-directory (`EISDIR` onto a directory), a
    /// directory replaces an EMPTY directory (`ENOTDIR` onto anything else,
    /// `ENOTEMPTY` onto a directory with entries). Two names for one node (a
    /// file onto its own hard link, a name onto itself) are the kernel's
    /// no-op success. A directory cannot move beneath itself (`EINVAL`).
    fn rename(&mut self, clock: FsClock, from: &str, to: &str) -> DriverResult<()> {
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
        if let Some(inode) = self.names.get(&from).copied() {
            if self.directories.contains_key(&to) {
                return Err(EffectError::new(
                    ErrorCode::IsDirectory,
                    format!("virtual rename destination is a directory: {to}"),
                ));
            }
            if self.names.get(&to) == Some(&inode) {
                return Ok(());
            }
            self.names.remove(&from);
            self.unlink_leaf_at(clock, &to);
            self.names.insert(to.clone(), inode);
            // Nothing else to do: a description holds the NODE, so every
            // descriptor on this entry moved with it by construction.
            self.stamp_renamed(clock, &from, &to);
            return Ok(());
        }
        if !self.directories.contains_key(&from) {
            return Err(not_found(&from));
        }
        if from == to {
            return Ok(());
        }
        if self.names.contains_key(&to) {
            return Err(EffectError::new(
                ErrorCode::NotDirectory,
                format!("virtual rename of a directory onto a non-directory: {to}"),
            ));
        }
        if self.directories.contains_key(&to) {
            if self.has_children(&to) {
                return Err(EffectError::new(
                    ErrorCode::DirectoryNotEmpty,
                    format!("virtual rename destination is not empty: {to}"),
                ));
            }
            // An empty directory is replaced: its name now belongs to the
            // moved directory, and the node it named is gone.
            self.drop_directory(&to);
        }
        let moved = self.take_subtree(&from);
        self.place_subtree(moved, &to);
        self.stamp_renamed(clock, &from, &to);
        Ok(())
    }

    /// `renameat2(RENAME_EXCHANGE)`: both names must exist; each takes the
    /// other's entry — a directory's whole subtree with it — whatever the two
    /// kinds are. One cannot hold the other (`EINVAL`); a name exchanged with
    /// itself, or with another name for the same node, changes nothing.
    fn exchange(&mut self, clock: FsClock, first: &str, second: &str) -> DriverResult<()> {
        let first = normalize_entry_path(first)?;
        let second = normalize_entry_path(second)?;
        self.resolve_guard(&first)?;
        self.resolve_guard(&second)?;
        self.check_directory_write(parent_path(&first))?;
        self.check_directory_write(parent_path(&second))?;
        for path in [&first, &second] {
            if !self.path_exists(path) {
                return Err(not_found(path));
            }
        }
        if first == "/"
            || second == "/"
            || second.starts_with(&format!("{first}/"))
            || first.starts_with(&format!("{second}/"))
        {
            return Err(EffectError::new(
                ErrorCode::InvalidInput,
                format!("invalid virtual exchange of {first} and {second}"),
            ));
        }
        if first == second || self.node_id(&first) == self.node_id(&second) {
            return Ok(());
        }
        let first_tree = self.take_subtree(&first);
        let second_tree = self.take_subtree(&second);
        self.place_subtree(first_tree, &second);
        self.place_subtree(second_tree, &first);
        for path in [&first, &second] {
            if let Some(times) = self.times_mut(path) {
                times.metadata_changed(clock);
            }
        }
        self.stamp_directory(clock, parent_path(&first));
        if parent_path(&second) != parent_path(&first) {
            self.stamp_directory(clock, parent_path(&second));
        }
        Ok(())
    }

    /// `link`: a second name for the node `from` names, whatever its kind but
    /// a directory's (`EPERM`) — a symlink's included: without
    /// `AT_SYMLINK_FOLLOW` the kernel links the link itself.
    fn link(&mut self, clock: FsClock, from: &str, to: &str) -> DriverResult<()> {
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
                ErrorCode::NotPermitted,
                format!("virtual hard link to a directory: {from}"),
            ));
        }
        let inode = self
            .names
            .get(&from)
            .copied()
            .ok_or_else(|| not_found(&from))?;
        self.names.insert(to.clone(), inode);
        let entry = self
            .inodes
            .get_mut(&inode)
            .expect("name references an inode");
        entry.links += 1;
        // The link count is inode metadata: `ctime` moves on the node, and the
        // new name is a data change to its directory.
        entry.times.metadata_changed(clock);
        self.stamp_directory(clock, parent_path(&to));
        Ok(())
    }

    fn symlink(&mut self, clock: FsClock, target: &str, link_path: &str) -> DriverResult<()> {
        if target.contains('\0') {
            return Err(EffectError::new(
                ErrorCode::InvalidInput,
                "virtual symlink target contains NUL",
            ));
        }
        let link_path = normalize_entry_path(link_path)?;
        self.check_new_name(&link_path)?;
        let inode = self.allocate_inode(
            clock,
            FsEntryKind::Symlink,
            target.as_bytes().to_vec(),
            SYMLINK_MODE,
        );
        self.names.insert(link_path.clone(), inode);
        self.stamp_directory(clock, parent_path(&link_path));
        Ok(())
    }

    fn read_link(&mut self, clock: FsClock, path: &str) -> DriverResult<String> {
        let path = normalize_entry_path(path)?;
        self.resolve_guard(&path)?;
        if let Some(ino) = self
            .names
            .get(&path)
            .copied()
            .filter(|ino| self.kind_of(*ino) == Some(FsEntryKind::Symlink))
        {
            let inode = self.inodes.get_mut(&ino).expect("name references an inode");
            // Reading a link is a read of the link: `atime`, under the policy.
            inode.times.accessed(clock);
            return Ok(String::from_utf8_lossy(&inode.contents).into_owned());
        }
        // An entry that exists but is not a symlink is `EINVAL` (readlink(2)),
        // distinguishable from a name that is not there at all.
        if self.path_exists(&path) {
            return Err(EffectError::new(
                ErrorCode::InvalidInput,
                format!("virtual filesystem entry is not a symbolic link: {path}"),
            ));
        }
        Err(not_found(&path))
    }

    /// `chmod` / `fchmodat`. Changing a mode is an OWNER right, not a
    /// permission-bit right, and the single modeled identity owns every entry —
    /// so only REACHING the entry is checked, never the entry's own bits.
    ///
    /// A symlink leaf has no mode of its own here (Linux ignores one too), so
    /// naming a link fails closed rather than silently recording a mode nothing
    /// will ever read. `chmod`'s follow-the-link spelling resolves above this
    /// boundary and arrives naming the target.
    fn set_mode(&mut self, clock: FsClock, path: &str, mode: u32) -> DriverResult<()> {
        let path = normalize_entry_path(path)?;
        self.resolve_guard(&path)?;
        if self.leaf_kind(&path) == Some(FsEntryKind::Symlink) {
            return Err(EffectError::new(
                ErrorCode::Denied,
                format!("virtual symlink has no mode of its own: {path}"),
            ));
        }
        self.apply_mode(clock, &path, mode)
    }

    /// `fchmod`. The bits belong to the NODE, so this reaches an unlinked entry
    /// through its descriptor exactly as a kernel does — and an `O_PATH`
    /// descriptor, which never opened the file, cannot change them at all.
    fn set_fd_mode(&mut self, clock: FsClock, fd: Fd, mode: u32) -> DriverResult<()> {
        let description = self.description(fd)?;
        if description.path_only {
            return Err(EffectError::new(
                ErrorCode::InvalidHandle,
                format!("virtual handle {} names a location and has no mode", fd.0),
            ));
        }
        let (node, kind) = (description.node, description.kind);
        if kind == FsEntryKind::Directory {
            let path = self
                .node_path(node, kind)
                .ok_or_else(|| not_found("<removed directory>"))?;
            return self.apply_mode(clock, &path, mode);
        }
        let inode = self.inodes.get_mut(&node).ok_or_else(|| invalid_fd(fd))?;
        inode.mode = mode & MODE_MASK;
        inode.times.metadata_changed(clock);
        Ok(())
    }

    /// The path this descriptor's NODE currently has — see
    /// [`FsDriver::fd_path`]. A description is bound to the node, and every
    /// rename that moves the node rewrites the descriptions that reference it,
    /// so this answers where the node IS rather than the name it was opened
    /// under.
    fn fd_path(&mut self, fd: Fd) -> DriverResult<String> {
        let description = self.description(fd)?;
        let (node, kind) = (description.node, description.kind);
        self.node_path(node, kind)
            .ok_or_else(|| not_found("<unlinked node>"))
    }

    fn fd_ino(&mut self, fd: Fd) -> DriverResult<u64> {
        Ok(self.description(fd)?.node)
    }

    /// `sync(2)`: nothing to write back — every change is already the image.
    fn sync_all(&mut self) -> DriverResult<()> {
        Ok(())
    }

    fn get_xattr(&mut self, target: &XattrTarget, name: &str) -> DriverResult<Vec<u8>> {
        let (ino, kind, mode) = self.xattr_node(target)?;
        Self::check_xattr(kind, mode, name, XattrAccess::Read)?;
        self.xattrs
            .get(&ino)
            .and_then(|attributes| attributes.get(name))
            .cloned()
            .ok_or_else(|| no_xattr(name))
    }

    /// The names a caller may see: every attribute but a `trusted.*` one, which
    /// is listed only to `CAP_SYS_ADMIN`. Listing checks no permission bits.
    fn list_xattr(&mut self, target: &XattrTarget) -> DriverResult<Vec<String>> {
        let (ino, _, _) = self.xattr_node(target)?;
        Ok(self
            .xattrs
            .get(&ino)
            .map(|attributes| {
                attributes
                    .keys()
                    .filter(|name| XattrNamespace::of(name) != XattrNamespace::Trusted)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default())
    }

    /// `XATTR_CREATE` on a name that exists is `EEXIST`, `XATTR_REPLACE` on
    /// one that does not `ENODATA` (with both, whichever applies). The node's
    /// `ctime` moves.
    fn set_xattr(
        &mut self,
        clock: FsClock,
        target: &XattrTarget,
        name: &str,
        value: &[u8],
        flags: u32,
    ) -> DriverResult<()> {
        let (ino, kind, mode) = self.xattr_node(target)?;
        Self::check_xattr(kind, mode, name, XattrAccess::Write)?;
        let exists = self
            .xattrs
            .get(&ino)
            .is_some_and(|attributes| attributes.contains_key(name));
        if exists && flags & XATTR_CREATE != 0 {
            return Err(EffectError::new(
                ErrorCode::AlreadyExists,
                format!("virtual extended attribute already exists: {name}"),
            ));
        }
        if !exists && flags & XATTR_REPLACE != 0 {
            return Err(no_xattr(name));
        }
        self.xattrs
            .entry(ino)
            .or_default()
            .insert(name.to_owned(), value.to_vec());
        self.stamp_node(clock, ino, kind);
        Ok(())
    }

    fn remove_xattr(
        &mut self,
        clock: FsClock,
        target: &XattrTarget,
        name: &str,
    ) -> DriverResult<()> {
        let (ino, kind, mode) = self.xattr_node(target)?;
        Self::check_xattr(kind, mode, name, XattrAccess::Write)?;
        let attributes = self.xattrs.get_mut(&ino).ok_or_else(|| no_xattr(name))?;
        attributes.remove(name).ok_or_else(|| no_xattr(name))?;
        if attributes.is_empty() {
            self.xattrs.remove(&ino);
        }
        self.stamp_node(clock, ino, kind);
        Ok(())
    }

    /// [`FsDriver::create_anonymous`]: a node with no name, alive while a
    /// descriptor holds it, exactly an unlinked file's lifetime.
    fn create_anonymous(
        &mut self,
        clock: FsClock,
        _name: &str,
        mode: u32,
        seals: u32,
        huge_page: u64,
    ) -> DriverResult<Fd> {
        let node = self.next_inode;
        self.next_inode = self.next_inode.checked_add(1).ok_or_else(|| {
            EffectError::new(ErrorCode::NoSpace, "virtual inode numbers exhausted")
        })?;
        self.inodes.insert(
            node,
            Inode {
                kind: FsEntryKind::File,
                contents: Vec::new(),
                links: 0,
                openers: 0,
                times: Times::created(clock),
                mode: mode & MODE_MASK,
                seals: Some(seals & F_ALL_SEALS),
                huge_page,
            },
        );
        let access = Access {
            readable: true,
            writable: true,
            append: false,
            path_only: false,
        };
        match self.allocate_handle(node, 0, access, FsEntryKind::File) {
            Ok(fd) => Ok(fd),
            Err(error) => {
                self.inodes.remove(&node);
                Err(error)
            }
        }
    }

    fn seals(&mut self, fd: Fd) -> DriverResult<u32> {
        let node = self.description(fd)?.node;
        self.inodes
            .get(&node)
            .and_then(|inode| inode.seals)
            .ok_or_else(not_sealable)
    }

    fn add_seals(&mut self, fd: Fd, seals: u32, writably_mapped: bool) -> DriverResult<()> {
        let description = self.description(fd)?;
        if !description.writable {
            return Err(EffectError::new(
                ErrorCode::NotPermitted,
                format!("virtual file handle {} is not open for writing", fd.0),
            ));
        }
        if seals & !F_ALL_SEALS != 0 {
            return Err(EffectError::new(ErrorCode::InvalidInput, "unknown seal"));
        }
        let node = description.node;
        let inode = self
            .inodes
            .get_mut(&node)
            .filter(|inode| inode.seals.is_some())
            .ok_or_else(not_sealable)?;
        let current = inode.seals.expect("filtered to a sealable node");
        if current & F_SEAL_SEAL != 0 {
            return Err(sealed());
        }
        if seals & F_SEAL_WRITE != 0 && current & F_SEAL_WRITE == 0 && writably_mapped {
            return Err(EffectError::new(
                ErrorCode::Busy,
                "a shared writable mapping of the virtual file is live",
            ));
        }
        // `F_SEAL_EXEC` on an executable file implies every write seal.
        let implied = if seals & F_SEAL_EXEC != 0 && inode.mode & 0o111 != 0 {
            F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_FUTURE_WRITE
        } else {
            0
        };
        inode.seals = Some(current | seals | implied);
        Ok(())
    }
}

fn not_sealable() -> EffectError {
    EffectError::new(
        ErrorCode::InvalidInput,
        "only an anonymous virtual file can be sealed",
    )
}

impl MemFs {
    /// A positional write through `fd`, judged against the node's write seals
    /// when `sealed`.
    fn write_node_at(
        &mut self,
        clock: FsClock,
        fd: Fd,
        offset: u64,
        bytes: &[u8],
        sealed: bool,
    ) -> DriverResult<usize> {
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
        if bytes.is_empty() {
            return Ok(0);
        }
        let start = usize::try_from(offset).map_err(|_| {
            EffectError::new(
                ErrorCode::InvalidInput,
                "virtual write offset exceeds the addressable range",
            )
        })?;
        let end = start.checked_add(bytes.len()).ok_or_else(|| {
            EffectError::new(ErrorCode::InvalidInput, "virtual file size overflowed")
        })?;
        let inode = self.handle_inode(fd)?;
        let inode = self
            .inodes
            .get_mut(&inode)
            .expect("open handle references a file");
        if sealed {
            inode.check_write_seals(end)?;
        }
        let file = &mut inode.contents;
        if file.len() < end {
            Self::resize_contents(file, end)?;
        }
        file[start..end].copy_from_slice(bytes);
        inode.times.data_changed(clock);
        Ok(bytes.len())
    }

    /// Enumerate one directory's immediate children, in path order and without
    /// enforcement. Both listing entry points share it: the access decision is
    /// theirs, the enumeration is one implementation.
    fn list_directory(&self, path: &str) -> DriverResult<Vec<FsDirectoryEntry>> {
        let prefix = if path == "/" {
            "/".to_owned()
        } else {
            format!("{path}/")
        };
        let child = |candidate: &String| {
            candidate
                .strip_prefix(&prefix)
                .filter(|relative| !relative.is_empty() && !relative.contains('/'))
                .map(str::to_owned)
        };
        let mut entries = BTreeMap::new();
        for (directory, metadata) in &self.directories {
            if let Some(name) = child(directory) {
                entries.insert(name, (FsEntryKind::Directory, metadata.ino));
            }
        }
        for (name, ino) in &self.names {
            if let Some(name) = child(name) {
                let kind = self.kind_of(*ino).expect("name references an inode");
                entries.insert(name, (kind, *ino));
            }
        }
        Ok(entries
            .into_iter()
            .map(|(name, (kind, ino))| FsDirectoryEntry { name, kind, ino })
            .collect())
    }

    /// The `.` and `..` a descriptor listing starts with: the directory's own
    /// inode and its parent's (the root is its own parent), as `getdents`
    /// reports them.
    fn dot_entries(&self, path: &str) -> [FsDirectoryEntry; 2] {
        let parent = match path.rfind('/') {
            Some(0) | None => "/",
            Some(slash) => &path[..slash],
        };
        [(".", path), ("..", parent)].map(|(name, directory)| FsDirectoryEntry {
            name: name.into(),
            kind: FsEntryKind::Directory,
            ino: self.directories[directory].ino,
        })
    }

    /// Drop whatever non-directory NAME sits at `path`, releasing its node
    /// reference. The one place a rename's destination is overwritten, so no
    /// kind can be dropped without its link count following.
    fn unlink_leaf_at(&mut self, clock: FsClock, path: &str) {
        if let Some(replaced) = self.names.remove(path) {
            self.drop_name(clock, replaced);
        }
    }

    /// Detach every entry at or beneath `root` — the entry itself and, for a
    /// directory, its whole subtree — as `(relative suffix, entry)` pairs.
    fn take_subtree(&mut self, root: &str) -> Subtree {
        let prefix = format!("{root}/");
        let within = |path: &String| *path == root || path.starts_with(&prefix);
        let directory_paths: Vec<String> = self
            .directories
            .keys()
            .filter(|path| within(path))
            .cloned()
            .collect();
        let name_paths: Vec<String> = self
            .names
            .keys()
            .filter(|path| within(path))
            .cloned()
            .collect();
        Subtree {
            directories: directory_paths
                .into_iter()
                .map(|path| {
                    let metadata = self.directories.remove(&path).expect("path was listed");
                    (path[root.len()..].to_owned(), metadata)
                })
                .collect(),
            names: name_paths
                .into_iter()
                .map(|path| {
                    let ino = self.names.remove(&path).expect("path was listed");
                    (path[root.len()..].to_owned(), ino)
                })
                .collect(),
        }
    }

    /// Re-attach a detached subtree under `root`. Nodes keep their identity, so
    /// every descriptor on one moves with it by construction.
    fn place_subtree(&mut self, subtree: Subtree, root: &str) {
        for (suffix, metadata) in subtree.directories {
            self.directories.insert(format!("{root}{suffix}"), metadata);
        }
        for (suffix, ino) in subtree.names {
            self.names.insert(format!("{root}{suffix}"), ino);
        }
    }

    /// A rename moved the node from `from` to `to`: both parents changed (a
    /// name left one, a name arrived in the other) and the node's own `ctime`
    /// moves, as every Linux filesystem's `rename` stamps it.
    fn stamp_renamed(&mut self, clock: FsClock, from: &str, to: &str) {
        if let Some(times) = self.times_mut(to) {
            times.metadata_changed(clock);
        }
        self.stamp_directory(clock, parent_path(from));
        if parent_path(to) != parent_path(from) {
            self.stamp_directory(clock, parent_path(to));
        }
    }

    /// A node's metadata changed (an attribute set or removed): its `ctime`.
    fn stamp_node(&mut self, clock: FsClock, ino: InodeId, kind: FsEntryKind) {
        let times = if kind == FsEntryKind::Directory {
            self.directories
                .values_mut()
                .find(|metadata| metadata.ino == ino)
                .map(|metadata| &mut metadata.times)
        } else {
            self.inodes.get_mut(&ino).map(|inode| &mut inode.times)
        };
        if let Some(times) = times {
            times.metadata_changed(clock);
        }
    }

    /// Write `mode`'s permission bits onto the entry `path` names, stamping
    /// `ctime`: the kernel writes the inode whether or not the bits changed.
    fn apply_mode(&mut self, clock: FsClock, path: &str, mode: u32) -> DriverResult<()> {
        let mode = mode & MODE_MASK;
        if let Some(inode) = self.names.get(path).copied() {
            let inode = self
                .inodes
                .get_mut(&inode)
                .expect("name references an inode");
            inode.mode = mode;
            inode.times.metadata_changed(clock);
            return Ok(());
        }
        if let Some(metadata) = self.directories.get_mut(path) {
            metadata.mode = mode;
            metadata.times.metadata_changed(clock);
            return Ok(());
        }
        Err(not_found(path))
    }

    /// Resize a file's contents (zero-filling growth) and stamp `mtime`/
    /// `ctime` — `do_truncate` moves them even when the length is unchanged.
    fn resize_contents(contents: &mut Vec<u8>, len: usize) -> DriverResult<()> {
        if len > contents.len() {
            contents.try_reserve(len - contents.len()).map_err(|_| {
                EffectError::new(ErrorCode::NoSpace, "virtual filesystem capacity exhausted")
            })?;
        }
        contents.resize(len, 0);
        Ok(())
    }

    fn truncate_inode(inode: Option<&mut Inode>, clock: FsClock, len: u64) -> DriverResult<()> {
        let len = usize::try_from(len).map_err(|_| {
            EffectError::new(
                ErrorCode::InvalidInput,
                "virtual file length exceeds the addressable range",
            )
        })?;
        let inode = inode.expect("a checked handle or name references an inode");
        Self::resize_contents(&mut inode.contents, len)?;
        inode.times.data_changed(clock);
        Ok(())
    }

    fn metadata_for_path(&self, path: &str) -> DriverResult<FsMetadata> {
        if let Some(inode_id) = self.names.get(path) {
            return self.metadata_for_inode(*inode_id);
        }
        if let Some(metadata) = self.directories.get(path) {
            return Ok(FsMetadata {
                kind: FsEntryKind::Directory,
                len: 0,
                ino: metadata.ino,
                nlink: self.directory_links(path),
                atime_nanos: metadata.times.atime_nanos,
                mtime_nanos: metadata.times.mtime_nanos,
                ctime_nanos: metadata.times.ctime_nanos,
                btime_nanos: metadata.times.btime_nanos,
                mode: metadata.mode,
            });
        }
        Err(not_found(path))
    }
}

/// The entries at and beneath one path, detached for a move: each keyed by its
/// suffix relative to that path (`""` for the entry itself).
struct Subtree {
    directories: Vec<(String, EntryMetadata)>,
    names: Vec<(String, InodeId)>,
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

/// A missing extended attribute (`ENODATA`).
fn no_xattr(name: &str) -> EffectError {
    EffectError::new(
        ErrorCode::NoData,
        format!("virtual extended attribute does not exist: {name}"),
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
    fn modes_are_the_creation_modes_handed_down_and_chmod_changes_them() {
        let mut fs = MemFs::new();
        fs.create_directory(FsClock::EPOCH, "/perm", 0o755).unwrap();
        let fd = fs
            .open(
                FsClock::EPOCH,
                "/perm/file",
                OpenFlags {
                    path_only: false,
                    mode: 0o644,
                    ..OpenFlags::create_truncate_write()
                },
            )
            .unwrap();
        fs.close(fd).unwrap();
        fs.symlink(FsClock::EPOCH, "/perm/file", "/perm/link")
            .unwrap();

        assert_eq!(fs.metadata("/perm").unwrap().mode, 0o755);
        assert_eq!(fs.metadata("/perm/file").unwrap().mode, 0o644);
        // The initial image's root and /tmp carry the conventional 0o755.
        assert_eq!(fs.metadata("/").unwrap().mode, 0o755);
        // Linux gives a symlink no mode of its own; it always reads 0o777 and
        // cannot be changed.
        assert_eq!(fs.metadata("/perm/link").unwrap().mode, 0o777);
        assert_eq!(
            fs.set_mode(FsClock::EPOCH, "/perm/link", 0o600)
                .unwrap_err()
                .code,
            ErrorCode::Denied
        );

        fs.set_mode(FsClock::EPOCH, "/perm/file", 0o600).unwrap();
        assert_eq!(fs.metadata("/perm/file").unwrap().mode, 0o600);
        // Only the permission bits are stored; file-type bits are the kind's.
        fs.set_mode(FsClock::EPOCH, "/perm/file", 0o100_644)
            .unwrap();
        assert_eq!(fs.metadata("/perm/file").unwrap().mode, 0o644);
    }

    /// RED before creating calls carried a mode: `open(path, O_CREAT, mode)`
    /// and `mkdir(path, mode)` dropped the argument and every new entry got a
    /// fixed default for its kind, so a file asked for at `0o400` came
    /// back writable and a directory asked for at `0o500` accepted new names.
    #[test]
    fn a_creating_call_gets_the_mode_it_asked_for_and_the_bits_are_enforced() {
        let mut fs = MemFs::new();

        // A creation mode is the caller's, verbatim.
        let read_only_file = OpenFlags {
            path_only: false,
            mode: 0o400,
            ..OpenFlags::create_truncate_write()
        };
        let fd = fs
            .open(FsClock::EPOCH, "/tmp/strict", read_only_file)
            .unwrap();
        fs.close(fd).unwrap();
        assert_eq!(fs.metadata("/tmp/strict").unwrap().mode, 0o400);

        // And it is JUDGED on a later open: `r--` is readable, never writable.
        let opened = fs
            .open(FsClock::EPOCH, "/tmp/strict", OpenFlags::read_only())
            .unwrap();
        fs.close(opened).unwrap();
        assert_eq!(
            fs.open(FsClock::EPOCH, "/tmp/strict", write_only())
                .unwrap_err()
                .code,
            ErrorCode::Denied
        );

        // No umask is applied here: the group/other triads arrive as the layer
        // above (the process umask's owner) already masked them, so `0o666`
        // handed down is `0o666` stored — the umask is the caller's business.
        let fd = fs
            .open(
                FsClock::EPOCH,
                "/tmp/plain",
                OpenFlags::create_truncate_write(),
            )
            .unwrap();
        fs.close(fd).unwrap();
        assert_eq!(fs.metadata("/tmp/plain").unwrap().mode, 0o666);
        let fd = fs
            .open(
                FsClock::EPOCH,
                "/tmp/wide",
                OpenFlags {
                    path_only: false,
                    mode: 0o777,
                    ..OpenFlags::create_truncate_write()
                },
            )
            .unwrap();
        fs.close(fd).unwrap();
        assert_eq!(fs.metadata("/tmp/wide").unwrap().mode, 0o777);

        // A directory's mode is the caller's too, and `0o500` refuses creation
        // inside it while still resolving through and listing.
        fs.create_directory(FsClock::EPOCH, "/tmp/locked", 0o500)
            .unwrap();
        assert_eq!(fs.metadata("/tmp/locked").unwrap().mode, 0o500);
        assert_eq!(
            fs.open(
                FsClock::EPOCH,
                "/tmp/locked/new",
                OpenFlags::create_truncate_write()
            )
            .unwrap_err()
            .code,
            ErrorCode::Denied
        );
        assert!(
            fs.read_directory(FsClock::EPOCH, "/tmp/locked")
                .unwrap()
                .is_empty()
        );
    }

    /// An `open` of an EXISTING entry must never touch its mode, whatever third
    /// argument the caller passes — POSIX does not read one on that branch.
    #[test]
    fn opening_an_existing_file_leaves_its_mode_alone() {
        let mut fs = MemFs::new();
        let fd = fs
            .open(
                FsClock::EPOCH,
                "/tmp/kept",
                OpenFlags {
                    path_only: false,
                    mode: 0o640,
                    ..OpenFlags::create_truncate_write()
                },
            )
            .unwrap();
        fs.close(fd).unwrap();
        assert_eq!(fs.metadata("/tmp/kept").unwrap().mode, 0o640);

        // `O_CREAT` on a name that is already there is not a creation.
        let fd = fs
            .open(
                FsClock::EPOCH,
                "/tmp/kept",
                OpenFlags {
                    path_only: false,
                    mode: 0o777,
                    ..OpenFlags::create_truncate_write()
                },
            )
            .unwrap();
        fs.close(fd).unwrap();
        assert_eq!(fs.metadata("/tmp/kept").unwrap().mode, 0o640);

        // Neither does an ordinary non-creating open.
        let fd = fs
            .open(FsClock::EPOCH, "/tmp/kept", OpenFlags::read_only())
            .unwrap();
        fs.close(fd).unwrap();
        assert_eq!(fs.metadata("/tmp/kept").unwrap().mode, 0o640);
    }

    /// RED before a FIFO was inode-backed: the link table is inode-keyed and a
    /// FIFO had no inode in it, so `link` to one answered `NotFound`.
    #[test]
    fn a_hard_link_to_a_fifo_is_a_second_name_for_the_same_node() {
        let mut fs = MemFs::new();
        fs.make_fifo(FsClock::EPOCH, "/tmp/pipe", 0o660).unwrap();
        fs.link(FsClock::EPOCH, "/tmp/pipe", "/tmp/also-pipe")
            .unwrap();

        let first = fs.metadata("/tmp/pipe").unwrap();
        let second = fs.metadata("/tmp/also-pipe").unwrap();
        assert_eq!(second.kind, FsEntryKind::Fifo);
        // ONE node: the identity the shim keys the pipe channel by, so both
        // names open onto the same pipe.
        assert_eq!(first.ino, second.ino);
        assert_eq!(first.nlink, 2);
        assert_eq!(second.nlink, 2);
        // One node, one mode: a chmod through either name is visible through
        // both.
        fs.set_mode(FsClock::EPOCH, "/tmp/also-pipe", 0o600)
            .unwrap();
        assert_eq!(fs.metadata("/tmp/pipe").unwrap().mode, 0o600);

        // Dropping one name leaves the node; dropping the last releases it.
        fs.remove_file(FsClock::EPOCH, "/tmp/pipe").unwrap();
        let remaining = fs.metadata("/tmp/also-pipe").unwrap();
        assert_eq!(remaining.nlink, 1);
        assert_eq!(remaining.ino, first.ino);
        assert_eq!(
            fs.inode_metadata(first.ino).unwrap().kind,
            FsEntryKind::Fifo
        );
        fs.remove_file(FsClock::EPOCH, "/tmp/also-pipe").unwrap();
        assert_eq!(
            fs.inode_metadata(first.ino).unwrap_err().code,
            ErrorCode::NotFound
        );
    }

    /// What `fstat` on a FIFO descriptor reads: the LIVE entry, by inode, so a
    /// `chmod` after the open is visible exactly as it is through a regular
    /// file's descriptor.
    #[test]
    fn inode_metadata_reads_the_live_entry() {
        let mut fs = MemFs::new();
        fs.make_fifo(FsClock::EPOCH, "/tmp/pipe", 0o644).unwrap();
        let ino = fs.metadata("/tmp/pipe").unwrap().ino;
        assert_eq!(fs.inode_metadata(ino).unwrap().mode, 0o644);

        fs.set_mode(FsClock::EPOCH, "/tmp/pipe", 0o400).unwrap();
        assert_eq!(fs.inode_metadata(ino).unwrap().mode, 0o400);

        // A rename moves the name, never the node, so the inode still answers.
        fs.rename(FsClock::EPOCH, "/tmp/pipe", "/tmp/moved")
            .unwrap();
        let after = fs.inode_metadata(ino).unwrap();
        assert_eq!(after.ino, ino);
        assert_eq!(after.mode, 0o400);

        // A regular file's inode answers here too (the same node identity the
        // link table uses), and an unknown inode is `NotFound`, never a guess.
        let fd = fs
            .open(
                FsClock::EPOCH,
                "/tmp/file",
                OpenFlags::create_truncate_write(),
            )
            .unwrap();
        fs.close(fd).unwrap();
        let file_ino = fs.metadata("/tmp/file").unwrap().ino;
        assert_eq!(fs.inode_metadata(file_ino).unwrap().kind, FsEntryKind::File);
        assert_eq!(
            fs.inode_metadata(u64::MAX).unwrap_err().code,
            ErrorCode::NotFound
        );
    }

    /// Renaming a directory has to carry every kind of leaf beneath it. RED
    /// before this: FIFOs were left behind at the old prefix while the
    /// directory that held them moved.
    #[test]
    fn renaming_a_directory_carries_the_fifos_beneath_it() {
        let mut fs = MemFs::new();
        fs.create_directory(FsClock::EPOCH, "/tmp/box", 0o777)
            .unwrap();
        fs.make_fifo(FsClock::EPOCH, "/tmp/box/pipe", 0o666)
            .unwrap();
        let ino = fs.metadata("/tmp/box/pipe").unwrap().ino;

        fs.rename(FsClock::EPOCH, "/tmp/box", "/tmp/crate").unwrap();
        assert_eq!(
            fs.metadata("/tmp/box/pipe").unwrap_err().code,
            ErrorCode::NotFound
        );
        let moved = fs.metadata("/tmp/crate/pipe").unwrap();
        assert_eq!(moved.kind, FsEntryKind::Fifo);
        assert_eq!(moved.ino, ino);
    }

    /// Overwriting a name by rename must release whatever node was there, so a
    /// FIFO's link count cannot leak an inode that no name references.
    #[test]
    fn renaming_over_a_fifo_releases_its_node() {
        let mut fs = MemFs::new();
        fs.make_fifo(FsClock::EPOCH, "/tmp/victim", 0o666).unwrap();
        let victim = fs.metadata("/tmp/victim").unwrap().ino;
        let fd = fs
            .open(
                FsClock::EPOCH,
                "/tmp/winner",
                OpenFlags::create_truncate_write(),
            )
            .unwrap();
        fs.close(fd).unwrap();

        fs.rename(FsClock::EPOCH, "/tmp/winner", "/tmp/victim")
            .unwrap();
        assert_eq!(fs.metadata("/tmp/victim").unwrap().kind, FsEntryKind::File);
        assert_eq!(
            fs.inode_metadata(victim).unwrap_err().code,
            ErrorCode::NotFound
        );
    }

    #[test]
    fn file_modes_are_enforced_for_read_and_write() {
        let mut fs = MemFs::new();
        let fd = fs
            .open(
                FsClock::EPOCH,
                "/tmp/data",
                OpenFlags::create_truncate_write(),
            )
            .unwrap();
        fs.write(FsClock::EPOCH, fd, b"bytes").unwrap();
        fs.close(fd).unwrap();

        fs.set_mode(FsClock::EPOCH, "/tmp/data", 0o000).unwrap();
        assert_eq!(
            fs.open(FsClock::EPOCH, "/tmp/data", OpenFlags::read_only())
                .unwrap_err()
                .code,
            ErrorCode::Denied,
            "a 0o000 file must be denied, not reported missing"
        );
        assert_eq!(
            fs.open(
                FsClock::EPOCH,
                "/tmp/data",
                OpenFlags::create_truncate_write()
            )
            .unwrap_err()
            .code,
            ErrorCode::Denied
        );

        fs.set_mode(FsClock::EPOCH, "/tmp/data", 0o400).unwrap();
        let fd = fs
            .open(FsClock::EPOCH, "/tmp/data", OpenFlags::read_only())
            .unwrap();
        assert_eq!(fs.read(FsClock::EPOCH, fd, 8).unwrap(), b"bytes");
        fs.close(fd).unwrap();
        assert_eq!(
            fs.open(
                FsClock::EPOCH,
                "/tmp/data",
                OpenFlags::create_truncate_write()
            )
            .unwrap_err()
            .code,
            ErrorCode::Denied,
            "a read-only mode must not be openable for write"
        );
        // A descriptor opened while the mode allowed it keeps working: the
        // check belongs to `open`, not to every later read (POSIX).
        let fd = fs
            .open(FsClock::EPOCH, "/tmp/data", OpenFlags::read_only())
            .unwrap();
        fs.set_mode(FsClock::EPOCH, "/tmp/data", 0o000).unwrap();
        assert_eq!(fs.read(FsClock::EPOCH, fd, 8).unwrap(), b"bytes");
        fs.close(fd).unwrap();
    }

    #[test]
    fn directory_modes_gate_search_listing_and_name_creation() {
        let mut fs = MemFs::new();
        fs.create_directory(FsClock::EPOCH, "/gate", 0o777).unwrap();
        let fd = fs
            .open(
                FsClock::EPOCH,
                "/gate/inner",
                OpenFlags::create_truncate_write(),
            )
            .unwrap();
        fs.close(fd).unwrap();

        // No `x`: nothing resolves THROUGH it, and the refusal is a permission
        // one even though the name behind it exists.
        fs.set_mode(FsClock::EPOCH, "/gate", 0o000).unwrap();
        assert_eq!(
            fs.open(FsClock::EPOCH, "/gate/inner", OpenFlags::read_only())
                .unwrap_err()
                .code,
            ErrorCode::Denied
        );
        assert_eq!(
            fs.metadata("/gate/inner").unwrap_err().code,
            ErrorCode::Denied
        );
        assert_eq!(
            fs.read_directory(FsClock::EPOCH, "/gate").unwrap_err().code,
            ErrorCode::Denied
        );
        // Same refusal for a name that does NOT exist, so the error cannot be
        // used to probe what is behind an unsearchable directory.
        assert_eq!(
            fs.metadata("/gate/absent").unwrap_err().code,
            ErrorCode::Denied
        );

        // `r-x`: listing and traversal work, creating a name does not.
        fs.set_mode(FsClock::EPOCH, "/gate", 0o500).unwrap();
        assert_eq!(fs.read_directory(FsClock::EPOCH, "/gate").unwrap().len(), 1);
        let opened = fs
            .open(FsClock::EPOCH, "/gate/inner", OpenFlags::read_only())
            .expect("search + read bits allow the open");
        fs.close(opened).unwrap();
        assert_eq!(
            fs.open(
                FsClock::EPOCH,
                "/gate/new",
                OpenFlags::create_truncate_write()
            )
            .unwrap_err()
            .code,
            ErrorCode::Denied
        );
        assert_eq!(
            fs.create_directory(FsClock::EPOCH, "/gate/sub", 0o777)
                .unwrap_err()
                .code,
            ErrorCode::Denied
        );
        assert_eq!(
            fs.remove_file(FsClock::EPOCH, "/gate/inner")
                .unwrap_err()
                .code,
            ErrorCode::Denied
        );
        assert_eq!(
            fs.rename(FsClock::EPOCH, "/gate/inner", "/gate/moved")
                .unwrap_err()
                .code,
            ErrorCode::Denied
        );
        assert_eq!(
            fs.symlink(FsClock::EPOCH, "/gate/inner", "/gate/link")
                .unwrap_err()
                .code,
            ErrorCode::Denied
        );

        // `--x`: traversal only. The entry behind it is reachable, the listing
        // is not — the distinction a search-only directory exists to make.
        fs.set_mode(FsClock::EPOCH, "/gate", 0o100).unwrap();
        let opened = fs
            .open(FsClock::EPOCH, "/gate/inner", OpenFlags::read_only())
            .expect("search alone is enough to resolve through");
        fs.close(opened).unwrap();
        assert_eq!(
            fs.read_directory(FsClock::EPOCH, "/gate").unwrap_err().code,
            ErrorCode::Denied
        );

        fs.set_mode(FsClock::EPOCH, "/gate", 0o755).unwrap();
        fs.remove_file(FsClock::EPOCH, "/gate/inner").unwrap();
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
            path_only: false,
            mode: patina_dst_abi::CREATE_MODE_UNUSED,
        }
    }

    #[test]
    fn fifos_carry_the_creation_mode_and_report_their_own_kind() {
        let mut fs = MemFs::new();
        fs.make_fifo(FsClock::EPOCH, "/tmp/pipe", 0o644).unwrap();
        let metadata = fs.metadata("/tmp/pipe").unwrap();
        assert_eq!(metadata.kind, FsEntryKind::Fifo);
        // The caller's mode IS honored here, verbatim.
        assert_eq!(metadata.mode, 0o644);
        // A FIFO's bytes are never filesystem state, so it has no length.
        assert_eq!(metadata.len, 0);
        assert_eq!(metadata.nlink, 1);
        assert_ne!(metadata.ino, 0);

        fs.make_fifo(FsClock::EPOCH, "/tmp/strict", 0o755).unwrap();
        assert_eq!(fs.metadata("/tmp/strict").unwrap().mode, 0o755);
        // A mode change reaches a FIFO like any other entry.
        fs.set_mode(FsClock::EPOCH, "/tmp/strict", 0o600).unwrap();
        assert_eq!(fs.metadata("/tmp/strict").unwrap().mode, 0o600);

        assert_eq!(
            fs.make_fifo(FsClock::EPOCH, "/tmp/pipe", 0o666)
                .unwrap_err()
                .code,
            ErrorCode::AlreadyExists
        );
        // Creating a name needs `w` and `x` on the directory, as for any kind.
        fs.create_directory(FsClock::EPOCH, "/tmp/locked", 0o777)
            .unwrap();
        fs.set_mode(FsClock::EPOCH, "/tmp/locked", 0o500).unwrap();
        assert_eq!(
            fs.make_fifo(FsClock::EPOCH, "/tmp/locked/pipe", 0o666)
                .unwrap_err()
                .code,
            ErrorCode::Denied
        );
    }

    #[test]
    fn opening_a_fifo_enforces_its_mode_and_then_defers_to_the_pipe_boundary() {
        let mut fs = MemFs::new();
        fs.make_fifo(FsClock::EPOCH, "/tmp/pipe", 0o666).unwrap();
        // Permitted: the driver has nothing to hand back, because the bytes are
        // not filesystem state — but it says so with `InvalidInput`, never with
        // a permission or existence error.
        assert_eq!(
            fs.open(FsClock::EPOCH, "/tmp/pipe", OpenFlags::read_only())
                .unwrap_err()
                .code,
            ErrorCode::InvalidInput
        );
        assert_eq!(
            fs.open(FsClock::EPOCH, "/tmp/pipe", write_only())
                .unwrap_err()
                .code,
            ErrorCode::InvalidInput
        );

        // Denied: the permission decision belongs to the ONE enforcement point,
        // and it has to stay distinguishable from "not found".
        fs.set_mode(FsClock::EPOCH, "/tmp/pipe", 0o000).unwrap();
        assert_eq!(
            fs.open(FsClock::EPOCH, "/tmp/pipe", OpenFlags::read_only())
                .unwrap_err()
                .code,
            ErrorCode::Denied,
            "a 0o000 FIFO must not be openable for reading"
        );
        assert_eq!(
            fs.open(FsClock::EPOCH, "/tmp/pipe", write_only())
                .unwrap_err()
                .code,
            ErrorCode::Denied
        );
        fs.set_mode(FsClock::EPOCH, "/tmp/pipe", 0o400).unwrap();
        assert_eq!(
            fs.open(FsClock::EPOCH, "/tmp/pipe", OpenFlags::read_only())
                .unwrap_err()
                .code,
            ErrorCode::InvalidInput
        );
        assert_eq!(
            fs.open(FsClock::EPOCH, "/tmp/pipe", write_only())
                .unwrap_err()
                .code,
            ErrorCode::Denied,
            "a read-only FIFO must not be openable for writing"
        );
        // An unsearchable parent hides it exactly as it hides a file.
        fs.create_directory(FsClock::EPOCH, "/tmp/gate", 0o777)
            .unwrap();
        fs.make_fifo(FsClock::EPOCH, "/tmp/gate/pipe", 0o666)
            .unwrap();
        fs.set_mode(FsClock::EPOCH, "/tmp/gate", 0o000).unwrap();
        assert_eq!(
            fs.metadata("/tmp/gate/pipe").unwrap_err().code,
            ErrorCode::Denied
        );
    }

    #[test]
    fn a_fifo_lists_renames_and_unlinks_like_any_other_entry() {
        let mut fs = MemFs::new();
        fs.make_fifo(FsClock::EPOCH, "/tmp/pipe", 0o666).unwrap();
        let listed = fs.read_directory(FsClock::EPOCH, "/tmp").unwrap();
        assert_eq!(
            listed,
            vec![FsDirectoryEntry {
                name: "pipe".into(),
                kind: FsEntryKind::Fifo,
                ino: fs.metadata("/tmp/pipe").unwrap().ino,
            }]
        );
        assert_eq!(
            fs.read_directory(FsClock::EPOCH, "/tmp/pipe")
                .unwrap_err()
                .code,
            ErrorCode::NotDirectory
        );
        assert_eq!(
            fs.remove_directory(FsClock::EPOCH, "/tmp/pipe")
                .unwrap_err()
                .code,
            ErrorCode::NotDirectory
        );

        // The swap a sandbox race plants: a FIFO over a regular file, and back.
        let fd = fs
            .open(
                FsClock::EPOCH,
                "/tmp/file",
                OpenFlags::create_truncate_write(),
            )
            .unwrap();
        fs.write(FsClock::EPOCH, fd, b"public").unwrap();
        fs.close(fd).unwrap();
        let ino = fs.metadata("/tmp/pipe").unwrap().ino;
        fs.rename(FsClock::EPOCH, "/tmp/pipe", "/tmp/file").unwrap();
        let replaced = fs.metadata("/tmp/file").unwrap();
        assert_eq!(replaced.kind, FsEntryKind::Fifo);
        assert_eq!(replaced.ino, ino, "a renamed FIFO keeps its identity");
        assert_eq!(
            fs.metadata("/tmp/pipe").unwrap_err().code,
            ErrorCode::NotFound
        );
        let fd = fs
            .open(
                FsClock::EPOCH,
                "/tmp/regular",
                OpenFlags::create_truncate_write(),
            )
            .unwrap();
        fs.close(fd).unwrap();
        fs.rename(FsClock::EPOCH, "/tmp/regular", "/tmp/file")
            .unwrap();
        assert_eq!(fs.metadata("/tmp/file").unwrap().kind, FsEntryKind::File);

        // Unlink is unconditional: nothing filesystem-side is holding a FIFO
        // open, because what an opener holds is the pipe.
        fs.make_fifo(FsClock::EPOCH, "/tmp/gone", 0o666).unwrap();
        fs.remove_file(FsClock::EPOCH, "/tmp/gone").unwrap();
        assert_eq!(
            fs.metadata("/tmp/gone").unwrap_err().code,
            ErrorCode::NotFound
        );
    }

    #[test]
    fn fifos_survive_a_restart_snapshot_with_their_mode_and_identity() {
        let mut fs = MemFs::new();
        fs.make_fifo(FsClock::EPOCH, "/tmp/pipe", 0o666).unwrap();
        fs.set_mode(FsClock::EPOCH, "/tmp/pipe", 0o640).unwrap();
        let before = fs.metadata("/tmp/pipe").unwrap();

        let encoded = fs.export_snapshot().encode().unwrap();
        let mut restored = MemFs::import_snapshot(&crate::FsSnapshot::decode(&encoded).unwrap());
        let after = restored.metadata("/tmp/pipe").unwrap();
        assert_eq!(after.kind, FsEntryKind::Fifo);
        assert_eq!(after.mode, 0o640);
        assert_eq!(after.ino, before.ino);
        assert_eq!(restored.export_snapshot().encode().unwrap(), encoded);
    }

    /// A hard-linked FIFO is ONE node, and a restart snapshot has to say so:
    /// two names, one inode, link count 2 — otherwise the shim would key two
    /// pipe channels off what used to be one pipe.
    #[test]
    fn linked_fifos_survive_a_restart_snapshot_as_one_node() {
        let mut fs = MemFs::new();
        fs.make_fifo(FsClock::EPOCH, "/tmp/pipe", 0o600).unwrap();
        fs.link(FsClock::EPOCH, "/tmp/pipe", "/tmp/alias").unwrap();
        let before = fs.metadata("/tmp/pipe").unwrap();

        let encoded = fs.export_snapshot().encode().unwrap();
        let mut restored = MemFs::import_snapshot(&crate::FsSnapshot::decode(&encoded).unwrap());
        let first = restored.metadata("/tmp/pipe").unwrap();
        let second = restored.metadata("/tmp/alias").unwrap();
        assert_eq!(first.ino, before.ino);
        assert_eq!(second.ino, before.ino);
        assert_eq!(first.nlink, 2);
        assert_eq!(first.mode, 0o600);
        assert_eq!(restored.export_snapshot().encode().unwrap(), encoded);
    }

    #[test]
    fn a_descriptor_follows_its_node_through_a_rename() {
        let mut fs = MemFs::new();
        fs.create_directory(FsClock::EPOCH, "/pinned", 0o777)
            .unwrap();
        let fd = fs
            .open(
                FsClock::EPOCH,
                "/pinned/file",
                OpenFlags::create_truncate_write(),
            )
            .unwrap();
        fs.close(fd).unwrap();

        let dir = fs
            .open(FsClock::EPOCH, "/pinned", OpenFlags::read_only())
            .unwrap();
        assert_eq!(fs.fd_path(dir).unwrap(), "/pinned");

        fs.rename(FsClock::EPOCH, "/pinned", "/moved").unwrap();
        assert_eq!(
            fs.fd_path(dir).unwrap(),
            "/moved",
            "the descriptor names an inode, so it moved with the directory"
        );

        // Planting a symlink at the vacated name must not recapture it.
        fs.symlink(FsClock::EPOCH, "/elsewhere", "/pinned").unwrap();
        assert_eq!(fs.fd_path(dir).unwrap(), "/moved");

        // An ancestor rename moves it too.
        fs.create_directory(FsClock::EPOCH, "/outer", 0o777)
            .unwrap();
        fs.rename(FsClock::EPOCH, "/moved", "/outer/inner").unwrap();
        assert_eq!(fs.fd_path(dir).unwrap(), "/outer/inner");
        fs.rename(FsClock::EPOCH, "/outer", "/renamed-outer")
            .unwrap();
        assert_eq!(fs.fd_path(dir).unwrap(), "/renamed-outer/inner");
    }

    #[test]
    fn modes_survive_a_restart_snapshot() {
        let mut fs = MemFs::new();
        fs.create_directory(FsClock::EPOCH, "/state", 0o777)
            .unwrap();
        let fd = fs
            .open(
                FsClock::EPOCH,
                "/state/file",
                OpenFlags::create_truncate_write(),
            )
            .unwrap();
        fs.close(fd).unwrap();
        fs.set_mode(FsClock::EPOCH, "/state/file", 0o600).unwrap();
        fs.set_mode(FsClock::EPOCH, "/state", 0o700).unwrap();

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
        fs.create_directory(FsClock::EPOCH, "/state", 0o777)
            .unwrap();
        let fd = fs
            .open(FsClock::EPOCH, "/state", OpenFlags::read_only())
            .unwrap();
        assert_eq!(fs.fd_metadata(fd).unwrap().kind, FsEntryKind::Directory);
        fs.sync(fd).unwrap();
        assert_eq!(
            fs.read(FsClock::EPOCH, fd, 1).unwrap_err().code,
            ErrorCode::IsDirectory
        );
        assert_eq!(
            fs.write(FsClock::EPOCH, fd, b"x").unwrap_err().code,
            ErrorCode::NotWritable
        );
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
            path_only: false,
            mode: patina_dst_abi::CREATE_MODE_UNUSED,
        };
        assert_eq!(
            fs.open(FsClock::EPOCH, "/state", write_dir)
                .unwrap_err()
                .code,
            ErrorCode::IsDirectory
        );
    }

    #[test]
    fn writes_reads_and_truncates_files() {
        let mut fs = MemFs::new();
        let write_fd = fs
            .open(
                FsClock::EPOCH,
                "/state/value",
                OpenFlags::create_truncate_write(),
            )
            .unwrap();
        assert_eq!(fs.write(FsClock::EPOCH, write_fd, b"patina").unwrap(), 6);
        fs.close(write_fd).unwrap();

        let read_fd = fs
            .open(FsClock::EPOCH, "/state//./value", OpenFlags::read_only())
            .unwrap();
        assert_eq!(fs.read(FsClock::EPOCH, read_fd, 3).unwrap(), b"pat");
        assert_eq!(fs.read(FsClock::EPOCH, read_fd, 99).unwrap(), b"ina");
        assert!(fs.read(FsClock::EPOCH, read_fd, 1).unwrap().is_empty());
        fs.close(read_fd).unwrap();
        assert_eq!(fs.contents("/state/value").unwrap(), b"patina");

        let truncate_fd = fs
            .open(
                FsClock::EPOCH,
                "/state/value",
                OpenFlags::create_truncate_write(),
            )
            .unwrap();
        fs.close(truncate_fd).unwrap();
        assert!(fs.contents("/state/value").unwrap().is_empty());
    }

    #[test]
    fn directories_metadata_seek_append_and_remove_are_deterministic() {
        let mut fs = MemFs::new();
        fs.create_directory(FsClock::EPOCH, "/state", 0o777)
            .unwrap();
        assert_eq!(fs.metadata("/state").unwrap().kind, FsEntryKind::Directory);
        let fd = fs
            .open(
                FsClock::EPOCH,
                "/state/value",
                OpenFlags {
                    read: true,
                    write: true,
                    create: true,
                    truncate: false,
                    append: false,
                    exclusive: true,
                    path_only: false,
                    mode: patina_dst_abi::DEFAULT_FILE_CREATE_MODE,
                },
            )
            .unwrap();
        fs.write(FsClock::EPOCH, fd, b"patina").unwrap();
        assert_eq!(fs.seek(fd, -3, SeekWhence::End).unwrap(), 3);
        assert_eq!(fs.read(FsClock::EPOCH, fd, 3).unwrap(), b"ina");
        assert_eq!(fs.fd_metadata(fd).unwrap().len, 6);
        fs.close(fd).unwrap();

        let append = fs
            .open(
                FsClock::EPOCH,
                "/state/value",
                OpenFlags {
                    read: false,
                    write: true,
                    create: false,
                    truncate: false,
                    append: true,
                    exclusive: false,
                    path_only: false,
                    mode: patina_dst_abi::CREATE_MODE_UNUSED,
                },
            )
            .unwrap();
        fs.write(FsClock::EPOCH, append, b"!").unwrap();
        fs.close(append).unwrap();
        assert_eq!(fs.contents("/state/value").unwrap(), b"patina!");
        fs.remove_file(FsClock::EPOCH, "/state/value").unwrap();
        assert_eq!(
            fs.metadata("/state/value").unwrap_err().code,
            ErrorCode::NotFound
        );
    }

    #[test]
    fn missing_and_closed_handles_fail_explicitly() {
        let mut fs = MemFs::new();
        let missing = fs
            .open(FsClock::EPOCH, "/missing", OpenFlags::read_only())
            .unwrap_err();
        assert_eq!(missing.code, ErrorCode::NotFound);

        let fd = fs
            .open(FsClock::EPOCH, "/value", OpenFlags::create_truncate_write())
            .unwrap();
        fs.close(fd).unwrap();
        let closed = fs.write(FsClock::EPOCH, fd, b"no").unwrap_err();
        assert_eq!(closed.code, ErrorCode::InvalidHandle);
    }

    #[test]
    fn dup_shares_cursor_and_is_deterministically_numbered() {
        let mut fs = MemFs::new();
        let write = fs
            .open(FsClock::EPOCH, "/value", OpenFlags::create_truncate_write())
            .unwrap();
        fs.write(FsClock::EPOCH, write, b"abcdef").unwrap();
        fs.close(write).unwrap();

        let first = fs
            .open(FsClock::EPOCH, "/value", OpenFlags::read_only())
            .unwrap();
        let second = fs.dup(first).unwrap();
        assert_eq!(second, Fd(first.0 + 1));
        assert_eq!(fs.read(FsClock::EPOCH, first, 3).unwrap(), b"abc");
        assert_eq!(fs.read(FsClock::EPOCH, second, 3).unwrap(), b"def");
        fs.seek(second, 1, SeekWhence::Start).unwrap();
        assert_eq!(fs.read(FsClock::EPOCH, first, 2).unwrap(), b"bc");
    }

    #[test]
    fn append_descriptions_use_current_eof_and_write_at_stays_positional() {
        let mut fs = MemFs::new().with_file("/log", b"head").unwrap();
        let append = fs
            .open(
                FsClock::EPOCH,
                "/log",
                OpenFlags {
                    read: false,
                    write: true,
                    create: false,
                    truncate: false,
                    append: true,
                    exclusive: false,
                    path_only: false,
                    mode: patina_dst_abi::CREATE_MODE_UNUSED,
                },
            )
            .unwrap();
        let duplicate = fs.dup(append).unwrap();

        let regular = fs
            .open(
                FsClock::EPOCH,
                "/log",
                OpenFlags {
                    read: false,
                    write: true,
                    create: false,
                    truncate: false,
                    append: false,
                    exclusive: false,
                    path_only: false,
                    mode: patina_dst_abi::CREATE_MODE_UNUSED,
                },
            )
            .unwrap();
        fs.seek(regular, 0, SeekWhence::End).unwrap();
        fs.write(FsClock::EPOCH, regular, b"-intervening").unwrap();
        fs.close(regular).unwrap();

        fs.seek(append, 0, SeekWhence::Start).unwrap();
        fs.write(FsClock::EPOCH, append, b"-a").unwrap();
        fs.write(FsClock::EPOCH, duplicate, b"-d").unwrap();
        fs.write_at(FsClock::EPOCH, append, 1, b"EA").unwrap();
        fs.write(FsClock::EPOCH, append, b"-tail").unwrap();

        assert_eq!(fs.contents("/log").unwrap(), b"hEAd-intervening-a-d-tail");
    }

    #[test]
    fn positional_write_does_not_move_the_shared_cursor() {
        let mut fs = MemFs::new().with_file("/value", b"abcde").unwrap();
        let fd = fs
            .open(
                FsClock::EPOCH,
                "/value",
                OpenFlags {
                    read: true,
                    write: true,
                    create: false,
                    truncate: false,
                    append: false,
                    exclusive: false,
                    path_only: false,
                    mode: patina_dst_abi::CREATE_MODE_UNUSED,
                },
            )
            .unwrap();
        fs.seek(fd, 2, SeekWhence::Start).unwrap();
        fs.write_at(FsClock::EPOCH, fd, 0, b"X").unwrap();
        fs.write(FsClock::EPOCH, fd, b"Y").unwrap();

        assert_eq!(fs.contents("/value").unwrap(), b"XbYde");
    }

    #[test]
    fn close_of_one_duplicate_keeps_the_description() {
        let mut fs = MemFs::new().with_file("/value", b"abc").unwrap();
        let first = fs
            .open(FsClock::EPOCH, "/value", OpenFlags::read_only())
            .unwrap();
        let second = fs.dup(first).unwrap();
        fs.close(first).unwrap();
        assert_eq!(fs.read(FsClock::EPOCH, second, 1).unwrap(), b"a");
        fs.close(second).unwrap();
        let error = fs.read(FsClock::EPOCH, second, 1).unwrap_err();
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

    /// RED before `O_PATH` was in the driver's flag vocabulary: every directory
    /// open was the same open — it charged `x` on the directory and handed back
    /// a readable handle, so a `cap-std` component walk paid for a capability it
    /// never asked for while a real read of the directory paid nothing extra,
    /// and the `r` a listing costs was charged at `read_directory` where a
    /// `chmod` after the open could still reach it.
    /// RED mutations: charge `READ` on the path-only branch (the `0o111` open
    /// below fails), or drop the `readable` check in `read_directory_fd` (the
    /// path-only descriptor lists).
    #[test]
    fn a_path_only_open_names_a_location_and_a_plain_one_opens_the_entry() {
        let mut fs = MemFs::new();
        fs.create_directory(FsClock::EPOCH, "/d", 0o777).unwrap();
        let fd = fs
            .open(
                FsClock::EPOCH,
                "/d/file",
                OpenFlags::create_truncate_write(),
            )
            .unwrap();
        fs.close(fd).unwrap();

        // A plain `O_RDONLY|O_DIRECTORY` open opens the directory for reading
        // and can iterate it: `.` (the directory), `..` (its parent), then the
        // children, each naming its inode.
        let readable = fs
            .open(FsClock::EPOCH, "/d", OpenFlags::read_only())
            .unwrap();
        let [dir, root, file] = ["/d", "/", "/d/file"].map(|path| fs.metadata(path).unwrap().ino);
        let entry = |name: &str, kind, ino| FsDirectoryEntry {
            name: name.into(),
            kind,
            ino,
        };
        assert_eq!(
            fs.read_directory_fd(FsClock::EPOCH, readable).unwrap(),
            [
                entry(".", FsEntryKind::Directory, dir),
                entry("..", FsEntryKind::Directory, root),
                entry("file", FsEntryKind::File, file),
            ]
        );

        // An `O_PATH` open opens nothing: it resolves and answers `fstat`, and
        // every operation that touches the entry is refused.
        let location = fs
            .open(FsClock::EPOCH, "/d", OpenFlags::path_only())
            .unwrap();
        assert_eq!(
            fs.fd_metadata(location).unwrap().kind,
            FsEntryKind::Directory
        );
        assert_eq!(fs.fd_path(location).unwrap(), "/d");
        assert_eq!(
            fs.read_directory_fd(FsClock::EPOCH, location)
                .unwrap_err()
                .code,
            ErrorCode::NotReadable
        );
        assert_eq!(
            fs.sync(location).unwrap_err().code,
            ErrorCode::InvalidHandle
        );
        assert_eq!(
            fs.set_fd_mode(FsClock::EPOCH, location, 0o700)
                .unwrap_err()
                .code,
            ErrorCode::InvalidHandle
        );

        // Search-only bits: a plain open pays `r` and is refused, a path-only
        // open pays nothing on the entry and succeeds — which is exactly how a
        // capability guest walks a directory it may traverse but not list.
        fs.set_mode(FsClock::EPOCH, "/d", 0o111).unwrap();
        assert_eq!(
            fs.open(FsClock::EPOCH, "/d", OpenFlags::read_only())
                .unwrap_err()
                .code,
            ErrorCode::Denied
        );
        let walked = fs
            .open(FsClock::EPOCH, "/d", OpenFlags::path_only())
            .unwrap();
        assert_eq!(fs.fd_path(walked).unwrap(), "/d");

        // The access was charged at open, so the `chmod` cannot reach back into
        // a descriptor already holding the directory — while the FUSED path form
        // (`opendir`+`readdir` in one call) charges its own `r` and is refused.
        assert_eq!(
            fs.read_directory_fd(FsClock::EPOCH, readable)
                .unwrap()
                .len(),
            3
        );
        assert_eq!(
            fs.read_directory(FsClock::EPOCH, "/d").unwrap_err().code,
            ErrorCode::Denied
        );
        fs.close(readable).unwrap();
        fs.close(location).unwrap();
        fs.close(walked).unwrap();
    }

    /// `O_PATH` is not a directory-only spelling: the kernel gives a path-only
    /// descriptor for any kind, charging nothing on the entry.
    #[test]
    fn a_path_only_open_of_a_file_or_fifo_reads_nothing_and_needs_no_permission() {
        let mut fs = MemFs::new();
        let fd = fs
            .open(
                FsClock::EPOCH,
                "/tmp/locked",
                OpenFlags {
                    mode: 0o000,
                    ..OpenFlags::create_truncate_write()
                },
            )
            .unwrap();
        fs.write(FsClock::EPOCH, fd, b"hidden").unwrap();
        fs.close(fd).unwrap();
        assert_eq!(
            fs.open(FsClock::EPOCH, "/tmp/locked", OpenFlags::read_only())
                .unwrap_err()
                .code,
            ErrorCode::Denied
        );

        let location = fs
            .open(FsClock::EPOCH, "/tmp/locked", OpenFlags::path_only())
            .unwrap();
        let metadata = fs.fd_metadata(location).unwrap();
        assert_eq!(metadata.kind, FsEntryKind::File);
        assert_eq!(metadata.len, 6);
        assert_eq!(metadata.mode, 0o000);
        assert_eq!(
            fs.read(FsClock::EPOCH, location, 8).unwrap_err().code,
            ErrorCode::NotReadable
        );
        assert_eq!(
            fs.write(FsClock::EPOCH, location, b"x").unwrap_err().code,
            ErrorCode::NotWritable
        );
        assert_eq!(
            fs.seek(location, 0, SeekWhence::End).unwrap_err().code,
            ErrorCode::InvalidInput
        );
        fs.close(location).unwrap();

        fs.make_fifo(FsClock::EPOCH, "/tmp/pipe", 0o000).unwrap();
        let fifo = fs
            .open(FsClock::EPOCH, "/tmp/pipe", OpenFlags::path_only())
            .unwrap();
        assert_eq!(fs.fd_metadata(fifo).unwrap().kind, FsEntryKind::Fifo);
        fs.close(fifo).unwrap();
        // A path-only open carries no access mode: asking for both is asking for
        // two different descriptors at once.
        assert_eq!(
            fs.open(
                FsClock::EPOCH,
                "/tmp/pipe",
                OpenFlags {
                    read: true,
                    ..OpenFlags::path_only()
                }
            )
            .unwrap_err()
            .code,
            ErrorCode::InvalidInput
        );
    }

    /// RED before inode lifetime: `remove_file` refused an open file outright
    /// (`InvalidState`, "cannot remove open virtual file"), because a
    /// description was keyed by PATH and unlinking the name would have left it
    /// pointing at nothing. A kernel refuses no such thing — it drops the name
    /// and keeps the node alive for every descriptor that still holds it.
    /// RED mutation: free the node in `drop_name` instead of
    /// `release_if_unreferenced`, and every read below fails.
    #[test]
    fn an_unlinked_file_stays_alive_behind_its_descriptors() {
        let mut fs = MemFs::new().with_file("/value", b"abc").unwrap();
        let first = fs
            .open(FsClock::EPOCH, "/value", OpenFlags::read_only())
            .unwrap();
        let second = fs.dup(first).unwrap();
        let before = fs.fd_metadata(first).unwrap();
        fs.close(first).unwrap();

        fs.remove_file(FsClock::EPOCH, "/value").unwrap();
        assert_eq!(fs.metadata("/value").unwrap_err().code, ErrorCode::NotFound);

        // The NAME is gone; the NODE is not. Reads, `fstat` and `fchmod` all
        // reach it through the descriptor, and the link count reads 0 exactly
        // as it does on a real unlinked-but-open file.
        assert_eq!(fs.read(FsClock::EPOCH, second, 8).unwrap(), b"abc");
        let after = fs.fd_metadata(second).unwrap();
        assert_eq!(after.ino, before.ino);
        assert_eq!(after.nlink, 0);
        assert_eq!(after.len, 3);
        fs.set_fd_mode(FsClock::EPOCH, second, 0o600).unwrap();
        assert_eq!(fs.fd_metadata(second).unwrap().mode, 0o600);
        // With no name left there is nothing to answer `fd_path` with.
        assert_eq!(fs.fd_path(second).unwrap_err().code, ErrorCode::NotFound);

        // The last reference of either kind is what frees it.
        let ino = after.ino;
        fs.close(second).unwrap();
        assert_eq!(
            fs.inode_metadata(ino).unwrap_err().code,
            ErrorCode::NotFound
        );
        // And a fresh entry never inherits a released node's identity.
        let fd = fs
            .open(FsClock::EPOCH, "/value", OpenFlags::create_truncate_write())
            .unwrap();
        assert_ne!(fs.fd_metadata(fd).unwrap().ino, ino);
    }

    /// A node with a name left over is released by the NAME, not by the
    /// descriptor: unlinking one hard link while the other is open is an
    /// ordinary link-count decrement.
    #[test]
    fn a_hard_link_is_removable_while_another_of_its_names_is_open() {
        let mut fs = MemFs::new().with_file("/a", b"abc").unwrap();
        fs.link(FsClock::EPOCH, "/a", "/b").unwrap();
        let fd = fs
            .open(FsClock::EPOCH, "/a", OpenFlags::read_only())
            .unwrap();
        fs.remove_file(FsClock::EPOCH, "/b").unwrap();
        assert_eq!(fs.fd_metadata(fd).unwrap().nlink, 1);
        fs.remove_file(FsClock::EPOCH, "/a").unwrap();
        assert_eq!(fs.fd_metadata(fd).unwrap().nlink, 0);
        assert_eq!(fs.read(FsClock::EPOCH, fd, 8).unwrap(), b"abc");
        fs.close(fd).unwrap();
    }

    /// A FIFO endpoint is the descriptor the filesystem hands back no handle
    /// for, so its reference is taken explicitly — and it is what keeps the node
    /// answerable after the last name is unlinked. RED before inode lifetime:
    /// `inode_metadata` searched the NAME tables, so the unlinked FIFO answered
    /// `NotFound` and the shim fell back to a copy taken at open time.
    #[test]
    fn an_unlinked_fifo_answers_through_the_reference_its_endpoint_holds() {
        let mut fs = MemFs::new();
        fs.make_fifo(FsClock::EPOCH, "/tmp/pipe", 0o640).unwrap();
        let ino = fs.metadata("/tmp/pipe").unwrap().ino;
        fs.retain_inode(ino).unwrap();

        fs.remove_file(FsClock::EPOCH, "/tmp/pipe").unwrap();
        assert_eq!(
            fs.metadata("/tmp/pipe").unwrap_err().code,
            ErrorCode::NotFound
        );
        let live = fs.inode_metadata(ino).unwrap();
        assert_eq!(live.kind, FsEntryKind::Fifo);
        assert_eq!(live.nlink, 0);
        assert_eq!(live.mode, 0o640);

        fs.release_inode(ino).unwrap();
        assert_eq!(
            fs.inode_metadata(ino).unwrap_err().code,
            ErrorCode::NotFound
        );
        // A release with nothing to release is a bug in the caller, not a no-op.
        assert_eq!(fs.release_inode(ino).unwrap_err().code, ErrorCode::NotFound);
    }

    #[test]
    fn persistent_snapshot_drops_descriptions() {
        let mut fs = MemFs::new().with_file("/value", b"abc").unwrap();
        let first = fs
            .open(FsClock::EPOCH, "/value", OpenFlags::read_only())
            .unwrap();
        let second = fs.dup(first).unwrap();
        let mut snapshot = fs.persistent_snapshot();
        assert_eq!(
            snapshot.read(FsClock::EPOCH, first, 1).unwrap_err().code,
            ErrorCode::InvalidHandle
        );
        assert_eq!(
            snapshot.read(FsClock::EPOCH, second, 1).unwrap_err().code,
            ErrorCode::InvalidHandle
        );
    }

    #[test]
    fn an_anonymous_file_lives_behind_its_handle_and_obeys_its_seals() {
        let mut fs = MemFs::new().with_file("/named", b"x").unwrap();
        let fd = fs
            .create_anonymous(FsClock::EPOCH, "buffer", 0o777, 0, 0)
            .unwrap();
        let metadata = fs.fd_metadata(fd).unwrap();
        assert_eq!(
            (metadata.kind, metadata.len, metadata.mode),
            (FsEntryKind::File, 0, 0o777)
        );
        assert_eq!(fs.write(FsClock::EPOCH, fd, b"hello").unwrap(), 5);
        assert_eq!(fs.seals(fd).unwrap(), 0);
        // Only an anonymous file can be sealed.
        let named = fs
            .open(FsClock::EPOCH, "/named", OpenFlags::read_only())
            .unwrap();
        assert_eq!(fs.seals(named).unwrap_err().code, ErrorCode::InvalidInput);
        // A live shared writable mapping refuses a new write seal; an unknown
        // seal bit is judged before anything else about the node.
        assert_eq!(
            fs.add_seals(fd, F_SEAL_WRITE, true).unwrap_err().code,
            ErrorCode::Busy
        );
        assert_eq!(
            fs.add_seals(fd, 0x100, false).unwrap_err().code,
            ErrorCode::InvalidInput
        );
        fs.add_seals(fd, F_SEAL_WRITE | F_SEAL_SHRINK, false)
            .unwrap();
        assert_eq!(
            fs.write(FsClock::EPOCH, fd, b"x").unwrap_err().code,
            ErrorCode::NotPermitted
        );
        assert_eq!(
            fs.write_at(FsClock::EPOCH, fd, 0, b"x").unwrap_err().code,
            ErrorCode::NotPermitted
        );
        assert_eq!(
            fs.set_len(FsClock::EPOCH, fd, 1).unwrap_err().code,
            ErrorCode::NotPermitted
        );
        fs.set_len(FsClock::EPOCH, fd, 8).unwrap();
        // The page cache's write-back is not a write the seal refuses.
        assert_eq!(fs.write_back_at(FsClock::EPOCH, fd, 0, b"J").unwrap(), 1);
        assert_eq!(fs.read_at(FsClock::EPOCH, fd, 0, 5).unwrap(), b"Jello");
        fs.add_seals(fd, F_SEAL_SEAL, false).unwrap();
        assert_eq!(
            fs.add_seals(fd, F_SEAL_GROW, false).unwrap_err().code,
            ErrorCode::NotPermitted
        );
        assert_eq!(
            fs.seals(fd).unwrap(),
            F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_SEAL
        );
        // No name reaches it, and the last handle frees it.
        let ino = metadata.ino;
        fs.close(fd).unwrap();
        assert_eq!(
            fs.inode_metadata(ino).unwrap_err().code,
            ErrorCode::NotFound
        );
    }

    /// A hugetlbfs file on a machine with no huge pages reserved: no write
    /// method, sized in whole huge pages, a punch frees nothing and an
    /// allocation finds no page.
    #[test]
    fn a_hugetlb_file_sizes_in_huge_pages_and_cannot_be_written() {
        const HUGE: u64 = 2 << 20;
        let mut fs = MemFs::new();
        let fd = fs
            .create_anonymous(FsClock::EPOCH, "huge", 0o777, 0, HUGE)
            .unwrap();
        assert_eq!(
            fs.write(FsClock::EPOCH, fd, b"x").unwrap_err().code,
            ErrorCode::InvalidInput
        );
        assert_eq!(
            fs.write_at(FsClock::EPOCH, fd, 0, b"x").unwrap_err().code,
            ErrorCode::InvalidInput
        );
        assert_eq!(
            fs.set_len(FsClock::EPOCH, fd, 4096).unwrap_err().code,
            ErrorCode::InvalidInput
        );
        fs.set_len(FsClock::EPOCH, fd, HUGE).unwrap();
        assert_eq!(fs.fd_metadata(fd).unwrap().len, HUGE);
        fs.allocate(FsClock::EPOCH, fd, 0, HUGE, true, true)
            .unwrap();
        assert_eq!(
            fs.allocate(FsClock::EPOCH, fd, 0, HUGE, false, false)
                .unwrap_err()
                .code,
            ErrorCode::NoSpace
        );
        assert_eq!(fs.read_at(FsClock::EPOCH, fd, 0, 4).unwrap(), [0; 4]);
    }

    #[test]
    fn access_modes_and_unsafe_paths_are_rejected() {
        let mut fs = MemFs::new().with_file("/value", b"x").unwrap();
        let read_fd = fs
            .open(FsClock::EPOCH, "/value", OpenFlags::read_only())
            .unwrap();
        assert_eq!(
            fs.write(FsClock::EPOCH, read_fd, b"no").unwrap_err().code,
            ErrorCode::NotWritable
        );
        assert_eq!(
            fs.open(FsClock::EPOCH, "../host", OpenFlags::read_only())
                .unwrap_err()
                .code,
            ErrorCode::InvalidInput
        );
        assert_eq!(
            fs.open(FsClock::EPOCH, "/safe/../host", OpenFlags::read_only())
                .unwrap_err()
                .code,
            ErrorCode::InvalidInput
        );
    }

    #[test]
    fn hard_links_share_inodes_and_drop_after_last_name() {
        let mut fs = MemFs::new().with_file("/a", b"abc").unwrap();
        fs.link(FsClock::EPOCH, "/a", "/b").unwrap();
        let a_metadata = fs.metadata("/a").unwrap();
        let b_metadata = fs.metadata("/b").unwrap();
        assert_eq!(a_metadata.ino, b_metadata.ino);
        assert_eq!(a_metadata.nlink, 2);
        assert_eq!(b_metadata.nlink, 2);
        let write = fs
            .open(
                FsClock::EPOCH,
                "/a",
                OpenFlags {
                    read: false,
                    write: true,
                    create: false,
                    truncate: false,
                    append: true,
                    exclusive: false,
                    path_only: false,
                    mode: patina_dst_abi::CREATE_MODE_UNUSED,
                },
            )
            .unwrap();
        fs.write(FsClock::EPOCH, write, b"!").unwrap();
        fs.close(write).unwrap();
        assert_eq!(fs.contents("/b").unwrap(), b"abc!");
        fs.remove_file(FsClock::EPOCH, "/a").unwrap();
        assert_eq!(fs.contents("/b").unwrap(), b"abc!");
        let survivor = fs.metadata("/b").unwrap();
        assert_eq!(survivor.ino, b_metadata.ino);
        assert_eq!(survivor.nlink, 1);
        fs.remove_file(FsClock::EPOCH, "/b").unwrap();
        assert_eq!(fs.metadata("/b").unwrap_err().code, ErrorCode::NotFound);
    }

    #[test]
    fn a_directory_moves_only_onto_a_directory_and_is_never_hard_linked() {
        let mut fs = MemFs::new().with_file("/file", b"").unwrap();
        fs.create_directory(FsClock::EPOCH, "/dir", 0o777).unwrap();
        // rename(2): a directory over a non-directory is ENOTDIR.
        assert_eq!(
            fs.rename(FsClock::EPOCH, "/dir", "/file").unwrap_err().code,
            ErrorCode::NotDirectory
        );
        // Over a non-empty directory it is ENOTEMPTY.
        fs.create_directory(FsClock::EPOCH, "/full", 0o777).unwrap();
        fs.create_directory(FsClock::EPOCH, "/full/inner", 0o777)
            .unwrap();
        assert_eq!(
            fs.rename(FsClock::EPOCH, "/dir", "/full").unwrap_err().code,
            ErrorCode::DirectoryNotEmpty
        );
        // link(2): a hard link to a directory is EPERM.
        assert_eq!(
            fs.link(FsClock::EPOCH, "/dir", "/alias").unwrap_err().code,
            ErrorCode::NotPermitted
        );
        assert!(fs.metadata("/dir").is_ok() && fs.metadata("/file").is_ok());
    }

    #[test]
    fn symlinks_store_verbatim_targets_and_are_listed() {
        let mut fs = MemFs::new();
        fs.create_directory(FsClock::EPOCH, "/state", 0o777)
            .unwrap();
        fs.symlink(FsClock::EPOCH, "../missing", "/state/link")
            .unwrap();
        assert_eq!(
            fs.read_link(FsClock::EPOCH, "/state/link").unwrap(),
            "../missing"
        );
        let metadata = fs.metadata("/state/link").unwrap();
        assert_eq!(metadata.kind, FsEntryKind::Symlink);
        assert_eq!(metadata.len, 10);
        assert_eq!(
            fs.read_directory(FsClock::EPOCH, "/state").unwrap(),
            vec![FsDirectoryEntry {
                name: "link".into(),
                kind: FsEntryKind::Symlink,
                ino: metadata.ino,
            }]
        );
        assert_eq!(
            fs.open(FsClock::EPOCH, "/state/link/x", OpenFlags::read_only())
                .unwrap_err()
                .code,
            ErrorCode::Denied
        );
        fs.remove_file(FsClock::EPOCH, "/state/link").unwrap();
        assert_eq!(
            fs.read_link(FsClock::EPOCH, "/state/link")
                .unwrap_err()
                .code,
            ErrorCode::NotFound
        );
    }

    #[test]
    fn explicit_timestamp_updates_are_reflected_in_metadata() {
        let mut fs = MemFs::new().with_file("/value", b"x").unwrap();
        let fd = fs
            .open(FsClock::EPOCH, "/value", OpenFlags::read_only())
            .unwrap();
        fs.set_times(FsClock::EPOCH, fd, Some(10), Some(20))
            .unwrap();
        assert_eq!(fs.fd_metadata(fd).unwrap().atime_nanos, 10);
        assert_eq!(fs.metadata("/value").unwrap().mtime_nanos, 20);
        fs.close(fd).unwrap();
        fs.create_directory(FsClock::EPOCH, "/state", 0o777)
            .unwrap();
        let state_ino = fs.metadata("/state").unwrap().ino;
        fs.symlink(FsClock::EPOCH, "missing", "/state/link")
            .unwrap();
        let link_metadata = fs.metadata("/state/link").unwrap();
        assert_ne!(state_ino, link_metadata.ino);
        assert_eq!(link_metadata.nlink, 1);
        fs.set_times_by_path(FsClock::EPOCH, "/state", Some(30), None)
            .unwrap();
        fs.set_times_by_path(FsClock::EPOCH, "/state/link", None, Some(40))
            .unwrap();
        assert_eq!(fs.metadata("/state").unwrap().atime_nanos, 30);
        assert_eq!(fs.metadata("/state/link").unwrap().mtime_nanos, 40);
    }

    // ---- The timestamp model: the kernel's rules on the clock each operation
    // is handed. Each test is the class detector for one rule; every assertion
    // below was RED against the two-timestamp filesystem (ctime/btime absent,
    // reads and writes stamping nothing).

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

    fn times(fs: &mut MemFs, path: &str) -> (u64, u64, u64, u64) {
        let metadata = fs.metadata(path).unwrap();
        (
            metadata.atime_nanos,
            metadata.mtime_nanos,
            metadata.ctime_nanos,
            metadata.btime_nanos,
        )
    }

    #[test]
    fn impossible_capacity_is_a_storage_error_not_a_process_abort() {
        // Class pairing: fallible guest-sized growth, also used by writes.
        let mut fs = MemFs::new().with_file("/f", b"abc".to_vec()).unwrap();
        let fd = fs.open(FsClock::at(10), "/f", read_write()).unwrap();
        assert_eq!(
            fs.set_len(FsClock::at(20), fd, i64::MAX as u64)
                .unwrap_err()
                .code,
            ErrorCode::NoSpace
        );
        assert_eq!(
            fs.allocate(FsClock::at(30), fd, 0, i64::MAX as u64, false, false)
                .unwrap_err()
                .code,
            ErrorCode::NoSpace
        );
        assert_eq!(fs.metadata("/f").unwrap().len, 3);
    }

    #[test]
    fn zero_io_preserves_times_size_and_cursor() {
        let mut fs = MemFs::new().with_file("/f", b"abc".to_vec()).unwrap();
        let fd = fs.open(FsClock::at(10), "/f", read_write()).unwrap();
        fs.seek(fd, 20, SeekWhence::Start).unwrap();
        let before = times(&mut fs, "/f");
        assert_eq!(fs.read(FsClock::at(30), fd, 0).unwrap(), b"");
        assert_eq!(fs.write(FsClock::at(40), fd, b"").unwrap(), 0);
        assert_eq!(fs.write_at(FsClock::at(50), fd, 30, b"").unwrap(), 0);
        assert_eq!(times(&mut fs, "/f"), before);
        assert_eq!(fs.metadata("/f").unwrap().len, 3);
        assert_eq!(fs.seek(fd, 0, SeekWhence::Current).unwrap(), 20);
    }

    #[test]
    fn read_after_truncate_past_cursor_returns_eof_without_rewinding() {
        let mut fs = MemFs::new().with_file("/f", b"abc".to_vec()).unwrap();
        let fd = fs.open(FsClock::at(10), "/f", read_write()).unwrap();
        fs.seek(fd, 3, SeekWhence::Start).unwrap();
        fs.set_len(FsClock::at(20), fd, 0).unwrap();
        assert!(fs.read(FsClock::at(30), fd, 8).unwrap().is_empty());
        assert_eq!(fs.seek(fd, 0, SeekWhence::Current).unwrap(), 3);
    }

    #[test]
    fn creation_stamps_all_four_times_and_the_parent_directory() {
        let mut fs = MemFs::new();
        assert_eq!(
            times(&mut fs, "/"),
            (0, 0, 0, 0),
            "the image is stamped at the epoch"
        );
        fs.create_directory(FsClock::at(10), "/d", 0o755).unwrap();
        assert_eq!(times(&mut fs, "/d"), (10, 10, 10, 10));
        assert_eq!(
            times(&mut fs, "/"),
            (0, 10, 10, 0),
            "a new name is a data change to its parent"
        );
        let fd = fs
            .open(FsClock::at(20), "/d/f", OpenFlags::create_truncate_write())
            .unwrap();
        fs.close(fd).unwrap();
        assert_eq!(times(&mut fs, "/d/f"), (20, 20, 20, 20));
        assert_eq!(times(&mut fs, "/d"), (10, 20, 20, 10));
        fs.symlink(FsClock::at(30), "f", "/d/l").unwrap();
        assert_eq!(times(&mut fs, "/d/l"), (30, 30, 30, 30));
        fs.make_fifo(FsClock::at(40), "/d/p", 0o644).unwrap();
        assert_eq!(times(&mut fs, "/d/p"), (40, 40, 40, 40));
        assert_eq!(times(&mut fs, "/d"), (10, 40, 40, 10));
        // Opening an existing entry touches nothing.
        let fd = fs.open(FsClock::at(50), "/d/f", read_write()).unwrap();
        fs.close(fd).unwrap();
        assert_eq!(times(&mut fs, "/d/f"), (20, 20, 20, 20));
    }

    #[test]
    fn data_changes_move_mtime_and_ctime_and_leave_atime_and_btime() {
        let mut fs = MemFs::new();
        let fd = fs
            .open(FsClock::at(10), "/f", OpenFlags::create_truncate_write())
            .unwrap();
        fs.write(FsClock::at(20), fd, b"abc").unwrap();
        assert_eq!(times(&mut fs, "/f"), (10, 20, 20, 10));
        fs.write_at(FsClock::at(30), fd, 1, b"x").unwrap();
        assert_eq!(times(&mut fs, "/f"), (10, 30, 30, 10));
        // A truncation to the SAME length still moves the times (do_truncate).
        fs.set_len(FsClock::at(40), fd, 3).unwrap();
        assert_eq!(times(&mut fs, "/f"), (10, 40, 40, 10));
        fs.allocate(FsClock::at(50), fd, 0, 8, false, false)
            .unwrap();
        assert_eq!(times(&mut fs, "/f"), (10, 50, 50, 10));
        fs.close(fd).unwrap();
        fs.set_len_by_path(FsClock::at(60), "/f", 2).unwrap();
        assert_eq!(times(&mut fs, "/f"), (10, 60, 60, 10));
        // O_TRUNC on an already-empty file is a truncation too.
        fs.set_len_by_path(FsClock::at(61), "/f", 0).unwrap();
        let fd = fs
            .open(FsClock::at(70), "/f", OpenFlags::create_truncate_write())
            .unwrap();
        fs.close(fd).unwrap();
        assert_eq!(times(&mut fs, "/f"), (10, 70, 70, 10));
    }

    #[test]
    fn relatime_refreshes_atime_after_a_data_change_or_a_day_and_not_otherwise() {
        let mut fs = MemFs::new();
        let fd = fs
            .open(FsClock::at(10), "/f", OpenFlags::create_truncate_write())
            .unwrap();
        fs.write(FsClock::at(10), fd, b"abc").unwrap();
        fs.close(fd).unwrap();
        let fd = fs
            .open(FsClock::at(10), "/f", OpenFlags::read_only())
            .unwrap();
        // atime == now: nothing to write, even though mtime >= atime.
        fs.read(FsClock::at(10), fd, 1).unwrap();
        assert_eq!(times(&mut fs, "/f").0, 10);
        // mtime (10) >= atime (10): the first read after the write refreshes.
        fs.read(FsClock::at(20), fd, 1).unwrap();
        assert_eq!(times(&mut fs, "/f").0, 20);
        // atime (20) is now newer than mtime/ctime and less than a day old.
        fs.read(FsClock::at(30), fd, 1).unwrap();
        assert_eq!(times(&mut fs, "/f").0, 20);
        // A day later it refreshes again.
        let day = super::RELATIME_REFRESH_NANOS;
        fs.read(FsClock::at(20 + day), fd, 1).unwrap();
        assert_eq!(times(&mut fs, "/f").0, 20 + day);
        // A metadata change (ctime >= atime) re-arms it as well.
        fs.set_fd_mode(FsClock::at(20 + day + 5), fd, 0o600)
            .unwrap();
        fs.read(FsClock::at(20 + day + 6), fd, 1).unwrap();
        assert_eq!(times(&mut fs, "/f").0, 20 + day + 6);
        // strictatime: every read; noatime: never.
        let strict = FsClock {
            now_nanos: 20 + day + 7,
            atime: AtimePolicy::Strict,
        };
        fs.read(strict, fd, 1).unwrap();
        assert_eq!(times(&mut fs, "/f").0, 20 + day + 7);
        let noatime = FsClock {
            now_nanos: 20 + day + 9,
            atime: AtimePolicy::NoAtime,
        };
        fs.set_fd_mode(FsClock::at(20 + day + 8), fd, 0o644)
            .unwrap();
        fs.read(noatime, fd, 1).unwrap();
        assert_eq!(times(&mut fs, "/f").0, 20 + day + 7);
        fs.close(fd).unwrap();
        // Directory listings and readlink are reads of their entries.
        fs.create_directory(FsClock::at(100), "/d", 0o755).unwrap();
        fs.read_directory(FsClock::at(110), "/d").unwrap();
        assert_eq!(times(&mut fs, "/d").0, 110);
        fs.symlink(FsClock::at(120), "f", "/l").unwrap();
        fs.read_link(FsClock::at(130), "/l").unwrap();
        assert_eq!(times(&mut fs, "/l").0, 130);
    }

    #[test]
    fn metadata_changes_move_ctime_only() {
        let mut fs = MemFs::new();
        fs.create_directory(FsClock::at(5), "/a", 0o755).unwrap();
        fs.create_directory(FsClock::at(5), "/b", 0o755).unwrap();
        let fd = fs
            .open(FsClock::at(10), "/a/f", OpenFlags::create_truncate_write())
            .unwrap();
        fs.close(fd).unwrap();
        fs.set_mode(FsClock::at(20), "/a/f", 0o600).unwrap();
        assert_eq!(times(&mut fs, "/a/f"), (10, 10, 20, 10));
        // Same bits again: the inode is still written.
        fs.set_mode(FsClock::at(21), "/a/f", 0o600).unwrap();
        assert_eq!(times(&mut fs, "/a/f"), (10, 10, 21, 10));
        fs.link(FsClock::at(30), "/a/f", "/b/g").unwrap();
        assert_eq!(
            times(&mut fs, "/a/f"),
            (10, 10, 30, 10),
            "a link count change"
        );
        assert_eq!(
            times(&mut fs, "/b"),
            (5, 30, 30, 5),
            "the new name's directory"
        );
        assert_eq!(times(&mut fs, "/a"), (5, 10, 10, 5), "not the old one's");
        fs.rename(FsClock::at(40), "/b/g", "/a/h").unwrap();
        assert_eq!(times(&mut fs, "/a/h"), (10, 10, 40, 10), "the moved node");
        assert_eq!(times(&mut fs, "/a"), (5, 40, 40, 5));
        assert_eq!(times(&mut fs, "/b"), (5, 40, 40, 5));
        let fd = fs
            .open(FsClock::at(45), "/a/f", OpenFlags::read_only())
            .unwrap();
        fs.remove_file(FsClock::at(50), "/a/h").unwrap();
        assert_eq!(
            fs.fd_metadata(fd).unwrap().ctime_nanos,
            50,
            "unlinking one name changes the node every other name and descriptor sees"
        );
        fs.close(fd).unwrap();
        assert_eq!(times(&mut fs, "/a"), (5, 50, 50, 5));
        // Explicit times: what was handed over, plus ctime; OMIT/OMIT is no-op.
        fs.set_times_by_path(FsClock::at(60), "/a/f", Some(1), None)
            .unwrap();
        assert_eq!(times(&mut fs, "/a/f"), (1, 10, 60, 10));
        fs.set_times_by_path(FsClock::at(70), "/a/f", None, None)
            .unwrap();
        assert_eq!(times(&mut fs, "/a/f"), (1, 10, 60, 10));
        let fd = fs
            .open(FsClock::at(75), "/a", OpenFlags::read_only())
            .unwrap();
        fs.set_times(FsClock::at(80), fd, None, Some(2)).unwrap();
        assert_eq!(
            times(&mut fs, "/a"),
            (5, 2, 80, 5),
            "a directory descriptor"
        );
        fs.close(fd).unwrap();
        let fd = fs
            .open(FsClock::at(85), "/a/f", OpenFlags::path_only())
            .unwrap();
        assert_eq!(
            fs.set_times(FsClock::at(90), fd, Some(3), Some(3))
                .unwrap_err()
                .code,
            ErrorCode::InvalidHandle,
            "an O_PATH descriptor cannot set times (futimens is EBADF)"
        );
    }

    #[test]
    fn a_directory_link_count_is_two_plus_its_subdirectories() {
        let mut fs = MemFs::new();
        // `/` holds `/tmp` in the initial image.
        assert_eq!(fs.metadata("/").unwrap().nlink, 3);
        fs.create_directory(FsClock::EPOCH, "/d", 0o755).unwrap();
        assert_eq!(fs.metadata("/d").unwrap().nlink, 2);
        assert_eq!(fs.metadata("/").unwrap().nlink, 4);
        fs.create_directory(FsClock::EPOCH, "/d/a", 0o755).unwrap();
        fs.create_directory(FsClock::EPOCH, "/d/a/deeper", 0o755)
            .unwrap();
        let fd = fs
            .open(
                FsClock::EPOCH,
                "/d/file",
                OpenFlags::create_truncate_write(),
            )
            .unwrap();
        fs.close(fd).unwrap();
        assert_eq!(
            fs.metadata("/d").unwrap().nlink,
            3,
            "files and grandchildren do not count"
        );
        let fd = fs
            .open(FsClock::EPOCH, "/d", OpenFlags::read_only())
            .unwrap();
        assert_eq!(fs.fd_metadata(fd).unwrap().nlink, 3);
        fs.close(fd).unwrap();
        fs.remove_directory(FsClock::EPOCH, "/d/a/deeper").unwrap();
        fs.remove_directory(FsClock::EPOCH, "/d/a").unwrap();
        assert_eq!(fs.metadata("/d").unwrap().nlink, 2);
    }

    #[test]
    fn truncation_by_descriptor_and_by_name_answer_the_kernels_errnos() {
        let mut fs = MemFs::new();
        fs.create_directory(FsClock::EPOCH, "/d", 0o755).unwrap();
        fs.make_fifo(FsClock::EPOCH, "/p", 0o644).unwrap();
        fs.symlink(FsClock::EPOCH, "f", "/l").unwrap();
        let fd = fs
            .open(FsClock::EPOCH, "/f", OpenFlags::create_truncate_write())
            .unwrap();
        fs.write(FsClock::EPOCH, fd, b"abcdef").unwrap();
        fs.close(fd).unwrap();
        let dir = fs
            .open(FsClock::EPOCH, "/d", OpenFlags::read_only())
            .unwrap();
        assert_eq!(
            fs.set_len(FsClock::EPOCH, dir, 0).unwrap_err().code,
            ErrorCode::InvalidInput,
            "ftruncate on a directory is EINVAL; EISDIR is the by-name answer"
        );
        let location = fs
            .open(FsClock::EPOCH, "/f", OpenFlags::path_only())
            .unwrap();
        assert_eq!(
            fs.set_len(FsClock::EPOCH, location, 0).unwrap_err().code,
            ErrorCode::InvalidHandle
        );
        let reader = fs
            .open(FsClock::EPOCH, "/f", OpenFlags::read_only())
            .unwrap();
        assert_eq!(
            fs.set_len(FsClock::EPOCH, reader, 0).unwrap_err().code,
            ErrorCode::InvalidInput,
            "not open for writing is EINVAL, not EBADF"
        );
        assert_eq!(
            fs.set_len_by_path(FsClock::EPOCH, "/d", 0)
                .unwrap_err()
                .code,
            ErrorCode::IsDirectory
        );
        assert_eq!(
            fs.set_len_by_path(FsClock::EPOCH, "/p", 0)
                .unwrap_err()
                .code,
            ErrorCode::InvalidInput
        );
        assert_eq!(
            fs.set_len_by_path(FsClock::EPOCH, "/l", 0)
                .unwrap_err()
                .code,
            ErrorCode::InvalidInput,
            "a link the caller declined to follow"
        );
        assert_eq!(
            fs.set_len_by_path(FsClock::EPOCH, "/missing", 0)
                .unwrap_err()
                .code,
            ErrorCode::NotFound
        );
        fs.set_mode(FsClock::EPOCH, "/f", 0o444).unwrap();
        assert_eq!(
            fs.set_len_by_path(FsClock::EPOCH, "/f", 0)
                .unwrap_err()
                .code,
            ErrorCode::Denied
        );
        fs.set_mode(FsClock::EPOCH, "/f", 0o644).unwrap();
        fs.set_len_by_path(FsClock::EPOCH, "/f", 8).unwrap();
        assert_eq!(fs.contents("/f").unwrap(), b"abcdef\0\0");
        fs.set_len_by_path(FsClock::EPOCH, "/f", 2).unwrap();
        assert_eq!(fs.contents("/f").unwrap(), b"ab");
    }

    #[test]
    fn allocate_grows_keeps_or_zeroes_and_answers_the_kernels_errnos() {
        let mut fs = MemFs::new();
        fs.create_directory(FsClock::EPOCH, "/d", 0o755).unwrap();
        let fd = fs
            .open(FsClock::EPOCH, "/f", OpenFlags::create_truncate_write())
            .unwrap();
        fs.write(FsClock::EPOCH, fd, b"abcdef").unwrap();
        // mode 0 past the end grows, zero-filled; within the end changes nothing.
        fs.allocate(FsClock::EPOCH, fd, 4, 4, false, false).unwrap();
        assert_eq!(fs.contents("/f").unwrap(), b"abcdef\0\0");
        fs.allocate(FsClock::EPOCH, fd, 0, 2, false, false).unwrap();
        assert_eq!(fs.contents("/f").unwrap(), b"abcdef\0\0");
        // KEEP_SIZE reserves without changing the visible length.
        fs.allocate(FsClock::EPOCH, fd, 0, 100, false, true)
            .unwrap();
        assert_eq!(fs.metadata("/f").unwrap().len, 8);
        // PUNCH_HOLE|KEEP_SIZE zeroes inside the file and never grows it.
        fs.allocate(FsClock::EPOCH, fd, 1, 2, true, true).unwrap();
        assert_eq!(fs.contents("/f").unwrap(), b"a\0\0def\0\0");
        fs.allocate(FsClock::EPOCH, fd, 6, 100, true, true).unwrap();
        assert_eq!(fs.metadata("/f").unwrap().len, 8);
        // ZERO_RANGE without KEEP_SIZE grows to cover the range.
        fs.allocate(FsClock::EPOCH, fd, 7, 3, true, false).unwrap();
        assert_eq!(fs.contents("/f").unwrap(), b"a\0\0def\0\0\0\0");
        fs.close(fd).unwrap();
        let reader = fs
            .open(FsClock::EPOCH, "/f", OpenFlags::read_only())
            .unwrap();
        assert_eq!(
            fs.allocate(FsClock::EPOCH, reader, 0, 1, false, false)
                .unwrap_err()
                .code,
            ErrorCode::NotWritable
        );
        let location = fs
            .open(FsClock::EPOCH, "/f", OpenFlags::path_only())
            .unwrap();
        assert_eq!(
            fs.allocate(FsClock::EPOCH, location, 0, 1, false, false)
                .unwrap_err()
                .code,
            ErrorCode::NotWritable
        );
        let dir = fs
            .open(FsClock::EPOCH, "/d", OpenFlags::read_only())
            .unwrap();
        assert_eq!(
            fs.allocate(FsClock::EPOCH, dir, 0, 1, false, false)
                .unwrap_err()
                .code,
            ErrorCode::NotWritable,
            "a directory descriptor is never open for writing, which the kernel checks first"
        );
    }

    #[test]
    fn a_crash_model_restores_all_four_times_verbatim() {
        let mut fs = MemFs::new();
        fs.create_directory(FsClock::at(10), "/d", 0o755).unwrap();
        fs.restore_times("/d", 1, 2, 3, 4).unwrap();
        assert_eq!(times(&mut fs, "/d"), (1, 2, 3, 4));
        fs.restore_mode("/d", 0o700).unwrap();
        assert_eq!(
            times(&mut fs, "/d"),
            (1, 2, 3, 4),
            "a restore stamps nothing"
        );
        assert_eq!(fs.metadata("/d").unwrap().mode, 0o700);
        assert_eq!(
            fs.restore_times("/missing", 1, 2, 3, 4).unwrap_err().code,
            ErrorCode::NotFound
        );
    }

    fn create(fs: &mut MemFs, path: &str, mode: u32) {
        let fd = fs
            .open(
                FsClock::EPOCH,
                path,
                OpenFlags {
                    mode,
                    ..OpenFlags::create_truncate_write()
                },
            )
            .unwrap();
        fs.close(fd).unwrap();
    }

    /// RED before: rename refused any existing directory target (`EEXIST`), so
    /// a directory could never replace an empty one the way the kernel's
    /// `rename` does.
    #[test]
    fn a_directory_replaces_an_empty_directory_and_nothing_else() {
        let mut fs = MemFs::new();
        for directory in ["/a", "/a/inner", "/b", "/full", "/full/child"] {
            fs.create_directory(FsClock::EPOCH, directory, 0o755)
                .unwrap();
        }
        let replaced = fs.metadata("/b").unwrap().ino;
        let moved = fs.metadata("/a").unwrap().ino;
        fs.rename(FsClock::at(5), "/a", "/b").unwrap();
        let now = fs.metadata("/b").unwrap();
        assert_eq!(now.ino, moved, "the moved directory took the name");
        assert_ne!(now.ino, replaced);
        assert_eq!(
            fs.metadata("/b/inner").unwrap().kind,
            FsEntryKind::Directory
        );
        assert_eq!(fs.metadata("/a").unwrap_err().code, ErrorCode::NotFound);
        assert_eq!(
            fs.rename(FsClock::at(6), "/b", "/full").unwrap_err().code,
            ErrorCode::DirectoryNotEmpty
        );
        create(&mut fs, "/file", 0o644);
        assert_eq!(
            fs.rename(FsClock::at(7), "/b", "/file").unwrap_err().code,
            ErrorCode::NotDirectory
        );
        assert_eq!(
            fs.rename(FsClock::at(8), "/file", "/full")
                .unwrap_err()
                .code,
            ErrorCode::IsDirectory
        );
    }

    /// RED before: a symlink was a path-keyed record, so `link` of one minted
    /// a second, independent symlink (its own inode, `nlink` 1 on both).
    #[test]
    fn a_hard_link_to_a_symlink_is_a_second_name_for_the_link_node() {
        let mut fs = MemFs::new();
        fs.symlink(FsClock::EPOCH, "target", "/l").unwrap();
        fs.link(FsClock::at(3), "/l", "/l2").unwrap();
        let first = fs.metadata("/l").unwrap();
        let second = fs.metadata("/l2").unwrap();
        assert_eq!(second.kind, FsEntryKind::Symlink);
        assert_eq!(first.ino, second.ino);
        assert_eq!((first.nlink, second.nlink), (2, 2));
        assert_eq!(fs.read_link(FsClock::EPOCH, "/l2").unwrap(), "target");
        fs.remove_file(FsClock::at(4), "/l").unwrap();
        assert_eq!(fs.metadata("/l2").unwrap().nlink, 1);
    }

    /// RED before: renaming a name onto another name for the same node dropped
    /// the source and a link, where the kernel's `vfs_rename` changes nothing.
    #[test]
    fn a_rename_between_two_names_of_one_node_changes_nothing() {
        let mut fs = MemFs::new();
        create(&mut fs, "/f", 0o644);
        fs.link(FsClock::EPOCH, "/f", "/g").unwrap();
        fs.rename(FsClock::at(9), "/f", "/g").unwrap();
        assert_eq!(fs.metadata("/f").unwrap().nlink, 2);
        assert_eq!(fs.metadata("/g").unwrap().nlink, 2);
    }

    fn xattr_value(fs: &mut MemFs, path: &str, name: &str) -> DriverResult<Vec<u8>> {
        fs.get_xattr(&XattrTarget::Path(path.into()), name)
    }

    fn set_xattr(
        fs: &mut MemFs,
        path: &str,
        name: &str,
        value: &[u8],
        flags: u32,
    ) -> Result<(), ErrorCode> {
        fs.set_xattr(
            FsClock::at(1),
            &XattrTarget::Path(path.into()),
            name,
            value,
            flags,
        )
        .map_err(|error| error.code)
    }

    #[test]
    fn user_attributes_round_trip_and_follow_the_node() {
        let mut fs = MemFs::new();
        create(&mut fs, "/f", 0o644);
        let path = XattrTarget::Path("/f".into());
        fs.set_xattr(FsClock::at(5), &path, "user.a", b"v1", 0)
            .unwrap();
        assert_eq!(xattr_value(&mut fs, "/f", "user.a").unwrap(), b"v1");
        assert_eq!(
            fs.metadata("/f").unwrap().ctime_nanos,
            5,
            "a set moves ctime"
        );
        assert_eq!(
            set_xattr(&mut fs, "/f", "user.a", b"v2", XATTR_CREATE),
            Err(ErrorCode::AlreadyExists)
        );
        assert_eq!(
            set_xattr(&mut fs, "/f", "user.b", b"v2", XATTR_REPLACE),
            Err(ErrorCode::NoData)
        );
        assert_eq!(
            set_xattr(&mut fs, "/f", "user.a", b"v2", XATTR_CREATE | XATTR_REPLACE),
            Err(ErrorCode::AlreadyExists)
        );
        fs.set_xattr(FsClock::at(6), &path, "user.a", b"v2", XATTR_REPLACE)
            .unwrap();
        fs.link(FsClock::EPOCH, "/f", "/h").unwrap();
        fs.rename(FsClock::EPOCH, "/f", "/moved").unwrap();
        assert_eq!(xattr_value(&mut fs, "/h", "user.a").unwrap(), b"v2");
        assert_eq!(xattr_value(&mut fs, "/moved", "user.a").unwrap(), b"v2");
        assert_eq!(
            fs.list_xattr(&XattrTarget::Path("/h".into())).unwrap(),
            ["user.a"]
        );
        fs.remove_xattr(FsClock::EPOCH, &XattrTarget::Path("/h".into()), "user.a")
            .unwrap();
        assert_eq!(
            xattr_value(&mut fs, "/moved", "user.a").unwrap_err().code,
            ErrorCode::NoData
        );
        assert_eq!(
            fs.remove_xattr(FsClock::EPOCH, &XattrTarget::Path("/h".into()), "user.a")
                .unwrap_err()
                .code,
            ErrorCode::NoData
        );
    }

    #[test]
    fn namespaces_are_judged_as_the_kernel_judges_an_unprivileged_caller() {
        let mut fs = MemFs::new();
        create(&mut fs, "/f", 0o644);
        create(&mut fs, "/ro", 0o444);
        create(&mut fs, "/wo", 0o200);
        fs.make_fifo(FsClock::EPOCH, "/p", 0o644).unwrap();
        fs.symlink(FsClock::EPOCH, "f", "/l").unwrap();
        // trusted.*: EPERM to write, ENODATA to read, never listed.
        assert_eq!(
            set_xattr(&mut fs, "/f", "trusted.x", b"v", 0),
            Err(ErrorCode::NotPermitted)
        );
        assert_eq!(
            xattr_value(&mut fs, "/f", "trusted.x").unwrap_err().code,
            ErrorCode::NoData
        );
        // security.*: readable, not writable.
        assert_eq!(
            set_xattr(&mut fs, "/f", "security.x", b"v", 0),
            Err(ErrorCode::NotPermitted)
        );
        assert_eq!(
            xattr_value(&mut fs, "/f", "security.x").unwrap_err().code,
            ErrorCode::NoData
        );
        // system.* and a name in no namespace have no handler.
        assert_eq!(
            set_xattr(&mut fs, "/f", "system.posix_acl_access", b"v", 0),
            Err(ErrorCode::Unsupported)
        );
        assert_eq!(
            set_xattr(&mut fs, "/f", "plain", b"v", 0),
            Err(ErrorCode::Unsupported)
        );
        assert_eq!(
            set_xattr(&mut fs, "/f", "user.", b"v", 0),
            Err(ErrorCode::InvalidInput)
        );
        // user.* needs a regular file or a directory...
        assert_eq!(
            set_xattr(&mut fs, "/p", "user.a", b"v", 0),
            Err(ErrorCode::NotPermitted)
        );
        assert_eq!(
            xattr_value(&mut fs, "/p", "user.a").unwrap_err().code,
            ErrorCode::NoData
        );
        assert_eq!(
            set_xattr(&mut fs, "/l", "user.a", b"v", 0),
            Err(ErrorCode::NotPermitted)
        );
        assert!(
            fs.list_xattr(&XattrTarget::Path("/l".into()))
                .unwrap()
                .is_empty()
        );
        // ...and the mode's bits: the permission check comes before the
        // handler lookup, so an unwritable file refuses even a bad name.
        assert_eq!(
            set_xattr(&mut fs, "/ro", "user.a", b"v", 0),
            Err(ErrorCode::Denied)
        );
        assert_eq!(
            set_xattr(&mut fs, "/ro", "plain", b"v", 0),
            Err(ErrorCode::Denied)
        );
        assert_eq!(
            xattr_value(&mut fs, "/wo", "user.a").unwrap_err().code,
            ErrorCode::Denied
        );
        assert_eq!(set_xattr(&mut fs, "/wo", "user.a", b"w", 0), Ok(()));
        fs.create_directory(FsClock::EPOCH, "/d", 0o755).unwrap();
        assert_eq!(set_xattr(&mut fs, "/d", "user.d", b"dir", 0), Ok(()));
        assert_eq!(
            fs.list_xattr(&XattrTarget::Path("/d".into())).unwrap(),
            ["user.d"]
        );
    }

    #[test]
    fn a_descriptor_names_its_node_and_a_location_names_none() {
        let mut fs = MemFs::new();
        create(&mut fs, "/f", 0o644);
        let reader = fs
            .open(FsClock::EPOCH, "/f", OpenFlags::read_only())
            .unwrap();
        fs.set_xattr(FsClock::EPOCH, &XattrTarget::Fd(reader), "user.fd", b"F", 0)
            .unwrap();
        assert_eq!(xattr_value(&mut fs, "/f", "user.fd").unwrap(), b"F");
        let location = fs
            .open(FsClock::EPOCH, "/f", OpenFlags::path_only())
            .unwrap();
        assert_eq!(
            fs.get_xattr(&XattrTarget::Fd(location), "user.fd")
                .unwrap_err()
                .code,
            ErrorCode::InvalidHandle
        );
        // An unlinked node keeps its attributes for as long as it is held, and
        // they go with it.
        fs.remove_file(FsClock::EPOCH, "/f").unwrap();
        assert_eq!(
            fs.get_xattr(&XattrTarget::Fd(reader), "user.fd").unwrap(),
            b"F"
        );
        fs.close(reader).unwrap();
        fs.close(location).unwrap();
        assert!(fs.xattrs.is_empty());
    }

    #[test]
    fn exchange_swaps_two_entries_of_any_kinds() {
        let mut fs = MemFs::new();
        create(&mut fs, "/a", 0o644);
        fs.create_directory(FsClock::EPOCH, "/d", 0o755).unwrap();
        create(&mut fs, "/d/inner", 0o600);
        let (file, directory) = (
            fs.metadata("/a").unwrap().ino,
            fs.metadata("/d").unwrap().ino,
        );
        fs.exchange(FsClock::at(4), "/a", "/d").unwrap();
        assert_eq!(fs.metadata("/a").unwrap().ino, directory);
        assert_eq!(fs.metadata("/a/inner").unwrap().mode, 0o600);
        assert_eq!(fs.metadata("/d").unwrap().ino, file);
        assert_eq!(fs.metadata("/d").unwrap().kind, FsEntryKind::File);
        assert_eq!(
            fs.exchange(FsClock::EPOCH, "/a", "/missing")
                .unwrap_err()
                .code,
            ErrorCode::NotFound
        );
        assert_eq!(
            fs.exchange(FsClock::EPOCH, "/a", "/a/inner")
                .unwrap_err()
                .code,
            ErrorCode::InvalidInput
        );
        fs.exchange(FsClock::EPOCH, "/d", "/d").unwrap();
    }

    #[test]
    fn mknod_makes_regular_files_sockets_and_whiteouts_that_open_nothing() {
        let mut fs = MemFs::new();
        fs.make_node(FsClock::EPOCH, "/r", FsNode::File, 0o640)
            .unwrap();
        fs.make_node(FsClock::EPOCH, "/s", FsNode::Socket, 0o600)
            .unwrap();
        fs.make_node(FsClock::EPOCH, "/w", FsNode::Whiteout, 0)
            .unwrap();
        assert_eq!(fs.metadata("/r").unwrap().kind, FsEntryKind::File);
        assert_eq!(fs.metadata("/s").unwrap().kind, FsEntryKind::Socket);
        assert_eq!(fs.metadata("/w").unwrap().mode, 0);
        assert_eq!(
            fs.make_node(FsClock::EPOCH, "/s", FsNode::Socket, 0o600)
                .unwrap_err()
                .code,
            ErrorCode::AlreadyExists
        );
        assert_eq!(
            fs.open(FsClock::EPOCH, "/s", OpenFlags::read_only())
                .unwrap_err()
                .code,
            ErrorCode::InvalidInput,
            "the caller answers ENXIO once the node is reached"
        );
        assert_eq!(
            fs.open(FsClock::EPOCH, "/w", OpenFlags::read_only())
                .unwrap_err()
                .code,
            ErrorCode::Denied,
            "the whiteout's 0 mode is judged first"
        );
        let names: Vec<_> = fs
            .read_directory(FsClock::EPOCH, "/")
            .unwrap()
            .into_iter()
            .map(|entry| (entry.name, entry.kind))
            .collect();
        assert!(names.contains(&("s".into(), FsEntryKind::Socket)));
        assert!(names.contains(&("w".into(), FsEntryKind::CharDevice)));
    }

    /// A device other than the whiteout needs `CAP_MKNOD`, judged after the
    /// name and the parent's `w`+`x` as `vfs_mknod` judges it.
    #[test]
    fn mknod_refuses_a_device_after_the_name_and_the_parent() {
        let mut fs = MemFs::new();
        fs.make_node(FsClock::EPOCH, "/s", FsNode::Socket, 0o600)
            .unwrap();
        fs.create_directory(FsClock::EPOCH, "/ro", 0o500).unwrap();
        let refusal = |fs: &mut MemFs, path: &str, node: FsNode| {
            fs.make_node(FsClock::EPOCH, path, node, 0o600)
                .unwrap_err()
                .code
        };
        let tty = FsNode::CharDevice { device: 0x0501 };
        assert_eq!(refusal(&mut fs, "/s", tty), ErrorCode::AlreadyExists);
        assert_eq!(refusal(&mut fs, "/ro/c", tty), ErrorCode::Denied);
        assert_eq!(refusal(&mut fs, "/c", tty), ErrorCode::NotPermitted);
        assert_eq!(
            refusal(&mut fs, "/b", FsNode::BlockDevice { device: 0 }),
            ErrorCode::NotPermitted
        );
        assert!(fs.metadata("/c").is_err() && fs.metadata("/b").is_err());
    }

    /// `RENAME_WHITEOUT` moves the entry and leaves a mode-0 whiteout where it
    /// was; between two names of one node it changes nothing.
    #[test]
    fn a_whiteout_rename_leaves_a_whiteout_at_the_old_name() {
        let mut fs = MemFs::new().with_file("/f", b"F".to_vec()).unwrap();
        fs.rename_whiteout(FsClock::EPOCH, "/f", "/g").unwrap();
        assert_eq!(fs.contents("/g").unwrap(), b"F");
        let whiteout = fs.metadata("/f").unwrap();
        assert_eq!((whiteout.kind, whiteout.mode), (FsEntryKind::CharDevice, 0));
        fs.link(FsClock::EPOCH, "/g", "/h").unwrap();
        fs.rename_whiteout(FsClock::EPOCH, "/g", "/h").unwrap();
        assert_eq!(fs.metadata("/g").unwrap().kind, FsEntryKind::File);
        assert_eq!(fs.metadata("/h").unwrap().nlink, 2);
    }

    #[test]
    fn nodes_links_and_attributes_survive_a_restart_snapshot() {
        let mut fs = MemFs::new();
        fs.symlink(FsClock::EPOCH, "t", "/l").unwrap();
        fs.link(FsClock::EPOCH, "/l", "/l2").unwrap();
        fs.make_node(FsClock::EPOCH, "/s", FsNode::Socket, 0o600)
            .unwrap();
        fs.create_directory(FsClock::EPOCH, "/d", 0o755).unwrap();
        fs.set_xattr(
            FsClock::EPOCH,
            &XattrTarget::Path("/d".into()),
            "user.k",
            b"v",
            0,
        )
        .unwrap();
        let encoded = fs.export_snapshot().encode().unwrap();
        let mut restored = FsSnapshot::decode(&encoded).unwrap().into_memfs();
        assert_eq!(restored.metadata("/l2").unwrap().nlink, 2);
        assert_eq!(
            restored.metadata("/l").unwrap().ino,
            restored.metadata("/l2").unwrap().ino
        );
        assert_eq!(restored.metadata("/s").unwrap().kind, FsEntryKind::Socket);
        assert_eq!(xattr_value(&mut restored, "/d", "user.k").unwrap(), b"v");
        assert_eq!(restored.export_snapshot().encode().unwrap(), encoded);
    }
}
