//! A small deterministic in-memory filesystem driver.

pub mod data;
pub mod image;
pub mod snapshot;

pub use data::{BLOCK_SIZE, BlockState, FileData};
pub use image::{FsImage, FsImageEntry, FsImageError};
pub use snapshot::{FsSnapshot, FsSnapshotError};

mod descriptors;
mod driver;
mod file_io;
mod metadata;
mod namespace;
mod persistence;
mod xattrs;

use crate::namespace::normalize_path;
use patina_dst_abi::{Fd, FsClock, FsEntryKind, OpenFlags};
use patina_dst_driver_api::DriverResult;
use std::collections::BTreeMap;

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

/// The length below which ext4 stores a symlink's target in the inode
/// (`EXT4_N_BLOCKS * 4`, `ext4_inode_is_fast_symlink`).
const FAST_SYMLINK_MAX: u64 = 60;

/// The volume's file size limit: ext4's `s_maxbytes` for an extent-mapped
/// file on 4 KiB blocks (`ext4_max_size`), 2^32 - 1 blocks.
pub const VOLUME_MAX_BYTES: u64 = ((1 << 32) - 1) << 12;

/// tmpfs's and hugetlbfs's `s_maxbytes`, a memfd's: `MAX_LFS_FILESIZE`, the
/// largest signed offset on a 64-bit kernel.
const MAX_LFS_FILESIZE: u64 = i64::MAX as u64;

/// The `relatime` refresh window: an access time at least this old is updated
/// by the next read even when it is newer than `mtime`/`ctime` (Linux's
/// `relatime_need_update`, 24 hours).
const RELATIME_REFRESH_NANOS: u64 = 24 * 60 * 60 * 1_000_000_000;

/// The four timestamps every entry carries, stamped by the kernel's rules from
/// the [`FsClock`] each operation is handed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Times {
    atime_nanos: i128,
    mtime_nanos: i128,
    ctime_nanos: i128,
    btime_nanos: i128,
}

/// The seconds a filesystem's timestamps hold (`s_time_min`/`s_time_max`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TimeRange {
    /// A named node: ext4 with 256-byte inodes, `EXT4_TIMESTAMP_MIN` to
    /// `EXT4_EXTRA_TIMESTAMP_MAX` (1901-12-13 to 2446-05-10).
    Ext4,
    /// An anonymous file (`memfd_create`): tmpfs, every 64-bit second.
    Tmpfs,
}

/// Owner-triad permission bits, as POSIX spells them.
const READ: u32 = 0o4;

const WRITE: u32 = 0o2;

const SEARCH: u32 = 0o1;

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
    /// kind. Stored sparsely ([`FileData`]): a hole costs nothing.
    contents: FileData,
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
    pub fn with_file(self, path: &str, contents: impl Into<Vec<u8>>) -> DriverResult<Self> {
        self.with_file_data(path, FileData::from_bytes(&contents.into()))
    }

    /// Seed a file with sparse contents, holes and reservations as they are.
    pub fn with_file_data(mut self, path: &str, contents: FileData) -> DriverResult<Self> {
        let path = normalize_path(path)?;
        self.insert_parent_directories(FsClock::EPOCH, &path);
        let inode = self.allocate_inode(FsClock::EPOCH, FsEntryKind::File, contents, FILE_MODE);
        self.names.insert(path, inode);
        Ok(self)
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
        contents: FileData,
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
}

#[cfg(test)]
mod tests;
