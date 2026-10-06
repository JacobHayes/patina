//! Filesystem clocks, open flags, node kinds, metadata, and cursor contracts.

use crate::*;
use serde::{Deserialize, Serialize};

/// When a read updates an entry's access time — the kernel's `atime` mount
/// policy, applied by the filesystem driver on every reading operation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AtimePolicy {
    /// Linux's default since 2.6.30 (`relatime`): a read updates `atime` only
    /// when it is not newer than `mtime` or `ctime`, or when it is at least a
    /// day old.
    #[default]
    Relatime,
    /// `strictatime`: every read updates `atime`.
    Strict,
    /// `noatime`: reads never touch `atime`.
    NoAtime,
}

/// The virtual clock a filesystem operation runs at, handed to the driver by
/// the runtime on every reading or mutating operation. Drivers hold no clock
/// of their own: the runtime reads its virtual realtime clock (unrecorded — the
/// value is a pure function of the recorded sleeps, so it reproduces on
/// replay) and passes it down, so a driver stamps `atime`/`mtime`/`ctime`/
/// `btime` by the kernel's rules without a second recorded effect per
/// operation. A runtime with no clock driver stamps everything at the epoch.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsClock {
    /// Virtual realtime, nanoseconds since the Unix epoch.
    pub now_nanos: u64,
    pub atime: AtimePolicy,
}

impl FsClock {
    /// The epoch under the default `relatime` policy: what a runtime without a
    /// clock driver hands down, and the fixed instant unit tests use.
    pub const EPOCH: FsClock = FsClock {
        now_nanos: 0,
        atime: AtimePolicy::Relatime,
    };

    /// A clock reading `now_nanos` under the default `relatime` policy.
    pub const fn at(now_nanos: u64) -> FsClock {
        FsClock {
            now_nanos,
            atime: AtimePolicy::Relatime,
        }
    }
}

/// Arguments accepted by the minimal filesystem `open` operation: POSIX
/// `open(path, flags, mode)` minus the path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenFlags {
    pub read: bool,
    pub write: bool,
    pub create: bool,
    pub truncate: bool,
    pub append: bool,
    pub exclusive: bool,
    /// `O_PATH`: a descriptor that names a LOCATION rather than opening the
    /// file behind it. It resolves `*at` paths, answers `fstat`/`readlinkat`
    /// and closes, and refuses every operation that touches the file's
    /// contents. `cap-std` opens each component of a path this way, so it is
    /// the flag a capability guest spends most of its opens on.
    ///
    /// It carries no access mode: `read`, `write`, and every creating flag must
    /// be false alongside it, exactly as the kernel ignores them under
    /// `O_PATH`. Permission is charged on the path PREFIX only — Linux checks
    /// nothing on the entry itself for an `O_PATH` open — which is what
    /// distinguishes it from the plain `O_RDONLY|O_DIRECTORY` open that pays
    /// `r` on the directory.
    pub path_only: bool,
    /// The creation mode — `open`'s third argument AFTER the process umask:
    /// the bits the kernel stores, which is what the umask-owning layer above
    /// the driver (the native shim's `umask` state, the WASI host's fixed
    /// `0o022`) hands down. It is consulted only when this open CREATES the
    /// entry: POSIX leaves it unread otherwise, and an `open` of an existing
    /// file must not touch that file's mode. A caller with no `create` flag
    /// passes [`CREATE_MODE_UNUSED`] so the recorded operation carries no
    /// argument the kernel would not have read.
    pub mode: u32,
}

/// The creation mode a non-creating `open` records: the kernel reads no third
/// argument at all, so there is nothing honest to put here but zero.
pub const CREATE_MODE_UNUSED: u32 = 0;
/// The mode `File::create`/`fopen("w")` and every other ordinary "make me a
/// file" caller passes (`0o666`); under the default `0o022` umask it is the
/// familiar `0o644`.
pub const DEFAULT_FILE_CREATE_MODE: u32 = 0o666;
/// The mode `mkdir(2)`'s ordinary callers pass (`0o777`); under the default
/// `0o022` umask it is the familiar `0o755`.
pub const DEFAULT_DIRECTORY_CREATE_MODE: u32 = 0o777;
/// The umask every POSIX process starts with, and the one a layer without a
/// `umask(2)` of its own (the WASI host) applies to every creating call.
pub const DEFAULT_UMASK: u32 = 0o022;

/// The `F_SEAL_*` bits (uapi/linux/fcntl.h) an anonymous file's seal set is
/// made of: [`Operation::FsCreateAnonymous`] and [`Operation::FsAddSeals`]
/// carry them, and the filesystem enforces them.
pub mod seals {
    pub const F_SEAL_SEAL: u32 = 0x1;
    pub const F_SEAL_SHRINK: u32 = 0x2;
    pub const F_SEAL_GROW: u32 = 0x4;
    pub const F_SEAL_WRITE: u32 = 0x8;
    pub const F_SEAL_FUTURE_WRITE: u32 = 0x10;
    pub const F_SEAL_EXEC: u32 = 0x20;
    /// Every seal a 6.8 kernel defines.
    pub const F_ALL_SEALS: u32 = F_SEAL_SEAL
        | F_SEAL_SHRINK
        | F_SEAL_GROW
        | F_SEAL_WRITE
        | F_SEAL_FUTURE_WRITE
        | F_SEAL_EXEC;
}

impl OpenFlags {
    pub const fn read_only() -> Self {
        Self {
            read: true,
            write: false,
            create: false,
            truncate: false,
            append: false,
            exclusive: false,
            path_only: false,
            mode: CREATE_MODE_UNUSED,
        }
    }

    /// An `O_PATH` open: no access mode, no creation, no contents.
    pub const fn path_only() -> Self {
        Self {
            read: false,
            write: false,
            create: false,
            truncate: false,
            append: false,
            exclusive: false,
            path_only: true,
            mode: CREATE_MODE_UNUSED,
        }
    }

    pub const fn create_truncate_write() -> Self {
        Self {
            read: false,
            write: true,
            create: true,
            truncate: true,
            append: false,
            exclusive: false,
            path_only: false,
            mode: DEFAULT_FILE_CREATE_MODE,
        }
    }
}

/// The kind of a virtual filesystem entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FsEntryKind {
    File,
    Directory,
    Symlink,
    /// A named pipe (`mkfifo`). The entry is a NAME in the filesystem; the bytes
    /// that flow through it are not filesystem state at all — they live in the
    /// pipe channel the openers share, exactly as a kernel FIFO's do — so an
    /// entry of this kind never carries contents and reports length 0.
    Fifo,
    /// A socket node (`mknod(S_IFSOCK)`): a name with no bytes behind it that
    /// no `open` can reach (`ENXIO`).
    Socket,
    /// A character device. The one an unprivileged caller can create is the
    /// whiteout, device 0:0 (`mknod(S_IFCHR, 0)`, `renameat2(RENAME_WHITEOUT)`),
    /// which is all this kind models: no driver answers it, so an `open` is
    /// `ENXIO`.
    CharDevice,
}

/// What `mknod` asks to make at a name. Every kind but a device is made for
/// anyone who may create the name; a device other than the whiteout needs
/// `CAP_MKNOD`, which the one modeled identity lacks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FsNode {
    /// An empty regular file (`S_IFREG`, or no type).
    File,
    Fifo,
    Socket,
    /// The character device 0:0 overlay filesystems use as a whiteout.
    Whiteout,
    /// Any other character device, by its kernel device word.
    CharDevice {
        device: u32,
    },
    /// A block device, by its kernel device word.
    BlockDevice {
        device: u32,
    },
}

impl FsNode {
    /// The entry kind the node is, or `None` for a device no entry here can
    /// be (nothing but the whiteout is ever made).
    pub fn kind(self) -> Option<FsEntryKind> {
        match self {
            Self::File => Some(FsEntryKind::File),
            Self::Fifo => Some(FsEntryKind::Fifo),
            Self::Socket => Some(FsEntryKind::Socket),
            Self::Whiteout => Some(FsEntryKind::CharDevice),
            Self::CharDevice { .. } | Self::BlockDevice { .. } => None,
        }
    }
}

/// Which node an extended-attribute operation names: the entry a resolved
/// path names (a final symlink NOT followed — the path resolver above the
/// driver has already decided that), the node an open descriptor holds, or a
/// bare inode (a FIFO endpoint's node, which the filesystem holds no
/// descriptor for).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum XattrTarget {
    Path(String),
    Fd(Fd),
    Inode(u64),
}

/// Deterministic filesystem metadata exposed at the effect boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsMetadata {
    pub kind: FsEntryKind,
    pub len: u64,
    /// The storage the entry holds, in the 512-byte units `st_blocks` counts:
    /// a regular file's allocated blocks (written or unwritten; a hole holds
    /// none), not its length.
    pub blocks: u64,
    /// Deterministic filesystem object identity.
    pub ino: u64,
    /// Number of directory entries linked to this filesystem object. A
    /// directory counts itself and every subdirectory's `..` (`2 +
    /// subdirectories`), as every Unix filesystem reports it.
    pub nlink: u32,
    /// Access time, nanoseconds since the epoch on the virtual clock (signed:
    /// a time before the epoch is negative, and a set time reaches the
    /// filesystem's own range, which `i64` nanoseconds cannot hold). Updated
    /// by reads under the [`FsClock`]'s [`AtimePolicy`], and set explicitly by
    /// the set-times operations.
    #[serde(with = "nanos")]
    pub atime_nanos: i128,
    /// Modification time: the last change to the entry's DATA (a write, a
    /// truncation, an allocation; for a directory, a name appearing or
    /// disappearing in it). Set explicitly by the set-times operations.
    #[serde(with = "nanos")]
    pub mtime_nanos: i128,
    /// Inode change time: the last change to the entry's data OR metadata (a
    /// mode change, a link count change, a rename, a set-times call). Never
    /// settable directly, exactly as on Linux.
    #[serde(with = "nanos")]
    pub ctime_nanos: i128,
    /// Birth time: when the entry was created. Never changes.
    #[serde(with = "nanos")]
    pub btime_nanos: i128,
    /// POSIX permission bits (`0o7777`) — the mode WITHOUT the file-type bits,
    /// which [`FsMetadata::kind`] already carries. A creating call stores the
    /// mode it is handed verbatim: the umask is process state the caller above
    /// the driver applies (the native shim's `umask`, the WASI host's fixed
    /// `0o022`), so the ordinary `0o666`/`0o777` requests arrive as
    /// `0o644`/`0o755`. The driver changes this only through an explicit
    /// set-mode call.
    pub mode: u32,
}

/// One entry of a deterministic directory listing: an immediate child, or the
/// `.`/`..` a descriptor listing starts with.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsDirectoryEntry {
    pub name: String,
    pub kind: FsEntryKind,
    /// The inode the name leads to, the [`FsMetadata::ino`] a metadata query
    /// on it answers (without following a symlink): `getdents`'s `d_ino`.
    pub ino: u64,
}

/// Reference point for changing a virtual file cursor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeekWhence {
    Start,
    Current,
    End,
    /// `SEEK_DATA`: the first byte at or past the offset that holds data (a
    /// written block; an unwritten, preallocated one reads as a hole).
    /// [`ErrorCode::NoSuchPosition`] when there is none before the end.
    Data,
    /// `SEEK_HOLE`: the first byte at or past the offset in a hole, the end
    /// of the file counting as one. [`ErrorCode::NoSuchPosition`] at or past
    /// the end.
    Hole,
}

/// What `fallocate(2)` does to its range (the operation bit of its mode;
/// `FALLOC_FL_KEEP_SIZE` travels alongside).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FsAllocateMode {
    /// Mode 0 or `FALLOC_FL_KEEP_SIZE`: every block the range touches is
    /// allocated; a block that was a hole becomes an unwritten extent, which
    /// counts as allocated and reads as zeros.
    Reserve,
    /// `FALLOC_FL_PUNCH_HOLE|FALLOC_FL_KEEP_SIZE`: the whole blocks inside the
    /// range are freed (a hole again); the partial blocks at its edges are
    /// zeroed in place.
    PunchHole,
    /// `FALLOC_FL_ZERO_RANGE`: the range reads as zeros; its whole blocks
    /// become unwritten extents, its partial edge blocks are zeroed in place,
    /// and every block it touches is allocated.
    ZeroRange,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filesystem_metadata_and_symlink_kind_round_trip() {
        let metadata = FsMetadata {
            kind: FsEntryKind::Symlink,
            len: 9,
            blocks: 0,
            ino: 42,
            nlink: 1,
            atime_nanos: 1,
            mtime_nanos: 2,
            ctime_nanos: 3,
            btime_nanos: 4,
            mode: 0o777,
        };
        let json = serde_json::to_string(&metadata).unwrap();
        assert!(json.contains("\"kind\":\"symlink\""));
        assert_eq!(serde_json::from_str::<FsMetadata>(&json).unwrap(), metadata);

        let fifo = FsMetadata {
            kind: FsEntryKind::Fifo,
            len: 0,
            blocks: 0,
            ino: 43,
            nlink: 1,
            atime_nanos: 0,
            mtime_nanos: 0,
            ctime_nanos: 0,
            btime_nanos: 0,
            mode: 0o644,
        };
        let json = serde_json::to_string(&fifo).unwrap();
        assert!(json.contains("\"kind\":\"fifo\""));
        assert_eq!(serde_json::from_str::<FsMetadata>(&json).unwrap(), fifo);

        // Signed times round-trip inside the tagged enums too: before the
        // epoch, past 64-bit signed nanoseconds, and past 64 bits at all.
        let wide = FsMetadata {
            atime_nanos: -1,
            mtime_nanos: 15_032_385_535_000_000_000,
            ctime_nanos: i128::from(i64::MIN) * 1_000_000_000,
            ..fifo
        };
        let outcome = Outcome::Metadata(wide);
        let json = serde_json::to_string(&outcome).unwrap();
        assert_eq!(serde_json::from_str::<Outcome>(&json).unwrap(), outcome);
        let operation = Operation::FsSetTimes {
            fd: Fd(3),
            atime_nanos: Some(-5),
            mtime_nanos: None,
        };
        let json = serde_json::to_string(&operation).unwrap();
        assert_eq!(serde_json::from_str::<Operation>(&json).unwrap(), operation);
        let entry = FsDirectoryEntry {
            name: "pipe".into(),
            kind: FsEntryKind::Fifo,
            ino: 7,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"kind\":\"fifo\""));
        assert_eq!(
            serde_json::from_str::<FsDirectoryEntry>(&json).unwrap(),
            entry
        );
    }
}
