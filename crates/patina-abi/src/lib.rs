//! Serializable contracts at Patina's deterministic effect boundary.
//!
//! Internal crate: this is the shared vocabulary — [`Operation`], [`Outcome`],
//! error codes, descriptor/socket/task ids — that the runtime, drivers, trace
//! format, native shim, and WASI host all speak. Adopters interact with these
//! types only indirectly (through `patina-dst-runtime`'s `Context` or by reading
//! recorded traces); depend on `patina-dst` or `patina-dst-runtime` instead.
//! See [ARCHITECTURE.md] for how the boundary fits the wider system.
//!
//! [ARCHITECTURE.md]: https://github.com/JacobHayes/patina/blob/main/ARCHITECTURE.md

use std::fmt;

use serde::{Deserialize, Serialize};

/// Base64 (RFC 4648 standard alphabet, padded) codec for the byte payloads that
/// cross the effect boundary.
///
/// Byte payloads - `fs_write`/`net_send` inputs, `bytes` outcomes, and datagram
/// bodies - are the bulk of a recorded trace. Serialized as JSON arrays of
/// integers they cost several characters per byte (and far more once pretty
/// printed); base64 costs ~1.37 characters per byte while staying valid,
/// greppable JSON. Fields tagged `#[serde(with = "bytes_base64")]` therefore
/// always *write* a base64 string.
///
/// On *read* the visitor also accepts a JSON array of integers. That single
/// tolerance is what lets a bundle recorded before base64 existed migrate
/// losslessly: the trace migration only needs to bump the version tag, and the
/// legacy number-array payloads decode here without a per-payload rewrite of the
/// JSON tree. Decoding is fail-closed - a malformed base64 string or an
/// out-of-range array element is a hard deserialization error.
mod bytes_base64 {
    use std::fmt;

    use serde::de::{self, SeqAccess, Visitor};
    use serde::{Deserializer, Serializer};

    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    pub(crate) fn encode(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
        for chunk in bytes.chunks(3) {
            let second = chunk.get(1).copied();
            let third = chunk.get(2).copied();
            let packed = (u32::from(chunk[0]) << 16)
                | (u32::from(second.unwrap_or(0)) << 8)
                | u32::from(third.unwrap_or(0));
            out.push(ALPHABET[(packed >> 18 & 0x3f) as usize] as char);
            out.push(ALPHABET[(packed >> 12 & 0x3f) as usize] as char);
            out.push(if second.is_some() {
                ALPHABET[(packed >> 6 & 0x3f) as usize] as char
            } else {
                '='
            });
            out.push(if third.is_some() {
                ALPHABET[(packed & 0x3f) as usize] as char
            } else {
                '='
            });
        }
        out
    }

    fn sextet(symbol: u8) -> Option<u32> {
        match symbol {
            b'A'..=b'Z' => Some(u32::from(symbol - b'A')),
            b'a'..=b'z' => Some(u32::from(symbol - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(symbol - b'0') + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }

    pub(crate) fn decode(text: &str) -> Result<Vec<u8>, String> {
        let symbols = text.as_bytes();
        if symbols.len() % 4 != 0 {
            return Err(format!(
                "base64 length {} is not a multiple of 4",
                symbols.len()
            ));
        }
        let mut out = Vec::with_capacity(symbols.len() / 4 * 3);
        for chunk in symbols.chunks(4) {
            let padding = chunk.iter().rev().take_while(|&&s| s == b'=').count();
            if padding > 2 {
                return Err("base64 chunk has more than two padding characters".into());
            }
            let mut packed = 0u32;
            for (index, &symbol) in chunk.iter().enumerate() {
                let value = if symbol == b'=' {
                    if index < 4 - padding {
                        return Err("base64 padding appears mid-chunk".into());
                    }
                    0
                } else {
                    sextet(symbol)
                        .ok_or_else(|| format!("invalid base64 character {:?}", symbol as char))?
                };
                packed = (packed << 6) | value;
            }
            out.push((packed >> 16 & 0xff) as u8);
            if padding < 2 {
                out.push((packed >> 8 & 0xff) as u8);
            }
            if padding < 1 {
                out.push((packed & 0xff) as u8);
            }
        }
        Ok(out)
    }

    pub(crate) fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&encode(bytes))
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        deserializer.deserialize_any(PayloadVisitor)
    }

    struct PayloadVisitor;

    impl<'de> Visitor<'de> for PayloadVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a base64 string or a legacy array of byte values")
        }

        fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
            decode(value).map_err(E::custom)
        }

        fn visit_bytes<E: de::Error>(self, value: &[u8]) -> Result<Self::Value, E> {
            Ok(value.to_vec())
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0));
            while let Some(byte) = seq.next_element::<u8>()? {
                out.push(byte);
            }
            Ok(out)
        }
    }
}

/// `Option` wrapper over [`bytes_base64`]: `None` serializes as JSON null,
/// `Some(bytes)` as the base64 payload (accepting the legacy integer-array
/// form on read, exactly like `bytes_base64`).
mod option_bytes_base64 {
    use std::fmt;

    use serde::de::{self, Visitor};
    use serde::{Deserializer, Serializer};

    pub(crate) fn serialize<S: Serializer>(
        bytes: &Option<Vec<u8>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match bytes {
            Some(bytes) => serializer.serialize_some(&super::bytes_base64::encode(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Vec<u8>>, D::Error> {
        deserializer.deserialize_option(OptionalPayloadVisitor)
    }

    struct OptionalPayloadVisitor;

    impl<'de> Visitor<'de> for OptionalPayloadVisitor {
        type Value = Option<Vec<u8>>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("null or a base64 string or legacy array of byte values")
        }

        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_some<D: Deserializer<'de>>(
            self,
            deserializer: D,
        ) -> Result<Self::Value, D::Error> {
            super::bytes_base64::deserialize(deserializer).map(Some)
        }
    }
}

/// A virtual filesystem handle. Handles are scoped to one runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Fd(pub u64);

/// A scheduler task identifier scoped to one runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TaskId(pub u64);

/// The target class of a generated signal: process-directed or a specific task.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalTarget {
    Process,
    Task(TaskId),
}

/// A virtual network socket identifier scoped to one runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SocketId(pub u64);

/// Clock domains exposed by the deterministic boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClockKind {
    Monotonic,
    Realtime,
}

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

/// Stable error categories crossing the effect boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    Denied,
    InvalidInput,
    InvalidHandle,
    MissingDriver,
    NotFound,
    NotReadable,
    NotWritable,
    AlreadyExists,
    IsDirectory,
    NotDirectory,
    DirectoryNotEmpty,
    Io,
    NoSpace,
    Interrupted,
    AlreadyBound,
    Deadlock,
    NoRoute,
    InvalidState,
    ConnectionRefused,
    ConnectionReset,
    BrokenPipe,
    NotConnected,
    /// The operation is not permitted for the calling identity (`EPERM`): a
    /// hard link to a directory, a device node, an owner change to someone else.
    NotPermitted,
    /// The named attribute does not exist (`ENODATA`).
    NoData,
    /// A result does not fit the caller's buffer (`ERANGE`: `getcwd`, an xattr
    /// value larger than the buffer offered).
    Range,
    /// An argument is larger than the kernel accepts (`E2BIG`).
    TooBig,
    /// The operation is not supported by this object or filesystem
    /// (`EOPNOTSUPP`): a mode change on a symlink, an unknown xattr namespace.
    Unsupported,
    /// The object is in use (`EBUSY`): removing the root, a mount point.
    Busy,
    /// A positional operation on an object with no position (`ESPIPE`).
    IllegalSeek,
    /// A link or rename across filesystems (`EXDEV`).
    CrossDevice,
}

/// A typed effect failure suitable for traces and user-facing diagnostics.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectError {
    pub code: ErrorCode,
    pub message: String,
}

impl EffectError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn missing_driver(capability: &str) -> Self {
        Self::new(
            ErrorCode::MissingDriver,
            format!("no {capability} driver is installed"),
        )
    }
}

impl fmt::Display for EffectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", ErrorCodeDisplay(self.code), self.message)
    }
}

impl std::error::Error for EffectError {}

struct ErrorCodeDisplay(ErrorCode);

impl fmt::Display for ErrorCodeDisplay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self.0 {
            ErrorCode::Denied => "denied",
            ErrorCode::InvalidInput => "invalid_input",
            ErrorCode::InvalidHandle => "invalid_handle",
            ErrorCode::MissingDriver => "missing_driver",
            ErrorCode::NotFound => "not_found",
            ErrorCode::NotReadable => "not_readable",
            ErrorCode::NotWritable => "not_writable",
            ErrorCode::AlreadyExists => "already_exists",
            ErrorCode::IsDirectory => "is_directory",
            ErrorCode::NotDirectory => "not_directory",
            ErrorCode::DirectoryNotEmpty => "directory_not_empty",
            ErrorCode::Io => "io",
            ErrorCode::NoSpace => "no_space",
            ErrorCode::Interrupted => "interrupted",
            ErrorCode::AlreadyBound => "already_bound",
            ErrorCode::Deadlock => "deadlock",
            ErrorCode::NoRoute => "no_route",
            ErrorCode::InvalidState => "invalid_state",
            ErrorCode::ConnectionRefused => "connection_refused",
            ErrorCode::ConnectionReset => "connection_reset",
            ErrorCode::BrokenPipe => "broken_pipe",
            ErrorCode::NotConnected => "not_connected",
            ErrorCode::NotPermitted => "not_permitted",
            ErrorCode::NoData => "no_data",
            ErrorCode::Range => "range",
            ErrorCode::TooBig => "too_big",
            ErrorCode::Unsupported => "unsupported",
            ErrorCode::Busy => "busy",
            ErrorCode::IllegalSeek => "illegal_seek",
            ErrorCode::CrossDevice => "cross_device",
        };
        f.write_str(value)
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
    /// Deterministic filesystem object identity.
    pub ino: u64,
    /// Number of directory entries linked to this filesystem object. A
    /// directory counts itself and every subdirectory's `..` (`2 +
    /// subdirectories`), as every Unix filesystem reports it.
    pub nlink: u32,
    /// Access time, nanoseconds since the epoch on the virtual clock. Updated
    /// by reads under the [`FsClock`]'s [`AtimePolicy`], and set explicitly by
    /// the set-times operations.
    pub atime_nanos: u64,
    /// Modification time: the last change to the entry's DATA (a write, a
    /// truncation, an allocation; for a directory, a name appearing or
    /// disappearing in it). Set explicitly by the set-times operations.
    pub mtime_nanos: u64,
    /// Inode change time: the last change to the entry's data OR metadata (a
    /// mode change, a link count change, a rename, a set-times call). Never
    /// settable directly, exactly as on Linux.
    pub ctime_nanos: u64,
    /// Birth time: when the entry was created. Never changes.
    pub btime_nanos: u64,
    /// POSIX permission bits (`0o7777`) — the mode WITHOUT the file-type bits,
    /// which [`FsMetadata::kind`] already carries. A creating call stores the
    /// mode it is handed verbatim: the umask is process state the caller above
    /// the driver applies (the native shim's `umask`, the WASI host's fixed
    /// `0o022`), so the ordinary `0o666`/`0o777` requests arrive as
    /// `0o644`/`0o755`. The driver changes this only through an explicit
    /// set-mode call.
    pub mode: u32,
}

/// One immediate child returned by a deterministic directory listing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsDirectoryEntry {
    pub name: String,
    pub kind: FsEntryKind,
}

/// Reference point for changing a virtual file cursor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeekWhence {
    Start,
    Current,
    End,
}

/// A datagram delivered by a virtual network.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Datagram {
    pub packet_id: u64,
    pub from: String,
    pub to: String,
    #[serde(with = "bytes_base64")]
    pub bytes: Vec<u8>,
    pub delivery_nanos: u64,
}

/// Why a virtual send did or did not queue packets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SendDisposition {
    Queued,
    DroppedByFault,
    DroppedByPartition,
}

/// Observable packet-lifecycle decisions made for one send.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SendReport {
    pub written: usize,
    pub copies: usize,
    pub delivery_nanos: Vec<u64>,
    pub disposition: SendDisposition,
}

/// Directions closed by a virtual TCP shutdown.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShutdownHow {
    Read,
    Write,
    Both,
}

/// One established connection handed to a virtual TCP accept.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpAccepted {
    /// The acceptor-side stream endpoint.
    pub socket: SocketId,
    /// The connecting side's virtual address, e.g. "127.0.0.1:49152".
    pub peer: String,
}

/// What a guest asserts about its own run through the verdict ABI — the single
/// verb `patina_verdict` (native shim) / the `patina_sdk` `verdict` import
/// (WASI) / `Context::verdict` (in-process).
///
/// A **closed** enum owned by the runtime: kinds are data, never new symbols, so
/// a new kind is one enum value the compiler walks to every consumer. The `u32`
/// wire values are the ABI and are pinned by test; the C header
/// (`patina_native.h`) and the SDK's mirror of it must agree with
/// [`VerdictKind::as_abi`].
///
/// A verdict `label` shares the `sites.json` label namespace with the SDK's
/// `sometimes!`/`buggify!` site labels and aggregates the same way, but a
/// verdict is *not* a buggify site: it registers no site, so the duplicate-label
/// gate does not apply to it and the same label may be reported many times in
/// one run (that is what aggregation means). Reusing a *site's* label for a
/// verdict is legal and deliberate — it joins the two views of one invariant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictKind {
    /// The guest detected a violation of its own invariant.
    Violation,
    /// The guest confirmed a property held.
    Pass,
    /// The guest is about to abort deliberately, on its own invariant — so the
    /// resulting SIGABRT is attributable to the guest and not to a Patina
    /// fail-closed refusal.
    AbortIntent,
}

impl VerdictKind {
    /// Every kind, in wire order. Exhaustive by construction: a new variant that
    /// is not added here fails [`VerdictKind::as_abi`]'s round-trip test.
    pub const ALL: &'static [VerdictKind] = &[
        VerdictKind::Violation,
        VerdictKind::Pass,
        VerdictKind::AbortIntent,
    ];

    /// The `u32` this kind travels as across the C / WASI ABI. Numbering starts
    /// at 1 so a zeroed argument is never a valid kind and fails closed.
    pub const fn as_abi(self) -> u32 {
        match self {
            VerdictKind::Violation => 1,
            VerdictKind::Pass => 2,
            VerdictKind::AbortIntent => 3,
        }
    }

    /// Decode an ABI `u32`. `None` for any unknown value — the embedder refuses
    /// the call rather than guessing a kind.
    pub const fn from_abi(value: u32) -> Option<Self> {
        match value {
            1 => Some(VerdictKind::Violation),
            2 => Some(VerdictKind::Pass),
            3 => Some(VerdictKind::AbortIntent),
            _ => None,
        }
    }

    /// The stable snake_case name used in the trace, the `PATINA_VERDICT` marker
    /// line, and the result envelope.
    pub const fn as_str(self) -> &'static str {
        match self {
            VerdictKind::Violation => "violation",
            VerdictKind::Pass => "pass",
            VerdictKind::AbortIntent => "abort_intent",
        }
    }

    /// Parse the name [`VerdictKind::as_str`] renders. `None` is a hard parse
    /// failure for the caller, never a default kind.
    pub fn from_name(text: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|kind| kind.as_str() == text)
    }
}

/// The verdict wire format: the `PATINA_VERDICT` diagnostic line that carries a
/// recorded verdict from the guest process to whatever reads its output.
///
/// The runtime records every verdict in the trace, but a *plain* seeded run
/// writes no trace and an aborting guest never finalizes one, so the line is the
/// channel the result envelope is built from. It lives here, beside the ABI
/// enum, so the producer (`patina-dst-runtime`) and the consumer (`cargo-patina`
/// building `patina.result/v1`) share one implementation and cannot drift.
///
/// Fields are whitespace-separated `key=value`; `label` and `detail` are escaped
/// by [`escape_verdict_field`] so no guest-supplied byte can introduce a space or
/// a newline and forge a second marker line.
pub mod verdict_line {
    use super::VerdictKind;

    /// The marker prefix, including its trailing space.
    pub const PREFIX: &str = "PATINA_VERDICT ";

    /// Render one verdict as its marker line (no trailing newline).
    pub fn render(seq: u64, kind: VerdictKind, label: &str, detail: &str) -> String {
        format!(
            "{PREFIX}seq={seq} kind={} label={} detail={}",
            kind.as_str(),
            escape(label),
            escape(detail),
        )
    }

    /// Parse a marker line back into `(seq, kind, label, detail)`. `None` for any
    /// line that is not a well-formed verdict marker — a truncated or malformed
    /// line is dropped, never half-decoded into a verdict that reads as real.
    pub fn parse(line: &str) -> Option<(u64, VerdictKind, String, String)> {
        let rest = line.trim().strip_prefix(PREFIX)?;
        let mut seq = None;
        let mut kind = None;
        let mut label = None;
        let mut detail = None;
        for token in rest.split(' ').filter(|token| !token.is_empty()) {
            let (key, value) = token.split_once('=')?;
            match key {
                "seq" => seq = Some(value.parse().ok()?),
                "kind" => kind = Some(VerdictKind::from_name(value)?),
                "label" => label = Some(unescape(value)?),
                "detail" => detail = Some(unescape(value)?),
                // Unknown keys are a format the reader does not understand, not
                // noise to skip: refuse rather than report a partial verdict.
                _ => return None,
            }
        }
        Some((seq?, kind?, label?, detail?))
    }

    /// Escape one field so it is a single whitespace-free token that round-trips
    /// through [`unescape`]. Backslash is the escape character; space, tab, CR,
    /// and LF get named escapes. Everything else passes through unchanged, so a
    /// label with no special bytes reads exactly as written.
    pub fn escape(value: &str) -> String {
        let mut out = String::with_capacity(value.len());
        for ch in value.chars() {
            match ch {
                '\\' => out.push_str("\\\\"),
                ' ' => out.push_str("\\s"),
                '\t' => out.push_str("\\t"),
                '\r' => out.push_str("\\r"),
                '\n' => out.push_str("\\n"),
                other => out.push(other),
            }
        }
        out
    }

    /// Reverse [`escape`]. `None` on a dangling or unknown escape.
    pub fn unescape(value: &str) -> Option<String> {
        let mut out = String::with_capacity(value.len());
        let mut chars = value.chars();
        while let Some(ch) = chars.next() {
            if ch != '\\' {
                out.push(ch);
                continue;
            }
            match chars.next()? {
                '\\' => out.push('\\'),
                's' => out.push(' '),
                't' => out.push('\t'),
                'r' => out.push('\r'),
                'n' => out.push('\n'),
                _ => return None,
            }
        }
        Some(out)
    }
}

/// A typed boundary operation. Its serialized form is part of trace matching.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Operation {
    EntropyFill {
        len: usize,
    },
    ClockNow {
        clock: ClockKind,
    },
    SleepUntil {
        clock: ClockKind,
        deadline_nanos: u64,
    },
    FsOpen {
        path: String,
        flags: OpenFlags,
    },
    FsRead {
        fd: Fd,
        max_len: usize,
    },
    FsWrite {
        fd: Fd,
        #[serde(with = "bytes_base64")]
        bytes: Vec<u8>,
    },
    /// Positional read at an explicit byte offset that does NOT disturb the file
    /// cursor (`pread`/`read_at`). Distinct from [`Operation::FsRead`] in the
    /// trace so a positional read and a cursor read at the same fd never
    /// reconcile against each other.
    FsReadAt {
        fd: Fd,
        offset: u64,
        max_len: usize,
    },
    /// Positional write at an explicit byte offset that does NOT disturb the
    /// file cursor (`pwrite`/`write_at`). Counts toward the `write` crash
    /// ordinal exactly like [`Operation::FsWrite`].
    FsWriteAt {
        fd: Fd,
        offset: u64,
        #[serde(with = "bytes_base64")]
        bytes: Vec<u8>,
    },
    FsClose {
        fd: Fd,
    },
    FsDup {
        fd: Fd,
    },
    FsSeek {
        fd: Fd,
        offset: i64,
        whence: SeekWhence,
    },
    FsMetadata {
        path: String,
    },
    FsFdMetadata {
        fd: Fd,
    },
    /// `mkdir`/`mkdirat`. Carries the caller's requested mode, like
    /// [`Operation::FsOpen`] and [`Operation::FsMakeFifo`]; the driver applies
    /// the modeled umask.
    FsCreateDirectory {
        path: String,
        mode: u32,
    },
    FsRemoveFile {
        path: String,
    },
    /// `fchmod` through a descriptor the filesystem holds no handle for: the
    /// bits belong to the NODE, so they are named by inode.
    FsSetInodeMode {
        ino: u64,
        mode: u32,
    },
    /// A descriptor that the filesystem hands back no handle for — a FIFO
    /// endpoint — takes its reference on the node explicitly, so the node
    /// outlives its last name for as long as the endpoint does.
    FsRetainInode {
        ino: u64,
    },
    /// The matching release. The node is freed when its last name and its last
    /// reference are both gone.
    FsReleaseInode {
        ino: u64,
    },
    FsSync {
        fd: Fd,
    },
    /// `sync(2)`/`syncfs(2)`: every change on the volume made durable at once.
    FsSyncAll,
    FsSetLength {
        fd: Fd,
        len: u64,
    },
    /// `truncate(2)`: a file's length by NAME. Separate from
    /// [`Operation::FsSetLength`] because it is a different question — the
    /// entry is resolved and its permission bits are charged here, where a
    /// descriptor form charged them at open.
    FsSetLengthByPath {
        path: String,
        len: u64,
    },
    /// `fallocate(2)` over a regular file: `zero` writes zeros over the range
    /// (`FALLOC_FL_PUNCH_HOLE`/`FALLOC_FL_ZERO_RANGE`), `keep_size` leaves the
    /// length alone (`FALLOC_FL_KEEP_SIZE`); without it the file grows to
    /// `offset + len` when that is past its end.
    FsAllocate {
        fd: Fd,
        offset: u64,
        len: u64,
        zero: bool,
        keep_size: bool,
    },
    FsSetTimes {
        fd: Fd,
        atime_nanos: Option<u64>,
        mtime_nanos: Option<u64>,
    },
    FsSetInodeTimes {
        ino: u64,
        atime_nanos: Option<u64>,
        mtime_nanos: Option<u64>,
    },
    FsSetTimesByPath {
        path: String,
        atime_nanos: Option<u64>,
        mtime_nanos: Option<u64>,
    },
    FsReadDirectory {
        path: String,
    },
    /// `getdents`/`readdir` on an open directory DESCRIPTOR. Separate from
    /// [`Operation::FsReadDirectory`] because it is a different question: the
    /// access was charged when the descriptor was opened, so this one asks the
    /// node the descriptor holds rather than re-resolving a name.
    FsReadDirectoryFd {
        fd: Fd,
    },
    FsRemoveDirectory {
        path: String,
    },
    FsRename {
        from: String,
        to: String,
    },
    FsLink {
        from: String,
        to: String,
    },
    FsSymlink {
        target: String,
        link_path: String,
    },
    FsReadLink {
        path: String,
    },
    /// Create a named pipe (`mkfifo`/`mkfifoat`/`mknod` with `S_IFIFO`).
    /// Carries the requested mode, like every other creating operation; the
    /// driver applies the modeled umask.
    FsMakeFifo {
        path: String,
        mode: u32,
    },
    /// `mknod`: create `node` at the caller's requested mode (the caller
    /// applied the process umask). A device other than the whiteout is refused
    /// after the name is judged. A FIFO is [`Operation::FsMakeFifo`].
    FsMakeNode {
        path: String,
        node: FsNode,
        mode: u32,
    },
    /// `renameat2(RENAME_WHITEOUT)`: a rename that leaves a whiteout at the
    /// source name, as one change.
    FsRenameWhiteout {
        from: String,
        to: String,
    },
    /// `renameat2(RENAME_EXCHANGE)`: swap two existing entries atomically,
    /// whatever their kinds.
    FsExchange {
        first: String,
        second: String,
    },
    /// Read one extended attribute's value. The outcome carries the value as
    /// [`Outcome::Bytes`].
    FsGetXattr {
        target: XattrTarget,
        name: String,
    },
    /// Every extended attribute name the caller may see, as the kernel lists
    /// them: NUL-terminated names in one [`Outcome::Bytes`].
    FsListXattr {
        target: XattrTarget,
    },
    /// Set one extended attribute. `flags` are `XATTR_CREATE` (1: the name must
    /// be new) and `XATTR_REPLACE` (2: it must exist).
    FsSetXattr {
        target: XattrTarget,
        name: String,
        #[serde(with = "bytes_base64")]
        value: Vec<u8>,
        flags: u32,
    },
    /// Remove one extended attribute.
    FsRemoveXattr {
        target: XattrTarget,
        name: String,
    },
    /// Change the permission bits of the entry `path` NAMES. Trailing-symlink
    /// resolution — the only difference between `chmod` and
    /// `fchmodat(…, AT_SYMLINK_NOFOLLOW)` — happens above this boundary, in the
    /// same place every other path operation resolves one, so the driver never
    /// needs a second resolver.
    FsSetMode {
        path: String,
        mode: u32,
    },
    /// Change the permission bits of the entry an open descriptor names
    /// (`fchmod`).
    FsSetFdMode {
        fd: Fd,
        mode: u32,
    },
    /// Metadata of the entry a bare INODE names, for the one descriptor class
    /// the filesystem itself does not hold: a FIFO endpoint is a pipe, and all
    /// the deterministic filesystem gave it is the node identity. `fstat` on
    /// such a descriptor must read the LIVE entry — a `chmod` after the open is
    /// visible through it on Linux, exactly as it is through a regular file's
    /// descriptor — so the inode is what crosses the boundary, never a copy of
    /// the metadata taken at open time.
    FsInodeMetadata {
        ino: u64,
    },
    /// The path an open descriptor's filesystem NODE currently has. A
    /// descriptor names an inode, not a name: a rename moves the node and the
    /// descriptor follows it, so `*at` resolution asks the filesystem where the
    /// node is now instead of replaying the name it was opened under. The
    /// outcome carries the path as [`Outcome::Bytes`], like `FsReadLink`.
    FsFdPath {
        fd: Fd,
    },
    /// Resolve a host name to a virtual IPv4 address. The outcome carries the
    /// dotted-quad address as [`Outcome::Bytes`], exactly like `FsReadLink`
    /// carries a link target, so a replay reproduces the resolution — including
    /// an injected failure — from the trace rather than re-deriving it.
    DnsResolve {
        name: String,
    },
    FsCrash,
    TaskSpawn {
        label: String,
    },
    TaskYield {
        task: TaskId,
    },
    TaskPark {
        task: TaskId,
        reason: String,
    },
    /// Park a task with a monotonic virtual-time deadline. The scheduler parks
    /// the task exactly like [`Operation::TaskPark`]; the runtime additionally
    /// registers a timer so the deadlock-rescue path can wake it when virtual
    /// time reaches `deadline_nanos`. `deadline_nanos` is always in the
    /// monotonic domain (realtime deadlines are converted at registration).
    TaskParkTimed {
        task: TaskId,
        reason: String,
        deadline_nanos: u64,
    },
    TaskWake {
        task: TaskId,
    },
    /// A successfully generated signal. Delivery is derived from signal state
    /// and scheduler operations; the generation itself is a boundary op so
    /// replay refuses divergent signal sequences.
    SignalGenerated {
        seq: u64,
        sig: u8,
        target: SignalTarget,
        code: i32,
        value: i64,
    },
    TaskComplete {
        task: TaskId,
    },
    SchedulerNext,
    NetBind {
        address: String,
    },
    NetSend {
        socket: SocketId,
        to: String,
        #[serde(with = "bytes_base64")]
        bytes: Vec<u8>,
        now_nanos: u64,
    },
    NetRecv {
        socket: SocketId,
        now_nanos: u64,
    },
    NetClose {
        socket: SocketId,
    },
    /// Query the earliest future delivery time (`delivery_nanos > now_nanos`)
    /// among packets addressed to `socket`, so a blocking receive under
    /// non-zero link latency can park until virtual time reaches it.
    NetNextDelivery {
        socket: SocketId,
        now_nanos: u64,
    },
    NetTcpListen {
        address: String,
        backlog: usize,
    },
    NetTcpAccept {
        listener: SocketId,
        now_nanos: u64,
    },
    NetTcpConnect {
        /// The connecting side's local virtual address (chosen by the caller;
        /// the shim assigns a deterministic ephemeral port).
        address: String,
        to: String,
        now_nanos: u64,
    },
    NetTcpSend {
        socket: SocketId,
        #[serde(with = "bytes_base64")]
        bytes: Vec<u8>,
        now_nanos: u64,
    },
    NetTcpRecv {
        socket: SocketId,
        max_len: usize,
        now_nanos: u64,
    },
    NetTcpShutdown {
        socket: SocketId,
        how: ShutdownHow,
    },
    /// One guest verdict reported through the verdict ABI. Recorded like any
    /// other boundary operation, so a replay whose verdict stream diverges from
    /// the recording — a missing verdict, an extra one, a changed label/detail,
    /// or the same verdicts in a different order — fails closed as an ordinary
    /// operation mismatch rather than being reconciled away.
    ///
    /// The field is `verdict_kind` rather than `kind` because `kind` is
    /// [`Operation`]'s own serde tag.
    Verdict {
        verdict_kind: VerdictKind,
        label: String,
        detail: String,
    },
    /// One guest-declared custom operation: an effect Patina does not model,
    /// which the guest wraps at a boundary it controls so Patina can mediate it.
    /// `label` names the op class; `key` is the operation's logical input. The
    /// [`Outcome::Bytes`] is the result the guest's `perform` produced on the
    /// record pass, and it is the authority on replay — replay returns these
    /// bytes and never runs `perform`.
    ///
    /// Both fields are opaque at this layer by deliberate design (custom-ops arc
    /// §6, "typed at the SDK, raw bytes at the ABI"): pinning a serialization
    /// format into the boundary contract would couple every non-Rust consumer of
    /// a trace to a Rust-side encoding. The SDK owns the encoding, and the guest
    /// binary that produced a trace is already the fingerprint contract for
    /// replaying it.
    ///
    /// A replay whose custom-op stream diverges from the recording — a different
    /// label, a different key, a missing or extra call — fails closed as an
    /// ordinary operation mismatch, which is what makes the recorded bytes safe
    /// to trust.
    ///
    /// `label` follows the same rules as a verdict label (see [`VerdictKind`]):
    /// it shares the `sites.json` label namespace and aggregates the same way,
    /// but a custom op registers no buggify site, so the duplicate-label gate
    /// does not apply and one label naming many calls in a run is exactly the
    /// point — the label names the op *class*, not the call.
    CustomOp {
        label: String,
        #[serde(with = "bytes_base64")]
        key: Vec<u8>,
    },
}

/// The result of a boundary operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Outcome {
    Unit,
    Handle(Fd),
    Bytes(#[serde(with = "bytes_base64")] Vec<u8>),
    U64(u64),
    OptionalU64(Option<u64>),
    Usize(usize),
    Task(TaskId),
    OptionalTask(Option<TaskId>),
    Socket(SocketId),
    SendReport(SendReport),
    Datagram(Option<Datagram>),
    TcpAccepted(Option<TcpAccepted>),
    OptionalBytes(#[serde(with = "option_bytes_base64")] Option<Vec<u8>>),
    Metadata(FsMetadata),
    DirectoryEntries(Vec<FsDirectoryEntry>),
    Error(EffectError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_variant_tags_are_pinned_by_name_not_declaration_order() {
        // `Operation` is `#[serde(tag = "kind", rename_all = "snake_case")]`, so
        // every variant's trace tag is its snake_case NAME, not a discriminant
        // derived from declaration order. Inserting a new variant anywhere is
        // therefore additive and can never renumber an existing one. This test
        // pins the exact tag string of representative pre-existing variants
        // (and the two positional-I/O additions) so any accidental switch to
        // order-based tagging -- or a variant rename -- breaks loudly and every
        // recorded trace stops decoding at the same instant this test fails.
        let cases: &[(Operation, &str)] = &[
            (
                Operation::FsRead {
                    fd: Fd(3),
                    max_len: 8,
                },
                "fs_read",
            ),
            (
                Operation::FsWrite {
                    fd: Fd(3),
                    bytes: vec![1],
                },
                "fs_write",
            ),
            (
                Operation::FsSeek {
                    fd: Fd(3),
                    offset: 0,
                    whence: SeekWhence::Start,
                },
                "fs_seek",
            ),
            (Operation::FsClose { fd: Fd(3) }, "fs_close"),
            (Operation::FsSync { fd: Fd(3) }, "fs_sync"),
            (Operation::FsCrash, "fs_crash"),
            (
                Operation::FsReadAt {
                    fd: Fd(3),
                    offset: 4096,
                    max_len: 8,
                },
                "fs_read_at",
            ),
            (
                Operation::FsWriteAt {
                    fd: Fd(3),
                    offset: 4096,
                    bytes: vec![1],
                },
                "fs_write_at",
            ),
        ];
        for (operation, tag) in cases {
            let json = serde_json::to_string(operation).unwrap();
            let needle = format!("\"kind\":\"{tag}\"");
            assert!(
                json.contains(&needle),
                "variant tag drifted: expected {needle} in {json}"
            );
            assert_eq!(
                &serde_json::from_str::<Operation>(&json).unwrap(),
                operation
            );
        }
    }

    #[test]
    fn signal_generated_round_trips_and_mismatches() {
        let operation = Operation::SignalGenerated {
            seq: 7,
            sig: 10,
            target: SignalTarget::Task(TaskId(3)),
            code: -6,
            value: 42,
        };
        let json = serde_json::to_string(&operation).unwrap();
        assert!(json.contains("\"kind\":\"signal_generated\""));
        assert!(json.contains("\"seq\":7"));
        assert!(json.contains("\"sig\":10"));
        assert!(json.contains("\"target\":{"));
        assert!(json.contains("\"code\":-6"));
        assert!(json.contains("\"value\":42"));
        assert_eq!(serde_json::from_str::<Operation>(&json).unwrap(), operation);

        let different_seq = Operation::SignalGenerated {
            seq: 8,
            sig: 10,
            target: SignalTarget::Task(TaskId(3)),
            code: -6,
            value: 42,
        };
        let different_sig = Operation::SignalGenerated {
            seq: 7,
            sig: 12,
            target: SignalTarget::Task(TaskId(3)),
            code: -6,
            value: 42,
        };
        let different_target = Operation::SignalGenerated {
            seq: 7,
            sig: 10,
            target: SignalTarget::Process,
            code: -6,
            value: 42,
        };
        assert_ne!(different_seq, operation);
        assert_ne!(different_sig, operation);
        assert_ne!(different_target, operation);
    }

    #[test]
    fn positional_io_offset_survives_round_trip() {
        // The positional offset must be preserved exactly through the trace so a
        // pread/pwrite reconciles only against the same offset on replay.
        for operation in [
            Operation::FsReadAt {
                fd: Fd(7),
                offset: 1 << 40,
                max_len: 4096,
            },
            Operation::FsWriteAt {
                fd: Fd(7),
                offset: 1 << 40,
                bytes: vec![9, 8, 7],
            },
        ] {
            let json = serde_json::to_string(&operation).unwrap();
            assert!(
                json.contains("\"offset\":1099511627776"),
                "offset lost: {json}"
            );
            assert_eq!(serde_json::from_str::<Operation>(&json).unwrap(), operation);
        }
    }

    #[test]
    fn operation_json_is_tagged_and_round_trips() {
        let operations = [
            Operation::FsOpen {
                path: "/state".into(),
                flags: OpenFlags::read_only(),
            },
            Operation::FsSetTimes {
                fd: Fd(3),
                atime_nanos: Some(11),
                mtime_nanos: None,
            },
            Operation::FsSetTimesByPath {
                path: "/state".into(),
                atime_nanos: None,
                mtime_nanos: Some(22),
            },
            Operation::FsLink {
                from: "/state/a".into(),
                to: "/state/b".into(),
            },
            Operation::FsSymlink {
                target: "../target".into(),
                link_path: "/state/link".into(),
            },
            Operation::FsReadLink {
                path: "/state/link".into(),
            },
            Operation::FsMakeFifo {
                path: "/state/pipe".into(),
                mode: 0o644,
            },
        ];
        for operation in operations {
            let json = serde_json::to_string(&operation).unwrap();
            assert!(json.contains("\"kind\""));
            assert_eq!(serde_json::from_str::<Operation>(&json).unwrap(), operation);
        }
    }

    #[test]
    fn timer_delivery_and_tcp_operations_round_trip() {
        let operations = [
            Operation::TaskParkTimed {
                task: TaskId(4),
                reason: "cond-timedwait".into(),
                deadline_nanos: 1_000,
            },
            Operation::NetNextDelivery {
                socket: SocketId(2),
                now_nanos: 42,
            },
            Operation::NetTcpListen {
                address: "127.0.0.1:80".into(),
                backlog: 4,
            },
            Operation::NetTcpAccept {
                listener: SocketId(3),
                now_nanos: 43,
            },
            Operation::NetTcpConnect {
                address: "127.0.0.1:49152".into(),
                to: "127.0.0.1:80".into(),
                now_nanos: 44,
            },
            Operation::NetTcpSend {
                socket: SocketId(5),
                bytes: b"ping".to_vec(),
                now_nanos: 45,
            },
            Operation::NetTcpRecv {
                socket: SocketId(6),
                max_len: 16,
                now_nanos: 46,
            },
            Operation::NetTcpShutdown {
                socket: SocketId(5),
                how: ShutdownHow::Write,
            },
        ];
        for operation in operations {
            let json = serde_json::to_string(&operation).unwrap();
            assert!(json.contains("\"kind\""));
            assert_eq!(serde_json::from_str::<Operation>(&json).unwrap(), operation);
        }
        let outcomes = [
            Outcome::OptionalU64(Some(7)),
            Outcome::OptionalU64(None),
            Outcome::TcpAccepted(None),
            Outcome::TcpAccepted(Some(TcpAccepted {
                socket: SocketId(6),
                peer: "127.0.0.1:49152".into(),
            })),
            Outcome::OptionalBytes(None),
            Outcome::OptionalBytes(Some(Vec::new())),
            Outcome::OptionalBytes(Some(b"pong".to_vec())),
        ];
        for outcome in outcomes {
            let json = serde_json::to_string(&outcome).unwrap();
            assert_eq!(serde_json::from_str::<Outcome>(&json).unwrap(), outcome);
        }
    }

    #[test]
    fn filesystem_metadata_and_symlink_kind_round_trip() {
        let metadata = FsMetadata {
            kind: FsEntryKind::Symlink,
            len: 9,
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
        let entry = FsDirectoryEntry {
            name: "pipe".into(),
            kind: FsEntryKind::Fifo,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"kind\":\"fifo\""));
        assert_eq!(
            serde_json::from_str::<FsDirectoryEntry>(&json).unwrap(),
            entry
        );
    }

    #[test]
    fn byte_payloads_serialize_as_base64_strings_and_round_trip() {
        // Byte payloads must serialize as base64 strings rather than JSON number
        // arrays; this is the whole point of the compact trace encoding.
        let write = Operation::FsWrite {
            fd: Fd(3),
            bytes: vec![1, 2, 3, 4],
        };
        let json = serde_json::to_string(&write).unwrap();
        assert!(
            json.contains("\"bytes\":\"AQIDBA==\""),
            "unexpected JSON: {json}"
        );
        assert!(
            !json.contains('['),
            "byte payload leaked a number array: {json}"
        );
        assert_eq!(serde_json::from_str::<Operation>(&json).unwrap(), write);

        let outcome = Outcome::Bytes(vec![255, 0, 128]);
        let json = serde_json::to_string(&outcome).unwrap();
        assert_eq!(json, "{\"kind\":\"bytes\",\"value\":\"/wCA\"}");
        assert_eq!(serde_json::from_str::<Outcome>(&json).unwrap(), outcome);
    }

    #[test]
    fn byte_payloads_still_accept_the_legacy_number_array_form() {
        // Bundles recorded before base64 stored payloads as arrays of integers;
        // the tolerant reader keeps migration lossless without rewriting them.
        let legacy = "{\"kind\":\"bytes\",\"value\":[1,2,3,4]}";
        assert_eq!(
            serde_json::from_str::<Outcome>(legacy).unwrap(),
            Outcome::Bytes(vec![1, 2, 3, 4])
        );
    }

    #[test]
    fn base64_round_trips_all_lengths_and_rejects_malformed_input() {
        for len in 0..=32usize {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 7 + 1) as u8).collect();
            let encoded = bytes_base64::encode(&bytes);
            assert_eq!(encoded.len() % 4, 0);
            assert_eq!(bytes_base64::decode(&encoded).unwrap(), bytes);
        }
        // Known vectors and fail-closed rejection of malformed strings.
        assert_eq!(bytes_base64::encode(b"Man"), "TWFu");
        assert_eq!(bytes_base64::encode(b"Ma"), "TWE=");
        assert!(bytes_base64::decode("TWFu=").is_err()); // not a multiple of 4
        assert!(bytes_base64::decode("T=Fu").is_err()); // mid-chunk padding
        assert!(bytes_base64::decode("T@Fu").is_err()); // invalid character
    }

    #[test]
    fn error_codes_have_stable_display_names() {
        let error = EffectError::missing_driver("filesystem");
        assert_eq!(
            error.to_string(),
            "missing_driver: no filesystem driver is installed"
        );
        assert_eq!(
            EffectError::new(ErrorCode::ConnectionRefused, "dial failed").to_string(),
            "connection_refused: dial failed"
        );
        assert_eq!(
            EffectError::new(ErrorCode::ConnectionReset, "peer reset").to_string(),
            "connection_reset: peer reset"
        );
        assert_eq!(
            EffectError::new(ErrorCode::BrokenPipe, "write closed").to_string(),
            "broken_pipe: write closed"
        );
        assert_eq!(
            EffectError::new(ErrorCode::NotConnected, "no peer").to_string(),
            "not_connected: no peer"
        );
    }

    // The ABI numbering is the contract three independent mirrors compile
    // against (the C header, the SDK's `extern "C"` block, the WASI import), so
    // pin the exact values: a renumber here silently misclassifies every verdict
    // a shim-linked guest reports.
    #[test]
    fn verdict_kind_abi_values_are_pinned_and_round_trip() {
        assert_eq!(VerdictKind::Violation.as_abi(), 1);
        assert_eq!(VerdictKind::Pass.as_abi(), 2);
        assert_eq!(VerdictKind::AbortIntent.as_abi(), 3);
        assert_eq!(VerdictKind::from_abi(0), None);
        assert_eq!(VerdictKind::from_abi(4), None);
        for kind in VerdictKind::ALL {
            assert_eq!(VerdictKind::from_abi(kind.as_abi()), Some(*kind));
            assert_eq!(VerdictKind::from_name(kind.as_str()), Some(*kind));
        }
        assert_eq!(VerdictKind::from_name("violation!"), None);
    }

    #[test]
    fn verdict_operation_tag_is_its_snake_case_name() {
        let operation = Operation::Verdict {
            verdict_kind: VerdictKind::AbortIntent,
            label: "checksum".into(),
            detail: "{\"page\":7}".into(),
        };
        let json = serde_json::to_string(&operation).unwrap();
        assert!(json.contains("\"kind\":\"verdict\""), "{json}");
        assert!(json.contains("\"abort_intent\""), "{json}");
        assert_eq!(serde_json::from_str::<Operation>(&json).unwrap(), operation);
    }

    // The custom-op key is arbitrary guest bytes, not text: it must survive the
    // trace round trip verbatim, including bytes that are not valid UTF-8 and the
    // empty key. A key that silently re-encoded would make a replay key check
    // compare something other than what the guest asked.
    #[test]
    fn custom_op_operation_tag_and_opaque_key_round_trip() {
        let operation = Operation::CustomOp {
            label: "s3.get_object".into(),
            key: vec![0x00, 0xff, 0xfe, b'k', 0x80],
        };
        let json = serde_json::to_string(&operation).unwrap();
        assert!(json.contains("\"kind\":\"custom_op\""), "{json}");
        assert_eq!(serde_json::from_str::<Operation>(&json).unwrap(), operation);

        let empty = Operation::CustomOp {
            label: String::new(),
            key: Vec::new(),
        };
        let json = serde_json::to_string(&empty).unwrap();
        assert_eq!(serde_json::from_str::<Operation>(&json).unwrap(), empty);
    }

    #[test]
    fn verdict_marker_line_round_trips_including_hostile_labels() {
        // A guest-supplied label carrying a newline must not be able to forge a
        // second marker line, and it must survive the round trip verbatim.
        let hostile = "two words\nPATINA_VERDICT seq=99 kind=pass label=forged detail=x";
        let line = verdict_line::render(7, VerdictKind::Violation, hostile, "a b\\c");
        assert_eq!(line.lines().count(), 1, "escaped line must stay one line");
        let (seq, kind, label, detail) = verdict_line::parse(&line).unwrap();
        assert_eq!(seq, 7);
        assert_eq!(kind, VerdictKind::Violation);
        assert_eq!(label, hostile);
        assert_eq!(detail, "a b\\c");
    }

    #[test]
    fn malformed_verdict_lines_are_refused_not_half_decoded() {
        assert!(verdict_line::parse("PATINA_RESULT ok").is_none());
        // Missing detail key.
        assert!(verdict_line::parse("PATINA_VERDICT seq=1 kind=pass label=x").is_none());
        // Unknown kind name.
        assert!(verdict_line::parse("PATINA_VERDICT seq=1 kind=maybe label=x detail=").is_none());
        // Unknown key.
        assert!(
            verdict_line::parse("PATINA_VERDICT seq=1 kind=pass label=x detail= extra=1").is_none()
        );
        // Dangling escape.
        assert!(verdict_line::parse("PATINA_VERDICT seq=1 kind=pass label=x\\ detail=").is_none());
        // An empty label/detail is legal and decodes as empty.
        let (_, _, label, detail) =
            verdict_line::parse("PATINA_VERDICT seq=0 kind=pass label= detail=").unwrap();
        assert!(label.is_empty() && detail.is_empty());
    }
}
