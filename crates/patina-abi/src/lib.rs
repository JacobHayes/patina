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

/// Flags accepted by the minimal filesystem `open` operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenFlags {
    pub read: bool,
    pub write: bool,
    pub create: bool,
    pub truncate: bool,
    pub append: bool,
    pub exclusive: bool,
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
}

/// Deterministic filesystem metadata exposed at the effect boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsMetadata {
    pub kind: FsEntryKind,
    pub len: u64,
    /// Deterministic filesystem object identity.
    pub ino: u64,
    /// Number of directory entries linked to this filesystem object.
    pub nlink: u32,
    /// Explicit virtual access timestamp in nanoseconds.
    ///
    /// Drivers without a clock do not auto-update this field. For example,
    /// `patina-dst-fs-mem` changes timestamps only via explicit set-times calls.
    pub atime_nanos: u64,
    /// Explicit virtual modification timestamp in nanoseconds.
    ///
    /// Drivers without a clock do not auto-update this field. For example,
    /// `patina-dst-fs-mem` changes timestamps only via explicit set-times calls.
    pub mtime_nanos: u64,
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
    FsCreateDirectory {
        path: String,
    },
    FsRemoveFile {
        path: String,
    },
    FsSync {
        fd: Fd,
    },
    FsSetLength {
        fd: Fd,
        len: u64,
    },
    FsSetTimes {
        fd: Fd,
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
        };
        let json = serde_json::to_string(&metadata).unwrap();
        assert!(json.contains("\"kind\":\"symlink\""));
        assert_eq!(serde_json::from_str::<FsMetadata>(&json).unwrap(), metadata);
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
}
