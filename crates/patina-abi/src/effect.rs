//! Typed boundary operations and their serialized outcomes.

use crate::*;
use serde::{Deserialize, Serialize};

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
    /// What a shared mapping of the descriptor's file stored, written into the
    /// file: the page cache's write-back, not a guest `write`. Write seals do
    /// not refuse it (a mapping that was writable before `F_SEAL_FUTURE_WRITE`
    /// keeps writing); it counts toward the `write` crash ordinal like
    /// [`Operation::FsWriteAt`].
    FsWriteBackAt {
        fd: Fd,
        offset: u64,
        #[serde(with = "bytes_base64")]
        bytes: Vec<u8>,
    },
    /// `memfd_create`: a regular file no name reaches, opened read-write.
    /// `mode` is its permission bits and `seals` its initial `F_SEAL_*` set
    /// ([`seals`]); `name` is the caller's, which names nothing.
    FsCreateAnonymous {
        name: String,
        mode: u32,
        seals: u32,
        /// The huge page size of a hugetlbfs file (`MFD_HUGETLB`), 0 for a
        /// shmem one.
        huge_page: u64,
    },
    /// `fcntl(F_GET_SEALS)`: the seals of a descriptor's node, as
    /// [`Outcome::U64`]. A node that cannot be sealed is `InvalidInput`.
    FsSeals {
        fd: Fd,
    },
    /// `fcntl(F_ADD_SEALS)`. `writably_mapped` says a shared mapping that may
    /// write the node is live, which refuses a new `F_SEAL_WRITE` (`Busy`).
    FsAddSeals {
        fd: Fd,
        seals: u32,
        writably_mapped: bool,
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
    /// `fallocate(2)` over a regular file: `mode` is what happens to the
    /// range, `keep_size` leaves the length alone (`FALLOC_FL_KEEP_SIZE`);
    /// without it the file grows to `offset + len` when that is past its end.
    FsAllocate {
        fd: Fd,
        offset: u64,
        len: u64,
        mode: FsAllocateMode,
        keep_size: bool,
    },
    FsSetTimes {
        fd: Fd,
        #[serde(with = "nanos::option")]
        atime_nanos: Option<i128>,
        #[serde(with = "nanos::option")]
        mtime_nanos: Option<i128>,
    },
    FsSetInodeTimes {
        ino: u64,
        #[serde(with = "nanos::option")]
        atime_nanos: Option<i128>,
        #[serde(with = "nanos::option")]
        mtime_nanos: Option<i128>,
    },
    FsSetTimesByPath {
        path: String,
        #[serde(with = "nanos::option")]
        atime_nanos: Option<i128>,
        #[serde(with = "nanos::option")]
        mtime_nanos: Option<i128>,
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
    /// The inode an open descriptor names, for the bookkeeping keyed on file
    /// identity (record and `flock` locks). Like [`Operation::FsFdPath`] it is
    /// the lookup inside the call, not a trip to storage. The outcome carries
    /// the inode as [`Outcome::U64`].
    FsFdIno {
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
    /// Bind one more member of a shared (`SO_REUSEPORT`) binding at `address`.
    NetBindShared {
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
    /// Mark the datagrams a socket sends from now on: the type of service or
    /// traffic class they carry, and the source address they leave from in
    /// place of the one the route gives (`IP_PKTINFO`).
    NetMark {
        socket: SocketId,
        tos: u8,
        source: Option<String>,
    },
    /// Pin a datagram socket to one peer (`connect`): it then receives only
    /// what `peer` sends to `local`; `None` releases it (`AF_UNSPEC`).
    NetConnect {
        socket: SocketId,
        local: String,
        peer: Option<String>,
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
mod tests;
