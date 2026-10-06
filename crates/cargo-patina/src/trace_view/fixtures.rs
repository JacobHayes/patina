//! Representative operation fixtures for registry tests.

use super::*;

#[cfg(test)]
pub(crate) fn representative_events_for_all_op_kinds() -> Vec<(Operation, Outcome)> {
    use patina_dst_abi::{
        ClockKind, Datagram, EffectError, ErrorCode, Fd, FsAllocateMode, FsDirectoryEntry,
        FsEntryKind, FsMetadata, FsNode, OpenFlags, SeekWhence, SendDisposition, SendReport,
        ShutdownHow, SignalTarget, SocketId, TaskId, TcpAccepted, VerdictKind, XattrTarget,
    };

    let metadata = FsMetadata {
        kind: FsEntryKind::File,
        len: 12,
        blocks: 8,
        ino: 1,
        nlink: 1,
        atime_nanos: 0,
        mtime_nanos: 0,
        ctime_nanos: 0,
        btime_nanos: 0,
        mode: 0o644,
    };
    let datagram = Datagram {
        packet_id: 1,
        from: "127.0.0.1:1".into(),
        to: "127.0.0.1:2".into(),
        bytes: vec![9, 8, 7],
        delivery_nanos: 5,
        dialed: "127.0.0.1:2".into(),
        tos: 0,
    };
    vec![
        (
            Operation::EntropyFill { len: 4 },
            Outcome::Bytes(vec![1, 2, 3, 4]),
        ),
        (
            Operation::ClockNow {
                clock: ClockKind::Monotonic,
            },
            Outcome::U64(1_000_000),
        ),
        (
            Operation::SleepUntil {
                clock: ClockKind::Monotonic,
                deadline_nanos: 2_000_000,
            },
            Outcome::Unit,
        ),
        (
            Operation::FsOpen {
                path: "/missing".into(),
                flags: OpenFlags::read_only(),
            },
            Outcome::Error(EffectError::new(ErrorCode::NotFound, "missing")),
        ),
        (
            Operation::FsRead {
                fd: Fd(3),
                max_len: 8,
            },
            Outcome::Bytes(vec![1, 2]),
        ),
        (
            Operation::FsWrite {
                fd: Fd(3),
                bytes: vec![1, 2, 3],
            },
            Outcome::Usize(3),
        ),
        (
            Operation::FsReadAt {
                fd: Fd(3),
                offset: 4,
                max_len: 8,
            },
            Outcome::Bytes(vec![4, 5]),
        ),
        (
            Operation::FsWriteAt {
                fd: Fd(3),
                offset: 4,
                bytes: vec![6, 7],
            },
            Outcome::Usize(2),
        ),
        (Operation::FsClose { fd: Fd(3) }, Outcome::Unit),
        (Operation::FsDup { fd: Fd(3) }, Outcome::Handle(Fd(4))),
        (
            Operation::FsSeek {
                fd: Fd(3),
                offset: 0,
                whence: SeekWhence::Start,
            },
            Outcome::U64(0),
        ),
        (
            Operation::FsMetadata {
                path: "/file".into(),
            },
            Outcome::Metadata(metadata),
        ),
        (
            Operation::FsFdMetadata { fd: Fd(3) },
            Outcome::Metadata(metadata),
        ),
        (
            Operation::FsInodeMetadata { ino: 7 },
            Outcome::Metadata(metadata),
        ),
        (
            Operation::FsCreateDirectory {
                path: "/d".into(),
                mode: 0o755,
            },
            Outcome::Unit,
        ),
        (
            Operation::FsRemoveFile {
                path: "/file".into(),
            },
            Outcome::Unit,
        ),
        (
            Operation::FsSetInodeMode {
                ino: 7,
                mode: 0o640,
            },
            Outcome::Unit,
        ),
        (Operation::FsRetainInode { ino: 7 }, Outcome::Unit),
        (
            Operation::FsWriteBackAt {
                fd: Fd(3),
                offset: 4096,
                bytes: b"mapped".to_vec(),
            },
            Outcome::Usize(6),
        ),
        (
            Operation::FsCreateAnonymous {
                name: "buffer".into(),
                mode: 0o777,
                seals: 1,
                huge_page: 0,
            },
            Outcome::Handle(Fd(4)),
        ),
        (Operation::FsSeals { fd: Fd(4) }, Outcome::U64(1)),
        (
            Operation::FsAddSeals {
                fd: Fd(4),
                seals: 8,
                writably_mapped: false,
            },
            Outcome::Unit,
        ),
        (Operation::FsReleaseInode { ino: 7 }, Outcome::Unit),
        (Operation::FsSync { fd: Fd(3) }, Outcome::Unit),
        (Operation::FsSetLength { fd: Fd(3), len: 9 }, Outcome::Unit),
        (
            Operation::FsSetLengthByPath {
                path: "/state/log".into(),
                len: 9,
            },
            Outcome::Unit,
        ),
        (
            Operation::FsAllocate {
                fd: Fd(3),
                offset: 0,
                len: 4096,
                mode: FsAllocateMode::Reserve,
                keep_size: true,
            },
            Outcome::Unit,
        ),
        (
            Operation::FsSetTimes {
                fd: Fd(3),
                atime_nanos: Some(1),
                mtime_nanos: Some(2),
            },
            Outcome::Unit,
        ),
        (
            Operation::FsSetInodeTimes {
                ino: 2,
                atime_nanos: Some(1),
                mtime_nanos: Some(2),
            },
            Outcome::Unit,
        ),
        (
            Operation::FsSetTimesByPath {
                path: "/file".into(),
                atime_nanos: Some(1),
                mtime_nanos: Some(2),
            },
            Outcome::Unit,
        ),
        (
            Operation::FsReadDirectory { path: "/d".into() },
            Outcome::DirectoryEntries(vec![FsDirectoryEntry {
                name: "file".into(),
                kind: FsEntryKind::File,
                ino: 2,
            }]),
        ),
        (
            Operation::FsReadDirectoryFd { fd: Fd(3) },
            Outcome::DirectoryEntries(vec![FsDirectoryEntry {
                name: "file".into(),
                kind: FsEntryKind::File,
                ino: 2,
            }]),
        ),
        (
            Operation::FsRemoveDirectory { path: "/d".into() },
            Outcome::Unit,
        ),
        (
            Operation::FsRename {
                from: "/a".into(),
                to: "/b".into(),
            },
            Outcome::Unit,
        ),
        (
            Operation::FsLink {
                from: "/a".into(),
                to: "/b".into(),
            },
            Outcome::Unit,
        ),
        (
            Operation::FsSymlink {
                target: "/target".into(),
                link_path: "/link".into(),
            },
            Outcome::Unit,
        ),
        (
            Operation::FsReadLink {
                path: "/link".into(),
            },
            Outcome::Bytes(b"/target".to_vec()),
        ),
        (
            Operation::FsMakeFifo {
                path: "/pipe".into(),
                mode: 0o644,
            },
            Outcome::Unit,
        ),
        (
            Operation::FsMakeNode {
                path: "/socket".into(),
                node: FsNode::Socket,
                mode: 0o600,
            },
            Outcome::Unit,
        ),
        (
            Operation::FsExchange {
                first: "/a".into(),
                second: "/b".into(),
            },
            Outcome::Unit,
        ),
        (
            Operation::FsRenameWhiteout {
                from: "/a".into(),
                to: "/b".into(),
            },
            Outcome::Unit,
        ),
        (Operation::FsSyncAll, Outcome::Unit),
        (
            Operation::FsGetXattr {
                target: XattrTarget::Path("/file".into()),
                name: "user.k".into(),
            },
            Outcome::Bytes(b"v".to_vec()),
        ),
        (
            Operation::FsListXattr {
                target: XattrTarget::Fd(Fd(3)),
            },
            Outcome::Bytes(b"user.k\0".to_vec()),
        ),
        (
            Operation::FsSetXattr {
                target: XattrTarget::Path("/file".into()),
                name: "user.k".into(),
                value: b"v".to_vec(),
                flags: 1,
            },
            Outcome::Unit,
        ),
        (
            Operation::FsRemoveXattr {
                target: XattrTarget::Inode(7),
                name: "user.k".into(),
            },
            Outcome::Unit,
        ),
        (
            Operation::FsSetMode {
                path: "/file".into(),
                mode: 0o600,
            },
            Outcome::Unit,
        ),
        (
            Operation::FsSetFdMode {
                fd: Fd(3),
                mode: 0o600,
            },
            Outcome::Unit,
        ),
        (
            Operation::FsFdPath { fd: Fd(3) },
            Outcome::Bytes(b"/dir".to_vec()),
        ),
        (Operation::FsFdIno { fd: Fd(3) }, Outcome::U64(7)),
        (
            Operation::DnsResolve {
                name: "db.internal".into(),
            },
            Outcome::Bytes(b"10.0.0.5".to_vec()),
        ),
        (Operation::FsCrash, Outcome::Unit),
        (
            Operation::TaskSpawn {
                label: "worker".into(),
            },
            Outcome::Task(TaskId(1)),
        ),
        (Operation::TaskYield { task: TaskId(1) }, Outcome::Unit),
        (
            Operation::TaskPark {
                task: TaskId(1),
                reason: "wait".into(),
            },
            Outcome::Unit,
        ),
        (
            Operation::TaskParkTimed {
                task: TaskId(1),
                reason: "timer".into(),
                deadline_nanos: 3_000_000,
            },
            Outcome::Unit,
        ),
        (Operation::TaskWake { task: TaskId(1) }, Outcome::Unit),
        (
            Operation::SignalGenerated {
                seq: 1,
                sig: 10,
                target: SignalTarget::Task(TaskId(1)),
                code: -6,
                value: 0,
            },
            Outcome::Unit,
        ),
        (Operation::TaskComplete { task: TaskId(1) }, Outcome::Unit),
        (
            Operation::SchedulerNext,
            Outcome::OptionalTask(Some(TaskId(1))),
        ),
        (
            Operation::NetBind {
                address: "127.0.0.1:1".into(),
            },
            Outcome::Socket(SocketId(1)),
        ),
        (
            Operation::NetBindShared {
                address: "127.0.0.1:3".into(),
            },
            Outcome::Socket(SocketId(2)),
        ),
        (
            Operation::NetMark {
                socket: SocketId(1),
                tos: 0x2e,
                source: Some("127.0.0.9:1".into()),
            },
            Outcome::Unit,
        ),
        (
            Operation::NetConnect {
                socket: SocketId(1),
                local: "127.0.0.1:1".into(),
                peer: Some("127.0.0.1:2".into()),
            },
            Outcome::Unit,
        ),
        (
            Operation::NetSend {
                socket: SocketId(1),
                to: "127.0.0.1:2".into(),
                bytes: vec![1, 2, 3],
                now_nanos: 4_000_000,
            },
            Outcome::SendReport(SendReport {
                written: 0,
                copies: 0,
                delivery_nanos: vec![],
                disposition: SendDisposition::DroppedByFault,
            }),
        ),
        (
            Operation::NetRecv {
                socket: SocketId(1),
                now_nanos: 4_000_001,
            },
            Outcome::Datagram(Some(datagram)),
        ),
        (
            Operation::NetClose {
                socket: SocketId(1),
            },
            Outcome::Unit,
        ),
        (
            Operation::NetNextDelivery {
                socket: SocketId(1),
                now_nanos: 4_000_002,
            },
            Outcome::OptionalU64(Some(4_100_000)),
        ),
        (
            Operation::NetTcpListen {
                address: "127.0.0.1:10".into(),
                backlog: 16,
            },
            Outcome::Socket(SocketId(2)),
        ),
        (
            Operation::NetTcpAccept {
                listener: SocketId(2),
                now_nanos: 4_000_003,
            },
            Outcome::TcpAccepted(Some(TcpAccepted {
                socket: SocketId(3),
                peer: "127.0.0.1:11".into(),
            })),
        ),
        (
            Operation::NetTcpConnect {
                address: "127.0.0.1:11".into(),
                to: "127.0.0.1:10".into(),
                now_nanos: 4_000_004,
            },
            Outcome::Socket(SocketId(4)),
        ),
        (
            Operation::NetTcpSend {
                socket: SocketId(4),
                bytes: vec![1, 2],
                now_nanos: 4_000_005,
            },
            Outcome::Usize(2),
        ),
        (
            Operation::NetTcpRecv {
                socket: SocketId(4),
                max_len: 8,
                now_nanos: 4_000_006,
            },
            Outcome::OptionalBytes(Some(vec![5, 6])),
        ),
        (
            Operation::NetTcpShutdown {
                socket: SocketId(4),
                how: ShutdownHow::Both,
            },
            Outcome::Unit,
        ),
        (
            Operation::Verdict {
                verdict_kind: VerdictKind::Violation,
                label: "two-leaders".into(),
                detail: "{\"term\":4}".into(),
            },
            Outcome::Unit,
        ),
        (
            Operation::CustomOp {
                label: "s3.get_object".into(),
                key: b"bucket/key".to_vec(),
            },
            Outcome::Bytes(b"{\"etag\":\"a\"}".to_vec()),
        ),
    ]
}
