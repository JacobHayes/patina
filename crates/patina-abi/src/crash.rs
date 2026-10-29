//! What a modeled crash loses, and which operations a crash can follow.

use crate::Operation;
use serde::{Deserialize, Serialize};

/// What a modeled crash takes down, and so what the restarted incarnation
/// finds on disk.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrashKind {
    /// The process dies (`SIGKILL`, the OOM killer) and the kernel lives on:
    /// the page cache survives, so every completed write is visible after the
    /// restart whether or not it was synced. Only process state is lost: open
    /// descriptors, anonymous files, bytes in flight through a pipe.
    Process,
    /// The machine goes down (power loss, a kernel panic): only what was made
    /// durable is certain to survive. Each unsynced block may or may not have
    /// reached the disk, independently of every other, and a namespace change
    /// (a new, removed or renamed name) whose parent directory was never
    /// fsynced is lost.
    #[default]
    Machine,
}

impl CrashKind {
    /// The CLI and control-plane spelling.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Process => "process",
            Self::Machine => "machine",
        }
    }

    /// Parse [`CrashKind::name`]'s spelling.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "process" => Some(Self::Process),
            "machine" => Some(Self::Machine),
            _ => None,
        }
    }
}

impl Operation {
    /// Whether a crash can land right after this operation completes: an
    /// operation with an effect outside the process that a crash could cut
    /// short — a change to the filesystem (data, metadata, namespace or
    /// durability) or bytes handed to the network. Reads, clock and entropy
    /// draws, and scheduling change nothing a crash could lose.
    ///
    /// Exhaustive, so a new operation is a decision rather than an omission.
    pub fn is_crash_point(&self) -> bool {
        match self {
            Operation::FsOpen { flags, .. } => flags.create || flags.truncate,
            Operation::FsWrite { .. }
            | Operation::FsWriteAt { .. }
            | Operation::FsWriteBackAt { .. }
            | Operation::FsClose { .. }
            | Operation::FsCreateDirectory { .. }
            | Operation::FsRemoveFile { .. }
            | Operation::FsSetInodeMode { .. }
            | Operation::FsSync { .. }
            | Operation::FsSyncAll
            | Operation::FsSetLength { .. }
            | Operation::FsSetLengthByPath { .. }
            | Operation::FsAllocate { .. }
            | Operation::FsSetTimes { .. }
            | Operation::FsSetInodeTimes { .. }
            | Operation::FsSetTimesByPath { .. }
            | Operation::FsRemoveDirectory { .. }
            | Operation::FsRename { .. }
            | Operation::FsLink { .. }
            | Operation::FsSymlink { .. }
            | Operation::FsMakeFifo { .. }
            | Operation::FsMakeNode { .. }
            | Operation::FsRenameWhiteout { .. }
            | Operation::FsExchange { .. }
            | Operation::FsSetXattr { .. }
            | Operation::FsRemoveXattr { .. }
            | Operation::FsSetMode { .. }
            | Operation::FsSetFdMode { .. }
            | Operation::NetSend { .. }
            | Operation::NetTcpSend { .. }
            | Operation::NetTcpShutdown { .. } => true,
            Operation::EntropyFill { .. }
            | Operation::ClockNow { .. }
            | Operation::SleepUntil { .. }
            | Operation::FsRead { .. }
            | Operation::FsReadAt { .. }
            // Anonymous files and seals live and die with the process.
            | Operation::FsCreateAnonymous { .. }
            | Operation::FsSeals { .. }
            | Operation::FsAddSeals { .. }
            | Operation::FsDup { .. }
            | Operation::FsSeek { .. }
            | Operation::FsMetadata { .. }
            | Operation::FsFdMetadata { .. }
            | Operation::FsRetainInode { .. }
            | Operation::FsReleaseInode { .. }
            | Operation::FsReadDirectory { .. }
            | Operation::FsReadDirectoryFd { .. }
            | Operation::FsReadLink { .. }
            | Operation::FsGetXattr { .. }
            | Operation::FsListXattr { .. }
            | Operation::FsInodeMetadata { .. }
            | Operation::FsFdPath { .. }
            | Operation::FsFdIno { .. }
            | Operation::DnsResolve { .. }
            | Operation::FsCrash
            | Operation::TaskSpawn { .. }
            | Operation::TaskYield { .. }
            | Operation::TaskPark { .. }
            | Operation::TaskParkTimed { .. }
            | Operation::TaskWake { .. }
            | Operation::SignalGenerated { .. }
            | Operation::TaskComplete { .. }
            | Operation::SchedulerNext
            | Operation::NetBind { .. }
            | Operation::NetBindShared { .. }
            | Operation::NetRecv { .. }
            | Operation::NetClose { .. }
            | Operation::NetMark { .. }
            | Operation::NetConnect { .. }
            | Operation::NetNextDelivery { .. }
            | Operation::NetTcpListen { .. }
            | Operation::NetTcpAccept { .. }
            | Operation::NetTcpConnect { .. }
            | Operation::NetTcpRecv { .. }
            | Operation::Verdict { .. }
            | Operation::CustomOp { .. } => false,
        }
    }
}
