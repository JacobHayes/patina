//! What each operation does outside the process, and what a modeled crash
//! loses.

use crate::{Operation, Outcome};
use serde::{Deserialize, Serialize};

/// What a modeled crash takes down, and so what the restarted incarnation
/// finds on disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrashKind {
    /// The process dies (`SIGKILL`, the OOM killer) and the kernel lives on:
    /// the page cache survives, so every completed write is visible after the
    /// restart whether or not it was synced. Only process state is lost: open
    /// descriptors, anonymous files, bytes in flight through a pipe.
    Process,
    /// The machine goes down (power loss, a kernel panic): the disk is what
    /// the last journal commit recorded, as ext4 leaves it. Metadata (names,
    /// sizes, times) rolls back to that commit atomically, and each block
    /// overwritten in place since may or may not have reached the disk,
    /// independently of every other.
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

/// What an operation does to the world outside the process: the one per-operation
/// classification every effect-based rule derives from, so a new operation
/// is a single decision rather than an entry in several parallel lists.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EffectClass {
    /// Something a peer can see: bytes handed to the network, and the
    /// connection setup and teardown (a SYN, a completed handshake, a FIN)
    /// another host observes.
    Emit,
    /// A change to storage that outlives the process: file data, metadata,
    /// the namespace, or a durability point.
    Persist,
    /// A read of state outside the process (a file, the network, the
    /// resolver, the entropy pool) that changes none of it.
    Observe,
    /// Process-local bookkeeping with no effect outside the process:
    /// descriptors, anonymous files, socket setup no peer sees yet, task
    /// lifecycle, verdicts.
    Local,
    /// Time and scheduling: reading the clock, sleeping, parking, waking,
    /// yielding, and the scheduler's own choice. Nothing but virtual time
    /// moves.
    Schedule,
}

impl EffectClass {
    /// Whether a crash right after an operation of this class can cut an
    /// effect short: something already left the process (a peer saw it, or
    /// storage took it) that the restarted process must cope with.
    pub const fn reaches_outside(self) -> bool {
        matches!(self, Self::Emit | Self::Persist)
    }

    /// Whether an operation of this class that ended with `outcome` is a
    /// crash point: it reached outside the process, it succeeded, and, for a
    /// poll (`poll`, [`Operation::is_poll`]), it found something to take.
    pub fn is_crash_point(self, poll: bool, outcome: &Outcome) -> bool {
        self.reaches_outside()
            && !matches!(outcome, Outcome::Error(_))
            && !(poll && outcome.is_empty_poll())
    }
}

impl Operation {
    /// This operation's [`EffectClass`].
    ///
    /// Exhaustive, so a new operation is a decision rather than an omission.
    pub fn effect_class(&self) -> EffectClass {
        match self {
            Operation::NetSend { .. }
            | Operation::NetTcpSend { .. }
            | Operation::NetTcpShutdown { .. }
            | Operation::NetTcpConnect { .. }
            | Operation::NetTcpAccept { .. }
            // Closing a stream sends its FIN (or a reset).
            | Operation::NetClose { .. } => EffectClass::Emit,
            Operation::FsOpen { flags, .. } => {
                if flags.create || flags.truncate {
                    EffectClass::Persist
                } else {
                    EffectClass::Observe
                }
            }
            Operation::FsWrite { .. }
            | Operation::FsWriteAt { .. }
            | Operation::FsWriteBackAt { .. }
            // A close can force delayed-allocation data out
            // (`auto_da_alloc` after a truncate to zero).
            | Operation::FsClose { .. }
            | Operation::FsCreateDirectory { .. }
            | Operation::FsRemoveFile { .. }
            | Operation::FsSetInodeMode { .. }
            | Operation::FsSync { .. }
            | Operation::FsSyncAll
            | Operation::FsSyncFilesystem { .. }
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
            | Operation::FsSetFdMode { .. } => EffectClass::Persist,
            Operation::EntropyFill { .. }
            | Operation::FsRead { .. }
            | Operation::FsReadAt { .. }
            | Operation::FsMetadata { .. }
            | Operation::FsFdMetadata { .. }
            | Operation::FsInodeMetadata { .. }
            | Operation::FsReadDirectory { .. }
            | Operation::FsReadDirectoryFd { .. }
            | Operation::FsReadLink { .. }
            | Operation::FsGetXattr { .. }
            | Operation::FsListXattr { .. }
            // Waits on writeback and reads back its error; makes nothing
            // durable.
            | Operation::FsWaitWriteback { .. }
            | Operation::DnsResolve { .. }
            | Operation::NetRecv { .. }
            | Operation::NetTcpRecv { .. } => EffectClass::Observe,
            // Anonymous files and seals live and die with the process, and
            // dropping clean pages changes nothing the disk holds.
            Operation::FsCreateAnonymous { .. }
            | Operation::FsSeals { .. }
            | Operation::FsAddSeals { .. }
            | Operation::FsDup { .. }
            | Operation::FsSeek { .. }
            | Operation::FsRetainInode { .. }
            | Operation::FsReleaseInode { .. }
            | Operation::FsFdPath { .. }
            | Operation::FsFdIno { .. }
            | Operation::FsDropCache { .. }
            | Operation::FsCrash
            | Operation::TaskSpawn { .. }
            | Operation::TaskComplete { .. }
            | Operation::SignalGenerated { .. }
            // No packet leaves until something is sent or a peer connects.
            | Operation::NetBind { .. }
            | Operation::NetBindShared { .. }
            | Operation::NetConnect { .. }
            | Operation::NetMark { .. }
            | Operation::NetTcpListen { .. }
            | Operation::Verdict { .. }
            | Operation::CustomOp { .. } => EffectClass::Local,
            Operation::ClockNow { .. }
            | Operation::SleepUntil { .. }
            | Operation::TaskYield { .. }
            | Operation::TaskPark { .. }
            | Operation::TaskParkTimed { .. }
            | Operation::TaskWake { .. }
            | Operation::SchedulerNext
            // The park-until-delivery probe: when, not what.
            | Operation::NetNextDelivery { .. } => EffectClass::Schedule,
        }
    }

    /// Whether this is a poll: an operation that may find nothing to take
    /// (a non-blocking receive or accept), in which case it had no effect.
    pub fn is_poll(&self) -> bool {
        matches!(
            self,
            Operation::NetRecv { .. }
                | Operation::NetTcpRecv { .. }
                | Operation::NetTcpAccept { .. }
        )
    }

    /// Whether this operation, having ended with `outcome`, is a crash point
    /// ([`EffectClass::is_crash_point`]).
    pub fn is_crash_point(&self, outcome: &Outcome) -> bool {
        self.effect_class().is_crash_point(self.is_poll(), outcome)
    }
}

impl Outcome {
    /// Whether a poll ([`Operation::is_poll`]) with this outcome found
    /// nothing to take. A stream's end of file and every error are outcomes
    /// in their own right.
    pub fn is_empty_poll(&self) -> bool {
        matches!(
            self,
            Outcome::Datagram(None) | Outcome::OptionalBytes(None) | Outcome::TcpAccepted(None)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EffectError, ErrorCode, SocketId, TcpAccepted};

    #[test]
    fn connection_setup_and_teardown_are_crash_points() {
        let socket = SocketId(3);
        for operation in [
            Operation::NetTcpConnect {
                address: "10.0.0.1:1".into(),
                to: "10.0.0.2:2".into(),
                now_nanos: 0,
            },
            Operation::NetClose { socket },
        ] {
            assert!(operation.is_crash_point(&Outcome::Unit), "{operation:?}");
        }
        let accept = Operation::NetTcpAccept {
            listener: socket,
            now_nanos: 0,
        };
        let accepted = Outcome::TcpAccepted(Some(TcpAccepted {
            socket,
            peer: "10.0.0.1:1".into(),
        }));
        assert!(accept.is_crash_point(&accepted));
        // An accept that found nothing, or failed, had no effect to cut short.
        assert!(!accept.is_crash_point(&Outcome::TcpAccepted(None)));
        let refused = Outcome::Error(EffectError::new(ErrorCode::ConnectionReset, "reset"));
        assert!(!accept.is_crash_point(&refused));
    }

    #[test]
    fn only_a_creating_or_truncating_open_persists() {
        let open = |create, truncate| Operation::FsOpen {
            path: "/f".into(),
            flags: crate::OpenFlags {
                write: true,
                create,
                truncate,
                ..crate::OpenFlags::read_only()
            },
        };
        assert_eq!(open(false, false).effect_class(), EffectClass::Observe);
        assert_eq!(open(true, false).effect_class(), EffectClass::Persist);
        assert_eq!(open(false, true).effect_class(), EffectClass::Persist);
    }
}
