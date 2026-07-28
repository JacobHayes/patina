//! Narrow data-plane interfaces implemented by deterministic drivers.
//!
//! Concrete drivers keep rich builders in their own crates. These traits only
//! describe effects required by the runtime boundary.

use patina_abi::{
    ClockKind, Datagram, EffectError, Fd, FsDirectoryEntry, FsMetadata, OpenFlags, SeekWhence,
    SendReport, ShutdownHow, SocketId, TaskId, TcpAccepted,
};

pub type DriverResult<T> = Result<T, EffectError>;

pub trait FsDriver: Send {
    fn open(&mut self, path: &str, flags: OpenFlags) -> DriverResult<Fd>;
    fn read(&mut self, fd: Fd, max_len: usize) -> DriverResult<Vec<u8>>;
    fn write(&mut self, fd: Fd, bytes: &[u8]) -> DriverResult<usize>;
    /// Positional read: read up to `max_len` bytes starting at `offset` WITHOUT
    /// disturbing the shared file cursor (the `pread`/`read_at` contract).
    ///
    /// The default composes `seek`(save)/`seek`(offset)/`read`/`seek`(restore)
    /// and runs entirely inside this one driver call. The runtime never
    /// interleaves a scheduler switch inside a single driver invocation, so the
    /// save/seek/read/restore sequence is atomic with respect to the
    /// deterministic scheduler even when multiple guest threads share the fd --
    /// which is exactly why positional I/O must reach the driver as ONE
    /// operation rather than being emulated with separate seek/read calls on the
    /// caller side. Drivers with native positional reads may override this.
    fn read_at(&mut self, fd: Fd, offset: u64, max_len: usize) -> DriverResult<Vec<u8>> {
        let saved = self.seek(fd, 0, SeekWhence::Current)?;
        self.seek(fd, checked_offset(offset)?, SeekWhence::Start)?;
        let result = self.read(fd, max_len);
        // Restore the cursor regardless of the read outcome, so a positional
        // read is a no-op on the file offset; the read result takes precedence.
        let restored = self.seek(fd, checked_offset(saved)?, SeekWhence::Start);
        result.and_then(|bytes| restored.map(|_| bytes))
    }
    /// Positional write: write `bytes` starting at `offset` WITHOUT disturbing
    /// the shared file cursor (the `pwrite`/`write_at` contract). Atomic with
    /// respect to the scheduler for the same reason as [`FsDriver::read_at`];
    /// crash-consistency wrappers see the underlying `write`, so a positional
    /// write is journaled and crash-losable exactly like a cursor write.
    fn write_at(&mut self, fd: Fd, offset: u64, bytes: &[u8]) -> DriverResult<usize> {
        let saved = self.seek(fd, 0, SeekWhence::Current)?;
        self.seek(fd, checked_offset(offset)?, SeekWhence::Start)?;
        let result = self.write(fd, bytes);
        let restored = self.seek(fd, checked_offset(saved)?, SeekWhence::Start);
        result.and_then(|written| restored.map(|_| written))
    }
    fn close(&mut self, fd: Fd) -> DriverResult<()>;
    fn seek(&mut self, _fd: Fd, _offset: i64, _whence: SeekWhence) -> DriverResult<u64> {
        Err(unsupported_filesystem_operation("seek"))
    }
    fn dup(&mut self, _fd: Fd) -> DriverResult<Fd> {
        Err(unsupported_filesystem_operation("dup"))
    }
    fn metadata(&mut self, _path: &str) -> DriverResult<FsMetadata> {
        Err(unsupported_filesystem_operation("metadata"))
    }
    fn fd_metadata(&mut self, _fd: Fd) -> DriverResult<FsMetadata> {
        Err(unsupported_filesystem_operation("descriptor metadata"))
    }
    fn create_directory(&mut self, _path: &str) -> DriverResult<()> {
        Err(unsupported_filesystem_operation("create directory"))
    }
    fn remove_file(&mut self, _path: &str) -> DriverResult<()> {
        Err(unsupported_filesystem_operation("remove file"))
    }
    fn sync(&mut self, _fd: Fd) -> DriverResult<()> {
        Err(unsupported_filesystem_operation("sync"))
    }
    fn set_len(&mut self, _fd: Fd, _len: u64) -> DriverResult<()> {
        Err(unsupported_filesystem_operation("set length"))
    }
    fn set_times(
        &mut self,
        _fd: Fd,
        _atime_nanos: Option<u64>,
        _mtime_nanos: Option<u64>,
    ) -> DriverResult<()> {
        Err(unsupported_filesystem_operation("set times"))
    }
    fn set_times_by_path(
        &mut self,
        _path: &str,
        _atime_nanos: Option<u64>,
        _mtime_nanos: Option<u64>,
    ) -> DriverResult<()> {
        Err(unsupported_filesystem_operation("set times by path"))
    }
    fn read_directory(&mut self, _path: &str) -> DriverResult<Vec<FsDirectoryEntry>> {
        Err(unsupported_filesystem_operation("read directory"))
    }
    fn remove_directory(&mut self, _path: &str) -> DriverResult<()> {
        Err(unsupported_filesystem_operation("remove directory"))
    }
    fn rename(&mut self, _from: &str, _to: &str) -> DriverResult<()> {
        Err(unsupported_filesystem_operation("rename"))
    }
    fn link(&mut self, _from: &str, _to: &str) -> DriverResult<()> {
        Err(unsupported_filesystem_operation("link"))
    }
    fn symlink(&mut self, _target: &str, _link_path: &str) -> DriverResult<()> {
        Err(unsupported_filesystem_operation("symlink"))
    }
    fn read_link(&mut self, _path: &str) -> DriverResult<String> {
        Err(unsupported_filesystem_operation("read link"))
    }
    fn crash(&mut self) -> DriverResult<()> {
        Err(unsupported_filesystem_operation("crash"))
    }
}

fn unsupported_filesystem_operation(operation: &str) -> EffectError {
    EffectError::new(
        patina_abi::ErrorCode::Denied,
        format!("filesystem driver does not support {operation}"),
    )
}

/// Convert an unsigned byte offset to the signed offset `seek` takes, rejecting
/// values past `i64::MAX` (unreachable for the in-memory filesystems but kept
/// sound rather than silently wrapping).
fn checked_offset(offset: u64) -> DriverResult<i64> {
    i64::try_from(offset).map_err(|_| {
        EffectError::new(
            patina_abi::ErrorCode::InvalidInput,
            format!("positional offset {offset} exceeds the addressable range"),
        )
    })
}

fn unsupported_network_operation(operation: &str) -> EffectError {
    EffectError::new(
        patina_abi::ErrorCode::Denied,
        format!("network driver does not support {operation}"),
    )
}

pub trait ClockDriver: Send {
    fn now(&mut self, clock: ClockKind) -> DriverResult<u64>;
    fn sleep_until(&mut self, clock: ClockKind, deadline_nanos: u64) -> DriverResult<()>;
}

pub trait EntropyDriver: Send {
    fn fill(&mut self, destination: &mut [u8]) -> DriverResult<()>;
}

/// End-of-run summary of an exploration scheduling policy (PCT priority-change
/// points, starvation intervals). Populated only during a live selection run
/// (`next()` decisions), so it reflects the record/seeded schedule; on replay the
/// recorded task selections are consumed through `select()` and `next()` is not
/// called, so a replay reports the inert default. The runtime folds these counts
/// into the machine-readable `PATINA_SCHEDULE_POLICY` diagnostic line and the
/// bug-depth annotation of a failing schedule.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SchedulePolicyReport {
    /// Whether the PCT (Probabilistic Concurrency Testing) policy was active.
    pub pct: bool,
    /// Configured PCT bug-depth `d` (number of priority bands; `d-1` change
    /// points).
    pub pct_depth: u32,
    /// Configured number of priority-change points (`d-1`).
    pub pct_change_points: u32,
    /// Number of priority-change points that were actually reached during the
    /// schedule (a live change point demoted a running task). This is the PCT
    /// contribution to the bug-depth estimate of a schedule.
    pub pct_change_points_hit: u32,
    /// Whether the starvation-interval policy was active.
    pub starvation: bool,
    /// Number of scheduling decisions where the starvation policy actually
    /// excluded at least one runnable task from selection.
    pub starve_events: u64,
    /// Number of scheduling decisions where honoring the starvation set would
    /// have left no schedulable task (every runnable task starved). The policy
    /// falls back to the full runnable set at those steps (liveness safety) and
    /// counts them here so a vacuous starvation configuration is diagnosed.
    pub starve_vacuous: u64,
    /// Total scheduling decisions (`next()` calls) observed under the policy.
    pub decisions: u64,
}

impl SchedulePolicyReport {
    /// Whether any exploration policy was active this run.
    pub fn is_active(&self) -> bool {
        self.pct || self.starvation
    }

    /// The bug-depth estimate for the realized schedule: the number of ordering
    /// decisions (priority-change points hit plus starvation exclusions) that
    /// were live in the schedule. A failure found under a schedule with a higher
    /// estimate exercised a deeper interleaving.
    pub fn bug_depth(&self) -> u64 {
        u64::from(self.pct_change_points_hit) + self.starve_events
    }
}

pub trait SchedulerDriver: Send {
    fn spawn(&mut self, label: &str) -> DriverResult<TaskId>;
    fn yield_task(&mut self, task: TaskId) -> DriverResult<()>;
    fn park(&mut self, task: TaskId, reason: &str) -> DriverResult<()>;
    fn wake(&mut self, task: TaskId) -> DriverResult<()>;
    fn complete(&mut self, task: TaskId) -> DriverResult<()>;
    fn next(&mut self) -> DriverResult<Option<TaskId>>;
    fn select(&mut self, task: Option<TaskId>) -> DriverResult<()>;
    /// End-of-run exploration-policy summary. The default scheduler policy
    /// (uniform random selection) reports `None`; PCT and starvation policies
    /// report their live counts. Read once at run finalization.
    fn policy_report(&self) -> Option<SchedulePolicyReport> {
        None
    }

    /// Whether the most recent scheduling decision deliberately withheld a
    /// runnable task from selection because of an active exploration policy — a
    /// starvation interval excluding a runnable task, or PCT priority ordering
    /// preferring a higher-priority task over an available strictly-lower-priority
    /// one. The liveness watchdog consults this so a *policy-explained*
    /// non-progress window (a deliberate starvation interval or a PCT priority
    /// deferral) is never misreported as a liveness violation: only genuine
    /// no-progress beyond policy-explained deferral trips the watchdog. The
    /// default (uniform-random) policy never defers, so it reports `false` and
    /// the watchdog is fully live for a plain run. Reflects the last `next()`
    /// decision; on replay `next()` is not called, so it reports `false`.
    fn liveness_deferring(&self) -> bool {
        false
    }
}

pub trait NetDriver: Send {
    fn bind(&mut self, address: &str) -> DriverResult<SocketId>;
    fn validate_send(&self, socket: SocketId, to: &str) -> DriverResult<()>;
    fn send(
        &mut self,
        socket: SocketId,
        to: &str,
        bytes: &[u8],
        delivery_nanos: u64,
    ) -> DriverResult<SendReport>;
    fn recv(&mut self, socket: SocketId, now_nanos: u64) -> DriverResult<Option<Datagram>>;
    /// The earliest future delivery time (`delivery_nanos > now_nanos`) among
    /// packets addressed to `socket`, or `None` when none are pending. A
    /// blocking receive uses this to park until virtual time reaches a
    /// deliverable packet under non-zero link latency. The default is
    /// conservative (`None`); drivers that model delivery timing override it,
    /// and wrappers must forward it so wrapped latency stays visible.
    fn next_delivery(&self, _socket: SocketId, _now_nanos: u64) -> DriverResult<Option<u64>> {
        Ok(None)
    }

    /// Bind a TCP listener at `address` with a pending-connection budget of
    /// `backlog` (values below 1 are treated as 1).
    fn tcp_listen(&mut self, _address: &str, _backlog: usize) -> DriverResult<SocketId> {
        Err(unsupported_network_operation("tcp listen"))
    }

    /// Pop the oldest established, not-yet-accepted connection, or `None` when
    /// nothing is pending at `now_nanos`.
    fn tcp_accept(
        &mut self,
        _listener: SocketId,
        _now_nanos: u64,
    ) -> DriverResult<Option<TcpAccepted>> {
        Err(unsupported_network_operation("tcp accept"))
    }

    /// Establish a connection from local `address` to the listener at `to`.
    /// Zero-latency drivers establish synchronously; `now_nanos` is the
    /// virtual send time of the handshake so a latency wrapper can delay it
    /// in a future revision.
    fn tcp_connect(
        &mut self,
        _address: &str,
        _to: &str,
        _now_nanos: u64,
    ) -> DriverResult<SocketId> {
        Err(unsupported_network_operation("tcp connect"))
    }

    /// Append up to `bytes.len()` bytes to the peer's receive buffer with
    /// delivery time `delivery_nanos` (callers pass "now"; wrappers may add
    /// latency). Returns the number of bytes accepted — `0` means the peer's
    /// buffer is full (would-block), never an error.
    fn tcp_send(
        &mut self,
        _socket: SocketId,
        _bytes: &[u8],
        _delivery_nanos: u64,
    ) -> DriverResult<usize> {
        Err(unsupported_network_operation("tcp send"))
    }

    /// Take up to `max_len` deliverable bytes. `None` = no data deliverable at
    /// `now_nanos` and the peer may still write (would-block); `Some(empty)` =
    /// end of stream; `Some(bytes)` = data (may cross segment boundaries).
    fn tcp_recv(
        &mut self,
        _socket: SocketId,
        _max_len: usize,
        _now_nanos: u64,
    ) -> DriverResult<Option<Vec<u8>>> {
        Err(unsupported_network_operation("tcp recv"))
    }

    /// Close one or both directions of an established stream.
    fn tcp_shutdown(&mut self, _socket: SocketId, _how: ShutdownHow) -> DriverResult<()> {
        Err(unsupported_network_operation("tcp shutdown"))
    }

    fn close(&mut self, socket: SocketId) -> DriverResult<()>;
}
