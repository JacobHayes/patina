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

pub trait SchedulerDriver: Send {
    fn spawn(&mut self, label: &str) -> DriverResult<TaskId>;
    fn yield_task(&mut self, task: TaskId) -> DriverResult<()>;
    fn park(&mut self, task: TaskId, reason: &str) -> DriverResult<()>;
    fn wake(&mut self, task: TaskId) -> DriverResult<()>;
    fn complete(&mut self, task: TaskId) -> DriverResult<()>;
    fn next(&mut self) -> DriverResult<Option<TaskId>>;
    fn select(&mut self, task: Option<TaskId>) -> DriverResult<()>;
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
