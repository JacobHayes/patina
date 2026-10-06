//! Network driver operations and socket readiness.

use crate::{DriverResult, NetFaultReport};
use patina_dst_abi::{Datagram, EffectError, SendReport, ShutdownHow, SocketId, TcpAccepted};

/// Level-triggered readiness of a virtual socket at a given virtual instant,
/// for a readiness reactor (`poll`/`epoll`/`kqueue`). `read_eof`/`write_eof`
/// carry the end-of-stream conditions: the peer will send no more and
/// everything it sent was read (`read_eof`), or will read no more / the stream
/// is torn down (`write_eof`). The rest are the facts a kernel's poll function
/// reads off the socket: whether the peer shut its writing side
/// (`peer_write_closed`, the FIN — arrived once every byte sent before it has,
/// and true while those bytes are still queued), whether the stream was reset, how many arrivals have become
/// deliverable so far (`arrivals`, the edge an edge-triggered interest fires
/// on), what a receive would take now (`pending`: the queued bytes of a
/// stream, the length of the next datagram), and what a send would take now
/// (`room`: the space left in a stream peer's receive buffer; `usize::MAX`
/// where a send never waits — a datagram, or a stream whose send fails
/// closed). A pure inspection — no bytes are
/// consumed and no state changes — so a reactor may call it repeatedly while
/// gathering events without perturbing the run.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NetReadiness {
    pub readable: bool,
    pub writable: bool,
    pub read_eof: bool,
    pub write_eof: bool,
    pub peer_write_closed: bool,
    pub reset: bool,
    pub arrivals: u64,
    pub pending: usize,
    pub room: usize,
}

fn unsupported_network_operation(operation: &str) -> EffectError {
    EffectError::new(
        patina_dst_abi::ErrorCode::Denied,
        format!("network driver does not support {operation}"),
    )
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

    /// Level-triggered readiness of `socket` at `now_nanos`, for a readiness
    /// reactor. The conditions mirror the blocking `recv`/`send` paths
    /// exactly: `readable` iff a receive would return data or end-of-stream,
    /// `writable` iff a send would make progress or fail closed rather than
    /// would-block. A pure `&self` inspection that consumes nothing, so a
    /// reactor gathers events without recording a boundary observation. The
    /// default reports "not ready"; drivers that model byte buffers override it
    /// and wrappers forward it so wrapped latency stays visible.
    fn readiness(&self, _socket: SocketId, _now_nanos: u64) -> DriverResult<NetReadiness> {
        Ok(NetReadiness::default())
    }

    /// Bind `address` as one more member of a shared binding (`SO_REUSEPORT`):
    /// every member receives a share of the traffic dialed at the address, a
    /// fixed member per sending address. `AlreadyBound` when the address is
    /// held by an unshared binding.
    fn bind_shared(&mut self, _address: &str) -> DriverResult<SocketId> {
        Err(unsupported_network_operation("shared bind"))
    }

    /// Mark the datagrams `socket` sends from now on with `tos` (the IPv4
    /// type of service or IPv6 traffic class) and, when `source` is given,
    /// the source address they leave from in place of the one the route
    /// gives (`IP_PKTINFO`'s `ipi_spec_dst`). A receiver sees both.
    fn mark_datagrams(
        &mut self,
        _socket: SocketId,
        _tos: u8,
        _source: Option<&str>,
    ) -> DriverResult<()> {
        Err(unsupported_network_operation("datagram marks"))
    }

    /// Pin datagram socket `socket` to one peer (`connect`): it then receives
    /// only datagrams `peer` sends to `local`, as the kernel's 4-tuple lookup
    /// admits them (another sender's datagram goes to another socket on the
    /// port, or is unreachable); `None` releases it (`AF_UNSPEC`).
    fn connect_datagram(
        &mut self,
        _socket: SocketId,
        _local: &str,
        _peer: Option<&str>,
    ) -> DriverResult<()> {
        Err(unsupported_network_operation("datagram connect"))
    }

    /// The datagram `recv` would return at `now_nanos`, left queued
    /// (`MSG_PEEK`). A pure inspection like [`NetDriver::readiness`]: what it
    /// answers is a function of the recorded history and the clock.
    fn peek(&self, _socket: SocketId, _now_nanos: u64) -> DriverResult<Option<Datagram>> {
        Err(unsupported_network_operation("peek"))
    }

    /// What `tcp_recv` would return at `now_nanos`, left queued (`MSG_PEEK` on
    /// a stream). A pure inspection like [`NetDriver::readiness`].
    fn tcp_peek(
        &self,
        _socket: SocketId,
        _max_len: usize,
        _now_nanos: u64,
    ) -> DriverResult<Option<Vec<u8>>> {
        Err(unsupported_network_operation("tcp peek"))
    }

    /// End-of-run network fault-injection summary for the default-on vacuity
    /// diagnostic. A driver that models faults reports its counts; the default
    /// (a driver with no fault model) reports `None` and is never diagnosed as
    /// vacuous. A pure `&self` inspection read once at run finalization.
    /// Wrappers forward it so a wrapped fault-modeling driver stays visible.
    fn fault_report(&self) -> Option<NetFaultReport> {
        None
    }

    fn close(&mut self, socket: SocketId) -> DriverResult<()>;
}
