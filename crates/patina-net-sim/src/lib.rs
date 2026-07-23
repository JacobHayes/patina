//! Deterministic in-memory datagram and stream networking.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use patina_abi::{
    Datagram, EffectError, ErrorCode, SendDisposition, SendReport, ShutdownHow, SocketId,
    TcpAccepted,
};
use patina_driver_api::{DriverResult, NetDriver};

#[derive(Default)]
pub struct SimNetBuilder {
    base_latency_nanos: u64,
    partitions: BTreeSet<(String, String)>,
    tcp_buffer_bytes: Option<usize>,
}

impl SimNetBuilder {
    pub fn base_latency_nanos(mut self, value: u64) -> Self {
        self.base_latency_nanos = value;
        self
    }

    pub fn tcp_buffer_bytes(mut self, value: usize) -> Self {
        self.tcp_buffer_bytes = Some(value);
        self
    }

    /// Partition both directions between two exact virtual addresses.
    pub fn partition(mut self, left: impl Into<String>, right: impl Into<String>) -> Self {
        let left = left.into();
        let right = right.into();
        self.partitions.insert((left.clone(), right.clone()));
        self.partitions.insert((right, left));
        self
    }

    pub fn build(self) -> DriverResult<SimNet> {
        let tcp_buffer_bytes = self.tcp_buffer_bytes.unwrap_or(65_536);
        if tcp_buffer_bytes == 0 {
            return Err(EffectError::new(
                ErrorCode::InvalidInput,
                "virtual TCP receive buffer size must be greater than zero",
            ));
        }
        Ok(SimNet {
            base_latency_nanos: self.base_latency_nanos,
            partitions: self.partitions,
            bindings: BTreeMap::new(),
            addresses: BTreeMap::new(),
            packets: Vec::new(),
            next_socket: 1,
            next_packet: 1,
            tcp_buffer_bytes,
            tcp_listeners: BTreeMap::new(),
            tcp_listener_addresses: BTreeMap::new(),
            tcp_endpoints: BTreeMap::new(),
        })
    }
}

#[derive(Clone, Debug)]
struct Packet {
    id: u64,
    from: String,
    to: String,
    bytes: Vec<u8>,
    delivery_nanos: u64,
}

struct TcpListenerState {
    address: String,
    backlog: usize,
    /// Established, not-yet-accepted acceptor-side endpoints, oldest first.
    pending: VecDeque<SocketId>,
}

/// One in-flight or buffered stream segment. Zero-latency sends are
/// deliverable immediately; per-segment deadlines leave room for later latency.
struct TcpSegment {
    delivery_nanos: u64,
    bytes: Vec<u8>,
}

struct TcpEndpoint {
    local: String,
    peer_addr: String,
    /// The paired endpoint, `None` once the peer is closed and removed.
    peer: Option<SocketId>,
    inbox: VecDeque<TcpSegment>,
    inbox_bytes: usize,
    remote_write_closed: bool,
    read_closed: bool,
    write_closed: bool,
    reset: bool,
}

/// A deterministic virtual network.
pub struct SimNet {
    base_latency_nanos: u64,
    partitions: BTreeSet<(String, String)>,
    bindings: BTreeMap<SocketId, String>,
    addresses: BTreeMap<String, SocketId>,
    packets: Vec<Packet>,
    next_socket: u64,
    next_packet: u64,
    tcp_buffer_bytes: usize,
    tcp_listeners: BTreeMap<SocketId, TcpListenerState>,
    tcp_listener_addresses: BTreeMap<String, SocketId>,
    tcp_endpoints: BTreeMap<SocketId, TcpEndpoint>,
}

impl SimNet {
    pub fn builder() -> SimNetBuilder {
        SimNetBuilder::default()
    }

    pub fn new() -> Self {
        Self::builder()
            .build()
            .expect("default SimNet builder configuration is valid")
    }

    pub fn queued_packets(&self) -> usize {
        self.packets.len()
    }

    fn address(&self, socket: SocketId) -> DriverResult<&str> {
        self.bindings
            .get(&socket)
            .map(String::as_str)
            .ok_or_else(|| invalid_socket(socket))
    }

    fn allocate_socket(&mut self) -> DriverResult<SocketId> {
        let socket = SocketId(self.next_socket);
        self.next_socket = self.next_socket.checked_add(1).ok_or_else(|| {
            EffectError::new(
                ErrorCode::InvalidHandle,
                "virtual socket identifiers exhausted",
            )
        })?;
        Ok(socket)
    }
}

impl Default for SimNet {
    fn default() -> Self {
        Self::new()
    }
}

impl NetDriver for SimNet {
    fn bind(&mut self, address: &str) -> DriverResult<SocketId> {
        validate_address(address)?;
        if self.addresses.contains_key(address) {
            return Err(EffectError::new(
                ErrorCode::AlreadyBound,
                format!("virtual network address is already bound: {address}"),
            ));
        }
        let socket = self.allocate_socket()?;
        self.bindings.insert(socket, address.into());
        self.addresses.insert(address.into(), socket);
        Ok(socket)
    }

    fn validate_send(&self, socket: SocketId, to: &str) -> DriverResult<()> {
        validate_address(to)?;
        self.address(socket)?;
        if !self.addresses.contains_key(to) {
            return Err(EffectError::new(
                ErrorCode::NoRoute,
                format!("no virtual socket is bound at {to}"),
            ));
        }
        Ok(())
    }

    fn send(
        &mut self,
        socket: SocketId,
        to: &str,
        bytes: &[u8],
        delivery_nanos: u64,
    ) -> DriverResult<SendReport> {
        self.validate_send(socket, to)?;
        let from = self.address(socket)?.to_owned();
        if self.partitions.contains(&(from.clone(), to.into())) {
            return Ok(SendReport {
                written: bytes.len(),
                copies: 0,
                delivery_nanos: Vec::new(),
                disposition: SendDisposition::DroppedByPartition,
            });
        }
        let delivery_nanos = delivery_nanos
            .checked_add(self.base_latency_nanos)
            .ok_or_else(|| {
                EffectError::new(
                    ErrorCode::InvalidInput,
                    "virtual packet deadline overflowed",
                )
            })?;
        let packet = Packet {
            id: self.next_packet,
            from,
            to: to.into(),
            bytes: bytes.to_vec(),
            delivery_nanos,
        };
        self.next_packet = self.next_packet.checked_add(1).ok_or_else(|| {
            EffectError::new(
                ErrorCode::InvalidHandle,
                "virtual packet identifiers exhausted",
            )
        })?;
        self.packets.push(packet);
        Ok(SendReport {
            written: bytes.len(),
            copies: 1,
            delivery_nanos: vec![delivery_nanos],
            disposition: SendDisposition::Queued,
        })
    }

    fn recv(&mut self, socket: SocketId, now_nanos: u64) -> DriverResult<Option<Datagram>> {
        let destination = self.address(socket)?.to_owned();
        let candidate = self
            .packets
            .iter()
            .enumerate()
            .filter(|(_, packet)| packet.to == destination && packet.delivery_nanos <= now_nanos)
            .min_by_key(|(_, packet)| (packet.delivery_nanos, packet.id))
            .map(|(index, _)| index);
        let Some(index) = candidate else {
            return Ok(None);
        };
        let packet = self.packets.remove(index);
        Ok(Some(Datagram {
            packet_id: packet.id,
            from: packet.from,
            to: packet.to,
            bytes: packet.bytes,
            delivery_nanos: packet.delivery_nanos,
        }))
    }

    fn next_delivery(&self, socket: SocketId, now_nanos: u64) -> DriverResult<Option<u64>> {
        if let Some(destination) = self.bindings.get(&socket) {
            return Ok(self
                .packets
                .iter()
                .filter(|packet| packet.to == *destination && packet.delivery_nanos > now_nanos)
                .map(|packet| packet.delivery_nanos)
                .min());
        }
        if let Some(endpoint) = self.tcp_endpoints.get(&socket) {
            return Ok(endpoint
                .inbox
                .iter()
                .filter(|segment| segment.delivery_nanos > now_nanos)
                .map(|segment| segment.delivery_nanos)
                .min());
        }
        if self.tcp_listeners.contains_key(&socket) {
            return Ok(None);
        }
        Err(invalid_socket(socket))
    }

    fn tcp_listen(&mut self, address: &str, backlog: usize) -> DriverResult<SocketId> {
        validate_address(address)?;
        if self.tcp_listener_addresses.contains_key(address) {
            return Err(EffectError::new(
                ErrorCode::AlreadyBound,
                format!("virtual TCP address is already listening: {address}"),
            ));
        }
        let socket = self.allocate_socket()?;
        self.tcp_listeners.insert(
            socket,
            TcpListenerState {
                address: address.into(),
                backlog: backlog.max(1),
                pending: VecDeque::new(),
            },
        );
        self.tcp_listener_addresses.insert(address.into(), socket);
        Ok(socket)
    }

    fn tcp_accept(
        &mut self,
        listener: SocketId,
        _now_nanos: u64,
    ) -> DriverResult<Option<TcpAccepted>> {
        let state = self.tcp_listeners.get_mut(&listener).ok_or_else(|| {
            EffectError::new(
                ErrorCode::InvalidHandle,
                format!("virtual TCP listener {} is not bound", listener.0),
            )
        })?;
        let Some(socket) = state.pending.pop_front() else {
            return Ok(None);
        };
        let endpoint = self.tcp_endpoints.get(&socket).ok_or_else(|| {
            EffectError::new(
                ErrorCode::InvalidState,
                format!("virtual TCP pending stream {} is missing", socket.0),
            )
        })?;
        debug_assert_eq!(endpoint.local, state.address);
        Ok(Some(TcpAccepted {
            socket,
            peer: endpoint.peer_addr.clone(),
        }))
    }

    fn tcp_connect(&mut self, address: &str, to: &str, _now_nanos: u64) -> DriverResult<SocketId> {
        validate_address(address)?;
        validate_address(to)?;
        if self
            .partitions
            .contains(&(address.to_owned(), to.to_owned()))
        {
            return Err(EffectError::new(
                ErrorCode::ConnectionRefused,
                format!("virtual connection refused: {address} -> {to} is partitioned"),
            ));
        }
        let listener_id = self
            .tcp_listener_addresses
            .get(to)
            .copied()
            .ok_or_else(|| {
                EffectError::new(
                    ErrorCode::ConnectionRefused,
                    format!("no virtual TCP listener at {to}"),
                )
            })?;
        let listener = self
            .tcp_listeners
            .get(&listener_id)
            .expect("listener address map points to a listener");
        if listener.pending.len() >= listener.backlog {
            return Err(EffectError::new(
                ErrorCode::ConnectionRefused,
                format!("virtual TCP backlog is full at {to}"),
            ));
        }

        let client = self.allocate_socket()?;
        let acceptor = self.allocate_socket()?;
        self.tcp_endpoints.insert(
            client,
            TcpEndpoint {
                local: address.into(),
                peer_addr: to.into(),
                peer: Some(acceptor),
                inbox: VecDeque::new(),
                inbox_bytes: 0,
                remote_write_closed: false,
                read_closed: false,
                write_closed: false,
                reset: false,
            },
        );
        self.tcp_endpoints.insert(
            acceptor,
            TcpEndpoint {
                local: to.into(),
                peer_addr: address.into(),
                peer: Some(client),
                inbox: VecDeque::new(),
                inbox_bytes: 0,
                remote_write_closed: false,
                read_closed: false,
                write_closed: false,
                reset: false,
            },
        );
        self.tcp_listeners
            .get_mut(&listener_id)
            .expect("listener was checked")
            .pending
            .push_back(acceptor);
        Ok(client)
    }

    fn tcp_send(
        &mut self,
        socket: SocketId,
        bytes: &[u8],
        delivery_nanos: u64,
    ) -> DriverResult<usize> {
        // SimNet's UDP base_latency_nanos is intentionally not applied here:
        // TCP latency is deferred to wrapper-level per-segment delivery times.
        let endpoint = self.tcp_endpoints.get(&socket).ok_or_else(|| {
            EffectError::new(
                ErrorCode::InvalidHandle,
                format!("virtual TCP stream {} is not connected", socket.0),
            )
        })?;
        if endpoint.reset {
            return Err(tcp_reset(socket));
        }
        if endpoint.write_closed {
            return Err(EffectError::new(
                ErrorCode::BrokenPipe,
                format!("virtual TCP stream {} is shut down for writing", socket.0),
            ));
        }
        let peer = endpoint.peer.ok_or_else(|| tcp_reset(socket))?;
        if bytes.is_empty() {
            return Ok(0);
        }
        let peer_endpoint = self
            .tcp_endpoints
            .get_mut(&peer)
            .ok_or_else(|| tcp_reset(socket))?;
        if peer_endpoint.read_closed {
            return Ok(bytes.len());
        }
        let available = self.tcp_buffer_bytes - peer_endpoint.inbox_bytes;
        let accepted = bytes.len().min(available);
        if accepted > 0 {
            peer_endpoint.inbox.push_back(TcpSegment {
                delivery_nanos,
                bytes: bytes[..accepted].to_vec(),
            });
            peer_endpoint.inbox_bytes += accepted;
        }
        Ok(accepted)
    }

    fn tcp_recv(
        &mut self,
        socket: SocketId,
        max_len: usize,
        now_nanos: u64,
    ) -> DriverResult<Option<Vec<u8>>> {
        let endpoint = self.tcp_endpoints.get_mut(&socket).ok_or_else(|| {
            EffectError::new(
                ErrorCode::InvalidHandle,
                format!("virtual TCP stream {} is not connected", socket.0),
            )
        })?;
        if endpoint.reset {
            return Err(tcp_reset(socket));
        }
        if endpoint.read_closed {
            return Ok(Some(Vec::new()));
        }
        let mut taken = Vec::new();
        while taken.len() < max_len {
            let Some(front) = endpoint.inbox.front_mut() else {
                break;
            };
            if front.delivery_nanos > now_nanos {
                break;
            }
            let remaining = max_len - taken.len();
            if front.bytes.len() <= remaining {
                let segment = endpoint.inbox.pop_front().expect("front exists");
                endpoint.inbox_bytes -= segment.bytes.len();
                taken.extend_from_slice(&segment.bytes);
            } else {
                taken.extend_from_slice(&front.bytes[..remaining]);
                front.bytes.drain(..remaining);
                endpoint.inbox_bytes -= remaining;
            }
        }
        if !taken.is_empty() {
            return Ok(Some(taken));
        }
        if endpoint.remote_write_closed && endpoint.inbox.is_empty() {
            return Ok(Some(Vec::new()));
        }
        Ok(None)
    }

    fn tcp_shutdown(&mut self, socket: SocketId, how: ShutdownHow) -> DriverResult<()> {
        let peer = {
            let endpoint = self.tcp_endpoints.get_mut(&socket).ok_or_else(|| {
                EffectError::new(
                    ErrorCode::InvalidHandle,
                    format!("virtual TCP stream {} is not connected", socket.0),
                )
            })?;
            if matches!(how, ShutdownHow::Write | ShutdownHow::Both) {
                endpoint.write_closed = true;
            }
            if matches!(how, ShutdownHow::Read | ShutdownHow::Both) {
                endpoint.read_closed = true;
                endpoint.inbox.clear();
                endpoint.inbox_bytes = 0;
            }
            endpoint.peer
        };
        if matches!(how, ShutdownHow::Write | ShutdownHow::Both) {
            if let Some(peer) = peer.and_then(|peer| self.tcp_endpoints.get_mut(&peer)) {
                peer.remote_write_closed = true;
            }
        }
        Ok(())
    }

    fn close(&mut self, socket: SocketId) -> DriverResult<()> {
        if let Some(address) = self.bindings.remove(&socket) {
            self.addresses.remove(&address);
            // A datagram already sent is independent of its sender's socket
            // lifetime, so in-flight packets FROM this address stay deliverable.
            self.packets.retain(|packet| packet.to != address);
            return Ok(());
        }
        if let Some(listener) = self.tcp_listeners.remove(&socket) {
            self.tcp_listener_addresses.remove(&listener.address);
            for acceptor in listener.pending {
                let peer = self
                    .tcp_endpoints
                    .get(&acceptor)
                    .and_then(|endpoint| endpoint.peer);
                if let Some(endpoint) = self.tcp_endpoints.get_mut(&acceptor) {
                    endpoint.reset = true;
                    endpoint.peer = None;
                }
                if let Some(peer) = peer {
                    if let Some(endpoint) = self.tcp_endpoints.get_mut(&peer) {
                        endpoint.reset = true;
                        endpoint.peer = None;
                    }
                }
                self.tcp_endpoints.remove(&acceptor);
            }
            return Ok(());
        }
        if let Some(endpoint) = self.tcp_endpoints.remove(&socket) {
            if let Some(peer) = endpoint.peer {
                if let Some(peer_endpoint) = self.tcp_endpoints.get_mut(&peer) {
                    peer_endpoint.remote_write_closed = true;
                    peer_endpoint.peer = None;
                }
            }
            return Ok(());
        }
        Err(invalid_socket(socket))
    }
}

fn validate_address(address: &str) -> DriverResult<()> {
    if address.trim().is_empty() {
        return Err(EffectError::new(
            ErrorCode::InvalidInput,
            "virtual network address must not be empty",
        ));
    }
    Ok(())
}

fn invalid_socket(socket: SocketId) -> EffectError {
    EffectError::new(
        ErrorCode::InvalidHandle,
        format!("virtual socket {} is not bound", socket.0),
    )
}

fn tcp_reset(socket: SocketId) -> EffectError {
    EffectError::new(
        ErrorCode::ConnectionReset,
        format!("virtual TCP stream {} was reset by its peer", socket.0),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packets_observe_delivery_time_and_can_reorder() {
        let mut net = SimNet::new();
        let left = net.bind("left").unwrap();
        let right = net.bind("right").unwrap();
        net.send(left, "right", b"late", 20).unwrap();
        net.send(left, "right", b"early", 10).unwrap();
        assert_eq!(net.recv(right, 9).unwrap(), None);
        assert_eq!(net.recv(right, 10).unwrap().unwrap().bytes, b"early");
        assert_eq!(net.recv(right, 20).unwrap().unwrap().bytes, b"late");
    }

    #[test]
    fn next_delivery_reports_the_earliest_future_arrival_and_ignores_dropped_packets() {
        let mut net = SimNet::builder()
            .base_latency_nanos(5)
            .partition("left", "blocked")
            .build()
            .unwrap();
        let left = net.bind("left").unwrap();
        let right = net.bind("right").unwrap();
        net.bind("blocked").unwrap();
        net.send(left, "right", b"late", 20).unwrap();
        net.send(left, "right", b"early", 10).unwrap();
        net.send(left, "blocked", b"lost", 1).unwrap();
        assert_eq!(net.next_delivery(right, 0).unwrap(), Some(15));
        assert_eq!(net.next_delivery(right, 15).unwrap(), Some(25));
        assert_eq!(net.next_delivery(right, 25).unwrap(), None);
        assert_eq!(
            net.next_delivery(SocketId(999), 0).unwrap_err().code,
            ErrorCode::InvalidHandle
        );
    }

    #[test]
    fn next_delivery_after_close_sees_no_packets() {
        let mut net = SimNet::new();
        let sender = net.bind("sender").unwrap();
        let receiver = net.bind("receiver").unwrap();
        net.send(sender, "receiver", b"data", 100).unwrap();
        assert_eq!(net.next_delivery(receiver, 0).unwrap(), Some(100));
        net.close(receiver).unwrap();
        let rebound = net.bind("receiver").unwrap();
        assert_eq!(net.next_delivery(rebound, 0).unwrap(), None);
    }

    #[test]
    fn partitions_drop_without_silently_routing_to_the_host() {
        let mut net = SimNet::builder()
            .partition("left", "right")
            .build()
            .unwrap();
        let left = net.bind("left").unwrap();
        let right = net.bind("right").unwrap();
        let report = net.send(left, "right", b"lost", 0).unwrap();
        assert_eq!(report.disposition, SendDisposition::DroppedByPartition);
        assert_eq!(report.copies, 0);
        assert_eq!(net.recv(right, u64::MAX).unwrap(), None);
    }

    #[test]
    fn close_keeps_in_flight_sends_and_drops_undelivered_arrivals() {
        let mut net = SimNet::new();
        let sender = net.bind("sender").unwrap();
        let receiver = net.bind("receiver").unwrap();
        net.send(sender, "receiver", b"reply", 0).unwrap();
        net.close(sender).unwrap();
        assert_eq!(net.recv(receiver, 0).unwrap().unwrap().bytes, b"reply");
        net.send(receiver, "sender", b"gone", 0).unwrap_err();
    }

    #[test]
    fn duplicate_bind_is_rejected() {
        let mut net = SimNet::new();
        net.bind("addr").unwrap();
        assert_eq!(net.bind("addr").unwrap_err().code, ErrorCode::AlreadyBound);
    }

    #[test]
    fn tcp_connect_accept_and_transfer_round_trip() {
        let mut net = SimNet::new();
        let listener = net.tcp_listen("127.0.0.1:80", 8).unwrap();
        let client = net
            .tcp_connect("127.0.0.1:49152", "127.0.0.1:80", 0)
            .unwrap();
        let accepted = net.tcp_accept(listener, 0).unwrap().unwrap();
        assert_eq!(accepted.peer, "127.0.0.1:49152");
        net.tcp_send(client, b"hello", 0).unwrap();
        net.tcp_send(client, b" world", 0).unwrap();
        assert_eq!(
            net.tcp_recv(accepted.socket, 64, 0).unwrap().unwrap(),
            b"hello world"
        );
        net.tcp_send(accepted.socket, b"reply", 0).unwrap();
        assert_eq!(net.tcp_recv(client, 64, 0).unwrap().unwrap(), b"reply");
    }

    #[test]
    fn tcp_connect_without_listener_or_full_backlog_is_refused() {
        let mut net = SimNet::builder()
            .partition("127.0.0.1:1", "127.0.0.1:2")
            .build()
            .unwrap();
        assert_eq!(
            net.tcp_connect("127.0.0.1:1", "127.0.0.1:9", 0)
                .unwrap_err()
                .code,
            ErrorCode::ConnectionRefused
        );
        net.tcp_listen("127.0.0.1:2", 1).unwrap();
        assert_eq!(
            net.tcp_connect("127.0.0.1:1", "127.0.0.1:2", 0)
                .unwrap_err()
                .code,
            ErrorCode::ConnectionRefused
        );
        net.tcp_listen("127.0.0.1:3", 1).unwrap();
        net.tcp_connect("127.0.0.1:4", "127.0.0.1:3", 0).unwrap();
        assert_eq!(
            net.tcp_connect("127.0.0.1:5", "127.0.0.1:3", 0)
                .unwrap_err()
                .code,
            ErrorCode::ConnectionRefused
        );
    }

    #[test]
    fn tcp_backpressure_caps_the_inbox_and_reads_reopen_it() {
        let mut net = SimNet::builder().tcp_buffer_bytes(4).build().unwrap();
        let listener = net.tcp_listen("server", 1).unwrap();
        let client = net.tcp_connect("client", "server", 0).unwrap();
        let server = net.tcp_accept(listener, 0).unwrap().unwrap().socket;
        assert_eq!(net.tcp_send(client, b"abcdef", 0).unwrap(), 4);
        assert_eq!(net.tcp_send(client, b"z", 0).unwrap(), 0);
        assert_eq!(net.tcp_recv(server, 2, 0).unwrap().unwrap(), b"ab");
        assert_eq!(net.tcp_send(client, b"xy", 0).unwrap(), 2);
        assert_eq!(net.tcp_recv(server, 16, 0).unwrap().unwrap(), b"cdxy");
    }

    #[test]
    fn tcp_half_close_drains_buffered_data_then_reads_eof() {
        let mut net = SimNet::new();
        let listener = net.tcp_listen("server", 1).unwrap();
        let client = net.tcp_connect("client", "server", 0).unwrap();
        let server = net.tcp_accept(listener, 0).unwrap().unwrap().socket;
        net.tcp_send(client, b"abc", 0).unwrap();
        net.tcp_shutdown(client, ShutdownHow::Write).unwrap();
        assert_eq!(net.tcp_recv(server, 2, 0).unwrap().unwrap(), b"ab");
        assert_eq!(net.tcp_recv(server, 2, 0).unwrap().unwrap(), b"c");
        assert_eq!(net.tcp_recv(server, 2, 0).unwrap().unwrap(), b"");
        assert_eq!(net.tcp_recv(server, 2, 0).unwrap().unwrap(), b"");
        net.tcp_send(server, b"back", 0).unwrap();
        assert_eq!(net.tcp_recv(client, 8, 0).unwrap().unwrap(), b"back");
        assert_eq!(
            net.tcp_send(client, b"again", 0).unwrap_err().code,
            ErrorCode::BrokenPipe
        );
    }

    #[test]
    fn tcp_shutdown_read_discards_and_peer_sends_are_swallowed() {
        let mut net = SimNet::new();
        let listener = net.tcp_listen("server", 1).unwrap();
        let client = net.tcp_connect("client", "server", 0).unwrap();
        let server = net.tcp_accept(listener, 0).unwrap().unwrap().socket;
        net.tcp_send(client, b"queued", 0).unwrap();
        net.tcp_shutdown(server, ShutdownHow::Read).unwrap();
        assert_eq!(net.tcp_recv(server, 8, 0).unwrap().unwrap(), b"");
        assert_eq!(net.tcp_send(client, b"discarded", 0).unwrap(), 9);
    }

    #[test]
    fn tcp_close_resets_pending_and_gracefully_eofs_established() {
        let mut net = SimNet::new();
        let listener = net.tcp_listen("server", 1).unwrap();
        let client = net.tcp_connect("client", "server", 0).unwrap();
        net.close(listener).unwrap();
        assert_eq!(
            net.tcp_recv(client, 1, 0).unwrap_err().code,
            ErrorCode::ConnectionReset
        );
        assert_eq!(
            net.tcp_send(client, b"x", 0).unwrap_err().code,
            ErrorCode::ConnectionReset
        );

        let listener = net.tcp_listen("server", 1).unwrap();
        let client = net.tcp_connect("client2", "server", 0).unwrap();
        let server = net.tcp_accept(listener, 0).unwrap().unwrap().socket;
        net.tcp_send(client, b"data", 0).unwrap();
        net.close(client).unwrap();
        assert_eq!(net.tcp_recv(server, 8, 0).unwrap().unwrap(), b"data");
        assert_eq!(net.tcp_recv(server, 8, 0).unwrap().unwrap(), b"");
        assert_eq!(
            net.tcp_send(server, b"late", 0).unwrap_err().code,
            ErrorCode::ConnectionReset
        );
    }

    #[test]
    fn tcp_ids_and_udp_ids_share_one_deterministic_counter() {
        let mut net = SimNet::new();
        let udp = net.bind("udp").unwrap();
        let listener = net.tcp_listen("server", 1).unwrap();
        let client = net.tcp_connect("client", "server", 0).unwrap();
        let accepted = net.tcp_accept(listener, 0).unwrap().unwrap().socket;
        assert_eq!(udp, SocketId(1));
        assert_eq!(listener, SocketId(2));
        assert_eq!(client, SocketId(3));
        assert_eq!(accepted, SocketId(4));
    }

    #[test]
    fn tcp_next_delivery_reports_future_segments() {
        let mut net = SimNet::new();
        let listener = net.tcp_listen("server", 1).unwrap();
        let client = net.tcp_connect("client", "server", 0).unwrap();
        let server = net.tcp_accept(listener, 0).unwrap().unwrap().socket;
        net.tcp_send(client, b"later", 100).unwrap();
        assert_eq!(net.next_delivery(server, 0).unwrap(), Some(100));
        assert_eq!(net.tcp_recv(server, 16, 99).unwrap(), None);
        assert_eq!(net.tcp_recv(server, 16, 100).unwrap().unwrap(), b"later");
        assert_eq!(net.next_delivery(server, 100).unwrap(), None);
    }
}
