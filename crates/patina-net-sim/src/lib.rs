//! Deterministic in-memory datagram and stream networking.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use patina_dst_abi::{
    Datagram, EffectError, ErrorCode, SendDisposition, SendReport, ShutdownHow, SocketId,
    TcpAccepted,
};
use patina_dst_driver_api::{DriverResult, NetDriver, NetFaultReport, NetReadiness};
use patina_dst_rng_seeded::SplitMix64;

/// TCP drop-retransmit backoff. A stream is reliable, so a "dropped" segment is
/// never lost — it is retransmitted after a retransmission timeout that doubles
/// per loss, is capped, and gives up after a bounded number of attempts (the
/// segment then delivers anyway). The base is deliberately small relative to
/// the millisecond-scale application timers a stream app uses, so a fault run
/// perturbs the delivery schedule without starving a liveness deadline.
const TCP_RETRANSMIT_BASE_NANOS: u64 = 200_000;
const TCP_RETRANSMIT_CAP_NANOS: u64 = 2_000_000;
const TCP_MAX_RETRANSMITS: u32 = 6;

#[derive(Default)]
pub struct SimNetBuilder {
    base_latency_nanos: u64,
    partitions: BTreeSet<(String, String)>,
    tcp_buffer_bytes: Option<usize>,
    fault_seed: u64,
    jitter_nanos: Option<(u64, u64)>,
    drop_permille: u16,
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

    /// Seed the deterministic datagram reorder/drop decision stream. Draws are a
    /// pure function of this seed and the exact send sequence, so identical
    /// configurations reproduce identical delivery schedules across record and
    /// replay.
    pub fn fault_seed(mut self, seed: u64) -> Self {
        self.fault_seed = seed;
        self
    }

    /// Add a seeded per-datagram delivery jitter drawn uniformly from the
    /// inclusive `[min, max]` nanosecond range. Because a blocking receiver
    /// delivers the earliest-deadline datagram first, varying per-packet jitter
    /// reorders datagrams relative to their send order — the UDP-reorder fault.
    pub fn jitter_nanos(mut self, min: u64, max: u64) -> Self {
        self.jitter_nanos = Some((min, max));
        self
    }

    /// Drop a fraction of datagrams, expressed in per-mille (0..=1000). Each send
    /// draws once against this probability before any jitter draw.
    pub fn drop_permille(mut self, permille: u16) -> Self {
        self.drop_permille = permille;
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
        if let Some((min, max)) = self.jitter_nanos {
            if min > max {
                return Err(EffectError::new(
                    ErrorCode::InvalidInput,
                    "virtual network jitter range requires min <= max",
                ));
            }
        }
        if self.drop_permille > 1000 {
            return Err(EffectError::new(
                ErrorCode::InvalidInput,
                "virtual network drop probability must be within [0, 1000] per-mille",
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
            fault_rng: SplitMix64::new(self.fault_seed),
            jitter_nanos: self.jitter_nanos,
            drop_permille: self.drop_permille,
            fault_send_ops: 0,
            faults_applied: 0,
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
    /// Seeded decision stream for datagram drop and delivery-jitter faults.
    /// Advanced once per datagram `send` in send order, so its consumption is a
    /// deterministic function of the traffic and reproduces on replay.
    fault_rng: SplitMix64,
    jitter_nanos: Option<(u64, u64)>,
    drop_permille: u16,
    /// Fault-eligible send operations observed: datagram `send`s that reached
    /// the fault-decision point (not pre-empted by a partition) plus `tcp_send`s
    /// that enqueued a segment. Backs the vacuity diagnostic.
    fault_send_ops: u64,
    /// Fault-eligible sends that actually had a fault effect applied — a dropped
    /// datagram, or a send whose delivery was pushed later by jitter or a TCP
    /// drop-retransmit backoff.
    faults_applied: u64,
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

    /// Draw the seeded drop decision for one datagram. Extreme probabilities are
    /// decision-free so the never-drop default and always-drop config do not
    /// perturb the stream consumed by jitter draws.
    fn decide_drop(&mut self) -> bool {
        match self.drop_permille {
            0 => false,
            1000 => true,
            permille => (self.fault_rng.next_u64() % 1000) < u64::from(permille),
        }
    }

    /// Draw the seeded per-datagram delivery jitter in nanoseconds, or zero when
    /// no jitter is configured (decision-free so latency-only configs are
    /// unaffected).
    fn draw_jitter(&mut self) -> u64 {
        match self.jitter_nanos {
            None => 0,
            Some((min, max)) if min == max => min,
            Some((min, max)) => {
                let span = max - min + 1;
                min + (self.fault_rng.next_u64() % span)
            }
        }
    }

    /// Seeded fault delivery time for one enqueued TCP segment. TCP is
    /// reliable, so a drop is NOT data loss: it is a retransmit that delays the
    /// segment by an RTO-style backoff (doubling per loss, capped, bounded
    /// attempts), after which it delivers regardless. Per-segment jitter then
    /// adds delivery latency. In-stream ordering is preserved by never letting a
    /// segment's deadline fall before the last already-buffered one (a later
    /// segment can be delayed relative to another connection — reorder across
    /// streams — but never ahead of an earlier byte on its own stream).
    ///
    /// Draws from the same seeded stream as the datagram path, in a fixed order
    /// (drop-retransmit, then jitter), so consumption is a pure function of the
    /// send sequence and reproduces byte-identically across record and replay.
    /// Decision-free configs (drop 0/1000, no jitter, jitter min==max) draw
    /// nothing, so a run with the knobs off never perturbs the stream.
    fn draw_tcp_fault_delivery(&mut self, base_delivery: u64, last_delivery: Option<u64>) -> u64 {
        self.fault_send_ops += 1;
        let mut delivery = base_delivery;
        let mut applied = false;
        let mut backoff = TCP_RETRANSMIT_BASE_NANOS;
        let mut retries = 0u32;
        while retries < TCP_MAX_RETRANSMITS && self.decide_drop() {
            delivery = delivery.saturating_add(backoff);
            backoff = backoff.saturating_mul(2).min(TCP_RETRANSMIT_CAP_NANOS);
            retries += 1;
            applied = true;
        }
        let jitter = self.draw_jitter();
        if jitter > 0 {
            delivery = delivery.saturating_add(jitter);
            applied = true;
        }
        if let Some(last) = last_delivery {
            delivery = delivery.max(last);
        }
        if applied {
            self.faults_applied += 1;
        }
        delivery
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
        // Seeded fault decisions, drawn in a fixed order (drop, then jitter) so
        // the stream is a stable function of the send sequence. A dropped
        // datagram still reports the bytes as written — a lossy UDP send
        // succeeds locally — but queues no packet, so the peer never receives it.
        // Count this as a fault-eligible send (the vacuity diagnostic) — it
        // reached the knob-decision point rather than being pre-empted by a
        // partition. Counting does not consume the fault RNG or alter outcomes.
        self.fault_send_ops += 1;
        if self.decide_drop() {
            self.faults_applied += 1;
            return Ok(SendReport {
                written: bytes.len(),
                copies: 0,
                delivery_nanos: Vec::new(),
                disposition: SendDisposition::DroppedByFault,
            });
        }
        let jitter = self.draw_jitter();
        if jitter > 0 {
            self.faults_applied += 1;
        }
        let delivery_nanos = delivery_nanos
            .checked_add(self.base_latency_nanos)
            .and_then(|value| value.checked_add(jitter))
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
        // Read the peer's buffer state, then release the borrow before drawing
        // faults (which mutably borrows the shared fault RNG).
        let (available, last_delivery) = {
            let peer_endpoint = self
                .tcp_endpoints
                .get(&peer)
                .ok_or_else(|| tcp_reset(socket))?;
            if peer_endpoint.read_closed {
                return Ok(bytes.len());
            }
            (
                self.tcp_buffer_bytes - peer_endpoint.inbox_bytes,
                peer_endpoint.inbox.back().map(|segment| segment.delivery_nanos),
            )
        };
        let accepted = bytes.len().min(available);
        if accepted == 0 {
            return Ok(0);
        }
        // Seeded stream faults: retransmit backoff (never loses data) + jitter,
        // clamped to preserve in-stream ordering. Drawn only for a segment that
        // is actually enqueued, so a would-block send consumes no fault RNG.
        let delivery = self.draw_tcp_fault_delivery(delivery_nanos, last_delivery);
        let peer_endpoint = self
            .tcp_endpoints
            .get_mut(&peer)
            .ok_or_else(|| tcp_reset(socket))?;
        peer_endpoint.inbox.push_back(TcpSegment {
            delivery_nanos: delivery,
            bytes: bytes[..accepted].to_vec(),
        });
        peer_endpoint.inbox_bytes += accepted;
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

    fn readiness(&self, socket: SocketId, now_nanos: u64) -> DriverResult<NetReadiness> {
        // Datagram: readable once a packet addressed here is deliverable at
        // `now_nanos` (the exact condition `recv` returns `Some` on); a virtual
        // datagram send never blocks, so it is always writable and has no EOF.
        if let Some(address) = self.bindings.get(&socket) {
            let readable = self
                .packets
                .iter()
                .any(|packet| packet.to == *address && packet.delivery_nanos <= now_nanos);
            return Ok(NetReadiness {
                readable,
                writable: true,
                read_eof: false,
                write_eof: false,
            });
        }
        if let Some(endpoint) = self.tcp_endpoints.get(&socket) {
            // A reset stream fails both directions on the next op; report both
            // ready-with-EOF so a reactor wakes and the op surfaces the reset.
            if endpoint.reset {
                return Ok(NetReadiness {
                    readable: true,
                    writable: true,
                    read_eof: true,
                    write_eof: true,
                });
            }
            // Mirror `tcp_recv`: `Some(nonempty)` = data, `Some(empty)` = EOF,
            // `None` = would-block. Readable iff a receive would not would-block.
            let has_due_data = endpoint
                .inbox
                .iter()
                .any(|segment| segment.delivery_nanos <= now_nanos);
            let read_eof =
                endpoint.read_closed || (endpoint.remote_write_closed && endpoint.inbox.is_empty());
            let readable = has_due_data || read_eof;
            // Mirror `tcp_send`: `Ok(0)` (would-block) only when the peer's
            // receive buffer is full and the peer is still reading; a shut-for-
            // write, gone, or non-reading peer fails closed rather than blocks,
            // which a reactor reports as writable-with-EOF.
            let write_eof = endpoint.write_closed
                || endpoint
                    .peer
                    .and_then(|peer| self.tcp_endpoints.get(&peer))
                    .is_none_or(|peer| peer.read_closed);
            let peer_has_space = endpoint
                .peer
                .and_then(|peer| self.tcp_endpoints.get(&peer))
                .is_none_or(|peer| peer.read_closed || peer.inbox_bytes < self.tcp_buffer_bytes);
            let writable = write_eof || peer_has_space;
            return Ok(NetReadiness {
                readable,
                writable,
                read_eof,
                write_eof,
            });
        }
        if let Some(listener) = self.tcp_listeners.get(&socket) {
            // A listener is "readable" once a connection is pending: `accept`
            // would return `Some`. A listener is never writable.
            return Ok(NetReadiness {
                readable: !listener.pending.is_empty(),
                writable: false,
                read_eof: false,
                write_eof: false,
            });
        }
        Err(invalid_socket(socket))
    }

    fn fault_report(&self) -> Option<NetFaultReport> {
        let could_apply = self.drop_permille > 0
            || self
                .jitter_nanos
                .is_some_and(|(_, max)| max > 0);
        Some(NetFaultReport {
            could_apply,
            send_ops: self.fault_send_ops,
            faults_applied: self.faults_applied,
        })
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

    /// Send `count` numbered datagrams at send-time zero and drain them in
    /// delivery order, returning the sequence numbers actually received.
    fn delivered_order(net: &mut SimNet, count: u32) -> Vec<u32> {
        net.bind("tx").unwrap();
        net.bind("rx").unwrap();
        let tx = net.addresses["tx"];
        for seq in 0..count {
            net.send(tx, "rx", &seq.to_le_bytes(), 0).unwrap();
        }
        let rx = net.addresses["rx"];
        let mut received = Vec::new();
        while let Some(datagram) = net.recv(rx, u64::MAX).unwrap() {
            received.push(u32::from_le_bytes(datagram.bytes.try_into().unwrap()));
        }
        received
    }

    #[test]
    fn jitter_reorders_datagrams_deterministically_per_seed() {
        // A seed that reorders: the received order differs from the send order,
        // and is byte-identical across two runs of the same configuration.
        let mut first = SimNet::builder()
            .fault_seed(7)
            .jitter_nanos(0, 1000)
            .build()
            .unwrap();
        let mut second = SimNet::builder()
            .fault_seed(7)
            .jitter_nanos(0, 1000)
            .build()
            .unwrap();
        let order_a = delivered_order(&mut first, 8);
        let order_b = delivered_order(&mut second, 8);
        assert_eq!(order_a, order_b, "same seed must reproduce delivery order");
        assert_eq!(order_a.len(), 8, "no jitter run should drop datagrams");
        let in_order: Vec<u32> = (0..8).collect();
        // At least one seed in a small sweep must actually reorder, proving the
        // knob is not vacuous.
        let any_reordered = (0..16u64).any(|seed| {
            let mut net = SimNet::builder()
                .fault_seed(seed)
                .jitter_nanos(0, 1000)
                .build()
                .unwrap();
            delivered_order(&mut net, 8) != in_order
        });
        assert!(any_reordered, "jitter never reordered across seeds");
    }

    #[test]
    fn zero_jitter_preserves_send_order() {
        let mut net = SimNet::builder().jitter_nanos(0, 0).build().unwrap();
        assert_eq!(delivered_order(&mut net, 8), (0..8).collect::<Vec<_>>());
    }

    #[test]
    fn drop_permille_loses_datagrams_deterministically_and_extremes_are_total() {
        // Certain drop loses everything; zero drop keeps everything.
        let mut all = SimNet::builder().drop_permille(1000).build().unwrap();
        assert!(delivered_order(&mut all, 8).is_empty());
        let mut none = SimNet::builder().drop_permille(0).build().unwrap();
        assert_eq!(delivered_order(&mut none, 8), (0..8).collect::<Vec<_>>());

        // A partial probability drops some but not all, reproducibly per seed.
        let received_a = {
            let mut net = SimNet::builder()
                .fault_seed(3)
                .drop_permille(500)
                .build()
                .unwrap();
            delivered_order(&mut net, 32)
        };
        let received_b = {
            let mut net = SimNet::builder()
                .fault_seed(3)
                .drop_permille(500)
                .build()
                .unwrap();
            delivered_order(&mut net, 32)
        };
        assert_eq!(received_a, received_b, "drops must reproduce per seed");
        assert!(
            received_a.len() < 32 && !received_a.is_empty(),
            "half-probability drop should lose some but not all of 32 datagrams, got {}",
            received_a.len()
        );
    }

    #[test]
    fn dropped_send_reports_bytes_written_but_queues_nothing() {
        let mut net = SimNet::builder().drop_permille(1000).build().unwrap();
        let tx = net.bind("tx").unwrap();
        net.bind("rx").unwrap();
        let report = net.send(tx, "rx", b"payload", 0).unwrap();
        assert_eq!(report.written, 7);
        assert_eq!(report.copies, 0);
        assert_eq!(report.disposition, SendDisposition::DroppedByFault);
        assert_eq!(net.queued_packets(), 0);
    }

    #[test]
    fn fault_builder_rejects_invalid_configuration() {
        let jitter_error = SimNet::builder()
            .jitter_nanos(100, 10)
            .build()
            .err()
            .expect("inverted jitter range must be rejected");
        assert_eq!(jitter_error.code, ErrorCode::InvalidInput);
        let drop_error = SimNet::builder()
            .drop_permille(1001)
            .build()
            .err()
            .expect("out-of-range drop probability must be rejected");
        assert_eq!(drop_error.code, ErrorCode::InvalidInput);
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

    // --- TCP stream fault injection (jitter + drop-retransmit) ---

    /// Open one client->server stream, send each payload as its own segment
    /// (retrying through backpressure without advancing time), then drain the
    /// server at `t=u64::MAX` (all deadlines due). Returns the concatenated
    /// delivered bytes — the byte content and order the receiver observes.
    fn tcp_stream_delivered(net: &mut SimNet, payloads: &[&[u8]]) -> Vec<u8> {
        let listener = net.tcp_listen("server", payloads.len().max(1)).unwrap();
        let client = net.tcp_connect("client", "server", 0).unwrap();
        let server = net.tcp_accept(listener, 0).unwrap().unwrap().socket;
        for payload in payloads {
            let mut offset = 0;
            while offset < payload.len() {
                offset += net.tcp_send(client, &payload[offset..], 0).unwrap();
            }
        }
        let mut out = Vec::new();
        while let Some(chunk) = net.tcp_recv(server, 4096, u64::MAX).unwrap() {
            if chunk.is_empty() {
                break;
            }
            out.extend_from_slice(&chunk);
        }
        out
    }

    #[test]
    fn tcp_jitter_delays_delivery_preserves_order_and_reproduces_per_seed() {
        // A nonzero jitter floor pushes every segment past t=0.
        let mut net = SimNet::builder()
            .fault_seed(9)
            .jitter_nanos(1_000, 5_000)
            .build()
            .unwrap();
        let listener = net.tcp_listen("server", 8).unwrap();
        let client = net.tcp_connect("client", "server", 0).unwrap();
        let server = net.tcp_accept(listener, 0).unwrap().unwrap().socket;
        assert_eq!(net.tcp_send(client, b"aa", 0).unwrap(), 2);
        assert_eq!(
            net.tcp_recv(server, 16, 0).unwrap(),
            None,
            "jitter must delay TCP delivery past the send instant"
        );
        assert_eq!(net.tcp_recv(server, 16, u64::MAX).unwrap().unwrap(), b"aa");

        // Same seed reproduces byte-for-byte; order preserved; nothing lost.
        let payloads: [&[u8]; 4] = [b"aa", b"bb", b"cc", b"dd"];
        let mut first = SimNet::builder()
            .fault_seed(9)
            .jitter_nanos(1_000, 5_000)
            .build()
            .unwrap();
        let mut second = SimNet::builder()
            .fault_seed(9)
            .jitter_nanos(1_000, 5_000)
            .build()
            .unwrap();
        let delivered = tcp_stream_delivered(&mut first, &payloads);
        assert_eq!(
            delivered,
            tcp_stream_delivered(&mut second, &payloads),
            "same seed must reproduce the delivered byte stream"
        );
        assert_eq!(
            delivered, b"aabbccdd",
            "TCP is reliable and in-order: jitter reorders across streams, never within one"
        );
        let report = first.fault_report().unwrap();
        assert!(report.could_apply);
        assert!(report.send_ops >= 4);
        assert!(report.faults_applied > 0, "jitter must register as applied");
        assert!(!report.is_vacuous());
    }

    #[test]
    fn tcp_drop_retransmits_and_never_loses_data() {
        // Certain drop: every segment exhausts the retransmit budget, so
        // delivery is delayed, but a reliable stream still delivers every byte.
        let mut net = SimNet::builder()
            .fault_seed(1)
            .drop_permille(1000)
            .build()
            .unwrap();
        let listener = net.tcp_listen("server", 1).unwrap();
        let client = net.tcp_connect("client", "server", 0).unwrap();
        let server = net.tcp_accept(listener, 0).unwrap().unwrap().socket;
        assert_eq!(net.tcp_send(client, b"reliable", 0).unwrap(), 8);
        assert_eq!(
            net.tcp_recv(server, 16, 0).unwrap(),
            None,
            "a dropped segment is retransmitted (delayed), not readable immediately"
        );
        assert_eq!(
            net.tcp_recv(server, 16, u64::MAX).unwrap().unwrap(),
            b"reliable",
            "TCP drop must never lose data"
        );
        let report = net.fault_report().unwrap();
        assert!(report.could_apply);
        assert_eq!(report.faults_applied, 1);
    }

    #[test]
    fn tcp_jitter_delivery_time_varies_across_seeds() {
        fn first_delivery(seed: u64) -> u64 {
            let mut net = SimNet::builder()
                .fault_seed(seed)
                .jitter_nanos(1, 1_000_000)
                .build()
                .unwrap();
            let listener = net.tcp_listen("server", 1).unwrap();
            let client = net.tcp_connect("client", "server", 0).unwrap();
            let server = net.tcp_accept(listener, 0).unwrap().unwrap().socket;
            net.tcp_send(client, b"x", 0).unwrap();
            net.next_delivery(server, 0)
                .unwrap()
                .expect("a delayed segment has a future delivery time")
        }
        // Different seeds draw different jitter, so the delivery schedule differs
        // — the fault is not a constant.
        let distinct = (0..8u64).map(first_delivery).collect::<BTreeSet<_>>();
        assert!(
            distinct.len() > 1,
            "jitter delivery time must vary across seeds, got {distinct:?}"
        );
    }

    #[test]
    fn tcp_without_fault_knobs_perturbs_nothing() {
        // The knobs-off default draws no fault RNG and delivers immediately, so
        // every pre-fault TCP test stays byte-identical.
        let mut net = SimNet::new();
        let listener = net.tcp_listen("server", 1).unwrap();
        let client = net.tcp_connect("client", "server", 0).unwrap();
        let server = net.tcp_accept(listener, 0).unwrap().unwrap().socket;
        net.tcp_send(client, b"hi", 0).unwrap();
        assert_eq!(
            net.tcp_recv(server, 16, 0).unwrap().unwrap(),
            b"hi",
            "no delay without fault knobs"
        );
        let report = net.fault_report().unwrap();
        assert!(!report.could_apply);
        assert_eq!(report.faults_applied, 0);
        assert_eq!(report.send_ops, 1);
        assert!(!report.is_vacuous());
    }

    #[test]
    fn fault_report_is_vacuous_exactly_on_the_silent_inertness_signature() {
        use patina_dst_driver_api::NetFaultReport;
        // The signature the pre-fix inert TCP path produced: knobs armed to
        // perturb, traffic occurred, yet zero effects — the bug this diagnostic
        // exists to catch.
        assert!(NetFaultReport {
            could_apply: true,
            send_ops: 5,
            faults_applied: 0,
        }
        .is_vacuous());
        // Faults actually landed.
        assert!(!NetFaultReport {
            could_apply: true,
            send_ops: 5,
            faults_applied: 3,
        }
        .is_vacuous());
        // Knobs incapable of any effect — silence is correct.
        assert!(!NetFaultReport {
            could_apply: false,
            send_ops: 5,
            faults_applied: 0,
        }
        .is_vacuous());
        // No fault-eligible traffic — nothing to perturb.
        assert!(!NetFaultReport {
            could_apply: true,
            send_ops: 0,
            faults_applied: 0,
        }
        .is_vacuous());
    }
}
