//! Deterministic in-memory datagram and stream networking.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use patina_dst_abi::{
    Datagram, EffectError, ErrorCode, SendDisposition, SendReport, ShutdownHow, SocketId,
    TcpAccepted,
};
use patina_dst_driver_api::{
    DriverResult, NetDriver, NetFaultReport, NetReadiness, range_vacuity_is_diagnosable,
    vacuity_is_diagnosable, wildcard_bind_key,
};
use patina_dst_rng_seeded::{SplitMix64, domain_seed, fault_domain};

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
    duplicate_permille: u16,
    connect_refuse_permille: u16,
    reset_permille: u16,
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

    /// Deliver a fraction of datagrams TWICE, expressed in per-mille (0..=1000).
    /// The duplicate is an independent copy with its own jitter draw, so the two
    /// arrivals can be separated in time and interleave with other traffic — the
    /// at-least-once delivery hazard an idempotence bug hides behind.
    pub fn duplicate_permille(mut self, permille: u16) -> Self {
        self.duplicate_permille = permille;
        self
    }

    /// Refuse a fraction of otherwise-establishable TCP connections, expressed in
    /// per-mille (0..=1000). Only connects that would have succeeded draw: a
    /// connect with no listener or a full backlog is refused by semantics.
    pub fn connect_refuse_permille(mut self, permille: u16) -> Self {
        self.connect_refuse_permille = permille;
        self
    }

    /// Reset a fraction of established TCP streams, expressed in per-mille
    /// (0..=1000). Each fault-eligible stream operation draws; on a fire the
    /// stream is torn down in BOTH directions and the operation fails with
    /// `ConnectionReset`, exactly as a peer RST does.
    pub fn reset_permille(mut self, permille: u16) -> Self {
        self.reset_permille = permille;
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
        for (name, permille) in [
            ("drop", self.drop_permille),
            ("duplicate", self.duplicate_permille),
            ("connect-refusal", self.connect_refuse_permille),
            ("reset", self.reset_permille),
        ] {
            if permille > 1000 {
                return Err(EffectError::new(
                    ErrorCode::InvalidInput,
                    format!(
                        "virtual network {name} probability must be within [0, 1000] per-mille"
                    ),
                ));
            }
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
            // Each class added after the original drop/jitter pair draws from its
            // own domain-separated substream of the same net-fault seed, so
            // enabling one class cannot shift the decisions another class makes —
            // the §1.2 derivation rule applied within the driver.
            duplicate_rng: SplitMix64::new(domain_seed(
                self.fault_seed,
                fault_domain::NET_DUPLICATE,
            )),
            connect_refuse_rng: SplitMix64::new(domain_seed(
                self.fault_seed,
                fault_domain::NET_CONNECT_REFUSE,
            )),
            reset_rng: SplitMix64::new(domain_seed(self.fault_seed, fault_domain::NET_RESET)),
            jitter_nanos: self.jitter_nanos,
            drop_permille: self.drop_permille,
            duplicate_permille: self.duplicate_permille,
            connect_refuse_permille: self.connect_refuse_permille,
            reset_permille: self.reset_permille,
            counts: FaultCounts::default(),
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
    /// Per-class decision streams, each domain-separated from the drop/jitter
    /// stream and from each other.
    duplicate_rng: SplitMix64,
    connect_refuse_rng: SplitMix64,
    reset_rng: SplitMix64,
    jitter_nanos: Option<(u64, u64)>,
    drop_permille: u16,
    duplicate_permille: u16,
    connect_refuse_permille: u16,
    reset_permille: u16,
    /// Per-class opportunity and application counters backing the vacuity
    /// diagnostic.
    counts: FaultCounts,
}

/// What the network fault plane observed this run, per class. Kept beside the
/// knobs rather than inside [`NetFaultReport`] because the report also carries
/// the derived `*_vacuity_diagnosable` verdicts, which are a pure function of
/// these counts and the configured rates.
#[derive(Clone, Copy, Debug, Default)]
struct FaultCounts {
    /// Datagram sends that reached the fault-decision point (not pre-empted by a
    /// partition) plus `tcp_send`s that enqueued a segment.
    send_ops: u64,
    drops_applied: u64,
    jitter_applied: u64,
    latency_applied: u64,
    duplicates_applied: u64,
    /// `tcp_connect` calls that would otherwise have succeeded.
    connect_ops: u64,
    connects_refused: u64,
    /// Established-stream operations that moved data.
    stream_ops: u64,
    resets_injected: u64,
    /// Sends and connects blocked by a configured partition.
    partition_blocks: u64,
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

    /// The datagram socket that receives traffic dialed at `to`: the exact
    /// binding if one exists, else a wildcard (`0.0.0.0:PORT`) binding under the
    /// shared routing rule. Returns the resolved socket AND the address it is
    /// actually bound under, because a queued packet is keyed by the RECEIVER's
    /// bound address — that keeps `recv`, `next_delivery`, `readiness` and
    /// `close` matching on one string apiece instead of each re-deriving the
    /// rule.
    fn resolve_datagram(&self, to: &str) -> Option<(SocketId, String)> {
        if let Some(socket) = self.addresses.get(to) {
            return Some((*socket, to.to_owned()));
        }
        let wildcard = wildcard_bind_key(to)?;
        let socket = self.addresses.get(&wildcard)?;
        Some((*socket, wildcard))
    }

    /// The TCP listener that accepts a connection dialed at `to`, exact match
    /// first and then the wildcard rule, mirroring [`SimNet::resolve_datagram`].
    fn resolve_listener(&self, to: &str) -> Option<SocketId> {
        if let Some(listener) = self.tcp_listener_addresses.get(to) {
            return Some(*listener);
        }
        let wildcard = wildcard_bind_key(to)?;
        self.tcp_listener_addresses.get(&wildcard).copied()
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

    /// Draw one seeded per-mille decision from a class's own stream. Extreme
    /// probabilities are decision-free, so a never-fire default and an
    /// always-fire configuration both leave the stream untouched.
    fn permille_fires(rng: &mut SplitMix64, permille: u16) -> bool {
        match permille {
            0 => false,
            1000 => true,
            value => (rng.next_u64() % 1000) < u64::from(value),
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
        self.counts.send_ops += 1;
        // The base link latency is applied by the caller (it is part of
        // `base_delivery`); count it here so a send path that skipped it reports
        // zero applications against a live knob rather than looking clean.
        if self.base_latency_nanos > 0 {
            self.counts.latency_applied += 1;
        }
        let mut delivery = base_delivery;
        let mut backoff = TCP_RETRANSMIT_BASE_NANOS;
        let mut retries = 0u32;
        while retries < TCP_MAX_RETRANSMITS && self.decide_drop() {
            delivery = delivery.saturating_add(backoff);
            backoff = backoff.saturating_mul(2).min(TCP_RETRANSMIT_CAP_NANOS);
            retries += 1;
        }
        if retries > 0 {
            self.counts.drops_applied += 1;
        }
        let jitter = self.draw_jitter();
        if jitter > 0 {
            delivery = delivery.saturating_add(jitter);
            self.counts.jitter_applied += 1;
        }
        if let Some(last) = last_delivery {
            delivery = delivery.max(last);
        }
        delivery
    }

    /// Whether an established-stream operation draws a reset this time, counting
    /// the opportunity either way. On a fire BOTH endpoints are torn down — a
    /// reset is not one-sided — and the caller surfaces `ConnectionReset`.
    fn decide_reset(&mut self, socket: SocketId) -> bool {
        self.counts.stream_ops += 1;
        if !Self::permille_fires(&mut self.reset_rng, self.reset_permille) {
            return false;
        }
        self.counts.resets_injected += 1;
        let peer = self
            .tcp_endpoints
            .get(&socket)
            .and_then(|endpoint| endpoint.peer);
        for endpoint in [Some(socket), peer].into_iter().flatten() {
            if let Some(endpoint) = self.tcp_endpoints.get_mut(&endpoint) {
                endpoint.reset = true;
            }
        }
        true
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
        if self.resolve_datagram(to).is_none() {
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
        // Route once, here, and queue the packet under the address the receiver
        // is actually BOUND to. A wildcard listener's queue is keyed `0.0.0.0:P`
        // whichever IP the sender dialed, so every downstream filter (recv,
        // next_delivery, readiness, close) keeps comparing one string and cannot
        // drift from the routing rule. The guest never observes this: a datagram
        // surfaces its `from`, not the address it was dialed at.
        let (_, destination) = self
            .resolve_datagram(to)
            .expect("validate_send resolved a destination");
        if self.partitions.contains(&(from.clone(), to.into())) {
            self.counts.partition_blocks += 1;
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
        self.counts.send_ops += 1;
        if self.decide_drop() {
            self.counts.drops_applied += 1;
            return Ok(SendReport {
                written: bytes.len(),
                copies: 0,
                delivery_nanos: Vec::new(),
                disposition: SendDisposition::DroppedByFault,
            });
        }
        // A duplicate is an independent copy: it draws its OWN jitter, so the two
        // arrivals can be separated in time and interleave with other traffic
        // rather than being an indistinguishable twin of the original.
        let copies = if Self::permille_fires(&mut self.duplicate_rng, self.duplicate_permille) {
            self.counts.duplicates_applied += 1;
            2
        } else {
            1
        };
        let mut delivery_times = Vec::with_capacity(copies);
        for _ in 0..copies {
            let jitter = self.draw_jitter();
            if jitter > 0 {
                self.counts.jitter_applied += 1;
            }
            if self.base_latency_nanos > 0 {
                self.counts.latency_applied += 1;
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
                from: from.clone(),
                to: destination.clone(),
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
            delivery_times.push(delivery_nanos);
        }
        Ok(SendReport {
            written: bytes.len(),
            copies,
            delivery_nanos: delivery_times,
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
        debug_assert!(
            endpoint.local == state.address
                || wildcard_bind_key(&endpoint.local).as_deref() == Some(state.address.as_str()),
            "accepted stream local {} matches neither the listener address {} nor its wildcard",
            endpoint.local,
            state.address
        );
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
            self.counts.partition_blocks += 1;
            return Err(EffectError::new(
                ErrorCode::ConnectionRefused,
                format!("virtual connection refused: {address} -> {to} is partitioned"),
            ));
        }
        let listener_id = self.resolve_listener(to).ok_or_else(|| {
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
        // Only a connect that would OTHERWISE HAVE SUCCEEDED is a fault
        // opportunity. A connect with no listener or a full backlog is refused by
        // semantics: counting it would inflate the denominator, and "injecting" a
        // refusal onto an already-refused connect would report an effect the
        // guest could not distinguish from the semantics.
        self.counts.connect_ops += 1;
        if Self::permille_fires(&mut self.connect_refuse_rng, self.connect_refuse_permille) {
            self.counts.connects_refused += 1;
            return Err(EffectError::new(
                ErrorCode::ConnectionRefused,
                format!("injected virtual connection refusal: {address} -> {to}"),
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
        let base_delivery = delivery_nanos
            .checked_add(self.base_latency_nanos)
            .ok_or_else(|| {
                EffectError::new(
                    ErrorCode::InvalidInput,
                    "virtual TCP segment deadline overflowed",
                )
            })?;
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
                peer_endpoint
                    .inbox
                    .back()
                    .map(|segment| segment.delivery_nanos),
            )
        };
        let accepted = bytes.len().min(available);
        if accepted == 0 {
            return Ok(0);
        }
        // Reset is decided for a send that actually moves bytes, so a caller
        // spinning on a full buffer (which returns would-block above) does not
        // make a reset more likely the harder it polls.
        if self.decide_reset(socket) {
            return Err(tcp_reset(socket));
        }
        // Seeded stream faults: retransmit backoff (never loses data) + jitter,
        // clamped to preserve in-stream ordering. Drawn only for a segment that
        // is actually enqueued, so a would-block send consumes no fault RNG.
        let delivery = self.draw_tcp_fault_delivery(base_delivery, last_delivery);
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
            // A receive that moved data is the other half of the stream's
            // fault-eligible surface, so a receive-only endpoint can still be
            // reset. The taken bytes are discarded with the stream, exactly as a
            // peer RST discards data already in flight.
            if self.decide_reset(socket) {
                return Err(tcp_reset(socket));
            }
            return Ok(Some(taken));
        }
        let endpoint = self
            .tcp_endpoints
            .get(&socket)
            .expect("endpoint was resolved above");
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

    /// Report whenever a network knob was live, so the run is self-describing
    /// about what the fault plane did. A knob-free network models nothing and
    /// reports `None`, exactly like a filesystem with no fault wrapper: it can
    /// never be diagnosed as vacuous because it was never asked to perturb.
    fn fault_report(&self) -> Option<NetFaultReport> {
        let counts = self.counts;
        let modeled = self.drop_permille > 0
            || self.jitter_nanos.is_some_and(|(_, max)| max > 0)
            || self.base_latency_nanos > 0
            || self.duplicate_permille > 0
            || self.connect_refuse_permille > 0
            || self.reset_permille > 0
            || !self.partitions.is_empty();
        if !modeled {
            return None;
        }
        let partition_opportunities = counts
            .send_ops
            .saturating_add(counts.connect_ops)
            .saturating_add(counts.partition_blocks);
        Some(NetFaultReport {
            send_ops: counts.send_ops,
            drop_vacuity_diagnosable: vacuity_is_diagnosable(counts.send_ops, self.drop_permille),
            drops_applied: counts.drops_applied,
            jitter_vacuity_diagnosable: self
                .jitter_nanos
                .is_some_and(|range| range_vacuity_is_diagnosable(counts.send_ops, range)),
            jitter_applied: counts.jitter_applied,
            // The base latency applies to every send at rate 1.0, so five sends
            // are enough to call zero applications anomalous.
            latency_vacuity_diagnosable: self.base_latency_nanos > 0
                && vacuity_is_diagnosable(counts.send_ops, 1000),
            latency_applied: counts.latency_applied,
            duplicate_vacuity_diagnosable: vacuity_is_diagnosable(
                counts.send_ops,
                self.duplicate_permille,
            ),
            duplicates_applied: counts.duplicates_applied,
            connect_ops: counts.connect_ops,
            connect_refuse_vacuity_diagnosable: vacuity_is_diagnosable(
                counts.connect_ops,
                self.connect_refuse_permille,
            ),
            connects_refused: counts.connects_refused,
            stream_ops: counts.stream_ops,
            reset_vacuity_diagnosable: vacuity_is_diagnosable(
                counts.stream_ops,
                self.reset_permille,
            ),
            resets_injected: counts.resets_injected,
            // A partition blocks at rate 1.0 the traffic it names, so a run with
            // enough traffic and zero blocks means the partition named addresses
            // this run never used — the operator-error signature.
            partition_vacuity_diagnosable: !self.partitions.is_empty()
                && vacuity_is_diagnosable(partition_opportunities, 1000),
            partition_blocks: counts.partition_blocks,
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
    fn a_wildcard_bind_receives_traffic_dialed_at_any_address_on_its_port() {
        // The producer-side enabler: ordinary server code binds INADDR_ANY as it
        // would in production, and a client that resolved a name to some virtual
        // IP reaches it by dialing that IP.
        let mut net = SimNet::new();
        let server = net.bind("0.0.0.0:80").unwrap();
        let client = net.bind("10.0.0.9:5000").unwrap();
        net.send(client, "10.0.0.5:80", b"hello", 0).unwrap();
        let datagram = net.recv(server, 0).unwrap().expect("wildcard delivery");
        assert_eq!(datagram.bytes, b"hello");
        assert_eq!(datagram.from, "10.0.0.9:5000");

        // TCP takes the same route.
        let listener = net.tcp_listen("0.0.0.0:81", 4).unwrap();
        let stream = net.tcp_connect("10.0.0.9:5001", "10.0.0.5:81", 0).unwrap();
        let accepted = net
            .tcp_accept(listener, 0)
            .unwrap()
            .expect("wildcard TCP accept");
        assert_eq!(accepted.peer, "10.0.0.9:5001");
        net.tcp_send(stream, b"ping", 0).unwrap();
        assert_eq!(
            net.tcp_recv(accepted.socket, 8, 0).unwrap().unwrap(),
            b"ping"
        );
    }

    #[test]
    fn an_exact_binding_always_wins_over_a_wildcard_one() {
        let mut net = SimNet::new();
        let wildcard = net.bind("0.0.0.0:80").unwrap();
        let exact = net.bind("10.0.0.5:80").unwrap();
        let client = net.bind("10.0.0.9:5000").unwrap();
        net.send(client, "10.0.0.5:80", b"exact", 0).unwrap();
        assert!(
            net.recv(wildcard, 0).unwrap().is_none(),
            "the wildcard socket must not steal an exactly-bound address"
        );
        assert_eq!(net.recv(exact, 0).unwrap().unwrap().bytes, b"exact");
    }

    #[test]
    fn the_wildcard_rule_never_invents_a_route() {
        // A port with no wildcard listener stays unroutable, and a non-`ip:port`
        // address (the explicit API binds bare labels) is exact-match only.
        let mut net = SimNet::new();
        net.bind("0.0.0.0:80").unwrap();
        let client = net.bind("10.0.0.9:5000").unwrap();
        net.send(client, "10.0.0.5:81", b"nope", 0)
            .expect_err("no wildcard listener on port 81");
        net.bind("server").unwrap();
        net.send(client, "other-label", b"nope", 0)
            .expect_err("a bare label has no wildcard form");
        assert_eq!(
            net.tcp_connect("10.0.0.9:5001", "10.0.0.5:80", 0)
                .unwrap_err()
                .code,
            ErrorCode::ConnectionRefused,
            "a datagram wildcard bind is not a TCP listener"
        );
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
    fn tcp_base_latency_delays_delivery_without_fault_knobs() {
        let mut net = SimNet::builder().base_latency_nanos(50).build().unwrap();
        let listener = net.tcp_listen("server", 1).unwrap();
        let client = net.tcp_connect("client", "server", 0).unwrap();
        let server = net.tcp_accept(listener, 0).unwrap().unwrap().socket;
        assert_eq!(net.tcp_send(client, b"latency", 0).unwrap(), 7);
        assert_eq!(net.tcp_recv(server, 16, 49).unwrap(), None);
        assert_eq!(net.next_delivery(server, 0).unwrap(), Some(50));
        assert_eq!(net.tcp_recv(server, 16, 50).unwrap().unwrap(), b"latency");
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
        assert!(report.send_ops >= 4);
        assert!(report.jitter_applied > 0, "jitter must register as applied");
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
        assert_eq!(report.drops_applied, 1);
        assert_eq!(report.jitter_applied, 0, "no jitter knob was configured");
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
        assert!(
            net.fault_report().is_none(),
            "a network with no knob live models no faults and must not be diagnosable"
        );
    }

    #[test]
    fn fault_report_is_vacuous_exactly_on_the_silent_inertness_signature() {
        use patina_dst_driver_api::NetFaultReport;
        // The signature the pre-fix inert TCP path produced: a knob armed to
        // perturb, traffic occurred, yet zero effects — the bug this diagnostic
        // exists to catch.
        assert!(
            NetFaultReport {
                send_ops: 5,
                drop_vacuity_diagnosable: true,
                drops_applied: 0,
                ..NetFaultReport::default()
            }
            .is_vacuous()
        );
        // Faults actually landed.
        assert!(
            !NetFaultReport {
                send_ops: 5,
                drop_vacuity_diagnosable: true,
                drops_applied: 3,
                ..NetFaultReport::default()
            }
            .is_vacuous()
        );
        // A knob whose rate over the traffic it saw never expected a fire —
        // silence is ordinary sampling, not inertness.
        assert!(
            !NetFaultReport {
                send_ops: 5,
                ..NetFaultReport::default()
            }
            .is_vacuous()
        );
        // No fault-eligible traffic — nothing to perturb.
        assert!(!NetFaultReport::default().is_vacuous());
        assert!(!NetFaultReport::default().had_opportunities());

        // The reason the report is PER CLASS. Before Wave E one merged
        // `faults_applied` counter answered for every knob, so this shape —
        // drops landing while an equally-live jitter knob applied nothing —
        // read as "faults applied" and the inert class stayed invisible.
        let merged_would_have_hidden_it = NetFaultReport {
            send_ops: 100,
            drop_vacuity_diagnosable: true,
            drops_applied: 30,
            jitter_vacuity_diagnosable: true,
            jitter_applied: 0,
            ..NetFaultReport::default()
        };
        assert!(merged_would_have_hidden_it.is_vacuous());
        // Each remaining class fires the verdict on its own.
        for report in [
            NetFaultReport {
                latency_vacuity_diagnosable: true,
                send_ops: 10,
                ..NetFaultReport::default()
            },
            NetFaultReport {
                duplicate_vacuity_diagnosable: true,
                send_ops: 10,
                ..NetFaultReport::default()
            },
            NetFaultReport {
                connect_refuse_vacuity_diagnosable: true,
                connect_ops: 10,
                ..NetFaultReport::default()
            },
            NetFaultReport {
                reset_vacuity_diagnosable: true,
                stream_ops: 10,
                ..NetFaultReport::default()
            },
            NetFaultReport {
                partition_vacuity_diagnosable: true,
                send_ops: 10,
                ..NetFaultReport::default()
            },
        ] {
            assert!(report.is_vacuous(), "{report:?} must be vacuous");
            assert!(report.had_opportunities());
        }
    }

    // --- Wave E: connection-level and duplication faults ---

    #[test]
    fn duplicated_datagrams_arrive_twice_with_independent_delivery_times() {
        let mut net = SimNet::builder()
            .fault_seed(5)
            .duplicate_permille(1000)
            .jitter_nanos(1, 1_000)
            .build()
            .unwrap();
        let tx = net.bind("tx").unwrap();
        let rx = net.bind("rx").unwrap();
        let report = net.send(tx, "rx", b"once?", 0).unwrap();
        assert_eq!(report.copies, 2);
        assert_eq!(report.delivery_nanos.len(), 2);
        assert_ne!(
            report.delivery_nanos[0], report.delivery_nanos[1],
            "each copy draws its own jitter, so the twins separate in time"
        );
        assert_eq!(net.recv(rx, u64::MAX).unwrap().unwrap().bytes, b"once?");
        assert_eq!(
            net.recv(rx, u64::MAX).unwrap().unwrap().bytes,
            b"once?",
            "the duplicate must be observable at the receiver"
        );
        let fault_report = net.fault_report().unwrap();
        assert_eq!(fault_report.duplicates_applied, 1);
        assert!(!fault_report.is_vacuous());
    }

    #[test]
    fn duplication_is_seed_deterministic_and_varies_across_seeds() {
        fn duplicated(seed: u64) -> Vec<usize> {
            let mut net = SimNet::builder()
                .fault_seed(seed)
                .duplicate_permille(500)
                .build()
                .unwrap();
            let tx = net.bind("tx").unwrap();
            net.bind("rx").unwrap();
            (0..32)
                .map(|index| net.send(tx, "rx", &[index as u8], 0).unwrap().copies)
                .collect()
        }
        for seed in 0..16 {
            assert_eq!(duplicated(seed), duplicated(seed), "seed {seed}");
        }
        let distinct = (0..16u64).map(duplicated).collect::<BTreeSet<_>>();
        assert!(distinct.len() > 1, "duplication must vary across seeds");
        let one_run = duplicated(3);
        assert!(one_run.contains(&2) && one_run.contains(&1));
    }

    #[test]
    fn connect_refusal_fires_only_on_connects_that_would_have_succeeded() {
        let mut net = SimNet::builder()
            .fault_seed(2)
            .connect_refuse_permille(1000)
            .build()
            .unwrap();
        // No listener: refused by semantics, and NOT counted as a fault
        // opportunity — the injector cannot claim credit for it.
        assert_eq!(
            net.tcp_connect("client", "absent", 0).unwrap_err().code,
            ErrorCode::ConnectionRefused
        );
        assert_eq!(net.fault_report().unwrap().connect_ops, 0);

        net.tcp_listen("server", 4).unwrap();
        let error = net.tcp_connect("client", "server", 0).unwrap_err();
        assert_eq!(error.code, ErrorCode::ConnectionRefused);
        assert!(error.message.contains("injected"), "{error:?}");
        let report = net.fault_report().unwrap();
        assert_eq!(report.connect_ops, 1);
        assert_eq!(report.connects_refused, 1);
        assert!(!report.is_vacuous());
    }

    #[test]
    fn connect_refusal_is_seed_deterministic_and_leaves_the_listener_usable() {
        fn refusals(seed: u64) -> Vec<bool> {
            let mut net = SimNet::builder()
                .fault_seed(seed)
                .connect_refuse_permille(500)
                .build()
                .unwrap();
            net.tcp_listen("server", 64).unwrap();
            (0..32)
                .map(|index| {
                    net.tcp_connect(&format!("client-{index}"), "server", 0)
                        .is_err()
                })
                .collect()
        }
        for seed in 0..16 {
            assert_eq!(refusals(seed), refusals(seed), "seed {seed}");
        }
        let one_run = refusals(1);
        assert!(
            one_run.contains(&true) && one_run.contains(&false),
            "a half-rate refusal must both refuse and admit: {one_run:?}"
        );
        assert!((0..16u64).map(refusals).collect::<BTreeSet<_>>().len() > 1);
    }

    #[test]
    fn an_injected_reset_tears_down_both_directions() {
        let mut net = SimNet::builder()
            .fault_seed(1)
            .reset_permille(1000)
            .build()
            .unwrap();
        let listener = net.tcp_listen("server", 1).unwrap();
        let client = net.tcp_connect("client", "server", 0).unwrap();
        let server = net.tcp_accept(listener, 0).unwrap().unwrap().socket;
        assert_eq!(
            net.tcp_send(client, b"doomed", 0).unwrap_err().code,
            ErrorCode::ConnectionReset
        );
        // The peer sees the reset too: a reset is not one-sided.
        assert_eq!(
            net.tcp_recv(server, 16, 0).unwrap_err().code,
            ErrorCode::ConnectionReset
        );
        assert_eq!(
            net.tcp_send(client, b"again", 0).unwrap_err().code,
            ErrorCode::ConnectionReset
        );
        let report = net.fault_report().unwrap();
        assert_eq!(report.stream_ops, 1, "the reset op is the only opportunity");
        assert_eq!(report.resets_injected, 1);
        assert!(!report.is_vacuous());
    }

    #[test]
    fn a_receiving_endpoint_can_be_reset_and_would_block_polls_do_not_draw() {
        let mut net = SimNet::builder()
            .fault_seed(1)
            .reset_permille(1000)
            .build()
            .unwrap();
        let listener = net.tcp_listen("server", 1).unwrap();
        let client = net.tcp_connect("client", "server", 0).unwrap();
        let server = net.tcp_accept(listener, 0).unwrap().unwrap().socket;
        // A poll with nothing to read is not a data operation, so it neither
        // draws nor counts — a reset must not get likelier the harder a guest
        // spins.
        assert_eq!(net.tcp_recv(server, 16, 0).unwrap(), None);
        assert_eq!(net.fault_report().unwrap().stream_ops, 0);
        assert_eq!(
            net.tcp_send(client, b"x", 0).unwrap_err().code,
            ErrorCode::ConnectionReset
        );
    }

    #[test]
    fn reset_is_seed_deterministic_and_varies_across_seeds() {
        fn sends_before_reset(seed: u64) -> usize {
            let mut net = SimNet::builder()
                .fault_seed(seed)
                .reset_permille(200)
                .build()
                .unwrap();
            let listener = net.tcp_listen("server", 1).unwrap();
            let client = net.tcp_connect("client", "server", 0).unwrap();
            let server = net.tcp_accept(listener, 0).unwrap().unwrap().socket;
            for index in 0..64 {
                if net.tcp_send(client, b"x", 0).is_err() {
                    return index;
                }
                // Drain so the small buffer never becomes the limiting factor.
                let _ = net.tcp_recv(server, 64, u64::MAX);
            }
            64
        }
        for seed in 0..8 {
            assert_eq!(sends_before_reset(seed), sends_before_reset(seed));
        }
        let distinct = (0..16u64).map(sends_before_reset).collect::<BTreeSet<_>>();
        assert!(distinct.len() > 1, "reset timing must vary across seeds");
    }

    #[test]
    fn a_partition_that_names_unused_addresses_is_vacuous() {
        // The operator-error signature: a partition spelled for addresses this
        // run never uses blocks nothing, and a clean result would otherwise read
        // as "tested under partition".
        let mut net = SimNet::builder()
            .partition("10.0.0.1:1", "10.0.0.2:2")
            .build()
            .unwrap();
        let tx = net.bind("tx").unwrap();
        net.bind("rx").unwrap();
        for _ in 0..8 {
            net.send(tx, "rx", b"through", 0).unwrap();
        }
        let report = net.fault_report().unwrap();
        assert!(report.partition_vacuity_diagnosable);
        assert_eq!(report.partition_blocks, 0);
        assert!(report.is_vacuous());

        // A partition that matches the traffic blocks it, and is not vacuous.
        let mut net = SimNet::builder().partition("tx", "rx").build().unwrap();
        let tx = net.bind("tx").unwrap();
        net.bind("rx").unwrap();
        for _ in 0..8 {
            net.send(tx, "rx", b"blocked", 0).unwrap();
        }
        let report = net.fault_report().unwrap();
        assert_eq!(report.partition_blocks, 8);
        assert!(!report.is_vacuous());
    }

    #[test]
    fn the_base_latency_class_catches_a_send_path_that_ignores_it() {
        // Defect 2's signature, now a first-class report row: the knob is set,
        // sends happened, and the path applied it zero times. A TCP send that
        // skipped `base_latency_nanos` (as the pre-Wave-A stream path did) lands
        // exactly here instead of reading clean.
        let mut net = SimNet::builder().base_latency_nanos(50).build().unwrap();
        let listener = net.tcp_listen("server", 8).unwrap();
        let client = net.tcp_connect("client", "server", 0).unwrap();
        let server = net.tcp_accept(listener, 0).unwrap().unwrap().socket;
        for _ in 0..8 {
            net.tcp_send(client, b"x", 0).unwrap();
            let _ = net.tcp_recv(server, 64, u64::MAX);
        }
        let report = net.fault_report().unwrap();
        assert!(report.latency_vacuity_diagnosable);
        assert_eq!(report.latency_applied, 8);
        assert!(!report.is_vacuous());
    }

    #[test]
    fn each_net_fault_class_draws_from_its_own_substream() {
        // The property with teeth: a class's decisions must not depend on how
        // much OTHER traffic the run pushed. The connect-refusal verdicts for a
        // fixed sequence of connects are identical whether or not datagrams are
        // interleaved between them — a refusal decision taken from the shared
        // drop/jitter stream would be shifted by every intervening datagram.
        //
        // Note the direction: this compares runs whose CONNECT sequence is
        // identical. Comparing drop verdicts across armed/unarmed TCP knobs
        // would prove nothing, because a refused connect removes the stream
        // sends that follow it and so changes the workload itself.
        fn refusals(with_datagram_traffic: bool) -> Vec<bool> {
            let mut net = SimNet::builder()
                .fault_seed(11)
                .drop_permille(500)
                .jitter_nanos(1, 1_000)
                .connect_refuse_permille(500)
                .build()
                .unwrap();
            let tx = net.bind("tx").unwrap();
            net.bind("rx").unwrap();
            net.tcp_listen("server", 64).unwrap();
            (0..32u8)
                .map(|index| {
                    if with_datagram_traffic {
                        for _ in 0..3 {
                            net.send(tx, "rx", &[index], 0).unwrap();
                        }
                    }
                    net.tcp_connect(&format!("c-{index}"), "server", 0).is_err()
                })
                .collect()
        }
        let quiet = refusals(false);
        assert_eq!(quiet, refusals(true));
        assert!(
            quiet.contains(&true) && quiet.contains(&false),
            "the control must actually have drawn both ways, or this proves nothing"
        );

        // And the streams are not merely independent objects: they are keyed to
        // DIFFERENT domains, so two classes never draw identical sequences.
        let seeds = BTreeSet::from([
            7,
            domain_seed(7, fault_domain::NET_DUPLICATE),
            domain_seed(7, fault_domain::NET_CONNECT_REFUSE),
            domain_seed(7, fault_domain::NET_RESET),
        ]);
        assert_eq!(seeds.len(), 4, "net fault substreams must not alias");
    }
}
