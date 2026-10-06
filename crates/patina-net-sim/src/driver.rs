//! Datagram and stream operations implementing the network driver contract.

use std::collections::VecDeque;

use crate::{Binding, Packet, SimNet, TcpEndpoint, TcpListenerState, TcpSegment, invalid_socket};
use patina_dst_abi::{
    Datagram, EffectError, ErrorCode, SendDisposition, SendReport, ShutdownHow, SocketId,
    TcpAccepted,
};
use patina_dst_driver_api::{
    DriverResult, NetDriver, NetFaultReport, NetReadiness, datagram_source,
    range_vacuity_is_diagnosable, vacuity_is_diagnosable, wildcard_bind_keys,
};

/// What the network fault plane observed this run, per class. Kept beside the
/// knobs rather than inside [`NetFaultReport`] because the report also carries
/// the derived `*_vacuity_diagnosable` verdicts, which are a pure function of
/// these counts and the configured rates.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct FaultCounts {
    /// Datagram sends that reached the fault-decision point (not pre-empted by a
    /// partition) plus `tcp_send`s that enqueued a segment.
    pub(super) send_ops: u64,
    pub(super) drops_applied: u64,
    pub(super) jitter_applied: u64,
    pub(super) latency_applied: u64,
    duplicates_applied: u64,
    /// `tcp_connect` calls that would otherwise have succeeded.
    connect_ops: u64,
    connects_refused: u64,
    /// Established-stream operations that moved data.
    pub(super) stream_ops: u64,
    pub(super) resets_injected: u64,
    /// Sends and connects blocked by a configured partition.
    partition_blocks: u64,
}

impl NetDriver for SimNet {
    fn bind(&mut self, address: &str) -> DriverResult<SocketId> {
        validate_address(address)?;
        if self.addresses.contains_key(address) {
            return Err(already_bound(address));
        }
        let socket = self.allocate_socket()?;
        self.bindings.insert(socket, address.into());
        self.addresses.insert(
            address.into(),
            Binding {
                members: vec![socket],
                shared: false,
            },
        );
        Ok(socket)
    }

    fn bind_shared(&mut self, address: &str) -> DriverResult<SocketId> {
        validate_address(address)?;
        if self
            .addresses
            .get(address)
            .is_some_and(|binding| !binding.shared)
        {
            return Err(already_bound(address));
        }
        let socket = self.allocate_socket()?;
        self.bindings.insert(socket, address.into());
        self.addresses
            .entry(address.into())
            .or_insert(Binding {
                members: Vec::new(),
                shared: true,
            })
            .members
            .push(socket);
        Ok(socket)
    }

    fn validate_send(&self, socket: SocketId, to: &str) -> DriverResult<()> {
        validate_address(to)?;
        self.address(socket)?;
        Ok(())
    }

    fn mark_datagrams(
        &mut self,
        socket: SocketId,
        tos: u8,
        source: Option<&str>,
    ) -> DriverResult<()> {
        self.address(socket)?;
        if tos == 0 && source.is_none() {
            self.datagram_marks.remove(&socket);
        } else {
            self.datagram_marks
                .insert(socket, (tos, source.map(str::to_owned)));
        }
        Ok(())
    }

    fn connect_datagram(
        &mut self,
        socket: SocketId,
        local: &str,
        peer: Option<&str>,
    ) -> DriverResult<()> {
        self.address(socket)?;
        match peer {
            Some(peer) => {
                self.datagram_peers
                    .insert(socket, (local.to_owned(), peer.to_owned()));
            }
            None => {
                self.datagram_peers.remove(&socket);
            }
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
        let (tos, source) = self
            .datagram_marks
            .get(&socket)
            .cloned()
            .unwrap_or_default();
        let bound = self.address(socket)?;
        let from = source.unwrap_or_else(|| datagram_source(bound, to));
        // Route once, here, and queue the packet for the socket that receives
        // it, under the address that socket is bound at: a wildcard binding's
        // queue is keyed `0.0.0.0:P` whichever IP the sender dialed, so every
        // downstream filter keeps comparing one socket. The guest never
        // observes this: a datagram surfaces its `from`, not the address it
        // was dialed at.
        let route = self.resolve_datagram(&from, to);
        if self.partitions.contains(&(from.clone(), to.into())) {
            self.counts.partition_blocks += 1;
            return Ok(SendReport {
                written: bytes.len(),
                copies: 0,
                delivery_nanos: Vec::new(),
                disposition: SendDisposition::DroppedByPartition,
            });
        }
        // Nothing bound at the destination: the datagram goes nowhere, and the
        // network's answer (a host's ICMP port-unreachable) is the report.
        let Some((receiver, destination)) = route else {
            return Ok(SendReport {
                written: bytes.len(),
                copies: 0,
                delivery_nanos: Vec::new(),
                disposition: SendDisposition::Unreachable,
            });
        };
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
                socket: receiver,
                bytes: bytes.to_vec(),
                delivery_nanos,
                dialed: to.to_owned(),
                tos,
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
        self.address(socket)?;
        let Some(index) = self.due_packet(socket, now_nanos) else {
            return Ok(None);
        };
        let packet = self.packets.remove(index);
        *self.received.entry(socket).or_default() += 1;
        Ok(Some(Datagram {
            packet_id: packet.id,
            from: packet.from,
            to: packet.to,
            bytes: packet.bytes,
            delivery_nanos: packet.delivery_nanos,
            dialed: packet.dialed,
            tos: packet.tos,
        }))
    }

    fn peek(&self, socket: SocketId, now_nanos: u64) -> DriverResult<Option<Datagram>> {
        self.address(socket)?;
        Ok(self.due_packet(socket, now_nanos).map(|index| {
            let packet = &self.packets[index];
            Datagram {
                packet_id: packet.id,
                from: packet.from.clone(),
                to: packet.to.clone(),
                bytes: packet.bytes.clone(),
                delivery_nanos: packet.delivery_nanos,
                dialed: packet.dialed.clone(),
                tos: packet.tos,
            }
        }))
    }

    fn next_delivery(&self, socket: SocketId, now_nanos: u64) -> DriverResult<Option<u64>> {
        if self.bindings.contains_key(&socket) {
            return Ok(self
                .packets
                .iter()
                .filter(|packet| packet.socket == socket && packet.delivery_nanos > now_nanos)
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
                || wildcard_bind_keys(&endpoint.local).contains(&state.address),
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
                retired: 0,
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
                retired: 0,
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
                endpoint.retired += 1;
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

    fn tcp_peek(
        &self,
        socket: SocketId,
        max_len: usize,
        now_nanos: u64,
    ) -> DriverResult<Option<Vec<u8>>> {
        let endpoint = self.tcp_endpoints.get(&socket).ok_or_else(|| {
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
        let mut peeked = Vec::new();
        for segment in &endpoint.inbox {
            if peeked.len() == max_len || segment.delivery_nanos > now_nanos {
                break;
            }
            let take = segment.bytes.len().min(max_len - peeked.len());
            peeked.extend_from_slice(&segment.bytes[..take]);
        }
        if !peeked.is_empty() {
            return Ok(Some(peeked));
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
                endpoint.retired += endpoint.inbox.len() as u64;
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
        if self.bindings.contains_key(&socket) {
            let due = self
                .packets
                .iter()
                .filter(|packet| packet.socket == socket && packet.delivery_nanos <= now_nanos);
            let arrivals =
                due.clone().count() as u64 + self.received.get(&socket).copied().unwrap_or(0);
            let pending = self
                .due_packet(socket, now_nanos)
                .map_or(0, |index| self.packets[index].bytes.len());
            return Ok(NetReadiness {
                readable: due.clone().next().is_some(),
                writable: true,
                arrivals,
                pending,
                room: usize::MAX,
                ..NetReadiness::default()
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
                    peer_write_closed: true,
                    reset: true,
                    arrivals: endpoint.retired + endpoint.inbox.len() as u64 + 1,
                    pending: 0,
                    room: usize::MAX,
                });
            }
            // Mirror `tcp_recv`: `Some(nonempty)` = data, `Some(empty)` = EOF,
            // `None` = would-block. Readable iff a receive would not would-block.
            let due: Vec<&TcpSegment> = endpoint
                .inbox
                .iter()
                .take_while(|segment| segment.delivery_nanos <= now_nanos)
                .collect();
            let read_eof =
                endpoint.read_closed || (endpoint.remote_write_closed && endpoint.inbox.is_empty());
            let readable = !due.is_empty() || read_eof;
            // Mirror `tcp_send`: `Ok(0)` (would-block) only when the peer's
            // receive buffer is full and the peer is still reading; a shut-for-
            // write, gone, or non-reading peer fails closed rather than blocks,
            // which a reactor reports as writable-with-EOF.
            let write_eof = endpoint.write_closed
                || endpoint
                    .peer
                    .and_then(|peer| self.tcp_endpoints.get(&peer))
                    .is_none_or(|peer| peer.read_closed);
            // Mirror `tcp_send`'s acceptance: what the peer's buffer has
            // left, or everything where the send does not wait.
            let room = match endpoint.peer.and_then(|peer| self.tcp_endpoints.get(&peer)) {
                Some(peer) if !write_eof && !peer.read_closed => {
                    self.tcp_buffer_bytes.saturating_sub(peer.inbox_bytes)
                }
                _ => usize::MAX,
            };
            let writable = room > 0;
            // The FIN arrives after every byte sent before it, and is an
            // arrival of its own: a peer's shutdown re-arms an edge-triggered
            // reader even when it had nothing left to send.
            let fin_arrived = endpoint.remote_write_closed && due.len() == endpoint.inbox.len();
            let arrivals = endpoint.retired + due.len() as u64 + u64::from(fin_arrived);
            return Ok(NetReadiness {
                readable,
                writable,
                read_eof,
                write_eof,
                peer_write_closed: fin_arrived,
                reset: false,
                arrivals,
                pending: due.iter().map(|segment| segment.bytes.len()).sum(),
                room,
            });
        }
        if let Some(listener) = self.tcp_listeners.get(&socket) {
            // A listener is "readable" once a connection is pending: `accept`
            // would return `Some`. A listener is never writable.
            return Ok(NetReadiness {
                readable: !listener.pending.is_empty(),
                pending: listener.pending.len(),
                ..NetReadiness::default()
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
            if let Some(binding) = self.addresses.get_mut(&address) {
                binding.members.retain(|member| *member != socket);
                if binding.members.is_empty() {
                    self.addresses.remove(&address);
                }
            }
            self.received.remove(&socket);
            self.datagram_peers.remove(&socket);
            self.datagram_marks.remove(&socket);
            // A datagram already sent is independent of its sender's socket
            // lifetime, so in-flight packets FROM this address stay deliverable.
            self.packets.retain(|packet| packet.socket != socket);
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

fn already_bound(address: &str) -> EffectError {
    EffectError::new(
        ErrorCode::AlreadyBound,
        format!("virtual network address is already bound: {address}"),
    )
}

fn tcp_reset(socket: SocketId) -> EffectError {
    EffectError::new(
        ErrorCode::ConnectionReset,
        format!("virtual TCP stream {} was reset by its peer", socket.0),
    )
}

#[cfg(test)]
mod tests;
