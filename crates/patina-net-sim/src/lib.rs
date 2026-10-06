//! Deterministic in-memory datagram and stream networking.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use patina_dst_abi::{EffectError, ErrorCode, SocketId};
use patina_dst_driver_api::{DriverResult, wildcard_bind_keys};
use patina_dst_rng_seeded::SplitMix64;

mod builder;
mod driver;
mod faults;

pub use builder::SimNetBuilder;
use driver::FaultCounts;

#[derive(Clone, Debug)]
struct Packet {
    id: u64,
    from: String,
    /// The address the receiver is bound under.
    to: String,
    /// The receiving socket, chosen when the packet is sent (one member of a
    /// shared binding).
    socket: SocketId,
    bytes: Vec<u8>,
    delivery_nanos: u64,
    /// The address the sender dialed.
    dialed: String,
    tos: u8,
}

/// The sockets bound at one datagram address: one, or the members of a shared
/// (`SO_REUSEPORT`) binding.
struct Binding {
    members: Vec<SocketId>,
    shared: bool,
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
    /// Segments that left the inbox (read or discarded): with the due ones
    /// still queued, the arrivals so far.
    retired: u64,
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
    addresses: BTreeMap<String, Binding>,
    /// Connected datagram sockets: the `(local, peer)` pair a datagram must
    /// carry to reach each.
    datagram_peers: BTreeMap<SocketId, (String, String)>,
    /// Datagram sockets' marks: the type of service their sends carry and
    /// the source address they leave from, when set.
    datagram_marks: BTreeMap<SocketId, (u8, Option<String>)>,
    /// Per datagram socket, the packets it has received: with the due ones
    /// still queued, the arrivals so far.
    received: BTreeMap<SocketId, u64>,
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

impl Default for SimNet {
    fn default() -> Self {
        Self::new()
    }
}

fn invalid_socket(socket: SocketId) -> EffectError {
    EffectError::new(
        ErrorCode::InvalidHandle,
        format!("virtual socket {} is not bound", socket.0),
    )
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

    /// The datagram socket that receives traffic `from` dialed at `to`: a
    /// connected member whose whole 4-tuple matches, under whichever binding
    /// it holds (a wildcard-bound socket that connects is found at its routed
    /// source, as the kernel rehashes it there, and `compute_score` ranks the
    /// 4-tuple match above every unconnected socket); else the exact binding
    /// if one exists, else a wildcard binding under the shared routing rule
    /// ([`wildcard_bind_keys`]), and within a shared binding the member the
    /// sender's address hashes to (a fixed member per sender, as a kernel's
    /// reuseport group picks by flow). A connected member that does not
    /// match takes nothing. Returns the socket AND the address it is bound
    /// under, because a queued packet names the address the receiver is
    /// bound at.
    fn resolve_datagram(&self, from: &str, to: &str) -> Option<(SocketId, String)> {
        let keys = || std::iter::once(to.to_owned()).chain(wildcard_bind_keys(to));
        let connected = keys().find_map(|address| {
            let binding = self.addresses.get(&address)?;
            binding
                .members
                .iter()
                .copied()
                .find(|member| {
                    self.datagram_peers
                        .get(member)
                        .is_some_and(|(local, peer)| local == to && peer == from)
                })
                .map(|member| (member, address))
        });
        if connected.is_some() {
            return connected;
        }
        keys().find_map(|address| {
            let binding = self.addresses.get(&address)?;
            let open: Vec<SocketId> = binding
                .members
                .iter()
                .copied()
                .filter(|member| !self.datagram_peers.contains_key(member))
                .collect();
            let member = match open.len() {
                0 => return None,
                1 => open[0],
                count => {
                    let hash = from.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
                        (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
                    });
                    open[(hash % count as u64) as usize]
                }
            };
            Some((member, address))
        })
    }

    /// The TCP listener that accepts a connection dialed at `to`, exact match
    /// first and then the wildcard rule, mirroring [`SimNet::resolve_datagram`].
    fn resolve_listener(&self, to: &str) -> Option<SocketId> {
        std::iter::once(to.to_owned())
            .chain(wildcard_bind_keys(to))
            .find_map(|address| self.tcp_listener_addresses.get(&address).copied())
    }

    /// The index of the packet `recv` takes for `socket` at `now_nanos`: the
    /// earliest deliverable one, ties by send order.
    fn due_packet(&self, socket: SocketId, now_nanos: u64) -> Option<usize> {
        self.packets
            .iter()
            .enumerate()
            .filter(|(_, packet)| packet.socket == socket && packet.delivery_nanos <= now_nanos)
            .min_by_key(|(_, packet)| (packet.delivery_nanos, packet.id))
            .map(|(index, _)| index)
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

#[cfg(test)]
mod tests;
