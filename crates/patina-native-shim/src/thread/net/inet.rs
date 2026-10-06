//! `AF_INET`/`AF_INET6`: TCP and UDP whose traffic is SimNet's.
//!
//! What crosses the wire — a bind of a datagram address, a listen, a connect,
//! the bytes of a send and a receive, a shutdown, a close — is a recorded
//! runtime operation. The rest of the kernel's socket layer is here: the bind
//! table and its conflicts (`inet_csk_bind_conflict`, `udp_lib_lport_inuse`),
//! which local addresses exist (the virtual interface table), the connection
//! state (`SS_CONNECTING` across a non-blocking connect), pending errors
//! (a refused connect, a connected datagram's port-unreachable answer), and
//! each call's refusals in the order `net/ipv4` and `net/ipv6` make them.
//! Blocking calls park on the scheduler until SimNet has what they wait for.
//!
//! An IPv6 socket's IPv4-mapped peers travel as IPv4 on the wire (the kernel
//! hands a mapped connect to IPv4 too), and an IPv6 socket bound to
//! `in6addr_any` without `IPV6_V6ONLY` is bound at the network's any-family
//! wildcard, so it receives both families.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use patina_dst_abi::{SendDisposition, ShutdownHow, SocketId};
use patina_dst_driver_api::{local_ipv4, local_ipv6, source_address, wildcard_bind_keys};

use super::addr::{self, Endpoint, V6Extra};
use super::*;
use crate::{EACCES, EPIPE};

/// The virtual kernel's `ip_local_port_range`.
const EPHEMERAL: std::ops::RangeInclusive<u16> = 32768..=60999;
/// `ip_unprivileged_port_start`: binding below it needs
/// `CAP_NET_BIND_SERVICE`.
const UNPRIVILEGED_PORT: u16 = 1024;
/// The most a UDP datagram carries over IPv4 (65535 less the IP and UDP
/// headers) and over IPv6 (less the UDP header alone).
const UDP4_MAX: usize = 65507;
const UDP6_MAX: usize = 65527;
/// The IP protocols this model has: the rest a type names are refused.
const IPPROTO_MAX: i32 = 263;

/// One inet socket's state.
pub(crate) struct Inet {
    pub(crate) v6: bool,
    /// The bound local endpoint (`inet_rcv_saddr`, `inet_num`): an
    /// unspecified address for a wildcard bind, `None` until bound.
    pub(crate) local: Option<Endpoint>,
    /// `SOCK_BINDADDR_LOCK`/`SOCK_BINDPORT_LOCK`: what `bind` fixed.
    addr_locked: bool,
    port_locked: bool,
    /// The address `bind` fixed while no port is held: a datagram
    /// disconnect gave back a port the kernel chose and kept the address
    /// (`__udp_disconnect`), which the socket reports and binds at again.
    kept: Option<IpAddr>,
    /// The connected peer (`inet_daddr`, `inet_dport`).
    pub(crate) peer: Option<Endpoint>,
    peer_extra: V6Extra,
    state: State,
    /// `SS_CONNECTING`: a non-blocking connect not yet reported by a second
    /// `connect`.
    connecting: bool,
    /// UDP: the SimNet socket, once bound.
    udp: Option<SocketId>,
    /// UDP: the marks the SimNet socket's sends carry now (type of service,
    /// source address), so a send re-marks it only when they change.
    #[cfg(target_os = "linux")]
    marked: (u8, Option<String>),
    /// A listener's connections so far: its edge-triggered arrivals.
    accepts: u64,
}

/// `sk_state`, as far as the model distinguishes it.
enum State {
    /// `TCP_CLOSE`: never connected, or a connect that failed. A UDP socket's
    /// association is `peer`.
    Closed,
    Listening {
        socket: SocketId,
        address: String,
    },
    /// `TCP_ESTABLISHED`: `key` names the connection in [`Tables::streams`].
    Established {
        socket: SocketId,
        key: String,
    },
}

impl Inet {
    fn new(v6: bool) -> Inet {
        Inet {
            v6,
            local: None,
            addr_locked: false,
            port_locked: false,
            kept: None,
            peer: None,
            peer_extra: V6Extra::default(),
            state: State::Closed,
            connecting: false,
            udp: None,
            #[cfg(target_os = "linux")]
            marked: (0, None),
            accepts: 0,
        }
    }
}

/// The two sockets of one connection, and its two directions. It lives
/// until both sides are gone and no listener's backlog holds it: a
/// connection whose client closed before the accept keeps what it sent (an
/// urgent byte included) until it is accepted or its listener closes.
#[derive(Clone, Copy, Default)]
struct Pair {
    client: Option<c_int>,
    server: Option<c_int>,
    /// The listener whose backlog holds the connection until its accept.
    backlog: Option<c_int>,
    to_server: Direction,
    to_client: Direction,
}

impl Pair {
    fn other(&self, handle: c_int) -> Option<c_int> {
        if self.client == Some(handle) {
            self.server
        } else if self.server == Some(handle) {
            self.client
        } else {
            None
        }
    }

    /// The direction `handle` sends into.
    fn sending(&mut self, handle: c_int) -> &mut Direction {
        if self.client == Some(handle) {
            &mut self.to_server
        } else {
            &mut self.to_client
        }
    }

    /// The direction `handle` receives from, as it stands.
    fn received(&self, handle: c_int) -> Direction {
        if self.client == Some(handle) {
            self.to_client
        } else {
            self.to_server
        }
    }

    /// The direction `handle` receives from.
    fn receiving(&mut self, handle: c_int) -> &mut Direction {
        if self.client == Some(handle) {
            &mut self.to_client
        } else {
            &mut self.to_server
        }
    }
}

/// One direction of a connection's byte stream, as far as urgent data needs
/// it: the bytes written into it (`write_seq`), the bytes the receiver took
/// out (`copied_seq`, a skipped urgent byte included) and the urgent byte
/// (`tcp_mark_urg` at the sender, `tcp_check_urg`/`tcp_urg` at the
/// receiver). It lives with the connection, so a connection not yet
/// accepted keeps what was sent to it.
#[derive(Clone, Copy, Default)]
struct Direction {
    written: u64,
    taken: u64,
    urgent: Option<Urgent>,
}

/// The urgent byte: its offset in the stream, its value, and whether a
/// `MSG_OOB` receive took it (`TCP_URG_READ`). The receiver learns of it
/// when the byte arrives, and forgets it once reading passes it.
#[derive(Clone, Copy, Debug)]
struct Urgent {
    at: u64,
    byte: u8,
    read: bool,
}

impl Direction {
    /// The urgent byte, once it has arrived (`pending` bytes wait unread).
    fn arrived(&self, pending: usize) -> Option<Urgent> {
        self.urgent
            .filter(|urgent| urgent.at < self.taken + pending as u64)
    }

    /// How many bytes a receive may take before the urgent byte stops it
    /// (`tcp_recvmsg_locked` stops at the mark); `Some(0)` at the mark.
    fn before_mark(&self) -> Option<u64> {
        self.urgent.map(|urgent| urgent.at - self.taken)
    }

    /// The receiver took `count` bytes: past the urgent byte, it is gone.
    fn took(&mut self, count: usize) {
        self.taken += count as u64;
        if self.urgent.is_some_and(|urgent| urgent.at < self.taken) {
            self.urgent = None;
        }
    }
}

/// The inet namespace: the bind table and the wire addresses to wake.
#[derive(Default)]
pub(crate) struct Tables {
    /// Bound sockets by `(tcp, port)`.
    ports: BTreeMap<(bool, u16), Vec<c_int>>,
    /// UDP sockets by the network address they are bound at.
    udp: BTreeMap<String, Vec<c_int>>,
    /// TCP listeners by the network address they listen at.
    listeners: BTreeMap<String, c_int>,
    /// Connections by the client's network address.
    streams: BTreeMap<String, Pair>,
    next_ephemeral: u16,
}

/// `inet_create`/`inet6_create`: the type/protocol pair, answered as the
/// kernel's protocol switch answers it for an unprivileged caller.
pub(super) fn create(v6: bool, ty: i32, protocol: i32) -> Result<(i32, i32, Proto), c_int> {
    // `__sock_create`: an IPv4 `SOCK_PACKET` is the packet family's (which
    // needs CAP_NET_RAW).
    #[cfg(target_os = "linux")]
    if !v6 && ty == SOCK_PACKET {
        return Err(crate::EPERM);
    }
    if !(0..IPPROTO_MAX).contains(&protocol) {
        return Err(EINVAL);
    }
    let icmp = if v6 { IPPROTO_ICMPV6 } else { IPPROTO_ICMP };
    let protocol = match ty {
        SOCK_STREAM if protocol == 0 || protocol == IPPROTO_TCP => IPPROTO_TCP,
        SOCK_DGRAM if protocol == 0 || protocol == IPPROTO_UDP => IPPROTO_UDP,
        // UDP-Lite is a protocol of its own (its own ports, partial
        // checksums) the virtual network does not carry.
        #[cfg(target_os = "linux")]
        SOCK_DGRAM if protocol == IPPROTO_UDPLITE => crate::trap_fatal(
            "socket(SOCK_DGRAM, IPPROTO_UDPLITE): UDP-Lite is not modeled; failing closed",
        ),
        // A ping socket needs a group in `ping_group_range`, empty by default.
        SOCK_DGRAM if protocol == icmp => return Err(EACCES),
        SOCK_STREAM | SOCK_DGRAM => return Err(EPROTONOSUPPORT),
        // Any protocol matches the raw switch entry; the socket needs
        // CAP_NET_RAW.
        SOCK_RAW => return Err(crate::EPERM),
        _ => return Err(ESOCKTNOSUPPORT),
    };
    Ok((ty, protocol, Proto::Inet(Inet::new(v6))))
}

fn as_inet(socket: &Socket) -> &Inet {
    match &socket.proto {
        Proto::Inet(inet) => inet,
        _ => unreachable!("an inet entry reached a socket of another family"),
    }
}

fn as_inet_mut(socket: &mut Socket) -> &mut Inet {
    match &mut socket.proto {
        Proto::Inet(inet) => inet,
        _ => unreachable!("an inet entry reached a socket of another family"),
    }
}

fn sock(state: &ThreadRuntime, handle: c_int) -> Result<&Socket, c_int> {
    state.net.sockets.table.get(&handle).ok_or(crate::EBADF)
}

fn sock_mut(state: &mut ThreadRuntime, handle: c_int) -> Result<&mut Socket, c_int> {
    state.net.sockets.table.get_mut(&handle).ok_or(crate::EBADF)
}

fn is_tcp(socket: &Socket) -> bool {
    socket.ty == SOCK_STREAM
}

/// An address as the socket's family reports it: an IPv6 socket names an
/// IPv4 endpoint by its mapped address.
fn encode(v6: bool, endpoint: Endpoint, extra: V6Extra) -> Vec<u8> {
    match (v6, endpoint.ip) {
        (false, IpAddr::V4(ip)) => addr::encode_in(ip, endpoint.port),
        (false, IpAddr::V6(_)) => unreachable!("an IPv4 socket has an IPv6 endpoint"),
        (true, IpAddr::V4(ip)) => addr::encode_in6(ip.to_ipv6_mapped(), endpoint.port, extra),
        (true, IpAddr::V6(ip)) => addr::encode_in6(ip, endpoint.port, extra),
    }
}

/// The unspecified endpoint of the socket's family.
fn unspecified(v6: bool) -> Endpoint {
    Endpoint {
        ip: if v6 {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        },
        port: 0,
    }
}

/// A peer address a socket names: `sockaddr_in` for IPv4, `sockaddr_in6` for
/// IPv6 with a mapped address taken as the IPv4 one it maps. `v6only` makes
/// a mapped address unreachable.
fn destination(
    v6: bool,
    v6only: bool,
    bytes: &[u8],
    short: c_int,
) -> Result<(Endpoint, V6Extra), c_int> {
    if !v6 {
        return addr::parse_in(bytes, EAFNOSUPPORT).map(|endpoint| (endpoint, V6Extra::default()));
    }
    if addr::family_of(bytes) == Some(AF_INET) {
        // An IPv6 socket may name an IPv4 peer with a `sockaddr_in` unless it
        // is IPv6-only.
        if v6only {
            return Err(EAFNOSUPPORT);
        }
        return addr::parse_in(bytes, EAFNOSUPPORT).map(|endpoint| (endpoint, V6Extra::default()));
    }
    if bytes.len() < 24 {
        return Err(short);
    }
    let (ip, port, extra) = addr::parse_in6(bytes, EAFNOSUPPORT)?;
    match ip.to_ipv4_mapped() {
        Some(_) if v6only => Err(ENETUNREACH),
        Some(v4) => Ok((Endpoint::v4(v4, port), extra)),
        None => Ok((
            Endpoint {
                ip: IpAddr::V6(ip),
                port,
            },
            extra,
        )),
    }
}

/// Where traffic toward `peer` leaves from, or `ENETUNREACH`. Connecting to
/// the unspecified address reaches the host itself.
fn route(peer: Endpoint) -> Result<(Endpoint, IpAddr), c_int> {
    let source = source_address(peer.ip).ok_or(ENETUNREACH)?;
    let peer = if peer.ip.is_unspecified() {
        Endpoint {
            ip: source,
            port: peer.port,
        }
    } else {
        peer
    };
    Ok((peer, source))
}

/// The network address a bound socket answers at: its own endpoint, or the
/// family's wildcard (the any-family one for a dual-stack IPv6 socket).
fn wire(inet: &Inet, v6only: bool) -> String {
    let local = inet
        .local
        .expect("a wire address is asked of a bound socket");
    match local.ip {
        IpAddr::V4(ip) if ip.is_unspecified() => {
            format!("{}:{}", patina_dst_driver_api::WILDCARD_HOST, local.port)
        }
        IpAddr::V6(ip) if ip.is_unspecified() && v6only => {
            format!("{}:{}", patina_dst_driver_api::WILDCARD_V6_HOST, local.port)
        }
        IpAddr::V6(ip) if ip.is_unspecified() => {
            format!("{}:{}", patina_dst_driver_api::ANY_FAMILY_HOST, local.port)
        }
        _ => local.wire(),
    }
}

/// A bound socket's claim on its port, as the bind conflict rules read it.
#[derive(Clone, Copy)]
struct Claim {
    ip: IpAddr,
    /// An IPv6 wildcard that takes IPv4 too.
    dual: bool,
    reuseaddr: bool,
    reuseport: bool,
    listening: bool,
    bound_if: u32,
}

fn claim(socket: &Socket, ip: IpAddr, listening: bool) -> Claim {
    let inet = as_inet(socket);
    Claim {
        ip,
        dual: inet.v6 && !socket.opts.v6only,
        reuseaddr: socket.opts.reuseaddr,
        reuseport: socket.opts.reuseport,
        listening,
        bound_if: socket.opts.bound_if,
    }
}

/// `inet_rcv_saddr_equal` with wildcards matching.
fn overlap(a: Claim, b: Claim) -> bool {
    match (a.ip, b.ip) {
        (IpAddr::V4(x), IpAddr::V4(y)) => x == y || x.is_unspecified() || y.is_unspecified(),
        (IpAddr::V6(x), IpAddr::V6(y)) => x == y || x.is_unspecified() || y.is_unspecified(),
        (IpAddr::V4(_), IpAddr::V6(y)) => y.is_unspecified() && b.dual,
        (IpAddr::V6(x), IpAddr::V4(_)) => x.is_unspecified() && a.dual,
    }
}

/// Whether `new` may not share a port with `held` (`inet_bind_conflict`,
/// `udp_lib_lport_inuse`): overlapping addresses on devices that can meet,
/// unless both allow reuse — address reuse against a TCP socket that does
/// not listen, or port reuse by the one owner.
fn conflicts(tcp: bool, new: Claim, held: Claim) -> bool {
    let devices_meet = new.bound_if == 0 || held.bound_if == 0 || new.bound_if == held.bound_if;
    if !devices_meet || !overlap(new, held) {
        return false;
    }
    if new.reuseport && held.reuseport {
        return false;
    }
    !(new.reuseaddr && held.reuseaddr && (!tcp || (!held.listening && !new.listening)))
}

/// Whether `port` is free for `new` among the other sockets on it.
fn port_free(state: &ThreadRuntime, tcp: bool, handle: c_int, port: u16, new: Claim) -> bool {
    let tables = &state.net.sockets.inet;
    tables.ports.get(&(tcp, port)).is_none_or(|holders| {
        holders
            .iter()
            .filter(|other| **other != handle)
            .all(|other| {
                let Some(held) = state.net.sockets.table.get(other) else {
                    return true;
                };
                let inet = as_inet(held);
                let Some(local) = inet.local else {
                    return true;
                };
                let listening = matches!(inet.state, State::Listening { .. });
                !conflicts(tcp, new, claim(held, local.ip, listening))
            })
    })
}

/// Pick a free ephemeral port for `new` (`inet_csk_find_open_port`):
/// `EADDRINUSE` when the range is exhausted.
fn ephemeral(
    state: &mut ThreadRuntime,
    tcp: bool,
    handle: c_int,
    new: Claim,
) -> Result<u16, c_int> {
    let span = u32::from(EPHEMERAL.end() - EPHEMERAL.start()) + 1;
    for _ in 0..span {
        let tables = &mut state.net.sockets.inet;
        let offset = tables.next_ephemeral;
        tables.next_ephemeral = ((u32::from(offset) + 1) % span) as u16;
        let port = EPHEMERAL.start() + offset;
        if !state.net.sockets.inet.ports.contains_key(&(tcp, port))
            && port_free(state, tcp, handle, port, new)
        {
            return Ok(port);
        }
    }
    Err(EADDRINUSE)
}

/// Enter `handle` in the bind table at `local`, binding a UDP socket's
/// network address.
fn register(state: &mut ThreadRuntime, handle: c_int, local: Endpoint) -> Result<(), c_int> {
    let socket = sock_mut(state, handle)?;
    let tcp = is_tcp(socket);
    let v6only = socket.opts.v6only;
    let shared = socket.opts.reuseport || socket.opts.reuseaddr;
    let inet = as_inet_mut(socket);
    inet.local = Some(local);
    inet.kept = None;
    if !tcp {
        let address = wire(inet, v6only);
        let bound = if shared {
            with_context_raw(|context| context.net_bind_shared(&address))
        } else {
            with_context_raw(|context| context.net_bind(&address))
        };
        let udp = match bound {
            Ok(udp) => udp,
            Err(errno) => {
                as_inet_mut(sock_mut(state, handle)?).local = None;
                return Err(if errno == crate::EEXIST {
                    EADDRINUSE
                } else {
                    errno
                });
            }
        };
        let inet = as_inet_mut(sock_mut(state, handle)?);
        inet.udp = Some(udp);
        // A fresh network socket carries no marks.
        #[cfg(target_os = "linux")]
        {
            inet.marked = (0, None);
        }
        state
            .net
            .sockets
            .inet
            .udp
            .entry(address)
            .or_default()
            .push(handle);
    }
    state
        .net
        .sockets
        .inet
        .ports
        .entry((tcp, local.port))
        .or_default()
        .push(handle);
    Ok(())
}

/// Take `handle` out of the bind table, closing a UDP socket's network
/// binding.
fn unregister(state: &mut ThreadRuntime, handle: c_int, tcp: bool, inet: &mut Inet, v6only: bool) {
    let Some(local) = inet.local else {
        return;
    };
    let tables = &mut state.net.sockets.inet;
    if let Some(holders) = tables.ports.get_mut(&(tcp, local.port)) {
        holders.retain(|other| *other != handle);
        if holders.is_empty() {
            tables.ports.remove(&(tcp, local.port));
        }
    }
    if let Some(udp) = inet.udp.take() {
        let address = wire(inet, v6only);
        if let Some(holders) = tables.udp.get_mut(&address) {
            holders.retain(|other| *other != handle);
            if holders.is_empty() {
                tables.udp.remove(&address);
            }
        }
        let _ = with_context_raw(|context| context.net_close(udp));
    }
}

/// Bind an unbound socket to an ephemeral port of the unspecified address
/// (`inet_autobind`), or to `source` when a connect picks the address.
fn autobind(state: &mut ThreadRuntime, handle: c_int, source: Option<IpAddr>) -> Result<(), c_int> {
    let socket = sock(state, handle)?;
    let inet = as_inet(socket);
    if inet.local.is_some() {
        return Ok(());
    }
    let tcp = is_tcp(socket);
    let ip = inet.kept.or(source).unwrap_or(unspecified(inet.v6).ip);
    let new = claim(socket, ip, false);
    let port = ephemeral(state, tcp, handle, new)?;
    register(state, handle, Endpoint { ip, port })
}

/// Whether some interface owns `ip` for a bind (`inet_addr_valid_or_nonlocal`):
/// a local address, a multicast or broadcast one, or the wildcard.
fn bindable_v4(ip: Ipv4Addr) -> bool {
    ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_broadcast()
        || local_ipv4(ip.octets())
        || patina_dst_driver_api::VIRTUAL_INTERFACES
            .iter()
            .any(|interface| interface.ipv4.broadcast() == ip.octets())
}

mod connect;
mod listener;
mod readiness;
mod recv;
mod send;

#[cfg(test)]
mod tests;

pub(super) use connect::{bind, connect};
use connect::{is_broadcast, listener_closed};
pub(super) use listener::{accept, close, listen, listening, name, shutdown};
use listener::{drop_stream, reset};
#[cfg(target_os = "linux")]
pub(super) use readiness::at_mark;
pub(super) use readiness::{pending, poll};
pub(super) use recv::recv;
pub(super) use send::send;
