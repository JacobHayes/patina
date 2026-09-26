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

/// The two sockets of one connection, and its two directions.
#[derive(Clone, Copy, Default)]
struct Pair {
    client: Option<c_int>,
    server: Option<c_int>,
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

/// `bind(2)` (`__inet_bind`, `__inet6_bind`).
pub(super) fn bind(handle: c_int, bytes: &[u8]) -> Result<(), c_int> {
    let mut state = lock_state();
    let socket = sock(&state, handle)?;
    let tcp = is_tcp(socket);
    let inet = as_inet(socket);
    let v6 = inet.v6;
    let already = inet.local.is_some_and(|local| local.port != 0)
        || !matches!(inet.state, State::Closed)
        || (!tcp && inet.peer.is_some());
    let endpoint = if !v6 {
        if bytes.len() < 16 {
            return Err(EINVAL);
        }
        // Compatibility games: AF_UNSPEC is AF_INET for the wildcard alone.
        let family = addr::family_of(bytes);
        let wildcard = bytes[4..8] == [0; 4];
        if family != Some(AF_INET) && !(family == Some(AF_UNSPEC) && wildcard) {
            return Err(EAFNOSUPPORT);
        }
        let ip = Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
        let port = u16::from_be_bytes([bytes[2], bytes[3]]);
        if !bindable_v4(ip) {
            return Err(EADDRNOTAVAIL);
        }
        if port != 0 && port < UNPRIVILEGED_PORT {
            return Err(EACCES);
        }
        if already {
            return Err(EINVAL);
        }
        Endpoint::v4(ip, port)
    } else {
        if bytes.len() < 24 {
            return Err(EINVAL);
        }
        let (ip, port, _) = addr::parse_in6(bytes, EAFNOSUPPORT)?;
        if ip.is_multicast() && tcp {
            return Err(EINVAL);
        }
        if port != 0 && port < UNPRIVILEGED_PORT {
            return Err(EACCES);
        }
        if already {
            return Err(EINVAL);
        }
        match ip.to_ipv4_mapped() {
            Some(_) if socket.opts.v6only => return Err(EINVAL),
            Some(v4) if !bindable_v4(v4) => return Err(EADDRNOTAVAIL),
            Some(v4) => Endpoint::v4(v4, port),
            None => {
                if !ip.is_unspecified() && !ip.is_multicast() && !local_ipv6(ip.octets()) {
                    return Err(EADDRNOTAVAIL);
                }
                Endpoint {
                    ip: IpAddr::V6(ip),
                    port,
                }
            }
        }
    };
    let new = claim(socket, endpoint.ip, false);
    let port = if endpoint.port == 0 {
        ephemeral(&mut state, tcp, handle, new)?
    } else if port_free(&state, tcp, handle, endpoint.port, new) {
        endpoint.port
    } else {
        return Err(EADDRINUSE);
    };
    let specific_v6 = matches!(endpoint.ip, IpAddr::V6(ip) if !ip.is_unspecified());
    {
        let socket = sock_mut(&mut state, handle)?;
        if specific_v6 {
            // Binding one IPv6 address makes the socket IPv6-only.
            socket.opts.v6only = true;
        }
        let inet = as_inet_mut(socket);
        inet.addr_locked = !endpoint.ip.is_unspecified();
        inet.port_locked = endpoint.port != 0;
    }
    register(
        &mut state,
        handle,
        Endpoint {
            ip: endpoint.ip,
            port,
        },
    )
}

/// `connect(2)`: a datagram socket's association, or a stream connection.
pub(super) fn connect(handle: c_int, bytes: &[u8], nonblocking: bool) -> Result<(), c_int> {
    if bytes.len() < 2 {
        return Err(EINVAL);
    }
    let tcp = is_tcp(sock(&lock_state(), handle)?);
    if addr::family_of(bytes) == Some(AF_UNSPEC) {
        return disconnect(handle, tcp);
    }
    if tcp {
        connect_stream(handle, bytes, nonblocking)
    } else {
        connect_datagram(handle, bytes)
    }
}

/// `connect` with `AF_UNSPEC`: dissolve a datagram association
/// (`__udp_disconnect`, which also gives back what `bind` did not fix), or
/// drop a stream's connection (`tcp_disconnect`).
fn disconnect(handle: c_int, tcp: bool) -> Result<(), c_int> {
    let mut state = lock_state();
    let socket = sock_mut(&mut state, handle)?;
    let v6only = socket.opts.v6only;
    let mut inet = std::mem::replace(as_inet_mut(socket), Inet::new(false));
    inet.peer = None;
    inet.connecting = false;
    let mut wakes = Vec::new();
    let mut released = Ok(());
    if tcp {
        if let State::Established { socket: sid, key } =
            std::mem::replace(&mut inet.state, State::Closed)
        {
            wakes.extend(drop_stream(&mut state, handle, &key));
            with_context_raw(|context| context.net_close(sid))?;
        }
        sock_mut(&mut state, handle)?.shutdown = 0;
    } else if !inet.port_locked {
        unregister(&mut state, handle, false, &mut inet, v6only);
        inet.kept = inet
            .local
            .take()
            .map(|local| local.ip)
            .filter(|_| inet.addr_locked);
    } else {
        if !inet.addr_locked {
            if let Some(local) = &mut inet.local {
                local.ip = unspecified(inet.v6).ip;
            }
        }
        if let Some(udp) = inet.udp {
            released = with_context_raw(|context| context.net_connect(udp, "", None));
        }
    }
    *as_inet_mut(sock_mut(&mut state, handle)?) = inet;
    drop(state);
    wake_all(wakes);
    released
}

/// A datagram `connect` (`__ip4_datagram_connect`, `__ip6_datagram_connect`):
/// autobind, the peer, and the source address the route gives an unbound
/// address.
fn connect_datagram(handle: c_int, bytes: &[u8]) -> Result<(), c_int> {
    let mut state = lock_state();
    autobind(&mut state, handle, None)?;
    let socket = sock(&state, handle)?;
    let (peer, extra) = destination(as_inet(socket).v6, socket.opts.v6only, bytes, EINVAL)?;
    let (peer, source) = route(peer)?;
    if is_broadcast(peer.ip) && !socket.opts.broadcast {
        return Err(EACCES);
    }
    let inet = as_inet_mut(sock_mut(&mut state, handle)?);
    inet.peer = Some(peer);
    inet.peer_extra = extra;
    if let Some(local) = &mut inet.local {
        if local.ip.is_unspecified() {
            local.ip = source;
        }
    }
    // The socket now receives only what its peer sends to its (routed) local
    // address: the kernel's 4-tuple lookup.
    let local = inet.local.map(|local| local.wire());
    if let (Some(udp), Some(local)) = (inet.udp, local) {
        with_context_raw(|context| context.net_connect(udp, &local, Some(&peer.wire())))?;
    }
    Ok(())
}

fn is_broadcast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_broadcast()
                || patina_dst_driver_api::VIRTUAL_INTERFACES
                    .iter()
                    .any(|interface| interface.ipv4.broadcast() == ip.octets())
        }
        IpAddr::V6(_) => false,
    }
}

/// A stream `connect` (`__inet_stream_connect`): a connection completes (or
/// is refused) at once over the virtual network, so a non-blocking connect
/// answers `EINPROGRESS` with the outcome already decided and the second
/// `connect` reports it.
fn connect_stream(handle: c_int, bytes: &[u8], nonblocking: bool) -> Result<(), c_int> {
    let mut state = lock_state();
    let socket = sock_mut(&mut state, handle)?;
    let inet = as_inet_mut(socket);
    if inet.connecting {
        inet.connecting = false;
        return match inet.state {
            State::Established { .. } => Ok(()),
            _ => {
                let error = socket.take_error().unwrap_or(ECONNABORTED);
                socket.shutdown = 0;
                Err(error)
            }
        };
    }
    match inet.state {
        State::Established { .. } | State::Listening { .. } => return Err(EISCONN),
        State::Closed => {}
    }
    let (peer, extra) = destination(inet.v6, socket.opts.v6only, bytes, EINVAL)?;
    let (peer, source) = route(peer)?;
    let bound = as_inet_mut(sock_mut(&mut state, handle)?).local;
    match bound {
        None => autobind(&mut state, handle, Some(source))?,
        Some(local) if local.ip.is_unspecified() => {
            if let Some(local) = &mut as_inet_mut(sock_mut(&mut state, handle)?).local {
                local.ip = source;
            }
        }
        Some(_) => {}
    }
    let local = as_inet(sock(&state, handle)?)
        .local
        .expect("the connect just bound the socket");
    let key = local.wire();
    let to = peer.wire();
    let outcome = with_context_raw(|context| context.net_tcp_connect(&key, &to));
    let socket = sock_mut(&mut state, handle)?;
    let inet = as_inet_mut(socket);
    inet.peer_extra = extra;
    let wakes = match outcome {
        Ok(sid) => {
            inet.state = State::Established {
                socket: sid,
                key: key.clone(),
            };
            inet.peer = Some(peer);
            state
                .net
                .sockets
                .inet
                .streams
                .entry(key)
                .or_default()
                .client = Some(handle);
            wake_listener(&mut state, &to)
        }
        Err(errno) if errno == ECONNREFUSED => {
            // `tcp_reset` on the answering RST: the pending error, and every
            // direction shut.
            socket.error = ECONNREFUSED;
            socket.shutdown = SHUTDOWN_MASK;
            let v6only = socket.opts.v6only;
            let mut inet = std::mem::replace(as_inet_mut(socket), Inet::new(false));
            if !inet.port_locked {
                unregister(&mut state, handle, true, &mut inet, v6only);
                inet.local = None;
            }
            *as_inet_mut(sock_mut(&mut state, handle)?) = inet;
            Vec::new()
        }
        Err(errno) => return Err(errno),
    };
    let socket = sock_mut(&mut state, handle)?;
    let result = if nonblocking {
        as_inet_mut(socket).connecting = true;
        Err(EINPROGRESS)
    } else if let Some(error) = socket.take_error() {
        socket.shutdown = 0;
        Err(error)
    } else {
        Ok(())
    };
    drop(state);
    wake_all(wakes);
    result
}

/// Wake whoever waits on the listener a connection to `to` reached, counting
/// the arrival.
fn wake_listener(state: &mut ThreadRuntime, to: &str) -> Vec<TaskId> {
    let listener = std::iter::once(to.to_owned())
        .chain(wildcard_bind_keys(to))
        .find_map(|address| state.net.sockets.inet.listeners.get(&address).copied());
    let Some(listener) = listener else {
        return Vec::new();
    };
    if let Some(socket) = state.net.sockets.table.get_mut(&listener) {
        as_inet_mut(socket).accepts += 1;
    }
    waiters(state, listener, Dir::Recv)
}

/// `listen(2)` (`inet_listen`): an unbound socket takes an ephemeral port; a
/// listener only takes the new backlog.
pub(super) fn listen(handle: c_int, backlog: i32) -> Result<(), c_int> {
    let mut state = lock_state();
    let socket = sock(&state, handle)?;
    if !is_tcp(socket) {
        return Err(EOPNOTSUPP);
    }
    let inet = as_inet(socket);
    if inet.connecting {
        return Err(EINVAL);
    }
    match inet.state {
        State::Listening { .. } => return Ok(()),
        State::Established { .. } => return Err(EINVAL),
        State::Closed => {}
    }
    match inet.local {
        None => autobind(&mut state, handle, None)?,
        Some(local) => {
            let socket = sock(&state, handle)?;
            if !port_free(
                &state,
                true,
                handle,
                local.port,
                claim(socket, local.ip, true),
            ) {
                return Err(EADDRINUSE);
            }
        }
    }
    let socket = sock(&state, handle)?;
    let address = wire(as_inet(socket), socket.opts.v6only);
    let listened =
        with_context_raw(|context| context.net_tcp_listen(&address, backlog.max(1) as usize));
    let sid = match listened {
        Ok(sid) => sid,
        Err(errno) if errno == crate::EEXIST => return Err(EADDRINUSE),
        Err(errno) => return Err(errno),
    };
    as_inet_mut(sock_mut(&mut state, handle)?).state = State::Listening {
        socket: sid,
        address: address.clone(),
    };
    state.net.sockets.inet.listeners.insert(address, handle);
    Ok(())
}

/// Whether `handle` is a listening inet socket (`SO_ACCEPTCONN`).
pub(super) fn listening(state: &ThreadRuntime, handle: c_int) -> bool {
    state.net.sockets.table.get(&handle).is_some_and(|socket| {
        matches!(&socket.proto, Proto::Inet(inet) if matches!(inet.state, State::Listening { .. }))
    })
}

/// `accept4(2)` (`inet_csk_accept`): the new socket's handle and its peer's
/// name.
pub(super) fn accept(handle: c_int, nonblocking: bool) -> Result<(c_int, Vec<u8>), c_int> {
    let deadline = {
        let state = lock_state();
        let socket = sock(&state, handle)?;
        if !is_tcp(socket) {
            return Err(EOPNOTSUPP);
        }
        if !matches!(as_inet(socket).state, State::Listening { .. }) {
            return Err(EINVAL);
        }
        super::deadline(socket.opts.recv_timeout())?
    };
    loop {
        let mut state = lock_state();
        let socket = sock(&state, handle)?;
        let State::Listening { socket: sid, .. } = as_inet(socket).state else {
            return Err(EINVAL);
        };
        match with_context_raw(|context| context.net_tcp_accept(sid))? {
            Some(accepted) => return Ok(adopt(&mut state, handle, accepted)),
            None => {
                if nonblocking || expired(deadline)? || deadline.is_some_and(|d| d == 0) {
                    return Err(EWOULDBLOCK);
                }
                park(state, handle, Dir::Recv, deadline, "tcp-accept")?;
                if expired(deadline)? {
                    return Err(EWOULDBLOCK);
                }
            }
        }
    }
}

/// Make the socket an accepted connection becomes: the listener's options,
/// the address the client dialed, the client's address as its peer.
fn adopt(
    state: &mut ThreadRuntime,
    listener: c_int,
    accepted: patina_dst_abi::TcpAccepted,
) -> (c_int, Vec<u8>) {
    let Some(peer) = Endpoint::from_wire(&accepted.peer) else {
        fatal("the network driver answered an accept with a malformed peer address");
    };
    let client = state
        .net
        .sockets
        .inet
        .streams
        .get(&accepted.peer)
        .and_then(|pair| pair.client);
    let dialed = client
        .and_then(|client| state.net.sockets.table.get(&client))
        .and_then(|client| as_inet(client).peer);
    let listening = state
        .net
        .sockets
        .table
        .get(&listener)
        .expect("the listener was checked");
    let local = dialed.or(as_inet(listening).local);
    let mut inet_state = Inet::new(as_inet(listening).v6);
    inet_state.local = local;
    inet_state.peer = Some(peer);
    inet_state.state = State::Established {
        socket: accepted.socket,
        key: accepted.peer.clone(),
    };
    let opts = listening.opts.clone();
    let (family, ty, protocol, v6) = (
        listening.family,
        listening.ty,
        listening.protocol,
        as_inet(listening).v6,
    );
    let handle = next_handle(state);
    let inode = mint_inode(state);
    let mut socket = Socket::new(family, ty, protocol, Proto::Inet(inet_state), inode);
    socket.opts = opts;
    state.net.sockets.table.insert(handle, socket);
    state
        .net
        .sockets
        .inet
        .streams
        .entry(accepted.peer)
        .or_default()
        .server = Some(handle);
    (handle, encode(v6, peer, V6Extra::default()))
}

/// `getsockname`/`getpeername` (`inet_getname`, `inet6_getname`).
pub(super) fn name(socket: &Socket, inet: &Inet, peer: bool) -> Result<Vec<u8>, c_int> {
    if peer {
        let connected = match inet.state {
            State::Established { .. } => true,
            State::Listening { .. } => false,
            State::Closed => !is_tcp(socket) && inet.peer.is_some(),
        };
        let peer = inet.peer.filter(|_| connected).ok_or(ENOTCONN)?;
        return Ok(encode(inet.v6, peer, inet.peer_extra));
    }
    let unbound = Endpoint {
        ip: inet.kept.unwrap_or(unspecified(inet.v6).ip),
        port: 0,
    };
    Ok(encode(
        inet.v6,
        inet.local.unwrap_or(unbound),
        V6Extra::default(),
    ))
}

/// `shutdown(2)` (`inet_shutdown`): an unconnected socket answers `ENOTCONN`
/// and still records the directions; a listener shut for reading stops
/// listening.
pub(super) fn shutdown(handle: c_int, bits: u8) -> Result<(), c_int> {
    let mut state = lock_state();
    let socket = sock_mut(&mut state, handle)?;
    let tcp = is_tcp(socket);
    let inet = as_inet_mut(socket);
    inet.connecting = false;
    let (result, stream) = match &inet.state {
        State::Listening { .. } if bits & RCV_SHUTDOWN == 0 => return Ok(()),
        State::Listening { .. } => {
            drop(state);
            return stop_listening(handle);
        }
        State::Established { socket: sid, key } => (Ok(()), Some((*sid, key.clone()))),
        State::Closed if !tcp && inet.peer.is_some() => (Ok(()), None),
        State::Closed => (Err(ENOTCONN), None),
    };
    socket.shutdown |= bits;
    let mut wakes = waiters(&mut state, handle, Dir::Recv);
    wakes.extend(waiters(&mut state, handle, Dir::Send));
    if let Some((sid, key)) = stream {
        if bits & SEND_SHUTDOWN != 0 {
            with_context_raw(|context| context.net_tcp_shutdown(sid, ShutdownHow::Write))?;
            if let Some(peer) = state
                .net
                .sockets
                .inet
                .streams
                .get(&key)
                .and_then(|pair| pair.other(handle))
            {
                wakes.extend(waiters(&mut state, peer, Dir::Recv));
            }
        }
    }
    drop(state);
    wake_all(wakes);
    result
}

/// A listener shut for reading: `tcp_disconnect` closes it.
fn stop_listening(handle: c_int) -> Result<(), c_int> {
    let mut state = lock_state();
    let socket = sock_mut(&mut state, handle)?;
    let inet = as_inet_mut(socket);
    if let State::Listening {
        socket: sid,
        address,
    } = std::mem::replace(&mut inet.state, State::Closed)
    {
        state.net.sockets.inet.listeners.remove(&address);
        with_context_raw(|context| context.net_close(sid))?;
    }
    let wakes = waiters(&mut state, handle, Dir::Recv);
    drop(state);
    wake_all(wakes);
    Ok(())
}

/// Take `handle`'s side out of the connection `key`, answering the peer's
/// waiters to wake.
fn drop_stream(state: &mut ThreadRuntime, handle: c_int, key: &str) -> Vec<TaskId> {
    let tables = &mut state.net.sockets.inet;
    let Some(pair) = tables.streams.get_mut(key) else {
        return Vec::new();
    };
    let peer = pair.other(handle);
    if pair.client == Some(handle) {
        pair.client = None;
    }
    if pair.server == Some(handle) {
        pair.server = None;
    }
    if pair.client.is_none() && pair.server.is_none() {
        tables.streams.remove(key);
    }
    let mut wakes = Vec::new();
    if let Some(peer) = peer {
        wakes.extend(waiters(state, peer, Dir::Recv));
        wakes.extend(waiters(state, peer, Dir::Send));
    }
    wakes
}

/// A connection the network reset (`tcp_reset`, then `tcp_done`): the
/// socket is closed with both directions shut and the network stream
/// released, so after the one `ECONNRESET` a receive reads end-of-file and a
/// send is `EPIPE`. Answers the tasks to wake.
fn reset(state: &mut ThreadRuntime, handle: c_int) -> Result<Vec<TaskId>, c_int> {
    let socket = sock_mut(state, handle)?;
    socket.shutdown = SHUTDOWN_MASK;
    let inet = as_inet_mut(socket);
    let State::Established { socket: sid, key } = std::mem::replace(&mut inet.state, State::Closed)
    else {
        return Ok(Vec::new());
    };
    let wakes = drop_stream(state, handle, &key);
    with_context_raw(|context| context.net_close(sid))?;
    Ok(wakes)
}

/// Free a closed socket's network state: its binding, its listener, its
/// connection. Answers the tasks to wake.
pub(super) fn close(
    state: &mut ThreadRuntime,
    handle: c_int,
    mut inet: Inet,
    tcp: bool,
    v6only: bool,
) -> Result<Vec<TaskId>, c_int> {
    let mut wakes = Vec::new();
    match std::mem::replace(&mut inet.state, State::Closed) {
        State::Closed => {}
        State::Listening {
            socket: sid,
            address,
        } => {
            state.net.sockets.inet.listeners.remove(&address);
            with_context_raw(|context| context.net_close(sid))?;
        }
        State::Established { socket: sid, key } => {
            wakes.extend(drop_stream(state, handle, &key));
            with_context_raw(|context| context.net_close(sid))?;
        }
    }
    unregister(state, handle, tcp, &mut inet, v6only);
    Ok(wakes)
}

/// Send one message (`udp_sendmsg`, `tcp_sendmsg_locked`).
pub(super) fn send(handle: c_int, message: Outgoing) -> Result<usize, c_int> {
    let tcp = is_tcp(sock(&lock_state(), handle)?);
    if tcp {
        send_stream(handle, message)
    } else {
        send_datagram(handle, message)
    }
}

fn send_datagram(handle: c_int, message: Outgoing) -> Result<usize, c_int> {
    let mut state = lock_state();
    let v6 = as_inet(sock(&state, handle)?).v6;
    if message.data.len() > 0xFFFF {
        return Err(EMSGSIZE);
    }
    if message.flags & MSG_OOB != 0 {
        return Err(EOPNOTSUPP);
    }
    // `inet_send_prepare`: the socket takes a port before the send is judged.
    autobind(&mut state, handle, None)?;
    let socket = sock(&state, handle)?;
    let inet = as_inet(socket);
    let peer = match &message.to {
        Some(bytes) => {
            let family = addr::family_of(bytes);
            let peer = if !v6 {
                if bytes.len() < 16 {
                    return Err(EINVAL);
                }
                if family != Some(AF_INET) && family != Some(AF_UNSPEC) {
                    return Err(EAFNOSUPPORT);
                }
                Endpoint::v4(
                    Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]),
                    u16::from_be_bytes([bytes[2], bytes[3]]),
                )
            } else if family == Some(AF_UNSPEC) {
                inet.peer.ok_or(EDESTADDRREQ)?
            } else if family == Some(AF_INET) || family == Some(AF_INET6) {
                destination(true, socket.opts.v6only, bytes, EINVAL)?.0
            } else {
                return Err(EINVAL);
            };
            if peer.port == 0 {
                return Err(EINVAL);
            }
            peer
        }
        None => inet.peer.ok_or(EDESTADDRREQ)?,
    };
    // `udp_cmsg_send`/`ip_cmsg_send` (`ip6_datagram_send_ctl`): the
    // protocol-level control messages, read for the destination's family.
    #[cfg(target_os = "linux")]
    let control =
        super::ipctl::send_control(&socket.opts.ip, v6, peer.ip.is_ipv4(), &message.protocol)?;
    let max = if peer.ip.is_ipv4() {
        UDP4_MAX
    } else {
        UDP6_MAX
    };
    if message.data.len() > max {
        return Err(EMSGSIZE);
    }
    let (peer, _) = route(peer)?;
    #[cfg(target_os = "linux")]
    let source = super::ipctl::chosen_source(&control)?;
    if is_broadcast(peer.ip) && !socket.opts.broadcast {
        return Err(EACCES);
    }
    // The ICMP answer to a send reaches the socket only when it names the
    // socket's own peer (`__udp4_lib_err` looks the socket up by the
    // datagram's 4-tuple).
    let to_peer = inet.peer.is_some_and(|connected| connected == peer);
    let udp = inet
        .udp
        .expect("an autobound datagram socket has a network binding");
    let shut = socket.shutdown & SEND_SHUTDOWN != 0;
    // `sock_alloc_send_pskb`: a pending error, then a shut sending side,
    // then the copy.
    if let Some(error) = sock_mut(&mut state, handle)?.take_error() {
        return Err(error);
    }
    if shut {
        return Err(EPIPE);
    }
    let bytes = message.data.read_all()?;
    let to = peer.wire();
    #[cfg(target_os = "linux")]
    let unreachable = {
        // `udp_send_skb`: the payload cut into segments, each a datagram.
        let datagrams = super::ipctl::segments(
            &bytes,
            control.gso,
            peer.ip.is_ipv4(),
            super::ipctl::mtu_to(peer.ip),
        )?;
        let port = as_inet(sock(&state, handle)?)
            .local
            .map_or(0, |local| local.port);
        let mark = (control.tos, source.map(|ip| Endpoint { ip, port }.wire()));
        let inet = as_inet_mut(sock_mut(&mut state, handle)?);
        if inet.marked != mark {
            with_context_raw(|context| context.net_mark(udp, mark.0, mark.1.as_deref()))?;
            inet.marked = mark;
        }
        let mut unreachable = false;
        for datagram in datagrams {
            let report = with_context_raw(|context| context.net_send(udp, &to, datagram))?;
            unreachable |= report.disposition == SendDisposition::Unreachable;
        }
        unreachable
    };
    #[cfg(target_os = "macos")]
    if let Some((level, kind, _)) = message.protocol.first() {
        crate::trap_fatal(&format!(
            "ancillary data at level {level}, type {kind} on a Darwin datagram socket is not \
             modeled; failing closed"
        ));
    }
    #[cfg(target_os = "macos")]
    let unreachable = with_context_raw(|context| context.net_send(udp, &to, &bytes))?.disposition
        == SendDisposition::Unreachable;
    let mut wakes = Vec::new();
    if unreachable && to_peer {
        // The port-unreachable answer reaches a connected socket as a
        // pending error (`__udp4_lib_err`).
        sock_mut(&mut state, handle)?.error = ECONNREFUSED;
        wakes.extend(waiters(&mut state, handle, Dir::Recv));
        wakes.extend(waiters(&mut state, handle, Dir::Send));
    }
    let receivers = std::iter::once(to.clone())
        .chain(wildcard_bind_keys(&to))
        .find_map(|address| state.net.sockets.inet.udp.get(&address).cloned())
        .unwrap_or_default();
    for receiver in receivers {
        wakes.extend(waiters(&mut state, receiver, Dir::Recv));
    }
    drop(state);
    wake_all(wakes);
    Ok(message.data.len())
}

/// A stream send; under `MSG_OOB` the last byte it wrote is the urgent byte
/// (`tcp_push` → `tcp_mark_urg`), which the receiver takes out of band.
/// One urgent byte is modeled at a time: a second before the receiver passed
/// the first (whose replacement 6.8 judges as the new mark arrives) is a
/// named fatal. Darwin's urgent data is not modeled (`EOPNOTSUPP`).
fn send_stream(handle: c_int, message: Outgoing) -> Result<usize, c_int> {
    if message.flags & MSG_OOB == 0 {
        return send_stream_bytes(handle, &message);
    }
    if cfg!(target_os = "macos") {
        return Err(EOPNOTSUPP);
    }
    let sent = send_stream_bytes(handle, &message)?;
    if sent == 0 {
        return Ok(sent);
    }
    let byte = message.data.read(sent - 1, 1)?[0];
    let mut state = lock_state();
    let State::Established { ref key, .. } = as_inet(sock(&state, handle)?).state else {
        return Ok(sent);
    };
    let key = key.clone();
    let Some(pair) = state.net.sockets.inet.streams.get_mut(&key) else {
        return Ok(sent);
    };
    let direction = pair.sending(handle);
    if direction.urgent.is_some() {
        fatal(
            "a second urgent byte (MSG_OOB) before the receiver passed the first is not \
             modeled; failing closed",
        );
    }
    direction.urgent = Some(Urgent {
        at: direction.written - 1,
        byte,
        read: false,
    });
    let peer = pair.other(handle);
    let wakes = peer
        .map(|peer| waiters(&mut state, peer, Dir::Recv))
        .unwrap_or_default();
    drop(state);
    wake_all(wakes);
    Ok(sent)
}

fn send_stream_bytes(handle: c_int, message: &Outgoing) -> Result<usize, c_int> {
    let nosigpipe = sock(&lock_state(), handle)?.opts.nosigpipe();
    let failed = |errno: c_int| {
        if errno == EPIPE {
            pipe_signal(message.flags, nosigpipe);
        }
        Err(errno)
    };
    let deadline = super::deadline(sock(&lock_state(), handle)?.opts.send_timeout())?;
    let nonblocking = message.flags & MSG_DONTWAIT != 0 || deadline == Some(now()?);
    let mut sent = 0;
    loop {
        let mut state = lock_state();
        let socket = sock_mut(&mut state, handle)?;
        let (sid, key) = match &as_inet(socket).state {
            State::Established { socket: sid, key } => (*sid, key.clone()),
            // `sk_stream_wait_connect`: a pending error, else `EPIPE`.
            _ => {
                return match socket.take_error() {
                    Some(error) => Err(error),
                    None => {
                        drop(state);
                        failed(EPIPE)
                    }
                };
            }
        };
        if let Some(error) = socket.take_error() {
            return if sent > 0 { Ok(sent) } else { Err(error) };
        }
        if socket.shutdown & SEND_SHUTDOWN != 0 {
            drop(state);
            return if sent > 0 { Ok(sent) } else { failed(EPIPE) };
        }
        if sent == message.data.len() {
            return Ok(sent);
        }
        // `sk_stream_wait_memory` before `copy_from_iter`: bytes that cannot
        // be read matter only once the stream has room for them (a full
        // stream waits, or is `EAGAIN`, first), and a piece is read only as
        // large as the room it goes into.
        let room = with_context_raw(|context| context.net_readiness(sid))?.room;
        let written = if room == 0 {
            Ok(0)
        } else {
            match message.data.read(sent, STREAM_CHUNK.min(room)) {
                Ok(chunk) => with_context_raw(|context| context.net_tcp_send(sid, &chunk)),
                Err(errno) => return if sent > 0 { Ok(sent) } else { Err(errno) },
            }
        };
        match written {
            Ok(0) => {
                if nonblocking || expired(deadline)? {
                    return if sent > 0 { Ok(sent) } else { Err(EWOULDBLOCK) };
                }
                park(state, handle, Dir::Send, deadline, "tcp-send")
                    .or_else(|errno| if sent > 0 { Ok(()) } else { Err(errno) })?;
            }
            Ok(written) => {
                sent += written;
                let peer = state
                    .net
                    .sockets
                    .inet
                    .streams
                    .get_mut(&key)
                    .and_then(|pair| {
                        pair.sending(handle).written += written as u64;
                        pair.other(handle)
                    });
                let wakes = peer
                    .map(|peer| waiters(&mut state, peer, Dir::Recv))
                    .unwrap_or_default();
                drop(state);
                wake_all(wakes);
            }
            Err(errno) => {
                let wakes = if errno == ECONNRESET {
                    let wakes = reset(&mut state, handle)?;
                    if sent > 0 {
                        sock_mut(&mut state, handle)?.error = ECONNRESET;
                    }
                    wakes
                } else {
                    Vec::new()
                };
                drop(state);
                wake_all(wakes);
                return if sent > 0 { Ok(sent) } else { failed(errno) };
            }
        }
    }
}

/// Receive one message (`udp_recvmsg`, `tcp_recvmsg_locked`).
pub(super) fn recv(handle: c_int, want: Want) -> Result<Incoming, c_int> {
    let tcp = is_tcp(sock(&lock_state(), handle)?);
    if tcp {
        recv_stream(handle, want)
    } else {
        recv_datagram(handle, want)
    }
}

/// The deadline a receive waits until: the socket's `SO_RCVTIMEO`, `None`
/// for none; `MSG_DONTWAIT` is an immediate one.
fn recv_deadline(handle: c_int, flags: c_int) -> Result<(Option<u64>, bool), c_int> {
    let timeout = sock(&lock_state(), handle)?.opts.recv_timeout();
    let nonblocking = flags & MSG_DONTWAIT != 0 || timeout == Some(0);
    Ok((super::deadline(timeout)?, nonblocking))
}

/// Park a receive until the next delivery SimNet has for `sid`, the
/// deadline, or a wake.
fn park_recv(
    state: SpinGuard<'_, ThreadRuntime>,
    handle: c_int,
    sid: Option<SocketId>,
    deadline: Option<u64>,
    reason: &'static str,
) -> Result<(), c_int> {
    let delivery = match sid {
        Some(sid) => with_context_raw(|context| context.net_next_delivery(sid))?,
        None => None,
    };
    let until = match (delivery, deadline) {
        (Some(delivery), Some(deadline)) => Some(delivery.min(deadline)),
        (delivery, deadline) => delivery.or(deadline),
    };
    park(state, handle, Dir::Recv, until, reason)
}

fn recv_datagram(handle: c_int, want: Want) -> Result<Incoming, c_int> {
    let (deadline, nonblocking) = recv_deadline(handle, want.flags)?;
    loop {
        let mut state = lock_state();
        let socket = sock_mut(&mut state, handle)?;
        let v6 = as_inet(socket).v6;
        let udp = as_inet(socket).udp;
        let datagram = match udp {
            Some(udp) if want.flags & MSG_PEEK != 0 => {
                with_context_raw(|context| context.net_peek(udp))?
            }
            Some(udp) => with_context_raw(|context| context.net_recv(udp))?,
            None => None,
        };
        if let Some(datagram) = datagram {
            let whole = datagram.bytes.len();
            let copied = whole.min(want.capacity);
            let from = Endpoint::from_wire(&datagram.from)
                .map(|from| encode(v6, from, V6Extra::default()));
            #[cfg(target_os = "linux")]
            let control = super::ipctl::received_control(&socket.opts.ip, v6, &datagram);
            #[cfg(target_os = "macos")]
            let control = Vec::new();
            return Ok(Incoming {
                control,
                data: datagram.bytes[..copied].to_vec(),
                len: if want.flags & MSG_TRUNC != 0 {
                    whole
                } else {
                    copied
                },
                from,
                flags: if copied < whole { MSG_TRUNC } else { 0 },
                ..Incoming::default()
            });
        }
        let socket = sock_mut(&mut state, handle)?;
        if let Some(error) = socket.take_error() {
            return Err(error);
        }
        if socket.shutdown & RCV_SHUTDOWN != 0 {
            return Ok(Incoming::default());
        }
        if nonblocking || expired(deadline)? {
            return Err(EWOULDBLOCK);
        }
        park_recv(state, handle, udp, deadline, "net-recv")?;
    }
}

fn recv_stream(handle: c_int, want: Want) -> Result<Incoming, c_int> {
    {
        let mut state = lock_state();
        let socket = sock_mut(&mut state, handle)?;
        match as_inet(socket).state {
            State::Listening { .. } => return Err(ENOTCONN),
            State::Established { .. } if want.flags & MSG_OOB != 0 => {
                drop(state);
                return recv_urgent(handle, want);
            }
            State::Established { .. } => {}
            State::Closed if want.flags & MSG_OOB != 0 => return Err(EINVAL),
            // Never connected, or a connect that failed.
            State::Closed => {
                return match socket.take_error() {
                    Some(error) => Err(error),
                    None if socket.shutdown & RCV_SHUTDOWN != 0 => Ok(Incoming::default()),
                    None => Err(ENOTCONN),
                };
            }
        }
    }
    if want.capacity == 0 {
        return Ok(Incoming::default());
    }
    let (deadline, nonblocking) = recv_deadline(handle, want.flags)?;
    let peek = want.flags & MSG_PEEK != 0;
    // `sock_rcvlowat`: all of it under `MSG_WAITALL`, else `SO_RCVLOWAT`,
    // for a peek as for a receive (`tcp_recvmsg_locked`).
    let target = if want.flags & MSG_WAITALL != 0 {
        want.capacity
    } else {
        let lowat = sock(&lock_state(), handle)?.opts.rcvlowat.max(1) as usize;
        lowat.min(want.capacity)
    };
    let mut got: Vec<u8> = Vec::new();
    loop {
        let mut state = lock_state();
        let socket = sock_mut(&mut state, handle)?;
        let State::Established {
            socket: sid,
            ref key,
        } = as_inet(socket).state
        else {
            return Ok(done(got, want));
        };
        let key = key.clone();
        let inline = socket.opts.oobinline;
        // The urgent mark stops a receive before it (`tcp_recvmsg_locked`):
        // at the mark, a receive with bytes in hand ends, and one without
        // skips an urgent byte not kept inline.
        let mark = state
            .net
            .sockets
            .inet
            .streams
            .get(&key)
            .and_then(|pair| pair.received(handle).before_mark());
        let skip = mark == Some(0) && !inline;
        if mark == Some(0) && !peek {
            if !got.is_empty() {
                return Ok(done(got, want));
            }
            // An error, or nothing to skip yet, is the receive's own to
            // answer below.
            if skip {
                if let Ok(Some(skipped)) = with_context_raw(|context| context.net_tcp_recv(sid, 1))
                {
                    if let (false, Some(pair)) = (
                        skipped.is_empty(),
                        state.net.sockets.inet.streams.get_mut(&key),
                    ) {
                        pair.receiving(handle).took(1);
                        continue;
                    }
                }
            }
        }
        let room = |left: usize| match mark {
            Some(before) if before > 0 => left.min(usize::try_from(before).unwrap_or(left)),
            _ => left,
        };
        let taken = if peek {
            with_context_raw(|context| context.net_tcp_peek(sid, want.capacity + usize::from(skip)))
                .map(|bytes| {
                    bytes.and_then(|mut bytes| {
                        if skip && !bytes.is_empty() {
                            bytes.remove(0);
                            if bytes.is_empty() {
                                return None;
                            }
                        }
                        bytes.truncate(room(bytes.len()));
                        Some(bytes)
                    })
                })
        } else {
            with_context_raw(|context| context.net_tcp_recv(sid, room(want.capacity - got.len())))
        };
        match taken {
            // A peek sees everything queued, afresh each time it looks, and
            // ends at the mark.
            Ok(Some(bytes)) if !bytes.is_empty() && peek => {
                let reached = mark.is_some_and(|before| before > 0 && bytes.len() as u64 >= before);
                got = bytes;
                if reached {
                    return Ok(done(got, want));
                }
            }
            Ok(Some(bytes)) if !bytes.is_empty() => {
                let count = bytes.len();
                got.extend(bytes);
                let peer = state
                    .net
                    .sockets
                    .inet
                    .streams
                    .get_mut(&key)
                    .and_then(|pair| {
                        pair.receiving(handle).took(count);
                        pair.other(handle)
                    });
                let wakes = peer
                    .map(|peer| room_freed(&mut state, peer))
                    .unwrap_or_default();
                drop(state);
                wake_all(wakes);
                if got.len() >= target {
                    return Ok(done(got, want));
                }
                continue;
            }
            // End of stream.
            Ok(Some(_)) => return Ok(done(got, want)),
            Ok(None) => {}
            Err(errno) => {
                if errno == ECONNRESET {
                    let wakes = reset(&mut state, handle)?;
                    if !got.is_empty() {
                        sock_mut(&mut state, handle)?.error = ECONNRESET;
                    }
                    drop(state);
                    wake_all(wakes);
                }
                return if got.is_empty() {
                    Err(errno)
                } else {
                    Ok(done(got, want))
                };
            }
        }
        if peek && got.len() >= target {
            return Ok(done(got, want));
        }
        let socket = sock_mut(&mut state, handle)?;
        // With bytes in hand the receive ends, leaving a pending error for
        // the next (`tcp_recvmsg_locked` takes `sock_error` only with none).
        if !got.is_empty()
            && (nonblocking || socket.shutdown & RCV_SHUTDOWN != 0 || socket.error != 0)
        {
            return Ok(done(got, want));
        }
        if let Some(error) = socket.take_error() {
            return if got.is_empty() {
                Err(error)
            } else {
                Ok(done(got, want))
            };
        }
        if socket.shutdown & RCV_SHUTDOWN != 0 {
            return Ok(done(got, want));
        }
        if nonblocking || expired(deadline)? {
            return if got.is_empty() {
                Err(EWOULDBLOCK)
            } else {
                Ok(done(got, want))
            };
        }
        park_recv(state, handle, Some(sid), deadline, "tcp-recv")
            .or_else(|errno| if got.is_empty() { Err(errno) } else { Ok(()) })?;
    }
}

/// `tcp_recv_urg`: the urgent byte, out of band. With none arrived, one
/// already taken, or `SO_OOBINLINE`, `EINVAL`; a zero-length buffer takes it
/// as `MSG_TRUNC`; `MSG_PEEK` leaves it.
fn recv_urgent(handle: c_int, want: Want) -> Result<Incoming, c_int> {
    let mut state = lock_state();
    let socket = sock(&state, handle)?;
    let inline = socket.opts.oobinline;
    let State::Established {
        socket: sid,
        ref key,
    } = as_inet(socket).state
    else {
        return Err(EINVAL);
    };
    let key = key.clone();
    let pending = with_context_raw(|context| context.net_readiness(sid))?.pending;
    let Some(pair) = state.net.sockets.inet.streams.get_mut(&key) else {
        return Err(EINVAL);
    };
    let direction = pair.receiving(handle);
    let urgent = match direction.arrived(pending) {
        Some(urgent) if !inline && !urgent.read => urgent,
        _ => return Err(EINVAL),
    };
    if want.flags & MSG_PEEK == 0 {
        direction.urgent = Some(Urgent {
            read: true,
            ..urgent
        });
    }
    if want.capacity == 0 {
        return Ok(Incoming {
            flags: MSG_OOB | MSG_TRUNC,
            ..Incoming::default()
        });
    }
    Ok(Incoming {
        data: if want.flags & MSG_TRUNC != 0 {
            Vec::new()
        } else {
            vec![urgent.byte]
        },
        len: 1,
        flags: MSG_OOB,
        ..Incoming::default()
    })
}

/// A stream receive's answer: the bytes, discarded under `MSG_TRUNC`.
fn done(got: Vec<u8>, want: Want) -> Incoming {
    let len = got.len();
    Incoming {
        data: if want.flags & MSG_TRUNC != 0 {
            Vec::new()
        } else {
            got
        },
        len,
        ..Incoming::default()
    }
}

/// The kernel poll mask (`udp_poll`/`datagram_poll`, `tcp_poll`) and the
/// arrivals so far.
pub(super) fn poll(
    state: &ThreadRuntime,
    handle: c_int,
    socket: &Socket,
    inet: &Inet,
) -> (u32, u64) {
    let readiness =
        |sid: SocketId| with_context_raw(|context| context.net_readiness(sid)).unwrap_or_default();
    let mut mask = 0;
    if socket.error != 0 {
        mask |= POLLERR;
    }
    if !is_tcp(socket) {
        let ready = inet.udp.map(readiness).unwrap_or_default();
        if socket.shutdown & RCV_SHUTDOWN != 0 {
            mask |= POLLRDHUP | POLLIN | POLLRDNORM;
        }
        if socket.shutdown == SHUTDOWN_MASK {
            mask |= POLLHUP;
        }
        if ready.readable {
            mask |= POLLIN | POLLRDNORM;
        }
        return (mask | POLLOUT | POLLWRNORM | POLLWRBAND, ready.arrivals);
    }
    match inet.state {
        State::Listening { socket: sid, .. } => {
            if readiness(sid).readable {
                mask |= POLLIN | POLLRDNORM;
            }
            (mask, inet.accepts)
        }
        State::Closed => {
            if socket.shutdown & RCV_SHUTDOWN != 0 {
                mask |= POLLIN | POLLRDNORM | POLLRDHUP;
            }
            (mask | POLLHUP | POLLOUT | POLLWRNORM, 0)
        }
        State::Established {
            socket: sid,
            ref key,
        } => {
            let ready = readiness(sid);
            let direction = state
                .net
                .sockets
                .inet
                .streams
                .get(key)
                .map(|pair| pair.received(handle))
                .unwrap_or_default();
            let urgent = direction.arrived(ready.pending);
            // `tcp_poll`: at the mark the urgent byte out of line is not
            // data, so one more byte must wait; an urgent byte not yet
            // taken is `EPOLLPRI`.
            let at_mark = urgent.is_some_and(|urgent| urgent.at == direction.taken);
            let needed = socket.opts.rcvlowat.max(1) as usize
                + usize::from(at_mark && !socket.opts.oobinline);
            if urgent.is_some_and(|urgent| !urgent.read) {
                mask |= POLLPRI;
            }
            let mut shutdown = socket.shutdown;
            if ready.peer_write_closed {
                shutdown |= RCV_SHUTDOWN;
            }
            if ready.reset {
                shutdown = SHUTDOWN_MASK;
                mask |= POLLERR;
            }
            if shutdown == SHUTDOWN_MASK {
                mask |= POLLHUP;
            }
            if shutdown & RCV_SHUTDOWN != 0 {
                mask |= POLLIN | POLLRDNORM | POLLRDHUP;
            }
            // `tcp_stream_is_readable`: as much as `SO_RCVLOWAT` asks.
            if ready.pending >= needed {
                mask |= POLLIN | POLLRDNORM;
            }
            if shutdown & SEND_SHUTDOWN != 0 || ready.writable {
                mask |= POLLOUT | POLLWRNORM;
            }
            (mask, ready.arrivals)
        }
    }
}

/// `SIOCINQ`: the next datagram's length, or a stream's queued bytes.
pub(super) fn pending(socket: &Socket, inet: &Inet) -> Result<i32, c_int> {
    let readiness = |sid: SocketId| {
        with_context_raw(|context| context.net_readiness(sid)).map(|ready| ready.pending)
    };
    let pending = match (&inet.state, inet.udp) {
        (State::Listening { .. }, _) => return Err(EINVAL),
        (State::Established { socket: sid, .. }, _) => readiness(*sid)?,
        (State::Closed, Some(udp)) if !is_tcp(socket) => readiness(udp)?,
        (State::Closed, _) => 0,
    };
    Ok(i32::try_from(pending).unwrap_or(i32::MAX))
}

#[cfg(test)]
mod tests {
    use super::{Direction, Urgent};

    #[test]
    fn the_urgent_byte_stops_a_receive_arrives_with_its_byte_and_goes_once_passed() {
        let mut direction = Direction {
            written: 4,
            taken: 0,
            urgent: Some(Urgent {
                at: 3,
                byte: b'!',
                read: false,
            }),
        };
        // Three bytes before the mark; the mark is known once its byte is in.
        assert_eq!(direction.before_mark(), Some(3));
        assert!(direction.arrived(3).is_none());
        assert!(direction.arrived(4).is_some());
        direction.took(3);
        assert_eq!(direction.before_mark(), Some(0));
        assert!(direction.urgent.is_some());
        // Taking the byte itself (skipped, or read inline) passes the mark.
        direction.took(1);
        assert!(direction.urgent.is_none());
        assert_eq!(direction.before_mark(), None);
    }
}
