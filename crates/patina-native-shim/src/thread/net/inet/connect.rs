//! Internet socket binding and connection setup.

use super::*;

/// `bind(2)` (`__inet_bind`, `__inet6_bind`).
pub(in crate::thread::net) fn bind(handle: c_int, bytes: &[u8]) -> Result<(), c_int> {
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
pub(in crate::thread::net) fn connect(
    handle: c_int,
    bytes: &[u8],
    nonblocking: bool,
) -> Result<(), c_int> {
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
pub(super) fn connect_datagram(handle: c_int, bytes: &[u8]) -> Result<(), c_int> {
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

pub(super) fn is_broadcast(ip: IpAddr) -> bool {
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
    // Connections are told apart by the client's address: a second one from
    // an address an earlier connection still holds (open, or waiting in a
    // backlog) cannot be.
    if state.net.sockets.inet.streams.contains_key(&key) {
        fatal(
            "a TCP connection from an address an earlier connection still holds (open, or \
             waiting in a listener's backlog) is not modeled; failing closed",
        );
    }
    let backlog = listener_at(&state, &to);
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
            state.net.sockets.inet.streams.insert(
                key,
                Pair {
                    client: Some(handle),
                    backlog,
                    ..Pair::default()
                },
            );
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
/// The listener a connection to `to` reaches, if one listens here.
fn listener_at(state: &ThreadRuntime, to: &str) -> Option<c_int> {
    std::iter::once(to.to_owned())
        .chain(wildcard_bind_keys(to))
        .find_map(|address| state.net.sockets.inet.listeners.get(&address).copied())
}

/// Listener `listener` closed: the connections still in its backlog are
/// gone with it (`inet_csk_listen_stop`), once neither side holds them.
pub(super) fn listener_closed(tables: &mut Tables, listener: c_int) {
    tables.streams.retain(|_, pair| {
        if pair.backlog == Some(listener) {
            pair.backlog = None;
        }
        pair.client.is_some() || pair.server.is_some() || pair.backlog.is_some()
    });
}

fn wake_listener(state: &mut ThreadRuntime, to: &str) -> Vec<TaskId> {
    let Some(listener) = listener_at(state, to) else {
        return Vec::new();
    };
    if let Some(socket) = state.net.sockets.table.get_mut(&listener) {
        as_inet_mut(socket).accepts += 1;
    }
    waiters(state, listener, Dir::Recv)
}
