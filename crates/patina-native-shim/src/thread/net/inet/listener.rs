//! Internet listen, accept, name, shutdown, and close lifecycle.

use super::*;

/// `listen(2)` (`inet_listen`): an unbound socket takes an ephemeral port; a
/// listener only takes the new backlog.
pub(in crate::thread::net) fn listen(handle: c_int, backlog: i32) -> Result<(), c_int> {
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
pub(in crate::thread::net) fn listening(state: &ThreadRuntime, handle: c_int) -> bool {
    state.net.sockets.table.get(&handle).is_some_and(|socket| {
        matches!(&socket.proto, Proto::Inet(inet) if matches!(inet.state, State::Listening { .. }))
    })
}

/// `accept4(2)` (`inet_csk_accept`): the new socket's handle and its peer's
/// name.
pub(in crate::thread::net) fn accept(
    handle: c_int,
    nonblocking: bool,
) -> Result<(c_int, Vec<u8>), c_int> {
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
pub(super) fn adopt(
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
    let pair = state
        .net
        .sockets
        .inet
        .streams
        .entry(accepted.peer)
        .or_default();
    pair.server = Some(handle);
    pair.backlog = None;
    (handle, encode(v6, peer, V6Extra::default()))
}

/// `getsockname`/`getpeername` (`inet_getname`, `inet6_getname`).
pub(in crate::thread::net) fn name(
    socket: &Socket,
    inet: &Inet,
    peer: bool,
) -> Result<Vec<u8>, c_int> {
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
pub(in crate::thread::net) fn shutdown(handle: c_int, bits: u8) -> Result<(), c_int> {
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
        listener_closed(&mut state.net.sockets.inet, handle);
        with_context_raw(|context| context.net_close(sid))?;
    }
    let wakes = waiters(&mut state, handle, Dir::Recv);
    drop(state);
    wake_all(wakes);
    Ok(())
}

/// Take `handle`'s side out of the connection `key`, answering the peer's
/// waiters to wake.
pub(super) fn drop_stream(state: &mut ThreadRuntime, handle: c_int, key: &str) -> Vec<TaskId> {
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
    if pair.client.is_none() && pair.server.is_none() && pair.backlog.is_none() {
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
pub(super) fn reset(state: &mut ThreadRuntime, handle: c_int) -> Result<Vec<TaskId>, c_int> {
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
pub(in crate::thread::net) fn close(
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
            listener_closed(&mut state.net.sockets.inet, handle);
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
