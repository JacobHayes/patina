//! Internet datagram and stream send paths.

use super::*;

/// Send one message (`udp_sendmsg`, `tcp_sendmsg_locked`).
pub(in crate::thread::net) fn send(handle: c_int, message: Outgoing) -> Result<usize, c_int> {
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
pub(super) fn send_stream(handle: c_int, message: Outgoing) -> Result<usize, c_int> {
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
                if message.flags & MSG_OOB != 0 && sent > 0 {
                    // `tcp_sendmsg_locked` pushes with `MSG_OOB` before it
                    // waits, marking the last byte sent so far urgent too.
                    fatal(
                        "a MSG_OOB send that waits for room after sending part of its bytes \
                         (an urgent mark at each wait) is not modeled; failing closed",
                    );
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
