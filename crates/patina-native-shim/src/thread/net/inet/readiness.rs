//! Internet socket readiness and pending-byte queries.

use super::*;

/// The kernel poll mask (`udp_poll`/`datagram_poll`, `tcp_poll`) and the
/// arrivals so far.
pub(in crate::thread::net) fn poll(
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
/// `SIOCATMARK` (`tcp_ioctl`): whether the urgent byte has arrived and the
/// next byte a receive would take is it; never for a socket not connected.
#[cfg(target_os = "linux")]
pub(in crate::thread::net) fn at_mark(
    state: &ThreadRuntime,
    handle: c_int,
    inet: &Inet,
) -> Result<bool, c_int> {
    let State::Established {
        socket: sid,
        ref key,
    } = inet.state
    else {
        return Ok(false);
    };
    let pending = with_context_raw(|context| context.net_readiness(sid))?.pending;
    let direction = state
        .net
        .sockets
        .inet
        .streams
        .get(key)
        .map(|pair| pair.received(handle))
        .unwrap_or_default();
    Ok(direction
        .arrived(pending)
        .is_some_and(|urgent| urgent.at == direction.taken))
}

pub(in crate::thread::net) fn pending(socket: &Socket, inet: &Inet) -> Result<i32, c_int> {
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
