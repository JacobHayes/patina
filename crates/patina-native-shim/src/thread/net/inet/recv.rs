//! Internet datagram, stream, and urgent receive paths.

use super::*;

/// Receive one message (`udp_recvmsg`, `tcp_recvmsg_locked`).
pub(in crate::thread::net) fn recv(handle: c_int, want: Want) -> Result<Incoming, c_int> {
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

pub(super) fn recv_stream(handle: c_int, want: Want) -> Result<Incoming, c_int> {
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
            if skip
                && let Ok(Some(skipped)) = with_context_raw(|context| context.net_tcp_recv(sid, 1))
                && let (false, Some(pair)) = (
                    skipped.is_empty(),
                    state.net.sockets.inet.streams.get_mut(&key),
                )
            {
                pair.receiving(handle).took(1);
                continue;
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
pub(super) fn done(got: Vec<u8>, want: Want) -> Incoming {
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
