//! SUD rows — network (SimNet): sockets, addresses, connect/accept, datagram and
//! stream transfer, shutdown, socket options, and `socketpair`, each the exact
//! entry the C socket interposers call.

use super::*;

// ---- Network (SimNet) ----

/// Parse a guest `struct sockaddr_in` (AF_INET only). Returns `(ip, port)` in
/// host byte order, mirroring the C `patina_parse_sockaddr`.
pub(super) fn parse_sockaddr(addr: u64, len: u32) -> Option<(u32, u16)> {
    if addr == 0 || (len as usize) < core::mem::size_of::<SockaddrIn>() {
        return None;
    }
    // SAFETY: `addr` points to at least `sizeof(sockaddr_in)` guest bytes.
    let sa = unsafe { (addr as *const SockaddrIn).read_unaligned() };
    if sa.sin_family != AF_INET {
        return None;
    }
    Some((u32::from_be(sa.sin_addr), u16::from_be(sa.sin_port)))
}

/// Fill a guest `struct sockaddr_in` and update its length in/out pointer,
/// mirroring the C `patina_fill_sockaddr`.
pub(super) fn fill_sockaddr(addr: u64, len_ptr: u64, ip: u32, port: u16) {
    if addr == 0 || len_ptr == 0 {
        return;
    }
    let sa = SockaddrIn {
        sin_family: AF_INET,
        sin_port: port.to_be(),
        sin_addr: ip.to_be(),
        sin_zero: [0; 8],
    };
    // SAFETY: `len_ptr` is a writable socklen_t; `addr` is writable for `copy`.
    unsafe {
        let provided = (len_ptr as *const u32).read();
        let full = core::mem::size_of::<SockaddrIn>() as u32;
        let copy = provided.min(full) as usize;
        std::ptr::copy_nonoverlapping(
            (&sa as *const SockaddrIn).cast::<u8>(),
            addr as *mut u8,
            copy,
        );
        (len_ptr as *mut u32).write(full);
    }
}

pub(super) fn sys_socket(domain: u64, ty: u64, protocol: u64) -> i64 {
    if domain as u16 != AF_INET {
        return -EAFNOSUPPORT;
    }
    let mut base = ty;
    let mut nonblocking = 0;
    if base & SOCK_NONBLOCK != 0 {
        nonblocking = 1;
        base &= !SOCK_NONBLOCK;
    }
    let cloexec = c_int::from(base & SOCK_CLOEXEC != 0);
    base &= !SOCK_CLOEXEC;
    let stream = if base == SOCK_DGRAM {
        if protocol != 0 && protocol != IPPROTO_UDP {
            return -EPROTONOSUPPORT;
        }
        0
    } else if base == SOCK_STREAM {
        if protocol != 0 && protocol != IPPROTO_TCP {
            return -EPROTONOSUPPORT;
        }
        1
    } else {
        return -EPROTOTYPE;
    };
    // SAFETY: no pointers.
    ret_i32(unsafe { patina_net_socket(stream, nonblocking, cloexec) })
}

/// The kind checks the socket family needs before the class entries, mirroring
/// the C `patina_socket_or_pair`: a number that names nothing is `EBADF`, one
/// that names anything but a socket or a socketpair endpoint is `ENOTSOCK`.
/// `Ok(true)` is a pipe/socketpair endpoint (whose send/recv are the pipe
/// transfer), `Ok(false)` a socket.
pub(super) fn socket_or_pair(fd: i64) -> Result<bool, i64> {
    match fd_kind(fd) {
        None => Err(-EBADF),
        Some(PATINA_FD_PIPE) => Ok(true),
        Some(PATINA_FD_SOCKET) => Ok(false),
        Some(_) => Err(-ENOTSOCK),
    }
}

pub(super) fn sys_bind(fd: i64, addr: u64, len: u32) -> i64 {
    let Some((ip, port)) = parse_sockaddr(addr, len) else {
        return -EAFNOSUPPORT;
    };
    // SAFETY: no pointers.
    ret_i32(unsafe { patina_net_bind(fd as c_int, ip, port) })
}

pub(super) fn sys_listen(fd: i64, backlog: i64) -> i64 {
    // SAFETY: no pointers.
    ret_i32(unsafe { patina_net_listen(fd as c_int, backlog as c_int) })
}

pub(super) fn sys_connect(fd: i64, addr: u64, len: u32) -> i64 {
    let Some((ip, port)) = parse_sockaddr(addr, len) else {
        return -EAFNOSUPPORT;
    };
    let cfd = fd as c_int;
    // SAFETY: no pointers.
    unsafe {
        match patina_net_kind(cfd) {
            3 => -EISCONN,
            1 => ret_i32(patina_net_tcp_connect(cfd, ip, port)),
            2 => -EOPNOTSUPP,
            // A datagram socket, or not a socket at all: the entry answers
            // EBADF/ENOTSOCK from the descriptor table.
            _ => ret_i32(patina_net_connect(cfd, ip, port)),
        }
    }
}

pub(super) fn sys_accept(fd: i64, addr: u64, len_ptr: u64, flags: u64) -> i64 {
    // accept4 flags: only SOCK_CLOEXEC / SOCK_NONBLOCK are meaningful, and they
    // describe the NEW descriptor.
    if flags & !(SOCK_CLOEXEC | SOCK_NONBLOCK) != 0 {
        return -EINVAL;
    }
    let mut ip: u32 = 0;
    let mut port: u16 = 0;
    // SAFETY: writable local storage.
    let accepted = unsafe {
        patina_net_accept(
            fd as c_int,
            &mut ip,
            &mut port,
            c_int::from(flags & SOCK_NONBLOCK != 0),
            c_int::from(flags & SOCK_CLOEXEC != 0),
        )
    };
    if accepted < 0 {
        // SAFETY: plain thread-local read.
        return -(unsafe { patina_errno() } as i64);
    }
    fill_sockaddr(addr, len_ptr, ip, port);
    accepted as i64
}

/// Whether the send/recv flags are all no-ops on a virtual socket (only
/// MSG_NOSIGNAL is tolerated), mirroring the C `patina_stream_flags_supported`.
pub(super) fn stream_flags_supported(flags: u64) -> bool {
    flags & !MSG_NOSIGNAL == 0
}

pub(super) fn sys_sendto(fd: i64, buf: u64, len: u64, flags: u64, addr: u64, alen: u32) -> i64 {
    let cfd = fd as c_int;
    let src = buf as *const c_void;
    let n = len as usize;
    let pair = match socket_or_pair(fd) {
        Ok(pair) => pair,
        Err(errno) => return errno,
    };
    if pair {
        if addr != 0 {
            return -EISCONN;
        }
        if !stream_flags_supported(flags) {
            return -EOPNOTSUPP;
        }
        // SAFETY: `buf`/`len` describe a guest buffer.
        return ret_isize(unsafe { patina_pipe_write(cfd, src, n, flags as c_int) });
    }
    // SAFETY: no pointers.
    let kind = unsafe { patina_net_kind(cfd) };
    if kind == 3 {
        if addr != 0 {
            return -EISCONN;
        }
        if !stream_flags_supported(flags) {
            return -EOPNOTSUPP;
        }
        // SAFETY: as above.
        return ret_isize(unsafe { patina_net_stream_send(cfd, src, n, flags as c_int) });
    }
    if addr != 0 {
        let Some((ip, port)) = parse_sockaddr(addr, alen) else {
            return -EAFNOSUPPORT;
        };
        // SAFETY: as above.
        return ret_isize(unsafe { patina_net_sendto(cfd, src, n, ip, port) });
    }
    // SAFETY: as above.
    ret_isize(unsafe { patina_net_send(cfd, src, n) })
}

pub(super) fn sys_recvfrom(fd: i64, buf: u64, len: u64, flags: u64, addr: u64, alen: u64) -> i64 {
    let cfd = fd as c_int;
    let dst = buf as *mut c_void;
    let n = len as usize;
    let pair = match socket_or_pair(fd) {
        Ok(pair) => pair,
        Err(errno) => return errno,
    };
    if pair {
        if !stream_flags_supported(flags) {
            return -EOPNOTSUPP;
        }
        // SAFETY: `buf`/`len` describe a guest buffer.
        return ret_isize(unsafe { patina_pipe_read(cfd, dst, n) });
    }
    // SAFETY: no pointers.
    let kind = unsafe { patina_net_kind(cfd) };
    if kind == 3 {
        if addr != 0 {
            return -EISCONN;
        }
        if !stream_flags_supported(flags) {
            return -EOPNOTSUPP;
        }
        // SAFETY: as above.
        return ret_isize(unsafe { patina_net_stream_recv(cfd, dst, n) });
    }
    let mut ip: u32 = 0;
    let mut port: u16 = 0;
    // SAFETY: `buf`/`len` describe a guest buffer; ip/port are local storage.
    let result = ret_isize(unsafe { patina_net_recvfrom(cfd, dst, n, &mut ip, &mut port) });
    if result >= 0 && addr != 0 {
        fill_sockaddr(addr, alen, ip, port);
    }
    result
}

/// `sendmsg`/`recvmsg` mirror the C interposers EXACTLY: the deterministic net
/// layer models only `sendto`/`recvfrom` (routed through `patina_net_*`), and
/// the C `sendmsg`/`recvmsg` strong defs fail closed with `ENOSYS` — no
/// supported guest uses the scatter-gather/ancillary variants. So the SUD rows
/// refuse them identically. This is deliberately NOT a per-iovec `sendto` loop:
/// a datagram socket coalesces the iovec array into ONE datagram, so per-iovec
/// sends would fragment one message into N — a *silently-wrong* semantics that
/// house doctrine forbids (fail-closed beats silently-wrong). Refusing with the
/// same `ENOSYS` the interposer returns keeps the two vehicles byte-identical
/// and closes the fragmentation hole.
pub(super) fn sys_sendmsg(_fd: i64, _msg: u64, _flags: u64) -> i64 {
    -ENOSYS
}

pub(super) fn sys_recvmsg(_fd: i64, _msg: u64, _flags: u64) -> i64 {
    -ENOSYS
}

pub(super) fn sys_shutdown(fd: i64, how: u64) -> i64 {
    let patina_how = match how {
        SHUT_RD => 0,
        SHUT_WR => 1,
        SHUT_RDWR => 2,
        _ => return -EINVAL,
    };
    // SAFETY: no pointers.
    ret_i32(unsafe { patina_net_shutdown(fd as c_int, patina_how) })
}

pub(super) fn sys_getsockname(fd: i64, addr: u64, len_ptr: u64) -> i64 {
    let mut ip: u32 = 0;
    let mut port: u16 = 0;
    // SAFETY: local storage.
    if unsafe { patina_net_getsockname(fd as c_int, &mut ip, &mut port) } != 0 {
        // SAFETY: plain thread-local read.
        return -(unsafe { patina_errno() } as i64);
    }
    fill_sockaddr(addr, len_ptr, ip, port);
    0
}

pub(super) fn sys_getpeername(fd: i64, addr: u64, len_ptr: u64) -> i64 {
    let mut ip: u32 = 0;
    let mut port: u16 = 0;
    // SAFETY: local storage.
    if unsafe { patina_net_getpeername(fd as c_int, &mut ip, &mut port) } != 0 {
        // SAFETY: plain thread-local read.
        return -(unsafe { patina_errno() } as i64);
    }
    fill_sockaddr(addr, len_ptr, ip, port);
    0
}

/// Whether `optval` points to a zero `struct timeval` (POSIX "no timeout"),
/// mirroring the C `patina_zero_timeval`. A null/short buffer is not zero.
pub(super) fn timeval_is_zero(value: u64, len: u32) -> bool {
    if value == 0 || (len as usize) < core::mem::size_of::<[i64; 2]>() {
        return false;
    }
    // SAFETY: `value` points to a `struct timeval { tv_sec: i64, tv_usec: i64 }`.
    unsafe {
        let p = value as *const i64;
        p.read() == 0 && p.add(1).read() == 0
    }
}

pub(super) fn sys_setsockopt(fd: i64, level: u64, optname: u64, value: u64, len: u32) -> i64 {
    // A socketpair endpoint is a socket for the option calls: the same
    // deterministic no-op answers (mirrors the C interposer).
    if let Err(errno) = socket_or_pair(fd) {
        return errno;
    }
    if level == SOL_SOCKET {
        match optname {
            SO_REUSEADDR | SO_REUSEPORT | SO_KEEPALIVE | SO_BROADCAST => return 0,
            SO_LINGER => {
                // Accept only linger-off (l_onoff == 0), like the C interposer.
                if value != 0 && (len as usize) >= 4 {
                    // SAFETY: `value` points to `struct linger`; l_onoff is its first int.
                    if unsafe { (value as *const i32).read() } == 0 {
                        return 0;
                    }
                }
            }
            SO_RCVTIMEO => {
                // struct timeval { tv_sec: i64, tv_usec: i64 } on 64-bit Linux.
                if value != 0 && (len as usize) >= 16 {
                    // SAFETY: `value` points to a `struct timeval`.
                    let (sec, usec) = unsafe {
                        let p = value as *const i64;
                        (p.read(), p.add(1).read())
                    };
                    let nanos = sec as u64 * NANOS_PER_SEC + usec as u64 * 1000;
                    // SAFETY: no pointers.
                    return ret_i32(unsafe { patina_net_set_read_timeout(fd as c_int, nanos) });
                }
            }
            // Only the no-op zero timeval is accepted (sends never block); a
            // non-zero send timeout falls through to ENOPROTOOPT below.
            SO_SNDTIMEO if timeval_is_zero(value, len) => return 0,
            _ => {}
        }
    }
    if level == IPPROTO_TCP && optname == TCP_NODELAY {
        return 0;
    }
    -ENOPROTOOPT
}

pub(super) fn sys_getsockopt(fd: i64, value: u64, len_ptr: u64) -> i64 {
    if let Err(errno) = socket_or_pair(fd) {
        return errno;
    }
    // Mirror the C getsockopt: zero the caller's buffer, report success.
    if value != 0 && len_ptr != 0 {
        // SAFETY: `len_ptr` is a socklen_t; `value` is writable for that many bytes.
        unsafe {
            let n = (len_ptr as *const u32).read() as usize;
            std::ptr::write_bytes(value as *mut u8, 0, n);
        }
    }
    0
}

/// `socketpair(2)`. Mirrors the C `socketpair` interposer (patina_posix.c) field
/// for field: only an `AF_UNIX` `SOCK_STREAM` pair (protocol 0) is a
/// deterministic in-process duplex; `SOCK_NONBLOCK`/`SOCK_CLOEXEC` are stripped
/// before the base-type check and carried to the two new descriptors. The two descriptors are written into the guest's
/// `int sv[2]` on success.
pub(super) fn sys_socketpair(domain: u64, sock_type: u64, protocol: u64, sv: u64) -> i64 {
    if sv == 0 {
        return -EFAULT;
    }
    if domain as i32 as i64 != AF_UNIX {
        return -EAFNOSUPPORT;
    }
    let type_bits = sock_type as i32 as i64;
    let nonblocking = (type_bits & SOCK_NONBLOCK as i64 != 0) as c_int;
    let cloexec = (type_bits & SOCK_CLOEXEC as i64 != 0) as c_int;
    let base = type_bits & !((SOCK_NONBLOCK | SOCK_CLOEXEC) as i64);
    if base != SOCK_STREAM as i64 {
        return -EOPNOTSUPP;
    }
    if protocol as i32 != 0 {
        return -EPROTONOSUPPORT;
    }
    let mut fd0: c_int = 0;
    let mut fd1: c_int = 0;
    // SAFETY: local writable storage for the pair.
    let rc = unsafe { patina_socketpair(&mut fd0, &mut fd1, nonblocking, cloexec) };
    if rc != 0 {
        // SAFETY: plain thread-local read.
        return -(unsafe { patina_errno() } as i64);
    }
    // SAFETY: `sv` is the guest's `int[2]`.
    unsafe {
        let out = sv as *mut c_int;
        out.write(fd0);
        out.add(1).write(fd1);
    }
    0
}
