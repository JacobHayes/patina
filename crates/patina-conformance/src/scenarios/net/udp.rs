//! net/udp — socket / bind / sendto / recvfrom / getsockname / getpeername /
//! connect / shutdown / setsockopt / getsockopt over loopback UDP: datagram
//! boundaries, truncation, MSG_PEEK, non-blocking EAGAIN, the 4-tuple a
//! connected socket receives by (ahead of an unconnected socket bound at the
//! exact address, and until an `AF_UNSPEC` disconnect), the source a
//! wildcard-bound socket is bound at once connected, and the errno
//! vocabulary.

use crate::catalog::{DEFAULTS, Scenario};
use patina_dst_syscalls::Syscall;

use crate::probe::{AT_FDCWD, Probe, SockAddr, neg};
use crate::scenarios::net::{check_allocated_port, int};
use libc::*;
use std::net::{Ipv4Addr, SocketAddrV4};

const ANY: SockAddr = SockAddr::v4(0);

pub fn run(p: &Probe) {
    let root = p.dir();
    let a = p.socket(AF_INET, SOCK_DGRAM, 0);
    p.require("socket a", a >= 0);
    p.check("bind a to an ephemeral port", p.bind_to(a, &ANY) == 0);
    let (r, addr_a, _) = p.name_of(a, false, 128);
    p.require("getsockname a", r == 0 && addr_a.is_some());
    let addr_a = addr_a.unwrap();
    let b = p.socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    p.require("socket b", b >= 0);
    p.check("bind b", p.bind_to(b, &ANY) == 0);
    let (_, addr_b, _) = p.name_of(b, false, 128);
    let addr_b = addr_b.expect("getsockname b");

    p.check(
        "sendto a -> b",
        p.send_to(a, b"ping", 0, Some(&addr_b)) == 4,
    );
    let (n, data, src) = p.recv_from(b, 64, 0, true);
    p.check(
        "b receives the datagram from a's address",
        n == 4 && data == b"ping" && src.as_ref() == Some(&addr_a),
    );
    p.check(
        "a second non-blocking recvfrom is EAGAIN",
        p.recv_from(b, 64, 0, true).0 == neg(EAGAIN),
    );
    p.check(
        "sendto b -> a",
        p.send_to(b, b"pong", 0, Some(&addr_a)) == 4,
    );
    let (n, data, _) = p.recv_from(a, 2, 0, true);
    p.check(
        "a short buffer truncates the datagram",
        n == 2 && data == b"po",
    );
    p.check(
        "the truncated tail is discarded",
        p.recv_from(a, 64, MSG_DONTWAIT, false).0 == neg(EAGAIN),
    );
    p.send_to(b, b"peek", 0, Some(&addr_a));
    let (n, _, _) = p.recv_from(a, 64, MSG_PEEK, false);
    p.check("MSG_PEEK returns the datagram", n == 4);
    let (n, data, _) = p.recv_from(a, 64, 0, false);
    p.check(
        "the peeked datagram is still there",
        n == 4 && data == b"peek",
    );
    p.check(
        "MSG_TRUNC reports the full length",
        p.send_to(b, b"truncated", 0, Some(&addr_a)) == 9
            && p.recv_from(a, 4, MSG_TRUNC, false).0 == 9,
    );

    p.check("connect a to b", p.connect_to(a, &addr_b) == 0);
    let (r, peer, _) = p.name_of(a, true, 128);
    p.check(
        "getpeername reports b",
        r == 0 && peer.as_ref() == Some(&addr_b),
    );
    p.check(
        "send without an address on a connected socket",
        p.send_to(a, b"c", 0, None) == 1,
    );
    let (n, _, src) = p.recv_from(b, 64, 0, true);
    p.check(
        "b receives it from a",
        n == 1 && src.as_ref() == Some(&addr_a),
    );
    p.check(
        "shutdown SHUT_WR on a connected datagram socket",
        p.shutdown(a, SHUT_WR) == 0,
    );

    let c = p.socket(AF_INET, SOCK_DGRAM, 0);
    p.require("socket c", c >= 0);
    p.check(
        "bind an already-bound socket is EINVAL",
        p.bind_to(b, &ANY) == neg(EINVAL),
    );
    p.check(
        "bind to a port in use is EADDRINUSE",
        p.bind_to(c, &addr_a) == neg(EADDRINUSE),
    );
    p.check(
        "setsockopt SO_REUSEADDR",
        p.setsockopt_bytes(c, SOL_SOCKET, SO_REUSEADDR, &int(1), 4, "1") == 0,
    );
    p.check(
        "SO_REUSEADDR on one side only is still EADDRINUSE",
        p.bind_to(c, &addr_a) == neg(EADDRINUSE),
    );
    p.check(
        "bind with the wrong family is EAFNOSUPPORT",
        p.bind_to(
            c,
            &SockAddr::Raw {
                family: AF_INET6 as u16,
                len: size_of::<sockaddr_in>(),
            },
        ) == neg(EAFNOSUPPORT),
    );
    p.check(
        "bind with a short address is EINVAL",
        p.bind_to(
            c,
            &SockAddr::Raw {
                family: AF_INET as u16,
                len: 8,
            },
        ) == neg(EINVAL),
    );
    p.check(
        "sendto without an address on an unconnected socket is EDESTADDRREQ",
        p.send_to(c, b"z", 0, None) == neg(EDESTADDRREQ),
    );
    // c gives SO_REUSEADDR up before it takes a port: w, below, binds port
    // 0 with SO_REUSEADDR and could otherwise draw c's port, which the host
    // lets two reusing sockets share (scenarios/net.rs, "Port identity").
    p.check(
        "clear SO_REUSEADDR on c",
        p.setsockopt_bytes(c, SOL_SOCKET, SO_REUSEADDR, &int(0), 4, "0") == 0,
    );
    p.check(
        "sendto autobinds an unbound socket",
        p.send_to(c, b"z", 0, Some(&addr_b)) == 1,
    );
    let (r, addr_c, _) = p.name_of(c, false, 128);
    p.check(
        "the autobound port is non-zero",
        r == 0 && addr_c.and_then(|a| a.port()).is_some_and(|port| port != 0),
    );
    let (n, _, _) = p.recv_from(b, 64, 0, true);
    p.check("b received the autobound send", n == 1);
    p.check(
        "a datagram to nobody is still sent",
        p.send_to(c, b"nobody", 0, Some(&SockAddr::v4(9))) == 6,
    );
    let d = p.socket(AF_INET, SOCK_DGRAM, 0);
    p.require("socket d", d >= 0);
    p.check(
        "shutdown on an unconnected datagram socket is ENOTCONN",
        p.shutdown(d, SHUT_RDWR) == neg(ENOTCONN),
    );
    // Even a refused shutdown marks the socket: a later send is EPIPE.
    p.check(
        "send after the refused shutdown is EPIPE",
        p.send_to(d, b"z", 0, Some(&addr_b)) == neg(EPIPE),
    );

    p.check(
        "socket with a protocol that does not match the type is EPROTONOSUPPORT",
        i64::from(p.socket(AF_INET, SOCK_DGRAM, IPPROTO_TCP)) == neg(EPROTONOSUPPORT),
    );
    p.check(
        "socket with an unknown family is EAFNOSUPPORT",
        i64::from(p.socket(999, SOCK_DGRAM, 0)) == neg(EAFNOSUPPORT),
    );
    p.check(
        "socket with an unknown type is EINVAL",
        i64::from(p.socket(AF_INET, 999, 0)) == neg(EINVAL),
    );
    p.check(
        "listen on a datagram socket is EOPNOTSUPP",
        p.listen(a, 1) == neg(EOPNOTSUPP),
    );
    p.check(
        "accept4 on a datagram socket is EOPNOTSUPP",
        i64::from(p.accept_from(a, 0, false, true).0) == neg(EOPNOTSUPP),
    );

    // A connected datagram socket is found by its whole 4-tuple
    // (`compute_score`): its peer's datagrams reach it, a third socket's do
    // not.
    let e = p.socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    p.require("socket e", e >= 0);
    p.check("bind e", p.bind_to(e, &ANY) == 0);
    let (_, addr_e, _) = p.name_of(e, false, 128);
    let addr_e = addr_e.expect("getsockname e");
    let f = p.socket(AF_INET, SOCK_DGRAM, 0);
    p.require("socket f", f >= 0);
    p.check("bind f", p.bind_to(f, &ANY) == 0);
    let (_, addr_f, _) = p.name_of(f, false, 128);
    let addr_f = addr_f.expect("getsockname f");
    let g = p.socket(AF_INET, SOCK_DGRAM, 0);
    p.require("socket g", g >= 0);
    p.check("connect e to f", p.connect_to(e, &addr_f) == 0);
    p.check(
        "g sends to e",
        p.send_to(g, b"stranger", 0, Some(&addr_e)) == 8,
    );
    p.check(
        "a datagram from another socket does not reach the connected e",
        p.recv_from(e, 64, 0, true).0 == neg(EAGAIN),
    );
    p.check("f sends to e", p.send_to(f, b"peer", 0, Some(&addr_e)) == 4);
    let (n, data, _) = p.recv_from(e, 64, 0, true);
    p.check("the peer's datagram does", n == 4 && data == b"peer");
    // `__udp_disconnect`: a port the kernel chose is given up (the socket
    // reads unbound at its address); one bound by number stays, and the
    // socket takes a stranger's datagrams again.
    let unspec = SockAddr::Raw {
        family: AF_UNSPEC as u16,
        len: 16,
    };
    p.check("disconnect e with AF_UNSPEC", p.connect_to(e, &unspec) == 0);
    let (_, after, _) = p.name_of(e, false, 128);
    p.check("the port the kernel chose is given up", after == Some(ANY));
    let k = p.socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    p.require("socket k", k >= 0);
    p.check("bind k to that port by number", p.bind_to(k, &addr_e) == 0);
    p.check("connect k to f", p.connect_to(k, &addr_f) == 0);
    p.check(
        "g sends to k",
        p.send_to(g, b"early", 0, Some(&addr_e)) == 5,
    );
    p.check(
        "the connected k does not take it",
        p.recv_from(k, 64, 0, true).0 == neg(EAGAIN),
    );
    p.check("disconnect k", p.connect_to(k, &unspec) == 0);
    let (_, after, _) = p.name_of(k, false, 128);
    p.check(
        "a port bound by number stays",
        after == Some(addr_e.clone()),
    );
    p.check(
        "g sends to k again",
        p.send_to(g, b"again", 0, Some(&addr_e)) == 5,
    );
    let (n, data, _) = p.recv_from(k, 64, 0, true);
    p.check("the disconnected k takes it", n == 5 && data == b"again");
    // A wildcard-bound socket that connects is bound, from then on, at the
    // source its route chose (`inet_rcv_saddr`, rehashed): getsockname says
    // so, and its peer's datagrams reach it ahead of an unconnected socket
    // bound at that exact address and port (`compute_score` ranks the whole
    // 4-tuple first); a stranger's reach the exact one.
    let w = p.socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    p.require("socket w", w >= 0);
    p.check(
        "SO_REUSEADDR on w",
        p.setsockopt_bytes(w, SOL_SOCKET, SO_REUSEADDR, &int(1), 4, "1") == 0,
    );
    p.check(
        "bind w to the wildcard",
        p.bind_to(
            w,
            &SockAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
        ) == 0,
    );
    let (_, bound_w, _) = p.name_of(w, false, 128);
    let port_w = bound_w.and_then(|a| a.port()).expect("getsockname w");
    let x = p.socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    p.require("socket x", x >= 0);
    p.check(
        "SO_REUSEADDR on x",
        p.setsockopt_bytes(x, SOL_SOCKET, SO_REUSEADDR, &int(1), 4, "1") == 0,
    );
    let exact = SockAddr::v4(port_w);
    p.check("bind x at w's port on 127.0.0.1", p.bind_to(x, &exact) == 0);
    p.check("connect w to f", p.connect_to(w, &addr_f) == 0);
    let (_, local_w, _) = p.name_of(w, false, 128);
    p.check(
        "the connected w reports the routed source",
        local_w.as_ref() == Some(&exact),
    );
    p.check(
        "f sends to 127.0.0.1",
        p.send_to(f, b"to-w", 0, Some(&exact)) == 4,
    );
    let (n, data, _) = p.recv_from(w, 64, 0, true);
    p.check(
        "the connected w takes its peer's datagram",
        n == 4 && data == b"to-w",
    );
    p.check(
        "not the exact x",
        p.recv_from(x, 64, 0, true).0 == neg(EAGAIN),
    );
    p.check(
        "g sends there too",
        p.send_to(g, b"to-x", 0, Some(&exact)) == 4,
    );
    let (n, data, _) = p.recv_from(x, 64, 0, true);
    p.check("the exact x takes a stranger's", n == 4 && data == b"to-x");
    for fd in [e, f, g, k, w, x] {
        p.close(fd);
    }

    let file = p.openat(AT_FDCWD, &format!("{root}/file"), O_RDWR | O_CREAT, 0o640);
    p.require("open a file", file >= 0);
    p.check(
        "sendto on a file is ENOTSOCK",
        p.send_to(file, b"x", 0, Some(&addr_b)) == neg(ENOTSOCK),
    );
    p.check(
        "getsockname on a file is ENOTSOCK",
        p.name_of(file, false, 128).0 == neg(ENOTSOCK),
    );
    for fd in [b, c, d, file] {
        p.close(fd);
    }
    p.check(
        "sendto on a closed descriptor is EBADF",
        p.send_to(b, b"x", 0, Some(&addr_b)) == neg(EBADF),
    );
    // Last on purpose: a runtime that ignores MSG_DONTWAIT parks here forever.
    p.check(
        "MSG_DONTWAIT on an empty blocking socket is EAGAIN",
        p.recv_from(a, 64, MSG_DONTWAIT, false).0 == neg(EAGAIN),
    );
    p.close(a);
    check_allocated_port(p, &addr_a);
}

pub const SCENARIO: Scenario = Scenario {
    name: "net/udp",
    run,
    covers: &[
        Syscall::N_socket,
        Syscall::N_bind,
        Syscall::N_sendto,
        Syscall::N_recvfrom,
        Syscall::N_getsockname,
        Syscall::N_getpeername,
        Syscall::N_connect,
        Syscall::N_shutdown,
        Syscall::N_setsockopt,
        Syscall::N_getsockopt,
        Syscall::N_listen,
        Syscall::N_accept4,
        Syscall::N_openat,
        Syscall::N_close,
    ],
    symbols: &[
        "socket",
        "bind",
        "sendto",
        "recvfrom",
        "getsockname",
        "getpeername",
        "connect",
        "shutdown",
        "setsockopt",
        "getsockopt",
        "listen",
        "accept4",
        "openat",
        "close",
    ],
    ..DEFAULTS
};
