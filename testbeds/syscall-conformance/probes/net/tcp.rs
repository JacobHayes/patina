//! net/tcp — socket / bind / listen / connect / accept4 / sendto / recvfrom /
//! shutdown / getsockopt / setsockopt over loopback TCP: the connection
//! lifecycle, byte-stream semantics, half-close, refusal, and the errno
//! vocabulary.

#[cfg(target_os = "linux")]
mod scenario {
    use libc::*;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use syscall_conformance::calls::{neg, Probe};

    const ANY: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0);

    pub fn run(p: &Probe) {
        let l = p.socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        p.require("listener socket", l >= 0);
        p.check("bind the listener", p.bind(l, ANY) == 0);
        p.check("listen", p.listen(l, 8) == 0);
        let (r, addr_l) = p.getsockname(l);
        p.require("getsockname l", r == 0 && addr_l.is_some());
        let addr_l = addr_l.unwrap();
        p.check("the listener has a port", addr_l.port() != 0);
        let (r, accepting) = p.getsockopt_int(l, SOL_SOCKET, SO_ACCEPTCONN);
        p.check(
            "SO_ACCEPTCONN is set on a listener",
            r == 0 && accepting == 1,
        );
        p.check("listen twice is allowed", p.listen(l, 4) == 0);
        p.check(
            "bind a listening socket again is EINVAL",
            p.bind(l, ANY) == neg(EINVAL),
        );

        let c = p.socket(AF_INET, SOCK_STREAM, 0);
        p.require("client socket", c >= 0);
        p.check("connect to the listener", p.connect(c, addr_l) == 0);
        let (_, addr_c) = p.getsockname(c);
        let addr_c = addr_c.expect("getsockname c");
        let (s, peer) = p.accept4(l, SOCK_CLOEXEC);
        p.require("accept4", s >= 0);
        p.check(
            "the accepted peer is the client's local address",
            peer == Some(addr_c),
        );
        let (r, speer) = p.getpeername(s);
        p.check(
            "getpeername on the server side is the client",
            r == 0 && speer == Some(addr_c),
        );
        let (r, cpeer) = p.getpeername(c);
        p.check(
            "getpeername on the client side is the listener",
            r == 0 && cpeer == Some(addr_l),
        );
        let (r, not_accepting) = p.getsockopt_int(c, SOL_SOCKET, SO_ACCEPTCONN);
        p.check(
            "SO_ACCEPTCONN is clear on a connected socket",
            r == 0 && not_accepting == 0,
        );
        p.check(
            "connect on a connected socket is EISCONN",
            p.connect(c, addr_l) == neg(EISCONN),
        );

        p.check("send client -> server", p.sendto(c, b"hi", 0, None) == 2);
        let (n, data, _) = p.recvfrom(s, 16, 0, false);
        p.check("the server reads it", n == 2 && data == b"hi");
        p.check("send server -> client", p.sendto(s, b"there", 0, None) == 5);
        let (n, data, _) = p.recvfrom(c, 2, 0, false);
        p.check("a short read returns the prefix", n == 2 && data == b"th");
        let (n, data, _) = p.recvfrom(c, 16, 0, false);
        p.check(
            "the stream continues where the short read stopped",
            n == 3 && data == b"ere",
        );
        p.check(
            "MSG_DONTWAIT on an empty stream is EAGAIN",
            p.recvfrom(c, 16, MSG_DONTWAIT, false).0 == neg(EAGAIN),
        );
        p.check(
            "setsockopt TCP_NODELAY",
            p.setsockopt_int(c, IPPROTO_TCP, TCP_NODELAY, 1) == 0,
        );
        let (r, nodelay) = p.getsockopt_int(c, IPPROTO_TCP, TCP_NODELAY);
        p.check("TCP_NODELAY reads back", r == 0 && nodelay == 1);
        let (r, kind) = p.getsockopt_int(c, SOL_SOCKET, SO_TYPE);
        p.check("SO_TYPE is SOCK_STREAM", r == 0 && kind == SOCK_STREAM);

        p.check(
            "shutdown SHUT_WR on the client",
            p.shutdown(c, SHUT_WR) == 0,
        );
        p.check("the server reads EOF", p.recvfrom(s, 16, 0, false).0 == 0);
        p.check(
            "the server can still send after the client's half-close",
            p.sendto(s, b"late", 0, None) == 4,
        );
        let (n, data, _) = p.recvfrom(c, 16, 0, false);
        p.check(
            "the client still reads after its own half-close",
            n == 4 && data == b"late",
        );
        p.check(
            "send after SHUT_WR is EPIPE",
            p.sendto(c, b"x", MSG_NOSIGNAL, None) == neg(EPIPE),
        );
        p.check(
            "shutdown with an unknown how is EINVAL",
            p.shutdown(c, 99) == neg(EINVAL),
        );
        p.check("close the server side", p.close(s) == 0);
        p.check(
            "the client reads EOF once the peer closes",
            p.recvfrom(c, 16, 0, false).0 == 0,
        );

        let u = p.socket(AF_INET, SOCK_STREAM, 0);
        p.require("unconnected socket", u >= 0);
        p.check(
            "accept4 on a non-listener is EINVAL",
            i64::from(p.accept4(u, 0).0) == neg(EINVAL),
        );
        p.check(
            "getpeername on an unconnected socket is ENOTCONN",
            p.getpeername(u).0 == neg(ENOTCONN),
        );
        p.check(
            "send on a never-connected stream socket is EPIPE",
            p.sendto(u, b"x", MSG_NOSIGNAL, None) == neg(EPIPE),
        );
        p.check("listen without bind autobinds", p.listen(u, 1) == 0);
        let u2 = p.socket(AF_INET, SOCK_STREAM, 0);
        p.require("second unconnected socket", u2 >= 0);
        p.check(
            "shutdown on an unconnected stream socket is ENOTCONN",
            p.shutdown(u2, SHUT_RD) == neg(ENOTCONN),
        );
        // Even a refused shutdown marks the socket: a later send is EPIPE.
        p.check(
            "send after the refused shutdown is EPIPE",
            p.sendto(u2, b"x", MSG_NOSIGNAL, None) == neg(EPIPE),
        );
        let (r, addr_u) = p.getsockname(u);
        p.check(
            "the autobound listener has a port",
            r == 0 && addr_u.is_some_and(|a| a.port() != 0),
        );

        let l2 = p.socket(AF_INET, SOCK_STREAM, 0);
        p.require("second listener socket", l2 >= 0);
        p.check(
            "bind to the listener's port is EADDRINUSE",
            p.bind(l2, addr_l) == neg(EADDRINUSE),
        );

        let t = p.socket(AF_INET, SOCK_STREAM, 0);
        p.require("temporary socket", t >= 0);
        p.bind(t, ANY);
        let (_, addr_t) = p.getsockname(t);
        let addr_t = addr_t.expect("getsockname t");
        p.close(t);
        let c2 = p.socket(AF_INET, SOCK_STREAM, 0);
        p.require("second client", c2 >= 0);
        p.check(
            "connect to a port nobody listens on is ECONNREFUSED",
            p.connect(c2, addr_t) == neg(ECONNREFUSED),
        );

        let c3 = p.socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        p.require("non-blocking client", c3 >= 0);
        let pending = p.connect(c3, addr_l);
        p.check(
            "a non-blocking connect is EINPROGRESS",
            pending == neg(EINPROGRESS),
        );
        let (s3, _) = p.accept4(l, 0);
        p.check("the listener accepts the pending connect", s3 >= 0);
        let (r, error) = p.getsockopt_int(c3, SOL_SOCKET, SO_ERROR);
        p.check(
            "SO_ERROR after the completed connect is 0",
            r == 0 && error == 0,
        );
        let (r, _) = p.getpeername(c3);
        p.check("the non-blocking client is connected", r == 0);

        for fd in [c, u, u2, l2, c2, c3, s3, l] {
            p.close(fd);
        }
    }
}

syscall_conformance::probe_main!("net/tcp", scenario::run);
