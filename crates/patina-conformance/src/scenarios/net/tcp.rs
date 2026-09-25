//! net/tcp — socket / bind / listen / connect / accept4 / sendto / recvfrom /
//! shutdown / getsockopt over loopback TCP: the connection lifecycle,
//! byte-stream semantics, half-close, refusal, and the errno vocabulary
//! (the option table is net/sockopt's, a connect that completes later
//! net/pending's).

use crate::catalog::{DEFAULTS, Scenario};
use patina_dst_syscalls::Syscall;

use crate::probe::{OptionShown, Probe, SockAddr, neg};
use crate::scenarios::net::{check_allocated_port, int};
use libc::*;

const ANY: SockAddr = SockAddr::v4(0);

pub fn run(p: &Probe) {
    let l = p.socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    p.require("listener socket", l >= 0);
    p.check("bind the listener", p.bind_to(l, &ANY) == 0);
    p.check("listen", p.listen(l, 8) == 0);
    let (r, addr_l, _) = p.name_of(l, false, 128);
    p.require("getsockname l", r == 0 && addr_l.is_some());
    let addr_l = addr_l.unwrap();
    let (r, accepting) = p.getsockopt_bytes(l, SOL_SOCKET, SO_ACCEPTCONN, 4, OptionShown::Exact);
    p.check(
        "SO_ACCEPTCONN is set on a listener",
        r == 0 && accepting == int(1),
    );
    p.check("listen twice is allowed", p.listen(l, 4) == 0);
    p.check(
        "bind a listening socket again is EINVAL",
        p.bind_to(l, &ANY) == neg(EINVAL),
    );

    let c = p.socket(AF_INET, SOCK_STREAM, 0);
    p.require("client socket", c >= 0);
    p.check("connect to the listener", p.connect_to(c, &addr_l) == 0);
    let (_, addr_c, _) = p.name_of(c, false, 128);
    let addr_c = addr_c.expect("getsockname c");
    let (s, peer) = p.accept_from(l, SOCK_CLOEXEC, false, true);
    p.require("accept4", s >= 0);
    p.check(
        "the accepted peer is the client's local address",
        peer.as_ref() == Some(&addr_c),
    );
    let (r, speer, _) = p.name_of(s, true, 128);
    p.check(
        "getpeername on the server side is the client",
        r == 0 && speer.as_ref() == Some(&addr_c),
    );
    let (r, cpeer, _) = p.name_of(c, true, 128);
    p.check(
        "getpeername on the client side is the listener",
        r == 0 && cpeer.as_ref() == Some(&addr_l),
    );
    let (r, not_accepting) =
        p.getsockopt_bytes(c, SOL_SOCKET, SO_ACCEPTCONN, 4, OptionShown::Exact);
    p.check(
        "SO_ACCEPTCONN is clear on a connected socket",
        r == 0 && not_accepting == int(0),
    );
    p.check(
        "connect on a connected socket is EISCONN",
        p.connect_to(c, &addr_l) == neg(EISCONN),
    );

    p.check("send client -> server", p.send_to(c, b"hi", 0, None) == 2);
    let (n, data, _) = p.recv_from(s, 16, 0, false);
    p.check("the server reads it", n == 2 && data == b"hi");
    p.check(
        "send server -> client",
        p.send_to(s, b"there", 0, None) == 5,
    );
    let (n, data, _) = p.recv_from(c, 2, 0, false);
    p.check("a short read returns the prefix", n == 2 && data == b"th");
    let (n, data, _) = p.recv_from(c, 16, 0, false);
    p.check(
        "the stream continues where the short read stopped",
        n == 3 && data == b"ere",
    );
    p.check(
        "MSG_DONTWAIT on an empty stream is EAGAIN",
        p.recv_from(c, 16, MSG_DONTWAIT, false).0 == neg(EAGAIN),
    );

    p.check(
        "shutdown SHUT_WR on the client",
        p.shutdown(c, SHUT_WR) == 0,
    );
    p.check("the server reads EOF", p.recv_from(s, 16, 0, false).0 == 0);
    p.check(
        "the server can still send after the client's half-close",
        p.send_to(s, b"late", 0, None) == 4,
    );
    let (n, data, _) = p.recv_from(c, 16, 0, false);
    p.check(
        "the client still reads after its own half-close",
        n == 4 && data == b"late",
    );
    p.check(
        "send after SHUT_WR is EPIPE",
        p.send_to(c, b"x", MSG_NOSIGNAL, None) == neg(EPIPE),
    );
    p.check(
        "shutdown with an unknown how is EINVAL",
        p.shutdown(c, 99) == neg(EINVAL),
    );
    p.check("close the server side", p.close(s) == 0);
    p.check(
        "the client reads EOF once the peer closes",
        p.recv_from(c, 16, 0, false).0 == 0,
    );

    let u = p.socket(AF_INET, SOCK_STREAM, 0);
    p.require("unconnected socket", u >= 0);
    p.check(
        "accept4 on a non-listener is EINVAL",
        i64::from(p.accept_from(u, 0, false, true).0) == neg(EINVAL),
    );
    p.check(
        "getpeername on an unconnected socket is ENOTCONN",
        p.name_of(u, true, 128).0 == neg(ENOTCONN),
    );
    p.check(
        "send on a never-connected stream socket is EPIPE",
        p.send_to(u, b"x", MSG_NOSIGNAL, None) == neg(EPIPE),
    );
    p.check("listen without bind autobinds", p.listen(u, 1) == 0);
    let u2 = p.socket(AF_INET, SOCK_STREAM, 0);
    p.require("second unconnected socket", u2 >= 0);
    p.check(
        "shutdown on an unconnected stream socket is ENOTCONN",
        p.shutdown(u2, SHUT_RD) == neg(ENOTCONN),
    );
    let (r, addr_u, _) = p.name_of(u, false, 128);
    p.check(
        "the autobound listener has a port",
        r == 0 && addr_u.and_then(|a| a.port()).is_some_and(|port| port != 0),
    );

    let l2 = p.socket(AF_INET, SOCK_STREAM, 0);
    p.require("second listener socket", l2 >= 0);
    p.check(
        "bind to the listener's port is EADDRINUSE",
        p.bind_to(l2, &addr_l) == neg(EADDRINUSE),
    );

    let t = p.socket(AF_INET, SOCK_STREAM, 0);
    p.require("temporary socket", t >= 0);
    p.bind_to(t, &ANY);
    let (_, addr_t, _) = p.name_of(t, false, 128);
    let addr_t = addr_t.expect("getsockname t");
    p.close(t);
    let c2 = p.socket(AF_INET, SOCK_STREAM, 0);
    p.require("second client", c2 >= 0);
    p.check(
        "connect to a port nobody listens on is ECONNREFUSED",
        p.connect_to(c2, &addr_t) == neg(ECONNREFUSED),
    );

    for fd in [c, u, u2, l2, c2, l] {
        p.close(fd);
    }
    check_allocated_port(p, &addr_l);
}

pub const SCENARIO: Scenario = Scenario {
    name: "net/tcp",
    run,
    covers: &[
        Syscall::N_socket,
        Syscall::N_bind,
        Syscall::N_listen,
        Syscall::N_connect,
        Syscall::N_accept4,
        Syscall::N_sendto,
        Syscall::N_recvfrom,
        Syscall::N_shutdown,
        Syscall::N_getsockname,
        Syscall::N_getpeername,
        Syscall::N_getsockopt,
        Syscall::N_close,
    ],
    symbols: &[
        "socket",
        "bind",
        "listen",
        "connect",
        "accept4",
        "sendto",
        "recvfrom",
        "shutdown",
        "getsockname",
        "getpeername",
        "getsockopt",
        "close",
    ],
    ..DEFAULTS
};
