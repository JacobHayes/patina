//! net/pending — connections that complete or fail after the call that
//! started them, over loopback (connect(2), socket(7) `SO_ERROR`, udp(7);
//! net/ipv4/af_inet.c `__inet_stream_connect`, net/ipv4/udp.c
//! `__udp4_lib_err`):
//!
//! * a non-blocking TCP connect is `EINPROGRESS`; to a listener it becomes
//!   writable with `SO_ERROR` 0 and a peer, a second `connect` then answers
//!   the completion (0: the socket was still `SS_CONNECTING`) and a third
//!   `EISCONN`; to a port nobody listens on it
//!   polls `POLLERR|POLLHUP`, `SO_ERROR` is `ECONNREFUSED` once — reading it
//!   clears it — and the socket has no peer (`ENOTCONN`);
//! * a connected UDP socket's datagram to a port nobody listens on is sent,
//!   and the ICMP port-unreachable answer surfaces asynchronously: the
//!   socket polls `POLLERR` and its next receive is `ECONNREFUSED`, once;
//! * `connect` with `AF_UNSPEC` dissolves a UDP association (`ENOTCONN`
//!   after);
//! * `bind` to an address no interface has (TEST-NET-1: nothing is sent) is
//!   `EADDRNOTAVAIL` (`Need::LocalBindOnly`: `ip_nonlocal_bind` off).
//!
//! Every wait is a poll bounded by `WAIT_MS`.

use crate::catalog::{DEFAULTS, Need, Scenario};
use crate::probe::{OptionShown, Probe, SockAddr, neg};
use libc::*;
use patina_dst_syscalls::Syscall;
use std::net::{Ipv4Addr, SocketAddrV4};

/// An address in TEST-NET-1 (RFC 5737): no interface has it, and binding to
/// it sends nothing.
const DOCUMENTATION: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

/// How long a scenario waits for an asynchronous completion.
const WAIT_MS: i32 = 5_000;

/// The poll bits a completion is judged by.
const COMPLETION: i16 = POLLIN | POLLOUT | POLLERR | POLLHUP;

fn int(value: i32) -> [u8; 4] {
    value.to_ne_bytes()
}

/// A loopback TCP port nobody listens on, held for the scenario's lifetime:
/// a socket bound to it but not listening. A SYN to a bound, non-listening
/// port is answered with RST exactly as to a free one (`tcp_v4_rcv` finds no
/// listener), and holding the binding keeps a concurrent test's `bind(0)`
/// from taking the port meanwhile.
fn held_port(p: &Probe) -> (i32, SockAddr) {
    let t = p.socket(AF_INET, SOCK_STREAM, 0);
    p.require("a socket to hold a port", t >= 0);
    p.check("bind it", p.bind_to(t, &SockAddr::v4(0)) == 0);
    let (_, addr, _) = p.name_of(t, false, 128);
    (t, addr.expect("the held socket's port"))
}

pub fn run(p: &Probe) {
    let l = p.socket(AF_INET, SOCK_STREAM, 0);
    p.require("a listener", l >= 0);
    p.check("bind the listener", p.bind_to(l, &SockAddr::v4(0)) == 0);
    p.check("listen", p.listen(l, 4) == 0);
    let (_, addr_l, _) = p.name_of(l, false, 128);
    let addr_l = addr_l.expect("getsockname l");

    let c = p.socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    p.require("a non-blocking client", c >= 0);
    p.check(
        "a non-blocking connect is EINPROGRESS",
        p.connect_to(c, &addr_l) == neg(EINPROGRESS),
    );
    let (n, revents) = p.poll(&[(c, POLLOUT)], WAIT_MS, COMPLETION);
    p.check("it becomes writable", n == 1 && revents == vec![POLLOUT]);
    let (r, error) = p.getsockopt_bytes(c, SOL_SOCKET, SO_ERROR, 4, OptionShown::Exact);
    p.check("SO_ERROR is 0", r == 0 && error == int(0));
    let (r, peer, _) = p.name_of(c, true, 128);
    p.check(
        "the peer is the listener",
        r == 0 && peer == Some(addr_l.clone()),
    );
    p.check(
        "a second connect reports the completed connection: 0",
        p.connect_to(c, &addr_l) == 0,
    );
    p.check(
        "a third is EISCONN",
        p.connect_to(c, &addr_l) == neg(EISCONN),
    );
    let (s, _) = p.accept_from(l, 0, false, false);
    p.check("the listener accepts it", s >= 0);

    let (held, nobody) = held_port(p);
    let r_sock = p.socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    p.require("a second non-blocking client", r_sock >= 0);
    p.check(
        "a non-blocking connect to nobody is EINPROGRESS too",
        p.connect_to(r_sock, &nobody) == neg(EINPROGRESS),
    );
    let (n, revents) = p.poll(&[(r_sock, POLLOUT)], WAIT_MS, POLLERR | POLLHUP);
    p.check(
        "the refused connect polls POLLERR|POLLHUP",
        n == 1
            && revents
                .first()
                .is_some_and(|r| r & (POLLERR | POLLHUP) == POLLERR | POLLHUP),
    );
    let (r, error) = p.getsockopt_bytes(r_sock, SOL_SOCKET, SO_ERROR, 4, OptionShown::Exact);
    p.check(
        "SO_ERROR is ECONNREFUSED",
        r == 0 && error == int(ECONNREFUSED),
    );
    let (r, error) = p.getsockopt_bytes(r_sock, SOL_SOCKET, SO_ERROR, 4, OptionShown::Exact);
    p.check("reading SO_ERROR cleared it", r == 0 && error == int(0));
    p.check(
        "the refused socket has no peer",
        p.name_of(r_sock, true, 128).0 == neg(ENOTCONN),
    );

    // UDP has no reservation that stays silent: a bound UDP socket takes the
    // datagram. The UDP port with the held TCP port's number is free with the
    // odds of any other (the port spaces are separate); a concurrent test's
    // bind(0) landing on it in the few calls below is the residual race.
    let closed = nobody.clone();
    let u = p.socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    p.require("a UDP socket", u >= 0);
    p.check("bind it", p.bind_to(u, &SockAddr::v4(0)) == 0);
    p.check(
        "connect it to a port nobody listens on",
        p.connect_to(u, &closed) == 0,
    );
    p.check(
        "the datagram is sent",
        p.send_to(u, b"anyone?", 0, None) == 7,
    );
    let (n, revents) = p.poll(&[(u, POLLIN)], WAIT_MS, COMPLETION);
    p.check(
        "the port-unreachable answer makes it poll POLLERR",
        n == 1 && revents == vec![POLLERR],
    );
    p.check(
        "the next receive is ECONNREFUSED",
        p.recv_from(u, 16, MSG_DONTWAIT, false).0 == neg(ECONNREFUSED),
    );
    p.check(
        "once: then the queue is merely empty",
        p.recv_from(u, 16, MSG_DONTWAIT, false).0 == neg(EAGAIN),
    );
    p.check(
        "connect with AF_UNSPEC dissolves the association",
        p.connect_to(
            u,
            &SockAddr::Raw {
                family: AF_UNSPEC as u16,
                len: size_of::<sockaddr_in>(),
            },
        ) == 0,
    );
    p.check(
        "and the socket has no peer",
        p.name_of(u, true, 128).0 == neg(ENOTCONN),
    );

    let w = p.socket(AF_INET, SOCK_DGRAM, 0);
    p.require("an unbound socket", w >= 0);
    p.check(
        "bind to an address no interface has is EADDRNOTAVAIL",
        p.bind_to(w, &SockAddr::V4(SocketAddrV4::new(DOCUMENTATION, 0))) == neg(EADDRNOTAVAIL),
    );

    for fd in [c, s, r_sock, u, w, held, l] {
        p.close(fd);
    }
    crate::scenarios::net::check_allocated_port(p, &addr_l);
}

pub const SCENARIO: Scenario = Scenario {
    name: "net/pending",
    run,
    covers: &[
        Syscall::N_socket,
        Syscall::N_bind,
        Syscall::N_listen,
        Syscall::N_connect,
        Syscall::N_accept4,
        Syscall::N_getsockname,
        Syscall::N_getpeername,
        Syscall::N_getsockopt,
        Syscall::N_sendto,
        Syscall::N_recvfrom,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_poll,
        #[cfg(not(target_arch = "x86_64"))]
        Syscall::N_ppoll,
        Syscall::N_close,
    ],
    symbols: &[
        "socket",
        "bind",
        "listen",
        "connect",
        "accept4",
        "getsockname",
        "getpeername",
        "getsockopt",
        "sendto",
        "recvfrom",
        "poll",
        "close",
    ],
    needs: &[Need::LocalBindOnly],
    ..DEFAULTS
};
