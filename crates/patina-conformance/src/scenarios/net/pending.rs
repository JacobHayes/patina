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

use crate::catalog::{Arc, DEFAULTS, Gap, Need, Scenario, Status};
use crate::compare::{Difference, Failure, Observed};
use crate::probe::{OptionShown, Probe, SockAddr, neg};
use crate::vehicle::Vehicle;
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
    gaps: &[
        Gap {
            status: Status::Pending(Arc::NetworkReadiness),
            vehicles: Vehicle::ALL,
            what: "a non-blocking TCP connect completes synchronously (lib.rs patina_net_tcp_connect: 0, or ECONNREFUSED at once) where the kernel answers EINPROGRESS and completes in the background (__inet_stream_connect), so a second connect is already EISCONN instead of reporting the completion",
            failure: Failure::Differs(&[
                Difference::field(7, "connect", "errno", Observed::Null),
                Difference::field(7, "connect", "ret", Observed::Int(0)),
                Difference::check(8, "a non-blocking connect is EINPROGRESS"),
                Difference::field(15, "connect", "errno", Observed::Str("EISCONN")),
                Difference::field(15, "connect", "ret", Observed::Int(-1)),
                Difference::check(16, "a second connect reports the completed connection: 0"),
                Difference::field(26, "connect", "errno", Observed::Str("ECONNREFUSED")),
                Difference::check(27, "a non-blocking connect to nobody is EINPROGRESS too"),
            ]),
        },
        Gap {
            status: Status::Pending(Arc::NetworkReadiness),
            vehicles: Vehicle::ALL,
            what: "a refused connect leaves no pending error: the socket polls nothing instead of POLLERR|POLLHUP, and SO_ERROR reads zeros (c/posix/net.c getsockopt has no option store) instead of ECONNREFUSED",
            failure: Failure::Differs(&[
                Difference::field(28, "poll", "fields.revents0", Observed::Int(0)),
                Difference::field(28, "poll", "ret", Observed::Int(0)),
                Difference::check(29, "the refused connect polls POLLERR|POLLHUP"),
                Difference::field(30, "getsockopt", "fields.value", Observed::Str("00000000")),
                Difference::check(31, "SO_ERROR is ECONNREFUSED"),
            ]),
        },
        Gap {
            status: Status::Pending(Arc::NetworkReadiness),
            vehicles: Vehicle::ALL,
            what: "a connected datagram to a port nobody holds answers EIO at once (patina's connected datagram send, c/posix/net.c send → lib.rs patina_net_send) where the kernel sends it and the ICMP port-unreachable answer surfaces asynchronously: POLLERR, then ECONNREFUSED on the next receive (__udp4_lib_err)",
            failure: Failure::Differs(&[
                Difference::field(41, "sendto", "errno", Observed::Str("EIO")),
                Difference::field(41, "sendto", "ret", Observed::Int(-1)),
                Difference::check(42, "the datagram is sent"),
                Difference::field(43, "poll", "fields.revents0", Observed::Int(0)),
                Difference::field(43, "poll", "ret", Observed::Int(0)),
                Difference::check(44, "the port-unreachable answer makes it poll POLLERR"),
                Difference::field(45, "recvfrom", "errno", Observed::Str("EAGAIN")),
                Difference::check(46, "the next receive is ECONNREFUSED"),
            ]),
        },
        Gap {
            status: Status::Pending(Arc::NetworkReadiness),
            vehicles: Vehicle::ALL,
            what: "connect with AF_UNSPEC answers EAFNOSUPPORT (c/posix/net.c connect, sud/net.rs sys_connect parse AF_INET alone) where it dissolves a datagram association (udp_disconnect), so the socket keeps its peer",
            failure: Failure::Differs(&[
                Difference::field(49, "connect", "errno", Observed::Str("EAFNOSUPPORT")),
                Difference::field(49, "connect", "ret", Observed::Int(-1)),
                Difference::check(50, "connect with AF_UNSPEC dissolves the association"),
                Difference::field(51, "getpeername", "errno", Observed::Null),
                Difference::field(
                    51,
                    "getpeername",
                    "fields.addr_family",
                    Observed::Str("AF_INET"),
                ),
                Difference::field(
                    51,
                    "getpeername",
                    "fields.addr_ip",
                    Observed::Str("127.0.0.1"),
                ),
                Difference::field(
                    51,
                    "getpeername",
                    "fields.addr_port",
                    Observed::Str("port@24"),
                ),
                Difference::field(51, "getpeername", "fields.addrlen", Observed::Int(16)),
                Difference::field(51, "getpeername", "ret", Observed::Int(0)),
                Difference::check(52, "and the socket has no peer"),
            ]),
        },
        Gap {
            status: Status::Pending(Arc::NetworkReadiness),
            vehicles: Vehicle::ALL,
            what: "bind to an address no interface has succeeds (lib.rs patina_net_bind checks no interface table) where inet_bind answers EADDRNOTAVAIL: the arc's table (`lo` + `eth0`/24) is to decide which local addresses exist",
            failure: Failure::Differs(&[
                Difference::field(54, "bind", "errno", Observed::Null),
                Difference::field(54, "bind", "ret", Observed::Int(0)),
                Difference::check(55, "bind to an address no interface has is EADDRNOTAVAIL"),
            ]),
        },
    ],
    ..DEFAULTS
};
