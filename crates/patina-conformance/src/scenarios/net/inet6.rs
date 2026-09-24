//! net/inet6 — AF_INET6 datagram and stream sockets over `::1` (ipv6(7),
//! udp(7), tcp(7); net/ipv6/af_inet6.c `inet6_bind`, net/ipv6/tcp_ipv6.c
//! `tcp_v6_connect`, net/ipv6/ipv6_sockglue.c):
//!
//! * a bound socket's name is a full `sockaddr_in6` (28 bytes: `::1`, the
//!   port, zero flow label and scope); datagrams carry the sender's name;
//! * `bind` refuses an address shorter than `SIN6_LEN_RFC2133` (24) with
//!   `EINVAL`, another family with `EAFNOSUPPORT`, and an address no
//!   interface has with `EADDRNOTAVAIL` (a documentation-prefix address:
//!   nothing is sent);
//! * `IPV6_V6ONLY` reads back what was set and is `EINVAL` once the socket
//!   is bound; `SO_DOMAIN`/`SO_PROTOCOL`/`SO_TYPE` name the socket;
//! * with `IPV6_V6ONLY` off an AF_INET6 socket reaches an AF_INET listener
//!   through the v4-mapped `::ffff:127.0.0.1` — its own name is v4-mapped
//!   and the listener sees a plain AF_INET peer with the same port — and
//!   with it on, a v4-mapped destination is `ENETUNREACH`;
//! * an IPv6 option on an AF_INET socket is refused.
//!
//! Needs IPv6 on the loopback interface (`Need::Ipv6Loopback`) and
//! `ip_nonlocal_bind` off (`Need::LocalBindOnly`) for the `EADDRNOTAVAIL`.
//!
//! Reads right after a send rely on loopback delivery before the send
//! returns (scenarios/net.rs, "Loopback delivery").

use crate::catalog::{Arc, DEFAULTS, Gap, Need, Scenario, Status};
use crate::compare::{Difference, Ending, Failure, Observed};
use crate::probe::{OptionShown, Probe, SockAddr, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV6};

/// `SIN6_LEN_RFC2133`: the shortest IPv6 address `bind` accepts (no scope).
const SIN6_LEN_RFC2133: usize = 24;

/// An address in the IPv6 documentation prefix (RFC 3849): no interface has
/// it, and binding to it sends nothing.
const DOCUMENTATION: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

fn int(value: i32) -> [u8; 4] {
    value.to_ne_bytes()
}

pub fn run(p: &Probe) {
    // ---- datagrams ----
    let u = p.socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    p.require("an AF_INET6 datagram socket", u >= 0);
    p.check("bind to [::1]:0", p.bind_to(u, &SockAddr::v6(0)) == 0);
    let (r, addr_u, len) = p.name_of(u, false, 128);
    p.check(
        "the name is a full sockaddr_in6 on ::1 with a port",
        r == 0
            && len as usize == size_of::<sockaddr_in6>()
            && matches!(&addr_u, Some(SockAddr::V6(a)) if *a.ip() == Ipv6Addr::LOCALHOST && a.port() != 0 && a.flowinfo() == 0 && a.scope_id() == 0),
    );
    let addr_u = addr_u.expect("getsockname u");
    let v = p.socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    p.require("a second datagram socket", v >= 0);
    p.check("bind v", p.bind_to(v, &SockAddr::v6(0)) == 0);
    let (_, addr_v, _) = p.name_of(v, false, 128);
    let addr_v = addr_v.expect("getsockname v");
    p.check("sendto [::1]", p.send_to(u, b"six", 0, Some(&addr_v)) == 3);
    let (n, data, from) = p.recv_from(v, 16, 0, true);
    p.check(
        "the datagram arrives with the sender's name",
        n == 3 && data == b"six" && from.as_ref() == Some(&addr_u),
    );
    p.check(
        "a non-blocking receive with nothing queued is EAGAIN",
        p.recv_from(v, 16, 0, false).0 == neg(EAGAIN),
    );

    let w = p.socket(AF_INET6, SOCK_DGRAM, 0);
    p.require("an unbound socket", w >= 0);
    p.check(
        "bind with an address shorter than SIN6_LEN_RFC2133 is EINVAL",
        p.bind_to(
            w,
            &SockAddr::Raw {
                family: AF_INET6 as u16,
                len: SIN6_LEN_RFC2133 - 1,
            },
        ) == neg(EINVAL),
    );
    p.check(
        "bind with another family is EAFNOSUPPORT",
        p.bind_to(
            w,
            &SockAddr::Raw {
                family: AF_INET as u16,
                len: size_of::<sockaddr_in6>(),
            },
        ) == neg(EAFNOSUPPORT),
    );
    p.check(
        "bind to an address no interface has is EADDRNOTAVAIL",
        p.bind_to(w, &SockAddr::V6(SocketAddrV6::new(DOCUMENTATION, 0, 0, 0)))
            == neg(EADDRNOTAVAIL),
    );
    p.check(
        "bind to the port in use is EADDRINUSE",
        p.bind_to(w, &addr_u) == neg(EADDRINUSE),
    );

    // ---- a stream, IPV6_V6ONLY and v4-mapped addresses ----
    let l = p.socket(AF_INET6, SOCK_STREAM, 0);
    p.require("an AF_INET6 listener", l >= 0);
    p.check(
        "set IPV6_V6ONLY",
        p.setsockopt_bytes(l, IPPROTO_IPV6, IPV6_V6ONLY, &int(1), 4, "1") == 0,
    );
    let (r, value) = p.getsockopt_bytes(l, IPPROTO_IPV6, IPV6_V6ONLY, 4, OptionShown::Exact);
    p.check("IPV6_V6ONLY reads back 1", r == 0 && value == int(1));
    p.check("bind the listener", p.bind_to(l, &SockAddr::v6(0)) == 0);
    p.check(
        "IPV6_V6ONLY on a bound socket is EINVAL",
        p.setsockopt_bytes(l, IPPROTO_IPV6, IPV6_V6ONLY, &int(0), 4, "0") == neg(EINVAL),
    );
    p.check("listen", p.listen(l, 4) == 0);
    let (_, addr_l, _) = p.name_of(l, false, 128);
    let addr_l = addr_l.expect("getsockname l");
    for (name, expected) in [
        (SO_DOMAIN, AF_INET6),
        (SO_PROTOCOL, IPPROTO_TCP),
        (SO_TYPE, SOCK_STREAM),
    ] {
        let (r, value) = p.getsockopt_bytes(l, SOL_SOCKET, name, 4, OptionShown::Exact);
        p.check(
            "SO_DOMAIN / SO_PROTOCOL / SO_TYPE name an IPv6 TCP socket",
            r == 0 && value == int(expected),
        );
    }
    let c = p.socket(AF_INET6, SOCK_STREAM, 0);
    p.require("a client", c >= 0);
    p.check("connect to [::1]", p.connect_to(c, &addr_l) == 0);
    let (_, addr_c, _) = p.name_of(c, false, 128);
    let (s, peer) = p.accept_from(l, SOCK_CLOEXEC, false, true);
    p.require("accept4", s >= 0);
    p.check("the peer is the client's name", peer == addr_c);
    let (_, speer, _) = p.name_of(c, true, 128);
    p.check(
        "the client's peer is the listener",
        speer.as_ref() == Some(&addr_l),
    );
    p.check("send over IPv6", p.send_to(c, b"hello6", 0, None) == 6);
    let (n, data, _) = p.recv_from(s, 16, 0, false);
    p.check("receive over IPv6", n == 6 && data == b"hello6");

    let l4 = p.socket(AF_INET, SOCK_STREAM, 0);
    p.require("an AF_INET listener", l4 >= 0);
    p.check("bind it to 127.0.0.1", p.bind_to(l4, &SockAddr::v4(0)) == 0);
    p.check("listen on it", p.listen(l4, 4) == 0);
    let (_, addr_l4, _) = p.name_of(l4, false, 128);
    let port4 = addr_l4
        .and_then(|a| a.port())
        .expect("the v4 listener's port");
    let mapped = SockAddr::V6(SocketAddrV6::new(
        Ipv4Addr::LOCALHOST.to_ipv6_mapped(),
        port4,
        0,
        0,
    ));
    let m = p.socket(AF_INET6, SOCK_STREAM, 0);
    p.require("a dual-stack client", m >= 0);
    p.check(
        "clear IPV6_V6ONLY",
        p.setsockopt_bytes(m, IPPROTO_IPV6, IPV6_V6ONLY, &int(0), 4, "0") == 0,
    );
    p.check(
        "a dual-stack socket connects to the v4-mapped listener",
        p.connect_to(m, &mapped) == 0,
    );
    let (_, addr_m, _) = p.name_of(m, false, 128);
    let port_m = match &addr_m {
        Some(SockAddr::V6(a)) if *a.ip() == Ipv4Addr::LOCALHOST.to_ipv6_mapped() => Some(a.port()),
        _ => None,
    };
    p.check("its own name is v4-mapped", port_m.is_some());
    let (s4, peer4) = p.accept_from(l4, 0, false, true);
    p.check(
        "the AF_INET listener sees a plain AF_INET peer on the same port",
        s4 >= 0 && port_m.is_some() && peer4 == Some(SockAddr::v4(port_m.unwrap_or(0))),
    );
    let n6 = p.socket(AF_INET6, SOCK_STREAM, 0);
    p.require("a v6-only client", n6 >= 0);
    p.check(
        "set IPV6_V6ONLY on it",
        p.setsockopt_bytes(n6, IPPROTO_IPV6, IPV6_V6ONLY, &int(1), 4, "1") == 0,
    );
    p.check(
        "a v6-only socket cannot reach a v4-mapped address: ENETUNREACH",
        p.connect_to(n6, &mapped) == neg(ENETUNREACH),
    );
    p.check(
        "IPV6_V6ONLY on an AF_INET socket is refused",
        p.setsockopt_bytes(l4, IPPROTO_IPV6, IPV6_V6ONLY, &int(1), 4, "1") == neg(ENOPROTOOPT),
    );

    for fd in [u, v, w, l, c, s, l4, m, s4, n6] {
        p.close(fd);
    }
}

pub const SCENARIO: Scenario = Scenario {
    name: "net/inet6",
    run,
    covers: &[
        Syscall::N_socket,
        Syscall::N_bind,
        Syscall::N_listen,
        Syscall::N_connect,
        Syscall::N_accept4,
        Syscall::N_getsockname,
        Syscall::N_getpeername,
        Syscall::N_setsockopt,
        Syscall::N_getsockopt,
        Syscall::N_sendto,
        Syscall::N_recvfrom,
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
        "setsockopt",
        "getsockopt",
        "sendto",
        "recvfrom",
        "close",
    ],
    needs: &[Need::Ipv6Loopback, Need::LocalBindOnly],
    gaps: &[
        Gap {
            status: Status::Pending(Arc::NetworkReadiness),
            vehicles: Vehicle::ALL,
            what: "socket(AF_INET6) answers EAFNOSUPPORT (c/posix/net.c socket, sud/net.rs sys_socket admit AF_INET alone): SimNet has no IPv6",
            failure: Failure::Differs(&[
                Difference::field(0, "socket", "errno", Observed::Str("EAFNOSUPPORT")),
                Difference::field(0, "socket", "ret", Observed::Int(-1)),
            ]),
        },
        Gap {
            status: Status::Pending(Arc::NetworkReadiness),
            vehicles: Vehicle::ALL,
            what: "with no AF_INET6 socket the scenario cannot continue",
            failure: Failure::Stops {
                events: 1,
                ending: Ending::Exit(101),
                diagnostic: "net/inet6: cannot continue: an AF_INET6 datagram socket",
            },
        },
    ],
    ..DEFAULTS
};
