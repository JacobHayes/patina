//! net/inet6_mapped — AF_INET6 sockets and v4-mapped addresses (ipv6(7);
//! net/ipv6/tcp_ipv6.c `tcp_v6_connect`, net/ipv6/ipv6_sockglue.c):
//!
//! * with `IPV6_V6ONLY` off an AF_INET6 socket reaches an AF_INET listener
//!   through the v4-mapped `::ffff:127.0.0.1` — its own name is v4-mapped
//!   and the listener sees a plain AF_INET peer with the same port — and
//!   with it on, a v4-mapped destination is `ENETUNREACH`;
//! * an IPv6 option on an AF_INET socket is refused.
//!
//! Needs IPv6 on the loopback interface (`Need::Ipv6Loopback`).
//!
//! Apart from net/inet6 because its AF_INET listener on `127.0.0.1` and
//! net/inet6's v6-only listener on `::1` never conflict, so the host may
//! give them one number, and no `bind` could make them conflict (an AF_INET
//! socket never does with a v6-only one; holding the number with an
//! explicit `bind` races other processes). Here the listener's `bind` port
//! and the client's `connect` port are distinct: a `connect` never takes a
//! port a `bind` holds (net/ipv4/inet_hashtables.c `__inet_hash_connect`).
//! (scenarios/net.rs, "Port identity".)

use crate::catalog::{DEFAULTS, Need, Scenario};
use crate::probe::{Probe, SockAddr, neg};
use crate::scenarios::net::int;
use libc::*;
use patina_dst_syscalls::Syscall;
use std::net::{Ipv4Addr, SocketAddrV6};

pub fn run(p: &Probe) {
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

    for fd in [l4, m, s4, n6] {
        p.close(fd);
    }
}

pub const SCENARIO: Scenario = Scenario {
    name: "net/inet6_mapped",
    run,
    covers: &[
        Syscall::N_socket,
        Syscall::N_bind,
        Syscall::N_listen,
        Syscall::N_connect,
        Syscall::N_accept4,
        Syscall::N_getsockname,
        Syscall::N_setsockopt,
        Syscall::N_close,
    ],
    symbols: &[
        "socket",
        "bind",
        "listen",
        "connect",
        "accept4",
        "getsockname",
        "setsockopt",
        "close",
    ],
    needs: &[Need::Ipv6Loopback],
    ..DEFAULTS
};
