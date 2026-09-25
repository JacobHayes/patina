//! net/sockopt — the socket option table over loopback IPv4 TCP and UDP
//! sockets (socket(7), tcp(7), ip(7); net/core/sock.c `sk_setsockopt`/
//! `sk_getsockopt`, net/ipv4/tcp.c, net/ipv4/ip_sockglue.c):
//!
//! * identity options: `SO_TYPE`, `SO_DOMAIN`, `SO_PROTOCOL`,
//!   `SO_ACCEPTCONN`, `SO_ERROR`, of a TCP and a UDP socket;
//! * boolean options default off and read back what was set: `SO_REUSEADDR`,
//!   `SO_REUSEPORT`, `SO_KEEPALIVE`, `SO_BROADCAST`, `TCP_NODELAY`;
//!   `SO_REUSEPORT` on two sockets of one owner lets both bind one UDP port;
//! * `SO_LINGER` reads back the `struct linger` set (default off);
//!   `SO_RCVTIMEO`/`SO_SNDTIMEO` read back a timeval (2 s: a whole second is
//!   exact at every `HZ`; `sock_set_timeout` rounds to jiffies), and a
//!   microsecond field of a million or more is `EDOM`;
//! * `SO_RCVBUF`/`SO_SNDBUF`: the kernel doubles the value set (for its
//!   bookkeeping); the defaults are the host's sysctls and are compared by
//!   relation (at least twice the value set: `tcp_rmem`/`tcp_wmem` defaults
//!   sit far above it on any host), never by value;
//! * `SO_RCVLOWAT` -1 is capped: on a TCP socket at half its receive buffer
//!   once `SO_RCVBUF` locked it, and below `INT_MAX` (half `tcp_rmem`'s
//!   maximum) otherwise (`tcp_set_rcvlowat`); on a datagram socket it is
//!   `INT_MAX` (the mark's readiness is readiness/poll's);
//! * `SO_BINDTODEVICE` to `lo` reads the name back (unprivileged since
//!   Linux 5.7 while unbound);
//! * lengths: an int option with `optlen` below `sizeof(int)` is `EINVAL`;
//!   a `getsockopt` buffer shorter than the value gets that many bytes and
//!   `optlen` says so (the faulting lengths and pointers are
//!   net/sockopt_fault);
//! * an unknown option is `ENOPROTOOPT` at `SOL_SOCKET` (both ways), and at
//!   an unknown level of a TCP socket `ENOPROTOOPT` to set and
//!   `EOPNOTSUPP` to get (`do_ip_setsockopt`/`do_ip_getsockopt`);
//! * `ENOTSOCK` on a file, `EBADF` on a closed descriptor.

use crate::catalog::{DEFAULTS, KernelFloor, Scenario};
use crate::probe::{AT_FDCWD, OptionShown, Probe, SockAddr, neg};
use crate::scenarios::net::{int, timeval};
use libc::*;
use patina_dst_syscalls::Syscall;

/// A socket option level no protocol has.
const NO_LEVEL: i32 = 9999;
/// A `SOL_SOCKET` option number no kernel has.
const NO_OPTION: i32 = 9999;
/// The buffer size set: small enough for any `rmem_max`/`wmem_max`, doubled
/// above the kernel's minimum.
const BUFFER: i32 = 4096;

fn linger(onoff: i32, secs: i32) -> [u8; 8] {
    let mut bytes = [0u8; 8];
    bytes[..4].copy_from_slice(&onoff.to_ne_bytes());
    bytes[4..].copy_from_slice(&secs.to_ne_bytes());
    bytes
}

pub fn run(p: &Probe) {
    let root = p.dir();
    let t = p.socket(AF_INET, SOCK_STREAM, 0);
    p.require("a TCP socket", t >= 0);
    for (label, level, name, expected) in [
        ("SO_TYPE is SOCK_STREAM", SOL_SOCKET, SO_TYPE, SOCK_STREAM),
        ("SO_DOMAIN is AF_INET", SOL_SOCKET, SO_DOMAIN, AF_INET),
        (
            "SO_PROTOCOL is IPPROTO_TCP",
            SOL_SOCKET,
            SO_PROTOCOL,
            IPPROTO_TCP,
        ),
        ("SO_ACCEPTCONN is 0", SOL_SOCKET, SO_ACCEPTCONN, 0),
        ("SO_ERROR is 0", SOL_SOCKET, SO_ERROR, 0),
    ] {
        let (r, value) = p.getsockopt_bytes(t, level, name, 4, OptionShown::Exact);
        p.check(label, r == 0 && value == int(expected));
    }
    for (label, level, name) in [
        ("SO_REUSEADDR", SOL_SOCKET, SO_REUSEADDR),
        ("SO_REUSEPORT", SOL_SOCKET, SO_REUSEPORT),
        ("SO_KEEPALIVE", SOL_SOCKET, SO_KEEPALIVE),
        ("TCP_NODELAY", IPPROTO_TCP, TCP_NODELAY),
    ] {
        let (r, value) = p.getsockopt_bytes(t, level, name, 4, OptionShown::Exact);
        p.check(&format!("{label} defaults to 0"), r == 0 && value == int(0));
        p.check(
            &format!("set {label}"),
            p.setsockopt_bytes(t, level, name, &int(1), 4, "1") == 0,
        );
        let (r, value) = p.getsockopt_bytes(t, level, name, 4, OptionShown::Exact);
        p.check(&format!("{label} reads back 1"), r == 0 && value == int(1));
    }

    let (r, value) = p.getsockopt_bytes(t, SOL_SOCKET, SO_LINGER, 8, OptionShown::Exact);
    p.check("SO_LINGER defaults to off", r == 0 && value == linger(0, 0));
    p.check(
        "set SO_LINGER on, 5 s",
        p.setsockopt_bytes(t, SOL_SOCKET, SO_LINGER, &linger(1, 5), 8, "{1, 5}") == 0,
    );
    let (r, value) = p.getsockopt_bytes(t, SOL_SOCKET, SO_LINGER, 8, OptionShown::Exact);
    p.check(
        "SO_LINGER reads back {1, 5}",
        r == 0 && value == linger(1, 5),
    );
    for (label, name) in [("SO_RCVTIMEO", SO_RCVTIMEO), ("SO_SNDTIMEO", SO_SNDTIMEO)] {
        let (r, value) = p.getsockopt_bytes(t, SOL_SOCKET, name, 16, OptionShown::Exact);
        p.check(
            &format!("{label} defaults to zero"),
            r == 0 && value == timeval(0, 0),
        );
        p.check(
            &format!("set {label} to 2 s"),
            p.setsockopt_bytes(t, SOL_SOCKET, name, &timeval(2, 0), 16, "{2, 0}") == 0,
        );
        let (r, value) = p.getsockopt_bytes(t, SOL_SOCKET, name, 16, OptionShown::Exact);
        p.check(
            &format!("{label} reads back 2 s"),
            r == 0 && value == timeval(2, 0),
        );
        p.check(
            &format!("{label} with a million microseconds is EDOM"),
            p.setsockopt_bytes(
                t,
                SOL_SOCKET,
                name,
                &timeval(0, 1_000_000),
                16,
                "{0, 1000000}",
            ) == neg(EDOM),
        );
    }
    p.check(
        "SO_RCVLOWAT -1 on the TCP socket",
        p.setsockopt_bytes(t, SOL_SOCKET, SO_RCVLOWAT, &int(-1), 4, "-1") == 0,
    );
    let (r, mark) = p.getsockopt_hidden(t, SOL_SOCKET, SO_RCVLOWAT);
    p.check(
        "is capped below INT_MAX (half the host's tcp_rmem maximum)",
        r == 0 && mark > 0 && mark < i32::MAX,
    );
    for (label, name) in [("SO_RCVBUF", SO_RCVBUF), ("SO_SNDBUF", SO_SNDBUF)] {
        let (r, default) = p.getsockopt_hidden(t, SOL_SOCKET, name);
        p.check(
            &format!("{label}'s default is at least twice the value set"),
            r == 0 && default >= 2 * BUFFER,
        );
        p.check(
            &format!("set {label}"),
            p.setsockopt_bytes(t, SOL_SOCKET, name, &int(BUFFER), 4, "4096") == 0,
        );
        let (r, value) = p.getsockopt_hidden(t, SOL_SOCKET, name);
        p.check(
            &format!("{label} reads back doubled"),
            r == 0 && value == 2 * BUFFER,
        );
    }
    p.check(
        "SO_RCVLOWAT -1 once SO_RCVBUF locked the buffer (8192)",
        p.setsockopt_bytes(t, SOL_SOCKET, SO_RCVLOWAT, &int(-1), 4, "-1") == 0,
    );
    let (r, value) = p.getsockopt_bytes(t, SOL_SOCKET, SO_RCVLOWAT, 4, OptionShown::Exact);
    p.check(
        "is capped at half the locked buffer",
        r == 0 && value == int(BUFFER),
    );
    let lo = b"lo\0";
    p.check(
        "SO_BINDTODEVICE to lo",
        p.setsockopt_bytes(t, SOL_SOCKET, SO_BINDTODEVICE, lo, lo.len(), "lo") == 0,
    );
    let (r, value) = p.getsockopt_bytes(t, SOL_SOCKET, SO_BINDTODEVICE, 16, OptionShown::Exact);
    p.check("SO_BINDTODEVICE reads back lo", r == 0 && value == lo);

    p.check(
        "an int option with a short optlen is EINVAL",
        p.setsockopt_bytes(t, SOL_SOCKET, SO_KEEPALIVE, &int(1), 2, "1") == neg(EINVAL),
    );
    let (r, value) = p.getsockopt_bytes(t, SOL_SOCKET, SO_TYPE, 2, OptionShown::Exact);
    p.check(
        "a two-byte getsockopt buffer gets two bytes of the value",
        r == 0 && value == int(SOCK_STREAM)[..2],
    );
    p.check(
        "an unknown SOL_SOCKET option is ENOPROTOOPT to set",
        p.setsockopt_bytes(t, SOL_SOCKET, NO_OPTION, &int(1), 4, "1") == neg(ENOPROTOOPT),
    );
    p.check(
        "and to get",
        p.getsockopt_bytes(t, SOL_SOCKET, NO_OPTION, 4, OptionShown::Exact)
            .0
            == neg(ENOPROTOOPT),
    );
    p.check(
        "an unknown level of a TCP socket is ENOPROTOOPT to set",
        p.setsockopt_bytes(t, NO_LEVEL, 1, &int(1), 4, "1") == neg(ENOPROTOOPT),
    );
    p.check(
        "and EOPNOTSUPP to get",
        p.getsockopt_bytes(t, NO_LEVEL, 1, 4, OptionShown::Exact).0 == neg(EOPNOTSUPP),
    );

    let u = p.socket(AF_INET, SOCK_DGRAM, 0);
    p.require("a UDP socket", u >= 0);
    for (label, name, expected) in [
        ("SO_TYPE is SOCK_DGRAM", SO_TYPE, SOCK_DGRAM),
        ("SO_PROTOCOL is IPPROTO_UDP", SO_PROTOCOL, IPPROTO_UDP),
        ("SO_ERROR is clear", SO_ERROR, 0),
    ] {
        let (r, value) = p.getsockopt_bytes(u, SOL_SOCKET, name, 4, OptionShown::Exact);
        p.check(label, r == 0 && value == int(expected));
    }
    let (r, value) = p.getsockopt_bytes(u, SOL_SOCKET, SO_BROADCAST, 4, OptionShown::Exact);
    p.check("SO_BROADCAST defaults to 0", r == 0 && value == int(0));
    p.check(
        "set SO_BROADCAST",
        p.setsockopt_bytes(u, SOL_SOCKET, SO_BROADCAST, &int(1), 4, "1") == 0,
    );
    let (r, value) = p.getsockopt_bytes(u, SOL_SOCKET, SO_BROADCAST, 4, OptionShown::Exact);
    p.check("SO_BROADCAST reads back 1", r == 0 && value == int(1));
    p.check(
        "SO_RCVLOWAT -1 on the UDP socket",
        p.setsockopt_bytes(u, SOL_SOCKET, SO_RCVLOWAT, &int(-1), 4, "-1") == 0,
    );
    let (r, value) = p.getsockopt_bytes(u, SOL_SOCKET, SO_RCVLOWAT, 4, OptionShown::Exact);
    p.check("is INT_MAX", r == 0 && value == int(i32::MAX));
    p.check(
        "SO_REUSEPORT on the first UDP socket",
        p.setsockopt_bytes(u, SOL_SOCKET, SO_REUSEPORT, &int(1), 4, "1") == 0,
    );
    p.check("bind it", p.bind_to(u, &SockAddr::v4(0)) == 0);
    let (_, addr_u, _) = p.name_of(u, false, 128);
    let addr_u = addr_u.expect("getsockname u");
    let u2 = p.socket(AF_INET, SOCK_DGRAM, 0);
    p.require("a second UDP socket", u2 >= 0);
    p.check(
        "without SO_REUSEPORT the port is EADDRINUSE",
        p.bind_to(u2, &addr_u) == neg(EADDRINUSE),
    );
    p.check(
        "SO_REUSEPORT on the second",
        p.setsockopt_bytes(u2, SOL_SOCKET, SO_REUSEPORT, &int(1), 4, "1") == 0,
    );
    p.check("both bind one port", p.bind_to(u2, &addr_u) == 0);

    let file = p.openat(AT_FDCWD, &format!("{root}/file"), O_RDWR | O_CREAT, 0o600);
    p.require("open a file", file >= 0);
    p.check(
        "setsockopt on a file is ENOTSOCK",
        p.setsockopt_bytes(file, SOL_SOCKET, SO_KEEPALIVE, &int(1), 4, "1") == neg(ENOTSOCK),
    );
    p.check(
        "getsockopt on a file is ENOTSOCK",
        p.getsockopt_bytes(file, SOL_SOCKET, SO_TYPE, 4, OptionShown::Exact)
            .0
            == neg(ENOTSOCK),
    );
    for fd in [t, u, u2, file] {
        p.close(fd);
    }
    p.check(
        "setsockopt on a closed descriptor is EBADF",
        p.setsockopt_bytes(t, SOL_SOCKET, SO_KEEPALIVE, &int(1), 4, "1") == neg(EBADF),
    );
    p.check(
        "getsockopt on a closed descriptor is EBADF",
        p.getsockopt_bytes(t, SOL_SOCKET, SO_TYPE, 4, OptionShown::Exact)
            .0
            == neg(EBADF),
    );
    crate::scenarios::net::check_allocated_port(p, &addr_u);
}

pub const SCENARIO: Scenario = Scenario {
    name: "net/sockopt",
    run,
    covers: &[
        Syscall::N_socket,
        Syscall::N_setsockopt,
        Syscall::N_getsockopt,
        Syscall::N_bind,
        Syscall::N_getsockname,
        Syscall::N_openat,
        Syscall::N_close,
    ],
    symbols: &[
        "socket",
        "setsockopt",
        "getsockopt",
        "bind",
        "getsockname",
        "openat",
        "close",
    ],
    kernel_floor: Some(KernelFloor {
        release: "5.7",
        why: "an unprivileged SO_BINDTODEVICE on an unbound socket (net/core/sock.c sock_bindtoindex_locked)",
    }),
    ..DEFAULTS
};
