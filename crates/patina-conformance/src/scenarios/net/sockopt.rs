//! net/sockopt — the socket option table over loopback IPv4 TCP and UDP
//! sockets (socket(7), tcp(7), ip(7); net/core/sock.c `sk_setsockopt`/
//! `sk_getsockopt`, net/ipv4/tcp.c, net/ipv4/ip_sockglue.c):
//!
//! * identity options: `SO_TYPE`, `SO_DOMAIN`, `SO_PROTOCOL`,
//!   `SO_ACCEPTCONN`, `SO_ERROR`;
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

use crate::catalog::{Arc, DEFAULTS, Gap, KernelFloor, Scenario, Status};
use crate::compare::{Difference, Failure, Observed};
use crate::probe::{AT_FDCWD, OptionShown, Probe, SockAddr, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

/// A socket option level no protocol has.
const NO_LEVEL: i32 = 9999;
/// A `SOL_SOCKET` option number no kernel has.
const NO_OPTION: i32 = 9999;
/// The buffer size set: small enough for any `rmem_max`/`wmem_max`, doubled
/// above the kernel's minimum.
const BUFFER: i32 = 4096;

fn int(value: i32) -> [u8; 4] {
    value.to_ne_bytes()
}

fn timeval(sec: i64, usec: i64) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&sec.to_ne_bytes());
    bytes[8..].copy_from_slice(&usec.to_ne_bytes());
    bytes
}

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
    let (r, value) = p.getsockopt_bytes(u, SOL_SOCKET, SO_PROTOCOL, 4, OptionShown::Exact);
    p.check(
        "SO_PROTOCOL is IPPROTO_UDP",
        r == 0 && value == int(IPPROTO_UDP),
    );
    let (r, value) = p.getsockopt_bytes(u, SOL_SOCKET, SO_BROADCAST, 4, OptionShown::Exact);
    p.check("SO_BROADCAST defaults to 0", r == 0 && value == int(0));
    p.check(
        "set SO_BROADCAST",
        p.setsockopt_bytes(u, SOL_SOCKET, SO_BROADCAST, &int(1), 4, "1") == 0,
    );
    let (r, value) = p.getsockopt_bytes(u, SOL_SOCKET, SO_BROADCAST, 4, OptionShown::Exact);
    p.check("SO_BROADCAST reads back 1", r == 0 && value == int(1));
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
    gaps: &[
        Gap {
            status: Status::Pending(Arc::NetworkReadiness),
            vehicles: Vehicle::ALL,
            what: "getsockopt has no option store: it zeroes the caller's buffer and reports success with optlen unchanged (c/posix/net.c getsockopt, sud/net.rs sys_getsockopt), so every identity, boolean, linger, timeout, buffer and device option reads 0 and an unknown option or level is not refused",
            failure: Failure::Differs(&[
                Difference::field(1, "getsockopt", "fields.value", Observed::Str("00000000")),
                Difference::check(2, "SO_TYPE is SOCK_STREAM"),
                Difference::field(3, "getsockopt", "fields.value", Observed::Str("00000000")),
                Difference::check(4, "SO_DOMAIN is AF_INET"),
                Difference::field(5, "getsockopt", "fields.value", Observed::Str("00000000")),
                Difference::check(6, "SO_PROTOCOL is IPPROTO_TCP"),
                Difference::field(15, "getsockopt", "fields.value", Observed::Str("00000000")),
                Difference::check(16, "SO_REUSEADDR reads back 1"),
                Difference::field(21, "getsockopt", "fields.value", Observed::Str("00000000")),
                Difference::check(22, "SO_REUSEPORT reads back 1"),
                Difference::field(27, "getsockopt", "fields.value", Observed::Str("00000000")),
                Difference::check(28, "SO_KEEPALIVE reads back 1"),
                Difference::field(33, "getsockopt", "fields.value", Observed::Str("00000000")),
                Difference::check(34, "TCP_NODELAY reads back 1"),
                Difference::field(
                    39,
                    "getsockopt",
                    "fields.value",
                    Observed::Str("0000000000000000"),
                ),
                Difference::check(40, "SO_LINGER reads back {1, 5}"),
                Difference::field(
                    45,
                    "getsockopt",
                    "fields.value",
                    Observed::Str("00000000000000000000000000000000"),
                ),
                Difference::check(46, "SO_RCVTIMEO reads back 2 s"),
                Difference::field(
                    53,
                    "getsockopt",
                    "fields.value",
                    Observed::Str("00000000000000000000000000000000"),
                ),
                Difference::check(54, "SO_SNDTIMEO reads back 2 s"),
                Difference::check(58, "SO_RCVBUF's default is at least twice the value set"),
                Difference::check(62, "SO_RCVBUF reads back doubled"),
                Difference::check(64, "SO_SNDBUF's default is at least twice the value set"),
                Difference::check(68, "SO_SNDBUF reads back doubled"),
                Difference::field(71, "getsockopt", "fields.optlen", Observed::Int(16)),
                Difference::field(
                    71,
                    "getsockopt",
                    "fields.value",
                    Observed::Str("00000000000000000000000000000000"),
                ),
                Difference::check(72, "SO_BINDTODEVICE reads back lo"),
                Difference::field(75, "getsockopt", "fields.value", Observed::Str("0000")),
                Difference::check(
                    76,
                    "a two-byte getsockopt buffer gets two bytes of the value",
                ),
                Difference::field(79, "getsockopt", "errno", Observed::Null),
                Difference::field(79, "getsockopt", "fields.optlen", Observed::Int(4)),
                Difference::field(79, "getsockopt", "fields.value", Observed::Str("00000000")),
                Difference::field(79, "getsockopt", "ret", Observed::Int(0)),
                Difference::check(80, "and to get"),
                Difference::field(83, "getsockopt", "errno", Observed::Null),
                Difference::field(83, "getsockopt", "fields.optlen", Observed::Int(4)),
                Difference::field(83, "getsockopt", "fields.value", Observed::Str("00000000")),
                Difference::field(83, "getsockopt", "ret", Observed::Int(0)),
                Difference::check(84, "and EOPNOTSUPP to get"),
                Difference::field(86, "getsockopt", "fields.value", Observed::Str("00000000")),
                Difference::check(87, "SO_PROTOCOL is IPPROTO_UDP"),
                Difference::field(92, "getsockopt", "fields.value", Observed::Str("00000000")),
                Difference::check(93, "SO_BROADCAST reads back 1"),
            ]),
        },
        Gap {
            status: Status::Pending(Arc::NetworkReadiness),
            vehicles: Vehicle::ALL,
            what: "setsockopt accepts a fixed no-op list (c/posix/net.c setsockopt, sud/net.rs sys_setsockopt): SO_LINGER on, a non-zero SO_SNDTIMEO, SO_RCVBUF, SO_SNDBUF and SO_BINDTODEVICE answer ENOPROTOOPT, and nothing is validated — no EDOM for a timeval's microseconds, no EINVAL for a short optlen",
            failure: Failure::Differs(&[
                Difference::field(37, "setsockopt", "errno", Observed::Str("ENOPROTOOPT")),
                Difference::field(37, "setsockopt", "ret", Observed::Int(-1)),
                Difference::check(38, "set SO_LINGER on, 5 s"),
                Difference::field(47, "setsockopt", "errno", Observed::Null),
                Difference::field(47, "setsockopt", "ret", Observed::Int(0)),
                Difference::check(48, "SO_RCVTIMEO with a million microseconds is EDOM"),
                Difference::field(51, "setsockopt", "errno", Observed::Str("ENOPROTOOPT")),
                Difference::field(51, "setsockopt", "ret", Observed::Int(-1)),
                Difference::check(52, "set SO_SNDTIMEO to 2 s"),
                Difference::field(55, "setsockopt", "errno", Observed::Str("ENOPROTOOPT")),
                Difference::check(56, "SO_SNDTIMEO with a million microseconds is EDOM"),
                Difference::field(59, "setsockopt", "errno", Observed::Str("ENOPROTOOPT")),
                Difference::field(59, "setsockopt", "ret", Observed::Int(-1)),
                Difference::check(60, "set SO_RCVBUF"),
                Difference::field(65, "setsockopt", "errno", Observed::Str("ENOPROTOOPT")),
                Difference::field(65, "setsockopt", "ret", Observed::Int(-1)),
                Difference::check(66, "set SO_SNDBUF"),
                Difference::field(69, "setsockopt", "errno", Observed::Str("ENOPROTOOPT")),
                Difference::field(69, "setsockopt", "ret", Observed::Int(-1)),
                Difference::check(70, "SO_BINDTODEVICE to lo"),
                Difference::field(73, "setsockopt", "errno", Observed::Null),
                Difference::field(73, "setsockopt", "ret", Observed::Int(0)),
                Difference::check(74, "an int option with a short optlen is EINVAL"),
            ]),
        },
        Gap {
            status: Status::Pending(Arc::NetworkReadiness),
            vehicles: Vehicle::ALL,
            what: "bind to a port another socket holds answers EEXIST instead of EADDRINUSE, and SO_REUSEPORT does not let two sockets share a port (SimNet's bound-address table)",
            failure: Failure::Differs(&[
                Difference::field(100, "bind", "errno", Observed::Str("EEXIST")),
                Difference::check(101, "without SO_REUSEPORT the port is EADDRINUSE"),
                Difference::field(104, "bind", "errno", Observed::Str("EEXIST")),
                Difference::field(104, "bind", "ret", Observed::Int(-1)),
                Difference::check(105, "both bind one port"),
            ]),
        },
    ],
    ..DEFAULTS
};
