//! net/ipopts — the IP-, IPv6- and UDP-level socket options the option store
//! models, set and read back (ip(7), ipv6(7), udp(7); net/ipv4/ip_sockglue.c
//! `do_ip_setsockopt`/`do_ip_getsockopt`, net/ipv6/ipv6_sockglue.c
//! `do_ipv6_setsockopt`/`do_ipv6_getsockopt`, net/ipv4/udp.c
//! `udp_lib_setsockopt`/`udp_lib_getsockopt`):
//!
//! * `IP_TTL` reads the default 64 until set; it takes 1..=255 as an `int`
//!   or a single byte, -1 restores the default, anything else (and an empty
//!   value) is `EINVAL`;
//! * `do_ip_getsockopt` answers a value that fits a byte as one byte when
//!   the caller's room is under an `int`, nothing for no room, and `EINVAL`
//!   for a negative room;
//! * `IP_MTU_DISCOVER` and `IPV6_MTU_DISCOVER` read `IP_PMTUDISC_WANT` until
//!   set and take the modes up to `IP_PMTUDISC_OMIT`; `IP_RECVTOS`,
//!   `IP_PKTINFO`, `IPV6_RECVTCLASS` and `IPV6_RECVPKTINFO` read back what
//!   was set;
//! * a stream keeps its own ECN bits under `IP_TOS` and `IPV6_TCLASS`;
//!   `IPV6_TCLASS` -1 is the default class 0, and past a byte `EINVAL`;
//! * `IPV6_DONTFRAG` is a boolean read back as 0 or 1, and a value shorter
//!   than an `int` clears it (the one IPv6 option without a length check);
//! * `IPV6_UNICAST_HOPS` reads the default 64 until set (and after -1),
//!   takes -1..=255, and reads back into a shorter buffer as the leading
//!   bytes of its `int`;
//! * `UDP_SEGMENT` reads 0 until set and back what was set; a value shorter
//!   than an `int` is `EINVAL`.
//!
//! The defaults (64 hops, `IP_PMTUDISC_WANT`) are the host's sysctls at
//! their kernel defaults (`ip_default_ttl`, `conf/all/hop_limit`,
//! `ip_no_pmtu_disc`).

use crate::catalog::{Arc, DEFAULTS, Gap, Need, Scenario, Status};
use crate::compare::{Difference, Failure, Observed};
use crate::probe::{OptionShown, Probe, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

const UDP_SEGMENT: i32 = 103;
const IPV6_DONTFRAG: i32 = 62;
const PMTUDISC_WANT: i32 = 1;
const PMTUDISC_OMIT: i32 = 5;

/// Set an `int` option and read it back.
fn set_get(p: &Probe, fd: i32, level: i32, name: i32, value: i32, what: &str) -> i32 {
    p.check(
        &format!("set {what} {value}"),
        p.setsockopt_int(fd, level, name, value) == 0,
    );
    let (r, got) = p.getsockopt_int(fd, level, name);
    p.require(&format!("read {what} back"), r == 0);
    got
}

pub fn run(p: &Probe) {
    // ---- IPv4 ----
    let u = p.socket(AF_INET, SOCK_DGRAM, 0);
    p.require("a UDP socket", u >= 0);
    p.check(
        "IP_TTL reads the default 64 until set",
        p.getsockopt_int(u, IPPROTO_IP, IP_TTL) == (0, 64),
    );
    p.check(
        "IP_TTL reads back what was set",
        set_get(p, u, IPPROTO_IP, IP_TTL, 5, "IP_TTL") == 5,
    );
    p.check(
        "IP_TTL as a single byte",
        p.setsockopt_bytes(u, IPPROTO_IP, IP_TTL, &[9], 1, "9") == 0,
    );
    p.check(
        "reads back",
        p.getsockopt_int(u, IPPROTO_IP, IP_TTL) == (0, 9),
    );
    p.check(
        "IP_TTL -1 restores the default",
        set_get(p, u, IPPROTO_IP, IP_TTL, -1, "IP_TTL") == 64,
    );
    for value in [0, 256, -2] {
        p.check(
            &format!("IP_TTL {value} is EINVAL"),
            p.setsockopt_int(u, IPPROTO_IP, IP_TTL, value) == neg(EINVAL),
        );
    }
    p.check(
        "an empty IP_TTL is EINVAL",
        p.setsockopt_bytes(u, IPPROTO_IP, IP_TTL, &[0; 4], 0, "empty") == neg(EINVAL),
    );
    let (r, bytes) = p.getsockopt_bytes(u, IPPROTO_IP, IP_TTL, 1, OptionShown::Exact);
    p.check(
        "one byte of room reads the value as a byte",
        r == 0 && bytes == [64],
    );
    let (r, bytes) = p.getsockopt_bytes(u, IPPROTO_IP, IP_TTL, 3, OptionShown::Exact);
    p.check("and so do three", r == 0 && bytes == [64]);
    let (r, bytes) = p.getsockopt_bytes(u, IPPROTO_IP, IP_TTL, 0, OptionShown::Exact);
    p.check("no room reads nothing", r == 0 && bytes.is_empty());
    p.check(
        "a negative room is EINVAL",
        p.getsockopt_optlen(u, IPPROTO_IP, IP_TTL, -1) == neg(EINVAL),
    );
    p.check(
        "IP_MTU_DISCOVER reads IP_PMTUDISC_WANT until set",
        p.getsockopt_int(u, IPPROTO_IP, IP_MTU_DISCOVER) == (0, PMTUDISC_WANT),
    );
    p.check(
        "reads back IP_PMTUDISC_OMIT",
        set_get(
            p,
            u,
            IPPROTO_IP,
            IP_MTU_DISCOVER,
            PMTUDISC_OMIT,
            "IP_MTU_DISCOVER",
        ) == PMTUDISC_OMIT,
    );
    for value in [PMTUDISC_OMIT + 1, -1] {
        p.check(
            &format!("IP_MTU_DISCOVER {value} is EINVAL"),
            p.setsockopt_int(u, IPPROTO_IP, IP_MTU_DISCOVER, value) == neg(EINVAL),
        );
    }
    for (name, what) in [(IP_RECVTOS, "IP_RECVTOS"), (IP_PKTINFO, "IP_PKTINFO")] {
        p.check(
            &format!("{what} reads 0 until set"),
            p.getsockopt_int(u, IPPROTO_IP, name) == (0, 0),
        );
        p.check(
            &format!("{what} reads back 1"),
            set_get(p, u, IPPROTO_IP, name, 1, what) == 1,
        );
    }
    p.check(
        "UDP_SEGMENT reads 0 until set",
        p.getsockopt_int(u, IPPROTO_UDP, UDP_SEGMENT) == (0, 0),
    );
    p.check(
        "UDP_SEGMENT reads back what was set",
        set_get(p, u, IPPROTO_UDP, UDP_SEGMENT, 1400, "UDP_SEGMENT") == 1400,
    );
    p.check(
        "a UDP_SEGMENT shorter than an int is EINVAL",
        p.setsockopt_bytes(u, IPPROTO_UDP, UDP_SEGMENT, &[1, 0], 2, "short") == neg(EINVAL),
    );
    let t4 = p.socket(AF_INET, SOCK_STREAM, 0);
    p.require("a TCP socket", t4 >= 0);
    p.check(
        "a stream's IP_TOS keeps its ECN bits",
        set_get(p, t4, IPPROTO_IP, IP_TOS, 0x2f, "IP_TOS") == 0x2c,
    );

    // ---- IPv6 ----
    let v = p.socket(AF_INET6, SOCK_DGRAM, 0);
    p.require("an IPv6 UDP socket", v >= 0);
    p.check(
        "IPV6_TCLASS reads 0 until set",
        p.getsockopt_int(v, IPPROTO_IPV6, IPV6_TCLASS) == (0, 0),
    );
    p.check(
        "IPV6_TCLASS reads back what was set",
        set_get(p, v, IPPROTO_IPV6, IPV6_TCLASS, 0x2e, "IPV6_TCLASS") == 0x2e,
    );
    p.check(
        "IPV6_TCLASS -1 is the default class 0",
        set_get(p, v, IPPROTO_IPV6, IPV6_TCLASS, -1, "IPV6_TCLASS") == 0,
    );
    for value in [256, -2] {
        p.check(
            &format!("IPV6_TCLASS {value} is EINVAL"),
            p.setsockopt_int(v, IPPROTO_IPV6, IPV6_TCLASS, value) == neg(EINVAL),
        );
    }
    p.check(
        "an IPV6_TCLASS shorter than an int is EINVAL",
        p.setsockopt_bytes(v, IPPROTO_IPV6, IPV6_TCLASS, &[1, 0], 2, "short") == neg(EINVAL),
    );
    p.check(
        "IPV6_MTU_DISCOVER reads IPV6_PMTUDISC_WANT until set",
        p.getsockopt_int(v, IPPROTO_IPV6, IPV6_MTU_DISCOVER) == (0, PMTUDISC_WANT),
    );
    p.check(
        "reads back IPV6_PMTUDISC_OMIT",
        set_get(
            p,
            v,
            IPPROTO_IPV6,
            IPV6_MTU_DISCOVER,
            PMTUDISC_OMIT,
            "IPV6_MTU_DISCOVER",
        ) == PMTUDISC_OMIT,
    );
    p.check(
        "IPV6_MTU_DISCOVER past IPV6_PMTUDISC_OMIT is EINVAL",
        p.setsockopt_int(v, IPPROTO_IPV6, IPV6_MTU_DISCOVER, PMTUDISC_OMIT + 1) == neg(EINVAL),
    );
    for (name, what) in [
        (IPV6_RECVTCLASS, "IPV6_RECVTCLASS"),
        (IPV6_RECVPKTINFO, "IPV6_RECVPKTINFO"),
    ] {
        p.check(
            &format!("{what} reads 0 until set"),
            p.getsockopt_int(v, IPPROTO_IPV6, name) == (0, 0),
        );
        p.check(
            &format!("{what} reads back 1"),
            set_get(p, v, IPPROTO_IPV6, name, 1, what) == 1,
        );
    }
    p.check(
        "IPV6_DONTFRAG reads 0 until set",
        p.getsockopt_int(v, IPPROTO_IPV6, IPV6_DONTFRAG) == (0, 0),
    );
    p.check(
        "IPV6_DONTFRAG 2 reads back 1",
        set_get(p, v, IPPROTO_IPV6, IPV6_DONTFRAG, 2, "IPV6_DONTFRAG") == 1,
    );
    p.check(
        "an IPV6_DONTFRAG shorter than an int clears it",
        p.setsockopt_bytes(v, IPPROTO_IPV6, IPV6_DONTFRAG, &[1, 0], 2, "short") == 0,
    );
    p.check(
        "reads back 0",
        p.getsockopt_int(v, IPPROTO_IPV6, IPV6_DONTFRAG) == (0, 0),
    );
    p.check(
        "IPV6_UNICAST_HOPS reads the default 64 until set",
        p.getsockopt_int(v, IPPROTO_IPV6, IPV6_UNICAST_HOPS) == (0, 64),
    );
    p.check(
        "IPV6_UNICAST_HOPS reads back what was set",
        set_get(
            p,
            v,
            IPPROTO_IPV6,
            IPV6_UNICAST_HOPS,
            7,
            "IPV6_UNICAST_HOPS",
        ) == 7,
    );
    let (r, bytes) = p.getsockopt_bytes(v, IPPROTO_IPV6, IPV6_UNICAST_HOPS, 1, OptionShown::Exact);
    p.check(
        "one byte of room reads the int's leading byte",
        r == 0 && bytes == 7i32.to_ne_bytes()[..1],
    );
    p.check(
        "IPV6_UNICAST_HOPS -1 restores the default",
        set_get(
            p,
            v,
            IPPROTO_IPV6,
            IPV6_UNICAST_HOPS,
            -1,
            "IPV6_UNICAST_HOPS",
        ) == 64,
    );
    for value in [256, -2] {
        p.check(
            &format!("IPV6_UNICAST_HOPS {value} is EINVAL"),
            p.setsockopt_int(v, IPPROTO_IPV6, IPV6_UNICAST_HOPS, value) == neg(EINVAL),
        );
    }
    p.check(
        "UDP_SEGMENT on an IPv6 socket reads back what was set",
        set_get(p, v, IPPROTO_UDP, UDP_SEGMENT, 1200, "UDP_SEGMENT") == 1200,
    );
    let t6 = p.socket(AF_INET6, SOCK_STREAM, 0);
    p.require("an IPv6 TCP socket", t6 >= 0);
    p.check(
        "a stream's IPV6_TCLASS keeps its ECN bits",
        set_get(p, t6, IPPROTO_IPV6, IPV6_TCLASS, 0x2f, "IPV6_TCLASS") == 0x2c,
    );
    for fd in [u, t4, v, t6] {
        p.close(fd);
    }
}

pub const SCENARIO: Scenario = Scenario {
    name: "net/ipopts",
    run,
    covers: &[
        Syscall::N_socket,
        Syscall::N_setsockopt,
        Syscall::N_getsockopt,
        Syscall::N_close,
    ],
    symbols: &["socket", "setsockopt", "getsockopt", "close"],
    needs: &[Need::Ipv6Loopback],
    gaps: &[
        Gap {
            status: Status::Pending(Arc::NetworkReadiness),
            vehicles: Vehicle::ALL,
            what: "IPV6_DONTFRAG shorter than an int is EINVAL (thread/net/opts.rs set_ipv6); do_ipv6_setsockopt takes it as 0",
            failure: Failure::Differs(&[
                Difference::field(109, "setsockopt", "errno", Observed::Str("EINVAL")),
                Difference::field(109, "setsockopt", "ret", Observed::Int(-1)),
                Difference::check(110, "an IPV6_DONTFRAG shorter than an int clears it"),
                Difference::field(111, "getsockopt", "fields.value", Observed::Int(1)),
                Difference::check(112, "reads back 0"),
            ]),
        },
        Gap {
            status: Status::Pending(Arc::NetworkReadiness),
            vehicles: Vehicle::ALL,
            what: "IPV6_TCLASS on a stream overwrites its ECN bits (thread/net/opts.rs set_ipv6); do_ipv6_setsockopt keeps them",
            failure: Failure::Differs(&[
                Difference::field(136, "getsockopt", "fields.value", Observed::Int(0x2f)),
                Difference::check(137, "a stream's IPV6_TCLASS keeps its ECN bits"),
            ]),
        },
    ],
    ..DEFAULTS
};
