//! net/ipctl — the IP- and UDP-level ancillary data a datagram socket sends
//! and receives over loopback (ip(7), ipv6(7), udp(7); net/ipv4/ip_sockglue.c
//! `ip_cmsg_send`/`ip_cmsg_recv`, net/ipv6/datagram.c
//! `ip6_datagram_send_ctl`/`ip6_datagram_recv_ctl`, net/ipv4/udp.c
//! `udp_cmsg_send`/`udp_send_skb`):
//!
//! * `IP_TOS` as a byte or an `int`, then `IP_RECVTOS`, reports the type of
//!   service a datagram carried; the `IP_TOS` socket option is the default;
//!   a value past 255 or another size is `EINVAL`;
//! * `IP_PKTINFO` reports the interface and the local address a datagram
//!   reached; sent, its `ipi_spec_dst` is the source the datagram leaves
//!   from — a local address, else `ENETUNREACH` — and its interface index
//!   must name an interface (`ENODEV`); another size is `EINVAL`;
//! * `IP_TTL` is taken; an unknown IP-level type is `EINVAL`, another
//!   family's level is skipped;
//! * `UDP_SEGMENT` cuts a send into datagrams of that size, the last shorter;
//!   more than 128 segments is `EINVAL`, another size `EINVAL`;
//! * over IPv6, `IPV6_TCLASS` (-1 is the byte 255) and `IPV6_PKTINFO` with
//!   `IPV6_RECVTCLASS`/`IPV6_RECVPKTINFO`; a source that is no local
//!   address is `EINVAL`, an unknown interface `ENODEV`; an IPv4 datagram on
//!   a dual-stack socket reports both families' packet information;
//! * the RFC 2292 numbers: `IPV6_2292PKTINFO` and `IPV6_2292HOPLIMIT` are
//!   their RFC 3542 types, `IPV6_2292PKTOPTIONS` is `EINVAL`; an
//!   `IPV6_PKTINFO` may be longer than `in6_pktinfo`, not shorter;
//!   `IPV6_DONTFRAG` is 0 or 1;
//! * an IPv4 source is judged before the interface (`ENETUNREACH` first),
//!   one on network 0 included.
//!
//! Reads right after a send rely on loopback delivery before the send
//! returns (scenarios/net.rs, "Loopback delivery").

use crate::catalog::{Arc, DEFAULTS, Gap, Need, Scenario, Status};
use crate::compare::{Ending, Failure};
use crate::probe::{Control, Probe, RecvSpec, SockAddr, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

const UDP_SEGMENT: i32 = 103;
// The RFC 2292 numbers (include/uapi/linux/in6.h).
const IPV6_2292PKTINFO: i32 = 2;
const IPV6_2292PKTOPTIONS: i32 = 6;
const IPV6_2292HOPLIMIT: i32 = 8;

fn int(value: i32) -> Vec<u8> {
    value.to_ne_bytes().to_vec()
}

fn pktinfo4(ifindex: i32, spec: Ipv4Addr) -> Vec<u8> {
    let mut bytes = int(ifindex);
    bytes.extend(spec.octets());
    bytes.extend([0; 4]);
    bytes
}

fn pktinfo6(address: Ipv6Addr, ifindex: i32) -> Vec<u8> {
    let mut bytes = address.octets().to_vec();
    bytes.extend(int(ifindex));
    bytes
}

/// A receive with room for ancillary data.
const WITH_CONTROL: RecvSpec<'static> = RecvSpec {
    segments: &[64],
    name: Some(128),
    control: 256,
    flags: 0,
};

/// Receive until `EAGAIN` (unrecorded), counting the datagrams and their
/// sizes.
fn drain(p: &Probe, fd: i32) -> Vec<i64> {
    let mut buf = [0u8; 256];
    let mut sizes = Vec::new();
    for _ in 0..512 {
        let n = p.call_unrecorded(
            Syscall::N_recvfrom,
            [
                fd as i64,
                buf.as_mut_ptr() as i64,
                buf.len() as i64,
                0,
                0,
                0,
            ],
        );
        if n < 0 {
            break;
        }
        sizes.push(n);
    }
    sizes
}

pub fn run(p: &Probe) {
    // ---- IPv4 ----
    let r = p.socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    p.require("a receiver", r >= 0);
    p.check("bind it", p.bind_to(r, &SockAddr::v4(0)) == 0);
    let (_, to, _) = p.name_of(r, false, 128);
    let to = to.expect("getsockname r");
    let s = p.socket(AF_INET, SOCK_DGRAM, 0);
    p.require("a sender", s >= 0);
    p.check(
        "bind the sender to the wildcard",
        p.bind_to(
            s,
            &SockAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
        ) == 0,
    );
    p.check(
        "IP_RECVTOS",
        p.setsockopt_int(r, IPPROTO_IP, IP_RECVTOS, 1) == 0,
    );
    p.check(
        "IP_PKTINFO",
        p.setsockopt_int(r, IPPROTO_IP, IP_PKTINFO, 1) == 0,
    );
    let tos = |value: Vec<u8>| Control::Protocol(vec![(IPPROTO_IP, IP_TOS, value)]);
    p.check(
        "IP_TOS as a byte",
        p.sendmsg(s, &[b"a"], Some(&to), &tos(vec![0x2e]), 0) == 1,
    );
    let got = p.recvmsg(r, WITH_CONTROL);
    p.check(
        "the receive reports the packet information, then the type of service",
        got.result == 1
            && got.protocol
                == vec![
                    (
                        IPPROTO_IP,
                        IP_PKTINFO,
                        [int(1), vec![127, 0, 0, 1, 127, 0, 0, 1]].concat(),
                    ),
                    (IPPROTO_IP, IP_TOS, vec![0x2e]),
                ],
    );
    p.check(
        "IP_TOS as an int",
        p.sendmsg(s, &[b"b"], Some(&to), &tos(int(0xb9)), 0) == 1,
    );
    let got = p.recvmsg(r, WITH_CONTROL);
    p.check(
        "carries it",
        got.protocol.get(1) == Some(&(IPPROTO_IP, IP_TOS, vec![0xb9])),
    );
    p.check(
        "a type of service past 255 is EINVAL",
        p.sendmsg(s, &[b"c"], Some(&to), &tos(int(256)), 0) == neg(EINVAL),
    );
    p.check(
        "an IP_TOS of another size is EINVAL",
        p.sendmsg(s, &[b"c"], Some(&to), &tos(vec![3, 0]), 0) == neg(EINVAL),
    );
    p.check(
        "the IP_TOS socket option",
        p.setsockopt_int(s, IPPROTO_IP, IP_TOS, 0x10) == 0,
    );
    p.check(
        "reads back",
        p.getsockopt_int(s, IPPROTO_IP, IP_TOS) == (0, 0x10),
    );
    p.check(
        "a plain send",
        p.sendmsg(s, &[b"d"], Some(&to), &Control::None, 0) == 1,
    );
    let got = p.recvmsg(r, WITH_CONTROL);
    p.check(
        "carries the socket's type of service",
        got.protocol.get(1) == Some(&(IPPROTO_IP, IP_TOS, vec![0x10])),
    );
    let info = |ifindex: i32, spec: Ipv4Addr| {
        Control::Protocol(vec![(IPPROTO_IP, IP_PKTINFO, pktinfo4(ifindex, spec))])
    };
    p.check(
        "IP_PKTINFO names another local source",
        p.sendmsg(
            s,
            &[b"e"],
            Some(&to),
            &info(0, Ipv4Addr::new(127, 0, 0, 9)),
            0,
        ) == 1,
    );
    let got = p.recvmsg(r, WITH_CONTROL);
    p.check(
        "the datagram leaves from it",
        got.result == 1
            && matches!(got.name, Some(SockAddr::V4(from)) if *from.ip() == Ipv4Addr::new(127, 0, 0, 9)),
    );
    p.check(
        "a source that is no local address is ENETUNREACH",
        p.sendmsg(
            s,
            &[b"f"],
            Some(&to),
            &info(0, Ipv4Addr::new(8, 8, 8, 8)),
            0,
        ) == neg(ENETUNREACH),
    );
    p.check(
        "an interface that does not exist is ENODEV",
        p.sendmsg(s, &[b"g"], Some(&to), &info(99, Ipv4Addr::UNSPECIFIED), 0) == neg(ENODEV),
    );
    p.check(
        "an IP_PKTINFO of another size is EINVAL",
        p.sendmsg(
            s,
            &[b"h"],
            Some(&to),
            &Control::Protocol(vec![(IPPROTO_IP, IP_PKTINFO, vec![0; 8])]),
            0,
        ) == neg(EINVAL),
    );
    p.check(
        "IP_TTL is taken",
        p.sendmsg(
            s,
            &[b"i"],
            Some(&to),
            &Control::Protocol(vec![(IPPROTO_IP, IP_TTL, int(5))]),
            0,
        ) == 1,
    );
    p.check(
        "an unknown IP-level type is EINVAL",
        p.sendmsg(
            s,
            &[b"j"],
            Some(&to),
            &Control::Protocol(vec![(IPPROTO_IP, 99, int(1))]),
            0,
        ) == neg(EINVAL),
    );
    p.check(
        "an IPv6-level message on an IPv4 send is skipped",
        p.sendmsg(
            s,
            &[b"k"],
            Some(&to),
            &Control::Protocol(vec![(IPPROTO_IPV6, IPV6_TCLASS, int(1))]),
            0,
        ) == 1,
    );
    let queued = drain(p, r);
    p.rec
        .event("drain", queued.len() as i64)
        .field("sizes", format!("{queued:?}"))
        .emit();

    // ---- UDP segmentation ----
    let payload = [b'x'; 256];
    let segment = |size: u16| {
        Control::Protocol(vec![(
            IPPROTO_UDP,
            UDP_SEGMENT,
            size.to_ne_bytes().to_vec(),
        )])
    };
    p.check(
        "UDP_SEGMENT cuts 25 bytes into 10-byte datagrams",
        p.sendmsg(s, &[&payload[..25]], Some(&to), &segment(10), 0) == 25,
    );
    let queued = drain(p, r);
    p.rec
        .event("drain", queued.len() as i64)
        .field("sizes", format!("{queued:?}"))
        .emit();
    p.check("10, 10 and 5", queued == [10, 10, 5]);
    p.check(
        "a payload no longer than a segment is one datagram",
        p.sendmsg(s, &[&payload[..8]], Some(&to), &segment(10), 0) == 8,
    );
    p.check("one", drain(p, r) == [8]);
    p.check(
        "128 segments",
        p.sendmsg(s, &[&payload[..128]], Some(&to), &segment(1), 0) == 128,
    );
    p.check("arrive as 128 datagrams", drain(p, r).len() == 128);
    p.check(
        "129 segments is EINVAL",
        p.sendmsg(s, &[&payload[..129]], Some(&to), &segment(1), 0) == neg(EINVAL),
    );
    p.check(
        "a UDP_SEGMENT of another size is EINVAL",
        p.sendmsg(
            s,
            &[&payload[..20]],
            Some(&to),
            &Control::Protocol(vec![(IPPROTO_UDP, UDP_SEGMENT, int(10))]),
            0,
        ) == neg(EINVAL),
    );
    p.check(
        "the UDP_SEGMENT socket option",
        p.setsockopt_int(s, IPPROTO_UDP, UDP_SEGMENT, 5) == 0,
    );
    p.check(
        "cuts a plain send",
        p.sendmsg(s, &[&payload[..12]], Some(&to), &Control::None, 0) == 12,
    );
    p.check("into 5, 5 and 2", drain(p, r) == [5, 5, 2]);
    p.check(
        "a UDP_SEGMENT option past 65535 is EINVAL",
        p.setsockopt_int(s, IPPROTO_UDP, UDP_SEGMENT, 65536) == neg(EINVAL),
    );
    p.close(s);
    p.close(r);

    // ---- IPv6 ----
    let r6 = p.socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    p.require("an IPv6 receiver", r6 >= 0);
    p.check(
        "bind it to the dual-stack wildcard",
        p.bind_to(
            r6,
            &SockAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
        ) == 0,
    );
    let (_, bound, _) = p.name_of(r6, false, 128);
    let port = bound.and_then(|a| a.port()).expect("getsockname r6");
    let to6 = SockAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, port, 0, 0));
    let s6 = p.socket(AF_INET6, SOCK_DGRAM, 0);
    p.require("an IPv6 sender", s6 >= 0);
    p.check(
        "IPV6_RECVTCLASS",
        p.setsockopt_int(r6, IPPROTO_IPV6, IPV6_RECVTCLASS, 1) == 0,
    );
    p.check(
        "IPV6_RECVPKTINFO",
        p.setsockopt_int(r6, IPPROTO_IPV6, IPV6_RECVPKTINFO, 1) == 0,
    );
    let tclass = |value: i32| Control::Protocol(vec![(IPPROTO_IPV6, IPV6_TCLASS, int(value))]);
    p.check(
        "IPV6_TCLASS",
        p.sendmsg(s6, &[b"t"], Some(&to6), &tclass(0x2e), 0) == 1,
    );
    let got = p.recvmsg(r6, WITH_CONTROL);
    p.check(
        "the receive reports the packet information, then the traffic class",
        got.protocol
            == vec![
                (IPPROTO_IPV6, IPV6_PKTINFO, pktinfo6(Ipv6Addr::LOCALHOST, 1)),
                (IPPROTO_IPV6, IPV6_TCLASS, int(0x2e)),
            ],
    );
    p.check(
        "IPV6_TCLASS -1",
        p.sendmsg(s6, &[b"u"], Some(&to6), &tclass(-1), 0) == 1,
    );
    let got = p.recvmsg(r6, WITH_CONTROL);
    p.check(
        "is the byte 255",
        got.protocol.get(1) == Some(&(IPPROTO_IPV6, IPV6_TCLASS, int(255))),
    );
    p.check(
        "a traffic class past 255 is EINVAL",
        p.sendmsg(s6, &[b"v"], Some(&to6), &tclass(256), 0) == neg(EINVAL),
    );
    let info6 = |address: Ipv6Addr, ifindex: i32| {
        Control::Protocol(vec![(
            IPPROTO_IPV6,
            IPV6_PKTINFO,
            pktinfo6(address, ifindex),
        )])
    };
    p.check(
        "IPV6_PKTINFO with the loopback source",
        p.sendmsg(s6, &[b"w"], Some(&to6), &info6(Ipv6Addr::LOCALHOST, 0), 0) == 1,
    );
    p.check("arrives", p.recvmsg(r6, WITH_CONTROL).result == 1);
    p.check(
        "a source that is no local address is EINVAL",
        p.sendmsg(
            s6,
            &[b"x"],
            Some(&to6),
            &info6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 0),
            0,
        ) == neg(EINVAL),
    );
    p.check(
        "an interface that does not exist is ENODEV",
        p.sendmsg(
            s6,
            &[b"y"],
            Some(&to6),
            &info6(Ipv6Addr::UNSPECIFIED, 99),
            0,
        ) == neg(ENODEV),
    );
    p.check(
        "and IPv4's packet information on the dual-stack receiver",
        p.setsockopt_int(r6, IPPROTO_IP, IP_PKTINFO, 1) == 0,
    );
    let s4 = p.socket(AF_INET, SOCK_DGRAM, 0);
    p.require("an IPv4 sender", s4 >= 0);
    p.check(
        "an IPv4 datagram to the dual-stack receiver",
        p.sendmsg(
            s4,
            &[b"z"],
            Some(&SockAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))),
            &Control::None,
            0,
        ) == 1,
    );
    let got = p.recvmsg(r6, WITH_CONTROL);
    p.check(
        "reports IPv6 packet information for the mapped address, then IPv4's",
        got.protocol
            == vec![
                (
                    IPPROTO_IPV6,
                    IPV6_PKTINFO,
                    pktinfo6(Ipv4Addr::LOCALHOST.to_ipv6_mapped(), 1),
                ),
                (
                    IPPROTO_IP,
                    IP_PKTINFO,
                    [int(1), vec![127, 0, 0, 1, 127, 0, 0, 1]].concat(),
                ),
            ],
    );

    // ---- the RFC 2292 numbers `ip6_datagram_send_ctl` still takes, and
    // the length and range rules around them ----
    let ipv6 = |kind: i32, data: Vec<u8>| Control::Protocol(vec![(IPPROTO_IPV6, kind, data)]);
    p.check(
        "IPV6_2292PKTINFO is IPV6_PKTINFO",
        p.sendmsg(
            s6,
            &[b"2"],
            Some(&to6),
            &ipv6(IPV6_2292PKTINFO, pktinfo6(Ipv6Addr::LOCALHOST, 0)),
            0,
        ) == 1,
    );
    p.check("arrives", p.recvmsg(r6, WITH_CONTROL).result == 1);
    p.check(
        "and judges its source as IPV6_PKTINFO does",
        p.sendmsg(
            s6,
            &[b"3"],
            Some(&to6),
            &ipv6(
                IPV6_2292PKTINFO,
                pktinfo6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 0),
            ),
            0,
        ) == neg(EINVAL),
    );
    p.check(
        "IPV6_2292HOPLIMIT is IPV6_HOPLIMIT",
        p.sendmsg(s6, &[b"4"], Some(&to6), &ipv6(IPV6_2292HOPLIMIT, int(7)), 0) == 1,
    );
    p.check("arrives", p.recvmsg(r6, WITH_CONTROL).result == 1);
    p.check(
        "and is range-checked as it is",
        p.sendmsg(
            s6,
            &[b"5"],
            Some(&to6),
            &ipv6(IPV6_2292HOPLIMIT, int(256)),
            0,
        ) == neg(EINVAL),
    );
    p.check(
        "IPV6_2292PKTOPTIONS is EINVAL",
        p.sendmsg(
            s6,
            &[b"6"],
            Some(&to6),
            &ipv6(IPV6_2292PKTOPTIONS, int(0)),
            0,
        ) == neg(EINVAL),
    );
    let mut long = pktinfo6(Ipv6Addr::LOCALHOST, 0);
    long.extend([0; 4]);
    p.check(
        "an IPV6_PKTINFO longer than in6_pktinfo is taken",
        p.sendmsg(s6, &[b"7"], Some(&to6), &ipv6(IPV6_PKTINFO, long), 0) == 1,
    );
    p.check("arrives", p.recvmsg(r6, WITH_CONTROL).result == 1);
    p.check(
        "a shorter one is EINVAL",
        p.sendmsg(s6, &[b"8"], Some(&to6), &ipv6(IPV6_PKTINFO, vec![0; 16]), 0) == neg(EINVAL),
    );
    p.check(
        "IPV6_DONTFRAG 1 is taken",
        p.sendmsg(s6, &[b"9"], Some(&to6), &ipv6(IPV6_DONTFRAG, int(1)), 0) == 1,
    );
    p.check("arrives", p.recvmsg(r6, WITH_CONTROL).result == 1);
    p.check(
        "IPV6_DONTFRAG 2 is EINVAL",
        p.sendmsg(s6, &[b"a"], Some(&to6), &ipv6(IPV6_DONTFRAG, int(2)), 0) == neg(EINVAL),
    );

    // ---- the IPv4 route lookup judges a named source before the interface ----
    let to4 = SockAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));
    let info4 = |ifindex: i32, spec: Ipv4Addr| {
        Control::Protocol(vec![(IPPROTO_IP, IP_PKTINFO, pktinfo4(ifindex, spec))])
    };
    p.check(
        "a source that is no local address is ENETUNREACH before a missing interface",
        p.sendmsg(
            s4,
            &[b"b"],
            Some(&to4),
            &info4(99, Ipv4Addr::new(8, 8, 8, 8)),
            0,
        ) == neg(ENETUNREACH),
    );
    p.check(
        "a source on network 0 is no local address either",
        p.sendmsg(
            s4,
            &[b"c"],
            Some(&to4),
            &info4(0, Ipv4Addr::new(0, 1, 2, 3)),
            0,
        ) == neg(ENETUNREACH),
    );
    for fd in [s4, s6, r6] {
        p.close(fd);
    }
}

pub const SCENARIO: Scenario = Scenario {
    name: "net/ipctl",
    run,
    covers: &[
        Syscall::N_socket,
        Syscall::N_bind,
        Syscall::N_getsockname,
        Syscall::N_setsockopt,
        Syscall::N_getsockopt,
        Syscall::N_sendmsg,
        Syscall::N_recvmsg,
        Syscall::N_recvfrom,
        Syscall::N_close,
    ],
    symbols: &[
        "socket",
        "bind",
        "getsockname",
        "setsockopt",
        "getsockopt",
        "sendmsg",
        "recvmsg",
        "recvfrom",
        "close",
    ],
    needs: &[Need::Ipv6Loopback, Need::LocalBindOnly],
    gaps: &[Gap {
        status: Status::Pending(Arc::NetworkReadiness),
        vehicles: Vehicle::ALL,
        what: "the RFC 2292 IPv6 ancillary types are a named fatal (thread/net/ipctl.rs send_control); ip6_datagram_send_ctl takes IPV6_2292PKTINFO and IPV6_2292HOPLIMIT as their RFC 3542 types and answers IPV6_2292PKTOPTIONS EINVAL",
        failure: Failure::Stops {
            events: 105,
            ending: Ending::Signal(libc::SIGABRT),
            diagnostic: "ancillary data at level 41, type 2",
        },
    }],
    ..DEFAULTS
};
