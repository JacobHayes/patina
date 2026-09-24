//! net/getaddrinfo — `getaddrinfo(3)`/`freeaddrinfo(3)` over numeric hosts
//! and services only (getaddrinfo(3)): nothing is looked up, so no name
//! service, file or network is consulted.
//!
//! * a numeric IPv4 host and service with a socket type answer one address
//!   of that type with its protocol filled in (`IPPROTO_TCP` for a stream,
//!   `IPPROTO_UDP` for datagrams), no canonical name;
//! * a numeric IPv6 host answers a 28-byte `sockaddr_in6` (numeric parsing
//!   needs no IPv6 on the host);
//! * no host with `AI_PASSIVE` is the wildcard address, without it the
//!   loopback address;
//! * `AI_NUMERICHOST` with a name is `EAI_NONAME`, `AI_NUMERICSERV` with a
//!   service name `EAI_NONAME`, an unknown family `EAI_FAMILY`;
//! * the address answered is usable: a datagram sent to it arrives.
//!
//! libc only: there is no kernel row under the resolver; the datagram's
//! rows are the ones every vehicle shares.
//!
//! Reads right after a send rely on loopback delivery before the send
//! returns (scenarios/net.rs, "Loopback delivery").

use crate::catalog::{DEFAULTS, Scenario};
use crate::probe::{Probe, SockAddr};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

/// A family number no libc knows.
const NO_FAMILY: i32 = 12345;

pub fn run(p: &Probe) {
    let flags = AI_NUMERICHOST | AI_NUMERICSERV;
    let (code, results) =
        p.getaddrinfo(Some("127.0.0.1"), Some("8080"), AF_INET, SOCK_STREAM, flags);
    p.check(
        "a numeric IPv4 stream address: one result, IPPROTO_TCP, no canonical name",
        code == 0
            && results.len() == 1
            && results[0].family == AF_INET
            && results[0].socktype == SOCK_STREAM
            && results[0].protocol == IPPROTO_TCP
            && results[0].addrlen as usize == size_of::<sockaddr_in>()
            && results[0].addr == SockAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080))
            && !results[0].canonname,
    );
    let (code, results) = p.getaddrinfo(Some("127.0.0.1"), Some("53"), AF_INET, SOCK_DGRAM, flags);
    p.check(
        "a numeric IPv4 datagram address: IPPROTO_UDP",
        code == 0 && results.len() == 1 && results[0].protocol == IPPROTO_UDP,
    );
    let (code, results) = p.getaddrinfo(Some("::1"), Some("8080"), AF_INET6, SOCK_STREAM, flags);
    p.check(
        "a numeric IPv6 address: a 28-byte sockaddr_in6",
        code == 0
            && results.len() == 1
            && results[0].family == AF_INET6
            && results[0].addrlen as usize == size_of::<sockaddr_in6>()
            && results[0].addr == SockAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 8080, 0, 0)),
    );
    let (code, results) = p.getaddrinfo(
        None,
        Some("8080"),
        AF_INET,
        SOCK_STREAM,
        AI_PASSIVE | AI_NUMERICSERV,
    );
    p.check(
        "no host with AI_PASSIVE is the wildcard address",
        code == 0
            && results.len() == 1
            && results[0].addr == SockAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 8080)),
    );
    let (code, results) = p.getaddrinfo(None, Some("8080"), AF_INET, SOCK_STREAM, AI_NUMERICSERV);
    p.check(
        "no host without AI_PASSIVE is the loopback address",
        code == 0 && results.len() == 1 && results[0].addr == SockAddr::v4(8080),
    );
    p.check(
        "AI_NUMERICHOST with a name is EAI_NONAME",
        p.getaddrinfo(
            Some("not-an-address"),
            Some("80"),
            AF_INET,
            SOCK_STREAM,
            flags,
        )
        .0 == EAI_NONAME,
    );
    p.check(
        "AI_NUMERICSERV with a service name is EAI_NONAME",
        p.getaddrinfo(Some("127.0.0.1"), Some("http"), AF_INET, SOCK_STREAM, flags)
            .0
            == EAI_NONAME,
    );
    p.check(
        "an unknown family is EAI_FAMILY",
        p.getaddrinfo(Some("127.0.0.1"), Some("80"), NO_FAMILY, SOCK_STREAM, flags)
            .0
            == EAI_FAMILY,
    );

    let r = p.socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    p.require("a receiver", r >= 0);
    p.check("bind it", p.bind_to(r, &SockAddr::v4(0)) == 0);
    let (_, bound, _) = p.name_of(r, false, 128);
    let port = bound.and_then(|a| a.port()).unwrap_or(0);
    let (code, results) =
        p.getaddrinfo(Some("127.0.0.1"), None, AF_INET, SOCK_DGRAM, AI_NUMERICHOST);
    p.require(
        "resolve the receiver's host with no service: port 0",
        code == 0 && results.len() == 1 && results[0].addr == SockAddr::v4(0),
    );
    let s = p.socket(AF_INET, SOCK_DGRAM, 0);
    p.require("a sender", s >= 0);
    p.check(
        "send to the resolved address with the receiver's port",
        p.send_to(s, b"resolved", 0, Some(&results[0].addr.with_port(port))) == 8,
    );
    let (n, data, _) = p.recv_from(r, 16, 0, false);
    p.check("it arrives", n == 8 && data == b"resolved");
    p.close(s);
    p.close(r);
    crate::scenarios::net::check_allocated_port(p, &SockAddr::v4(port));
}

pub const SCENARIO: Scenario = Scenario {
    name: "net/getaddrinfo",
    run,
    vehicles: &[Vehicle::Libc],
    covers: &[
        Syscall::N_socket,
        Syscall::N_bind,
        Syscall::N_getsockname,
        Syscall::N_sendto,
        Syscall::N_recvfrom,
        Syscall::N_close,
    ],
    symbols: &[
        "getaddrinfo",
        "freeaddrinfo",
        "socket",
        "bind",
        "getsockname",
        "sendto",
        "recvfrom",
        "close",
    ],
    ..DEFAULTS
};
