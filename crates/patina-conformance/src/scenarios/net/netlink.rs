//! net/netlink — the routing netlink family's link and address dumps, read
//! for the loopback interface (netlink(7), rtnetlink(7);
//! net/netlink/af_netlink.c, net/core/rtnetlink.c, net/ipv4/devinet.c):
//!
//! * a `NETLINK_ROUTE` socket autobinds on `bind` with port id 0 to the
//!   process id (the first netlink socket of the process), which its name
//!   reports; a protocol past the families is `EPROTONOSUPPORT`, a stream
//!   socket `ESOCKTNOSUPPORT`;
//! * an `RTM_GETLINK` dump answers `RTM_NEWLINK` messages flagged
//!   `NLM_F_MULTI`, echoing the request's sequence number to this socket's
//!   port, ending with `NLMSG_DONE`; the one for interface 1 is
//!   `ARPHRD_LOOPBACK`, up, loopback and running, named `lo`, with an
//!   all-zero six-byte address and an MTU of at least 576 (the IPv4 minimum);
//! * an `RTM_GETLINK` for one index answers one `RTM_NEWLINK` for it without
//!   `NLM_F_MULTI`; for an index no interface has, `NLMSG_ERROR` with
//!   `-ENODEV`; a message type past the family's, `NLMSG_ERROR` with
//!   `-EOPNOTSUPP`;
//! * an `RTM_GETADDR` dump of AF_INET answers `lo`'s `127.0.0.1/8`, host
//!   scope, labeled `lo`.
//!
//! How the kernel splits a dump across reads, and every interface but
//! `lo`, are the host's business: the answers are read unrecorded and only
//! the loopback facts are recorded (`mark` events).

use crate::catalog::{DEFAULTS, Scenario};
use crate::probe::{ARPHRD_LOOPBACK, NlMsg, Probe, SockAddr, attributes, neg, nl};
use crate::scenarios::net::ifconfig::MIN_MTU as MIN_MTU_I32;
use libc::*;
use patina_dst_syscalls::Syscall;
use serde_json::Value;

/// The IPv4 minimum reassembly size, as IFLA_MTU's type.
const MIN_MTU: u32 = MIN_MTU_I32 as u32;

/// A netlink protocol number past `MAX_LINKS` (32).
const NO_PROTOCOL: i32 = 99;
/// A routing message type past `RTM_MAX`.
const NO_TYPE: u16 = 0x7ff0;
/// The most reads one answer may take.
const MAX_READS: usize = 64;
/// The flags every up loopback device carries.
const LOOPBACK_FLAGS: u32 = (IFF_UP | IFF_LOOPBACK | IFF_RUNNING) as u32;

/// An `ifinfomsg` asking about `index` (0: every interface).
fn ifinfomsg(index: i32) -> Vec<u8> {
    let mut body = vec![0u8; nl::IFINFOMSG];
    body[0] = AF_UNSPEC as u8;
    body[4..8].copy_from_slice(&index.to_ne_bytes());
    body
}

/// An `ifaddrmsg` asking about `family`'s addresses.
fn ifaddrmsg(family: i32) -> Vec<u8> {
    let mut body = vec![0u8; nl::IFADDRMSG];
    body[0] = family as u8;
    body
}

/// The interface index, type and flags of an `RTM_NEWLINK` payload.
fn link_of(message: &NlMsg) -> Option<(i32, u16, u32)> {
    let payload = &message.payload;
    (message.kind == nl::RTM_NEWLINK && payload.len() >= nl::IFINFOMSG).then(|| {
        (
            i32::from_ne_bytes(payload[4..8].try_into().unwrap()),
            u16::from_ne_bytes([payload[2], payload[3]]),
            u32::from_ne_bytes(payload[8..12].try_into().unwrap()),
        )
    })
}

/// The error an `NLMSG_ERROR` payload carries (a negative errno, 0 an ack).
fn error_of(message: &NlMsg) -> Option<i32> {
    (message.kind == nl::NLMSG_ERROR && message.payload.len() >= 4)
        .then(|| i32::from_ne_bytes(message.payload[..4].try_into().unwrap()))
}

fn attribute(payload: &[u8], fixed: usize, kind: u16) -> Option<Vec<u8>> {
    attributes(payload, fixed)
        .into_iter()
        .find(|(k, _)| *k == kind)
        .map(|(_, data)| data)
}

fn text(bytes: Option<Vec<u8>>) -> Option<String> {
    bytes.map(|bytes| {
        let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
        String::from_utf8_lossy(&bytes[..end]).into_owned()
    })
}

pub fn run(p: &Probe) {
    p.check(
        "a netlink protocol past the families is EPROTONOSUPPORT",
        i64::from(p.socket(AF_NETLINK, SOCK_RAW, NO_PROTOCOL)) == neg(EPROTONOSUPPORT),
    );
    p.check(
        "a netlink stream socket is ESOCKTNOSUPPORT",
        i64::from(p.socket(AF_NETLINK, SOCK_STREAM, NETLINK_ROUTE)) == neg(ESOCKTNOSUPPORT),
    );
    let fd = p.socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    p.require("a NETLINK_ROUTE socket", fd >= 0);
    p.check(
        "bind with port id 0",
        p.bind_to(fd, &SockAddr::Netlink { pid: 0, groups: 0 }) == 0,
    );
    let pid = p.getpid();
    let (r, name, len) = p.name_of(fd, false, 128);
    let port = match name {
        Some(SockAddr::Netlink { pid, groups: 0 }) => Some(pid),
        _ => None,
    };
    p.check(
        "the kernel assigned the process id as the port id",
        r == 0 && len == 12 && port == Some(pid as u32),
    );
    let port = port.unwrap_or(0);

    // ---- the link dump ----
    p.check(
        "request an RTM_GETLINK dump",
        p.nl_request(
            fd,
            nl::RTM_GETLINK,
            nl::NLM_F_REQUEST | nl::NLM_F_DUMP,
            1,
            &ifinfomsg(0),
        ) == (nl::HEADER + nl::IFINFOMSG) as i64,
    );
    let answer = p.nl_answer(fd, MAX_READS);
    let messages = answer.as_deref().unwrap_or(&[]);
    let done = messages.last().is_some_and(|m| m.kind == nl::NLMSG_DONE);
    let addressed = messages.iter().all(|m| m.seq == 1 && m.pid == port);
    let multi = messages
        .iter()
        .filter(|m| m.kind == nl::RTM_NEWLINK)
        .all(|m| m.flags & nl::NLM_F_MULTI != 0);
    let lo = messages
        .iter()
        .find(|m| link_of(m).is_some_and(|(index, _, _)| index == 1));
    let facts = lo.and_then(|m| link_of(m).map(|link| (m, link)));
    let mtu = facts
        .and_then(|(m, _)| attribute(&m.payload, nl::IFINFOMSG, nl::IFLA_MTU))
        .filter(|data| data.len() == 4)
        .map_or(0, |data| u32::from_ne_bytes(data[..4].try_into().unwrap()));
    let lo_name =
        facts.and_then(|(m, _)| text(attribute(&m.payload, nl::IFINFOMSG, nl::IFLA_IFNAME)));
    let lo_address =
        facts.and_then(|(m, _)| attribute(&m.payload, nl::IFINFOMSG, nl::IFLA_ADDRESS));
    let lo_broadcast =
        facts.and_then(|(m, _)| attribute(&m.payload, nl::IFINFOMSG, nl::IFLA_BROADCAST));
    p.mark(
        "rtm_getlink_dump",
        &[
            ("answered", Value::from(answer.is_ok())),
            ("done", Value::from(done)),
            ("addressed", Value::from(addressed)),
            ("multi", Value::from(multi)),
            (
                "lo_type",
                facts.map_or(Value::Null, |(_, (_, t, _))| Value::from(t)),
            ),
            (
                "lo_flags",
                facts.map_or(Value::Null, |(_, (_, _, f))| {
                    Value::from(f & LOOPBACK_FLAGS)
                }),
            ),
            ("lo_name", lo_name.clone().map_or(Value::Null, Value::from)),
            (
                "lo_address",
                lo_address
                    .clone()
                    .map_or(Value::Null, |a| Value::from(format!("{a:?}"))),
            ),
            (
                "lo_broadcast",
                lo_broadcast
                    .clone()
                    .map_or(Value::Null, |a| Value::from(format!("{a:?}"))),
            ),
            ("lo_mtu_at_least_576", Value::from(mtu >= MIN_MTU)),
        ],
    );
    p.check(
        "the dump ends with NLMSG_DONE, every message to this port with the request's seq",
        answer.is_ok() && done && addressed && multi,
    );
    p.check(
        "interface 1 is lo: ARPHRD_LOOPBACK, up, loopback, running",
        facts.is_some_and(|(_, (_, kind, flags))| {
            kind == ARPHRD_LOOPBACK && flags & LOOPBACK_FLAGS == LOOPBACK_FLAGS
        }) && lo_name.as_deref() == Some("lo"),
    );
    p.check(
        "lo's link and broadcast addresses are six zero bytes; its MTU is at least 576",
        lo_address == Some(vec![0; 6]) && lo_broadcast == Some(vec![0; 6]) && mtu >= MIN_MTU,
    );

    // ---- one link, and the errors ----
    p.check(
        "request RTM_GETLINK for interface 1",
        p.nl_request(fd, nl::RTM_GETLINK, nl::NLM_F_REQUEST, 2, &ifinfomsg(1)) > 0,
    );
    let answer = p.nl_answer(fd, MAX_READS);
    let single = answer.as_deref().ok().and_then(|messages| match messages {
        [one] => Some(one.clone()),
        _ => None,
    });
    p.mark(
        "rtm_getlink_one",
        &[
            ("messages", Value::from(answer.as_ref().map_or(0, Vec::len))),
            (
                "kind",
                single.as_ref().map_or(Value::Null, |m| Value::from(m.kind)),
            ),
            (
                "multi",
                single
                    .as_ref()
                    .map_or(Value::Null, |m| Value::from(m.flags & nl::NLM_F_MULTI != 0)),
            ),
            (
                "index",
                single
                    .as_ref()
                    .and_then(link_of)
                    .map_or(Value::Null, |(i, _, _)| Value::from(i)),
            ),
        ],
    );
    p.check(
        "one RTM_NEWLINK for interface 1, without NLM_F_MULTI",
        single.as_ref().is_some_and(|m| {
            m.flags & nl::NLM_F_MULTI == 0 && link_of(m).is_some_and(|(i, _, _)| i == 1)
        }),
    );
    p.nl_request(
        fd,
        nl::RTM_GETLINK,
        nl::NLM_F_REQUEST,
        3,
        &ifinfomsg(0x7fff_fff0),
    );
    let answer = p.nl_answer(fd, MAX_READS);
    let error = answer
        .as_deref()
        .ok()
        .and_then(|m| m.last())
        .and_then(error_of);
    p.mark(
        "rtm_getlink_missing",
        &[("error", error.map_or(Value::Null, Value::from))],
    );
    p.check(
        "an index no interface has answers NLMSG_ERROR -ENODEV",
        error == Some(-ENODEV),
    );
    p.nl_request(fd, NO_TYPE, nl::NLM_F_REQUEST, 4, &ifinfomsg(0));
    let answer = p.nl_answer(fd, MAX_READS);
    let error = answer
        .as_deref()
        .ok()
        .and_then(|m| m.last())
        .and_then(error_of);
    p.mark(
        "rtm_unknown_type",
        &[("error", error.map_or(Value::Null, Value::from))],
    );
    p.check(
        "a message type past the family's answers NLMSG_ERROR -EOPNOTSUPP",
        error == Some(-EOPNOTSUPP),
    );

    // ---- the IPv4 address dump ----
    p.check(
        "request an RTM_GETADDR dump of AF_INET",
        p.nl_request(
            fd,
            nl::RTM_GETADDR,
            nl::NLM_F_REQUEST | nl::NLM_F_DUMP,
            5,
            &ifaddrmsg(AF_INET),
        ) > 0,
    );
    let answer = p.nl_answer(fd, MAX_READS);
    let messages = answer.as_deref().unwrap_or(&[]);
    let lo = messages.iter().find(|m| {
        m.kind == nl::RTM_NEWADDR
            && m.payload.len() >= nl::IFADDRMSG
            && u32::from_ne_bytes(m.payload[4..8].try_into().unwrap()) == 1
    });
    let family = lo.map(|m| m.payload[0]);
    let prefix = lo.map(|m| m.payload[1]);
    let scope = lo.map(|m| m.payload[3]);
    let local = lo.and_then(|m| attribute(&m.payload, nl::IFADDRMSG, nl::IFA_LOCAL));
    let address = lo.and_then(|m| attribute(&m.payload, nl::IFADDRMSG, nl::IFA_ADDRESS));
    let label = lo.and_then(|m| text(attribute(&m.payload, nl::IFADDRMSG, nl::IFA_LABEL)));
    p.mark(
        "rtm_getaddr_dump",
        &[
            ("answered", Value::from(answer.is_ok())),
            (
                "done",
                Value::from(messages.last().is_some_and(|m| m.kind == nl::NLMSG_DONE)),
            ),
            ("lo_family", family.map_or(Value::Null, Value::from)),
            ("lo_prefixlen", prefix.map_or(Value::Null, Value::from)),
            ("lo_scope", scope.map_or(Value::Null, Value::from)),
            (
                "lo_local",
                local
                    .clone()
                    .map_or(Value::Null, |a| Value::from(format!("{a:?}"))),
            ),
            (
                "lo_address",
                address
                    .clone()
                    .map_or(Value::Null, |a| Value::from(format!("{a:?}"))),
            ),
            ("lo_label", label.clone().map_or(Value::Null, Value::from)),
        ],
    );
    p.check(
        "lo's IPv4 address is 127.0.0.1/8, host scope, labeled lo",
        family == Some(AF_INET as u8)
            && prefix == Some(8)
            && scope == Some(nl::RT_SCOPE_HOST)
            && local == Some(vec![127, 0, 0, 1])
            && address == Some(vec![127, 0, 0, 1])
            && label.as_deref() == Some("lo"),
    );
    p.close(fd);
}

pub const SCENARIO: Scenario = Scenario {
    name: "net/netlink",
    run,
    covers: &[
        Syscall::N_socket,
        Syscall::N_bind,
        Syscall::N_getsockname,
        Syscall::N_sendto,
        Syscall::N_recvfrom,
        Syscall::N_getpid,
        Syscall::N_close,
    ],
    symbols: &[
        "socket",
        "bind",
        "getsockname",
        "sendto",
        "recvfrom",
        "getpid",
        "close",
    ],
    ..DEFAULTS
};
