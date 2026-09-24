//! `AF_NETLINK`'s routing family (`NETLINK_ROUTE`), answered from the virtual
//! interface table (net/netlink/af_netlink.c, net/core/rtnetlink.c,
//! net/ipv4/devinet.c, net/ipv6/addrconf.c).
//!
//! A request to the kernel (port 0) is answered at once into the sender's
//! receive queue, as `netlink_rcv_skb` answers it: an `RTM_GETLINK` or
//! `RTM_GETADDR` dump as `NLM_F_MULTI` messages ending with `NLMSG_DONE`, a
//! lookup of one link as one message, and a refusal (a missing link, a type
//! past `RTM_MAX`, a change an unprivileged caller may not make) as
//! `NLMSG_ERROR`. The routing tables and every other object rtnetlink serves
//! are not modeled: a request for one is a named refusal. The other netlink
//! families are not modeled and are `EPROTONOSUPPORT`.

use patina_dst_driver_api::{NetInterface, VIRTUAL_INTERFACES};

use super::addr;
use super::iface::TXQLEN;
use super::*;

const NETLINK_ROUTE: i32 = 0;
/// `MAX_LINKS`: one past the highest netlink protocol.
const MAX_LINKS: i32 = 32;

const NLMSG_HDRLEN: usize = 16;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
/// `NLMSG_MIN_TYPE`: below it a type is a control message.
const NLMSG_MIN_TYPE: u16 = 0x10;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_MULTI: u16 = 0x2;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_DUMP: u16 = 0x300;

const RTM_BASE: u16 = 16;
const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const RTM_NEWADDR: u16 = 20;
const RTM_GETADDR: u16 = 22;
/// The virtual kernel's (6.8) highest routing message type.
const RTM_MAX: u16 = 123;

const IFLA_ADDRESS: u16 = 1;
const IFLA_BROADCAST: u16 = 2;
const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;
const IFLA_STATS: u16 = 7;
const IFLA_TXQLEN: u16 = 13;
const IFLA_OPERSTATE: u16 = 16;
const IFLA_LINKMODE: u16 = 17;
/// `struct rtnl_link_stats`: 24 counters.
const LINK_STATS: usize = 24 * 4;
/// `IF_OPER_UNKNOWN` (a loopback device), `IF_OPER_UP`.
const IF_OPER_UNKNOWN: u8 = 0;
const IF_OPER_UP: u8 = 6;

const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_LABEL: u16 = 3;
const IFA_BROADCAST: u16 = 4;
const IFA_CACHEINFO: u16 = 6;
const IFA_FLAGS: u16 = 8;
const IFA_F_PERMANENT: u8 = 0x80;
const RT_SCOPE_HOST: u8 = 254;

/// The Linux errnos an `NLMSG_ERROR` carries (the family is Linux-only).
const ENODEV: i32 = 19;
const EPERM: i32 = 1;
const LINUX_EINVAL: i32 = 22;
const LINUX_EOPNOTSUPP: i32 = 95;

/// One netlink socket.
pub(crate) struct Netlink {
    /// The port id, 0 until bound.
    port: u32,
    groups: u32,
    /// The connected destination port.
    dst_port: u32,
    /// Datagrams the kernel answered, oldest first.
    queue: VecDeque<Vec<u8>>,
    arrivals: u64,
}

/// The ports netlink sockets hold.
#[derive(Default)]
pub(crate) struct Ports {
    taken: std::collections::BTreeSet<u32>,
    /// The next negative port id an autobind tries once the process id is
    /// taken (`netlink_autobind`'s rover).
    rover: i32,
}

/// `netlink_create`: a raw or datagram socket of a known protocol.
pub(super) fn create(ty: i32, protocol: i32) -> Result<(i32, i32, Proto), c_int> {
    if ty != SOCK_RAW && ty != SOCK_DGRAM {
        return Err(ESOCKTNOSUPPORT);
    }
    if !(0..MAX_LINKS).contains(&protocol) || protocol != NETLINK_ROUTE {
        return Err(EPROTONOSUPPORT);
    }
    Ok((
        ty,
        protocol,
        Proto::Netlink(Netlink {
            port: 0,
            groups: 0,
            dst_port: 0,
            queue: VecDeque::new(),
            arrivals: 0,
        }),
    ))
}

fn netlink_mut(state: &mut ThreadRuntime, handle: c_int) -> Result<&mut Netlink, c_int> {
    match &mut state
        .net
        .sockets
        .table
        .get_mut(&handle)
        .ok_or(crate::EBADF)?
        .proto
    {
        Proto::Netlink(netlink) => Ok(netlink),
        _ => unreachable!("a netlink entry reached a socket of another family"),
    }
}

/// `netlink_autobind`: the process id for the first socket, then negative
/// ids counting down from -4097.
fn autobind(state: &mut ThreadRuntime, handle: c_int) -> Result<(), c_int> {
    if netlink_mut(state, handle)?.port != 0 {
        return Ok(());
    }
    let ports = &mut state.net.sockets.netlink;
    let mut port = IDENTITY_PID;
    while ports.taken.contains(&port) {
        if ports.rover >= -4096 {
            ports.rover = -4097;
        }
        port = ports.rover as u32;
        ports.rover -= 1;
    }
    ports.taken.insert(port);
    netlink_mut(state, handle)?.port = port;
    Ok(())
}

/// `bind(2)` (`netlink_bind`): port id 0 autobinds; a bound socket may only
/// name its own port again.
pub(super) fn bind(handle: c_int, bytes: &[u8]) -> Result<(), c_int> {
    let (pid, groups) = addr::parse_nl(bytes)?;
    let mut state = lock_state();
    let bound = netlink_mut(&mut state, handle)?.port;
    if bound != 0 {
        if pid != bound {
            return Err(EINVAL);
        }
    } else if pid == 0 {
        autobind(&mut state, handle)?;
    } else {
        if state.net.sockets.netlink.taken.contains(&pid) {
            return Err(EADDRINUSE);
        }
        state.net.sockets.netlink.taken.insert(pid);
        netlink_mut(&mut state, handle)?.port = pid;
    }
    netlink_mut(&mut state, handle)?.groups = groups;
    Ok(())
}

/// `connect(2)` (`netlink_connect`): only the kernel is a destination an
/// unprivileged routing socket may name.
pub(super) fn connect(handle: c_int, bytes: &[u8]) -> Result<(), c_int> {
    if bytes.len() < addr::SUN_PATH {
        return Err(EINVAL);
    }
    let mut state = lock_state();
    if addr::family_of(bytes) == Some(AF_UNSPEC) {
        netlink_mut(&mut state, handle)?.dst_port = 0;
        return Ok(());
    }
    let (pid, groups) = addr::parse_nl(bytes)?;
    if pid != 0 || groups != 0 {
        return Err(crate::EPERM);
    }
    autobind(&mut state, handle)?;
    netlink_mut(&mut state, handle)?.dst_port = 0;
    Ok(())
}

/// `getsockname`/`getpeername` (`netlink_getname`).
pub(super) fn name(netlink: &Netlink, peer: bool) -> Vec<u8> {
    if peer {
        addr::encode_nl(netlink.dst_port, 0)
    } else {
        addr::encode_nl(netlink.port, netlink.groups)
    }
}

/// Send one message (`netlink_sendmsg`): a request to the kernel is answered
/// into this socket's queue.
pub(super) fn send(handle: c_int, message: Outgoing) -> Result<usize, c_int> {
    if message.flags & MSG_OOB != 0 {
        return Err(EOPNOTSUPP);
    }
    if message.data.is_empty() {
        return Ok(0);
    }
    if let Some(to) = message.to.as_ref().filter(|to| !to.is_empty()) {
        let (pid, groups) = addr::parse_nl(to)?;
        if pid != 0 || groups != 0 {
            return Err(crate::EPERM);
        }
    }
    let mut state = lock_state();
    autobind(&mut state, handle)?;
    let sndbuf = state
        .net
        .sockets
        .table
        .get(&handle)
        .ok_or(crate::EBADF)?
        .opts
        .sndbuf;
    if message.data.len() > (sndbuf.max(32) - 32) as usize {
        return Err(EMSGSIZE);
    }
    let request = message.data.read_all()?;
    let netlink = netlink_mut(&mut state, handle)?;
    let answers = answer(&request, netlink.port);
    let len = request.len();
    if !answers.is_empty() {
        netlink.arrivals += answers.len() as u64;
        netlink.queue.extend(answers);
        let wakes = waiters(&mut state, handle, Dir::Recv);
        drop(state);
        wake_all(wakes);
    }
    Ok(len)
}

/// Receive one queued answer (`netlink_recvmsg`); the source is the kernel.
pub(super) fn recv(handle: c_int, want: Want) -> Result<Incoming, c_int> {
    if want.flags & MSG_OOB != 0 {
        return Err(EOPNOTSUPP);
    }
    let timeout = lock_state()
        .net
        .sockets
        .table
        .get(&handle)
        .ok_or(crate::EBADF)?
        .opts
        .recv_timeout();
    let deadline = super::deadline(timeout)?;
    let nonblocking = want.flags & MSG_DONTWAIT != 0 || timeout == Some(0);
    loop {
        let mut state = lock_state();
        let netlink = netlink_mut(&mut state, handle)?;
        let datagram = if want.flags & MSG_PEEK != 0 {
            netlink.queue.front().cloned()
        } else {
            netlink.queue.pop_front()
        };
        if let Some(datagram) = datagram {
            let copied = datagram.len().min(want.capacity);
            return Ok(Incoming {
                data: datagram[..copied].to_vec(),
                len: if want.flags & MSG_TRUNC != 0 {
                    datagram.len()
                } else {
                    copied
                },
                from: Some(addr::encode_nl(0, 0)),
                flags: if copied < datagram.len() {
                    MSG_TRUNC
                } else {
                    0
                },
                ..Incoming::default()
            });
        }
        if nonblocking || expired(deadline)? {
            return Err(EWOULDBLOCK);
        }
        park(state, handle, Dir::Recv, deadline, "netlink-recv")?;
    }
}

/// `datagram_poll` over the answer queue.
pub(super) fn poll(socket: &Socket, netlink: &Netlink) -> (u32, u64) {
    let mut mask = POLLOUT | POLLWRNORM | POLLWRBAND;
    if socket.error != 0 {
        mask |= POLLERR;
    }
    if !netlink.queue.is_empty() {
        mask |= POLLIN | POLLRDNORM;
    }
    (mask, netlink.arrivals)
}

/// `SIOCINQ`: the next answer's length.
pub(super) fn pending(netlink: &Netlink) -> i32 {
    netlink.queue.front().map_or(0, |datagram| {
        i32::try_from(datagram.len()).unwrap_or(i32::MAX)
    })
}

/// Free a closed socket's port.
pub(super) fn close(state: &mut ThreadRuntime, netlink: Netlink) {
    if netlink.port != 0 {
        state.net.sockets.netlink.taken.remove(&netlink.port);
    }
}

// ---- rtnetlink ----------------------------------------------------------

fn align(len: usize) -> usize {
    len.div_ceil(4) * 4
}

/// One netlink message, padded to its alignment.
fn message(kind: u16, flags: u16, seq: u32, pid: u32, payload: &[u8]) -> Vec<u8> {
    let len = NLMSG_HDRLEN + payload.len();
    let mut bytes = Vec::with_capacity(align(len));
    bytes.extend((len as u32).to_ne_bytes());
    bytes.extend(kind.to_ne_bytes());
    bytes.extend(flags.to_ne_bytes());
    bytes.extend(seq.to_ne_bytes());
    bytes.extend(pid.to_ne_bytes());
    bytes.extend_from_slice(payload);
    bytes.resize(align(len), 0);
    bytes
}

/// One `struct rtattr`, padded.
fn attribute(kind: u16, data: &[u8]) -> Vec<u8> {
    let len = 4 + data.len();
    let mut bytes = Vec::with_capacity(align(len));
    bytes.extend((len as u16).to_ne_bytes());
    bytes.extend(kind.to_ne_bytes());
    bytes.extend_from_slice(data);
    bytes.resize(align(len), 0);
    bytes
}

fn name_bytes(interface: &NetInterface) -> Vec<u8> {
    interface.name.bytes().chain([0]).collect()
}

/// `rtnl_fill_ifinfo`: an `ifinfomsg` and the link's attributes.
fn link(interface: &NetInterface) -> Vec<u8> {
    let mut payload = vec![0u8; 16];
    payload[2..4].copy_from_slice(&interface.hardware_type.to_ne_bytes());
    payload[4..8].copy_from_slice(&(interface.index as i32).to_ne_bytes());
    payload[8..12].copy_from_slice(&interface.flags.to_ne_bytes());
    let operstate = if interface.hardware_type == 772 {
        IF_OPER_UNKNOWN
    } else {
        IF_OPER_UP
    };
    payload.extend(attribute(IFLA_IFNAME, &name_bytes(interface)));
    payload.extend(attribute(IFLA_TXQLEN, &TXQLEN.to_ne_bytes()));
    payload.extend(attribute(IFLA_OPERSTATE, &[operstate]));
    payload.extend(attribute(IFLA_LINKMODE, &[0]));
    payload.extend(attribute(IFLA_MTU, &interface.mtu.to_ne_bytes()));
    payload.extend(attribute(IFLA_ADDRESS, &interface.hardware_address));
    payload.extend(attribute(
        IFLA_BROADCAST,
        &interface.broadcast_hardware_address,
    ));
    payload.extend(attribute(IFLA_STATS, &[0; LINK_STATS]));
    payload
}

/// The addresses of `family` (`AF_UNSPEC`: both) as `RTM_NEWADDR` payloads
/// (`inet_fill_ifaddr`, `inet6_fill_ifaddr`).
fn addresses(family: i32) -> Vec<Vec<u8>> {
    let forever = [
        u32::MAX.to_ne_bytes(),
        u32::MAX.to_ne_bytes(),
        [0; 4],
        [0; 4],
    ]
    .concat();
    let mut out = Vec::new();
    if family == AF_UNSPEC || family == AF_INET {
        for interface in VIRTUAL_INTERFACES {
            let ipv4 = interface.ipv4;
            let mut payload = vec![AF_INET as u8, ipv4.prefix, IFA_F_PERMANENT, ipv4.scope];
            payload.extend(interface.index.to_ne_bytes());
            payload.extend(attribute(IFA_ADDRESS, &ipv4.address));
            payload.extend(attribute(IFA_LOCAL, &ipv4.address));
            if interface.flags & 0x2 != 0 {
                payload.extend(attribute(IFA_BROADCAST, &ipv4.broadcast()));
            }
            payload.extend(attribute(IFA_LABEL, &name_bytes(interface)));
            payload.extend(attribute(
                IFA_FLAGS,
                &u32::from(IFA_F_PERMANENT).to_ne_bytes(),
            ));
            payload.extend(attribute(IFA_CACHEINFO, &forever));
            out.push(payload);
        }
    }
    if family == AF_UNSPEC || family == AF_INET6 {
        for interface in VIRTUAL_INTERFACES {
            let Some((address, prefix)) = interface.ipv6 else {
                continue;
            };
            let mut payload = vec![AF_INET6 as u8, prefix, IFA_F_PERMANENT, RT_SCOPE_HOST];
            payload.extend(interface.index.to_ne_bytes());
            payload.extend(attribute(IFA_ADDRESS, &address));
            payload.extend(attribute(IFA_CACHEINFO, &forever));
            payload.extend(attribute(
                IFA_FLAGS,
                &u32::from(IFA_F_PERMANENT).to_ne_bytes(),
            ));
            out.push(payload);
        }
    }
    out
}

/// `netlink_ack`: an `NLMSG_ERROR` carrying `error` (0 for an ack) and the
/// request's header — the whole request when it is an error.
fn ack(request: &[u8], seq: u32, pid: u32, error: i32) -> Vec<u8> {
    let mut payload = error.to_ne_bytes().to_vec();
    if error == 0 {
        payload.extend_from_slice(&request[..NLMSG_HDRLEN]);
    } else {
        payload.extend_from_slice(request);
    }
    message(NLMSG_ERROR, 0, seq, pid, &payload)
}

/// `netlink_rcv_skb` over `rtnetlink_rcv_msg`: the datagrams answering every
/// message in `request`.
fn answer(request: &[u8], pid: u32) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut at = 0;
    while request.len() - at >= NLMSG_HDRLEN {
        let header = &request[at..];
        let len = u32::from_ne_bytes(header[..4].try_into().unwrap()) as usize;
        if len < NLMSG_HDRLEN || len > header.len() {
            break;
        }
        let one = &header[..len];
        let kind = u16::from_ne_bytes([one[4], one[5]]);
        let flags = u16::from_ne_bytes([one[6], one[7]]);
        let seq = u32::from_ne_bytes(one[8..12].try_into().unwrap());
        let body = &one[NLMSG_HDRLEN..];
        let result = if flags & NLM_F_REQUEST == 0 || kind < NLMSG_MIN_TYPE {
            Ok(Vec::new())
        } else {
            route_message(kind, flags, seq, pid, body)
        };
        let error = match result {
            Ok(answers) => {
                out.extend(answers);
                0
            }
            Err(error) => error,
        };
        if flags & NLM_F_ACK != 0 || error != 0 {
            out.push(ack(one, seq, pid, -error));
        }
        at += align(len).min(request.len() - at);
    }
    out
}

/// `rtnetlink_rcv_msg` for one request: its answers, or the Linux errno an
/// `NLMSG_ERROR` reports.
fn route_message(
    kind: u16,
    flags: u16,
    seq: u32,
    pid: u32,
    body: &[u8],
) -> Result<Vec<Vec<u8>>, i32> {
    if kind > RTM_MAX {
        return Err(LINUX_EOPNOTSUPP);
    }
    // Every message carries at least its family byte.
    let Some(&family) = body.first() else {
        return Ok(Vec::new());
    };
    let family = i32::from(family);
    if (kind - RTM_BASE) & 3 != 2 {
        // A change: CAP_NET_ADMIN.
        return Err(EPERM);
    }
    let dump = flags & NLM_F_DUMP == NLM_F_DUMP;
    match kind {
        RTM_GETLINK if dump => {
            let mut datagram: Vec<u8> = VIRTUAL_INTERFACES
                .iter()
                .flat_map(|interface| message(RTM_NEWLINK, NLM_F_MULTI, seq, pid, &link(interface)))
                .collect();
            datagram.extend(message(
                NLMSG_DONE,
                NLM_F_MULTI,
                seq,
                pid,
                &0i32.to_ne_bytes(),
            ));
            Ok(vec![datagram])
        }
        RTM_GETLINK => {
            if body.len() < 16 {
                return Err(LINUX_EINVAL);
            }
            let index = i32::from_ne_bytes(body[4..8].try_into().unwrap());
            if index <= 0 {
                return Err(LINUX_EINVAL);
            }
            let interface = super::iface::by_index(index as u32).ok_or(ENODEV)?;
            Ok(vec![message(RTM_NEWLINK, 0, seq, pid, &link(interface))])
        }
        RTM_GETADDR if dump => {
            let mut datagram: Vec<u8> = addresses(family)
                .iter()
                .flat_map(|payload| message(RTM_NEWADDR, NLM_F_MULTI, seq, pid, payload))
                .collect();
            datagram.extend(message(
                NLMSG_DONE,
                NLM_F_MULTI,
                seq,
                pid,
                &0i32.to_ne_bytes(),
            ));
            Ok(vec![datagram])
        }
        RTM_GETADDR => Err(LINUX_EOPNOTSUPP),
        _ => crate::trap_fatal(&format!(
            "rtnetlink request type {kind} is not modeled (the virtual kernel answers links \
             and addresses from its interface table; routes, neighbours and the other \
             routing objects are not modeled); failing closed"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(kind: u16, flags: u16, seq: u32, body: &[u8]) -> Vec<u8> {
        message(kind, flags, seq, 0, body)
    }

    fn messages(datagram: &[u8]) -> Vec<(u16, u16, Vec<u8>)> {
        let mut out = Vec::new();
        let mut at = 0;
        while at + NLMSG_HDRLEN <= datagram.len() {
            let len = u32::from_ne_bytes(datagram[at..at + 4].try_into().unwrap()) as usize;
            out.push((
                u16::from_ne_bytes([datagram[at + 4], datagram[at + 5]]),
                u16::from_ne_bytes([datagram[at + 6], datagram[at + 7]]),
                datagram[at + NLMSG_HDRLEN..at + len].to_vec(),
            ));
            at += align(len);
        }
        out
    }

    #[test]
    fn a_link_dump_lists_every_interface_then_done() {
        let answers = answer(
            &request(RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, 1, &[0; 16]),
            7,
        );
        assert_eq!(answers.len(), 1);
        let all = messages(&answers[0]);
        assert_eq!(all.len(), VIRTUAL_INTERFACES.len() + 1);
        assert!(
            all[..all.len() - 1]
                .iter()
                .all(|(kind, flags, _)| *kind == RTM_NEWLINK && flags & NLM_F_MULTI != 0)
        );
        assert_eq!(all.last().unwrap().0, NLMSG_DONE);
    }

    #[test]
    fn a_missing_link_and_a_type_past_the_family_are_errors() {
        let mut body = [0u8; 16];
        body[4..8].copy_from_slice(&0x7fff_fff0i32.to_ne_bytes());
        let answers = answer(&request(RTM_GETLINK, NLM_F_REQUEST, 3, &body), 7);
        let (kind, _, payload) = &messages(&answers[0])[0];
        assert_eq!(*kind, NLMSG_ERROR);
        assert_eq!(
            i32::from_ne_bytes(payload[..4].try_into().unwrap()),
            -ENODEV
        );
        let answers = answer(&request(0x7ff0, NLM_F_REQUEST, 4, &[0; 16]), 7);
        let (_, _, payload) = &messages(&answers[0])[0];
        assert_eq!(
            i32::from_ne_bytes(payload[..4].try_into().unwrap()),
            -LINUX_EOPNOTSUPP
        );
    }
}
