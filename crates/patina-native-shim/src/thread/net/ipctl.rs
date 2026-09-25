//! The IP- and UDP-level ancillary data of a datagram socket: what a send's
//! control buffer asks of the datagram (`udp_cmsg_send`, then `ip_cmsg_send`
//! for an IPv4 destination or `ip6_datagram_send_ctl` for an IPv6 one) and
//! what a receive reports (`ip_cmsg_recv`, `ip6_datagram_recv_ctl`).
//!
//! Modeled: the type of service and traffic class (`IP_TOS`,
//! `IPV6_TCLASS`), the source and interface a datagram leaves from
//! (`IP_PKTINFO`, `IPV6_PKTINFO`), the hop limits and `IPV6_DONTFRAG` (taken
//! and range-checked; the virtual network routes no hops), and UDP
//! segmentation (`UDP_SEGMENT`). IP options, flow labels and the IPv6
//! extension headers are not modeled and fail closed by name.

use std::ffi::c_int;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use patina_dst_abi::Datagram;
use patina_dst_driver_api::VIRTUAL_INTERFACES;

use super::abi::*;
use super::addr::Endpoint;
use super::msg::ProtocolCmsg;
use super::opts::IpOptions;
use crate::{EINVAL, ENODEV};

/// `UDP_MAX_SEGMENTS`: the most segments one send is cut into.
const UDP_MAX_SEGMENTS: usize = 128;
/// The IPv4 and IPv6 headers a UDP datagram carries before its own.
const IPV4_HEADER: usize = 20;
const IPV6_HEADER: usize = 40;
const UDP_HEADER: usize = 8;

// Types the model refuses by name rather than answer.
const IP_PROTOCOL: i32 = 52;
const IPV6_FLOWINFO: i32 = 11;
// The RFC 2292 numbers `ip6_datagram_send_ctl` takes as their RFC 3542
// types (`IPV6_2292PKTOPTIONS`, 6, is `EINVAL` there, as any unknown type).
const IPV6_2292PKTINFO: i32 = 2;
const IPV6_2292HOPLIMIT: i32 = 8;
/// `sizeof(struct in6_pktinfo)`: an `IPV6_PKTINFO` may be longer, not
/// shorter.
const IN6_PKTINFO: usize = 20;

/// What one send asks of its datagrams.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct SendControl {
    /// The type of service (IPv4) or traffic class (IPv6) they carry.
    pub(super) tos: u8,
    /// The source address they leave from, in place of the route's.
    pub(super) source: Option<IpAddr>,
    /// The interface they leave by (`ipi_ifindex`), 0 for the route's.
    pub(super) ifindex: u32,
    /// The segment size the payload is cut into, 0 for one datagram.
    pub(super) gso: u16,
}

fn int(data: &[u8]) -> i32 {
    i32::from_ne_bytes(data[..4].try_into().expect("four bytes"))
}

fn unmodeled(level: i32, kind: i32) -> ! {
    crate::trap_fatal(&format!(
        "ancillary data at level {level}, type {kind} (IP options, protocol, flow label or \
         an IPv6 extension header) on a datagram socket is not modeled; failing closed"
    ))
}

/// Read a send's protocol-level control messages for a destination of the
/// given family (`v4_destination`, an IPv4-mapped one included), from a
/// socket of family `v6_socket`, over the socket's defaults.
pub(super) fn send_control(
    ip: &IpOptions,
    v6_socket: bool,
    v4_destination: bool,
    cmsgs: &[ProtocolCmsg],
) -> Result<SendControl, c_int> {
    let mut control = SendControl {
        tos: if v4_destination { ip.tos } else { ip.tclass },
        gso: ip.gso,
        ..SendControl::default()
    };
    // `udp_cmsg_send`: the UDP level first, over the whole buffer.
    for (level, kind, data) in cmsgs {
        if *level != SOL_UDP {
            continue;
        }
        match *kind {
            UDP_SEGMENT if data.len() == 2 => {
                control.gso = u16::from_ne_bytes([data[0], data[1]]);
            }
            _ => return Err(EINVAL),
        }
    }
    for (level, kind, data) in cmsgs {
        match (*level, v4_destination) {
            // `ip_cmsg_send`, which an IPv6 socket's IPv4-mapped send reaches
            // with its IPv6 packet information converted.
            // (Its RFC 2292 number is not converted: another level's type.)
            (SOL_IPV6, true) if v6_socket && *kind == IPV6_PKTINFO => {
                if data.len() < IN6_PKTINFO {
                    return Err(EINVAL);
                }
                let address = Ipv6Addr::from(<[u8; 16]>::try_from(&data[..16]).unwrap());
                let Some(v4) = address.to_ipv4_mapped() else {
                    return Err(EINVAL);
                };
                control.ifindex = int(&data[16..]) as u32;
                control.source = (!v4.is_unspecified()).then_some(IpAddr::V4(v4));
            }
            (SOL_IP, true) => match *kind {
                IP_PKTINFO => {
                    if data.len() != 12 {
                        return Err(EINVAL);
                    }
                    control.ifindex = int(data) as u32;
                    let spec = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
                    control.source = (!spec.is_unspecified()).then_some(IpAddr::V4(spec));
                }
                IP_TTL => {
                    if data.len() != 4 || !(1..=255).contains(&int(data)) {
                        return Err(EINVAL);
                    }
                }
                IP_TOS => {
                    let tos = match data.len() {
                        1 => i32::from(data[0]),
                        4 => int(data),
                        _ => return Err(EINVAL),
                    };
                    control.tos = u8::try_from(tos).map_err(|_| EINVAL)?;
                }
                IP_RETOPTS | IP_PROTOCOL => unmodeled(*level, *kind),
                _ => return Err(EINVAL),
            },
            (SOL_IPV6, false) => match *kind {
                IPV6_PKTINFO | IPV6_2292PKTINFO => {
                    if data.len() < IN6_PKTINFO {
                        return Err(EINVAL);
                    }
                    let address = Ipv6Addr::from(<[u8; 16]>::try_from(&data[..16]).unwrap());
                    control.ifindex = int(&data[16..]) as u32;
                    if control.ifindex != 0 && super::iface::by_index(control.ifindex).is_none() {
                        return Err(ENODEV);
                    }
                    if !address.is_unspecified() {
                        if !patina_dst_driver_api::local_ipv6(address.octets()) {
                            return Err(EINVAL);
                        }
                        control.source = Some(IpAddr::V6(address));
                    }
                }
                IPV6_TCLASS => {
                    if data.len() != 4 || !(-1..=0xff).contains(&int(data)) {
                        return Err(EINVAL);
                    }
                    // The kernel takes -1 here as the byte it truncates to.
                    control.tos = int(data) as u8;
                }
                IPV6_HOPLIMIT | IPV6_2292HOPLIMIT => {
                    if data.len() != 4 || !(-1..=255).contains(&int(data)) {
                        return Err(EINVAL);
                    }
                }
                IPV6_DONTFRAG => {
                    if data.len() != 4 || !(0..=1).contains(&int(data)) {
                        return Err(EINVAL);
                    }
                }
                // Flow labels and the extension headers (`IPV6_HOPOPTS`,
                // `IPV6_RTHDRDSTOPTS`, `IPV6_RTHDR`, `IPV6_DSTOPTS`, and
                // the RFC 2292 `IPV6_2292HOPOPTS`, `IPV6_2292DSTOPTS`,
                // `IPV6_2292RTHDR`).
                IPV6_FLOWINFO | 3..=5 | 54 | 55 | 57 | 59 => unmodeled(*level, *kind),
                _ => return Err(EINVAL),
            },
            // Another family's level, and the UDP level read above.
            _ => {}
        }
    }
    Ok(control)
}

/// The source a send with `control` leaves from, when it names one, judged
/// as the route lookup (`ip_route_output_key_hash_rcu`) judges it: an IPv4
/// source first — a multicast or broadcast one is `EINVAL`, one that is no
/// address of this host `ENETUNREACH` (an IPv6 one was judged with the
/// control message) — then the interface, which must exist (`ENODEV`).
pub(super) fn chosen_source(control: &SendControl) -> Result<Option<IpAddr>, c_int> {
    match control.source {
        Some(IpAddr::V4(v4)) if v4.is_multicast() || v4.is_broadcast() => return Err(EINVAL),
        Some(IpAddr::V4(v4)) if !patina_dst_driver_api::local_ipv4(v4.octets()) => {
            return Err(ENETUNREACH);
        }
        _ => {}
    }
    if control.ifindex != 0 && super::iface::by_index(control.ifindex).is_none() {
        return Err(ENODEV);
    }
    Ok(control.source)
}

/// The payload cut into the datagrams a send with segment size `gso` makes
/// (`udp_send_skb`): one when it is no longer than a segment; `EMSGSIZE` for
/// a segment the interface cannot carry, `EINVAL` past `UDP_MAX_SEGMENTS`.
pub(super) fn segments(
    payload: &[u8],
    gso: u16,
    v4_destination: bool,
    mtu: u32,
) -> Result<Vec<&[u8]>, c_int> {
    let gso = usize::from(gso);
    if gso == 0 {
        return Ok(vec![payload]);
    }
    let header = if v4_destination {
        IPV4_HEADER
    } else {
        IPV6_HEADER
    } + UDP_HEADER;
    if header + payload.len().min(gso) > mtu as usize {
        return Err(EMSGSIZE);
    }
    if payload.len() > gso * UDP_MAX_SEGMENTS {
        return Err(EINVAL);
    }
    if payload.len() <= gso {
        return Ok(vec![payload]);
    }
    Ok(payload.chunks(gso).collect())
}

/// The interface that carries traffic for `ip` on this host.
fn interface_of(ip: IpAddr) -> Option<&'static patina_dst_driver_api::NetInterface> {
    VIRTUAL_INTERFACES.iter().find(|interface| match ip {
        IpAddr::V4(v4) => interface.ipv4.owns(v4.octets()),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => interface.ipv4.owns(v4.octets()),
            None => interface.ipv6.is_some_and(|(own, _)| own == v6.octets()),
        },
    })
}

/// The MTU of the interface a destination is reached by.
pub(super) fn mtu_to(destination: IpAddr) -> u32 {
    interface_of(destination).map_or(65536, |interface| interface.mtu)
}

/// `in6_pktinfo`: the address, then the interface index.
fn pktinfo6(address: Ipv6Addr, ifindex: u32) -> Vec<u8> {
    let mut bytes = address.octets().to_vec();
    bytes.extend((ifindex as i32).to_ne_bytes());
    bytes
}

/// The ancillary data a receive of `datagram` reports on a socket of family
/// `v6_socket` with options `ip`, in the kernel's order: an IPv6 socket's
/// `IPV6_PKTINFO` first, then the IPv4 packet information and type of
/// service an IPv4 datagram carries, or the IPv6 traffic class.
pub(super) fn received_control(
    ip: &IpOptions,
    v6_socket: bool,
    datagram: &Datagram,
) -> Vec<ProtocolCmsg> {
    if !(ip.pktinfo || ip.recv_tos || ip.recv_pktinfo6 || ip.recv_tclass) {
        return Vec::new();
    }
    let dialed = if datagram.dialed.is_empty() {
        &datagram.to
    } else {
        &datagram.dialed
    };
    let Some(dialed) = Endpoint::from_wire(dialed) else {
        return Vec::new();
    };
    let ifindex = interface_of(dialed.ip).map_or(0, |interface| interface.index);
    let mut control = Vec::new();
    match dialed.ip {
        IpAddr::V4(destination) => {
            if v6_socket && ip.recv_pktinfo6 {
                control.push((
                    SOL_IPV6,
                    IPV6_PKTINFO,
                    pktinfo6(destination.to_ipv6_mapped(), ifindex),
                ));
            }
            if ip.pktinfo {
                // `ipi_spec_dst` is the local address a reply would leave
                // from: for a datagram delivered here, the one it was sent to.
                let mut info = (ifindex as i32).to_ne_bytes().to_vec();
                info.extend(destination.octets());
                info.extend(destination.octets());
                control.push((SOL_IP, IP_PKTINFO, info));
            }
            if ip.recv_tos {
                control.push((SOL_IP, IP_TOS, vec![datagram.tos]));
            }
        }
        IpAddr::V6(destination) => {
            if ip.recv_pktinfo6 {
                control.push((SOL_IPV6, IPV6_PKTINFO, pktinfo6(destination, ifindex)));
            }
            if ip.recv_tclass {
                control.push((
                    SOL_IPV6,
                    IPV6_TCLASS,
                    i32::from(datagram.tos).to_ne_bytes().to_vec(),
                ));
            }
        }
    }
    control
}

#[cfg(test)]
mod tests {
    use super::*;

    fn defaults() -> IpOptions {
        IpOptions {
            ttl: -1,
            hops: -1,
            ..IpOptions::default()
        }
    }

    #[test]
    fn ipv4_control_takes_the_kernels_sizes_and_ranges() {
        let ip = defaults();
        let tos = |data: Vec<u8>| send_control(&ip, false, true, &[(SOL_IP, IP_TOS, data)]);
        assert_eq!(tos(vec![0x2e]).map(|c| c.tos), Ok(0x2e));
        assert_eq!(tos(0xb9i32.to_ne_bytes().to_vec()).map(|c| c.tos), Ok(0xb9));
        assert_eq!(tos(256i32.to_ne_bytes().to_vec()), Err(EINVAL));
        assert_eq!(tos(vec![3, 0]), Err(EINVAL));
        let mut info = 0i32.to_ne_bytes().to_vec();
        info.extend([127, 0, 0, 9, 0, 0, 0, 0]);
        let control = send_control(&ip, false, true, &[(SOL_IP, IP_PKTINFO, info)]).unwrap();
        assert_eq!(
            control.source,
            Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 9)))
        );
        assert_eq!(chosen_source(&control), Ok(control.source));
        let far = SendControl {
            source: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            ..SendControl::default()
        };
        assert_eq!(chosen_source(&far), Err(ENETUNREACH));
        let nowhere = SendControl {
            ifindex: 99,
            ..SendControl::default()
        };
        assert_eq!(chosen_source(&nowhere), Err(ENODEV));
        let far_and_nowhere = SendControl { ifindex: 99, ..far };
        assert_eq!(chosen_source(&far_and_nowhere), Err(ENETUNREACH));
        assert_eq!(
            send_control(&ip, false, true, &[(SOL_IP, 99, vec![0; 4])]),
            Err(EINVAL)
        );
        // Another family's level is skipped.
        assert!(send_control(&ip, false, true, &[(SOL_IPV6, 67, vec![0; 4])]).is_ok());
    }

    #[test]
    fn ipv6_control_takes_the_kernels_sizes_and_ranges() {
        let ip = defaults();
        let tclass = |value: i32| {
            send_control(
                &ip,
                true,
                false,
                &[(SOL_IPV6, IPV6_TCLASS, value.to_ne_bytes().to_vec())],
            )
        };
        assert_eq!(tclass(0x2e).map(|c| c.tos), Ok(0x2e));
        assert_eq!(tclass(-1).map(|c| c.tos), Ok(0xff));
        assert_eq!(tclass(256), Err(EINVAL));
        let mut remote = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)
            .octets()
            .to_vec();
        remote.extend(0i32.to_ne_bytes());
        assert_eq!(
            send_control(&ip, true, false, &[(SOL_IPV6, IPV6_PKTINFO, remote)]),
            Err(EINVAL)
        );
        let mut bad_index = Ipv6Addr::UNSPECIFIED.octets().to_vec();
        bad_index.extend(99i32.to_ne_bytes());
        assert_eq!(
            send_control(&ip, true, false, &[(SOL_IPV6, IPV6_PKTINFO, bad_index)]),
            Err(ENODEV)
        );
    }

    #[test]
    fn ipv6_control_takes_the_rfc_2292_numbers_ip6_datagram_send_ctl_does() {
        let ip = defaults();
        let send =
            |kind: i32, data: Vec<u8>| send_control(&ip, true, false, &[(SOL_IPV6, kind, data)]);
        let loopback = |extra: usize| {
            let mut info = Ipv6Addr::LOCALHOST.octets().to_vec();
            info.extend(0i32.to_ne_bytes());
            info.extend(vec![0; extra]);
            info
        };
        let source = Some(IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(
            send(IPV6_2292PKTINFO, loopback(0)).map(|c| c.source),
            Ok(source)
        );
        assert_eq!(
            send(IPV6_PKTINFO, loopback(4)).map(|c| c.source),
            Ok(source)
        );
        assert_eq!(send(IPV6_PKTINFO, vec![0; 16]), Err(EINVAL));
        assert!(send(IPV6_2292HOPLIMIT, 7i32.to_ne_bytes().to_vec()).is_ok());
        assert_eq!(
            send(IPV6_2292HOPLIMIT, 256i32.to_ne_bytes().to_vec()),
            Err(EINVAL)
        );
        // IPV6_2292PKTOPTIONS, IPV6_CHECKSUM, IPV6_NEXTHOP.
        for kind in [6, 7, 9] {
            assert_eq!(send(kind, 0i32.to_ne_bytes().to_vec()), Err(EINVAL));
        }
        assert!(send(IPV6_DONTFRAG, 1i32.to_ne_bytes().to_vec()).is_ok());
        assert_eq!(
            send(IPV6_DONTFRAG, 2i32.to_ne_bytes().to_vec()),
            Err(EINVAL)
        );
        // An IPv4-mapped send converts only the RFC 3542 number.
        let mut mapped = Ipv4Addr::LOCALHOST.to_ipv6_mapped().octets().to_vec();
        mapped.extend(0i32.to_ne_bytes());
        let v4 = |kind: i32| send_control(&ip, true, true, &[(SOL_IPV6, kind, mapped.clone())]);
        assert_eq!(
            v4(IPV6_PKTINFO).map(|c| c.source),
            Ok(Some(IpAddr::V4(Ipv4Addr::LOCALHOST)))
        );
        assert_eq!(v4(IPV6_2292PKTINFO).map(|c| c.source), Ok(None));
    }

    #[test]
    fn segmentation_follows_udp_send_skb() {
        let payload = [0u8; 25];
        let cut = segments(&payload, 10, true, 65536).unwrap();
        assert_eq!(cut.iter().map(|s| s.len()).collect::<Vec<_>>(), [10, 10, 5]);
        assert_eq!(segments(&payload, 0, true, 65536).unwrap().len(), 1);
        assert_eq!(segments(&payload, 65535, true, 65536).unwrap().len(), 1);
        assert_eq!(segments(&[0u8; 128], 1, true, 65536).unwrap().len(), 128);
        assert_eq!(segments(&[0u8; 129], 1, true, 65536), Err(EINVAL));
        assert_eq!(segments(&[0u8; 1500], 1480, true, 1500), Err(EMSGSIZE));
    }

    #[test]
    fn a_receive_reports_what_the_socket_asked_for_in_order() {
        let ip = IpOptions {
            pktinfo: true,
            recv_tos: true,
            recv_pktinfo6: true,
            ..defaults()
        };
        let datagram = Datagram {
            packet_id: 1,
            from: "127.0.0.9:5".into(),
            to: "0.0.0.0:7".into(),
            bytes: vec![1],
            delivery_nanos: 0,
            dialed: "127.0.0.1:7".into(),
            tos: 0x44,
        };
        let control = received_control(&ip, true, &datagram);
        let kinds: Vec<(i32, i32)> = control.iter().map(|(l, k, _)| (*l, *k)).collect();
        assert_eq!(
            kinds,
            [
                (SOL_IPV6, IPV6_PKTINFO),
                (SOL_IP, IP_PKTINFO),
                (SOL_IP, IP_TOS)
            ]
        );
        assert_eq!(control[1].2[..4], 1i32.to_ne_bytes());
        assert_eq!(control[1].2[4..], [127, 0, 0, 1, 127, 0, 0, 1]);
        assert_eq!(control[2].2, [0x44]);
    }
}
