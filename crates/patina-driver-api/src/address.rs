//! Guest path normalization, virtual network interfaces, and address routing.

use crate::DriverResult;
use patina_dst_abi::EffectError;

/// Resolve a guest path to the absolute, symlink-free *spelling* the
/// deterministic filesystems key their entries under: reject a relative or
/// NUL-bearing path, drop `.` and empty (`//`) components, and resolve `..`
/// lexically against the accumulated prefix (a `..` at the root stays at the
/// root, as it does on a real filesystem). This performs no I/O -- it is the
/// pure lexical half of `realpath`, shared here so the C-ABI shim and any driver
/// produce ONE canonical spelling rather than each risking a subtly different
/// one. The output is idempotent under the drivers' own entry normalization, so
/// a canonicalized path fed straight back into a driver operation names the
/// identical entry.
pub fn canonicalize_path(path: &str) -> DriverResult<String> {
    if !path.starts_with('/') {
        return Err(EffectError::new(
            patina_dst_abi::ErrorCode::InvalidInput,
            format!("virtual filesystem path must be absolute: {path:?}"),
        ));
    }
    if path.contains('\0') {
        return Err(EffectError::new(
            patina_dst_abi::ErrorCode::InvalidInput,
            "virtual filesystem path contains NUL",
        ));
    }
    let mut components: Vec<&str> = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            value => components.push(value),
        }
    }
    Ok(format!("/{}", components.join("/")))
}

/// The wildcard bindings that receive traffic dialed at `address` when nothing
/// is bound at it exactly, most specific first.
///
/// The ONE wildcard-bind routing rule, shared by every layer that resolves a
/// virtual address to a socket: a socket bound to `0.0.0.0:PORT` receives IPv4
/// traffic addressed to any `IP:PORT` with no exact-match binding, one bound
/// to `[::]:PORT` the same for IPv6, and one bound to `*:PORT` (an IPv6
/// socket that also takes IPv4, the kernel's dual-stack `in6addr_any` bind)
/// receives either family after the family's own wildcard. Exact match always
/// wins; this function only supplies the fallbacks, in the order to try them.
///
/// It lives here, beside [`canonicalize_path`], because two layers resolve
/// addresses independently — the network driver routes the packet and the native
/// shim wakes the receiving task from its own address-keyed table. A rule
/// implemented in only one of them delivers a datagram that nothing ever wakes
/// for, so both call this.
///
/// Addresses are opaque strings in the virtual network (tests and the explicit
/// API bind bare labels like `"server"`); only `IPv4:PORT`, `[IPv6]:PORT` and
/// the wildcards themselves have fallbacks, so a label keeps exact-match-only
/// behavior. A wildcard never falls back to itself, which would invite a lookup
/// loop: `0.0.0.0:P` and `[::]:P` fall back to `*:P` alone, and `*:P` to
/// nothing.
pub fn wildcard_bind_keys(address: &str) -> Vec<String> {
    let Some((host, port)) = address.rsplit_once(':') else {
        return Vec::new();
    };
    if port.parse::<u16>().is_err() {
        return Vec::new();
    }
    let any = format!("{ANY_FAMILY_HOST}:{port}");
    if host == WILDCARD_HOST || host == WILDCARD_V6_HOST {
        return vec![any];
    }
    if host.parse::<std::net::Ipv4Addr>().is_ok() {
        return vec![format!("{WILDCARD_HOST}:{port}"), any];
    }
    let v6 = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .and_then(|host| host.parse::<std::net::Ipv6Addr>().ok());
    if v6.is_some() {
        return vec![format!("{WILDCARD_V6_HOST}:{port}"), any];
    }
    Vec::new()
}

/// The dotted-quad spelling of `INADDR_ANY`, the host half of an IPv4 wildcard
/// bind.
pub const WILDCARD_HOST: &str = "0.0.0.0";

/// The spelling of `in6addr_any` for an IPv6 socket that takes IPv6 alone
/// (`IPV6_V6ONLY`), the host half of an IPv6 wildcard bind.
pub const WILDCARD_V6_HOST: &str = "[::]";

/// The host half of a wildcard bind that receives both families: an IPv6
/// socket bound to `in6addr_any` without `IPV6_V6ONLY`.
pub const ANY_FAMILY_HOST: &str = "*";

/// One interface of the virtual host (`lo` + `eth0`, the arc's table): what
/// `SIOCGIF*`, `if_nametoindex`, `getifaddrs` and the rtnetlink dumps answer,
/// and which local addresses a socket may bind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetInterface {
    pub index: u32,
    pub name: &'static str,
    /// `IFF_*` flags as `SIOCGIFFLAGS` reports them (the low 16 bits) plus
    /// `IFF_LOWER_UP` (bit 16), which rtnetlink and `getifaddrs` add.
    pub flags: u32,
    /// `ARPHRD_*`.
    pub hardware_type: u16,
    pub hardware_address: [u8; 6],
    pub broadcast_hardware_address: [u8; 6],
    pub mtu: u32,
    pub ipv4: InterfaceIpv4,
    /// The interface's IPv6 address and prefix, when it has one.
    pub ipv6: Option<([u8; 16], u8)>,
}

/// An interface's IPv4 address. The interface owns every address of its
/// prefix: the virtual network runs every host of its one LAN in this process,
/// so a guest may bind any of them (as it may bind any of `127.0.0.0/8`), and
/// an address outside every prefix belongs to no interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InterfaceIpv4 {
    pub address: [u8; 4],
    pub prefix: u8,
    /// `RT_SCOPE_*`: host for loopback, universe otherwise.
    pub scope: u8,
}

const IFF_UP: u32 = 0x1;
const IFF_BROADCAST: u32 = 0x2;
const IFF_LOOPBACK: u32 = 0x8;
const IFF_RUNNING: u32 = 0x40;
const IFF_MULTICAST: u32 = 0x1000;
const IFF_LOWER_UP: u32 = 0x10000;
const ARPHRD_ETHER: u16 = 1;
const ARPHRD_LOOPBACK: u16 = 772;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RT_SCOPE_HOST: u8 = 254;

/// The virtual host's interfaces, in index order: the loopback device every
/// network namespace registers first, and one Ethernet interface on
/// `10.0.0.0/24`, the LAN the virtual network's hosts share (the DNS service
/// allocator hands out its addresses). There is no default route.
pub const VIRTUAL_INTERFACES: &[NetInterface] = &[
    NetInterface {
        index: 1,
        name: "lo",
        flags: IFF_UP | IFF_LOOPBACK | IFF_RUNNING | IFF_LOWER_UP,
        hardware_type: ARPHRD_LOOPBACK,
        hardware_address: [0; 6],
        broadcast_hardware_address: [0; 6],
        mtu: 65536,
        ipv4: InterfaceIpv4 {
            address: [127, 0, 0, 1],
            prefix: 8,
            scope: RT_SCOPE_HOST,
        },
        ipv6: Some(([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 128)),
    },
    NetInterface {
        index: 2,
        name: "eth0",
        flags: IFF_UP | IFF_BROADCAST | IFF_RUNNING | IFF_MULTICAST | IFF_LOWER_UP,
        hardware_type: ARPHRD_ETHER,
        hardware_address: [0x02, 0, 0, 0, 0, 0x01],
        broadcast_hardware_address: [0xff; 6],
        mtu: 1500,
        ipv4: InterfaceIpv4 {
            address: [10, 0, 0, 1],
            prefix: 24,
            scope: RT_SCOPE_UNIVERSE,
        },
        ipv6: None,
    },
];

impl InterfaceIpv4 {
    /// The prefix as a netmask.
    pub fn netmask(&self) -> [u8; 4] {
        (u32::MAX
            .checked_shl(32 - u32::from(self.prefix))
            .unwrap_or(0))
        .to_be_bytes()
    }

    /// The directed broadcast address of the prefix.
    pub fn broadcast(&self) -> [u8; 4] {
        (u32::from_be_bytes(self.address) | !u32::from_be_bytes(self.netmask())).to_be_bytes()
    }

    /// Whether `address` is in this interface's prefix.
    pub fn owns(&self, address: [u8; 4]) -> bool {
        let mask = u32::from_be_bytes(self.netmask());
        u32::from_be_bytes(address) & mask == u32::from_be_bytes(self.address) & mask
    }
}

/// Whether some virtual interface owns the IPv4 `address` — what `bind` asks
/// before it accepts a local address (`EADDRNOTAVAIL` otherwise).
pub fn local_ipv4(address: [u8; 4]) -> bool {
    VIRTUAL_INTERFACES
        .iter()
        .any(|interface| interface.ipv4.owns(address))
}

/// Whether some virtual interface has the IPv6 `address`.
pub fn local_ipv6(address: [u8; 16]) -> bool {
    VIRTUAL_INTERFACES
        .iter()
        .any(|interface| interface.ipv6.is_some_and(|(own, _)| own == address))
}

/// The address traffic toward `destination` leaves from — the address of the
/// interface whose prefix holds it — or `None` when no interface routes
/// there (the table has no default route). An unspecified destination is the
/// host itself, as the kernel takes a connect to `INADDR_ANY`/`in6addr_any`.
pub fn source_address(destination: std::net::IpAddr) -> Option<std::net::IpAddr> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    match destination {
        IpAddr::V4(ip) if ip.is_unspecified() => Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        IpAddr::V4(ip) => VIRTUAL_INTERFACES
            .iter()
            .find(|interface| interface.ipv4.owns(ip.octets()))
            .map(|interface| IpAddr::V4(Ipv4Addr::from(interface.ipv4.address))),
        IpAddr::V6(ip) if ip.is_unspecified() || ip.is_loopback() => {
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST))
        }
        IpAddr::V6(_) => None,
    }
}

/// The address a datagram from a socket bound at the network address
/// `bound` carries toward `to`: a wildcard binding sends from the address of
/// the interface that routes to the destination (`source_address`); anything
/// else sends from where it is bound.
pub fn datagram_source(bound: &str, to: &str) -> String {
    let Some((host, port)) = bound.rsplit_once(':') else {
        return bound.to_owned();
    };
    if host != WILDCARD_HOST && host != WILDCARD_V6_HOST && host != ANY_FAMILY_HOST {
        return bound.to_owned();
    }
    let destination = to.rsplit_once(':').and_then(|(host, _)| {
        host.parse::<std::net::IpAddr>().ok().or_else(|| {
            host.strip_prefix('[')?
                .strip_suffix(']')?
                .parse::<std::net::Ipv6Addr>()
                .ok()
                .map(std::net::IpAddr::V6)
        })
    });
    match destination.and_then(source_address) {
        Some(std::net::IpAddr::V4(ip)) => format!("{ip}:{port}"),
        Some(std::net::IpAddr::V6(ip)) => format!("[{ip}]:{port}"),
        None => bound.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exact binds are the caller's; the fallbacks go family wildcard first,
    /// then the dual-stack wildcard, and a wildcard never falls back to
    /// itself. A label has none.
    #[test]
    fn wildcard_bind_keys_fall_back_by_family_then_to_any() {
        assert_eq!(wildcard_bind_keys("127.0.0.1:80"), ["0.0.0.0:80", "*:80"]);
        assert_eq!(wildcard_bind_keys("[::1]:80"), ["[::]:80", "*:80"]);
        assert_eq!(wildcard_bind_keys("0.0.0.0:80"), ["*:80"]);
        assert_eq!(wildcard_bind_keys("[::]:80"), ["*:80"]);
        assert!(wildcard_bind_keys("*:80").is_empty());
        assert!(wildcard_bind_keys("server").is_empty());
        assert!(wildcard_bind_keys("server:http").is_empty());
    }

    /// `lo` owns `127.0.0.0/8` and `::1`, `eth0` `10.0.0.0/24`; routing picks
    /// the owning interface's address, and there is no default route.
    #[test]
    fn interface_table_owns_its_prefixes_and_routes_without_a_default() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        assert!(local_ipv4([127, 1, 2, 3]));
        assert!(local_ipv4([10, 0, 0, 77]));
        assert!(!local_ipv4([10, 0, 1, 1]));
        assert!(local_ipv6(Ipv6Addr::LOCALHOST.octets()));
        assert!(!local_ipv6([
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
        ]));
        let eth0 = VIRTUAL_INTERFACES[1].ipv4;
        assert_eq!(eth0.netmask(), [255, 255, 255, 0]);
        assert_eq!(eth0.broadcast(), [10, 0, 0, 255]);
        assert_eq!(VIRTUAL_INTERFACES[0].ipv4.netmask(), [255, 0, 0, 0]);
        assert_eq!(
            source_address(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9))),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        );
        assert_eq!(
            source_address(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
        assert_eq!(source_address(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))), None);
        assert_eq!(datagram_source("0.0.0.0:5", "10.0.0.9:7"), "10.0.0.1:5");
        assert_eq!(datagram_source("*:5", "[::1]:7"), "[::1]:5");
        assert_eq!(datagram_source("127.0.0.1:5", "10.0.0.9:7"), "127.0.0.1:5");
    }
}
