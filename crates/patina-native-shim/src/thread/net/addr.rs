//! Socket addresses: the guest's `struct sockaddr_*` bytes in, the kernel's
//! answers out.
//!
//! The kernel copies an address in with `move_addr_to_kernel` (a length past
//! `sizeof(struct sockaddr_storage)` or negative is `EINVAL`, an unreadable
//! one `EFAULT`) and leaves its interpretation — and the errno for a short or
//! foreign one — to the family, so the parsers here take the copied bytes and
//! answer exactly what that family's `bind`/`connect`/`sendmsg` would. Out,
//! `move_addr_to_user` copies at most the caller's buffer and always reports
//! the address's full length.

use std::ffi::c_int;
use std::net::{Ipv4Addr, Ipv6Addr};

use super::abi::*;
use crate::uaccess;
use crate::{EFAULT, EINVAL};

/// An IPv4 or IPv6 transport address, as the network routes it. An
/// IPv4-mapped IPv6 address is the IPv4 address it maps.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Endpoint {
    pub(crate) ip: std::net::IpAddr,
    pub(crate) port: u16,
}

impl Endpoint {
    pub(crate) const fn v4(ip: Ipv4Addr, port: u16) -> Endpoint {
        Endpoint {
            ip: std::net::IpAddr::V4(ip),
            port,
        }
    }

    /// The network's spelling (`patina_dst_driver_api::wildcard_bind_keys`):
    /// `a.b.c.d:P`, `[v6]:P`.
    pub(crate) fn wire(&self) -> String {
        match self.ip {
            std::net::IpAddr::V4(ip) => format!("{ip}:{}", self.port),
            std::net::IpAddr::V6(ip) => format!("[{ip}]:{}", self.port),
        }
    }

    /// Parse the network's spelling back.
    pub(crate) fn from_wire(text: &str) -> Option<Endpoint> {
        let (host, port) = text.rsplit_once(':')?;
        let port = port.parse().ok()?;
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            return Some(Endpoint::v4(ip, port));
        }
        let ip = host
            .strip_prefix('[')?
            .strip_suffix(']')?
            .parse::<Ipv6Addr>()
            .ok()?;
        Some(Endpoint {
            ip: std::net::IpAddr::V6(ip),
            port,
        })
    }
}

/// An IPv6 socket address's own fields beyond the endpoint.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct V6Extra {
    pub(crate) flowinfo: u32,
    pub(crate) scope_id: u32,
}

/// An AF_UNIX socket's name (net/unix/af_unix.c `struct unix_address`): the
/// bytes of `sun_path` as the kernel keeps them.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum UnixName {
    /// No name: a pair's end, a connected client, an unbound socket.
    Unnamed,
    /// A filesystem path (without its NUL).
    Path(Vec<u8>),
    /// An abstract name: the bytes after the leading NUL, exactly as many as
    /// the address's length gave.
    Abstract(Vec<u8>),
}

/// The platform's `sa_family` of an address the guest passed.
pub(crate) fn family_of(bytes: &[u8]) -> Option<i32> {
    #[cfg(target_os = "linux")]
    return (bytes.len() >= 2).then(|| i32::from(u16::from_ne_bytes([bytes[0], bytes[1]])));
    #[cfg(target_os = "macos")]
    return (bytes.len() >= 2).then(|| i32::from(bytes[1]));
}

/// The header an address of `family` and total `len` starts with.
fn header(family: i32, len: usize) -> [u8; 2] {
    #[cfg(target_os = "linux")]
    {
        let _ = len;
        (family as u16).to_ne_bytes()
    }
    #[cfg(target_os = "macos")]
    return [len as u8, family as u8];
}

/// `move_addr_to_kernel`: the guest's `len` address bytes at `addr`.
pub(crate) fn copy_in(addr: usize, len: i64) -> Result<Vec<u8>, c_int> {
    if len < 0 || len as usize > SOCKADDR_STORAGE_LEN {
        return Err(EINVAL);
    }
    uaccess::read_bytes(addr, len as usize)
}

/// `move_addr_to_user`: copy as much of `address` as the guest's buffer
/// holds (`*len_ptr` in) and report its full length (`*len_ptr` out). A
/// negative buffer length is `EINVAL`.
pub(crate) fn copy_out(address: &[u8], addr: usize, len_ptr: usize) -> Result<(), c_int> {
    let len: i32 = uaccess::read(len_ptr)?;
    let len = (len as i64).min(address.len() as i64);
    if len < 0 {
        return Err(EINVAL);
    }
    if len > 0 {
        uaccess::write_bytes(addr, &address[..len as usize])?;
    }
    uaccess::write(len_ptr, &(address.len() as i32))
}

/// A `sockaddr_in`: the endpoint, or `EINVAL` for fewer bytes than the
/// structure and `wrong_family` for another family.
pub(crate) fn parse_in(bytes: &[u8], wrong_family: c_int) -> Result<Endpoint, c_int> {
    if bytes.len() < 16 {
        return Err(EINVAL);
    }
    if family_of(bytes) != Some(AF_INET) {
        return Err(wrong_family);
    }
    Ok(Endpoint::v4(
        Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]),
        u16::from_be_bytes([bytes[2], bytes[3]]),
    ))
}

/// `SIN6_LEN_RFC2133`: the shortest `sockaddr_in6` the kernel takes (no scope).
const SIN6_LEN_RFC2133: usize = 24;

/// A `sockaddr_in6`: the address, port and extra fields, or `EINVAL` for
/// fewer bytes than `SIN6_LEN_RFC2133` and `wrong_family` for another family.
/// The address is the raw sixteen bytes: whether a mapped one names IPv4 is
/// the caller's to judge.
pub(crate) fn parse_in6(
    bytes: &[u8],
    wrong_family: c_int,
) -> Result<(Ipv6Addr, u16, V6Extra), c_int> {
    if bytes.len() < SIN6_LEN_RFC2133 {
        return Err(EINVAL);
    }
    if family_of(bytes) != Some(AF_INET6) {
        return Err(wrong_family);
    }
    let mut octets = [0u8; 16];
    octets.copy_from_slice(&bytes[8..24]);
    let scope_id = if bytes.len() >= 28 {
        u32::from_ne_bytes([bytes[24], bytes[25], bytes[26], bytes[27]])
    } else {
        0
    };
    Ok((
        Ipv6Addr::from(octets),
        u16::from_be_bytes([bytes[2], bytes[3]]),
        V6Extra {
            flowinfo: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            scope_id,
        },
    ))
}

/// A `sockaddr_in` for `endpoint` (an IPv4 one).
pub(crate) fn encode_in(ip: Ipv4Addr, port: u16) -> Vec<u8> {
    let mut bytes = vec![0u8; 16];
    bytes[..2].copy_from_slice(&header(AF_INET, 16));
    bytes[2..4].copy_from_slice(&port.to_be_bytes());
    bytes[4..8].copy_from_slice(&ip.octets());
    bytes
}

/// A `sockaddr_in6`.
pub(crate) fn encode_in6(ip: Ipv6Addr, port: u16, extra: V6Extra) -> Vec<u8> {
    let mut bytes = vec![0u8; 28];
    bytes[..2].copy_from_slice(&header(AF_INET6, 28));
    bytes[2..4].copy_from_slice(&port.to_be_bytes());
    bytes[4..8].copy_from_slice(&extra.flowinfo.to_be_bytes());
    bytes[8..24].copy_from_slice(&ip.octets());
    bytes[24..28].copy_from_slice(&extra.scope_id.to_ne_bytes());
    bytes
}

/// `offsetof(struct sockaddr_un, sun_path)`.
pub(crate) const SUN_PATH: usize = 2;

/// What an AF_UNIX `bind`/`connect` address asks for (`unix_validate_addr`
/// and `unix_mkname_bsd`): `Unnamed` for the bare family (`bind`'s autobind),
/// else a path up to its first NUL or an abstract name of every byte the
/// length gave. A length at or below the family or past `sockaddr_un`, or
/// another family, is `EINVAL`.
pub(crate) fn parse_un(bytes: &[u8]) -> Result<UnixName, c_int> {
    if bytes.len() == SUN_PATH && family_of(bytes) == Some(AF_UNIX) {
        return Ok(UnixName::Unnamed);
    }
    if bytes.len() <= SUN_PATH || bytes.len() > SOCKADDR_UN_LEN {
        return Err(EINVAL);
    }
    if family_of(bytes) != Some(AF_UNIX) {
        return Err(EINVAL);
    }
    let path = &bytes[SUN_PATH..];
    if path[0] == 0 {
        return Ok(UnixName::Abstract(path[1..].to_vec()));
    }
    let end = path
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(path.len());
    Ok(UnixName::Path(path[..end].to_vec()))
}

/// The `sockaddr_un` a name reports: the family alone for no name, the path
/// and its NUL, or the NUL and the abstract bytes.
pub(crate) fn encode_un(name: &UnixName) -> Vec<u8> {
    let body: Vec<u8> = match name {
        UnixName::Unnamed => Vec::new(),
        UnixName::Path(path) => path.iter().copied().chain([0]).collect(),
        UnixName::Abstract(name) => [0].into_iter().chain(name.iter().copied()).collect(),
    };
    let mut bytes = header(AF_UNIX, SUN_PATH + body.len()).to_vec();
    bytes.extend(body);
    bytes
}

/// A `sockaddr_nl`'s port id and groups, or `EINVAL` for a short or foreign
/// address (`netlink_bind`, `netlink_connect`, `netlink_sendmsg`).
#[cfg(target_os = "linux")]
pub(crate) fn parse_nl(bytes: &[u8]) -> Result<(u32, u32), c_int> {
    if bytes.len() < 12 || family_of(bytes) != Some(AF_NETLINK) {
        return Err(EINVAL);
    }
    Ok((
        u32::from_ne_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        u32::from_ne_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
    ))
}

/// A `sockaddr_nl`.
#[cfg(target_os = "linux")]
pub(crate) fn encode_nl(pid: u32, groups: u32) -> Vec<u8> {
    let mut bytes = vec![0u8; 12];
    bytes[..2].copy_from_slice(&header(AF_NETLINK, 12));
    bytes[4..8].copy_from_slice(&pid.to_ne_bytes());
    bytes[8..12].copy_from_slice(&groups.to_ne_bytes());
    bytes
}

/// A guest pointer argument read as the kernel reads an `int __user *`.
pub(crate) fn read_len(len_ptr: usize) -> Result<i32, c_int> {
    if len_ptr == 0 {
        return Err(EFAULT);
    }
    uaccess::read(len_ptr)
}

/// A numeric host as `getaddrinfo` reads one (glibc `__inet_aton_exact`,
/// `inet_pton`): IPv4 in one to four parts, each decimal, octal (leading `0`)
/// or hexadecimal (`0x`), the last filling the remaining bytes; or IPv6, with
/// an optional `%scope` naming an interface by number or by name.
pub(crate) fn numeric_host(text: &str) -> Option<(std::net::IpAddr, u32)> {
    if let Some(ip) = inet_aton(text) {
        return Some((ip.into(), 0));
    }
    let (address, scope) = match text.split_once('%') {
        Some((address, scope)) => {
            let index = match scope.parse::<u32>() {
                Ok(index) => index,
                Err(_) => super::iface::by_name(scope)?.index,
            };
            (address, index)
        }
        None => (text, 0),
    };
    Some((address.parse::<Ipv6Addr>().ok()?.into(), scope))
}

fn inet_aton(text: &str) -> Option<Ipv4Addr> {
    let mut parts = [0u32; 4];
    let mut count = 0;
    for part in text.split('.') {
        if count == 4 {
            return None;
        }
        let (digits, radix) =
            if let Some(hex) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
                (hex, 16)
            } else if part.len() > 1 && part.starts_with('0') {
                (&part[1..], 8)
            } else {
                (part, 10)
            };
        if digits.is_empty() && radix != 16 || !digits.chars().all(|c| c.is_digit(radix)) {
            return None;
        }
        parts[count] = if digits.is_empty() {
            0
        } else {
            u32::from_str_radix(digits, radix).ok()?
        };
        count += 1;
    }
    let (head, last) = parts[..count].split_at(count - 1);
    if head.iter().any(|part| *part > 0xff) || u64::from(last[0]) >> (8 * (4 - head.len())) != 0 {
        return None;
    }
    let value = head
        .iter()
        .enumerate()
        .fold(last[0], |value, (at, part)| value | part << (24 - 8 * at));
    Some(Ipv4Addr::from(value))
}

/// `getaddrinfo`'s numeric-host parse ([`numeric_host`]): the family with
/// the address in `out` (4 or 16 bytes, network order) and the IPv6 scope in
/// `scope`, or 0 when `node` is no numeric host.
///
/// # Safety
/// `node` is a NUL-terminated string; `out` names 16 writable bytes and
/// `scope` a writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_net_numeric_host(
    node: *const std::ffi::c_char,
    out: *mut u8,
    scope: *mut u32,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the caller's contract.
    let text = unsafe { std::ffi::CStr::from_ptr(node) };
    let Some((ip, index)) = text.to_str().ok().and_then(numeric_host) else {
        return 0;
    };
    let (family, bytes) = match ip {
        std::net::IpAddr::V4(ip) => (AF_INET, ip.octets().to_vec()),
        std::net::IpAddr::V6(ip) => (AF_INET6, ip.octets().to_vec()),
    };
    // SAFETY: the caller's contract.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len());
        *scope = index;
    }
    family
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_hosts_read_as_inet_aton_and_inet_pton() {
        let v4 = |text| numeric_host(text).map(|(ip, _)| ip);
        assert_eq!(v4("127.0.0.1"), Some(Ipv4Addr::LOCALHOST.into()));
        assert_eq!(v4("127.1"), Some(Ipv4Addr::LOCALHOST.into()));
        assert_eq!(v4("0x7f.1"), Some(Ipv4Addr::LOCALHOST.into()));
        assert_eq!(v4("0177.0.0.01"), Some(Ipv4Addr::LOCALHOST.into()));
        assert_eq!(v4("2130706433"), Some(Ipv4Addr::LOCALHOST.into()));
        assert_eq!(v4("10.65535"), Some(Ipv4Addr::new(10, 0, 255, 255).into()));
        assert_eq!(v4("10.65536.1"), None);
        assert_eq!(v4("256.0.0.1"), None);
        assert_eq!(v4("1.2.3.4.5"), None);
        assert_eq!(v4("1..2"), None);
        assert_eq!(v4("08.1.1.1"), None);
        assert_eq!(v4("127.0.0.1 "), None);
        assert_eq!(v4("not-an-address"), None);
        assert_eq!(numeric_host("::1"), Some((Ipv6Addr::LOCALHOST.into(), 0)));
        assert_eq!(
            numeric_host("fe80::1%lo"),
            Some(("fe80::1".parse::<Ipv6Addr>().unwrap().into(), 1))
        );
        assert_eq!(
            numeric_host("fe80::1%7"),
            Some(("fe80::1".parse::<Ipv6Addr>().unwrap().into(), 7))
        );
        assert_eq!(numeric_host("fe80::1%nope"), None);
    }

    #[test]
    fn inet_addresses_round_trip_and_judge_length_before_family() {
        let bytes = encode_in(Ipv4Addr::LOCALHOST, 8080);
        assert_eq!(
            parse_in(&bytes, EAFNOSUPPORT),
            Ok(Endpoint::v4(Ipv4Addr::LOCALHOST, 8080))
        );
        assert_eq!(parse_in(&bytes[..8], EAFNOSUPPORT), Err(EINVAL));
        let six = encode_in6(Ipv6Addr::LOCALHOST, 1, V6Extra::default());
        assert_eq!(parse_in(&six[..16], EAFNOSUPPORT), Err(EAFNOSUPPORT));
        assert_eq!(parse_in6(&six[..23], EAFNOSUPPORT), Err(EINVAL));
        assert_eq!(
            parse_in6(&six[..24], EAFNOSUPPORT),
            Ok((Ipv6Addr::LOCALHOST, 1, V6Extra::default()))
        );
    }

    #[test]
    fn unix_names_follow_unix_validate_addr() {
        let family = header(AF_UNIX, 2);
        assert_eq!(parse_un(&family), Ok(UnixName::Unnamed));
        let mut path = family.to_vec();
        path.extend(b"/run/s.sock\0garbage");
        assert_eq!(parse_un(&path), Ok(UnixName::Path(b"/run/s.sock".to_vec())));
        let mut abstract_name = family.to_vec();
        abstract_name.extend(b"\0name\0x");
        assert_eq!(
            parse_un(&abstract_name),
            Ok(UnixName::Abstract(b"name\0x".to_vec()))
        );
        assert_eq!(parse_un(&[0u8; SOCKADDR_UN_LEN + 1]), Err(EINVAL));
        assert_eq!(parse_un(&encode_in(Ipv4Addr::LOCALHOST, 1)), Err(EINVAL));
        assert_eq!(
            encode_un(&UnixName::Path(b"/a".to_vec())).len(),
            SUN_PATH + 3
        );
        assert_eq!(
            encode_un(&UnixName::Abstract(b"ab".to_vec())).len(),
            SUN_PATH + 3
        );
    }

    #[test]
    fn a_wire_address_round_trips_both_families() {
        for text in ["127.0.0.1:80", "[::1]:443"] {
            assert_eq!(Endpoint::from_wire(text).unwrap().wire(), text);
        }
        assert_eq!(Endpoint::from_wire("label"), None);
    }
}
