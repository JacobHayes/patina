//! The network rows: sockets and their socket addresses of every family a
//! scenario uses ([`SockAddr`]: IPv4, IPv6, AF_UNIX path, abstract and
//! unnamed, AF_NETLINK), the message rows (`sendmsg`/`recvmsg` with
//! ancillary data, `sendmmsg`/`recvmmsg`), socket options, the interface
//! ioctls and lookups, netlink requests, and the readiness rows over sockets
//! (`poll`, `select`, `pselect6`, `epoll_create`, `epoll_pwait`,
//! `epoll_pwait2`, `eventfd`).
//!
//! Host-dependent values are recorded by relation, never by value: ports,
//! netlink port ids and AF_UNIX autobind names as [`Norm::Relative`] labels;
//! buffer sizes, MTUs and the interface table beyond `lo` not at all (the
//! scenario checks their relations — the value the kernel doubles, the MTU
//! one interface reports two ways). Scenarios never contact anything off the
//! host: every address is loopback (`127.0.0.1`, `::1`), a path under the
//! run directory, an abstract name derived from it, or the kernel's netlink.

use super::{Probe, SIGSET_BYTES, cstr, neg, printable, read_vector, write_vector};
use crate::observe::{Id, Norm};
use crate::record::EventBuilder;
use crate::vehicle::{Args, Vehicle, fold_errno};
use patina_dst_syscalls::Syscall;
use serde_json::Value;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

mod interfaces;
mod messages;
mod name_resolution;
mod options;
mod readiness;
mod socket;

// ---- kernel ABI constants the libc crate spells per target or not at all ----

/// `SIOCATMARK` (asm-generic/sockios.h): whether the next byte is the urgent
/// one.
pub const SIOCATMARK: u64 = 0x8905;

/// `SIOCGIF*` requests (include/uapi/linux/sockios.h; one table on every
/// Linux architecture).
pub const SIOCGIFNAME: u64 = 0x8910;
pub const SIOCGIFCONF: u64 = 0x8912;
pub const SIOCGIFFLAGS: u64 = 0x8913;
pub const SIOCGIFADDR: u64 = 0x8915;
pub const SIOCGIFBRDADDR: u64 = 0x8919;
pub const SIOCGIFNETMASK: u64 = 0x891b;
pub const SIOCGIFMTU: u64 = 0x8921;
pub const SIOCGIFHWADDR: u64 = 0x8927;
pub const SIOCGIFINDEX: u64 = 0x8933;

/// `ARPHRD_LOOPBACK` (include/uapi/linux/if_arp.h): the loopback device's
/// hardware type.
pub const ARPHRD_LOOPBACK: u16 = 772;

/// Netlink (include/uapi/linux/netlink.h, rtnetlink.h, if_link.h,
/// if_addr.h).
pub mod nl {
    pub const NLMSG_ERROR: u16 = 2;
    pub const NLMSG_DONE: u16 = 3;
    pub const NLM_F_REQUEST: u16 = 0x1;
    pub const NLM_F_MULTI: u16 = 0x2;
    pub const NLM_F_ACK: u16 = 0x4;
    pub const NLM_F_DUMP: u16 = 0x300;
    pub const RTM_NEWLINK: u16 = 16;
    pub const RTM_GETLINK: u16 = 18;
    pub const RTM_NEWADDR: u16 = 20;
    pub const RTM_GETADDR: u16 = 22;
    pub const IFLA_ADDRESS: u16 = 1;
    pub const IFLA_BROADCAST: u16 = 2;
    pub const IFLA_IFNAME: u16 = 3;
    pub const IFLA_MTU: u16 = 4;
    pub const IFA_ADDRESS: u16 = 1;
    pub const IFA_LOCAL: u16 = 2;
    pub const IFA_LABEL: u16 = 3;
    /// `RT_SCOPE_HOST`: an address valid only on this host (loopback).
    pub const RT_SCOPE_HOST: u8 = 254;
    /// `sizeof(struct nlmsghdr)`.
    pub const HEADER: usize = 16;
    /// `sizeof(struct ifinfomsg)`.
    pub const IFINFOMSG: usize = 16;
    /// `sizeof(struct ifaddrmsg)`.
    pub const IFADDRMSG: usize = 8;
}

/// The kernel's `interface name` capacity (`IFNAMSIZ`).
pub const IFNAMSIZ: usize = 16;

/// `sizeof(struct ifreq)` on a 64-bit kernel: the name and a 24-byte union.
pub const IFREQ: usize = 40;

/// `sizeof(struct sockaddr_un)`: the family and a 108-byte path.
pub const SOCKADDR_UN: usize = 110;

/// The capacity of `sun_path`: a path needs its NUL within it.
pub const SUN_PATH_MAX: usize = 108;

/// The offset of `sun_path` in `struct sockaddr_un`.
pub const SUN_PATH: usize = 2;

// ---- addresses ----------------------------------------------------------------

/// A socket address of any family a scenario names, or the raw bytes of an
/// invalid one (the error rows).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SockAddr {
    V4(SocketAddrV4),
    V6(SocketAddrV6),
    /// AF_UNIX: a filesystem path.
    UnixPath(String),
    /// AF_UNIX: an abstract name (the bytes after the leading NUL).
    UnixAbstract(Vec<u8>),
    /// AF_UNIX with only the family (`addrlen == sizeof(sa_family_t)`): the
    /// address of an unbound socket, and as a `bind` argument autobind.
    UnixUnnamed,
    /// AF_NETLINK: a port id (0 is the kernel) and a multicast group mask.
    Netlink {
        pid: u32,
        groups: u32,
    },
    /// A zeroed address of `family` passed with `len` bytes.
    Raw {
        family: u16,
        len: usize,
    },
}

/// The name of an address family, as recorded.
pub fn family_name(family: i32) -> String {
    match family {
        libc::AF_UNSPEC => "AF_UNSPEC".into(),
        libc::AF_UNIX => "AF_UNIX".into(),
        libc::AF_INET => "AF_INET".into(),
        libc::AF_INET6 => "AF_INET6".into(),
        libc::AF_NETLINK => "AF_NETLINK".into(),
        libc::AF_PACKET => "AF_PACKET".into(),
        other => format!("AF#{other}"),
    }
}

/// An abstract AF_UNIX name the kernel assigned by autobind: exactly five
/// lowercase hex digits (net/unix/af_unix.c `unix_autobind`, `"%05x"`). The
/// names scenarios choose are longer, so they never read as one.
fn autobind_number(name: &[u8]) -> Option<i64> {
    (name.len() == 5
        && name
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b)))
    .then(|| i64::from_str_radix(std::str::from_utf8(name).ok()?, 16).ok())
    .flatten()
}

impl SockAddr {
    /// The address as the kernel reads it: a `sockaddr_storage` and the length
    /// passed with it.
    pub fn encode(&self) -> (libc::sockaddr_storage, u32) {
        // SAFETY: an all-zero sockaddr_storage is a valid value.
        let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let bytes = &mut storage as *mut libc::sockaddr_storage as *mut u8;
        let put = |offset: usize, data: &[u8]| {
            // SAFETY: every caller stays within the 128-byte storage.
            unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), bytes.add(offset), data.len()) }
        };
        let family = |family: i32| (family as u16).to_ne_bytes();
        let len = match self {
            SockAddr::V4(addr) => {
                put(0, &family(libc::AF_INET));
                put(2, &addr.port().to_be_bytes());
                put(4, &addr.ip().octets());
                std::mem::size_of::<libc::sockaddr_in>()
            }
            SockAddr::V6(addr) => {
                put(0, &family(libc::AF_INET6));
                put(2, &addr.port().to_be_bytes());
                put(4, &addr.flowinfo().to_be_bytes());
                put(8, &addr.ip().octets());
                put(24, &addr.scope_id().to_ne_bytes());
                std::mem::size_of::<libc::sockaddr_in6>()
            }
            SockAddr::UnixPath(path) => {
                // Scenarios build paths with `Probe::unix_path`, which requires
                // the fit before anything is issued.
                assert!(path.len() < SUN_PATH_MAX, "an AF_UNIX path fits sun_path");
                put(0, &family(libc::AF_UNIX));
                put(SUN_PATH, path.as_bytes());
                SUN_PATH + path.len() + 1
            }
            SockAddr::UnixAbstract(name) => {
                assert!(name.len() < SUN_PATH_MAX, "an abstract name fits sun_path");
                put(0, &family(libc::AF_UNIX));
                put(SUN_PATH + 1, name);
                SUN_PATH + 1 + name.len()
            }
            SockAddr::UnixUnnamed => {
                put(0, &family(libc::AF_UNIX));
                SUN_PATH
            }
            SockAddr::Netlink { pid, groups } => {
                put(0, &family(libc::AF_NETLINK));
                put(4, &pid.to_ne_bytes());
                put(8, &groups.to_ne_bytes());
                12
            }
            SockAddr::Raw { family: f, len } => {
                assert!(*len <= std::mem::size_of::<libc::sockaddr_storage>());
                if *len >= 2 {
                    put(0, &f.to_ne_bytes());
                }
                *len
            }
        };
        (storage, len as u32)
    }

    /// Decode the first `len` bytes of `storage` (the length the kernel
    /// reported, capped at what the buffer holds).
    pub fn decode(storage: &libc::sockaddr_storage, len: u32) -> SockAddr {
        let len = (len as usize).min(std::mem::size_of::<libc::sockaddr_storage>());
        // SAFETY: the storage is 128 initialized bytes.
        let bytes = unsafe {
            std::slice::from_raw_parts(storage as *const libc::sockaddr_storage as *const u8, len)
        };
        if len < 2 {
            return SockAddr::Raw { family: 0, len };
        }
        let family = u16::from_ne_bytes([bytes[0], bytes[1]]);
        let u16be = |at: usize| u16::from_be_bytes([bytes[at], bytes[at + 1]]);
        let u32ne = |at: usize| u32::from_ne_bytes(bytes[at..at + 4].try_into().unwrap());
        match i32::from(family) {
            libc::AF_INET if len >= 16 => SockAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]),
                u16be(2),
            )),
            libc::AF_INET6 if len >= 28 => {
                let ip: [u8; 16] = bytes[8..24].try_into().unwrap();
                SockAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(ip),
                    u16be(2),
                    u32::from_be_bytes(bytes[4..8].try_into().unwrap()),
                    u32ne(24),
                ))
            }
            libc::AF_UNIX if len == SUN_PATH => SockAddr::UnixUnnamed,
            libc::AF_UNIX if bytes[SUN_PATH] == 0 => {
                SockAddr::UnixAbstract(bytes[SUN_PATH + 1..].to_vec())
            }
            libc::AF_UNIX => {
                let path = &bytes[SUN_PATH..];
                let end = path.iter().position(|b| *b == 0).unwrap_or(path.len());
                SockAddr::UnixPath(String::from_utf8_lossy(&path[..end]).into_owned())
            }
            libc::AF_NETLINK if len >= 12 => SockAddr::Netlink {
                pid: u32ne(4),
                groups: u32ne(8),
            },
            _ => SockAddr::Raw { family, len },
        }
    }

    /// The loopback IPv4 address with `port`.
    pub const fn v4(port: u16) -> SockAddr {
        SockAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
    }

    /// The loopback IPv6 address with `port`.
    pub const fn v6(port: u16) -> SockAddr {
        SockAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, port, 0, 0))
    }

    /// The port of an internet address.
    pub fn port(&self) -> Option<u16> {
        match self {
            SockAddr::V4(addr) => Some(addr.port()),
            SockAddr::V6(addr) => Some(addr.port()),
            _ => None,
        }
    }

    /// The same address with `port` (internet families only).
    pub fn with_port(&self, port: u16) -> SockAddr {
        match self {
            SockAddr::V4(addr) => SockAddr::V4(SocketAddrV4::new(*addr.ip(), port)),
            SockAddr::V6(addr) => SockAddr::V6(SocketAddrV6::new(
                *addr.ip(),
                port,
                addr.flowinfo(),
                addr.scope_id(),
            )),
            other => other.clone(),
        }
    }

    /// Whether this is an AF_UNIX autobind name.
    pub fn autobound(&self) -> bool {
        matches!(self, SockAddr::UnixAbstract(name) if autobind_number(name).is_some())
    }

    /// Record the address under `key` in `args` or `fields`.
    fn record<'a>(&self, builder: EventBuilder<'a>, fields: bool, key: &str) -> EventBuilder<'a> {
        let place = if fields { "fields" } else { "args" };
        let put = |builder: EventBuilder<'a>, name: &str, value: Value| {
            let name = format!("{key}_{name}");
            if fields {
                builder.field(&name, value)
            } else {
                builder.arg(&name, value)
            }
        };
        let relative =
            |builder: EventBuilder<'a>, name: &str, value: i64, namespace: &'static str| {
                let builder = put(builder, name, Value::from(value));
                // 0 is a fixed fact for a port (unbound) and a netlink port
                // id (the kernel), so it stays a value; an autobind name of
                // 00000 is as allocated as any other.
                if value != 0 || namespace == "autobind" {
                    builder.norm(&format!("{place}.{key}_{name}"), Norm::Relative(namespace))
                } else {
                    builder
                }
            };
        match self {
            SockAddr::V4(addr) => {
                let builder = put(builder, "family", "AF_INET".into());
                let builder = put(builder, "ip", addr.ip().to_string().into());
                relative(builder, "port", i64::from(addr.port()), "port")
            }
            SockAddr::V6(addr) => {
                let builder = put(builder, "family", "AF_INET6".into());
                let builder = put(builder, "ip", addr.ip().to_string().into());
                let builder = put(builder, "flowinfo", addr.flowinfo().into());
                let builder = put(builder, "scope_id", addr.scope_id().into());
                relative(builder, "port", i64::from(addr.port()), "port")
            }
            SockAddr::UnixPath(path) => {
                let builder = put(builder, "family", "AF_UNIX".into());
                put(builder, "path", path.clone().into())
            }
            SockAddr::UnixAbstract(name) => {
                let builder = put(builder, "family", "AF_UNIX".into());
                match autobind_number(name) {
                    Some(number) => relative(builder, "autobind", number, "autobind"),
                    None => put(builder, "abstract", printable(name).into()),
                }
            }
            SockAddr::UnixUnnamed => {
                let builder = put(builder, "family", "AF_UNIX".into());
                put(builder, "unnamed", true.into())
            }
            SockAddr::Netlink { pid, groups } => {
                let builder = put(builder, "family", "AF_NETLINK".into());
                let builder = put(builder, "groups", (*groups).into());
                relative(builder, "nl_pid", i64::from(*pid), "nlpid")
            }
            SockAddr::Raw { family, len } => {
                let builder = put(builder, "family", family_name(i32::from(*family)).into());
                put(builder, "raw_len", (*len).into())
            }
        }
    }
}

// ---- messages ------------------------------------------------------------------

/// The ancillary data a `sendmsg` carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Control {
    None,
    /// `SCM_RIGHTS` with these descriptors.
    Rights(Vec<i32>),
    /// `SCM_CREDENTIALS` claiming this pid, uid and gid.
    Creds {
        pid: i32,
        uid: u32,
        gid: u32,
    },
    /// One `SCM_RIGHTS` header whose `cmsg_len` is shorter than a header
    /// (`__scm_send`: `EINVAL`).
    ShortHeader,
    /// Protocol-level messages, each its level, type and data.
    Protocol(Vec<(i32, i32, Vec<u8>)>),
}

/// What a `recvmsg` asks for: the segment sizes, the name buffer's capacity
/// (`None` passes a NULL name) and the control buffer's.
#[derive(Clone, Copy, Debug)]
pub struct RecvSpec<'a> {
    pub segments: &'a [usize],
    pub name: Option<usize>,
    pub control: usize,
    pub flags: i32,
}

impl RecvSpec<'_> {
    /// One segment of `len` bytes, no name, no control.
    pub const fn plain(len: &[usize]) -> RecvSpec<'_> {
        RecvSpec {
            segments: len,
            name: None,
            control: 0,
            flags: 0,
        }
    }
}

/// What a `recvmsg` returned.
#[derive(Clone, Debug, Default)]
pub struct Received {
    pub result: i64,
    /// The bytes each segment received.
    pub segments: Vec<Vec<u8>>,
    pub name: Option<SockAddr>,
    pub namelen: u32,
    pub msg_flags: i32,
    pub controllen: usize,
    /// Descriptors an `SCM_RIGHTS` message installed.
    pub rights: Vec<i32>,
    /// An `SCM_CREDENTIALS` message's pid, uid and gid.
    pub creds: Option<(i32, u32, u32)>,
    /// Every other message: its level, type and data.
    pub protocol: Vec<(i32, i32, Vec<u8>)>,
}

impl Received {
    /// Every segment's bytes, joined.
    pub fn data(&self) -> Vec<u8> {
        self.segments.concat()
    }
}

/// A control message as the record shows it: `level/type:hex bytes`.
fn cmsg_text(level: i32, kind: i32, data: &[u8]) -> String {
    let hex: String = data.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("{level}/{kind}:{hex}")
}

/// The space `CMSG_SPACE(len)` takes.
fn cmsg_space(len: usize) -> usize {
    // SAFETY: pure arithmetic.
    unsafe { libc::CMSG_SPACE(len as u32) as usize }
}

/// Build a control buffer (8-byte aligned) for `control`.
fn control_bytes(control: &Control) -> Vec<u64> {
    let (level_type, payload): ((i32, i32), Vec<u8>) = match control {
        Control::None => return Vec::new(),
        Control::Protocol(messages) => {
            let space: usize = messages
                .iter()
                .map(|(_, _, data)| cmsg_space(data.len()))
                .sum();
            let mut buf = vec![0u64; space.div_ceil(8)];
            let mut at = 0;
            for (level, kind, data) in messages {
                // SAFETY: each message's CMSG_SPACE lies within the buffer, its
                // header at `at` (8-byte aligned) and its data at CMSG_DATA.
                unsafe {
                    let header = (buf.as_mut_ptr() as *mut u8).add(at) as *mut libc::cmsghdr;
                    (*header).cmsg_level = *level;
                    (*header).cmsg_type = *kind;
                    (*header).cmsg_len = libc::CMSG_LEN(data.len() as u32) as _;
                    std::ptr::copy_nonoverlapping(
                        data.as_ptr(),
                        libc::CMSG_DATA(header),
                        data.len(),
                    );
                }
                at += cmsg_space(data.len());
            }
            return buf;
        }
        Control::Rights(fds) => (
            (libc::SOL_SOCKET, libc::SCM_RIGHTS),
            fds.iter().flat_map(|fd| fd.to_ne_bytes()).collect(),
        ),
        Control::Creds { pid, uid, gid } => (
            (libc::SOL_SOCKET, libc::SCM_CREDENTIALS),
            [pid.to_ne_bytes(), uid.to_ne_bytes(), gid.to_ne_bytes()].concat(),
        ),
        Control::ShortHeader => ((libc::SOL_SOCKET, libc::SCM_RIGHTS), vec![0; 4]),
    };
    let space = cmsg_space(payload.len());
    let mut buf = vec![0u64; space.div_ceil(8)];
    let bytes = buf.as_mut_ptr() as *mut u8;
    // SAFETY: the buffer holds CMSG_SPACE(payload) bytes; the header is at
    // its start and the payload at CMSG_DATA.
    unsafe {
        let header = bytes as *mut libc::cmsghdr;
        (*header).cmsg_level = level_type.0;
        (*header).cmsg_type = level_type.1;
        (*header).cmsg_len = if matches!(control, Control::ShortHeader) {
            4
        } else {
            libc::CMSG_LEN(payload.len() as u32) as _
        };
        let data = libc::CMSG_DATA(header);
        std::ptr::copy_nonoverlapping(payload.as_ptr(), data, payload.len());
    }
    buf
}

/// One message of a `sendmmsg`: its bytes and its destination.
#[derive(Clone, Debug)]
pub struct Outgoing<'a> {
    pub data: &'a [u8],
    pub to: Option<SockAddr>,
}

/// One message a `recvmmsg` received: its bytes, `msg_len`, `msg_flags` and
/// source.
#[derive(Clone, Debug)]
pub struct Incoming {
    pub data: Vec<u8>,
    pub len: u32,
    pub flags: i32,
    pub from: Option<SockAddr>,
}

// ---- options ---------------------------------------------------------------------

/// Whether a `getsockopt` value is recorded: `Exact` values are kernel facts;
/// `Hidden` ones (buffer sizes the kernel derives from host sysctls) are
/// left to the scenario's relation checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OptionShown {
    Exact,
    Hidden,
}

// ---- interfaces ------------------------------------------------------------------

/// What an `SIOCGIF*` request answers, decoded from the returned `ifreq`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IfField {
    /// `ifr_ifindex` (`SIOCGIFINDEX`).
    Index,
    /// `ifr_flags` (`SIOCGIFFLAGS`), recorded as given by `mask`.
    Flags(u16),
    /// An IPv4 `ifr_addr` (`SIOCGIFADDR`, `SIOCGIFNETMASK`, `SIOCGIFBRDADDR`).
    Addr,
    /// `ifr_mtu` (`SIOCGIFMTU`): the host's configuration, never recorded.
    Mtu,
    /// `ifr_name` (`SIOCGIFNAME`, which takes `ifr_ifindex`).
    Name,
    /// `ifr_hwaddr` (`SIOCGIFHWADDR`): the hardware type and six bytes.
    HwAddr,
}

/// The decoded answer of an `SIOCGIF*` request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IfAnswer {
    pub index: i32,
    pub flags: u16,
    pub addr: Option<Ipv4Addr>,
    pub mtu: i32,
    pub name: String,
    pub hw_family: u16,
    pub hw_bytes: [u8; 6],
}

/// One netlink message: its type, flags, sequence number, sender port and
/// payload (after the header).
#[derive(Clone, Debug)]
pub struct NlMsg {
    pub kind: u16,
    pub flags: u16,
    pub seq: u32,
    pub pid: u32,
    pub payload: Vec<u8>,
}

/// The attributes (`rtattr`) of a netlink payload past its fixed header of
/// `fixed` bytes, as `(type, data)`.
pub fn attributes(payload: &[u8], fixed: usize) -> Vec<(u16, Vec<u8>)> {
    let mut out = Vec::new();
    let mut at = fixed;
    while at + 4 <= payload.len() {
        let len = usize::from(u16::from_ne_bytes([payload[at], payload[at + 1]]));
        let kind = u16::from_ne_bytes([payload[at + 2], payload[at + 3]]);
        if len < 4 || at + len > payload.len() {
            break;
        }
        out.push((kind, payload[at + 4..at + len].to_vec()));
        at += len.div_ceil(4) * 4;
    }
    out
}

/// An `fd_set` over the descriptors in `fds`.
/// The one value every item of `items` shares, when there are several: a
/// flood of like items (a `vlen` past `UIO_MAXIOV`, `SCM_MAX_FD`
/// descriptors) is recorded once with its count, which pins exactly what
/// the full list would.
fn shared<T: PartialEq>(items: &[T]) -> Option<&T> {
    match items {
        [first, rest @ ..] if !rest.is_empty() && rest.iter().all(|item| item == first) => {
            Some(first)
        }
        _ => None,
    }
}

/// `values` as recorded: the shared value and the count when every value
/// is one (see [`shared`]), the array otherwise.
fn list_or_shared(values: Vec<Value>) -> Value {
    match shared(&values) {
        Some(value) => serde_json::json!({ "each": value, "count": values.len() }),
        None => Value::Array(values),
    }
}

/// The `pollfd` array a poll-shaped call takes for `(fd, events)` pairs.
pub(super) fn pollfd_array(fds: &[(i32, i16)]) -> Vec<libc::pollfd> {
    fds.iter()
        .map(|&(fd, events)| libc::pollfd {
            fd,
            events,
            revents: 0,
        })
        .collect()
}

fn fd_set(fds: &[i32]) -> libc::fd_set {
    // SAFETY: FD_ZERO/FD_SET on a local set; the scenario's descriptors are
    // below FD_SETSIZE.
    unsafe {
        let mut set: libc::fd_set = std::mem::zeroed();
        libc::FD_ZERO(&mut set);
        for fd in fds {
            libc::FD_SET(*fd, &mut set);
        }
        set
    }
}

fn is_set(set: &libc::fd_set, fd: i32) -> bool {
    // SAFETY: a read of a local set.
    unsafe { libc::FD_ISSET(fd, set) }
}

/// The three descriptor sets of a `select`: which descriptors to watch for
/// reading, writing and exceptional conditions.
#[derive(Clone, Copy, Debug, Default)]
pub struct Sets<'a> {
    pub read: &'a [i32],
    pub write: &'a [i32],
    pub except: &'a [i32],
}

/// Which of each set's descriptors a `select` left set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ready {
    pub read: Vec<bool>,
    pub write: Vec<bool>,
    pub except: Vec<bool>,
}

/// One `getaddrinfo(3)` result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddrInfo {
    pub family: i32,
    pub socktype: i32,
    pub protocol: i32,
    pub addrlen: u32,
    pub addr: SockAddr,
    /// Whether `ai_canonname` is set.
    pub canonname: bool,
}

/// The name of a `getaddrinfo` result code (netdb.h).
pub fn eai_name(code: i32) -> String {
    match code {
        0 => "0".into(),
        libc::EAI_BADFLAGS => "EAI_BADFLAGS".into(),
        libc::EAI_NONAME => "EAI_NONAME".into(),
        libc::EAI_AGAIN => "EAI_AGAIN".into(),
        libc::EAI_FAIL => "EAI_FAIL".into(),
        libc::EAI_FAMILY => "EAI_FAMILY".into(),
        libc::EAI_SOCKTYPE => "EAI_SOCKTYPE".into(),
        libc::EAI_SERVICE => "EAI_SERVICE".into(),
        libc::EAI_MEMORY => "EAI_MEMORY".into(),
        libc::EAI_SYSTEM => "EAI_SYSTEM".into(),
        other => format!("EAI#{other}"),
    }
}

impl Probe {
    /// Issue `row` through glibc's `syscall(2)` under the libc vehicle, the
    /// vehicle's own door otherwise: the spelling of a call shape glibc's
    /// wrapper cannot express (a wrong `sigsetsize`, an invalid pointer the
    /// wrapper would read first).
    fn call_unwrapped(&self, row: Syscall, args: Args) -> i64 {
        match self.vehicle {
            Vehicle::Libc => self.call_as(Vehicle::Syscall, row, args),
            other => self.call_as(other, row, args),
        }
    }

    fn call_as(&self, vehicle: Vehicle, row: Syscall, args: Args) -> i64 {
        if self.declared_absent && super::past_virtual_abi(row) {
            return neg(libc::ENOSYS);
        }
        vehicle.call(row, args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_several_like_items_are_recorded_once() {
        assert_eq!(shared(&[7, 7, 7]), Some(&7));
        assert_eq!(shared(&[7, 7, 8]), None);
        assert_eq!(shared(&[7]), None);
        assert_eq!(shared::<i32>(&[]), None);
        assert_eq!(
            list_or_shared(vec![Value::from(0); 3]),
            serde_json::json!({ "each": 0, "count": 3 })
        );
        assert_eq!(
            list_or_shared(vec![Value::from(0), Value::from(1)]),
            serde_json::json!([0, 1])
        );
    }

    fn roundtrip(addr: SockAddr) {
        let (raw, len) = addr.encode();
        assert_eq!(SockAddr::decode(&raw, len), addr, "{addr:?} ({len} bytes)");
    }

    #[test]
    fn every_family_roundtrips() {
        roundtrip(SockAddr::v4(8080));
        roundtrip(SockAddr::V6(SocketAddrV6::new(
            Ipv6Addr::LOCALHOST,
            443,
            7,
            2,
        )));
        roundtrip(SockAddr::UnixPath("/tmp/run/stream.sock".into()));
        roundtrip(SockAddr::UnixAbstract(
            b"patina-conformance:/tmp/x".to_vec(),
        ));
        roundtrip(SockAddr::UnixUnnamed);
        roundtrip(SockAddr::Netlink { pid: 42, groups: 1 });
    }

    #[test]
    fn lengths_are_the_kernel_shapes() {
        assert_eq!(SockAddr::v4(1).encode().1, 16);
        assert_eq!(SockAddr::v6(1).encode().1, 28);
        assert_eq!(SockAddr::UnixPath("/a".into()).encode().1, 2 + 2 + 1);
        assert_eq!(SockAddr::UnixAbstract(b"ab".to_vec()).encode().1, 2 + 1 + 2);
        assert_eq!(SockAddr::UnixUnnamed.encode().1, 2);
        assert_eq!(SockAddr::Netlink { pid: 0, groups: 0 }.encode().1, 12);
    }

    #[test]
    fn only_five_hex_digits_read_as_an_autobind_name() {
        assert!(SockAddr::UnixAbstract(b"0a1f3".to_vec()).autobound());
        assert!(!SockAddr::UnixAbstract(b"0a1f".to_vec()).autobound());
        assert!(!SockAddr::UnixAbstract(b"0A1F3".to_vec()).autobound());
        assert!(!SockAddr::UnixAbstract(b"patina-conformance:/x".to_vec()).autobound());
    }

    #[test]
    fn attributes_walk_aligned_rtattrs() {
        // Two attributes after a 4-byte fixed header: a 5-byte name padded
        // to 8, then a 4-byte value.
        let mut payload = vec![0u8; 4];
        payload.extend_from_slice(&5u16.to_ne_bytes());
        payload.extend_from_slice(&3u16.to_ne_bytes());
        payload.extend_from_slice(b"l\0\0\0");
        payload.extend_from_slice(&8u16.to_ne_bytes());
        payload.extend_from_slice(&4u16.to_ne_bytes());
        payload.extend_from_slice(&65536u32.to_ne_bytes());
        assert_eq!(
            attributes(&payload, 4),
            vec![(3, b"l".to_vec()), (4, 65536u32.to_ne_bytes().to_vec())]
        );
    }
}
