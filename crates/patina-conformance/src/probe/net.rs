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

// ---- kernel ABI constants the libc crate spells per target or not at all ----

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

    // ---- sockets -----------------------------------------------------------

    pub fn socket(&self, domain: i32, kind: i32, protocol: i32) -> i32 {
        let result = self.call(
            Syscall::N_socket,
            [domain as i64, kind as i64, protocol as i64, 0, 0, 0],
        );
        self.event(Syscall::N_socket, result)
            .arg("domain", domain)
            .arg("type", kind)
            .arg("protocol", protocol)
            .norm("ret", Norm::Relative("fd"))
            .emit();
        result as i32
    }

    pub fn listen(&self, fd: i32, backlog: i32) -> i64 {
        let result = self.call(Syscall::N_listen, [fd as i64, backlog as i64, 0, 0, 0, 0]);
        let builder = self.event(Syscall::N_listen, result);
        self.fd_arg(builder, "fd", fd)
            .arg("backlog", backlog)
            .emit();
        result
    }

    pub fn shutdown(&self, fd: i32, how: i32) -> i64 {
        let result = self.call(Syscall::N_shutdown, [fd as i64, how as i64, 0, 0, 0, 0]);
        let builder = self.event(Syscall::N_shutdown, result);
        self.fd_arg(builder, "fd", fd).arg("how", how).emit();
        result
    }

    // ---- addresses ---------------------------------------------------------
    /// An AF_UNIX path under the run directory, required to fit `sun_path`
    /// (a deep `TMPDIR` leaves no room: the scenario cannot run there).
    pub fn unix_path(&self, name: &str) -> String {
        let path = format!("{}/{name}", self.dir());
        self.require(
            &format!("the AF_UNIX path {path:?} fits sun_path ({SUN_PATH_MAX} bytes with its NUL)"),
            path.len() < SUN_PATH_MAX,
        );
        path
    }

    /// `bind` to any address.
    pub fn bind_to(&self, fd: i32, addr: &SockAddr) -> i64 {
        let (raw, len) = addr.encode();
        let result = self.call(
            Syscall::N_bind,
            [fd as i64, &raw as *const _ as i64, len as i64, 0, 0, 0],
        );
        let builder = self.fd_arg(self.event(Syscall::N_bind, result), "fd", fd);
        addr.record(builder, false, "addr")
            .arg("addrlen", len)
            .emit();
        result
    }

    /// `connect` to any address.
    pub fn connect_to(&self, fd: i32, addr: &SockAddr) -> i64 {
        let (raw, len) = addr.encode();
        let result = self.call(
            Syscall::N_connect,
            [fd as i64, &raw as *const _ as i64, len as i64, 0, 0, 0],
        );
        let builder = self.fd_arg(self.event(Syscall::N_connect, result), "fd", fd);
        addr.record(builder, false, "addr")
            .arg("addrlen", len)
            .emit();
        result
    }

    /// `getsockname` (or `getpeername`) of any family with a name buffer of
    /// `cap` bytes; the reported length is recorded (it exceeds `cap` when
    /// the name was truncated).
    pub fn name_of(&self, fd: i32, peer: bool, cap: u32) -> (i64, Option<SockAddr>, u32) {
        let row = if peer {
            Syscall::N_getpeername
        } else {
            Syscall::N_getsockname
        };
        // SAFETY: an all-zero sockaddr_storage is a valid value.
        let mut raw: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut len = cap;
        let result = self.call(
            row,
            [
                fd as i64,
                &mut raw as *mut _ as i64,
                &mut len as *mut u32 as i64,
                0,
                0,
                0,
            ],
        );
        let addr = (result >= 0).then(|| SockAddr::decode(&raw, len.min(cap)));
        let builder = self
            .fd_arg(self.event(row, result), "fd", fd)
            .arg("cap", cap);
        let builder = match &addr {
            Some(addr) => addr.record(builder, true, "addr").field("addrlen", len),
            None => builder,
        };
        builder.emit();
        (result, addr, len)
    }

    /// `accept` (`legacy`: the `accept` row and symbol) or `accept4`, with a
    /// peer-name buffer when `want_addr`.
    pub fn accept_from(
        &self,
        fd: i32,
        flags: i32,
        legacy: bool,
        want_addr: bool,
    ) -> (i32, Option<SockAddr>) {
        // SAFETY: an all-zero sockaddr_storage is a valid value.
        let mut raw: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::sockaddr_storage>() as u32;
        let (addr_ptr, len_ptr) = if want_addr {
            (&mut raw as *mut _ as i64, &mut len as *mut u32 as i64)
        } else {
            (0, 0)
        };
        let row = if legacy {
            Syscall::N_accept
        } else {
            Syscall::N_accept4
        };
        let result = self.call(row, [fd as i64, addr_ptr, len_ptr, flags as i64, 0, 0]);
        let peer = (result >= 0 && want_addr).then(|| SockAddr::decode(&raw, len));
        let builder = self.fd_arg(self.event(row, result), "fd", fd);
        let builder = if legacy {
            builder
        } else {
            builder.arg("flags", flags)
        };
        let builder = builder
            .arg("want_addr", want_addr)
            .norm("ret", Norm::Relative("fd"));
        let builder = match &peer {
            Some(peer) => peer.record(builder, true, "peer").field("addrlen", len),
            None => builder,
        };
        builder.emit();
        (result as i32, peer)
    }

    /// `sendto` with any destination (`None` passes NULL).
    pub fn send_to(&self, fd: i32, data: &[u8], flags: i32, to: Option<&SockAddr>) -> i64 {
        let encoded = to.map(SockAddr::encode);
        let (ptr, len) = encoded.as_ref().map_or((0, 0), |(raw, len)| {
            (raw as *const _ as i64, i64::from(*len))
        });
        let result = self.call(
            Syscall::N_sendto,
            [
                fd as i64,
                data.as_ptr() as i64,
                data.len() as i64,
                flags as i64,
                ptr,
                len,
            ],
        );
        let builder = self
            .fd_arg(self.event(Syscall::N_sendto, result), "fd", fd)
            .arg("len", data.len())
            .arg("flags", flags);
        match to {
            Some(to) => to.record(builder, false, "addr").emit(),
            None => builder.arg("addr", Value::Null).emit(),
        }
        result
    }

    /// `recvfrom` of any family, with a source-name buffer when `want_addr`.
    pub fn recv_from(
        &self,
        fd: i32,
        len: usize,
        flags: i32,
        want_addr: bool,
    ) -> (i64, Vec<u8>, Option<SockAddr>) {
        let mut buf = vec![0u8; len];
        // SAFETY: an all-zero sockaddr_storage is a valid value.
        let mut raw: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut alen = std::mem::size_of::<libc::sockaddr_storage>() as u32;
        let (aptr, lptr) = if want_addr {
            (&mut raw as *mut _ as i64, &mut alen as *mut u32 as i64)
        } else {
            (0, 0)
        };
        let result = self.call(
            Syscall::N_recvfrom,
            [
                fd as i64,
                buf.as_mut_ptr() as i64,
                len as i64,
                flags as i64,
                aptr,
                lptr,
            ],
        );
        // MSG_TRUNC on a datagram answers the full length, past the buffer.
        buf.truncate(if result >= 0 {
            (result as usize).min(len)
        } else {
            0
        });
        let from = (result >= 0 && want_addr).then(|| SockAddr::decode(&raw, alen));
        let builder = self
            .fd_arg(self.event(Syscall::N_recvfrom, result), "fd", fd)
            .arg("len", len)
            .arg("flags", flags)
            .arg("want_addr", want_addr);
        let builder = if result >= 0 {
            builder.field("data", printable(&buf))
        } else {
            builder
        };
        let builder = match &from {
            Some(from) => from.record(builder, true, "src").field("addrlen", alen),
            None => builder,
        };
        builder.emit();
        (result, buf, from)
    }

    /// `send(3)`: glibc's `send` under the libc vehicle, the `sendto` row
    /// with no address (glibc's own spelling) otherwise.
    pub fn send(&self, fd: i32, data: &[u8], flags: i32) -> i64 {
        let args = [
            fd as i64,
            data.as_ptr() as i64,
            data.len() as i64,
            flags as i64,
            0,
            0,
        ];
        let result = match self.vehicle {
            // SAFETY: the buffer holds `data.len()` bytes.
            Vehicle::Libc => {
                fold_errno(
                    unsafe { libc::send(fd, data.as_ptr().cast(), data.len(), flags) } as i64,
                )
            }
            _ => self.call(Syscall::N_sendto, args),
        };
        self.fd_arg(self.rec.event("send", result), "fd", fd)
            .arg("len", data.len())
            .arg("flags", flags)
            .emit();
        result
    }

    /// `recv(3)`: glibc's `recv` under the libc vehicle, the `recvfrom` row
    /// with no address otherwise.
    pub fn recv(&self, fd: i32, len: usize, flags: i32) -> (i64, Vec<u8>) {
        let mut buf = vec![0u8; len];
        let args = [
            fd as i64,
            buf.as_mut_ptr() as i64,
            len as i64,
            flags as i64,
            0,
            0,
        ];
        let result = match self.vehicle {
            // SAFETY: the buffer holds `len` bytes.
            Vehicle::Libc => {
                fold_errno(unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), len, flags) } as i64)
            }
            _ => self.call(Syscall::N_recvfrom, args),
        };
        buf.truncate(if result >= 0 {
            (result as usize).min(len)
        } else {
            0
        });
        let builder = self
            .fd_arg(self.rec.event("recv", result), "fd", fd)
            .arg("len", len)
            .arg("flags", flags);
        let builder = if result >= 0 {
            builder.field("data", printable(&buf))
        } else {
            builder
        };
        builder.emit();
        (result, buf)
    }

    // ---- messages ----------------------------------------------------------

    /// `sendmsg` of `segments` (one iovec each) to `to`, with `control`.
    pub fn sendmsg(
        &self,
        fd: i32,
        segments: &[&[u8]],
        to: Option<&SockAddr>,
        control: &Control,
        flags: i32,
    ) -> i64 {
        let mut iov = write_vector(segments);
        let encoded = to.map(SockAddr::encode);
        let mut cbuf = control_bytes(control);
        // SAFETY: an all-zero msghdr is a valid value.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        if let Some((raw, len)) = &encoded {
            msg.msg_name = raw as *const _ as *mut libc::c_void;
            msg.msg_namelen = *len;
        }
        msg.msg_iov = iov.as_mut_ptr();
        msg.msg_iovlen = iov.len() as _;
        if !cbuf.is_empty() {
            msg.msg_control = cbuf.as_mut_ptr().cast();
            msg.msg_controllen = match control {
                Control::ShortHeader => cmsg_space(4),
                Control::Rights(fds) => cmsg_space(fds.len() * 4),
                Control::Creds { .. } => cmsg_space(12),
                Control::Protocol(messages) => messages
                    .iter()
                    .map(|(_, _, data)| cmsg_space(data.len()))
                    .sum(),
                Control::None => 0,
            } as _;
        }
        let result = self.call(
            Syscall::N_sendmsg,
            [fd as i64, &msg as *const _ as i64, flags as i64, 0, 0, 0],
        );
        let lens: Vec<Value> = segments.iter().map(|s| Value::from(s.len())).collect();
        let builder = self
            .fd_arg(self.event(Syscall::N_sendmsg, result), "fd", fd)
            .arg("iov", Value::Array(lens))
            .arg("flags", flags);
        let builder = match to {
            Some(to) => to.record(builder, false, "name"),
            None => builder.arg("name", Value::Null),
        };
        let builder = match control {
            Control::None => builder.arg("control", "none"),
            Control::ShortHeader => builder.arg("control", "short-header"),
            Control::Rights(fds) => {
                let mut builder = builder.arg("control", format!("rights x{}", fds.len()));
                for (index, fd) in fds.iter().enumerate() {
                    builder = self.fd_arg(builder, &format!("right{index}"), *fd);
                }
                builder
            }
            Control::Protocol(messages) => {
                let described: Vec<Value> = messages
                    .iter()
                    .map(|(level, kind, data)| Value::from(cmsg_text(*level, *kind, data)))
                    .collect();
                builder.arg("control", Value::Array(described))
            }
            Control::Creds { pid, uid, gid } => builder
                .arg("control", "credentials")
                .arg("cred_pid", *pid)
                .norm("args.cred_pid", Norm::Identity(Id::Process))
                .arg("cred_uid", *uid)
                .norm("args.cred_uid", Norm::Identity(Id::User))
                .arg("cred_gid", *gid)
                .norm("args.cred_gid", Norm::Identity(Id::Group)),
        };
        builder.emit();
        result
    }

    /// `sendmsg` with a message header the kernel cannot read (`msg` is the
    /// address 1): `EFAULT` before anything else. glibc's wrapper passes the
    /// pointer straight through, so every vehicle issues the same call.
    pub fn sendmsg_bad_header(&self, fd: i32) -> i64 {
        let result = self.call(Syscall::N_sendmsg, [fd as i64, 1, 0, 0, 0, 0]);
        self.fd_arg(self.event(Syscall::N_sendmsg, result), "fd", fd)
            .arg("msg", "bad pointer")
            .emit();
        result
    }

    /// `sendmsg` with `iovlen` zero-length segments (the count alone is
    /// judged: `UIO_MAXIOV` bounds it).
    pub fn sendmsg_iovlen(&self, fd: i32, iovlen: usize) -> i64 {
        let mut iov = vec![
            libc::iovec {
                iov_base: std::ptr::null_mut(),
                iov_len: 0,
            };
            iovlen.max(1)
        ];
        // SAFETY: an all-zero msghdr is a valid value.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = iov.as_mut_ptr();
        msg.msg_iovlen = iovlen as _;
        let result = self.call(
            Syscall::N_sendmsg,
            [fd as i64, &msg as *const _ as i64, 0, 0, 0, 0],
        );
        self.fd_arg(self.event(Syscall::N_sendmsg, result), "fd", fd)
            .arg("iovlen", iovlen)
            .emit();
        result
    }

    /// `recvmsg` into `spec`'s segments, name and control buffers. Received
    /// descriptors are recorded as `fd` labels, credentials as identities.
    pub fn recvmsg(&self, fd: i32, spec: RecvSpec<'_>) -> Received {
        let (buffers, mut iov) = read_vector(spec.segments);
        // SAFETY: an all-zero sockaddr_storage / msghdr is a valid value.
        let mut raw: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut cbuf = vec![0u64; spec.control.div_ceil(8)];
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        if let Some(cap) = spec.name {
            msg.msg_name = &mut raw as *mut _ as *mut libc::c_void;
            msg.msg_namelen = cap as u32;
        }
        msg.msg_iov = iov.as_mut_ptr();
        msg.msg_iovlen = iov.len() as _;
        if spec.control > 0 {
            msg.msg_control = cbuf.as_mut_ptr().cast();
            msg.msg_controllen = spec.control as _;
        }
        let result = self.call(
            Syscall::N_recvmsg,
            [
                fd as i64,
                &mut msg as *mut _ as i64,
                spec.flags as i64,
                0,
                0,
                0,
            ],
        );
        let mut received = Received {
            result,
            ..Received::default()
        };
        if result >= 0 {
            let mut left = result as usize;
            for buf in &buffers {
                let take = left.min(buf.len());
                received.segments.push(buf[..take].to_vec());
                left -= take;
            }
            received.msg_flags = msg.msg_flags;
            received.namelen = msg.msg_namelen;
            if spec.name.is_some() {
                received.name = Some(SockAddr::decode(
                    &raw,
                    msg.msg_namelen.min(spec.name.unwrap_or(0) as u32),
                ));
            }
            received.controllen = msg.msg_controllen as usize;
            // SAFETY: the kernel filled `msg_controllen` bytes of cmsgs.
            unsafe {
                let mut header = libc::CMSG_FIRSTHDR(&msg);
                while !header.is_null() {
                    let data = libc::CMSG_DATA(header);
                    let len = (*header).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                    match ((*header).cmsg_level, (*header).cmsg_type) {
                        (libc::SOL_SOCKET, libc::SCM_RIGHTS) => {
                            for index in 0..len / 4 {
                                let mut fd = [0u8; 4];
                                std::ptr::copy_nonoverlapping(
                                    data.add(index * 4),
                                    fd.as_mut_ptr(),
                                    4,
                                );
                                received.rights.push(i32::from_ne_bytes(fd));
                            }
                        }
                        (libc::SOL_SOCKET, libc::SCM_CREDENTIALS) if len >= 12 => {
                            let mut creds = [0u8; 12];
                            std::ptr::copy_nonoverlapping(data, creds.as_mut_ptr(), 12);
                            received.creds = Some((
                                i32::from_ne_bytes(creds[0..4].try_into().unwrap()),
                                u32::from_ne_bytes(creds[4..8].try_into().unwrap()),
                                u32::from_ne_bytes(creds[8..12].try_into().unwrap()),
                            ));
                        }
                        (level, kind) => {
                            let mut bytes = vec![0u8; len];
                            std::ptr::copy_nonoverlapping(data, bytes.as_mut_ptr(), len);
                            received.protocol.push((level, kind, bytes));
                        }
                    }
                    header = libc::CMSG_NXTHDR(&msg, header);
                }
            }
        }
        let lens: Vec<Value> = spec.segments.iter().map(|len| Value::from(*len)).collect();
        let builder = self
            .fd_arg(self.event(Syscall::N_recvmsg, result), "fd", fd)
            .arg("iov", Value::Array(lens))
            .arg("name_cap", spec.name.map_or(Value::Null, Value::from))
            .arg("control_cap", spec.control)
            .arg("flags", spec.flags);
        let mut builder = if result >= 0 {
            let data: Vec<Value> = received
                .segments
                .iter()
                .map(|segment| Value::from(printable(segment)))
                .collect();
            builder
                .field("segments", Value::Array(data))
                .field("msg_flags", received.msg_flags)
                .field("controllen", received.controllen)
        } else {
            builder
        };
        if let Some(name) = &received.name {
            builder = name
                .record(builder, true, "name")
                .field("namelen", received.namelen);
        }
        if result >= 0 && spec.control > 0 {
            builder = builder.field("rights", received.rights.len());
            for (index, right) in received.rights.iter().enumerate() {
                builder = builder
                    .field(&format!("right{index}"), *right)
                    .norm(&format!("fields.right{index}"), Norm::Relative("fd"));
            }
        }
        if !received.protocol.is_empty() {
            let described: Vec<Value> = received
                .protocol
                .iter()
                .map(|(level, kind, data)| Value::from(cmsg_text(*level, *kind, data)))
                .collect();
            builder = builder.field("cmsgs", Value::Array(described));
        }
        if let Some((pid, uid, gid)) = received.creds {
            builder = builder
                .field("cred_pid", pid)
                .norm("fields.cred_pid", Norm::Identity(Id::Process))
                .field("cred_uid", uid)
                .norm("fields.cred_uid", Norm::Identity(Id::User))
                .field("cred_gid", gid)
                .norm("fields.cred_gid", Norm::Identity(Id::Group));
        }
        builder.emit();
        received
    }

    /// `sendmmsg` of `messages` (one iovec each). The recorded `sent` array is
    /// every message's `msg_len` the kernel filled (sent messages only).
    pub fn sendmmsg(&self, fd: i32, messages: &[Outgoing<'_>], flags: i32) -> (i64, Vec<u32>) {
        let names: Vec<Option<(libc::sockaddr_storage, u32)>> = messages
            .iter()
            .map(|message| message.to.as_ref().map(SockAddr::encode))
            .collect();
        let data: Vec<&[u8]> = messages.iter().map(|message| message.data).collect();
        let mut iov = write_vector(&data);
        let mut headers: Vec<libc::mmsghdr> = (0..messages.len())
            .map(|index| {
                // SAFETY: an all-zero mmsghdr is a valid value.
                let mut header: libc::mmsghdr = unsafe { std::mem::zeroed() };
                header.msg_hdr.msg_iov = &mut iov[index];
                header.msg_hdr.msg_iovlen = 1;
                if let Some((raw, len)) = &names[index] {
                    header.msg_hdr.msg_name = raw as *const _ as *mut libc::c_void;
                    header.msg_hdr.msg_namelen = *len;
                }
                header
            })
            .collect();
        let pointer = if headers.is_empty() {
            0
        } else {
            headers.as_mut_ptr() as i64
        };
        let result = self.call(
            Syscall::N_sendmmsg,
            [
                fd as i64,
                pointer,
                messages.len() as i64,
                flags as i64,
                0,
                0,
            ],
        );
        let sent: Vec<u32> = headers
            .iter()
            .take(result.max(0) as usize)
            .map(|header| header.msg_len)
            .collect();
        let lens: Vec<Value> = messages.iter().map(|m| Value::from(m.data.len())).collect();
        let mut builder = self
            .fd_arg(self.event(Syscall::N_sendmmsg, result), "fd", fd)
            .arg("vlen", messages.len())
            .arg("lens", Value::Array(lens))
            .arg("flags", flags);
        for (index, message) in messages.iter().enumerate() {
            if let Some(to) = &message.to {
                builder = to.record(builder, false, &format!("to{index}"));
            }
        }
        let builder = if result >= 0 {
            builder.field(
                "sent",
                Value::Array(sent.iter().map(|len| Value::from(*len)).collect()),
            )
        } else {
            builder
        };
        builder.emit();
        (result, sent)
    }

    /// `recvmmsg` into one buffer of each capacity in `caps`, with source
    /// names; `timeout` is `(sec, nsec)` (`None` passes NULL).
    pub fn recvmmsg(
        &self,
        fd: i32,
        caps: &[usize],
        flags: i32,
        timeout: Option<(i64, i64)>,
    ) -> (i64, Vec<Incoming>) {
        let (buffers, mut iov) = read_vector(caps);
        // SAFETY: all-zero sockaddr_storage values are valid.
        let mut names: Vec<libc::sockaddr_storage> = (0..caps.len())
            .map(|_| unsafe { std::mem::zeroed() })
            .collect();
        let mut headers: Vec<libc::mmsghdr> = (0..caps.len())
            .map(|index| {
                // SAFETY: an all-zero mmsghdr is a valid value.
                let mut header: libc::mmsghdr = unsafe { std::mem::zeroed() };
                header.msg_hdr.msg_iov = &mut iov[index];
                header.msg_hdr.msg_iovlen = 1;
                header.msg_hdr.msg_name = &mut names[index] as *mut _ as *mut libc::c_void;
                header.msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as u32;
                header
            })
            .collect();
        let mut ts = timeout.map(|(tv_sec, tv_nsec)| libc::timespec { tv_sec, tv_nsec });
        let result = self.call(
            Syscall::N_recvmmsg,
            [
                fd as i64,
                headers.as_mut_ptr() as i64,
                caps.len() as i64,
                flags as i64,
                ts.as_mut().map_or(0, |ts| ts as *mut libc::timespec as i64),
                0,
            ],
        );
        let incoming: Vec<Incoming> = headers
            .iter()
            .enumerate()
            .take(result.max(0) as usize)
            .map(|(index, header)| Incoming {
                data: buffers[index][..(header.msg_len as usize).min(caps[index])].to_vec(),
                len: header.msg_len,
                flags: header.msg_hdr.msg_flags,
                from: Some(SockAddr::decode(&names[index], header.msg_hdr.msg_namelen)),
            })
            .collect();
        let caps_value: Vec<Value> = caps.iter().map(|cap| Value::from(*cap)).collect();
        let mut builder = self
            .fd_arg(self.event(Syscall::N_recvmmsg, result), "fd", fd)
            .arg("vlen", caps.len())
            .arg("caps", Value::Array(caps_value))
            .arg("flags", flags)
            .arg(
                "timeout",
                timeout.map_or(Value::Null, |(s, ns)| Value::from(format!("{s}s{ns}ns"))),
            );
        for (index, message) in incoming.iter().enumerate() {
            builder = builder
                .field(&format!("data{index}"), printable(&message.data))
                .field(&format!("len{index}"), message.len)
                .field(&format!("flags{index}"), message.flags);
            if let Some(from) = &message.from {
                builder = from.record(builder, true, &format!("src{index}"));
            }
        }
        builder.emit();
        (result, incoming)
    }

    // ---- options -----------------------------------------------------------

    /// `setsockopt` with `value`'s bytes and `optlen` (normally its length;
    /// a shorter one is an error row). `label` names the value as recorded.
    pub fn setsockopt_bytes(
        &self,
        fd: i32,
        level: i32,
        name: i32,
        value: &[u8],
        optlen: usize,
        label: &str,
    ) -> i64 {
        let result = self.call(
            Syscall::N_setsockopt,
            [
                fd as i64,
                level as i64,
                name as i64,
                value.as_ptr() as i64,
                optlen as i64,
                0,
            ],
        );
        self.fd_arg(self.event(Syscall::N_setsockopt, result), "fd", fd)
            .arg("level", level)
            .arg("name", name)
            .arg("value", label)
            .arg("optlen", optlen)
            .emit();
        result
    }

    /// `getsockopt` into a buffer of `cap` bytes (`optlen` in); answers the
    /// bytes the kernel reported and the `optlen` out. `Exact` records the
    /// bytes, `Hidden` only the length.
    pub fn getsockopt_bytes(
        &self,
        fd: i32,
        level: i32,
        name: i32,
        cap: usize,
        shown: OptionShown,
    ) -> (i64, Vec<u8>) {
        let mut buf = vec![0u8; cap.max(1)];
        let mut len = cap as u32;
        let result = self.call(
            Syscall::N_getsockopt,
            [
                fd as i64,
                level as i64,
                name as i64,
                buf.as_mut_ptr() as i64,
                &mut len as *mut u32 as i64,
                0,
            ],
        );
        buf.truncate(if result >= 0 {
            (len as usize).min(cap)
        } else {
            0
        });
        let builder = self
            .fd_arg(self.event(Syscall::N_getsockopt, result), "fd", fd)
            .arg("level", level)
            .arg("name", name)
            .arg("cap", cap);
        let builder = if result >= 0 {
            let builder = builder.field("optlen", len);
            match shown {
                OptionShown::Exact => builder.field(
                    "value",
                    buf.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                ),
                OptionShown::Hidden => builder,
            }
        } else {
            builder
        };
        builder.emit();
        (result, buf)
    }

    /// `getsockopt` of an int option whose value is the host's business (a
    /// buffer size the kernel derives from sysctls): the length is recorded,
    /// the value only returned for the scenario's relation checks.
    pub fn getsockopt_hidden(&self, fd: i32, level: i32, name: i32) -> (i64, i32) {
        let (result, bytes) = self.getsockopt_bytes(fd, level, name, 4, OptionShown::Hidden);
        let value = if bytes.len() == 4 {
            i32::from_ne_bytes(bytes[..4].try_into().unwrap())
        } else {
            0
        };
        (result, value)
    }

    /// `SO_PEERCRED`: the peer's pid, uid and gid when the connection was
    /// made, recorded as identities (the host's ids are its business; their
    /// relation to `getpid`/`getuid`/`getgid` is the scenario's check).
    pub fn peercred(&self, fd: i32) -> (i64, Option<(i32, u32, u32)>) {
        let mut creds = [0u8; 12];
        let mut len = creds.len() as u32;
        let result = self.call(
            Syscall::N_getsockopt,
            [
                fd as i64,
                libc::SOL_SOCKET as i64,
                libc::SO_PEERCRED as i64,
                creds.as_mut_ptr() as i64,
                &mut len as *mut u32 as i64,
                0,
            ],
        );
        let value = (result >= 0).then(|| {
            (
                i32::from_ne_bytes(creds[0..4].try_into().unwrap()),
                u32::from_ne_bytes(creds[4..8].try_into().unwrap()),
                u32::from_ne_bytes(creds[8..12].try_into().unwrap()),
            )
        });
        let builder = self
            .fd_arg(self.event(Syscall::N_getsockopt, result), "fd", fd)
            .arg("level", libc::SOL_SOCKET)
            .arg("name", libc::SO_PEERCRED);
        let builder = match value {
            Some((pid, uid, gid)) => builder
                .field("optlen", len)
                .field("pid", pid)
                .norm("fields.pid", Norm::Identity(Id::Process))
                .field("uid", uid)
                .norm("fields.uid", Norm::Identity(Id::User))
                .field("gid", gid)
                .norm("fields.gid", Norm::Identity(Id::Group)),
            None => builder,
        };
        builder.emit();
        (result, value)
    }

    /// `getsockopt` with the length word itself set to `optlen` (a negative
    /// length is an error row), a 16-byte buffer behind it.
    pub fn getsockopt_optlen(&self, fd: i32, level: i32, name: i32, optlen: i32) -> i64 {
        let mut buf = [0u8; 16];
        let mut len = optlen;
        let result = self.call(
            Syscall::N_getsockopt,
            [
                fd as i64,
                level as i64,
                name as i64,
                buf.as_mut_ptr() as i64,
                &mut len as *mut i32 as i64,
                0,
            ],
        );
        self.fd_arg(self.event(Syscall::N_getsockopt, result), "fd", fd)
            .arg("level", level)
            .arg("name", name)
            .arg("optlen", optlen)
            .emit();
        result
    }

    /// `setsockopt` of `optlen` bytes from a NULL `optval`.
    pub fn setsockopt_null(&self, fd: i32, level: i32, name: i32, optlen: usize) -> i64 {
        let result = self.call(
            Syscall::N_setsockopt,
            [fd as i64, level as i64, name as i64, 0, optlen as i64, 0],
        );
        self.fd_arg(self.event(Syscall::N_setsockopt, result), "fd", fd)
            .arg("level", level)
            .arg("name", name)
            .arg("value", "NULL")
            .arg("optlen", optlen)
            .emit();
        result
    }

    /// `getsockopt` into a 16-byte buffer with a NULL `optlen` pointer.
    pub fn getsockopt_null_len(&self, fd: i32, level: i32, name: i32) -> i64 {
        let mut buf = [0u8; 16];
        let result = self.call(
            Syscall::N_getsockopt,
            [
                fd as i64,
                level as i64,
                name as i64,
                buf.as_mut_ptr() as i64,
                0,
                0,
            ],
        );
        self.fd_arg(self.event(Syscall::N_getsockopt, result), "fd", fd)
            .arg("level", level)
            .arg("name", name)
            .arg("optlen", "NULL")
            .emit();
        result
    }

    // ---- interfaces --------------------------------------------------------

    /// An `SIOCGIF*` request on `fd` naming interface `name` (or, for
    /// `SIOCGIFNAME`, index `index`), decoded as `field`.
    pub fn ifreq(
        &self,
        fd: i32,
        request: u64,
        request_name: &str,
        name: &str,
        index: i32,
        field: IfField,
    ) -> (i64, IfAnswer) {
        let mut ifr = [0u8; IFREQ];
        let bytes = name.as_bytes();
        ifr[..bytes.len().min(IFNAMSIZ)].copy_from_slice(&bytes[..bytes.len().min(IFNAMSIZ)]);
        if field == IfField::Name {
            ifr[IFNAMSIZ..IFNAMSIZ + 4].copy_from_slice(&index.to_ne_bytes());
        }
        let result = self.call(
            Syscall::N_ioctl,
            [fd as i64, request as i64, ifr.as_mut_ptr() as i64, 0, 0, 0],
        );
        let union = &ifr[IFNAMSIZ..];
        let int = i32::from_ne_bytes(union[..4].try_into().unwrap());
        let mut answer = IfAnswer::default();
        let builder = self
            .fd_arg(self.event(Syscall::N_ioctl, result), "fd", fd)
            .arg("request", request_name)
            .arg("number", request);
        let builder = if field == IfField::Name {
            builder.arg("ifindex", index)
        } else {
            builder.arg("ifname", name)
        };
        let builder = if result < 0 {
            builder
        } else {
            match field {
                IfField::Index => {
                    answer.index = int;
                    builder.field("ifindex", int)
                }
                IfField::Flags(mask) => {
                    answer.flags = u16::from_ne_bytes([union[0], union[1]]);
                    builder.field("flags", answer.flags & mask)
                }
                IfField::Addr => {
                    let family = u16::from_ne_bytes([union[0], union[1]]);
                    let ip = Ipv4Addr::new(union[4], union[5], union[6], union[7]);
                    answer.addr = Some(ip);
                    builder
                        .field("family", family_name(i32::from(family)))
                        .field("addr", ip.to_string())
                }
                IfField::Mtu => {
                    answer.mtu = int;
                    builder
                }
                IfField::Name => {
                    let end = ifr[..IFNAMSIZ]
                        .iter()
                        .position(|b| *b == 0)
                        .unwrap_or(IFNAMSIZ);
                    answer.name = String::from_utf8_lossy(&ifr[..end]).into_owned();
                    builder.field("ifname", answer.name.clone())
                }
                IfField::HwAddr => {
                    answer.hw_family = u16::from_ne_bytes([union[0], union[1]]);
                    answer.hw_bytes.copy_from_slice(&union[2..8]);
                    builder.field("hw_family", answer.hw_family).field(
                        "hw_addr",
                        answer
                            .hw_bytes
                            .iter()
                            .map(|b| format!("{b:02x}"))
                            .collect::<Vec<_>>()
                            .join(":"),
                    )
                }
            }
        };
        builder.emit();
        (result, answer)
    }

    /// `SIOCGIFCONF` into room for `slots` entries: the interfaces with an
    /// IPv4 address, `(name, address)`. Only the entry the scenario asks
    /// about is recorded (`lo`); how many others the host has is its own
    /// business.
    pub fn ifconf(&self, fd: i32, slots: usize, find: &str) -> (i64, Vec<(String, Ipv4Addr)>) {
        let mut buf = vec![0u8; slots * IFREQ];
        #[repr(C)]
        struct Ifconf {
            len: i32,
            buf: *mut u8,
        }
        let mut conf = Ifconf {
            len: buf.len() as i32,
            buf: buf.as_mut_ptr(),
        };
        let result = self.call(
            Syscall::N_ioctl,
            [
                fd as i64,
                SIOCGIFCONF as i64,
                &mut conf as *mut _ as i64,
                0,
                0,
                0,
            ],
        );
        let mut entries = Vec::new();
        if result >= 0 {
            for entry in buf[..(conf.len.max(0) as usize).min(buf.len())].chunks_exact(IFREQ) {
                let end = entry[..IFNAMSIZ]
                    .iter()
                    .position(|b| *b == 0)
                    .unwrap_or(IFNAMSIZ);
                let name = String::from_utf8_lossy(&entry[..end]).into_owned();
                let union = &entry[IFNAMSIZ..];
                entries.push((name, Ipv4Addr::new(union[4], union[5], union[6], union[7])));
            }
        }
        let found = entries.iter().find(|(name, _)| name == find);
        let builder = self
            .fd_arg(self.event(Syscall::N_ioctl, result), "fd", fd)
            .arg("request", "SIOCGIFCONF")
            .arg("number", SIOCGIFCONF)
            .arg("slots", slots)
            .arg("find", find);
        let builder = if result >= 0 {
            builder
                .field("whole_entries", conf.len as usize % IFREQ == 0)
                .field(
                    "found",
                    found.map_or(Value::Null, |(_, ip)| Value::from(ip.to_string())),
                )
        } else {
            builder
        };
        builder.emit();
        (result, entries)
    }

    /// `if_nametoindex(3)`: glibc's wrapper under the libc vehicle; otherwise
    /// the calls glibc makes (a datagram socket, `SIOCGIFINDEX`, close), not
    /// recorded one by one. Recorded as the index, or `-1` with the errno
    /// where glibc answers 0 and sets it.
    pub fn if_nametoindex(&self, name: &str) -> i64 {
        let result = match self.vehicle {
            Vehicle::Libc => {
                let c = cstr(name);
                // SAFETY: a NUL-terminated name.
                let index = unsafe { libc::if_nametoindex(c.as_ptr()) };
                if index == 0 {
                    neg(crate::vehicle::errno())
                } else {
                    i64::from(index)
                }
            }
            _ => {
                let fd = self.call(
                    Syscall::N_socket,
                    [
                        libc::AF_INET as i64,
                        (libc::SOCK_DGRAM | libc::SOCK_CLOEXEC) as i64,
                        0,
                        0,
                        0,
                        0,
                    ],
                );
                if fd < 0 {
                    fd
                } else {
                    let mut ifr = [0u8; IFREQ];
                    let bytes = name.as_bytes();
                    let take = bytes.len().min(IFNAMSIZ - 1);
                    ifr[..take].copy_from_slice(&bytes[..take]);
                    let result = self.call(
                        Syscall::N_ioctl,
                        [fd, SIOCGIFINDEX as i64, ifr.as_mut_ptr() as i64, 0, 0, 0],
                    );
                    self.call(Syscall::N_close, [fd, 0, 0, 0, 0, 0]);
                    if result < 0 {
                        result
                    } else {
                        i64::from(i32::from_ne_bytes(
                            ifr[IFNAMSIZ..IFNAMSIZ + 4].try_into().unwrap(),
                        ))
                    }
                }
            }
        };
        self.rec
            .event("if_nametoindex", result)
            .arg("ifname", name)
            .emit();
        result
    }

    // ---- netlink -----------------------------------------------------------

    /// Send one netlink request (`sendto` to the kernel, port 0): a header of
    /// `kind`, `flags` and `seq` followed by `body`.
    pub fn nl_request(&self, fd: i32, kind: u16, flags: u16, seq: u32, body: &[u8]) -> i64 {
        let len = nl::HEADER + body.len();
        let mut message = Vec::with_capacity(len);
        message.extend_from_slice(&(len as u32).to_ne_bytes());
        message.extend_from_slice(&kind.to_ne_bytes());
        message.extend_from_slice(&flags.to_ne_bytes());
        message.extend_from_slice(&seq.to_ne_bytes());
        message.extend_from_slice(&0u32.to_ne_bytes());
        message.extend_from_slice(body);
        let (raw, alen) = SockAddr::Netlink { pid: 0, groups: 0 }.encode();
        let result = self.call(
            Syscall::N_sendto,
            [
                fd as i64,
                message.as_ptr() as i64,
                len as i64,
                0,
                &raw as *const _ as i64,
                i64::from(alen),
            ],
        );
        self.fd_arg(self.event(Syscall::N_sendto, result), "fd", fd)
            .arg("len", len)
            .arg("nlmsg_type", kind)
            .arg("nlmsg_flags", flags)
            .arg("nlmsg_seq", seq)
            .arg("addr_family", "AF_NETLINK")
            .arg("addr_nl_pid", 0)
            .emit();
        result
    }

    /// Every netlink message queued for `fd` up to and including the one
    /// that ends the answer to a request (`NLMSG_DONE`, `NLMSG_ERROR`, or a
    /// single message without `NLM_F_MULTI`), read with `MSG_DONTWAIT` and
    /// not recorded (how the kernel splits a dump across reads is its
    /// business). `Err` names what went wrong: a read error, a queue that ran
    /// dry first, or more than `max_reads` reads.
    pub fn nl_answer(&self, fd: i32, max_reads: usize) -> Result<Vec<NlMsg>, String> {
        let mut out = Vec::new();
        let mut buf = vec![0u8; 32 * 1024];
        for _ in 0..max_reads {
            let n = self.call(
                Syscall::N_recvfrom,
                [
                    fd as i64,
                    buf.as_mut_ptr() as i64,
                    buf.len() as i64,
                    libc::MSG_DONTWAIT as i64,
                    0,
                    0,
                ],
            );
            if n < 0 {
                return Err(format!(
                    "recvfrom answered {}",
                    crate::vehicle::errno_name((-n) as i32)
                ));
            }
            let mut at = 0;
            let n = n as usize;
            while at + nl::HEADER <= n {
                let len = u32::from_ne_bytes(buf[at..at + 4].try_into().unwrap()) as usize;
                if len < nl::HEADER || at + len > n {
                    return Err(format!("a malformed netlink header (len {len})"));
                }
                let message = NlMsg {
                    kind: u16::from_ne_bytes([buf[at + 4], buf[at + 5]]),
                    flags: u16::from_ne_bytes([buf[at + 6], buf[at + 7]]),
                    seq: u32::from_ne_bytes(buf[at + 8..at + 12].try_into().unwrap()),
                    pid: u32::from_ne_bytes(buf[at + 12..at + 16].try_into().unwrap()),
                    payload: buf[at + nl::HEADER..at + len].to_vec(),
                };
                let last = matches!(message.kind, nl::NLMSG_DONE | nl::NLMSG_ERROR)
                    || message.flags & nl::NLM_F_MULTI == 0;
                out.push(message);
                if last {
                    return Ok(out);
                }
                at += len.div_ceil(4) * 4;
            }
        }
        Err(format!("no end of the answer within {max_reads} reads"))
    }

    // ---- readiness ---------------------------------------------------------

    /// `poll(2)` over `(fd, events)` with a millisecond timeout; revents per
    /// slot, kept to `mask`'s bits when recorded. The generic (arm64) table
    /// has no `poll` row: there the syscall vehicle issues `ppoll` with the
    /// timeout as a timespec (glibc's own spelling).
    pub fn poll(&self, fds: &[(i32, i16)], timeout_ms: i32, mask: i16) -> (i64, Vec<i16>) {
        let mut pollfds = pollfd_array(fds);
        let pointer = if pollfds.is_empty() {
            0
        } else {
            pollfds.as_mut_ptr() as i64
        };
        #[cfg(target_arch = "x86_64")]
        let result = self.call(
            Syscall::N_poll,
            [pointer, pollfds.len() as i64, timeout_ms as i64, 0, 0, 0],
        );
        #[cfg(not(target_arch = "x86_64"))]
        let result = {
            let ts = libc::timespec {
                tv_sec: i64::from(timeout_ms / 1000),
                tv_nsec: i64::from(timeout_ms % 1000) * 1_000_000,
            };
            let ts_ptr = if timeout_ms < 0 {
                0
            } else {
                &ts as *const libc::timespec as i64
            };
            let count = pollfds.len();
            self.legacy(
                // SAFETY: the array holds `count` entries.
                || unsafe { libc::poll(pollfds.as_mut_ptr(), count as libc::nfds_t, timeout_ms) }
                    as i64,
                Syscall::N_ppoll,
                [pointer, count as i64, ts_ptr, 0, SIGSET_BYTES, 0],
            )
        };
        let builder = self.rec.event("poll", result).arg("timeout_ms", timeout_ms);
        self.record_pollfds(builder, fds, &pollfds, result, mask)
    }

    /// Record a poll-shaped call's slots — each descriptor and the events
    /// asked, and once it answered each slot's revents kept to `mask` — and
    /// answer the result and the revents.
    pub(super) fn record_pollfds(
        &self,
        builder: EventBuilder<'_>,
        fds: &[(i32, i16)],
        pollfds: &[libc::pollfd],
        result: i64,
        mask: i16,
    ) -> (i64, Vec<i16>) {
        let revents: Vec<i16> = pollfds.iter().map(|p| p.revents).collect();
        let mut builder = builder.arg("nfds", fds.len());
        for (index, &(fd, events)) in fds.iter().enumerate() {
            builder = self
                .fd_arg(builder, &format!("fd{index}"), fd)
                .arg(&format!("events{index}"), events);
        }
        if result >= 0 {
            for (index, revent) in revents.iter().enumerate() {
                builder = builder.field(&format!("revents{index}"), *revent & mask);
            }
        }
        builder.emit();
        (result, revents)
    }

    /// `poll` with `nfds` entries at an address the kernel cannot read (1),
    /// through the row on every vehicle (a shape glibc's wrapper passes
    /// straight through). The generic (arm64) table has no `poll` row: there
    /// it is `ppoll` with a zero timeout.
    pub fn poll_fault(&self, nfds: usize) -> i64 {
        #[cfg(target_arch = "x86_64")]
        let result = self.call_unwrapped(Syscall::N_poll, [1, nfds as i64, 0, 0, 0, 0]);
        #[cfg(not(target_arch = "x86_64"))]
        let result = {
            let zero = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            self.call_unwrapped(
                Syscall::N_ppoll,
                [1, nfds as i64, &zero as *const _ as i64, 0, SIGSET_BYTES, 0],
            )
        };
        self.rec
            .event("poll", result)
            .arg("fds", "bad pointer")
            .arg("nfds", nfds)
            .emit();
        result
    }

    /// Record a `select`-shaped event (`op`) and answer which descriptors
    /// stayed set.
    #[allow(clippy::too_many_arguments)]
    fn record_select(
        &self,
        op: &str,
        result: i64,
        nfds: i32,
        sets: Sets<'_>,
        read: &libc::fd_set,
        write: &libc::fd_set,
        except: &libc::fd_set,
        timeout: Value,
    ) -> Ready {
        let ready = Ready {
            read: sets
                .read
                .iter()
                .map(|fd| result > 0 && is_set(read, *fd))
                .collect(),
            write: sets
                .write
                .iter()
                .map(|fd| result > 0 && is_set(write, *fd))
                .collect(),
            except: sets
                .except
                .iter()
                .map(|fd| result > 0 && is_set(except, *fd))
                .collect(),
        };
        let mut builder = self
            .rec
            .event(op, result)
            .arg("nfds", nfds)
            .arg("timeout", timeout);
        for (name, fds, flags) in [
            ("r", sets.read, &ready.read),
            ("w", sets.write, &ready.write),
            ("e", sets.except, &ready.except),
        ] {
            for (index, fd) in fds.iter().enumerate() {
                builder = self.fd_arg(builder, &format!("{name}{index}"), *fd);
                if result >= 0 {
                    builder = builder.field(&format!("{name}{index}_ready"), flags[index]);
                }
            }
        }
        builder.emit();
        ready
    }

    /// `select(2)` over `sets` with a `(sec, usec)` timeout (`None` passes
    /// NULL). Answers the ready descriptors and the timeout as the call left
    /// it (Linux writes the unslept time back). The generic (arm64) table
    /// has no `select` row: there the syscall vehicle issues `pselect6` with
    /// a timespec and converts the unslept time back (glibc's own spelling).
    pub fn select(
        &self,
        nfds: i32,
        sets: Sets<'_>,
        timeout: Option<(i64, i64)>,
    ) -> (i64, Ready, Option<(i64, i64)>) {
        let mut read = fd_set(sets.read);
        let mut write = fd_set(sets.write);
        let mut except = fd_set(sets.except);
        let mut tv = timeout.map(|(tv_sec, tv_usec)| libc::timeval { tv_sec, tv_usec });
        let tv_ptr = tv.as_mut().map_or(0, |tv| tv as *mut libc::timeval as i64);
        #[cfg(target_arch = "x86_64")]
        let result = self.call(
            Syscall::N_select,
            [
                nfds as i64,
                &mut read as *mut _ as i64,
                &mut write as *mut _ as i64,
                &mut except as *mut _ as i64,
                tv_ptr,
                0,
            ],
        );
        #[cfg(not(target_arch = "x86_64"))]
        let result = match self.vehicle {
            // SAFETY: local sets and timeval.
            Vehicle::Libc => fold_errno(unsafe {
                libc::select(
                    nfds,
                    &mut read,
                    &mut write,
                    &mut except,
                    tv_ptr as *mut libc::timeval,
                )
            } as i64),
            // glibc's select: a negative timeout is EINVAL without a call;
            // microseconds reaching a second are normalized into seconds.
            _ if tv.is_some_and(|tv| tv.tv_sec < 0 || tv.tv_usec < 0) => neg(libc::EINVAL),
            _ => {
                let mut ts = tv.map(|tv| libc::timespec {
                    tv_sec: tv.tv_sec + tv.tv_usec / 1_000_000,
                    tv_nsec: (tv.tv_usec % 1_000_000) * 1000,
                });
                let result = self.call(
                    Syscall::N_pselect6,
                    [
                        nfds as i64,
                        &mut read as *mut _ as i64,
                        &mut write as *mut _ as i64,
                        &mut except as *mut _ as i64,
                        ts.as_mut().map_or(0, |ts| ts as *mut libc::timespec as i64),
                        0,
                    ],
                );
                if let (Some(tv), Some(ts)) = (tv.as_mut(), ts) {
                    tv.tv_sec = ts.tv_sec;
                    tv.tv_usec = ts.tv_nsec / 1000;
                }
                result
            }
        };
        let left = tv.map(|tv| (tv.tv_sec, tv.tv_usec));
        let ready = self.record_select(
            "select",
            result,
            nfds,
            sets,
            &read,
            &write,
            &except,
            timeout.map_or(Value::Null, |(s, us)| Value::from(format!("{s}s{us}us"))),
        );
        (result, ready, left)
    }

    /// `pselect6` over `sets` with a `(sec, nsec)` timeout and an optional
    /// signal mask of `sigsetsize` bytes. glibc's `pselect` is the libc door
    /// (it copies the timeout, so what the kernel writes back is never
    /// recorded); a `sigsetsize` other than 8 is a shape glibc cannot
    /// express, issued through `syscall(2)` on every vehicle.
    pub fn pselect6(
        &self,
        nfds: i32,
        sets: Sets<'_>,
        timeout: Option<(i64, i64)>,
        mask: Option<&libc::sigset_t>,
        sigsetsize: usize,
    ) -> (i64, Ready) {
        let mut read = fd_set(sets.read);
        let mut write = fd_set(sets.write);
        let mut except = fd_set(sets.except);
        let mut ts = timeout.map(|(tv_sec, tv_nsec)| libc::timespec { tv_sec, tv_nsec });
        let pair: [usize; 2] = [
            mask.map_or(0, |m| m as *const libc::sigset_t as usize),
            sigsetsize,
        ];
        let args = [
            nfds as i64,
            &mut read as *mut _ as i64,
            &mut write as *mut _ as i64,
            &mut except as *mut _ as i64,
            ts.as_mut().map_or(0, |ts| ts as *mut libc::timespec as i64),
            &pair as *const [usize; 2] as i64,
        ];
        let result = if sigsetsize as i64 == SIGSET_BYTES {
            self.call(Syscall::N_pselect6, args)
        } else {
            self.call_unwrapped(Syscall::N_pselect6, args)
        };
        let ready = self.record_select(
            "pselect6",
            result,
            nfds,
            sets,
            &read,
            &write,
            &except,
            timeout.map_or(Value::Null, |(s, ns)| Value::from(format!("{s}s{ns}ns"))),
        );
        (result, ready)
    }

    /// The legacy `epoll_create(size)` row (x86_64 only; glibc's wrapper is
    /// not one the shim defines, so every vehicle issues the row).
    #[cfg(target_arch = "x86_64")]
    pub fn epoll_create(&self, size: i32) -> i32 {
        let result = self.call(Syscall::N_epoll_create, [size as i64, 0, 0, 0, 0, 0]);
        self.event(Syscall::N_epoll_create, result)
            .arg("size", size)
            .norm("ret", Norm::Relative("fd"))
            .emit();
        result as i32
    }

    /// The legacy `eventfd(initval)` row (x86_64 only: glibc's `eventfd`
    /// issues `eventfd2`, so every vehicle issues the row itself).
    #[cfg(target_arch = "x86_64")]
    pub fn eventfd(&self, initval: u32) -> i32 {
        let result = self.call(Syscall::N_eventfd, [initval as i64, 0, 0, 0, 0, 0]);
        self.event(Syscall::N_eventfd, result)
            .arg("initval", initval)
            .norm("ret", Norm::Relative("fd"))
            .emit();
        result as i32
    }

    /// Record an epoll wait's delivered events, sorted by data.
    pub(super) fn record_epoll<'a>(
        &self,
        builder: EventBuilder<'a>,
        result: i64,
        events: &[libc::epoll_event],
    ) -> (EventBuilder<'a>, Vec<(u64, u32)>) {
        let mut delivered: Vec<(u64, u32)> = if result > 0 {
            events[..result as usize]
                .iter()
                .map(|event| (event.u64, event.events))
                .collect()
        } else {
            Vec::new()
        };
        delivered.sort();
        let rendered: Vec<Value> = delivered
            .iter()
            .map(|(data, mask)| Value::from(format!("{data}:{mask:#x}")))
            .collect();
        let builder = if result >= 0 {
            builder.field("events", Value::Array(rendered))
        } else {
            builder
        };
        (builder, delivered)
    }

    /// `epoll_pwait` with an optional mask of `sigsetsize` bytes. glibc's
    /// `epoll_pwait` is the libc door for the kernel's size (8); another size
    /// is issued through `syscall(2)` on every vehicle.
    pub fn epoll_pwait(
        &self,
        epfd: i32,
        maxevents: i32,
        timeout_ms: i32,
        mask: Option<&libc::sigset_t>,
        sigsetsize: usize,
    ) -> (i64, Vec<(u64, u32)>) {
        let mut events = vec![libc::epoll_event { events: 0, u64: 0 }; maxevents.max(1) as usize];
        let args = [
            epfd as i64,
            events.as_mut_ptr() as i64,
            maxevents as i64,
            timeout_ms as i64,
            mask.map_or(0, |m| m as *const libc::sigset_t as i64),
            sigsetsize as i64,
        ];
        let result = if sigsetsize as i64 == SIGSET_BYTES {
            self.call(Syscall::N_epoll_pwait, args)
        } else {
            self.call_unwrapped(Syscall::N_epoll_pwait, args)
        };
        let builder = self
            .fd_arg(self.event(Syscall::N_epoll_pwait, result), "epfd", epfd)
            .arg("maxevents", maxevents)
            .arg("timeout_ms", timeout_ms)
            .arg("mask", mask.is_some())
            .arg("sigsetsize", sigsetsize);
        let (builder, delivered) = self.record_epoll(builder, result, &events);
        builder.emit();
        (result, delivered)
    }

    /// `epoll_pwait2` with a `(sec, nsec)` timeout (`None` passes NULL: wait
    /// without bound) and no mask.
    pub fn epoll_pwait2(
        &self,
        epfd: i32,
        maxevents: i32,
        timeout: Option<(i64, i64)>,
    ) -> (i64, Vec<(u64, u32)>) {
        let mut events = vec![libc::epoll_event { events: 0, u64: 0 }; maxevents.max(1) as usize];
        let ts = timeout.map(|(tv_sec, tv_nsec)| libc::timespec { tv_sec, tv_nsec });
        let result = self.call(
            Syscall::N_epoll_pwait2,
            [
                epfd as i64,
                events.as_mut_ptr() as i64,
                maxevents as i64,
                ts.as_ref()
                    .map_or(0, |ts| ts as *const libc::timespec as i64),
                0,
                SIGSET_BYTES,
            ],
        );
        let builder = self
            .fd_arg(self.event(Syscall::N_epoll_pwait2, result), "epfd", epfd)
            .arg("maxevents", maxevents)
            .arg(
                "timeout",
                timeout.map_or(Value::Null, |(s, ns)| Value::from(format!("{s}s{ns}ns"))),
            );
        let (builder, delivered) = self.record_epoll(builder, result, &events);
        builder.emit();
        (result, delivered)
    }

    // ---- name resolution -------------------------------------------------------

    /// `getaddrinfo(3)` (libc only: there is no kernel row under it) with
    /// hints of `family`, `socktype` and `flags`; every result is recorded
    /// and freed with `freeaddrinfo(3)`. Recorded as the `EAI_*` code in
    /// `fields.code` (the call's result is not an errno).
    pub fn getaddrinfo(
        &self,
        node: Option<&str>,
        service: Option<&str>,
        family: i32,
        socktype: i32,
        flags: i32,
    ) -> (i32, Vec<AddrInfo>) {
        let node_c = node.map(cstr);
        let service_c = service.map(cstr);
        // SAFETY: an all-zero addrinfo is valid hints.
        let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
        hints.ai_family = family;
        hints.ai_socktype = socktype;
        hints.ai_flags = flags;
        let mut list: *mut libc::addrinfo = std::ptr::null_mut();
        // SAFETY: NUL-terminated strings or NULL, valid hints, an out-pointer.
        let code = unsafe {
            libc::getaddrinfo(
                node_c.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
                service_c.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
                &hints,
                &mut list,
            )
        };
        let mut results = Vec::new();
        if code == 0 {
            let mut at = list;
            while !at.is_null() && results.len() < 16 {
                // SAFETY: a node of the list getaddrinfo returned.
                let entry = unsafe { &*at };
                // SAFETY: an all-zero sockaddr_storage is a valid value; the
                // entry's address is `ai_addrlen` readable bytes.
                let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
                let len = (entry.ai_addrlen as usize).min(size_of::<libc::sockaddr_storage>());
                if !entry.ai_addr.is_null() {
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            entry.ai_addr as *const u8,
                            &mut storage as *mut _ as *mut u8,
                            len,
                        )
                    };
                }
                results.push(AddrInfo {
                    family: entry.ai_family,
                    socktype: entry.ai_socktype,
                    protocol: entry.ai_protocol,
                    addrlen: entry.ai_addrlen,
                    addr: SockAddr::decode(&storage, len as u32),
                    canonname: !entry.ai_canonname.is_null(),
                });
                at = entry.ai_next;
            }
            // SAFETY: the list getaddrinfo returned, freed once.
            unsafe { libc::freeaddrinfo(list) };
        }
        let mut builder = self
            .rec
            .event("getaddrinfo", 0)
            .arg("node", node.map_or(Value::Null, Value::from))
            .arg("service", service.map_or(Value::Null, Value::from))
            .arg("family", family_name(family))
            .arg("socktype", socktype)
            .arg("flags", flags)
            .field("code", eai_name(code))
            .field("results", results.len());
        for (index, info) in results.iter().enumerate() {
            builder = builder
                .field(&format!("family{index}"), family_name(info.family))
                .field(&format!("socktype{index}"), info.socktype)
                .field(&format!("protocol{index}"), info.protocol)
                .field(&format!("addrlen{index}"), info.addrlen)
                .field(&format!("canonname{index}"), info.canonname);
            builder = info.addr.record(builder, true, &format!("addr{index}"));
        }
        builder.emit();
        (code, results)
    }

    // ---- symbols the shim leaves undefined -----------------------------------

    /// Resolve `symbol` through `dlsym(RTLD_DEFAULT, …)` and record whether
    /// it resolved. The door of a symbol the registry lists `Absent`: the
    /// probe binary cannot import it (the pre-run audit would refuse the
    /// whole binary), so the libc vehicle reaches glibc's definition
    /// dynamically, and under patina `dlsym` answers only what the shim
    /// defines (c/posix/dlsym.c `__wrap_dlsym`).
    pub fn resolve(&self, symbol: &str) -> Option<*mut libc::c_void> {
        let c = cstr(symbol);
        // SAFETY: a NUL-terminated name looked up in the global scope.
        let address = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c.as_ptr()) };
        self.rec
            .event("dlsym", 0)
            .arg("symbol", symbol)
            .field("resolved", !address.is_null())
            .emit();
        (!address.is_null()).then_some(address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
