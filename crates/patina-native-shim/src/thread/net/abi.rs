//! The socket ABI's numbers as the platform spells them: address families,
//! socket types, option levels and names, message flags and control-message
//! types. The model below is written against these names, so the one socket
//! layer answers each platform in its own numbering (Linux's is the virtual
//! kernel's; Darwin's is what its libc headers hand the C interposers).

#[cfg(target_os = "linux")]
mod platform {
    pub(crate) const AF_UNSPEC: i32 = 0;
    pub(crate) const AF_UNIX: i32 = 1;
    pub(crate) const AF_INET: i32 = 2;
    pub(crate) const AF_INET6: i32 = 10;
    pub(crate) const AF_NETLINK: i32 = 16;
    pub(crate) const AF_PACKET: i32 = 17;
    /// `NPROTO`: every family number below it is one the kernel knows.
    pub(crate) const AF_MAX: i32 = 46;

    pub(crate) const SOCK_STREAM: i32 = 1;
    pub(crate) const SOCK_DGRAM: i32 = 2;
    pub(crate) const SOCK_RAW: i32 = 3;
    pub(crate) const SOCK_SEQPACKET: i32 = 5;
    pub(crate) const SOCK_PACKET: i32 = 10;
    pub(crate) const SOCK_TYPE_MASK: i32 = 0xf;
    pub(crate) const SOCK_NONBLOCK: i32 = 0o4000;
    pub(crate) const SOCK_CLOEXEC: i32 = 0o2000000;

    pub(crate) const IPPROTO_ICMP: i32 = 1;
    pub(crate) const IPPROTO_TCP: i32 = 6;
    pub(crate) const IPPROTO_UDP: i32 = 17;
    pub(crate) const IPPROTO_UDPLITE: i32 = 136;
    pub(crate) const IPPROTO_ICMPV6: i32 = 58;

    pub(crate) const SOL_SOCKET: i32 = 1;
    pub(crate) const SOL_IP: i32 = 0;
    pub(crate) const SOL_TCP: i32 = 6;
    pub(crate) const SOL_IPV6: i32 = 41;

    pub(crate) const SO_DEBUG: i32 = 1;
    pub(crate) const SO_REUSEADDR: i32 = 2;
    pub(crate) const SO_TYPE: i32 = 3;
    pub(crate) const SO_ERROR: i32 = 4;
    pub(crate) const SO_DONTROUTE: i32 = 5;
    pub(crate) const SO_BROADCAST: i32 = 6;
    pub(crate) const SO_SNDBUF: i32 = 7;
    pub(crate) const SO_RCVBUF: i32 = 8;
    pub(crate) const SO_KEEPALIVE: i32 = 9;
    pub(crate) const SO_OOBINLINE: i32 = 10;
    pub(crate) const SO_PRIORITY: i32 = 12;
    pub(crate) const SO_LINGER: i32 = 13;
    pub(crate) const SO_REUSEPORT: i32 = 15;
    pub(crate) const SO_PASSCRED: i32 = 16;
    pub(crate) const SO_PEERCRED: i32 = 17;
    pub(crate) const SO_RCVLOWAT: i32 = 18;
    pub(crate) const SO_SNDLOWAT: i32 = 19;
    pub(crate) const SO_RCVTIMEO: i32 = 20;
    pub(crate) const SO_SNDTIMEO: i32 = 21;
    pub(crate) const SO_BINDTODEVICE: i32 = 25;
    pub(crate) const SO_ACCEPTCONN: i32 = 30;
    pub(crate) const SO_SNDBUFFORCE: i32 = 32;
    pub(crate) const SO_RCVBUFFORCE: i32 = 33;
    pub(crate) const SO_MARK: i32 = 36;
    pub(crate) const SO_PROTOCOL: i32 = 38;
    pub(crate) const SO_DOMAIN: i32 = 39;
    pub(crate) const SO_BINDTOIFINDEX: i32 = 62;

    pub(crate) const TCP_NODELAY: i32 = 1;
    pub(crate) const TCP_MAXSEG: i32 = 2;
    pub(crate) const TCP_CORK: i32 = 3;
    pub(crate) const TCP_KEEPIDLE: i32 = 4;
    pub(crate) const TCP_KEEPINTVL: i32 = 5;
    pub(crate) const TCP_KEEPCNT: i32 = 6;
    pub(crate) const TCP_QUICKACK: i32 = 12;
    pub(crate) const TCP_USER_TIMEOUT: i32 = 18;

    pub(crate) const IPV6_V6ONLY: i32 = 26;

    pub(crate) const IP_TOS: i32 = 1;
    pub(crate) const IP_TTL: i32 = 2;
    pub(crate) const IP_RETOPTS: i32 = 7;
    pub(crate) const IP_PKTINFO: i32 = 8;
    pub(crate) const IP_MTU_DISCOVER: i32 = 10;
    pub(crate) const IP_RECVTOS: i32 = 13;
    pub(crate) const IPV6_UNICAST_HOPS: i32 = 16;
    pub(crate) const IPV6_MTU_DISCOVER: i32 = 23;
    pub(crate) const IPV6_RECVPKTINFO: i32 = 49;
    pub(crate) const IPV6_PKTINFO: i32 = 50;
    pub(crate) const IPV6_HOPLIMIT: i32 = 52;
    pub(crate) const IPV6_DONTFRAG: i32 = 62;
    pub(crate) const IPV6_RECVTCLASS: i32 = 66;
    pub(crate) const IPV6_TCLASS: i32 = 67;
    /// `IP_PMTUDISC_OMIT`/`IPV6_PMTUDISC_OMIT`: the last path-MTU mode.
    pub(crate) const PMTUDISC_OMIT: i32 = 5;
    /// `IP_PMTUDISC_WANT`: a socket's mode until one is set.
    pub(crate) const PMTUDISC_WANT: i32 = 1;

    pub(crate) const SOL_UDP: i32 = 17;
    pub(crate) const UDP_SEGMENT: i32 = 103;

    pub(crate) const MSG_OOB: i32 = 0x1;
    pub(crate) const MSG_PEEK: i32 = 0x2;
    pub(crate) const MSG_CTRUNC: i32 = 0x8;
    pub(crate) const MSG_TRUNC: i32 = 0x20;
    pub(crate) const MSG_DONTWAIT: i32 = 0x40;
    pub(crate) const MSG_WAITALL: i32 = 0x100;
    pub(crate) const MSG_NOSIGNAL: i32 = 0x4000;
    pub(crate) const MSG_WAITFORONE: i32 = 0x10000;
    pub(crate) const MSG_CMSG_CLOEXEC: i32 = 0x4000_0000;

    pub(crate) const SCM_RIGHTS: i32 = 1;
    pub(crate) const SCM_CREDENTIALS: i32 = 2;

    /// `sizeof(struct sockaddr_un)`.
    pub(crate) const SOCKADDR_UN_LEN: usize = 110;
    /// `sizeof(struct sockaddr_storage)`: the most `move_addr_to_kernel` takes.
    pub(crate) const SOCKADDR_STORAGE_LEN: usize = 128;
    /// `SO_RCVTIMEO`/`SO_SNDTIMEO`'s `struct timeval`: two `long`s.
    pub(crate) const TIMEVAL_LEN: usize = 16;

    pub(crate) const EDOM: i32 = 33;
    pub(crate) const EDESTADDRREQ: i32 = 89;
    pub(crate) const EMSGSIZE: i32 = 90;
    pub(crate) const EPROTOTYPE: i32 = 91;
    pub(crate) const ENOPROTOOPT: i32 = 92;
    pub(crate) const EPROTONOSUPPORT: i32 = 93;
    pub(crate) const ESOCKTNOSUPPORT: i32 = 94;
    pub(crate) const EAFNOSUPPORT: i32 = 97;
    pub(crate) const EADDRINUSE: i32 = 98;
    pub(crate) const EADDRNOTAVAIL: i32 = 99;
    pub(crate) const ENETUNREACH: i32 = 101;
    pub(crate) const ECONNABORTED: i32 = 103;
    pub(crate) const ECONNRESET: i32 = 104;
    pub(crate) const ENOBUFS: i32 = 105;
    pub(crate) const ECONNREFUSED: i32 = 111;
    pub(crate) const EINPROGRESS: i32 = 115;
}

#[cfg(target_os = "macos")]
mod platform {
    pub(crate) const AF_UNSPEC: i32 = 0;
    pub(crate) const AF_UNIX: i32 = 1;
    pub(crate) const AF_INET: i32 = 2;
    pub(crate) const AF_INET6: i32 = 30;
    pub(crate) const AF_MAX: i32 = 41;

    pub(crate) const SOCK_STREAM: i32 = 1;
    pub(crate) const SOCK_DGRAM: i32 = 2;
    pub(crate) const SOCK_RAW: i32 = 3;
    pub(crate) const SOCK_SEQPACKET: i32 = 5;
    pub(crate) const SOCK_TYPE_MASK: i32 = 0xf;

    pub(crate) const IPPROTO_ICMP: i32 = 1;
    pub(crate) const IPPROTO_TCP: i32 = 6;
    pub(crate) const IPPROTO_UDP: i32 = 17;
    pub(crate) const IPPROTO_ICMPV6: i32 = 58;

    pub(crate) const SOL_SOCKET: i32 = 0xffff;
    pub(crate) const SOL_IP: i32 = 0;
    pub(crate) const SOL_TCP: i32 = 6;
    pub(crate) const SOL_IPV6: i32 = 41;

    pub(crate) const SO_DEBUG: i32 = 0x1;
    pub(crate) const SO_ACCEPTCONN: i32 = 0x2;
    pub(crate) const SO_REUSEADDR: i32 = 0x4;
    pub(crate) const SO_KEEPALIVE: i32 = 0x8;
    pub(crate) const SO_DONTROUTE: i32 = 0x10;
    pub(crate) const SO_BROADCAST: i32 = 0x20;
    pub(crate) const SO_LINGER: i32 = 0x80;
    pub(crate) const SO_OOBINLINE: i32 = 0x100;
    pub(crate) const SO_REUSEPORT: i32 = 0x200;
    pub(crate) const SO_SNDBUF: i32 = 0x1001;
    pub(crate) const SO_RCVBUF: i32 = 0x1002;
    pub(crate) const SO_SNDLOWAT: i32 = 0x1003;
    pub(crate) const SO_RCVLOWAT: i32 = 0x1004;
    pub(crate) const SO_SNDTIMEO: i32 = 0x1005;
    pub(crate) const SO_RCVTIMEO: i32 = 0x1006;
    pub(crate) const SO_ERROR: i32 = 0x1007;
    pub(crate) const SO_TYPE: i32 = 0x1008;
    /// `SO_NOSIGPIPE`: Darwin's per-socket `MSG_NOSIGNAL`.
    pub(crate) const SO_NOSIGPIPE: i32 = 0x1022;

    pub(crate) const TCP_NODELAY: i32 = 0x1;
    pub(crate) const TCP_MAXSEG: i32 = 0x2;
    pub(crate) const TCP_KEEPIDLE: i32 = 0x10;
    pub(crate) const TCP_KEEPINTVL: i32 = 0x101;
    pub(crate) const TCP_KEEPCNT: i32 = 0x102;

    pub(crate) const IPV6_V6ONLY: i32 = 27;

    pub(crate) const MSG_OOB: i32 = 0x1;
    pub(crate) const MSG_PEEK: i32 = 0x2;
    pub(crate) const MSG_TRUNC: i32 = 0x10;
    pub(crate) const MSG_CTRUNC: i32 = 0x20;
    pub(crate) const MSG_WAITALL: i32 = 0x40;
    pub(crate) const MSG_DONTWAIT: i32 = 0x80;
    pub(crate) const MSG_NOSIGNAL: i32 = 0x80000;

    pub(crate) const SCM_RIGHTS: i32 = 1;

    pub(crate) const SOCKADDR_UN_LEN: usize = 106;
    pub(crate) const SOCKADDR_STORAGE_LEN: usize = 128;
    /// Darwin's `struct timeval`: a `long` and an `int`, padded to 16.
    pub(crate) const TIMEVAL_LEN: usize = 16;

    pub(crate) const EDOM: i32 = 33;
    pub(crate) const EINPROGRESS: i32 = 36;
    pub(crate) const EDESTADDRREQ: i32 = 39;
    pub(crate) const EMSGSIZE: i32 = 40;
    pub(crate) const EPROTOTYPE: i32 = 41;
    pub(crate) const ENOPROTOOPT: i32 = 42;
    pub(crate) const EPROTONOSUPPORT: i32 = 43;
    pub(crate) const ESOCKTNOSUPPORT: i32 = 44;
    pub(crate) const EAFNOSUPPORT: i32 = 47;
    pub(crate) const EADDRINUSE: i32 = 48;
    pub(crate) const EADDRNOTAVAIL: i32 = 49;
    pub(crate) const ENETUNREACH: i32 = 51;
    pub(crate) const ECONNABORTED: i32 = 53;
    pub(crate) const ECONNRESET: i32 = 54;
    pub(crate) const ENOBUFS: i32 = 55;
    pub(crate) const ECONNREFUSED: i32 = 61;
}

pub(crate) use platform::*;

/// A kernel poll mask's bits (`EPOLL*`, which Linux `poll`'s `POLL*` share):
/// the one readiness vocabulary the reactors read a socket through.
pub(crate) const POLLIN: u32 = 0x001;
pub(crate) const POLLOUT: u32 = 0x004;
pub(crate) const POLLERR: u32 = 0x008;
pub(crate) const POLLHUP: u32 = 0x010;
pub(crate) const POLLRDNORM: u32 = 0x040;
pub(crate) const POLLWRNORM: u32 = 0x100;
pub(crate) const POLLWRBAND: u32 = 0x200;
pub(crate) const POLLRDHUP: u32 = 0x2000;

/// `sk_shutdown`'s bits (include/net/sock.h): the kernel's `shutdown(2)` maps
/// `SHUT_RD`/`SHUT_WR`/`SHUT_RDWR` onto them by adding one.
pub(crate) const RCV_SHUTDOWN: u8 = 1;
pub(crate) const SEND_SHUTDOWN: u8 = 2;
pub(crate) const SHUTDOWN_MASK: u8 = 3;

/// `UIO_MAXIOV`: the most iovecs one message, and the most messages one
/// `sendmmsg`/`recvmmsg`, carry.
pub(crate) const UIO_MAXIOV: usize = 1024;
/// `SCM_MAX_FD`: the most descriptors one `SCM_RIGHTS` message carries.
pub(crate) const SCM_MAX_FD: usize = 253;
/// `IFNAMSIZ`.
pub(crate) const IFNAMSIZ: usize = 16;
