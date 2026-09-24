//! net/ifconfig — the loopback interface through the `SIOCGIF*` ioctls and
//! `if_nametoindex(3)` (netdevice(7); net/core/dev_ioctl.c,
//! net/ipv4/devinet.c `devinet_ioctl`):
//!
//! * `lo` is interface 1 (the first device every network namespace
//!   registers), `SIOCGIFNAME` maps 1 back to `lo`;
//! * its flags include `IFF_UP|IFF_LOOPBACK|IFF_RUNNING`, its address is
//!   `127.0.0.1` with netmask `255.0.0.0`, its hardware type
//!   `ARPHRD_LOOPBACK` with an all-zero address;
//! * `SIOCGIFCONF` lists it with `127.0.0.1` in whole `ifreq` entries;
//! * a name no interface has is `ENODEV` (ioctl and `if_nametoindex`), an
//!   index none has `ENODEV`; the requests on a regular file are `ENOTTY`,
//!   on a closed descriptor `EBADF`.
//!
//! Only loopback facts are compared. What else the host has — its other
//! interfaces, their count and addresses, `lo`'s MTU (configurable; checked
//! against the IPv4 minimum of 576, never recorded) — is its own business, as the `eth0` of
//! the interface table the arc models is patina's.

use crate::catalog::{DEFAULTS, Scenario};
use crate::probe::{
    ARPHRD_LOOPBACK, AT_FDCWD, IfField, Probe, SIOCGIFADDR, SIOCGIFFLAGS, SIOCGIFHWADDR,
    SIOCGIFINDEX, SIOCGIFMTU, SIOCGIFNAME, SIOCGIFNETMASK, neg,
};
use libc::*;
use patina_dst_syscalls::Syscall;
use std::net::Ipv4Addr;

/// The IPv4 minimum reassembly size (RFC 791): no interface that carries
/// IPv4 has a smaller MTU, whatever its configuration.
pub const MIN_MTU: i32 = 576;

/// The loopback device's interface index.
const LOOPBACK_INDEX: i32 = 1;
/// An interface name no host has (within `IFNAMSIZ`).
const NO_SUCH: &str = "ptnone0";
/// The flags every up loopback device carries.
const LOOPBACK_FLAGS: u16 = (IFF_UP | IFF_LOOPBACK | IFF_RUNNING) as u16;

pub fn run(p: &Probe) {
    let root = p.dir();
    let fd = p.socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    p.require("a socket to ask through", fd >= 0);
    let (r, answer) = p.ifreq(fd, SIOCGIFINDEX, "SIOCGIFINDEX", "lo", 0, IfField::Index);
    p.check(
        "lo is interface 1",
        r == 0 && answer.index == LOOPBACK_INDEX,
    );
    let (r, answer) = p.ifreq(
        fd,
        SIOCGIFNAME,
        "SIOCGIFNAME",
        "",
        LOOPBACK_INDEX,
        IfField::Name,
    );
    p.check("interface 1 is lo", r == 0 && answer.name == "lo");
    let (r, answer) = p.ifreq(
        fd,
        SIOCGIFFLAGS,
        "SIOCGIFFLAGS",
        "lo",
        0,
        IfField::Flags(LOOPBACK_FLAGS),
    );
    p.check(
        "lo is up, loopback and running",
        r == 0 && answer.flags & LOOPBACK_FLAGS == LOOPBACK_FLAGS,
    );
    let (r, answer) = p.ifreq(fd, SIOCGIFADDR, "SIOCGIFADDR", "lo", 0, IfField::Addr);
    p.check(
        "lo's address is 127.0.0.1",
        r == 0 && answer.addr == Some(Ipv4Addr::LOCALHOST),
    );
    let (r, answer) = p.ifreq(fd, SIOCGIFNETMASK, "SIOCGIFNETMASK", "lo", 0, IfField::Addr);
    p.check(
        "lo's netmask is 255.0.0.0",
        r == 0 && answer.addr == Some(Ipv4Addr::new(255, 0, 0, 0)),
    );
    let (r, answer) = p.ifreq(fd, SIOCGIFHWADDR, "SIOCGIFHWADDR", "lo", 0, IfField::HwAddr);
    p.check(
        "lo's hardware type is ARPHRD_LOOPBACK with an all-zero address",
        r == 0 && answer.hw_family == ARPHRD_LOOPBACK && answer.hw_bytes == [0; 6],
    );
    let (r, answer) = p.ifreq(fd, SIOCGIFMTU, "SIOCGIFMTU", "lo", 0, IfField::Mtu);
    p.check(
        "lo's MTU is at least the IPv4 minimum reassembly size",
        r == 0 && answer.mtu >= MIN_MTU,
    );
    let (r, entries) = p.ifconf(fd, 64, "lo");
    p.check(
        "SIOCGIFCONF lists lo with 127.0.0.1",
        r == 0
            && entries
                .iter()
                .any(|(name, ip)| name == "lo" && *ip == Ipv4Addr::LOCALHOST),
    );
    p.check(
        "a name no interface has is ENODEV",
        p.ifreq(fd, SIOCGIFINDEX, "SIOCGIFINDEX", NO_SUCH, 0, IfField::Index)
            .0
            == neg(ENODEV),
    );
    p.check(
        "an index no interface has is ENODEV",
        p.ifreq(
            fd,
            SIOCGIFNAME,
            "SIOCGIFNAME",
            "",
            0x7fff_fff0,
            IfField::Name,
        )
        .0 == neg(ENODEV),
    );

    p.check("if_nametoindex(lo) is 1", p.if_nametoindex("lo") == 1);
    p.check(
        "if_nametoindex of a name no interface has is ENODEV",
        p.if_nametoindex(NO_SUCH) == neg(ENODEV),
    );

    let file = p.openat(AT_FDCWD, &format!("{root}/file"), O_RDWR | O_CREAT, 0o600);
    p.require("open a file", file >= 0);
    p.check(
        "SIOCGIFINDEX on a regular file is ENOTTY",
        p.ifreq(file, SIOCGIFINDEX, "SIOCGIFINDEX", "lo", 0, IfField::Index)
            .0
            == neg(ENOTTY),
    );
    p.close(file);
    p.close(fd);
    p.check(
        "SIOCGIFINDEX on a closed descriptor is EBADF",
        p.ifreq(fd, SIOCGIFINDEX, "SIOCGIFINDEX", "lo", 0, IfField::Index)
            .0
            == neg(EBADF),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "net/ifconfig",
    run,
    covers: &[
        Syscall::N_socket,
        Syscall::N_ioctl,
        Syscall::N_openat,
        Syscall::N_close,
    ],
    symbols: &["socket", "ioctl", "if_nametoindex", "openat", "close"],
    ..DEFAULTS
};
