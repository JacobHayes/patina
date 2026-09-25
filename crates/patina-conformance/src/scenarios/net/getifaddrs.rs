//! net/getifaddrs — `getifaddrs(3)`/`freeifaddrs(3)` for the loopback
//! interface, cross-checked with the ioctls (getifaddrs(3), netdevice(7)):
//!
//! * the list holds an AF_INET entry for `lo`: `127.0.0.1`, netmask
//!   `255.0.0.0`, flags `IFF_UP|IFF_LOOPBACK|IFF_RUNNING` — the flags
//!   `SIOCGIFFLAGS` reports for it;
//! * and an AF_PACKET entry for `lo` whose link address names interface 1
//!   (`SIOCGIFINDEX`), hardware type `ARPHRD_LOOPBACK`, six address bytes,
//!   with link statistics in `ifa_data`;
//! * `freeifaddrs` releases the list.
//!
//! libc only: there is no kernel row under the list (glibc builds it from
//! netlink dumps, net/netlink covers those). The scenario reaches both
//! symbols through `dlsym`, a program's other way to them: the shim defines
//! both, and under patina `dlsym` answers its own definitions
//! (c/posix/dlsym.c `patina_dlsym_route`).

use crate::catalog::{DEFAULTS, Scenario};
use crate::probe::{ARPHRD_LOOPBACK, IfField, Probe, SIOCGIFFLAGS, SIOCGIFINDEX, family_name};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;
use serde_json::Value;
use std::net::Ipv4Addr;

/// The flags every up loopback device carries.
const LOOPBACK_FLAGS: u32 = super::LOOPBACK_FLAGS as u32;

type GetIfAddrs = unsafe extern "C" fn(*mut *mut ifaddrs) -> c_int;
type FreeIfAddrs = unsafe extern "C" fn(*mut ifaddrs);

fn ipv4(addr: *const sockaddr) -> Option<Ipv4Addr> {
    // SAFETY: a non-null AF_INET entry is a sockaddr_in.
    unsafe {
        (!addr.is_null() && i32::from((*addr).sa_family) == AF_INET).then(|| {
            let sin = &*(addr as *const sockaddr_in);
            Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr))
        })
    }
}

pub fn run(p: &Probe) {
    let fd = p.socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    p.require("a socket to ask through", fd >= 0);
    let (_, index) = p.ifreq(fd, SIOCGIFINDEX, "SIOCGIFINDEX", "lo", 0, IfField::Index);
    let (_, flags) = p.ifreq(
        fd,
        SIOCGIFFLAGS,
        "SIOCGIFFLAGS",
        "lo",
        0,
        IfField::Flags(LOOPBACK_FLAGS as u16),
    );
    p.close(fd);

    let get = p.resolve("getifaddrs");
    let free = p.resolve("freeifaddrs");
    p.require(
        "getifaddrs and freeifaddrs resolve",
        get.is_some() && free.is_some(),
    );
    // SAFETY: glibc's getifaddrs and freeifaddrs, by their documented types.
    let (get, free): (GetIfAddrs, FreeIfAddrs) = unsafe {
        (
            std::mem::transmute::<*mut c_void, GetIfAddrs>(get.unwrap()),
            std::mem::transmute::<*mut c_void, FreeIfAddrs>(free.unwrap()),
        )
    };
    let mut list: *mut ifaddrs = std::ptr::null_mut();
    // SAFETY: an out-pointer for the list.
    let result = crate::vehicle::fold_errno(i64::from(unsafe { get(&mut list) }));
    let mut inet = None;
    let mut packet = None;
    let mut at = list;
    while !at.is_null() {
        // SAFETY: a node of the list getifaddrs returned.
        let entry = unsafe { &*at };
        // SAFETY: a NUL-terminated interface name.
        let name = unsafe { std::ffi::CStr::from_ptr(entry.ifa_name) }.to_string_lossy();
        if name == "lo" && !entry.ifa_addr.is_null() {
            // SAFETY: a non-null address.
            let family = i32::from(unsafe { (*entry.ifa_addr).sa_family });
            if family == AF_INET && inet.is_none() {
                inet = Some((
                    ipv4(entry.ifa_addr),
                    ipv4(entry.ifa_netmask),
                    entry.ifa_flags & LOOPBACK_FLAGS,
                ));
            } else if family == AF_PACKET && packet.is_none() {
                // SAFETY: an AF_PACKET entry is a sockaddr_ll.
                let ll = unsafe { &*(entry.ifa_addr as *const sockaddr_ll) };
                packet = Some((
                    ll.sll_ifindex,
                    ll.sll_hatype,
                    ll.sll_halen,
                    !entry.ifa_data.is_null(),
                ));
            }
        }
        at = entry.ifa_next;
    }
    // SAFETY: the list getifaddrs returned, freed once.
    unsafe { free(list) };
    let mut builder = p.rec.event("getifaddrs", result);
    if let Some((addr, mask, flags)) = inet {
        builder = builder
            .field(
                "lo_inet_addr",
                addr.map_or(Value::Null, |a| Value::from(a.to_string())),
            )
            .field(
                "lo_inet_netmask",
                mask.map_or(Value::Null, |a| Value::from(a.to_string())),
            )
            .field("lo_inet_flags", flags);
    }
    if let Some((ifindex, hatype, halen, stats)) = packet {
        builder = builder
            .field("lo_packet_family", family_name(AF_PACKET))
            .field("lo_packet_ifindex", ifindex)
            .field("lo_packet_hatype", hatype)
            .field("lo_packet_halen", halen)
            .field("lo_packet_stats", stats);
    }
    builder.emit();
    p.rec.event("freeifaddrs", 0).emit();
    p.check("getifaddrs succeeds", result == 0);
    p.check(
        "lo's AF_INET entry: 127.0.0.1/255.0.0.0, the flags SIOCGIFFLAGS reports",
        inet == Some((
            Some(Ipv4Addr::LOCALHOST),
            Some(Ipv4Addr::new(255, 0, 0, 0)),
            u32::from(flags.flags) & LOOPBACK_FLAGS,
        )) && u32::from(flags.flags) & LOOPBACK_FLAGS == LOOPBACK_FLAGS,
    );
    p.check(
        "lo's AF_PACKET entry: the SIOCGIFINDEX index, ARPHRD_LOOPBACK, six bytes, statistics",
        packet == Some((index.index, ARPHRD_LOOPBACK, 6, true)),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "net/getifaddrs",
    run,
    vehicles: &[Vehicle::Libc],
    covers: &[Syscall::N_socket, Syscall::N_ioctl, Syscall::N_close],
    symbols: &["getifaddrs", "freeifaddrs", "socket", "ioctl", "close"],
    ..DEFAULTS
};
