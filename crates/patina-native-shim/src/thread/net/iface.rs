//! The virtual host's interfaces (`patina_dst_driver_api::VIRTUAL_INTERFACES`:
//! `lo` and `eth0`) through the kernel's interface requests
//! (net/core/dev_ioctl.c `dev_ioctl`, `dev_ifconf`; net/ipv4/devinet.c
//! `devinet_ioctl`, `inet_gifconf`) and the record `getifaddrs` builds its
//! list from.

#[cfg(target_os = "linux")]
use std::ffi::c_int;

use patina_dst_driver_api::{NetInterface, VIRTUAL_INTERFACES};

#[cfg(target_os = "linux")]
use super::abi::*;
use crate::EINVAL;
use crate::uaccess;
#[cfg(target_os = "linux")]
use crate::{ENODEV, EPERM};

pub(crate) fn by_name(name: &str) -> Option<&'static NetInterface> {
    VIRTUAL_INTERFACES
        .iter()
        .find(|interface| interface.name == name)
}

#[cfg(target_os = "linux")]
pub(crate) fn by_index(index: u32) -> Option<&'static NetInterface> {
    VIRTUAL_INTERFACES
        .iter()
        .find(|interface| interface.index == index)
}

/// The interface requests (`include/uapi/linux/sockios.h`).
#[cfg(target_os = "linux")]
mod request {
    pub(super) const SIOCGIFNAME: u64 = 0x8910;
    pub(super) const SIOCGIFCONF: u64 = 0x8912;
    pub(super) const SIOCGIFFLAGS: u64 = 0x8913;
    pub(super) const SIOCSIFFLAGS: u64 = 0x8914;
    pub(super) const SIOCGIFADDR: u64 = 0x8915;
    pub(super) const SIOCSIFADDR: u64 = 0x8916;
    pub(super) const SIOCGIFDSTADDR: u64 = 0x8917;
    pub(super) const SIOCGIFBRDADDR: u64 = 0x8919;
    pub(super) const SIOCGIFNETMASK: u64 = 0x891b;
    pub(super) const SIOCGIFMETRIC: u64 = 0x891d;
    pub(super) const SIOCGIFMTU: u64 = 0x8921;
    pub(super) const SIOCSIFMTU: u64 = 0x8922;
    pub(super) const SIOCGIFHWADDR: u64 = 0x8927;
    pub(super) const SIOCGIFINDEX: u64 = 0x8933;
    pub(super) const SIOCGIFTXQLEN: u64 = 0x8942;
}

/// `struct ifreq`: the name, then a 24-byte union.
#[cfg(target_os = "linux")]
const IFREQ: usize = 40;
/// A device's transmit queue length (`tx_queue_len`, the default).
#[cfg(target_os = "linux")]
pub(crate) const TXQLEN: u32 = 1000;

/// An `ioctl` on a socket that names an interface: `None` when `request` is
/// no interface request.
#[cfg(target_os = "linux")]
pub(crate) fn ioctl(family: i32, request: u64, arg: usize) -> Option<Result<(), c_int>> {
    use request::*;
    let result = match request {
        SIOCGIFCONF => ifconf(arg),
        SIOCGIFNAME | SIOCGIFFLAGS | SIOCGIFMETRIC | SIOCGIFMTU | SIOCGIFHWADDR | SIOCGIFINDEX
        | SIOCGIFTXQLEN => device_request(request, arg),
        SIOCGIFADDR | SIOCGIFDSTADDR | SIOCGIFBRDADDR | SIOCGIFNETMASK if family == AF_INET => {
            address_request(request, arg)
        }
        // Configuring an interface needs CAP_NET_ADMIN.
        SIOCSIFFLAGS | SIOCSIFADDR | SIOCSIFMTU => Err(EPERM),
        _ => return None,
    };
    Some(result)
}

/// The `ifreq` at `arg`, its name up to the first NUL or colon (an alias).
#[cfg(target_os = "linux")]
fn ifreq(arg: usize) -> Result<([u8; IFREQ], String), c_int> {
    let mut ifr: [u8; IFREQ] = uaccess::read(arg)?;
    ifr[IFNAMSIZ - 1] = 0;
    let end = ifr[..IFNAMSIZ]
        .iter()
        .position(|byte| *byte == 0 || *byte == b':')
        .unwrap_or(IFNAMSIZ);
    Ok((ifr, String::from_utf8_lossy(&ifr[..end]).into_owned()))
}

/// `dev_ifname` and `dev_ifsioc_locked`: the requests any socket answers.
#[cfg(target_os = "linux")]
fn device_request(request: u64, arg: usize) -> Result<(), c_int> {
    use request::*;
    let (mut ifr, name) = ifreq(arg)?;
    if request == SIOCGIFNAME {
        let index = u32::from_ne_bytes(ifr[IFNAMSIZ..IFNAMSIZ + 4].try_into().unwrap());
        let interface = by_index(index).ok_or(ENODEV)?;
        ifr[..IFNAMSIZ].fill(0);
        ifr[..interface.name.len()].copy_from_slice(interface.name.as_bytes());
        return uaccess::write(arg, &ifr);
    }
    let interface = by_name(&name).ok_or(ENODEV)?;
    let value = &mut ifr[IFNAMSIZ..];
    match request {
        SIOCGIFFLAGS => value[..2].copy_from_slice(&(interface.flags as u16).to_ne_bytes()),
        SIOCGIFMETRIC => value[..4].fill(0),
        SIOCGIFMTU => value[..4].copy_from_slice(&interface.mtu.to_ne_bytes()),
        SIOCGIFINDEX => value[..4].copy_from_slice(&interface.index.to_ne_bytes()),
        SIOCGIFTXQLEN => value[..4].copy_from_slice(&TXQLEN.to_ne_bytes()),
        SIOCGIFHWADDR => {
            value[..2].copy_from_slice(&interface.hardware_type.to_ne_bytes());
            value[2..8].copy_from_slice(&interface.hardware_address);
            value[8..16].fill(0);
        }
        _ => unreachable!("device_request takes the device requests"),
    }
    uaccess::write(arg, &ifr)
}

/// `devinet_ioctl`'s reads: the interface's IPv4 address, broadcast,
/// destination (its own address on a broadcast link) or netmask.
#[cfg(target_os = "linux")]
fn address_request(request: u64, arg: usize) -> Result<(), c_int> {
    use request::*;
    let (mut ifr, name) = ifreq(arg)?;
    let interface = by_name(&name).ok_or(ENODEV)?;
    let ipv4 = interface.ipv4;
    let address = match request {
        SIOCGIFADDR | SIOCGIFDSTADDR => ipv4.address,
        // `lo`'s address carries no broadcast.
        SIOCGIFBRDADDR if interface.flags & 0x2 == 0 => [0; 4],
        SIOCGIFBRDADDR => ipv4.broadcast(),
        SIOCGIFNETMASK => ipv4.netmask(),
        _ => unreachable!("address_request takes the address requests"),
    };
    ifr[IFNAMSIZ..].fill(0);
    ifr[IFNAMSIZ..IFNAMSIZ + 16].copy_from_slice(&super::addr::encode_in(address.into(), 0));
    uaccess::write(arg, &ifr)
}

/// `dev_ifconf`: one whole `ifreq` per IPv4 address while the buffer has
/// room, or (a NULL buffer) the room they need; `ifc_len` says how much.
#[cfg(target_os = "linux")]
fn ifconf(arg: usize) -> Result<(), c_int> {
    let header: [u8; 16] = uaccess::read(arg)?;
    let len = i32::from_ne_bytes(header[..4].try_into().unwrap());
    let buf = usize::from_ne_bytes(header[8..16].try_into().unwrap());
    let mut total = 0usize;
    for interface in VIRTUAL_INTERFACES {
        if buf == 0 {
            total += IFREQ;
            continue;
        }
        if (len as i64) - (total as i64) < IFREQ as i64 {
            break;
        }
        let mut ifr = [0u8; IFREQ];
        ifr[..interface.name.len()].copy_from_slice(interface.name.as_bytes());
        ifr[IFNAMSIZ..IFNAMSIZ + 16]
            .copy_from_slice(&super::addr::encode_in(interface.ipv4.address.into(), 0));
        uaccess::write(buf + total, &ifr)?;
        total += IFREQ;
    }
    uaccess::write(arg, &(total as i32))
}

/// One interface as `getifaddrs` reads it (`struct patina_interface` in
/// `include/patina_native.h`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PatinaInterface {
    pub index: u32,
    pub flags: u32,
    pub mtu: u32,
    pub hardware_type: u16,
    pub name: [u8; 16],
    pub hardware_address: [u8; 6],
    pub broadcast_hardware_address: [u8; 6],
    pub ipv4: [u8; 4],
    pub ipv4_netmask: [u8; 4],
    /// Zero for an interface without broadcast (`lo`).
    pub ipv4_broadcast: [u8; 4],
    pub has_ipv6: u8,
    pub ipv6_prefix: u8,
    pub ipv6: [u8; 16],
}

/// The `position`th interface (index order), for `getifaddrs`: 0 with the
/// record written, `-EINVAL` past the last.
///
/// # Safety
/// `out` must point to a writable `struct patina_interface`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_net_interface(position: u32, out: *mut PatinaInterface) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let Some(interface) = VIRTUAL_INTERFACES.get(position as usize) else {
        return -i64::from(EINVAL);
    };
    let mut name = [0u8; 16];
    name[..interface.name.len()].copy_from_slice(interface.name.as_bytes());
    let broadcast = interface.flags & 0x2 != 0;
    let record = PatinaInterface {
        index: interface.index,
        flags: interface.flags,
        mtu: interface.mtu,
        hardware_type: interface.hardware_type,
        name,
        hardware_address: interface.hardware_address,
        broadcast_hardware_address: interface.broadcast_hardware_address,
        ipv4: interface.ipv4.address,
        ipv4_netmask: interface.ipv4.netmask(),
        ipv4_broadcast: if broadcast {
            interface.ipv4.broadcast()
        } else {
            [0; 4]
        },
        has_ipv6: u8::from(interface.ipv6.is_some()),
        ipv6_prefix: interface.ipv6.map_or(0, |(_, prefix)| prefix),
        ipv6: interface.ipv6.map_or([0; 16], |(address, _)| address),
    };
    match uaccess::write(out as usize, &record) {
        Ok(()) => 0,
        Err(errno) => -i64::from(errno),
    }
}
