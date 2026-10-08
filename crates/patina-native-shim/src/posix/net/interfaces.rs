//! libc-owned getifaddrs allocation, with the virtual interface table.
#![deny(clippy::undocumented_unsafe_blocks)]

use crate::thread::net::iface;
use core::ffi::{c_char, c_int};

#[repr(C)]
struct LinkStats {
    rx_packets: u32,
    tx_packets: u32,
    rx_bytes: u32,
    tx_bytes: u32,
    rx_errors: u32,
    tx_errors: u32,
    rx_dropped: u32,
    tx_dropped: u32,
    multicast: u32,
    collisions: u32,
    rx_length_errors: u32,
    rx_over_errors: u32,
    rx_crc_errors: u32,
    rx_frame_errors: u32,
    rx_fifo_errors: u32,
    rx_missed_errors: u32,
    tx_aborted_errors: u32,
    tx_carrier_errors: u32,
    tx_fifo_errors: u32,
    tx_heartbeat_errors: u32,
    tx_window_errors: u32,
    rx_compressed: u32,
    tx_compressed: u32,
    rx_nohandler: u32,
}
const _: () = {
    assert!(size_of::<LinkStats>() == 96);
    assert!(core::mem::offset_of!(LinkStats, rx_packets) == 0);
    assert!(core::mem::offset_of!(LinkStats, tx_packets) == 4);
    assert!(core::mem::offset_of!(LinkStats, rx_bytes) == 8);
    assert!(core::mem::offset_of!(LinkStats, tx_bytes) == 12);
    assert!(core::mem::offset_of!(LinkStats, rx_errors) == 16);
    assert!(core::mem::offset_of!(LinkStats, tx_errors) == 20);
    assert!(core::mem::offset_of!(LinkStats, rx_dropped) == 24);
    assert!(core::mem::offset_of!(LinkStats, tx_dropped) == 28);
    assert!(core::mem::offset_of!(LinkStats, multicast) == 32);
    assert!(core::mem::offset_of!(LinkStats, collisions) == 36);
    assert!(core::mem::offset_of!(LinkStats, rx_length_errors) == 40);
    assert!(core::mem::offset_of!(LinkStats, rx_over_errors) == 44);
    assert!(core::mem::offset_of!(LinkStats, rx_crc_errors) == 48);
    assert!(core::mem::offset_of!(LinkStats, rx_frame_errors) == 52);
    assert!(core::mem::offset_of!(LinkStats, rx_fifo_errors) == 56);
    assert!(core::mem::offset_of!(LinkStats, rx_missed_errors) == 60);
    assert!(core::mem::offset_of!(LinkStats, tx_aborted_errors) == 64);
    assert!(core::mem::offset_of!(LinkStats, tx_carrier_errors) == 68);
    assert!(core::mem::offset_of!(LinkStats, tx_fifo_errors) == 72);
    assert!(core::mem::offset_of!(LinkStats, tx_heartbeat_errors) == 76);
    assert!(core::mem::offset_of!(LinkStats, tx_window_errors) == 80);
    assert!(core::mem::offset_of!(LinkStats, rx_compressed) == 84);
    assert!(core::mem::offset_of!(LinkStats, tx_compressed) == 88);
    assert!(core::mem::offset_of!(LinkStats, rx_nohandler) == 92);
};

#[repr(C)]
union Address {
    ll: libc::sockaddr_ll,
    ip: libc::sockaddr_in,
    ip6: libc::sockaddr_in6,
}
#[repr(C)]
struct Entry {
    ifa: libc::ifaddrs,
    addr: Address,
    netmask: Address,
    broadcast: Address,
    name: [c_char; libc::IF_NAMESIZE],
    stats: LinkStats,
}

fn prefix(mask: &mut [u8; 16], mut prefix: u32) {
    for byte in mask {
        let bits = prefix.min(8);
        *byte = (0xff00u32 >> bits) as u8;
        prefix -= bits;
    }
}
/// # Safety
/// `out` is writable for a list pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getifaddrs(out: *mut *mut libc::ifaddrs) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: `out` is caller-writable, successful interface queries initialize their entries, and `calloc` holds the counted `Entry` list.
    unsafe {
        let mut interfaces = [core::mem::MaybeUninit::<iface::PatinaInterface>::uninit(); 8];
        let mut count = 0;
        let mut entries = 0;
        while count < interfaces.len()
            && iface::patina_net_interface(count as u32, interfaces[count].as_mut_ptr()) == 0
        {
            entries += 2 + usize::from((*interfaces[count].as_ptr()).has_ipv6 != 0);
            count += 1;
        }
        let list = libc::calloc(entries, size_of::<Entry>()).cast::<Entry>();
        if list.is_null() {
            return crate::posix::error(libc::ENOMEM);
        }
        let mut at = 0;
        for pass in 0..3 {
            for interface in &interfaces[..count] {
                let interface = interface.assume_init_ref();
                if pass == 2 && interface.has_ipv6 == 0 {
                    continue;
                }
                let entry = list.add(at);
                core::ptr::copy_nonoverlapping(
                    interface.name.as_ptr().cast::<c_char>(),
                    core::ptr::addr_of_mut!((*entry).name).cast(),
                    libc::IF_NAMESIZE,
                );
                (*entry).name[libc::IF_NAMESIZE - 1] = 0;
                (*entry).ifa.ifa_name = core::ptr::addr_of_mut!((*entry).name).cast();
                (*entry).ifa.ifa_flags = interface.flags;
                (*entry).ifa.ifa_addr = core::ptr::addr_of_mut!((*entry).addr).cast();
                if pass == 0 {
                    let ll = core::ptr::addr_of_mut!((*entry).addr.ll);
                    (*ll).sll_family = libc::AF_PACKET as libc::c_ushort;
                    (*ll).sll_ifindex = interface.index as c_int;
                    (*ll).sll_hatype = interface.hardware_type;
                    (*ll).sll_halen = 6;
                    core::ptr::copy_nonoverlapping(
                        interface.hardware_address.as_ptr(),
                        core::ptr::addr_of_mut!((*ll).sll_addr).cast(),
                        6,
                    );
                    (*entry).broadcast.ll = *ll;
                    core::ptr::copy_nonoverlapping(
                        interface.broadcast_hardware_address.as_ptr(),
                        core::ptr::addr_of_mut!((*entry).broadcast.ll.sll_addr).cast(),
                        6,
                    );
                    (*entry).ifa.ifa_ifu = core::ptr::addr_of_mut!((*entry).broadcast).cast();
                    (*entry).ifa.ifa_data = core::ptr::addr_of_mut!((*entry).stats).cast();
                } else if pass == 1 {
                    (*entry).addr.ip.sin_family = libc::AF_INET as libc::sa_family_t;
                    core::ptr::copy_nonoverlapping(
                        interface.ipv4.as_ptr(),
                        core::ptr::addr_of_mut!((*entry).addr.ip.sin_addr).cast(),
                        4,
                    );
                    (*entry).netmask.ip.sin_family = libc::AF_INET as libc::sa_family_t;
                    core::ptr::copy_nonoverlapping(
                        interface.ipv4_netmask.as_ptr(),
                        core::ptr::addr_of_mut!((*entry).netmask.ip.sin_addr).cast(),
                        4,
                    );
                    (*entry).ifa.ifa_netmask = core::ptr::addr_of_mut!((*entry).netmask).cast();
                    if interface.flags & libc::IFF_BROADCAST as u32 != 0 {
                        (*entry).broadcast.ip.sin_family = libc::AF_INET as libc::sa_family_t;
                        core::ptr::copy_nonoverlapping(
                            interface.ipv4_broadcast.as_ptr(),
                            core::ptr::addr_of_mut!((*entry).broadcast.ip.sin_addr).cast(),
                            4,
                        );
                        (*entry).ifa.ifa_ifu = core::ptr::addr_of_mut!((*entry).broadcast).cast();
                    }
                } else {
                    (*entry).addr.ip6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                    core::ptr::copy_nonoverlapping(
                        interface.ipv6.as_ptr(),
                        core::ptr::addr_of_mut!((*entry).addr.ip6.sin6_addr).cast(),
                        16,
                    );
                    (*entry).netmask.ip6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                    prefix(
                        &mut (*entry).netmask.ip6.sin6_addr.s6_addr,
                        u32::from(interface.ipv6_prefix),
                    );
                    (*entry).ifa.ifa_netmask = core::ptr::addr_of_mut!((*entry).netmask).cast();
                }
                if at > 0 {
                    (*list.add(at - 1)).ifa.ifa_next = core::ptr::addr_of_mut!((*entry).ifa);
                }
                at += 1;
            }
        }
        *out = core::ptr::addr_of_mut!((*list).ifa);
        0
    }
}
/// # Safety
/// `list` is null or the allocation returned by getifaddrs.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn freeifaddrs(list: *mut libc::ifaddrs) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the caller guarantees null or the allocation returned by getifaddrs.
    unsafe {
        libc::free(list.cast());
    }
}
