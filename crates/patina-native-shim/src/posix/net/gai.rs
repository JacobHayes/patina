//! Name resolution from numeric inputs and Patina's deterministic host table.
//! Returned lists use the guest's libc allocator, as their C predecessors do.
#![deny(clippy::undocumented_unsafe_blocks)]

use crate::thread::net::{addr, iface};
use core::ffi::{c_char, c_int};
use core::ptr::{null, null_mut};

struct GaiType {
    socktype: c_int,
    protocol: c_int,
    any_protocol: bool,
    no_service: bool,
}
const TYPES: &[GaiType] = &[
    GaiType {
        socktype: libc::SOCK_STREAM,
        protocol: libc::IPPROTO_TCP,
        any_protocol: false,
        no_service: false,
    },
    GaiType {
        socktype: libc::SOCK_DGRAM,
        protocol: libc::IPPROTO_UDP,
        any_protocol: false,
        no_service: false,
    },
    #[cfg(target_os = "linux")]
    GaiType {
        socktype: libc::SOCK_DCCP,
        protocol: libc::IPPROTO_DCCP,
        any_protocol: false,
        no_service: true,
    },
    #[cfg(target_os = "linux")]
    GaiType {
        socktype: libc::SOCK_DGRAM,
        protocol: libc::IPPROTO_UDPLITE,
        any_protocol: false,
        no_service: false,
    },
    #[cfg(target_os = "linux")]
    GaiType {
        socktype: libc::SOCK_STREAM,
        protocol: libc::IPPROTO_SCTP,
        any_protocol: false,
        no_service: false,
    },
    #[cfg(target_os = "linux")]
    GaiType {
        socktype: libc::SOCK_SEQPACKET,
        protocol: libc::IPPROTO_SCTP,
        any_protocol: false,
        no_service: false,
    },
    GaiType {
        socktype: libc::SOCK_RAW,
        protocol: 0,
        any_protocol: true,
        no_service: true,
    },
];
#[derive(Clone, Copy, Default)]
struct Address {
    family: c_int,
    bytes: [u8; 16],
    scope: u32,
}

unsafe fn configured(family: c_int) -> bool {
    // SAFETY: `patina_net_interface` initializes the output before returning 0, which is checked before `assume_init`.
    unsafe {
        let mut interface = core::mem::MaybeUninit::<iface::PatinaInterface>::uninit();
        let mut at = 0;
        while iface::patina_net_interface(at, interface.as_mut_ptr()) == 0 {
            at += 1;
            let interface = interface.assume_init();
            if interface.flags & libc::IFF_LOOPBACK as u32 != 0 {
                continue;
            }
            if family == libc::AF_INET || interface.has_ipv6 != 0 {
                return true;
            }
        }
        false
    }
}
unsafe fn make_node(
    address: &Address,
    port: u16,
    socktype: c_int,
    protocol: c_int,
    canonical: *const c_char,
) -> *mut libc::addrinfo {
    // SAFETY: allocations are checked before dereference, and `address` and `canonical` satisfy the caller's read contract.
    unsafe {
        let node = libc::calloc(1, size_of::<libc::addrinfo>()).cast::<libc::addrinfo>();
        if node.is_null() {
            return null_mut();
        }
        (*node).ai_family = address.family;
        (*node).ai_socktype = socktype;
        (*node).ai_protocol = protocol;
        if address.family == libc::AF_INET {
            let ip = libc::calloc(1, size_of::<libc::sockaddr_in>()).cast::<libc::sockaddr_in>();
            if ip.is_null() {
                libc::free(node.cast());
                return null_mut();
            }
            #[cfg(target_os = "macos")]
            {
                (*ip).sin_len = size_of::<libc::sockaddr_in>() as u8;
            }
            (*ip).sin_family = libc::AF_INET as libc::sa_family_t;
            (*ip).sin_port = port.to_be();
            core::ptr::copy_nonoverlapping(
                address.bytes.as_ptr(),
                core::ptr::addr_of_mut!((*ip).sin_addr).cast(),
                4,
            );
            (*node).ai_addr = ip.cast();
            (*node).ai_addrlen = size_of::<libc::sockaddr_in>() as libc::socklen_t;
        } else {
            let ip = libc::calloc(1, size_of::<libc::sockaddr_in6>()).cast::<libc::sockaddr_in6>();
            if ip.is_null() {
                libc::free(node.cast());
                return null_mut();
            }
            #[cfg(target_os = "macos")]
            {
                (*ip).sin6_len = size_of::<libc::sockaddr_in6>() as u8;
            }
            (*ip).sin6_family = libc::AF_INET6 as libc::sa_family_t;
            (*ip).sin6_port = port.to_be();
            core::ptr::copy_nonoverlapping(
                address.bytes.as_ptr(),
                core::ptr::addr_of_mut!((*ip).sin6_addr).cast(),
                16,
            );
            (*ip).sin6_scope_id = address.scope;
            (*node).ai_addr = ip.cast();
            (*node).ai_addrlen = size_of::<libc::sockaddr_in6>() as libc::socklen_t;
        }
        if !canonical.is_null() {
            let bytes = libc::strlen(canonical) + 1;
            (*node).ai_canonname = libc::malloc(bytes).cast();
            if (*node).ai_canonname.is_null() {
                libc::free((*node).ai_addr.cast());
                libc::free(node.cast());
                return null_mut();
            }
            core::ptr::copy_nonoverlapping(canonical, (*node).ai_canonname, bytes);
        }
        node
    }
}
unsafe fn free_list(mut res: *mut libc::addrinfo) {
    // SAFETY: `res` is null or a complete list whose nodes and members are libc allocations.
    unsafe {
        while !res.is_null() {
            let next = (*res).ai_next;
            libc::free((*res).ai_addr.cast());
            libc::free((*res).ai_canonname.cast());
            libc::free(res.cast());
            res = next;
        }
    }
}
/// # Safety
/// `res` is null or a complete list returned by getaddrinfo.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn freeaddrinfo(res: *mut libc::addrinfo) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the caller guarantees null or a complete list returned by getaddrinfo.
    unsafe {
        free_list(res);
    }
}
unsafe fn parse_port(mut service: *const c_char) -> c_int {
    // SAFETY: callers pass null or a valid NUL-terminated service string before this helper is called.
    unsafe {
        if *service == 0 {
            return -1;
        }
        let mut parsed = 0u64;
        while *service != 0 {
            if *service < b'0' as c_char || *service > b'9' as c_char {
                return -1;
            }
            parsed = parsed * 10 + (*service - b'0' as c_char) as u64;
            if parsed > 65535 {
                return -1;
            }
            service = service.add(1);
        }
        parsed as c_int
    }
}
fn v4mapped(address: &mut Address) {
    let v4 = [
        address.bytes[0],
        address.bytes[1],
        address.bytes[2],
        address.bytes[3],
    ];
    address.bytes[..10].fill(0);
    address.bytes[10] = 0xff;
    address.bytes[11] = 0xff;
    address.bytes[12..].copy_from_slice(&v4);
    address.family = libc::AF_INET6;
}
/// # Safety
/// Strings are null or terminated; hints is null or readable, res writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getaddrinfo(
    node: *const c_char,
    service: *const c_char,
    hints: *const libc::addrinfo,
    res: *mut *mut libc::addrinfo,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the documented contract makes `hints` readable and `res` writable; non-null strings are NUL-terminated.
    unsafe {
        let no_hints = core::mem::MaybeUninit::<libc::addrinfo>::zeroed();
        let hints = if hints.is_null() {
            no_hints.as_ptr()
        } else {
            hints
        };
        let family = (*hints).ai_family;
        let flags = (*hints).ai_flags;
        #[cfg(target_os = "linux")]
        {
            // glibc's IDN flags are absent from libc's bindings. They are
            // recognized here exactly as by the previous C adapter.
            const AI_IDN: c_int = 0x40;
            const AI_CANONIDN: c_int = 0x80;
            let known = libc::AI_PASSIVE
                | libc::AI_CANONNAME
                | libc::AI_NUMERICHOST
                | libc::AI_ADDRCONFIG
                | libc::AI_V4MAPPED
                | libc::AI_NUMERICSERV
                | libc::AI_ALL
                | AI_IDN
                | AI_CANONIDN
                | 0x100
                | 0x200;
            if flags & !known != 0 {
                return libc::EAI_BADFLAGS;
            }
        }
        if flags & libc::AI_CANONNAME != 0 && node.is_null() {
            return libc::EAI_BADFLAGS;
        }
        if family != libc::AF_UNSPEC && family != libc::AF_INET && family != libc::AF_INET6 {
            return libc::EAI_FAMILY;
        }
        if node.is_null() && service.is_null() {
            return libc::EAI_NONAME;
        }
        let only = if (*hints).ai_socktype != 0 || (*hints).ai_protocol != 0 {
            let found = TYPES.iter().position(|ty| {
                ((*hints).ai_socktype == 0 || (*hints).ai_socktype == ty.socktype)
                    && ((*hints).ai_protocol == 0
                        || ty.any_protocol
                        || (*hints).ai_protocol == ty.protocol)
            });
            let Some(index) = found else {
                return if (*hints).ai_socktype != 0 {
                    libc::EAI_SOCKTYPE
                } else {
                    libc::EAI_SERVICE
                };
            };
            if !service.is_null() && TYPES[index].no_service {
                return libc::EAI_SERVICE;
            }
            Some(index)
        } else {
            None
        };
        let port = if service.is_null() {
            0
        } else {
            let parsed = parse_port(service);
            if parsed < 0 {
                return if flags & libc::AI_NUMERICSERV != 0 {
                    libc::EAI_NONAME
                } else {
                    libc::EAI_SERVICE
                };
            }
            parsed as u16
        };
        let mut addresses = [Address::default(); 2];
        let mut count = 0;
        if node.is_null() {
            let mut four = Address {
                family: libc::AF_INET,
                ..Address::default()
            };
            let mut six = Address {
                family: libc::AF_INET6,
                ..Address::default()
            };
            if flags & libc::AI_PASSIVE == 0 {
                four.bytes[..4].copy_from_slice(&[127, 0, 0, 1]);
                six.bytes[15] = 1;
            }
            let passive = flags & libc::AI_PASSIVE != 0;
            if family != libc::AF_INET && !passive {
                addresses[count] = six;
                count += 1;
            }
            if family != libc::AF_INET6 {
                addresses[count] = four;
                count += 1;
            }
            if family != libc::AF_INET && passive {
                addresses[count] = six;
                count += 1;
            }
        } else {
            let mut address = Address::default();
            address.family = addr::patina_net_numeric_host(
                node,
                address.bytes.as_mut_ptr(),
                &raw mut address.scope,
            );
            if address.family == 0 {
                if flags & libc::AI_NUMERICHOST != 0 {
                    return libc::EAI_NONAME;
                }
                let mut ip = 0u32;
                if crate::thread::patina_dns_resolve(node, &raw mut ip) != 0 {
                    return if crate::patina_errno() == libc::EINTR {
                        libc::EAI_AGAIN
                    } else {
                        libc::EAI_NONAME
                    };
                }
                address.family = libc::AF_INET;
                address.bytes[..4].copy_from_slice(&ip.to_be_bytes());
                if family == libc::AF_INET6 {
                    if flags & libc::AI_V4MAPPED == 0 {
                        return libc::EAI_NONAME;
                    }
                    v4mapped(&mut address);
                }
            } else if family != libc::AF_UNSPEC && family != address.family {
                if family == libc::AF_INET6 && flags & libc::AI_V4MAPPED != 0 {
                    v4mapped(&mut address);
                } else {
                    #[cfg(target_os = "linux")]
                    {
                        return -9;
                    } // EAI_ADDRFAMILY, absent from libc bindings.
                    #[cfg(target_os = "macos")]
                    {
                        return 1;
                    } // EAI_ADDRFAMILY in Darwin netdb.h.
                }
            }
            addresses[count] = address;
            count += 1;
        }
        if flags & libc::AI_ADDRCONFIG != 0 {
            let mut kept = 0;
            for at in 0..count {
                if configured(addresses[at].family) {
                    addresses[kept] = addresses[at];
                    kept += 1;
                }
            }
            count = kept;
            if count == 0 {
                return libc::EAI_NONAME;
            }
        }
        let mut head: *mut libc::addrinfo = null_mut();
        let mut tail = &raw mut head;
        let mut canonical = if flags & libc::AI_CANONNAME != 0 {
            node
        } else {
            null()
        };
        for address in &addresses[..count] {
            for (index, ty) in TYPES.iter().enumerate() {
                let (socktype, protocol) = if let Some(only) = only {
                    if index != only {
                        continue;
                    }
                    (
                        ty.socktype,
                        if ty.any_protocol {
                            (*hints).ai_protocol
                        } else {
                            ty.protocol
                        },
                    )
                } else {
                    if ty.protocol != libc::IPPROTO_TCP
                        && ty.protocol != libc::IPPROTO_UDP
                        && ty.socktype != libc::SOCK_RAW
                    {
                        continue;
                    }
                    (ty.socktype, ty.protocol)
                };
                let made = make_node(address, port, socktype, protocol, canonical);
                if made.is_null() {
                    free_list(head);
                    return libc::EAI_MEMORY;
                }
                canonical = null();
                *tail = made;
                tail = core::ptr::addr_of_mut!((*made).ai_next);
            }
        }
        *res = head;
        0
    }
}
