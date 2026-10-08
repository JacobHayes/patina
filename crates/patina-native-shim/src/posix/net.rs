//! Socket libc doors project the shared typed cores after preserving delivery order.

#![deny(clippy::undocumented_unsafe_blocks)]

use super::cancel;
use crate::thread::net;
use core::ffi::{c_char, c_int, c_void};
mod gai;
#[cfg(target_os = "linux")]
mod interfaces;

#[unsafe(no_mangle)]
pub extern "C" fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::abi::libc_delivered(net::socket(domain, ty, protocol), -1) as c_int
}
#[unsafe(no_mangle)]
pub extern "C" fn socketpair(domain: c_int, ty: c_int, protocol: c_int, sv: *mut c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::abi::libc_delivered(net::socketpair(domain, ty, protocol, sv as usize), -1) as c_int
}
#[unsafe(no_mangle)]
pub extern "C" fn bind(fd: c_int, addr: *const libc::sockaddr, len: libc::socklen_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::abi::libc_delivered(
        net::bind(
            fd,
            addr as usize,
            i64::from(crate::abi::kernel_int(len as usize)),
        ),
        -1,
    ) as c_int
}
#[unsafe(no_mangle)]
pub extern "C" fn connect(fd: c_int, addr: *const libc::sockaddr, len: libc::socklen_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"connect");
    crate::abi::libc_delivered(
        net::connect(
            fd,
            addr as usize,
            i64::from(crate::abi::kernel_int(len as usize)),
        ),
        -1,
    ) as c_int
}
#[unsafe(no_mangle)]
pub extern "C" fn listen(fd: c_int, backlog: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::abi::libc_delivered(net::listen(fd, backlog), -1) as c_int
}
#[unsafe(no_mangle)]
pub extern "C" fn accept(fd: c_int, addr: *mut libc::sockaddr, len: *mut libc::socklen_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"accept");
    crate::abi::libc_delivered(net::accept(fd, addr as usize, len as usize, 0), -1) as c_int
}
#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub extern "C" fn accept4(
    fd: c_int,
    addr: *mut libc::sockaddr,
    len: *mut libc::socklen_t,
    flags: c_int,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"accept4");
    crate::abi::libc_delivered(net::accept(fd, addr as usize, len as usize, flags), -1) as c_int
}
#[unsafe(no_mangle)]
pub extern "C" fn getsockname(
    fd: c_int,
    addr: *mut libc::sockaddr,
    len: *mut libc::socklen_t,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::abi::libc_delivered(net::name(fd, addr as usize, len as usize, 0), -1) as c_int
}
#[unsafe(no_mangle)]
pub extern "C" fn getpeername(
    fd: c_int,
    addr: *mut libc::sockaddr,
    len: *mut libc::socklen_t,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::abi::libc_delivered(net::name(fd, addr as usize, len as usize, 1), -1) as c_int
}
#[unsafe(no_mangle)]
pub extern "C" fn shutdown(fd: c_int, how: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::abi::libc_delivered(net::shutdown(fd, how), -1) as c_int
}
#[unsafe(no_mangle)]
pub extern "C" fn setsockopt(
    fd: c_int,
    level: c_int,
    optname: c_int,
    value: *const c_void,
    len: libc::socklen_t,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::abi::libc_delivered(
        net::setsockopt(
            fd,
            level,
            optname,
            value as usize,
            i64::from(crate::abi::kernel_int(len as usize)),
        ),
        -1,
    ) as c_int
}
#[unsafe(no_mangle)]
pub extern "C" fn getsockopt(
    fd: c_int,
    level: c_int,
    optname: c_int,
    value: *mut c_void,
    len: *mut libc::socklen_t,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::abi::libc_delivered(
        net::getsockopt(fd, level, optname, value as usize, len as usize),
        -1,
    ) as c_int
}
#[unsafe(no_mangle)]
pub extern "C" fn sendto(
    fd: c_int,
    buf: *const c_void,
    len: usize,
    flags: c_int,
    addr: *const libc::sockaddr,
    alen: libc::socklen_t,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"sendto");
    crate::abi::libc_delivered(
        net::sendto(
            fd,
            buf as usize,
            len,
            flags,
            addr as usize,
            i64::from(crate::abi::kernel_int(alen as usize)),
        ),
        -1,
    ) as isize
}
#[unsafe(no_mangle)]
pub extern "C" fn send(fd: c_int, buf: *const c_void, len: usize, flags: c_int) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"send");
    crate::abi::libc_delivered(net::sendto(fd, buf as usize, len, flags, 0, 0), -1) as isize
}
#[unsafe(no_mangle)]
pub extern "C" fn recvfrom(
    fd: c_int,
    buf: *mut c_void,
    len: usize,
    flags: c_int,
    addr: *mut libc::sockaddr,
    alen: *mut libc::socklen_t,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"recvfrom");
    crate::abi::libc_delivered(
        net::recvfrom(fd, buf as usize, len, flags, addr as usize, alen as usize),
        -1,
    ) as isize
}
#[unsafe(no_mangle)]
pub extern "C" fn recv(fd: c_int, buf: *mut c_void, len: usize, flags: c_int) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"recv");
    crate::abi::libc_delivered(net::recvfrom(fd, buf as usize, len, flags, 0, 0), -1) as isize
}
#[unsafe(no_mangle)]
pub extern "C" fn sendmsg(fd: c_int, msg: *const libc::msghdr, flags: c_int) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"sendmsg");
    crate::abi::libc_delivered(net::msg::sendmsg(fd, msg as usize, flags), -1) as isize
}
#[unsafe(no_mangle)]
pub extern "C" fn recvmsg(fd: c_int, msg: *mut libc::msghdr, flags: c_int) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"recvmsg");
    crate::abi::libc_delivered(net::msg::recvmsg(fd, msg as usize, flags), -1) as isize
}
#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub extern "C" fn sendmmsg(
    fd: c_int,
    vec: *mut libc::mmsghdr,
    vlen: libc::c_uint,
    flags: c_int,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"sendmmsg");
    crate::abi::libc_delivered(net::msg::sendmmsg(fd, vec as usize, vlen, flags), -1) as c_int
}
#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub extern "C" fn recvmmsg(
    fd: c_int,
    vec: *mut libc::mmsghdr,
    vlen: libc::c_uint,
    flags: c_int,
    timeout: *mut libc::timespec,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"recvmmsg");
    crate::abi::libc_delivered(
        net::msg::recvmmsg(fd, vec as usize, vlen, flags, timeout as usize),
        -1,
    ) as c_int
}
#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub extern "C" fn __recv_chk(
    fd: c_int,
    buf: *mut c_void,
    len: usize,
    buflen: usize,
    flags: c_int,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"__recv_chk");
    if len > buflen {
        super::chk_fail();
    }
    crate::abi::libc_delivered(net::recvfrom(fd, buf as usize, len, flags, 0, 0), -1) as isize
}
#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub extern "C" fn __recvfrom_chk(
    fd: c_int,
    buf: *mut c_void,
    len: usize,
    buflen: usize,
    flags: c_int,
    addr: *mut libc::sockaddr,
    alen: *mut libc::socklen_t,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"__recvfrom_chk");
    if len > buflen {
        super::chk_fail();
    }
    crate::abi::libc_delivered(
        net::recvfrom(fd, buf as usize, len, flags, addr as usize, alen as usize),
        -1,
    ) as isize
}
/// # Safety
/// Buffers follow the corresponding libc function's valid-buffer contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn if_nametoindex(ifname: *const c_char) -> libc::c_uint {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: each successful query initializes the output, and the caller supplies a valid C string for this call.
    unsafe {
        let mut interface = core::mem::MaybeUninit::<net::iface::PatinaInterface>::uninit();
        let mut at = 0;
        while net::iface::patina_net_interface(at, interface.as_mut_ptr()) == 0 {
            if libc::strncmp((*interface.as_ptr()).name.as_ptr().cast(), ifname, 16) == 0 {
                return (*interface.as_ptr()).index;
            }
            at += 1;
        }
        #[cfg(target_os = "linux")]
        super::errno(libc::ENODEV);
        #[cfg(target_os = "macos")]
        super::errno(libc::ENXIO);
        0
    }
}
