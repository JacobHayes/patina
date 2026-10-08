//! Socket adapters preserve signed kernel results and signal-before-errno order.
use super::cancel;
use crate::thread::net;
use core::ffi::{c_char, c_int, c_void};
mod gai;
#[cfg(target_os = "linux")]
mod interfaces;

fn socket_result(rc: i64) -> isize {
    #[cfg(target_os = "linux")]
    crate::thread::signals::patina_signal_deliver();
    if rc < 0 {
        super::errno(-rc as c_int);
        -1
    } else {
        rc as isize
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    socket_result(net::patina_sock_socket(domain, ty, protocol)) as c_int
}
#[unsafe(no_mangle)]
pub extern "C" fn socketpair(domain: c_int, ty: c_int, protocol: c_int, sv: *mut c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    socket_result(net::patina_sock_socketpair(
        domain,
        ty,
        protocol,
        sv as usize,
    )) as c_int
}
#[unsafe(no_mangle)]
pub extern "C" fn bind(fd: c_int, addr: *const libc::sockaddr, len: libc::socklen_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    socket_result(net::patina_sock_bind(
        fd,
        addr as usize,
        i64::from(len as i32),
    )) as c_int
}
#[unsafe(no_mangle)]
pub extern "C" fn connect(fd: c_int, addr: *const libc::sockaddr, len: libc::socklen_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"connect");
    socket_result(net::patina_sock_connect(
        fd,
        addr as usize,
        i64::from(len as i32),
    )) as c_int
}
#[unsafe(no_mangle)]
pub extern "C" fn listen(fd: c_int, backlog: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    socket_result(net::patina_sock_listen(fd, backlog)) as c_int
}
#[unsafe(no_mangle)]
pub extern "C" fn accept(fd: c_int, addr: *mut libc::sockaddr, len: *mut libc::socklen_t) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"accept");
    socket_result(net::patina_sock_accept(fd, addr as usize, len as usize, 0)) as c_int
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
    socket_result(net::patina_sock_accept(
        fd,
        addr as usize,
        len as usize,
        flags,
    )) as c_int
}
#[unsafe(no_mangle)]
pub extern "C" fn getsockname(
    fd: c_int,
    addr: *mut libc::sockaddr,
    len: *mut libc::socklen_t,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    socket_result(net::patina_sock_name(fd, addr as usize, len as usize, 0)) as c_int
}
#[unsafe(no_mangle)]
pub extern "C" fn getpeername(
    fd: c_int,
    addr: *mut libc::sockaddr,
    len: *mut libc::socklen_t,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    socket_result(net::patina_sock_name(fd, addr as usize, len as usize, 1)) as c_int
}
#[unsafe(no_mangle)]
pub extern "C" fn shutdown(fd: c_int, how: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    socket_result(net::patina_sock_shutdown(fd, how)) as c_int
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
    socket_result(net::patina_sock_setsockopt(
        fd,
        level,
        optname,
        value as usize,
        i64::from(len as i32),
    )) as c_int
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
    socket_result(net::patina_sock_getsockopt(
        fd,
        level,
        optname,
        value as usize,
        len as usize,
    )) as c_int
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
    socket_result(net::patina_sock_sendto(
        fd,
        buf as usize,
        len,
        flags,
        addr as usize,
        i64::from(alen as i32),
    ))
}
#[unsafe(no_mangle)]
pub extern "C" fn send(fd: c_int, buf: *const c_void, len: usize, flags: c_int) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"send");
    socket_result(net::patina_sock_sendto(fd, buf as usize, len, flags, 0, 0))
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
    socket_result(net::patina_sock_recvfrom(
        fd,
        buf as usize,
        len,
        flags,
        addr as usize,
        alen as usize,
    ))
}
#[unsafe(no_mangle)]
pub extern "C" fn recv(fd: c_int, buf: *mut c_void, len: usize, flags: c_int) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"recv");
    socket_result(net::patina_sock_recvfrom(
        fd,
        buf as usize,
        len,
        flags,
        0,
        0,
    ))
}
#[unsafe(no_mangle)]
pub extern "C" fn sendmsg(fd: c_int, msg: *const libc::msghdr, flags: c_int) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"sendmsg");
    socket_result(net::msg::patina_sock_sendmsg(fd, msg as usize, flags))
}
#[unsafe(no_mangle)]
pub extern "C" fn recvmsg(fd: c_int, msg: *mut libc::msghdr, flags: c_int) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"recvmsg");
    socket_result(net::msg::patina_sock_recvmsg(fd, msg as usize, flags))
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
    socket_result(net::msg::patina_sock_sendmmsg(
        fd,
        vec as usize,
        vlen,
        flags,
    )) as c_int
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
    socket_result(net::msg::patina_sock_recvmmsg(
        fd,
        vec as usize,
        vlen,
        flags,
        timeout as usize,
    )) as c_int
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
    socket_result(net::patina_sock_recvfrom(
        fd,
        buf as usize,
        len,
        flags,
        0,
        0,
    ))
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
    socket_result(net::patina_sock_recvfrom(
        fd,
        buf as usize,
        len,
        flags,
        addr as usize,
        alen as usize,
    ))
}
/// # Safety
/// Buffers follow the corresponding libc function's valid-buffer contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn if_nametoindex(ifname: *const c_char) -> libc::c_uint {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
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
