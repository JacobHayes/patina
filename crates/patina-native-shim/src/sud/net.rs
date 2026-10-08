//! SUD rows — sockets. The kernel-sized operands are decoded in `bindings`
//! and these handlers call the same typed cores as the libc doors.

#![deny(clippy::undocumented_unsafe_blocks)]

use super::*;

pub(super) fn sys_socket(family: c_int, ty: c_int, protocol: c_int) -> i64 {
    crate::abi::raw(crate::thread::net::socket(family, ty, protocol))
}

pub(super) fn sys_socketpair(family: c_int, ty: c_int, protocol: c_int, sv: usize) -> i64 {
    crate::abi::raw(crate::thread::net::socketpair(family, ty, protocol, sv))
}

pub(super) fn sys_bind(fd: c_int, addr: usize, len: i64) -> i64 {
    crate::abi::raw(crate::thread::net::bind(fd, addr, len))
}

pub(super) fn sys_listen(fd: c_int, backlog: c_int) -> i64 {
    crate::abi::raw(crate::thread::net::listen(fd, backlog))
}

pub(super) fn sys_connect(fd: c_int, addr: usize, len: i64) -> i64 {
    crate::abi::raw(crate::thread::net::connect(fd, addr, len))
}

pub(super) fn sys_accept(fd: c_int, addr: usize, len_ptr: usize, flags: c_int) -> i64 {
    crate::abi::raw(crate::thread::net::accept(fd, addr, len_ptr, flags))
}

pub(super) fn sys_sendto(
    fd: c_int,
    buf: usize,
    len: usize,
    flags: c_int,
    addr: usize,
    alen: i64,
) -> i64 {
    crate::abi::raw(crate::thread::net::sendto(fd, buf, len, flags, addr, alen))
}

pub(super) fn sys_recvfrom(
    fd: c_int,
    buf: usize,
    len: usize,
    flags: c_int,
    addr: usize,
    alen_ptr: usize,
) -> i64 {
    crate::abi::raw(crate::thread::net::recvfrom(
        fd, buf, len, flags, addr, alen_ptr,
    ))
}

pub(super) fn sys_sendmsg(fd: c_int, msg: usize, flags: c_int) -> i64 {
    crate::abi::raw(crate::thread::net::msg::sendmsg(fd, msg, flags))
}

pub(super) fn sys_recvmsg(fd: c_int, msg: usize, flags: c_int) -> i64 {
    crate::abi::raw(crate::thread::net::msg::recvmsg(fd, msg, flags))
}

pub(super) fn sys_sendmmsg(fd: c_int, vec: usize, vlen: u32, flags: c_int) -> i64 {
    crate::abi::raw(crate::thread::net::msg::sendmmsg(fd, vec, vlen, flags))
}

pub(super) fn sys_recvmmsg(fd: c_int, vec: usize, vlen: u32, flags: c_int, timeout: usize) -> i64 {
    crate::abi::raw(crate::thread::net::msg::recvmmsg(
        fd, vec, vlen, flags, timeout,
    ))
}

pub(super) fn sys_shutdown(fd: c_int, how: c_int) -> i64 {
    crate::abi::raw(crate::thread::net::shutdown(fd, how))
}

pub(super) fn sys_name(fd: c_int, addr: usize, len_ptr: usize, peer: bool) -> i64 {
    crate::abi::raw(crate::thread::net::name(
        fd,
        addr,
        len_ptr,
        c_int::from(peer),
    ))
}

pub(super) fn sys_setsockopt(fd: c_int, level: c_int, name: c_int, value: usize, len: i64) -> i64 {
    crate::abi::raw(crate::thread::net::setsockopt(fd, level, name, value, len))
}

pub(super) fn sys_getsockopt(
    fd: c_int,
    level: c_int,
    name: c_int,
    value: usize,
    len_ptr: usize,
) -> i64 {
    crate::abi::raw(crate::thread::net::getsockopt(
        fd, level, name, value, len_ptr,
    ))
}
