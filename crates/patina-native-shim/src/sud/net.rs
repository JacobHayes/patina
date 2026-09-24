//! SUD rows — sockets: every row is the shared `patina_sock_*` entry the C
//! socket interposers call, argument for argument (the kernel reads the
//! `int` arguments from the low register bits, a length as `int`).

use super::*;

pub(super) fn sys_socket(family: u64, ty: u64, protocol: u64) -> i64 {
    // SAFETY: no pointers.
    unsafe { patina_sock_socket(family as c_int, ty as c_int, protocol as c_int) }
}

pub(super) fn sys_socketpair(family: u64, ty: u64, protocol: u64, sv: u64) -> i64 {
    // SAFETY: `sv` is the guest's `int[2]`, written through `uaccess`.
    unsafe { patina_sock_socketpair(family as c_int, ty as c_int, protocol as c_int, sv as usize) }
}

pub(super) fn sys_bind(fd: i64, addr: u64, len: u64) -> i64 {
    // SAFETY: the address is copied in through `uaccess`.
    unsafe { patina_sock_bind(fd as c_int, addr as usize, i64::from(len as i32)) }
}

pub(super) fn sys_listen(fd: i64, backlog: u64) -> i64 {
    // SAFETY: no pointers.
    unsafe { patina_sock_listen(fd as c_int, backlog as c_int) }
}

pub(super) fn sys_connect(fd: i64, addr: u64, len: u64) -> i64 {
    // SAFETY: the address is copied in through `uaccess`.
    unsafe { patina_sock_connect(fd as c_int, addr as usize, i64::from(len as i32)) }
}

pub(super) fn sys_accept(fd: i64, addr: u64, len_ptr: u64, flags: u64) -> i64 {
    // SAFETY: the name is copied out through `uaccess`.
    unsafe { patina_sock_accept(fd as c_int, addr as usize, len_ptr as usize, flags as c_int) }
}

pub(super) fn sys_sendto(fd: i64, buf: u64, len: u64, flags: u64, addr: u64, alen: u64) -> i64 {
    // SAFETY: the buffer and the address are copied in through `uaccess`.
    unsafe {
        patina_sock_sendto(
            fd as c_int,
            buf as usize,
            len as usize,
            flags as c_int,
            addr as usize,
            i64::from(alen as i32),
        )
    }
}

pub(super) fn sys_recvfrom(fd: i64, buf: u64, len: u64, flags: u64, addr: u64, alen: u64) -> i64 {
    // SAFETY: the buffer and the name are copied out through `uaccess`.
    unsafe {
        patina_sock_recvfrom(
            fd as c_int,
            buf as usize,
            len as usize,
            flags as c_int,
            addr as usize,
            alen as usize,
        )
    }
}

pub(super) fn sys_sendmsg(fd: i64, msg: u64, flags: u64) -> i64 {
    // SAFETY: the header and what it names are copied through `uaccess`.
    unsafe { patina_sock_sendmsg(fd as c_int, msg as usize, flags as c_int) }
}

pub(super) fn sys_recvmsg(fd: i64, msg: u64, flags: u64) -> i64 {
    // SAFETY: as above.
    unsafe { patina_sock_recvmsg(fd as c_int, msg as usize, flags as c_int) }
}

pub(super) fn sys_sendmmsg(fd: i64, vec: u64, vlen: u64, flags: u64) -> i64 {
    // SAFETY: as above.
    unsafe { patina_sock_sendmmsg(fd as c_int, vec as usize, vlen as u32, flags as c_int) }
}

pub(super) fn sys_recvmmsg(fd: i64, vec: u64, vlen: u64, flags: u64, timeout: u64) -> i64 {
    // SAFETY: as above; the timeout too.
    unsafe {
        patina_sock_recvmmsg(
            fd as c_int,
            vec as usize,
            vlen as u32,
            flags as c_int,
            timeout as usize,
        )
    }
}

pub(super) fn sys_shutdown(fd: i64, how: u64) -> i64 {
    // SAFETY: no pointers.
    unsafe { patina_sock_shutdown(fd as c_int, how as c_int) }
}

pub(super) fn sys_name(fd: i64, addr: u64, len_ptr: u64, peer: bool) -> i64 {
    // SAFETY: the name is copied out through `uaccess`.
    unsafe {
        patina_sock_name(
            fd as c_int,
            addr as usize,
            len_ptr as usize,
            c_int::from(peer),
        )
    }
}

pub(super) fn sys_setsockopt(fd: i64, level: u64, name: u64, value: u64, len: u64) -> i64 {
    // SAFETY: the value is copied in through `uaccess`.
    unsafe {
        patina_sock_setsockopt(
            fd as c_int,
            level as c_int,
            name as c_int,
            value as usize,
            i64::from(len as i32),
        )
    }
}

pub(super) fn sys_getsockopt(fd: i64, level: u64, name: u64, value: u64, len_ptr: u64) -> i64 {
    // SAFETY: the value and its length are copied through `uaccess`.
    unsafe {
        patina_sock_getsockopt(
            fd as c_int,
            level as c_int,
            name as c_int,
            value as usize,
            len_ptr as usize,
        )
    }
}
