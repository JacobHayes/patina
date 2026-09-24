//! `ioctl(2)`'s generic descriptor requests, one entry both doors call.
//!
//! The kernel resolves the number with `fdget` (an `O_PATH` descriptor is
//! `EBADF`, like an empty slot) and then answers the requests every descriptor
//! understands (`fs/ioctl.c do_vfs_ioctl`): `FIOCLEX`/`FIONCLEX` set and clear
//! the number's `FD_CLOEXEC`, `FIONBIO` reads an `int` through the argument
//! (`EFAULT` for NULL) and sets or clears the description's `O_NONBLOCK`, and
//! `FIONREAD` on a regular file is its size minus the position, as an `int`
//! (negative past the end). Everything else goes to the object: a pipe's
//! `FIONREAD` is the bytes queued in it; any other request, and `FIONREAD` on
//! a directory or a descriptor with no such answer, is `ENOTTY`.
//!
//! `request` is the platform's own request number: the C door passes its
//! libc's, the SUD row the Linux kernel's.

use std::ffi::{c_int, c_void};

use patina_dst_abi::{Fd, SeekWhence};

use crate::fdtable::FdKind;
use crate::{
    EFAULT, fail, fdget, patina_fd_set_nonblocking, patina_fd_setfd, set_errno, thread,
    with_context,
};

/// The generic requests, in the platform's numbering (`asm-generic/ioctls.h`,
/// identical on every Linux architecture the shim runs on; `<sys/filio.h>` on
/// Darwin).
#[cfg(target_os = "linux")]
pub(crate) mod request {
    pub(crate) const FIONREAD: u64 = 0x541B;
    pub(crate) const FIONBIO: u64 = 0x5421;
    pub(crate) const FIONCLEX: u64 = 0x5450;
    pub(crate) const FIOCLEX: u64 = 0x5451;
}

#[cfg(target_os = "macos")]
pub(crate) mod request {
    pub(crate) const FIONREAD: u64 = 0x4004_667F;
    pub(crate) const FIONBIO: u64 = 0x8004_667E;
    pub(crate) const FIONCLEX: u64 = 0x2000_6602;
    pub(crate) const FIOCLEX: u64 = 0x2000_6601;
}

use request::{FIOCLEX, FIONBIO, FIONCLEX, FIONREAD};

const ENOTTY: c_int = 25;

/// Write an `int` answer through the guest's argument.
fn put_int(arg: *mut c_void, value: i32) -> c_int {
    if arg.is_null() {
        return fail(EFAULT);
    }
    // SAFETY: a non-null argument of an int-valued request is the guest's
    // writable `int`.
    unsafe { arg.cast::<i32>().write_unaligned(value) };
    set_errno(0);
    0
}

/// `FIONREAD` on a regular file: its size minus the description's position,
/// truncated to an `int` exactly as `put_user` into an `int *` does.
fn file_fionread(handle: Fd, arg: *mut c_void) -> c_int {
    let size = match with_context(|context| context.fs_fd_metadata(handle)) {
        Ok(metadata) => metadata.len,
        Err(errno) => return fail(errno),
    };
    let position = match with_context(|context| context.fs_seek(handle, 0, SeekWhence::Current)) {
        Ok(position) => position,
        Err(errno) => return fail(errno),
    };
    put_int(arg, size.wrapping_sub(position) as i32)
}

/// `ioctl(fd, request, arg)`.
///
/// # Safety
/// `arg`, when the request reads or writes through it and it is non-null,
/// must point to the guest's `int`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_ioctl(raw_fd: c_int, request: u64, arg: *mut c_void) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let resolved = match fdget(raw_fd) {
        Ok(resolved) => resolved,
        Err(errno) => return fail(errno),
    };
    match request {
        FIOCLEX => patina_fd_setfd(raw_fd, 1),
        FIONCLEX => patina_fd_setfd(raw_fd, 0),
        FIONBIO => {
            if arg.is_null() {
                return fail(EFAULT);
            }
            // SAFETY: a non-null FIONBIO argument is the guest's `int`.
            let on = unsafe { arg.cast::<i32>().read_unaligned() } != 0;
            patina_fd_set_nonblocking(raw_fd, c_int::from(on))
        }
        FIONREAD => match resolved.kind {
            FdKind::File => file_fionread(Fd(resolved.handle), arg),
            FdKind::Pipe => match thread::pipe_queued(resolved.handle) {
                Some(queued) => put_int(arg, i32::try_from(queued).unwrap_or(i32::MAX)),
                None => fail(ENOTTY),
            },
            FdKind::Dir
            | FdKind::OPath
            | FdKind::Stdin
            | FdKind::Stdout
            | FdKind::Stderr
            | FdKind::Urandom
            | FdKind::Socket => fail(ENOTTY),
            #[cfg(target_os = "linux")]
            FdKind::EventFd | FdKind::TimerFd | FdKind::Epoll | FdKind::SignalFd => fail(ENOTTY),
            // An mqueue inode is a regular file: its size less the position.
            #[cfg(target_os = "linux")]
            FdKind::MessageQueue => match thread::ipc::mq_unread(resolved.handle) {
                Some(unread) => put_int(arg, unread),
                None => fail(ENOTTY),
            },
            #[cfg(target_os = "macos")]
            FdKind::Kqueue => fail(ENOTTY),
        },
        _ => fail(ENOTTY),
    }
}
