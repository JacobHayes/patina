//! Linux terminal adapters. All requests reach the virtual machine. The
//! pseudoterminal calls (`posix_openpt`, `openpty`, `grantpt`, ...) are not
//! defined: pseudoterminals are not modeled, so a guest importing one meets
//! the pre-run audit, and a raw `/dev/ptmx` open is a named stop.
#![deny(clippy::undocumented_unsafe_blocks)]

use crate::posix::{cancel, errno, error, get_errno, model_result};
use core::ffi::{c_char, c_int, c_void};
use core::mem::MaybeUninit;

#[repr(C)]
struct KernelTermios {
    iflag: libc::tcflag_t,
    oflag: libc::tcflag_t,
    cflag: libc::tcflag_t,
    lflag: libc::tcflag_t,
    line: libc::cc_t,
    cc: [libc::cc_t; 19],
}
const _: () = {
    assert!(size_of::<KernelTermios>() == 36);
    assert!(core::mem::offset_of!(KernelTermios, iflag) == 0);
    assert!(core::mem::offset_of!(KernelTermios, oflag) == 4);
    assert!(core::mem::offset_of!(KernelTermios, cflag) == 8);
    assert!(core::mem::offset_of!(KernelTermios, lflag) == 12);
    assert!(core::mem::offset_of!(KernelTermios, line) == 16);
    assert!(core::mem::offset_of!(KernelTermios, cc) == 17);
};
const IBAUD0: libc::tcflag_t = 0o20000000000;

pub(in crate::posix) fn isatty_impl(fd: c_int) -> c_int {
    let mut kernel = MaybeUninit::<KernelTermios>::uninit();
    c_int::from(
        // SAFETY: `kernel` is a writable local output buffer for TCGETS and is not read here.
        unsafe {
            model_result(crate::ioctl::patina_ioctl(
                fd,
                libc::TCGETS,
                kernel.as_mut_ptr().cast(),
            ))
        } == 0,
    )
}
/// # Safety
/// `termios_p` is writable as tcgetattr requires.
#[unsafe(no_mangle)]
unsafe extern "C" fn tcgetattr(fd: c_int, termios_p: *mut libc::termios) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the C contract requires `termios_p` writable; TCGETS initializes `kernel` before it is read.
    unsafe {
        let mut kernel = MaybeUninit::<KernelTermios>::uninit();
        if model_result(crate::ioctl::patina_ioctl(
            fd,
            libc::TCGETS,
            kernel.as_mut_ptr().cast(),
        )) != 0
        {
            return -1;
        }
        let kernel = kernel.assume_init();
        (*termios_p).c_iflag = kernel.iflag;
        (*termios_p).c_oflag = kernel.oflag;
        (*termios_p).c_cflag = kernel.cflag;
        (*termios_p).c_lflag = kernel.lflag;
        (*termios_p).c_line = kernel.line;
        (*termios_p).c_ispeed = kernel.cflag & (libc::CBAUD | libc::CBAUDEX);
        (*termios_p).c_ospeed = kernel.cflag & (libc::CBAUD | libc::CBAUDEX);
        core::ptr::copy_nonoverlapping(
            kernel.cc.as_ptr(),
            core::ptr::addr_of_mut!((*termios_p).c_cc).cast(),
            19,
        );
        core::ptr::write_bytes(
            core::ptr::addr_of_mut!((*termios_p).c_cc)
                .cast::<libc::cc_t>()
                .add(19),
            libc::_POSIX_VDISABLE,
            libc::NCCS - 19,
        );
        0
    }
}
unsafe fn setattr_impl(
    fd: c_int,
    optional_actions: c_int,
    termios_p: *const libc::termios,
) -> c_int {
    // SAFETY: the caller guarantees `termios_p` points to a readable termios; ioctl buffers are local and writable.
    unsafe {
        let mut old = MaybeUninit::<KernelTermios>::uninit();
        let old_result = model_result(crate::ioctl::patina_ioctl(
            fd,
            libc::TCGETS,
            old.as_mut_ptr().cast(),
        ));
        let command = match optional_actions {
            libc::TCSANOW => libc::TCSETS,
            libc::TCSADRAIN => libc::TCSETSW,
            libc::TCSAFLUSH => libc::TCSETSF,
            _ => return error(libc::EINVAL),
        };
        let mut kernel = KernelTermios {
            iflag: (*termios_p).c_iflag & !IBAUD0,
            oflag: (*termios_p).c_oflag,
            cflag: (*termios_p).c_cflag,
            lflag: (*termios_p).c_lflag,
            line: (*termios_p).c_line,
            cc: [0; 19],
        };
        core::ptr::copy_nonoverlapping(
            core::ptr::addr_of!((*termios_p).c_cc).cast(),
            kernel.cc.as_mut_ptr(),
            19,
        );
        let result = model_result(crate::ioctl::patina_ioctl(
            fd,
            command,
            (&raw mut kernel).cast(),
        ));
        if result != 0 || old_result != 0 {
            return result;
        }
        let saved = get_errno();
        if model_result(crate::ioctl::patina_ioctl(
            fd,
            libc::TCGETS,
            (&raw mut kernel).cast(),
        )) != 0
        {
            errno(saved);
            return 0;
        }
        let old = old.assume_init();
        let unchanged = old.oflag == kernel.oflag
            && old.lflag == kernel.lflag
            && old.line == kernel.line
            && old.cflag == kernel.cflag
            && (old.iflag | IBAUD0) == (kernel.iflag | IBAUD0);
        let asked = (*termios_p).c_cflag;
        let refused = asked & (libc::PARENB | libc::CREAD)
            != kernel.cflag & (libc::PARENB | libc::CREAD)
            || (asked & libc::CSIZE != 0 && asked & libc::CSIZE != kernel.cflag & libc::CSIZE);
        if unchanged && refused {
            return error(libc::EINVAL);
        }
        errno(saved);
        0
    }
}
/// # Safety
/// `termios_p` is readable as tcsetattr requires.
#[unsafe(no_mangle)]
unsafe extern "C" fn tcsetattr(
    fd: c_int,
    optional_actions: c_int,
    termios_p: *const libc::termios,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: this forwards the caller's documented readable `termios_p` contract to the implementation.
    unsafe { setattr_impl(fd, optional_actions, termios_p) }
}
#[unsafe(no_mangle)]
extern "C" fn tcflush(fd: c_int, queue_selector: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: TCFLSH consumes this integer as a scalar ioctl argument and does not dereference it.
    unsafe {
        model_result(crate::ioctl::patina_ioctl(
            fd,
            libc::TCFLSH,
            queue_selector as isize as *mut c_void,
        ))
    }
}
#[unsafe(no_mangle)]
extern "C" fn tcdrain(fd: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"tcdrain");
    // SAFETY: TCSBRK consumes the nonzero sentinel as a scalar ioctl argument and does not dereference it.
    unsafe {
        model_result(crate::ioctl::patina_ioctl(
            fd,
            libc::TCSBRK,
            core::ptr::without_provenance_mut(1),
        ))
    }
}
fn ioctl_error() -> c_int {
    let value = crate::patina_errno();
    errno(value);
    value
}
unsafe fn ttyname_into(fd: c_int, buf: *mut c_char, buflen: usize) -> c_int {
    // SAFETY: callers guarantee writable storage for `buflen`; null and minimum length are checked before writing.
    unsafe {
        if buf.is_null() {
            errno(libc::EINVAL);
            return libc::EINVAL;
        }
        if buflen < 10 {
            errno(libc::ERANGE);
            return libc::ERANGE;
        }
        let mut kernel = MaybeUninit::<KernelTermios>::uninit();
        if crate::ioctl::patina_ioctl(fd, libc::TCGETS, kernel.as_mut_ptr().cast()) != 0 {
            return ioctl_error();
        }
        // A descriptor that answers TCGETS names a terminal, and the virtual machine has none.
        errno(libc::ENODEV);
        libc::ENODEV
    }
}
/// # Safety
/// `buf` is writable for `buflen` bytes.
#[unsafe(no_mangle)]
unsafe extern "C" fn ttyname_r(fd: c_int, buf: *mut c_char, buflen: usize) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: this forwards the caller's documented writable buffer and length to the implementation.
    unsafe { ttyname_into(fd, buf, buflen) }
}
/// # Safety
/// `buf` is writable for `nreal` bytes.
#[unsafe(no_mangle)]
unsafe extern "C" fn __ttyname_r_chk(
    fd: c_int,
    buf: *mut c_char,
    buflen: usize,
    nreal: usize,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if buflen > nreal {
        crate::posix::chk_fail();
    }
    // SAFETY: the caller guarantees `nreal` writable bytes and the check ensures `buflen` fits that allocation.
    unsafe { ttyname_into(fd, buf, buflen) }
}
static mut TTY_NAME: [c_char; 4096] = [0; 4096];
#[unsafe(no_mangle)]
extern "C" fn ttyname(fd: c_int) -> *mut c_char {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let name = (&raw mut TTY_NAME).cast::<c_char>();
    // SAFETY: `name` points to the 4096-byte static return buffer and ttyname_into writes no more than buflen bytes.
    if unsafe { ttyname_into(fd, name, 4096) } == 0 {
        name
    } else {
        core::ptr::null_mut()
    }
}
