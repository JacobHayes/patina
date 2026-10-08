//! Linux terminal/PTY adapters. All requests reach the virtual machine.
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
#[unsafe(no_mangle)]
extern "C" fn posix_openpt(flags: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the path is a static NUL-terminated string and openat reads it for the duration of the call.
    unsafe {
        crate::variadic::open::patina_openat_impl(libc::AT_FDCWD, c"/dev/ptmx".as_ptr(), flags, 0)
    }
}
unsafe fn master_request(fd: c_int, request: u64, arg: *mut c_void) -> c_int {
    // SAFETY: callers pass the valid argument buffer required by each PTY ioctl request.
    unsafe {
        if crate::ioctl::patina_ioctl(fd, request, arg) == 0 {
            return 0;
        }
        let value = crate::patina_errno();
        error(if value == libc::ENOTTY {
            libc::EINVAL
        } else {
            value
        })
    }
}
#[unsafe(no_mangle)]
extern "C" fn grantpt(fd: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let mut index = MaybeUninit::<libc::c_uint>::uninit();
    // SAFETY: TIOCGPTN writes its result to this local output slot.
    unsafe { master_request(fd, libc::TIOCGPTN, index.as_mut_ptr().cast()) }
}
#[unsafe(no_mangle)]
extern "C" fn unlockpt(fd: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let mut unlock: c_int = 0;
    // SAFETY: TIOCSPTLCK reads this initialized local integer argument.
    unsafe { master_request(fd, libc::TIOCSPTLCK, (&raw mut unlock).cast()) }
}
fn ioctl_error() -> c_int {
    let value = crate::patina_errno();
    errno(value);
    value
}
unsafe fn ptsname_into(fd: c_int, buf: *mut c_char, buflen: usize) -> c_int {
    // SAFETY: callers guarantee `buf` is writable for `buflen`; this function checks the needed length before writing.
    unsafe {
        let saved = get_errno();
        let mut index = MaybeUninit::<libc::c_uint>::uninit();
        if crate::ioctl::patina_ioctl(fd, libc::TIOCGPTN, index.as_mut_ptr().cast()) != 0 {
            return ioctl_error();
        }
        let mut index = index.assume_init();
        let mut digits = [0u8; 10];
        let mut count = 0;
        loop {
            digits[count] = b'0' + (index % 10) as u8;
            count += 1;
            index /= 10;
            if index == 0 {
                break;
            }
        }
        let prefix = b"/dev/pts/";
        if buflen < prefix.len() + count + 1 {
            errno(libc::ERANGE);
            return libc::ERANGE;
        }
        core::ptr::copy_nonoverlapping(prefix.as_ptr(), buf.cast(), prefix.len());
        for i in 0..count {
            *buf.add(prefix.len() + i) = digits[count - 1 - i] as c_char;
        }
        *buf.add(prefix.len() + count) = 0;
        errno(saved);
        0
    }
}
/// # Safety
/// `buf` is writable for `buflen` bytes.
#[unsafe(no_mangle)]
unsafe extern "C" fn ptsname_r(fd: c_int, buf: *mut c_char, buflen: usize) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: this forwards the caller's documented writable buffer and length to the implementation.
    unsafe { ptsname_into(fd, buf, buflen) }
}
static mut PTS_NAME: [c_char; 30] = [0; 30];
#[unsafe(no_mangle)]
extern "C" fn ptsname(fd: c_int) -> *mut c_char {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let name = (&raw mut PTS_NAME).cast::<c_char>();
    // SAFETY: `name` points to the 30-byte static return buffer; ptsname_into writes only after checking its length.
    if unsafe { ptsname_into(fd, name, 30) } == 0 {
        name
    } else {
        core::ptr::null_mut()
    }
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
        let mut name = [0 as c_char; 30];
        let length = crate::thread::pty::patina_pty_name(fd, name.as_mut_ptr(), name.len());
        if length < 0 {
            return ioctl_error();
        }
        if length as usize >= buflen {
            errno(libc::ENODEV);
            return libc::ENODEV;
        }
        core::ptr::copy_nonoverlapping(name.as_ptr(), buf, length as usize + 1);
        0
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
unsafe extern "C" fn __ptsname_r_chk(
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
    unsafe { ptsname_into(fd, buf, buflen) }
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
/// # Safety
/// Out parameters are writable; optional settings are readable.
#[unsafe(no_mangle)]
unsafe extern "C" fn openpty(
    amaster: *mut c_int,
    aslave: *mut c_int,
    name: *mut c_char,
    termp: *const libc::termios,
    winp: *const libc::winsize,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the caller supplies writable output pointers and readable optional settings; local ioctl buffers are valid.
    unsafe {
        let mut path = [0 as c_char; 30];
        let master = crate::variadic::open::patina_openat_impl(
            libc::AT_FDCWD,
            c"/dev/ptmx".as_ptr(),
            libc::O_RDWR,
            0,
        );
        if master == -1 {
            return -1;
        }
        let mut slave = -1;
        let mut index = MaybeUninit::<libc::c_uint>::uninit();
        let mut unlock: c_int = 0;
        let result = (|| {
            if master_request(master, libc::TIOCGPTN, index.as_mut_ptr().cast()) != 0 {
                return -1;
            }
            if master_request(master, libc::TIOCSPTLCK, (&raw mut unlock).cast()) != 0 {
                return -1;
            }
            slave = model_result(crate::ioctl::patina_ioctl(
                master,
                libc::TIOCGPTPEER,
                (libc::O_RDWR | libc::O_NOCTTY) as isize as *mut c_void,
            ));
            if slave == -1 {
                if ptsname_into(master, path.as_mut_ptr(), path.len()) != 0 {
                    return -1;
                }
                slave = crate::variadic::open::patina_openat_impl(
                    libc::AT_FDCWD,
                    path.as_ptr(),
                    libc::O_RDWR | libc::O_NOCTTY,
                    0,
                );
                if slave == -1 {
                    return -1;
                }
            }
            if !termp.is_null() {
                let _ = setattr_impl(slave, libc::TCSAFLUSH, termp);
            }
            if !winp.is_null() {
                let _ = crate::ioctl::patina_ioctl(slave, libc::TIOCSWINSZ, winp.cast_mut().cast());
            }
            if !name.is_null() {
                if ptsname_into(master, path.as_mut_ptr(), path.len()) != 0 {
                    return -1;
                }
                core::ptr::copy_nonoverlapping(
                    path.as_ptr(),
                    name,
                    libc::strlen(path.as_ptr()) + 1,
                );
            }
            *amaster = master;
            *aslave = slave;
            0
        })();
        if result != 0 {
            let _ = crate::patina_close(master);
            if slave != -1 {
                let _ = crate::patina_close(slave);
            }
        }
        result
    }
}
