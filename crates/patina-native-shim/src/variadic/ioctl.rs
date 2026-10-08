//! Request-directed ioctl decoding; unknown/refused operations consume nothing.
#![deny(clippy::undocumented_unsafe_blocks)]

use core::ffi::{c_int, c_ulong, c_void};

/// # Safety
/// A modeled consuming request supplies its promoted integer or pointer operand.
#[unsafe(no_mangle)]
unsafe extern "C" fn ioctl(fd: c_int, request: c_ulong, mut args: ...) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: a recognized consuming request has the promoted operand type
    // required by ioctl's C contract; unrecognized requests consume no operand.
    let argument = unsafe { ioctl_arg(request, &mut args) };
    #[cfg(target_os = "linux")]
    let request = u64::from(request as u32);
    let argument = match argument {
        IoctlArg::Absent => core::ptr::null_mut(),
        #[cfg(target_os = "linux")]
        IoctlArg::Int(value) => value as usize as *mut c_void,
        #[cfg(target_os = "linux")]
        IoctlArg::Word(value) => value as *mut c_void,
        IoctlArg::Pointer(value) => value,
    };
    // SAFETY: the model validates guest memory through uaccess.
    super::model_result(unsafe { crate::ioctl::patina_ioctl(fd, request, argument) })
}

enum IoctlArg {
    Absent,
    #[cfg(target_os = "linux")]
    Int(c_int),
    #[cfg(target_os = "linux")]
    Word(c_ulong),
    Pointer(*mut c_void),
}

/// # Safety
/// `request` selects a consuming operand of exactly the promoted C type read here.
unsafe fn ioctl_arg(request: c_ulong, args: &mut core::ffi::VaList<'_>) -> IoctlArg {
    let mutated = super::fault(4);
    #[cfg(target_os = "linux")]
    let request = u64::from(request as u32);
    // SAFETY: this request decoder selects the exact promoted C operand type;
    // the public ioctl caller contract supplies it for modeled consuming requests.
    unsafe {
        match payload(request) {
            PayloadKind::Absent => IoctlArg::Absent,
            #[cfg(target_os = "linux")]
            PayloadKind::Int => {
                let value = args.next_arg::<c_int>();
                // The armed terminal probe supplies a second int sentinel.
                IoctlArg::Int(if mutated {
                    args.next_arg::<c_int>()
                } else {
                    value
                })
            }
            #[cfg(target_os = "linux")]
            PayloadKind::Word => {
                let word = args.next_arg::<c_ulong>();
                // The width probe deliberately models a narrowing decoder.
                IoctlArg::Word(if mutated {
                    u64::from(word as u32) as c_ulong
                } else {
                    word
                })
            }
            PayloadKind::Pointer => {
                let pointer = args.next_arg::<*mut c_void>();
                // The armed FIONBIO probe supplies a second pointer sentinel.
                IoctlArg::Pointer(if mutated {
                    args.next_arg::<*mut c_void>()
                } else {
                    pointer
                })
            }
        }
    }
}

enum PayloadKind {
    Absent,
    #[cfg(target_os = "linux")]
    Int,
    #[cfg(target_os = "linux")]
    Word,
    Pointer,
}

fn payload(request: c_ulong) -> PayloadKind {
    use crate::ioctl::request::{FIONBIO, FIONREAD};
    if matches!(request, FIONBIO | FIONREAD) {
        return PayloadKind::Pointer;
    }
    #[cfg(target_os = "linux")]
    {
        use linux_raw_sys::ioctl::*;
        if request == crate::thread::inotify::INOTIFY_IOC_SETNEXTWD {
            // inotify_ioctl validates the full word before narrowing the id.
            return PayloadKind::Word;
        }
        if matches!(request as u32, TCFLSH | TIOCGPTPEER) {
            return PayloadKind::Int;
        }
        if matches!(
            request as u32,
            TCGETS
                | TCSETS
                | TCSETSW
                | TCSETSF
                | TIOCGPGRP
                | TIOCSPGRP
                | TIOCOUTQ
                | TIOCGWINSZ
                | TIOCSWINSZ
                | TIOCGETD
                | TIOCGSID
                | TIOCGPTN
                | TIOCSPTLCK
                | TIOCGPTLCK
                | FIOASYNC
                | FIOQSIZE
                | FIGETBSZ
                | SIOCATMARK
                | SIOCGIFNAME
                | SIOCGIFCONF
                | SIOCGIFFLAGS
                | SIOCGIFADDR
                | SIOCGIFDSTADDR
                | SIOCGIFBRDADDR
                | SIOCGIFNETMASK
                | SIOCGIFMETRIC
                | SIOCGIFMTU
                | SIOCGIFHWADDR
                | SIOCGIFINDEX
                | SIOCGIFTXQLEN
        ) || request == crate::mem::userfaultfd::UFFDIO_API
        {
            return PayloadKind::Pointer;
        }
    }
    PayloadKind::Absent
}
