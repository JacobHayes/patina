//! Request-directed ioctl decoding; unknown/refused operations consume nothing.
use core::ffi::{c_int, c_ulong, c_void};

/// # Safety
/// A modeled consuming request supplies its promoted integer or pointer operand.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ioctl(fd: c_int, request: c_ulong, mut args: ...) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let mutated = super::fault(4);
    #[cfg(target_os = "linux")]
    let request = u64::from(request as u32);
    // SAFETY: the selected request names the operand type. No generic IOC-bit
    // inference: some _IOW operations take an integer, some _IO take a pointer.
    let payload = payload(request);
    let mutate_pointer = mutated && matches!(payload, Payload::Pointer);
    let mut argument = unsafe {
        match payload {
            Payload::Absent => core::ptr::null_mut(),
            #[cfg(target_os = "linux")]
            Payload::Int => {
                let value = args.next_arg::<c_int>();
                // The armed terminal probe supplies a second int sentinel.
                (if mutated {
                    args.next_arg::<c_int>()
                } else {
                    value
                }) as usize as *mut c_void
            }
            #[cfg(target_os = "linux")]
            Payload::Word => {
                let word = args.next_arg::<c_ulong>();
                // The width probe deliberately models a narrowing decoder.
                (if mutated {
                    u64::from(word as u32)
                } else {
                    word
                }) as *mut c_void
            }
            Payload::Pointer => args.next_arg::<*mut c_void>(),
        }
    };
    if mutate_pointer {
        // SAFETY: the armed FIONBIO probe supplies a second pointer sentinel.
        argument = unsafe { args.next_arg::<*mut c_void>() };
    }
    // SAFETY: the model validates guest memory through uaccess.
    super::model_result(unsafe { crate::ioctl::patina_ioctl(fd, request, argument) })
}

enum Payload {
    Absent,
    #[cfg(target_os = "linux")]
    Int,
    #[cfg(target_os = "linux")]
    Word,
    Pointer,
}

fn payload(request: u64) -> Payload {
    use crate::ioctl::request::{FIONBIO, FIONREAD};
    if matches!(request, FIONBIO | FIONREAD) {
        return Payload::Pointer;
    }
    #[cfg(target_os = "linux")]
    {
        use linux_raw_sys::ioctl::*;
        if request == crate::thread::inotify::INOTIFY_IOC_SETNEXTWD {
            // inotify_ioctl validates the full word before narrowing the id.
            return Payload::Word;
        }
        if matches!(request as u32, TCFLSH | TIOCGPTPEER) {
            return Payload::Int;
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
            return Payload::Pointer;
        }
    }
    Payload::Absent
}
