//! Guest-only C variadic doors. Compile this archive with one codegen unit so
//! the definitions, extraction anchor and assembler aliases share an object.
use core::ffi::{VaList, c_int, c_void};

unsafe extern "C" {
    fn patina_fcntl_impl(
        fd: c_int,
        command: c_int,
        argument: c_int,
        pointer: *mut c_void,
        large_file: c_int,
    ) -> c_int;
}

// A C alias attribute cannot name a definition in another translation unit.
#[cfg(target_os = "linux")]
core::arch::global_asm!(
    ".globl patina_route_fcntl",
    ".hidden patina_route_fcntl",
    ".set patina_route_fcntl, fcntl",
    ".globl patina_route_fcntl64",
    ".hidden patina_route_fcntl64",
    ".set patina_route_fcntl64, fcntl64",
);

/// An unresolved private reference in the POSIX object extracts this member,
/// even when an earlier libc/libSystem already offered the public symbols.
#[unsafe(no_mangle)]
pub extern "C" fn patina_variadic_link() {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
}

/// # Safety
/// The optional argument must have the promoted type required by `command`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fcntl(fd: c_int, command: c_int, args: ...) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the public fcntl contract supplies the command's argument.
    unsafe { dispatch(fd, command, args, 0) }
}

/// Linux's large-file spelling shares the decoder, never retypes a pointer as
/// an int or reads an absent argument in order to forward to public fcntl.
/// # Safety
/// The optional argument must have the promoted type required by `command`.
#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fcntl64(fd: c_int, command: c_int, args: ...) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: same 64-bit-platform contract as fcntl.
    unsafe { dispatch(fd, command, args, 1) }
}

unsafe fn dispatch(fd: c_int, command: c_int, mut args: VaList<'_>, large_file: c_int) -> c_int {
    let mutated = fault(1);
    use libc::{F_DUPFD, F_DUPFD_CLOEXEC, F_GETLK, F_SETFD, F_SETFL, F_SETLK, F_SETLKW};
    #[allow(unused_mut)]
    let mut pointer = matches!(command, F_GETLK | F_SETLK | F_SETLKW);
    #[allow(unused_mut)]
    let mut integer = matches!(command, F_SETFD | F_SETFL | F_DUPFD | F_DUPFD_CLOEXEC);
    #[cfg(target_os = "linux")]
    {
        use linux_raw_sys::general as k;
        pointer |= matches!(
            command as u32,
            k::F_OFD_GETLK | k::F_OFD_SETLK | k::F_OFD_SETLKW | k::F_GETOWN_EX
        );
        integer |= matches!(command as u32, k::F_SETPIPE_SZ | k::F_ADD_SEALS);
    }
    // Only modeled consuming commands fetch an argument. Queries, rejected
    // commands and the owner-setting named refusal need no variadic read.
    // SAFETY: command selects the caller's promoted C type; pointers stay pointers.
    let (argument, pointer) = unsafe {
        if pointer {
            (0, args.next_arg::<*mut c_void>())
        } else if integer {
            (
                {
                    let value = args.next_arg::<c_int>();
                    if mutated {
                        args.next_arg::<c_int>()
                    } else {
                        value
                    }
                },
                core::ptr::null_mut(),
            )
        } else {
            (0, core::ptr::null_mut())
        }
    };
    // SAFETY: fixed platform adapter, with exactly the decoded command payload.
    unsafe { patina_fcntl_impl(fd, command, argument, pointer, large_file) }
}

#[cfg(target_os = "linux")]
mod memory;

#[cfg(target_os = "linux")]
fn errno(value: c_int) {
    // SAFETY: libc provides the current thread's errno cell on both platforms.
    unsafe {
        #[cfg(target_os = "linux")]
        {
            *libc::__errno_location() = value;
        }
        #[cfg(target_os = "macos")]
        {
            *libc::__error() = value;
        }
    }
}

#[cfg(target_os = "linux")]
fn raw_result(value: i64) -> i64 {
    if (-4095..=-1).contains(&value) {
        errno(-value as c_int);
        -1
    } else {
        value
    }
}

#[cfg(feature = "test-panic")]
static TEST_FAULT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Arm a single explicitly selected variadic boundary in acceptance builds.
#[cfg(feature = "test-panic")]
#[unsafe(no_mangle)]
pub extern "C" fn patina_variadic_test_arm(family: u32, fault: u32) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    TEST_FAULT.store(family * 256 + fault, std::sync::atomic::Ordering::SeqCst);
}

fn fault(family: u32) -> bool {
    #[cfg(feature = "test-panic")]
    {
        use std::sync::atomic::Ordering;
        let state = TEST_FAULT.load(Ordering::SeqCst);
        if state / 256 == family {
            TEST_FAULT.store(0, Ordering::SeqCst);
            if state % 256 == 1 {
                panic!("planted variadic boundary panic");
            }
            return state % 256 == 2;
        }
    }
    let _ = family;
    false
}
