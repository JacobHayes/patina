//! Guest-only C variadic doors. Compile this archive with one codegen unit so
//! the definitions, extraction anchor and assembler aliases share an object.
use core::ffi::{CStr, c_int};

mod fcntl;
mod ioctl;
pub(crate) mod open;
mod stdio;

/// An unresolved private reference in the POSIX object extracts this member,
/// even when an earlier libc/libSystem already offered the public symbols.
#[unsafe(no_mangle)]
pub extern "C" fn patina_variadic_link() {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
}

#[cfg(target_os = "linux")]
mod memory;

pub(crate) fn errno(value: c_int) {
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

pub(crate) fn error(value: c_int) -> c_int {
    errno(value);
    -1
}

pub(crate) fn model_result(result: c_int) -> c_int {
    if result < 0 {
        errno(crate::patina_errno());
    }
    result
}

fn cancel(name: &CStr) {
    #[cfg(target_os = "linux")]
    // SAFETY: a static C string; this check refuses, never initiates forced unwind.
    unsafe {
        crate::thread::cancel::patina_cancel_point(name.as_ptr());
    }
    #[cfg(target_os = "macos")]
    let _ = name;
}

fn cancel_fcntl(command: c_int, name: &CStr) {
    #[cfg(target_os = "linux")]
    if matches!(command, libc::F_SETLKW | libc::F_OFD_SETLKW) {
        cancel(name);
    }
    #[cfg(target_os = "macos")]
    let _ = (command, name);
}

#[cfg(target_os = "linux")]
mod prctl;
#[cfg(target_os = "linux")]
mod ptrace;

#[cfg(target_os = "linux")]
fn deliver_signals() {
    unsafe extern "C" {
        fn patina_signal_deliver();
    }
    // SAFETY: the shared signal boundary requires no arguments.
    unsafe {
        patina_signal_deliver();
    }
}

#[cfg(target_os = "linux")]
mod syscall;
