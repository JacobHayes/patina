//! Readiness adapters; the Rust reactors own scheduling and descriptor state.
#![deny(clippy::undocumented_unsafe_blocks)]

use super::cancel;
#[cfg(target_os = "macos")]
use super::error;
use core::ffi::c_int;

/// # Safety
/// The caller supplies writable poll records.
#[unsafe(no_mangle)]
unsafe extern "C" fn poll(fds: *mut libc::pollfd, count: libc::nfds_t, timeout: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    cancel(c"poll");
    // SAFETY: Linux consumes the guest records through uaccess; Darwin's limited
    // fallback follows poll's writable-record contract directly.
    unsafe {
        #[cfg(target_os = "linux")]
        {
            crate::abi::libc_delivered(
                crate::thread::readiness::poll_core(
                    fds.cast(),
                    count as usize,
                    if timeout < 0 {
                        -1
                    } else {
                        i64::from(timeout) * 1_000_000
                    },
                    core::ptr::null(),
                    core::ptr::null_mut(),
                ),
                -1,
            ) as c_int
        }
        #[cfg(target_os = "macos")]
        {
            if count != 0 {
                if timeout != 0 {
                    return error(libc::ENOSYS);
                }
                for index in 0..count as usize {
                    if (*fds.add(index)).events != 0 {
                        return error(libc::ENOSYS);
                    }
                    (*fds.add(index)).revents = 0;
                }
                return 0;
            }
            if timeout > 0 {
                let duration = libc::timespec {
                    tv_sec: (timeout / 1000) as libc::time_t,
                    tv_nsec: (timeout % 1000) as libc::c_long * 1_000_000,
                };
                if super::time::sleep_for(&duration, core::ptr::null_mut()) != 0 {
                    return -1;
                }
            }
            0
        }
    }
}

#[cfg(target_os = "macos")]
mod darwin;
#[cfg(target_os = "linux")]
mod linux;
