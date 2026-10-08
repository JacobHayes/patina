#![deny(clippy::undocumented_unsafe_blocks)]

use core::cell::Cell;
use core::ffi::c_int;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Errno(c_int);

impl Errno {
    pub(crate) const fn new(code: c_int) -> Self {
        assert!(code > 0, "errno must be positive");
        Self(code)
    }

    #[cfg_attr(not(any(target_os = "linux", patina_posix_exports)), allow(dead_code))]
    pub(crate) fn last() -> Self {
        Self(crate::LAST_ERRNO.with(Cell::get))
    }

    pub(crate) const fn get(self) -> c_int {
        self.0
    }
}

pub(crate) type SysResult<T> = Result<T, Errno>;

/// Preserve `fail(code)`'s model-errno write while returning its error value.
#[allow(dead_code)]
pub(crate) fn failed(code: c_int) -> Errno {
    crate::set_errno(code);
    Errno::new(code)
}

#[cfg_attr(not(patina_posix_exports), allow(dead_code))]
pub(crate) fn set_host_errno(code: c_int) {
    // SAFETY: libc exposes the current thread's errno cell on both supported hosts.
    unsafe {
        #[cfg(target_os = "linux")]
        {
            *libc::__errno_location() = code;
        }
        #[cfg(target_os = "macos")]
        {
            *libc::__error() = code;
        }
    }
}

/// Project a model result to libc's failure value, writing host errno on errors.
#[cfg_attr(not(patina_posix_exports), allow(dead_code))]
pub(crate) fn libc_result<T>(result: SysResult<T>, failure: T) -> T {
    match result {
        Ok(value) => value,
        Err(errno) => {
            set_host_errno(errno.get());
            failure
        }
    }
}

/// Deliver pending Linux signals before projecting the result to libc.
#[cfg_attr(not(patina_posix_exports), allow(dead_code))]
pub(crate) fn libc_delivered<T>(result: SysResult<T>, failure: T) -> T {
    #[cfg(all(target_os = "linux", patina_posix_exports))]
    crate::thread::signals::patina_signal_deliver();
    libc_result(result, failure)
}

/// Project a result to the positive pthread error-code convention.
#[allow(dead_code)]
pub(crate) fn pthread_result(result: SysResult<()>) -> c_int {
    match result {
        Ok(()) => 0,
        Err(errno) => errno.get(),
    }
}

/// Project a result to the raw-syscall convention (`-errno` on failure).
pub(crate) fn raw(result: SysResult<i64>) -> i64 {
    match result {
        Ok(value) => value,
        Err(errno) => -i64::from(errno.get()),
    }
}

/// Decode Linux's reserved raw error range without confusing pointer bits for errors.
#[cfg_attr(not(all(target_os = "linux", patina_posix_exports)), allow(dead_code))]
pub(crate) struct LinuxReturn(i64);

#[cfg_attr(not(all(target_os = "linux", patina_posix_exports)), allow(dead_code))]
impl LinuxReturn {
    pub(crate) const fn new(value: i64) -> Self {
        Self(value)
    }

    pub(crate) fn decode(self) -> SysResult<u64> {
        if (-4095..=-1).contains(&self.0) {
            Err(Errno::new(-self.0 as c_int))
        } else {
            Ok(self.0 as u64)
        }
    }
}

#[cfg_attr(not(any(target_os = "linux", patina_posix_exports)), allow(dead_code))]
pub(crate) trait Signed: Copy {
    fn is_negative(self) -> bool;
}

impl Signed for c_int {
    fn is_negative(self) -> bool {
        self < 0
    }
}

impl Signed for isize {
    fn is_negative(self) -> bool {
        self < 0
    }
}

/// Bridge a legacy model result, whose failure reads errno from model TLS.
#[cfg_attr(not(any(target_os = "linux", patina_posix_exports)), allow(dead_code))]
pub(crate) fn from_model<T: Signed>(result: T) -> SysResult<T> {
    if result.is_negative() {
        Err(Errno::last())
    } else {
        Ok(result)
    }
}

/// Bridge a legacy result encoded as a negative errno.
#[cfg_attr(not(patina_posix_exports), allow(dead_code))]
pub(crate) fn from_neg(result: i64) -> SysResult<i64> {
    if result < 0 {
        Err(Errno::new(-result as c_int))
    } else {
        Ok(result)
    }
}
