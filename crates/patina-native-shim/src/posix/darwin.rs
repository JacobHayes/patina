//! Darwin clocks, synchronization and fixed host identity over existing models.
#![deny(clippy::undocumented_unsafe_blocks)]
use core::ffi::{c_char, c_int, c_uint, c_void};
use core::ptr;
mod inventory;
mod task;
const MONOTONIC: u32 = 1;
const REALTIME: u32 = 0;
const PHYSICAL_MEMORY_BYTES: i64 = 8 * 1024 * 1024 * 1024;
fn trap() -> ! {
    // SAFETY: this deliberately executes an architecture trap and never returns.
    unsafe {
        #[cfg(target_arch = "aarch64")]
        core::arch::asm!("brk #1", options(noreturn));
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!("ud2", options(noreturn));
    }
}

#[unsafe(no_mangle)]
extern "C" fn mach_absolute_time() -> u64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter_op(crate::charge::Op::ClockRead);
    let mut nanos = 0;
    // SAFETY: `nanos` is writable local storage for the clock bridge.
    if unsafe { crate::patina_clock_now(MONOTONIC, &mut nanos) } != 0 {
        trap()
    }
    nanos
}
/// # Safety
/// info is null or writable as mach_timebase_info requires.
#[unsafe(no_mangle)]
#[allow(deprecated)] // libc retains the SDK layout; its deprecation suggests an unnecessary dependency.
unsafe extern "C" fn mach_timebase_info(info: *mut libc::mach_timebase_info) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if info.is_null() {
        return libc::KERN_INVALID_ARGUMENT;
    }
    // SAFETY: the ABI contract supplies a writable object and NULL was rejected above.
    unsafe {
        (*info).numer = 1;
        (*info).denom = 1;
    }
    libc::KERN_SUCCESS
}
#[unsafe(no_mangle)]
extern "C" fn mach_wait_until(deadline: u64) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if crate::patina_sleep_until(MONOTONIC, deadline) != 0 {
        trap()
    }
    libc::KERN_SUCCESS
}
#[unsafe(no_mangle)]
extern "C" fn clock_gettime_nsec_np(clock: libc::clockid_t) -> u64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter_op(crate::charge::Op::ClockGettime);
    let clock = match clock {
        libc::CLOCK_REALTIME => REALTIME,
        libc::CLOCK_MONOTONIC | libc::CLOCK_MONOTONIC_RAW | libc::CLOCK_UPTIME_RAW => MONOTONIC,
        _ => {
            super::errno(libc::EINVAL);
            return 0;
        }
    };
    let mut nanos = 0;
    // SAFETY: `nanos` is writable local storage for the clock bridge.
    if unsafe { crate::patina_clock_now(clock, &mut nanos) } != 0 {
        super::errno(crate::patina_errno());
        return 0;
    }
    nanos
}
/// # Safety
/// lock is a live os_unfair_lock identity.
#[unsafe(no_mangle)]
unsafe extern "C" fn os_unfair_lock_lock(lock: *mut c_void) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter_op(crate::charge::Op::UnfairLock);
    // SAFETY: the caller supplies a live unfair-lock identity per this ABI.
    unsafe {
        crate::thread::patina_os_unfair_lock_lock(lock);
    }
}
/// # Safety
/// lock is a live os_unfair_lock identity.
#[unsafe(no_mangle)]
unsafe extern "C" fn os_unfair_lock_trylock(lock: *mut c_void) -> bool {
    let _panic_scope = crate::panic_boundary::PanicScope::enter_op(crate::charge::Op::UnfairLock);
    // SAFETY: the caller supplies a live unfair-lock identity per this ABI.
    unsafe { crate::thread::patina_os_unfair_lock_trylock(lock) != 0 }
}
/// # Safety
/// lock is a live os_unfair_lock identity.
#[unsafe(no_mangle)]
unsafe extern "C" fn os_unfair_lock_unlock(lock: *mut c_void) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter_op(crate::charge::Op::UnfairLock);
    // SAFETY: the caller supplies a live unfair-lock identity per this ABI.
    unsafe {
        crate::thread::patina_os_unfair_lock_unlock(lock);
    }
}
#[unsafe(no_mangle)]
extern "C" fn issetugid() -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    0
}
#[unsafe(no_mangle)]
extern "C" fn dispatch_time(when: u64, delta: i64) -> u64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::thread::patina_dispatch_time(when, delta)
}
#[unsafe(no_mangle)]
extern "C" fn dispatch_semaphore_create(value: isize) -> *mut c_void {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::thread::patina_dispatch_semaphore_create(value)
}
#[unsafe(no_mangle)]
extern "C" fn dispatch_semaphore_wait(sem: *mut c_void, timeout: u64) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::thread::patina_dispatch_semaphore_wait(sem, timeout)
}
#[unsafe(no_mangle)]
extern "C" fn dispatch_semaphore_signal(sem: *mut c_void) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::thread::patina_dispatch_semaphore_signal(sem)
}
#[unsafe(no_mangle)]
extern "C" fn dispatch_release(object: *mut c_void) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::thread::patina_dispatch_release(object);
}
/// # Safety
/// buf is null or writable for len bytes.
#[unsafe(no_mangle)]
unsafe extern "C" fn confstr(name: c_int, buf: *mut c_char, len: usize) -> usize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if name != libc::_CS_DARWIN_USER_TEMP_DIR {
        if !buf.is_null() && len > 0 {
            // SAFETY: `buf` is non-null and writable for at least one byte.
            unsafe {
                buf.write(0);
            }
        }
        return 0;
    }
    let value = c"/tmp/".to_bytes_with_nul();
    if !buf.is_null() && len > 0 {
        // SAFETY: `buf` is writable for `len`; `copy <= len`, and `copy >= 1`.
        unsafe {
            let copy = value.len().min(len);
            ptr::copy_nonoverlapping(value.as_ptr(), buf.cast(), copy);
            buf.add(copy - 1).write(0);
        }
    }
    value.len()
}
/// # Safety
/// Diagnostic strings are null or readable, NUL-terminated strings.
#[unsafe(no_mangle)]
unsafe extern "C" fn __assert_rtn(
    function: *const c_char,
    file: *const c_char,
    line: c_int,
    expression: *const c_char,
) -> ! {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let mut message = [0 as c_char; 512];
    // SAFETY: each optional string is null or readable and NUL-terminated by the ABI contract;
    // the diagnostic buffer is writable local storage.
    unsafe {
        let needed = crate::variadic::stdio::diagnostic(
            message.as_mut_ptr(),
            message.len(),
            c"patina: assertion failed: (%s), function %s, file %s, line %d.\n".as_ptr(),
            if expression.is_null() {
                c"".as_ptr()
            } else {
                expression
            },
            if function.is_null() {
                c"".as_ptr()
            } else {
                function
            },
            if file.is_null() { c"".as_ptr() } else { file },
            line,
        );
        if needed > 0 {
            crate::patina_stdio_write(
                2,
                message.as_ptr().cast(),
                (needed as usize).min(message.len() - 1),
            );
        }
    }
    crate::patina_flush_captured_stdio();
    crate::host_abort()
}
unsafe fn emit<T: crate::plain::Plain>(value: T, oldp: *mut c_void, oldlenp: *mut usize) -> c_int {
    // SAFETY: the caller supplies writable output and length storage; the null checks and length
    // read below validate the exact range before copying.
    unsafe {
        if !oldp.is_null() {
            if oldlenp.is_null() {
                return super::error(libc::EINVAL);
            }
            if oldlenp.read() < size_of::<T>() {
                return super::error(libc::ENOMEM);
            }
            let bytes = crate::plain::bytes(&value);
            ptr::copy_nonoverlapping(bytes.as_ptr(), oldp.cast(), bytes.len());
            oldlenp.write(size_of::<T>());
        } else if !oldlenp.is_null() {
            oldlenp.write(size_of::<T>());
        }
        0
    }
}
/// # Safety
/// Arguments follow BSD sysctl's MIB and buffer contracts.
#[unsafe(no_mangle)]
unsafe extern "C" fn sysctl(
    name: *mut c_int,
    namelen: c_uint,
    oldp: *mut c_void,
    oldlenp: *mut usize,
    newp: *mut c_void,
    newlen: usize,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if !newp.is_null() || newlen != 0 {
        return super::error(libc::EPERM);
    }
    if name.is_null() || namelen < 2 {
        return super::error(libc::ENOENT);
    }
    // SAFETY: the caller's MIB contract makes `namelen` integers readable; the checks above
    // guarantee the first two entries exist.
    unsafe {
        if name.read() == libc::CTL_HW {
            match name.add(1).read() {
                libc::HW_MEMSIZE => return emit(PHYSICAL_MEMORY_BYTES, oldp, oldlenp),
                libc::HW_NCPU | libc::HW_AVAILCPU => return emit(1 as c_int, oldp, oldlenp),
                libc::HW_PAGESIZE => return emit(4096 as c_int, oldp, oldlenp),
                _ => {}
            }
        }
    }
    super::error(libc::ENOENT)
}
/// # Safety
/// Arguments follow sysctlbyname's name and buffer contracts.
#[unsafe(no_mangle)]
unsafe extern "C" fn sysctlbyname(
    name: *const c_char,
    oldp: *mut c_void,
    oldlenp: *mut usize,
    newp: *mut c_void,
    newlen: usize,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if !newp.is_null() || newlen != 0 {
        return super::error(libc::EPERM);
    }
    if name.is_null() {
        return super::error(libc::EINVAL);
    }
    // SAFETY: NULL was rejected and the caller's name contract requires a readable C string.
    let name = unsafe { core::ffi::CStr::from_ptr(name) }.to_bytes();
    // SAFETY: the caller's sysctlbyname contract governs the output pointers; `emit` validates
    // their nullness and capacity before writing.
    unsafe {
        match name {
            b"hw.memsize" => emit(PHYSICAL_MEMORY_BYTES, oldp, oldlenp),
            b"hw.pagesize" => emit(4096 as c_int, oldp, oldlenp),
            b"hw.ncpu"
            | b"hw.logicalcpu"
            | b"hw.logicalcpu_max"
            | b"hw.physicalcpu"
            | b"hw.physicalcpu_max"
            | b"hw.activecpu" => emit(1 as c_int, oldp, oldlenp),
            name if name.starts_with(b"hw.optional.") => emit(0 as c_int, oldp, oldlenp),
            _ => super::error(libc::ENOENT),
        }
    }
}
#[unsafe(no_mangle)]
extern "C" fn _NSGetExecutablePath(_buf: *mut c_char, _size: *mut u32) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    -1
}
