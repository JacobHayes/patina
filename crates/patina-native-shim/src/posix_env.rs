//! POSIX environment ownership, including the original stack and private control map.
//! Guest pointers remain borrowed; replaced strings intentionally live forever,
//! as libc getenv/putenv require. Only mutators take the scheduler's envlock.
use core::ffi::{c_char, c_int};
use core::ptr::{self, null_mut};

// Startup fields are written before guest threads run. ALLOCATED is accessed
// under EnvLock; unlocked readers have libc's caller synchronization contract.
static mut CONTROL: *mut *mut c_char = null_mut();
static mut CAPTURED: bool = false;
static mut HOST: *mut *mut c_char = null_mut();
static mut HOST_COUNT: usize = 0;
static mut ALLOCATED: *mut *mut c_char = null_mut();
static mut ENV_LOCK: libc::pthread_mutex_t = libc::PTHREAD_MUTEX_INITIALIZER;

#[cfg(target_os = "linux")]
unsafe extern "C" {
    static mut environ: *mut *mut c_char;
}
#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn _NSGetEnviron() -> *mut *mut *mut c_char;
    fn _NSGetArgv() -> *mut *mut *mut c_char;
    fn _NSGetArgc() -> *mut c_int;
}

unsafe fn array() -> *mut *mut c_char {
    // SAFETY: process CRT storage remains live throughout startup and teardown.
    unsafe {
        #[cfg(target_os = "linux")]
        {
            environ
        }
        #[cfg(target_os = "macos")]
        {
            *_NSGetEnviron()
        }
    }
}

/// # Safety
/// Startup-only: `next` is the original, terminated stack envp array.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_env_save_host(next: *mut *mut c_char) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe {
        HOST = next;
    }
}

/// # Safety
/// `next` is a process-lifetime terminated array, or null for clearenv.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_environ_install(next: *mut *mut c_char) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe {
        #[cfg(target_os = "linux")]
        {
            environ = next;
        }
        #[cfg(target_os = "macos")]
        {
            *_NSGetEnviron() = next;
        }
    }
}

fn fatal(message: &'static [u8]) -> ! {
    // SAFETY: static diagnostic bytes; this is also safe before runtime install.
    unsafe {
        crate::patina_stdio_write(2, message.as_ptr().cast(), message.len());
    }
    crate::host_abort()
}

/// Capture once, before startup publishes the deterministic guest map.
/// # Safety
/// Called only during single-threaded CRT startup.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_capture_control_plane() {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: startup is single-threaded; original CRT arrays are terminated.
    unsafe {
        if CAPTURED {
            return;
        }
        CAPTURED = true;
        #[cfg(target_os = "macos")]
        {
            HOST = (*_NSGetArgv()).add(*_NSGetArgc() as usize + 1);
        }
        if HOST.is_null() {
            HOST = array();
        }
        if HOST.is_null() {
            return;
        }
        let mut kept = 0;
        let mut entry = HOST;
        while !(*entry).is_null() {
            HOST_COUNT += 1;
            if libc::strncmp(*entry, c"PATINA_".as_ptr(), 7) == 0 {
                kept += 1;
            }
            entry = entry.add(1);
        }
        let snapshot = libc::calloc(kept + 1, size_of::<*mut c_char>()).cast::<*mut c_char>();
        if snapshot.is_null() {
            fatal(b"patina: failed to capture the PATINA_* control plane before scrubbing the environment\n");
        }
        let mut index = 0;
        entry = HOST;
        while !(*entry).is_null() {
            if libc::strncmp(*entry, c"PATINA_".as_ptr(), 7) == 0 {
                *snapshot.add(index) = *entry;
                index += 1;
                crate::startup::patina_control_set_entry(*entry);
            }
            entry = entry.add(1);
        }
        CONTROL = snapshot;
    }
}

/// # Safety
/// `name` is null or a terminated C string; called during startup only.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_control_getenv(name: *const c_char) -> *const c_char {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe {
        if name.is_null() || libc::strncmp(name, c"PATINA_".as_ptr(), 7) != 0 {
            return ptr::null();
        }
        patina_capture_control_plane();
        let (entry, _) = find(CONTROL, name, libc::strlen(name));
        if entry.is_null() || (*entry).is_null() {
            ptr::null()
        } else {
            (*entry).add(libc::strlen(name) + 1)
        }
    }
}

/// Commit the startup map without moving libc/dyld's retained trailer.
/// # Safety
/// Called once after capture, runtime installation and Linux auxv scrubbing.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_scrub_environ() {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe {
        if HOST.is_null() {
            return;
        }
        let guest = array();
        let mut count = 0;
        while !guest.is_null() && !(*guest.add(count)).is_null() {
            count += 1;
        }
        let reserved = patina_control_getenv(c"PATINA_INITIAL_STACK".as_ptr());
        if reserved.is_null() {
            if count != 0 {
                fatal(b"patina: unreserved initial-stack environment: nonempty map requires cargo patina run\n");
            }
            ptr::write_bytes(HOST, 0, HOST_COUNT + 1);
            patina_environ_install(HOST);
            return;
        }
        let trailer = HOST.add(HOST_COUNT + 1);
        // Linux Elf{32,64}_auxv_t is a pair of native words on our 64-bit
        // targets. Darwin's apple vector is a terminated pointer array.
        #[cfg(target_os = "linux")]
        let trailer_bytes = {
            let mut end = trailer.cast::<usize>();
            while *end != libc::AT_NULL as usize {
                end = end.add(2);
            }
            end.add(2).byte_offset_from(trailer) as usize
        };
        #[cfg(target_os = "macos")]
        let trailer_bytes = {
            let mut end = trailer;
            while !(*end).is_null() {
                end = end.add(1);
            }
            end.add(1).byte_offset_from(trailer) as usize
        };
        if libc::strcmp(reserved, c"1".as_ptr()) != 0
            || count > HOST_COUNT
            || trailer_bytes > (HOST_COUNT - count) * size_of::<*mut c_char>()
        {
            fatal(b"patina: insufficient initial-stack environment reservation\n");
        }
        ptr::write_bytes(HOST, 0, HOST_COUNT + 1);
        if count != 0 {
            ptr::copy_nonoverlapping(guest, HOST, count);
        }
        ptr::copy_nonoverlapping(
            trailer.cast::<u8>(),
            HOST.add(count + 1).cast(),
            trailer_bytes,
        );
        patina_environ_install(HOST);
    }
}

struct EnvLock(bool);
impl EnvLock {
    unsafe fn take() -> Self {
        Self(
            crate::process::patina_in_teardown() == 0
                && unsafe { crate::thread::patina_mutex_lock((&raw mut ENV_LOCK).cast()) } == 0,
        )
    }
}
impl Drop for EnvLock {
    fn drop(&mut self) {
        if self.0 {
            // SAFETY: this guard acquired the same process-lifetime lock.
            unsafe {
                crate::thread::patina_mutex_unlock((&raw mut ENV_LOCK).cast());
            }
        }
    }
}

unsafe fn invalid(name: *const c_char) -> bool {
    unsafe { name.is_null() || *name == 0 || !libc::strchr(name, b'=' as c_int).is_null() }
}

// Return the first matching slot or the terminator, and the preceding count.
unsafe fn find(
    mut entry: *mut *mut c_char,
    name: *const c_char,
    length: usize,
) -> (*mut *mut c_char, usize) {
    let mut count = 0;
    unsafe {
        if !entry.is_null() {
            while !(*entry).is_null() {
                if libc::strncmp(*entry, name, length) == 0
                    && *(*entry).add(length) == b'=' as c_char
                {
                    break;
                }
                entry = entry.add(1);
                count += 1;
            }
        }
    }
    (entry, count)
}

/// Shared with localtime_r, never through the public interposable getenv name.
/// # Safety
/// `name` is a C string; callers synchronize environment reads with mutations.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_env_lookup(name: *const c_char) -> *mut c_char {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe {
        if crate::patina_env_read_gate() == 0 {
            return null_mut();
        }
        let base = array();
        if base.is_null() || *name == 0 {
            return null_mut();
        }
        let length = libc::strlen(name);
        let (entry, _) = find(base, name, length);
        if (*entry).is_null() {
            null_mut()
        } else {
            (*entry).add(length + 1)
        }
    }
}

// All allocation uses the same libc allocator as C guests, not their Rust
// global allocator. Only pointer arrays we allocated ourselves may be freed.
unsafe fn add(
    name: *const c_char,
    value: *const c_char,
    combined: *mut c_char,
    replace: c_int,
) -> c_int {
    unsafe {
        let length = libc::strlen(name);
        let _lock = EnvLock::take();
        let base = array();
        let (mut entry, size) = find(base, name, length);
        if entry.is_null() || (*entry).is_null() {
            let Some(bytes) = size
                .checked_add(2)
                .and_then(|n| n.checked_mul(size_of::<*mut c_char>()))
            else {
                return crate::variadic::error(libc::ENOMEM);
            };
            // Remember ownership before realloc invalidates the old pointer.
            let owned = base == ALLOCATED;
            let grown = libc::realloc(ALLOCATED.cast(), bytes).cast::<*mut c_char>();
            if grown.is_null() {
                return crate::variadic::error(libc::ENOMEM);
            }
            if !owned && size != 0 {
                ptr::copy_nonoverlapping(base, grown, size);
            }
            *grown.add(size) = null_mut();
            *grown.add(size + 1) = null_mut();
            entry = grown.add(size);
            ALLOCATED = grown;
            patina_environ_install(grown);
        }
        if (*entry).is_null() || replace != 0 {
            let mut string = combined;
            if string.is_null() {
                let bytes = libc::strlen(value) + 1;
                let Some(total) = length.checked_add(1).and_then(|n| n.checked_add(bytes)) else {
                    return crate::variadic::error(libc::ENOMEM);
                };
                string = libc::malloc(total).cast();
                if string.is_null() {
                    return crate::variadic::error(libc::ENOMEM);
                }
                ptr::copy_nonoverlapping(name, string, length);
                *string.add(length) = b'=' as c_char;
                ptr::copy_nonoverlapping(value, string.add(length + 1), bytes);
            }
            *entry = string;
        }
        0
    }
}

unsafe fn remove(name: *const c_char, length: usize) {
    unsafe {
        let _lock = EnvLock::take();
        let mut entry = array();
        if entry.is_null() {
            return;
        }
        while !(*entry).is_null() {
            if libc::strncmp(*entry, name, length) == 0 && *(*entry).add(length) == b'=' as c_char {
                let mut shift = entry;
                loop {
                    *shift = *shift.add(1);
                    if (*shift).is_null() {
                        break;
                    }
                    shift = shift.add(1);
                }
            } else {
                entry = entry.add(1);
            }
        }
    }
}

/// # Safety
/// `name` is a C string; readers synchronize with mutations as in libc.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getenv(name: *const c_char) -> *mut c_char {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::patina_note_boundary_symbol(c"getenv".as_ptr());
    unsafe { patina_env_lookup(name) }
}

/// # Safety
/// `name` and `value` are C strings (null/invalid names are rejected).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn setenv(
    name: *const c_char,
    value: *const c_char,
    overwrite: c_int,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::patina_note_boundary_symbol(c"setenv".as_ptr());
    unsafe {
        if invalid(name) {
            return crate::variadic::error(libc::EINVAL);
        }
        if crate::patina_env_write_gate() != 0 {
            return crate::variadic::model_result(-1);
        }
        add(name, value, null_mut(), overwrite)
    }
}

/// # Safety
/// `name` is a C string (null/invalid names are rejected).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unsetenv(name: *const c_char) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::patina_note_boundary_symbol(c"unsetenv".as_ptr());
    unsafe {
        if invalid(name) {
            return crate::variadic::error(libc::EINVAL);
        }
        if crate::patina_env_write_gate() != 0 {
            return crate::variadic::model_result(-1);
        }
        remove(name, libc::strlen(name));
        0
    }
}

#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub extern "C" fn clearenv() -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::patina_note_boundary_symbol(c"clearenv".as_ptr());
    if crate::patina_env_write_gate() != 0 {
        return crate::variadic::model_result(-1);
    }
    unsafe {
        let _lock = EnvLock::take();
        let base = array();
        if !base.is_null() && base == ALLOCATED {
            libc::free(base.cast());
            ALLOCATED = null_mut();
        }
        patina_environ_install(null_mut());
    }
    0
}

/// # Safety
/// `string` is writable, terminated, and stays live while present in environ.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn putenv(string: *mut c_char) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::patina_note_boundary_symbol(c"putenv".as_ptr());
    if crate::patina_env_write_gate() != 0 {
        return crate::variadic::model_result(-1);
    }
    unsafe {
        let end = libc::strchr(string, b'=' as c_int);
        if end.is_null() {
            remove(string, libc::strlen(string));
            return 0;
        }
        let length = end.offset_from(string) as usize;
        let name = libc::malloc(length + 1).cast::<c_char>();
        if name.is_null() {
            return crate::variadic::error(libc::ENOMEM);
        }
        ptr::copy_nonoverlapping(string, name, length);
        *name.add(length) = 0;
        let result = add(name, ptr::null(), string, 1);
        libc::free(name.cast());
        result
    }
}

#[cfg(target_os = "linux")]
/// # Safety
/// Same contract as getenv; the modeled process has no AT_SECURE.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn secure_getenv(name: *const c_char) -> *mut c_char {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::patina_note_boundary_symbol(c"secure_getenv".as_ptr());
    unsafe { patina_env_lookup(name) }
}

#[cfg(target_os = "linux")]
core::arch::global_asm!(
    ".globl patina_route_getenv",
    ".hidden patina_route_getenv",
    ".set patina_route_getenv, getenv"
);

#[cfg(target_os = "linux")]
core::arch::global_asm!(
    ".globl patina_route_setenv",
    ".hidden patina_route_setenv",
    ".set patina_route_setenv, setenv"
);

#[cfg(target_os = "linux")]
core::arch::global_asm!(
    ".globl patina_route_unsetenv",
    ".hidden patina_route_unsetenv",
    ".set patina_route_unsetenv, unsetenv"
);

#[cfg(target_os = "linux")]
core::arch::global_asm!(
    ".globl patina_route_clearenv",
    ".hidden patina_route_clearenv",
    ".set patina_route_clearenv, clearenv"
);

#[cfg(target_os = "linux")]
core::arch::global_asm!(
    ".globl patina_route_putenv",
    ".hidden patina_route_putenv",
    ".set patina_route_putenv, putenv"
);

#[cfg(target_os = "linux")]
core::arch::global_asm!(
    ".globl patina_route_secure_getenv",
    ".hidden patina_route_secure_getenv",
    ".set patina_route_secure_getenv, secure_getenv"
);

#[cfg(target_os = "linux")]
core::arch::global_asm!(".hidden patina_env_save_host");
#[cfg(target_os = "macos")]
core::arch::global_asm!(".private_extern _patina_env_save_host");

#[cfg(target_os = "linux")]
core::arch::global_asm!(".hidden patina_environ_install");
#[cfg(target_os = "macos")]
core::arch::global_asm!(".private_extern _patina_environ_install");

#[cfg(target_os = "linux")]
core::arch::global_asm!(".hidden patina_capture_control_plane");
#[cfg(target_os = "macos")]
core::arch::global_asm!(".private_extern _patina_capture_control_plane");

#[cfg(target_os = "linux")]
core::arch::global_asm!(".hidden patina_control_getenv");
#[cfg(target_os = "macos")]
core::arch::global_asm!(".private_extern _patina_control_getenv");

#[cfg(target_os = "linux")]
core::arch::global_asm!(".hidden patina_scrub_environ");
#[cfg(target_os = "macos")]
core::arch::global_asm!(".private_extern _patina_scrub_environ");

#[cfg(target_os = "linux")]
core::arch::global_asm!(".hidden patina_env_lookup");
#[cfg(target_os = "macos")]
core::arch::global_asm!(".private_extern _patina_env_lookup");
