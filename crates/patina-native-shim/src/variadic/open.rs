//! libc open spellings share one flag/mode adapter with fixed C callers.
use core::ffi::{VaList, c_char, c_int};

#[cfg(target_os = "linux")]
core::arch::global_asm!(
    ".globl patina_route_open",
    ".hidden patina_route_open",
    ".set patina_route_open, open",
);
/// # Safety
/// `path` is a C string; creation flags supply the promoted mode argument.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn open(path: *const c_char, flags: c_int, args: ...) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::cancel(c"open");
    // SAFETY: the variadic contract supplies a creation mode when required.
    unsafe { decode(libc::AT_FDCWD, path, flags, args) }
}

#[cfg(target_os = "linux")]
core::arch::global_asm!(
    ".globl patina_route_openat",
    ".hidden patina_route_openat",
    ".set patina_route_openat, openat",
);
/// # Safety
/// `path` is a C string; creation flags supply the promoted mode argument.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn openat(
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
    args: ...
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::cancel(c"openat");
    // SAFETY: the variadic contract supplies a creation mode when required.
    unsafe { decode(dirfd, path, flags, args) }
}

#[cfg(target_os = "linux")]
core::arch::global_asm!(
    ".globl patina_route_open64",
    ".hidden patina_route_open64",
    ".set patina_route_open64, open64",
);
#[cfg(target_os = "linux")]
/// # Safety
/// `path` is a C string; creation flags supply the promoted mode argument.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn open64(path: *const c_char, flags: c_int, args: ...) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::cancel(c"open64");
    // SAFETY: the variadic contract supplies a creation mode when required.
    unsafe { decode(libc::AT_FDCWD, path, flags, args) }
}

#[cfg(target_os = "linux")]
core::arch::global_asm!(
    ".globl patina_route_openat64",
    ".hidden patina_route_openat64",
    ".set patina_route_openat64, openat64",
);
#[cfg(target_os = "linux")]
/// # Safety
/// `path` is a C string; creation flags supply the promoted mode argument.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn openat64(
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
    args: ...
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::cancel(c"openat64");
    // SAFETY: the variadic contract supplies a creation mode when required.
    unsafe { decode(dirfd, path, flags, args) }
}

#[cfg(target_os = "linux")]
core::arch::global_asm!(
    ".globl patina_route___open",
    ".hidden patina_route___open",
    ".set patina_route___open, __open",
);
#[cfg(target_os = "linux")]
/// # Safety
/// `path` is a C string; creation flags supply the promoted mode argument.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __open(path: *const c_char, flags: c_int, args: ...) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::cancel(c"__open");
    // SAFETY: the variadic contract supplies a creation mode when required.
    unsafe { decode(libc::AT_FDCWD, path, flags, args) }
}

#[cfg(target_os = "linux")]
core::arch::global_asm!(
    ".globl patina_route___open64",
    ".hidden patina_route___open64",
    ".set patina_route___open64, __open64",
);
#[cfg(target_os = "linux")]
/// # Safety
/// `path` is a C string; creation flags supply the promoted mode argument.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __open64(path: *const c_char, flags: c_int, args: ...) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::cancel(c"__open64");
    // SAFETY: the variadic contract supplies a creation mode when required.
    unsafe { decode(libc::AT_FDCWD, path, flags, args) }
}

unsafe fn decode(dirfd: c_int, path: *const c_char, flags: c_int, mut args: VaList<'_>) -> c_int {
    let mutated = super::fault(3);
    let needs_mode = flags & libc::O_CREAT != 0;
    #[cfg(target_os = "linux")]
    let needs_mode = needs_mode || flags & libc::O_TMPFILE == libc::O_TMPFILE;
    let mut mode = 0;
    if needs_mode {
        // SAFETY: Linux mode_t is unsigned int; Darwin's u16 promotes to int.
        #[cfg(target_os = "linux")]
        {
            mode = unsafe { args.next_arg::<core::ffi::c_uint>() };
        }
        #[cfg(target_os = "macos")]
        {
            mode = unsafe { args.next_arg::<c_int>() } as u32;
        }
    }
    if mutated {
        #[cfg(target_os = "linux")]
        {
            mode = unsafe { args.next_arg::<core::ffi::c_uint>() };
        }
        #[cfg(target_os = "macos")]
        {
            mode = unsafe { args.next_arg::<c_int>() } as u32;
        }
    }
    // SAFETY: same path contract as the public door.
    unsafe { implementation(dirfd, path, flags, mode) }
}

/// Fixed entry shared by creat and fortify wrappers that remain in C.
/// # Safety
/// `path` points to a NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_openat_impl(
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
    mode: u32,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: caller supplies a valid path.
    unsafe { implementation(dirfd, path, flags, mode) }
}

unsafe fn implementation(dirfd: c_int, path: *const c_char, flags: c_int, mode: u32) -> c_int {
    crate::patina_note_boundary_symbol(c"open".as_ptr());
    let supported = libc::O_ACCMODE
        | libc::O_CREAT
        | libc::O_TRUNC
        | libc::O_APPEND
        | libc::O_EXCL
        | libc::O_CLOEXEC
        | libc::O_NOFOLLOW
        | libc::O_DIRECTORY
        | libc::O_NONBLOCK
        | libc::O_NOCTTY;
    #[cfg(target_os = "linux")]
    let supported = supported | libc::O_LARGEFILE | libc::O_PATH;
    if flags & !supported != 0 {
        return super::error(libc::ENOSYS);
    }
    #[cfg(target_os = "linux")]
    let path_only = flags & libc::O_PATH != 0;
    #[cfg(target_os = "macos")]
    let path_only = false;
    let mut translated = if path_only {
        crate::O_PATH
    } else {
        match flags & libc::O_ACCMODE {
            libc::O_RDONLY => crate::O_READ,
            libc::O_WRONLY => crate::O_WRITE,
            libc::O_RDWR => crate::O_READ | crate::O_WRITE,
            _ => return super::error(libc::EINVAL),
        }
    };
    if !path_only {
        for (source, target) in [
            (libc::O_CREAT, crate::O_CREATE),
            (libc::O_TRUNC, crate::O_TRUNCATE),
            (libc::O_APPEND, crate::O_APPEND),
            (libc::O_EXCL, crate::O_EXCLUSIVE),
        ] {
            if flags & source != 0 {
                translated |= target;
            }
        }
    }
    for (source, target) in [
        (libc::O_NOFOLLOW, crate::O_NOFOLLOW),
        (libc::O_NONBLOCK, crate::O_NONBLOCK),
        (libc::O_CLOEXEC, crate::O_CLOEXEC),
        (libc::O_DIRECTORY, crate::O_DIRECTORY),
        (libc::O_NOCTTY, crate::O_NOCTTY),
    ] {
        if flags & source != 0 {
            translated |= target;
        }
    }
    let dirfd = if dirfd == libc::AT_FDCWD {
        crate::paths::AT_FDCWD
    } else {
        dirfd
    };
    // SAFETY: path belongs to the caller; model owns all descriptor/path resolution.
    super::model_result(unsafe { crate::patina_openat(dirfd, path, translated, mode & 0o7777) })
}

// Fixed C callers must bind the adapter defined in this guest archive.
#[cfg(target_os = "linux")]
core::arch::global_asm!(".hidden patina_openat_impl");
#[cfg(target_os = "macos")]
core::arch::global_asm!(".private_extern _patina_openat_impl");
