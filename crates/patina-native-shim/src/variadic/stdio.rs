//! Variadic formatting doors; C retains FILE layouts, locking and vsnprintf.
use core::ffi::{VaList, c_char, c_int};

unsafe extern "C" {
    fn patina_format_bridge(
        stream: *mut libc::FILE,
        format: *const c_char,
        args: VaList<'_>,
        stdout: c_int,
    ) -> c_int;
}

#[cfg(target_os = "linux")]
core::arch::global_asm!(
    ".globl patina_route_printf",
    ".hidden patina_route_printf",
    ".set patina_route_printf, printf",
    ".globl patina_route_fprintf",
    ".hidden patina_route_fprintf",
    ".set patina_route_fprintf, fprintf",
);

/// # Safety
/// Format and arguments obey printf's contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn printf(format: *const c_char, args: ...) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the modeled C engine owns the stdout sentinel and copies VaList.
    unsafe { format_to(core::ptr::null_mut(), format, args, 1) }
}

/// # Safety
/// Stream, format and arguments obey fprintf's contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fprintf(
    stream: *mut libc::FILE,
    format: *const c_char,
    args: ...
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the bridge validates the sentinel before formatting.
    unsafe { format_to(stream, format, args, 0) }
}

/// Internal assertion formatter using the same modeled stream door.
/// # Safety
/// Stream, format and arguments obey fprintf's contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_stream_printf(
    stream: *mut libc::FILE,
    format: *const c_char,
    args: ...
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: callers supply a modeled FILE sentinel, never an internal layout.
    unsafe { format_to(stream, format, args, 0) }
}

unsafe fn format_to(
    stream: *mut libc::FILE,
    format: *const c_char,
    mut args: VaList<'_>,
    stdout: c_int,
) -> c_int {
    if super::fault(7) {
        // SAFETY: the armed probe supplies two int operands to expose this shift.
        let _ = unsafe { args.next_arg::<c_int>() };
    }
    // SAFETY: this is a real platform VaList, not a pointer-sized substitute.
    unsafe { patina_format_bridge(stream, format, args, stdout) }
}
