// The platform libc's entropy surface, whose answers its Patina run must
// match natively: `getentropy`'s size limit and its errno (glibc `EIO`, XNU
// `EINVAL`), an empty request, and which entropy names `dlsym` finds
// (libSystem defines no `getrandom`).
use std::ffi::{c_char, c_void};

unsafe extern "C" {
    fn getentropy(buffer: *mut c_void, length: usize) -> i32;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}

#[cfg(target_os = "linux")]
const RTLD_DEFAULT: *mut c_void = std::ptr::null_mut();
#[cfg(target_os = "macos")]
const RTLD_DEFAULT: *mut c_void = -2isize as *mut c_void;

/// A call's result, or its errno when it failed.
fn answer(result: i32) -> String {
    if result < 0 {
        format!("errno{}", std::io::Error::last_os_error().raw_os_error().unwrap())
    } else {
        result.to_string()
    }
}

fn found(symbol: &std::ffi::CStr) -> &'static str {
    // SAFETY: RTLD_DEFAULT and a NUL-terminated name are dlsym's contract.
    if unsafe { dlsym(RTLD_DEFAULT, symbol.as_ptr()) }.is_null() { "absent" } else { "found" }
}

fn main() {
    let mut buffer = [0u8; 257];
    let pointer = buffer.as_mut_ptr().cast::<c_void>();
    // SAFETY: `buffer` is writable for 257 bytes; an empty request writes none.
    let over = answer(unsafe { getentropy(pointer, 257) });
    let limit = answer(unsafe { getentropy(pointer, 256) });
    let empty = answer(unsafe { getentropy(std::ptr::null_mut(), 0) });
    println!(
        "NATIVE_ENTROPY_LIBC over={over} limit={limit} empty={empty} getentropy={} getrandom={}",
        found(c"getentropy"),
        found(c"getrandom"),
    );
}
