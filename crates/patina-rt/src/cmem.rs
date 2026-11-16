//! memcpy and friends for a freestanding image. Written with string
//! instructions so the compiler cannot turn them back into calls to themselves.

use core::arch::asm;
use core::ffi::c_void;

#[no_mangle]
pub unsafe extern "C" fn memcpy(d: *mut c_void, s: *const c_void, n: usize) -> *mut c_void {
    asm!("rep movsb", inout("rcx") n => _, inout("rdi") d => _, inout("rsi") s => _, options(nostack, preserves_flags));
    d
}

#[no_mangle]
pub unsafe extern "C" fn memmove(d: *mut c_void, s: *const c_void, n: usize) -> *mut c_void {
    if (d as usize) <= (s as usize) || (d as usize) >= (s as usize + n) {
        return memcpy(d, s, n);
    }
    let (d8, s8) = (d as *mut u8, s as *const u8);
    // overlapping, copy backwards
    asm!("std", "rep movsb", "cld",
         inout("rcx") n => _, inout("rdi") d8.add(n).wrapping_sub(1) => _, inout("rsi") s8.add(n).wrapping_sub(1) => _,
         options(nostack));
    d
}

#[no_mangle]
pub unsafe extern "C" fn memset(d: *mut c_void, c: i32, n: usize) -> *mut c_void {
    asm!("rep stosb", inout("rcx") n => _, inout("rdi") d => _, in("al") c as u8, options(nostack, preserves_flags));
    d
}

#[no_mangle]
pub unsafe extern "C" fn memcmp(a: *const c_void, b: *const c_void, n: usize) -> i32 {
    let (a, b) = (a as *const u8, b as *const u8);
    let mut i = 0;
    while i < n {
        let x = core::ptr::read_volatile(a.add(i));
        let y = core::ptr::read_volatile(b.add(i));
        if x != y {
            return x as i32 - y as i32;
        }
        i += 1;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn bcmp(a: *const c_void, b: *const c_void, n: usize) -> i32 {
    memcmp(a, b, n)
}
