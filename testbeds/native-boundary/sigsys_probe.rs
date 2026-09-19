fn main() {
    unsafe extern "C" {
        fn sigaction(sig: i32, act: *const core::ffi::c_void, old: *mut core::ffi::c_void) -> i32;
    }
    const SIGSYS: i32 = 31;
    // The interposer refuses SIGSYS before dereferencing `act`, so null is safe.
    let rc = unsafe { sigaction(SIGSYS, core::ptr::null(), core::ptr::null_mut()) };
    println!("SIGSYS_REGISTER_REFUSED={}", rc != 0);
}
