use std::ffi::{c_int, c_void};

unsafe extern "C" {
    fn signal(signum: c_int, handler: *mut c_void) -> *mut c_void;
}

extern "C" fn ignore(_signum: c_int) {}

fn main() {
    // SAFETY: a plain signal(2) registration; the shim refuses SIGSEGV while the
    // timestamp-counter trap is armed.
    let previous = unsafe { signal(11, ignore as *mut c_void) };
    println!("SEGV_REGISTER_REFUSED={}", previous as isize == -1);
}
