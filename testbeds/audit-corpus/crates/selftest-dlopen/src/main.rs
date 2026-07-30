use std::os::raw::{c_char, c_int, c_void};

extern "C" {
    fn dlopen(path: *const c_char, flags: c_int) -> *mut c_void;
}

fn main() {
    // Keeps the `dlopen` import live without ever calling it: the guard is an
    // argv the selftest never passes.
    if std::env::args().any(|arg| arg == "--dlopen") {
        let handle = unsafe { dlopen(b"libnever.so\0".as_ptr().cast(), 2) };
        println!("handle={:?}", handle);
    } else {
        println!("dlopen not requested");
    }
}
