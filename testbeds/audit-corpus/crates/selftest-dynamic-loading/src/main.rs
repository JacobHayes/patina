use std::os::raw::{c_char, c_void};

#[cfg(target_os = "linux")]
extern "C" {
    fn dlmopen(namespace: isize, path: *const c_char, flags: i32) -> *mut c_void;
}
#[cfg(target_os = "macos")]
extern "C" {
    fn dlopen_preflight(path: *const c_char) -> bool;
}

fn main() {
    // Keeps the loader import live without ever calling it: the guard is an
    // argv the selftest never passes.
    if std::env::args().any(|arg| arg == "--load") {
        let path = b"libnever.so\0".as_ptr().cast();
        #[cfg(target_os = "linux")]
        println!("handle={:?}", unsafe { dlmopen(0, path, 2) });
        #[cfg(target_os = "macos")]
        println!("loadable={}", unsafe { dlopen_preflight(path) });
    } else {
        println!("load not requested");
    }
}
