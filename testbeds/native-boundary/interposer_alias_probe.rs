// glibc exports `__mmap` and `__munmap` beside `mmap` and `munmap`. The shim
// defines only the plain names, so these aliases would run glibc's own text,
// whose system calls reach the host kernel past the mapping model: the
// pre-run gate refuses the binary by name. The calls are unconditional so the
// imports survive linking.
use std::ffi::{c_int, c_void};
unsafe extern "C" {
    fn __mmap(hint: *mut c_void, length: usize, prot: c_int, flags: c_int, fd: c_int, offset: i64)
    -> *mut c_void;
    fn __munmap(address: *mut c_void, length: usize) -> c_int;
}
const PROT_READ: c_int = 1;
const MAP_PRIVATE: c_int = 2;
const MAP_ANONYMOUS: c_int = 0x20;
fn main() {
    let page = unsafe { __mmap(std::ptr::null_mut(), 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) };
    std::hint::black_box(unsafe { __munmap(page, 4096) });
    println!("INTERPOSER_ALIAS_RAN");
}
