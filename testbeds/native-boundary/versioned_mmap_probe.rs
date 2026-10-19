// A `.symver`-pinned reference to a name the shim interposes,
// `mmap@GLIBC_2.2.5` (x86-64; `GLIBC_2.17` on aarch64, the architecture base
// version, present on every supported glibc), still reaches the shim's `mmap`:
// GNU ld (the aarch64 default) binds it to the executable's own unversioned
// definition, and lld (rustc's x86-64 default) leaves an undefined versioned
// import that the loader binds to the executable's exported definition before
// libc's, since a definition at the global version index satisfies a
// reference of any version. The probe reports which `mmap` its call is bound
// to. The call is unconditional so the reference survives linking.
use std::ffi::{c_int, c_void};

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(".symver mmap_versioned, mmap@GLIBC_2.2.5");
#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(".symver mmap_versioned, mmap@GLIBC_2.17");

unsafe extern "C" {
    // The plain name binds to the shim's definition in a shim-linked guest.
    fn mmap(
        hint: *mut c_void,
        length: usize,
        prot: c_int,
        flags: c_int,
        fd: c_int,
        offset: i64,
    ) -> *mut c_void;
    fn mmap_versioned(
        hint: *mut c_void,
        length: usize,
        prot: c_int,
        flags: c_int,
        fd: c_int,
        offset: i64,
    ) -> *mut c_void;
}

const PROT_READ: c_int = 1;
const MAP_PRIVATE: c_int = 2;
const MAP_ANONYMOUS: c_int = 0x20;

fn main() {
    let page = unsafe {
        mmap_versioned(
            std::ptr::null_mut(),
            4096,
            PROT_READ,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    std::hint::black_box(page);
    let versioned = mmap_versioned as *const ();
    let interposed = mmap as *const ();
    let bound = if versioned == interposed { "shim" } else { "libc" };
    println!("VERSIONED_MMAP_BOUND={bound}");
}
