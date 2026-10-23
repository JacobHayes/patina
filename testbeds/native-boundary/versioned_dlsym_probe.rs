// A versioned reference to `dlsym` reaches around the shim's `-Wl,--wrap=dlsym`
// interposer. `--wrap` only rewrites UNVERSIONED undefined references, so a
// `.symver`-pinned `dlsym@GLIBC_2.2.5` (x86-64; `GLIBC_2.17` on aarch64 — each
// is the architecture's base version and present on every supported glibc)
// stays an undefined versioned import that the dynamic linker binds to glibc's
// own resolver at load time, not the shim's restricted `__wrap_dlsym`. With
// libc's real `dlsym` in hand, `dlsym(RTLD_NEXT, "__mmap")` returns glibc's
// mapping primitive, whose system call reaches the host kernel past the mapping
// model. The call is unconditional so the import survives linking.
//
// The binary also imports glibc's `__mmap` and `__munmap`, its aliases of
// `mmap` and `munmap`. The shim defines only the plain names, so the aliases
// would run glibc's own text, whose system calls reach the host kernel past
// the mapping model: the pre-run gate refuses those by name too.
use std::ffi::{CStr, c_int, c_void};
use std::os::raw::c_char;

// `dlsym_versioned` becomes an undefined reference to `dlsym@<base>` — the exact
// escape a compatibility shim writes when it asks for a pinned dlsym ABI. The
// reference is weak, as compatibility code that probes for an optional symbol
// declares it: the shim's own `dlsym` import is weak too, so weakness alone
// cannot tell the two apart (strong pins are refused just the same).
core::arch::global_asm!(".weak dlsym_versioned");
#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(".symver dlsym_versioned, dlsym@GLIBC_2.2.5");
#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(".symver dlsym_versioned, dlsym@GLIBC_2.17");

unsafe extern "C" {
    fn dlsym_versioned(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn __mmap(
        hint: *mut c_void,
        length: usize,
        prot: c_int,
        flags: c_int,
        fd: c_int,
        offset: i64,
    ) -> *mut c_void;
    fn __munmap(address: *mut c_void, length: usize) -> c_int;
}

// `<dlfcn.h>`: `RTLD_NEXT == (void *)-1`.
const RTLD_NEXT: *mut c_void = usize::MAX as *mut c_void;
const PROT_READ: c_int = 1;
const MAP_PRIVATE: c_int = 2;
const MAP_ANONYMOUS: c_int = 0x20;

type MmapFn = unsafe extern "C" fn(*mut c_void, usize, c_int, c_int, c_int, i64) -> *mut c_void;
type MunmapFn = unsafe extern "C" fn(*mut c_void, usize) -> c_int;

fn main() {
    let mmap_name = CStr::from_bytes_with_nul(b"__mmap\0").unwrap();
    let mmap_ptr = unsafe { dlsym_versioned(RTLD_NEXT, mmap_name.as_ptr()) };
    assert!(
        !mmap_ptr.is_null(),
        "versioned dlsym did not resolve __mmap"
    );
    let host_mmap: MmapFn = unsafe { std::mem::transmute(mmap_ptr) };

    let munmap_name = CStr::from_bytes_with_nul(b"__munmap\0").unwrap();
    let munmap_ptr = unsafe { dlsym_versioned(RTLD_NEXT, munmap_name.as_ptr()) };
    let host_munmap: MunmapFn = unsafe { std::mem::transmute(munmap_ptr) };

    let page = unsafe {
        host_mmap(
            std::ptr::null_mut(),
            4096,
            PROT_READ,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert!(page as isize != -1, "host mmap failed");
    std::hint::black_box(unsafe { host_munmap(page, 4096) });
    let alias = unsafe {
        __mmap(
            std::ptr::null_mut(),
            4096,
            PROT_READ,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    std::hint::black_box(unsafe { __munmap(alias, 4096) });
    println!("VERSIONED_DLSYM_ESCAPED");
}
