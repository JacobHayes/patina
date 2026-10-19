// Entropy requests whose destination stops being writable, answered as the
// host kernel answers them. Linux 6.8 (`get_random_bytes_user`) answers a
// `getrandom` or `/dev/urandom` read with the bytes written before the fault,
// or `EFAULT` when there are none, and a NULL request of `MAX_RW_COUNT` bytes
// is `EFAULT` without the request's size ever being allocated. XNU's
// `random_read` answers a short `/dev/urandom` read with `EFAULT`. A
// `getentropy` that straddles the fault is `EFAULT` on both.
//
// Linux's `getrandom` requests go through `syscall(2)`, which enters the
// kernel on every glibc: from 2.41 glibc's `getrandom` fills the buffer from
// the vDSO in user space, so a fault there is the caller's own SIGSEGV, not
// the kernel's answer. With `ENTROPY_BOUNDS_DOOR=libc` they go through the
// `getrandom` symbol instead: under patina the shim's exported wrapper,
// which answers as glibc 2.39's (the system call) does.
use std::ffi::c_void;
use std::os::fd::AsRawFd;

/// A multiple of every host page size: Linux's 4 KiB and Apple silicon's 16 KiB.
const SPAN: usize = 16 * 1024;
#[cfg(target_os = "linux")]
const MAX_RW_COUNT: usize = 2_147_479_552;
const PROT_READ_WRITE: i32 = 0x1 | 0x2;
#[cfg(target_os = "linux")]
const MAP_PRIVATE_ANONYMOUS: i32 = 0x02 | 0x20;
#[cfg(target_os = "macos")]
const MAP_PRIVATE_ANONYMOUS: i32 = 0x02 | 0x1000;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SYS_GETRANDOM: i64 = 318;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const SYS_GETRANDOM: i64 = 278;

unsafe extern "C" {
    #[cfg(target_os = "linux")]
    fn syscall(number: i64, ...) -> i64;
    #[cfg(target_os = "linux")]
    #[link_name = "getrandom"]
    fn libc_getrandom(buffer: *mut c_void, length: usize, flags: u32) -> isize;
    fn getentropy(buffer: *mut c_void, length: usize) -> i32;
    fn read(fd: i32, buffer: *mut c_void, length: usize) -> isize;
    fn mmap(address: *mut c_void, length: usize, prot: i32, flags: i32, fd: i32, offset: i64)
    -> *mut c_void;
    fn munmap(address: *mut c_void, length: usize) -> i32;
}

/// `getrandom(2)`, through the door `ENTROPY_BOUNDS_DOOR` names: the libc
/// symbol for `libc`, else the kernel.
#[cfg(target_os = "linux")]
unsafe fn getrandom(buffer: *mut c_void, length: usize, flags: u32) -> isize {
    if std::env::var_os("ENTROPY_BOUNDS_DOOR").is_some_and(|door| door == "libc") {
        // SAFETY: the caller's request, as the wrapper takes it.
        return unsafe { libc_getrandom(buffer, length, flags) };
    }
    // SAFETY: the caller's request, passed through as the kernel takes it:
    // each argument a full register, as `syscall(2)` reads them.
    unsafe {
        syscall(SYS_GETRANDOM, buffer as i64, length as i64, i64::from(flags)) as isize
    }
}

/// A call's result, or its errno when it failed.
fn answer(result: isize) -> String {
    if result < 0 {
        format!("errno{}", std::io::Error::last_os_error().raw_os_error().unwrap())
    } else {
        result.to_string()
    }
}

fn main() {
    let mut fields = Vec::new();
    #[cfg(target_os = "linux")]
    // SAFETY: NULL with a length is the request under test; nothing is written.
    fields.push(format!(
        "huge_null={}",
        answer(unsafe { getrandom(std::ptr::null_mut(), MAX_RW_COUNT, 0) })
    ));

    // One writable span of host pages followed by an unmapped one.
    // SAFETY: a fresh private anonymous mapping, its second page then unmapped.
    let page = unsafe {
        let base = mmap(std::ptr::null_mut(), 2 * SPAN, PROT_READ_WRITE, MAP_PRIVATE_ANONYMOUS, -1, 0);
        assert_ne!(base as isize, -1, "mmap");
        assert_eq!(munmap(base.cast::<u8>().add(SPAN).cast(), SPAN), 0, "munmap");
        base
    };
    // Each call below writes at most the mapped span; the rest faults.
    #[cfg(target_os = "linux")]
    // SAFETY: as above.
    fields.push(format!("partial={}", answer(unsafe { getrandom(page, 2 * SPAN, 0) })));
    let urandom = std::fs::File::open("/dev/urandom").expect("open /dev/urandom");
    // SAFETY: as above.
    let urandom_partial = answer(unsafe { read(urandom.as_raw_fd(), page, 2 * SPAN) });
    fields.push(format!("urandom_partial={urandom_partial}"));
    // SAFETY: the address stays inside the mapping's first span.
    let straddle = unsafe { page.cast::<u8>().add(SPAN - 16).cast() };
    // SAFETY: as above.
    let getentropy_straddle = answer(unsafe { getentropy(straddle, 32) } as isize);
    fields.push(format!("getentropy_straddle={getentropy_straddle}"));
    println!("NATIVE_ENTROPY_BOUNDS {}", fields.join(" "));
}
