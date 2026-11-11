// Create a file whose name is not UTF-8 (`a\xffb`, a valid Linux name),
// through the door the argument names: `libc` (std's `open`, the C
// interposer) or, on Linux, `raw` (an `openat` syscall instruction, the SUD
// row). The simulated filesystem holds UTF-8 names only, so under patina the
// run stops before `CREATED` prints; natively the file round-trips.
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
unsafe fn raw_openat(path: *const u8, flags: i64, mode: i64) -> i64 {
    let ret: i64;
    unsafe {
        std::arch::asm!("syscall", inlateout("rax") 257i64 => ret, in("rdi") -100i64,
             in("rsi") path, in("rdx") flags, in("r10") mode,
             out("rcx") _, out("r11") _, options(nostack));
    }
    ret
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
unsafe fn raw_openat(path: *const u8, flags: i64, mode: i64) -> i64 {
    let ret: i64;
    unsafe {
        std::arch::asm!("svc #0", in("x8") 56i64, inlateout("x0") -100i64 => ret,
             in("x1") path, in("x2") flags, in("x3") mode, options(nostack));
    }
    ret
}

fn main() {
    let name = b"/tmp/a\xffb";
    match std::env::args().nth(1).as_deref() {
        Some("libc") => std::fs::write(OsStr::from_bytes(name), b"x").unwrap(),
        #[cfg(target_os = "linux")]
        Some("raw") => {
            let path = [&name[..], b"\0"].concat();
            // O_CREAT | O_WRONLY
            let fd = unsafe { raw_openat(path.as_ptr(), 0o100 | 1, 0o644) };
            assert!(fd >= 0, "openat: {fd}");
        }
        other => panic!("unknown door {other:?}"),
    }
    println!("CREATED");
}
