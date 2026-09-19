use std::arch::asm;
use std::os::fd::AsRawFd;
#[repr(C)]
struct Flock {
    l_type: i16,
    l_whence: i16,
    l_start: i64,
    l_len: i64,
    l_pid: i32,
}
fn whole(l_type: i16) -> Flock {
    Flock {
        l_type,
        l_whence: 0,
        l_start: 0,
        l_len: 0,
        l_pid: 0,
    }
}
fn main() {
    let f = std::fs::File::create("/fcntl-lock.txt").expect("create");
    let fd = f.as_raw_fd() as i64;
    const FCNTL: i64 = 72;
    const F_GETLK: i64 = 5;
    const F_SETLK: i64 = 6;
    let mut lock = whole(1);
    let raw_set: i64;
    unsafe {
        asm!("syscall", inlateout("rax") FCNTL => raw_set, in("rdi") fd,
        in("rsi") F_SETLK, in("rdx") &mut lock as *mut Flock as i64, in("r10") 0i64,
        out("rcx") _, out("r11") _, options(nostack));
    }
    let mut probe = whole(1);
    let raw_get: i64;
    unsafe {
        asm!("syscall", inlateout("rax") FCNTL => raw_get, in("rdi") fd,
        in("rsi") F_GETLK, in("rdx") &mut probe as *mut Flock as i64, in("r10") 0i64,
        out("rcx") _, out("r11") _, options(nostack));
    }
    unsafe extern "C" {
        fn fcntl(fd: i32, cmd: i32, ...) -> i32;
    }
    let mut lib_lock = whole(1);
    let lib_set = unsafe { fcntl(fd as i32, 6, &mut lib_lock as *mut Flock) };
    let mut lib_probe = whole(1);
    let lib_get = unsafe { fcntl(fd as i32, 5, &mut lib_probe as *mut Flock) };
    println!(
        "FCNTL_LOCK_PARITY raw_set={raw_set} raw_get={raw_get} raw_type={} libc_set={lib_set} libc_get={lib_get} libc_type={}",
        probe.l_type, lib_probe.l_type
    );
}
