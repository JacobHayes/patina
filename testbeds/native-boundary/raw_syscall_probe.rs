#[cfg(target_arch = "x86_64")]
mod raw {
    use std::arch::asm;
    pub const CLOCK_GETTIME: i64 = 228;
    pub const OPENAT: i64 = 257;
    pub const WRITE: i64 = 1;
    pub const READ: i64 = 0;
    pub const LSEEK: i64 = 8;
    pub const CLOSE: i64 = 3;
    pub const GETRANDOM: i64 = 318;
    pub unsafe fn syscall6(nr: i64, a0: i64, a1: i64, a2: i64, a3: i64, a4: i64, a5: i64) -> i64 {
        let ret: i64;
        unsafe {
            asm!("syscall", inlateout("rax") nr => ret, in("rdi") a0, in("rsi") a1,
                 in("rdx") a2, in("r10") a3, in("r8") a4, in("r9") a5,
                 out("rcx") _, out("r11") _, options(nostack));
        }
        ret
    }
}

#[cfg(target_arch = "aarch64")]
mod raw {
    use std::arch::asm;
    pub const CLOCK_GETTIME: i64 = 113;
    pub const OPENAT: i64 = 56;
    pub const WRITE: i64 = 64;
    pub const READ: i64 = 63;
    pub const LSEEK: i64 = 62;
    pub const CLOSE: i64 = 57;
    pub const GETRANDOM: i64 = 278;
    pub unsafe fn syscall6(nr: i64, a0: i64, a1: i64, a2: i64, a3: i64, a4: i64, a5: i64) -> i64 {
        let ret: i64;
        unsafe {
            asm!("svc #0", in("x8") nr, inlateout("x0") a0 => ret, in("x1") a1,
                 in("x2") a2, in("x3") a3, in("x4") a4, in("x5") a5, options(nostack));
        }
        ret
    }
}

const CLOCK_MONOTONIC: i64 = 1;
const AT_FDCWD: i64 = -100;
const O_CREAT: i64 = 0o100;
const O_RDWR: i64 = 2;
// The virtual clock starts near zero and only advances via sleeps; a wall clock
// would read ~1.7e18 ns. Anything under this bound proves the read was virtual.
const VIRTUAL_BOUND: u64 = 1_000_000_000_000_000;

unsafe fn clock_mono() -> u64 {
    let mut ts = [0i64; 2];
    let rc = unsafe {
        raw::syscall6(
            raw::CLOCK_GETTIME,
            CLOCK_MONOTONIC,
            ts.as_mut_ptr() as i64,
            0,
            0,
            0,
            0,
        )
    };
    assert_eq!(rc, 0, "raw clock_gettime rc");
    ts[0] as u64 * 1_000_000_000 + ts[1] as u64
}

fn main() {
    // REGRESSION SHAPE — keep the raw clock reads FIRST, before any thread spawn:
    // the main thread gets its managed TaskId lazily (on first thread-subsystem
    // use), so these deliberately trap on the PRE-ACTIVATION main thread. A
    // dispatch-side check stricter than the interposer thread-semantics (the CI
    // failure that removed §4.2 invariant 1's hard abort) turns this leg red.
    let t0 = unsafe { clock_mono() };
    let t1 = unsafe { clock_mono() };
    let path = b"/sud-raw\0";
    let fd = unsafe {
        raw::syscall6(
            raw::OPENAT,
            AT_FDCWD,
            path.as_ptr() as i64,
            O_CREAT | O_RDWR,
            0o600,
            0,
            0,
        )
    };
    assert!(fd >= 0, "raw openat fd={fd}");
    let msg = b"sud";
    let w = unsafe {
        raw::syscall6(
            raw::WRITE,
            fd,
            msg.as_ptr() as i64,
            msg.len() as i64,
            0,
            0,
            0,
        )
    };
    assert_eq!(w, 3, "raw write");
    let _ = unsafe { raw::syscall6(raw::LSEEK, fd, 0, 0, 0, 0, 0) };
    let mut buf = [0u8; 3];
    let r = unsafe { raw::syscall6(raw::READ, fd, buf.as_mut_ptr() as i64, 3, 0, 0, 0) };
    assert_eq!(r, 3, "raw read");
    let _ = unsafe { raw::syscall6(raw::CLOSE, fd, 0, 0, 0, 0, 0) };
    let mut rnd = [0u8; 8];
    let g = unsafe { raw::syscall6(raw::GETRANDOM, rnd.as_mut_ptr() as i64, 8, 0, 0, 0, 0) };
    assert_eq!(g, 8, "raw getrandom");
    let handles: Vec<_> = (0..3)
        .map(|_| std::thread::spawn(|| unsafe { clock_mono() }))
        .collect();
    let mut all_virtual = t0 < VIRTUAL_BOUND && t1 < VIRTUAL_BOUND && t1 >= t0;
    for h in handles {
        all_virtual &= h.join().unwrap() < VIRTUAL_BOUND;
    }
    let rand_hex: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
    println!(
        "RAW_SUD_RESULT fs={} rand={} threads_virtual={}",
        std::str::from_utf8(&buf).unwrap(),
        rand_hex,
        all_virtual
    );
}
