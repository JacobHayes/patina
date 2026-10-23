use std::arch::asm;
#[repr(C)]
struct Ts {
    sec: i64,
    nsec: i64,
}
unsafe fn sc5(nr: i64, a0: i64, a1: i64, a2: i64, a3: i64, a4: i64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", inlateout("rax") nr => r, in("rdi") a0, in("rsi") a1,
        in("rdx") a2, in("r10") a3, in("r8") a4, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
fn mono_ns() -> i64 {
    let mut ts = Ts { sec: 0, nsec: 0 };
    unsafe {
        sc5(
            228, /*clock_gettime*/
            1,   /*MONOTONIC*/
            &mut ts as *mut Ts as i64,
            0,
            0,
            0,
        );
    }
    ts.sec * 1_000_000_000 + ts.nsec
}
// Class pairing: readiness/poll host oracle, whose ppoll passes its timeout
// read-only; the raw row writes the remaining time back.
fn main() {
    const PPOLL: i64 = 271;
    let before = mono_ns();
    let mut tmo = Ts {
        sec: 0,
        nsec: 5_000_000,
    };
    assert_eq!(
        unsafe { sc5(PPOLL, 0, 0, &mut tmo as *mut Ts as i64, 0, 0) },
        0
    );
    // The timeout, and the calls charged around it.
    let delta = mono_ns() - before;
    assert!((5_000_000..5_100_000).contains(&delta), "{delta}");
    assert_eq!(
        (tmo.sec, tmo.nsec),
        (0, 0),
        "raw ppoll writes remaining timeout"
    );
    println!("PPOLL_TIMEOUT elapsed_ms={} remaining=0", delta / 1_000_000);
}
