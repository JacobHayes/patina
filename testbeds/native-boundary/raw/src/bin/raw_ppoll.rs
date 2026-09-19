use std::arch::asm;
#[repr(C)]
struct Ts {
    sec: i64,
    nsec: i64,
}
#[repr(C)]
struct Pollfd {
    fd: i32,
    events: i16,
    revents: i16,
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
fn main() {
    const PPOLL: i64 = 271;
    let before = mono_ns();
    let tmo = Ts {
        sec: 0,
        nsec: 5_000_000,
    }; // 5ms
    let rc = unsafe { sc5(PPOLL, 0, 0, &tmo as *const Ts as i64, 0, 0) };
    assert_eq!(rc, 0, "ppoll empty+timeout rc {rc}");
    let delta = mono_ns() - before;
    assert!(
        delta >= 5_000_000,
        "ppoll must advance virtual time >= 5ms, got {delta}"
    );
    // Real events with an fd: the deterministic layer models no readiness → soft ENOSYS.
    let mut pfd = Pollfd {
        fd: 0,
        events: 1, /*POLLIN*/
        revents: 0,
    };
    let z = Ts { sec: 0, nsec: 0 };
    let r2 = unsafe {
        sc5(
            PPOLL,
            &mut pfd as *mut Pollfd as i64,
            1,
            &z as *const Ts as i64,
            0,
            0,
        )
    };
    assert_eq!(
        r2, -38,
        "real-events ppoll must be soft -ENOSYS(-38), got {r2}"
    );
    println!("PPOLL_ROW empty_sleep={delta} real_enosys={r2}");
}
