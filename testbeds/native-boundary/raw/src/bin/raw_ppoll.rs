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
// Class pairing: readiness/poll host oracle and signals readiness wait tests.
fn main() {
    const PPOLL: i64 = 271;
    const PIPE2: i64 = 293;
    const WRITE: i64 = 1;
    const POLLIN: i16 = 1;
    match std::env::args().nth(1).as_deref() {
        Some("timeout") => {
            let before = mono_ns();
            let mut tmo = Ts {
                sec: 0,
                nsec: 5_000_000,
            };
            assert_eq!(
                unsafe { sc5(PPOLL, 0, 0, &mut tmo as *mut Ts as i64, 0, 0) },
                0
            );
            let delta = mono_ns() - before;
            assert_eq!(delta, 5_000_000);
            assert_eq!(
                (tmo.sec, tmo.nsec),
                (0, 0),
                "raw ppoll writes remaining timeout"
            );
            println!("PPOLL_TIMEOUT elapsed={delta} remaining=0");
        }
        Some("readiness") => {
            let mut fds = [-1i32; 2];
            assert_eq!(
                unsafe { sc5(PIPE2, fds.as_mut_ptr() as i64, 0, 0, 0, 0) },
                0
            );
            let mut pfd = Pollfd {
                fd: fds[0],
                events: POLLIN,
                revents: 0,
            };
            let mut z = Ts { sec: 0, nsec: 0 };
            assert_eq!(
                unsafe {
                    sc5(
                        PPOLL,
                        &mut pfd as *mut Pollfd as i64,
                        1,
                        &mut z as *mut Ts as i64,
                        0,
                        0,
                    )
                },
                0
            );
            assert_eq!(pfd.revents, 0, "an empty pipe is not readable");
            assert_eq!(
                unsafe { sc5(WRITE, fds[1] as i64, b"x".as_ptr() as i64, 1, 0, 0) },
                1
            );
            assert_eq!(
                unsafe {
                    sc5(
                        PPOLL,
                        &mut pfd as *mut Pollfd as i64,
                        1,
                        &mut z as *mut Ts as i64,
                        0,
                        0,
                    )
                },
                1
            );
            assert_eq!(pfd.revents, POLLIN);
            println!("PPOLL_READINESS empty=0 ready=1 revents=1");
        }
        _ => panic!("expected timeout or readiness"),
    }
}
