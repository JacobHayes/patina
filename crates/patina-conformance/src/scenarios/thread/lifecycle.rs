//! thread/lifecycle — set_tid_address return value, futex mismatch semantics,
//! and main-thread raw exit while another thread keeps the process alive
//! (checked in a child oracle).

use crate::catalog::{DEFAULTS, Gap, Scenario, Status};
use crate::compare::{Ending, Failure};
use crate::vehicle::Vehicle;
use patina_dst_syscalls::Syscall;

use crate::probe::{Probe, neg};
use crate::vehicle::fold_errno;
use libc::*;
use std::sync::atomic::AtomicU32;
use std::thread;

const WAIT: i32 = FUTEX_WAIT;

/// The wait status reported when the child's helper thread never wrote: an
/// exit with status 127, which the child never produces.
const NO_HELPER_WRITE: c_int = 0x7f00;

fn main_exit_child_status(p: &Probe) -> c_int {
    let mut fds = [0; 2];
    assert_eq!(unsafe { pipe(fds.as_mut_ptr()) }, 0);
    let child = p.fork_child(
        || fold_errno(unsafe { fork() } as i64),
        || unsafe {
            close(fds[0]);
            thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(80));
                write(fds[1], b"a".as_ptr() as *const _, 1);
                close(fds[1]);
            });
            syscall(SYS_exit, 0);
            99
        },
    );
    let mut b = [0u8; 1];
    let n = unsafe {
        close(fds[1]);
        let n = read(fds[0], b.as_mut_ptr() as *mut _, 1);
        close(fds[0]);
        n
    };
    let status = child.wait();
    if n == 1 { status } else { NO_HELPER_WRITE }
}

pub fn run(p: &Probe) {
    let word = AtomicU32::new(0);
    let mut own = 0i32;
    let my_tid = p.set_tid_address(&mut own as *mut i32);
    p.check(
        "set_tid_address returns the caller tid",
        my_tid == p.gettid(),
    );

    let st = main_exit_child_status(p);
    p.rec
        .event("wait_status", 0)
        .arg("case", "main-thread-raw-exit")
        .field("exited", WIFEXITED(st))
        .field("code", WEXITSTATUS(st))
        .emit();
    p.check(
        "main thread raw exit leaves process alive until other threads finish",
        WIFEXITED(st) && WEXITSTATUS(st) == 0,
    );
    p.check(
        "futex wait with mismatched value is EAGAIN",
        p.futex(&word, WAIT, 1, None) == neg(EAGAIN),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "thread/lifecycle",
    run,
    covers: &[
        Syscall::N_set_tid_address,
        Syscall::N_gettid,
        Syscall::N_futex,
        Syscall::N_exit,
    ],
    symbols: &["syscall"],
    gaps: &[Gap {
        status: Status::ByDesign,
        vehicles: Vehicle::ALL,
        what: "fork is a process-lifecycle trap (docs/arcs/syscall-conformance.md §7); the child oracle runs natively only",
        failure: Failure::Stops {
            events: 3,
            ending: Ending::Signal(libc::SIGABRT),
            diagnostic: "patina: process spawn reached under patina: fork; the process class is a deterministic-runtime non-goal; failing closed",
        },
    }],
    ..DEFAULTS
};
