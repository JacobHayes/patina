//! time/fault — the clock, sleep and timeout rows handed pointers the kernel
//! cannot use (kernel/time/posix-timers.c, time.c, hrtimer.c, sys.c,
//! fs/select.c, fs/eventpoll.c, kernel/futex/syscalls.c): each is `EFAULT`,
//! judged in the kernel's order, and what the call did before the copy
//! stands:
//!
//! * `clock_gettime`, `clock_getres`, `gettimeofday` (its time, then its zone,
//!   the time already written), `time`, `times` and `getrusage` into an
//!   unwritable buffer; an unknown clock or `who` is `EINVAL` first;
//! * `nanosleep` and `clock_nanosleep` from an unreadable (or NULL) request;
//!   a sleep a handler interrupts, its remaining time unwritable, is `EFAULT`
//!   instead of `EINTR` (`nanosleep_copyout`);
//! * `settimeofday` from an unreadable time or zone (the zone is copied in
//!   before the privilege is judged), `clock_settime` from an unreadable
//!   time;
//! * `adjtimex` copies its structure back whatever it answered, so a
//!   read-only one is `EFAULT` even for a request it refuses;
//!   `clock_adjtime` copies back only what the clock took (`EPERM`);
//! * `FUTEX_WAIT`, `epoll_pwait2` (before its mask's size is judged),
//!   `ppoll` and `pselect6` from an unreadable timeout; a timeout in
//!   read-only memory is not written back, and the wait answers as it
//!   would have (`poll_select_finish`);
//! * `getitimer`, `timer_gettime` and `sched_rr_get_interval` into an
//!   unwritable setting (an unknown `which`, timer or a negative pid is
//!   `EINVAL` first); `setitimer` and `timer_settime` from an unreadable one
//!   (`setitimer`'s before `which` is judged) and into an unwritable old one,
//!   after the new one took; `timer_create` from an unreadable `sigevent`
//!   (before the clock is judged) and into an unwritable id;
//! * `semtimedop` from an unreadable timeout, and from unreadable operations
//!   before the id is judged; `mq_timedsend`/`mq_timedreceive` from an
//!   unreadable timeout before the descriptor is judged.
//!
//! Its own scenario, because a door that dereferences the pointer itself
//! ends the whole run (and a crash loses the captured event stream). Raw
//! vehicles only: glibc's wrappers of the clock reads are not the rows
//! (time/libc_fault holds them).

use crate::catalog::{DEFAULTS, Need, Scenario};
use crate::probe::{FUTEX_WAIT_PRIVATE, Probe, neg};
use crate::signals as support;
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

/// An address no mapping holds (the zero page).
pub(super) const UNMAPPED: i64 = 1;

/// `ADJ_FREQUENCY`: a change an unprivileged caller may not make.
const ADJ_FREQUENCY: u64 = 0x0002;

/// The kernel's `struct __kernel_timex` (208 bytes, `modes` its first word
/// on both little-endian arches).
type Timex = [u64; 26];

fn address<T>(value: &T) -> i64 {
    value as *const T as i64
}

fn out<T>(value: &mut T) -> i64 {
    value as *mut T as i64
}

/// A page holding `value`, then made read-only; the returned address is
/// `value`'s copy.
pub(super) fn read_only<T: Copy>(value: T) -> i64 {
    // SAFETY: a fresh anonymous page, written before it is protected.
    unsafe {
        let page = mmap(
            std::ptr::null_mut(),
            4096,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        );
        assert_ne!(page, MAP_FAILED);
        (page as *mut T).write(value);
        assert_eq!(mprotect(page, 4096, PROT_READ), 0);
        page as i64
    }
}

pub fn run(p: &Probe) {
    let raw = |call: Syscall, args: [i64; 6]| p.call_observed(call, args);
    let efault = |call: Syscall, args: [i64; 6]| raw(call, args) == neg(EFAULT);

    p.check(
        "clock_gettime into an unwritable time is EFAULT",
        efault(
            Syscall::N_clock_gettime,
            [CLOCK_MONOTONIC as i64, UNMAPPED, 0, 0, 0, 0],
        ),
    );
    p.check(
        "an unknown clock is EINVAL before the copy",
        raw(Syscall::N_clock_gettime, [10, UNMAPPED, 0, 0, 0, 0]) == neg(EINVAL),
    );
    p.check(
        "clock_getres into an unwritable resolution is EFAULT",
        efault(
            Syscall::N_clock_getres,
            [CLOCK_MONOTONIC as i64, UNMAPPED, 0, 0, 0, 0],
        ),
    );
    p.check(
        "gettimeofday into an unwritable time is EFAULT",
        efault(Syscall::N_gettimeofday, [UNMAPPED, 0, 0, 0, 0, 0]),
    );
    let mut now = timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    p.check(
        "gettimeofday into an unwritable zone is EFAULT",
        efault(
            Syscall::N_gettimeofday,
            [out(&mut now), UNMAPPED, 0, 0, 0, 0],
        ),
    );
    p.check("after the time was written", now.tv_sec > 0);
    #[cfg(target_arch = "x86_64")]
    p.check(
        "time into an unwritable time is EFAULT",
        efault(Syscall::N_time, [UNMAPPED, 0, 0, 0, 0, 0]),
    );
    p.check(
        "times into an unwritable buffer is EFAULT",
        efault(Syscall::N_times, [UNMAPPED, 0, 0, 0, 0, 0]),
    );
    p.check(
        "getrusage into an unwritable buffer is EFAULT",
        efault(
            Syscall::N_getrusage,
            [RUSAGE_SELF as i64, UNMAPPED, 0, 0, 0, 0],
        ),
    );
    p.check(
        "an unknown who is EINVAL before the copy",
        raw(Syscall::N_getrusage, [99, UNMAPPED, 0, 0, 0, 0]) == neg(EINVAL),
    );

    p.check(
        "nanosleep from an unreadable request is EFAULT",
        efault(Syscall::N_nanosleep, [UNMAPPED, 0, 0, 0, 0, 0]),
    );
    p.check(
        "and from a NULL one",
        efault(Syscall::N_nanosleep, [0, 0, 0, 0, 0, 0]),
    );
    p.check(
        "clock_nanosleep from an unreadable request is EFAULT",
        efault(
            Syscall::N_clock_nanosleep,
            [CLOCK_MONOTONIC as i64, 0, UNMAPPED, 0, 0, 0],
        ),
    );
    support::reset();
    support::install(SIGALRM, 0, false);
    let second = timespec {
        tv_sec: 1,
        tv_nsec: 0,
    };
    let soon = itimerval {
        it_interval: timeval {
            tv_sec: 0,
            tv_usec: 0,
        },
        it_value: timeval {
            tv_sec: 0,
            tv_usec: 1000,
        },
    };
    for (what, call, args) in [
        (
            "nanosleep",
            Syscall::N_nanosleep,
            [address(&second), UNMAPPED, 0, 0, 0, 0],
        ),
        (
            "a relative clock_nanosleep",
            Syscall::N_clock_nanosleep,
            [CLOCK_MONOTONIC as i64, 0, address(&second), UNMAPPED, 0, 0],
        ),
    ] {
        p.require(
            "arm a 1 ms ITIMER_REAL",
            raw(
                Syscall::N_setitimer,
                [ITIMER_REAL as i64, address(&soon), 0, 0, 0, 0],
            ) == 0,
        );
        p.check(
            &format!("{what} a handler interrupts, its remaining time unwritable, is EFAULT"),
            efault(call, args),
        );
    }
    p.check("the handler ran for each", support::count() == 2);

    p.check(
        "settimeofday from an unreadable time is EFAULT",
        efault(Syscall::N_settimeofday, [UNMAPPED, 0, 0, 0, 0, 0]),
    );
    p.check(
        "and from an unreadable zone, before the privilege is judged",
        efault(Syscall::N_settimeofday, [0, UNMAPPED, 0, 0, 0, 0]),
    );
    p.check(
        "clock_settime from an unreadable time is EFAULT",
        efault(
            Syscall::N_clock_settime,
            [CLOCK_REALTIME as i64, UNMAPPED, 0, 0, 0, 0],
        ),
    );

    let read: Timex = [0; 26];
    let mut refused = read;
    refused[0] = ADJ_FREQUENCY;
    p.check(
        "adjtimex from an unreadable timex is EFAULT",
        efault(Syscall::N_adjtimex, [UNMAPPED, 0, 0, 0, 0, 0]),
    );
    p.check(
        "adjtimex of a read-only timex is EFAULT: the answer is copied back",
        efault(Syscall::N_adjtimex, [read_only(read), 0, 0, 0, 0, 0]),
    );
    p.check(
        "even for a request it refuses, copied back as it was",
        efault(Syscall::N_adjtimex, [read_only(refused), 0, 0, 0, 0, 0]),
    );
    p.check(
        "clock_adjtime from an unreadable timex is EFAULT",
        efault(
            Syscall::N_clock_adjtime,
            [CLOCK_REALTIME as i64, UNMAPPED, 0, 0, 0, 0],
        ),
    );
    p.check(
        "copied in before the clock is judged",
        efault(Syscall::N_clock_adjtime, [1234, UNMAPPED, 0, 0, 0, 0]),
    );
    p.check(
        "clock_adjtime copies back only what the clock took: EPERM",
        raw(
            Syscall::N_clock_adjtime,
            [CLOCK_REALTIME as i64, read_only(refused), 0, 0, 0, 0],
        ) == neg(EPERM),
    );

    let word = 0u32;
    p.check(
        "FUTEX_WAIT from an unreadable timeout is EFAULT",
        efault(
            Syscall::N_futex,
            [address(&word), FUTEX_WAIT_PRIVATE as i64, 0, UNMAPPED, 0, 0],
        ),
    );
    let epfd = p.epoll_create1(EPOLL_CLOEXEC);
    p.require("create an epoll instance", epfd >= 0);
    let mut events = [epoll_event { events: 0, u64: 0 }];
    p.check(
        "epoll_pwait2 from an unreadable timeout is EFAULT",
        efault(
            Syscall::N_epoll_pwait2,
            [epfd as i64, out(&mut events), 1, UNMAPPED, 0, 8],
        ),
    );
    p.check(
        "before its signal mask's size is judged",
        efault(
            Syscall::N_epoll_pwait2,
            [
                epfd as i64,
                out(&mut events),
                1,
                UNMAPPED,
                address(&word),
                7,
            ],
        ),
    );
    p.close(epfd);
    p.check(
        "ppoll from an unreadable timeout is EFAULT",
        efault(Syscall::N_ppoll, [0, 0, UNMAPPED, 0, 8, 0]),
    );
    p.check(
        "pselect6 from an unreadable timeout is EFAULT",
        efault(Syscall::N_pselect6, [0, 0, 0, 0, UNMAPPED, 0]),
    );
    let nanosecond = timespec {
        tv_sec: 0,
        tv_nsec: 1,
    };
    p.check(
        "ppoll with a timeout in read-only memory answers as it would have",
        raw(Syscall::N_ppoll, [0, 0, read_only(nanosecond), 0, 8, 0]) == 0,
    );
    p.check(
        "and pselect6",
        raw(Syscall::N_pselect6, [0, 0, 0, 0, read_only(nanosecond), 0]) == 0,
    );

    timers(p);
    timeouts(p);
}

/// The interval and POSIX timers, and the round-robin slice.
fn timers(p: &Probe) {
    let raw = |call: Syscall, args: [i64; 6]| p.call_observed(call, args);
    let efault = |call: Syscall, args: [i64; 6]| raw(call, args) == neg(EFAULT);
    let real = ITIMER_REAL as i64;
    p.check(
        "getitimer into an unwritable setting is EFAULT",
        efault(Syscall::N_getitimer, [real, UNMAPPED, 0, 0, 0, 0]),
    );
    p.check(
        "an unknown which is EINVAL before the copy",
        raw(Syscall::N_getitimer, [99, UNMAPPED, 0, 0, 0, 0]) == neg(EINVAL),
    );
    p.check(
        "setitimer from an unreadable value is EFAULT",
        efault(Syscall::N_setitimer, [real, UNMAPPED, 0, 0, 0, 0]),
    );
    p.check(
        "copied in before which is judged",
        efault(Syscall::N_setitimer, [99, UNMAPPED, 0, 0, 0, 0]),
    );
    let later = itimerval {
        it_interval: timeval {
            tv_sec: 0,
            tv_usec: 0,
        },
        it_value: timeval {
            tv_sec: 100,
            tv_usec: 0,
        },
    };
    p.check(
        "setitimer into an unwritable old setting is EFAULT",
        efault(
            Syscall::N_setitimer,
            [real, address(&later), UNMAPPED, 0, 0, 0],
        ),
    );
    let mut armed = later;
    raw(Syscall::N_getitimer, [real, out(&mut armed), 0, 0, 0, 0]);
    p.check("after the new one took", armed.it_value.tv_sec > 0);
    let disarm = itimerval {
        it_value: later.it_interval,
        ..later
    };
    raw(Syscall::N_setitimer, [real, address(&disarm), 0, 0, 0, 0]);

    // A `struct sigevent` of `SIGEV_NONE` (64 bytes, `sigev_notify` the
    // fourth word).
    let mut quiet = [0i32; 16];
    quiet[3] = SIGEV_NONE;
    let mut id = 0i32;
    let monotonic = CLOCK_MONOTONIC as i64;
    p.check(
        "timer_create from an unreadable sigevent is EFAULT",
        efault(
            Syscall::N_timer_create,
            [monotonic, UNMAPPED, out(&mut id), 0, 0, 0],
        ),
    );
    p.check(
        "copied in before the clock is judged",
        efault(
            Syscall::N_timer_create,
            [10, UNMAPPED, out(&mut id), 0, 0, 0],
        ),
    );
    p.check(
        "timer_create into an unwritable id is EFAULT",
        efault(
            Syscall::N_timer_create,
            [monotonic, address(&quiet), UNMAPPED, 0, 0, 0],
        ),
    );
    p.require(
        "create a SIGEV_NONE timer",
        raw(
            Syscall::N_timer_create,
            [monotonic, address(&quiet), out(&mut id), 0, 0, 0],
        ) == 0,
    );
    let timer = id as i64;
    let setting = itimerspec {
        it_interval: timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value: timespec {
            tv_sec: 100,
            tv_nsec: 0,
        },
    };
    p.check(
        "timer_settime from an unreadable setting is EFAULT",
        efault(Syscall::N_timer_settime, [timer, 0, UNMAPPED, 0, 0, 0]),
    );
    p.check(
        "timer_settime into an unwritable old setting is EFAULT",
        efault(
            Syscall::N_timer_settime,
            [timer, 0, address(&setting), UNMAPPED, 0, 0],
        ),
    );
    let mut current = setting;
    current.it_value.tv_sec = 0;
    raw(
        Syscall::N_timer_gettime,
        [timer, out(&mut current), 0, 0, 0, 0],
    );
    p.check("after the new one took", current.it_value.tv_sec > 0);
    p.check(
        "timer_gettime into an unwritable setting is EFAULT",
        efault(Syscall::N_timer_gettime, [timer, UNMAPPED, 0, 0, 0, 0]),
    );
    p.check(
        "an unknown timer is EINVAL before the copy",
        raw(
            Syscall::N_timer_gettime,
            [timer + 1000, UNMAPPED, 0, 0, 0, 0],
        ) == neg(EINVAL),
    );
    raw(Syscall::N_timer_delete, [timer, 0, 0, 0, 0, 0]);

    p.check(
        "sched_rr_get_interval into an unwritable slice is EFAULT",
        efault(Syscall::N_sched_rr_get_interval, [0, UNMAPPED, 0, 0, 0, 0]),
    );
    p.check(
        "a negative pid is EINVAL before the copy",
        raw(Syscall::N_sched_rr_get_interval, [-1, UNMAPPED, 0, 0, 0, 0]) == neg(EINVAL),
    );
}

/// The System V semaphore and POSIX message queue timeouts, copied in
/// before anything else is judged.
fn timeouts(p: &Probe) {
    let raw = |call: Syscall, args: [i64; 6]| p.call_observed(call, args);
    let efault = |call: Syscall, args: [i64; 6]| raw(call, args) == neg(EFAULT);
    // The set's id is the host's business: recorded as success alone.
    let set = p.call_unrecorded(Syscall::N_semget, [IPC_PRIVATE as i64, 1, 0o600, 0, 0, 0]);
    p.record_result(Syscall::N_semget, set.min(0));
    p.require("create a semaphore set", set >= 0);
    // `struct sembuf`: semaphore 0, +1, no flags.
    let post: [i16; 3] = [0, 1, 0];
    p.check(
        "semtimedop from an unreadable timeout is EFAULT",
        efault(
            Syscall::N_semtimedop,
            [set, address(&post), 1, UNMAPPED, 0, 0],
        ),
    );
    p.check(
        "semtimedop from unreadable operations is EFAULT",
        efault(Syscall::N_semtimedop, [set, UNMAPPED, 1, 0, 0, 0]),
    );
    p.check(
        "copied in before the id is judged",
        efault(Syscall::N_semtimedop, [-1, UNMAPPED, 1, 0, 0, 0]),
    );
    raw(Syscall::N_semctl, [set, 0, IPC_RMID as i64, 0, 0, 0]);
    let byte = 0u8;
    p.check(
        "mq_timedsend from an unreadable timeout is EFAULT before its descriptor is judged",
        efault(
            Syscall::N_mq_timedsend,
            [-1, address(&byte), 1, 0, UNMAPPED, 0],
        ),
    );
    let mut buffer = [0u8; 64];
    p.check(
        "and mq_timedreceive",
        efault(
            Syscall::N_mq_timedreceive,
            [-1, out(&mut buffer), 64, 0, UNMAPPED, 0],
        ),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "time/fault",
    run,
    covers: &[
        Syscall::N_clock_gettime,
        Syscall::N_clock_getres,
        Syscall::N_gettimeofday,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_time,
        Syscall::N_times,
        Syscall::N_getrusage,
        Syscall::N_nanosleep,
        Syscall::N_clock_nanosleep,
        Syscall::N_setitimer,
        Syscall::N_settimeofday,
        Syscall::N_clock_settime,
        Syscall::N_adjtimex,
        Syscall::N_clock_adjtime,
        Syscall::N_futex,
        Syscall::N_epoll_create1,
        Syscall::N_epoll_pwait2,
        Syscall::N_ppoll,
        Syscall::N_pselect6,
        Syscall::N_getitimer,
        Syscall::N_timer_create,
        Syscall::N_timer_settime,
        Syscall::N_timer_gettime,
        Syscall::N_timer_delete,
        Syscall::N_sched_rr_get_interval,
        Syscall::N_semget,
        Syscall::N_semtimedop,
        Syscall::N_semctl,
        Syscall::N_mq_timedsend,
        Syscall::N_mq_timedreceive,
        Syscall::N_close,
    ],
    vehicles: Vehicle::KERNEL,
    needs: &[Need::SysvSem, Need::PosixMqueue],
    ..DEFAULTS
};
