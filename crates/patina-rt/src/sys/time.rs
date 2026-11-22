//! Clocks: answered from the virtual clock. The kernel is not asked.

use super::*;
use proto::layout::{REALTIME_EPOCH_S, VCLOCK_BOOT_NS};

const NS: u64 = 1_000_000_000;

pub fn now() -> u64 {
    ctl().vclock_ns.load(Relaxed)
}

/// The realtime clock: virtual time from the epoch, plus the machine's offset (`clock-skew-ms`,
/// `clock NAME`; 0 for main).
fn realtime_ns() -> u64 {
    let off = crate::state::clock_offset();
    crate::state::clock_read(off);
    (now() - VCLOCK_BOOT_NS + REALTIME_EPOCH_S * NS).saturating_add_signed(off)
}

/// An absolute `CLOCK_REALTIME` time of this machine as a virtual monotonic time (0 if before
/// boot). A step of the machine's clock moves it (`Slot::clock_flags`).
pub fn realtime_to_vclock(ns: u64) -> u64 {
    (ns.saturating_add_signed(crate::state::clock_offset().saturating_neg()) + VCLOCK_BOOT_NS)
        .saturating_sub(REALTIME_EPOCH_S * NS)
}

/// A guest `timespec` as nanoseconds (EINVAL for a negative or malformed value).
pub fn read_timespec(p: u64) -> Result<u64, i64> {
    let [s, ns] = get::<[i64; 2]>(p)?;
    if s < 0 || !(0..NS as i64).contains(&ns) {
        return Err(-e::EINVAL);
    }
    Ok((s as u64).saturating_mul(NS).saturating_add(ns as u64))
}

/// Sleep until the virtual monotonic `deadline`: the supervisor parks the thread.
fn sleep_until(deadline: u64) -> i64 {
    crate::sup::call_sup(proto::ctl::Op::Sleep, [deadline, 0, 0, 0, 0, 0]).ret
}

/// Sleep until `deadline`, an absolute realtime time converted: a step of the machine's clock
/// moves it.
fn sleep_until_realtime(deadline: u64) -> i64 {
    crate::state::clock_flags(proto::ctl::CLK_REALTIME_ABS);
    let r = sleep_until(deadline);
    crate::state::clock_flags(0);
    r
}

fn nanosleep(req: u64, rem: u64) -> Result<i64, i64> {
    let ns = read_timespec(req)?;
    let deadline = now().saturating_add(ns);
    Ok(interruptible(deadline, rem, false, false))
}

/// A sleep that a signal may interrupt (remaining time and restart block). `realtime`: an
/// absolute realtime deadline.
fn interruptible(deadline: u64, rem: u64, absolute: bool, realtime: bool) -> i64 {
    let r = if realtime {
        sleep_until_realtime(deadline)
    } else {
        sleep_until(deadline)
    };
    match r {
        r if r == -e::EINTR => super::sig::sleep_interrupted(deadline, rem, absolute),
        r => r,
    }
}

fn clock_nanosleep(clk: i64, flags: u64, req: u64, rem: u64) -> Result<i64, i64> {
    const TIMER_ABSTIME: u64 = 1;
    let t = read_timespec(req)?;
    let deadline = match (clk, flags & TIMER_ABSTIME != 0) {
        (0 | 11, true) => realtime_to_vclock(t), // REALTIME, TAI (offset ignored)
        (1 | 7, true) => t,                      // MONOTONIC, BOOTTIME
        (0 | 1 | 7 | 11, false) => now().saturating_add(t),
        _ => return Err(-e::EINVAL),
    };
    let abs = flags & TIMER_ABSTIME != 0;
    Ok(interruptible(
        deadline,
        rem,
        abs,
        abs && matches!(clk, 0 | 11),
    ))
}

fn cpu_ns(call: &mut dyn Call) -> u64 {
    call.thread().cpu_ns()
}

fn clock(call: &mut dyn Call, id: i64) -> Result<u64, i64> {
    Ok(match id {
        0 | 5 | 8 => realtime_ns(), // REALTIME, REALTIME_COARSE, REALTIME_ALARM
        11 => realtime_ns() + 37 * NS, // TAI (the machine's offset included)
        1 | 4 | 6 | 7 | 9 => now(), // MONOTONIC, _RAW, _COARSE, BOOTTIME, BOOTTIME_ALARM
        2 | 3 => cpu_ns(call),      // PROCESS_CPUTIME_ID, THREAD_CPUTIME_ID
        _ => return Err(-e::EINVAL),
    })
}

fn ts(ns: u64) -> [u64; 2] {
    [ns / NS, ns % NS]
}

pub fn handle(call: &mut dyn Call) -> Action {
    let (a0, a1) = (call.arg(0), call.arg(1));
    let r = match call.nr() {
        nr::CLOCK_GETTIME => clock(call, a0 as i32 as i64)
            .and_then(|t| put(a1, ts(t)))
            .map(|_| 0),
        nr::CLOCK_GETRES => {
            let id = a0 as i32 as i64;
            clock(call, id).and_then(|_| {
                let res = if id == 5 || id == 6 { 4_000_000 } else { 1 };
                if a1 != 0 {
                    put(a1, ts(res))?;
                }
                Ok(0)
            })
        }
        nr::GETTIMEOFDAY => {
            let t = realtime_ns();
            let mut r: Result<i64, i64> = Ok(0);
            if call.arg(0) != 0 {
                r = put(call.arg(0), [t / NS, (t % NS) / 1000]).map(|_| 0);
            }
            if call.arg(1) != 0 {
                r = r.and(put(call.arg(1), [0u32; 2]).map(|_| 0));
            }
            r
        }
        nr::TIME => {
            let s = realtime_ns() / NS;
            if call.arg(0) != 0 {
                put(call.arg(0), s).map(|_| s as i64)
            } else {
                Ok(s as i64)
            }
        }
        nr::TIMES => {
            let tick = NS / 100;
            let u = cpu_ns(call) / tick;
            let r = (now() / tick) as i64;
            if call.arg(0) != 0 {
                put(call.arg(0), [u, 0u64, 0, 0]).map(|_| r)
            } else {
                Ok(r)
            }
        }
        nr::NANOSLEEP => nanosleep(a0, a1),
        nr::CLOCK_NANOSLEEP => clock_nanosleep(a0 as i32 as i64, a1, call.arg(2), call.arg(3)),
        _ => return stop_here(call),
    };
    Action::Return(r.unwrap_or_else(|e| e))
}
