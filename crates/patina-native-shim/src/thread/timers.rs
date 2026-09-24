//! The process's timers on the virtual clock (`kernel/time/itimer.c`,
//! `posix-timers.c`, `posix-cpu-timers.c`, `fs/timerfd.c`): the interval
//! timers (`setitimer`/`getitimer`/`alarm`), POSIX timers (`timer_*`) and
//! timer descriptors (`timerfd_*`), one model both doors reach.
//!
//! A timer expires when virtual time reaches it. Virtual time moves only at
//! recorded points, so expiry is checked there: at every boundary return
//! (signal delivery), wherever a row reads a timer or the pending signals,
//! and — while every task waits — by advancing idle time to the earliest
//! deadline (`Context::advance_idle_to`), the way the deadlock rescue advances
//! it to a parked task's own deadline. An expiry is what the kernel does in
//! its interrupt: the interval timers send `SIGALRM`/`SIGVTALRM`/`SIGPROF`
//! (`SI_KERNEL`), a POSIX timer its `sigevent` (`SI_TIMER`; a periodic one
//! moves on, counting the periods it skipped as overruns, when its signal is
//! dequeued — `posixtimer_rearm`), and a timer descriptor counts expirations
//! its readers take. The CPU-time timers run on the virtual CPU time
//! (`Context::cpu_time_nanos`), which only the advance-on-spin rescue moves:
//! a task reading the clock again and again at frozen virtual time. A loop
//! that computes without reading the clock accrues no CPU time and fires no
//! CPU-time timer, and idle time never reaches one.
//!
//! Timers on `CLOCK_REALTIME`/`CLOCK_TAI` are kept on the monotonic line:
//! nothing ever sets the virtual clock, so the realtime clock is the
//! monotonic one at a fixed offset. An absolute realtime expiry maps onto
//! that line the way an absolute realtime sleep does
//! (`Context::monotonic_deadline`).

use super::signals::{Info, SIGALRM, SIGPROF, SIGVTALRM};
use super::*;
use crate::clocks::{Clock, CpuOf, NANOS, TICK_NSEC, Timespec, Timeval};
use crate::neg_errno as errno;
use crate::{EBADF, EFAULT};
use patina_dst_abi::SignalTarget;

/// `hrtimer_forward`: move `expires` by whole `interval`s until it lies
/// after `now`, answering how many it moved (0 when it already does).
fn forward(expires: &mut u64, now: u64, interval: u64) -> u64 {
    if now < *expires || interval == 0 {
        return 0;
    }
    let periods = (now - *expires) / interval + 1;
    *expires += periods * interval;
    periods
}

/// Where a timer's clock runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Line {
    /// The monotonic line (every clock but the CPU clocks).
    Monotonic,
    /// A CPU clock: the process's or one thread's CPU time.
    Cpu(CpuOf),
}

/// A reading of `line`, unrecorded: the time expiry is judged at.
fn now_on(line: Line) -> Result<u64, c_int> {
    with_context_raw(|context| match line {
        Line::Monotonic => context.monotonic_now_unrecorded(),
        Line::Cpu(of) => Ok(crate::clocks::cpu_nanos_unrecorded(context, of)),
    })
}

/// A reading of `line` a row takes: a recorded clock observation (so a
/// guest polling a timer is a clock spin the runtime can see).
fn observe(line: Line) -> Result<u64, c_int> {
    match line {
        Line::Monotonic => crate::with_context(|context| context.now(ClockKind::Monotonic)),
        Line::Cpu(of) => crate::clocks::cpu_nanos(of),
    }
}

/// A requested expiry on the monotonic line: relative to `now`, or
/// (`TIMER_ABSTIME`) an absolute time on the timer's own clock, a realtime
/// one moved onto the line as an absolute realtime sleep is.
fn deadline(value: u64, absolute: bool, realtime: bool, now: u64) -> Result<u64, c_int> {
    Ok(match (absolute, realtime) {
        (false, _) => now.saturating_add(value),
        (true, false) => value,
        (true, true) => {
            with_context_raw(|context| context.monotonic_deadline(ClockKind::Realtime, value))?
        }
    })
}

/// What a POSIX timer does at expiry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Notify {
    /// `SIGEV_NONE`: nothing; the timer is only read.
    Quiet,
    /// A signal, to the process or (`SIGEV_THREAD_ID`) one thread.
    Signal {
        sig: u8,
        value: u64,
        target: SignalTarget,
    },
}

/// A POSIX timer (`struct k_itimer`).
#[derive(Debug)]
struct PosixTimer {
    line: Line,
    realtime: bool,
    notify: Notify,
    /// The programmed expiry on its line (kept past an expiry, for the
    /// periods a rearm skips).
    expires: u64,
    interval: u64,
    /// Queued in the timer queue: armed and not yet fired (`it_active`).
    active: bool,
    /// `it_requeue_pending`: bumped per periodic expiry and rearm, its low bit
    /// set while a periodic expiry's signal awaits its dequeue.
    requeue: u32,
    /// `it_overrun`, and `it_overrun_last` (what the rows report).
    overrun: i64,
    overrun_last: i64,
}

/// `REQUEUE_PENDING`.
const REQUEUE_PENDING: u32 = 1;

/// A timer descriptor (`struct timerfd_ctx`).
#[derive(Debug)]
pub(super) struct TimerFd {
    realtime: bool,
    /// The monotonic expiry (kept past an expiry, for the periods a read
    /// forwards over).
    expires: u64,
    /// Queued in the timer queue: armed and not yet fired.
    queued: bool,
    interval: u64,
    /// Expirations not yet read.
    ticks: u64,
    /// The timer fired and has not been forwarded since.
    expired: bool,
    waiters: VecDeque<TaskId>,
    /// A descriptor still names it. A reader blocked when the last one
    /// closed holds the file, as the kernel's `read` does, so the timer
    /// lives on until the last waiter leaves.
    open: bool,
}

/// A CPU-time interval timer (`struct cpu_itimer`): an absolute CPU time
/// (0: disarmed) and a reload.
#[derive(Clone, Copy, Debug, Default)]
struct CpuItimer {
    expires: u64,
    incr: u64,
}

/// `ITIMER_REAL`: the monotonic expiry (kept past an expiry, for the periods
/// a rearm skips), whether it is queued, and the reload.
#[derive(Clone, Copy, Debug, Default)]
struct RealItimer {
    expires: u64,
    queued: bool,
    incr: u64,
}

/// The process's timers.
#[derive(Default)]
pub(super) struct Timers {
    real: RealItimer,
    /// `ITIMER_VIRTUAL`, `ITIMER_PROF`.
    cpu: [CpuItimer; 2],
    posix: BTreeMap<i32, PosixTimer>,
    next_id: i32,
    fds: BTreeMap<u64, TimerFd>,
    next_fd: u64,
}

impl Timers {
    /// Whether any timer is armed on any line.
    fn any_armed(&self) -> bool {
        self.real.queued
            || self.cpu.iter().any(|timer| timer.expires != 0)
            || self.posix.values().any(|timer| timer.active)
            || self.fds.values().any(|fd| fd.queued)
    }

    /// The earliest monotonic deadline whose expiry does something: the
    /// deadline idle time advances to. A periodic POSIX timer whose signal is
    /// discarded rearms at every expiry, which could never let idle time end,
    /// so it is not one; nor is a CPU-time timer, which idle time never
    /// reaches.
    fn alarm(&self, signals: &signals::SignalRuntime) -> Option<u64> {
        let posix = self
            .posix
            .values()
            .filter_map(|timer| match (timer.line, timer.notify) {
                (Line::Monotonic, Notify::Signal { sig, target, .. })
                    if timer.active && !signals.discards(sig, target) =>
                {
                    Some(timer.expires)
                }
                _ => None,
            });
        let fds = self
            .fds
            .values()
            .filter(|fd| fd.queued)
            .map(|fd| fd.expires);
        self.real
            .queued
            .then_some(self.real.expires)
            .into_iter()
            .chain(posix)
            .chain(fds)
            .min()
    }

    /// The CPU time the earliest armed CPU-time timer still needs: the
    /// process's interval timers and CPU-line POSIX timers against the
    /// process's CPU time, and the calling task's thread-clock timers against
    /// its own (the task the advance-on-spin rescue charges while it spins).
    fn cpu_alarm(&self, process: u64, own: (TaskId, u64)) -> Option<u64> {
        let itimers = self
            .cpu
            .iter()
            .filter(|timer| timer.expires != 0)
            .map(|timer| timer.expires.saturating_sub(process));
        let posix =
            self.posix
                .values()
                .filter(|timer| timer.active)
                .filter_map(|timer| match timer.line {
                    Line::Cpu(CpuOf::Process) => Some(timer.expires.saturating_sub(process)),
                    Line::Cpu(CpuOf::Thread(task)) if task == own.0 => {
                        Some(timer.expires.saturating_sub(own.1))
                    }
                    _ => None,
                });
        itimers.chain(posix).min()
    }

    /// `dequeue_signal`'s timer half. A `SIGALRM` restarts an `ITIMER_REAL`
    /// with a reload that is not queued, at its next period after now. A
    /// periodic POSIX timer's own record moves the timer to its next period
    /// after now, the periods it skipped its overrun (`posixtimer_rearm`),
    /// reported in the record and by `timer_getoverrun`.
    pub(super) fn dequeued(&mut self, info: &mut Info) {
        if info.signo() == SIGALRM && !self.real.queued && self.real.incr != 0 {
            if let Ok(now) = now_on(Line::Monotonic) {
                forward(&mut self.real.expires, now, self.real.incr);
                self.real.queued = true;
            }
        }
        let Some(id) = info.timer_id() else {
            return;
        };
        let generation = info.generation();
        info.clear_generation();
        let Some(timer) = self.posix.get_mut(&id) else {
            return;
        };
        if timer.interval == 0 || timer.requeue != generation {
            return;
        }
        let Ok(now) = now_on(timer.line) else {
            return;
        };
        timer.overrun += forward(&mut timer.expires, now, timer.interval) as i64;
        timer.active = true;
        timer.overrun_last = timer.overrun;
        timer.overrun = -1;
        timer.requeue = timer.requeue.wrapping_add(1);
        let overrun = timer.overrun_last + i64::from(info.overrun());
        info.set_overrun(overrun.min(i64::from(i32::MAX)) as i32);
    }
}

impl ThreadRuntime {
    /// Fire every timer virtual time has reached, under the runtime lock the
    /// caller holds: the tasks to wake once it is released.
    pub(super) fn fire_timers(&mut self) -> Result<Vec<TaskId>, c_int> {
        let mut wakes = Vec::new();
        if !self.timers.any_armed() {
            return Ok(wakes);
        }
        let monotonic = now_on(Line::Monotonic)?;
        if self.timers.real.queued && monotonic >= self.timers.real.expires {
            self.timers.real.queued = false;
            wakes.extend(self.generate_locked(SignalTarget::Process, Info::kernel(SIGALRM)));
        }
        let process = now_on(Line::Cpu(CpuOf::Process))?;
        for (index, sig) in [SIGVTALRM, SIGPROF].into_iter().enumerate() {
            let timer = &mut self.timers.cpu[index];
            if timer.expires != 0 && process >= timer.expires {
                timer.expires = if timer.incr == 0 {
                    0
                } else {
                    timer.expires + timer.incr
                };
                wakes.extend(self.generate_locked(SignalTarget::Process, Info::kernel(sig)));
            }
        }
        let due: Vec<i32> = self
            .timers
            .posix
            .iter()
            .filter(|(_, timer)| timer.active)
            .map(|(id, _)| *id)
            .collect();
        for id in due {
            let timer = &self.timers.posix[&id];
            let (line, expires) = (timer.line, timer.expires);
            let now = now_on(line)?;
            if now < expires {
                continue;
            }
            wakes.extend(self.fire_posix(id, now));
        }
        let mut readers = Vec::new();
        for fd in self.timers.fds.values_mut() {
            if fd.queued && monotonic >= fd.expires {
                fd.queued = false;
                fd.expired = true;
                fd.ticks += 1;
                readers.extend(fd.waiters.drain(..));
            }
        }
        for task in readers {
            // A reader or a readiness wait: its registration ends with the
            // wake, as `wake_all` ends it.
            self.remove_signal_wait(task);
            wakes.push(task);
        }
        self.publish_alarm();
        // One wake per task, whichever expiries woke it.
        let mut once = Vec::with_capacity(wakes.len());
        for task in wakes {
            if !once.contains(&task) {
                once.push(task);
            }
        }
        Ok(once)
    }

    /// One POSIX timer's expiry (`posix_timer_fn`, `cpu_timer_fire`).
    fn fire_posix(&mut self, id: i32, now: u64) -> Vec<TaskId> {
        let timer = self.timers.posix.get_mut(&id).expect("a due timer");
        timer.active = false;
        let Notify::Signal { sig, value, target } = timer.notify else {
            // Only a CPU timer is queued without a signal: `cpu_timer_fire`
            // clears its expiry.
            timer.expires = 0;
            return Vec::new();
        };
        let generation = if timer.interval != 0 {
            timer.requeue = timer.requeue.wrapping_add(1);
            timer.requeue
        } else {
            if let Line::Cpu(_) = timer.line {
                // A one-shot CPU timer clears as it fires.
                timer.expires = 0;
            }
            0
        };
        // A thread target that exited takes nothing.
        if let SignalTarget::Task(task) = target {
            if !self.signals.has_task(task) {
                return Vec::new();
            }
        }
        if let Some(queued) = self.signals.queued_timer(sig, id) {
            // Its record is still pending: one more overrun.
            queued.set_overrun(queued.overrun().saturating_add(1));
            return Vec::new();
        }
        if self.signals.discards(sig, target) {
            // Nothing queued, so no dequeue will rearm it: a periodic timer
            // rearms now, at least a tick ahead (`posix_timer_fn`).
            let timer = self.timers.posix.get_mut(&id).expect("a due timer");
            if timer.interval != 0 {
                let floor = if timer.line == Line::Monotonic && timer.interval < TICK_NSEC {
                    now + TICK_NSEC
                } else {
                    now
                };
                timer.overrun += forward(&mut timer.expires, floor, timer.interval) as i64;
                timer.requeue = timer.requeue.wrapping_add(1);
                timer.active = true;
            }
            return Vec::new();
        }
        self.generate_locked(target, Info::timer(sig, id, value, generation))
    }

    /// Let the runtime's advance-on-spin rescue stop at the earliest
    /// monotonic deadline, and advance toward the earliest CPU-time timer in
    /// whole steps (`Context::set_cpu_alarm`).
    fn publish_alarm(&self) {
        let alarm = self.timers.alarm(&self.signals);
        let me = current_task();
        let _ = with_context_raw(|context| {
            context.set_alarm(alarm);
            let process = crate::clocks::cpu_nanos_unrecorded(context, CpuOf::Process);
            let own = crate::clocks::cpu_nanos_unrecorded(context, CpuOf::Thread(me));
            context.set_cpu_alarm(self.timers.cpu_alarm(process, (me, own)));
            Ok(())
        });
    }

    /// Before the scheduler picks the next task: fire what is due, and while
    /// every task waits with a timer's deadline ahead of all of theirs,
    /// advance idle time to it and fire it (which may wake one). Answers the
    /// tasks the expiries woke; the caller wakes them.
    pub(super) fn idle_timers(&mut self) -> Result<Vec<TaskId>, ThreadError> {
        loop {
            // A woken task is runnable: idle time ends here.
            let wakes = self.fire_timers().map_err(ThreadError::Posix)?;
            if !wakes.is_empty() {
                return Ok(wakes);
            }
            let Some(alarm) = self.timers.alarm(&self.signals) else {
                return Ok(wakes);
            };
            if !with_context_raw(|context| context.advance_idle_to(alarm))
                .map_err(ThreadError::Posix)?
            {
                return Ok(wakes);
            }
        }
    }
}

/// Fire every timer virtual time has reached (the boundary-return check).
pub(crate) fn fire_due() {
    // The same guards as signal delivery: nothing fires in the shim's
    // bootstrap window, on a finished task, or in the post-`main` teardown.
    if crate::in_shim_bootstrap() || task_completed() || main_returned() {
        return;
    }
    let wakes = {
        let mut state = lock_state();
        if !state.active {
            return;
        }
        state
            .fire_timers()
            .unwrap_or_else(|errno| fatal(&format!("firing the timers failed ({errno})")))
    };
    wake_all(wakes);
}

/// `ITIMER_REAL`, `ITIMER_VIRTUAL`, `ITIMER_PROF`.
const ITIMER_REAL: i32 = 0;
const ITIMER_VIRTUAL: i32 = 1;
const ITIMER_PROF: i32 = 2;

/// `struct itimerval`: interval, then value, as (seconds, microseconds).
pub(crate) type Itimerval = [i64; 4];

/// An `itimerval` of a reload and a remaining time, in nanoseconds.
fn itimerval(interval: u64, value: u64) -> Itimerval {
    let (interval, value) = (Timeval::from_nanos(interval), Timeval::from_nanos(value));
    [
        interval.tv_sec,
        interval.tv_usec,
        value.tv_sec,
        value.tv_usec,
    ]
}

/// `timeval_valid`, then the value in nanoseconds.
fn timeval_nanos(value: [i64; 2]) -> Option<u64> {
    if value[0] < 0 || !(0..1_000_000).contains(&value[1]) {
        return None;
    }
    (value[0] as u64)
        .checked_mul(NANOS)?
        .checked_add(value[1] as u64 * 1000)
}

/// One interval timer's remaining time and reload, in nanoseconds, read
/// (`getitimer`) or replaced (`setitimer`, whose old value counts an expiry
/// at exactly now as about to fire).
fn get_itimer(state: &ThreadRuntime, which: i32, now: u64, replacing: bool) -> (u64, u64) {
    match which {
        ITIMER_REAL => {
            // `itimer_get_remtime`: a queued timer at or past its expiry
            // reports 1 µs; under a microsecond it reports what is left.
            let remaining = match state.timers.real.expires.saturating_sub(now) {
                _ if !state.timers.real.queued => 0,
                0 => 1000,
                remaining => remaining,
            };
            (remaining, state.timers.real.incr)
        }
        ITIMER_VIRTUAL | ITIMER_PROF => {
            // `get_cpu_itimer` (`val < t`) and `set_process_cpu_timer`
            // (`*oldval <= now`): about to fire answers one tick.
            let timer = state.timers.cpu[(which - 1) as usize];
            let about_to_fire = if replacing {
                timer.expires <= now
            } else {
                timer.expires < now
            };
            let remaining = match timer.expires {
                0 => 0,
                _ if about_to_fire => TICK_NSEC,
                expires => expires - now,
            };
            (remaining, timer.incr)
        }
        _ => unreachable!("the rows check `which`"),
    }
}

/// `getitimer(which, value)`.
///
/// # Safety
/// `out` must be NULL or writable for a `struct itimerval`.
pub(crate) unsafe fn getitimer(which: i32, out: *mut Itimerval) -> i64 {
    if !(ITIMER_REAL..=ITIMER_PROF).contains(&which) {
        return errno(EINVAL);
    }
    fire_due();
    let line = if which == ITIMER_REAL {
        Line::Monotonic
    } else {
        Line::Cpu(CpuOf::Process)
    };
    let now = match observe(line) {
        Ok(now) => now,
        Err(code) => return errno(code),
    };
    let (remaining, interval) = get_itimer(&lock_state(), which, now, false);
    if out.is_null() {
        return errno(EFAULT);
    }
    // SAFETY: per this function's contract.
    unsafe { out.write_unaligned(itimerval(interval, remaining)) };
    0
}

/// `setitimer(which, value, old)` (`do_setitimer`): the new value is
/// validated first (a NULL one disarms), then `which`; the old setting is
/// written into a non-NULL `old`. An `ITIMER_REAL` value arms relative to
/// now; a CPU-time one relative to the process's CPU time, a tick later
/// (`set_cpu_itimer`).
///
/// # Safety
/// `new` must be NULL or readable, `old` NULL or writable, each for a
/// `struct itimerval`.
pub(crate) unsafe fn setitimer(which: i32, new: *const Itimerval, old: *mut Itimerval) -> i64 {
    let (value, interval) = if new.is_null() {
        (0, 0)
    } else {
        // SAFETY: per this function's contract.
        let [interval_sec, interval_usec, value_sec, value_usec] = unsafe { new.read_unaligned() };
        match (
            timeval_nanos([value_sec, value_usec]),
            timeval_nanos([interval_sec, interval_usec]),
        ) {
            (Some(value), Some(interval)) => (value, interval),
            _ => return errno(EINVAL),
        }
    };
    if !(ITIMER_REAL..=ITIMER_PROF).contains(&which) {
        return errno(EINVAL);
    }
    let previous = match set_itimer(which, value, interval) {
        Ok(previous) => previous,
        Err(code) => return errno(code),
    };
    if !old.is_null() {
        let (remaining, interval) = previous;
        // SAFETY: per this function's contract.
        unsafe { old.write_unaligned(itimerval(interval, remaining)) };
    }
    0
}

/// Arm (or, with a zero value, disarm) interval timer `which`, answering the
/// previous remaining time and reload in nanoseconds.
fn set_itimer(which: i32, value: u64, interval: u64) -> Result<(u64, u64), c_int> {
    super::signals::activate();
    fire_due();
    let line = if which == ITIMER_REAL {
        Line::Monotonic
    } else {
        Line::Cpu(CpuOf::Process)
    };
    let now = observe(line)?;
    let mut state = lock_state();
    let previous = get_itimer(&state, which, now, true);
    if which == ITIMER_REAL {
        let real = &mut state.timers.real;
        real.queued = value != 0;
        real.incr = if value != 0 { interval } else { 0 };
        if value != 0 {
            real.expires = now.saturating_add(value);
        }
    } else {
        let timer = &mut state.timers.cpu[(which - 1) as usize];
        timer.expires = if value != 0 {
            now.saturating_add(value).saturating_add(TICK_NSEC)
        } else {
            0
        };
        timer.incr = interval;
    }
    state.publish_alarm();
    Ok(previous)
}

/// `alarm(seconds)` (`alarm_setitimer`): `ITIMER_REAL` for whole seconds,
/// answering the previous alarm's remaining time as a `timeval` rounded to
/// the nearest second (a remainder under a second with a nonzero
/// microsecond count rounds up to 1). A row of the x86_64 table only (glibc
/// spells it `setitimer` on the generic table).
#[cfg(target_arch = "x86_64")]
pub(crate) fn alarm(seconds: u32) -> i64 {
    match set_itimer(ITIMER_REAL, u64::from(seconds) * NANOS, 0) {
        Ok((remaining, _)) => {
            let old = Timeval::from_nanos(remaining);
            if (old.tv_sec == 0 && old.tv_usec != 0) || old.tv_usec >= 500_000 {
                old.tv_sec + 1
            } else {
                old.tv_sec
            }
        }
        Err(code) => errno(code),
    }
}

/// `struct sigevent`: the members `timer_create` reads.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Sigevent {
    value: u64,
    signo: i32,
    notify: i32,
    thread_id: i32,
    pad: [i32; 11],
}

const SIGEV_SIGNAL: i32 = 0;
const SIGEV_NONE: i32 = 1;
const SIGEV_THREAD: i32 = 2;
const SIGEV_THREAD_ID: i32 = 4;

/// `struct itimerspec`: interval, then value.
pub(crate) type Itimerspec = [Timespec; 2];

/// The line a clock's timers run on, whether it is a realtime clock, and
/// whether the clock takes a timer at all.
fn timer_line(clock: Clock) -> Result<(Line, bool), c_int> {
    match clock {
        Clock::Realtime | Clock::Tai => Ok((Line::Monotonic, true)),
        Clock::Monotonic | Clock::Boottime => Ok((Line::Monotonic, false)),
        Clock::ProcessCpu | Clock::ThreadCpu | Clock::Cpu { .. } => {
            let (of, _) = clock.cpu(false).expect("a CPU clock")?;
            Ok((Line::Cpu(of), false))
        }
        // `alarm_timer_create`: the RTC is there; `CAP_WAKE_ALARM` is not.
        Clock::RealtimeAlarm | Clock::BoottimeAlarm => Err(EPERM),
        Clock::MonotonicRaw | Clock::RealtimeCoarse | Clock::MonotonicCoarse | Clock::Device => {
            Err(EOPNOTSUPP)
        }
    }
}

/// `timer_create(clock, sevp, id)` (`do_timer_create`): an unknown clock is
/// `EINVAL`, one that takes no timer (the raw and coarse clocks, a clock
/// device) `EOPNOTSUPP`; an id is allocated before the `sigevent` is
/// validated (an unknown `sigev_notify`, a signal outside 1..=64, or a
/// `SIGEV_THREAD_ID` naming no thread of the caller is `EINVAL`), and written
/// before the clock's own create (a CPU clock of a pid or tid the process
/// does not have is `EINVAL`; an alarm clock needs `CAP_WAKE_ALARM`,
/// `EPERM`). A NULL `sevp` is `SIGALRM` to the
/// process carrying the id; `SIGEV_THREAD` is, to the kernel, a signal.
///
/// # Safety
/// `event` must be NULL or readable for a `struct sigevent`, `id` NULL or
/// writable for an `int`.
pub(crate) unsafe fn timer_create(clock: i32, event: *const Sigevent, id_out: *mut i32) -> i64 {
    let Some(decoded) = Clock::decode(clock) else {
        return errno(EINVAL);
    };
    if matches!(
        decoded,
        Clock::MonotonicRaw | Clock::RealtimeCoarse | Clock::MonotonicCoarse | Clock::Device
    ) {
        return errno(EOPNOTSUPP);
    }
    // SAFETY: per this function's contract.
    let event = (!event.is_null()).then(|| unsafe { event.read_unaligned() });
    super::signals::activate();
    let mut state = lock_state();
    let id = state.timers.next_id;
    state.timers.next_id = id.wrapping_add(1) & i32::MAX;
    let notify = match event {
        None => Notify::Signal {
            sig: SIGALRM,
            value: id as u32 as u64,
            target: SignalTarget::Process,
        },
        Some(event) => {
            let target = match event.notify {
                SIGEV_NONE => None,
                SIGEV_SIGNAL | SIGEV_THREAD => Some(SignalTarget::Process),
                notify if notify == SIGEV_SIGNAL | SIGEV_THREAD_ID => {
                    // `good_sigevent`: a thread of the caller's process.
                    let Some(task) =
                        task_of(event.thread_id).filter(|task| state.signals.has_task(*task))
                    else {
                        return errno(EINVAL);
                    };
                    Some(SignalTarget::Task(task))
                }
                _ => return errno(EINVAL),
            };
            match target {
                None => Notify::Quiet,
                Some(_) if !(1..=64).contains(&event.signo) => return errno(EINVAL),
                Some(target) => Notify::Signal {
                    sig: event.signo as u8,
                    value: event.value,
                    target,
                },
            }
        }
    };
    if id_out.is_null() {
        return errno(EFAULT);
    }
    // SAFETY: per this function's contract.
    unsafe { id_out.write_unaligned(id) };
    let (line, realtime) = match timer_line(decoded) {
        Ok(line) => line,
        Err(code) => return errno(code),
    };
    state.timers.posix.insert(
        id,
        PosixTimer {
            line,
            realtime,
            notify,
            expires: 0,
            interval: 0,
            active: false,
            requeue: 0,
            overrun: -1,
            overrun_last: 0,
        },
    );
    0
}

/// `common_timer_get`/`posix_cpu_timer_get`: the remaining time and the
/// reload. Replacing a CPU timer's setting (`posix_cpu_timer_set`) first
/// moves a periodic one past now (`bump_cpu_timer`, the skipped periods its
/// overrun).
fn posix_get(timer: &mut PosixTimer, now: u64, replacing: bool) -> (u64, u64) {
    let quiet = timer.notify == Notify::Quiet;
    if let Line::Cpu(_) = timer.line {
        if replacing && timer.expires != 0 {
            timer.overrun += forward(&mut timer.expires, now, timer.interval) as i64;
        }
        let remaining = match timer.expires {
            0 => 0,
            expires if now < expires => expires - now,
            // Expired, not yet fired: about to expire.
            _ => 1,
        };
        return (remaining, timer.interval);
    }
    if timer.interval == 0 && !timer.active && !quiet {
        return (0, 0);
    }
    if timer.interval != 0 && (timer.requeue & REQUEUE_PENDING != 0 || quiet) {
        timer.overrun += forward(&mut timer.expires, now, timer.interval) as i64;
    }
    let remaining = match timer.expires.checked_sub(now) {
        Some(remaining) if remaining > 0 => remaining,
        // Expired: a `SIGEV_NONE` one-shot reads disarmed, a timer whose
        // signal is on its way 1 ns.
        _ if quiet => 0,
        _ => 1,
    };
    (remaining, timer.interval)
}

/// Write a remaining time and a reload as a `struct itimerspec`.
///
/// # Safety
/// `out` must be writable for a `struct itimerspec`.
unsafe fn write_spec(out: *mut Itimerspec, (value, interval): (u64, u64)) {
    // SAFETY: per this function's contract.
    unsafe { out.write_unaligned([Timespec::from_nanos(interval), Timespec::from_nanos(value)]) };
}

/// `timer_settime(id, flags, new, old)`: the new setting is validated
/// (`EINVAL`) before the id (`EINVAL`); the old setting is answered; a zero
/// value disarms; `TIMER_ABSTIME` takes an absolute time on the timer's clock.
///
/// # Safety
/// `new` must be NULL or readable, `old` NULL or writable, each for a
/// `struct itimerspec`.
pub(crate) unsafe fn timer_settime(
    id: i32,
    flags: i32,
    new: *const Itimerspec,
    old: *mut Itimerspec,
) -> i64 {
    if new.is_null() {
        return errno(EINVAL);
    }
    // SAFETY: per this function's contract.
    let [interval, value] = unsafe { new.read_unaligned() };
    let (Some(interval), Some(value)) = (interval.valid_nanos(), value.valid_nanos()) else {
        return errno(EINVAL);
    };
    fire_due();
    let Some(line) = lock_state().timers.posix.get(&id).map(|timer| timer.line) else {
        return errno(EINVAL);
    };
    let now = match observe(line) {
        Ok(now) => now,
        Err(code) => return errno(code),
    };
    let absolute = flags & crate::clocks::TIMER_ABSTIME != 0;
    let mut state = lock_state();
    let Some(realtime) = state.timers.posix.get(&id).map(|timer| timer.realtime) else {
        return errno(EINVAL);
    };
    let expires = match (value, line) {
        (0, _) => 0,
        (_, Line::Monotonic) => match deadline(value, absolute, realtime, now) {
            Ok(expires) => expires,
            Err(code) => return errno(code),
        },
        (_, Line::Cpu(_)) if absolute => value,
        (_, Line::Cpu(_)) => now.saturating_add(value),
    };
    let timer = state.timers.posix.get_mut(&id).expect("looked up above");
    let previous = posix_get(timer, now, true);
    timer.requeue = timer.requeue.wrapping_add(2) & !REQUEUE_PENDING;
    timer.overrun_last = 0;
    timer.overrun = -1;
    timer.expires = expires;
    let due_now = match line {
        // `common_timer_set`: a zero value disarms and drops the reload; a
        // `SIGEV_NONE` timer is never queued, only read.
        Line::Monotonic => {
            timer.interval = if value != 0 { interval } else { 0 };
            timer.active = value != 0 && timer.notify != Notify::Quiet;
            false
        }
        // `posix_cpu_timer_set`: the reload is stored either way, every
        // armed timer is queued (a `SIGEV_NONE` one clears as it fires), and
        // one already due fires at once.
        Line::Cpu(_) => {
            timer.interval = interval;
            timer.active = value != 0;
            value != 0 && now >= expires
        }
    };
    let wakes = if due_now {
        state.fire_posix(id, now)
    } else {
        Vec::new()
    };
    state.publish_alarm();
    drop(state);
    wake_all(wakes);
    if !old.is_null() {
        // SAFETY: per this function's contract.
        unsafe { write_spec(old, previous) };
    }
    0
}

/// `timer_gettime(id, value)`.
///
/// # Safety
/// `out` must be NULL or writable for a `struct itimerspec`.
pub(crate) unsafe fn timer_gettime(id: i32, out: *mut Itimerspec) -> i64 {
    fire_due();
    let Some(line) = lock_state().timers.posix.get(&id).map(|timer| timer.line) else {
        return errno(EINVAL);
    };
    let now = match observe(line) {
        Ok(now) => now,
        Err(code) => return errno(code),
    };
    let current = {
        let mut state = lock_state();
        let Some(timer) = state.timers.posix.get_mut(&id) else {
            return errno(EINVAL);
        };
        posix_get(timer, now, false)
    };
    if out.is_null() {
        return errno(EFAULT);
    }
    // SAFETY: per this function's contract.
    unsafe { write_spec(out, current) };
    0
}

/// `timer_getoverrun(id)`: the overruns of the last expiry dequeued.
pub(crate) fn timer_getoverrun(id: i32) -> i64 {
    fire_due();
    lock_state()
        .timers
        .posix
        .get(&id)
        .map_or(errno(EINVAL), |timer| {
            timer.overrun_last.min(i64::from(i32::MAX))
        })
}

/// `timer_delete(id)`; a signal it queued stays pending.
pub(crate) fn timer_delete(id: i32) -> i64 {
    let mut state = lock_state();
    if state.timers.posix.remove(&id).is_none() {
        return errno(EINVAL);
    }
    state.publish_alarm();
    0
}

const TFD_TIMER_ABSTIME: i32 = 1;
const TFD_TIMER_CANCEL_ON_SET: i32 = 2;
const TFD_CLOEXEC: c_int = 0o2000000;
const TFD_NONBLOCK: c_int = 0o4000;

/// `timerfd_create(clock, flags)`: an unknown flag, or a clock other than
/// the realtime, monotonic, boot and alarm clocks, is `EINVAL`; the alarm
/// clocks need `CAP_WAKE_ALARM` (`EPERM`).
pub(crate) fn timerfd_create(clock: i32, flags: c_int) -> i64 {
    let decoded = Clock::decode(clock);
    let realtime = match decoded {
        _ if flags & !(TFD_CLOEXEC | TFD_NONBLOCK) != 0 => return errno(EINVAL),
        Some(Clock::Realtime) => true,
        Some(Clock::Monotonic | Clock::Boottime) => false,
        Some(Clock::RealtimeAlarm | Clock::BoottimeAlarm) => return errno(EPERM),
        _ => return errno(EINVAL),
    };
    super::signals::activate();
    let handle = {
        let mut state = lock_state();
        let handle = state.timers.next_fd;
        state.timers.next_fd += 1;
        state.timers.fds.insert(
            handle,
            TimerFd {
                realtime,
                expires: 0,
                queued: false,
                interval: 0,
                ticks: 0,
                expired: false,
                waiters: VecDeque::new(),
                open: true,
            },
        );
        handle
    };
    let nonblock = if flags & TFD_NONBLOCK != 0 {
        O_NONBLOCK
    } else {
        0
    };
    match crate::install_fd(
        FdKind::TimerFd,
        handle,
        O_READ | O_WRITE | nonblock,
        flags & TFD_CLOEXEC != 0,
    ) {
        Ok(fd) => i64::from(fd),
        Err(code) => {
            lock_state().timers.fds.remove(&handle);
            errno(code)
        }
    }
}

/// The timer descriptor `fd` names: `EBADF` for no descriptor, `EINVAL` for
/// one that is not a timer.
fn timerfd_handle(fd: c_int) -> Result<u64, c_int> {
    let resolved = crate::fd_table().lock().resolve(fd).ok_or(EBADF)?;
    if resolved.kind != FdKind::TimerFd {
        return Err(EINVAL);
    }
    Ok(resolved.handle)
}

impl TimerFd {
    /// `timerfd_gettime`'s forward: a fired periodic timer moves to its next
    /// period after now, the periods it skipped counted as expirations.
    fn forward_expired(&mut self, now: u64) {
        if self.expired && self.interval != 0 {
            self.expired = false;
            self.ticks += forward(&mut self.expires, now, self.interval).saturating_sub(1);
            self.queued = true;
        }
    }

    fn remaining(&self, now: u64) -> u64 {
        self.expires.saturating_sub(now)
    }
}

/// `timerfd_settime(fd, flags, new, old)`: an unknown flag or an invalid
/// time is `EINVAL` before the descriptor is looked at; the old setting is
/// answered; arming drops the expirations not yet read.
/// `TFD_TIMER_CANCEL_ON_SET` is accepted: only a clock set cancels, and
/// nothing sets the virtual clock.
///
/// # Safety
/// `new` must be NULL or readable, `old` NULL or writable, each for a
/// `struct itimerspec`.
pub(crate) unsafe fn timerfd_settime(
    fd: c_int,
    flags: i32,
    new: *const Itimerspec,
    old: *mut Itimerspec,
) -> i64 {
    if new.is_null() {
        return errno(EFAULT);
    }
    // SAFETY: per this function's contract.
    let [interval, value] = unsafe { new.read_unaligned() };
    let (Some(interval), Some(value)) = (interval.valid_nanos(), value.valid_nanos()) else {
        return errno(EINVAL);
    };
    if flags & !(TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET) != 0 {
        return errno(EINVAL);
    }
    let handle = match timerfd_handle(fd) {
        Ok(handle) => handle,
        Err(code) => return errno(code),
    };
    fire_due();
    let now = match observe(Line::Monotonic) {
        Ok(now) => now,
        Err(code) => return errno(code),
    };
    let mut state = lock_state();
    let Some(realtime) = state.timers.fds.get(&handle).map(|timer| timer.realtime) else {
        return errno(EBADF);
    };
    let expires = match value {
        0 => 0,
        _ => match deadline(value, flags & TFD_TIMER_ABSTIME != 0, realtime, now) {
            Ok(expires) => expires,
            Err(code) => return errno(code),
        },
    };
    let timer = state.timers.fds.get_mut(&handle).expect("looked up above");
    if timer.expired && timer.interval != 0 {
        forward(&mut timer.expires, now, timer.interval);
    }
    let previous = (timer.remaining(now), timer.interval);
    // `timerfd_setup`: the expiry is the new value, even a zero one that
    // leaves the timer unqueued.
    timer.expired = false;
    timer.ticks = 0;
    timer.interval = interval;
    timer.expires = expires;
    timer.queued = value != 0;
    state.publish_alarm();
    drop(state);
    if !old.is_null() {
        // SAFETY: per this function's contract.
        unsafe { write_spec(old, previous) };
    }
    0
}

/// `timerfd_gettime(fd, value)`: the remaining time (0 the moment a period
/// ends, until the timer is forwarded — here, by this read) and the reload.
///
/// # Safety
/// `out` must be NULL or writable for a `struct itimerspec`.
pub(crate) unsafe fn timerfd_gettime(fd: c_int, out: *mut Itimerspec) -> i64 {
    let handle = match timerfd_handle(fd) {
        Ok(handle) => handle,
        Err(code) => return errno(code),
    };
    fire_due();
    let now = match observe(Line::Monotonic) {
        Ok(now) => now,
        Err(code) => return errno(code),
    };
    let current = {
        let mut state = lock_state();
        let Some(timer) = state.timers.fds.get_mut(&handle) else {
            return errno(EBADF);
        };
        timer.forward_expired(now);
        let current = (timer.remaining(now), timer.interval);
        state.publish_alarm();
        current
    };
    if out.is_null() {
        return errno(EFAULT);
    }
    // SAFETY: per this function's contract.
    unsafe { write_spec(out, current) };
    0
}

/// Read a timer descriptor: the expirations since the last read, one `u64`,
/// and the count resets (a fired periodic timer moves to its next period
/// after now, the periods it skipped counted). A buffer shorter than a `u64`
/// is `EINVAL`; with none expired, `EAGAIN` nonblocking, else the reader
/// waits for the expiry.
///
/// # Safety
/// `buf` must be writable for `len` bytes.
pub(crate) unsafe fn timerfd_read(
    handle: u64,
    nonblocking: bool,
    buf: *mut c_void,
    len: usize,
) -> isize {
    if len < 8 {
        return crate::fail(EINVAL) as isize;
    }
    if buf.is_null() {
        return crate::fail(EFAULT) as isize;
    }
    let me = current_task();
    loop {
        fire_due();
        let mut state = lock_state();
        let Some(timer) = state.timers.fds.get_mut(&handle) else {
            return crate::fail(EBADF) as isize;
        };
        if timer.ticks > 0 {
            let mut ticks = timer.ticks;
            if timer.expired && timer.interval != 0 {
                let now = match now_on(Line::Monotonic) {
                    Ok(now) => now,
                    Err(code) => return crate::fail(code) as isize,
                };
                ticks += forward(&mut timer.expires, now, timer.interval).saturating_sub(1);
                timer.queued = true;
            }
            timer.expired = false;
            timer.ticks = 0;
            state.release_closed_timerfd(handle);
            state.publish_alarm();
            // SAFETY: `buf` is writable for >= 8 bytes (checked above).
            unsafe {
                buf.cast::<u8>()
                    .copy_from_nonoverlapping(ticks.to_ne_bytes().as_ptr(), 8)
            };
            return 8;
        }
        if nonblocking {
            return crate::fail(EWOULDBLOCK) as isize;
        }
        timer.waiters.push_back(me);
        let step = state.block(
            me,
            "timerfd-read",
            Wait::new(BlockClass::Io, vec![WaiterLoc::TimerFdRecv(handle)]),
        );
        match step {
            Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
            Ok(Step::Continue) => drop(state),
            Err(error) => return crate::fail(error.into_posix()) as isize,
        }
        lock_state().timed_out.remove(&me);
        if signals::resume() == signals::Resumed::Eintr {
            lock_state().release_closed_timerfd(handle);
            return crate::fail(crate::EINTR) as isize;
        }
    }
}

/// Whether a timer descriptor has expirations to read.
pub(super) fn timerfd_readable(state: &ThreadRuntime, handle: u64) -> bool {
    state
        .timers
        .fds
        .get(&handle)
        .is_some_and(|timer| timer.ticks > 0)
}

/// Park `me` on a timer descriptor's readers, for a readiness wait.
pub(super) fn timerfd_watch(
    state: &mut ThreadRuntime,
    handle: u64,
    me: TaskId,
) -> Option<WaiterLoc> {
    let timer = state.timers.fds.get_mut(&handle)?;
    timer.waiters.push_back(me);
    Some(WaiterLoc::TimerFdRecv(handle))
}

/// Unlink `me` from a timer descriptor's readers.
pub(super) fn timerfd_unwatch(state: &mut ThreadRuntime, handle: u64, me: TaskId) {
    if let Some(timer) = state.timers.fds.get_mut(&handle) {
        timer.waiters.retain(|task| *task != me);
    }
    state.release_closed_timerfd(handle);
}

impl ThreadRuntime {
    /// Free a timer descriptor no descriptor names once no reader waits on it.
    fn release_closed_timerfd(&mut self, handle: u64) {
        if self
            .timers
            .fds
            .get(&handle)
            .is_some_and(|timer| !timer.open && timer.waiters.is_empty())
        {
            self.timers.fds.remove(&handle);
            self.publish_alarm();
        }
    }
}

/// The last descriptor naming a timer descriptor closed. A reader blocked on
/// it keeps it (the kernel's `read` holds the file): it runs on and the
/// reader completes at its expiry. With none, it is freed.
pub(crate) fn timerfd_close(handle: u64) {
    let mut state = lock_state();
    if let Some(timer) = state.timers.fds.get_mut(&handle) {
        timer.open = false;
    }
    state.release_closed_timerfd(handle);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forwarding_counts_the_periods_up_to_the_first_after_now() {
        let mut expires = 1_000;
        // Exactly at the expiry: one period.
        assert_eq!(forward(&mut expires, 1_000, 1_000), 1);
        assert_eq!(expires, 2_000);
        // Twenty periods measured from the programmed expiry.
        let mut expires = 1_000_000;
        assert_eq!(forward(&mut expires, 20_000_000, 1_000_000), 20);
        assert_eq!(expires, 21_000_000);
        // Before the expiry, nothing moves.
        assert_eq!(forward(&mut expires, 20_000_000, 1_000_000), 0);
    }

    #[test]
    fn a_timeval_is_valid_below_one_second_of_microseconds() {
        assert_eq!(timeval_nanos([1, 5]), Some(NANOS + 5_000));
        assert_eq!(timeval_nanos([0, 1_000_000]), None);
        assert_eq!(timeval_nanos([0, -1]), None);
        assert_eq!(timeval_nanos([-1, 0]), None);
    }

    #[test]
    fn a_quiet_timer_reads_disarmed_once_expired_and_a_signalling_one_one_nanosecond() {
        let timer = |notify| PosixTimer {
            line: Line::Monotonic,
            realtime: false,
            notify,
            expires: 100,
            interval: 0,
            active: true,
            requeue: 0,
            overrun: -1,
            overrun_last: 0,
        };
        assert_eq!(posix_get(&mut timer(Notify::Quiet), 200, false), (0, 0));
        let signal = Notify::Signal {
            sig: SIGALRM,
            value: 0,
            target: SignalTarget::Process,
        };
        assert_eq!(posix_get(&mut timer(signal), 200, false), (1, 0));
        assert_eq!(posix_get(&mut timer(signal), 40, false), (60, 0));
    }
}
