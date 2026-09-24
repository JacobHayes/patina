//! The time rows beyond reading and sleeping on a clock: clock resolution,
//! `time(2)`, the interval timers (`setitimer`/`getitimer`/`alarm`), POSIX
//! timers (`timer_*`), timer descriptors (`timerfd_*`), process CPU time
//! (`times`, `getrusage`), and the clock-setting rows an unprivileged caller
//! is refused.
//!
//! A timer's remaining time is a clock reading, so it is never recorded as a
//! value: an event records whether the timer is armed and its reload interval
//! (which the kernel keeps exactly as set), and hands the remaining time back
//! to the scenario for its relation checks (`0 < remaining <= set`). An
//! expiration count, an overrun count or a CPU-time figure the host's
//! scheduling decides is recorded the same way: by relation, never by value.

use super::Probe;
use crate::observe::{Id, Norm};
use crate::record::EventBuilder;
use patina_dst_syscalls::Syscall;
use serde_json::Value;

const NANOS: i64 = 1_000_000_000;

/// A `(tv_sec, tv_nsec)` pair as the scenario wrote it (an invalid one
/// included).
pub type Spec = (i64, i64);

/// A `(tv_sec, tv_usec)` pair of the `itimerval` rows.
pub type Micros = (i64, i64);

/// `ms` milliseconds as a [`Spec`].
pub const fn ms(ms: i64) -> Spec {
    (ms / 1000, (ms % 1000) * 1_000_000)
}

/// `ms` milliseconds as [`Micros`].
pub const fn ms_us(ms: i64) -> Micros {
    (ms / 1000, (ms % 1000) * 1000)
}

/// A spec's length in nanoseconds.
pub fn spec_ns(spec: Spec) -> i128 {
    i128::from(spec.0) * i128::from(NANOS) + i128::from(spec.1)
}

/// A microsecond pair's length in microseconds.
pub fn micros(value: Micros) -> i64 {
    value.0 * 1_000_000 + value.1
}

fn spec_label(spec: Spec) -> String {
    format!("{}.{:09}", spec.0, spec.1)
}

fn micros_label(value: Micros) -> String {
    format!("{}.{:06}", value.0, value.1)
}

fn timespec(spec: Spec) -> libc::timespec {
    libc::timespec {
        tv_sec: spec.0,
        tv_nsec: spec.1,
    }
}

fn of_timespec(ts: &libc::timespec) -> Spec {
    (ts.tv_sec, ts.tv_nsec)
}

fn timeval(value: Micros) -> libc::timeval {
    libc::timeval {
        tv_sec: value.0,
        tv_usec: value.1,
    }
}

fn itimerspec(value: Spec, interval: Spec) -> libc::itimerspec {
    libc::itimerspec {
        it_interval: timespec(interval),
        it_value: timespec(value),
    }
}

/// `SI_TIMER`: the `si_code` of a POSIX timer's signal.
pub const SI_TIMER: i32 = -2;

/// `SI_KERNEL`: the `si_code` of an interval timer's `SIGALRM`.
pub const SI_KERNEL: i32 = 0x80;

/// A POSIX timer as a scenario holds it: the kernel's id, and whether it is
/// one the process created (recorded by relation) or a number the scenario
/// chose to be no timer (recorded as it is).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimerId {
    pub raw: i32,
    allocated: bool,
}

impl TimerId {
    /// A number no `timer_create` of this process returned.
    pub const fn unallocated(raw: i32) -> TimerId {
        TimerId {
            raw,
            allocated: false,
        }
    }
}

/// What a POSIX timer's expiry notifies (`struct sigevent`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sigev {
    /// A NULL `sigevent`: `SIGALRM` to the process, `sival_int` = the id.
    Default,
    /// `SIGEV_NONE`: nothing is delivered; the timer is only read.
    Quiet,
    /// `SIGEV_SIGNAL` with this signal and `sival_int`.
    Signal { signo: i32, value: i32 },
    /// `SIGEV_THREAD` as the kernel sees it (glibc builds its helper thread
    /// on `SIGEV_THREAD_ID`): a process-directed signal.
    Thread { signo: i32, value: i32 },
    /// `SIGEV_SIGNAL | SIGEV_THREAD_ID` to thread `tid` (`own` when it is a
    /// thread of this process, recorded by relation).
    ThreadId {
        signo: i32,
        value: i32,
        tid: i32,
        own: bool,
    },
    /// A `sigev_notify` the kernel does not define.
    Unknown(i32),
}

impl Sigev {
    fn raw(self) -> Option<libc::sigevent> {
        // SAFETY: all-zero is a valid sigevent (SIGEV_SIGNAL, signal 0).
        let mut event: libc::sigevent = unsafe { std::mem::zeroed() };
        let (notify, signo, value, tid) = match self {
            Sigev::Default => return None,
            Sigev::Quiet => (libc::SIGEV_NONE, 0, 0, 0),
            Sigev::Signal { signo, value } => (libc::SIGEV_SIGNAL, signo, value, 0),
            Sigev::Thread { signo, value } => (libc::SIGEV_THREAD, signo, value, 0),
            Sigev::ThreadId {
                signo, value, tid, ..
            } => (
                libc::SIGEV_THREAD_ID | libc::SIGEV_SIGNAL,
                signo,
                value,
                tid,
            ),
            Sigev::Unknown(notify) => (notify, libc::SIGALRM, 0, 0),
        };
        event.sigev_notify = notify;
        event.sigev_signo = signo;
        event.sigev_value = libc::sigval {
            sival_ptr: value as usize as *mut libc::c_void,
        };
        event.sigev_notify_thread_id = tid;
        Some(event)
    }

    fn record<'a>(self, builder: EventBuilder<'a>) -> EventBuilder<'a> {
        match self {
            Sigev::Default => builder.arg("sevp", "NULL"),
            Sigev::Quiet => builder.arg("notify", "SIGEV_NONE"),
            Sigev::Signal { signo, value } => builder
                .arg("notify", "SIGEV_SIGNAL")
                .arg("signo", signo)
                .arg("value", value),
            Sigev::Thread { signo, value } => builder
                .arg("notify", "SIGEV_THREAD")
                .arg("signo", signo)
                .arg("value", value),
            Sigev::ThreadId {
                signo,
                value,
                tid,
                own,
            } => {
                let builder = builder
                    .arg("notify", "SIGEV_THREAD_ID")
                    .arg("signo", signo)
                    .arg("value", value)
                    .arg("tid", tid);
                if own {
                    builder.norm("args.tid", Norm::Identity(Id::Process))
                } else {
                    builder
                }
            }
            Sigev::Unknown(notify) => builder.arg("notify", notify),
        }
    }
}

/// The `it_value` of a `*_settime` row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arm {
    /// This `(tv_sec, tv_nsec)` as written (relative, or an absolute time the
    /// scenario chose, such as one in the past): recorded as it is.
    Spec(Spec),
    /// An absolute time computed from a clock reading: recorded as `reading`.
    Reading(Spec),
}

impl Arm {
    fn spec(self) -> Spec {
        match self {
            Arm::Spec(spec) | Arm::Reading(spec) => spec,
        }
    }

    fn label(self) -> String {
        match self {
            Arm::Spec(spec) => spec_label(spec),
            Arm::Reading(_) => "reading".to_string(),
        }
    }
}

/// The value `clock_settime` is asked to set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetTo {
    /// The clock's own current reading (read quietly just before).
    Now,
    /// This `(tv_sec, tv_nsec)`, as written.
    Raw(Spec),
}

/// How an expiration or overrun count is recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Count {
    /// The count is a kernel fact (a one-shot timer expired once; nothing
    /// expired since the last read): recorded as it is.
    Exact,
    /// The host's scheduling decides how many periods passed beyond a
    /// lower bound the scenario derives from measured elapsed time (a
    /// periodic timer counts every period from its programmed expiry, so a
    /// longer wait only raises the count): recorded as whether the count
    /// reaches the bound.
    AtLeast(u64),
}

/// A clock's resolution as `clock_getres` answers it, and how it is recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Res {
    /// A kernel fact of a high-resolution clock (1 ns): recorded as it is.
    Exact,
    /// A coarse clock's tick (`TICK_NSEC`, the host's `CONFIG_HZ`): recorded
    /// as whether it is one second divided by a kernel `HZ` choice.
    Tick,
}

/// The `HZ` values the kernel's Kconfig offers (kernel/Kconfig.hz).
const HZ_CHOICES: [i64; 4] = [100, 250, 300, 1000];

/// A `clock_getres` subject: a clock id the scenario names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClockArg {
    /// A static clock id, recorded as it is.
    Id(i32),
    /// The process CPU clock of this pid (`clock_getcpuclockid(3)`), the pid
    /// recorded by relation.
    ProcessCpu(i32),
    /// The process CPU clock of a pid no process has.
    MissingProcessCpu,
}

/// A pid no process has (`pid_max` is at most 2^22).
pub const MISSING_PID: i32 = 0x7fff_fff0;

/// `MAKE_PROCESS_CPUCLOCK(pid, CPUCLOCK_SCHED)` (include/linux/posix-timers.h).
fn process_cpu_clock(pid: i32) -> i32 {
    ((!pid) << 3) | 2
}

impl ClockArg {
    fn raw(self) -> i32 {
        match self {
            ClockArg::Id(id) => id,
            ClockArg::ProcessCpu(pid) => process_cpu_clock(pid),
            ClockArg::MissingProcessCpu => process_cpu_clock(MISSING_PID),
        }
    }

    fn record<'a>(self, builder: EventBuilder<'a>) -> EventBuilder<'a> {
        match self {
            ClockArg::Id(id) => builder.arg("clock", id),
            ClockArg::ProcessCpu(pid) => builder
                .arg("cpu_clock_of", pid)
                .norm("args.cpu_clock_of", Norm::Identity(Id::Process)),
            ClockArg::MissingProcessCpu => builder.arg("cpu_clock_of", "missing"),
        }
    }
}

/// The `struct tms` members a scenario relates.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tms {
    pub utime: i64,
    pub stime: i64,
    pub cutime: i64,
    pub cstime: i64,
}

/// The CPU time of a `getrusage` answer, in microseconds, and whether every
/// accounting member is zero.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    pub cpu_us: i64,
    pub all_zero: bool,
}

impl Probe {
    // ---- clock resolution and whole seconds ----------------------------------

    /// `clock_getres(clock, &res)` (or a NULL `res`).
    pub fn clock_getres(&self, clock: ClockArg, null: bool, shown: Res) -> (i64, i128) {
        let mut res = libc::timespec {
            tv_sec: -1,
            tv_nsec: -1,
        };
        let out = if null {
            0
        } else {
            &mut res as *mut libc::timespec as i64
        };
        let result = self.call(
            Syscall::N_clock_getres,
            [clock.raw() as i64, out, 0, 0, 0, 0],
        );
        let ns = spec_ns(of_timespec(&res));
        let builder = clock
            .record(self.event(Syscall::N_clock_getres, result))
            .arg("res", if null { "NULL" } else { "buffer" });
        let builder = match (result, null, shown) {
            (0, false, Res::Exact) => builder.field("res_ns", ns as i64),
            (0, false, Res::Tick) => builder.field(
                "res_is_a_tick",
                HZ_CHOICES.iter().any(|hz| {
                    i128::from(NANOS / hz) == ns || i128::from((NANOS + hz - 1) / hz) == ns
                }),
            ),
            _ => builder,
        };
        builder.emit();
        (result, ns)
    }

    /// `time(2)`: whole `CLOCK_REALTIME` seconds, returned and (with a
    /// buffer) stored. The generic (arm64) table has no `time` row: there the
    /// libc vehicle calls glibc's `time` and the syscall vehicle reads
    /// `CLOCK_REALTIME`, as glibc itself does. The answer is a clock reading,
    /// recorded by its order relation to the previous one.
    pub fn time(&self, buffer: bool) -> (i64, i64) {
        let mut stored: libc::time_t = -1;
        let out = if buffer {
            &mut stored as *mut libc::time_t
        } else {
            std::ptr::null_mut()
        };
        #[cfg(target_arch = "x86_64")]
        let result = self.call(Syscall::N_time, [out as i64, 0, 0, 0, 0, 0]);
        #[cfg(not(target_arch = "x86_64"))]
        let result = {
            let mut ts = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            let read = self.legacy(
                // SAFETY: `out` is NULL or this frame's time_t.
                || unsafe { libc::time(out) },
                Syscall::N_clock_gettime,
                [
                    libc::CLOCK_REALTIME as i64,
                    &mut ts as *mut libc::timespec as i64,
                    0,
                    0,
                    0,
                    0,
                ],
            );
            match (self.vehicle, read) {
                (crate::vehicle::Vehicle::Syscall, 0) => {
                    if buffer {
                        stored = ts.tv_sec;
                    }
                    ts.tv_sec
                }
                _ => read,
            }
        };
        let builder = self
            .rec
            .event("time", result)
            .arg("buffer", buffer)
            .norm("ret", Norm::Monotonic);
        let builder = if buffer && result >= 0 {
            builder.field("stored_matches", stored == result)
        } else {
            builder
        };
        builder.emit();
        (result, stored)
    }

    // ---- interval timers ------------------------------------------------------

    /// `setitimer(which, {value, interval}, &old)`: records the old timer's
    /// armed state and interval; returns the old `(value, interval)`.
    pub fn setitimer(&self, which: i32, value: Micros, interval: Micros) -> (i64, Micros, Micros) {
        let new = libc::itimerval {
            it_interval: timeval(interval),
            it_value: timeval(value),
        };
        let mut old = libc::itimerval {
            it_interval: timeval((-1, -1)),
            it_value: timeval((-1, -1)),
        };
        let result = self.call(
            Syscall::N_setitimer,
            [
                which as i64,
                &new as *const libc::itimerval as i64,
                &mut old as *mut libc::itimerval as i64,
                0,
                0,
                0,
            ],
        );
        let old_value = (old.it_value.tv_sec, old.it_value.tv_usec);
        let old_interval = (old.it_interval.tv_sec, old.it_interval.tv_usec);
        let builder = self
            .event(Syscall::N_setitimer, result)
            .arg("which", which)
            .arg("value", micros_label(value))
            .arg("interval", micros_label(interval));
        let builder = if result == 0 {
            builder
                .field("old_armed", micros(old_value) != 0)
                .field("old_interval", micros_label(old_interval))
        } else {
            builder
        };
        builder.emit();
        (result, old_value, old_interval)
    }

    /// `getitimer(which, &cur)`: records whether it is armed and its
    /// interval; returns `(value, interval)`.
    pub fn getitimer(&self, which: i32) -> (i64, Micros, Micros) {
        let mut cur = libc::itimerval {
            it_interval: timeval((-1, -1)),
            it_value: timeval((-1, -1)),
        };
        let result = self.call(
            Syscall::N_getitimer,
            [
                which as i64,
                &mut cur as *mut libc::itimerval as i64,
                0,
                0,
                0,
                0,
            ],
        );
        let value = (cur.it_value.tv_sec, cur.it_value.tv_usec);
        let interval = (cur.it_interval.tv_sec, cur.it_interval.tv_usec);
        let builder = self.event(Syscall::N_getitimer, result).arg("which", which);
        let builder = if result == 0 {
            builder
                .field("armed", micros(value) != 0)
                .field("interval", micros_label(interval))
                .field(
                    "usec_in_range",
                    (0..1_000_000).contains(&cur.it_value.tv_usec),
                )
        } else {
            builder
        };
        builder.emit();
        (result, value, interval)
    }

    /// `alarm(seconds)` (x86_64: the generic table has no `alarm` row, and
    /// glibc's wrapper there is `setitimer`). The previous alarm's remaining
    /// seconds are rounded to the nearest (a nonzero remainder under half a
    /// second rounds up to 1), so a host that took longer than half a second
    /// between two calls answers one less: the answer is recorded as text
    /// among `previous` when the scenario names the documented values, else
    /// as it is.
    #[cfg(target_arch = "x86_64")]
    pub fn alarm(&self, seconds: u32, previous: &'static [&'static str]) -> i64 {
        let result = self.call(Syscall::N_alarm, [i64::from(seconds), 0, 0, 0, 0, 0]);
        let builder = self.event(
            Syscall::N_alarm,
            if previous.is_empty() { result } else { 0 },
        );
        let builder = builder.arg("seconds", seconds);
        let builder = if previous.is_empty() {
            builder
        } else {
            builder
                .field("previous", result.to_string())
                .norm("fields.previous", Norm::Alternatives(previous))
        };
        builder.emit();
        result
    }

    // ---- POSIX timers -----------------------------------------------------------

    /// `timer_create(clock, sevp, &id)`.
    pub fn timer_create(&self, clock: i32, sev: Sigev) -> (i64, TimerId) {
        let event = sev.raw();
        let mut id: i32 = -1;
        let result = self.call(
            Syscall::N_timer_create,
            [
                clock as i64,
                event
                    .as_ref()
                    .map_or(0, |event| event as *const libc::sigevent as i64),
                &mut id as *mut i32 as i64,
                0,
                0,
                0,
            ],
        );
        let builder = sev.record(
            self.event(Syscall::N_timer_create, result)
                .arg("clock", clock),
        );
        let builder = if result == 0 {
            builder
                .field("id", id)
                .norm("fields.id", Norm::Relative("timer"))
        } else {
            builder
        };
        builder.emit();
        (
            result,
            TimerId {
                raw: id,
                allocated: result == 0,
            },
        )
    }

    fn timer_arg<'a>(&self, builder: EventBuilder<'a>, id: TimerId) -> EventBuilder<'a> {
        if id.allocated {
            builder
                .arg("id", id.raw)
                .norm("args.id", Norm::Relative("timer"))
        } else {
            builder.arg("id", id.raw)
        }
    }

    /// `timer_settime(id, flags, {value, interval}, &old)`: records the old
    /// timer's armed state and interval; returns the old `(value, interval)`.
    pub fn timer_settime(
        &self,
        id: TimerId,
        flags: i32,
        value: Arm,
        interval: Spec,
    ) -> (i64, Spec, Spec) {
        let new = itimerspec(value.spec(), interval);
        let mut old = itimerspec((-1, -1), (-1, -1));
        let result = self.call(
            Syscall::N_timer_settime,
            [
                id.raw as i64,
                flags as i64,
                &new as *const libc::itimerspec as i64,
                &mut old as *mut libc::itimerspec as i64,
                0,
                0,
            ],
        );
        let builder = self.timer_arg(self.event(Syscall::N_timer_settime, result), id);
        let builder = settime_args(builder, flags, value, interval);
        let builder = old_fields(builder, result, &old, false);
        builder.emit();
        (
            result,
            of_timespec(&old.it_value),
            of_timespec(&old.it_interval),
        )
    }

    /// `timer_gettime(id, &cur)`: records whether it is armed and its
    /// interval; returns `(value, interval)`.
    pub fn timer_gettime(&self, id: TimerId) -> (i64, Spec, Spec) {
        let mut cur = itimerspec((-1, -1), (-1, -1));
        let result = self.call(
            Syscall::N_timer_gettime,
            [
                id.raw as i64,
                &mut cur as *mut libc::itimerspec as i64,
                0,
                0,
                0,
                0,
            ],
        );
        let builder = self.timer_arg(self.event(Syscall::N_timer_gettime, result), id);
        let builder = current_fields(builder, result, &cur, false);
        builder.emit();
        (
            result,
            of_timespec(&cur.it_value),
            of_timespec(&cur.it_interval),
        )
    }

    /// `timer_getoverrun(id)`.
    pub fn timer_getoverrun(&self, id: TimerId, shown: Count) -> i64 {
        let result = self.call(Syscall::N_timer_getoverrun, [id.raw as i64, 0, 0, 0, 0, 0]);
        let builder = match shown {
            Count::Exact => self.event(Syscall::N_timer_getoverrun, result),
            Count::AtLeast(bound) => {
                let builder = self.event(Syscall::N_timer_getoverrun, bucket(result));
                if result >= 0 {
                    builder.field("at_least", result as u64 >= bound)
                } else {
                    builder
                }
            }
        };
        self.timer_arg(builder, id).emit();
        result
    }

    /// `timer_delete(id)`.
    pub fn timer_delete(&self, id: TimerId) -> i64 {
        let result = self.call(Syscall::N_timer_delete, [id.raw as i64, 0, 0, 0, 0, 0]);
        self.timer_arg(self.event(Syscall::N_timer_delete, result), id)
            .emit();
        result
    }

    /// `rt_sigtimedwait` for a timer's signal: records the signal, its code,
    /// the timer id it names (by relation) and the value it carries; returns
    /// the result and `si_overrun` for the scenario's relation checks.
    /// A default (`NULL` `sevp`) timer carries its own id as the value
    /// (`value_is_id`), recorded by relation too; `si_overrun` is recorded
    /// as it is (`Count::Exact`) or against its lower bound.
    pub fn timer_signal_wait(
        &self,
        set: &libc::sigset_t,
        timeout_ns: i64,
        value_is_id: bool,
        overrun_shown: Count,
    ) -> (i64, i32) {
        // SAFETY: all-zero is a valid siginfo_t.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let timeout = libc::timespec {
            tv_sec: timeout_ns / NANOS,
            tv_nsec: timeout_ns % NANOS,
        };
        let result = self.call(
            Syscall::N_rt_sigtimedwait,
            [
                set as *const libc::sigset_t as i64,
                &mut info as *mut libc::siginfo_t as i64,
                &timeout as *const libc::timespec as i64,
                super::SIGSET_BYTES,
                0,
                0,
            ],
        );
        // The `_timer` member of the union at offset 16 (after si_signo,
        // si_errno, si_code and the padding int): si_tid, si_overrun, then
        // si_sigval (whose low 32 bits are `sival_int` on these
        // little-endian targets).
        #[allow(deprecated)]
        let (timer, overrun, value) = (info._pad[1], info._pad[2], info._pad[3]);
        let builder = self
            .event(Syscall::N_rt_sigtimedwait, result)
            .arg("timeout_ns", timeout_ns)
            .field("si_signo", info.si_signo)
            .field("si_code", info.si_code);
        let builder = if result > 0 && info.si_code == SI_TIMER {
            let builder = builder
                .field("si_timerid", timer)
                .norm("fields.si_timerid", Norm::Relative("timer"))
                .field("si_value", value);
            let builder = match overrun_shown {
                Count::Exact => builder.field("si_overrun", overrun),
                Count::AtLeast(bound) => {
                    builder.field("si_overrun_at_least", i64::from(overrun) >= bound as i64)
                }
            };
            if value_is_id {
                builder.norm("fields.si_value", Norm::Relative("timer"))
            } else {
                builder
            }
        } else {
            builder
        };
        builder.emit();
        (result, overrun)
    }

    // ---- timer descriptors ----------------------------------------------------

    /// `timerfd_create(clock, flags)`; the result is a descriptor.
    pub fn timerfd_create(&self, clock: i32, flags: i32) -> i32 {
        let result = self.call(
            Syscall::N_timerfd_create,
            [clock as i64, flags as i64, 0, 0, 0, 0],
        );
        self.event(Syscall::N_timerfd_create, result)
            .arg("clock", clock)
            .arg("flags", flags)
            .norm("ret", Norm::Relative("fd"))
            .emit();
        result as i32
    }

    /// `timerfd_settime(fd, flags, {value, interval}, &old)`; as
    /// [`Self::timer_settime`].
    pub fn timerfd_settime(
        &self,
        fd: i32,
        flags: i32,
        value: Arm,
        interval: Spec,
    ) -> (i64, Spec, Spec) {
        let new = itimerspec(value.spec(), interval);
        let mut old = itimerspec((-1, -1), (-1, -1));
        let result = self.call(
            Syscall::N_timerfd_settime,
            [
                fd as i64,
                flags as i64,
                &new as *const libc::itimerspec as i64,
                &mut old as *mut libc::itimerspec as i64,
                0,
                0,
            ],
        );
        let builder = self.fd_arg(self.event(Syscall::N_timerfd_settime, result), "fd", fd);
        let builder = settime_args(builder, flags, value, interval);
        let builder = old_fields(builder, result, &old, true);
        builder.emit();
        (
            result,
            of_timespec(&old.it_value),
            of_timespec(&old.it_interval),
        )
    }

    /// `timerfd_gettime(fd, &cur)`; as [`Self::timer_gettime`].
    pub fn timerfd_gettime(&self, fd: i32) -> (i64, Spec, Spec) {
        let mut cur = itimerspec((-1, -1), (-1, -1));
        let result = self.call(
            Syscall::N_timerfd_gettime,
            [
                fd as i64,
                &mut cur as *mut libc::itimerspec as i64,
                0,
                0,
                0,
                0,
            ],
        );
        let builder = self.fd_arg(self.event(Syscall::N_timerfd_gettime, result), "fd", fd);
        let builder = current_fields(builder, result, &cur, true);
        builder.emit();
        (
            result,
            of_timespec(&cur.it_value),
            of_timespec(&cur.it_interval),
        )
    }

    /// `read(fd, buf, len)` of a timer descriptor: the expirations since the
    /// last read, one native-endian `u64`.
    pub fn timerfd_read(&self, fd: i32, len: usize, shown: Count) -> (i64, u64) {
        let mut buf = vec![0u8; len.max(8)];
        let result = self.call(
            Syscall::N_read,
            [fd as i64, buf.as_mut_ptr() as i64, len as i64, 0, 0, 0],
        );
        let count = u64::from_ne_bytes(buf[..8].try_into().expect("eight bytes"));
        let builder = self.fd_arg(self.rec.event("read", result), "fd", fd);
        let builder = builder.arg("len", len);
        let builder = if result == 8 {
            match shown {
                Count::Exact => builder.field("expirations", count),
                Count::AtLeast(bound) => builder.field("at_least", count >= bound),
            }
        } else {
            builder
        };
        builder.emit();
        (result, count)
    }

    // ---- process CPU time -------------------------------------------------------

    /// `times(&buf)` (or a NULL buffer). The answer is clock ticks since an
    /// arbitrary point, recorded by its order relation; the children's times
    /// are recorded (a process that never waited for a child has none).
    pub fn times(&self, null: bool) -> (i64, Tms) {
        // SAFETY: all-zero is a valid tms.
        let mut buf: libc::tms = unsafe { std::mem::zeroed() };
        buf.tms_cutime = -1;
        buf.tms_cstime = -1;
        let out = if null {
            0
        } else {
            &mut buf as *mut libc::tms as i64
        };
        let result = self.call(Syscall::N_times, [out, 0, 0, 0, 0, 0]);
        let builder = self
            .event(Syscall::N_times, result)
            .arg("buf", if null { "NULL" } else { "buffer" })
            .norm("ret", Norm::Monotonic);
        let builder = if !null && result >= 0 {
            builder.field("children_zero", buf.tms_cutime == 0 && buf.tms_cstime == 0)
        } else {
            builder
        };
        builder.emit();
        (
            result,
            Tms {
                utime: buf.tms_utime as i64,
                stime: buf.tms_stime as i64,
                cutime: buf.tms_cutime as i64,
                cstime: buf.tms_cstime as i64,
            },
        )
    }

    /// `getrusage(who, &usage)`: records whether every accounting member is
    /// zero when `who` is `RUSAGE_CHILDREN` (a process that never waited for a
    /// child has nothing there); a live process's own figures are host facts,
    /// returned for the scenario's relation checks.
    pub fn getrusage(&self, who: i32) -> (i64, Usage) {
        // SAFETY: all-zero is a valid rusage.
        let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
        usage.ru_maxrss = -1;
        let result = self.call(
            Syscall::N_getrusage,
            [
                who as i64,
                &mut usage as *mut libc::rusage as i64,
                0,
                0,
                0,
                0,
            ],
        );
        let cpu_us = usage.ru_utime.tv_sec * 1_000_000
            + usage.ru_utime.tv_usec
            + usage.ru_stime.tv_sec * 1_000_000
            + usage.ru_stime.tv_usec;
        let all_zero = cpu_us == 0
            && usage.ru_maxrss == 0
            && usage.ru_minflt == 0
            && usage.ru_majflt == 0
            && usage.ru_inblock == 0
            && usage.ru_oublock == 0
            && usage.ru_nvcsw == 0
            && usage.ru_nivcsw == 0;
        let builder = self.event(Syscall::N_getrusage, result).arg("who", who);
        let builder = if result == 0 && who == libc::RUSAGE_CHILDREN {
            builder.field("all_zero", all_zero)
        } else if result == 0 {
            builder.field(
                "usec_in_range",
                (0..1_000_000).contains(&usage.ru_utime.tv_usec)
                    && (0..1_000_000).contains(&usage.ru_stime.tv_usec),
            )
        } else {
            builder
        };
        builder.emit();
        (result, Usage { cpu_us, all_zero })
    }

    // ---- setting the clock -------------------------------------------------------

    /// `settimeofday(tv, tz)`: `tv` NULL or this `(tv_sec, tv_usec)`, `tz`
    /// NULL or UTC with no DST correction.
    pub fn settimeofday(&self, tv: Option<Micros>, tz: bool) -> i64 {
        let value = tv.map(timeval);
        // `struct timezone` (libc declares it opaque): minutes west, DST.
        let zone: [i32; 2] = [0, 0];
        let result = self.call(
            Syscall::N_settimeofday,
            [
                value
                    .as_ref()
                    .map_or(0, |value| value as *const libc::timeval as i64),
                if tz { zone.as_ptr() as i64 } else { 0 },
                0,
                0,
                0,
                0,
            ],
        );
        self.event(Syscall::N_settimeofday, result)
            .arg(
                "tv",
                tv.map_or(Value::from("NULL"), |tv| micros_label(tv).into()),
            )
            .arg("tz", if tz { "utc" } else { "NULL" })
            .emit();
        result
    }

    /// `clock_settime(clock, value)`.
    pub fn clock_settime(&self, clock: ClockArg, to: SetTo) -> i64 {
        let spec = match to {
            SetTo::Raw(spec) => spec,
            SetTo::Now => {
                let (_, now) = self.rec.quiet(|| self.clock_gettime(clock.raw()));
                (
                    (now / i128::from(NANOS)) as i64,
                    (now % i128::from(NANOS)) as i64,
                )
            }
        };
        let ts = timespec(spec);
        let result = self.call(
            Syscall::N_clock_settime,
            [
                clock.raw() as i64,
                &ts as *const libc::timespec as i64,
                0,
                0,
                0,
                0,
            ],
        );
        clock
            .record(self.event(Syscall::N_clock_settime, result))
            .arg(
                "value",
                match to {
                    SetTo::Now => "now".to_string(),
                    SetTo::Raw(spec) => spec_label(spec),
                },
            )
            .emit();
        result
    }

    /// `adjtimex(&buf)` with `modes` (and, for `ADJ_TICK`, `tick`). A query's
    /// answer is the host clock's synchronization state (`TIME_OK` …
    /// `TIME_ERROR`), a host fact recorded as whether it is one of them.
    pub fn adjtimex(&self, modes: u32, tick: i64) -> i64 {
        let mut buf = timex(modes, tick);
        let result = self.call(
            Syscall::N_adjtimex,
            [&mut buf as *mut libc::timex as i64, 0, 0, 0, 0, 0],
        );
        clock_state(self.event(Syscall::N_adjtimex, bucket(result)), result)
            .arg("modes", modes)
            .emit();
        result
    }

    /// `clock_adjtime(clock, &buf)` with `modes`; as [`Self::adjtimex`].
    pub fn clock_adjtime(&self, clock: i32, modes: u32) -> i64 {
        let mut buf = timex(modes, 0);
        let result = self.call(
            Syscall::N_clock_adjtime,
            [
                clock as i64,
                &mut buf as *mut libc::timex as i64,
                0,
                0,
                0,
                0,
            ],
        );
        clock_state(self.event(Syscall::N_clock_adjtime, bucket(result)), result)
            .arg("clock", clock)
            .arg("modes", modes)
            .emit();
        result
    }

    /// `syslog(type, NULL, len)` (glibc's `klogctl`).
    pub fn syslog(&self, kind: i32, len: i32) -> i64 {
        let result = self.call(Syscall::N_syslog, [kind as i64, 0, len as i64, 0, 0, 0]);
        self.event(Syscall::N_syslog, result)
            .arg("type", kind)
            .arg("len", len)
            .emit();
        result
    }
}

fn timex(modes: u32, tick: i64) -> libc::timex {
    // SAFETY: all-zero is a valid timex.
    let mut buf: libc::timex = unsafe { std::mem::zeroed() };
    buf.modes = modes;
    buf.tick = tick as _;
    buf
}

/// A success whose value is a host fact, recorded as 0 (the fact's relation
/// is a field beside it); a failure as it is.
fn bucket(result: i64) -> i64 {
    if result >= 0 { 0 } else { result }
}

/// A clock query's answer: `TIME_OK` (0) through `TIME_ERROR` (5).
fn clock_state(builder: EventBuilder<'_>, result: i64) -> EventBuilder<'_> {
    if result >= 0 {
        builder.field("state_in_range", (0..=5).contains(&result))
    } else {
        builder
    }
}

/// The `new_value` args of a `*_settime` row.
fn settime_args(
    builder: EventBuilder<'_>,
    flags: i32,
    value: Arm,
    interval: Spec,
) -> EventBuilder<'_> {
    builder
        .arg("flags", flags)
        .arg("value", value.label())
        .arg("interval", spec_label(interval))
}

/// Whether a setting is armed. A timerfd answers a remaining time of 0 the
/// moment a period ends, until its interrupt forwards the timer
/// (`timerfd_get_remaining`), so a periodic timerfd is armed by its interval
/// (`periodic_by_interval`); the other timers answer a positive remaining
/// time while armed.
fn armed(setting: &libc::itimerspec, periodic_by_interval: bool) -> bool {
    spec_ns(of_timespec(&setting.it_value)) != 0
        || (periodic_by_interval && spec_ns(of_timespec(&setting.it_interval)) != 0)
}

/// The `old_value` fields of a `*_settime` row: whether the old timer was
/// armed, and its interval.
fn old_fields<'a>(
    builder: EventBuilder<'a>,
    result: i64,
    old: &libc::itimerspec,
    periodic_by_interval: bool,
) -> EventBuilder<'a> {
    if result == 0 {
        builder
            .field("old_armed", armed(old, periodic_by_interval))
            .field("old_interval", spec_label(of_timespec(&old.it_interval)))
    } else {
        builder
    }
}

/// The `curr_value` fields of a `*_gettime` row.
fn current_fields<'a>(
    builder: EventBuilder<'a>,
    result: i64,
    cur: &libc::itimerspec,
    periodic_by_interval: bool,
) -> EventBuilder<'a> {
    if result == 0 {
        builder
            .field("armed", armed(cur, periodic_by_interval))
            .field("interval", spec_label(of_timespec(&cur.it_interval)))
            .field("nsec_in_range", (0..NANOS).contains(&cur.it_value.tv_nsec))
    } else {
        builder
    }
}
