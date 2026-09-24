//! The virtual kernel's clocks (`kernel/time/posix-timers.c`,
//! `posix-cpu-timers.c`, `time.c`, `timekeeping.c`, `ntp.c`): every clock id
//! `clock_gettime`/`clock_getres`/`clock_nanosleep`/`clock_settime`/
//! `clock_adjtime`/`timer_create`/`timerfd_create` take is decoded here once,
//! the way `clockid_to_kclock` and `pid_for_clock` decode it, and both doors
//! (the C interposers and the SUD rows) answer through these functions.
//!
//! The clocks read the one virtual clock. `CLOCK_MONOTONIC_RAW` and
//! `CLOCK_BOOTTIME` are the monotonic clock (the virtual machine never slews
//! and never suspends), `CLOCK_TAI` the realtime clock (a TAI offset of 0, as
//! a kernel nobody has set one on), and the coarse clocks the reading at the
//! last tick of the virtual kernel's `HZ`. The virtual machine has an RTC, so
//! the alarm clocks read `CLOCK_REALTIME`/`CLOCK_BOOTTIME`; arming or sleeping
//! on them needs `CAP_WAKE_ALARM` (`EPERM`). The CPU-time clocks read the
//! runtime's virtual CPU time (`Context::cpu_time_nanos`): the modeled
//! startup cost (`patina_dst_abi::STARTUP_CPU_NANOS`), then only what the
//! advance-on-spin rescue charges — a task reading the clock again and again
//! at frozen virtual time. A loop that computes without reading the clock
//! accrues nothing. All of it is user time: the runtime does not split guest
//! work into user and kernel phases. Init's CPU time is its startup's (it
//! sleeps).
//!
//! The clock-setting rows answer as they answer an unprivileged caller:
//! validation first, then `EPERM` (no `CAP_SYS_TIME`); `adjtimex` reads the
//! virtual kernel's NTP state, which no daemon ever synchronized.

use crate::thread;
use crate::{EFAULT, EINVAL, EOPNOTSUPP, EPERM, with_context};
use patina_dst_abi::ClockKind;
use patina_dst_abi::TaskId;
use std::ffi::c_int;

/// The virtual kernel's `CONFIG_HZ`.
pub(crate) const HZ: u64 = 1000;
/// `TICK_NSEC`: one tick of [`HZ`].
pub(crate) const TICK_NSEC: u64 = (NANOS + HZ / 2) / HZ;
/// `USER_HZ`: the unit of `times(2)` and `sysconf(_SC_CLK_TCK)`.
pub(crate) const USER_HZ: u64 = 100;
pub(crate) const NANOS: u64 = 1_000_000_000;

/// Kernel `struct timespec` on the 64-bit Linux targets.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

impl Timespec {
    pub(crate) fn from_nanos(nanos: u64) -> Self {
        Timespec {
            tv_sec: (nanos / NANOS) as i64,
            tv_nsec: (nanos % NANOS) as i64,
        }
    }

    /// `timespec64_valid`: a nonnegative second and a nanosecond below one
    /// second; the value in nanoseconds.
    pub(crate) fn valid_nanos(self) -> Option<u64> {
        if self.tv_sec < 0 || !(0..NANOS as i64).contains(&self.tv_nsec) {
            return None;
        }
        (self.tv_sec as u64)
            .checked_mul(NANOS)
            .and_then(|nanos| nanos.checked_add(self.tv_nsec as u64))
    }
}

/// Which CPU time a CPU clock reads (`CPUCLOCK_PROF`/`VIRT`/`SCHED`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CpuWhich {
    /// User plus system time.
    Prof,
    /// User time.
    Virt,
    /// The scheduler's runtime.
    Sched,
}

/// Whose CPU time a CPU clock reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CpuOf {
    Process,
    Thread(TaskId),
    /// The pid namespace's init, which only ever ran its startup.
    Init,
}

/// A clock id as the kernel decodes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Clock {
    Realtime,
    Monotonic,
    /// `CLOCK_PROCESS_CPUTIME_ID`, the static process CPU clock.
    ProcessCpu,
    /// `CLOCK_THREAD_CPUTIME_ID`, the static thread CPU clock.
    ThreadCpu,
    MonotonicRaw,
    RealtimeCoarse,
    MonotonicCoarse,
    Boottime,
    RealtimeAlarm,
    BoottimeAlarm,
    Tai,
    /// A CPU clock by id (`clock_getcpuclockid(3)`,
    /// `pthread_getcpuclockid(3)`): `MAKE_PROCESS_CPUCLOCK`/
    /// `MAKE_THREAD_CPUCLOCK` of a pid (0: the caller) and a `which`.
    Cpu {
        pid: i32,
        thread: bool,
        which: u32,
    },
    /// A dynamic POSIX clock: a clock device's descriptor. The virtual machine
    /// has no clock device.
    Device,
}

/// `CLOCKFD`: the low bits of a negative id naming a clock device.
const CLOCKFD: i32 = 3;

impl Clock {
    /// `clockid_to_kclock`: `None` for an id no clock has (`EINVAL`).
    pub(crate) fn decode(id: i32) -> Option<Clock> {
        if id < 0 {
            if id & 7 == CLOCKFD {
                return Some(Clock::Device);
            }
            return Some(Clock::Cpu {
                pid: !(id >> 3),
                thread: id & 4 != 0,
                which: (id & 3) as u32,
            });
        }
        Some(match id {
            0 => Clock::Realtime,
            1 => Clock::Monotonic,
            2 => Clock::ProcessCpu,
            3 => Clock::ThreadCpu,
            4 => Clock::MonotonicRaw,
            5 => Clock::RealtimeCoarse,
            6 => Clock::MonotonicCoarse,
            7 => Clock::Boottime,
            8 => Clock::RealtimeAlarm,
            9 => Clock::BoottimeAlarm,
            11 => Clock::Tai,
            _ => return None,
        })
    }

    /// The CPU time a CPU clock names (`pid_for_clock`): `gettime` allows a
    /// process clock named by the calling thread's own tid. `EINVAL` for a
    /// `which` past `CPUCLOCK_SCHED`, a pid that is not the virtual process,
    /// and a tid that is not one of its live threads. `None` for a clock that
    /// is not a CPU clock.
    pub(crate) fn cpu(self, gettime: bool) -> Option<Result<(CpuOf, CpuWhich), c_int>> {
        let (pid, thread, which) = match self {
            Clock::ProcessCpu => (0, false, 2),
            Clock::ThreadCpu => (0, true, 2),
            Clock::Cpu { pid, thread, which } => (pid, thread, which),
            _ => return None,
        };
        Some(cpu_target(pid, thread, which, gettime))
    }

    /// The monotonic- or realtime-domain clock a reading of this clock is
    /// taken on, for the clocks that are one of the two.
    pub(crate) fn domain(self) -> Option<ClockKind> {
        match self {
            Clock::Realtime | Clock::RealtimeCoarse | Clock::Tai | Clock::RealtimeAlarm => {
                Some(ClockKind::Realtime)
            }
            Clock::Monotonic
            | Clock::MonotonicRaw
            | Clock::MonotonicCoarse
            | Clock::Boottime
            | Clock::BoottimeAlarm => Some(ClockKind::Monotonic),
            _ => None,
        }
    }

    fn coarse(self) -> bool {
        matches!(self, Clock::RealtimeCoarse | Clock::MonotonicCoarse)
    }
}

fn cpu_target(
    pid: i32,
    thread: bool,
    which: u32,
    gettime: bool,
) -> Result<(CpuOf, CpuWhich), c_int> {
    let which = match which {
        0 => CpuWhich::Prof,
        1 => CpuWhich::Virt,
        2 => CpuWhich::Sched,
        _ => return Err(EINVAL),
    };
    let me = thread::current_tid();
    let task = |tid| thread::task_of(tid).ok_or(EINVAL);
    let of = match (pid, thread) {
        (0, true) => CpuOf::Thread(task(me)?),
        (0, false) => CpuOf::Process,
        // A thread clock names a thread of the caller's own process.
        (tid, true) if thread::live_tid(tid) => CpuOf::Thread(task(tid)?),
        (pid, false) if pid == crate::registry::IDENTITY_PID as i32 => CpuOf::Process,
        (pid, false) if pid == crate::registry::INIT_PID as i32 => CpuOf::Init,
        // `gettime` finds the process by the calling thread's own pid.
        (tid, false) if gettime && tid == me => CpuOf::Process,
        _ => return Err(EINVAL),
    };
    Ok((of, which))
}

/// The CPU time of `of`, in nanoseconds, observed through a recorded
/// monotonic reading (so a loop that polls a CPU clock is a clock spin the
/// runtime's advance-on-spin rescue can see). Like that reading, it answers
/// the shim-bootstrap window: 0 before the runtime is installed.
pub(crate) fn cpu_nanos(of: CpuOf) -> Result<u64, c_int> {
    let mut monotonic = 0;
    // SAFETY: `monotonic` is local, writable storage.
    if unsafe { crate::patina_clock_now(1, &mut monotonic) } != 0 {
        return Err(crate::patina_errno());
    }
    Ok(crate::with_context_raw(|context| Ok(cpu_nanos_unrecorded(context, of))).unwrap_or(0))
}

/// [`cpu_nanos`] without the clock observation, for a caller already
/// holding the context.
pub(crate) fn cpu_nanos_unrecorded(context: &patina_dst_runtime::Context, of: CpuOf) -> u64 {
    match of {
        CpuOf::Process => context.cpu_time_nanos(),
        CpuOf::Thread(task) => {
            // The main thread also holds the startup cost and whatever ran
            // before the thread subsystem first scheduled it.
            let before = if thread::tid_of(task) == crate::registry::IDENTITY_PID as c_int {
                context.task_cpu_time_nanos(None)
            } else {
                0
            };
            context.task_cpu_time_nanos(Some(task)) + before
        }
        CpuOf::Init => patina_dst_abi::STARTUP_CPU_NANOS,
    }
}

/// A reading of `clock` in nanoseconds (`clock_gettime`). The realtime and
/// monotonic lines are read through `patina_clock_now`, which also answers
/// the shim-bootstrap window (an allocator's constructor timing itself before
/// the runtime is installed).
pub(crate) fn read(clock: Clock) -> Result<u64, c_int> {
    if let Some(domain) = clock.domain() {
        let id = match domain {
            ClockKind::Realtime => 0,
            ClockKind::Monotonic => 1,
        };
        let mut now = 0;
        // SAFETY: `now` is local, writable storage.
        if unsafe { crate::patina_clock_now(id, &mut now) } != 0 {
            return Err(crate::patina_errno());
        }
        if !clock.coarse() {
            return Ok(now);
        }
        // The coarse clocks read the timekeeper at its last tick: the
        // monotonic line floored to a tick, and the realtime clock that
        // line's epoch-offset twin (0 in the shim-bootstrap window).
        let monotonic =
            crate::with_context_raw(|context| context.monotonic_now_unrecorded()).unwrap_or(0);
        return Ok(now.saturating_sub(monotonic % TICK_NSEC));
    }
    if let Some(target) = clock.cpu(true) {
        let (of, _) = target?;
        return cpu_nanos(of);
    }
    // The virtual machine has no clock device for a descriptor to name.
    Err(EINVAL)
}

/// `clock_getres`: the high-resolution clocks resolve to 1 ns, the coarse
/// ones to a tick, a CPU clock to 1 ns (`CPUCLOCK_SCHED`) or a tick.
pub(crate) fn resolution(clock: Clock) -> Result<u64, c_int> {
    if clock.domain().is_some() {
        return Ok(if clock.coarse() { TICK_NSEC } else { 1 });
    }
    if let Some(target) = clock.cpu(false) {
        let (_, which) = target?;
        return Ok(if which == CpuWhich::Sched {
            1
        } else {
            NANOS.div_ceil(HZ)
        });
    }
    Err(EINVAL)
}

/// `clock_gettime(2)`: 0 or `-errno`.
///
/// # Safety
/// `out` must be NULL or writable for a `struct timespec`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_clock_gettime(id: c_int, out: *mut Timespec) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let Some(clock) = Clock::decode(id) else {
        return -i64::from(EINVAL);
    };
    let nanos = match read(clock) {
        Ok(nanos) => nanos,
        Err(errno) => return -i64::from(errno),
    };
    if out.is_null() {
        return -i64::from(EFAULT);
    }
    // SAFETY: per this function's contract.
    unsafe { out.write_unaligned(Timespec::from_nanos(nanos)) };
    0
}

/// `clock_getres(2)`: 0 or `-errno`; a NULL `res` is not written.
///
/// # Safety
/// `res` must be NULL or writable for a `struct timespec`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_clock_getres(id: c_int, res: *mut Timespec) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let resolution = match Clock::decode(id).ok_or(EINVAL).and_then(resolution) {
        Ok(resolution) => resolution,
        Err(errno) => return -i64::from(errno),
    };
    if !res.is_null() {
        // SAFETY: per this function's contract.
        unsafe { res.write_unaligned(Timespec::from_nanos(resolution)) };
    }
    0
}

/// What `clock_nanosleep` does on a clock, once the request is valid.
enum Sleep {
    On(ClockKind),
    Refused(c_int),
}

/// `clock_nanosleep`'s clock (`clockid_to_kclock`, then the clock's
/// `nsleep`): an unknown id is `EINVAL`; a clock with no `nsleep` (the raw
/// and coarse clocks, the static thread CPU clock, a clock device) is
/// `EOPNOTSUPP`. The answer for the rest comes once the request is valid.
fn sleep_clock(id: c_int) -> Result<Clock, c_int> {
    let clock = Clock::decode(id).ok_or(EINVAL)?;
    match clock {
        Clock::MonotonicRaw
        | Clock::RealtimeCoarse
        | Clock::MonotonicCoarse
        | Clock::ThreadCpu
        | Clock::Device => Err(EOPNOTSUPP),
        _ => Ok(clock),
    }
}

/// A clock's `nsleep` for a valid request: the realtime and monotonic lines
/// sleep; an alarm clock checks its flags (`EINVAL`) and then needs
/// `CAP_WAKE_ALARM` (`EPERM`); a CPU clock refuses the caller's own thread
/// clock and one naming nothing (`posix_cpu_nsleep`, `pid_for_clock`:
/// `EINVAL`). A sleep on a CPU clock that could end — the process's, another
/// thread's, init's — waits for CPU time the sleeper does not spend: only
/// another task's clock reads (or never, for init) could end it. It is a
/// named refusal.
fn sleep_on(clock: Clock, flags: c_int) -> Sleep {
    match clock {
        Clock::Realtime | Clock::Tai => Sleep::On(ClockKind::Realtime),
        Clock::Monotonic | Clock::Boottime => Sleep::On(ClockKind::Monotonic),
        Clock::RealtimeAlarm | Clock::BoottimeAlarm if flags & !TIMER_ABSTIME != 0 => {
            Sleep::Refused(EINVAL)
        }
        Clock::RealtimeAlarm | Clock::BoottimeAlarm => Sleep::Refused(EPERM),
        _ => match clock.cpu(false).expect("the other clocks are CPU clocks") {
            Err(errno) => Sleep::Refused(errno),
            Ok((CpuOf::Thread(task), _)) if thread::tid_of(task) == thread::current_tid() => {
                Sleep::Refused(EINVAL)
            }
            Ok(_) => crate::trap_fatal(
                "clock_nanosleep on a CPU clock is not modeled (the sleeper spends no CPU time, so                  only another task's clock reads could end the sleep, or nothing, for init's);                  failing closed",
            ),
        },
    }
}

/// `clock_nanosleep(2)`: 0 or `-errno`. The clock is checked first (an
/// unknown one `EINVAL`, one with no sleep `EOPNOTSUPP`), then the request
/// (`EFAULT`, then `EINVAL`), then the clock's own rules ([`sleep_on`]); a
/// flag other than `TIMER_ABSTIME` is ignored on the lines that sleep, as the
/// kernel ignores it. A relative sleep interrupted by a handler writes
/// the time it had left into a non-NULL `rem`.
///
/// # Safety
/// `request` must be NULL or readable for a `struct timespec`, `rem` NULL or
/// writable for one.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_clock_nanosleep(
    id: c_int,
    flags: c_int,
    request: *const Timespec,
    rem: *mut Timespec,
) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let clock = match sleep_clock(id) {
        Ok(clock) => clock,
        Err(errno) => return -i64::from(errno),
    };
    if request.is_null() {
        return -i64::from(EFAULT);
    }
    // SAFETY: per this function's contract.
    let Some(requested) = (unsafe { request.read_unaligned() }).valid_nanos() else {
        return -i64::from(EINVAL);
    };
    let domain = match sleep_on(clock, flags) {
        Sleep::On(domain) => domain,
        Sleep::Refused(errno) => return -i64::from(errno),
    };
    let absolute = flags & TIMER_ABSTIME != 0;
    let deadline = if absolute {
        requested
    } else {
        match with_context(|context| context.now(domain)) {
            Ok(now) => now.saturating_add(requested),
            Err(errno) => return -i64::from(errno),
        }
    };
    let clock = match domain {
        ClockKind::Realtime => 0,
        ClockKind::Monotonic => 1,
    };
    let rem = if absolute { std::ptr::null_mut() } else { rem };
    // SAFETY: `rem` is NULL or writable for a timespec, per this contract.
    if unsafe { crate::patina_sleep_until_remaining(clock, deadline, rem.cast()) } != 0 {
        return -i64::from(crate::patina_errno());
    }
    0
}

/// `TIMER_ABSTIME`.
pub(crate) const TIMER_ABSTIME: c_int = 1;

/// `struct timeval` on the 64-bit targets.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct Timeval {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

impl Timeval {
    /// `ns_to_kernel_old_timeval`: whole microseconds.
    pub(crate) fn from_nanos(nanos: u64) -> Self {
        Timeval {
            tv_sec: (nanos / NANOS) as i64,
            tv_usec: ((nanos % NANOS) / 1000) as i64,
        }
    }
}

/// `struct rusage` on the 64-bit targets: the two times and fourteen
/// counters.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct Rusage {
    utime: Timeval,
    stime: Timeval,
    counters: [i64; 14],
}

const RUSAGE_SELF: i32 = 0;
const RUSAGE_CHILDREN: i32 = -1;
const RUSAGE_THREAD: i32 = 1;

/// `getrusage(2)`: an unknown `who` is `EINVAL`; the process's (or the
/// calling thread's) CPU time is all user time; the process has waited for
/// no child, so `RUSAGE_CHILDREN` is all zero, and it models no memory
/// high-water mark, faults, I/O blocks or context switches (zero).
///
/// # Safety
/// `out` must be NULL or writable for a `struct rusage`.
pub(crate) unsafe fn getrusage(who: i32, out: *mut Rusage) -> i64 {
    let of = match who {
        RUSAGE_SELF => Some(CpuOf::Process),
        RUSAGE_THREAD => thread::task_of(thread::current_tid()).map(CpuOf::Thread),
        RUSAGE_CHILDREN => None,
        _ => return -i64::from(EINVAL),
    };
    let mut usage = Rusage::default();
    if let Some(of) = of {
        match cpu_nanos(of) {
            Ok(nanos) => usage.utime = Timeval::from_nanos(nanos),
            Err(errno) => return -i64::from(errno),
        }
    }
    if out.is_null() {
        return -i64::from(EFAULT);
    }
    // SAFETY: per this function's contract.
    unsafe { out.write_unaligned(usage) };
    0
}

/// `INITIAL_JIFFIES`: the kernel starts `jiffies` five minutes short of its
/// 32-bit wrap, so the tick count `times(2)` answers is that plus the ticks
/// since boot.
const INITIAL_JIFFIES: u64 = (-300i64 * HZ as i64) as u32 as u64;

/// `times(2)`: the process's CPU time in `USER_HZ` ticks (all user time; no
/// child ever waited for) into a non-NULL buffer, and the tick count since
/// an arbitrary point (`jiffies_64_to_clock_t(get_jiffies_64())`).
///
/// # Safety
/// `out` must be NULL or writable for a `struct tms` (four longs).
pub(crate) unsafe fn times(out: *mut [i64; 4]) -> i64 {
    let (uptime, cpu) = match with_context(|context| {
        let uptime = context.now(ClockKind::Monotonic)?;
        Ok((uptime, cpu_nanos_unrecorded(context, CpuOf::Process)))
    }) {
        Ok(read) => read,
        Err(errno) => return -i64::from(errno),
    };
    if !out.is_null() {
        let ticks = (cpu / (NANOS / USER_HZ)) as i64;
        // SAFETY: per this function's contract.
        unsafe { out.write_unaligned([ticks, 0, 0, 0]) };
    }
    let jiffies = INITIAL_JIFFIES + uptime / TICK_NSEC;
    (jiffies / (HZ / USER_HZ)) as i64
}

/// `settimeofday(2)` of an unprivileged caller: a `tv_usec` past a second
/// (`EINVAL` here, or as a nanosecond count of a second) or a negative
/// second is `EINVAL`, then setting anything — a NULL time too — is `EPERM`.
///
/// # Safety
/// `tv` must be NULL or readable for a `struct timeval`.
pub(crate) unsafe fn settimeofday(tv: *const [i64; 2]) -> i64 {
    if !tv.is_null() {
        // SAFETY: per this function's contract.
        let [seconds, micros] = unsafe { tv.read_unaligned() };
        if !(0..=1_000_000).contains(&micros) {
            return -i64::from(EINVAL);
        }
        let ts = Timespec {
            tv_sec: seconds,
            tv_nsec: micros * 1000,
        };
        if ts.valid_nanos().is_none() {
            return -i64::from(EINVAL);
        }
    }
    -i64::from(EPERM)
}

/// `clock_settime(2)` of an unprivileged caller: a clock with no setter
/// (every one but `CLOCK_REALTIME` and the CPU clocks by id) or an unknown
/// one is `EINVAL`; `CLOCK_REALTIME` validates the time, then `EPERM`; a CPU
/// clock validates its pid, then `EPERM` even to root.
///
/// # Safety
/// `ts` must be NULL or readable for a `struct timespec`.
pub(crate) unsafe fn clock_settime(id: c_int, ts: *const Timespec) -> i64 {
    let clock = match Clock::decode(id) {
        Some(clock @ (Clock::Realtime | Clock::Cpu { .. })) => clock,
        _ => return -i64::from(EINVAL),
    };
    if ts.is_null() {
        return -i64::from(EFAULT);
    }
    // SAFETY: per this function's contract.
    let ts = unsafe { ts.read_unaligned() };
    if let Some(target) = clock.cpu(false) {
        return match target {
            Ok(_) => -i64::from(EPERM),
            Err(errno) => -i64::from(errno),
        };
    }
    if ts.valid_nanos().is_none() {
        return -i64::from(EINVAL);
    }
    -i64::from(EPERM)
}

/// `struct __kernel_timex` (`include/uapi/linux/timex.h`), 208 bytes.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Timex {
    modes: u32,
    offset: i64,
    freq: i64,
    maxerror: i64,
    esterror: i64,
    status: i32,
    constant: i64,
    precision: i64,
    tolerance: i64,
    time: [i64; 2],
    tick: i64,
    ppsfreq: i64,
    jitter: i64,
    shift: i32,
    stabil: i64,
    jitcnt: i64,
    calcnt: i64,
    errcnt: i64,
    stbcnt: i64,
    tai: i32,
    reserved: [i32; 11],
}

// The kernel's `ADJ_*` mode bits (the uapi's, not glibc's: glibc spells
// `ADJ_OFFSET_SINGLESHOT` with `ADJ_ADJTIME` folded in).
const ADJ_FREQUENCY: u32 = 0x0002;
const ADJ_SETOFFSET: u32 = 0x0100;
const ADJ_ADJTIME: u32 = 0x8000;
const ADJ_OFFSET_SINGLESHOT: u32 = 0x0001;
const ADJ_OFFSET_READONLY: u32 = 0x2000;
/// `STA_UNSYNC`: no NTP daemon ever synchronized the virtual clock.
const STA_UNSYNC: i32 = 0x0040;
/// `TIME_ERROR`: what `adjtimex` answers while `STA_UNSYNC` is set.
const TIME_ERROR: i64 = 5;
/// `NTP_PHASE_LIMIT`: the initial maximum and estimated error, in µs.
const NTP_PHASE_LIMIT: i64 = 16_000_000;
/// `MAXFREQ_SCALED / PPM_SCALE`: 500 ppm in the kernel's scaled units.
const NTP_TOLERANCE: i64 = 500 << 16;
/// `PPM_SCALE`, for the `ADJ_FREQUENCY` overflow check.
const PPM_SCALE: i64 = 1000 << 16;

/// `do_adjtimex` for an unprivileged caller (`timekeeping_validate_timex`,
/// then `__do_adjtimex` reading the NTP state): `ADJ_ADJTIME` needs the
/// single-shot offset bit (`EINVAL`) and, unless read-only, the privilege
/// (`EPERM`); any other mode that changes something is `EPERM`; a read
/// answers `TIME_ERROR` with the state of a clock no daemon synchronized.
///
/// # Safety
/// `buf` must be NULL or readable and writable for a `struct timex`.
pub(crate) unsafe fn adjtimex(buf: *mut Timex) -> i64 {
    if buf.is_null() {
        return -i64::from(EFAULT);
    }
    // SAFETY: per this function's contract.
    let mut txc = unsafe { buf.read_unaligned() };
    let modes = txc.modes;
    if modes & ADJ_ADJTIME != 0 {
        if modes & ADJ_OFFSET_SINGLESHOT == 0 {
            return -i64::from(EINVAL);
        }
        if modes & ADJ_OFFSET_READONLY == 0 {
            return -i64::from(EPERM);
        }
    } else if modes != 0 {
        return -i64::from(EPERM);
    }
    if modes & ADJ_SETOFFSET != 0 {
        return -i64::from(EPERM);
    }
    if modes & ADJ_FREQUENCY != 0
        && (i64::MIN / PPM_SCALE > txc.freq || i64::MAX / PPM_SCALE < txc.freq)
    {
        return -i64::from(EINVAL);
    }
    let now = match read(Clock::Realtime) {
        Ok(now) => now,
        Err(errno) => return -i64::from(errno),
    };
    txc.offset = 0;
    txc.freq = 0;
    txc.maxerror = NTP_PHASE_LIMIT;
    txc.esterror = NTP_PHASE_LIMIT;
    txc.status = STA_UNSYNC;
    txc.constant = 2;
    txc.precision = 1;
    txc.tolerance = NTP_TOLERANCE;
    txc.time = [(now / NANOS) as i64, ((now % NANOS) / 1000) as i64];
    txc.tick = (1_000_000 + USER_HZ as i64 / 2) / USER_HZ as i64;
    txc.ppsfreq = 0;
    txc.jitter = 0;
    txc.shift = 0;
    txc.stabil = 0;
    txc.jitcnt = 0;
    txc.calcnt = 0;
    txc.errcnt = 0;
    txc.stbcnt = 0;
    txc.tai = 0;
    // SAFETY: per this function's contract.
    unsafe { buf.write_unaligned(txc) };
    TIME_ERROR
}

/// `clock_adjtime(2)`: `CLOCK_REALTIME` is `adjtimex`; a clock with no
/// adjuster is `EOPNOTSUPP`, an unknown one (or a clock device, of which the
/// virtual machine has none) `EINVAL`.
///
/// # Safety
/// As [`adjtimex`].
pub(crate) unsafe fn clock_adjtime(id: c_int, buf: *mut Timex) -> i64 {
    match Clock::decode(id) {
        None | Some(Clock::Device) => -i64::from(EINVAL),
        // SAFETY: per this function's contract.
        Some(Clock::Realtime) => unsafe { adjtimex(buf) },
        Some(_) => -i64::from(EOPNOTSUPP),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clock_ids_decode_as_the_kernel_decodes_them() {
        assert_eq!(Clock::decode(0), Some(Clock::Realtime));
        assert_eq!(Clock::decode(11), Some(Clock::Tai));
        assert_eq!(Clock::decode(10), None);
        assert_eq!(Clock::decode(12), None);
        assert_eq!(Clock::decode(1234), None);
        // clock_getcpuclockid(3) of pid 1: MAKE_PROCESS_CPUCLOCK(1, SCHED).
        assert_eq!(
            Clock::decode((!1 << 3) | 2),
            Some(Clock::Cpu {
                pid: 1,
                thread: false,
                which: 2
            })
        );
        // pthread_getcpuclockid(3): MAKE_THREAD_CPUCLOCK(tid, SCHED).
        assert_eq!(
            Clock::decode((!7 << 3) | 4 | 2),
            Some(Clock::Cpu {
                pid: 7,
                thread: true,
                which: 2
            })
        );
        assert_eq!(Clock::decode((!5 << 3) | CLOCKFD), Some(Clock::Device));
    }

    #[test]
    fn resolutions_are_the_kernels() {
        assert_eq!(resolution(Clock::Monotonic), Ok(1));
        assert_eq!(resolution(Clock::MonotonicCoarse), Ok(TICK_NSEC));
        assert_eq!(resolution(Clock::RealtimeAlarm), Ok(1));
        assert_eq!(resolution(Clock::Device), Err(EINVAL));
        // A CPU clock's `which` past CPUCLOCK_SCHED names nothing.
        let past = Clock::Cpu {
            pid: 0,
            thread: false,
            which: 3,
        };
        assert_eq!(resolution(past), Err(EINVAL));
    }

    #[test]
    fn a_timespec_is_valid_below_one_second_of_nanoseconds() {
        let spec = |tv_sec, tv_nsec| Timespec { tv_sec, tv_nsec };
        assert_eq!(spec(1, 5).valid_nanos(), Some(NANOS + 5));
        assert_eq!(spec(0, NANOS as i64).valid_nanos(), None);
        assert_eq!(spec(-1, 0).valid_nanos(), None);
        assert_eq!(spec(0, -1).valid_nanos(), None);
    }

    #[test]
    fn setting_the_time_validates_before_the_privilege() {
        // SAFETY: local buffers.
        unsafe {
            assert_eq!(settimeofday(&[0, 1_000_000]), -i64::from(EINVAL));
            assert_eq!(settimeofday(&[-1, 0]), -i64::from(EINVAL));
            assert_eq!(settimeofday(&[0, 999_999]), -i64::from(EPERM));
            assert_eq!(settimeofday(std::ptr::null()), -i64::from(EPERM));
            let second = Timespec {
                tv_sec: 0,
                tv_nsec: NANOS as i64,
            };
            assert_eq!(clock_settime(0, &second), -i64::from(EINVAL));
            assert_eq!(clock_settime(0, &Timespec::default()), -i64::from(EPERM));
            assert_eq!(clock_settime(1, &Timespec::default()), -i64::from(EINVAL));
            assert_eq!(clock_settime(2, &Timespec::default()), -i64::from(EINVAL));
        }
    }

    #[test]
    fn adjtimex_refuses_in_the_kernels_order() {
        let timex = |modes| {
            // SAFETY: all-zero is a valid timex.
            let mut txc: Timex = unsafe { std::mem::zeroed() };
            txc.modes = modes;
            txc
        };
        // SAFETY: local buffers.
        unsafe {
            assert_eq!(adjtimex(&mut timex(ADJ_ADJTIME)), -i64::from(EINVAL));
            assert_eq!(
                adjtimex(&mut timex(ADJ_ADJTIME | ADJ_OFFSET_SINGLESHOT)),
                -i64::from(EPERM)
            );
            assert_eq!(adjtimex(&mut timex(ADJ_FREQUENCY)), -i64::from(EPERM));
            assert_eq!(clock_adjtime(1, &mut timex(0)), -i64::from(EOPNOTSUPP));
            assert_eq!(clock_adjtime(1234, &mut timex(0)), -i64::from(EINVAL));
        }
    }
}
