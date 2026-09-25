//! Per-thread scheduling attributes of the virtual process
//! (`kernel/sched/syscalls.c`, `kernel/sys.c`, `block/ioprio.c`,
//! `kernel/exec_domain.c`): policy and priority, nice, utilization clamps,
//! I/O priority, and the persona, which the kernel keeps per task, the way a
//! thread inherits them at creation (`sched_fork`, `copy_io`).
//!
//! None of it changes how the deterministic scheduler picks the next task:
//! the baton goes where the seeded scheduler sends it. These are the values
//! the rows read back and the permission rules an unprivileged caller meets
//! (no `CAP_SYS_NICE`; `RLIMIT_NICE`/`RLIMIT_RTPRIO` from the virtual limit
//! table). The virtual machine has one CPU: the affinity of every thread is
//! that CPU, and every thread runs on it.

use super::*;
use crate::limits::{RLIMIT_NICE, RLIMIT_RTPRIO};
use crate::neg_errno as errno;
use crate::registry::{IDENTITY_PID, INIT_PID};
use crate::{E2BIG, EACCES, EFAULT};

const SCHED_OTHER: u32 = 0;
const SCHED_FIFO: u32 = 1;
const SCHED_RR: u32 = 2;
const SCHED_BATCH: u32 = 3;
const SCHED_IDLE: u32 = 5;
const SCHED_DEADLINE: u32 = 6;
/// `SCHED_RESET_ON_FORK`, or'd into a policy.
const RESET_ON_FORK: i32 = 0x4000_0000;
/// `SETPARAM_POLICY`: keep the policy (`sched_setparam`).
const SETPARAM_POLICY: i32 = -1;
const MAX_RT_PRIO: u32 = 100;
const MIN_NICE: i32 = -20;
const MAX_NICE: i32 = 19;

const SCHED_FLAG_RESET_ON_FORK: u64 = 0x01;
const SCHED_FLAG_KEEP_POLICY: u64 = 0x08;
const SCHED_FLAG_KEEP_PARAMS: u64 = 0x10;
const SCHED_FLAG_UTIL_CLAMP_MIN: u64 = 0x20;
const SCHED_FLAG_UTIL_CLAMP_MAX: u64 = 0x40;
const SCHED_FLAG_UTIL_CLAMP: u64 = SCHED_FLAG_UTIL_CLAMP_MIN | SCHED_FLAG_UTIL_CLAMP_MAX;
/// `SCHED_FLAG_ALL`.
const SCHED_FLAG_ALL: u64 = 0x7f;
const SCHED_FLAG_SUGOV: u64 = 0x1000_0000;
/// `SCHED_CAPACITY_SCALE`: the utilization clamps' range.
const CAPACITY: u32 = 1024;
/// `struct sched_attr` sizes: the first version, and the kernel's.
const ATTR_SIZE_VER0: u32 = 48;
const ATTR_SIZE: u32 = 56;
const PAGE_SIZE: u32 = 4096;
/// `sysctl_sched_dl_period_min`/`_max`, in µs, and `DL_SCALE`.
const DL_PERIOD_MIN_US: u64 = 100;
const DL_PERIOD_MAX_US: u64 = 1 << 22;
const DL_SCALE: u32 = 10;
/// `sysctl_sched_base_slice` on one CPU (0.75 ms), and the round-robin
/// slice (`RR_TIMESLICE`, 100 ms).
const BASE_SLICE_NS: u64 = 750_000;
const RR_TIMESLICE_NS: u64 = 100_000_000;

const PRIO_PROCESS: i32 = 0;
const PRIO_PGRP: i32 = 1;
const PRIO_USER: i32 = 2;

const IOPRIO_WHO_PROCESS: i32 = 1;
const IOPRIO_WHO_PGRP: i32 = 2;
const IOPRIO_WHO_USER: i32 = 3;
const IOPRIO_CLASS_NONE: i32 = 0;
const IOPRIO_CLASS_RT: i32 = 1;
const IOPRIO_CLASS_BE: i32 = 2;
const IOPRIO_CLASS_IDLE: i32 = 3;
const IOPRIO_CLASS_SHIFT: i32 = 13;
const IOPRIO_LEVELS: i32 = 8;

/// The persona query (`personality(0xffffffff)`).
const PERSONA_QUERY: u32 = 0xffff_ffff;

/// One task's attributes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Attrs {
    policy: u32,
    reset_on_fork: bool,
    nice: i32,
    rt_priority: u32,
    util_min: u32,
    util_max: u32,
    /// The I/O priority it set (`IOPRIO_CLASS_NONE` until it sets one).
    ioprio: i32,
    persona: u32,
}

impl Default for Attrs {
    fn default() -> Self {
        Attrs {
            policy: SCHED_OTHER,
            reset_on_fork: false,
            nice: 0,
            rt_priority: 0,
            util_min: 0,
            util_max: CAPACITY,
            ioprio: 0,
            persona: 0,
        }
    }
}

fn rt_policy(policy: u32) -> bool {
    matches!(policy, SCHED_FIFO | SCHED_RR)
}

fn fair_policy(policy: u32) -> bool {
    matches!(policy, SCHED_OTHER | SCHED_BATCH)
}

fn valid_policy(policy: u32) -> bool {
    fair_policy(policy) || rt_policy(policy) || matches!(policy, SCHED_IDLE | SCHED_DEADLINE)
}

/// `is_nice_reduction`: a nice value `RLIMIT_NICE` allows (`20 - nice` at
/// most the soft limit).
fn nice_allowed(nice: i32) -> bool {
    (20 - nice) as u64 <= crate::limits::soft(RLIMIT_NICE)
}

/// The per-task table, keyed by tid. A thread that never changed anything
/// has no entry (the defaults), so reading an attribute never activates the
/// thread subsystem.
#[derive(Default)]
pub(super) struct SchedRuntime {
    tasks: BTreeMap<i32, Attrs>,
}

impl SchedRuntime {
    fn get(&self, tid: i32) -> Attrs {
        self.tasks.get(&tid).copied().unwrap_or_default()
    }

    fn set(&mut self, tid: i32, attrs: Attrs) {
        self.tasks.insert(tid, attrs);
    }

    /// `sched_fork`/`copy_io`: a new thread inherits its creator's
    /// attributes; under `SCHED_RESET_ON_FORK` a realtime or deadline policy
    /// falls back to `SCHED_OTHER` at nice 0, a negative nice resets to 0,
    /// and the flag clears.
    pub(super) fn spawn(&mut self, child: TaskId, parent: TaskId) {
        let mut attrs = self.get(tid_of(parent));
        if attrs.reset_on_fork {
            if rt_policy(attrs.policy) || attrs.policy == SCHED_DEADLINE {
                attrs.policy = SCHED_OTHER;
                attrs.nice = 0;
                attrs.rt_priority = 0;
            } else if attrs.nice < 0 {
                attrs.nice = 0;
            }
            attrs.reset_on_fork = false;
        }
        self.set(tid_of(child), attrs);
    }

    pub(super) fn finish(&mut self, task: TaskId) {
        self.tasks.remove(&tid_of(task));
    }
}

/// The guest's live threads, main first.
fn threads(state: &ThreadRuntime) -> Vec<i32> {
    if state.signals.is_empty() {
        return vec![IDENTITY_PID as i32];
    }
    state.signals.task_ids().map(tid_of).collect()
}

/// Init's one thread.
const INIT: i32 = INIT_PID as i32;

/// `find_process_by_pid`: 0 is the caller, anything else a live thread of
/// the guest or init's.
fn find(state: &ThreadRuntime, pid: i32) -> Option<i32> {
    let tid = if pid == 0 { current_tid() } else { pid };
    (tid == INIT || threads(state).contains(&tid)).then_some(tid)
}

/// The threads a `which`/`who` pair of `getpriority`/`setpriority`/
/// `ioprio_*` names: `None` for an unknown `which`, an empty list for a
/// `who` naming no process. A group holds init's thread when it is group 1
/// and the guest's threads when it is the guest's; every thread runs as the
/// one user.
fn targets(
    state: &ThreadRuntime,
    which: i32,
    who: i32,
    process: i32,
    group: i32,
    user: i32,
) -> Option<Vec<i32>> {
    Some(if which == process {
        find(state, who).into_iter().collect()
    } else if which == group {
        let own = crate::identity::pgid();
        let group = if who == 0 { own } else { who };
        let mut members = Vec::new();
        if group == INIT {
            members.push(INIT);
        }
        if group == own {
            members.extend(threads(state));
        }
        members
    } else if which == user {
        if who == 0 || who as u32 == crate::identity::credential().uid {
            let mut members = vec![INIT];
            members.extend(threads(state));
            members
        } else {
            Vec::new()
        }
    } else {
        return None;
    })
}

/// `getpriority(which, who)`: `20 - nice` of the highest-priority thread
/// named (the raw row's encoding; glibc converts it back).
pub(crate) fn getpriority(which: i32, who: i32) -> i64 {
    let state = lock_state();
    let Some(targets) = targets(&state, which, who, PRIO_PROCESS, PRIO_PGRP, PRIO_USER) else {
        return errno(EINVAL);
    };
    targets
        .iter()
        .map(|tid| i64::from(20 - state.sched.get(*tid).nice))
        .max()
        .unwrap_or(errno(ESRCH))
}

/// `setpriority(which, who, nice)`: the nice value clamped to `-20..=19`;
/// raising a thread's priority past what `RLIMIT_NICE` allows is `EACCES`.
pub(crate) fn setpriority(which: i32, who: i32, nice: i32) -> i64 {
    let mut state = lock_state();
    let Some(targets) = targets(&state, which, who, PRIO_PROCESS, PRIO_PGRP, PRIO_USER) else {
        return errno(EINVAL);
    };
    let nice = nice.clamp(MIN_NICE, MAX_NICE);
    let mut result = errno(ESRCH);
    for tid in targets {
        let mut attrs = state.sched.get(tid);
        if nice < attrs.nice && !nice_allowed(nice) {
            result = errno(EACCES);
            continue;
        }
        if result == errno(ESRCH) {
            result = 0;
        }
        attrs.nice = nice;
        state.sched.set(tid, attrs);
    }
    result
}

/// `sched_getscheduler`: the policy, with `SCHED_RESET_ON_FORK` or'd in.
pub(crate) fn getscheduler(pid: i32) -> i64 {
    if pid < 0 {
        return errno(EINVAL);
    }
    let state = lock_state();
    let Some(tid) = find(&state, pid) else {
        return errno(ESRCH);
    };
    let attrs = state.sched.get(tid);
    i64::from(attrs.policy)
        | if attrs.reset_on_fork {
            i64::from(RESET_ON_FORK)
        } else {
            0
        }
}

/// `sched_getparam`: the realtime priority (0 under a normal policy).
///
/// # Safety
/// `param` must be NULL or writable for an `int`.
pub(crate) unsafe fn getparam(pid: i32, param: *mut i32) -> i64 {
    if param.is_null() || pid < 0 {
        return errno(EINVAL);
    }
    let state = lock_state();
    let Some(tid) = find(&state, pid) else {
        return errno(ESRCH);
    };
    let attrs = state.sched.get(tid);
    let priority = if rt_policy(attrs.policy) {
        attrs.rt_priority
    } else {
        0
    };
    // SAFETY: per this function's contract.
    unsafe { param.write_unaligned(priority as i32) };
    0
}

/// A request to `__sched_setscheduler`.
#[derive(Clone, Copy, Debug, Default)]
struct Request {
    /// `SETPARAM_POLICY` keeps the policy.
    policy: i32,
    flags: u64,
    nice: i32,
    priority: u32,
    runtime: u64,
    deadline: u64,
    period: u64,
    util_min: u32,
    util_max: u32,
}

/// `__checkparam_dl`.
fn deadline_params_valid(request: &Request) -> bool {
    if request.flags & SCHED_FLAG_SUGOV != 0 {
        return true;
    }
    if request.deadline == 0 || request.runtime < 1 << DL_SCALE {
        return false;
    }
    if request.deadline & (1 << 63) != 0 || request.period & (1 << 63) != 0 {
        return false;
    }
    let period = if request.period == 0 {
        request.deadline
    } else {
        request.period
    };
    period >= request.deadline
        && request.deadline >= request.runtime
        && (DL_PERIOD_MIN_US * 1000..=DL_PERIOD_MAX_US * 1000).contains(&period)
}

/// `__sched_setscheduler` for an unprivileged caller.
fn setscheduler(state: &mut ThreadRuntime, tid: i32, request: Request) -> i64 {
    let current = state.sched.get(tid);
    let (policy, reset_on_fork) = if request.policy < 0 {
        (current.policy, current.reset_on_fork)
    } else {
        let policy = request.policy as u32;
        if !valid_policy(policy) {
            return errno(EINVAL);
        }
        (policy, request.flags & SCHED_FLAG_RESET_ON_FORK != 0)
    };
    if request.flags & !(SCHED_FLAG_ALL | SCHED_FLAG_SUGOV) != 0 {
        return errno(EINVAL);
    }
    if request.priority > MAX_RT_PRIO - 1 {
        return errno(EINVAL);
    }
    if (policy == SCHED_DEADLINE && !deadline_params_valid(&request))
        || rt_policy(policy) != (request.priority != 0)
    {
        return errno(EINVAL);
    }
    // user_check_sched_setscheduler: whatever needs CAP_SYS_NICE is EPERM.
    let privileged = (fair_policy(policy)
        && request.nice < current.nice
        && !nice_allowed(request.nice))
        || (rt_policy(policy) && {
            let limit = crate::limits::soft(RLIMIT_RTPRIO);
            (policy != current.policy && limit == 0)
                || (request.priority > current.rt_priority && u64::from(request.priority) > limit)
        })
        || policy == SCHED_DEADLINE
        || (current.policy == SCHED_IDLE && policy != SCHED_IDLE && !nice_allowed(current.nice))
        || (current.reset_on_fork && !reset_on_fork);
    if privileged {
        return errno(EPERM);
    }
    if request.flags & SCHED_FLAG_SUGOV != 0 {
        return errno(EINVAL);
    }
    let mut next = current;
    if request.flags & SCHED_FLAG_UTIL_CLAMP != 0 {
        // uclamp_validate: -1 resets a clamp to its default.
        let requested = |flag, value: u32, default| {
            if request.flags & flag == 0 {
                Ok(None)
            } else if value == u32::MAX {
                Ok(Some(default))
            } else if value > CAPACITY {
                Err(())
            } else {
                Ok(Some(value))
            }
        };
        let (Ok(min), Ok(max)) = (
            requested(SCHED_FLAG_UTIL_CLAMP_MIN, request.util_min, 0),
            requested(SCHED_FLAG_UTIL_CLAMP_MAX, request.util_max, CAPACITY),
        ) else {
            return errno(EINVAL);
        };
        let (min, max) = (
            min.unwrap_or(current.util_min),
            max.unwrap_or(current.util_max),
        );
        if min > max {
            return errno(EINVAL);
        }
        next.util_min = min;
        next.util_max = max;
    }
    next.policy = policy;
    next.reset_on_fork = reset_on_fork;
    if fair_policy(policy) {
        next.nice = request.nice;
    }
    next.rt_priority = request.priority;
    state.sched.set(tid, next);
    0
}

/// `sched_setscheduler` (a policy, or'd with `SCHED_RESET_ON_FORK`) and
/// `sched_setparam` (`None`: the policy kept): the realtime priority, the
/// nice value kept.
///
/// # Safety
/// `param` must be NULL or readable for an `int`.
pub(crate) unsafe fn setscheduler_param(pid: i32, policy: Option<i32>, param: *const i32) -> i64 {
    let policy = match policy {
        Some(policy) if policy < 0 => return errno(EINVAL),
        Some(policy) => policy,
        None => SETPARAM_POLICY,
    };
    if param.is_null() || pid < 0 {
        return errno(EINVAL);
    }
    // SAFETY: per this function's contract.
    let priority = unsafe { param.read_unaligned() } as u32;
    let mut state = lock_state();
    let Some(tid) = find(&state, pid) else {
        return errno(ESRCH);
    };
    let (policy, flags) = if policy != SETPARAM_POLICY && policy & RESET_ON_FORK != 0 {
        (policy & !RESET_ON_FORK, SCHED_FLAG_RESET_ON_FORK)
    } else {
        (policy, 0)
    };
    let request = Request {
        policy,
        flags,
        nice: state.sched.get(tid).nice,
        priority,
        ..Request::default()
    };
    setscheduler(&mut state, tid, request)
}

/// `sched_get_priority_max`/`_min`: the realtime policies' 1..99, 0 for the
/// others, `EINVAL` for an unknown policy.
pub(crate) fn priority_bound(policy: i32, max: bool) -> i64 {
    match policy as u32 {
        SCHED_FIFO | SCHED_RR if policy >= 0 => {
            if max {
                i64::from(MAX_RT_PRIO - 1)
            } else {
                1
            }
        }
        SCHED_OTHER | SCHED_BATCH | SCHED_IDLE | SCHED_DEADLINE if policy >= 0 => 0,
        _ => errno(EINVAL),
    }
}

/// `sched_rr_get_interval`: a round-robin thread's slice, 0 for FIFO and
/// deadline, and a fair thread's base slice in whole ticks (on one CPU
/// under a tick, so 0).
///
/// # Safety
/// `out` must be NULL or writable for a `struct timespec`.
pub(crate) unsafe fn rr_interval(pid: i32, out: *mut crate::clocks::Timespec) -> i64 {
    if pid < 0 {
        return errno(EINVAL);
    }
    let policy = {
        let state = lock_state();
        let Some(tid) = find(&state, pid) else {
            return errno(ESRCH);
        };
        state.sched.get(tid).policy
    };
    let slice = match policy {
        SCHED_RR => RR_TIMESLICE_NS,
        SCHED_FIFO | SCHED_DEADLINE => 0,
        _ => BASE_SLICE_NS,
    };
    let ticks = slice / crate::clocks::TICK_NSEC;
    if out.is_null() {
        return errno(EFAULT);
    }
    // SAFETY: per this function's contract.
    unsafe {
        out.write_unaligned(crate::clocks::Timespec::from_nanos(
            ticks * crate::clocks::TICK_NSEC,
        ))
    };
    0
}

/// `struct sched_attr`, the kernel's size.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct SchedAttr {
    size: u32,
    policy: u32,
    flags: u64,
    nice: i32,
    priority: u32,
    runtime: u64,
    deadline: u64,
    period: u64,
    util_min: u32,
    util_max: u32,
}

/// `sched_getattr(pid, attr, size, flags)`: the policy, flags, nice or
/// priority and clamps, `min(size, 56)` bytes written and that size in
/// `attr.size`; a size under the first version or above a page, a flag, a
/// NULL attr or a negative pid is `EINVAL`.
///
/// # Safety
/// `attr` must be NULL or writable for `size` bytes.
pub(crate) unsafe fn getattr(pid: i32, attr: *mut u8, size: u32, flags: u32) -> i64 {
    if attr.is_null() || pid < 0 || !(ATTR_SIZE_VER0..=PAGE_SIZE).contains(&size) || flags != 0 {
        return errno(EINVAL);
    }
    let attrs = {
        let state = lock_state();
        let Some(tid) = find(&state, pid) else {
            return errno(ESRCH);
        };
        state.sched.get(tid)
    };
    let written = size.min(ATTR_SIZE);
    let value = SchedAttr {
        size: written,
        policy: attrs.policy,
        flags: if attrs.reset_on_fork {
            SCHED_FLAG_RESET_ON_FORK
        } else {
            0
        },
        nice: if rt_policy(attrs.policy) {
            0
        } else {
            attrs.nice
        },
        priority: if rt_policy(attrs.policy) {
            attrs.rt_priority
        } else {
            0
        },
        util_min: attrs.util_min,
        util_max: attrs.util_max,
        ..SchedAttr::default()
    };
    // SAFETY: `value` is `ATTR_SIZE` bytes and `attr` holds `written` of them.
    unsafe {
        std::ptr::copy_nonoverlapping((&raw const value).cast::<u8>(), attr, written as usize)
    };
    0
}

/// `sched_setattr(pid, attr, flags)`: `sched_copy_attr`'s size negotiation
/// (0 is the first version; a size under it, above a page, or a larger
/// struct with a nonzero byte past the kernel's is `E2BIG` with the kernel's
/// size written back), then `__sched_setscheduler`.
///
/// # Safety
/// `attr` must be NULL or readable and writable for its `size` bytes.
pub(crate) unsafe fn setattr(pid: i32, attr: *mut u8, flags: u32) -> i64 {
    if attr.is_null() || pid < 0 || flags != 0 {
        return errno(EINVAL);
    }
    // SAFETY: per this function's contract (the first field is the size).
    let mut size = unsafe { attr.cast::<u32>().read_unaligned() };
    if size == 0 {
        size = ATTR_SIZE_VER0;
    }
    // SAFETY: as above, for every byte past the kernel's struct.
    let tail_zero = || (ATTR_SIZE..size).all(|index| unsafe { *attr.add(index as usize) } == 0);
    if !(ATTR_SIZE_VER0..=PAGE_SIZE).contains(&size) || !tail_zero() {
        // SAFETY: as above.
        unsafe { attr.cast::<u32>().write_unaligned(ATTR_SIZE) };
        return errno(E2BIG);
    }
    let mut value = SchedAttr::default();
    // SAFETY: as above; the first `min(size, 56)` bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(
            attr,
            (&raw mut value).cast::<u8>(),
            size.min(ATTR_SIZE) as usize,
        )
    };
    if value.flags & SCHED_FLAG_UTIL_CLAMP != 0 && size < ATTR_SIZE {
        return errno(EINVAL);
    }
    if (value.policy as i32) < 0 {
        return errno(EINVAL);
    }
    let mut state = lock_state();
    let Some(tid) = find(&state, pid) else {
        return errno(ESRCH);
    };
    let mut request = Request {
        policy: if value.flags & SCHED_FLAG_KEEP_POLICY != 0 {
            SETPARAM_POLICY
        } else {
            value.policy as i32
        },
        flags: value.flags,
        nice: value.nice.clamp(MIN_NICE, MAX_NICE),
        priority: value.priority,
        runtime: value.runtime,
        deadline: value.deadline,
        period: value.period,
        util_min: value.util_min,
        util_max: value.util_max,
    };
    if value.flags & SCHED_FLAG_KEEP_PARAMS != 0 {
        let current = state.sched.get(tid);
        if rt_policy(current.policy) {
            request.priority = current.rt_priority;
        } else {
            request.nice = current.nice;
        }
    }
    setscheduler(&mut state, tid, request)
}

/// The I/O priority a thread reads: one it never set (or set to
/// `IOPRIO_CLASS_NONE`) follows its CPU scheduling (`__get_task_ioprio`).
fn effective_ioprio(attrs: Attrs) -> i32 {
    if attrs.ioprio >> IOPRIO_CLASS_SHIFT != IOPRIO_CLASS_NONE {
        return attrs.ioprio;
    }
    let class = match attrs.policy {
        SCHED_IDLE => IOPRIO_CLASS_IDLE,
        policy if rt_policy(policy) => IOPRIO_CLASS_RT,
        _ => IOPRIO_CLASS_BE,
    };
    (class << IOPRIO_CLASS_SHIFT) | ((attrs.nice + 20) / 5)
}

/// `ioprio_set(which, who, ioprio)`: the realtime class needs
/// `CAP_SYS_NICE` (`EPERM`), an unknown class or a level past 7 is `EINVAL`
/// (checked first), then an unknown `which` is `EINVAL` and nobody named
/// `ESRCH`.
pub(crate) fn ioprio_set(which: i32, who: i32, ioprio: i32) -> i64 {
    let class = (ioprio >> IOPRIO_CLASS_SHIFT) & 7;
    let level = ioprio & 7;
    let checked = match class {
        IOPRIO_CLASS_RT => Err(EPERM),
        IOPRIO_CLASS_BE if level >= IOPRIO_LEVELS => Err(EINVAL),
        IOPRIO_CLASS_BE | IOPRIO_CLASS_IDLE => Ok(()),
        IOPRIO_CLASS_NONE if level != 0 => Err(EINVAL),
        IOPRIO_CLASS_NONE => Ok(()),
        _ => Err(EINVAL),
    };
    if let Err(code) = checked {
        return errno(code);
    }
    let mut state = lock_state();
    let Some(targets) = targets(
        &state,
        which,
        who,
        IOPRIO_WHO_PROCESS,
        IOPRIO_WHO_PGRP,
        IOPRIO_WHO_USER,
    ) else {
        return errno(EINVAL);
    };
    if targets.is_empty() {
        return errno(ESRCH);
    }
    for tid in targets {
        let mut attrs = state.sched.get(tid);
        attrs.ioprio = ioprio;
        state.sched.set(tid, attrs);
    }
    0
}

/// `ioprio_get(which, who)`: the best (lowest) of the named threads'.
pub(crate) fn ioprio_get(which: i32, who: i32) -> i64 {
    let state = lock_state();
    let Some(targets) = targets(
        &state,
        which,
        who,
        IOPRIO_WHO_PROCESS,
        IOPRIO_WHO_PGRP,
        IOPRIO_WHO_USER,
    ) else {
        return errno(EINVAL);
    };
    targets
        .iter()
        .map(|tid| i64::from(effective_ioprio(state.sched.get(*tid))))
        .min()
        .unwrap_or(errno(ESRCH))
}

/// `personality(persona)`: the caller's previous persona; the query
/// `0xffffffff` changes nothing.
pub(crate) fn personality(persona: u32) -> i64 {
    let mut state = lock_state();
    let tid = current_tid();
    let mut attrs = state.sched.get(tid);
    let previous = attrs.persona;
    if persona != PERSONA_QUERY {
        attrs.persona = persona;
        state.sched.set(tid, attrs);
    }
    i64::from(previous)
}

/// The caller's persona (what `uname` answers under).
pub(crate) fn persona() -> u32 {
    lock_state().sched.get(current_tid()).persona
}

/// The CPU mask's size: `cpumask_size()` of one CPU.
const CPUMASK_BYTES: usize = std::mem::size_of::<u64>();

/// `sched_getaffinity(pid, len, mask)`: the one CPU, `min(len, 8)` bytes
/// written and answered; a buffer shorter than the kernel's CPU count or not
/// a whole number of longs is `EINVAL`, a pid no thread has `ESRCH`.
///
/// # Safety
/// `mask` must be NULL or writable for `len` bytes.
pub(crate) unsafe fn getaffinity(pid: i32, len: u32, mask: *mut u8) -> i64 {
    if (len as usize) * 8 < 1 || len as usize % CPUMASK_BYTES != 0 {
        return errno(EINVAL);
    }
    if find(&lock_state(), pid).is_none() {
        return errno(ESRCH);
    }
    let written = (len as usize).min(CPUMASK_BYTES);
    if mask.is_null() {
        return errno(EFAULT);
    }
    let bits = 1u64.to_ne_bytes();
    // SAFETY: per this function's contract.
    unsafe { std::ptr::copy_nonoverlapping(bits.as_ptr(), mask, written) };
    written as i64
}

/// `sched_setaffinity(pid, len, mask)`: the mask is read first (a short one
/// padded with zeros), then the pid (`ESRCH`); a mask naming no CPU the
/// machine has is `EINVAL`. The affinity of every thread is the one CPU, so
/// an accepted mask changes nothing.
///
/// # Safety
/// `mask` must be NULL or readable for `len` bytes.
pub(crate) unsafe fn setaffinity(pid: i32, len: u32, mask: *const u8) -> i64 {
    let read = (len as usize).min(CPUMASK_BYTES);
    if read > 0 && mask.is_null() {
        return errno(EFAULT);
    }
    let mut bytes = [0u8; CPUMASK_BYTES];
    // SAFETY: per this function's contract.
    unsafe { std::ptr::copy_nonoverlapping(mask, bytes.as_mut_ptr(), read) };
    if find(&lock_state(), pid).is_none() {
        return errno(ESRCH);
    }
    if u64::from_ne_bytes(bytes) & 1 == 0 {
        return errno(EINVAL);
    }
    0
}

/// `getcpu(cpu, node, cache)`: CPU 0 on node 0.
///
/// # Safety
/// `cpu` and `node` must be NULL or writable for a `u32`.
pub(crate) unsafe fn getcpu(cpu: *mut u32, node: *mut u32) -> i64 {
    for out in [cpu, node] {
        if !out.is_null() {
            // SAFETY: per this function's contract.
            unsafe { out.write_unaligned(0) };
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reset_on_fork_child_drops_a_raised_priority() {
        let mut runtime = SchedRuntime::default();
        let parent = TaskId(1);
        runtime.set(
            tid_of(parent),
            Attrs {
                nice: -5,
                reset_on_fork: true,
                ..Attrs::default()
            },
        );
        runtime.spawn(TaskId(2), parent);
        assert_eq!(runtime.get(tid_of(TaskId(2))), Attrs::default());
        runtime.set(
            tid_of(parent),
            Attrs {
                nice: 7,
                ioprio: IOPRIO_CLASS_IDLE << IOPRIO_CLASS_SHIFT,
                ..Attrs::default()
            },
        );
        runtime.spawn(TaskId(3), parent);
        assert_eq!(runtime.get(tid_of(TaskId(3))), runtime.get(tid_of(parent)));
    }

    #[test]
    fn priority_bounds_are_the_kernels() {
        assert_eq!(priority_bound(SCHED_FIFO as i32, true), 99);
        assert_eq!(priority_bound(SCHED_RR as i32, false), 1);
        assert_eq!(priority_bound(SCHED_IDLE as i32, true), 0);
        assert_eq!(priority_bound(4, true), errno(EINVAL));
        assert_eq!(priority_bound(-1, false), errno(EINVAL));
    }

    #[test]
    fn a_thread_that_never_set_an_io_priority_follows_its_nice() {
        assert_eq!(
            effective_ioprio(Attrs::default()),
            (IOPRIO_CLASS_BE << IOPRIO_CLASS_SHIFT) | 4
        );
        let idle = Attrs {
            policy: SCHED_IDLE,
            ..Attrs::default()
        };
        assert_eq!(
            effective_ioprio(idle) >> IOPRIO_CLASS_SHIFT,
            IOPRIO_CLASS_IDLE
        );
    }

    #[test]
    fn deadline_parameters_are_checked_as_the_kernel_checks_them() {
        let valid = Request {
            runtime: 1_000_000,
            deadline: 2_000_000,
            period: 4_000_000,
            ..Request::default()
        };
        assert!(deadline_params_valid(&valid));
        assert!(!deadline_params_valid(&Request {
            runtime: 3_000_000,
            ..valid
        }));
        assert!(!deadline_params_valid(&Request {
            deadline: 0,
            ..valid
        }));
        assert!(!deadline_params_valid(&Request {
            period: 1 << 63,
            ..valid
        }));
    }
}
