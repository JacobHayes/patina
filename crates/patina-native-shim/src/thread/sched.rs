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
//! table; another user's process, init, root's, is not the caller's to
//! change: [`same_owner`]). The virtual machine's CPUs, each thread's
//! affinity and the CPU it runs on are [`affinity`]'s.
#![deny(clippy::undocumented_unsafe_blocks)]

use super::*;
use crate::abi::{Errno, SysResult};
use crate::identity::Process;
use crate::limits::{RLIMIT_NICE, RLIMIT_RTPRIO};
use crate::registry::INIT_PID;
use crate::{E2BIG, EACCES, EFAULT, ERANGE};
use std::ffi::CStr;

mod affinity;

use affinity::{CpuMask, CpuSlot};
pub(in crate::thread) use affinity::{bind_cpu_slot, cpu_of_task, unbind_cpu_slot};
pub(crate) use affinity::{current_cpu, getaffinity, getcpu, setaffinity};

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
/// The process, group and user selectors of `getpriority`/`setpriority`.
const PRIO_WHICH: [i32; 3] = [PRIO_PROCESS, PRIO_PGRP, PRIO_USER];

const IOPRIO_WHO_PROCESS: i32 = 1;
const IOPRIO_WHO_PGRP: i32 = 2;
const IOPRIO_WHO_USER: i32 = 3;
/// The process, group and user selectors of `ioprio_set`/`ioprio_get`.
const IOPRIO_WHICH: [i32; 3] = [IOPRIO_WHO_PROCESS, IOPRIO_WHO_PGRP, IOPRIO_WHO_USER];
const IOPRIO_CLASS_NONE: i32 = 0;
const IOPRIO_CLASS_RT: i32 = 1;
const IOPRIO_CLASS_BE: i32 = 2;
const IOPRIO_CLASS_IDLE: i32 = 3;
const IOPRIO_CLASS_SHIFT: i32 = 13;
/// `IOPRIO_DEFAULT`: `IOPRIO_CLASS_NONE` at level 0.
const IOPRIO_DEFAULT: i32 = 0;
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
    /// Whether it has an I/O context (`task->io_context`), which it gets from
    /// its first I/O priority (see [`SchedRuntime::set_ioprio`],
    /// [`SchedRuntime::spawn`]).
    io_context: bool,
    /// Its memory policy (`task->mempolicy`), which a new thread inherits.
    mempolicy: crate::numa::Policy,
    persona: u32,
    /// The thread's name (`comm`), NUL-padded.
    comm: [u8; COMM_LEN],
    /// The CPUs it may run on (`cpus_mask`), `None` for every CPU.
    affinity: Option<CpuMask>,
}

/// `TASK_COMM_LEN`: a thread name's bytes, its NUL included.
const COMM_LEN: usize = 16;

/// The name the main thread starts with, and so (by inheritance) every
/// thread that never set one: the basename of `argv[0]`, truncated to 15
/// bytes. The kernel takes it from the file `execve` ran, whose path is the
/// host's; the supervisor fixes `argv[0]` (`patina-guest`), so the name is
/// the same on every machine and in every replay, and a native run executed
/// through a link of that name gets the same one from the kernel.
static PROGRAM_COMM: OnceLock<[u8; COMM_LEN]> = OnceLock::new();

/// A NUL-padded name from `bytes`, truncated to `COMM_LEN - 1`.
fn comm_of(bytes: &[u8]) -> [u8; COMM_LEN] {
    let mut comm = [0; COMM_LEN];
    let len = bytes.len().min(COMM_LEN - 1);
    comm[..len].copy_from_slice(&bytes[..len]);
    comm
}

#[unsafe(no_mangle)]
/// Record `argv[0]` at startup.
///
/// # Safety
/// Non-null `argv0` must be a NUL-terminated string.
pub unsafe extern "C" fn patina_note_program_name(argv0: *const c_char) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if argv0.is_null() {
        return;
    }
    // SAFETY: a NUL-terminated string, per this function's contract.
    let path = unsafe { CStr::from_ptr(argv0) }.to_bytes();
    let base = path.rsplit(|byte| *byte == b'/').next().unwrap_or(path);
    let _ = PROGRAM_COMM.set(comm_of(base));
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
            io_context: false,
            mempolicy: crate::numa::Policy::DEFAULT,
            persona: 0,
            comm: PROGRAM_COMM.get().copied().unwrap_or([0; COMM_LEN]),
            affinity: None,
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
    /// Each managed thread's [`CpuSlot`], and the slots of finished ones.
    slots: BTreeMap<i32, &'static CpuSlot>,
    free_slots: Vec<&'static CpuSlot>,
    /// The highest thread id a spawn has handed out (0 before the first).
    last_tid: i32,
}

impl SchedRuntime {
    fn get(&self, tid: i32) -> Attrs {
        self.tasks.get(&tid).copied().unwrap_or_default()
    }

    fn set(&mut self, tid: i32, attrs: Attrs) {
        self.tasks.insert(tid, attrs);
    }

    /// `set_task_ioprio`: the thread's I/O context takes the priority, the
    /// thread getting one first if it has none. The context keeps 16 bits
    /// (`io_context.ioprio` is an `unsigned short`).
    fn set_ioprio(&mut self, tid: i32, ioprio: i32) {
        let mut attrs = self.get(tid);
        attrs.ioprio = i32::from(ioprio as u16);
        attrs.io_context = true;
        self.set(tid, attrs);
    }

    /// `sched_fork`/`copy_io`: a new thread inherits its creator's
    /// attributes; under `SCHED_RESET_ON_FORK` a realtime or deadline policy
    /// falls back to `SCHED_OTHER` at nice 0, a negative nice resets to 0,
    /// and the flag clears. It shares no I/O context (glibc passes no
    /// `CLONE_IO`): it gets one of its own when its creator's holds a valid
    /// priority (`ioprio_valid`: a class other than `IOPRIO_CLASS_NONE`),
    /// and none otherwise.
    pub(super) fn spawn(&mut self, child: TaskId, parent: TaskId) {
        let mut attrs = self.get(tid_of(parent));
        let valid = attrs.ioprio >> IOPRIO_CLASS_SHIFT != IOPRIO_CLASS_NONE;
        attrs.io_context &= valid;
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
        let tid = tid_of(child);
        self.last_tid = self.last_tid.max(tid);
        let slot = self
            .free_slots
            .pop()
            .unwrap_or_else(|| Box::leak(Box::new(CpuSlot::new())));
        self.slots.insert(tid, slot);
        self.mirror(tid, attrs.affinity);
        self.set(tid, attrs);
    }

    /// Task `task` exited. The thread-group leader's attributes stay: its
    /// task is a zombie until the last thread exits, and what it set (its
    /// name, its nice value) still answers for it.
    pub(super) fn finish(&mut self, task: TaskId) {
        let tid = tid_of(task);
        if tid != crate::patina_pid() {
            self.tasks.remove(&tid);
        }
        if let Some(slot) = self.slots.remove(&tid) {
            self.free_slots.push(slot);
        }
    }
}

/// What procfs reports of a thread's scheduling (`/proc/<pid>/stat`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Scheduling {
    /// Its name (`comm`), NUL-padded.
    pub(crate) comm: [u8; COMM_LEN],
    pub(crate) nice: i32,
    /// `task_prio`: `20 + nice` under a fair or idle policy, `-1 -
    /// rt_priority` under a realtime one, -101 under `SCHED_DEADLINE`.
    pub(crate) prio: i32,
    pub(crate) policy: u32,
    pub(crate) rt_priority: u32,
}

/// Thread `tid`'s [`Scheduling`].
pub(crate) fn scheduling(tid: i32) -> Scheduling {
    let attrs = lock_state().sched.get(tid);
    let prio = match attrs.policy {
        SCHED_DEADLINE => -101,
        policy if rt_policy(policy) => -1 - attrs.rt_priority as i32,
        _ => 20 + attrs.nice,
    };
    Scheduling {
        comm: attrs.comm,
        nice: attrs.nice,
        prio,
        policy: attrs.policy,
        rt_priority: attrs.rt_priority,
    }
}

impl SchedRuntime {
    /// The highest thread id handed out so far (0 before the first spawn).
    pub(super) fn last_tid(&self) -> i32 {
        self.last_tid
    }

    /// Thread `tid`'s nice value.
    pub(super) fn nice(&self, tid: i32) -> i32 {
        self.get(tid).nice
    }
}

/// The calling thread's name (`PR_GET_NAME`).
pub(crate) fn current_name() -> [u8; COMM_LEN] {
    lock_state().sched.get(current_tid()).comm
}

/// Name the calling thread (`PR_SET_NAME`), truncating to 15 bytes.
pub(crate) fn set_current_name(name: &[u8]) {
    let mut state = lock_state();
    let tid = current_tid();
    let mut attrs = state.sched.get(tid);
    attrs.comm = comm_of(name);
    state.sched.set(tid, attrs);
}

/// The thread a `pthread_t` names: the caller's own, or a managed thread's.
fn handle_tid(state: &ThreadRuntime, handle: usize) -> Option<i32> {
    // SAFETY: the real glibc `pthread_self`, resolved through the host-alias
    // table.
    if handle == unsafe { (crate::hostapi::get().host_pthread_self)() } {
        return Some(current_tid());
    }
    state.handles.get(&handle).map(|task| tid_of(*task))
}

#[unsafe(no_mangle)]
/// glibc's `pthread_getname_np`: the thread's name, into a buffer of at
/// least `TASK_COMM_LEN` bytes (`ERANGE` otherwise).
///
/// # Safety
/// `name` must be writable for `len` bytes.
pub unsafe extern "C" fn patina_thread_getname(
    handle: usize,
    name: *mut c_char,
    len: usize,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if len < COMM_LEN {
        return ERANGE;
    }
    let state = lock_state();
    let Some(tid) = handle_tid(&state, handle) else {
        return ESRCH;
    };
    let comm = state.sched.get(tid).comm;
    // SAFETY: `name` holds at least `COMM_LEN` bytes, checked above.
    unsafe { std::ptr::copy_nonoverlapping(comm.as_ptr(), name.cast::<u8>(), COMM_LEN) };
    0
}

#[unsafe(no_mangle)]
/// glibc's `pthread_setname_np`: name the thread; a name longer than 15
/// bytes is `ERANGE`.
///
/// # Safety
/// `name` must be a NUL-terminated string.
pub unsafe extern "C" fn patina_thread_setname(handle: usize, name: *const c_char) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: a NUL-terminated string, per this function's contract.
    let name = unsafe { CStr::from_ptr(name) }.to_bytes();
    if name.len() >= COMM_LEN {
        return ERANGE;
    }
    let mut state = lock_state();
    let Some(tid) = handle_tid(&state, handle) else {
        return ESRCH;
    };
    let mut attrs = state.sched.get(tid);
    attrs.comm = comm_of(name);
    state.sched.set(tid, attrs);
    0
}

/// The guest's live threads, main first.
fn threads(state: &ThreadRuntime) -> Vec<i32> {
    if state.signals.is_empty() {
        return vec![crate::patina_pid()];
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

/// The process a thread [`find`] found belongs to.
fn process_of(tid: i32) -> Process {
    if tid == INIT {
        Process::INIT
    } else {
        Process::current()
    }
}

/// Whether the thread's process is the caller's user's, by its credential:
/// the owner rules of `check_same_owner` (the sched rows),
/// `set_one_prio_perm` (`setpriority`) and `set_task_ioprio` (`ioprio_set`)
/// compare the caller's uid with the target's real or effective one, which
/// agree when each credential holds one uid. The caller has no
/// `CAP_SYS_NICE` to pass them otherwise, so init, root's, is `EPERM`.
fn same_owner(tid: i32) -> bool {
    process_of(tid).credential().uid == crate::identity::credential().uid
}

/// What a `who` of 0 names to a row's user selector.
#[derive(Clone, Copy)]
enum UserZero {
    /// The caller's uid: `getpriority`/`setpriority` (`kernel/sys.c`: `uid =
    /// cred->uid`) and `ioprio_get` (it compares with `user->uid`).
    Caller,
    /// uid 0 itself: `ioprio_set` makes the uid from `who` before it takes
    /// `current_user()` for 0, and matches tasks against that uid.
    Root,
}

/// The threads a `which`/`who` pair of `getpriority`/`setpriority`/
/// `ioprio_*` names, in the kernel's order: `None` for an unknown `which`,
/// an empty list for a `who` naming no process. A group holds the guest's
/// threads when it is the guest's, then init's thread when it is group 1
/// (the kernel walks a group's most recent member first); a user holds the
/// processes whose credential is that uid's (for 0, the row's
/// [`UserZero`]), in the order they started.
fn targets(
    state: &ThreadRuntime,
    which: i32,
    who: i32,
    [process, group, user]: [i32; 3],
    user_zero: UserZero,
) -> Option<Vec<i32>> {
    Some(if which == process {
        find(state, who).into_iter().collect()
    } else if which == group {
        let own = crate::identity::pgid();
        let group = if who == 0 { own } else { who };
        let mut members = Vec::new();
        if group == own {
            members.extend(threads(state));
        }
        if group == INIT {
            members.push(INIT);
        }
        members
    } else if which == user {
        let uid = match (who, user_zero) {
            (0, UserZero::Caller) => crate::identity::credential().uid,
            _ => who as u32,
        };
        let mut members = Vec::new();
        if Process::INIT.credential().uid == uid {
            members.push(INIT);
        }
        if Process::current().credential().uid == uid {
            members.extend(threads(state));
        }
        members
    } else {
        return None;
    })
}

/// `getpriority(which, who)`: `20 - nice` of the highest-priority thread
/// named (the raw row's encoding; glibc converts it back).
pub(crate) fn getpriority(which: i32, who: i32) -> SysResult<i64> {
    let state = lock_state();
    let Some(targets) = targets(&state, which, who, PRIO_WHICH, UserZero::Caller) else {
        return Err(Errno::new(EINVAL));
    };
    targets
        .iter()
        .map(|tid| i64::from(20 - state.sched.get(*tid).nice))
        .max()
        .ok_or_else(|| Errno::new(ESRCH))
}

/// `setpriority(which, who, nice)`: the nice value clamped to `-20..=19`,
/// set on every named thread the caller may change; another user's is
/// `EPERM` ([`same_owner`]), and raising a thread's priority past what
/// `RLIMIT_NICE` allows `EACCES`. The last refusal is the answer.
pub(crate) fn setpriority(which: i32, who: i32, nice: i32) -> SysResult<i64> {
    let mut state = lock_state();
    let Some(targets) = targets(&state, which, who, PRIO_WHICH, UserZero::Caller) else {
        return Err(Errno::new(EINVAL));
    };
    let nice = nice.clamp(MIN_NICE, MAX_NICE);
    let mut result = Err(Errno::new(ESRCH));
    for tid in targets {
        let mut attrs = state.sched.get(tid);
        if !same_owner(tid) {
            result = Err(Errno::new(EPERM));
            continue;
        }
        if nice < attrs.nice && !nice_allowed(nice) {
            result = Err(Errno::new(EACCES));
            continue;
        }
        if result == Err(Errno::new(ESRCH)) {
            result = Ok(0);
        }
        attrs.nice = nice;
        state.sched.set(tid, attrs);
    }
    result
}

/// `sched_getscheduler`: the policy, with `SCHED_RESET_ON_FORK` or'd in.
pub(crate) fn getscheduler(pid: i32) -> SysResult<i64> {
    if pid < 0 {
        return Err(Errno::new(EINVAL));
    }
    let state = lock_state();
    let Some(tid) = find(&state, pid) else {
        return Err(Errno::new(ESRCH));
    };
    let attrs = state.sched.get(tid);
    Ok(i64::from(attrs.policy)
        | if attrs.reset_on_fork {
            i64::from(RESET_ON_FORK)
        } else {
            0
        })
}

/// `sched_getparam`: the realtime priority (0 under a normal policy).
///
/// # Safety
/// `param` must be NULL or writable for an `int`.
pub(crate) unsafe fn getparam(pid: i32, param: *mut i32) -> SysResult<i64> {
    if param.is_null() || pid < 0 {
        return Err(Errno::new(EINVAL));
    }
    let state = lock_state();
    let Some(tid) = find(&state, pid) else {
        return Err(Errno::new(ESRCH));
    };
    let attrs = state.sched.get(tid);
    let priority = if rt_policy(attrs.policy) {
        attrs.rt_priority
    } else {
        0
    };
    // SAFETY: per this function's contract.
    unsafe { param.write_unaligned(priority as i32) };
    Ok(0)
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

/// `__sched_setscheduler` for an unprivileged caller: past the argument
/// checks (`EINVAL`), `user_check_sched_setscheduler`'s `EPERM`s, another
/// user's thread ([`same_owner`]) among them.
fn setscheduler(state: &mut ThreadRuntime, tid: i32, request: Request) -> SysResult<i64> {
    let current = state.sched.get(tid);
    let (policy, reset_on_fork) = if request.policy < 0 {
        (current.policy, current.reset_on_fork)
    } else {
        let policy = request.policy as u32;
        if !valid_policy(policy) {
            return Err(Errno::new(EINVAL));
        }
        (policy, request.flags & SCHED_FLAG_RESET_ON_FORK != 0)
    };
    if request.flags & !(SCHED_FLAG_ALL | SCHED_FLAG_SUGOV) != 0 {
        return Err(Errno::new(EINVAL));
    }
    if request.priority > MAX_RT_PRIO - 1 {
        return Err(Errno::new(EINVAL));
    }
    if (policy == SCHED_DEADLINE && !deadline_params_valid(&request))
        || rt_policy(policy) != (request.priority != 0)
    {
        return Err(Errno::new(EINVAL));
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
        || !same_owner(tid)
        || (current.reset_on_fork && !reset_on_fork);
    if privileged {
        return Err(Errno::new(EPERM));
    }
    if request.flags & SCHED_FLAG_SUGOV != 0 {
        return Err(Errno::new(EINVAL));
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
            return Err(Errno::new(EINVAL));
        };
        let (min, max) = (
            min.unwrap_or(current.util_min),
            max.unwrap_or(current.util_max),
        );
        if min > max {
            return Err(Errno::new(EINVAL));
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
    Ok(0)
}

/// `sched_setscheduler` (a policy, or'd with `SCHED_RESET_ON_FORK`) and
/// `sched_setparam` (`None`: the policy kept): the realtime priority, the
/// nice value kept.
///
/// # Safety
/// `param` must be NULL or readable for an `int`.
pub(crate) unsafe fn setscheduler_param(
    pid: i32,
    policy: Option<i32>,
    param: *const i32,
) -> SysResult<i64> {
    let policy = match policy {
        Some(policy) if policy < 0 => return Err(Errno::new(EINVAL)),
        Some(policy) => policy,
        None => SETPARAM_POLICY,
    };
    if param.is_null() || pid < 0 {
        return Err(Errno::new(EINVAL));
    }
    // SAFETY: per this function's contract.
    let priority = unsafe { param.read_unaligned() } as u32;
    let mut state = lock_state();
    let Some(tid) = find(&state, pid) else {
        return Err(Errno::new(ESRCH));
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
pub(crate) fn priority_bound(policy: i32, max: bool) -> SysResult<i64> {
    match policy as u32 {
        SCHED_FIFO | SCHED_RR if policy >= 0 => {
            if max {
                Ok(i64::from(MAX_RT_PRIO - 1))
            } else {
                Ok(1)
            }
        }
        SCHED_OTHER | SCHED_BATCH | SCHED_IDLE | SCHED_DEADLINE if policy >= 0 => Ok(0),
        _ => Err(Errno::new(EINVAL)),
    }
}

/// `sched_rr_get_interval`: a round-robin thread's slice, 0 for FIFO and
/// deadline, and a fair thread's base slice in whole ticks (on one CPU
/// under a tick, so 0). The pid is judged, then the slice copied out
/// (`EFAULT`).
pub(crate) fn rr_interval(pid: i32, out: *mut crate::clocks::Timespec) -> SysResult<i64> {
    if pid < 0 {
        return Err(Errno::new(EINVAL));
    }
    let policy = {
        let state = lock_state();
        let Some(tid) = find(&state, pid) else {
            return Err(Errno::new(ESRCH));
        };
        state.sched.get(tid).policy
    };
    let slice = match policy {
        SCHED_RR => RR_TIMESLICE_NS,
        SCHED_FIFO | SCHED_DEADLINE => 0,
        _ => BASE_SLICE_NS,
    };
    let ticks = slice / crate::clocks::TICK_NSEC;
    let slice = crate::clocks::Timespec::from_nanos(ticks * crate::clocks::TICK_NSEC);
    match crate::uaccess::write(out as usize, &slice) {
        Ok(()) => Ok(0),
        Err(_) => Err(Errno::new(EFAULT)),
    }
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

mod plain_impls {
    #![deny(clippy::undocumented_unsafe_blocks)]

    crate::plain!(super::SchedAttr {
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
    });
}

/// `sched_getattr(pid, attr, size, flags)`: the policy, flags, nice or
/// priority and clamps, `min(size, 56)` bytes written and that size in
/// `attr.size`; a size under the first version or above a page, a flag, a
/// NULL attr or a negative pid is `EINVAL`.
///
/// # Safety
/// `attr` must be NULL or writable for `size` bytes.
pub(crate) unsafe fn getattr(pid: i32, attr: *mut u8, size: u32, flags: u32) -> SysResult<i64> {
    if attr.is_null() || pid < 0 || !(ATTR_SIZE_VER0..=PAGE_SIZE).contains(&size) || flags != 0 {
        return Err(Errno::new(EINVAL));
    }
    let attrs = {
        let state = lock_state();
        let Some(tid) = find(&state, pid) else {
            return Err(Errno::new(ESRCH));
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
    Ok(0)
}

/// `sched_setattr(pid, attr, flags)`: `sched_copy_attr`'s size negotiation
/// (0 is the first version; a size under it, above a page, or a larger
/// struct with a nonzero byte past the kernel's is `E2BIG` with the kernel's
/// size written back), then `__sched_setscheduler`.
///
/// # Safety
/// `attr` must be NULL or readable and writable for its `size` bytes.
pub(crate) unsafe fn setattr(pid: i32, attr: *mut u8, flags: u32) -> SysResult<i64> {
    if attr.is_null() || pid < 0 || flags != 0 {
        return Err(Errno::new(EINVAL));
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
        return Err(Errno::new(E2BIG));
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
        return Err(Errno::new(EINVAL));
    }
    if (value.policy as i32) < 0 {
        return Err(Errno::new(EINVAL));
    }
    let mut state = lock_state();
    let Some(tid) = find(&state, pid) else {
        return Err(Errno::new(ESRCH));
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

/// The I/O priority `ioprio_get` reads of one thread. A thread without an
/// I/O context reads `IOPRIO_DEFAULT` (`IOPRIO_CLASS_NONE`, level 0) either
/// way. `IOPRIO_WHO_PROCESS` reads the context's priority as set, class
/// `NONE` included (`get_task_raw_ioprio`, `raw`); the group and user
/// selectors read `__get_task_ioprio`, where a context whose class is `NONE`
/// follows the thread's CPU scheduling instead.
fn read_ioprio(attrs: Attrs, raw: bool) -> i32 {
    if !attrs.io_context {
        return IOPRIO_DEFAULT;
    }
    if raw || attrs.ioprio >> IOPRIO_CLASS_SHIFT != IOPRIO_CLASS_NONE {
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
/// `ESRCH`; the named threads are set in turn, stopping at the first of
/// another user's (`EPERM`, [`same_owner`]).
pub(crate) fn ioprio_set(which: i32, who: i32, ioprio: i32) -> SysResult<i64> {
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
        return Err(Errno::new(code));
    }
    let mut state = lock_state();
    let Some(targets) = targets(&state, which, who, IOPRIO_WHICH, UserZero::Root) else {
        return Err(Errno::new(EINVAL));
    };
    if targets.is_empty() {
        return Err(Errno::new(ESRCH));
    }
    for tid in targets {
        if !same_owner(tid) {
            return Err(Errno::new(EPERM));
        }
        state.sched.set_ioprio(tid, ioprio);
    }
    Ok(0)
}

/// `ioprio_get(which, who)`: the best (lowest) of the named threads'.
pub(crate) fn ioprio_get(which: i32, who: i32) -> SysResult<i64> {
    let state = lock_state();
    let Some(targets) = targets(&state, which, who, IOPRIO_WHICH, UserZero::Caller) else {
        return Err(Errno::new(EINVAL));
    };
    targets
        .iter()
        .map(|tid| {
            i64::from(read_ioprio(
                state.sched.get(*tid),
                which == IOPRIO_WHO_PROCESS,
            ))
        })
        .min()
        .ok_or_else(|| Errno::new(ESRCH))
}

/// `personality(persona)`: the caller's previous persona; the query
/// `0xffffffff` changes nothing.
pub(crate) fn personality(persona: u32) -> SysResult<i64> {
    let mut state = lock_state();
    let tid = current_tid();
    let mut attrs = state.sched.get(tid);
    let previous = attrs.persona;
    if persona != PERSONA_QUERY {
        attrs.persona = persona;
        state.sched.set(tid, attrs);
    }
    Ok(i64::from(previous))
}

/// The caller's persona (what `uname` answers under).
pub(crate) fn persona() -> u32 {
    lock_state().sched.get(current_tid()).persona
}

/// The calling thread's memory policy (`current->mempolicy`).
pub(crate) fn current_mempolicy() -> crate::numa::Policy {
    lock_state().sched.get(current_tid()).mempolicy
}

/// Set the calling thread's memory policy.
pub(crate) fn set_current_mempolicy(policy: crate::numa::Policy) {
    let mut state = lock_state();
    let tid = current_tid();
    let mut attrs = state.sched.get(tid);
    attrs.mempolicy = policy;
    state.sched.set(tid, attrs);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_child_inherits_attributes_but_never_an_io_context() {
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

        // A thread gets an I/O context from its first I/O priority and keeps
        // it; a thread it creates has one only while that priority is valid.
        let mut runtime = SchedRuntime::default();
        let parent = TaskId(1);
        let context = |runtime: &SchedRuntime, task| runtime.get(tid_of(task)).io_context;
        runtime.spawn(TaskId(2), parent);
        assert!(!context(&runtime, TaskId(2)));
        runtime.set_ioprio(tid_of(parent), IOPRIO_CLASS_NONE << IOPRIO_CLASS_SHIFT);
        assert!(context(&runtime, parent));
        runtime.spawn(TaskId(3), parent);
        assert!(!context(&runtime, TaskId(3)));
        runtime.set_ioprio(tid_of(parent), (IOPRIO_CLASS_BE << IOPRIO_CLASS_SHIFT) | 4);
        runtime.spawn(TaskId(4), parent);
        assert!(context(&runtime, TaskId(4)));
    }

    #[test]
    fn a_child_inherits_its_creators_memory_policy() {
        let mut runtime = SchedRuntime::default();
        let parent = TaskId(1);
        let mut attrs = runtime.get(tid_of(parent));
        attrs.mempolicy = crate::numa::Policy::bound_to_node_zero();
        runtime.set(tid_of(parent), attrs);
        runtime.spawn(TaskId(2), parent);
        assert_eq!(runtime.get(tid_of(TaskId(2))).mempolicy, attrs.mempolicy);
        assert_ne!(attrs.mempolicy, crate::numa::Policy::DEFAULT);
    }

    #[test]
    fn get_mempolicy_reads_back_what_set_mempolicy_set() {
        crate::thread::signals::tests::isolated(|| {
            const MPOL_BIND: i32 = 2;
            const STATIC_NODES: i32 = 1 << 15;
            let read = |flags: u64| {
                let (mut mode, mut mask) = (-1i32, [9u64; 2]);
                // SAFETY: the outputs are writable for what the call names.
                let result = unsafe {
                    crate::numa::get_mempolicy(&mut mode, mask.as_mut_ptr(), 65, 0, flags)
                };
                (result, mode, mask[0])
            };
            assert_eq!(read(0), (0, 0, 0));
            let node0 = 1u64;
            // SAFETY: the mask is readable for the 64 bits named.
            let set = |mode: i32, mask: &u64| unsafe { crate::numa::set_mempolicy(mode, mask, 65) };
            assert_eq!(set(MPOL_BIND | STATIC_NODES, &node0), 0);
            assert_eq!(read(0), (0, MPOL_BIND | STATIC_NODES, 1));
            // A refused request leaves the policy as it was.
            assert_eq!(set(MPOL_BIND, &2), -i64::from(crate::EINVAL));
            assert_eq!(read(0), (0, MPOL_BIND | STATIC_NODES, 1));
            // An address range has no policy of its own, whatever the thread's.
            assert_eq!(read(2), (0, 0, 0));
            // The allowed nodes are the machine's, whatever the thread's policy.
            assert_eq!(read(4), (0, 0, 1));
            assert_eq!(set(0, &0), 0);
            assert_eq!(read(0), (0, 0, 0));
        });
    }

    /// Init is another user's process (root's): outside the caller's user,
    /// and refusing a change wherever it is named, after the guest's own
    /// threads in a group they share.
    #[test]
    fn init_is_another_users_process() {
        crate::thread::signals::tests::isolated(|| {
            let best_effort = |level| (IOPRIO_CLASS_BE << IOPRIO_CLASS_SHIFT) | level;
            assert_eq!(setpriority(PRIO_PROCESS, 0, 5), Ok(0));
            assert_eq!(getpriority(PRIO_USER, 0), Ok(15));
            assert_eq!(setpriority(PRIO_PROCESS, INIT, 5), Err(Errno::new(EPERM)));
            let own = ioprio_get(IOPRIO_WHO_PROCESS, 0);
            assert_eq!(
                ioprio_set(IOPRIO_WHO_USER, 0, best_effort(2)),
                Err(Errno::new(EPERM))
            );
            assert_eq!(ioprio_get(IOPRIO_WHO_PROCESS, 0), own);
            assert_eq!(crate::identity::setpgid(0, INIT), 0);
            assert_eq!(setpriority(PRIO_PGRP, 0, 6), Err(Errno::new(EPERM)));
            assert_eq!(getpriority(PRIO_PROCESS, 0), Ok(14));
            assert_eq!(
                ioprio_set(IOPRIO_WHO_PGRP, 0, best_effort(3)),
                Err(Errno::new(EPERM))
            );
            assert_eq!(
                ioprio_get(IOPRIO_WHO_PROCESS, 0),
                Ok(i64::from(best_effort(3)))
            );
        });
    }

    #[test]
    fn priority_bounds_and_deadline_parameters_are_the_kernels() {
        assert_eq!(priority_bound(SCHED_FIFO as i32, true), Ok(99));
        assert_eq!(priority_bound(SCHED_RR as i32, false), Ok(1));
        assert_eq!(priority_bound(SCHED_IDLE as i32, true), Ok(0));
        assert_eq!(priority_bound(4, true), Err(Errno::new(EINVAL)));
        assert_eq!(priority_bound(-1, false), Err(Errno::new(EINVAL)));

        // Deadline parameters are checked as the kernel checks them.
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

    #[test]
    fn an_io_priority_of_class_none_reads_raw_by_process_and_by_nice_otherwise() {
        let best_effort = |level| (IOPRIO_CLASS_BE << IOPRIO_CLASS_SHIFT) | level;
        let unset = Attrs::default();
        assert_eq!(read_ioprio(unset, true), IOPRIO_DEFAULT);
        assert_eq!(read_ioprio(unset, false), IOPRIO_DEFAULT);
        let none = Attrs {
            io_context: true,
            nice: 10,
            ..Attrs::default()
        };
        assert_eq!(read_ioprio(none, true), IOPRIO_DEFAULT);
        assert_eq!(read_ioprio(none, false), best_effort(6));
        let idle = Attrs {
            policy: SCHED_IDLE,
            ..none
        };
        assert_eq!(
            read_ioprio(idle, false) >> IOPRIO_CLASS_SHIFT,
            IOPRIO_CLASS_IDLE
        );
        let set = Attrs {
            ioprio: best_effort(2),
            ..none
        };
        assert_eq!(read_ioprio(set, true), best_effort(2));
        assert_eq!(read_ioprio(set, false), best_effort(2));
    }
}
