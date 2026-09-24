//! Linux signal state. Generation only mutates virtual queues; the baton holder
//! transfers a delivery batch to kernel-built frames after releasing the lock.
use super::*;
use crate::EINTR;
pub(crate) mod fd;
mod waits;
use patina_dst_abi::SignalTarget;
use std::sync::atomic::Ordering;
use waits::Blocked;
pub(crate) use waits::{Resumed, resume};
pub(crate) use waits::{Timespec, WaitMode, patina_signal_wait};
pub(super) use waits::{resume_with, take_sync_resume};

mod constants;
pub(super) use constants::*;

thread_local! {
    // Nested handler boundaries must refresh the virtual mask before generation.
    static RELEASING_FRAMES: Cell<bool> = const { Cell::new(false) };
    // Only mask/stack-changing entries need to rewrite a SIGSYS return frame.
    static FRAME_DIRTY: Cell<u8> = const { Cell::new(0) };
}
const FRAME_MASK: u8 = 1;
const FRAME_STACK: u8 = 2;

static RESTORER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[unsafe(no_mangle)]
pub extern "C" fn patina_signal_restorer(restorer: usize) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    RESTORER.store(restorer, Ordering::Relaxed);
}

pub(super) fn bit(sig: impl Into<i64>) -> u64 {
    1u64 << (sig.into() - 1)
}
fn uncatchable(mask: u64) -> u64 {
    mask & !bit(SIGKILL) & !bit(SIGSTOP)
}
fn ignored(sig: u8) -> bool {
    matches!(sig, SIGCHLD | SIGCONT | SIGURG | SIGWINCH)
}

#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub(crate) struct Action {
    pub handler: usize,
    pub flags: u64,
    pub restorer: usize,
    pub mask: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Stack {
    pub base: usize,
    pub flags: i32,
    pub size: usize,
}
impl Default for Stack {
    fn default() -> Self {
        Self {
            base: 0,
            flags: SS_DISABLE,
            size: 0,
        }
    }
}

// Linux's 128-byte siginfo, kept whole so queueinfo preserves every caller field.
#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Info {
    pub words: [u64; 16],
}
impl Info {
    fn new(sig: u8, code: i32) -> Self {
        let mut info = Self { words: [0; 16] };
        info.words[0] = u64::from(sig);
        info.words[1] = u64::from(code as u32);
        info.words[2] = u64::from(crate::registry::IDENTITY_PID)
            | ((crate::registry::IDENTITY_UID as u64) << 32);
        info
    }
    fn code(self) -> i32 {
        self.words[1] as i32
    }
    fn value(self) -> i64 {
        self.words[3] as i64
    }
    /// `SEND_SIG_PRIV`: a signal the kernel sends itself (`SI_KERNEL`, no
    /// sender), as the interval timers do.
    pub(crate) fn kernel(sig: u8) -> Self {
        let mut info = Self::new(sig, SI_KERNEL);
        info.words[2] = 0;
        info
    }
    /// A POSIX timer's signal (`SI_TIMER`): the timer id, an overrun of 0,
    /// its value, and the arming generation in `si_sys_private` (which the
    /// dequeue clears before the guest sees the record).
    pub(crate) fn timer(sig: u8, id: i32, value: u64, generation: u32) -> Self {
        let mut info = Self::new(sig, SI_TIMER);
        info.words[2] = u64::from(id as u32);
        info.words[3] = value;
        info.words[4] = u64::from(generation);
        info
    }
    pub(crate) fn signo(&self) -> u8 {
        self.words[0] as u8
    }
    /// The timer id of an `SI_TIMER` record.
    pub(crate) fn timer_id(&self) -> Option<i32> {
        (self.code() == SI_TIMER).then_some(self.words[2] as u32 as i32)
    }
    pub(crate) fn overrun(&self) -> i32 {
        (self.words[2] >> 32) as u32 as i32
    }
    pub(crate) fn set_overrun(&mut self, overrun: i32) {
        self.words[2] = (self.words[2] & 0xffff_ffff) | (u64::from(overrun as u32) << 32);
    }
    pub(crate) fn generation(&self) -> u32 {
        self.words[4] as u32
    }
    pub(crate) fn clear_generation(&mut self) {
        self.words[4] &= !0xffff_ffff;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Instance {
    seq: u64,
    sig: u8,
    info: Info,
}

#[derive(Default)]
struct Pending(BTreeMap<u8, VecDeque<Instance>>);
impl Pending {
    fn push(&mut self, instance: Instance) {
        let queue = self.0.entry(instance.sig).or_default();
        if instance.sig >= KERNEL_SIGRTMIN || queue.is_empty() {
            queue.push_back(instance);
        }
    }
    fn mask(&self) -> u64 {
        self.0.keys().fold(0, |mask, sig| mask | bit(*sig))
    }
    fn take(&mut self, eligible: u64) -> Option<Instance> {
        let sig = self
            .0
            .keys()
            .copied()
            .find(|sig| eligible & bit(*sig) != 0)?;
        let queue = self.0.get_mut(&sig).unwrap();
        let instance = queue.pop_front();
        if queue.is_empty() {
            self.0.remove(&sig);
        }
        instance
    }
}

#[derive(Default)]
struct TaskSignals {
    mask: u64,
    private: Pending,
    clear_child_tid: Option<usize>,
}

struct Interrupt {
    instance: Instance,
    class: BlockClass,
    sync_wait: Option<Blocked>,
}

pub(super) struct SignalRuntime {
    actions: [Action; 65],
    shared: Pending,
    tasks: BTreeMap<TaskId, TaskSignals>,
    next_seq: u64,
    pub(in crate::thread) signalfds: BTreeMap<u64, fd::SignalFd>,
    next_fd: u64,
    pub(super) blocked: BTreeMap<TaskId, Blocked>,
    interrupted: BTreeMap<TaskId, Interrupt>,
}
impl Default for SignalRuntime {
    fn default() -> Self {
        Self {
            actions: [Action::default(); 65],
            shared: Pending::default(),
            tasks: BTreeMap::new(),
            next_seq: 0,
            signalfds: BTreeMap::new(),
            next_fd: 0,
            blocked: BTreeMap::new(),
            interrupted: BTreeMap::new(),
        }
    }
}
impl SignalRuntime {
    pub(super) fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }
    pub(super) fn has_task(&self, task: TaskId) -> bool {
        self.tasks.contains_key(&task)
    }
    pub(super) fn task_count(&self) -> usize {
        self.tasks.len()
    }
    pub(super) fn task_ids(&self) -> impl Iterator<Item = TaskId> + '_ {
        self.tasks.keys().copied()
    }
    pub(super) fn mask(&self, task: TaskId) -> u64 {
        self.tasks[&task].mask
    }
    pub(super) fn spawn(&mut self, task: TaskId, parent: Option<TaskId>) {
        let mask = parent.map_or(0, |parent| self.tasks[&parent].mask);
        self.tasks.insert(
            task,
            TaskSignals {
                mask,
                ..TaskSignals::default()
            },
        );
    }
    fn pending(&self, task: TaskId) -> u64 {
        let task = &self.tasks[&task];
        (task.private.mask() | self.shared.mask()) & task.mask
    }
    fn dequeue(&mut self, task: TaskId, eligible: u64) -> Option<Instance> {
        self.tasks
            .get_mut(&task)
            .unwrap()
            .private
            .take(eligible)
            .or_else(|| self.shared.take(eligible))
    }
    fn has_deliverable(&self, task: TaskId) -> bool {
        let private = self.tasks[&task].private.mask();
        let shared = self.shared.mask();
        (1..=64).any(|sig| {
            self.handles(task, sig)
                && (private & bit(sig) != 0
                    || (shared & bit(sig) != 0
                        && self.target(sig, SignalTarget::Process) == Some(task)))
        })
    }
    fn dequeue_delivery(&mut self, task: TaskId, eligible: u64) -> Option<Instance> {
        if let Some(instance) = self.tasks.get_mut(&task).unwrap().private.take(eligible) {
            return Some(instance);
        }
        let eligible = (1..=64)
            .filter(|sig| {
                eligible & bit(*sig) != 0 && self.target(*sig, SignalTarget::Process) == Some(task)
            })
            .fold(0, |mask, sig| mask | bit(sig));
        self.shared.take(eligible)
    }
    fn action(&mut self, sig: u8, action: Action) -> Action {
        let old = std::mem::replace(&mut self.actions[sig as usize], action);
        if action.handler == SIG_IGN || (action.handler == SIG_DFL && ignored(sig)) {
            self.shared.0.remove(&sig);
            for task in self.tasks.values_mut() {
                task.private.0.remove(&sig);
            }
        }
        old
    }
    fn handles(&self, task: TaskId, sig: u8) -> bool {
        let action = self.actions[sig as usize];
        self.tasks[&task].mask & bit(sig) == 0
            && action.handler != SIG_IGN
            && !(action.handler == SIG_DFL && ignored(sig))
    }
    fn waits_for(&self, task: TaskId, sig: u8) -> bool {
        self.blocked.get(&task).is_some_and(|blocked| {
            blocked.wanted & bit(sig) != 0 && blocked.class != BlockClass::Readiness
        })
    }
    fn target(&self, sig: u8, target: SignalTarget) -> Option<TaskId> {
        // Prefer the leader, then the lowest live unblocked task. A blocked
        // synchronous reader is eligible only if nobody can handle the signal.
        match target {
            SignalTarget::Task(task) => self
                .tasks
                .get(&task)
                .filter(|_| self.handles(task, sig) || self.waits_for(task, sig))
                .map(|_| task),
            SignalTarget::Process => self
                .tasks
                .keys()
                .copied()
                .find(|task| self.handles(*task, sig))
                .or_else(|| {
                    self.tasks
                        .keys()
                        .copied()
                        .find(|task| self.waits_for(*task, sig))
                }),
        }
    }
    pub(super) fn finish(&mut self, task: TaskId) {
        self.tasks.remove(&task);
        self.blocked.remove(&task);
        self.interrupted.remove(&task);
    }
    /// Whether a generation of `sig` for `target` is discarded: the signal is
    /// ignored and no task it could reach blocks it.
    pub(super) fn discards(&self, sig: u8, target: SignalTarget) -> bool {
        let action = self.actions[sig as usize];
        let blocked = match target {
            SignalTarget::Process => self.tasks.values().any(|task| task.mask & bit(sig) != 0),
            SignalTarget::Task(task) => self
                .tasks
                .get(&task)
                .is_some_and(|task| task.mask & bit(sig) != 0),
        };
        !blocked && (action.handler == SIG_IGN || (action.handler == SIG_DFL && ignored(sig)))
    }
    /// The queued record of POSIX timer `id`'s signal `sig`, if one is still
    /// pending (a timer queues at most one: `send_sigqueue`).
    pub(super) fn queued_timer(&mut self, sig: u8, id: i32) -> Option<&mut Info> {
        let queues = std::iter::once(&mut self.shared)
            .chain(self.tasks.values_mut().map(|task| &mut task.private));
        for pending in queues {
            if let Some(instance) = pending.0.get_mut(&sig).and_then(|queue| {
                queue
                    .iter_mut()
                    .find(|instance| instance.info.timer_id() == Some(id))
            }) {
                return Some(&mut instance.info);
            }
        }
        None
    }
    fn enqueue(&mut self, sig: u8, target: SignalTarget, info: Info) -> (Instance, Option<TaskId>) {
        let instance = Instance {
            seq: self.next_seq,
            sig,
            info,
        };
        self.next_seq += 1;
        if self.discards(sig, target) {
            return (instance, None);
        }
        match target {
            SignalTarget::Process => self.shared.push(instance),
            SignalTarget::Task(task) => self.tasks.get_mut(&task).unwrap().private.push(instance),
        }
        (instance, self.target(sig, target))
    }
}

// All host operations use the already-resolved syscall alias in glibc's allowed
// text region, never a guest-visible symbol or an inline syscall instruction.
fn host(nr: i64, args: [u64; 6]) -> i64 {
    #[cfg(test)]
    tests::observe_host_call(nr, args);
    unsafe {
        crate::sud_host_syscall(
            nr,
            args[0] as i64,
            args[1] as i64,
            args[2] as i64,
            args[3] as i64,
            args[4] as i64,
            args[5] as i64,
        )
    }
}

pub(crate) fn host_mask(mask: u64) -> u64 {
    let mut mask = uncatchable(mask) & !bit(SIGSYS);
    if crate::PATINA_TSC_ARMED.load(Ordering::Relaxed) != 0 {
        mask &= !bit(SIGSEGV);
    }
    mask
}
pub(super) fn read_mask() -> u64 {
    let mut mask = 0u64;
    if host(
        SYS_RT_SIGPROCMASK,
        [
            SIG_BLOCK as u64,
            0,
            &mut mask as *mut _ as u64,
            SIGSET_BYTES as u64,
            0,
            0,
        ],
    ) != 0
    {
        fatal("host signal mask query failed (rt_sigprocmask)");
    }
    mask
}
pub(super) fn install_mask(mask: u64) {
    FRAME_DIRTY.with(|dirty| dirty.set(dirty.get() | FRAME_MASK));
    let mask = host_mask(mask);
    if host(
        SYS_RT_SIGPROCMASK,
        [
            SIG_SETMASK as u64,
            &mask as *const _ as u64,
            0,
            SIGSET_BYTES as u64,
            0,
            0,
        ],
    ) != 0
    {
        fatal("host signal mask install failed (rt_sigprocmask)");
    }
}

pub(super) fn activate() -> TaskId {
    let mut state = lock_state();
    if let Err(error) = state.ensure_active() {
        error.into_posix();
    }
    current_task()
}

/// # Safety
/// Pointers name the signal frame's mask and alternate-stack fields.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_signal_frame(mask: *mut u64, stack: *mut Stack) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let dirty = FRAME_DIRTY.with(|dirty| dirty.replace(0));
    if dirty & FRAME_MASK != 0 {
        unsafe {
            mask.write(read_mask());
        }
    }
    if dirty & FRAME_STACK != 0 && host(SYS_SIGALTSTACK, [0, stack as u64, 0, 0, 0, 0]) != 0 {
        fatal("host signal stack query failed (sigaltstack)");
    }
}

/// Called at the boundary return, not at generation. No lock survives a host
/// unblock: handlers can re-enter either door and acquire the runtime normally.
#[unsafe(no_mangle)]
pub extern "C" fn patina_signal_deliver() {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    deliver();
}

/// Host masks are authoritative inside nested guest handlers. Refresh at the
/// boundary, before generation chooses a recipient; generation itself stays
/// host-free. Outside frame release the no-pending path needs no host syscall.
pub(crate) fn refresh_handler_mask() {
    if RELEASING_FRAMES.with(Cell::get) {
        let mask = read_mask();
        if let Some(task) = lock_state().signals.tasks.get_mut(&current_task()) {
            task.mask = mask;
        }
    }
}

pub(crate) fn deliver() {
    if crate::in_shim_bootstrap() || task_completed() || main_returned() {
        return;
    }
    super::timers::fire_due();
    refresh_handler_mask();
    loop {
        let me = current_task();
        // Explicit C-ABI embedders may have a Context but no managed task or
        // host-alias link. An inactive delivery point must remain a no-op.
        {
            let state = lock_state();
            let Some(task) = state.signals.tasks.get(&me) else {
                return;
            };
            if task.private.mask() | state.signals.shared.mask() == 0 {
                return;
            }
        }
        let mask = read_mask();
        let batch = {
            let mut state = lock_state();
            state.signals.tasks.get_mut(&me).unwrap().mask = mask;
            let mut batch = Vec::new();
            let mut eligible = !mask;
            while let Some(instance) = state.dequeue_signal(me, eligible, true) {
                let action = state.signals.actions[instance.sig as usize];
                if action.handler == SIG_IGN || (action.handler == SIG_DFL && ignored(instance.sig))
                {
                    continue;
                }
                if action.flags & SA_RESETHAND != 0 {
                    // Linux resets only sa_handler; flags, mask and restorer
                    // remain observable through rt_sigaction after delivery.
                    state.signals.actions[instance.sig as usize].handler = SIG_DFL;
                }
                // Later members blocked by this frame stay virtual, visible to
                // sigpending/signalfd inside the handler. Independent frames still
                // stack through one host unblock. Host masks encode nesting, so
                // a separate in_delivery flag would wrongly forbid nested delivery.
                if action.handler != SIG_DFL {
                    eligible &= !action.mask;
                    if action.flags & SA_NODEFER == 0 {
                        eligible &= !bit(instance.sig);
                    }
                }
                batch.push((instance, action));
            }
            batch
        };
        if batch.is_empty() {
            return;
        }
        install_mask(u64::MAX);
        let pid = host(SYS_GETPID, [0; 6]);
        let tid = host(SYS_GETTID, [0; 6]);
        for (instance, action) in batch {
            if action.handler == SIG_DFL {
                if matches!(instance.sig, SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU) {
                    fatal("default Stop-class signal would stop the only virtual process");
                }
                if crate::patina_shutdown() != 0 {
                    fatal("signal termination finalization failed");
                }
                let default = Action::default();
                if instance.sig != SIGKILL
                    && host(
                        SYS_RT_SIGACTION,
                        [
                            instance.sig as u64,
                            &default as *const _ as u64,
                            0,
                            SIGSET_BYTES as u64,
                            0,
                            0,
                        ],
                    ) != 0
                {
                    fatal("host default signal action install failed (rt_sigaction)");
                }
                // Release only the dying signal; queued handler frames stay blocked.
                install_mask(!bit(instance.sig));
            }
            let rc = host(
                SYS_RT_TGSIGQUEUEINFO,
                [
                    pid as u64,
                    tid as u64,
                    instance.sig as u64,
                    &instance.info as *const _ as u64,
                    0,
                    0,
                ],
            );
            if rc != 0 {
                fatal("host signal-frame queue failed (rt_tgsigqueueinfo)");
            }
        }
        let was_releasing = RELEASING_FRAMES.with(|flag| flag.replace(true));
        let outer_dirty = FRAME_DIRTY.with(Cell::get);
        crate::sud::with_signal_delivery(|| {
            let _guest = crate::panic_boundary::PanicScope::suspend();
            install_mask(mask);
        });
        // Inner SIGSYS fixups may consume these bits while handlers run. The
        // enclosing frame still owns its changes, including the release mask.
        FRAME_DIRTY.with(|dirty| dirty.set(dirty.get() | outer_dirty | FRAME_MASK));
        RELEASING_FRAMES.with(|flag| flag.set(was_releasing));
        // Nested boundary calls observed the handler mask. rt_sigreturn restored
        // this enclosing mask, even if no pending work remains for another loop.
        lock_state().signals.tasks.get_mut(&me).unwrap().mask = mask;
    }
}

/// Libc-layout marshalling supplies glibc's init-time restorer; raw callers keep
/// their exact flags/restorer. Both doors perform one install through the core.
/// # Safety
/// Non-null pointers name readable/writable kernel action records.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_signal_action_libc(
    sig: i32,
    action: *const Action,
    old: *mut Action,
) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let converted = if action.is_null() {
        None
    } else {
        Some(unsafe { *action })
    };
    #[cfg(target_arch = "x86_64")]
    let converted = converted.map(|mut action| {
        if action.flags & SA_RESTORER == 0 {
            action.restorer = RESTORER.load(Ordering::Relaxed);
            if action.restorer == 0 {
                fatal("glibc signal restorer was not captured at init");
            }
            action.flags |= SA_RESTORER;
        }
        action
    });
    unsafe {
        patina_signal_action(
            sig,
            converted.as_ref().map_or(std::ptr::null(), |action| action),
            old,
            SIGSET_BYTES,
        )
    }
}

/// Kernel-layout action entry shared by both syscall doors.
/// # Safety
/// Non-null pointers must name readable/writable kernel sigaction structures.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_signal_action(
    sig: i32,
    action: *const Action,
    old: *mut Action,
    size: usize,
) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if !(1..=SIGNAL_MAX).contains(&sig)
        || size != SIGSET_BYTES
        || (!action.is_null() && matches!(sig as u8, SIGKILL | SIGSTOP))
    {
        return -i64::from(EINVAL);
    }
    if !action.is_null()
        && (sig == i32::from(SIGSYS)
            || (sig == i32::from(SIGSEGV) && crate::PATINA_TSC_ARMED.load(Ordering::Relaxed) != 0))
    {
        fatal("reserved signal registration would disable deterministic containment");
    }
    // Rust std performs registration before a deferred harness installs Context.
    // Dispositions are unrecorded process state; do not activate the scheduler.
    let mut state = lock_state();
    let mut previous = state.signals.actions[sig as usize];
    // Rust std installs stack-overflow handlers only over SIG_DFL. Report the
    // reserved host disposition so it does not try to replace our containment.
    if action.is_null()
        && (sig == i32::from(SIGSYS)
            || (sig == i32::from(SIGSEGV) && crate::PATINA_TSC_ARMED.load(Ordering::Relaxed) != 0))
    {
        let rc = host(
            SYS_RT_SIGACTION,
            [
                sig as u64,
                0,
                &mut previous as *mut _ as u64,
                SIGSET_BYTES as u64,
                0,
                0,
            ],
        );
        if rc != 0 {
            return -i64::from(
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or_else(|| fatal("host signal syscall failed without errno")),
            );
        }
    }
    if !action.is_null() {
        let action = unsafe { *action };
        let rc = host(
            SYS_RT_SIGACTION,
            [
                sig as u64,
                &action as *const _ as u64,
                0,
                SIGSET_BYTES as u64,
                0,
                0,
            ],
        );
        if rc != 0 {
            return -i64::from(
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or_else(|| fatal("host signal syscall failed without errno")),
            );
        }
        state.signals.action(sig as u8, action);
    }
    if !old.is_null() {
        unsafe {
            old.write(previous);
        }
    }
    0
}

/// # Safety
/// The optional mask pointers must be valid for eight bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_signal_mask(
    how: i32,
    set: *const u64,
    old: *mut u64,
    size: usize,
) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if size != SIGSET_BYTES
        || (!set.is_null() && !matches!(how, SIG_BLOCK | SIG_UNBLOCK | SIG_SETMASK))
    {
        return -i64::from(EINVAL);
    }
    let me = activate();
    let previous = read_mask();
    if !old.is_null() {
        unsafe {
            old.write(previous);
        }
    }
    let mask = if set.is_null() {
        previous
    } else {
        let set = unsafe { *set };
        host_mask(match how {
            SIG_BLOCK => previous | set,
            SIG_UNBLOCK => previous & !set,
            _ => set,
        })
    };
    lock_state().signals.tasks.get_mut(&me).unwrap().mask = mask;
    install_mask(mask);
    0
}

/// # Safety
/// `set` must be writable for `size` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_signal_pending(set: *mut u8, size: usize) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if size > SIGSET_BYTES {
        return -i64::from(EINVAL);
    }
    if set.is_null() {
        return -i64::from(EFAULT);
    }
    let me = activate();
    super::timers::fire_due();
    let mut state = lock_state();
    state.signals.tasks.get_mut(&me).unwrap().mask = read_mask();
    let pending = state.signals.pending(me).to_ne_bytes();
    unsafe {
        std::ptr::copy_nonoverlapping(pending.as_ptr(), set, size);
    }
    0
}

/// # Safety
/// Stack pointers must be valid Linux stack_t buffers when non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_signal_altstack(stack: *const Stack, old: *mut Stack) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // One managed task per host thread: the kernel is the sole altstack store
    // and validator, and builds frames on that very stack (no shadow state).
    // Startup stack registration likewise requires no Context/scheduler.
    let mut previous = Stack::default();
    let rc = host(
        SYS_SIGALTSTACK,
        [stack as u64, &mut previous as *mut _ as u64, 0, 0, 0, 0],
    );
    if rc != 0 {
        return -(std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or_else(|| fatal("host signal syscall failed without errno"))
            as i64);
    }
    if !old.is_null() {
        unsafe {
            old.write(previous);
        }
    }
    if !stack.is_null() {
        FRAME_DIRTY.with(|dirty| dirty.set(dirty.get() | FRAME_STACK));
    }
    0
}

#[derive(Clone, Copy)]
pub(crate) enum GenerationTarget {
    Process { pid: i32 },
    Thread { tgid: Option<i32>, tid: i32 },
}
#[derive(Clone, Copy)]
pub(crate) enum GenerationInfo {
    User,
    Thread,
    Queued(*const Info),
}

/// The one generation entry owns target and queued-info validation. Doors only
/// marshal; a thread with tid zero can never become process-directed.
pub(crate) unsafe fn generate_signal(
    target: GenerationTarget,
    sig: i32,
    info: GenerationInfo,
) -> i64 {
    assert!(
        !crate::in_shim_critical(),
        "signal generation under the runtime lock"
    );
    if !(0..=SIGNAL_MAX).contains(&sig) {
        return -i64::from(EINVAL);
    }
    let queued = matches!(info, GenerationInfo::Queued(_));
    let info = match info {
        GenerationInfo::User => Info::new(sig as u8, SI_USER),
        GenerationInfo::Thread => Info::new(sig as u8, SI_TKILL),
        GenerationInfo::Queued(ptr) => {
            if ptr.is_null() {
                return -i64::from(EFAULT);
            }
            unsafe { *ptr }
        }
    };
    // `do_rt_sigqueueinfo`/`do_rt_tgsigqueueinfo`: a caller may forge a
    // kernel or `tkill` code only to itself, judged by its own thread id.
    let forged = queued && (info.code() >= 0 || info.code() == SI_TKILL);
    let target = match target {
        GenerationTarget::Process { pid } => {
            if forged && pid != current_tid() {
                return -i64::from(EPERM);
            }
            // A queued signal names one process; `kill` also names groups.
            match crate::identity::signal_target(pid, !queued) {
                Some(crate::identity::Process::Guest) => SignalTarget::Process,
                // Init takes no handlers, and the kernel drops what a member
                // of its namespace sends it by default.
                Some(crate::identity::Process::Init) => return 0,
                None => return -i64::from(ESRCH),
            }
        }
        GenerationTarget::Thread { tgid, tid } => {
            if tid <= 0 || tgid.is_some_and(|pid| pid <= 0) {
                return -i64::from(EINVAL);
            }
            if forged && tid != current_tid() {
                return -i64::from(EPERM);
            }
            let init = crate::registry::INIT_PID as i32;
            let guest = crate::registry::IDENTITY_PID as i32;
            if tid == init {
                // Init's one thread, reached by `tkill` or with its own tgid.
                return if tgid.is_none_or(|pid| pid == init) {
                    0
                } else {
                    -i64::from(ESRCH)
                };
            }
            match task_of(tid) {
                Some(task) if tgid.is_none_or(|pid| pid == guest) => SignalTarget::Task(task),
                _ => return -i64::from(ESRCH),
            }
        }
    };
    activate();
    let mut state = lock_state();
    if let SignalTarget::Task(task) = target {
        if !state.signals.tasks.contains_key(&task) {
            return -i64::from(ESRCH);
        }
    }
    if sig == 0 {
        return 0;
    }
    let wakes = state.generate_locked(target, info);
    drop(state);
    for task in wakes {
        RealScheduler
            .wake(task)
            .unwrap_or_else(|error| fatal(&error));
    }
    0
}

impl ThreadRuntime {
    /// Generate `info` for `target` under the runtime lock the caller holds:
    /// queue it (unless discarded), record the generation, count signalfd
    /// arrivals, and answer the tasks to wake once the lock is released.
    pub(in crate::thread) fn generate_locked(
        &mut self,
        target: SignalTarget,
        info: Info,
    ) -> Vec<TaskId> {
        let (instance, wake) = self.signals.enqueue(info.signo(), target, info);
        with_context_raw(|context| {
            context.signal_generated(
                instance.seq,
                instance.sig,
                target,
                info.code(),
                info.value(),
            )
        })
        .unwrap_or_else(|errno| fatal(&format!("recording signal generation failed ({errno})")));
        for fd in self.signals.signalfds.values_mut() {
            if fd.mask & bit(instance.sig) != 0 {
                fd.arrivals += 1;
            }
        }
        self.prepare_signal_wakes(instance, wake)
    }

    /// `dequeue_signal`: take the next pending signal in `eligible` (for
    /// delivery, only one the process-wide target rule sends this task), and
    /// let the timers rearm on its dequeue — `ITIMER_REAL` on `SIGALRM`, a
    /// periodic POSIX timer on its own `SI_TIMER` record.
    fn dequeue_signal(&mut self, task: TaskId, eligible: u64, delivery: bool) -> Option<Instance> {
        let mut instance = if delivery {
            self.signals.dequeue_delivery(task, eligible)
        } else {
            self.signals.dequeue(task, eligible)
        }?;
        self.timers.dequeued(&mut instance.info);
        Some(instance)
    }
}

/// Register the guest word without replacing glibc's host clear-child-tid.
/// # Safety
/// A non-null address must remain writable until the calling task exits.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_set_tid_address(address: *mut i32) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let me = activate();
    lock_state()
        .signals
        .tasks
        .get_mut(&me)
        .unwrap()
        .clear_child_tid = (!address.is_null()).then_some(address as usize);
    i64::from(tid_of(me))
}

pub(super) fn clear_tid(task: TaskId) {
    let address = lock_state()
        .signals
        .tasks
        .get_mut(&task)
        .unwrap()
        .clear_child_tid
        .take();
    if let Some(address) = address {
        // The guest keeps this word alive through exit, as for set_tid_address(2).
        unsafe {
            (address as *mut i32).write_volatile(0);
        }
        patina_futex_wake(address, 1);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn patina_raw_exit_group(status: i32) -> ! {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::patina_note_guest_exit_status(status & 255);
    if crate::patina_shutdown() != 0 {
        fatal("exit_group finalization failed");
    }
    note_main_returned();
    host(SYS_EXIT_GROUP, [(status & 255) as u64, 0, 0, 0, 0, 0]);
    fatal("host exit_group returned")
}

#[unsafe(no_mangle)]
pub extern "C" fn patina_raw_exit(status: i32) -> ! {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let me = activate();
    thread_finish(me, (status & 255) as usize, status & 255);
    host(SYS_EXIT, [(status & 255) as u64, 0, 0, 0, 0, 0]);
    fatal("host exit returned")
}

#[unsafe(no_mangle)]
pub extern "C" fn patina_pthread_kill(handle: usize, sig: i32) -> i32 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if !(0..=SIGNAL_MAX).contains(&sig) || matches!(sig, GLIBC_SIGCANCEL | GLIBC_SIGSETXID) {
        return EINVAL;
    }
    activate();
    refresh_handler_mask();
    let task = if handle == unsafe { (crate::hostapi::get().host_pthread_self)() } {
        Some(current_task())
    } else {
        lock_state().handles.get(&handle).copied()
    };
    let Some(task) = task else {
        return ESRCH;
    };
    let rc = unsafe {
        generate_signal(
            GenerationTarget::Thread {
                tgid: Some(crate::registry::IDENTITY_PID as i32),
                tid: tid_of(task),
            },
            sig,
            GenerationInfo::Thread,
        )
    };
    deliver();
    -rc as i32
}

#[cfg(test)]
pub(super) mod tests;

/// A temporary mask belongs to the entire wait, including handler delivery.
/// The old mask is restored before either syscall door returns.
pub(super) unsafe fn with_temporary_mask(mask: *const u64, body: impl FnOnce() -> i64) -> i64 {
    if mask.is_null() {
        return body();
    }
    let me = activate();
    let old = read_mask();
    let temporary = host_mask(unsafe { *mask });
    lock_state().signals.tasks.get_mut(&me).unwrap().mask = temporary;
    install_mask(temporary);
    let pending = lock_state().signals.has_deliverable(me);
    let rc = if pending {
        deliver();
        -i64::from(EINTR)
    } else {
        body()
    };
    lock_state().signals.tasks.get_mut(&me).unwrap().mask = old;
    install_mask(old);
    rc
}
