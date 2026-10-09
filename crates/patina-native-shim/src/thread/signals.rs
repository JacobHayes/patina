//! Linux signal state. Generation only mutates virtual queues; the baton holder
//! transfers a delivery batch to kernel-built frames after releasing the lock.
use super::*;
use crate::EINTR;
mod fault;
pub(crate) mod fd;
mod frames;
mod waits;
pub(super) use fault::front_installed;
use fault::{Scoped, SegvBlock, trap_routed};
pub(super) use frames::{arm as arm_signal_stack, release as release_signal_stack};
use patina_dst_abi::SignalTarget;
use std::sync::atomic::Ordering;
use waits::Blocked;
pub(crate) use waits::{Resumed, resume, resume_timed};
pub(crate) use waits::{Timespec, WaitMode, patina_signal_wait};
pub(super) use waits::{resume_with, take_sync_resume};

mod constants;
pub(super) use constants::*;

thread_local! {
    // Nested handler boundaries must refresh the virtual mask before generation.
    static RELEASING_FRAMES: Cell<bool> = const { Cell::new(false) };
    // A guest restorer's frame blocked SIGSEGV for the mask its return installs.
    static RESTORED_SEGV: Cell<bool> = const { Cell::new(false) };
    // Only mask-changing entries need to rewrite a SIGSYS return frame.
    static FRAME_DIRTY: Cell<u8> = const { Cell::new(0) };
}
const FRAME_MASK: u8 = 1;

static RESTORER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[unsafe(no_mangle)]
pub extern "C" fn patina_signal_restorer(restorer: usize) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    RESTORER.store(restorer, Ordering::Relaxed);
}

pub(super) fn bit(sig: impl Into<i64>) -> u64 {
    1u64 << (sig.into() - 1)
}
/// The kernel's `SYNCHRONOUS_MASK`: signals an instruction raises, dequeued
/// before any other pending one.
const SYNCHRONOUS: u64 = 1 << (SIGSEGV - 1)
    | 1 << (SIGBUS - 1)
    | 1 << (SIGILL - 1)
    | 1 << (SIGTRAP - 1)
    | 1 << (SIGFPE - 1)
    | 1 << (SIGSYS - 1);
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

#[allow(dead_code)]
mod plain_impls {
    #![deny(clippy::undocumented_unsafe_blocks)]

    crate::plain!(super::Action {
        handler: usize,
        flags: u64,
        restorer: usize,
        mask: u64,
    });
    crate::plain!(super::Info { words: [u64; 16] });
}

impl Info {
    fn new(sig: u8, code: i32) -> Self {
        let mut info = Self { words: [0; 16] };
        info.words[0] = u64::from(sig);
        info.words[1] = u64::from(code as u32);
        info.words[2] = u64::from(crate::registry::IDENTITY_PID)
            | (u64::from(crate::identity::credential().uid) << 32);
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
    /// `next_signal`: the synchronous signals first, then the lowest number.
    fn take(&mut self, eligible: u64) -> Option<Instance> {
        let ready = self.mask() & eligible;
        let synchronous = ready & SYNCHRONOUS;
        let pick = if synchronous != 0 { synchronous } else { ready };
        if pick == 0 {
            return None;
        }
        let sig = pick.trailing_zeros() as u8 + 1;
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
    /// How many delivery batches this task is inside ([`deliver`]): while it
    /// is not 0, the task runs a guest handler above the shim's own delivery
    /// frames, which no unwind may cross.
    delivering: u32,
}

struct Interrupt {
    instance: Instance,
    class: BlockClass,
    sync_wait: Option<Blocked>,
}

pub(super) struct SignalRuntime {
    actions: [Action; 65],
    /// How often the guest has set each signal's action: a delivery batch's
    /// member whose count moved since its dequeue runs the action it was
    /// dequeued with, which the host no longer holds.
    changes: [u32; 65],
    /// Signals whose host action is, for the frame being built, the one a
    /// batch member was dequeued with, not the guest's current one.
    swapped: u64,
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
            changes: [0; 65],
            swapped: 0,
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
    /// Whether `task` runs a guest signal handler: glibc's forced unwind
    /// (`pthread_exit`) from there would cross the shim's Rust delivery
    /// frames, which cannot be unwound.
    pub(super) fn in_handler(&self, task: TaskId) -> bool {
        self.depth(task) > 0
    }
    /// How many delivery batches `task` is inside: 0 outside every handler.
    pub(super) fn depth(&self, task: TaskId) -> u32 {
        self.tasks.get(&task).map_or(0, |task| task.delivering)
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
    /// The signal a delivery to `task` would take first (synchronous ones
    /// first, then the lowest number), of those `wanted` leaves to a dequeue.
    fn first_deliverable(&self, task: TaskId, wanted: u64) -> Option<u8> {
        let private = self.tasks[&task].private.mask();
        let shared = self.shared.mask();
        // Only the signals pending at all, of those a dequeue does not take.
        let mut candidates = (private | shared) & !wanted;
        let mut ready = 0u64;
        while candidates != 0 {
            let sig = candidates.trailing_zeros() as u8 + 1;
            candidates &= candidates - 1;
            if self.handles(task, sig)
                && (private & bit(sig) != 0
                    || self.target(sig, SignalTarget::Process) == Some(task))
            {
                ready |= bit(sig);
            }
        }
        let pick = if ready & SYNCHRONOUS != 0 {
            ready & SYNCHRONOUS
        } else {
            ready
        };
        (pick != 0).then(|| pick.trailing_zeros() as u8 + 1)
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
        self.changes[sig as usize] = self.changes[sig as usize].wrapping_add(1);
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

#[cfg(test)]
pub(super) mod tests;

mod actions;
mod delivery;
mod generation;
/// A temporary mask belongs to the entire wait, including handler delivery.
/// The old mask is restored before either syscall door returns.
mod mask;

pub use actions::{
    patina_signal_action, patina_signal_action_libc, patina_signal_altstack, patina_signal_mask,
    patina_signal_pending,
};
pub(crate) use delivery::owe_errno;
#[cfg(any(test, patina_posix_exports))]
pub(crate) use delivery::patina_signal_deliver;
pub(crate) use delivery::{deliver, deliver_saving, refresh_handler_mask};
use delivery::{fault_entered, install_host_action};
use delivery::{file_restart, file_temporary_mask, plan_pending};
#[cfg(any(test, patina_posix_exports))]
pub(crate) use generation::patina_pthread_kill;
pub use generation::patina_raw_exit_group;
#[cfg(patina_posix_exports)]
pub(crate) use generation::patina_signal_reserved;
pub(crate) use generation::{
    GenerationInfo, GenerationTarget, abort_through_kernel, generate_signal,
};
pub(super) use generation::{clear_tid, temporary_mask, with_mask, with_temporary_mask};
pub(crate) use generation::{patina_raw_exit, patina_set_tid_address};
#[cfg(test)]
use mask::patina_signal_frame;
use mask::{SEGV_UNKNOWN, containment_kept_unblocked, host, segv_bit, segv_blocked};
pub(super) use mask::{activate, install_mask, read_mask, set_segv, with_segv};
pub(crate) use mask::{host_mask, write_through};
