//! Thread cancellation as glibc 2.39 keeps it (nptl `pthread_cancel.c`,
//! `pthread_setcancelstate.c`, `pthread_setcanceltype.c`,
//! `pthread_testcancel.c`, `cancellation.c`): per thread, whether
//! cancellation is enabled and asynchronous, whether a cancel was requested,
//! and whether the thread is already exiting.
//!
//! A deferred cancel acts at a cancellation point: at its entry when the
//! request is already pending, and inside it when the request arrives while
//! the thread waits there (glibc makes the thread asynchronously cancellable
//! for the length of the wait, and `SIGCANCEL` ends it). Acting is
//! `pthread_exit(PTHREAD_CANCELED)`, glibc's forced unwind, so it happens in
//! the C wrappers once the Rust calls here have returned ([`ACT`]); no Rust
//! frame can be unwound.
//!
//! The model acts at the sleeps (`nanosleep`, `clock_nanosleep`, `sleep`) and
//! at `pthread_testcancel`, and when enabling asynchronous cancellation meets
//! a pending request. Every other glibc cancellation point a guest can reach
//! is a shim C wrapper that checks at its entry ([`patina_cancel_point`]) or
//! an import the audit refuses (patina-syscalls `cancellation.rs`, gated
//! against the shim's C): a thread reaching one with a cancel to act on stops
//! the run by name. So does a thread with one blocking in such a wait (a raw
//! syscall's included, which glibc would not cancel: conservative), a cancel
//! that would have to end a thread blocked in one, a cancel reaching a thread
//! that runs a signal handler inside a sleep (glibc ends it in the handler),
//! and cancelling another thread asynchronously (it acts wherever that thread
//! is). Acting inside a signal handler is `patina_thread_exiting`'s named
//! fatal: the unwind would cross the shim's delivery frames.

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

/// The answer that tells a C wrapper to act on the cancellation now.
const ACT: c_int = -1;

const CANCEL_DISABLE: c_int = 1;
const CANCEL_ASYNCHRONOUS: c_int = 1;

/// How many threads have a cancel requested: while none has, a cancellation
/// point's entry check is one load.
static REQUESTS: AtomicUsize = AtomicUsize::new(0);

/// One thread's `cancelhandling`.
#[derive(Clone, Copy, Default)]
pub(in crate::thread) struct Cancel {
    /// `PTHREAD_CANCEL_DISABLE`.
    disabled: bool,
    /// `PTHREAD_CANCEL_ASYNCHRONOUS`.
    asynchronous: bool,
    /// A cancel was requested (`CANCELED_BITMASK`).
    pending: bool,
    /// The thread is ending (`EXITING_BITMASK`): no cancel acts any more.
    exiting: bool,
    /// Inside a cancellation point the model acts at, where glibc makes the
    /// thread asynchronously cancellable: the signal-delivery depth it
    /// entered at. The point's own wait is the sleep at that depth; a
    /// handler that runs inside the point runs deeper.
    point: Option<u32>,
}

impl Cancel {
    /// glibc's `cancel_enabled_and_canceled`.
    fn acts(self) -> bool {
        self.pending && !self.disabled && !self.exiting
    }
}

/// Every thread's cancellation state; a thread absent from it has glibc's
/// initial one (enabled, deferred, nothing requested).
#[derive(Default)]
pub(in crate::thread) struct Cancels {
    tasks: BTreeMap<TaskId, Cancel>,
}

impl Cancels {
    fn get(&self, task: TaskId) -> Cancel {
        self.tasks.get(&task).copied().unwrap_or_default()
    }

    fn entry(&mut self, task: TaskId) -> &mut Cancel {
        self.tasks.entry(task).or_default()
    }

    /// The thread is ending: `pthread_exit`, or a cancel it acts on.
    pub(in crate::thread) fn exiting(&mut self, task: TaskId) {
        self.entry(task).exiting = true;
    }

    pub(in crate::thread) fn finish(&mut self, task: TaskId) {
        if self
            .tasks
            .remove(&task)
            .is_some_and(|cancel| cancel.pending)
        {
            REQUESTS.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// `task`, at signal-delivery depth `depth`, is inside a cancellation
    /// point the model acts at, at that point's own depth, with a cancel to
    /// act on: glibc would already have ended it.
    pub(in crate::thread) fn acts_in_point(&self, task: TaskId, depth: u32) -> bool {
        let cancel = self.get(task);
        cancel.acts() && cancel.point == Some(depth)
    }
}

/// Whether a wait is one of glibc's cancellation points (a cancellable
/// syscall, `pthread_join`, `pthread_cond_wait`), from its class and what it
/// waits on. A sleep is judged by the thread's `point` instead: the raw
/// `nanosleep` row, which no C wrapper enters, is none.
fn cancellation_point(class: BlockClass, locs: &[WaiterLoc]) -> bool {
    match class {
        BlockClass::Io
        | BlockClass::Readiness
        | BlockClass::Pause
        | BlockClass::SigSuspend
        | BlockClass::SigWait
        | BlockClass::SignalfdRead => true,
        // `semop` is no cancellation point; the message queues are.
        BlockClass::Ipc => locs
            .iter()
            .any(|loc| !matches!(loc, WaiterLoc::Ipc(ipc::IpcWait::Sem(_)))),
        BlockClass::Sync => locs
            .iter()
            .any(|loc| matches!(loc, WaiterLoc::Cond(..) | WaiterLoc::Join(_))),
        BlockClass::Sleep | BlockClass::Futex | BlockClass::TimedFutex => false,
    }
}

/// What a cancel of another thread does, given that thread's state after the
/// request was recorded, its signal-delivery depth, and the wait it is
/// blocked in, if any (its class and what it waits on).
#[derive(Debug, PartialEq, Eq)]
enum Reach {
    /// The request waits for the thread's next cancellation point.
    Pending,
    /// End the thread's wait: the sleep it waits in acts as it returns.
    Wake,
    /// Stop the run by name: the model cannot end the thread where glibc
    /// would.
    Refuse(&'static str),
}

fn reach(cancel: Cancel, depth: u32, blocked: Option<(BlockClass, &[WaiterLoc])>) -> Reach {
    if !cancel.acts() {
        return Reach::Pending;
    }
    if cancel.asynchronous {
        return Reach::Refuse(
            "pthread_cancel of another thread that is asynchronously cancellable is not \
             modeled: the cancellation acts wherever that thread is",
        );
    }
    match (cancel.point, blocked) {
        (Some(at), Some((BlockClass::Sleep, _))) if at == depth => Reach::Wake,
        (Some(at), _) if at != depth || blocked.is_some() => Reach::Refuse(
            "pthread_cancel of a thread running a signal handler inside a sleep is not \
             modeled: glibc ends it inside the handler",
        ),
        // Inside the sleep's entry, before it waits: the sleep acts before
        // it would park (`ThreadRuntime::block_timed`).
        (Some(_), _) => Reach::Pending,
        (None, Some((class, locs))) if cancellation_point(class, locs) => Reach::Refuse(
            "pthread_cancel of a thread blocked in a cancellation point the model does not act \
             at (only the sleeps and pthread_testcancel act): ending that wait is not modeled",
        ),
        (None, _) => Reach::Pending,
    }
}

impl ThreadRuntime {
    /// Refuse a wait the model would get wrong: `me` has a cancel to act on
    /// and is about to block in a cancellation point the model does not act
    /// at, where glibc would have ended it.
    pub(in crate::thread) fn refuse_unmodeled_cancellation(
        &self,
        me: TaskId,
        reason: &str,
        wait: &Wait,
    ) {
        if self.cancels.get(me).acts() && cancellation_point(wait.class, &wait.locs) {
            fatal(&format!(
                "a thread with a pending cancellation blocks in {reason}: acting on a \
                 cancellation there is not modeled (only the sleeps and pthread_testcancel act)"
            ));
        }
    }

    /// A join that would answer `EDEADLK`: glibc skips that answer for a
    /// thread with a cancel to act on and waits instead, and so acts, which
    /// the model does not follow.
    pub(in crate::thread) fn refuse_deadlocked_join(&self, me: TaskId) {
        if self.cancels.get(me).acts() {
            fatal(
                "a pending cancellation reaches pthread_join where glibc waits and so acts \
                 (a join that would otherwise be EDEADLK): not modeled",
            );
        }
    }

    /// `me` is inside a sleep with a cancel to act on (one that arrived
    /// between the sleep's entry and its wait): glibc's thread, asynchronously
    /// cancellable there, has already ended, so the sleep must not wait, and
    /// virtual time must not pass for it.
    pub(in crate::thread) fn cancel_ends_sleep(&self, me: TaskId) -> bool {
        self.cancels.acts_in_point(me, self.signals.depth(me))
    }
}

/// `pthread_cancel(handle)`: 0, `ESRCH` for a handle the model does not
/// know, or [`ACT`] when the caller cancels itself while asynchronously
/// cancellable (its own type, or inside a sleep, where only a signal
/// handler runs guest code).
#[unsafe(no_mangle)]
pub extern "C" fn patina_thread_cancel(handle: usize) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let me = current_task();
    // SAFETY: the real glibc `pthread_self`, resolved through the host-alias
    // table.
    let own = handle == unsafe { (crate::hostapi::get().host_pthread_self)() };
    let mut state = lock_state();
    let target = if own {
        me
    } else {
        match state.handles.get(&handle) {
            Some(&task) => task,
            None => return ESRCH,
        }
    };
    // A thread that has ended keeps the outcome it had.
    if state
        .table
        .threads
        .get(&target)
        .is_some_and(|entry| entry.finished)
    {
        return 0;
    }
    let cancel = state.cancels.entry(target);
    if cancel.pending {
        return 0;
    }
    cancel.pending = true;
    REQUESTS.fetch_add(1, Ordering::Relaxed);
    let cancel = *cancel;
    if own {
        return if cancel.acts() && (cancel.asynchronous || cancel.point.is_some()) {
            ACT
        } else {
            0
        };
    }
    let depth = state.signals.depth(target);
    let blocked = state
        .signals
        .blocked
        .get(&target)
        .map(|blocked| (blocked.class, blocked.locs.clone(), blocked.reason));
    match reach(
        cancel,
        depth,
        blocked
            .as_ref()
            .map(|(class, locs, _)| (*class, locs.as_slice())),
    ) {
        Reach::Pending => 0,
        Reach::Wake => {
            state.remove_signal_wait(target);
            drop(state);
            RealScheduler
                .wake(target)
                .unwrap_or_else(|message| fatal(&message));
            0
        }
        Reach::Refuse(why) => match blocked {
            Some((_, _, reason)) => fatal(&format!("{why} (the thread waits in {reason})")),
            None => fatal(why),
        },
    }
}

/// `pthread_setcancelstate(state, old)`: 0, `EINVAL` for an unknown state,
/// or [`ACT`] when enabling meets a pending cancel asynchronously.
///
/// # Safety
/// `old` must be null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_cancel_setstate(new: c_int, old: *mut c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if !(0..=CANCEL_DISABLE).contains(&new) {
        return EINVAL;
    }
    let me = current_task();
    let mut state = lock_state();
    let cancel = state.cancels.entry(me);
    if !old.is_null() {
        // SAFETY: writable, per this function's contract.
        unsafe { old.write(c_int::from(cancel.disabled)) };
    }
    cancel.disabled = new == CANCEL_DISABLE;
    if cancel.acts() && cancel.asynchronous {
        ACT
    } else {
        0
    }
}

/// `pthread_setcanceltype(type, old)`: 0, `EINVAL` for an unknown type, or
/// [`ACT`] when becoming asynchronous meets a pending cancel.
///
/// # Safety
/// `old` must be null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_cancel_settype(new: c_int, old: *mut c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if !(0..=CANCEL_ASYNCHRONOUS).contains(&new) {
        return EINVAL;
    }
    let me = current_task();
    let mut state = lock_state();
    let cancel = state.cancels.entry(me);
    if !old.is_null() {
        // SAFETY: writable, per this function's contract.
        unsafe { old.write(c_int::from(cancel.asynchronous)) };
    }
    cancel.asynchronous = new == CANCEL_ASYNCHRONOUS;
    if cancel.acts() && cancel.asynchronous {
        ACT
    } else {
        0
    }
}

/// `pthread_testcancel`: 1 when the caller must act on a cancel now.
#[unsafe(no_mangle)]
pub extern "C" fn patina_cancel_test() -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    c_int::from(lock_state().cancels.get(current_task()).acts())
}

/// A C wrapper enters a cancellation point the model acts at: [`ACT`] when a
/// cancel is pending, else the point the thread was already inside (a signal
/// handler's sleep runs inside another's), which [`patina_cancel_leave`]
/// restores: 0 for none, else its depth plus one.
#[unsafe(no_mangle)]
pub extern "C" fn patina_cancel_enter() -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let me = current_task();
    let mut state = lock_state();
    let depth = state.signals.depth(me);
    let cancel = state.cancels.entry(me);
    if cancel.acts() {
        return ACT;
    }
    let outer = cancel.point.map_or(0, |at| at as c_int + 1);
    cancel.point = Some(depth);
    outer
}

/// The C wrapper leaves the cancellation point [`patina_cancel_enter`]
/// entered: [`ACT`] when a cancel arrived while the thread was in it.
#[unsafe(no_mangle)]
pub extern "C" fn patina_cancel_leave(outer: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let me = current_task();
    let mut state = lock_state();
    let cancel = state.cancels.entry(me);
    cancel.point = (outer > 0).then(|| (outer - 1) as u32);
    if cancel.acts() { ACT } else { 0 }
}

/// The entry of a glibc cancellation point the model does not act at (the C
/// `PATINA_CANCEL_POINT`): a thread with a cancel to act on stops the run by
/// name, where glibc would end it here.
///
/// # Safety
/// `name` must be a NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_cancel_point(name: *const std::ffi::c_char) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if REQUESTS.load(Ordering::Relaxed) == 0 {
        return;
    }
    if lock_state().cancels.get(current_task()).acts() {
        // SAFETY: NUL-terminated, per this function's contract.
        let name = unsafe { std::ffi::CStr::from_ptr(name) }.to_string_lossy();
        fatal(&format!(
            "a pending cancellation reaches {name}, a cancellation point the model does not act \
             at (only the sleeps and pthread_testcancel act): glibc would end the thread there"
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::thread::signals::tests::{isolated, join, spawn};
    use std::sync::atomic::{AtomicBool, AtomicU64};

    fn monotonic() -> u64 {
        with_context_raw(|context| context.now(ClockKind::Monotonic)).unwrap()
    }

    /// A cancel that reaches a thread between a sleep's entry and its wait
    /// ends the sleep before it waits, as glibc's thread, asynchronously
    /// cancellable inside the sleep, ends at once: no virtual time passes for
    /// the sleep, and its wrapper acts as the sleep returns.
    #[test]
    fn a_cancel_before_a_sleep_waits_ends_it_at_once() {
        const HOUR: u64 = 3_600_000_000_000;
        static ENTERED: AtomicBool = AtomicBool::new(false);
        static CANCELED: AtomicBool = AtomicBool::new(false);
        static SLEPT: AtomicU64 = AtomicU64::new(u64::MAX);
        static LEFT: AtomicUsize = AtomicUsize::new(0);
        isolated(|| {
            let worker = spawn(|| {
                let outer = patina_cancel_enter();
                ENTERED.store(true, Ordering::SeqCst);
                // Inside the sleep, before it waits: the main thread cancels.
                while !CANCELED.load(Ordering::SeqCst) {
                    crate::patina_sched_yield();
                }
                let before = monotonic();
                assert_eq!(crate::patina_sleep_until(1, before + HOUR), 0);
                SLEPT.store(monotonic() - before, Ordering::SeqCst);
                LEFT.store(patina_cancel_leave(outer) as usize, Ordering::SeqCst);
            });
            while !ENTERED.load(Ordering::SeqCst) {
                crate::patina_sched_yield();
            }
            assert_eq!(patina_thread_cancel(worker as usize), 0);
            CANCELED.store(true, Ordering::SeqCst);
            join(worker);
            assert_eq!(SLEPT.load(Ordering::SeqCst), 0, "the sleep waited");
            assert_eq!(LEFT.load(Ordering::SeqCst), ACT as usize);
        });
    }

    /// A cancel of another thread: where it reaches the thread decides
    /// whether it waits for a cancellation point, ends the thread's sleep, or
    /// stops the run.
    #[test]
    fn a_cancel_reaches_a_thread_where_the_model_can_follow_it() {
        let pending = Cancel {
            pending: true,
            ..Cancel::default()
        };
        let asleep = Cancel {
            point: Some(0),
            ..pending
        };
        let sleep: &[WaiterLoc] = &[];
        let pipe = [WaiterLoc::PipeRecv(1)];
        let mutex = [WaiterLoc::Mutex(1)];
        let refused = |reach: Reach| matches!(reach, Reach::Refuse(_));
        // Runnable, outside any point: it acts at its next one.
        assert_eq!(reach(pending, 0, None), Reach::Pending);
        // Disabled: nothing acts.
        let disabled = Cancel {
            disabled: true,
            ..asleep
        };
        assert_eq!(
            reach(disabled, 0, Some((BlockClass::Sleep, sleep))),
            Reach::Pending
        );
        // Blocked in a wait that is no cancellation point.
        assert_eq!(
            reach(pending, 0, Some((BlockClass::Sync, &mutex))),
            Reach::Pending
        );
        // Blocked in a cancellation point the model does not act at.
        assert!(refused(reach(pending, 0, Some((BlockClass::Io, &pipe)))));
        // Asleep in its own sleep: the wait ends and the sleep acts.
        assert_eq!(
            reach(asleep, 0, Some((BlockClass::Sleep, sleep))),
            Reach::Wake
        );
        // Inside the sleep's entry, before it waits.
        assert_eq!(reach(asleep, 0, None), Reach::Pending);
        // A signal handler runs inside the sleep: runnable, or waiting in any
        // wait of its own, a sleep's included.
        assert!(refused(reach(asleep, 1, None)));
        assert!(refused(reach(asleep, 1, Some((BlockClass::Sleep, sleep)))));
        assert!(refused(reach(asleep, 1, Some((BlockClass::Sync, &mutex)))));
        // Asynchronous: it would act wherever the thread is.
        let asynchronous = Cancel {
            asynchronous: true,
            ..pending
        };
        assert!(refused(reach(asynchronous, 0, None)));
    }

    /// A mutex, reader/writer lock, futex or semaphore wait is no
    /// cancellation point; a condition wait, a join and the I/O waits are.
    #[test]
    fn only_glibc_cancellation_points_are_cancellable_waits() {
        let cases = [
            (BlockClass::Sync, vec![WaiterLoc::Mutex(1)], false),
            (BlockClass::Sync, vec![WaiterLoc::RwWrite(1)], false),
            (BlockClass::Sync, vec![WaiterLoc::Cond(1, 2)], true),
            (BlockClass::Sync, vec![WaiterLoc::Join(TaskId(3))], true),
            (
                BlockClass::Ipc,
                vec![WaiterLoc::Ipc(ipc::IpcWait::Sem(1))],
                false,
            ),
            (
                BlockClass::Ipc,
                vec![WaiterLoc::Ipc(ipc::IpcWait::MsgRecv(1))],
                true,
            ),
            (BlockClass::Futex, vec![WaiterLoc::Futex(8)], false),
            (BlockClass::Io, vec![WaiterLoc::PipeRecv(1)], true),
            (BlockClass::Sleep, vec![], false),
        ];
        for (index, (class, locs, point)) in cases.into_iter().enumerate() {
            assert_eq!(cancellation_point(class, &locs), point, "case {index}");
        }
    }
}
