//! The thread runtime's lock, and the settlement of timer expiries into it.
//!
//! [`lock_state`] is the only way to take the thread runtime (the watchdog's
//! read-only `try_lock` aside): it settles the runtime's pending timer
//! expiries first, and while its [`StateGuard`] lives, every Context call this
//! thread makes runs as an embedder section, whose clock reads never advance
//! virtual time.

use super::*;

impl ThreadRuntime {
    /// Settle the runtime's timer expiries into the native wait state: unlink
    /// every task whose timed park expired from the primitive it was waiting
    /// on and flag cond/futex timeouts, in expiry order. [`lock_state`] runs
    /// this on every acquisition, so no code holding the thread runtime sees a
    /// waiter the runtime has already woken (a `FUTEX_WAKE`, requeue, cancel or
    /// signal would wake it a second time). Sections that can expire timers
    /// themselves (a park, a pick) run it again before going on.
    pub(super) fn settle_expired(&mut self) {
        if !EXPIRIES_PENDING.load(Ordering::Acquire) {
            return;
        }
        // Cleared under the Context lock, where every setter runs.
        let expired = with_context_raw(|context| {
            EXPIRIES_PENDING.store(false, Ordering::Release);
            Ok(context.take_expired_timeouts())
        })
        .unwrap_or_else(|_| {
            // No Context (finalized): nothing is left to settle.
            EXPIRIES_PENDING.store(false, Ordering::Release);
            Vec::new()
        });
        for task in expired {
            self.mark_timed_out(task);
        }
    }

    /// Record `me`'s wait: the one registration a timer expiry settles it
    /// through. On Linux it is the signal model's (`register_signal_wait`),
    /// which signal delivery unlinks through as well.
    pub(super) fn register_wait(
        &mut self,
        me: TaskId,
        reason: &'static str,
        wait: Wait,
        deadline: Option<(ClockKind, u64)>,
    ) {
        #[cfg(target_os = "linux")]
        self.register_signal_wait(me, reason, wait, deadline);
        #[cfg(target_os = "macos")]
        {
            let _ = (reason, deadline, wait.class);
            self.waits.insert(me, wait.locs);
        }
    }

    /// End `task`'s wait: drop its registration and unlink it from every
    /// queue the registration names. The one removal path, on every platform:
    /// a wake, a resume ([`Self::resumed`]), an expiry ([`Self::mark_timed_out`])
    /// and thread exit ([`Self::finish_wait`]) all come here. Answers the
    /// locations it was queued at, if it had a registration.
    pub(super) fn remove_wait(&mut self, task: TaskId) -> Option<Vec<WaiterLoc>> {
        #[cfg(target_os = "linux")]
        let locs = self
            .signals
            .blocked
            .remove(&task)
            .map(|blocked| blocked.locs);
        #[cfg(target_os = "macos")]
        let locs = self.waits.remove(&task);
        if let Some(locs) = &locs {
            unregister_waiters(self, task, locs);
        }
        locs
    }

    /// The resumed task's wait is over, however it ended: answers whether it
    /// was a pthread (`Sync`) wait, whose retained signal delivery the caller
    /// then runs.
    pub(super) fn resumed(&mut self, me: TaskId) -> bool {
        #[cfg(target_os = "linux")]
        let sync = self
            .signals
            .blocked
            .get(&me)
            .is_some_and(|wait| wait.class == BlockClass::Sync);
        #[cfg(target_os = "macos")]
        let sync = false;
        self.remove_wait(me);
        sync
    }

    /// A finished thread waits on nothing: drop any registration it left.
    pub(super) fn finish_wait(&mut self, task: TaskId) {
        self.remove_wait(task);
    }

    /// Whether `task` has a wait registration.
    #[cfg(test)]
    pub(super) fn has_wait(&self, task: TaskId) -> bool {
        #[cfg(target_os = "linux")]
        let registered = self.signals.blocked.contains_key(&task);
        #[cfg(target_os = "macos")]
        let registered = self.waits.contains_key(&task);
        registered
    }

    /// Settle one expired wait through its registration: unlink `task` from
    /// every queue it waits at (a condition waiter a signal moved onto its
    /// held mutex's queue included). A wait whose expiry is its result (a
    /// cond, futex, IPC or dispatch-semaphore wait) also enters `timed_out`,
    /// so it returns `ETIMEDOUT`; a socket waiter simply retries, and a bare
    /// timed sleep is on no queue at all.
    pub(super) fn mark_timed_out(&mut self, task: TaskId) {
        if self
            .remove_wait(task)
            .is_some_and(|locs| locs.iter().any(WaiterLoc::times_out))
        {
            self.timed_out.insert(task);
        }
    }
}

impl ThreadRuntime {
    /// An empty thread runtime: no tasks, nothing waiting.
    pub(super) fn new() -> Self {
        ThreadRuntime {
            table: ThreadTable::default(),
            #[cfg(target_os = "linux")]
            signals: signals::SignalRuntime::default(),
            #[cfg(target_os = "linux")]
            ipc: ipc::Ipc::default(),
            #[cfg(target_os = "linux")]
            ptys: pty::Ptys::default(),
            locks: locks::Locks::default(),
            #[cfg(target_os = "linux")]
            sched: sched::SchedRuntime::default(),
            #[cfg(target_os = "linux")]
            registrations: registrations::RegistrationRuntime::default(),
            #[cfg(target_os = "linux")]
            timers: timers::Timers::default(),
            #[cfg(target_os = "linux")]
            cancels: cancel::Cancels::default(),
            #[cfg(target_os = "linux")]
            inotify: inotify::Inotify::default(),
            handles: BTreeMap::new(),
            sems: BTreeMap::new(),
            net: NetState::new(),
            futexes: BTreeMap::new(),
            #[cfg(target_os = "linux")]
            futex_woken: BTreeMap::new(),
            timed_out: std::collections::BTreeSet::new(),
            #[cfg(target_os = "macos")]
            waits: BTreeMap::new(),
            #[cfg(target_os = "macos")]
            dispatch: BTreeMap::new(),
            #[cfg(target_os = "macos")]
            next_dispatch_handle: 1,
            active: false,
        }
    }
}

fn thread_runtime() -> &'static SpinMutex<ThreadRuntime> {
    static RUNTIME: OnceLock<SpinMutex<ThreadRuntime>> = OnceLock::new();
    RUNTIME.get_or_init(|| SpinMutex::new(ThreadRuntime::new()))
}
/// Set while the runtime holds timed-park expiries the native wait state has
/// not settled. Raised by [`note_expiries`] under the Context lock after every
/// Context call the shim makes, cleared by [`ThreadRuntime::settle_expired`].
pub(super) static EXPIRIES_PENDING: AtomicBool = AtomicBool::new(false);

/// After a Context call: publish whether it left expiries to settle. Every
/// shim Context gateway (`with_context_raw`, `with_context_msg`) calls this.
pub(crate) fn note_expiries(context: &crate::Context) {
    if context.has_expired_timeouts() {
        EXPIRIES_PENDING.store(true, Ordering::Release);
    }
}

thread_local! {
    /// How many [`StateGuard`]s this thread holds (the thread runtime lock is
    /// not reentrant, so at most one, but a counter keeps it honest).
    static SECTION: Cell<u32> = const { Cell::new(0) };
}

/// Whether this thread holds the thread runtime. The Context gateways run a
/// call made under it as an embedder section
/// ([`Context::in_embedder_section`](crate::Context::in_embedder_section)):
/// its clock reads never advance virtual time, so no expiry the section cannot
/// settle can happen while the holder is still choosing what to wake.
pub(crate) fn in_state_section() -> bool {
    SECTION.with(Cell::get) != 0
}

/// The thread runtime, held. Taking it settles the runtime's pending timer
/// expiries; while it is held, Context calls run as an embedder section.
pub(super) struct StateGuard {
    guard: SpinGuard<'static, ThreadRuntime>,
}

impl std::ops::Deref for StateGuard {
    type Target = ThreadRuntime;
    fn deref(&self) -> &ThreadRuntime {
        &self.guard
    }
}

impl std::ops::DerefMut for StateGuard {
    fn deref_mut(&mut self) -> &mut ThreadRuntime {
        &mut self.guard
    }
}

impl Drop for StateGuard {
    fn drop(&mut self) {
        SECTION.with(|depth| depth.set(depth.get() - 1));
    }
}

/// The one way to take the thread runtime (the watchdog's read-only
/// `try_lock` aside): settled on acquisition, so every wake path sees the
/// waiters the runtime's timer expiries left, and a section from then on.
pub(super) fn lock_state() -> StateGuard {
    let guard = thread_runtime().lock();
    SECTION.with(|depth| depth.set(depth.get() + 1));
    let mut state = StateGuard { guard };
    state.settle_expired();
    state
}

/// The thread runtime as it is, without settling: only for tests that prove a
/// settlement had something to do.
#[cfg(all(test, target_os = "linux"))]
pub(super) fn unsettled_state() -> SpinGuard<'static, ThreadRuntime> {
    thread_runtime().lock()
}

/// Observer lock order is the ordinary ThreadRuntime -> Context order.
/// Never wait for the guest: a busy shim is not compute-only starvation.
pub(crate) fn watchdog_observe(
    observe: impl FnOnce(&mut crate::Context, &BTreeMap<usize, TaskId>),
) {
    let Some(state) = thread_runtime().try_lock() else {
        return;
    };
    if !state.active || main_returned() {
        return;
    }
    let Some(mut slot) = crate::slot().try_lock() else {
        return;
    };
    if let Some(context) = slot.as_mut() {
        observe(context, &state.handles);
    }
}
