use super::*;

#[derive(Clone)]
pub(in crate::thread) struct Blocked {
    pub class: BlockClass,
    pub locs: Vec<WaiterLoc>,
    pub wanted: u64,
    pub reason: &'static str,
    pub deadline: Option<(ClockKind, u64)>,
}

impl ThreadRuntime {
    /// Interrupt one consumer, then independently notify readable signalfd
    /// reactors. A notification never marks a second task Interrupted.
    pub(super) fn prepare_signal_wakes(
        &mut self,
        instance: Instance,
        chosen: Option<TaskId>,
    ) -> Vec<TaskId> {
        let chosen = chosen.filter(|task| {
            self.signals.blocked.get(task).is_some_and(|wait| {
                wait.class != BlockClass::Sync
                    || wait
                        .locs
                        .iter()
                        .any(|loc| self.table.still_waiting(*task, *loc))
            })
        });
        let mut wakes = std::collections::BTreeSet::new();
        if let Some(task) = chosen {
            let blocked = &self.signals.blocked[&task];
            debug_assert!(
                !matches!(blocked.class, BlockClass::Sleep | BlockClass::TimedFutex)
                    || blocked.deadline.is_some()
            );
            if self.signals.mask(task) & bit(instance.sig) == 0
                && !(blocked.wanted & bit(instance.sig) != 0)
            {
                self.signals.interrupted.insert(
                    task,
                    Interrupt {
                        instance,
                        class: blocked.class,
                        sync_wait: (blocked.class == BlockClass::Sync).then(|| blocked.clone()),
                    },
                );
            }
            wakes.insert(task);
        }
        for fd in self.signals.signalfds.values() {
            for &task in fd.waiters.iter() {
                if self
                    .signals
                    .blocked
                    .get(&task)
                    .is_some_and(|blocked| blocked.class == BlockClass::Readiness)
                    && self.signals.pending(task) & fd.mask != 0
                {
                    wakes.insert(task);
                }
            }
        }
        // Unlink syscall registrations before tasks become runnable; Sync queue
        // ownership is retained below. Scheduler wake cancels the old timer.
        for &task in &wakes {
            if self
                .signals
                .blocked
                .get(&task)
                .is_some_and(|blocked| blocked.class == BlockClass::Sync)
            {
                // Non-EINTR pthread waits keep FIFO position and cond→mutex
                // handoffs while a handler executes. Only the scheduler park is
                // interrupted; an ordinary grant marks completion exactly once.
                self.table.threads.get_mut(&task).unwrap().signal_resume = Some(false);
                self.signals.blocked.remove(&task);
            } else {
                self.remove_wait(task);
            }
        }
        wakes.into_iter().collect()
    }

    pub(in crate::thread) fn register_signal_wait(
        &mut self,
        task: TaskId,
        reason: &'static str,
        wait: Wait,
        deadline: Option<(ClockKind, u64)>,
    ) {
        self.signals.blocked.insert(
            task,
            Blocked {
                class: wait.class,
                locs: wait.locs,
                wanted: wait.wanted,
                deadline,
                reason,
            },
        );
    }
}

impl ThreadRuntime {
    /// Under a trap handler's hold delivery waits for its exit, so a wait
    /// must not park on a signal already deliverable to it (the kernel's
    /// `signal_pending` before it sleeps). Answers whether `me`'s wait, just
    /// registered, ends at once instead: interrupted as a signal would
    /// interrupt it, for its resume to settle.
    pub(in crate::thread) fn interrupt_before_park(&mut self, me: TaskId) -> bool {
        if !crate::panic_boundary::exit_owned() {
            return false;
        }
        // What comes due by now is pending before the wait parks, as a
        // delivery point before it would have found it. A timer that
        // interrupts this wait already ended it.
        let wakes = self
            .fire_timers()
            .unwrap_or_else(|errno| fatal(&format!("firing the timers failed ({errno})")));
        let mut scheduler = RealScheduler;
        for task in wakes.into_iter().filter(|task| *task != me) {
            self.remove_wait(task);
            if let Err(message) = scheduler.wake(task) {
                fatal(&message);
            }
        }
        if self.signals.interrupted.contains_key(&me) {
            return true;
        }
        let Some(blocked) = self.signals.blocked.get(&me) else {
            return false;
        };
        // Pthread waits keep their registration while a handler runs.
        if blocked.class == BlockClass::Sync {
            return false;
        }
        let class = blocked.class;
        let Some(sig) = self.signals.first_deliverable(me, blocked.wanted) else {
            return false;
        };
        self.signals.interrupted.insert(
            me,
            Interrupt {
                instance: Instance {
                    seq: 0,
                    sig,
                    info: Info::kernel(sig),
                },
                class,
                sync_wait: None,
            },
        );
        self.remove_wait(me);
        true
    }
}

pub(in crate::thread) fn take_sync_resume(task: TaskId) -> Option<Blocked> {
    let mut state = lock_state();
    if state
        .signals
        .interrupted
        .get(&task)
        .is_some_and(|interrupt| interrupt.class == BlockClass::Sync)
    {
        state.signals.interrupted.remove(&task).unwrap().sync_wait
    } else {
        None
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Resumed {
    Normal,
    Restart,
    Eintr,
}

/// Consume one resume outcome and deliver before applying the syscall restart rule.
pub(crate) fn resume() -> Resumed {
    resume_with(|_| {})
}

/// [`resume`] for a wait with a timeout when `timed` (a socket's
/// `SO_RCVTIMEO`/`SO_SNDTIMEO`, `sock_intr_errno`): never restarted.
pub(crate) fn resume_timed(timed: bool) -> Resumed {
    resume_policy(!timed, |_| {})
}

/// A signal wait a deliverable signal ended (`EINTR`): delivered here, or
/// under a trap handler's hold by its exit; a suspension's mask is restored
/// after, and its first frame saves the mask it restores (`old`, the mask
/// `wanted` stood in for).
fn interrupted(me: TaskId, mode: WaitMode, old: u64, wanted: u64) -> i64 {
    if mode != WaitMode::Suspend {
        deliver();
    } else if crate::panic_boundary::exit_owned() {
        file_temporary_mask(old, wanted);
    } else {
        deliver_saving(old);
        install_mask(old);
        lock_state().signals.tasks.get_mut(&me).unwrap().mask = old;
    }
    -i64::from(EINTR)
}

/// The resume of a blocking call is a delivery point: a signal that came
/// pending while the task waited without interrupting it (one generated as
/// its own deadline ended the wait, or after a wake) is delivered before the
/// call returns, as the kernel delivers on the way back to user space. The
/// call's result is settled first: `before_delivery` reads it, given the
/// resume's outcome, before any handler runs.
pub(in crate::thread) fn resume_with(before_delivery: impl FnOnce(Resumed)) -> Resumed {
    resume_policy(true, before_delivery)
}

/// [`resume_with`], where `restartable` says whether `SA_RESTART` may restart
/// the wait at all. Under a trap handler's hold nothing is delivered here: a
/// restart is asked of the trap's exit ([`file_restart`]) and the call answers
/// `EINTR` meanwhile, which the exit runs again once it delivered.
fn resume_policy(restartable: bool, before_delivery: impl FnOnce(Resumed)) -> Resumed {
    let me = current_task();
    let outcome = {
        let mut state = lock_state();
        state.remove_wait(me);
        let Some(interrupt) = state.signals.interrupted.remove(&me) else {
            drop(state);
            before_delivery(Resumed::Normal);
            deliver();
            return Resumed::Normal;
        };
        let restart =
            matches!(
                interrupt.class,
                BlockClass::Io | BlockClass::Futex | BlockClass::SignalfdRead
            ) && state.signals.actions[interrupt.instance.sig as usize].flags & SA_RESTART != 0;
        if restart && restartable {
            Resumed::Restart
        } else {
            Resumed::Eintr
        }
    };
    before_delivery(outcome);
    if crate::panic_boundary::exit_owned() {
        if outcome == Resumed::Restart {
            file_restart();
            return Resumed::Eintr;
        }
        return outcome;
    }
    deliver();
    outcome
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Timespec {
    pub sec: i64,
    pub nsec: i64,
}

#[allow(dead_code)]
mod plain_impls {
    #![deny(clippy::undocumented_unsafe_blocks)]

    crate::plain!(super::Timespec {
        sec: i64,
        nsec: i64
    });
}

#[repr(i32)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum WaitMode {
    Dequeue = 0,
    Suspend = 1,
    Pause = 2,
}

#[unsafe(no_mangle)]
/// Wait/dequeue entry shared by pause, suspend, and timed signal waits.
/// # Safety
/// Pointers must be valid kernel-layout mask, info, and timespec buffers.
pub unsafe extern "C" fn patina_signal_wait(
    set: *const u64,
    info: *mut Info,
    timeout: *const Timespec,
    size: usize,
    mode: WaitMode,
) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if size != SIGSET_BYTES {
        return -i64::from(EINVAL);
    }
    // `rt_sigsuspend`/`rt_sigtimedwait` copy the set in, then the timeout.
    let wanted = if mode == WaitMode::Pause {
        0
    } else {
        match crate::uaccess::read::<u64>(set as usize) {
            Ok(set) => set,
            Err(_) => return -i64::from(EFAULT),
        }
    };
    let timeout = if timeout.is_null() {
        None
    } else {
        match crate::uaccess::read::<Timespec>(timeout as usize) {
            Ok(timeout) => Some(timeout),
            Err(_) => return -i64::from(EFAULT),
        }
    };
    let me = activate();
    let old = with_segv(read_mask());
    lock_state().signals.tasks.get_mut(&me).unwrap().mask = old;
    // The suspension's SIGSEGV block is its mask's, until it returns.
    let mut scope = Scoped::new();
    if mode == WaitMode::Suspend {
        scope.open();
        set_segv(wanted);
        install_mask(wanted);
        lock_state().signals.tasks.get_mut(&me).unwrap().mask = with_segv(host_mask(wanted));
    }
    let deadline = if let Some(timeout) = timeout {
        if timeout.sec < 0 || !(0..1_000_000_000).contains(&timeout.nsec) {
            return -i64::from(EINVAL);
        }
        let now = with_context_raw(|context| context.now(ClockKind::Monotonic))
            .unwrap_or_else(|_| fatal("signal wait clock read failed"));
        Some(
            now.saturating_add((timeout.sec as u64).saturating_mul(1_000_000_000))
                .saturating_add(timeout.nsec as u64),
        )
    } else {
        None
    };
    loop {
        super::super::timers::fire_due();
        let mut state = lock_state();
        if mode == WaitMode::Dequeue
            && let Some(instance) = state.dequeue_signal(me, wanted, false)
        {
            // Dequeued: a siginfo that cannot be copied out loses it.
            if !info.is_null() && crate::uaccess::write(info as usize, &instance.info).is_err() {
                return -i64::from(EFAULT);
            }
            return i64::from(instance.sig);
        }
        if let Some(deadline) = deadline {
            let now = with_context_raw(|context| context.now(ClockKind::Monotonic))
                .unwrap_or_else(|_| fatal("signal wait clock read failed"));
            if now >= deadline {
                return -i64::from(EAGAIN);
            }
        }
        if state.signals.has_deliverable(me) {
            drop(state);
            return interrupted(me, mode, old, wanted);
        }
        let reason = match mode {
            WaitMode::Suspend => "sigsuspend",
            WaitMode::Pause => "pause",
            WaitMode::Dequeue => "signal-wait",
        };
        let class = match mode {
            WaitMode::Suspend => BlockClass::SigSuspend,
            WaitMode::Pause => BlockClass::Pause,
            WaitMode::Dequeue => BlockClass::SigWait,
        };
        let wait =
            Wait::new(class, vec![]).signals(if mode == WaitMode::Dequeue { wanted } else { 0 });
        let step = match deadline {
            Some(deadline) => state.block_timed(me, reason, wait, ClockKind::Monotonic, deadline),
            None => state.block(me, reason, wait),
        };
        match step {
            Ok(Step::Continue) => drop(state),
            Ok(Step::Switch(task)) => switch_and_park(state, task, me),
            Err(error) => {
                return -i64::from(c_int::from(error.into_posix()));
            }
        }
        let matched = {
            let mut state = lock_state();
            state.signals.blocked.remove(&me);
            let instance = state.signals.interrupted.remove(&me);
            instance.map(|interrupt| {
                mode == WaitMode::Dequeue && wanted & bit(interrupt.instance.sig) != 0
            })
        };
        if matched == Some(false) {
            return interrupted(me, mode, old, wanted);
        }
    }
}
