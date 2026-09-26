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
            for &task in &fd.waiters {
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
                self.remove_signal_wait(task);
            }
        }
        wakes.into_iter().collect()
    }

    pub(in crate::thread) fn remove_signal_wait(&mut self, task: TaskId) {
        if let Some(blocked) = self.signals.blocked.remove(&task) {
            unregister_waiters(self, task, &blocked.locs);
        }
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

/// The resume of a blocking call is a delivery point: a signal that came
/// pending while the task waited without interrupting it (one generated as
/// its own deadline ended the wait, or after a wake) is delivered before the
/// call returns, as the kernel delivers on the way back to user space. The
/// call's result is settled first: `before_delivery` reads it, given the
/// resume's outcome, before any handler runs.
pub(in crate::thread) fn resume_with(before_delivery: impl FnOnce(Resumed)) -> Resumed {
    let me = current_task();
    let outcome = {
        let mut state = lock_state();
        state.remove_signal_wait(me);
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
        if restart {
            Resumed::Restart
        } else {
            Resumed::Eintr
        }
    };
    before_delivery(outcome);
    deliver();
    outcome
}

#[repr(C)]
pub(crate) struct Timespec {
    pub sec: i64,
    pub nsec: i64,
}

#[repr(i32)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum WaitMode {
    Dequeue = 0,
    Suspend = 1,
    Pause = 2,
}

/// Wait/dequeue entry shared by pause, suspend, and timed signal waits.
/// # Safety
/// Pointers must be valid kernel-layout mask, info, and timespec buffers.
#[unsafe(no_mangle)]
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
    if set.is_null() && mode != WaitMode::Pause {
        return -i64::from(EFAULT);
    }
    let me = activate();
    let old = read_mask();
    lock_state().signals.tasks.get_mut(&me).unwrap().mask = old;
    let wanted = if set.is_null() { 0 } else { unsafe { *set } };
    if mode == WaitMode::Suspend {
        install_mask(wanted);
        lock_state().signals.tasks.get_mut(&me).unwrap().mask = host_mask(wanted);
    }
    let deadline = if timeout.is_null() {
        None
    } else {
        let timeout = unsafe { &*timeout };
        if timeout.sec < 0 || !(0..1_000_000_000).contains(&timeout.nsec) {
            return -i64::from(EINVAL);
        }
        let now = with_context_raw(|context| context.now(ClockKind::Monotonic))
            .unwrap_or_else(|_| fatal("signal wait clock read failed"));
        Some(
            now.saturating_add((timeout.sec as u64).saturating_mul(1_000_000_000))
                .saturating_add(timeout.nsec as u64),
        )
    };
    loop {
        super::super::timers::fire_due();
        let mut state = lock_state();
        if mode == WaitMode::Dequeue {
            if let Some(instance) = state.dequeue_signal(me, wanted, false) {
                if !info.is_null() {
                    unsafe {
                        info.write(instance.info);
                    }
                }
                return i64::from(instance.sig);
            }
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
            deliver();
            if mode == WaitMode::Suspend {
                install_mask(old);
                lock_state().signals.tasks.get_mut(&me).unwrap().mask = old;
            }
            return -i64::from(EINTR);
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
                return -i64::from(error.into_posix());
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
            deliver();
            if mode == WaitMode::Suspend {
                install_mask(old);
                lock_state().signals.tasks.get_mut(&me).unwrap().mask = old;
            }
            return -i64::from(EINTR);
        }
    }
}
