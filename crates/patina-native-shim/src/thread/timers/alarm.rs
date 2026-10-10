//! The alarms the runtime context holds for the timers, and the change a
//! context-free transition parks for the context's next call.

use super::super::with_context_raw;
use std::cell::Cell;

/// The alarms the runtime context holds for the timers
/// (`ThreadRuntime::publish_alarm`): the earliest monotonic deadline and
/// the earliest CPU-time deadlines, all absolute.
#[derive(Clone, Copy)]
pub(super) struct AlarmUpdate {
    pub(super) deadline: Option<u64>,
    pub(super) cpu: patina_dst_runtime::CpuAlarms,
}

impl AlarmUpdate {
    pub(super) fn apply(self, context: &mut crate::Context) {
        context.set_alarm(self.deadline);
        context.set_cpu_alarms(self.cpu);
    }
}

thread_local! {
    /// An alarm change a context-free transition made under the thread
    /// runtime, for the context to take before its next call
    /// ([`apply_parked_alarm`]).
    static PARKED_ALARM: Cell<Option<AlarmUpdate>> = const { Cell::new(None) };
}

/// Keep `update` for the runtime context. The context reads its alarms only
/// within a call; every call made in a state section passes a gateway that
/// applies a parked update first, and the section's end applies one still
/// parked ([`flush_parked_alarm`]). So each call finds the alarms it would
/// have found had they been set here.
pub(super) fn park_alarm(update: AlarmUpdate) {
    PARKED_ALARM.with(|parked| parked.set(Some(update)));
}

/// Set a parked alarm change on the context, at a gateway inside a state
/// section, before the call it carries.
pub(crate) fn apply_parked_alarm(context: &mut crate::Context) {
    if let Some(update) = PARKED_ALARM.with(Cell::take) {
        update.apply(context);
    }
}

/// At the end of a state section: hand the context a still-parked alarm
/// change, through a gateway that applies it ([`apply_parked_alarm`]). A
/// panicking section drops it.
pub(in crate::thread) fn flush_parked_alarm() {
    if PARKED_ALARM.with(|parked| parked.get().is_none()) {
        return;
    }
    if std::thread::panicking() {
        PARKED_ALARM.with(|parked| parked.set(None));
        return;
    }
    let _ = with_context_raw(|_| Ok(()));
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use patina_dst_abi::ChargeClass;

    #[test]
    fn a_context_call_in_the_section_that_freed_a_timer_finds_the_alarm_it_left() {
        // Freeing a closed timer descriptor parks the alarm change. An
        // escalation later in the same section charges up to the earliest
        // deadline the context knows, so with the freed timer's deadline still
        // published it would carry the clock all the way there.
        super::super::super::signals::tests::isolated(|| {
            let deadline = now_on(Line::Monotonic).unwrap() + 10 * NANOS;
            let mut state = lock_state();
            let handle = state.timers.next_fd;
            state.timers.next_fd += 1;
            state.timers.fds.insert(
                handle,
                TimerFd {
                    realtime: false,
                    expires: deadline,
                    queued: true,
                    interval: 0,
                    ticks: 0,
                    fires: 0,
                    expired: false,
                    waiters: WaitQueue::new(),
                    open: false,
                },
            );
            state.publish_alarm();
            // Its last reader left: nothing names it, and it goes.
            state.release_closed_timerfd(handle);
            with_context_raw(|context| {
                context.escalate_call(crate::thread::charge_task(), ChargeClass::Clock)
            })
            .unwrap();
            drop(state);
            let now = with_context_raw(|context| {
                context.show_carry()?;
                context.monotonic_now_unrecorded()
            })
            .unwrap();
            assert!(
                now < deadline,
                "the clock reached the freed deadline {deadline}: {now}"
            );
        });
    }
}
