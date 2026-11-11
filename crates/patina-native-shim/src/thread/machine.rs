//! What the machine of processes (`crate::machine`) asks of this process's
//! thread runtime: to run (every process of a machine switches at the
//! scheduling points of managed tasks), to pick the task the baton goes to
//! next, and to park and wake a task waiting for a child process.

use super::*;

/// Start the thread runtime: the calling thread becomes the main task.
#[cfg_attr(not(patina_posix_exports), allow(dead_code))]
pub(crate) fn activate() -> Result<(), String> {
    lock_state().ensure_active().map_err(|error| match error {
        ThreadError::Fatal(message) => message,
        ThreadError::Posix(code) => format!("activating the thread runtime failed ({code})"),
    })
}

/// The task the baton goes to next, picked through the scheduler as any
/// pick is (timers first).
pub(crate) fn pick_next() -> TaskId {
    match lock_state().next_task() {
        Ok(Some(task)) => task,
        Ok(None) => fatal("the machine found no task to run"),
        Err(error) => fatal(&format!(
            "picking the next task failed ({})",
            c_int::from(error.into_posix())
        )),
    }
}

/// Park the calling task until a child process changes state: `register`
/// hears its task first, so [`wake_waiting`] can find it. `Err(EINTR)` when
/// a signal ended the wait.
pub(crate) fn wait_for_child(register: impl FnOnce(TaskId)) -> Result<(), c_int> {
    let mut state = lock_state();
    state
        .ensure_active()
        .map_err(|error| c_int::from(error.into_posix()))?;
    let me = current_task();
    register(me);
    match state.block(me, "wait-child", Wait::new(BlockClass::Io, vec![])) {
        Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
        Ok(Step::Continue) => drop(state),
        Err(error) => return Err(c_int::from(error.into_posix())),
    }
    if signals::resume() == signals::Resumed::Eintr {
        return Err(EINTR);
    }
    Ok(())
}

/// Wake each of `tasks` still parked in [`wait_for_child`] (one a signal
/// already woke is left alone).
pub(crate) fn wake_waiting(tasks: &[TaskId]) {
    let mut state = lock_state();
    for task in tasks {
        if state.remove_wait(*task).is_some()
            && let Err(message) = RealScheduler.wake(*task)
        {
            fatal(&message);
        }
    }
}
