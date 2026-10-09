//! One CPU charge per guest call (see `patina_dst_abi::ChargeClass`).
//!
//! The shim counts a call when it takes the thread from guest code: a door's
//! outermost [`PanicScope`](crate::panic_boundary::PanicScope) entry (a system
//! call, unless the door names its [`Op`]), or a counter read the trap
//! answers. A trapped system call is classed through the same [`Op`] table,
//! so a door and the raw call it models cannot disagree. A sync-class call
//! that has to park (a contended lock) also enters the kernel natively, so it
//! is charged one system call more ([`parked`]). Glue entries the C side calls around a guest call (boundary
//! notes, cancellation brackets, trap decode and completion, thread start)
//! are not calls and are never counted. Counts accumulate per thread and are
//! flushed into the runtime at its Context gateways, attributed to the
//! thread's task. Nothing is charged for the bootstrap window (dropped when
//! the runtime is installed) or after the thread's task (or `main`) has
//! finished (flushed just before, dropped after): teardown runs in host
//! order.
//!
//! Inert for now: the runtime totals them, and nothing reads them.

use std::cell::Cell;

use patina_dst_abi::{ChargeClass, ChargeCounts};

use crate::Context;

/// The guest operations not charged as a plain system call, and the class
/// each is charged as. Doors name their operation
/// ([`PanicScope::enter_op`](crate::panic_boundary::PanicScope::enter_op));
/// a trapped system call takes the class of the operation it performs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
// On macOS only the guest archive's doors (`patina_posix_exports`) name most of
// these; Linux also classes trapped system calls through them.
#[cfg_attr(all(target_os = "macos", not(patina_posix_exports)), allow(dead_code))]
pub(crate) enum Op {
    /// A read of the virtual clock (`patina_clock_now`, the counter trap).
    ClockRead,
    /// `clock_gettime`.
    ClockGettime,
    /// `gettimeofday` (and `time`, which reads it).
    TimeOfDay,
    /// `time(2)`, a system call on x86_64 only.
    #[cfg(target_os = "linux")]
    Time,
    Getpid,
    Getppid,
    #[cfg(target_os = "linux")]
    Gettid,
    /// A mutex, rwlock, condition signal or once: user space unless it
    /// must wait.
    PthreadSync,
    /// A Darwin `os_unfair_lock`.
    #[cfg(target_os = "macos")]
    UnfairLock,
}

/// Every [`Op`], for the trapped-call lookup.
#[cfg(target_os = "linux")]
const OPS: &[Op] = &[
    Op::ClockRead,
    Op::ClockGettime,
    Op::TimeOfDay,
    Op::Time,
    Op::Getpid,
    Op::Getppid,
    Op::Gettid,
    Op::PthreadSync,
];

impl Op {
    pub(crate) const fn class(self) -> ChargeClass {
        match self {
            Op::ClockRead | Op::ClockGettime | Op::TimeOfDay => ChargeClass::Clock,
            #[cfg(target_os = "linux")]
            Op::Time => ChargeClass::Clock,
            Op::Getpid | Op::Getppid | Op::PthreadSync => ChargeClass::Sync,
            #[cfg(target_os = "linux")]
            Op::Gettid => ChargeClass::Sync,
            #[cfg(target_os = "macos")]
            Op::UnfairLock => ChargeClass::Sync,
        }
    }

    /// The system call that performs this operation, if one does.
    #[cfg(target_os = "linux")]
    fn syscall(self) -> Option<crate::registry::Syscall> {
        use crate::registry::Syscall;
        match self {
            Op::ClockGettime => Some(Syscall::N_clock_gettime),
            Op::TimeOfDay => Some(Syscall::N_gettimeofday),
            #[cfg(target_arch = "x86_64")]
            Op::Time => Some(Syscall::N_time),
            Op::Getpid => Some(Syscall::N_getpid),
            Op::Getppid => Some(Syscall::N_getppid),
            Op::Gettid => Some(Syscall::N_gettid),
            _ => None,
        }
    }
}

/// The class a trapped system call `nr` is charged as: its operation's, or a
/// system call's.
#[cfg(target_os = "linux")]
pub(crate) fn syscall_class(nr: i64) -> ChargeClass {
    OPS.iter()
        .find(|op| op.syscall().is_some_and(|call| call.number() as i64 == nr))
        .map_or(ChargeClass::Syscall, |op| op.class())
}

thread_local! {
    /// This thread's counted, not yet flushed calls, one counter per class:
    /// a door's entry pays one thread-local increment, nothing more.
    static OWED: [Cell<u64>; 3] = const { [Cell::new(0), Cell::new(0), Cell::new(0)] };
    /// The class the running call was counted as.
    static CURRENT: Cell<Option<ChargeClass>> = const { Cell::new(None) };
}

fn slot(class: ChargeClass) -> usize {
    match class {
        ChargeClass::Clock => 0,
        ChargeClass::Sync => 1,
        ChargeClass::Syscall => 2,
    }
}

/// Count one guest call of `class` on this thread.
#[inline]
pub(crate) fn count(class: ChargeClass) {
    OWED.with(|owed| {
        let counter = &owed[slot(class)];
        counter.set(counter.get().wrapping_add(1));
    });
    CURRENT.with(|current| current.set(Some(class)));
}

/// The running call parks. A sync-class call that waits enters the kernel
/// natively (a futex wait), so it is charged one system call more; every
/// other call's charge already covers its wait.
pub(crate) fn parked() {
    if CURRENT.with(|current| current.replace(None)) == Some(ChargeClass::Sync) {
        count(ChargeClass::Syscall);
        CURRENT.with(|current| current.set(None));
    }
}

fn take() -> ChargeCounts {
    let mut counts = ChargeCounts::new();
    OWED.with(|owed| {
        for class in ChargeClass::ALL {
            counts.add(class, owed[slot(class)].replace(0));
        }
    });
    counts
}

#[cfg(test)]
fn pending() -> bool {
    OWED.with(|owed| owed.iter().any(|counter| counter.get() != 0))
}

/// Hand this thread's counted calls to the runtime, charged to its task.
/// Calls a thread counts once its task (or `main`) has finished are teardown
/// in host order: they are dropped here, never charged. Allocation-free on
/// the runtime side (`Context::charge_calls`), since the counter trap
/// reaches it from a signal handler.
pub(crate) fn flush(context: &mut Context) {
    let counts = take();
    if counts.is_empty() || crate::thread::charges_silenced() {
        return;
    }
    context.charge_calls(crate::thread::charge_task(), counts);
}

/// Hand this thread's counted calls over now, before it goes silent. The
/// finalizer (`shutdown_run`) calls it before it takes the runtime away, so
/// the run's last calls are in the totals; a call counted after that is
/// teardown, like one after `main` returned, and is not charged.
pub(crate) fn flush_now() {
    let _ = crate::with_context_raw(|_| Ok(()));
}

/// Drop what this thread counted before the runtime was installed (the
/// bootstrap window, which runs before any guest code the run models).
pub(crate) fn discard() {
    let _ = take();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_trapped_call_is_classed_as_the_door_for_its_operation() {
        #[cfg(target_os = "linux")]
        for op in OPS {
            if let Some(call) = op.syscall() {
                assert_eq!(syscall_class(call.number() as i64), op.class(), "{op:?}");
            }
        }
        #[cfg(target_os = "linux")]
        assert_eq!(
            syscall_class(crate::registry::Syscall::N_read.number() as i64),
            ChargeClass::Syscall
        );
    }

    #[test]
    fn a_sync_call_that_parks_is_charged_one_system_call_more() {
        let _ = take();
        count(ChargeClass::Sync);
        parked();
        // A second park in the same call is the same wait.
        parked();
        count(ChargeClass::Syscall);
        parked();
        let counts = take();
        assert_eq!(counts.calls(ChargeClass::Sync), 1);
        assert_eq!(counts.calls(ChargeClass::Syscall), 2);
        assert!(!pending());
    }
}
