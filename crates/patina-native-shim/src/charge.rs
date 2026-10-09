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
//! The runtime moves virtual time by what they cost, and the CPU clocks,
//! resource usage and CPU-time timers read the totals. An escalation a
//! call's poll earns is applied as that call ends ([`finish_call`]).

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
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
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
    /// A Darwin dispatch semaphore's wait or signal: user space unless the
    /// wait must block.
    #[cfg(target_os = "macos")]
    DispatchSemaphore,
}

/// Every [`Op`]: the trapped-call classing is checked against it.
#[cfg(all(test, target_os = "linux"))]
const OPS: &[Op] = &[
    Op::ClockRead,
    Op::ClockGettime,
    Op::TimeOfDay,
    #[cfg(target_arch = "x86_64")]
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
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            Op::Time => ChargeClass::Clock,
            Op::Getpid | Op::Getppid | Op::PthreadSync => ChargeClass::Sync,
            #[cfg(target_os = "linux")]
            Op::Gettid => ChargeClass::Sync,
            #[cfg(target_os = "macos")]
            Op::UnfairLock | Op::DispatchSemaphore => ChargeClass::Sync,
        }
    }

    /// The system call that performs this operation, if one does.
    #[cfg(target_os = "linux")]
    const fn syscall(self) -> Option<crate::registry::Syscall> {
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
    /// `op`'s system call number, as a pattern can name it.
    const fn number(op: Op) -> i64 {
        match op.syscall() {
            Some(call) => call.number() as i64,
            None => -1,
        }
    }
    const CLOCK_GETTIME: i64 = number(Op::ClockGettime);
    const TIME_OF_DAY: i64 = number(Op::TimeOfDay);
    #[cfg(target_arch = "x86_64")]
    const TIME: i64 = number(Op::Time);
    const GETPID: i64 = number(Op::Getpid);
    const GETPPID: i64 = number(Op::Getppid);
    const GETTID: i64 = number(Op::Gettid);
    // A jump on the number, not a search: every trapped or forwarded call
    // takes it. `a_trapped_call_is_classed_as_the_door_for_its_operation`
    // checks it against every operation in `OPS`.
    match nr {
        CLOCK_GETTIME => Op::ClockGettime.class(),
        TIME_OF_DAY => Op::TimeOfDay.class(),
        #[cfg(target_arch = "x86_64")]
        TIME => Op::Time.class(),
        GETPID => Op::Getpid.class(),
        GETPPID => Op::Getppid.class(),
        GETTID => Op::Gettid.class(),
        _ => ChargeClass::Syscall,
    }
}

thread_local! {
    /// This thread's counted, not yet flushed calls, one counter per class:
    /// a door's entry pays one thread-local increment, nothing more.
    static OWED: [Cell<u64>; 3] = const { [Cell::new(0), Cell::new(0), Cell::new(0)] };
    /// The class the innermost live guest call was counted as, until it
    /// parks ([`parked`]) or returns.
    static CURRENT: Cell<Option<ChargeClass>> = const { Cell::new(None) };
    /// An escalation the running call's poll earned, applied as the call
    /// ends ([`finish_call`]).
    static ESCALATION: Cell<bool> = const { Cell::new(false) };
}

/// The call a door's entry began ([`begin`]), handed back when it returns
/// ([`end`]): the class of the call it interrupted, if any. A handler the shim
/// runs from inside a call (at a scheduling point) makes calls of its own;
/// each gives the interrupted call its class back, so that call's wait is
/// still charged as its own. One byte (0 for none, else the class), so a C
/// frame can keep it (the trap exit's record, while handlers run).
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[must_use]
pub struct Began(u8);

impl Began {
    /// No call was running (a trap exit's record before its handlers run).
    #[cfg(target_os = "linux")]
    pub(crate) const NONE: Self = Self(0);

    fn of(outer: Option<ChargeClass>) -> Self {
        Self(outer.map_or(0, |class| slot(class) as u8 + 1))
    }

    fn outer(self) -> Option<ChargeClass> {
        ChargeClass::ALL
            .into_iter()
            .find(|class| slot(*class) as u8 + 1 == self.0)
    }
}

fn slot(class: ChargeClass) -> usize {
    match class {
        ChargeClass::Clock => 0,
        ChargeClass::Sync => 1,
        ChargeClass::Syscall => 2,
    }
}

/// Count one guest call of `class` on this thread that cannot park (the
/// counter trap's read).
#[inline]
pub(crate) fn count(class: ChargeClass) {
    OWED.with(|owed| {
        let counter = &owed[slot(class)];
        counter.set(counter.get().wrapping_add(1));
    });
}

/// Count a door's guest call of `class` and make it the running call.
#[inline]
pub(crate) fn begin(class: ChargeClass) -> Began {
    count(class);
    Began::of(CURRENT.with(|current| current.replace(Some(class))))
}

/// The running call's state, for a C wrapper that makes the call through
/// several shim entries to hold between them: `pthread_once`, whose init
/// routine runs from C between its claim and its completion. The first entry
/// hands it to the C frame and a later one continues the call with it
/// ([`resume`], [`PanicScope::resume`](crate::panic_boundary::PanicScope::resume)),
/// so the call's class, and whether its wait has paid the parked surcharge,
/// last until the C wrapper returns to the guest, whatever the guest code it
/// ran meanwhile did.
#[cfg(any(test, patina_posix_exports))]
pub(crate) fn hold() -> Began {
    Began::of(CURRENT.with(Cell::get))
}

/// Continue the held call: it is the running call again until [`end`],
/// which gives back the call it interrupted.
#[cfg(any(test, patina_posix_exports))]
pub(crate) fn resume(held: Began) -> Began {
    Began::of(CURRENT.with(|current| current.replace(held.outer())))
}

/// The running call, as guest code the shim calls from inside it (a
/// callback, a delivery's handlers) interrupts it: [`end`] gives it back
/// when that code returns.
#[inline]
pub(crate) fn interrupted() -> Began {
    Began::of(CURRENT.with(Cell::get))
}

/// The call [`begin`] began returns: the call it interrupted runs again.
#[inline]
pub(crate) fn end(began: Began) {
    CURRENT.with(|current| current.set(began.outer()));
}

/// The running call parks. A sync-class call that waits enters the kernel
/// natively (a futex wait), so it is charged one system call more, once per
/// call; every other call's charge already covers its wait.
pub(crate) fn parked() {
    // The call's escalation first, while it is still the running call.
    if let Some(class) = CURRENT.with(Cell::get) {
        finish_call(class);
    }
    if CURRENT.with(|current| current.replace(None)) == Some(ChargeClass::Sync) {
        count(ChargeClass::Syscall);
    }
}

fn take() -> ChargeCounts {
    let mut counts = ChargeCounts::new();
    OWED.with(|owed| {
        // Read before writing: most flushes find nothing new to hand over.
        if owed.iter().all(|counter| counter.get() == 0) {
            return;
        }
        for class in ChargeClass::ALL {
            counts.add(class, owed[slot(class)].replace(0));
        }
    });
    counts
}

/// This thread's counted calls, taken (for the trap exit's tests).
#[cfg(all(test, target_os = "linux"))]
pub(crate) fn taken() -> ChargeCounts {
    take()
}

#[cfg(test)]
fn pending() -> bool {
    OWED.with(|owed| owed.iter().any(|counter| counter.get() != 0))
}

/// Whether this thread's calls are teardown, never charged: its task (or
/// `main`) has finished.
pub(crate) fn silenced() -> bool {
    crate::thread::charges_silenced()
}

/// Hand this thread's counted calls to the runtime, charged to its task
/// (`Context::accrue_calls`), their time carried: a gateway may sit between
/// a wake decision and the wake, which an expiry would make stale. The door's
/// own gateway (`with_context`) shows the carried time before the door's
/// work. Calls a thread counts once its task (or `main`) has finished are
/// teardown in host order: they are dropped here, never charged.
/// Allocation-free on the runtime side, since the counter trap reaches it
/// from a signal handler.
pub(crate) fn flush(context: &mut Context) {
    let counts = take();
    if counts.is_empty() || silenced() {
        return;
    }
    context.accrue_calls(crate::thread::charge_task(), counts);
}

/// After a gateway's Context call: an escalation the call's poll earned
/// (`Context::take_poll_streak`) is this thread's to apply, as the guest
/// call that made the poll ends ([`finish_call`]).
pub(crate) fn note_streak(context: &mut Context) {
    if context.take_poll_streak() {
        ESCALATION.with(|owed| owed.set(true));
    }
}

/// Whether the running guest call owes an escalation ([`finish_call`]).
pub(crate) fn escalation_owed() -> bool {
    ESCALATION.with(Cell::get)
}

/// The running guest call, of `class`, ends (it returns, parks, or is the
/// counter trap's read): apply an escalation one of its polls earned, to
/// this thread's task, as the call's class, after all its reads
/// (`Context::escalate_call`).
pub(crate) fn finish_call(class: ChargeClass) {
    if !ESCALATION.with(|owed| owed.replace(false)) || silenced() {
        return;
    }
    // A refusal (frozen-clock churn) is fatal in the gateway itself.
    let _ = crate::with_context_raw(|context| {
        context.escalate_call(crate::thread::charge_task(), class)
    });
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

    #[cfg(target_os = "linux")]
    #[test]
    fn a_call_a_trap_holds_the_thread_for_is_charged_once() {
        use crate::charge::Op;
        use crate::panic_boundary::{PanicScope, claim, release};
        let _ = take();
        // A trapped system call, or a libc door its C thunk holds the thread
        // around: the holder's first entry is the call; what it calls, and
        // the holder's glue, are not.
        assert!(!claim(0));
        {
            let _door = PanicScope::enter_op(Op::Getpid);
            drop(PanicScope::enter());
        }
        drop(PanicScope::enter_glue());
        release();
        let counts = take();
        assert_eq!(counts.calls(ChargeClass::Sync), 1);
        assert_eq!(counts.calls(ChargeClass::Syscall), 0);
    }

    #[test]
    fn a_sync_call_that_parks_is_charged_one_system_call_more() {
        let _ = take();
        let lock = begin(ChargeClass::Sync);
        parked();
        // A second park in the same call is the same wait.
        parked();
        end(lock);
        let read = begin(ChargeClass::Syscall);
        parked();
        end(read);
        let counts = take();
        assert_eq!(counts.calls(ChargeClass::Sync), 1);
        assert_eq!(counts.calls(ChargeClass::Syscall), 2);
        assert!(!pending());
    }

    #[test]
    fn a_handlers_calls_leave_the_interrupted_calls_wait_its_own() {
        use crate::charge::Op;
        use crate::panic_boundary::PanicScope;
        let _ = take();
        {
            // A lock call delivers a handler at its scheduling point, before
            // it finds the lock contended; the handler reads the clock (as a
            // door, and through the counter trap).
            let _lock = PanicScope::enter_op(Op::PthreadSync);
            {
                let _handler = PanicScope::suspend();
                drop(PanicScope::enter_op(Op::ClockGettime));
                count(Op::ClockRead.class());
            }
            parked();
        }
        {
            // A handler run from inside a lock call raises a signal whose
            // handler `siglongjmp`s back into it: the raise never returns,
            // and the lock still parks as itself.
            let _lock = PanicScope::enter_op(Op::PthreadSync);
            {
                let _handler = PanicScope::suspend();
                std::mem::forget(PanicScope::enter());
            }
            parked();
        }
        // A call that returned no longer parks.
        parked();
        let counts = take();
        assert_eq!(counts.calls(ChargeClass::Sync), 2);
        assert_eq!(counts.calls(ChargeClass::Clock), 2);
        // Each lock's surcharge, and the abandoned raise.
        assert_eq!(counts.calls(ChargeClass::Syscall), 3);
    }

    #[test]
    fn a_once_call_held_across_its_init_routine_still_owes_its_surcharge() {
        use crate::charge::Op;
        use crate::panic_boundary::PanicScope;
        let _ = take();
        // `pthread_once`: the claim (a sync door) returns to C, which runs
        // the init routine (guest calls of its own) and then the completion,
        // whose wait for the registry is the once call's.
        let held = {
            let _claim = PanicScope::enter_op(Op::PthreadSync);
            hold()
        };
        drop(PanicScope::enter_op(Op::ClockGettime));
        {
            let _done = PanicScope::resume(held);
            parked();
        }
        // A claim that already paid its wait hands that on too.
        let held = {
            let _claim = PanicScope::enter_op(Op::PthreadSync);
            parked();
            hold()
        };
        {
            let _done = PanicScope::resume(held);
            parked();
        }
        let counts = take();
        assert_eq!(counts.calls(ChargeClass::Sync), 2);
        assert_eq!(counts.calls(ChargeClass::Clock), 1);
        assert_eq!(counts.calls(ChargeClass::Syscall), 2);
    }
}
