use super::*;
use crate::thread::signals::tests::*;
use std::sync::atomic::{AtomicI64, AtomicU32, Ordering};

const U32_PRIVATE: u64 = (SIZE_U32 | PRIVATE) as u64;
const U32_SHARED: u64 = SIZE_U32 as u64;
const ANY: u64 = MATCH_ANY as u64;
const SIGUSR1: i32 = 10;

/// A futex word that outlives the test's threads.
fn word() -> usize {
    Box::leak(Box::new(AtomicU32::new(0))) as *const AtomicU32 as usize
}

fn store(word: usize, value: u32) {
    // SAFETY: a word [`word`] leaked.
    unsafe { &*(word as *const AtomicU32) }.store(value, Ordering::SeqCst);
}

fn queued(word: usize) -> usize {
    lock_state().futexes.get(&word).map_or(0, VecDeque::len)
}

fn waitv(word: usize) -> Waitv {
    Waitv {
        val: 0,
        uaddr: word as u64,
        flags: U32_PRIVATE as u32,
        reserved: 0,
    }
}

/// A parked `futex_wait` whose deadline passes answers `ETIMEDOUT`, even
/// though its word changed meanwhile (the timer ended it, not the value);
/// a handler restarts it under `SA_RESTART`, where a wake then ends it with
/// 0, and ends it with `EINTR` otherwise.
#[test]
fn a_parked_futex2_wait_ends_by_its_deadline_or_its_handler() {
    isolated(|| {
        let word = word();
        let me = current_task();
        let helper = spawn(move || {
            after_others_park(me);
            store(word, 1);
        });
        let now = with_context_raw(|context| context.now(ClockKind::Monotonic)).unwrap();
        let deadline = [0, (now + 1_000) as i64];
        let timed = [
            word as u64,
            0,
            ANY,
            U32_PRIVATE,
            deadline.as_ptr() as u64,
            1,
        ];
        assert_eq!(futex_wait(timed), fail(ETIMEDOUT));
        join(helper);
        assert_eq!(queued(word), 0);
        store(word, 0);
        for restart in [true, false] {
            action(restart);
            let helper = spawn(move || {
                after_others_park(me);
                generate(SIGUSR1);
                if restart {
                    after_others_park(me);
                    assert_eq!(futex_wake([word as u64, ANY, 1, U32_PRIVATE, 0, 0]), 1);
                }
            });
            let answer = futex_wait([word as u64, 0, ANY, U32_PRIVATE, 0, 0]);
            assert_eq!(answer, if restart { 0 } else { fail(EINTR) });
            join(helper);
            assert_eq!(queued(word), 0);
        }
    });
}

/// A `futex_waitv` waiter is passed by a wake by the other key. One of its
/// entries requeued to a third word stays its entry there: a wake of the
/// third word answers that entry's index, and a wake of its first word
/// takes it off the third word's queue too. A negative count wakes one
/// entry, though the first word queues two of them.
#[test]
fn a_requeued_futex_waitv_entry_stays_the_waiters() {
    isolated(|| {
        let [first, second, third] = [word(), word(), word()];
        let me = current_task();
        for wake_third in [true, false] {
            let helper = spawn(move || {
                after_others_park(me);
                assert_eq!(futex_wake([second as u64, ANY, 1, U32_SHARED, 0, 0]), 0);
                let pair = [waitv(second), waitv(third)];
                assert_eq!(futex_requeue([pair.as_ptr() as u64, 0, 0, 1, 0, 0]), 1);
                assert_eq!((queued(second), queued(third)), (0, 1));
                let woken = if wake_third { third } else { first };
                assert_eq!(
                    futex_wake([woken as u64, ANY, u64::MAX, U32_PRIVATE, 0, 0]),
                    1
                );
            });
            let words = [waitv(first), waitv(second), waitv(first)];
            let index = futex_waitv([words.as_ptr() as u64, 3, 0, 0, 0, 0]);
            assert_eq!(index, if wake_third { 1 } else { 0 });
            join(helper);
            assert_eq!((queued(first), queued(second), queued(third)), (0, 0, 0));
        }
    });
}

/// A woken futex2 wait answers its own outcome even when a signal that came
/// pending after the wake runs a handler before the call returns: the
/// kernel returns the result first and runs the handler on the way out, so
/// the handler's own timed wait ends by its deadline and the woken
/// `futex_waitv` answers the index the wake unqueued.
#[test]
fn a_woken_futex2_wait_keeps_its_outcome_across_a_handler() {
    static INNER: AtomicI64 = AtomicI64::new(0);
    extern "C" fn waiting_handler(_: i32) {
        let now = with_context_raw(|context| context.now(ClockKind::Monotonic)).unwrap();
        let deadline = [0, (now + 1_000) as i64];
        let timed = [
            word() as u64,
            0,
            ANY,
            U32_PRIVATE,
            deadline.as_ptr() as u64,
            1,
        ];
        INNER.store(futex_wait(timed), Ordering::SeqCst);
    }
    isolated(|| {
        install_handler(SIGUSR1, waiting_handler, 0, 0);
        let [first, second] = [word(), word()];
        let me = current_task();
        let helper = spawn(move || {
            after_others_park(me);
            assert_eq!(futex_wake([second as u64, ANY, 1, U32_PRIVATE, 0, 0]), 1);
            generate(SIGUSR1);
        });
        let now = with_context_raw(|context| context.now(ClockKind::Monotonic)).unwrap();
        let deadline = [0, (now + 1_000_000) as i64];
        let words = [waitv(first), waitv(second)];
        let outer = [words.as_ptr() as u64, 2, 0, deadline.as_ptr() as u64, 1, 0];
        assert_eq!(futex_waitv(outer), 1);
        assert_eq!(INNER.load(Ordering::SeqCst), fail(ETIMEDOUT));
        join(helper);
    });
}

/// A multiplexed `futex` waiter shares the queues with its key and bitset: a
/// `FUTEX_WAIT_BITSET` waiter is passed by a wake of other bits from either
/// row and by a wake by the other key; `FUTEX_CMP_REQUEUE` moves it, and a
/// `FUTEX_WAKE` of count 0 still wakes one.
#[test]
fn a_multiplexed_waiter_keeps_its_key_and_bitset() {
    isolated(|| {
        let [first, second] = [word(), word()];
        let me = current_task();
        let helper = spawn(move || {
            after_others_park(me);
            assert_eq!(futex_wake([first as u64, 1, 1, U32_PRIVATE, 0, 0]), 0);
            assert_eq!(multiplexed_wake(first, true, 1, 1), 0);
            assert_eq!(multiplexed_wake(first, false, 1, MATCH_ANY), 0);
            assert_eq!(multiplexed_requeue(first, second, true, (0, 1), Some(0)), 1);
            assert_eq!(multiplexed_wake(second, true, 0, MATCH_ANY), 1);
        });
        assert_eq!(crate::thread::futex_wait(first, 0, true, 2), 0);
        join(helper);
        assert_eq!((queued(first), queued(second)), (0, 0));
    });
}
