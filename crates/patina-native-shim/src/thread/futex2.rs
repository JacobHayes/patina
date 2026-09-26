//! The futex2 rows (kernel/futex/syscalls.c): `futex_waitv` (5.16),
//! `futex_wake`, `futex_wait` and `futex_requeue` (6.7), on the futex queues
//! the multiplexed `futex` row parks on.
//!
//! A futex2 word is 32 bits (`FUTEX2_SIZE_U32`: 6.8 implements no other
//! size), keyed by its address and its privacy: a wake by one key wakes only
//! waiters queued by the same key (`futex_match`). Every waiter carries a
//! bitset (`futex_wait`'s mask; any bit for `futex_waitv`), and a
//! `futex_wake` passes by a waiter whose bitset shares no bit with its own.
//! `futex_requeue` moves waiters to the second word's key, bitset and all.
//! `futex_waitv` queues the caller on every word of its vector at once (the
//! multi-location park every blocking row uses, interruptible by a
//! handler), answers the highest index a wake unqueued, and leaves its other
//! queues when it wakes. The multiplexed row's wakes and requeues run here
//! too ([`multiplexed_wake`], [`multiplexed_requeue`]), by the same rules.
//!
//! Deadlines are absolute, on the virtual `CLOCK_MONOTONIC` or
//! `CLOCK_REALTIME`: one already past answers `ETIMEDOUT` once every word
//! still holds its value. A handler ends a wait with `ERESTARTSYS`, so under
//! `SA_RESTART` the whole call runs again, and otherwise it is `EINTR`.
//!
//! A word's key is its address in this one process: the second address of
//! a shared mapping of the same page is another key here, where the
//! kernel's shared key (the page) would match it.

use super::*;
use linux_raw_sys::errno::{EAGAIN, EFAULT, EINTR, EINVAL, ETIMEDOUT};

/// `FUTEX2_SIZE_MASK` and `FUTEX2_SIZE_U32` (include/uapi/linux/futex.h).
const SIZE_MASK: u32 = 0x03;
const SIZE_U32: u32 = 0x02;
/// `FUTEX2_PRIVATE`.
const PRIVATE: u32 = 128;
/// `FUTEX2_VALID_MASK`: 6.8 accepts a size and `FUTEX2_PRIVATE` only.
const VALID_MASK: u32 = SIZE_MASK | PRIVATE;
/// `FUTEX_WAITV_MAX`.
const WAITV_MAX: u32 = 128;
/// `FUTEX_BITSET_MATCH_ANY`: a `futex_waitv` waiter's bitset.
const MATCH_ANY: u32 = u32::MAX;
/// The kernel's `-ERESTARTSYS`: a handler interrupted the wait, and the
/// call runs again under `SA_RESTART`. Never returned to the guest.
const ERESTARTSYS: i64 = -512;

fn fail(code: u32) -> i64 {
    -i64::from(code)
}

/// One word of a futex2 call: its address, the value it must hold and
/// whether its key is private.
#[derive(Clone, Copy)]
struct Word {
    addr: usize,
    val: u32,
    private: bool,
}

/// `struct futex_waitv`.
#[repr(C)]
#[derive(Clone, Copy)]
struct Waitv {
    val: u64,
    uaddr: u64,
    flags: u32,
    reserved: u32,
}

/// A word's flags (`futex2_to_flags`, `futex_flags_valid`): a flag outside
/// `FUTEX2_VALID_MASK` or a size other than 32 bits is `EINVAL`. Answers
/// whether the key is private.
fn privacy(flags: u32) -> Result<bool, i64> {
    if flags & !VALID_MASK != 0 || flags & SIZE_MASK != SIZE_U32 {
        return Err(fail(EINVAL));
    }
    Ok(flags & PRIVATE != 0)
}

/// `futex_validate_input`: a value or mask wider than the word is `EINVAL`.
fn fits(value: u64) -> Result<u32, i64> {
    u32::try_from(value).map_err(|_| fail(EINVAL))
}

/// `get_futex_key`: a word not naturally aligned is `EINVAL`, one outside
/// the user address space `EFAULT` (`access_ok`), and a shared key needs a
/// page the caller can read (`get_user_pages_fast`: `EFAULT`). A private
/// key reads nothing, so a wake by it names any user address.
fn key(word: &Word) -> Result<(), i64> {
    if word.addr % 4 != 0 {
        return Err(fail(EINVAL));
    }
    if !crate::uaccess::access_ok(word.addr, 4) {
        return Err(fail(EFAULT));
    }
    if !word.private && crate::uaccess::read::<u32>(word.addr).is_err() {
        return Err(fail(EFAULT));
    }
    Ok(())
}

/// `futex2_setup_timeout`: no timeout, or an absolute deadline on
/// `CLOCK_MONOTONIC` or `CLOCK_REALTIME` (another clock is `EINVAL`), copied
/// in (`EFAULT`) and a valid `timespec` (`EINVAL`).
fn deadline(timeout: usize, clockid: i32) -> Result<Option<(ClockKind, u64)>, i64> {
    if timeout == 0 {
        return Ok(None);
    }
    let clock = match clockid {
        0 => ClockKind::Realtime,
        1 => ClockKind::Monotonic,
        _ => return Err(fail(EINVAL)),
    };
    let [sec, nsec] = crate::uaccess::read::<[i64; 2]>(timeout).map_err(|_| fail(EFAULT))?;
    if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
        return Err(fail(EINVAL));
    }
    let nanos = (sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(nsec as u64);
    Ok(Some((clock, nanos)))
}

/// `futex_parse_waitv`: each entry copied in (`EFAULT`), then an unknown
/// flag or a reserved field set (`EINVAL`), its size and its value
/// ([`privacy`], [`fits`]).
fn parse(at: usize, count: usize) -> Result<Vec<Word>, i64> {
    (0..count)
        .map(|index| {
            let entry = at.wrapping_add(index * std::mem::size_of::<Waitv>());
            let waiter = crate::uaccess::read::<Waitv>(entry).map_err(|_| fail(EFAULT))?;
            if waiter.flags & !VALID_MASK != 0 || waiter.reserved != 0 {
                return Err(fail(EINVAL));
            }
            let private = privacy(waiter.flags)?;
            Ok(Word {
                addr: waiter.uaddr as usize,
                val: fits(waiter.val)?,
                private,
            })
        })
        .collect()
}

/// Run a row, again whenever a handler that asked for it (`SA_RESTART`)
/// interrupted it: the kernel restarts an `ERESTARTSYS` call from scratch.
fn restarting(row: impl Fn() -> Result<i64, i64>) -> i64 {
    loop {
        let answer = row().unwrap_or_else(|code| code);
        if answer != ERESTARTSYS {
            return answer;
        }
    }
}

/// Park the caller on every word of `words` (`futex_wait_multiple_setup`,
/// `futex_wait_setup`): once each, in order, still holds its value (`EFAULT`,
/// then `EAGAIN` for the first that does not, with nothing queued), it is
/// queued with `bitset` on each until a wake unqueues one (the highest index
/// unqueued), the deadline passes (`ETIMEDOUT`) or a handler runs
/// (`ERESTARTSYS`, `EINTR` without `SA_RESTART`). A resume that is none of
/// these queues it again.
fn wait_on(
    words: &[Word],
    bitset: u32,
    deadline: Option<(ClockKind, u64)>,
    reason: &'static str,
) -> i64 {
    loop {
        let mut state = lock_state();
        if let Err(error) = state.ensure_active() {
            return -i64::from(error.into_posix());
        }
        for word in words {
            match crate::uaccess::read::<u32>(word.addr) {
                Ok(current) if current == word.val => {}
                Ok(_) => return fail(EAGAIN),
                Err(_) => return fail(EFAULT),
            }
        }
        if let Some((clock, at)) = deadline {
            match with_context_raw(|context| context.now(clock)) {
                Ok(now) if now >= at => return fail(ETIMEDOUT),
                Ok(_) => {}
                Err(code) => return -i64::from(code),
            }
        }
        let me = current_task();
        for (slot, word) in (0..).zip(words) {
            state.queue_futex_waiter(
                word.addr,
                FutexWaiter {
                    task: me,
                    bitset,
                    private: word.private,
                    slot: Some(slot),
                },
            );
        }
        let locs = words.iter().map(|word| WaiterLoc::Futex(word.addr));
        let wait = Wait::new(BlockClass::Futex, locs.collect());
        let step = match deadline {
            Some((clock, at)) => state.block_timed(me, reason, wait, clock, at),
            None => state.block(me, reason, wait),
        };
        match step {
            Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
            Ok(Step::Continue) => drop(state),
            Err(error) => {
                state.remove_signal_wait(me);
                return -i64::from(error.into_posix());
            }
        }
        // The outcome is read before a pending handler runs: the kernel
        // returns it first, and a handler's own futex2 wait must not take it.
        let (mut woken, mut timed_out) = (None, false);
        let resumed = signals::resume_with(|_| {
            let mut state = lock_state();
            (woken, timed_out) = (state.futex_woken.remove(&me), state.timed_out.remove(&me));
        });
        if let Some(slot) = woken {
            return i64::from(slot);
        }
        if timed_out {
            return fail(ETIMEDOUT);
        }
        match resumed {
            signals::Resumed::Restart => return ERESTARTSYS,
            signals::Resumed::Eintr => return fail(EINTR),
            signals::Resumed::Normal => {}
        }
    }
}

/// `futex_wait(uaddr, val, mask, flags, timeout, clockid)`: the flags, the
/// value and mask (each [`fits`]), the deadline ([`deadline`]), an empty
/// mask (`EINVAL`) and the key ([`key`]), then the wait ([`wait_on`]): 0
/// once woken.
pub(crate) fn futex_wait(a: [u64; 6]) -> i64 {
    restarting(|| {
        let private = privacy(a[3] as u32)?;
        let val = fits(a[1])?;
        let bitset = fits(a[2])?;
        let deadline = deadline(a[4] as usize, a[5] as i32)?;
        if bitset == 0 {
            return Err(fail(EINVAL));
        }
        let word = Word {
            addr: a[0] as usize,
            val,
            private,
        };
        key(&word)?;
        Ok(wait_on(&[word], bitset, deadline, "futex-wait"))
    })
}

/// `futex_wake(uaddr, mask, nr, flags)`: the flags, the mask ([`fits`], and
/// not empty: `EINVAL`), the key ([`key`]); then no count wakes nobody, and
/// otherwise the first waiters by the word's key whose bitset shares a bit
/// with the mask are woken, as many as `nr`, or one when it is negative
/// (`++ret >= nr_wake`). Answers how many.
pub(crate) fn futex_wake(a: [u64; 6]) -> i64 {
    let row = || {
        let private = privacy(a[3] as u32)?;
        let bitset = fits(a[1])?;
        if bitset == 0 {
            return Err(fail(EINVAL));
        }
        let word = Word {
            addr: a[0] as usize,
            val: 0,
            private,
        };
        key(&word)?;
        let nr = a[2] as i32;
        if nr == 0 {
            return Ok(0);
        }
        Ok(wake(&word, bitset, usize::try_from(nr).unwrap_or(1)))
    };
    row().unwrap_or_else(|code| code)
}

/// Wake, in queue order, up to `limit` waiters by `word`'s key whose bitset
/// shares a bit with `bitset` (`futex_wake`'s loop). Answers how many.
fn wake(word: &Word, bitset: u32, limit: usize) -> i64 {
    let mut state = lock_state();
    let woken = state.take_futex_waiters(word.addr, limit, |waiter| {
        waiter.private == word.private && waiter.bitset & bitset != 0
    });
    state.wake_futex_waiters(&woken);
    woken.len() as i64
}

/// The multiplexed row's `FUTEX_WAKE` (any bit) and `FUTEX_WAKE_BITSET`:
/// an empty bitset is `EINVAL`, then the key ([`key`]) and [`wake`]. The
/// row is not `FLAGS_STRICT`, so `++ret >= nr_wake` wakes one for a count
/// of 0 or below.
pub(crate) fn multiplexed_wake(addr: usize, private: bool, nr: i32, bitset: u32) -> i64 {
    let word = Word {
        addr,
        val: 0,
        private,
    };
    if bitset == 0 {
        return fail(EINVAL);
    }
    if let Err(code) = key(&word) {
        return code;
    }
    wake(&word, bitset, usize::try_from(nr).map_or(1, |nr| nr.max(1)))
}

/// `futex_requeue(waiters, flags, nr_wake, nr_requeue)`: a flag or a NULL
/// vector is `EINVAL`, then the two entries ([`parse`]), then [`requeue`]
/// against the first entry's value.
pub(crate) fn futex_requeue(a: [u64; 6]) -> i64 {
    let row = || {
        if a[1] as u32 != 0 || a[0] == 0 {
            return Err(fail(EINVAL));
        }
        let words = parse(a[0] as usize, 2)?;
        requeue(words[0], words[1], (a[2] as i32, a[3] as i32), true)
    };
    row().unwrap_or_else(|code| code)
}

/// The multiplexed row's `FUTEX_REQUEUE` and `FUTEX_CMP_REQUEUE` (with a
/// `cmpval`): [`requeue`] with both words by the op's key.
pub(crate) fn multiplexed_requeue(
    from: usize,
    to: usize,
    private: bool,
    counts: (i32, i32),
    cmpval: Option<u32>,
) -> i64 {
    let word = |addr, val| Word { addr, val, private };
    let (from, to) = (word(from, cmpval.unwrap_or(0)), word(to, 0));
    requeue(from, to, counts, cmpval.is_some()).unwrap_or_else(|code| code)
}

/// `futex_requeue`: a negative count is `EINVAL`, then both keys ([`key`]);
/// when `compare`, the first word must still hold `from`'s value (`EFAULT`,
/// `EAGAIN`). Then the first word's waiters by its key, in order:
/// `nr_wake` of them are woken whatever their bitset, and the next
/// `nr_requeue` move to the second word's key. Answers how many were woken
/// or moved.
fn requeue(from: Word, to: Word, counts: (i32, i32), compare: bool) -> Result<i64, i64> {
    let (nr_wake, nr_requeue) = counts;
    if nr_wake < 0 || nr_requeue < 0 {
        return Err(fail(EINVAL));
    }
    key(&from)?;
    key(&to)?;
    let mut state = lock_state();
    if compare {
        match crate::uaccess::read::<u32>(from.addr) {
            Ok(current) if current == from.val => {}
            Ok(_) => return Err(fail(EAGAIN)),
            Err(_) => return Err(fail(EFAULT)),
        }
    }
    let by_key = |waiter: &FutexWaiter| waiter.private == from.private;
    let woken = state.take_futex_waiters(from.addr, nr_wake as usize, by_key);
    let moved = if from.addr == to.addr {
        state.rekey_futex_waiters(from.addr, nr_requeue as usize, by_key, to.private)
    } else {
        let moved = state.take_futex_waiters(from.addr, nr_requeue as usize, by_key);
        for waiter in &moved {
            state.move_futex_waiter(*waiter, from.addr, to);
        }
        moved.len()
    };
    state.wake_futex_waiters(&woken);
    Ok((woken.len() + moved) as i64)
}

/// `futex_waitv(waiters, nr_futexes, flags, timeout, clockid)`: a flag, no
/// entries, more than `FUTEX_WAITV_MAX` or a NULL vector is `EINVAL`, then
/// the deadline ([`deadline`]), the entries ([`parse`]) and every key
/// ([`key`]), then the wait on all of them ([`wait_on`]): the index woken.
pub(crate) fn futex_waitv(a: [u64; 6]) -> i64 {
    restarting(|| {
        let (at, count) = (a[0] as usize, a[1] as u32);
        if a[2] as u32 != 0 || count == 0 || count > WAITV_MAX || at == 0 {
            return Err(fail(EINVAL));
        }
        let deadline = deadline(a[3] as usize, a[4] as i32)?;
        let words = parse(at, count as usize)?;
        for word in &words {
            key(word)?;
        }
        Ok(wait_on(&words, MATCH_ANY, deadline, "futex-waitv"))
    })
}

impl ThreadRuntime {
    /// Give the first `limit` waiters on `addr` that `matches` accepts the
    /// private key `private` or not, in place (`requeue_futex` onto the
    /// same word). Answers how many.
    fn rekey_futex_waiters(
        &mut self,
        addr: usize,
        limit: usize,
        matches: impl Fn(&FutexWaiter) -> bool,
        private: bool,
    ) -> usize {
        let Some(queue) = self.futexes.get_mut(&addr) else {
            return 0;
        };
        let mut moved = 0;
        for waiter in queue.iter_mut() {
            if moved < limit && matches(waiter) {
                waiter.private = private;
                moved += 1;
            }
        }
        moved
    }

    /// Queue an unqueued `waiter` by `to`'s key instead of `from`'s
    /// (`requeue_futex`), and move its place in its task's wait with it, so
    /// the wake that ends that wait (by any of its words) unqueues it there.
    /// Every queued waiter's task is waiting: one that is not is a broken
    /// queue, a named fatal rather than a waiter silently lost.
    fn move_futex_waiter(&mut self, waiter: FutexWaiter, from: usize, to: Word) {
        let Some(blocked) = self.signals.blocked.get_mut(&waiter.task) else {
            fatal("futex requeue: a queued waiter's task is not waiting");
        };
        if let Some(loc) = blocked
            .locs
            .iter_mut()
            .find(|loc| matches!(loc, WaiterLoc::Futex(addr) if *addr == from))
        {
            *loc = WaiterLoc::Futex(to.addr);
        }
        self.queue_futex_waiter(
            to.addr,
            FutexWaiter {
                private: to.private,
                ..waiter
            },
        );
    }
}

#[cfg(test)]
mod tests;
