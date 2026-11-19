//! Futex wait queues: supervisor state keyed by (address-space id, address), FIFO.
//! The guest's word is compared by the runtime while it holds the turn, so a wait
//! request is already atomic with the comparison; no kernel futex on guest memory.

use super::sched::{FutexKey, Sched, Wait, WakeReason};
use super::signal::MayPark;

impl Sched {
    pub fn futex_wait(
        &mut self,
        slot: usize,
        key: FutexKey,
        bitset: u32,
        deadline: Option<u64>,
        ok: MayPark,
    ) {
        self.park(slot, Wait::Futex { key, bitset }, deadline, ok);
    }

    /// Wake up to `n` waiters on `key` whose bitset intersects `bitset`, oldest first.
    pub fn futex_wake(&mut self, key: FutexKey, n: u64, bitset: u32) -> u64 {
        let Some(q) = self.futex.get(&key) else {
            return 0;
        };
        let mut wake = vec![];
        for &s in q {
            if wake.len() as u64 >= n {
                break;
            }
            if let super::sched::State::Parked {
                wait: Wait::Futex { bitset: b, .. },
                ..
            } = self.entries[s].state
            {
                if b & bitset != 0 {
                    wake.push(s);
                }
            }
        }
        for &s in &wake {
            self.make_runnable(s, WakeReason::Woken);
        }
        wake.len() as u64
    }

    /// Wake up to `n_wake` waiters on `from`, then move up to `n_requeue` of the
    /// remaining ones (in order) to the tail of `to`. Returns (woken, requeued).
    pub fn futex_requeue(
        &mut self,
        from: FutexKey,
        to: FutexKey,
        n_wake: u64,
        n_requeue: u64,
    ) -> (u64, u64) {
        let woken = self.futex_wake(from, n_wake, u32::MAX);
        if from == to {
            return (woken, 0);
        }
        let mut moved = 0;
        while moved < n_requeue {
            let Some(q) = self.futex.get_mut(&from) else {
                break;
            };
            let Some(s) = q.pop_front() else { break };
            if q.is_empty() {
                self.futex.remove(&from);
            }
            self.futex.entry(to).or_default().push_back(s);
            if let super::sched::State::Parked {
                wait: Wait::Futex { key, .. },
                ..
            } = &mut self.entries[s].state
            {
                *key = to;
            }
            moved += 1;
        }
        (woken, moved)
    }

    /// Waiters on `key`, oldest first.
    pub fn futex_waiters(&self, key: FutexKey) -> Vec<usize> {
        self.futex
            .get(&key)
            .map(|q| q.iter().copied().collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::super::sched::*;
    use super::super::signal::MayPark;

    fn sched(n: usize) -> Sched {
        let mut s = Sched::new(1, 16);
        for i in 0..n {
            s.add(i, 10 + i as i32, 2, 0);
        }
        s
    }

    #[test]
    fn fifo_wake() {
        let mut s = sched(5);
        let k = (0, 0x1000);
        for slot in [3, 1, 4, 2] {
            s.futex_wait(slot, k, u32::MAX, None, MayPark::for_test(slot));
        }
        assert_eq!(s.futex_wake(k, 2, u32::MAX), 2);
        // The two oldest waiters, whatever their slot numbers.
        assert!(s.is_runnable(3) && s.is_runnable(1));
        assert!(!s.is_runnable(4) && !s.is_runnable(2));
        assert_eq!(s.futex_waiters(k), vec![4, 2]);
        assert_eq!(s.entries[3].reply, 0);
        // A different address space with the same address is a different key.
        assert_eq!(s.futex_wake((5, 0x1000), 10, u32::MAX), 0);
        assert_eq!(s.futex_wake(k, 10, u32::MAX), 2);
        assert_eq!(s.futex_wake(k, 10, u32::MAX), 0);
    }

    #[test]
    fn bitset_wake() {
        let mut s = sched(3);
        let k = (0, 0x2000);
        s.futex_wait(0, k, 0b01, None, MayPark::for_test(0));
        s.futex_wait(1, k, 0b10, None, MayPark::for_test(1));
        assert_eq!(s.futex_wake(k, 10, 0b10), 1);
        assert!(s.is_runnable(1) && !s.is_runnable(0));
    }

    #[test]
    fn requeue() {
        let mut s = sched(6);
        let (a, b) = ((0, 0x10), (0, 0x20));
        s.futex_wait(5, b, u32::MAX, None, MayPark::for_test(5));
        for slot in [0, 1, 2, 3] {
            s.futex_wait(slot, a, u32::MAX, None, MayPark::for_test(slot));
        }
        assert_eq!(s.futex_requeue(a, b, 1, 2), (1, 2));
        assert!(s.is_runnable(0));
        assert_eq!(s.futex_waiters(a), vec![3]);
        // Requeued waiters go to the tail of b, after its own waiter, in order.
        assert_eq!(s.futex_waiters(b), vec![5, 1, 2]);
        // A wake on b now wakes them in that order, and their key moved with them.
        assert_eq!(s.futex_wake(b, 2, u32::MAX), 2);
        assert!(s.is_runnable(5) && s.is_runnable(1) && !s.is_runnable(2));
        assert!(
            matches!(s.entries[2].state, State::Parked { wait: Wait::Futex { key, .. }, .. } if key == b)
        );
    }

    #[test]
    fn timeout_vs_wake_resolved_by_order() {
        // The wake comes first (its request is handled before the deadline is reached):
        // the waiter is woken (0) and its timer is cancelled.
        let mut s = sched(2);
        let k = (0, 0x30);
        s.futex_wait(0, k, u32::MAX, Some(1_000), MayPark::for_test(0));
        assert_eq!(s.fire_due(999), 0);
        assert_eq!(s.futex_wake(k, 1, u32::MAX), 1);
        assert_eq!(s.entries[0].reply, 0);
        assert_eq!(s.next_deadline(), None);
        assert_eq!(s.fire_due(5_000), 0);
        assert_eq!(s.entries[0].woke, Some(WakeReason::Woken));

        // The deadline is due first (the supervisor fires due events before it handles
        // the next request): the waiter times out, and the later wake finds nobody.
        let mut s = sched(2);
        s.futex_wait(0, k, u32::MAX, Some(1_000), MayPark::for_test(0));
        assert_eq!(s.fire_due(1_000), 1);
        assert_eq!(s.futex_wake(k, 1, u32::MAX), 0);
        assert_eq!(s.entries[0].reply, -ETIMEDOUT);
        assert_eq!(s.entries[0].woke, Some(WakeReason::Timeout));
        assert!(s.futex_waiters(k).is_empty());
    }
}
