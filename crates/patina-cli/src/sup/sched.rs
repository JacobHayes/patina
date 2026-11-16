//! The scheduler: an ordinary struct, driven by the supervisor's request loop and
//! testable without any guest. It holds who is runnable, who waits on what, the
//! virtual-time event queue (`time.rs`), the futex queues (`futex.rs`) and the I/O
//! generation. It never reads a clock: the caller passes the virtual time.

use proto::{draw, Stream};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Futex key: (address-space id, address). The address-space id is the slot of the
/// process's first thread.
pub type FutexKey = (u64, u64);

/// What a parked thread waits for. The deadline, if any, is kept beside it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wait {
    Futex {
        key: FutexKey,
        bitset: u32,
    },
    Sleep,
    /// An `Attempt` call that would have blocked: re-attempt once the generation moved past `gen`.
    Io {
        gen: u64,
    },
    Child,
    Signal,
    Vfork,
}

/// Why a parked thread became runnable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WakeReason {
    Woken,
    Timeout,
    Signal,
    Recheck,
}

/// Events of the virtual-time queue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// The deadline of a parked thread.
    Timeout { slot: usize },
    /// A process's `ITIMER_REAL` expiry: queued in `due_timers` for the supervisor.
    SigTimer { pid: i32 },
    /// A timerfd expiry: collected in `fired_timers` for the supervisor to deliver.
    TimerFd { key: u64 },
    /// A network wire event: collected in `fired_wire` for the supervisor's wire.
    Wire { key: u64 },
}

/// Identity of a scheduled event: (time, insertion number). Unique and totally ordered.
pub type EventId = (u64, u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Free,
    Runnable,
    Parked {
        wait: Wait,
        deadline: Option<u64>,
    },
    /// Sent `ThreadExit`; the kernel task may still be finishing.
    Exiting,
}

#[derive(Clone, Debug)]
pub struct Entry {
    pub state: State,
    pub tid: i32,
    pub pid: i32,
    pub asid: u64,
    /// The pending deadline event of a parked thread.
    pub timer: Option<EventId>,
    /// Return value handed over with the turn next time this thread is picked.
    pub reply: i64,
    /// Why it last became runnable after a park.
    pub woke: Option<WakeReason>,
}

impl Entry {
    fn free() -> Entry {
        Entry {
            state: State::Free,
            tid: 0,
            pid: 0,
            asid: 0,
            timer: None,
            reply: 0,
            woke: None,
        }
    }
}

pub const ETIMEDOUT: i64 = 110;
pub const EINTR: i64 = 4;

pub struct Sched {
    pub seed: u64,
    pub entries: Vec<Entry>,
    /// Runnable slots, ordered by slot index (the picking rule depends on this order).
    pub(super) runnable: BTreeSet<usize>,
    pub(super) events: BTreeMap<EventId, Event>,
    pub(super) next_event: u64,
    pub(super) futex: BTreeMap<FutexKey, VecDeque<usize>>,
    /// Incremented whenever a call completes that can change readiness. The
    /// authoritative counter is the control region's `io.gen`; this is the supervisor's
    /// last seen value of it.
    pub io_generation: u64,
    /// Interval timers that fired, (pid, expiry), for the supervisor's signal code.
    pub due_timers: Vec<(i32, u64)>,
    /// timerfd keys whose expiry event fired, in firing order, not yet delivered.
    pub fired_timers: Vec<u64>,
    /// Wire event keys that fired, in firing order.
    pub fired_wire: Vec<u64>,
}

impl Sched {
    pub fn new(seed: u64, slots: usize) -> Sched {
        Sched {
            seed,
            entries: vec![Entry::free(); slots],
            runnable: BTreeSet::new(),
            events: BTreeMap::new(),
            next_event: 0,
            futex: BTreeMap::new(),
            io_generation: 0,
            due_timers: Vec::new(),
            fired_timers: Vec::new(),
            fired_wire: Vec::new(),
        }
    }

    /// A new thread (or process image) in `slot`, runnable.
    pub fn add(&mut self, slot: usize, tid: i32, pid: i32, asid: u64) {
        self.entries[slot] = Entry {
            state: State::Runnable,
            tid,
            pid,
            asid,
            timer: None,
            reply: 0,
            woke: None,
        };
        self.runnable.insert(slot);
    }

    pub fn is_runnable(&self, slot: usize) -> bool {
        self.runnable.contains(&slot)
    }

    pub fn runnable(&self) -> impl Iterator<Item = usize> + '_ {
        self.runnable.iter().copied()
    }

    /// The picking rule: the runnable set in slot order, `runnable[draw(Sched, seq) % len]`.
    pub fn pick(&self, seq: u64) -> Option<usize> {
        let n = self.runnable.len() as u64;
        if n == 0 {
            return None;
        }
        let i = draw(self.seed, Stream::Sched, seq) % n;
        self.runnable.iter().nth(i as usize).copied()
    }

    /// Park `slot` on `wait`, with an optional virtual deadline.
    pub fn park(&mut self, slot: usize, wait: Wait, deadline: Option<u64>) {
        self.runnable.remove(&slot);
        if let Wait::Futex { key, .. } = wait {
            self.futex.entry(key).or_default().push_back(slot);
        }
        let timer = deadline.map(|at| self.schedule(at, Event::Timeout { slot }));
        let e = &mut self.entries[slot];
        e.state = State::Parked { wait, deadline };
        e.timer = timer;
        e.woke = None;
    }

    /// Wake a parked thread. Returns false if it was not parked. Sets the reply its
    /// call will return: futex wait 0 / -ETIMEDOUT / -EINTR; sleep 0 / -EINTR; others 0.
    pub fn make_runnable(&mut self, slot: usize, reason: WakeReason) -> bool {
        let State::Parked { wait, .. } = self.entries[slot].state else {
            return false;
        };
        if let Wait::Futex { key, .. } = wait {
            self.unqueue(key, slot);
        }
        if let Some(id) = self.entries[slot].timer.take() {
            self.events.remove(&id);
        }
        let reply = match (wait, reason) {
            (_, WakeReason::Signal) => -EINTR,
            (Wait::Futex { .. }, WakeReason::Timeout) => -ETIMEDOUT,
            _ => 0,
        };
        let e = &mut self.entries[slot];
        e.state = State::Runnable;
        e.reply = reply;
        e.woke = Some(reason);
        self.runnable.insert(slot);
        true
    }

    fn unqueue(&mut self, key: FutexKey, slot: usize) {
        if let Some(q) = self.futex.get_mut(&key) {
            q.retain(|&s| s != slot);
            if q.is_empty() {
                self.futex.remove(&key);
            }
        }
    }

    /// Take `slot` out of every queue and the runnable set.
    fn detach(&mut self, slot: usize) {
        if let State::Parked {
            wait: Wait::Futex { key, .. },
            ..
        } = self.entries[slot].state
        {
            self.unqueue(key, slot);
        }
        if let Some(id) = self.entries[slot].timer.take() {
            self.events.remove(&id);
        }
        self.runnable.remove(&slot);
    }

    /// `slot` sent `ThreadExit`.
    pub fn exiting(&mut self, slot: usize) {
        self.detach(slot);
        self.entries[slot].state = State::Exiting;
    }

    /// `slot` is gone for good (its process passed the exit barrier).
    pub fn free(&mut self, slot: usize) {
        self.detach(slot);
        self.entries[slot] = Entry::free();
    }

    /// Slots of process `pid` that are not free.
    pub fn slots_of(&self, pid: i32) -> Vec<usize> {
        (0..self.entries.len())
            .filter(|&i| self.entries[i].state != State::Free && self.entries[i].pid == pid)
            .collect()
    }

    /// Threads of `pid` that have not sent `ThreadExit`.
    pub fn live_in(&self, pid: i32) -> usize {
        self.entries
            .iter()
            .filter(|e| e.pid == pid && matches!(e.state, State::Runnable | State::Parked { .. }))
            .count()
    }

    /// Threads that have not exited (runnable or parked).
    pub fn live(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| matches!(e.state, State::Runnable | State::Parked { .. }))
            .count()
    }

    /// Parked threads in slot order, with what they wait for (deadlock detail).
    pub fn parked(&self) -> Vec<(usize, &Entry, Wait, Option<u64>)> {
        let mut v = vec![];
        for (i, e) in self.entries.iter().enumerate() {
            if let State::Parked { wait, deadline } = e.state {
                v.push((i, e, wait, deadline));
            }
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sched(seed: u64, n: usize) -> Sched {
        let mut s = Sched::new(seed, 16);
        for i in 0..n {
            s.add(i, 10 + i as i32, 2, 0);
        }
        s
    }

    #[test]
    fn same_seed_same_picks() {
        let (a, b) = (sched(7, 5), sched(7, 5));
        let pa: Vec<_> = (1..200).map(|q| a.pick(q)).collect();
        let pb: Vec<_> = (1..200).map(|q| b.pick(q)).collect();
        assert_eq!(pa, pb);
        // Every runnable slot is picked at some point, and another seed picks differently.
        for i in 0..5 {
            assert!(pa.contains(&Some(i)));
        }
        let c = sched(8, 5);
        let pc: Vec<_> = (1..200).map(|q| c.pick(q)).collect();
        assert_ne!(pa, pc);
    }

    #[test]
    fn pick_follows_slot_order_and_park_state() {
        let mut s = sched(3, 4);
        s.park(1, Wait::Sleep, Some(100));
        s.park(3, Wait::Sleep, Some(200));
        for q in 0..100 {
            let p = s.pick(q).unwrap();
            assert!(p == 0 || p == 2);
            // runnable[draw % 2] over [0, 2]
            let d = draw(3, Stream::Sched, q) % 2;
            assert_eq!(p, [0, 2][d as usize]);
        }
        s.park(0, Wait::Sleep, None);
        s.park(2, Wait::Sleep, None);
        assert_eq!(s.pick(1), None);
    }
}
