//! The virtual-time event queue. Events are ordered by (time, insertion number), so
//! two events due at the same virtual time fire in the order they were scheduled.
//! Nothing here reads a clock: the supervisor owns `vclock_ns` and passes it in.

use super::sched::{Event, EventId, Sched, WakeReason};

impl Sched {
    /// Schedule `ev` at virtual time `at_ns`.
    pub fn schedule(&mut self, at_ns: u64, ev: Event) -> EventId {
        let id = (at_ns, self.next_event);
        self.next_event += 1;
        self.events.insert(id, ev);
        id
    }

    pub fn cancel(&mut self, id: EventId) -> bool {
        self.events.remove(&id).is_some()
    }

    /// Earliest pending event (`next_deadline_ns` in the control region).
    pub fn next_deadline(&self) -> Option<u64> {
        self.events.keys().next().map(|&(at, _)| at)
    }

    /// Fire every event due at or before `now`, in order. Returns how many fired.
    pub fn fire_due(&mut self, now: u64) -> usize {
        let mut n = 0;
        while let Some((&id, _)) = self.events.iter().next() {
            if id.0 > now {
                break;
            }
            let ev = self.events.remove(&id).unwrap();
            match ev {
                Event::Timeout { slot } => {
                    if self.entries[slot].timer == Some(id) {
                        self.entries[slot].timer = None;
                        self.make_runnable(slot, WakeReason::Timeout);
                    }
                }
                Event::SigTimer { pid } => self.due_timers.push((pid, id.0)),
                Event::TimerFd { key } => self.fired_timers.push(key),
                Event::Wire { key } => self.fired_wire.push(key),
            }
            n += 1;
        }
        n
    }

    /// Nothing runnable: move the clock to the earliest event and fire everything due
    /// then. Returns the new time, or None when nothing is runnable and nothing is pending
    /// (deadlock) or something is runnable (no jump needed).
    pub fn idle_jump(&mut self, now: u64) -> Option<u64> {
        if !self.runnable.is_empty() {
            return None;
        }
        let at = self.next_deadline()?;
        let t = at.max(now);
        self.fire_due(t);
        Some(t)
    }
}

#[cfg(test)]
mod tests {
    use super::super::sched::*;

    #[test]
    fn idle_jump_to_earliest_deadline() {
        let mut s = Sched::new(1, 8);
        for i in 0..3 {
            s.add(i, 10 + i as i32, 2, 0);
        }
        s.park(0, Wait::Sleep, Some(5_000));
        s.park(1, Wait::Sleep, Some(2_000));
        s.park(2, Wait::Sleep, Some(9_000));
        assert_eq!(s.next_deadline(), Some(2_000));
        assert_eq!(s.idle_jump(1_000), Some(2_000));
        assert!(s.is_runnable(1) && !s.is_runnable(0) && !s.is_runnable(2));
        assert_eq!(s.entries[1].woke, Some(WakeReason::Timeout));
        assert_eq!(s.entries[1].reply, 0); // a sleep returns 0
                                           // Something is runnable: no jump.
        assert_eq!(s.idle_jump(2_000), None);
        s.park(1, Wait::Sleep, None);
        assert_eq!(s.idle_jump(2_000), Some(5_000));
        assert!(s.is_runnable(0));
        s.park(0, Wait::Sleep, None);
        assert_eq!(s.idle_jump(5_000), Some(9_000));
        s.park(2, Wait::Sleep, None);
        // Nothing runnable, nothing pending: deadlock.
        assert_eq!(s.idle_jump(9_000), None);
        assert_eq!(s.parked().len(), 3);
    }

    #[test]
    fn same_time_events_fire_in_insertion_order() {
        let mut s = Sched::new(1, 8);
        for i in 0..3 {
            s.add(i, 10 + i as i32, 2, 0);
        }
        s.park(2, Wait::Sleep, Some(100));
        s.park(0, Wait::Sleep, Some(100));
        s.park(1, Wait::Sleep, Some(100));
        let order: Vec<_> = s
            .events
            .values()
            .map(|e| match e {
                Event::Timeout { slot } => *slot,
                Event::SigTimer { .. } => usize::MAX,
                Event::TimerFd { .. } | Event::Wire { .. } => unreachable!(),
            })
            .collect();
        assert_eq!(order, vec![2, 0, 1]);
        assert_eq!(s.fire_due(99), 0);
        assert_eq!(s.fire_due(100), 3);
        assert_eq!(s.runnable().collect::<Vec<_>>(), vec![0, 1, 2]);
    }

    #[test]
    fn wire_events_fire_in_time_order() {
        let mut s = Sched::new(1, 8);
        s.schedule(300, Event::Wire { key: 3 });
        s.schedule(100, Event::Wire { key: 1 });
        s.schedule(100, Event::Wire { key: 2 });
        s.fire_due(200);
        assert_eq!(std::mem::take(&mut s.fired_wire), vec![1, 2]);
        s.fire_due(300);
        assert_eq!(s.fired_wire, vec![3]);
    }
}
