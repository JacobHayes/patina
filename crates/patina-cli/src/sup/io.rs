//! Blocking I/O in the supervisor.
//!
//! - `Park`: a thread whose non-blocking attempt would have waited parks on the global
//!   I/O generation. The generation lives in the control region (`Ctl::io.gen`): the
//!   runtime of the thread holding the turn increments it after any call that can change
//!   readiness, and the supervisor increments it at timerfd expiries. Whenever the
//!   supervisor sees it moved, every I/O waiter becomes runnable and re-attempts. No wait
//!   lists per object: the spurious re-attempts are counted instead.
//! - The `Park` request carries the generation the runtime saw *before* its attempt: if
//!   it moved in between (a timer delivered by the supervisor while handling this very
//!   request), the thread is not parked but re-attempts at once. That closes the only
//!   window in which a change could be missed.
//! - timerfd: the guest's descriptor is an eventfd made by the runtime; the supervisor
//!   holds a duplicate (`pidfd_getfd`) and writes the expiry count at virtual expiry.

use super::sched::{Event, EventId, Sched, State, Wait, WakeReason};
use proto::ctl::*;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::Ordering::*;

/// What a parked thread was attempting (for the deadlock detail).
#[derive(Clone, Copy, Debug)]
pub struct ParkInfo {
    pub fd: i64,
    pub dir: u64,
    pub nr: u64,
    pub nfds: u64,
}

struct TimerFd {
    /// The supervisor's duplicate of the guest's eventfd.
    fd: i32,
    /// Next expiry (virtual monotonic ns), None when disarmed.
    next: Option<u64>,
    interval: u64,
    event: Option<EventId>,
    /// Processes holding a descriptor of it (`fork` copies descriptors).
    holders: BTreeSet<i32>,
}

#[derive(Default)]
pub struct Io {
    waiters: BTreeSet<usize>,
    info: BTreeMap<usize, ParkInfo>,
    /// Keyed by the eventfd's virtual inode number (the same in every process).
    timers: BTreeMap<u64, TimerFd>,
}

fn bump(ctl: &Ctl) {
    ctl.io.gen.store(ctl.io.gen.load(Relaxed) + 1, Relaxed);
}

fn inc(c: &std::sync::atomic::AtomicU64) {
    c.store(c.load(Relaxed) + 1, Relaxed);
}

impl Io {
    /// `Park` from `idx`. Returns `Some(ret)` when the caller continues at once (the
    /// generation moved since its attempt, or the deadline has passed), None when parked.
    pub fn park(
        &mut self,
        sched: &mut Sched,
        ctl: &Ctl,
        idx: usize,
        a: [u64; 6],
        now: u64,
    ) -> Option<i64> {
        inc(&ctl.io.parks);
        let cur = ctl.io.gen.load(Relaxed);
        if cur != a[0] {
            return Some(0);
        }
        let deadline = if a[1] == NO_DEADLINE {
            None
        } else {
            Some(a[1])
        };
        if deadline.is_some_and(|d| d <= now) {
            return Some(0);
        }
        sched.park(idx, Wait::Io { gen: cur }, deadline);
        self.waiters.insert(idx);
        self.info.insert(
            idx,
            ParkInfo {
                fd: a[2] as i64,
                dir: a[3],
                nr: a[4],
                nfds: a[5],
            },
        );
        None
    }

    /// If the generation moved, every I/O waiter becomes runnable (it re-attempts).
    pub fn sync(&mut self, sched: &mut Sched, ctl: &Ctl) {
        let g = ctl.io.gen.load(Relaxed);
        if g != sched.io_generation {
            sched.io_generation = g;
            for s in std::mem::take(&mut self.waiters) {
                match sched.entries[s].state {
                    State::Parked {
                        wait: Wait::Io { gen },
                        ..
                    } if gen < g => {
                        sched.make_runnable(s, WakeReason::Recheck);
                    }
                    State::Parked {
                        wait: Wait::Io { .. },
                        ..
                    } => {
                        self.waiters.insert(s);
                    }
                    _ => {}
                }
            }
        }
        self.refresh(sched, ctl);
    }

    /// Forget waiters that are no longer parked on I/O (deadline, signal, exit) and
    /// publish the count the runtime looks at.
    pub fn refresh(&mut self, sched: &Sched, ctl: &Ctl) {
        self.waiters.retain(|&s| {
            matches!(
                sched.entries[s].state,
                State::Parked {
                    wait: Wait::Io { .. },
                    ..
                }
            )
        });
        let w = &self.waiters;
        self.info.retain(|s, _| w.contains(s));
        ctl.io.waiters.store(self.waiters.len() as u64, Relaxed);
    }

    pub fn describe(&self, slot: usize) -> String {
        match self.info.get(&slot) {
            Some(p) => {
                let dir = match p.dir {
                    PARK_IN => "in",
                    PARK_OUT => "out",
                    PARK_LOCK => "lock",
                    PARK_OPEN => "open",
                    _ => "?",
                };
                format!(
                    " fd={} dir={dir} call={} nfds={}",
                    p.fd,
                    proto::table::name(p.nr),
                    p.nfds
                )
            }
            None => String::new(),
        }
    }

    /// `TimerFdSet` from a thread of process `pid`.
    pub fn timer_set(&mut self, sched: &mut Sched, pid: i32, a: [u64; 6]) -> i64 {
        let key = a[1];
        match a[0] {
            TFD_CREATE => {
                let fd = match getfd(pid, a[2] as i32) {
                    Ok(fd) => fd,
                    Err(e) => return -(e.raw_os_error().unwrap_or(libc::EIO) as i64),
                };
                let holders = BTreeSet::from([pid]);
                if let Some(old) = self.timers.insert(
                    key,
                    TimerFd {
                        fd,
                        next: None,
                        interval: 0,
                        event: None,
                        holders,
                    },
                ) {
                    release(sched, old);
                }
                0
            }
            TFD_ARM => {
                let Some(t) = self.timers.get_mut(&key) else {
                    return -(libc::EINVAL as i64);
                };
                if let Some(id) = t.event.take() {
                    sched.cancel(id);
                }
                t.interval = a[3];
                t.next = if a[2] == 0 { None } else { Some(a[2]) };
                if let Some(at) = t.next {
                    t.event = Some(sched.schedule(at, Event::TimerFd { key }));
                }
                0
            }
            TFD_RELEASE => {
                // The last descriptor in process `pid` closed: the timer lives on while another
                // process holds one.
                let gone = match self.timers.get_mut(&key) {
                    Some(t) => {
                        t.holders.remove(&pid);
                        t.holders.is_empty()
                    }
                    None => false,
                };
                if gone {
                    release(sched, self.timers.remove(&key).unwrap());
                }
                0
            }
            _ => -(libc::EINVAL as i64),
        }
    }

    /// `child` was forked from `parent`: it holds copies of the parent's descriptors.
    pub fn timers_forked(&mut self, parent: i32, child: i32) {
        for t in self.timers.values_mut() {
            if t.holders.contains(&parent) {
                t.holders.insert(child);
            }
        }
    }

    /// Process `pid` passed its exit barrier: its descriptors are closed.
    pub fn timers_exited(&mut self, sched: &mut Sched, pid: i32) {
        let gone: Vec<u64> = self
            .timers
            .iter_mut()
            .filter_map(|(k, t)| (t.holders.remove(&pid) && t.holders.is_empty()).then_some(*k))
            .collect();
        for k in gone {
            release(sched, self.timers.remove(&k).unwrap());
        }
    }

    /// `TimerFdGet`: next expiry (0 when disarmed) or interval.
    pub fn timer_get(&self, a: [u64; 6]) -> i64 {
        let Some(t) = self.timers.get(&a[0]) else {
            return -(libc::EINVAL as i64);
        };
        match a[1] {
            0 => t.next.unwrap_or(0) as i64,
            _ => t.interval as i64,
        }
    }

    /// Deliver the timer expiries that fired by `now`: add the expiry count (with overruns
    /// of periodic timers) to the eventfd, re-arm periodic timers, move the generation.
    /// Returns (key, count) per delivery, in firing order, for the decision records.
    pub fn deliver_timers(&mut self, sched: &mut Sched, ctl: &Ctl, now: u64) -> Vec<(u64, u64)> {
        let mut done = vec![];
        for key in std::mem::take(&mut sched.fired_timers) {
            let Some(t) = self.timers.get_mut(&key) else {
                continue;
            };
            let Some(next) = t.next else { continue };
            t.event = None;
            let late = now.saturating_sub(next);
            let count = if t.interval > 0 {
                1 + late / t.interval
            } else {
                1
            };
            let v = count.to_ne_bytes();
            unsafe { libc::write(t.fd, v.as_ptr() as *const _, 8) };
            if t.interval > 0 {
                let at = next + count * t.interval;
                t.next = Some(at);
                t.event = Some(sched.schedule(at, Event::TimerFd { key }));
            } else {
                t.next = None;
            }
            bump(ctl);
            done.push((key, count));
        }
        done
    }
}

fn release(sched: &mut Sched, t: TimerFd) {
    if let Some(id) = t.event {
        sched.cancel(id);
    }
    unsafe { libc::close(t.fd) };
}

/// A duplicate of descriptor `fd` of process `pid` (the supervisor is its ancestor).
fn getfd(pid: i32, fd: i32) -> std::io::Result<i32> {
    let pidfd = crate::sys::pidfd_open(pid)?;
    let r = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd, fd, 0) };
    let e = std::io::Error::last_os_error();
    unsafe { libc::close(pidfd) };
    if r < 0 {
        Err(e)
    } else {
        Ok(r as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctl() -> Vec<u64> {
        vec![0u64; CTL_HEADER_SIZE / 8]
    }

    #[test]
    fn park_and_wake_on_generation() {
        let mem = ctl();
        let c = unsafe { Ctl::at(mem.as_ptr() as *mut u8) };
        let mut s = Sched::new(1, 8);
        let mut io = Io::default();
        for i in 0..3 {
            s.add(i, 10 + i as i32, 2, 0);
        }
        // Parks at the generation it saw.
        assert_eq!(
            io.park(&mut s, c, 1, [0, NO_DEADLINE, 5, PARK_IN, 0, 1], 100),
            None
        );
        assert_eq!(
            io.park(&mut s, c, 2, [0, 500, 6, PARK_OUT, 1, 1], 100),
            None
        );
        io.refresh(&s, c);
        assert_eq!(c.io.waiters.load(Relaxed), 2);
        assert!(!s.is_runnable(1) && !s.is_runnable(2));
        // Nothing moved: nothing wakes.
        io.sync(&mut s, c);
        assert!(!s.is_runnable(1));
        // The generation moves: both re-attempt.
        bump(c);
        io.sync(&mut s, c);
        assert!(s.is_runnable(1) && s.is_runnable(2));
        assert_eq!(s.entries[1].woke, Some(WakeReason::Recheck));
        assert_eq!(c.io.waiters.load(Relaxed), 0);
        // A park carrying an old generation is not parked: it re-attempts at once.
        assert_eq!(
            io.park(&mut s, c, 1, [0, NO_DEADLINE, 5, PARK_IN, 0, 1], 100),
            Some(0)
        );
        assert!(s.is_runnable(1));
        // A deadline wakes it with reply 0 (the runtime decides it timed out).
        assert_eq!(io.park(&mut s, c, 2, [1, 500, 6, PARK_IN, 0, 1], 100), None);
        s.fire_due(500);
        assert!(s.is_runnable(2));
        assert_eq!(s.entries[2].woke, Some(WakeReason::Timeout));
        assert_eq!(s.entries[2].reply, 0);
        io.refresh(&s, c);
        assert_eq!(c.io.waiters.load(Relaxed), 0);
    }

    #[test]
    fn periodic_timer_counts_overruns() {
        let mem = ctl();
        let c = unsafe { Ctl::at(mem.as_ptr() as *mut u8) };
        let mut s = Sched::new(1, 8);
        let mut io = Io::default();
        let mut p = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(p.as_mut_ptr()) }, 0);
        io.timers.insert(
            7,
            TimerFd {
                fd: p[1],
                next: None,
                interval: 0,
                event: None,
                holders: BTreeSet::from([0]),
            },
        );
        assert_eq!(io.timer_set(&mut s, 0, [TFD_ARM, 7, 1_000, 100, 0, 0]), 0);
        assert_eq!(s.next_deadline(), Some(1_000));
        s.fire_due(1_000);
        assert_eq!(io.deliver_timers(&mut s, c, 1_000), vec![(7, 1)]);
        assert_eq!(io.timer_get([7, 0, 0, 0, 0, 0]), 1_100);
        // Delivered 250 ns late: two more periods have passed.
        s.fire_due(1_350);
        assert_eq!(io.deliver_timers(&mut s, c, 1_350), vec![(7, 3)]);
        assert_eq!(io.timer_get([7, 0, 0, 0, 0, 0]), 1_400);
        assert_eq!(c.io.gen.load(Relaxed), 2);
        let mut buf = [0u8; 16];
        assert_eq!(
            unsafe { libc::read(p[0], buf.as_mut_ptr() as *mut _, 16) },
            16
        );
        assert_eq!(u64::from_ne_bytes(buf[..8].try_into().unwrap()), 1);
        assert_eq!(u64::from_ne_bytes(buf[8..].try_into().unwrap()), 3);
        // Disarm: no event left.
        assert_eq!(io.timer_set(&mut s, 0, [TFD_ARM, 7, 0, 0, 0, 0]), 0);
        assert_eq!(s.next_deadline(), None);
        assert_eq!(io.timer_get([7, 0, 0, 0, 0, 0]), 0);
        unsafe { libc::close(p[0]) };
        io.timer_set(&mut s, 0, [TFD_RELEASE, 7, 0, 0, 0, 0]);
    }
}
