//! Virtual signals in the supervisor: per-process dispositions (their kind), pending
//! sets and queues, the interval timer; per-thread pending sets and waits. Sending marks a
//! signal pending and wakes the receiving thread if it is parked; the runtime dequeues with
//! `SigTake` at the thread's trap exit and builds the frame. Nothing here is a kernel signal.
//!
//! The thread's virtual mask lives in its slot (`Slot::vmask`, written by the runtime under
//! the turn); the supervisor keeps each slot's `sigpend` word equal to the thread's private
//! set or'ed with its process's set.

use super::sched::{Event, EventId, State, Wait, WakeReason};
use super::{Next, Sup};
use crate::outcome::Verdict;
use proto::ctl::*;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::atomic::Ordering::*;

pub const NSIG: usize = 65;
const SIGILL: u64 = 4;
const SIGTRAP: u64 = 5;
const SIGBUS: u64 = 7;
const SIGFPE: u64 = 8;
const SIGKILL: u64 = 9;
const SIGSEGV: u64 = 11;
const SIGALRM: u64 = 14;
const SIGSTOP: u64 = 19;
const SIGSYS: u64 = 31;
const SI_KERNEL: u64 = 0x80;
const EINVAL: i64 = 22;
const ESRCH: i64 = 3;

const fn bit(sig: u64) -> u64 {
    1 << (sig - 1)
}
/// The kernel dequeues these first (`SYNCHRONOUS_MASK`).
const SYNC_MASK: u64 =
    bit(SIGSEGV) | bit(SIGBUS) | bit(SIGILL) | bit(SIGTRAP) | bit(SIGFPE) | bit(SIGSYS);
const UNBLOCKABLE: u64 = bit(SIGKILL) | bit(SIGSTOP);

pub type Info = [u64; 16];

/// A pending set with its queue. Standard signals (1..31) coalesce: a second one while the
/// first is pending is dropped. Real-time signals queue in arrival order.
#[derive(Default, Debug, Clone)]
pub struct Pending {
    pub set: u64,
    q: VecDeque<(u64, Info)>,
}

impl Pending {
    pub fn add(&mut self, sig: u64, info: Info) -> bool {
        if sig < 32 && self.set & bit(sig) != 0 {
            return false;
        }
        self.set |= bit(sig);
        self.q.push_back((sig, info));
        true
    }
    /// The kernel's `next_signal`: synchronous signals first, then the lowest number.
    pub fn next(&self, allowed: u64) -> Option<u64> {
        let x = self.set & allowed;
        if x == 0 {
            return None;
        }
        let s = x & SYNC_MASK;
        let y = if s != 0 { s } else { x };
        Some(y.trailing_zeros() as u64 + 1)
    }
    pub fn take(&mut self, sig: u64) -> Option<Info> {
        let i = self.q.iter().position(|e| e.0 == sig)?;
        let (_, info) = self.q.remove(i).unwrap();
        if !self.q.iter().any(|e| e.0 == sig) {
            self.set &= !bit(sig);
        }
        Some(info)
    }
    pub fn flush(&mut self, sig: u64) {
        self.q.retain(|e| e.0 != sig);
        self.set &= !bit(sig);
    }
}

pub struct SigProc {
    /// `SIGK_*` per signal.
    pub kinds: [u64; NSIG],
    pub pending: Pending,
    /// `ITIMER_REAL`: the scheduled expiry and the interval.
    pub timer: Option<(EventId, u64)>,
    /// The union of the masks of the signalfds the process holds (`Op::SigFd`).
    pub sigfd: u64,
}

impl SigProc {
    /// A forked child's signal state: the parent's dispositions and signalfds, nothing
    /// pending, no timer.
    pub fn forked(parent: &SigProc) -> SigProc {
        SigProc {
            kinds: parent.kinds,
            pending: Pending::default(),
            timer: None,
            sigfd: parent.sigfd,
        }
    }
    fn new() -> SigProc {
        let mut kinds = [SIGK_DEFAULT; NSIG];
        for (s, k) in kinds.iter_mut().enumerate().skip(1) {
            if sig_default_ignored(s as u64) {
                *k = SIGK_IGNORE;
            }
        }
        SigProc {
            kinds,
            pending: Pending::default(),
            timer: None,
            sigfd: 0,
        }
    }
}

#[derive(Default, Clone)]
pub struct SigThread {
    pub pending: Pending,
    /// While parked in `SigWait`: the awaited set (unblocked for the wait); `SigSuspend`: 0.
    pub wait_set: Option<u64>,
    /// The `deliver` flags of the next reply.
    pub deliver: u64,
}

pub struct Signals {
    pub procs: BTreeMap<i32, SigProc>,
    pub threads: Vec<SigThread>,
    /// Slots whose `wait_set` is set.
    pub(crate) waiting: BTreeSet<usize>,
    /// Number of processes in `procs` with a non-empty `pending.set`.
    pub(crate) proc_pending_count: usize,
}

impl Signals {
    pub fn new(slots: usize) -> Signals {
        Signals {
            procs: BTreeMap::new(),
            threads: vec![SigThread::default(); slots],
            waiting: BTreeSet::new(),
            proc_pending_count: 0,
        }
    }
    fn set_wait(&mut self, s: usize, w: Option<u64>) {
        self.threads[s].wait_set = w;
        if w.is_some() {
            self.waiting.insert(s);
        } else {
            self.waiting.remove(&s);
        }
    }
}

/// Leave for a thread to park. Only `Sup::may_block` makes one, and only when no signal the
/// thread does not block is pending for it: the kernel's `signal_pending` check before every
/// interruptible sleep. `Sched::park` takes one, for the slot it was given for, so no wait
/// parks past a deliverable signal (a signal that comes later finds the thread parked and
/// `send` wakes it). `vfork`'s wait is the one wait a signal does not end, as in the kernel.
pub struct MayPark(usize);

impl MayPark {
    /// The `vfork` parent's wait: the kernel's is killable only; signals wait until the
    /// child execs or exits.
    pub(super) fn vfork(slot: usize) -> MayPark {
        MayPark(slot)
    }
    #[cfg(test)]
    pub fn for_test(slot: usize) -> MayPark {
        MayPark(slot)
    }
    pub fn slot(&self) -> usize {
        self.0
    }
}

pub enum Target {
    Proc(i32),
    Thread(usize),
}

impl Sup {
    /// A forked child's signal state, from process `pid`'s.
    pub fn sproc_forked(&mut self, pid: i32) -> SigProc {
        SigProc::forked(self.sproc(pid))
    }

    /// Send from the supervisor (SIGCHLD, parent-death signals).
    pub fn send_to(&mut self, t: Target, sig: u64, info: Info) {
        self.send(t, sig, info);
    }

    fn sproc(&mut self, pid: i32) -> &mut SigProc {
        self.sig.procs.entry(pid).or_insert_with(SigProc::new)
    }

    fn vmask(&self, s: usize) -> u64 {
        self.slot(s).vmask.load(Relaxed)
    }

    /// What `s` blocks right now: its mask, minus the set it waits for in `sigtimedwait`.
    fn blocked(&self, s: usize) -> u64 {
        self.vmask(s) & !self.sig.threads[s].wait_set.unwrap_or(0) & !UNBLOCKABLE
    }

    /// Leave for `s` to park now, or None when a signal it does not block is pending for it
    /// (the caller answers `-EINTR`, the runtime's restart rules do the rest).
    pub fn may_block(&self, s: usize) -> Option<MayPark> {
        (self.deliverable(s) == 0).then_some(MayPark(s))
    }

    /// The pending signals `s` would take now.
    fn deliverable(&self, s: usize) -> u64 {
        self.slot(s).sigpend.load(Relaxed) & !self.blocked(s)
    }

    /// The detector of lost signals: a parked thread (not a `vfork` parent) with a signal
    /// pending that it does not block. `send` wakes a parked receiver, `may_block` refuses to
    /// park one, and a process-directed signal is passed on when its chosen thread blocks it
    /// or exits (`retarget`); one found here was lost by Patina. Checked whenever nothing is
    /// runnable, which a lost wakeup always reaches. Not a frozen thread (a paused machine's): a
    /// process-directed signal waits for a runnable thread of its process that is frozen too,
    /// and the check sees the thread again once its machine resumes.
    pub fn lost_signal(&self) -> Option<String> {
        self.sched.parked().into_iter().find_map(|(s, e, w, _)| {
            let d = self.deliverable(s);
            (w != Wait::Vfork && d != 0 && !self.sched.is_frozen(s)).then(|| {
                format!(
                    "runtime invariant: slot {s} (tid {}) is parked ({}) with {} pending and not blocked",
                    e.tid,
                    Self::describe_wait(w),
                    name(d.trailing_zeros() as u64 + 1)
                )
            })
        })
    }

    /// Pass on process-directed signals of `pid` that no thread can take now: when no
    /// runnable thread leaves one unblocked (the thread it was meant for blocked it, or
    /// exited), a parked thread that does not block it is woken for it, as the kernel's
    /// `retarget_shared_pending` does. Checked after every request of the process: a mask
    /// changes only in the thread holding the turn, and nothing else runs before its next
    /// request.
    pub fn retarget(&mut self, pid: i32) {
        if self.sig.proc_pending_count == 0 {
            return;
        }
        let Some(p) = self.sig.procs.get(&pid) else {
            return;
        };
        let mut set = p.pending.set;
        if set == 0 {
            return;
        }
        while set != 0 {
            let sig = set.trailing_zeros() as u64 + 1;
            set &= set - 1;
            let threads = self.threads_of(pid);
            // A runnable thread that can take it takes it at its trap exit.
            if threads.iter().any(|&s| {
                self.blocked(s) & bit(sig) == 0 && self.sched.entries[s].state == State::Runnable
            }) {
                continue;
            }
            if let Some(s) = threads.into_iter().find(|&s| {
                self.blocked(s) & bit(sig) == 0
                    && matches!(self.sched.entries[s].state, State::Parked { wait, .. } if wait != Wait::Vfork)
            }) {
                self.interrupt(s, sig);
            }
        }
    }

    /// Live threads of a process (not exiting), in slot order.
    fn threads_of(&self, pid: i32) -> Vec<usize> {
        self.sched
            .slots_of(pid)
            .into_iter()
            .filter(|&s| {
                matches!(
                    self.sched.entries[s].state,
                    State::Runnable | State::Parked { .. }
                )
            })
            .collect()
    }

    fn live_tid(&self, tid: i32) -> Option<usize> {
        (0..self.sched.entries.len()).find(|&s| {
            let e = &self.sched.entries[s];
            e.tid == tid && matches!(e.state, State::Runnable | State::Parked { .. })
        })
    }

    /// Keep every thread's `sigpend` word equal to its private set or'ed with its process's.
    pub fn refresh_pending(&mut self, pid: i32) {
        let pp = self.sproc(pid).pending.set;
        for s in self.threads_of(pid) {
            self.slot(s)
                .sigpend
                .store(self.sig.threads[s].pending.set | pp, Relaxed);
        }
    }

    /// A new thread (or process image) in slot `s`: nothing pending of its own.
    pub fn signal_thread_new(&mut self, s: usize, pid: i32) {
        self.sig.set_wait(s, None);
        self.sig.threads[s] = SigThread::default();
        self.refresh_pending(pid);
    }

    /// Slot `s` exited: its private pending signals are discarded.
    pub fn signal_thread_gone(&mut self, s: usize) {
        self.sig.set_wait(s, None);
        self.sig.threads[s] = SigThread::default();
        self.slot(s).sigpend.store(0, Relaxed);
    }

    /// Mark `sig` pending for `t` and wake the receiving thread if it is parked.
    fn send(&mut self, t: Target, sig: u64, info: Info) {
        let pid = match t {
            Target::Proc(p) => p,
            Target::Thread(s) => self.sched.entries[s].pid,
        };
        // SIGKILL is carried out for real at once: no thread of the target holds the
        // turn (or the sender is the target), so its death is a function of history.
        if sig == SIGKILL {
            self.kill_now(pid);
            return;
        }
        if !self.is_live(pid) {
            return;
        }
        let threads = self.threads_of(pid);
        let kind = self.sproc(pid).kinds[sig as usize];
        // Discarded at generation when ignored and not blocked by the target (for a
        // process: by its first thread, as the kernel checks the group leader).
        let probe = match t {
            Target::Thread(s) => Some(s),
            Target::Proc(_) => threads.first().copied(),
        };
        let blocked_by_probe = probe
            .map(|s| self.blocked(s) & bit(sig) != 0)
            .unwrap_or(false);
        if sig != SIGKILL && kind == SIGK_IGNORE && !blocked_by_probe {
            return;
        }
        let added = match t {
            Target::Thread(s) => self.sig.threads[s].pending.add(sig, info),
            Target::Proc(_) => {
                let p = self.sproc(pid);
                let was_empty = p.pending.set == 0;
                let a = p.pending.add(sig, info);
                if a && was_empty {
                    self.sig.proc_pending_count += 1;
                }
                a
            }
        };
        if !added {
            return;
        }
        self.refresh_pending(pid);
        if self.sproc(pid).sigfd & bit(sig) != 0 {
            // A signalfd of the process may now be readable: its waiters check again.
            let g = &self.ctl.io.gen;
            g.store(g.load(Relaxed) + 1, Relaxed);
        }
        let chosen = match t {
            Target::Thread(s) => (self.blocked(s) & bit(sig) == 0).then_some(s),
            // The lowest slot of the process that does not block it and can be woken: a
            // `vfork` parent would hold it until the child execs or exits while another
            // thread sleeps on (POSIX lets any thread that does not block it take it).
            Target::Proc(_) => threads.into_iter().find(|&s| {
                self.blocked(s) & bit(sig) == 0
                    && !matches!(
                        self.sched.entries[s].state,
                        State::Parked {
                            wait: Wait::Vfork,
                            ..
                        }
                    )
            }),
        };
        if let Some(s) = chosen {
            self.interrupt(s, sig);
        }
    }

    /// `s` can take `sig`: if it is parked, wake it. A `sigtimedwait` for `sig` gets the
    /// signal as its result; anything else returns -EINTR and the runtime delivers at the
    /// trap exit (or restarts the call).
    fn interrupt(&mut self, s: usize, sig: u64) {
        let State::Parked { wait, .. } = self.sched.entries[s].state else {
            return;
        };
        if wait == Wait::Vfork {
            return;
        }
        let waits_for = self.sig.threads[s]
            .wait_set
            .map(|w| w & bit(sig) != 0)
            .unwrap_or(false);
        self.sig.set_wait(s, None);
        if waits_for {
            let pid = self.sched.entries[s].pid;
            let got = self.take_from(s, pid, bit(sig));
            self.sched.make_runnable(s, WakeReason::Woken);
            if let Some(sig) = got {
                self.sched.entries[s].reply = sig as i64;
            }
        } else {
            self.sched.make_runnable(s, WakeReason::Signal);
        }
    }

    /// Dequeue one signal of `allowed` for slot `s` (its own first, then its process's),
    /// writing its siginfo into the slot.
    fn take_from(&mut self, s: usize, pid: i32, allowed: u64) -> Option<u64> {
        let (sig, info) = if let Some(sig) = self.sig.threads[s].pending.next(allowed) {
            (sig, self.sig.threads[s].pending.take(sig).unwrap())
        } else {
            let p = self.sproc(pid);
            let sig = p.pending.next(allowed)?;
            let info = p.pending.take(sig).unwrap();
            if p.pending.set == 0 {
                self.sig.proc_pending_count -= 1;
            }
            (sig, info)
        };
        unsafe { std::ptr::write_volatile(&mut (*self.ctl.slot(s)).siginfo, info) };
        self.refresh_pending(pid);
        Some(sig)
    }

    /// Clear the wait state of threads no longer parked (woken by a timeout).
    pub fn sweep_waits(&mut self) {
        if self.sig.waiting.is_empty() {
            return;
        }
        let done: Vec<usize> = self
            .sig
            .waiting
            .iter()
            .copied()
            .filter(|&s| !matches!(self.sched.entries[s].state, State::Parked { .. }))
            .collect();
        for s in done {
            self.sig.set_wait(s, None);
        }
    }

    /// Interval timers that expired (the scheduler queued them while firing events).
    pub fn fire_signal_timers(&mut self) {
        let due = std::mem::take(&mut self.sched.due_timers);
        for (pid, at) in due {
            let now = self.now();
            let Some(p) = self.sig.procs.get_mut(&pid) else {
                continue;
            };
            let Some((_, interval)) = p.timer else {
                continue;
            };
            p.timer = None;
            if interval > 0 {
                let mut next = at + interval;
                while next <= now {
                    next += interval;
                }
                let id = self.sched.schedule(next, Event::SigTimer { pid });
                self.sig.procs.get_mut(&pid).unwrap().timer = Some((id, interval));
            }
            self.decide(DEC_SIGNAL_TIMER, 0, [pid as u64, at, interval, 0, 0, 0], 0);
            let mut info = [0u64; 16];
            info[0] = SIGALRM;
            info[1] = SI_KERNEL;
            self.send(Target::Proc(pid), SIGALRM, info);
        }
        self.sweep_waits();
    }

    /// Serve a signal request from `idx`.
    pub fn signal_op(&mut self, op: Op, idx: usize, a: [u64; 6]) -> Next {
        let pid = self.sched.entries[idx].pid;
        match op {
            Op::SigSend => {
                let [mode, tpid, tid, sig, ..] = a;
                if sig > 64 {
                    return Next::Continue(-EINVAL);
                }
                let (tpid, tid) = (tpid as i32, tid as i32);
                let info = unsafe { std::ptr::read_volatile(&(*self.ctl.slot(idx)).siginfo) };
                match mode {
                    SIGSEND_PROC | SIGSEND_PGRP | SIGSEND_ALL => {
                        // Processes from the table; zombies count as found and take nothing.
                        let Some(targets) = self.kill_targets(mode, tpid, pid) else {
                            return Next::Continue(-ESRCH);
                        };
                        if sig != 0 {
                            for (p, st) in targets {
                                if st == super::proc::PState::Live {
                                    self.send(Target::Proc(p), sig, info);
                                }
                            }
                        }
                    }
                    SIGSEND_TGKILL | SIGSEND_TKILL => {
                        let machine = |p: i32| self.procs.map.get(&p).map_or(0, |p| p.machine);
                        let target = match self.live_tid(tid) {
                            Some(s)
                                if (mode == SIGSEND_TKILL || self.sched.entries[s].pid == tpid)
                                    && machine(self.sched.entries[s].pid) == machine(pid) =>
                            {
                                Target::Thread(s)
                            }
                            _ => return Next::Continue(-ESRCH),
                        };
                        if sig != 0 {
                            self.send(target, sig, info);
                        }
                    }
                    _ => return Next::Continue(-EINVAL),
                }
                // The sender killed its own process.
                if !self.is_live(pid) {
                    return Next::Pick;
                }
                Next::Continue(0)
            }
            Op::SigTake => {
                let allowed = !a[0] | UNBLOCKABLE;
                let sig = self.take_from(idx, pid, allowed).unwrap_or(0);
                self.sig.threads[idx].deliver = sig;
                Next::Continue(0)
            }
            Op::SigWait => {
                let set = a[0] & !UNBLOCKABLE;
                if let Some(sig) = self.take_from(idx, pid, set) {
                    return Next::Continue(sig as i64);
                }
                let deadline = if a[1] == NO_DEADLINE {
                    None
                } else {
                    Some(a[1])
                };
                if deadline.is_some_and(|d| d <= self.now()) {
                    return Next::Continue(0);
                }
                // An unblocked signal that is already pending interrupts at once.
                let Some(ok) = self.may_block(idx) else {
                    return Next::Continue(-4);
                };
                self.sig.set_wait(idx, Some(set));
                self.sched.park(idx, Wait::Signal, deadline, ok);
                Next::Pick
            }
            Op::SigSuspend => {
                let Some(ok) = self.may_block(idx) else {
                    return Next::Continue(-4);
                };
                self.sig.set_wait(idx, Some(0));
                self.sched.park(idx, Wait::Signal, None, ok);
                Next::Pick
            }
            Op::TimerSet => {
                let [which, value, interval, query, ..] = a;
                if which != 0 {
                    return Next::Continue(-EINVAL);
                }
                let now = self.now();
                let old = match self.sproc(pid).timer {
                    Some(((at, _), iv)) => [at.saturating_sub(now).max(1000), iv],
                    None => [0, 0],
                };
                unsafe {
                    let w = &mut (*self.ctl.slot(idx)).siginfo;
                    std::ptr::write_volatile(&mut w[0], old[0]);
                    std::ptr::write_volatile(&mut w[1], old[1]);
                }
                if query == 0 {
                    if let Some((id, _)) = self.sproc(pid).timer.take() {
                        self.sched.cancel(id);
                    }
                    if value > 0 {
                        let id = self.sched.schedule(now + value, Event::SigTimer { pid });
                        self.sproc(pid).timer = Some((id, interval));
                    }
                }
                Next::Continue(0)
            }
            Op::SigFd => {
                self.sproc(pid).sigfd = a[0];
                Next::Continue(0)
            }
            Op::SigAction => {
                let [sig, kind, ..] = a;
                if sig == 0 {
                    return self.pdeathsig(idx, a);
                }
                if sig == 17 {
                    self.note_autoreap(pid, a[2] != 0);
                }
                if sig == 0 || sig as usize >= NSIG {
                    self.finish(Verdict::new(
                        "infra",
                        format!("SigAction: bad signal {sig}"),
                    ));
                }
                self.sproc(pid).kinds[sig as usize] = kind;
                if kind == SIGK_IGNORE {
                    // POSIX: setting a pending signal to be ignored discards it.
                    let p = self.sproc(pid);
                    let was_nz = p.pending.set != 0;
                    p.pending.flush(sig);
                    if was_nz && p.pending.set == 0 {
                        self.sig.proc_pending_count -= 1;
                    }
                    for s in self.threads_of(pid) {
                        self.sig.threads[s].pending.flush(sig);
                    }
                    self.refresh_pending(pid);
                }
                Next::Continue(0)
            }
            _ => unreachable!(),
        }
    }
}

/// Name of a signal for outcome details.
pub fn name(sig: u64) -> String {
    const N: [&str; 32] = [
        "0",
        "SIGHUP",
        "SIGINT",
        "SIGQUIT",
        "SIGILL",
        "SIGTRAP",
        "SIGABRT",
        "SIGBUS",
        "SIGFPE",
        "SIGKILL",
        "SIGUSR1",
        "SIGSEGV",
        "SIGUSR2",
        "SIGPIPE",
        "SIGALRM",
        "SIGTERM",
        "SIGSTKFLT",
        "SIGCHLD",
        "SIGCONT",
        "SIGSTOP",
        "SIGTSTP",
        "SIGTTIN",
        "SIGTTOU",
        "SIGURG",
        "SIGXCPU",
        "SIGXFSZ",
        "SIGVTALRM",
        "SIGPROF",
        "SIGWINCH",
        "SIGIO",
        "SIGPWR",
        "SIGSYS",
    ];
    if (sig as usize) < N.len() {
        N[sig as usize].to_string()
    } else {
        format!("SIGRTMIN+{}", sig - 34)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_coalesce_realtime_queue() {
        let mut p = Pending::default();
        let i = |v: u64| {
            let mut x = [0u64; 16];
            x[3] = v;
            x
        };
        assert!(p.add(10, i(1)));
        assert!(!p.add(10, i(2)));
        assert!(p.add(40, i(3)));
        assert!(p.add(40, i(4)));
        assert_eq!(p.next(u64::MAX), Some(10));
        assert_eq!(p.take(10).unwrap()[3], 1);
        assert_eq!(p.next(u64::MAX), Some(40));
        assert_eq!(p.take(40).unwrap()[3], 3);
        assert_eq!(p.set, bit(40));
        assert_eq!(p.take(40).unwrap()[3], 4);
        assert_eq!(p.set, 0);
    }

    #[test]
    fn synchronous_first_then_lowest() {
        let mut p = Pending::default();
        p.add(2, [0; 16]);
        p.add(11, [0; 16]);
        p.add(10, [0; 16]);
        assert_eq!(p.next(u64::MAX), Some(11));
        assert_eq!(p.next(!bit(11)), Some(2));
        assert_eq!(p.next(bit(10)), Some(10));
        assert_eq!(p.next(0), None);
    }
}
