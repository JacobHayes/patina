//! Pauses of a machine (`proto::machine`): `pause NAME` and `resume NAME` from main,
//! and the seed's (`pause-gap-ms`, `pause-ms`, each machine its own).
//!
//! A paused machine is a frozen machine: none of its threads is picked (`Sched::freeze`, every
//! slot of the machine, and a slot it gains while paused, `Sup::slot_machine`), whatever it waits
//! for; its clocks are not stopped, so what falls due while it is paused (a sleep's end, a
//! futex timeout, a timerfd's expiry, a signal timer, data a peer sent before the pause) is
//! done at its time as for any thread, and the machine's threads see it all at once when they run
//! again, in the scheduler's order. Its links are cut by a layer of their own
//! (`Links::paused`): what a peer sends to it is held as on a cut, so the peer's own give-up
//! clock (Linux's, or its `TCP_USER_TIMEOUT`) runs; what was on its way to the machine and
//! not yet delivered is held too (`wire_pause`), with the rest of its delay; a connect to it
//! or from it waits for its SYN retries; a datagram to it is lost; a keepalive probe either way
//! goes unanswered (its clocks run, so the machine's own probes do too). At the resume every link
//! that nothing else cuts opens and what was held is delivered (`wire_heal`).
//!
//! A pause takes effect where the supervisor acts: a script's when main's request is
//! served, the seed's when its event falls due (before the turn holder's request is handled,
//! or at an idle jump). A thread of the machine inside a call then (the turn holder, a thread in a
//! blocking call) finishes that call as at the pause and is stopped before it returns to its
//! program; a thread that holds a lock keeps it, and the machine's other threads, which are
//! frozen too, wait as they would.
//!
//! The seed's pauses are a chain of machine events per machine: a gap drawn from `pause-gap-ms`, a
//! pause of a length drawn from `pause-ms`, the next gap from its end. Every draw is on
//! `Stream::Machine`, keyed by the machine, the pause's ordinal in the chain and a sub-key
//! (`NSUB_PAUSE_*`), so turning pauses on moves no other decision. A start that falls while
//! faults may not act (outside the fault window: before a declared setup ends, after the
//! faults end), while the machine is down, or while a script has paused it, makes no
//! pause. A start does not keep a run alive (`Live::No`): with every other thread waiting for
//! nothing, a pause changes nothing. An end does (`Live::Yes`): the machine's threads run again.
//! A script's pause with no resume ahead keeps nothing alive, nor do the paused machine's timers
//! (`only_frozen`): if every other thread waits with no deadline, the run is deadlocked, the
//! paused machine named.

use super::link::{ev_key, EVK_PAUSE_END, EVK_PAUSE_START};
use super::sched::{Event, EventId, Live};
use super::{Next, Sup};
use proto::ctl::*;
use proto::machine::*;
use std::sync::atomic::Ordering::Relaxed;

#[derive(Default)]
pub struct Pauses {
    /// Machines paused (bit `k`).
    pub on: u64,
    /// Each machine's pause in force: who made it, and when it began.
    by: [u64; MAX_MACHINES],
    since: [u64; MAX_MACHINES],
    /// The seed's chain: its next start or end event, and the ordinal of its last draw.
    ev: [Option<EventId>; MAX_MACHINES],
    n: [u64; MAX_MACHINES],
}

impl Sup {
    /// Is machine `k` paused?
    pub(super) fn paused(&self, k: usize) -> bool {
        k < MAX_MACHINES && self.pauses.on >> k & 1 != 0
    }

    /// The seed's first pause of every machine that has pauses, once every machine has started.
    pub(super) fn pauses_begin(&mut self) {
        for k in 1..self.machine_count() {
            if self.machine_tab().conf[k].pause_gap_max_ns > 0 {
                self.pause_next(k);
            }
        }
    }

    fn pause_draw(&self, k: usize, n: u64, sub: u64, lo: u64, hi: u64) -> u64 {
        let d = proto::draw(
            self.ctl.config.seed,
            proto::Stream::Machine,
            (k as u64) << 24 | (n & 0xffff) << 8 | sub,
        );
        lo + d % (hi.saturating_sub(lo) + 1)
    }

    /// The seed's next pause of machine `k`: a gap drawn with its ordinal from now.
    fn pause_next(&mut self, k: usize) {
        let c = self.machine_tab().conf[k];
        self.pauses.n[k] += 1;
        let n = self.pauses.n[k];
        let gap = self
            .pause_draw(k, n, NSUB_PAUSE_GAP, c.pause_gap_min_ns, c.pause_gap_max_ns)
            .max(1);
        self.pauses.ev[k] = Some(self.sched.schedule(
            self.now() + gap,
            Event::Machine {
                key: ev_key(EVK_PAUSE_START, k),
                live: Live::No,
            },
        ));
    }

    /// A pause event of machine `k` fired (`machine_event`).
    pub(super) fn pause_event(&mut self, kind: u64, k: usize) {
        self.pauses.ev[k] = None;
        if kind == EVK_PAUSE_END {
            if self.paused(k) && self.pauses.by[k] == BY_SEED {
                self.resume(k, PEND_SEED);
            }
            self.pause_next(k);
            return;
        }
        if !self.faults_on() || !self.machine_is_up(k) || self.paused(k) {
            self.pause_next(k);
            return;
        }
        let c = self.machine_tab().conf[k];
        let n = self.pauses.n[k];
        let len = self
            .pause_draw(k, n, NSUB_PAUSE_LEN, c.pause_min_ns, c.pause_max_ns)
            .max(1);
        self.pause(k, BY_SEED, len);
        self.pause_inject(k, len);
        self.pauses.ev[k] = Some(self.sched.schedule(
            self.now() + len,
            Event::Machine {
                key: ev_key(EVK_PAUSE_END, k),
                live: Live::Yes,
            },
        ));
    }

    /// Freeze machine `k` (`by`: `BY_SEED` with its length `len`, or `BY_SCRIPT`).
    fn pause(&mut self, k: usize, by: u64, len: u64) {
        let now = self.now();
        self.pauses.on |= 1 << k;
        self.pauses.by[k] = by;
        self.pauses.since[k] = now;
        self.refreeze();
        self.links.paused |= 1 << k;
        self.wire_pause(k);
        // Keepalive probes to the machine, and the machine's own, now go unanswered.
        self.ka_arm_all();
        let t = self.machine_tab();
        let i = t.pauses[k] as usize;
        t.pauses[k] += 1;
        if let Some(p) = t.pause[k].get_mut(i) {
            *p = Pause {
                from_ns: now,
                to_ns: 0,
                by,
                end: 0,
            };
        }
        let b = t.boots[k].saturating_sub(1);
        self.decide(
            DEC_MACHINE_PAUSE,
            0,
            [k as u64, b, by, i as u64 + 1, len, 0],
            0,
        );
    }

    /// End machine `k`'s pause (`end`: `PEND_*`): its threads may run again, and every link of it
    /// that nothing else cuts opens.
    pub(super) fn resume(&mut self, k: usize, end: u64) {
        if !self.paused(k) {
            return;
        }
        let now = self.now();
        self.pauses.on &= !(1 << k);
        self.links.paused &= !(1 << k);
        self.refreeze();
        let lasted = now - self.pauses.since[k];
        let t = self.machine_tab();
        t.paused_ns[k] += lasted;
        let i = t.pauses[k].saturating_sub(1) as usize;
        if let Some(p) = t.pause[k].get_mut(i) {
            (p.to_ns, p.end) = (now, end);
        }
        let b = t.boots[k].saturating_sub(1);
        self.decide(
            DEC_MACHINE_RESUME,
            0,
            [k as u64, b, end, i as u64 + 1, lasted, 0],
            0,
        );
        let opened: Vec<(usize, usize)> = (0..self.machine_count())
            .flat_map(|j| [(k, j), (j, k)])
            .filter(|&(a, b)| a != b && !self.link_cut(a, b))
            .collect();
        if !opened.is_empty() {
            self.wire_heal(&opened);
        }
    }

    /// The faults end: the seed's pause of each machine ends now, and no other is drawn.
    pub(super) fn pauses_done(&mut self) {
        for k in 1..MAX_MACHINES {
            if let Some(e) = self.pauses.ev[k].take() {
                self.sched.cancel(e);
            }
            if self.paused(k) && self.pauses.by[k] == BY_SEED {
                self.resume(k, PEND_DONE);
            }
        }
    }

    /// Machine `k` goes down (a kill or a machine crash): a pause of it ends there, before its
    /// processes are killed; the seed's chain goes on from now.
    pub(super) fn pause_down(&mut self, k: usize) {
        if !self.paused(k) {
            return;
        }
        let seed = self.pauses.by[k] == BY_SEED;
        self.resume(k, PEND_DOWN);
        if seed {
            if let Some(e) = self.pauses.ev[k].take() {
                self.sched.cancel(e);
            }
            self.pause_next(k);
        }
    }

    /// The frozen slots: every slot of a paused machine that holds a thread.
    fn refreeze(&mut self) {
        for i in 0..self.sched.entries.len() {
            let machine = self.slot(i).machine.load(Relaxed) as usize;
            let live = self.sched.entries[i].state != super::sched::State::Free;
            if live && self.paused(machine) {
                self.sched.freeze(i);
            } else {
                self.sched.thaw(i);
            }
        }
    }

    /// The seed's pause as a fault: an `Injected` record, counted under `pause`.
    fn pause_inject(&mut self, k: usize, len: u64) {
        let seq = self.next_seq();
        let t = self.machine_tab();
        let rec = proto::Rec {
            seq,
            vclock_ns: self.now(),
            slot: 0,
            kind: proto::RecKind::Injected as u8,
            class: 0,
            nr: 0,
            args: [
                INJ_MACHINE_PAUSE,
                k as u64,
                t.boots[k].saturating_sub(1),
                t.pauses[k],
                len,
                0,
            ],
            ret: 0,
            out_hash: 0,
            in_hash: 0,
        };
        self.append(&rec);
        let f = &self.ctl.faults;
        f.injected.store(f.injected.load(Relaxed) + 1, Relaxed);
        let s = &self.ctl.stats.faults_injected;
        s.store(s.load(Relaxed) + 1, Relaxed);
    }

    /// `pause NAME` (`MACHINE_PAUSE`) and `resume NAME` (`MACHINE_RESUME`) from main.
    /// A pause of a machine that is down or starting answers `EAGAIN`, of one already paused
    /// `EALREADY`; a resume of one not paused `EALREADY`. A script's resume ends the seed's
    /// pause too; the seed's next is drawn from then.
    pub(super) fn pause_op(&mut self, verb: u64, k: usize) -> Next {
        if verb == MACHINE_PAUSE {
            if !self.machine_is_up(k) {
                return Next::Continue(-(libc::EAGAIN as i64));
            }
            if self.paused(k) {
                return Next::Continue(-(libc::EALREADY as i64));
            }
            self.pause(k, BY_SCRIPT, 0);
            return Next::Continue(0);
        }
        if !self.paused(k) {
            return Next::Continue(-(libc::EALREADY as i64));
        }
        let seed = self.pauses.by[k] == BY_SEED;
        self.resume(k, PEND_SCRIPT);
        if seed {
            if let Some(e) = self.pauses.ev[k].take() {
                self.sched.cancel(e);
            }
            self.pause_next(k);
        }
        Next::Continue(0)
    }

    /// Nothing eligible to run and every pending event only reaches paused machines: no thread
    /// that may run will ever wake, so the run is deadlocked, though a paused machine's periodic
    /// timers (an interval timerfd, an interval timer) would fire forever. Weak machine events
    /// (`Sched::only_weak`) count as nothing; a sleep's or a wait's end counts as nothing for
    /// a frozen slot, a timerfd's or a signal timer's for a paused machine; everything else (the
    /// end of a pause, the wire) may wake a thread that runs. Only with a machine paused.
    pub(super) fn only_frozen(&self) -> bool {
        if self.pauses.on == 0 {
            return false;
        }
        let setup = self.faults_on();
        let pid_paused = |pid: i32| {
            self.procs
                .map
                .get(&pid)
                .is_some_and(|p| self.paused(p.machine))
        };
        self.sched.events.values().all(|e| match e {
            Event::Machine { live, .. } => {
                *live == Live::No || (*live == Live::AfterSetup && !setup)
            }
            Event::Timeout { slot } => self.sched.is_frozen(*slot),
            Event::TimerFd { key } => self.io.timer_machine(*key).is_some_and(|k| self.paused(k)),
            Event::SigTimer { pid } => pid_paused(*pid),
            Event::Wire { .. } => false,
        })
    }

    /// The paused machines, for a deadlock's detail: `; paused: NAME (by script, N threads
    /// would run)`.
    pub(super) fn paused_detail(&self) -> String {
        let mut v = vec![];
        for k in 1..self.machine_count() {
            if self.paused(k) {
                let n = self
                    .sched
                    .runnable()
                    .filter(|&i| self.slot(i).machine.load(Relaxed) as usize == k)
                    .count();
                let by = if self.pauses.by[k] == BY_SEED {
                    "seed"
                } else {
                    "script"
                };
                v.push(format!(
                    "{} (by {by}, {n} threads would run)",
                    self.machine_name(k)
                ));
            }
        }
        if v.is_empty() {
            String::new()
        } else {
            format!("; paused: {}", v.join(", "))
        }
    }
}
