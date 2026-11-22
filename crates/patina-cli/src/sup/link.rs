//! Links between machines (`proto::machine`): the cut matrix, which links the link faults act on,
//! and the seed's partition schedule.
//!
//! A link is an ordered pair of machines. It is cut while any of four layers says so: a script's
//! `partition` (`Op::Net`, `machines::Sup::net_op`), a partition the seed drew, a machine crash of
//! either machine (until the machine is back, `machines::Sup::machine_crash`), or a pause of either machine
//! (until its resume, `pause`). The wire
//! asks `link_cut` when it stamps a delivery, and re-stamps what a cut held when a layer opens
//! a link (`wire_heal`); the script's `heal` clears scripted cuts only.
//!
//! The partition schedule (`partition-gap-ms`, `partition-ms`) is a chain
//! of machine events: a start draws a shape and two sides of the machines the link faults act on,
//! cuts the links between them for a drawn length, and an end opens them and draws the gap to
//! the next start. Every draw is on `Stream::Partition`, keyed by the partition's ordinal and
//! a sub-key (`proto::machine::PSUB_*`), so turning partitions on moves no other decision and no
//! draw depends on traffic. A start that falls while faults are off (before a declared setup
//! ends) makes no partition; the next is drawn. A start
//! does not keep a run alive (`Live::No`): a run that waits only for it is deadlocked. An end
//! does, since it may release held traffic.
//!
//! Records: `DEC_NET_PART` [ordinal, shape, side A, side B, length, bridge] and an `Injected`
//! record (`INJ_NET_CUT`) at a start; `DEC_NET_PART_END` [ordinal] at an end.

use super::sched::{Event, EventId, Live};
use super::Sup;
use proto::ctl::*;
use proto::machine::*;
use proto::wire::LINKS_MAIN;
use proto::{draw, Stream};
use std::sync::atomic::Ordering::Relaxed;

/// Kinds of machine events, in the low bits of their key (`Event::Machine`).
pub const EVK_PART_START: u64 = 0;
pub const EVK_PART_END: u64 = 1;
/// The seed's kill of a machine's processes, and a machine's restart.
pub const EVK_MACHINE_KILL: u64 = 2;
pub const EVK_MACHINE_START: u64 = 3;
/// The seed's pause of a machine, and its end.
pub const EVK_PAUSE_START: u64 = 4;
pub const EVK_PAUSE_END: u64 = 5;
const EVK_BITS: u64 = 4;

pub fn ev_key(kind: u64, machine: usize) -> u64 {
    (machine as u64) << EVK_BITS | kind
}

#[derive(Default)]
pub struct Links {
    /// Scripted cuts and the seed's: bit `to` of `x[from]`.
    pub script: [u64; MAX_MACHINES],
    pub seed: [u64; MAX_MACHINES],
    /// Machines whose machine is down (bit `k`): every link from or to one is cut.
    pub down: u64,
    /// Machines that are paused (bit `k`): every link from or to one is cut.
    pub paused: u64,
    /// Partitions started (the ordinal of the last), and the one in force.
    k: u64,
    active: Option<u64>,
    /// Its index in the machine table's list, if it has one, and whether it acted yet.
    slot: Option<usize>,
    acted: bool,
    ev: Option<EventId>,
}

impl Sup {
    fn tab(&self) -> &'static mut MachineTab {
        unsafe { MachineTab::at(self.ctl as *const Ctl as *mut u8) }
    }

    /// Is the link from machine `from` to machine `to` cut (a machine's own traffic never is)?
    pub(super) fn link_cut(&self, from: usize, to: usize) -> bool {
        from != to
            && from < MAX_MACHINES
            && ((self.links.script[from] | self.links.seed[from]) & (1 << to) != 0
                || ((self.links.down | self.links.paused) >> from
                    | (self.links.down | self.links.paused) >> to)
                    & 1
                    != 0)
    }

    /// A cut link held, lost or kept back something: the partition in force acted, if the
    /// seed's layer cuts it.
    pub(super) fn cut_acted(&mut self, from: usize, to: usize) {
        if from < MAX_MACHINES && self.links.seed[from] & (1 << to) != 0 && !self.links.acted {
            self.links.acted = true;
            self.tab().parts_acted += 1;
            if let Some(i) = self.links.slot {
                self.tab().parts[i].acted = 1;
            }
        }
    }

    /// Do the link faults (`net-*`) act on the link from `from` to `to`? Without machines there
    /// is only loopback, and they do; with machines, between two machines other than main, and
    /// main's links too with `net@main` (`NetCfg::links`); never a machine's loopback.
    pub(super) fn link_faulted(&self, from: usize, to: usize) -> bool {
        // Outside the fault window (before a declared setup ends, after the faults end) no
        // link is faulted.
        if !self.faults_on() {
            return false;
        }
        if self.machine_count() == 0 {
            return true;
        }
        if from == to {
            false
        } else if from == 0 || to == 0 {
            self.net_cfg_links() >= LINKS_MAIN
        } else {
            true
        }
    }

    fn net_cfg_links(&self) -> u64 {
        unsafe { proto::wire::WireTab::at(self.ctl as *const Ctl as *mut u8) }
            .cfg
            .links
    }

    /// The machines the seed's partitions are drawn over, in order.
    fn faultable(&self) -> Vec<usize> {
        let from = if self.net_cfg_links() >= LINKS_MAIN {
            0
        } else {
            1
        };
        (from..self.machine_count()).collect()
    }

    /// One of the partition schedule's draws.
    fn part_draw(&self, k: u64, sub: u64, i: u64) -> u64 {
        draw(
            self.ctl.config.seed,
            Stream::Partition,
            k << 16 | sub << 8 | (i & 0xff),
        )
    }

    fn part_range(&self, k: u64, sub: u64, (lo, hi): (u64, u64)) -> u64 {
        lo + self.part_draw(k, sub, 0) % (hi - lo + 1)
    }

    /// The schedule's first start, once every machine has started (`boot_machines`).
    pub(super) fn partitions_begin(&mut self) {
        let c = unsafe { proto::wire::WireTab::at(self.ctl as *const Ctl as *mut u8) }.cfg;
        if c.part_gap_max_ns == 0 || self.faultable().len() < 2 {
            return;
        }
        self.part_next(1);
    }

    /// Schedule partition `k`'s start: a gap drawn with its ordinal from now.
    fn part_next(&mut self, k: u64) {
        let c = unsafe { proto::wire::WireTab::at(self.ctl as *const Ctl as *mut u8) }.cfg;
        let t = self.now() + self.part_range(k, PSUB_GAP, (c.part_gap_min_ns, c.part_gap_max_ns));
        self.links.ev = Some(self.sched.schedule(
            t,
            Event::Machine {
                key: ev_key(EVK_PART_START, 0),
                live: Live::No,
            },
        ));
    }

    /// A machine event fired (`after_events`).
    pub(super) fn machine_event(&mut self, key: u64) {
        match key & ((1 << EVK_BITS) - 1) {
            EVK_PART_START => self.part_start(),
            EVK_PART_END => self.part_end(),
            k @ (EVK_PAUSE_START | EVK_PAUSE_END) => {
                self.pause_event(k, (key >> EVK_BITS) as usize)
            }
            k => self.machine_event_more(k, (key >> EVK_BITS) as usize),
        }
    }

    fn part_start(&mut self) {
        self.links.ev = None;
        self.links.k += 1;
        let k = self.links.k;
        let c = unsafe { proto::wire::WireTab::at(self.ctl as *const Ctl as *mut u8) }.cfg;
        if !self.faults_on() {
            self.part_next(k + 1);
            return;
        }
        let machines = self.faultable();
        let shapes: Vec<u64> = SHAPES
            .iter()
            .map(|s| s.0)
            .filter(|s| machines.len() >= shape_min_machines(*s))
            .collect();
        if shapes.is_empty() {
            return; // nothing this run's machines can be cut into: the schedule ends
        }
        let shape = shapes[(self.part_draw(k, PSUB_SHAPE, 0) % shapes.len() as u64) as usize];
        let seed = self.ctl.config.seed;
        let d = |sub: u64, i: u64| draw(seed, Stream::Partition, k << 16 | sub << 8 | (i & 0xff));
        let Some((a, b, bridge)) = sides(shape, &machines, d) else {
            return;
        };
        let len = self.part_range(k, PSUB_LEN, (c.part_min_ns, c.part_max_ns));
        for i in 0..MAX_MACHINES {
            for j in 0..MAX_MACHINES {
                if a & (1 << i) != 0 && b & (1 << j) != 0 {
                    self.links.seed[i] |= 1 << j;
                    if shape != SHAPE_ONEWAY {
                        self.links.seed[j] |= 1 << i;
                    }
                }
            }
        }
        let now = self.now();
        self.decide(DEC_NET_PART, 0, [k, shape, a, b, len, bridge], 0);
        self.part_inject(k, shape, a, b, len);
        let t = self.tab();
        let i = t.parts_n as usize;
        t.parts_n += 1;
        self.links.slot = None;
        if i < PARTS_MAX {
            t.parts[i] = Part {
                n: k,
                shape,
                a,
                b,
                from_ns: now,
                to_ns: 0,
                acted: 0,
                bridge,
            };
            self.links.slot = Some(i);
        }
        self.links.active = Some(k);
        self.links.acted = false;
        // Keepalive probes across the cut now go unanswered.
        self.ka_arm_all();
        self.links.ev = Some(self.sched.schedule(
            now + len,
            Event::Machine {
                key: ev_key(EVK_PART_END, 0),
                live: Live::Yes,
            },
        ));
    }

    fn part_end(&mut self) {
        self.links.ev = None;
        let Some(k) = self.links.active.take() else {
            return;
        };
        let seed = std::mem::take(&mut self.links.seed);
        // What the seed cut and nothing else still cuts (a script's cut, a machine that is
        // down).
        let mut opened = vec![];
        for (i, cut) in seed.iter().enumerate() {
            for j in 0..MAX_MACHINES {
                if cut & (1 << j) != 0 && !self.link_cut(i, j) {
                    opened.push((i, j));
                }
            }
        }
        if let Some(i) = self.links.slot.take() {
            self.tab().parts[i].to_ns = self.now();
        }
        self.decide(DEC_NET_PART_END, 0, [k, 0, 0, 0, 0, 0], 0);
        if !opened.is_empty() {
            self.wire_heal(&opened);
        }
        self.part_next(k + 1);
    }

    /// The faults end (`faults-done`, or the main command's end before `--finally`): the
    /// seed's partition in force heals now, and no other is drawn.
    pub(super) fn partitions_done(&mut self) {
        if let Some(e) = self.links.ev.take() {
            self.sched.cancel(e);
        }
        if self.links.active.is_some() {
            self.part_end();
            if let Some(e) = self.links.ev.take() {
                self.sched.cancel(e);
            }
        }
    }

    /// The faults stop before the final check (`phase::settle`): every link the script cut
    /// opens.
    pub(super) fn heal_all(&mut self) {
        let n = self.machine_count();
        let mut opened = vec![];
        for a in 0..n {
            for b in 0..n {
                let was = self.link_cut(a, b);
                self.links.script[a] &= !(1u64 << b);
                if was && !self.link_cut(a, b) {
                    opened.push((a, b));
                }
            }
        }
        self.machine_tab().cut_at_end = self.links.script;
        if !opened.is_empty() {
            self.wire_heal(&opened);
        }
    }

    /// The partition's `Injected` record: what the seed did, counted as a fault.
    fn part_inject(&mut self, k: u64, shape: u64, a: u64, b: u64, len: u64) {
        let seq = self.next_seq();
        let rec = proto::Rec {
            seq,
            vclock_ns: self.now(),
            slot: 0,
            kind: proto::RecKind::Injected as u8,
            class: 0,
            nr: 0,
            args: [proto::wire::INJ_NET_CUT, shape, k, a, b, len],
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
}
