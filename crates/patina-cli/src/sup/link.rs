//! Links between nodes (`proto::node`): the cut matrix, which links the link faults act on,
//! and the seed's partition schedule.
//!
//! A link is an ordered pair of nodes. It is cut while any of three layers says so: a
//! script's `net cut` (`Op::Net`, `nodes::Sup::net_op`), a partition the seed drew, or a
//! machine crash of either node (until the node is back, `nodes::Sup::node_crash`). The wire
//! asks `link_cut` when it stamps a delivery, and re-stamps what a cut held when a layer opens
//! a link (`wire_heal`); `net heal` clears scripted cuts only.
//!
//! The partition schedule (`partition-gap-ms`, `partition-ms`, `partition-shape`) is a chain
//! of node events: a start draws a shape and two sides of the nodes the link faults act on,
//! cuts the links between them for a drawn length, and an end opens them and draws the gap to
//! the next start. Every draw is on `Stream::Partition`, keyed by the partition's ordinal and
//! a sub-key (`proto::node::PSUB_*`), so turning partitions on moves no other decision and no
//! draw depends on traffic. A start falls while faults are off (before `setup-complete`, or
//! after a crash with `faults-in-recovery=0`) makes no partition; the next is drawn. A start
//! does not keep a run alive (`Live::No`): a run that waits only for it is deadlocked. An end
//! does, since it may release held traffic.
//!
//! Records: `DEC_NET_PART` [ordinal, shape, side A, side B, length, bridge] and an `Injected`
//! record (`INJ_NET_CUT`) at a start; `DEC_NET_PART_END` [ordinal] at an end.

use super::sched::{Event, EventId, Live};
use super::Sup;
use proto::ctl::*;
use proto::node::*;
use proto::wire::{LINKS_ALL, LINKS_DRIVER};
use proto::{draw, Stream};
use std::sync::atomic::Ordering::Relaxed;

/// Kinds of node events, in the low bits of their key (`Event::Node`).
pub const EVK_PART_START: u64 = 0;
pub const EVK_PART_END: u64 = 1;
/// The seed's kill of a node's processes, and a node's restart.
pub const EVK_NODE_KILL: u64 = 2;
pub const EVK_NODE_START: u64 = 3;
const EVK_BITS: u64 = 4;

pub fn ev_key(kind: u64, node: usize) -> u64 {
    (node as u64) << EVK_BITS | kind
}

#[derive(Default)]
pub struct Links {
    /// Scripted cuts and the seed's: bit `to` of `x[from]`.
    pub script: [u64; MAX_NODES],
    pub seed: [u64; MAX_NODES],
    /// Nodes whose machine is down (bit `k`): every link from or to one is cut.
    pub down: u64,
    /// Partitions started (the ordinal of the last), and the one in force.
    k: u64,
    active: Option<u64>,
    /// Its index in the node table's list, if it has one, and whether it acted yet.
    slot: Option<usize>,
    acted: bool,
    ev: Option<EventId>,
}

impl Sup {
    fn tab(&self) -> &'static mut NodeTab {
        unsafe { NodeTab::at(self.ctl as *const Ctl as *mut u8) }
    }

    /// Is the link from node `from` to node `to` cut (a node's own traffic never is)?
    pub(super) fn link_cut(&self, from: usize, to: usize) -> bool {
        from != to
            && from < MAX_NODES
            && ((self.links.script[from] | self.links.seed[from]) & (1 << to) != 0
                || (self.links.down >> from | self.links.down >> to) & 1 != 0)
    }

    /// A cut link held, lost or kept back something: the partition in force acted, if the
    /// seed's layer cuts it.
    pub(super) fn cut_acted(&mut self, from: usize, to: usize) {
        if from < MAX_NODES && self.links.seed[from] & (1 << to) != 0 && !self.links.acted {
            self.links.acted = true;
            self.tab().parts_acted += 1;
            if let Some(i) = self.links.slot {
                self.tab().parts[i].acted = 1;
            }
        }
    }

    /// Do the link faults (`net-*`) act on the link from `from` to `to`? Without nodes there
    /// is only loopback, and they do; with nodes, by `net-links`: between two nodes other than
    /// the driver, also the driver's links, also each node's loopback.
    pub(super) fn link_faulted(&self, from: usize, to: usize) -> bool {
        if self.node_count() == 0 {
            return true;
        }
        let l = self.net_cfg_links();
        if from == to {
            l >= LINKS_ALL
        } else if from == 0 || to == 0 {
            l >= LINKS_DRIVER
        } else {
            true
        }
    }

    fn net_cfg_links(&self) -> u64 {
        unsafe { proto::wire::WireTab::at(self.ctl as *const Ctl as *mut u8) }
            .cfg
            .links
    }

    /// The nodes the seed's partitions are drawn over, in order.
    fn faultable(&self) -> Vec<usize> {
        let from = if self.net_cfg_links() >= LINKS_DRIVER {
            0
        } else {
            1
        };
        (from..self.node_count()).collect()
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

    /// The schedule's first start, once every node has started (`boot_nodes`).
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
            Event::Node {
                key: ev_key(EVK_PART_START, 0),
                live: Live::No,
            },
        ));
    }

    /// A node event fired (`after_events`).
    pub(super) fn node_event(&mut self, key: u64) {
        match key & ((1 << EVK_BITS) - 1) {
            EVK_PART_START => self.part_start(),
            EVK_PART_END => self.part_end(),
            k => self.node_event_more(k, (key >> EVK_BITS) as usize),
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
        let nodes = self.faultable();
        let shapes: Vec<u64> = SHAPES
            .iter()
            .map(|s| s.0)
            .filter(|s| c.part_shapes & (1 << s) != 0 && nodes.len() >= shape_min_nodes(*s))
            .collect();
        if shapes.is_empty() {
            return; // nothing this run's nodes can be cut into: the schedule ends
        }
        let shape = shapes[(self.part_draw(k, PSUB_SHAPE, 0) % shapes.len() as u64) as usize];
        let seed = self.ctl.config.seed;
        let d = |sub: u64, i: u64| draw(seed, Stream::Partition, k << 16 | sub << 8 | (i & 0xff));
        let Some((a, b, bridge)) = sides(shape, &nodes, d) else {
            return;
        };
        let len = self.part_range(k, PSUB_LEN, (c.part_min_ns, c.part_max_ns));
        for i in 0..MAX_NODES {
            for j in 0..MAX_NODES {
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
            Event::Node {
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
            for j in 0..MAX_NODES {
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

    /// The partition's `Injected` record: what the seed did, counted as a fault.
    fn part_inject(&mut self, k: u64, shape: u64, a: u64, b: u64, len: u64) {
        let seq = self.ctl.seq.load(Relaxed) + 1;
        self.ctl.seq.store(seq, Relaxed);
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
