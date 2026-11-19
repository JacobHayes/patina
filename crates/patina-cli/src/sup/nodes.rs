//! Nodes in the supervisor (`proto::node`): the boot of every node's first process, the
//! scripted network cuts, and each node's end.
//!
//! Boot is sequential and happens before any guest runs: the driver (forked by `main`) says
//! `Hello` and waits; then for each node in order the supervisor reserves its slot (marked
//! with the node), asks the sandbox's keeper to start the node's first process in the node's
//! own view (`FD_NODES`, `sandbox::Keeper::view`), and waits for its `Hello`. Only one
//! process is ever starting, so slots, pids and records come in one order. Then the driver
//! gets the turn; every node's thread is runnable from the start, waiting for the scheduler.
//!
//! A scripted cut (`Op::Net`) is a matrix of links, `cut[from]` holding a bit per `to`; the
//! wire consults it when it stamps a delivery (`Sup::link_cut`) and re-stamps what it held when
//! a heal opens a link (`Sup::wire_heal`).

use super::{Next, Sup};
use crate::outcome::Verdict;
use proto::ctl::*;
use proto::layout::FD_NODES;
use proto::node::{NodeTab, MAX_NODES, NET_CUT, NET_HEAL, RUNNING};
use std::sync::atomic::Ordering::*;

#[derive(Default)]
pub struct Nodes {
    /// The slot of the node whose first process is starting (`proc::hello`).
    pub booting: Option<usize>,
    /// Each node's first process (0: none yet).
    first: [i32; MAX_NODES],
    /// System V shared memory of the nodes besides the driver's (`Sup::shm`): each node is
    /// its own IPC namespace.
    pub shm: std::collections::BTreeMap<usize, super::shm::Shm>,
    /// The node each slot was last said to belong to (`DEC_NODE_SLOT`; absent: the driver's).
    slot_node: std::collections::BTreeMap<usize, usize>,
}

impl Nodes {
    /// A node's first process said `Hello` (`proc::hello`; node 0 is the driver).
    pub fn started(&mut self, node: usize, pid: i32) {
        if node < MAX_NODES {
            self.first[node] = pid;
        }
        self.booting = None;
    }
}

impl Sup {
    fn node_tab(&self) -> &'static mut NodeTab {
        unsafe { NodeTab::at(self.ctl as *const Ctl as *mut u8) }
    }

    /// Nodes in the run, the driver included (0: none).
    pub(super) fn node_count(&self) -> usize {
        (self.ctl.config.nodes as usize).min(MAX_NODES)
    }

    pub(super) fn node_name(&self, node: usize) -> String {
        String::from_utf8_lossy(self.node_tab().name(node)).into_owned()
    }

    /// The node of the thread in slot `idx`.
    pub(super) fn node_of(&self, idx: usize) -> usize {
        let pid = self.sched.entries[idx].pid;
        self.procs.map.get(&pid).map_or(0, |p| p.node)
    }

    /// Slot `slot` now runs a thread of node `node`: a record when that is news, so that the
    /// log says which node each record's slot belongs to (`patina log`). None without nodes.
    pub(super) fn slot_node(&mut self, slot: usize, node: usize) {
        if self.node_count() == 0 {
            return;
        }
        let was = self.nodes.slot_node.get(&slot).copied().unwrap_or(0);
        if was != node {
            self.nodes.slot_node.insert(slot, node);
            self.decide(
                DEC_NODE_SLOT,
                slot,
                [slot as u64, node as u64, 0, 0, 0, 0],
                0,
            );
        }
    }

    /// The driver has said `Hello` and waits; start every node, in order, then give the
    /// driver the turn (`main`, only in a run with nodes).
    pub(super) fn boot_nodes(&mut self) {
        self.boot_hello(0, 0);
        for node in 1..self.node_count() {
            // Every slot but the driver's is free before any guest runs.
            let slot = node;
            let s = self.slot(slot);
            s.go.store(0, SeqCst);
            s.tid.store(0, Relaxed);
            s.pid.store(0, Relaxed);
            s.vmask.store(0, Relaxed);
            s.sigpend.store(0, Relaxed);
            s.sched.store(0, Relaxed);
            s.node.store(node as u64, Relaxed);
            s.state.store(SLOT_RESERVED, SeqCst);
            self.nodes.booting = Some(slot);
            if let Err(e) = keeper_start(node) {
                self.finish(Verdict::new(
                    "infra",
                    format!("node {}: {e}", self.node_name(node)),
                ));
            }
            self.boot_hello(slot, node);
        }
        self.partitions_begin();
        // The driver's `Hello` was answered with its reply kept: it runs first.
        self.reply(0, 0);
    }

    /// Wait for the `Hello` of slot `slot` and serve it; its reply waits for the scheduler.
    fn boot_hello(&mut self, slot: usize, node: usize) {
        let limit = self.ctl.config.stall_ms.max(1);
        let start = super::now_ns();
        while self.ctl.sup_word.load(SeqCst) == 0 {
            crate::sys::futex_wait_ms(&self.ctl.sup_word as *const _ as *const u32, 0, 100);
            if self.ctl.sup_word.load(SeqCst) == 0
                && super::now_ns().saturating_sub(start) / 1_000_000 > limit
            {
                self.finish(Verdict::new(
                    "infra",
                    format!(
                        "node {}: its first process did not start the runtime",
                        self.node_name(node)
                    ),
                ));
            }
        }
        self.ctl.sup_word.store(0, SeqCst);
        let idx = self.ctl.pending_slot.load(SeqCst) as usize;
        let req = unsafe { std::ptr::read_volatile(&(*self.ctl.slot(idx)).req) };
        if idx != slot || Op::from_u32(req.op) != Some(Op::Hello) {
            self.finish(Verdict::new(
                "infra",
                format!(
                    "node {}: request {} from slot {idx} at boot, not its Hello",
                    self.node_name(node),
                    req.op
                ),
            ));
        }
        let Next::Continue(ret) = self.handle(idx, req) else {
            unreachable!("Hello continues")
        };
        self.sched.entries[idx].reply = ret;
        self.decide(req.op, idx, req.args, idx as i64);
        if node > 0 {
            let pid = self.sched.entries[idx].pid;
            self.node_tab().first_pid[node] = pid as u64;
            self.node_tab().status[node] = RUNNING;
            self.decide(
                DEC_NODE_START,
                slot,
                [node as u64, pid as u64, 0, 0, 0, 0],
                0,
            );
        }
    }

    /// `Op::Net` [verb, from set, to set, both] from the driver's node (the runtime checked).
    pub(super) fn net_op(&mut self, idx: usize, a: [u64; 6]) -> Next {
        let n = self.node_count();
        let all = (1u64 << n) - 1;
        let (verb, from, to, both) = (a[0], a[1], a[2], a[3] != 0);
        if self.node_of(idx) != 0 || from & !all != 0 || to & !all != 0 {
            return Next::Continue(-(libc::EPERM as i64));
        }
        let t = self.node_tab();
        match verb {
            NET_CUT => t.cuts += 1,
            NET_HEAL => t.heals += 1,
            _ => return Next::Continue(-(libc::EINVAL as i64)),
        }
        let mut opened = vec![];
        let (from, to) = if verb == NET_HEAL && from == 0 && to == 0 {
            (all, all)
        } else {
            (from, to)
        };
        let mut set = |a: usize, b: usize| {
            if a == b {
                return;
            }
            let bit = 1u64 << b;
            let was = self.link_cut(a, b);
            if verb == NET_CUT {
                self.links.script[a] |= bit;
            } else {
                self.links.script[a] &= !bit;
                if was && !self.link_cut(a, b) {
                    opened.push((a, b));
                }
            }
        };
        for a in 0..n {
            for b in 0..n {
                if from & (1 << a) != 0 && to & (1 << b) != 0 {
                    set(a, b);
                    if both {
                        set(b, a);
                    }
                }
            }
        }
        self.node_tab().cut_at_end = self.links.script;
        if !opened.is_empty() {
            self.wire_heal(&opened);
        }
        Next::Continue(0)
    }

    /// `Op::PidNode` [pid]: the node of a process of the run (zombies included), or `ESRCH`.
    pub(super) fn pid_node(&self, a: [u64; 6]) -> Next {
        match self.procs.map.get(&(a[0] as i32)) {
            Some(p) => Next::Continue(p.node as i64),
            None => Next::Continue(-(libc::ESRCH as i64)),
        }
    }

    /// More kinds of node events (node kills and restarts).
    pub(super) fn node_event_more(&mut self, _kind: u64, _node: usize) {}

    /// A process ended: if it was a node's first, its status is the node's.
    pub(super) fn node_gone(&mut self, pid: i32, word: i64) {
        if self.node_count() == 0 {
            return;
        }
        if let Some(k) = (1..MAX_NODES).find(|&k| self.nodes.first[k] == pid) {
            self.node_tab().status[k] = word as u64;
            // Once: a later process given the same pid is not the node's first.
            self.nodes.first[k] = 0;
        }
    }

    /// The driver ended the run: a record for each node that still has processes.
    pub(super) fn nodes_stop(&mut self) {
        for k in 1..self.node_count() {
            let live = self
                .procs
                .map
                .values()
                .filter(|p| p.node == k && p.state == super::proc::PState::Live)
                .count();
            if live > 0 {
                self.decide(DEC_NODE_STOP, 0, [k as u64, live as u64, 0, 0, 0, 0], 0);
            }
        }
    }
}

/// Ask the keeper to start node `node`'s first process; returns once it exists.
fn keeper_start(node: usize) -> Result<(), String> {
    let b = [node as u8];
    let r = unsafe { libc::send(FD_NODES, b.as_ptr().cast(), 1, libc::MSG_NOSIGNAL) };
    if r != 1 {
        return Err(format!(
            "asking the keeper to start it: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut buf = [0u8; 4096];
    let n = unsafe { libc::recv(FD_NODES, buf.as_mut_ptr().cast(), buf.len(), 0) };
    match n {
        n if n < 0 => Err(format!(
            "the keeper's answer: {}",
            std::io::Error::last_os_error()
        )),
        0 => Err("the keeper is gone".into()),
        n if &buf[..n as usize] == b"ok" => Ok(()),
        n => Err(String::from_utf8_lossy(&buf[..n as usize]).into_owned()),
    }
}
