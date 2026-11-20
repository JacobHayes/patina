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
//!
//! A node goes down three ways, each a `DEC_NODE_DOWN` record: its processes are killed (by the
//! seed, `--crash process`, or by `node kill NAME --process`), each `SIGKILL`ed by the
//! supervisor (`kill_now`) as the kernel kills a process: its sockets close, so peers see the
//! FIN or RST, its listeners go and connects to them are refused; or its first process ends
//! by itself, which ends the node (its other processes are killed): an exit status of its
//! `ok-exit` stops it, another ends the run `failure`, a signal Patina did not send ends it
//! `crash`. The work tree, `/tmp` and `/dev/shm` stay as they were. A restart (its `restart`
//! policy after a down time drawn from `down-ms`, or `node start NAME`) asks the keeper for a
//! new first process in the node's existing view, with `PATINA_INCARNATION` set to the boot.
//!
//! Kills and restarts the clock brings (node events) wait for a point where no request is in
//! flight that they could disturb (`node_actions`): before the turn holder's request is
//! handled, or at an idle jump. A kill there may end the turn holder's own process: its
//! request is then not served. A restart waits while a slot is reserved for a process that has
//! not said `Hello` (a fork or vfork in flight), whose slot the new process could otherwise
//! claim. Every such state is the turn's, so the wait is the same in every run of a seed.

use super::link::{ev_key, EVK_NODE_KILL, EVK_NODE_START};
use super::proc::PState;
use super::sched::{Event, EventId, Live};
use super::{Next, Sup};
use crate::outcome::Verdict;
use proto::ctl::*;
use proto::layout::FD_NODES;
use proto::node::*;
use std::collections::VecDeque;
use std::sync::atomic::Ordering::*;

#[derive(Default)]
pub struct Nodes {
    /// Node events and control calls to act on at the next point where they may
    /// (`node_actions`): (`EVK_NODE_KILL` or `EVK_NODE_START`, node).
    pending: VecDeque<(u64, usize)>,
    /// The supervisor is killing a node's processes: their ends are not the node's own.
    killing: bool,
    /// Whether each node is up, its seed kill and its restart to come, and how many kills of
    /// its boot came while faults were off (each drawn again).
    up: [bool; MAX_NODES],
    kill_ev: [Option<EventId>; MAX_NODES],
    start_ev: [Option<EventId>; MAX_NODES],
    kill_try: [u64; MAX_NODES],
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
    pub(super) fn node_tab(&self) -> &'static mut NodeTab {
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
        self.boot_hello(0, 0, 0);
        for node in 1..self.node_count() {
            // Every slot but the driver's is free before any guest runs.
            self.start_node(node, node);
        }
        self.partitions_begin();
        // The driver's `Hello` was answered with its reply kept: it runs first.
        self.reply(0, 0);
    }

    /// Start boot `boots[node]` of `node` in the free slot `slot`: the keeper starts its first
    /// process (in its existing view after the first boot), which says `Hello`.
    fn start_node(&mut self, node: usize, slot: usize) {
        let s = self.slot(slot);
        s.go.store(0, SeqCst);
        s.tid.store(0, Relaxed);
        s.pid.store(0, Relaxed);
        s.vmask.store(0, Relaxed);
        s.sigpend.store(0, Relaxed);
        s.sched.store(0, Relaxed);
        s.node.store(node as u64, Relaxed);
        s.state.store(SLOT_RESERVED, SeqCst);
        // A new process tree: its runtime installs the seccomp filter again.
        self.ctl.filter_installed.fetch_and(!(1u64 << node), SeqCst);
        self.nodes.booting = Some(slot);
        let b = self.node_tab().boots[node];
        let (out, err) = match keeper_start(node, b) {
            Ok(x) => x,
            Err(e) => self.finish(Verdict::new(
                "infra",
                format!("node {}: {e}", self.node_name(node)),
            )),
        };
        let now = self.now();
        self.boot_hello(slot, node, b);
        let pid = self.nodes.first[node] as u64;
        let t = self.node_tab();
        if let Some(e) = t.boot[node].get_mut(b as usize) {
            *e = Boot {
                pid,
                start_ns: now,
                out_off: out,
                err_off: err,
                ..Boot::default()
            };
        }
        t.boots[node] = b + 1;
        self.nodes.up[node] = true;
        self.nodes.kill_try[node] = 0;
        self.kill_next(node);
    }

    /// Wait for the `Hello` of slot `slot` and serve it; its reply waits for the scheduler.
    fn boot_hello(&mut self, slot: usize, node: usize, boot: u64) {
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
                [node as u64, pid as u64, boot, 0, 0, 0],
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

    /// The link faults and partitions stopped: the seed killed a node under
    /// `faults-in-recovery=0`.
    pub(super) fn nodes_quiet(&self) -> bool {
        self.node_count() > 0 && self.node_tab().quiet != 0
    }

    /// A node kill or restart came due (`node_event`): acted on at the next point it may be.
    pub(super) fn node_event_more(&mut self, kind: u64, node: usize) {
        match kind {
            EVK_NODE_KILL => self.nodes.kill_ev[node] = None,
            EVK_NODE_START => self.nodes.start_ev[node] = None,
            _ => return,
        }
        self.nodes.pending.push_back((kind, node));
    }

    /// Nothing is runnable (`choose`): act on the node kills and restarts that came due but
    /// waited (a restart after a kill in the same call), as at an idle jump. Whether one acted.
    pub(super) fn node_actions_idle(&mut self) -> bool {
        if self.nodes.pending.is_empty() {
            return false;
        }
        let before = self.nodes.pending.len();
        let killed = self.node_actions();
        if killed.is_empty() && self.nodes.pending.len() == before {
            return false;
        }
        self.wire_step();
        self.io.sync(&mut self.sched, self.ctl);
        true
    }

    /// Act on the node kills and restarts that came due, where nothing in flight can be
    /// disturbed (`serve`, before the request it handles; `choose`, at an idle jump). Returns
    /// the processes killed.
    pub(super) fn node_actions(&mut self) -> Vec<i32> {
        let mut killed = vec![];
        let mut later = VecDeque::new();
        // A process or thread being created (its slot reserved, or a vfork child that has not
        // said `Hello`) is not in the process table yet: a kill or a restart waits for it.
        let creating = (0..MAX_THREADS).any(|i| self.slot(i).state.load(SeqCst) == SLOT_RESERVED)
            || self.vfork_in_flight();
        while let Some((kind, k)) = self.nodes.pending.pop_front() {
            match kind {
                EVK_NODE_KILL | EVK_NODE_START if creating => later.push_back((kind, k)),
                // After a kill in the same call, a restart waits for the next: the killed
                // request's records come first, and its slot is not taken under it.
                EVK_NODE_START if !killed.is_empty() => later.push_back((kind, k)),
                EVK_NODE_KILL if self.nodes.up[k] => {
                    if self.setup_done() {
                        killed.extend(self.node_kill(k, DOWN_KILL_SEED));
                    } else {
                        self.kill_next(k);
                    }
                }
                EVK_NODE_START if !self.nodes.up[k] => {
                    let Some(slot) =
                        (0..MAX_THREADS).find(|&i| self.slot(i).state.load(SeqCst) == SLOT_FREE)
                    else {
                        self.finish(Verdict::new(
                            "capacity",
                            format!(
                                "node {}: no thread slot left for its restart",
                                self.node_name(k)
                            ),
                        ))
                    };
                    self.start_node(k, slot);
                }
                _ => {}
            }
        }
        self.nodes.pending = later;
        killed
    }

    /// Draw the seed's kill of `node`'s current boot (`--crash process`, `crash-gap-ms`): none
    /// in its last permitted boot (`max-incarnations`).
    fn kill_next(&mut self, k: usize) {
        let t = self.node_tab();
        let c = t.conf[k];
        let b = t.boots[k].saturating_sub(1);
        if c.crash == 0 || b + 1 >= c.max_boots {
            return;
        }
        let tries = self.nodes.kill_try[k];
        self.nodes.kill_try[k] += 1;
        let d = proto::draw(
            self.ctl.config.seed,
            proto::Stream::Node,
            (k as u64) << 24 | (b & 0xff) << 16 | (tries & 0xff) << 8 | NSUB_KILL,
        );
        let (lo, hi) = (t.crash_gap_min_ns, t.crash_gap_max_ns);
        // In [A, B), A when A = B: as `restart-gap-ms`.
        let gap = lo + if hi > lo { d % (hi - lo) } else { 0 };
        self.nodes.kill_ev[k] = Some(self.sched.schedule(
            self.now() + gap,
            Event::Node {
                key: ev_key(EVK_NODE_KILL, k),
                live: Live::AfterSetup,
            },
        ));
    }

    /// The down time of `node`'s restart after boot `b` (`down-ms`), if its restart comes: by
    /// its policy (`always` after an exit within `ok-exit`), and within `max-incarnations`.
    fn down_time(&self, k: usize, b: u64, how: u64) -> u64 {
        let t = self.node_tab();
        let c = t.conf[k];
        let restart = match how {
            DOWN_KILL_SEED => c.restart != RESTART_NEVER,
            DOWN_EXIT => c.restart == RESTART_ALWAYS,
            _ => false,
        };
        if !restart || t.boots[k] >= c.max_boots.min(BOOTS_MAX as u64) {
            return 0;
        }
        let d = proto::draw(
            self.ctl.config.seed,
            proto::Stream::Node,
            (k as u64) << 24 | (b & 0xff) << 16 | NSUB_DOWN,
        );
        let (lo, hi) = (t.down_min_ns, t.down_max_ns);
        (lo + if hi > lo { d % (hi - lo) } else { 0 }).max(1)
    }

    /// The live processes of node `k`, the newest first.
    fn node_pids(&self, k: usize) -> Vec<i32> {
        self.procs
            .map
            .iter()
            .rev()
            .filter(|(_, p)| p.node == k && p.state == PState::Live)
            .map(|(pid, _)| *pid)
            .collect()
    }

    /// Node `k` is down (`how`, with an exit status or signal `value`): the record, its boot's
    /// end, its other processes killed (`others`), and its restart queued after `down` ns.
    fn node_down(&mut self, k: usize, how: u64, value: u64, others: &[i32], down: u64) {
        let t = self.node_tab();
        let b = t.boots[k].saturating_sub(1);
        if let Some(e) = self.nodes.kill_ev[k].take() {
            self.sched.cancel(e);
        }
        self.nodes.up[k] = false;
        self.decide(
            DEC_NODE_DOWN,
            0,
            [k as u64, b, how, value, others.len() as u64, down],
            0,
        );
        let now = self.now();
        if let Some(e) = self.node_tab().boot[k].get_mut(b as usize) {
            (e.end_ns, e.how, e.value, e.down_ns) = (now, how, value, down);
        }
        if how == DOWN_KILL_SEED {
            self.kill_inject(k, b);
            if self.node_tab().recovery_off != 0 {
                self.node_tab().quiet = 1;
            }
        }
        self.nodes.killing = true;
        for &pid in others {
            self.kill_now(pid);
        }
        self.nodes.killing = false;
        if down > 0 {
            self.nodes.start_ev[k] = Some(self.sched.schedule(
                now + down,
                Event::Node {
                    key: ev_key(EVK_NODE_START, k),
                    live: Live::Yes,
                },
            ));
        }
    }

    /// Kill every process of node `k` (`DOWN_KILL_SEED` or `DOWN_KILL_SCRIPT`); a kill by the
    /// seed queues its restart. A script's kill of a node that is down cancels its restart.
    /// Returns the processes killed.
    pub(super) fn node_kill(&mut self, k: usize, how: u64) -> Vec<i32> {
        if let Some(e) = self.nodes.start_ev[k].take() {
            self.sched.cancel(e);
        }
        self.nodes.pending.retain(|&(_, n)| n != k);
        if !self.nodes.up[k] {
            return vec![];
        }
        let pids = self.node_pids(k);
        let b = self.node_tab().boots[k].saturating_sub(1);
        let down = self.down_time(k, b, how);
        self.node_down(k, how, libc::SIGKILL as u64, &pids, down);
        pids
    }

    /// The seed's kill as a fault: an `Injected` record, counted under `crash`.
    fn kill_inject(&mut self, k: usize, b: u64) {
        let seq = self.ctl.seq.load(Relaxed) + 1;
        self.ctl.seq.store(seq, Relaxed);
        let rec = proto::Rec {
            seq,
            vclock_ns: self.now(),
            slot: 0,
            kind: proto::RecKind::Injected as u8,
            class: 0,
            nr: 0,
            args: [INJ_NODE_KILL, k as u64, b, 0, 0, 0],
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

    /// `Op::Node` [verb, node] from the driver's node (the runtime checked the words).
    pub(super) fn node_op(&mut self, idx: usize, a: [u64; 6]) -> Next {
        let k = a[1] as usize;
        if self.node_of(idx) != 0 || k == 0 || k >= self.node_count() {
            return Next::Continue(-(libc::EPERM as i64));
        }
        match a[0] {
            // A node that is down stays down: its restart to come is cancelled.
            NODE_KILL => {
                let up = self.nodes.up[k];
                self.node_kill(k, DOWN_KILL_SCRIPT);
                Next::Continue(if up { 0 } else { -(libc::EALREADY as i64) })
            }
            NODE_START => {
                let queued = self.nodes.pending.contains(&(EVK_NODE_START, k));
                if self.nodes.up[k] || queued {
                    return Next::Continue(-(libc::EALREADY as i64));
                }
                // `max-incarnations` bounds the seed; the script only the table's record.
                if self.node_tab().boots[k] >= BOOTS_MAX as u64 {
                    return Next::Continue(-(libc::EAGAIN as i64));
                }
                if let Some(e) = self.nodes.start_ev[k].take() {
                    self.sched.cancel(e);
                }
                self.nodes.pending.push_back((EVK_NODE_START, k));
                Next::Continue(0)
            }
            _ => Next::Continue(-(libc::EINVAL as i64)),
        }
    }

    /// A process ended: if it was a node's first, its status is the node's, and unless the
    /// supervisor killed it, the node's end: its other processes are killed, and its exit
    /// status or signal says what follows (an exit within its `ok-exit` stops it, perhaps to
    /// restart; another ends the run `failure`; a signal ends it `crash`).
    pub(super) fn node_gone(&mut self, pid: i32, word: i64) {
        if self.node_count() == 0 {
            return;
        }
        let Some(k) = (1..MAX_NODES).find(|&k| self.nodes.first[k] == pid) else {
            return;
        };
        self.node_tab().status[k] = word as u64;
        // Once: a later process given the same pid is not the node's first.
        self.nodes.first[k] = 0;
        if self.nodes.killing || !self.nodes.up[k] {
            return;
        }
        let c = self.node_tab().conf[k];
        let (how, value) = if word & 0x7f != 0 {
            (DOWN_SIGNAL, (word & 0x7f) as u64)
        } else {
            let s = ((word >> 8) & 0xff) as u64;
            (if c.ok(s) { DOWN_EXIT } else { DOWN_FAILED }, s)
        };
        let others: Vec<i32> = self
            .node_pids(k)
            .into_iter()
            .filter(|&p| p != pid)
            .collect();
        let b = self.node_tab().boots[k].saturating_sub(1);
        let down = self.down_time(k, b, how);
        self.node_down(k, how, value, &others, down);
        if how == DOWN_EXIT {
            return;
        }
        self.node_tab().ended_by = k as u64 + 1;
        let name = self.node_name(k);
        let mut v = if how == DOWN_SIGNAL {
            let mut v = Verdict::new(
                "node-crash",
                format!(
                    "node {name}: killed by signal {value} ({})",
                    crate::outcome::signal_name(value as i64)
                ),
            );
            v.signal = Some(value as i64);
            v
        } else {
            let mut v = Verdict::new("node-failed", format!("node {name}: exit status {value}"));
            v.exit_status = Some(value as i64);
            v
        };
        v.detail.truncate(400);
        self.nodes_stop();
        self.finish(v)
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

/// Ask the keeper to start boot `boot` of node `node` (its first process); returns once it
/// exists, with where its output starts in the node's stdout and stderr.
fn keeper_start(node: usize, boot: u64) -> Result<(u64, u64), String> {
    let b = [node as u8, boot as u8];
    let r = unsafe { libc::send(FD_NODES, b.as_ptr().cast(), 2, libc::MSG_NOSIGNAL) };
    if r != 2 {
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
        n => {
            let s = String::from_utf8_lossy(&buf[..n as usize]).into_owned();
            let mut w = s.split(' ');
            match (w.next(), w.next(), w.next()) {
                (Some("ok"), Some(o), Some(e)) => match (o.parse(), e.parse()) {
                    (Ok(o), Ok(e)) => Ok((o, e)),
                    _ => Err(s),
                },
                _ => Err(s),
            }
        }
    }
}
