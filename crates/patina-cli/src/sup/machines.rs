//! Machines in the supervisor (`proto::machine`): the boot of every machine's first process, the
//! scripted network cuts, and each machine's end.
//!
//! Boot is sequential and happens before any guest runs: main (forked by `main`) says
//! `Hello` and waits; then for each machine in order the supervisor reserves its slot (marked
//! with the machine), asks the sandbox's keeper to start the machine's first process in the machine's
//! own view (`FD_MACHINES`, `sandbox::Keeper::view`), and waits for its `Hello`. Only one
//! process is ever starting, so slots, pids and records come in one order. Then main
//! gets the turn; every machine's thread is runnable from the start, waiting for the scheduler.
//!
//! A scripted cut (`Op::Net`) is a matrix of links, `cut[from]` holding a bit per `to`; the
//! wire consults it when it stamps a delivery (`Sup::link_cut`) and re-stamps what it held when
//! a heal opens a link (`Sup::wire_heal`).
//!
//! A machine goes down three ways, each a `DEC_MACHINE_DOWN` record: its processes are killed (by the
//! seed, `--faults kill`, or by `kill NAME`), each `SIGKILL`ed by the
//! supervisor (`kill_now`) as the kernel kills a process: its sockets close, so peers see the
//! FIN or RST, its listeners go and connects to them are refused; or its first process ends
//! by itself, which ends the machine (its other processes are killed): an exit status of its
//! `ok-exit` stops it, another ends the run `failure`, a signal Patina did not send ends it
//! `crash`. The disk, `/tmp` and `/dev/shm` stay as they were. A restart (its `restart`
//! policy after a down time drawn from `down-ms`, or `start NAME`) asks the keeper for a
//! new first process in the machine's existing view, with `PATINA_BOOT` set to the boot.
//!
//! Kills and restarts the clock brings (machine events) wait for a point where no request is in
//! flight that they could disturb (`machine_actions`): before the turn holder's request is
//! handled, or at an idle jump. A kill there may end the turn holder's own process: its
//! request is then not served. A restart waits while a slot is reserved for a process that has
//! not said `Hello` (a fork or vfork in flight), whose slot the new process could otherwise
//! claim. Every such state is the turn's, so the wait is the same in every run of a seed.

use super::link::{ev_key, EVK_MACHINE_KILL, EVK_MACHINE_START};
use super::proc::PState;
use super::sched::{Event, EventId, Live};
use super::{Next, Sup};
use crate::outcome::Verdict;
use proto::ctl::*;
use proto::layout::FD_MACHINES;
use proto::machine::*;
use std::collections::VecDeque;
use std::sync::atomic::Ordering::*;

#[derive(Default)]
pub struct Machines {
    /// Machine events and control calls to act on at the next point where they may
    /// (`machine_actions`): (`EVK_MACHINE_KILL` or `EVK_MACHINE_START`, machine).
    pub(super) pending: VecDeque<(u64, usize)>,
    /// The supervisor is killing a machine's processes: their ends are not the machine's own.
    killing: bool,
    /// The machine is crashing: its stores were flushed before its `Crash` record, and
    /// nothing of its may follow that record on its disk.
    pub crashing: bool,
    /// The crash point the crashing machine crashes at (0: a crash at a drawn time or
    /// by script).
    point: u64,
    /// Whether each machine is up, its seed kill and its restart to come, and how many kills of
    /// its boot came while faults were off (each drawn again).
    up: [bool; MAX_MACHINES],
    kill_ev: [Option<EventId>; MAX_MACHINES],
    start_ev: [Option<EventId>; MAX_MACHINES],
    kill_try: [u64; MAX_MACHINES],
    /// The slot of the machine whose first process is starting (`proc::hello`).
    pub booting: Option<usize>,
    /// Each machine's first process (0: none yet).
    first: [i32; MAX_MACHINES],
    /// System V shared memory of the machines besides main's (`Sup::shm`): each machine is
    /// its own IPC namespace.
    pub shm: std::collections::BTreeMap<usize, super::shm::Shm>,
    /// The machine each slot was last said to belong to (`DEC_MACHINE_SLOT`; absent: main's).
    slot_machine: std::collections::BTreeMap<usize, usize>,
    /// Where each machine's disk begins in the shared operation log (`oplog.meta` bytes), and
    /// the tree its next boot starts from after a machine crash (a tree archive) and that
    /// tree's times (`Tree::times`).
    disk_at: [u64; MAX_MACHINES],
    next_tree: [Option<Vec<u8>>; MAX_MACHINES],
    next_times: [Option<Vec<u8>>; MAX_MACHINES],
}

impl Machines {
    /// A machine's first process said `Hello` (`proc::hello`; machine 0 is main).
    pub fn started(&mut self, machine: usize, pid: i32) {
        if machine < MAX_MACHINES {
            self.first[machine] = pid;
        }
        self.booting = None;
    }
}

impl Sup {
    pub(super) fn machine_tab(&self) -> &'static mut MachineTab {
        unsafe { MachineTab::at(self.ctl as *const Ctl as *mut u8) }
    }

    /// Machines in the run, main included (0: none).
    pub(super) fn machine_count(&self) -> usize {
        (self.ctl.config.machines as usize).min(MAX_MACHINES)
    }

    pub(super) fn machine_name(&self, machine: usize) -> String {
        String::from_utf8_lossy(self.machine_tab().name(machine)).into_owned()
    }

    /// The machine of the thread in slot `idx`.
    pub(super) fn machine_of(&self, idx: usize) -> usize {
        let pid = self.sched.entries[idx].pid;
        self.procs.map.get(&pid).map_or(0, |p| p.machine)
    }

    /// Slot `slot` now runs a thread of machine `machine`: a record when that is news, so that the
    /// log says which machine each record's slot belongs to (`patina log`), and frozen if the machine
    /// is paused (a thread or process its turn holder made as the pause came). None without
    /// machines.
    pub(super) fn slot_machine(&mut self, slot: usize, machine: usize) {
        if self.machine_count() == 0 {
            return;
        }
        if self.paused(machine) {
            self.sched.freeze(slot);
        }
        let was = self.machines.slot_machine.get(&slot).copied().unwrap_or(0);
        if was != machine {
            self.machines.slot_machine.insert(slot, machine);
            self.decide(
                DEC_MACHINE_SLOT,
                slot,
                [slot as u64, machine as u64, 0, 0, 0, 0],
                0,
            );
        }
    }

    /// Main has said `Hello` and waits; start every machine, in order, then give the
    /// main the turn (`main`, only in a run with machines).
    pub(super) fn boot_machines(&mut self) {
        // Every machine's processes keep their work files' shadows in the same stores.
        let stores: Vec<i32> = (0..proto::oplog::SHADOW_SLOTS as i32)
            .map(|k| proto::layout::FD_SHADOWS + k)
            .collect();
        if let Err(e) =
            crate::sandbox::send_with(FD_MACHINES, &[crate::sandbox::SHADOWS_MSG], &stores)
        {
            self.finish(Verdict::new(
                "infra",
                format!("shadow stores to the keeper: {e}"),
            ));
        }
        self.boot_hello(0, 0, 0);
        for machine in 1..self.machine_count() {
            // Every slot but main's is free before any guest runs.
            self.start_machine(machine, machine);
        }
        self.partitions_begin();
        self.pauses_begin();
        // Main's `Hello` was answered with its reply kept: it runs first.
        self.reply(0, 0);
    }

    /// Start boot `boots[machine]` of `machine` in the free slot `slot`: the keeper starts its first
    /// process (in its existing view after the first boot), which says `Hello`.
    fn start_machine(&mut self, machine: usize, slot: usize) {
        let s = self.slot(slot);
        s.go.store(0, SeqCst);
        s.tid.store(0, Relaxed);
        s.pid.store(0, Relaxed);
        s.vmask.store(0, Relaxed);
        s.sigpend.store(0, Relaxed);
        s.sched.store(0, Relaxed);
        s.machine.store(machine as u64, Relaxed);
        s.state.store(SLOT_RESERVED, SeqCst);
        // A new process tree: its runtime installs the seccomp filter again.
        self.ctl
            .filter_installed
            .fetch_and(!(1u64 << machine), SeqCst);
        self.machines.booting = Some(slot);
        let b = self.machine_tab().boots[machine];
        let tree = self.machines.next_tree[machine].take();
        if tree.is_some() {
            // Back after a machine crash: its links open again; what they held is delivered
            // (to a connection the machine has no more: a RST back).
            self.links.down &= !(1u64 << machine);
            let opened: Vec<(usize, usize)> = (0..self.machine_count())
                .flat_map(|j| [(machine, j), (j, machine)])
                .filter(|&(a, b)| a != b && !self.link_cut(a, b))
                .collect();
            self.wire_heal(&opened);
        }
        self.arm_points(machine, b);
        let (out, err) = match keeper_start(machine, b, tree.as_deref()) {
            Ok(x) => x,
            Err(e) => self.finish(Verdict::new(
                "infra",
                format!("machine {}: {e}", self.machine_name(machine)),
            )),
        };
        let now = self.now();
        self.boot_hello(slot, machine, b);
        let pid = self.machines.first[machine] as u64;
        let t = self.machine_tab();
        if let Some(e) = t.boot[machine].get_mut(b as usize) {
            *e = Boot {
                pid,
                start_ns: now,
                out_off: out,
                err_off: err,
                ..Boot::default()
            };
        }
        t.boots[machine] = b + 1;
        self.clock_boot(machine, b);
        self.machines.up[machine] = true;
        self.machines.kill_try[machine] = 0;
        self.kill_next(machine);
    }

    /// Wait for the `Hello` of slot `slot` and serve it; its reply waits for the scheduler.
    pub(super) fn boot_hello(&mut self, slot: usize, machine: usize, boot: u64) {
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
                        "machine {}: its first process did not start the runtime",
                        self.machine_name(machine)
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
                    "machine {}: request {} from slot {idx} at boot, not its Hello",
                    self.machine_name(machine),
                    req.op
                ),
            ));
        }
        let Next::Continue(ret) = self.handle(idx, req) else {
            unreachable!("Hello continues")
        };
        self.sched.entries[idx].reply = ret;
        self.decide(req.op, idx, req.args, idx as i64);
        if machine > 0 {
            let pid = self.sched.entries[idx].pid;
            // A first boot, or the first after a machine crash: a new disk.
            if self.disks.dev(machine).is_err() {
                self.disk_start(machine, pid, boot);
            }
            self.machine_tab().first_pid[machine] = pid as u64;
            self.machine_tab().status[machine] = RUNNING;
            self.decide(
                DEC_MACHINE_START,
                slot,
                [machine as u64, pid as u64, boot, 0, 0, 0],
                0,
            );
        }
    }

    /// Machine `machine`'s disk starts (the first process of its first boot, or of its first after a
    /// machine crash, `pid`, said `Hello`, before it runs): its
    /// disk is reached and its base records written, exempt from `[run] log-limit` as the
    /// main's are. After a machine crash (`boot` above 0) the times its tree carries go into
    /// the virtual time table first (`crash::seed_times`).
    fn disk_start(&mut self, machine: usize, pid: i32, boot: u64) {
        let work = self.machine_tab().work_path(machine).to_vec();
        let len = |c: &proto::ctl::Ctl| c.oplog_len.load(Relaxed) + c.opdata_len.load(Relaxed);
        let before = len(self.ctl);
        self.machines.disk_at[machine] = self.ctl.oplog_len.load(Relaxed);
        let r = self.disks.open(machine, pid, &work).and_then(|()| {
            let p = self.disks.path(machine).ok_or("no disk")?;
            if boot > 0 {
                let times = self.machines.next_times[machine].take().unwrap_or_default();
                super::crash::seed_times(self.ctl, machine, &p, &times)?;
            }
            super::crash::write_base(self.ctl, machine, &p)
        });
        if let Err(e) = r {
            self.finish(Verdict::new(
                "infra",
                format!("machine {}: base records: {e}", self.machine_name(machine)),
            ));
        }
        self.ctl
            .log_exempt
            .fetch_add(len(self.ctl) - before, Relaxed);
    }

    /// `Op::Net` [verb, from set, to set, both] from main (the runtime checked).
    pub(super) fn net_op(&mut self, idx: usize, a: [u64; 6]) -> Next {
        let n = self.machine_count();
        let all = (1u64 << n) - 1;
        let (verb, from, to, both) = (a[0], a[1], a[2], a[3] != 0);
        if self.machine_of(idx) != 0 || from & !all != 0 || to & !all != 0 {
            return Next::Continue(-(libc::EPERM as i64));
        }
        let t = self.machine_tab();
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
        self.machine_tab().cut_at_end = self.links.script;
        if !opened.is_empty() {
            self.wire_heal(&opened);
        }
        if verb == NET_CUT {
            self.ka_arm_all();
        }
        Next::Continue(0)
    }

    /// `Op::PidMachine` [pid]: the machine of a process of the run (zombies included), or `ESRCH`.
    pub(super) fn pid_machine(&self, a: [u64; 6]) -> Next {
        match self.procs.map.get(&(a[0] as i32)) {
            Some(p) => Next::Continue(p.machine as i64),
            None => Next::Continue(-(libc::ESRCH as i64)),
        }
    }

    /// A machine kill or restart came due (`machine_event`): acted on at the next point it may be.
    pub(super) fn machine_event_more(&mut self, kind: u64, machine: usize) {
        match kind {
            EVK_MACHINE_KILL => self.machines.kill_ev[machine] = None,
            EVK_MACHINE_START => self.machines.start_ev[machine] = None,
            _ => return,
        }
        self.machines.pending.push_back((kind, machine));
    }

    /// Nothing is runnable (`choose`): act on the machine kills and restarts that came due but
    /// waited (a restart after a kill in the same call), as at an idle jump. Whether one acted.
    pub(super) fn machine_actions_idle(&mut self) -> bool {
        if self.machines.pending.is_empty() && self.phases.pending == 0 {
            return false;
        }
        let before = (self.machines.pending.len(), self.phases.pending);
        let killed = self.machine_actions();
        if killed.is_empty() && (self.machines.pending.len(), self.phases.pending) == before {
            return false;
        }
        self.wire_step();
        self.io.sync(&mut self.sched, self.ctl);
        true
    }

    /// Act on the machine kills and restarts that came due, where nothing in flight can be
    /// disturbed (`serve`, before the request it handles; `choose`, at an idle jump). Returns
    /// the processes killed.
    pub(super) fn machine_actions(&mut self) -> Vec<i32> {
        let mut killed = vec![];
        let mut later = VecDeque::new();
        // A process or thread being created (its slot reserved, or a vfork child that has not
        // said `Hello`) is not in the process table yet: a kill or a restart waits for it.
        let creating = (0..MAX_THREADS).any(|i| self.slot(i).state.load(SeqCst) == SLOT_RESERVED)
            || self.vfork_in_flight();
        while let Some((kind, k)) = self.machines.pending.pop_front() {
            match kind {
                EVK_MACHINE_KILL | EVK_MACHINE_START if creating => later.push_back((kind, k)),
                // After a kill in the same call, a restart waits for the next: the killed
                // request's records come first, and its slot is not taken under it.
                EVK_MACHINE_START if !killed.is_empty() => later.push_back((kind, k)),
                EVK_MACHINE_KILL if self.machines.up[k] => {
                    if self.faults_on() {
                        killed.extend(if self.machine_tab().conf[k].crash == SEED_CRASH {
                            self.machine_crash(k, DOWN_CRASH_SEED, 0)
                        } else {
                            self.machine_kill(k, DOWN_KILL_SEED)
                        });
                    } else {
                        self.kill_next(k);
                    }
                }
                EVK_MACHINE_START if !self.machines.up[k] => {
                    let Some(slot) =
                        (0..MAX_THREADS).find(|&i| self.slot(i).state.load(SeqCst) == SLOT_FREE)
                    else {
                        self.finish(Verdict::new(
                            "capacity",
                            format!(
                                "machine {}: no thread slot left for its restart",
                                self.machine_name(k)
                            ),
                        ))
                    };
                    self.start_machine(k, slot);
                }
                _ => {}
            }
        }
        self.machines.pending = later;
        // The next phase's root, once the machine restarts queued before it have started.
        if self.phases.pending != 0
            && !creating
            && killed.is_empty()
            && self.machines.pending.is_empty()
        {
            self.phase_start();
        }
        killed
    }

    /// Whether machine `k`'s start is queued (`machine_actions`) or scheduled.
    pub(super) fn machines_start_queued(&self, k: usize) -> bool {
        self.machines.start_ev[k].is_some()
            || self.machines.pending.contains(&(EVK_MACHINE_START, k))
    }

    /// Queue machine `k`'s start for the next point where nothing is in flight (`machine_actions`),
    /// in place of a restart scheduled later.
    pub(super) fn machine_start_now(&mut self, k: usize) {
        if let Some(e) = self.machines.start_ev[k].take() {
            self.sched.cancel(e);
        }
        self.machines.pending.push_back((EVK_MACHINE_START, k));
    }

    /// Boot `b` of machine `k` starts: its crash points (`machine:PERMILLE`, `machine-at:N`,
    /// in its `FaultCfg`) count from 0, and fire in no boot past its last permitted one
    /// (`max-boots`), as a single machine's boots do. An `-at` crash fired once
    /// is off (`machine_point_crash`).
    fn arm_points(&mut self, k: usize, b: u64) {
        let t = self.machine_tab();
        let max_boots = t.conf[k].max_boots;
        let f = &mut t.faults[k];
        // `machine-at:N` names a point of the first boot only.
        let on = f.cfg.crash_kind != proto::faults::CRASH_NONE
            && b + 1 < max_boots
            && (f.cfg.crash_at == 0 || b == 0);
        // The runtimes read these: written as shared memory is.
        unsafe {
            std::ptr::write_volatile(std::ptr::addr_of_mut!(f.cfg.crash_enabled), on as u64);
            std::ptr::write_volatile(std::ptr::addr_of_mut!(f.cfg.boot), b);
        }
        f.crash_points.store(0, Relaxed);
    }

    /// `Op::CrashPoint` [kind, seq, k] from a process of machine `k` > 0: its machine crashes
    /// here, at its `crash_points`-th point, as a crash at a drawn time does (`machine_crash`,
    /// with the point in its `Crash` and `Injected` records), or under `process-at:N` its
    /// processes are killed as the seed's kill does (`machine_kill`, the point in its `Injected`
    /// record), the caller among the processes killed; the run goes on. An `-at` crash fires
    /// once. A process or thread being created
    /// on the machine (a reserved slot of it, a vfork child of it that has not said `Hello`) is in
    /// no table yet, so a crash then could not kill it: the run stops `unsupported` rather than
    /// leave it. Another machine's creations do not matter: the crash does not touch them.
    pub(super) fn machine_point_crash(&mut self, idx: usize) -> Next {
        let k = self.machine_of(idx);
        let creating = (0..MAX_THREADS).any(|i| {
            let s = self.slot(i);
            i != idx && s.state.load(SeqCst) == SLOT_RESERVED && s.machine.load(Relaxed) == k as u64
        }) || self.vfork_on(k);
        if creating {
            self.finish(Verdict::new(
                "unsupported",
                format!(
                    "machine {}: a crash point while a process or thread of the machine was being \
                     created",
                    self.machine_name(k)
                ),
            ));
        }
        let f = &self.machine_tab().faults[k];
        let kind = f.cfg.crash_kind;
        if kind != proto::faults::CRASH_MACHINE && kind != proto::faults::CRASH_PROCESS {
            // `Config::crash_machines` sets no other kind for a machine's points.
            self.finish(Verdict::new(
                "internal",
                format!(
                    "machine {}: a crash point of kind {kind}",
                    self.machine_name(k)
                ),
            ));
        }
        let point = f.crash_points.load(Relaxed);
        if f.cfg.crash_at != 0 {
            let f = &mut self.machine_tab().faults[k];
            unsafe {
                std::ptr::write_volatile(std::ptr::addr_of_mut!(f.cfg.crash_enabled), 0);
                std::ptr::write_volatile(
                    std::ptr::addr_of_mut!(f.cfg.crash_kind),
                    proto::faults::CRASH_NONE,
                );
            }
        }
        if kind == proto::faults::CRASH_PROCESS {
            // `process-at:N`: its processes killed, as the seed's kill at a drawn time; its
            // disk goes on.
            let b = self.machine_tab().boots[k].saturating_sub(1);
            self.machines.point = point;
            self.machine_kill(k, DOWN_KILL_SEED);
            self.machines.point = 0;
            if let Some(e) = self.machine_tab().boot[k].get_mut(b as usize) {
                e.point = point;
            }
        } else {
            self.machine_crash(k, DOWN_CRASH_SEED, point);
        }
        Next::Pick
    }

    /// Draw the seed's kill of `machine`'s current boot (`--faults kill`, `crash-gap-ms`): none
    /// in its last permitted boot (`max-boots`).
    fn kill_next(&mut self, k: usize) {
        let t = self.machine_tab();
        let c = t.conf[k];
        let b = t.boots[k].saturating_sub(1);
        if c.crash == 0 || b + 1 >= c.max_boots {
            return;
        }
        let tries = self.machines.kill_try[k];
        self.machines.kill_try[k] += 1;
        let d = proto::draw(
            self.ctl.config.seed,
            proto::Stream::Machine,
            (k as u64) << 24 | (b & 0xff) << 16 | (tries & 0xff) << 8 | NSUB_KILL,
        );
        let (lo, hi) = (t.crash_gap_min_ns, t.crash_gap_max_ns);
        // In [A, B), A when A = B: as `down-ms`.
        let gap = lo + if hi > lo { d % (hi - lo) } else { 0 };
        self.machines.kill_ev[k] = Some(self.sched.schedule(
            self.now() + gap,
            Event::Machine {
                key: ev_key(EVK_MACHINE_KILL, k),
                live: Live::AfterSetup,
            },
        ));
    }

    /// The down time of `machine`'s restart after boot `b` (`down-ms`), if its restart comes: by
    /// its policy (`always` after an exit within `ok-exit`), and within `max-boots`.
    fn down_time(&self, k: usize, b: u64, how: u64) -> u64 {
        let t = self.machine_tab();
        let c = t.conf[k];
        let restart = match how {
            DOWN_KILL_SEED | DOWN_CRASH_SEED => c.restart != RESTART_NEVER,
            DOWN_EXIT => c.restart == RESTART_ALWAYS,
            _ => false,
        };
        if !restart || t.boots[k] >= c.max_boots.min(BOOTS_MAX as u64) {
            return 0;
        }
        let d = proto::draw(
            self.ctl.config.seed,
            proto::Stream::Machine,
            (k as u64) << 24 | (b & 0xff) << 16 | NSUB_DOWN,
        );
        let (lo, hi) = (t.down_min_ns, t.down_max_ns);
        (lo + if hi > lo { d % (hi - lo) } else { 0 }).max(1)
    }

    /// The live processes of machine `k`, the newest first.
    fn machine_pids(&self, k: usize) -> Vec<i32> {
        self.procs
            .map
            .iter()
            .rev()
            .filter(|(_, p)| p.machine == k && p.state == PState::Live)
            .map(|(pid, _)| *pid)
            .collect()
    }

    /// Whether machine `k` is up (its first process started, and it is not down).
    pub(super) fn machine_is_up(&self, k: usize) -> bool {
        k < MAX_MACHINES && self.machines.up[k]
    }

    /// Machine `k` is down (`how`, with an exit status or signal `value`): the record, its boot's
    /// end, its other processes killed (`others`), and its restart queued after `down` ns. A
    /// pause of it ends first.
    fn machine_down(&mut self, k: usize, how: u64, value: u64, others: &[i32], down: u64) {
        self.pause_down(k);
        let t = self.machine_tab();
        let b = t.boots[k].saturating_sub(1);
        if let Some(e) = self.machines.kill_ev[k].take() {
            self.sched.cancel(e);
        }
        self.machines.up[k] = false;
        self.decide(
            DEC_MACHINE_DOWN,
            0,
            [k as u64, b, how, value, others.len() as u64, down],
            0,
        );
        let now = self.now();
        let points = self.machine_tab().faults[k].crash_points.load(Relaxed);
        if let Some(e) = self.machine_tab().boot[k].get_mut(b as usize) {
            (e.end_ns, e.how, e.value, e.down_ns, e.points) = (now, how, value, down, points);
        }
        if how == DOWN_KILL_SEED || how == DOWN_CRASH_SEED {
            self.kill_inject(k, b, (how == DOWN_CRASH_SEED) as u64, self.machines.point);
        }
        self.machines.killing = true;
        for &pid in others {
            self.kill_now(pid);
        }
        self.machines.killing = false;
        if down > 0 {
            self.machines.start_ev[k] = Some(self.sched.schedule(
                now + down,
                Event::Machine {
                    key: ev_key(EVK_MACHINE_START, k),
                    live: Live::Yes,
                },
            ));
        }
    }

    /// Kill every process of machine `k` (`DOWN_KILL_SEED` or `DOWN_KILL_SCRIPT`); a kill by the
    /// seed queues its restart. A script's kill of a machine that is down cancels its restart.
    /// Returns the processes killed.
    pub(super) fn machine_kill(&mut self, k: usize, how: u64) -> Vec<i32> {
        if let Some(e) = self.machines.start_ev[k].take() {
            self.sched.cancel(e);
        }
        self.machines.pending.retain(|&(_, n)| n != k);
        if !self.machines.up[k] {
            return vec![];
        }
        let pids = self.machine_pids(k);
        let b = self.machine_tab().boots[k].saturating_sub(1);
        let down = self.down_time(k, b, how);
        self.machine_down(k, how, libc::SIGKILL as u64, &pids, down);
        pids
    }

    /// Crash machine `k`'s machine (`DOWN_CRASH_SEED` or `DOWN_CRASH_SCRIPT`), silently: what its
    /// processes' shared mappings hold is logged, then a `Crash` record ends its disk's log;
    /// the wire forgets its ends (no FIN, no RST) and its links are down until it is back, so
    /// a peer learns of the crash only from its own timeouts, or from the RST the machine answers
    /// with once back; its processes are killed; its live tree is logged and its next tree
    /// materialised from its disk's log (`fs-model`, drawn from the seed and the crash's
    /// sequence number); its System V shared memory goes. A crash by the seed queues its
    /// restart; a script's of a machine that is down cancels it. Returns the processes killed.
    pub(super) fn machine_crash(&mut self, k: usize, how: u64, point: u64) -> Vec<i32> {
        if let Some(e) = self.machines.start_ev[k].take() {
            self.sched.cancel(e);
        }
        self.machines.pending.retain(|&(_, n)| n != k);
        if !self.machines.up[k] {
            return vec![];
        }
        let pids = self.machine_pids(k);
        let b = self.machine_tab().boots[k].saturating_sub(1);
        let down = self.down_time(k, b, how);
        let seq = self.ctl.seq.load(Relaxed);
        let mapping: Vec<(i32, usize)> = self
            .mapping_pids()
            .into_iter()
            .filter(|&(_, n)| n == k)
            .collect();
        let crash = [proto::faults::CRASH_MACHINE, b, point, 0, 0, 0];
        if let Err(e) = self.flush_maps(&mapping, seq).and_then(|()| {
            super::crash::append(
                self.ctl,
                k,
                proto::oplog::OpKind::Crash,
                0,
                crash,
                &[],
                seq,
                0,
            )
        }) {
            self.finish(Self::maps_verdict(e));
        }
        self.links.down |= 1 << k;
        self.wire_machine_down(k);
        self.machines.crashing = true;
        self.machines.point = point;
        self.machine_down(k, how, 0, &pids, down);
        self.machines.point = 0;
        self.machines.crashing = false;
        if let Some(e) = self.machine_tab().boot[k].get_mut(b as usize) {
            e.point = point;
        }
        self.machine_tab().crashes[k] += 1;
        let next = self.disk_end(k, seq);
        match next {
            Ok(t) => self.machines.next_tree[k] = Some(t),
            Err(e) => self.finish(Verdict::new(
                "infra",
                format!("machine {}: its machine crash: {e}", self.machine_name(k)),
            )),
        }
        self.machines.shm.remove(&k);
        pids
    }

    /// Machine `k`'s disk ends at a machine crash at sequence number `seq` (its processes are
    /// dead): its live tree is logged, and the tree its next boot starts from returned.
    fn disk_end(&mut self, k: usize, seq: u64) -> Result<Vec<u8>, String> {
        let p = self.disks.path(k).ok_or("its disk was not reached")?;
        let live = super::crash::export_machine(self.ctl, k, &p)?;
        self.disks.close(k);
        super::shadows::forget_machine(self.ctl, k)?;
        let log = super::crash::disk_log(self.ctl, k, self.machines.disk_at[k])?;
        let model = if self.machine_tab().fs_model == 1 {
            crate::durability::materialise::Model::PosixStrict
        } else {
            crate::durability::materialise::Model::Ext4Ordered
        };
        let mut t = crate::durability::materialise::materialise(
            &log,
            u64::MAX,
            self.ctl.config.seed,
            seq,
            model,
        )?;
        t.times_from(&live);
        self.machines.next_times[k] = Some(t.times());
        Ok(t.encode())
    }

    /// The seed's kill as a fault: an `Injected` record, counted under `crash`.
    fn kill_inject(&mut self, k: usize, b: u64, machine: u64, point: u64) {
        let seq = self.next_seq();
        let rec = proto::Rec {
            seq,
            vclock_ns: self.now(),
            slot: 0,
            kind: proto::RecKind::Injected as u8,
            class: 0,
            nr: 0,
            args: [INJ_MACHINE_KILL, k as u64, b, machine, point, 0],
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

    /// `Op::Machine` [verb, machine] from main (the runtime checked the words).
    pub(super) fn machine_op(&mut self, idx: usize, a: [u64; 6]) -> Next {
        let k = a[1] as usize;
        if self.machine_of(idx) != 0 || k == 0 || k >= self.machine_count() {
            return Next::Continue(-(libc::EPERM as i64));
        }
        match a[0] {
            // A machine that is down stays down: its restart to come is cancelled.
            MACHINE_KILL => {
                let up = self.machines.up[k];
                self.machine_kill(k, DOWN_KILL_SCRIPT);
                Next::Continue(if up { 0 } else { -(libc::EALREADY as i64) })
            }
            MACHINE_CRASH => {
                let up = self.machines.up[k];
                self.machine_crash(k, DOWN_CRASH_SCRIPT, 0);
                Next::Continue(if up { 0 } else { -(libc::EALREADY as i64) })
            }
            CLOCK_STEP => self.clock_step(k, a[2] as i64),
            MACHINE_PAUSE | MACHINE_RESUME => {
                // A starting machine cannot be paused yet (and is not paused: a resume of it is
                // `EALREADY`, `pause_op`).
                if a[0] == MACHINE_PAUSE && self.machines.pending.contains(&(EVK_MACHINE_START, k))
                {
                    return Next::Continue(-(libc::EAGAIN as i64));
                }
                self.pause_op(a[0], k)
            }
            MACHINE_START => {
                let queued = self.machines.pending.contains(&(EVK_MACHINE_START, k));
                if self.machines.up[k] || queued {
                    return Next::Continue(-(libc::EALREADY as i64));
                }
                // `max-boots` bounds the seed; the script only the table's record.
                if self.machine_tab().boots[k] >= BOOTS_MAX as u64 {
                    return Next::Continue(-(libc::EAGAIN as i64));
                }
                if let Some(e) = self.machines.start_ev[k].take() {
                    self.sched.cancel(e);
                }
                self.machines.pending.push_back((EVK_MACHINE_START, k));
                Next::Continue(0)
            }
            _ => Next::Continue(-(libc::EINVAL as i64)),
        }
    }

    /// A process ended: if it was a machine's first, its status is the machine's, and unless the
    /// supervisor killed it, the machine's end: its other processes are killed, and its exit
    /// status or signal says what follows (an exit within its `ok-exit` stops it, perhaps to
    /// restart; another ends the run `failure`; a signal ends it `crash`).
    pub(super) fn machine_gone(&mut self, pid: i32, word: i64) {
        if self.machine_count() == 0 {
            return;
        }
        let Some(k) = (1..MAX_MACHINES).find(|&k| self.machines.first[k] == pid) else {
            return;
        };
        self.machine_tab().status[k] = word as u64;
        // Once: a later process given the same pid is not the machine's first.
        self.machines.first[k] = 0;
        if self.machines.killing || !self.machines.up[k] {
            return;
        }
        let c = self.machine_tab().conf[k];
        let (how, value) = if word & 0x7f != 0 {
            (DOWN_SIGNAL, (word & 0x7f) as u64)
        } else {
            let s = ((word >> 8) & 0xff) as u64;
            (if c.ok(s) { DOWN_EXIT } else { DOWN_FAILED }, s)
        };
        let others: Vec<i32> = self
            .machine_pids(k)
            .into_iter()
            .filter(|&p| p != pid)
            .collect();
        let b = self.machine_tab().boots[k].saturating_sub(1);
        let down = self.down_time(k, b, how);
        self.machine_down(k, how, value, &others, down);
        if how == DOWN_EXIT {
            return;
        }
        self.machine_tab().ended_by = k as u64 + 1;
        let name = self.machine_name(k);
        let mut v = if how == DOWN_SIGNAL {
            let mut v = Verdict::new(
                "machine-crash",
                format!(
                    "machine {name}: killed by signal {value} ({})",
                    crate::outcome::signal_name(value as i64)
                ),
            );
            v.signal = Some(value as i64);
            v
        } else {
            let mut v = Verdict::new(
                "machine-failed",
                format!("machine {name}: exit status {value}"),
            );
            v.exit_status = Some(value as i64);
            v
        };
        v.detail.truncate(400);
        self.machines_stop();
        self.finish(v)
    }

    /// Main ended the run: a record for each machine that still has processes.
    pub(super) fn machines_stop(&mut self) {
        for k in 1..self.machine_count() {
            if self.machines.up[k] {
                let t = self.machine_tab();
                let b = t.boots[k].saturating_sub(1) as usize;
                let points = t.faults[k].crash_points.load(Relaxed);
                if let Some(e) = t.boot[k].get_mut(b) {
                    e.points = points;
                }
            }
            let live = self
                .procs
                .map
                .values()
                .filter(|p| p.machine == k && p.state == super::proc::PState::Live)
                .count();
            if live > 0 {
                self.decide(DEC_MACHINE_STOP, 0, [k as u64, live as u64, 0, 0, 0, 0], 0);
            }
        }
    }
}

/// Ask the keeper to start boot `boot` of machine `machine` (its first process); returns once it
/// exists, with where its output starts in the machine's stdout and stderr.
fn keeper_start(machine: usize, boot: u64, tree: Option<&[u8]>) -> Result<(u64, u64), String> {
    let asked = match tree {
        None => {
            let b = [machine as u8, boot as u8];
            let r = unsafe { libc::send(FD_MACHINES, b.as_ptr().cast(), 2, libc::MSG_NOSIGNAL) };
            if r == 2 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error().to_string())
            }
        }
        Some(t) => tree_fd(t).and_then(|fd| {
            use std::os::fd::AsRawFd;
            crate::sandbox::send_with(
                FD_MACHINES,
                &[machine as u8, boot as u8, 1],
                &[fd.as_raw_fd()],
            )
        }),
    };
    if let Err(e) = asked {
        return Err(format!("asking the keeper to start it: {e}"));
    }
    let mut buf = [0u8; 4096];
    let n = unsafe { libc::recv(FD_MACHINES, buf.as_mut_ptr().cast(), buf.len(), 0) };
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

/// A memfd holding `tree`, read from its start.
fn tree_fd(tree: &[u8]) -> Result<std::os::fd::OwnedFd, String> {
    use std::io::{Seek, Write};
    use std::os::fd::FromRawFd;
    let fd = unsafe { libc::memfd_create(c"patina-tree".as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(format!("memfd: {}", std::io::Error::last_os_error()));
    }
    let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
    f.write_all(tree)
        .and_then(|()| f.rewind())
        .map_err(|e| format!("the tree: {e}"))?;
    Ok(f.into())
}
