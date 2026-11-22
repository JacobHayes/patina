//! `ready` probes (`[machine.NAME] ready`) and the start of the fault window.
//!
//! A run that declares a probe on any machine, main included, starts with its fault window
//! closed (`FaultCfg::fault_after_seq` at its maximum, set by the launcher from the
//! configuration: known before the first instruction). At boot, once every machine's first
//! process has started, the supervisor starts one runner per probe on the probe's machine
//! (main's forked as a phase's root is, another's by the keeper in the machine's view), a guest
//! process (`crate::ready::runner`) that runs the probe every 100 ms of virtual time until it
//! exits 0, then exits 0 itself: its end makes its machine ready. A machine without a probe is
//! ready when it starts. While a machine other than main waits, main's first thread is frozen
//! with its `Hello` answered (`Sched::freeze`, as a paused machine's): main's command starts
//! when every other machine is ready. When the last machine is ready (`DEC_READY`), the window
//! opens at that record. A machine whose first process (main: its command) ends before it is ready, or any probe
//! not passed 60 s of virtual time after boot, ends the run `error`, stop `ready`: the faults
//! never began. Probes start at the first boot; a runner killed before its machine is ready
//! (with the machine, by a script's `kill`, or alone) starts again once the machine is up, so
//! its probe keeps polling. Everything here is in the turn's order.

use super::link::{ev_key, EVK_READY};
use super::phase::Cmd;
use super::sched::{Event, EventId, Live};
use super::{Sup, Verdict};
use proto::ctl::*;
use proto::machine::MAX_MACHINES;
use std::sync::atomic::Ordering::SeqCst;

/// Virtual time after boot by which every probe must have passed.
const DEADLINE_NS: u64 = 60_000_000_000;

#[derive(Default)]
pub struct Ready {
    /// Each machine's probe (`--ready K`, `--ready-arg W`; empty: none).
    pub words: Vec<Vec<String>>,
    /// Machines whose probe has not passed (bit `k`).
    waiting: u64,
    /// Each machine's runner while it runs (0: none).
    runner: [i32; MAX_MACHINES],
    /// The slot of a runner whose `Hello` is awaited (`proc::hello`, `machines::boot_hello`).
    pub starting: Option<usize>,
    /// Main's command waits for the other machines: its first thread is frozen.
    pub hold: bool,
    deadline: Option<EventId>,
}

impl Ready {
    pub fn new(words: Vec<Vec<String>>) -> Ready {
        Ready {
            words,
            ..Default::default()
        }
    }

    /// Machine `k`'s probe, if it declares one.
    pub fn probe(&self, k: usize) -> Option<&[String]> {
        self.words
            .get(k)
            .filter(|w| !w.is_empty())
            .map(|w| w.as_slice())
    }

    pub fn declared(&self) -> bool {
        self.words.iter().any(|w| !w.is_empty())
    }
}

impl Sup {
    /// Boot, every machine's first process started and main's `Hello` answered with its reply
    /// kept: start the runners, and say who runs first (main, unless it waits for the others).
    pub(super) fn ready_begin(&mut self) {
        let n = self.machine_count().max(1);
        let now = self.now();
        for k in 0..n {
            match self.ready.probe(k) {
                Some(_) => self.ready.waiting |= 1 << k,
                None => self.machine_tab().ready_ns[k] = now,
            }
        }
        for k in 0..n {
            if self.ready.probe(k).is_some() {
                self.ready_start(k);
            }
        }
        self.ready.deadline = Some(self.sched.schedule(
            now + DEADLINE_NS,
            Event::Machine {
                key: ev_key(EVK_READY, 0),
                live: Live::Yes,
            },
        ));
        if self.ready.waiting & !1 == 0 {
            self.reply(0, 0);
            return;
        }
        self.ready.hold = true;
        self.sched.freeze(0);
        let (to, seq) = self.choose();
        let got = self.decide(DEC_READY, 0, [READY_HOLD, 0, 0, 0, 0, 0], to as i64);
        debug_assert_eq!(got, seq);
        self.reply(0, to);
    }

    /// Start machine `k`'s runner in a free slot and wait for its `Hello`.
    fn ready_start(&mut self, k: usize) {
        let Some(slot) = (0..MAX_THREADS).find(|&i| self.slot(i).state.load(SeqCst) == SLOT_FREE)
        else {
            self.finish(Verdict::new(
                "capacity",
                "no thread slot left for a ready probe",
            ))
        };
        let s = self.slot(slot);
        s.go.store(0, SeqCst);
        s.tid.store(0, SeqCst);
        s.pid.store(0, SeqCst);
        s.vmask.store(0, SeqCst);
        s.sigpend.store(0, SeqCst);
        s.sched.store(0, SeqCst);
        s.machine.store(k as u64, SeqCst);
        s.state.store(SLOT_RESERVED, SeqCst);
        // A process tree of its own: its runtime installs the seccomp filter (the machine's
        // other processes wait for the turn until its `Hello`, keeping theirs).
        self.ctl.filter_installed.fetch_and(!(1u64 << k), SeqCst);
        self.machines.booting = Some(slot);
        self.ready.starting = Some(slot);
        if k == 0 {
            self.slot_machine(slot, 0);
            let argv = crate::ready::runner_argv(self.ready.probe(0).unwrap_or_default());
            let exe = argv[1].clone();
            self.fork_root(&Cmd { exe, argv });
        } else if let Err(e) = super::machines::keeper_probe(k) {
            self.finish(Verdict::new(
                "infra",
                format!("machine {}: its ready probe: {e}", self.machine_name(k)),
            ));
        }
        self.boot_hello(slot, k, 0);
        self.ready.starting = None;
        self.ready.runner[k] = self.sched.entries[slot].pid;
    }

    /// Process `pid` ended with wait status `word` (`proc::process_died`): if it was a
    /// runner, its machine is ready when it exited 0. A runner killed while its machine waits
    /// runs again: now if its machine is up, else when it is back (`machines::start_machine`).
    pub(super) fn ready_gone(&mut self, pid: i32, word: i64) {
        let Some(k) = (0..MAX_MACHINES).find(|&k| pid != 0 && self.ready.runner[k] == pid) else {
            return;
        };
        self.ready.runner[k] = 0;
        if word == 0 && self.ready_waits(k) {
            self.machine_ready(k);
        } else if word & 0x7f != 0 && (k == 0 || self.machine_is_up(k)) {
            self.ready_queue(k);
        }
    }

    /// Machine `k` waits and its runner is gone: start one again where nothing in flight can
    /// be disturbed (`machine_actions`).
    pub(super) fn ready_queue(&mut self, k: usize) {
        if self.ready_waits(k) && self.ready.runner[k] == 0 {
            self.machines.pending.push_back((EVK_READY, k));
        }
    }

    /// The runner queued by `ready_queue`, if its machine still waits, is up and has none.
    pub(super) fn ready_again(&mut self, k: usize) {
        if self.ready_waits(k) && self.ready.runner[k] == 0 && (k == 0 || self.machine_is_up(k)) {
            self.ready_start(k);
        }
    }

    /// Machine `k` is ready: its time, the record, and when it is the last, the window opens
    /// and main's command may run.
    fn machine_ready(&mut self, k: usize) {
        self.ready.waiting &= !(1 << k);
        self.machine_tab().ready_ns[k] = self.now();
        let all = self.ready.waiting == 0;
        let seq = self.decide(DEC_READY, 0, [k as u64, all as u64, 0, 0, 0, 0], 0);
        // Main's command runs once every other machine is ready (its own probe holds only
        // the faults).
        if self.ready.waiting & !1 == 0 && std::mem::take(&mut self.ready.hold) {
            self.sched.thaw(0);
        }
        if !all {
            return;
        }
        let f = &self.ctl.faults.cfg;
        unsafe {
            let at = std::ptr::addr_of!(f.fault_after_seq) as *mut u64;
            if std::ptr::read_volatile(at) == u64::MAX {
                std::ptr::write_volatile(at, seq);
            }
        }
        if let Some(e) = self.ready.deadline.take() {
            self.sched.cancel(e);
        }
    }

    /// Main's command ended (`proc::process_died`): before main was ready, the run ends
    /// `ready`, as a machine's run that ends before it is ready does.
    pub(super) fn ready_main_gone(&mut self, word: i64) {
        if !self.ready_waits(0) {
            return;
        }
        let ended = if word & 0x7f != 0 {
            format!("was killed by signal {}", word & 0x7f)
        } else {
            format!("exited {}", (word >> 8) & 0xff)
        };
        if self.machine_count() > 0 {
            self.machines_stop();
        }
        self.finish(Verdict::new(
            "ready",
            format!("main's command {ended} before main was ready; the faults had not begun"),
        ))
    }

    /// Whether machine `k` has a probe that has not passed.
    pub(super) fn ready_waits(&self, k: usize) -> bool {
        k < MAX_MACHINES && self.ready.waiting >> k & 1 != 0
    }

    /// The deadline came (`EVK_READY`): a machine still waiting ends the run, the first
    /// besides main named before main.
    pub(super) fn ready_deadline(&mut self) {
        self.ready.deadline = None;
        let w = self.ready.waiting;
        if w == 0 {
            return;
        }
        let k = if w & !1 != 0 {
            (w & !1).trailing_zeros() as usize
        } else {
            0
        };
        let name = if self.machine_count() == 0 {
            "main".to_string()
        } else {
            self.machine_name(k)
        };
        let probe = self.ready.probe(k).unwrap_or_default().join(" ");
        if self.machine_count() > 0 {
            self.machines_stop();
        }
        self.finish(Verdict::new(
            "ready",
            format!(
                "machine {name} was not ready {} s after boot: its probe `{probe}` never exited 0 \
                 (what it last said is in {name}'s stderr); the faults had not begun",
                DEADLINE_NS / 1_000_000_000
            ),
        ))
    }
}
