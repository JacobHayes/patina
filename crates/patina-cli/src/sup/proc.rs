//! Processes in the supervisor: the process table, fork, vfork, exec, the exit
//! barrier of every process, wait, reparenting to PID 1, `SIGCHLD`, and the real kill
//! of a process sent `SIGKILL`.
//!
//! Everything here runs while the supervisor holds the turn, so the table changes only in
//! the order of boundary events. The kernel does the plumbing (fork, exec, wait, reparenting);
//! the table mirrors what the supervisor needs to decide: who is whose parent, who is a
//! zombie, the virtual death signal of each zombie, and the pidfd of the exit barrier.

use super::sched::{State, Wait, WakeReason};
use super::signal::Target;
use super::{Next, Sup};
use crate::outcome::Verdict;
use crate::sys::*;
use proto::ctl::*;
use std::collections::BTreeMap;
use std::sync::atomic::Ordering::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PState {
    Live,
    /// Passed its exit barrier, not yet waited for. (Reaped processes leave the table.)
    Zombie,
}

#[derive(Debug)]
pub struct Process {
    pub ppid: i32,
    pub state: PState,
    pub pidfd: i32,
    /// The signal that reports this child to its parent (SIGCHLD or 0).
    pub exit_signal: u64,
    /// Death: the status word the kernel reports, and the virtual signal (0: none).
    pub status: i64,
    pub vsig: u64,
    /// While a vfork child has not exec'd: the parent's slot, blocked in the kernel.
    pub vfork_parent: Option<usize>,
    /// SIGCHLD ignored or `SA_NOCLDWAIT`: the kernel reaps its children itself.
    pub autoreap: bool,
    pub pdeathsig: u64,
    /// Signals whose disposition is `SIG_IGN` (carried across execve).
    pub ign: u64,
    /// Processes started and images executed (evidence).
    pub execs: u64,
}

#[derive(Default)]
pub struct Procs {
    pub map: BTreeMap<i32, Process>,
    /// The first guest: the run ends when it exits.
    pub main: i32,
    /// Address-space ids handed out (futex keys of private memory).
    next_asid: u64,
    /// vfork children announced by `VforkStart` and not yet said `Hello`: child slot → parent slot.
    vfork_pending: BTreeMap<usize, usize>,
    /// Counters for the outcome: processes created, execs.
    pub created: u64,
    pub execs: u64,
}

impl Procs {
    pub fn new_asid(&mut self) -> u64 {
        self.next_asid += 1;
        // Above every slot number (the asid of images started before processes was their slot).
        (1 << 20) + self.next_asid
    }
}

const SIGKILL: u64 = 9;
const CLD_EXITED: u64 = 1;
const CLD_KILLED: u64 = 2;

impl Sup {
    fn proc_new(&mut self, pid: i32, ppid: i32, pidfd: i32, exit_signal: u64, from: Option<i32>) {
        let (autoreap, ign) = from
            .and_then(|p| self.procs.map.get(&p))
            .map(|p| (p.autoreap, p.ign))
            .unwrap_or((false, 0));
        self.procs.map.insert(
            pid,
            Process {
                ppid,
                state: PState::Live,
                pidfd,
                exit_signal,
                status: 0,
                vsig: 0,
                vfork_parent: None,
                autoreap,
                pdeathsig: 0,
                ign,
                execs: 0,
            },
        );
        self.procs.created += 1;
        // Signal state of a child: the parent's dispositions, nothing pending, no timer.
        if let Some(p) = from {
            let child = self.sproc_forked(p);
            self.sig.procs.insert(pid, child);
            self.io.timers_forked(p, pid);
        }
    }

    fn open_pidfd(&self, pid: i32) -> i32 {
        match pidfd_open(pid) {
            Ok(fd) => fd,
            Err(e) => self.finish(Verdict::new("infra", format!("pidfd_open({pid}): {e}"))),
        }
    }

    /// `Hello` from slot `idx`.
    pub fn hello(&mut self, idx: usize, a: [u64; 6]) -> Next {
        if self.ctl.timing[TM_FIRST_HELLO].load(Relaxed) == 0 {
            self.ctl.timing[TM_FIRST_HELLO].store(super::now_ns(), Relaxed);
        }
        let (pid, tid) = (a[0] as i32, a[1] as i32);
        match a[2] {
            HELLO_VFORK => {
                let Some(parent) = self.procs.vfork_pending.remove(&idx) else {
                    self.finish(Verdict::new(
                        "infra",
                        format!("vfork child in slot {idx} without VforkStart"),
                    ));
                };
                let ppid = self.sched.entries[parent].pid;
                let asid = self.sched.entries[parent].asid; // the same memory as the parent
                self.sched.add(idx, tid, pid, asid);
                let s = self.slot(idx);
                s.tid.store(tid, Relaxed);
                s.pid.store(pid, Relaxed);
                s.state.store(SLOT_LIVE, SeqCst);
                let fd = self.open_pidfd(pid);
                self.proc_new(pid, ppid, fd, SIGCHLD_U, Some(ppid));
                self.procs.map.get_mut(&pid).unwrap().vfork_parent = Some(parent);
                self.signal_thread_new(idx, pid);
                Next::Continue(0)
            }
            HELLO_IMAGE if self.sched.entries[idx].state == State::Free => {
                // The first guest.
                let asid = self.procs.new_asid();
                self.sched.add(idx, tid, pid, asid);
                self.slot(idx).state.store(SLOT_LIVE, SeqCst);
                self.procs.main = pid;
                self.proc_new(pid, 1, self.pidfd, SIGCHLD_U, None);
                self.signal_thread_new(idx, pid);
                Next::Continue(0)
            }
            HELLO_IMAGE => {
                // A new image after execve, in the same task and slot, holding the turn.
                // close-on-exec descriptors are closed now: read every hidden end.
                self.wire_scan_all();
                let release = self
                    .procs
                    .map
                    .get_mut(&pid)
                    .and_then(|p| p.vfork_parent.take());
                if let Some(parent) = release {
                    self.sched.make_runnable(parent, WakeReason::Woken);
                }
                let ign = self.procs.map.get(&pid).map(|p| p.ign).unwrap_or(0);
                Next::Continue(ign as i64)
            }
            // Threads and fork children were registered by their parent's `Forked`.
            _ => Next::Continue(0),
        }
    }

    /// `Forked` of a process (threads are served in `mod.rs`).
    pub fn forked_process(&mut self, idx: usize, a: [u64; 6]) -> Next {
        let (child, tid, pid) = (a[0] as usize, a[1] as i32, a[2] as i32);
        if child >= MAX_THREADS
            || !matches!(
                self.sched.entries[child].state,
                State::Free | State::Exiting
            )
        {
            self.finish(Verdict::new(
                "infra",
                format!("Forked: slot {child} is in use"),
            ));
        }
        let ppid = self.sched.entries[idx].pid;
        let asid = self.procs.new_asid();
        self.sched.free(child);
        self.sched.add(child, tid, pid, asid);
        let s = self.slot(child);
        s.tid.store(tid, Relaxed);
        s.pid.store(pid, Relaxed);
        s.state.store(SLOT_LIVE, SeqCst);
        let fd = self.open_pidfd(pid);
        self.proc_new(pid, ppid, fd, a[4], Some(ppid));
        self.shm.forked(ppid, pid);
        self.signal_thread_new(child, pid);
        Next::Continue(0)
    }

    /// `VforkStart` [child slot, 0 start | 1 the clone failed].
    pub fn vfork_start(&mut self, idx: usize, a: [u64; 6]) -> Next {
        let child = a[0] as usize;
        if a[1] == 0 {
            // An `Exiting` slot was reclaimed by the runtime (its kernel task is gone), as for
            // `Forked` (CPython's `subprocess` after its threads exited).
            if child >= MAX_THREADS
                || !matches!(
                    self.sched.entries[child].state,
                    State::Free | State::Exiting
                )
            {
                self.finish(Verdict::new(
                    "infra",
                    format!("VforkStart: slot {child} is in use"),
                ));
            }
            self.sched.free(child);
            self.procs.vfork_pending.insert(child, idx);
            // Not runnable until the child execs or exits; it keeps the turn until it blocks
            // in the kernel, which hands the turn to the child.
            self.sched
                .park(idx, Wait::Vfork, None, super::signal::MayPark::vfork(idx));
        } else {
            self.procs.vfork_pending.remove(&child);
            self.sched.make_runnable(idx, WakeReason::Woken);
        }
        Next::Continue(0)
    }

    /// `Exec` [SIG_IGN set] from `idx`: the image is about to be replaced.
    pub fn exec(&mut self, idx: usize, a: [u64; 6]) -> Next {
        let pid = self.sched.entries[idx].pid;
        // The kernel kills the other threads during the exec; they never say ThreadExit.
        for s in self.sched.slots_of(pid) {
            if s != idx {
                self.sched.free(s);
                self.signal_thread_gone(s);
                self.slot(s).state.store(SLOT_FREE, SeqCst);
            }
        }
        self.sched.entries[idx].asid = self.procs.new_asid();
        // A thread other than the leader takes over the process id.
        if self.sched.entries[idx].tid != pid {
            self.sched.entries[idx].tid = pid;
            self.slot(idx).tid.store(pid, Relaxed);
        }
        // The old image's shared memory attachments end.
        let now = self.now();
        self.shm.gone(pid, now);
        // Handled signals return to their default; ignored ones stay ignored.
        if let Some(p) = self.sig.procs.get_mut(&pid) {
            for (s, k) in p.kinds.iter_mut().enumerate().skip(1) {
                if *k == SIGK_HANDLER {
                    *k = if sig_default_ignored(s as u64) {
                        SIGK_IGNORE
                    } else {
                        SIGK_DEFAULT
                    };
                }
            }
        }
        if let Some(p) = self.procs.map.get_mut(&pid) {
            p.ign = a[0];
            p.autoreap = a[0] & (1 << 16) != 0; // SA_NOCLDWAIT does not survive exec; SIG_IGN does
            p.execs += 1;
        }
        self.procs.execs += 1;
        Next::Continue(0)
    }

    /// `WaitPark` from `idx`.
    pub fn wait_park(&mut self, idx: usize, a: [u64; 6]) -> Next {
        match a[0] {
            WAIT_PARK => {
                // A signal already deliverable interrupts at once.
                let Some(ok) = self.may_block(idx) else {
                    return Next::Continue(-(libc::EINTR as i64));
                };
                self.sched.park(idx, Wait::Child, None, ok);
                Next::Pick
            }
            WAIT_REAPED => {
                let pid = a[1] as i32;
                let Some(p) = self.procs.map.get(&pid) else {
                    return Next::Continue(-1);
                };
                let v = if p.vsig != 0 {
                    (p.vsig & 0x7f) as i64
                } else {
                    -1
                };
                if a[2] != 0 && p.state == PState::Zombie {
                    let p = self.procs.map.remove(&pid).unwrap();
                    if pid != self.procs.main {
                        unsafe { libc::close(p.pidfd) };
                    }
                }
                Next::Continue(v)
            }
            _ => Next::Continue(-(libc::EINVAL as i64)),
        }
    }

    /// PR_SET_PDEATHSIG / PR_GET_PDEATHSIG (`SigAction` with signal 0).
    pub fn pdeathsig(&mut self, idx: usize, a: [u64; 6]) -> Next {
        let pid = self.sched.entries[idx].pid;
        let Some(p) = self.procs.map.get_mut(&pid) else {
            return Next::Continue(0);
        };
        if a[1] == SIGACT_PDEATHSIG {
            p.pdeathsig = a[2];
            Next::Continue(0)
        } else {
            Next::Continue(p.pdeathsig as i64)
        }
    }

    /// SIGCHLD's disposition changed: is auto-reaping on?
    pub fn note_autoreap(&mut self, pid: i32, on: bool) {
        if let Some(p) = self.procs.map.get_mut(&pid) {
            p.autoreap = on;
        }
    }

    /// `ProcExit` (and the `ThreadExit` of a last thread) has no reply: the process runs
    /// its real exit while the supervisor works, closing its descriptors. Wait for the exit
    /// barrier before events due now are fired (a wire delivery writes into guest-visible
    /// buffers), so the kernel's readiness order, e.g. epoll's ready list, does not depend on
    /// that race. `process_died` waits on the same pidfd again (readable at once).
    pub fn exit_barrier_first(&mut self, idx: usize, op: u32) {
        let pid = self.sched.entries[idx].pid;
        let last = op == Op::ThreadExit as u32 && self.sched.live_in(pid) <= 1;
        if op != Op::ProcExit as u32 && !last {
            return;
        }
        let Some(pidfd) = self.procs.map.get(&pid).map(|p| p.pidfd) else {
            return;
        };
        if !readable(pidfd, self.ctl.config.stall_ms as i32) {
            self.finish(Verdict::new(
                "stall",
                format!("exit barrier: process {pid} did not finish exiting"),
            ));
        }
    }

    /// Process `pid` is ending: `exit_group`, a default-action signal, the exit of its last
    /// thread, or a real SIGKILL sent by the supervisor. Exit barrier: nothing runs until the
    /// kernel has finished the exit. Then the I/O generation moves (its descriptors are
    /// closed), its children go to PID 1, its parent gets SIGCHLD and its waiters wake.
    /// `status` is the exit code as `128 + sig` for a death by signal; `vsig` that signal.
    pub fn process_died(&mut self, pid: i32, status: i64, vsig: u64) {
        let Some(pidfd) = self.procs.map.get(&pid).map(|p| p.pidfd) else {
            return;
        };
        let cfg = self.ctl.config;
        if !readable(pidfd, cfg.stall_ms as i32) {
            self.finish(Verdict::new(
                "stall",
                format!("exit barrier: process {pid} did not finish exiting"),
            ));
        }
        for s in self.sched.slots_of(pid) {
            self.sched.free(s);
            self.signal_thread_gone(s);
            self.slot(s).state.store(SLOT_FREE, SeqCst);
        }
        if let Some(sp) = self.sig.procs.remove(&pid) {
            if let Some((id, _)) = sp.timer {
                self.sched.cancel(id);
            }
        }
        self.io.timers_exited(&mut self.sched, pid);
        let now = self.now();
        self.shm.gone(pid, now);
        // The process's descriptors are closed now.
        self.ctl
            .io
            .gen
            .store(self.ctl.io.gen.load(Relaxed) + 1, Relaxed);
        self.wire_scan_all(); // its sockets' last references may be gone
        let word = if vsig != 0 {
            (vsig & 0x7f) as i64
        } else {
            (status & 0xff) << 8
        };
        let (ppid, exit_signal, vfork_parent) = {
            let p = self.procs.map.get_mut(&pid).unwrap();
            p.state = PState::Zombie;
            p.status = word;
            p.vsig = vsig;
            (p.ppid, p.exit_signal, p.vfork_parent.take())
        };
        self.decide(
            DEC_PROC_GONE,
            0,
            [pid as u64, word as u64, vsig, ppid as u64, 0, 0],
            0,
        );
        if pid == self.procs.main {
            return; // the caller ends the run
        }
        if let Some(parent) = vfork_parent {
            self.sched.make_runnable(parent, WakeReason::Woken);
        }
        // Orphans go to PID 1 (the kernel has reparented them by now); zombies among them
        // are reaped by the supervisor; a parent-death signal is raised.
        let kids: Vec<i32> = self
            .procs
            .map
            .iter()
            .filter(|(_, c)| c.ppid == pid)
            .map(|(k, _)| *k)
            .collect();
        for k in kids {
            let (zombie, pds) = {
                let c = self.procs.map.get_mut(&k).unwrap();
                c.ppid = 1;
                (c.state == PState::Zombie, c.pdeathsig)
            };
            if zombie {
                self.reap_orphan(k);
            } else if pds != 0 {
                self.send_to(Target::Proc(k), pds, sig_info(pds, 0, pid, 0));
            }
        }
        let parent_live = self
            .procs
            .map
            .get(&ppid)
            .is_some_and(|p| p.state == PState::Live);
        let autoreap = self.procs.map.get(&ppid).is_some_and(|p| p.autoreap);
        if ppid == 1 {
            self.reap_orphan(pid);
        } else if autoreap {
            // The kernel released it already (its parent ignores SIGCHLD or set SA_NOCLDWAIT).
            if let Some(p) = self.procs.map.remove(&pid) {
                unsafe { libc::close(p.pidfd) };
            }
        }
        if parent_live && ppid != 1 {
            for s in self.sched.slots_of(ppid) {
                if let State::Parked {
                    wait: Wait::Child, ..
                } = self.sched.entries[s].state
                {
                    self.sched.make_runnable(s, WakeReason::Woken);
                }
            }
            if exit_signal != 0 {
                let (code, st) = if vsig != 0 {
                    (CLD_KILLED, vsig)
                } else {
                    (CLD_EXITED, (status & 0xff) as u64)
                };
                let mut info = sig_info(exit_signal, code as i32, pid, 0);
                info[3] = st;
                self.send_to(Target::Proc(ppid), exit_signal, info);
            }
        }
        self.io.sync(&mut self.sched, self.ctl);
    }

    /// The supervisor is the parent: reap the zombie and forget it.
    fn reap_orphan(&mut self, pid: i32) {
        let mut st = 0;
        unsafe { libc::waitpid(pid, &mut st, 0) };
        if let Some(p) = self.procs.map.remove(&pid) {
            unsafe { libc::close(p.pidfd) };
        }
    }

    /// Kill process `pid` for real (`SIGKILL`): every thread of it sleeps in the runtime or,
    /// for a vfork parent, in the kernel; none holds the turn unless it is the sender.
    pub fn kill_now(&mut self, pid: i32) {
        let Some(fd) = self
            .procs
            .map
            .get(&pid)
            .filter(|p| p.state == PState::Live)
            .map(|p| p.pidfd)
        else {
            return;
        };
        let r = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                fd,
                SIGKILL as i32,
                std::ptr::null::<u8>(),
                0,
            )
        };
        if r != 0 {
            self.finish(Verdict::new(
                "infra",
                format!("pidfd_send_signal({pid}, SIGKILL) failed"),
            ));
        }
        self.process_died(pid, 128 + SIGKILL as i64, SIGKILL);
        if pid == self.procs.main {
            self.main_exit(128 + SIGKILL as i64, SIGKILL as i64);
        }
    }

    /// The first guest is gone: the run's verdict.
    pub fn main_exit(&self, status: i64, sig: i64) -> ! {
        let mut v = if sig != 0 {
            Verdict::new("failed", format!("killed by signal {sig}"))
        } else if status == 0 {
            Verdict::new("ok", "")
        } else {
            Verdict::new("failed", format!("exit status {status}"))
        };
        v.exit_status = Some(status);
        v.signal = if sig != 0 { Some(sig) } else { None };
        self.finish(v)
    }

    /// A live process's pidfd became readable without its exit going through the runtime.
    /// A guest process that ended without telling the supervisor (its pidfd is readable).
    pub fn unexpected_death(&self) -> Option<i32> {
        let live: Vec<(i32, i32)> = self
            .procs
            .map
            .iter()
            .filter(|(_, p)| p.state == PState::Live)
            .map(|(k, p)| (*k, p.pidfd))
            .collect();
        if live.is_empty() {
            return None;
        }
        let mut pf: Vec<libc::pollfd> = live
            .iter()
            .map(|&(_, fd)| libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        let n = unsafe { libc::poll(pf.as_mut_ptr(), pf.len() as libc::nfds_t, 0) };
        if n <= 0 {
            return None;
        }
        pf.iter()
            .zip(&live)
            .find(|(p, _)| p.revents != 0)
            .map(|(_, &(pid, _))| pid)
    }

    /// Target processes of a `kill` with a pid, a group, or -1, in pid order. None: no such
    /// process (`ESRCH`). PID 1 is never a target.
    pub fn kill_targets(&self, mode: u64, id: i32, caller: i32) -> Option<Vec<(i32, PState)>> {
        let v: Vec<(i32, PState)> = match mode {
            SIGSEND_PROC => {
                if id == 1 {
                    return Some(vec![]);
                }
                let p = self.procs.map.get(&id)?;
                vec![(id, p.state)]
            }
            SIGSEND_PGRP => self
                .procs
                .map
                .iter()
                .filter(|(k, _)| **k != 1 && unsafe { libc::getpgid(**k) } == id)
                .map(|(k, p)| (*k, p.state))
                .collect(),
            _ => self
                .procs
                .map
                .iter()
                .filter(|(k, _)| **k != 1 && **k != caller)
                .map(|(k, p)| (*k, p.state))
                .collect(),
        };
        if v.is_empty() {
            None
        } else {
            Some(v)
        }
    }

    pub fn is_live(&self, pid: i32) -> bool {
        self.procs
            .map
            .get(&pid)
            .is_some_and(|p| p.state == PState::Live)
    }
}

const SIGCHLD_U: u64 = 17;

/// A kernel siginfo for a signal sent by `pid`.
pub fn sig_info(sig: u64, code: i32, pid: i32, _uid: u32) -> [u64; 16] {
    let uid = unsafe { libc::getuid() } as u64;
    let mut i = [0u64; 16];
    i[0] = sig;
    i[1] = code as u32 as u64;
    i[2] = pid as u32 as u64 | uid << 32;
    i
}

/// A process's name (`/proc/PID/comm`; a zombie keeps it), or empty.
pub fn comm(pid: i32) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// The wait status of `pid`, a zombie not the supervisor's child, as (status, signal) the
/// way `Sup::reap` gives them: the kernel's `exit_code` (field 52 of `/proc/PID/stat`). None
/// when its parent has reaped it already.
pub fn zombie_status(pid: i32) -> Option<(i64, i64)> {
    let t = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = &t[t.rfind(')')? + 1..];
    // Fields from 3 (state) on: exit_code is field 52.
    let w: i64 = rest.split_whitespace().nth(52 - 3)?.parse().ok()?;
    Some(wait_pair(w))
}

/// A raw wait status as (status, signal): 128 + the signal for a process a signal ended.
fn wait_pair(w: i64) -> (i64, i64) {
    match w & 0x7f {
        0 => ((w >> 8) & 0xff, 0),
        sig => (128 + sig, sig),
    }
}

/// The verdict for a guest process that ended without telling the supervisor: the runtime
/// tells it of every exit, so the process was killed outright, by SIGKILL from outside the
/// run (the host's out-of-memory killer, or a kill sent on the host: `killed`), or the
/// runtime failed (`infra`). `st`: its wait status, when it could be read.
pub fn death_verdict(pid: i32, name: &str, st: Option<(i64, i64)>) -> Verdict {
    let who = if name.is_empty() {
        format!("guest process {pid}")
    } else {
        format!("guest process {pid} ({name})")
    };
    let mut v = match st {
        Some((_, 9)) => Verdict::new(
            "killed",
            format!(
                "{who} was killed by SIGKILL from outside the run: the host's out-of-memory killer \
                 (a memory limit on the run's processes or on the host), or a kill sent on the host"
            ),
        ),
        Some((_, sig)) if sig != 0 => Verdict::new(
            "infra",
            format!(
                "{who} ended on signal {sig} ({}) without telling the supervisor",
                crate::outcome::signal_name(sig)
            ),
        ),
        Some((status, _)) => Verdict::new(
            "infra",
            format!("{who} exited with status {status} without telling the supervisor"),
        ),
        None => Verdict::new(
            "infra",
            format!("{who} ended without telling the supervisor (its wait status was taken by its parent)"),
        ),
    };
    if let Some((status, sig)) = st {
        v.exit_status = Some(status);
        v.signal = (sig != 0).then_some(sig);
    }
    v
}

#[cfg(test)]
mod death_tests {
    use super::*;
    use crate::outcome::{classify, Outcome};

    #[test]
    fn a_process_killed_from_outside_is_named_with_its_wait_status() {
        // Raw statuses as the kernel keeps them: SIGKILL, SIGSEGV with a core, exit 3.
        assert_eq!(wait_pair(9), (137, 9));
        assert_eq!(wait_pair(11 | 0x80), (139, 11));
        assert_eq!(wait_pair(3 << 8), (3, 0));
        let v = death_verdict(7, "db", Some(wait_pair(9)));
        assert_eq!((v.exit_status, v.signal), (Some(137), Some(9)));
        let c = classify(&v, &[]);
        assert_eq!((c.outcome, c.stop.as_str()), (Outcome::Internal, "killed"));
        let v = death_verdict(7, "db", Some(wait_pair(11)));
        assert_eq!((v.exit_status, v.signal), (Some(139), Some(11)));
        assert_eq!(classify(&v, &[]).stop, "internal");
    }

    #[test]
    fn a_zombies_wait_status_is_read_from_proc() {
        // A child of this test process that a signal ends: its status, read before reaping,
        // is the one waitpid then gives.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            unsafe {
                libc::raise(libc::SIGKILL);
                libc::_exit(0)
            }
        }
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // Wait for it to end without reaping it.
        unsafe {
            libc::waitid(
                libc::P_PID,
                pid as u32,
                &mut info,
                libc::WEXITED | libc::WNOWAIT,
            )
        };
        assert_eq!(zombie_status(pid), Some((137, 9)));
        let mut st = 0;
        unsafe { libc::waitpid(pid, &mut st, 0) };
        assert_eq!(zombie_status(pid), None);
    }
}
