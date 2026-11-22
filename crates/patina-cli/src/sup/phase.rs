//! A run's phases: the setup command (`--setup`), the main command (after `--`) and the final
//! check (`--finally`), run one after the other as main's root process, in the same
//! sandbox, seed and log. Faults act only in the main phase: the window opens where the setup
//! command exits 0 and closes where the main command ends.
//!
//! The end of a phase's root process is a request under the turn (`ProcExit`); its record
//! (`DEC_PHASE`) moves the fault window. The next phase's root does not start there: a
//! process another guest is creating may hold a reserved slot, so the start waits, as a machine's
//! restart does, for the next point where nothing is in flight (`machines::machine_actions`), and
//! comes after the machine restarts queued before it. The supervisor forks it as it forked the
//! first root, with the descriptors the first had (`Phases::fds`), and waits for its `Hello`.
//! Processes an earlier phase left running keep running. Everything is in the turn's order, so
//! every transition is the same in every run of a seed.

use super::link::EVK_MACHINE_START;
use super::{Sup, Verdict};
use proto::ctl::*;
use proto::layout::*;
use proto::machine::*;
use std::ffi::CString;
use std::sync::atomic::Ordering::{Relaxed, SeqCst};

/// A phase's command: the program's guest path and the runtime's arguments (`rt`, the program,
/// its argv).
#[derive(Clone, Debug)]
pub struct Cmd {
    pub exe: String,
    pub argv: Vec<String>,
}

#[derive(Default)]
pub struct Phases {
    pub setup: Option<Cmd>,
    pub main: Option<Cmd>,
    pub finally: Option<Cmd>,
    /// Exit statuses of the main command besides 0 after which the final check runs
    /// (`--ok-exit`).
    pub ok: Vec<i64>,
    /// The phase whose root waits to start (0: none).
    pub pending: u64,
    /// The main command's wait status word, kept for the run's verdict after the final check.
    pub main_word: Option<i64>,
    /// The descriptors the first root was forked with, and the environment every root gets.
    pub fds: Vec<i32>,
    pub env: Vec<CString>,
    /// A root process is ending into another phase: its exit is an ordinary process's.
    pub continuing: bool,
    /// The slot the current phase's root started in (its records' slot).
    pub root_slot: usize,
}

/// The descriptors this process has open.
pub fn open_fds() -> Vec<i32> {
    let mut v: Vec<i32> = std::fs::read_dir("/proc/self/fd")
        .map(|d| {
            d.flatten()
                .filter_map(|e| e.file_name().to_str().and_then(|s| s.parse().ok()))
                .collect()
        })
        .unwrap_or_default();
    // Not the directory's own descriptor, closed by now.
    v.retain(|&fd| unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0);
    v.sort();
    v
}

fn word(status: i64, sig: i64) -> i64 {
    if sig != 0 {
        sig & 0x7f
    } else {
        (status & 0xff) << 8
    }
}

impl Sup {
    fn phase(&self) -> u64 {
        self.ctl.phases.phase.load(Relaxed)
    }

    /// Phase `p` begins now (its root is about to start): its start and where its output
    /// begins.
    pub(super) fn phase_begin(&mut self, p: u64) {
        let ph = &self.ctl.phases;
        let i = (p - 1) as usize;
        ph.phase.store(p, Relaxed);
        ph.from_seq[i].store(self.ctl.seq.load(Relaxed) + 1, Relaxed);
        let size = |fd: i32| {
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(fd, &mut st) } == 0 {
                st.st_size as u64
            } else {
                0
            }
        };
        ph.out_off[i].store(size(1), Relaxed);
        ph.err_off[i].store(size(2), Relaxed);
    }

    /// The root process of the current phase ended (`status`, `sig`): which phase follows
    /// (`None`: the run ends). Called before its exit is processed; `phase_end` follows.
    pub(super) fn phase_next(&self, status: i64, sig: i64) -> Option<u64> {
        match self.phase() {
            PHASE_SETUP if sig == 0 && status == 0 => Some(PHASE_MAIN),
            PHASE_MAIN if self.phases.finally.is_some() => (sig == 0
                && (status == 0 || self.phases.ok.contains(&status)))
            .then_some(PHASE_FINALLY),
            _ => None,
        }
    }

    /// The root of the current phase ended with `status`/`sig`; `next` follows (0: none, the
    /// run ends now). The record, the fault window, and the next root's start queued.
    pub(super) fn phase_end(&mut self, status: i64, sig: i64, next: u64) {
        let p = self.phase();
        if p == 0 {
            return;
        }
        let w = word(status, sig);
        let i = (p - 1) as usize;
        let seq = self.decide(
            DEC_PHASE,
            self.phases.root_slot,
            [p, w as u64, next, 0, 0, 0],
            0,
        );
        let ph = &self.ctl.phases;
        ph.to_seq[i].store(seq, Relaxed);
        ph.word[i].store(w as u64 + 1, Relaxed);
        let f = &self.ctl.faults.cfg;
        match (p, next) {
            (PHASE_SETUP, PHASE_MAIN) => unsafe {
                let at = std::ptr::addr_of!(f.fault_after_seq) as *mut u64;
                std::ptr::write_volatile(at, seq);
            },
            (PHASE_MAIN, _) => {
                self.phases.main_word = Some(w);
                if next == PHASE_FINALLY {
                    if f.fault_until_seq == 0 {
                        let at = std::ptr::addr_of!(f.fault_until_seq) as *mut u64;
                        unsafe { std::ptr::write_volatile(at, seq) };
                    }
                    self.settle();
                }
            }
            _ => {}
        }
        if next != 0 {
            self.phases.pending = next;
        }
    }

    /// The faults stop before the final check: the seed's partition and pauses end, the
    /// script's cuts heal and its pauses end, and every down machine whose restart its policy
    /// scheduled is queued to start now (the final check's root starts after them).
    fn settle(&mut self) {
        self.partitions_done();
        self.pauses_done();
        let n = self.machine_count();
        if n == 0 {
            return;
        }
        self.heal_all();
        for k in 1..n {
            if self.paused(k) {
                self.resume(k, PEND_DONE);
            }
        }
        for k in 1..n {
            if self.machine_is_up(k) || self.machines.pending.contains(&(EVK_MACHINE_START, k)) {
                continue;
            }
            // A restart its policy scheduled comes now; a machine the script took down, or
            // one its policy or `max-boots` leaves down, stays down.
            if self.machines_start_queued(k) {
                self.machine_start_now(k);
            }
        }
    }

    /// Start the root of the pending phase (`machines::machine_actions`, where nothing is being
    /// created): a free slot, a fork as the first root's, and its `Hello`.
    pub(super) fn phase_start(&mut self) {
        let p = std::mem::take(&mut self.phases.pending);
        let cmd = match p {
            PHASE_MAIN => self.phases.main.clone(),
            PHASE_FINALLY => self.phases.finally.clone(),
            _ => None,
        };
        let Some(cmd) = cmd else {
            self.finish(Verdict::new("infra", format!("phase {p} has no command")));
        };
        let Some(slot) = (0..MAX_THREADS).find(|&i| self.slot(i).state.load(SeqCst) == SLOT_FREE)
        else {
            self.finish(Verdict::new(
                "capacity",
                format!("no thread slot left to start the {} command", phase_name(p)),
            ))
        };
        let s = self.slot(slot);
        s.go.store(0, SeqCst);
        s.tid.store(0, Relaxed);
        s.pid.store(0, Relaxed);
        s.vmask.store(0, Relaxed);
        s.sigpend.store(0, Relaxed);
        s.sched.store(0, Relaxed);
        s.machine.store(0, Relaxed);
        s.state.store(SLOT_RESERVED, SeqCst);
        // A process tree of its own: its runtime installs the seccomp filter (main's
        // other processes, parked until its `Hello`, keep theirs).
        self.ctl.filter_installed.fetch_and(!1u64, SeqCst);
        self.machines.booting = Some(slot);
        // The slot may have been a machine's: the log says it is main's again.
        self.slot_machine(slot, 0);
        self.phases.root_slot = slot;
        self.phase_begin(p);
        let pid = self.fork_root(&cmd);
        self.child = pid;
        self.pidfd = match crate::sys::pidfd_open(pid) {
            Ok(fd) => fd,
            Err(e) => self.finish(Verdict::new("infra", format!("pidfd_open: {e}"))),
        };
        self.exe = cmd.exe.clone();
        self.boot_hello(slot, 0, 0);
    }

    /// Fork the root of a phase, as `main` forked the first: the same descriptors, process
    /// state and environment, the runtime executed from `FD_RT`.
    pub(super) fn fork_root(&mut self, cmd: &Cmd) -> i32 {
        let cs = |v: &[String]| -> Vec<CString> {
            v.iter()
                .map(|s| CString::new(s.as_bytes()).unwrap_or_default())
                .collect()
        };
        let argv_c = cs(&cmd.argv);
        let mut argv: Vec<*const libc::c_char> = argv_c.iter().map(|c| c.as_ptr()).collect();
        argv.push(std::ptr::null());
        let mut envp: Vec<*const libc::c_char> =
            self.phases.env.iter().map(|c| c.as_ptr()).collect();
        envp.push(std::ptr::null());
        let mut close: Vec<i32> = open_fds()
            .into_iter()
            .filter(|f| *f > 2 && !self.phases.fds.contains(f))
            .collect();
        close.extend([FD_OUTCOME, FD_EXPORT, FD_SHM]);
        if self.machine_count() > 0 {
            close.push(FD_MACHINES);
        }
        let empty = c"";
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            self.finish(Verdict::new("infra", "fork failed"));
        }
        if pid == 0 {
            unsafe {
                for fd in &close {
                    libc::close(*fd);
                }
                if !super::inherit::child() {
                    libc::_exit(126);
                }
                libc::syscall(
                    libc::SYS_execveat,
                    FD_RT,
                    empty.as_ptr(),
                    argv.as_ptr(),
                    envp.as_ptr(),
                    libc::AT_EMPTY_PATH,
                );
                libc::_exit(127);
            }
        }
        pid
    }
}
