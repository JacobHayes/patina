//! The supervisor: PID 1 of the sandbox, one sequential program that owns the turn.
//! It serves the requests of one guest process and its threads: scheduling (`sched`),
//! virtual time (`time`), futexes (`futex`), thread creation and exit, the exit
//! barrier, the stall timeout, deadlock and liveness.

use crate::cli::Res;
use crate::outcome::Verdict;
use crate::sys::*;
use proto::ctl::*;
use proto::layout::*;
use proto::rec::{chain, Rec, REC_SIZE};
use proto::RecKind;
use std::ffi::CString;
use std::path::Path;
use std::process::ExitCode;
use std::sync::atomic::Ordering::*;

const BASE_ENV: [&str; 4] = [
    "PATH=/usr/local/bin:/usr/bin:/bin",
    "HOME=/work",
    "LANG=C.UTF-8",
    "TZ=UTC",
];

// Parts of the scheduler's interface (`Wait::Io`, `WakeReason::Signal`, `io_generation`,
// `cancel`, ...) are for blocking I/O and signals; unit tests use the rest.
pub mod crash;
#[allow(dead_code)]
pub mod futex;
mod inherit;
pub mod io;
pub mod proc;
#[allow(dead_code)]
pub mod sched;
pub mod signal;
#[allow(dead_code)]
pub mod time;
pub mod wire;

#[allow(unused_imports)]
pub use sched::{Event, Sched, Wait, WakeReason};

struct Sup {
    ctl: &'static Ctl,
    log_base: *mut u8,
    log_mapped: u64,
    pidfd: i32,
    child: i32,
    sched: Sched,
    /// Blocking I/O: I/O waiters and timerfds.
    io: io::Io,
    /// The slot holding the turn (None while the supervisor runs).
    running: Option<usize>,
    /// Virtual signals.
    sig: signal::Signals,
    /// Processes.
    procs: proc::Procs,
    /// The network wire.
    wire: wire::Wire,
}

/// What a request does with the turn.
enum Next {
    /// The caller continues with this return value.
    Continue(i64),
    /// The caller parked, yielded or exited: pick who runs next.
    Pick,
}

impl Sup {
    fn ensure_log(&mut self, len: u64) {
        if len <= self.log_mapped {
            return;
        }
        let mut cap = self.ctl.log_cap.load(Relaxed);
        if len > cap {
            cap += LOG_STEP;
            if unsafe { libc::ftruncate(FD_LOG, cap as i64) } != 0 {
                self.finish(Verdict::new("infra", "cannot extend the boundary log"));
            }
            self.ctl.log_cap.store(cap, Relaxed);
        }
        let p = unsafe {
            libc::mmap(
                self.log_base.add(self.log_mapped as usize) as *mut _,
                (cap - self.log_mapped) as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_FIXED,
                FD_LOG,
                self.log_mapped as i64,
            )
        };
        if p == libc::MAP_FAILED {
            self.finish(Verdict::new("infra", "cannot map the boundary log"));
        }
        self.log_mapped = cap;
    }

    fn append(&mut self, rec: &Rec) {
        let off = self.ctl.log_len.load(Relaxed);
        self.ensure_log(off + REC_SIZE as u64);
        unsafe {
            std::ptr::copy_nonoverlapping(
                rec.as_bytes().as_ptr(),
                self.log_base.add(off as usize),
                REC_SIZE,
            );
        }
        self.ctl.log_len.store(off + REC_SIZE as u64, Relaxed);
        self.ctl
            .log_hash
            .store(chain(self.ctl.log_hash.load(Relaxed), rec), Relaxed);
    }

    /// A supervisor decision is a boundary event of its own.
    fn decide(&mut self, code: u32, slot: usize, args: [u64; 6], ret: i64) -> u64 {
        let seq = self.ctl.seq.load(Relaxed) + 1;
        self.ctl.seq.store(seq, Relaxed);
        let s = &self.ctl.stats.decisions;
        s.store(s.load(Relaxed) + 1, Relaxed);
        let rec = Rec {
            seq,
            vclock_ns: self.ctl.vclock_ns.load(Relaxed),
            slot: slot as u16,
            kind: RecKind::SupDecision as u8,
            class: 0,
            nr: code,
            args,
            ret,
            out_hash: 0,
            in_hash: 0,
        };
        self.append(&rec);
        seq
    }

    fn slot(&self, i: usize) -> &'static Slot {
        unsafe { &*self.ctl.slot(i) }
    }

    fn now(&self) -> u64 {
        self.ctl.vclock_ns.load(Relaxed)
    }

    /// Give the turn to slot `to` with its pending reply.
    fn reply(&mut self, from: usize, to: usize) {
        if from != to {
            let s = &self.ctl.stats.switches;
            s.store(s.load(Relaxed) + 1, Relaxed);
        }
        let ret = self.sched.entries[to].reply;
        self.sched.entries[to].reply = 0;
        let flags = std::mem::take(&mut self.sig.threads[to].deliver);
        self.ctl
            .next_deadline_ns
            .store(self.sched.next_deadline().unwrap_or(u64::MAX), Relaxed);
        self.running = Some(to);
        let s = unsafe { &mut *self.ctl.slot(to) };
        unsafe { std::ptr::write_volatile(&mut s.rep, Reply { ret, flags }) };
        s.go.store(1, SeqCst);
        futex_wake(&s.go as *const _ as *const u32, 1);
    }

    /// `req`: the request being handled when this is checked (its thread is not parked).
    fn check_liveness(&self, req: Option<(usize, Request)>) {
        let cfg = self.ctl.config;
        if self.now() > VCLOCK_BOOT_NS + cfg.vtime_limit_ns {
            // Name what every thread is doing, as `deadlock` does, so a writer stuck
            // in a sleep loop is visible in the detail.
            let running = match req {
                Some((i, r)) => {
                    let op = Op::from_u32(r.op).map(|o| o.name()).unwrap_or("?");
                    let rel = r.args[0].saturating_sub(self.now());
                    format!(
                        "requesting: slot={i} tid={} op={op} arg0={} (now+{rel} ns); ",
                        self.sched.entries[i].tid, r.args[0]
                    )
                }
                None => String::new(),
            };
            self.finish(Verdict::new(
                "liveness",
                format!(
                    "virtual time passed --vtime-limit-s ({} s); {running}parked: {}",
                    cfg.vtime_limit_ns / 1_000_000_000,
                    self.parked_detail()
                ),
            ));
        }
    }

    /// Every parked thread: slot, tid, what it waits for, its deadline.
    fn parked_detail(&self) -> String {
        let parts: Vec<String> = self
            .sched
            .parked()
            .into_iter()
            .map(|(i, e, w, d)| {
                let d = d.map(|d| d.to_string()).unwrap_or_else(|| "none".into());
                format!(
                    "slot={i} tid={} wait={}{} deadline={d}",
                    e.tid,
                    Self::describe_wait(w),
                    self.io.describe(i)
                )
            })
            .collect();
        parts.join("; ")
    }

    /// Who runs next: the seeded pick among runnable threads; with nothing runnable,
    /// an idle jump to the earliest event; with nothing pending either, deadlock.
    /// Returns (slot, seq of the decision that will record it).
    fn choose(&mut self) -> (usize, u64) {
        loop {
            let seq = self.ctl.seq.load(Relaxed) + 1;
            if let Some(to) = self.sched.pick(seq) {
                return (to, seq);
            }
            let old = self.now();
            // A jump past the liveness limit is reported before it wakes anyone, so
            // the detail shows what every thread was parked on (a sleep loop, a futex).
            if self
                .sched
                .next_deadline()
                .is_some_and(|t| t > VCLOCK_BOOT_NS + self.ctl.config.vtime_limit_ns)
            {
                self.ctl
                    .vclock_ns
                    .store(VCLOCK_BOOT_NS + self.ctl.config.vtime_limit_ns + 1, Relaxed);
                self.check_liveness(None);
            }
            match self.sched.idle_jump(old) {
                Some(t) => {
                    self.ctl.vclock_ns.store(t, Relaxed);
                    self.decide(DEC_IDLE_JUMP, 0, [old, t, 0, 0, 0, 0], 0);
                    self.check_liveness(None);
                    self.fire_signal_timers();
                    self.after_events();
                }
                None => self.deadlock(),
            }
        }
    }

    /// After timer events fired: deliver timerfd expiries (each a decision record), then
    /// wake the I/O waiters if the generation moved.
    fn after_events(&mut self) {
        let now = self.now();
        for (key, count) in self.io.deliver_timers(&mut self.sched, self.ctl, now) {
            self.decide(DEC_TIMERFD, 0, [key, count, 0, 0, 0, 0], 0);
        }
        self.wire_step();
        self.io.sync(&mut self.sched, self.ctl);
    }

    fn describe_wait(w: Wait) -> String {
        match w {
            Wait::Futex {
                key: (asid, addr),
                bitset,
            } => format!("futex addr=0x{addr:x} asid={asid} bitset=0x{bitset:x}"),
            Wait::Sleep => "sleep".into(),
            Wait::Io { gen } => format!("io gen={gen}"),
            Wait::Child => "child".into(),
            Wait::Signal => "signal".into(),
            Wait::Vfork => "vfork".into(),
        }
    }

    fn deadlock(&self) -> ! {
        self.finish(Verdict::new("deadlock", self.parked_detail()))
    }

    fn finish(&self, v: Verdict) -> ! {
        self.ctl.timing[TM_FINISH].store(now_ns(), Relaxed);
        unsafe {
            libc::kill(-1, libc::SIGKILL);
            let mut st = 0;
            while libc::waitpid(-1, &mut st, 0) > 0 {}
        }
        // Every guest is dead: the live tree is final.
        crash::export(Path::new("/work"));
        self.wire_note_hwm();
        self.ctl.timing[TM_EXPORTED].store(now_ns(), Relaxed);
        let _ = write_fd(FD_OUTCOME, v.encode().as_bytes());
        std::process::exit(0)
    }

    /// Reap the child and describe how it ended.
    fn reap(&self) -> (i64, i64) {
        let mut st = 0;
        unsafe { libc::waitpid(self.child, &mut st, 0) };
        if libc::WIFSIGNALED(st) {
            (128 + libc::WTERMSIG(st) as i64, libc::WTERMSIG(st) as i64)
        } else {
            (libc::WEXITSTATUS(st) as i64, 0)
        }
    }

    /// The process of `idx` is ending (`exit_group`, a fatal signal, or the exit of its
    /// last thread). Exit barrier and the rest: `proc::process_died`. The run ends when the
    /// first guest exits.
    fn proc_exit(&mut self, op: Op, idx: usize, args: [u64; 6], status: i64, sig: i64) -> Next {
        let pid = self.sched.entries[idx].pid;
        if pid == self.procs.main {
            self.ctl.timing[TM_MAIN_EXIT].store(now_ns(), Relaxed);
        }
        self.process_died(pid, status, sig as u64);
        if pid == self.procs.main {
            let _ = self.reap();
            self.decide(op as u32, idx, args, 0);
            self.main_exit(status, sig);
        }
        Next::Pick
    }

    /// Handle one request from `idx` (which held the turn).
    fn handle(&mut self, idx: usize, req: Request) -> Next {
        let a = req.args;
        let own_asid = self.sched.entries[idx].asid;
        // Words in memory shared across processes are keyed globally.
        let asid_of = |addr: u64| {
            if addr & FUTEX_SHARED_BIT != 0 {
                u64::MAX
            } else {
                own_asid
            }
        };
        let asid = own_asid;
        match Op::from_u32(req.op) {
            Some(Op::Hello) => self.hello(idx, a),
            Some(Op::VforkStart) => self.vfork_start(idx, a),
            Some(Op::Exec) => self.exec(idx, a),
            Some(Op::WaitPark) => self.wait_park(idx, a),
            Some(Op::Yield) => {
                self.sched.entries[idx].reply = 0;
                Next::Pick
            }
            Some(Op::Sleep) => {
                self.sched.park(idx, Wait::Sleep, Some(a[0]));
                Next::Pick
            }
            Some(Op::FutexWait) => {
                let deadline = if a[2] == NO_DEADLINE {
                    None
                } else {
                    Some(a[2])
                };
                self.sched
                    .futex_wait(idx, (asid_of(a[0]), a[0]), a[3] as u32, deadline);
                Next::Pick
            }
            Some(Op::FutexWake) => {
                let mut n = self
                    .sched
                    .futex_wake((asid_of(a[0]), a[0]), a[1], a[2] as u32);
                if a[3] != 0 {
                    n += self.sched.futex_wake((asid_of(a[3]), a[3]), a[4], u32::MAX);
                }
                Next::Continue(n as i64)
            }
            Some(Op::FutexRequeue) => {
                let (w, r) = self.sched.futex_requeue(
                    (asid_of(a[0]), a[0]),
                    (asid_of(a[1]), a[1]),
                    a[2],
                    a[3],
                );
                Next::Continue(if a[4] != 0 { (w + r) as i64 } else { w as i64 })
            }
            Some(Op::Forked) if a[3] == FORKED_PROCESS => self.forked_process(idx, a),
            Some(Op::Forked) => {
                let (child, tid, pid) = (a[0] as usize, a[1] as i32, a[2] as i32);
                if child >= MAX_THREADS
                    || self.sched.entries[child].state != sched::State::Free
                        && self.sched.entries[child].state != sched::State::Exiting
                {
                    self.finish(Verdict::new(
                        "infra",
                        format!("Forked: slot {child} is in use"),
                    ));
                }
                self.sched.add(child, tid, pid, asid);
                let s = self.slot(child);
                s.tid.store(tid, Relaxed);
                s.pid.store(pid, Relaxed);
                s.state.store(SLOT_LIVE, SeqCst);
                self.signal_thread_new(child, pid);
                Next::Continue(0)
            }
            Some(Op::ThreadExit) => {
                // Emulated CLONE_CHILD_CLEARTID: the runtime stored 0; wake one waiter.
                if a[1] != 0 {
                    self.sched.futex_wake((asid, a[1]), 1, u32::MAX);
                }
                let pid = self.sched.entries[idx].pid;
                if self.sched.live_in(pid) <= 1 {
                    return self.proc_exit(Op::ThreadExit, idx, a, a[0] as i64, 0);
                }
                self.sched.exiting(idx);
                self.signal_thread_gone(idx);
                self.slot(idx).state.store(SLOT_EXITING, SeqCst);
                Next::Pick
            }
            Some(Op::ProcExit) => self.proc_exit(Op::ProcExit, idx, a, a[0] as i64, a[1] as i64),
            Some(Op::Park) => {
                let now = self.now();
                match self.io.park(&mut self.sched, self.ctl, idx, a, now) {
                    Some(r) => Next::Continue(r),
                    None => Next::Pick,
                }
            }
            Some(Op::TimerFdSet) => {
                let pid = self.sched.entries[idx].pid;
                let r = self.io.timer_set(&mut self.sched, pid, a);
                // An expiry already due (an absolute time in the past) is delivered before
                // the call returns, as the kernel does.
                let now = self.now();
                if self.sched.fire_due(now) > 0 {
                    self.after_events();
                }
                Next::Continue(r)
            }
            Some(Op::TimerFdGet) => Next::Continue(self.io.timer_get(a)),
            Some(Op::Stop) => {
                self.decide(Op::Stop as u32, idx, a, 0);
                self.finish(Verdict::new("unsupported", proto::table::name(a[0])));
            }
            Some(Op::HostError) => {
                self.decide(Op::HostError as u32, idx, a, 0);
                let [errno, nr, code, ..] = a;
                if code == HE_OUTSIDE_SIGNAL {
                    self.finish(Verdict::new(
                        "infra",
                        format!(
                            "signal {} ({errno}) from outside the sandbox",
                            signal::name(errno)
                        ),
                    ));
                }
                if code == HE_HOST_LIMIT {
                    self.finish(Verdict::new(
                        "infra",
                        format!("host limit: errno {} in {} (launcher rlimit or per-user kernel accounting)", -(errno as i64), proto::table::name(nr)),
                    ));
                }
                if code == HE_PMU {
                    let what = match errno {
                        PMU_E_OVERSHOOT => {
                            "overshoot (overflow skid past the margin; raise --pmu-margin)"
                        }
                        PMU_E_MISSED => "missed overflow",
                        PMU_E_DECODE => "cannot decode guest code",
                        PMU_E_OPEN => "cannot open a counter",
                        PMU_E_PAGE => "counter page or period",
                        _ => "unknown",
                    };
                    self.finish(Verdict::new("infra", format!("pmu: {what} (value {nr})")));
                }
                if code == HE_REAL_MASK {
                    self.finish(Verdict::new(
                        "infra",
                        format!("runtime invariant: real signal mask changed to {errno:#x}"),
                    ));
                }
                self.finish(Verdict::new(
                    "infra",
                    format!(
                        "host error: errno {} in {} (code {code})",
                        -(errno as i64),
                        proto::table::name(nr)
                    ),
                ));
            }
            Some(Op::CrashPoint) => {
                self.decide(Op::CrashPoint as u32, idx, a, 0);
                self.finish(crash::crash_verdict(a, self.now()))
            }
            Some(
                op @ (Op::SigSend
                | Op::SigWait
                | Op::SigSuspend
                | Op::TimerSet
                | Op::SigTake
                | Op::SigAction),
            ) => self.signal_op(op, idx, a),
            Some(
                op @ (Op::WireSocket
                | Op::WireBind
                | Op::WireConnect
                | Op::WireAccepted
                | Op::WireSent
                | Op::WireQuery),
            ) => self.wire_op(op, a),
            None => self.finish(Verdict::new("infra", format!("unknown request {}", req.op))),
        }
    }

    fn serve(&mut self) -> ! {
        let cfg = self.ctl.config;
        let stall = cfg.stall_ms * 1_000_000;
        let slice = (cfg.stall_ms / 8).clamp(1, 250);
        let mut last_seq = self.ctl.seq.load(Relaxed);
        let mut last_progress = now_ns();
        // The stall watchdog counts the running guest thread's CPU time since its last
        // trap, not wall time: a spinning thread accumulates it, a thread the host does not
        // schedule (load) does not. Wall time is a backstop only, at 10x, for a thread that
        // neither traps nor runs (blocked in the kernel outside any row).
        let mut last_cpu: Option<(i32, u64)> = None;
        loop {
            if self.ctl.sup_word.load(SeqCst) == 0 {
                futex_wait_ms(&self.ctl.sup_word as *const _ as *const u32, 0, slice);
                if self.ctl.sup_word.load(SeqCst) == 0 {
                    if let Some(pid) = self.unexpected_death() {
                        let (status, sig) = if pid == self.child {
                            self.reap()
                        } else {
                            (0, 0)
                        };
                        let mut v = Verdict::new(
                            "infra",
                            format!("guest process {pid} ended without telling the supervisor (status {status})"),
                        );
                        v.exit_status = Some(status);
                        v.signal = if sig != 0 { Some(sig) } else { None };
                        self.finish(v);
                    }
                    let s = self.ctl.seq.load(Relaxed);
                    let who = self
                        .running
                        .map(|i| self.slot(i).tid.load(Relaxed) as i32)
                        .unwrap_or(0);
                    let cpu = thread_cpu_ns(who);
                    if s != last_seq {
                        last_seq = s;
                        last_progress = now_ns();
                        last_cpu = cpu.map(|c| (who, c));
                    } else {
                        let spun = match (cpu, last_cpu) {
                            (Some(c), Some((t, c0))) if t == who => c.saturating_sub(c0) >= stall,
                            (Some(c), _) => {
                                last_cpu = Some((who, c));
                                false
                            }
                            (None, _) => false,
                        };
                        let waited = now_ns() - last_progress;
                        if spun
                            || waited >= stall.saturating_mul(10)
                            || (cpu.is_none() && waited >= stall)
                        {
                            self.finish(Verdict::new(
                                "stall",
                                format!(
                                    "no trap for {} ms of guest CPU time (tid {who}, last seq {s})",
                                    cfg.stall_ms
                                ),
                            ));
                        }
                    }
                    continue;
                }
            }
            self.ctl.sup_word.store(0, SeqCst);
            last_progress = now_ns();
            last_cpu = None;
            let idx = self.ctl.pending_slot.load(SeqCst) as usize;
            let req = unsafe { std::ptr::read_volatile(&(*self.ctl.slot(idx)).req) };
            self.running = None;
            self.exit_barrier_first(idx, req.op);
            self.check_liveness(Some((idx, req)));
            // Timers due by now fire before the request is handled (their seq order).
            let now = self.now();
            self.sched.fire_due(now);
            self.fire_signal_timers();
            self.after_events();
            let next = self.handle(idx, req);
            // What the request changed on the wire (a close by an exit, a connect) and
            // what that makes runnable.
            self.wire_step();
            self.io.sync(&mut self.sched, self.ctl);
            let to = match next {
                Next::Continue(ret) => {
                    self.sched.entries[idx].reply = ret;
                    self.decide(req.op, idx, req.args, idx as i64);
                    idx
                }
                Next::Pick => {
                    let (to, seq) = self.choose();
                    let got = self.decide(req.op, idx, req.args, to as i64);
                    debug_assert_eq!(got, seq);
                    to
                }
            };
            last_seq = self.ctl.seq.load(Relaxed);
            self.io.refresh(&self.sched, self.ctl);
            self.reply(idx, to);
        }
    }
}

/// Wall-clock monotonic time by a real syscall. The supervisor runs with the
/// timestamp counter faulting (see `main`), so it must not use the vDSO, which reads it.
/// CPU time of guest thread `tid` (a PID-namespace id; 0: none), from
/// `/proc/TID/schedstat`.
fn thread_cpu_ns(tid: i32) -> Option<u64> {
    if tid <= 0 {
        return None;
    }
    let t = std::fs::read_to_string(format!("/proc/{tid}/schedstat")).ok()?;
    t.split_whitespace().next()?.parse().ok()
}

pub(crate) fn now_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::syscall(libc::SYS_clock_gettime, libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

pub fn main(args: &[String]) -> Res<ExitCode> {
    let mut env: Vec<String> = BASE_ENV.iter().map(|s| s.to_string()).collect();
    let mut cmd: Vec<String> = vec![];
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--env" => {
                let kv = it.next().ok_or("--env needs K=V")?;
                let k = kv.split('=').next().unwrap_or("");
                env.retain(|e| e.split('=').next() != Some(k));
                env.push(kv.clone());
            }
            "--" => {
                cmd = it.cloned().collect();
                break;
            }
            _ => return Err(format!("__sup: unknown option {a}")),
        }
    }
    if unsafe { libc::getpid() } != 1 {
        return Err("__sup must run as PID 1 of the sandbox".into());
    }
    if cmd.is_empty() {
        return Err("__sup: no command".into());
    }
    // Containment when the launcher is killed: die with the parent (bwrap outside the
    // PID namespace, which dies with the launcher); the kernel then kills every process of the
    // namespace. bwrap's --die-with-parent does not reach this process (measured: after a
    // SIGKILL of the launcher, the supervisor and its guests lived on, reparented to the host's
    // init). If the launcher was already gone before the prctl, the outcome pipe says so (its
    // only reader is the launcher; a pipe's write end polls POLLERR without readers).
    unsafe {
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
        let mut p = libc::pollfd {
            fd: FD_OUTCOME,
            events: 0,
            revents: 0,
        };
        if libc::poll(&mut p, 1, 0) == 1 && p.revents & libc::POLLERR != 0 {
            libc::_exit(1);
        }
    }
    unsafe {
        // The guest's stdio memfds become 0, 1 and 2 of the supervisor, and so of every
        // guest process (bwrap's own stdio, a host file, is dropped here).
        for (from, to) in [(FD_STDIN, 0), (FD_STDOUT, 1), (FD_STDERR, 2)] {
            if libc::dup2(from, to) != to {
                return Err(format!(
                    "stdio descriptor {from}: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }
        // Every other inherited descriptor, from the launcher's caller or bwrap.
        inherit::close_inherited();
    }
    let ctl_ptr = map_shared(FD_CTL, CTL_SIZE).map_err(|e| format!("map ctl: {e}"))?;
    let ctl: &'static Ctl = unsafe { Ctl::at(ctl_ptr) };
    if !ctl.check() {
        return Err("control region magic mismatch".into());
    }
    ctl.timing[TM_SUP_START].store(now_ns(), Relaxed);
    let log_base = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            64 << 30,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
            -1,
            0,
        )
    };
    if log_base == libc::MAP_FAILED {
        return Err("cannot reserve the log mapping".into());
    }
    let mut sup = Sup {
        ctl,
        log_base: log_base as *mut u8,
        log_mapped: 0,
        pidfd: -1,
        child: 0,
        sched: Sched::new(ctl.config.seed, MAX_THREADS),
        io: io::Io::default(),
        running: None,
        sig: signal::Signals::new(MAX_THREADS),
        procs: proc::Procs::default(),
        wire: wire::Wire::default(),
    };
    // The rest of the process state guests inherit from the supervisor.
    if let Err(e) = inherit::normalise(ctl.config.tmpfs_bytes) {
        sup.finish(Verdict::new("infra", e));
    }
    if let Err(e) = sup.wire.init() {
        sup.finish(Verdict::new("infra", e));
    }

    // The guest directory: a copy on sandbox tmpfs, not a bind of the host's.
    if let Err(e) = inherit::copy_tree(Path::new("/.patina/guest"), Path::new("/guest")) {
        sup.finish(Verdict::new(
            "infra",
            format!("copying the guest directory into /guest: {e}"),
        ));
    }
    if Path::new("/.patina/in").is_dir() {
        if let Err(e) = crash::copy_in(Path::new("/.patina/in"), Path::new("/work")) {
            sup.finish(Verdict::new("infra", format!("copying /in to /work: {e}")));
        }
    }
    if let Err(e) = crash::write_base(ctl, Path::new("/work")) {
        sup.finish(Verdict::new("infra", format!("base records: {e}")));
    }

    ctl.timing[TM_COPIED].store(now_ns(), Relaxed);
    // The first guest: slot 0, reserved before the task exists.
    sup.slot(0).state.store(SLOT_RESERVED, SeqCst);
    let cstrs = |v: &[String]| -> Vec<CString> {
        v.iter()
            .map(|s| CString::new(s.as_bytes()).unwrap())
            .collect()
    };
    let mut rt_args = vec!["rt".to_string(), cmd[0].clone()];
    rt_args.extend(cmd.iter().cloned());
    let argv_c = cstrs(&rt_args);
    let envp_c = cstrs(&env);
    let mut argv: Vec<*const libc::c_char> = argv_c.iter().map(|c| c.as_ptr()).collect();
    argv.push(std::ptr::null());
    let mut envp: Vec<*const libc::c_char> = envp_c.iter().map(|c| c.as_ptr()).collect();
    envp.push(std::ptr::null());
    let empty = c"";

    // Make rdtsc fault in the supervisor too. Guest tasks run with it (set by the
    // runtime); if the supervisor did not, every hand-off would switch between tasks
    // with different CR4.TSD and, on this VM, cost about 13 us more (measured in the skeleton).
    if unsafe { libc::prctl(libc::PR_SET_TSC, libc::PR_TSC_SIGSEGV, 0, 0, 0) } != 0 {
        sup.finish(Verdict::new("infra", "PR_SET_TSC failed in the supervisor"));
    }
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        sup.finish(Verdict::new("infra", "fork failed"));
    }
    if pid == 0 {
        unsafe {
            libc::close(FD_OUTCOME);
            libc::close(FD_EXPORT);
            if !inherit::child() {
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
    sup.child = pid;
    sup.pidfd = match pidfd_open(pid) {
        Ok(fd) => fd,
        Err(e) => sup.finish(Verdict::new("infra", format!("pidfd_open: {e}"))),
    };
    sup.serve()
}
