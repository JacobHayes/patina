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

/// What a record of the boundary log is, for the `log-limit` message.
fn record_kind(r: &Rec) -> String {
    match RecKind::from_u8(r.kind) {
        Some(RecKind::Trap) => format!("{} system call records", proto::table::name(r.nr as u64)),
        Some(RecKind::Preempt) => match r.nr {
            1 => "counter-preemption records".into(),
            2 => "spin-point records".into(),
            _ => "compute-switch records".into(),
        },
        Some(RecKind::SupDecision) => "scheduling-decision records".into(),
        Some(RecKind::SignalDelivery) => "signal-delivery records".into(),
        Some(RecKind::InsnEmulation) => "instruction-emulation records".into(),
        Some(RecKind::Injected) => "injected-fault records".into(),
        Some(RecKind::Str) => "string records (SDK labels, --log-paths)".into(),
        _ => "other records".into(),
    }
}

/// A write to the run directory failed with `errno`.
fn log_write_verdict(errno: i32, what: &str) -> Verdict {
    if errno == libc::ENOSPC || errno == libc::EDQUOT {
        Verdict::new(
            "disk-full",
            format!("the filesystem holding the run directory is full ({what})"),
        )
    } else {
        Verdict::new("infra", format!("host error: errno {errno} {what}"))
    }
}

/// The guest's fixed environment; `--env` adds to it. `PATINA=1` tells a program it runs
/// under Patina.
const BASE_ENV: [&str; 5] = [
    "PATH=/guest:/usr/local/bin:/usr/bin:/bin",
    "HOME=/work",
    "LANG=C.UTF-8",
    "TZ=UTC",
    "PATINA=1",
];

// Parts of the scheduler's interface (`Wait::Io`, `WakeReason::Signal`, `io_generation`,
// `cancel`, ...) are for blocking I/O and signals; unit tests use the rest.
mod contain;
pub mod crash;
#[allow(dead_code)]
pub mod futex;
mod inherit;
pub mod io;
pub mod proc;
#[allow(dead_code)]
pub mod sched;
mod sdk;
pub mod signal;
mod stall;
#[allow(dead_code)]
pub mod time;
pub mod udp;
mod vtgc;
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
    /// Datagram sockets.
    udp: udp::Udp,
    /// The program's path in the sandbox (the first image).
    exe: String,
    /// An `execve` has replaced an image: a runtime that cannot run its image now was handed
    /// one an `execve` resolved, not the program.
    execed: bool,
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
            // Blocks allocated now, as the runtime does (`rt::log::grow`).
            let r = unsafe { libc::fallocate(FD_LOG, 0, cap as i64, LOG_STEP as i64) };
            let err = std::io::Error::last_os_error();
            let r = if r != 0 && err.raw_os_error() == Some(libc::EOPNOTSUPP) {
                unsafe { libc::ftruncate(FD_LOG, (cap + LOG_STEP) as i64) }
            } else {
                r
            };
            if r != 0 {
                let err = std::io::Error::last_os_error();
                self.finish(log_write_verdict(
                    err.raw_os_error().unwrap_or(0),
                    "extending the boundary log",
                ));
            }
            cap += LOG_STEP;
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
        let c = self.ctl;
        if c.log_used() + REC_SIZE as u64 > c.config.log_limit {
            {
                let v = self.log_limit_verdict();
                self.finish(v);
            }
        }
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

    /// The run's logs reached `--log-limit`: what they hold, and which records filled them.
    fn log_limit_verdict(&mut self) -> Verdict {
        let c = self.ctl;
        let len = c.log_len.load(Relaxed);
        self.ensure_log(len);
        let n = (len / REC_SIZE as u64) as usize;
        let recs = unsafe { std::slice::from_raw_parts(self.log_base, n * REC_SIZE) };
        // Counted by (kind, nr), named once.
        let mut kinds: std::collections::HashMap<(u8, u32), u64> = Default::default();
        for r in recs.as_chunks::<REC_SIZE>().0 {
            let r = Rec::from_bytes(r);
            *kinds.entry((r.kind, r.nr)).or_default() += 1;
        }
        let mut named: std::collections::BTreeMap<String, u64> = Default::default();
        for ((kind, nr), v) in kinds {
            let r = Rec {
                kind,
                nr,
                ..Rec::from_bytes(&[0; REC_SIZE])
            };
            *named.entry(record_kind(&r)).or_default() += v;
        }
        let top = named
            .into_iter()
            .max_by_key(|(k, v)| (*v, std::cmp::Reverse(k.clone())))
            .map(|(k, v)| format!(", {}% {k}", v * 100 / n.max(1) as u64))
            .unwrap_or_default();
        let ops = (c.oplog_len.load(Relaxed) + c.opdata_len.load(Relaxed))
            .saturating_sub(c.log_exempt.load(Relaxed));
        let ops = if ops >= 1 << 20 {
            format!(" and {} of operation log", crate::report::bytes(ops))
        } else {
            String::new()
        };
        Verdict::new(
            "log-limit",
            format!(
                "{} of boundary log ({n} records{top}){ops} reached --log-limit: the program \
                 had not finished, likely a livelock under this schedule (a run that is only \
                 long, or writes that much to the work tree, needs a higher --log-limit)",
                crate::report::bytes(len)
            ),
        )
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
                    "virtual time passed --time-limit ({} s); {running}parked: {}",
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
        crash::export(&work_dir(self.ctl));
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
            Some(Op::Exec) => {
                self.execed = true;
                self.exec(idx, a)
            }
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
                let [errno, nr, code, ..] = a;
                if code == HE_LOG_LIMIT {
                    // No record: the log has no room for one.
                    {
                        let v = self.log_limit_verdict();
                        self.finish(v);
                    }
                }
                self.decide(Op::HostError as u32, idx, a, 0);
                if code == HE_CAPACITY {
                    self.finish(Verdict::new(
                        "capacity",
                        format!(
                            "the program keeps more than {nr} {} in use; Patina's table for them is full",
                            limit_name(errno)
                        ),
                    ));
                }
                if code == HE_EXEC {
                    let why = proto::exec::Why::from_code(nr);
                    if self.execed {
                        // The image an `execve` resolved (and the guest left) does not resolve
                        // again in the new runtime: Patina's failure, not the program's.
                        self.finish(Verdict::new(
                            "infra",
                            format!(
                                "the runtime could not load again the image an execve resolved ({}errno {errno})",
                                match why.text() {
                                    "" => String::new(),
                                    t => format!("{t}, "),
                                }
                            ),
                        ));
                    }
                    let d = exec_failure(&self.exe, errno, why, a[3] as usize);
                    // What the kernel would run and Patina does not load is not the request's
                    // fault.
                    let class = match why {
                        proto::exec::Why::Elf32
                        | proto::exec::Why::ElfHeaders
                        | proto::exec::Why::Unreadable => "exec-unsupported",
                        _ => "exec",
                    };
                    self.finish(Verdict::new(class, d));
                }
                if code == HE_SIGNAL_CONTEXT {
                    self.finish(Verdict::new(
                        "signal-context",
                        format!(
                            "a signal frame would hold {} (record {errno:#x}), which Patina does not build",
                            signal_context_name(errno)
                        ),
                    ));
                }
                if code == HE_DISK_FULL {
                    self.finish(log_write_verdict(
                        -(errno as i64) as i32,
                        &format!("in {}", proto::table::name(nr)),
                    ));
                }
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
                if code == HE_LOADER {
                    let step = proto::ctl::Setup::from_code(nr).name();
                    let why = match errno {
                        0 => String::new(),
                        e => format!(": errno {e}"),
                    };
                    self.finish(Verdict::new(
                        "infra",
                        format!("runtime setup failed: {step}{why}"),
                    ));
                }
                if code == HE_CONTAINMENT {
                    let [kind, addr, _, rip, store, _] = a;
                    self.finish(Verdict::new(
                        "containment",
                        contain::describe(kind, addr, rip, store != 0),
                    ));
                }
                if code == HE_COMPUTE_CELL {
                    let what = if nr == 1 {
                        "could not be mapped (the program has a mapping there)"
                    } else {
                        "was unmapped or protected by the program"
                    };
                    self.finish(Verdict::new(
                        "compute-cell",
                        format!(
                            "the compute-point cell at {:#x} {what} (errno {})",
                            proto::layout::COMPUTE_CELL,
                            -(errno as i64)
                        ),
                    ));
                }
                if code == HE_GUEST_FAULT_IN_RUNTIME {
                    self.finish(Verdict::new(
                        "infra",
                        format!("runtime fault: signal {errno} at {nr:#x}"),
                    ));
                }
                if code == HE_RUNTIME_ASSERT {
                    // args[1] is a value of the check (an address, a call), not always a call.
                    self.finish(Verdict::new(
                        "infra",
                        format!(
                            "runtime check failed: errno {}, value {nr:#x}",
                            -(errno as i64)
                        ),
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
            Some(Op::SdkViolation) => self.sdk_violation(idx, a),
            Some(Op::VtReclaim) => {
                vtgc::reclaim(self.ctl);
                Next::Continue(0)
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
            Some(op @ (Op::UdpSocket | Op::UdpBind | Op::UdpConnect | Op::UdpSend)) => {
                self.udp_op(op, a)
            }
            None => self.finish(Verdict::new("infra", format!("unknown request {}", req.op))),
        }
    }

    fn serve(&mut self) -> ! {
        let cfg = self.ctl.config;
        let slice = stall::Watchdog::slice_ms(cfg.stall_ms);
        let mut dog = stall::Watchdog::new(
            cfg.stall_ms,
            cfg.sched & SCHED_SPIN_PROBE != 0,
            self.ctl.seq.load(Relaxed),
            now_ns(),
        );
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
                    let holder = self.running.map(|i| stall::Holder {
                        slot: i,
                        tid: self.slot(i).tid.load(Relaxed),
                        pid: self.slot(i).pid.load(Relaxed),
                    });
                    let running = self.running;
                    let sched = &self.sched;
                    match dog.poll(self.ctl.seq.load(Relaxed), now_ns(), holder, || {
                        sched.waiting_besides(running)
                    }) {
                        stall::Poll::Quiet => {}
                        stall::Poll::Probe { tid, pid } => stall::probe(pid, tid),
                        stall::Poll::End(mut v) => {
                            if v.class == "stall" {
                                v.detail += &stall::spin_host(self.ctl);
                            }
                            self.finish(v)
                        }
                    }
                    continue;
                }
            }
            self.ctl.sup_word.store(0, SeqCst);
            dog.progress(self.ctl.seq.load(Relaxed), now_ns());
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
            dog.progress(self.ctl.seq.load(Relaxed), now_ns());
            self.io.refresh(&self.sched, self.ctl);
            self.reply(idx, to);
        }
    }
}

/// Wall-clock monotonic time by a real syscall. The supervisor runs with the
/// timestamp counter faulting (see `main`), so it must not use the vDSO, which reads it.
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
    // `HIDDEN:DST`: trees the launcher bound at a hidden place, copied to DST.
    let mut copies: Vec<(String, String)> = vec![];
    let mut exe: Option<String> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--copy" => {
                let v = it.next().ok_or("--copy needs HIDDEN:DST")?;
                let (h, d) = v.split_once(':').ok_or("--copy needs HIDDEN:DST")?;
                copies.push((h.to_string(), d.to_string()));
            }
            "--exe" => exe = Some(it.next().ok_or("--exe needs PATH")?.clone()),
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
        udp: udp::Udp::default(),
        exe: exe.clone().unwrap_or_else(|| cmd[0].clone()),
        execed: false,
    };
    // The rest of the process state guests inherit from the supervisor.
    if let Err(e) = inherit::normalise(ctl.config.tmpfs_bytes) {
        sup.finish(Verdict::new("infra", e));
    }
    if let Err(e) = sup.wire.init() {
        sup.finish(Verdict::new("infra", e));
    }
    if let Err(e) = sup.udp.init() {
        sup.finish(Verdict::new("infra", e));
    }

    // The program and the `:copy` mounts: copies on sandbox tmpfs, not binds of the host's.
    for (h, d) in &copies {
        if let Err(e) = inherit::copy_tree(Path::new(h), Path::new(d)) {
            sup.finish(Verdict::new("infra", format!("copying into {d}: {e}")));
        }
    }
    if Path::new("/.patina/in").is_dir() {
        if let Err(e) = crash::copy_in(Path::new("/.patina/in"), &work_dir(ctl)) {
            sup.finish(Verdict::new(
                "infra",
                format!("copying /in to the work tree: {e}"),
            ));
        }
    }
    if let Err(e) = crash::write_base(ctl, &work_dir(ctl)) {
        if ["(os error 28)", "(os error 122)"]
            .iter()
            .any(|c| e.contains(c))
        {
            sup.finish(log_write_verdict(libc::ENOSPC, "writing the base records"));
        }
        sup.finish(Verdict::new("infra", format!("base records: {e}")));
    }
    // The starting tree's records are the program's input, not its output: not counted.
    ctl.log_exempt.store(
        ctl.oplog_len.load(Relaxed) + ctl.opdata_len.load(Relaxed),
        Relaxed,
    );

    ctl.timing[TM_COPIED].store(now_ns(), Relaxed);
    // The first guest: slot 0, reserved before the task exists.
    sup.slot(0).state.store(SLOT_RESERVED, SeqCst);
    let cstrs = |v: &[String]| -> Vec<CString> {
        v.iter()
            .map(|s| CString::new(s.as_bytes()).unwrap())
            .collect()
    };
    let mut rt_args = vec!["rt".to_string(), exe.unwrap_or_else(|| cmd[0].clone())];
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

/// The work tree's guest path (`--work DIR:GUEST`).
fn work_dir(ctl: &Ctl) -> std::path::PathBuf {
    use std::os::unix::ffi::OsStrExt;
    Path::new(std::ffi::OsStr::from_bytes(ctl.config.work_path())).to_path_buf()
}

/// Why the first image cannot run, in a sentence: the program, the `#!` interpreter that
/// failed (read again along the program's `#!` lines, `depth` deep), the reason and the errno.
fn exec_failure(exe: &str, errno: u64, why: proto::exec::Why, depth: usize) -> String {
    use proto::exec::Why;
    use std::io::Read;
    let mut file = exe.to_string();
    let mut chain = vec![];
    for _ in 0..depth {
        let mut head = vec![0u8; proto::exec::BINPRM_BUF_SIZE];
        let n = std::fs::File::open(&file)
            .and_then(|mut f| f.read(&mut head))
            .unwrap_or(0);
        let Ok(s) = proto::exec::parse(&head[..n]) else {
            break;
        };
        file = String::from_utf8_lossy(s.interp).into_owned();
        chain.push(file.escape_debug().to_string());
    }
    let errno_name = match errno {
        1 => "EPERM",
        2 => "ENOENT",
        8 => "ENOEXEC",
        13 => "EACCES",
        20 => "ENOTDIR",
        26 => "ETXTBSY",
        36 => "ENAMETOOLONG",
        5 => "EIO",
        40 => "ELOOP",
        80 => "ELIBBAD",
        _ => "",
    };
    let reason = match (why, errno) {
        (Why::Errno, 2) => "not in the sandbox",
        (Why::Errno, 13) => "permission denied (a directory on its path)",
        (Why::Errno, 20) => "a component of its path is not a directory",
        (Why::Errno, 40) => "too many symbolic links",
        (Why::Errno, 36) => "its name is too long",
        (w, _) => w.text(),
    };
    let errno = match errno_name {
        "" => format!("errno {errno}"),
        n => n.to_string(),
    };
    let reason = if reason.is_empty() {
        "cannot run"
    } else {
        reason
    };
    match chain.as_slice() {
        [] => format!("cannot run the program {exe}: {reason} ({errno})"),
        c => format!(
            "cannot run the program {exe}: its #! interpreter {}: {reason} ({errno})",
            c.join(" -> #! ")
        ),
    }
}
