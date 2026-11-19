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

/// For a copy into a sandbox tmpfs that failed with `ENOSPC`: the size that bounds it.
fn tmpfs_hint(ctl: &Ctl, e: &str) -> String {
    if !e.contains("(os error 28)") {
        return String::new();
    }
    format!(
        " (each sandbox tmpfs holds {} bytes: --tmpfs-bytes, [run] tmpfs-bytes)",
        ctl.config.tmpfs_bytes
    )
}

/// The guest's fixed environment; `--env` adds to it. `PATINA=1` tells a program it runs
/// under Patina.
pub(crate) const BASE_ENV: [&str; 5] = [
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
pub mod inherit;
pub mod io;
mod link;
mod maps;
mod nodes;
pub mod proc;
#[allow(dead_code)]
pub mod sched;
mod sdk;
pub mod shm;
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
    /// System V shared memory.
    shm: shm::Shm,
    /// Nodes: their boot and end (a run with nodes).
    nodes: nodes::Nodes,
    /// Links between nodes: the cuts of a script and of the seed.
    links: link::Links,
    /// The program's path in the sandbox (the first image).
    exe: String,
    /// Processes in which an `execve` has replaced an image (pids are unique in a run): a
    /// runtime there that cannot run its image was handed one an `execve` resolved, not the
    /// program (or a node's command).
    execed: std::collections::BTreeSet<i32>,
    /// The shared mappings of the processes still alive were logged for the end of the run
    /// (`end_maps`): a crash point did it before its `Crash` record.
    maps_ended: std::cell::Cell<bool>,
}

/// What a request does with the turn.
enum Next {
    /// The caller continues with this return value.
    Continue(i64),
    /// The caller parked, yielded or exited: pick who runs next.
    Pick,
    /// The caller yielded at a load-time point the runtime drew as a switch
    /// (`Op::Yield` with `YIELD_OTHER`): pick another runnable thread when there is one.
    PickOther,
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
        let pid = self.sched.entries[to].pid;
        let quiet = self.sig.procs.get(&pid).is_none_or(|p| p.pending.set == 0);
        let v = &self.ctl.view;
        v.seq.store(self.ctl.seq.load(Relaxed), Relaxed);
        v.slot.store(to as u64, Relaxed);
        v.runnable
            .store(self.sched.runnable().count() as u64, Relaxed);
        v.quiet.store(quiet as u64, Relaxed);
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

    /// Who runs next after `idx` yielded at a point drawn as a switch: the seeded pick among the
    /// runnable threads other than `idx`; `choose` when there is none.
    fn choose_other(&mut self, idx: usize) -> (usize, u64) {
        let seq = self.ctl.seq.load(Relaxed) + 1;
        match self.sched.pick_except(seq, idx) {
            Some(to) => (to, seq),
            None => self.choose(),
        }
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
            if let Some(d) = self.lost_signal() {
                self.finish(Verdict::new("infra", d));
            }
            let old = self.now();
            // Nothing pending but a partition or a kill to come: deadlock, now.
            if self.sched.only_weak() {
                self.deadlock();
            }
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
        // Node events first: a heal re-stamps what the wire then delivers.
        for key in std::mem::take(&mut self.sched.fired_node) {
            self.node_event(key);
        }
        self.wire_step();
        self.io.sync(&mut self.sched, self.ctl);
    }

    pub(super) fn describe_wait(w: Wait) -> String {
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

    /// Log what the shared mappings of `pids` hold that the log does not: they end without
    /// their runtime (`maps`).
    fn flush_maps(&self, pids: &[i32], seq: u64) -> Result<(), String> {
        let mut pass = maps::Pass::new(self.ctl, &work_dir(self.ctl), seq);
        for &pid in pids {
            pass.process(pid)?;
        }
        Ok(())
    }

    /// The end of the run (a finish, a crash point): log the shared mappings of every process
    /// still alive, once, in pid order, with sequence number `seq`. Not a vfork child's (its
    /// mappings are its parent's, logged with it). Only a stall ends the run while a thread
    /// runs guest code (the turn's holder): its process is stopped first (`stop_holder`), so
    /// nothing changes while the files are read; where it stopped depends on the host, as
    /// does a stall itself.
    fn end_maps(&self, seq: u64) -> Result<(), String> {
        if self.maps_ended.replace(true) {
            return Ok(());
        }
        if let Some(i) = self.running {
            if !self.stop_holder(i) {
                return Err("the thread holding the turn did not stop".into());
            }
        }
        let pids: Vec<i32> = self
            .procs
            .map
            .iter()
            .filter(|(_, p)| p.state == proc::PState::Live && p.vfork_parent.is_none())
            .map(|(pid, _)| *pid)
            .collect();
        self.flush_maps(&pids, seq)
    }

    /// Stop the process of slot `i`'s thread, which runs guest code, with `SIGSTOP`, and wait
    /// (at most a second) until that thread is stopped. Whether it did.
    fn stop_holder(&self, i: usize) -> bool {
        let (pid, tid) = (
            self.slot(i).pid.load(Relaxed),
            self.slot(i).tid.load(Relaxed),
        );
        if unsafe { libc::kill(pid, libc::SIGSTOP) } != 0 {
            return false;
        }
        for _ in 0..1000 {
            let Ok(s) = std::fs::read_to_string(format!("/proc/{pid}/task/{tid}/stat")) else {
                return true; // gone: nothing runs
            };
            // The state follows the command's closing parenthesis.
            if let Some('T' | 't' | 'Z' | 'X') =
                s.rsplit_once(") ").and_then(|(_, r)| r.chars().next())
            {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        false
    }

    /// A failure to log shared mappings: a full disk is named as for the other logs.
    fn maps_verdict(e: String) -> Verdict {
        if ["(os error 28)", "(os error 122)"]
            .iter()
            .any(|c| e.contains(c))
        {
            log_write_verdict(libc::ENOSPC, "logging shared mappings")
        } else {
            Verdict::new("infra", e)
        }
    }

    fn finish(&self, v: Verdict) -> ! {
        self.ctl.timing[TM_FINISH].store(now_ns(), Relaxed);
        // The run ends whatever this finds: a failure shows in the operation log's check.
        let _ = self.end_maps(self.ctl.seq.load(Relaxed));
        unsafe {
            libc::kill(-1, libc::SIGKILL);
            let mut st = 0;
            while libc::waitpid(-1, &mut st, 0) > 0 {}
        }
        // Every guest is dead: the live tree is final, and so is the shared memory a process
        // crash leaves to the next incarnation (any other end leaves none).
        crash::export(&work_dir(self.ctl));
        let carried = if v.class == "crash" && v.detail.starts_with("process ") {
            self.shm.save(self.now())
        } else {
            vec![]
        };
        write_shm_state(&carried);
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

    /// A System V shared memory request (`Op::Shm`).
    fn shm_op(&mut self, idx: usize, a: [u64; 6]) -> i64 {
        let pid = self.sched.entries[idx].pid;
        let now = self.now();
        let id = a[1] as i32 as i64;
        let slot = unsafe { self.ctl.slot(idx) };
        let mut out = [0u64; 16];
        // Each node is its own IPC namespace: its own table of segments.
        let node = self.node_of(idx);
        let shm = if node == 0 {
            &mut self.shm
        } else {
            self.nodes.shm.entry(node).or_default()
        };
        let r = match a[0] {
            SHMOP_GET => shm.get(
                pid,
                a[1] as i32,
                a[2],
                a[3],
                (a[4] as u32, (a[4] >> 32) as u32),
                now,
            ),
            _ if id < 0 => -(libc::EINVAL as i64),
            SHMOP_AT => match shm.attach(pid, id, now) {
                Ok((size, fd)) => {
                    out[0] = fd as u64;
                    size as i64
                }
                Err(e) => e,
            },
            SHMOP_DT => shm.detach(pid, id, now),
            SHMOP_CTL => shm.ctl(id, a[2], [a[3], a[4], a[5]], now, &mut out),
            _ => -(libc::EINVAL as i64),
        };
        unsafe { std::ptr::write_volatile(&mut (*slot).siginfo, out) };
        r
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
        // Words in memory shared across processes are keyed globally, per node: the same
        // file or segment identity on two nodes is two objects.
        let node = if self.node_count() > 0 {
            self.node_of(idx) as u64
        } else {
            0
        };
        let asid_of = |addr: u64| {
            if addr & FUTEX_SHARED_BIT != 0 {
                u64::MAX - node
            } else {
                own_asid
            }
        };
        let asid = own_asid;
        match Op::from_u32(req.op) {
            Some(Op::Hello) => self.hello(idx, a),
            Some(Op::VforkStart) => self.vfork_start(idx, a),
            Some(Op::Exec) => {
                let pid = self.sched.entries[idx].pid;
                self.execed.insert(pid);
                if let Err(e) = self.io.timers_exec(&mut self.sched, pid) {
                    self.finish(Verdict::new(
                        "infra",
                        format!("host error: errno {e} in kcmp (timers kept across execve)"),
                    ));
                }
                self.exec(idx, a)
            }
            Some(Op::WaitPark) => self.wait_park(idx, a),
            Some(Op::Yield) => {
                self.sched.entries[idx].reply = 0;
                if a[0] == YIELD_OTHER {
                    Next::PickOther
                } else {
                    Next::Pick
                }
            }
            Some(Op::Sleep) => {
                let Some(ok) = self.may_block(idx) else {
                    return Next::Continue(-(libc::EINTR as i64));
                };
                self.sched.park(idx, Wait::Sleep, Some(a[0]), ok);
                Next::Pick
            }
            Some(Op::FutexWait) => {
                let deadline = if a[2] == NO_DEADLINE {
                    None
                } else {
                    Some(a[2])
                };
                let Some(ok) = self.may_block(idx) else {
                    return Next::Continue(-(libc::EINTR as i64));
                };
                self.sched
                    .futex_wait(idx, (asid_of(a[0]), a[0]), a[3] as u32, deadline, ok);
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
                self.slot_node(child, self.node_of(idx));
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
                // A signal the thread does not block came while it was runnable between two
                // attempts (woken to re-check, or before its first): the wait ends now, as
                // the kernel's would have, instead of parking past it (`Io::park`).
                let ok = self.may_block(idx);
                let now = self.now();
                match self.io.park(&mut self.sched, self.ctl, idx, a, now, ok) {
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
            Some(Op::Shm) => Next::Continue(self.shm_op(idx, a)),
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
                    if self.execed.contains(&self.sched.entries[idx].pid) {
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
                    // A node's first image: its command (the launcher checked it on the host).
                    let node = self.node_of(idx);
                    let d = if node > 0 {
                        let what = format!("node {}'s command", self.node_name(node));
                        exec_failure(&what, errno, why, 0)
                    } else {
                        exec_failure(&self.exe, errno, why, a[3] as usize)
                    };
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
                if code == HE_WALK {
                    self.finish(Verdict::new(
                        "infra",
                        format!(
                            "--preempt points: this host does not let a walk single-step (errno {}, {}); --fault compute-walk=0 takes every switch at its point",
                            -(errno as i64),
                            if nr == 0 { "/proc/self/mem" } else { proto::table::name(nr) }
                        ),
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
            Some(Op::Net) => self.net_op(idx, a),
            Some(Op::PidNode) => self.pid_node(a),
            Some(Op::CrashPoint) => {
                // Every process ends here: what their shared mappings hold, then the end.
                let pid = self.sched.entries[idx].pid as u32;
                if let Err(e) = self
                    .end_maps(a[1])
                    .and_then(|_| crash::append_crash(self.ctl, a[0], a[1], pid))
                {
                    self.finish(Self::maps_verdict(e));
                }
                self.decide(Op::CrashPoint as u32, idx, a, 0);
                self.finish(crash::crash_verdict(a, self.now()))
            }
            Some(
                op @ (Op::SigSend
                | Op::SigWait
                | Op::SigSuspend
                | Op::TimerSet
                | Op::SigTake
                | Op::SigAction
                | Op::SigFd),
            ) => self.signal_op(op, idx, a),
            Some(
                op @ (Op::WireSocket
                | Op::WireBind
                | Op::WireConnect
                | Op::WireAccepted
                | Op::WireSent
                | Op::WireRenew),
            ) => self.wire_op(op, idx, a),
            Some(op @ (Op::UdpSocket | Op::UdpBind | Op::UdpConnect | Op::UdpSend)) => {
                self.udp_op(op, idx, a)
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
                        let name = proc::comm(pid);
                        let st = if pid == self.child {
                            Some(self.reap())
                        } else {
                            proc::zombie_status(pid)
                        };
                        self.finish(proc::death_verdict(pid, &name, st));
                    }
                    let holder = self.running.map(|i| stall::Holder {
                        slot: i,
                        tid: self.slot(i).tid.load(Relaxed),
                        pid: self.slot(i).pid.load(Relaxed),
                    });
                    let running = self.running;
                    let sched = &self.sched;
                    // A plan being made for the holder: wall time only, progress here.
                    if self.ctl.compute.planning.load(Relaxed) != 0 {
                        dog.progress(self.ctl.seq.load(Relaxed), now_ns());
                    }
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
            let pid = self.sched.entries[idx].pid;
            let next = self.handle(idx, req);
            // The request may have followed a mask change or a thread's exit.
            self.retarget(pid);
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
                Next::Pick | Next::PickOther => {
                    let (to, seq) = match next {
                        Next::PickOther => self.choose_other(idx),
                        _ => self.choose(),
                    };
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
    // A run with nodes: the keeper's channel is at `FD_NODES`.
    let mut nodes = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--copy" => {
                let v = it.next().ok_or("--copy needs HIDDEN:DST")?;
                let (h, d) = v.split_once(':').ok_or("--copy needs HIDDEN:DST")?;
                copies.push((h.to_string(), d.to_string()));
            }
            "--exe" => exe = Some(it.next().ok_or("--exe needs PATH")?.clone()),
            "--nodes" => nodes = true,
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
    // Containment when the launcher is killed: die with the parent (the sandbox's keeper,
    // outside the PID namespace, which dies with the launcher); the kernel then kills every
    // process of the namespace. PID 1 set the same signal before executing this (`sandbox`);
    // set again here, where it is seen. If the launcher was already gone, the outcome pipe says
    // so (its only reader is the launcher; a pipe's write end polls POLLERR without readers).
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
        // guest process (the keeper's stdio, a host file, is dropped here).
        for (from, to) in [(FD_STDIN, 0), (FD_STDOUT, 1), (FD_STDERR, 2)] {
            if libc::dup2(from, to) != to {
                return Err(format!(
                    "stdio descriptor {from}: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }
        // Every other inherited descriptor, from the launcher's caller or the keeper.
        inherit::close_inherited(nodes);
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
        shm: shm::Shm::default(),
        nodes: nodes::Nodes::default(),
        links: link::Links::default(),
        exe: exe.clone().unwrap_or_else(|| cmd[0].clone()),
        execed: Default::default(),
        maps_ended: std::cell::Cell::new(false),
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
    // Shared memory a process crash left for this incarnation.
    match read_all_fd(FD_SHM).and_then(|b| shm::Shm::restore(&b)) {
        Ok(s) => sup.shm = s,
        Err(e) => sup.finish(Verdict::new("infra", format!("shared memory state: {e}"))),
    }

    // The program and the `:copy` mounts: copies on sandbox tmpfs, not binds of the host's.
    for (h, d) in &copies {
        if let Err(e) = inherit::copy_tree(Path::new(h), Path::new(d)) {
            sup.finish(Verdict::new(
                "infra",
                format!("copying into {d}: {e}{}", tmpfs_hint(ctl, &e)),
            ));
        }
    }
    if Path::new("/.patina/in").is_dir() {
        if let Err(e) = crash::copy_in(Path::new("/.patina/in"), &work_dir(ctl)) {
            sup.finish(Verdict::new(
                "infra",
                format!("copying /in to the work tree: {e}{}", tmpfs_hint(ctl, &e)),
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
    if nodes != (ctl.config.nodes > 1) {
        sup.finish(Verdict::new("infra", "--nodes and the node table disagree"));
    }
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        sup.finish(Verdict::new("infra", "fork failed"));
    }
    if pid == 0 {
        unsafe {
            libc::close(FD_OUTCOME);
            libc::close(FD_EXPORT);
            libc::close(FD_SHM);
            if nodes {
                libc::close(FD_NODES);
            }
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
    if nodes {
        sup.boot_nodes();
    }
    sup.serve()
}

/// The work tree's guest path (`--work DIR:GUEST`).
/// The whole of descriptor `fd` (a regular file or memfd; absent: empty).
fn read_all_fd(fd: i32) -> Result<Vec<u8>, String> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Ok(vec![]);
    }
    let mut b = vec![0u8; st.st_size as usize];
    let mut done = 0;
    while done < b.len() {
        let r = unsafe {
            libc::pread(
                fd,
                b[done..].as_mut_ptr() as *mut _,
                b.len() - done,
                done as i64,
            )
        };
        if r <= 0 {
            return Err(format!(
                "reading descriptor {fd}: {}",
                std::io::Error::last_os_error()
            ));
        }
        done += r as usize;
    }
    Ok(b)
}

/// Replace what `FD_SHM` holds (absent when the launcher passed none).
fn write_shm_state(b: &[u8]) {
    unsafe {
        if libc::ftruncate(FD_SHM, 0) != 0 {
            return;
        }
        let mut done = 0;
        while done < b.len() {
            let r = libc::pwrite(
                FD_SHM,
                b[done..].as_ptr() as *const _,
                b.len() - done,
                done as i64,
            );
            if r <= 0 {
                return;
            }
            done += r as usize;
        }
    }
}

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
        [] if exe.starts_with("node ") => format!("cannot run {exe}: {reason} ({errno})"),
        [] => format!("cannot run the program {exe}: {reason} ({errno})"),
        c => format!(
            "cannot run the program {exe}: its #! interpreter {}: {reason} ({errno})",
            c.join(" -> #! ")
        ),
    }
}
