//! The stall watchdog: what the supervisor does while a guest thread holds the turn and
//! computes without a boundary event.
//!
//! It measures the turn holder's CPU time since its last boundary event
//! (`/proc/TID/schedstat`), not wall time: a spinning thread accumulates it, a thread the host
//! does not schedule (load) does not.
//!
//! - **Probes.** After `PROBE_FIRST_NS` of CPU time, and at four times the previous amount
//!   after each, the thread is sent a spin probe (`patina-rt/src/spin.rs`): if it is in a
//!   loop whose iterations leave its state unchanged, it yields there and keeps doing so.
//!   A probe changes nothing the guest can see, so its wall-clock timing does not reach the
//!   schedule.
//! - **compute-stall.** When the CPU time passes `stall_ms` while another thread is runnable
//!   or a virtual-time event is due, the run ends `unsupported`, stop `compute-stall`
//!   (verdict `stall`), naming the thread. A thread computing alone is left to run.
//! - **Backstop.** A thread that neither makes progress nor runs (blocked in the kernel
//!   outside any row) ends the run `internal` after ten times `stall_ms` of wall time. A
//!   thread waiting for a load-time plan (`--preempt points`) is making progress.

use crate::outcome::Verdict;

/// CPU time without a boundary event before the first probe.
const PROBE_FIRST_NS: u64 = 20_000_000;

/// The turn holder, as the watchdog sees it.
pub struct Holder {
    pub slot: usize,
    pub tid: i32,
    pub pid: i32,
}

/// What the rest of the run could do if the holder yielded.
pub struct Others {
    pub runnable: usize,
    pub timed: bool,
}

pub enum Poll {
    Quiet,
    /// Send the holder a spin probe.
    Probe {
        tid: i32,
        pid: i32,
    },
    End(Verdict),
}

pub struct Watchdog {
    stall_ns: u64,
    probes: bool,
    last_seq: u64,
    last_progress: u64,
    /// (tid, CPU time) at the holder's last boundary event as first seen here.
    base: Option<(i32, u64)>,
    next_probe: u64,
}

impl Watchdog {
    pub fn new(stall_ms: u64, probes: bool, seq: u64, now: u64) -> Watchdog {
        Watchdog {
            stall_ns: stall_ms * 1_000_000,
            probes,
            last_seq: seq,
            last_progress: now,
            base: None,
            next_probe: PROBE_FIRST_NS,
        }
    }

    /// How long the supervisor may sleep between polls, in ms.
    pub fn slice_ms(stall_ms: u64) -> u64 {
        (stall_ms / 8).clamp(1, 10)
    }

    /// A request arrived (the holder made progress).
    pub fn progress(&mut self, seq: u64, now: u64) {
        self.last_seq = seq;
        self.last_progress = now;
        self.base = None;
        self.next_probe = PROBE_FIRST_NS;
    }

    /// No request for a slice: decide what to do about the holder.
    pub fn poll(
        &mut self,
        seq: u64,
        now: u64,
        holder: Option<Holder>,
        others: impl FnOnce() -> Others,
    ) -> Poll {
        let tid = holder.as_ref().map(|h| h.tid).unwrap_or(0);
        let cpu = thread_cpu_ns(tid);
        if seq != self.last_seq {
            // Progress without a request (a trap that did not yield).
            self.last_seq = seq;
            self.last_progress = now;
            self.base = cpu.map(|c| (tid, c));
            self.next_probe = PROBE_FIRST_NS;
            return Poll::Quiet;
        }
        let spun = match (cpu, self.base) {
            (Some(c), Some((t, c0))) if t == tid => c.saturating_sub(c0),
            (Some(c), _) => {
                self.base = Some((tid, c));
                0
            }
            (None, _) => 0,
        };
        let waited = now.saturating_sub(self.last_progress);
        if let Some(h) = holder {
            if spun >= self.stall_ns {
                let o = others();
                if o.runnable > 0 || o.timed {
                    return Poll::End(compute_stall(&h, spun, &o));
                }
            } else if self.probes && spun >= self.next_probe {
                self.next_probe = self.next_probe.saturating_mul(4);
                return Poll::Probe {
                    tid: h.tid,
                    pid: h.pid,
                };
            }
            if spun > 0 {
                return Poll::Quiet;
            }
        }
        if waited >= self.stall_ns.saturating_mul(10) || (cpu.is_none() && waited >= self.stall_ns)
        {
            return Poll::End(Verdict::new(
                "infra",
                format!(
                    "no progress for {} ms of wall time: thread {tid} neither made a request nor ran (last seq {seq})",
                    waited / 1_000_000
                ),
            ));
        }
        Poll::Quiet
    }
}

fn compute_stall(h: &Holder, spun: u64, o: &Others) -> Verdict {
    let name = std::fs::read_to_string(format!("/proc/{}/comm", h.tid))
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let waiting = match (o.runnable, o.timed) {
        (0, _) => "a timed event was due".to_string(),
        (1, _) => "1 other thread was runnable".to_string(),
        (n, _) => format!("{n} other threads were runnable"),
    };
    Verdict::new(
        "stall",
        format!(
            "thread {} (tid {}, {name}) computed for {:.1} s without a system call or pause while {waiting}. \
             This is a spin-wait Patina could not preempt, or an endless loop. \
             If that code was not rebuilt with compute points, rebuilding it with them makes such a loop a scheduling point \
             (docs/GUIDE.md, \"Scheduling\"){BRANCHES}",
            h.slot,
            h.tid,
            spun as f64 / 1e9
        ),
    )
}

/// Why spin probes could not help, when the host or the thread's state is the reason: the
/// launcher turned them off (`patina doctor`'s "spin probes" says why), or a probe met a
/// refusal.
pub fn spin_host(ctl: &proto::ctl::Ctl) -> String {
    if ctl.config.sched & proto::ctl::SCHED_SPIN_HOST_OFF != 0 {
        return " Spin probes are off: this host cannot make them work (`patina doctor` says why)."
            .into();
    }
    let v = ctl
        .sched
        .spin_host
        .load(std::sync::atomic::Ordering::Relaxed);
    let Some(t) = proto::ctl::spin_host_text(v) else {
        return String::new();
    };
    let errno = v & 0xffff_ffff;
    let errno = if errno != 0 {
        format!(" (errno {errno})")
    } else {
        String::new()
    };
    let doctor = if v >> 32 == proto::ctl::SPIN_HOST_EXTRA {
        ""
    } else {
        " (`patina doctor`)"
    };
    format!(" A spin probe could not run: {t}{errno}{doctor}.")
}

/// The other ways out: switch points written in as the code loads (x86_64), branch counters.
#[cfg(target_arch = "x86_64")]
const BRANCHES: &str =
    "; or rerun with --preempt points (switch points written into the code as it loads; \
     code it leaves dark, such as JIT output, stays without them), or with --preempt branches \
     (needs CAP_PERFMON and a host PMU; see `patina doctor`).";
#[cfg(not(target_arch = "x86_64"))]
const BRANCHES: &str =
    "; or rerun with --preempt branches (needs CAP_PERFMON and a host PMU; see `patina doctor`).";

/// CPU time of guest thread `tid` (a PID-namespace id; 0: none), from `/proc/TID/schedstat`.
fn thread_cpu_ns(tid: i32) -> Option<u64> {
    if tid <= 0 {
        return None;
    }
    let t = std::fs::read_to_string(format!("/proc/{tid}/schedstat")).ok()?;
    t.split_whitespace().next()?.parse().ok()
}

/// Send the turn holder a spin probe.
pub fn probe(pid: i32, tid: i32) {
    unsafe { libc::syscall(libc::SYS_tgkill, pid, tid, libc::SIGTRAP) };
}
