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
//!   thread waiting for a load-time plan (load-time points) is making progress for the
//!   budget the broker gives that plan (`Planning`); past it the backstop applies, and its
//!   verdict says what the thread was waiting for.

use crate::outcome::Verdict;

/// CPU time without a boundary event before the first probe.
const PROBE_FIRST_NS: u64 = 20_000_000;

/// The turn holder, as the watchdog sees it.
pub struct Holder {
    pub slot: usize,
    pub tid: i32,
    pub pid: i32,
    /// Where a spin probe last found it in program code (`Slot::probe_pc`, 0: nowhere).
    pub pc: u64,
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
        /// The first of this stretch of computing: what an earlier one found is stale.
        first: bool,
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
                    // Where a probe of this stretch found it: none sent, nothing known.
                    let probed = self.next_probe != PROBE_FIRST_NS;
                    let h = Holder {
                        pc: if probed { h.pc } else { 0 },
                        ..h
                    };
                    return Poll::End(compute_stall(&h, spun, &o));
                }
            } else if self.probes && spun >= self.next_probe {
                let first = self.next_probe == PROBE_FIRST_NS;
                self.next_probe = self.next_probe.saturating_mul(4);
                return Poll::Probe {
                    tid: h.tid,
                    pid: h.pid,
                    first,
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

/// The word the plan broker writes to `ctl.compute.planning` while it makes a plan: the
/// request's token (high half) and its budget in seconds (low half, at least 1, so nonzero).
pub fn planning_word(token: u64, budget_s: u64) -> u64 {
    (token << 32) | budget_s.clamp(1, u32::MAX as u64)
}

/// The plan the turn holder waits for, as the supervisor sees it: since when (its own clock,
/// from the first poll that saw the request) and for how long that counts as progress.
#[derive(Default)]
pub struct Planning {
    word: u64,
    since: u64,
}

impl Planning {
    /// Does the plan being made (`word` from `ctl.compute.planning`, 0 for none) count as
    /// progress at `now`?
    pub fn counts(&mut self, word: u64, now: u64) -> bool {
        if word != self.word {
            self.word = word;
            self.since = now;
        }
        word != 0 && now.saturating_sub(self.since) < self.budget_ns()
    }

    fn budget_ns(&self) -> u64 {
        (self.word & 0xffff_ffff) * 1_000_000_000
    }

    /// For a verdict while a plan is past its budget: what the thread was waiting for.
    pub fn overdue(&self, now: u64) -> Option<String> {
        let waited = now.saturating_sub(self.since);
        (self.word != 0 && waited >= self.budget_ns()).then(|| {
            format!(
                "; it was waiting for a load-time plan for {} s, past that \
                 plan's bound of {} s (the launcher's stderr names the file)",
                waited / 1_000_000_000,
                self.budget_ns() / 1_000_000_000
            )
        })
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
    let at = match (h.pc != 0).then(|| place(h.tid, h.pc)).flatten() {
        Some(p) => format!(", last seen in {p}"),
        None => String::new(),
    };
    Verdict::new(
        "stall",
        format!(
            "thread {} (tid {}, {name}) computed for {:.1} s without a system call or pause while {waiting}{at}. \
             This is a spin-wait Patina could not preempt, or an endless loop. \
             If that code was not rebuilt with compute points, rebuilding it with them makes such a loop a scheduling point \
             (docs/GUIDE.md, \"Scheduling\"){BRANCHES}",
            h.slot,
            h.tid,
            spun as f64 / 1e9
        ),
    )
}

/// Where `pc` is in thread `tid`'s memory: the function holding it (from the file's symbols)
/// and the file with the offset (`/proc/TID/maps`), or anonymous memory.
fn place(tid: i32, pc: u64) -> Option<String> {
    let maps = std::fs::read_to_string(format!("/proc/{tid}/maps")).ok()?;
    for line in maps.lines() {
        // start-end perms offset dev inode path (which may hold spaces)
        let mut f = line.splitn(6, ' ');
        let (lo, hi) = f.next()?.split_once('-')?;
        let (lo, hi) = (
            u64::from_str_radix(lo, 16).ok()?,
            u64::from_str_radix(hi, 16).ok()?,
        );
        if pc < lo || pc >= hi {
            continue;
        }
        let off = u64::from_str_radix(f.nth(1)?, 16).ok()?;
        let Some(path) = f.nth(2).map(str::trim_start).filter(|p| p.starts_with('/')) else {
            return Some(format!("anonymous memory at {pc:#x}"));
        };
        let fo = pc - lo + off;
        // A file deleted since it was mapped: its path may name another file now.
        let gone = path.ends_with(" (deleted)");
        let func = (!gone)
            .then(|| std::fs::read(path).ok())
            .flatten()
            .and_then(|d| {
                crate::rewrite::elf::Elf::parse(&d)
                    .ok()?
                    .function_at_offset(fo)
            });
        return Some(match func {
            Some(s) => format!("{s} ({path}+{fo:#x})"),
            None => format!("{path}+{fo:#x}"),
        });
    }
    None
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

/// The other ways out: load-time points (the default) cover loaded code but not code made at
/// run time or text they leave dark; branch counters cover every branch.
const BRANCHES: &str =
    ". Load-time points (the default) put switch points into code as it loads, but not into \
     code made at run time (JIT output) or text they leave dark (result.json's rewrite says \
     which); [sched] preempt = \"branches\" preempts there too (needs CAP_PERFMON and a host \
     PMU; see `patina doctor`).";

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

#[cfg(test)]
mod tests {
    use super::*;

    const S: u64 = 1_000_000_000;

    #[test]
    fn planning_counts_for_its_budget_only() {
        let mut p = Planning::default();
        assert!(!p.counts(0, 0));
        let a = planning_word(1, 5);
        assert!(p.counts(a, 10 * S));
        assert!(p.counts(a, 14 * S));
        assert!(p.overdue(14 * S).is_none());
        assert!(!p.counts(a, 15 * S));
        assert!(p.overdue(15 * S).is_some());
        // The next request (another token, the same budget) has a budget of its own.
        let b = planning_word(2, 5);
        assert!(p.counts(b, 16 * S));
        assert!(p.counts(b, 20 * S));
        assert!(!p.counts(0, 21 * S));
        assert!(p.overdue(21 * S).is_none());
    }
}
