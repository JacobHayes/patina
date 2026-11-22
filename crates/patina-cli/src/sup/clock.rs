//! Each machine's realtime clock (`proto::machine`): one virtual time serves the run; a machine's
//! `CLOCK_REALTIME` (and what derives from it: `gettimeofday`, `time`, the times it writes
//! on its files, `/proc/stat`'s `btime`) is that time plus the machine's offset
//! (`MachineTab::clock_off`), which the runtime adds. Monotonic and boot-time clocks have no
//! offset, and no clock runs fast or slow.
//!
//! The offset is the boot's skew plus the script's steps: with `clock-skew-ms=A..B` each
//! boot of a machine draws a skew in A..B ms, ahead or behind (`Stream::Machine`, keyed by the machine,
//! the boot and `MSUB_SKEW`); `clock NAME DELTA` from main moves the machine's clock
//! by DELTA, and the move stays across its restarts, as a clock set on a machine does. The
//! main's clock is never moved: it is the run's virtual time.
//!
//! A step does what setting the clock does on Linux: an absolute realtime deadline (a
//! `clock_nanosleep` or futex wait with `TIMER_ABSTIME` on `CLOCK_REALTIME`, a timerfd armed
//! with `TFD_TIMER_ABSTIME` on it) is a realtime time, so it moves with the clock: one now
//! past is due at once; a relative one, on any clock, does not move (the kernel keeps relative
//! realtime timers on the monotonic base). A timerfd armed with `TFD_TIMER_ABSTIME |
//! TFD_TIMER_CANCEL_ON_SET` on `CLOCK_REALTIME` becomes readable, and its next read answers
//! `ECANCELED` (the runtime's `timerfd::canceled`). The runtime says which deadline is which
//! in `Slot::clock_flags`, outside the request, so the log of a run without steps is the same.

use super::{Next, Sup};
use proto::ctl::*;
use proto::layout::{REALTIME_EPOCH_S, VCLOCK_BOOT_NS};
use proto::machine::*;
use std::sync::atomic::Ordering::Relaxed;

impl Sup {
    /// A thread just parked on `Sleep` or `FutexWait`: whether its deadline is an absolute
    /// realtime time (`f`: the slot's `clock_flags`, which the request's handler read and
    /// cleared).
    pub(super) fn park_clock(&mut self, idx: usize, f: u64) {
        self.sched.entries[idx].rt_abs = f & CLK_REALTIME_ABS != 0;
    }

    /// Boot `b` of machine `k` started: its offset is its skew (drawn with `clock-skew-ms`) plus
    /// the steps so far.
    pub(super) fn clock_boot(&mut self, k: usize, b: u64) {
        let c = self.machine_tab().conf[k];
        if c.skew_max_ns == 0 {
            return;
        }
        // After the faults end a boot draws no skew: its clock is the steps alone.
        if self.ctl.faults.cfg.fault_until_seq != 0 {
            let t = self.machine_tab();
            t.clock_off[k] = t.clock_stepped[k];
            return;
        }
        let d = proto::draw(
            self.ctl.config.seed,
            proto::Stream::Machine,
            (k as u64) << 24 | (b & 0xffff) << 8 | MSUB_SKEW,
        );
        let span = c.skew_max_ns.saturating_sub(c.skew_min_ns) + 1;
        let mag = (c.skew_min_ns + (d >> 1) % span) as i64;
        let skew = if d & 1 != 0 { -mag } else { mag };
        // Not before 1970 (as a step may not be): steps back by decades and a skew behind
        // leave the machine at the epoch.
        let now = self.now();
        let real = (now - VCLOCK_BOOT_NS + REALTIME_EPOCH_S * 1_000_000_000) as i64;
        let stepped = self.machine_tab().clock_stepped[k] as i64;
        let skew = skew.max(-real.saturating_add(stepped));
        let t = self.machine_tab();
        let off = skew.saturating_add(t.clock_stepped[k] as i64);
        t.clock_off[k] = off as u64;
        if let Some(e) = t.boot[k].get_mut(b as usize) {
            e.skew_ns = skew as u64;
        }
        self.decide(
            DEC_MACHINE_CLOCK,
            0,
            [k as u64, b, CLK_SKEW, skew as u64, off as u64, 0],
            0,
        );
    }

    /// `clock NAME DELTA` from main: machine `k`'s clock moves by `delta` ns. A step
    /// that would put the machine's realtime before 1970 answers `EINVAL`.
    pub(super) fn clock_step(&mut self, k: usize, delta: i64) -> Next {
        let now = self.now();
        let t = self.machine_tab();
        let off = (t.clock_off[k] as i64).saturating_add(delta);
        let real = (now - VCLOCK_BOOT_NS + REALTIME_EPOCH_S * 1_000_000_000) as i64;
        if real.saturating_add(off) < 0 {
            return Next::Continue(-(libc::EINVAL as i64));
        }
        t.clock_off[k] = off as u64;
        t.clock_sets[k] += 1;
        t.clock_stepped[k] = (t.clock_stepped[k] as i64).saturating_add(delta) as u64;
        let b = t.boots[k].saturating_sub(1);
        self.decide(
            DEC_MACHINE_CLOCK,
            0,
            [k as u64, b, CLK_STEP, delta as u64, off as u64, 0],
            0,
        );
        // The machine's absolute realtime deadlines move with its clock.
        for i in 0..self.sched.entries.len() {
            let e = &self.sched.entries[i];
            if !e.rt_abs || self.slot(i).machine.load(Relaxed) as usize != k {
                continue;
            }
            if let super::sched::State::Parked {
                deadline: Some(d), ..
            } = e.state
            {
                let at = d.saturating_add_signed(delta.saturating_neg());
                self.sched.retime(i, at, now);
            }
        }
        self.io
            .timers_clock_set(&mut self.sched, self.ctl, k, delta, now);
        self.sched.fire_due(now);
        self.after_events();
        Next::Continue(0)
    }
}
