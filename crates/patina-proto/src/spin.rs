//! A spin probe's reading of its trace (`rt::spin`): from the addresses a thread's single steps
//! reach, the loop it is in and where in that loop to compare its state. Compiled on every host
//! so that its tests run everywhere.
//!
//! **The invariant.** What a probe decides is a function of the thread's execution, never of
//! the instruction the probe arrived at (which wall-clock timing picks). Take a thread whose
//! addresses from the arrival repeat every P steps (P least) and whose whole state repeats
//! with them (it waits for another thread): it is found, with period P, at the least rotation
//! of the cycle's addresses, whenever P <= `PERIOD_MAX`, and never when P is larger. A thread
//! whose state does not come back with its addresses (a counter, or a state that comes back
//! only every second pass, as `x ^= 1`) is never found. (A probe that arrives before the
//! cycle begins may find it or not; when it does, the answer is the same.)
//!
//! **How.** The trace's prefix function (Knuth, Morris and Pratt) gives at each step the
//! least period of the trace so far, which never decreases. A period is a candidate once the
//! trace holds it twice; candidates come in increasing order. A candidate is checked at the
//! same position of its cycle each time, the least rotation of its addresses: the runtime
//! compares registers and written memory with the last check (`Trace::checked`). Equal states
//! `d` steps apart make the thread's execution `d`-periodic from there on, so a candidate
//! shorter than the cycle never passes, and the cycle itself passes at its first comparison.
//! A candidate whose state keeps changing (an inner loop's counter) is rejected and the trace
//! goes on: when the path leaves that loop, the least period grows to that of the loop around
//! it, the next candidate. Since the period is established at twice its length and checked
//! within three more, every candidate up to `PERIOD_MAX` is decided inside `TRACE_MAX`
//! steps, wherever in its cycle the trace began.
//!
//! **Retraces** (arm64, `RETRACES` of its stepper): where the path leaves a cycle the trace had
//! come back to the start of, the trace may start again there instead, for a store-exclusive that failed once and made a
//! loop retry: a trace that holds that extra pass would never be periodic.

/// Single steps a trace may hold.
pub const TRACE_MAX: usize = 1 << 16;
/// The longest period a probe finds: established by `2 * PERIOD_MAX` steps and checked three
/// times before `TRACE_MAX`.
pub const PERIOD_MAX: usize = TRACE_MAX / 5;
/// Unequal comparisons of one candidate before it is rejected.
pub const CHECKS: u32 = 4;

/// What the runtime does after a step was recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Take the next step.
    Go,
    /// The thread is at the candidate's position: compare its state (`Trace::checked`).
    Check,
    /// The path left the candidate's cycle: start the trace again here (`Trace::restart`).
    Retrace,
    /// No candidate can be found any more.
    Abort,
}

/// What a comparison at a check decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Checked {
    /// The state is the last check's: a fixed point, with period `Trace::period`.
    Found,
    /// Keep this check's state for the next comparison.
    Again,
    /// The candidate was rejected; the trace goes on.
    Rejected,
}

/// A probe's trace analysis. The trace (`t`) and its prefix function (`f`) are the runtime's
/// arrays of `TRACE_MAX` entries, passed to each call.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Trace {
    /// Steps in the trace.
    pub len: u32,
    /// The candidate period, being checked or rejected (0: none).
    pub period: u32,
    /// Checks made of the candidate.
    pub checks: u32,
    /// The trace index of its next check.
    next: u32,
    rejected: u8,
    retraces: u8,
}

impl Trace {
    pub const fn new() -> Trace {
        Trace {
            len: 0,
            period: 0,
            checks: 0,
            next: 0,
            rejected: 0,
            retraces: 0,
        }
    }

    /// A new probe at `pc`, which may start its trace again `retraces` times.
    pub fn start(&mut self, t: &mut [u64], f: &mut [u32], pc: u64, retraces: u8) {
        self.retraces = retraces;
        self.restart(t, f, pc);
    }

    /// Start the trace again at `pc`, with no candidate.
    pub fn restart(&mut self, t: &mut [u64], f: &mut [u32], pc: u64) {
        t[0] = pc;
        f[0] = 0;
        self.len = 1;
        self.period = 0;
        self.checks = 0;
        self.next = 0;
        self.rejected = 0;
    }

    /// A step ended at `pc`.
    pub fn record(&mut self, t: &mut [u64], f: &mut [u32], pc: u64) -> Step {
        let i = self.len as usize;
        if i >= TRACE_MAX.min(t.len()).min(f.len()) {
            return Step::Abort;
        }
        t[i] = pc;
        let mut k = f[i - 1] as usize;
        while k > 0 && t[k] != pc {
            k = f[k - 1] as usize;
        }
        if t[k] == pc {
            k += 1;
        }
        let back = f[i - 1] != 0;
        let was = i - f[i - 1] as usize;
        f[i] = k as u32;
        self.len += 1;
        let len = i + 1;
        let per = len - k;
        if back && per != was {
            // The trace had come back to its start, and the path now left that cycle.
            self.period = 0;
            if self.retraces > 0 {
                self.retraces -= 1;
                return Step::Retrace;
            }
        }
        if per > PERIOD_MAX {
            return Step::Abort;
        }
        if self.period == 0 {
            if len < 2 * per {
                return Step::Go;
            }
            self.period = per as u32;
            self.rejected = 0;
            self.checks = 0;
            let r = least_rotation(&t[..per]);
            self.next = (i + (r + per - i % per) % per) as u32;
        } else if self.rejected != 0 {
            // A period that appears from here on is longer than PERIOD_MAX: its prefix would
            // hold both it and this one, so it would be a multiple of this one, and the trace
            // would still have this one as its least period.
            return if len >= 2 * PERIOD_MAX {
                Step::Abort
            } else {
                Step::Go
            };
        }
        if i == self.next as usize {
            self.next += per as u32;
            return Step::Check;
        }
        Step::Go
    }

    /// The comparison at a check: `equal`, the state is the last check's (the runtime has no
    /// earlier state to compare at the first two checks of a candidate, `checks` < 2).
    pub fn checked(&mut self, equal: bool) -> Checked {
        if equal {
            return Checked::Found;
        }
        if self.checks > CHECKS {
            self.rejected = 1;
            return Checked::Rejected;
        }
        self.checks += 1;
        Checked::Again
    }
}

impl Default for Trace {
    fn default() -> Trace {
        Trace::new()
    }
}

/// Index of the least rotation of `s` (the two-pointer minimum-expression algorithm).
pub fn least_rotation(s: &[u64]) -> usize {
    let n = s.len();
    let (mut i, mut j, mut k) = (0usize, 1usize, 0usize);
    while i < n && j < n && k < n {
        let (a, b) = (s[(i + k) % n], s[(j + k) % n]);
        if a == b {
            k += 1;
            continue;
        }
        if a > b {
            i += k + 1;
        } else {
            j += k + 1;
        }
        if i == j {
            j += 1;
        }
        k = 0;
    }
    i.min(j)
}

#[cfg(test)]
mod tests;
