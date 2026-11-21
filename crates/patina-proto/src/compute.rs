//! Compute points: what the runtime and the launcher agree on for code rebuilt with the
//! compilers' coverage hooks (`sdk/c/patina_compute.c`, ARCHITECTURE.md "Scheduling points").
//!
//! Each hook call (an *event*) decrements one guest word, the cell
//! (`layout::COMPUTE_CELL`), and enters the runtime (`sdk::OP_COMPUTE_POINT`) when it reaches
//! 0. On every return to program code the runtime writes the next segment's gap there; at
//! every runtime entry it reads back how many events ran and charges them to virtual time.
//! A run has one mean gap G (`Config::compute_gap`, drawn per seed); each segment's gap is
//! uniform in `1..=2G-1`, cut short at the next deadline (`arm`).

use crate::draw::{draw, mix64, Stream};

/// The longest run the cell is armed for, whatever the gap and the deadlines: when it runs out
/// the thread yields (`REASON_REFILL`). So an instrumented spin-wait hands over by itself in
/// every gap setting (a spin probe cannot find one: its cell changes every pass), and what one
/// runtime entry charges stays bounded however the program writes its cell. About 4 ms of
/// virtual time, and a few ms of CPU time: well before the stall watchdog's first probe.
pub const REFILL: u64 = 1 << 22;

/// `Rec::nr` of a compute point's `Preempt` record (2 is a spin point; 1 is unused): args
/// [rip, the value the cell was armed with, reason, events of this process so far, the
/// segment's drawn gap (0: switches off), the instructions a load-time switch walked
/// past its site]; `out_hash` hashes the general registers where it was taken.
pub const PREEMPT_NR: u32 = 3;
/// Reasons in a compute point's record: the drawn gap ran out (a switch), a deadline or the
/// time limit fell due, or the longest run (`REFILL`) ran out.
pub const REASON_SWITCH: u64 = 1;
pub const REASON_DEADLINE: u64 = 2;
pub const REASON_REFILL: u64 = 3;

/// Virtual time one event costs: a model of a machine, the same for every build and host.
pub const CHARGE_NS: u64 = 1;

/// The mean gap's ranges when the run gives none (`--fault compute-gap`): half the seeds draw
/// from the small range (the windows of short programs need a switch every few events), the
/// other half from the large (long programs, at their natural pace); each log-uniformly
/// (`default_gap`). A long program at a small gap is held to its switch budget (`budget`).
pub const GAP_SMALL: (u64, u64) = (1, 16);
pub const GAP_LARGE: (u64, u64) = (16, 65_536);
/// The largest mean gap a run may ask for (so `2G - 1` and every count stay far from overflow).
pub const GAP_MAX: u64 = 1 << 40;

/// The run's mean gap from the plan's draw `d`: `lo` when `lo == hi`, else log-uniform in
/// `[lo, hi]` (`lo >= 1`).
pub fn mean_gap(d: u64, lo: u64, hi: u64) -> u64 {
    if lo >= hi {
        lo
    } else {
        crate::draw::log_uniform(d, lo, hi)
    }
}

/// The run's mean gap when the run gives none, from the plan's draw `d` of `compute-gap`: the
/// draw's top bit picks the range (`GAP_SMALL` or `GAP_LARGE`), its low bits the gap in it, as
/// `mean_gap` does for a range given.
pub fn default_gap(d: u64) -> u64 {
    let (lo, hi) = if d >> 63 == 1 { GAP_SMALL } else { GAP_LARGE };
    mean_gap(d, lo, hi)
}

/// The draw key of a segment: the run's sequence number at its start, the thread's slot, and
/// the thread's segment count (two segments of one thread may start at the same `seq`).
pub fn key(seq: u64, slot: u32, segs: u64) -> u64 {
    mix64(seq.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ ((slot as u64) << 48))
        ^ segs.wrapping_mul(0xd6e8_feb8_6659_fd93)
}

/// The gap of the segment keyed by `key`: uniform in `1..=2G-1` for mean gap `G`; `None` when
/// switches are off (`G = 0`). Integer arithmetic only.
pub fn gap(seed: u64, mean: u64, key: u64) -> Option<u64> {
    if mean == 0 {
        return None;
    }
    let m = mean.min(GAP_MAX);
    Some(1 + draw(seed, Stream::Compute, key) % (2 * m - 1))
}

/// Under load-time points with the gap drawn by default (`Config::compute_budget`), in a process
/// whose rebuilt code has not said hello, the switch points a run takes at its drawn mean gap:
/// `ALLOWANCE`, and one more per `EVENTS_PER_SWITCH` events charged. Past that its segments
/// draw their gaps with a mean of at least `EVENTS_PER_SWITCH` until it is back within
/// (`budget`).
pub const ALLOWANCE: u64 = 1 << 11;
pub const EVENTS_PER_SWITCH: u64 = 1 << 13;

/// The mean gap of a segment armed when the run has taken `switches` switch points (a gap or the
/// longest run ran out) and charged `events` events: the run's `mean`, raised to
/// `EVENTS_PER_SWITCH` while the switches are past their allowance. So a program that computes
/// long at a small mean gap takes about `ALLOWANCE` switches at it and then one per
/// `EVENTS_PER_SWITCH` events, still at places drawn uniformly, and a seed costs a bounded
/// multiple of its program's own work whatever its gap; a short program (a test of a race) seldom
/// reaches the allowance.
pub fn budget(mean: u64, switches: u64, events: u64) -> u64 {
    if mean == 0 || switches < ALLOWANCE.saturating_add(events / EVENTS_PER_SWITCH) {
        mean
    } else {
        mean.max(EVENTS_PER_SWITCH)
    }
}

/// The longest walk's range when the run gives none (`PATINA_TEST_COMPUTE_WALK`).
pub const WALK_DEFAULT: (u64, u64) = (2, 64);
/// The longest walk a run may ask for.
pub const WALK_MAX: u64 = 1 << 16;

/// The instructions a switch walks on before it is taken (load-time points), for the
/// switch keyed by `key`, `max` the run's longest walk: 2 switches in `max` (half of them when
/// `max` is below 4) walk uniformly `1..=max`, the rest none. So a run steps about one
/// instruction per switch whatever `max` is: the walk's cost is the switches', not its reach.
pub fn walk(seed: u64, max: u64, key: u64) -> u64 {
    let m = max.min(WALK_MAX);
    if m == 0 {
        return 0;
    }
    let d = draw(seed, Stream::Walk, key);
    match d % m.max(4) {
        0 | 1 => 1 + (d >> 32) % m,
        _ => 0,
    }
}

/// What the cell is armed with on a return to program code, and why it will run out: the
/// smallest of the drawn gap (`None`: switches off), the events until `due_ns` (the earliest
/// of the next deadline and the first time past the time limit; rounded up, at least 1, so the
/// point comes at the first event at or after it, never before), and `REFILL`. A deadline wins
/// a tie, then the gap.
pub fn arm(gap: Option<u64>, now_ns: u64, due_ns: u64, charge_ns: u64) -> (u64, u64) {
    let charge = charge_ns.max(1);
    let due = due_ns.saturating_sub(now_ns).div_ceil(charge).max(1);
    let gap = gap.unwrap_or(u64::MAX);
    if due <= gap.min(REFILL) {
        (due, REASON_DEADLINE)
    } else if gap <= REFILL {
        (gap, REASON_SWITCH)
    } else {
        (REFILL, REASON_REFILL)
    }
}

/// A segment armed ahead (`chain`): the cell's value, why it runs out (`REASON_*`), the last
/// gap drawn (0: none), how many gaps were drawn, and how many of them were points that stayed
/// with their thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Chain {
    pub armed: u64,
    pub reason: u64,
    pub draw: u64,
    pub gaps: u64,
    pub stays: u64,
}

/// Whether the switch point keyed by `key` stays with its thread when `runnable` threads (it
/// included) could run: one chance in `runnable`, as the supervisor's pick among all of them.
pub fn stays(seed: u64, key: u64, runnable: u64) -> bool {
    draw(seed, Stream::Stay, key).is_multiple_of(runnable.max(1))
}

/// What a segment is armed with under load-time points when the runtime knows how many threads
/// are runnable (`runnable`, the arming thread included; 0: not known), `key(k)` keying its
/// `k`-th gap. Not known: `arm` of one drawn gap, as for rebuilt code. Alone (1): no switch
/// point, only the next deadline or `REFILL`. Otherwise the points are drawn ahead: each gap
/// in turn (`gap`), and at its end a point that stays with the thread (`stays`) or switches; the
/// cell is armed with the sum of the gaps up to the first that switches, cut at the deadline
/// and at `REFILL` by `arm`'s rules (a tie goes to the deadline, then the gap). A point that
/// stays changes nothing the program or the supervisor sees, so it is not taken: no trap, no
/// record. The sum of the events is charged as before, at the trap that ends the segment.
pub fn chain(
    seed: u64,
    mean: u64,
    key: impl Fn(u64) -> u64,
    runnable: u64,
    now_ns: u64,
    due_ns: u64,
    charge_ns: u64,
) -> Chain {
    let one = |armed, reason, draw| Chain {
        armed,
        reason,
        draw,
        gaps: 1,
        stays: 0,
    };
    if runnable == 0 {
        let g = gap(seed, mean, key(0));
        let (armed, reason) = arm(g, now_ns, due_ns, charge_ns);
        return one(armed, reason, g.unwrap_or(0));
    }
    let (cap, cap_reason) = arm(None, now_ns, due_ns, charge_ns);
    if runnable == 1 || mean == 0 {
        return one(cap, cap_reason, 0);
    }
    let due = if cap_reason == REASON_DEADLINE {
        cap
    } else {
        u64::MAX
    };
    let mut total = 0u64;
    let mut k = 0;
    loop {
        let g = gap(seed, mean, key(k)).unwrap_or(u64::MAX);
        k += 1;
        let at = total.saturating_add(g);
        let mut c = Chain {
            armed: 0,
            reason: 0,
            draw: g,
            gaps: k,
            stays: k - 1,
        };
        (c.armed, c.reason) = if due <= at.min(REFILL) {
            (due, REASON_DEADLINE)
        } else if at <= REFILL {
            if stays(seed, key(k - 1), runnable) {
                total = at;
                continue;
            }
            (at, REASON_SWITCH)
        } else {
            (REFILL, REASON_REFILL)
        };
        return c;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_gap_draws_from_both_ranges() {
        let (mut small, mut large) = (0, 0);
        for k in 0..2000u64 {
            let d = mix64(k);
            let g = default_gap(d);
            assert_eq!(g, default_gap(d));
            let (lo, hi) = if d >> 63 == 1 { GAP_SMALL } else { GAP_LARGE };
            assert!((lo..=hi).contains(&g), "{g} outside {lo}..{hi}");
            if g < GAP_SMALL.1 {
                small += 1;
            } else if g > GAP_SMALL.1 {
                large += 1;
            }
        }
        assert!(small > 0 && large > 0, "{small} small, {large} large");
    }

    #[test]
    fn gaps_lie_in_range_repeat_and_average_to_the_mean() {
        for mean in [1u64, 8, 64, 1000, 65_536] {
            let mut sum = 0u128;
            let n = 4000u64;
            for k in 0..n {
                let g = gap(7, mean, key(k, (k % 5) as u32, k / 3)).unwrap();
                assert!((1..=2 * mean - 1).contains(&g), "mean {mean}: {g}");
                assert_eq!(Some(g), gap(7, mean, key(k, (k % 5) as u32, k / 3)));
                sum += g as u128;
            }
            let avg = (sum / n as u128) as u64;
            assert!(
                avg * 2 >= mean && avg <= mean * 2,
                "mean {mean}: average {avg}"
            );
        }
        assert_eq!(gap(7, 0, 1), None);
    }

    #[test]
    fn the_cell_runs_out_at_the_first_event_at_or_after_the_deadline() {
        for charge in [1u64, 3, 1000] {
            for (now, due) in [(0u64, 1u64), (100, 100), (100, 50), (7, 7 + 5 * charge + 1)] {
                let (n, why) = arm(None, now, due, charge);
                assert_eq!(why, REASON_DEADLINE);
                assert!(
                    n >= 1 && now + n * charge >= due,
                    "{now} {due} {charge}: {n}"
                );
                assert!(
                    n == 1 || now + (n - 1) * charge < due,
                    "{now} {due} {charge}: {n}"
                );
            }
        }
        // The earliest of the three; a tie goes to the deadline.
        assert_eq!(arm(Some(10), 0, 10, 1), (10, REASON_DEADLINE));
        assert_eq!(arm(Some(9), 0, 10, 1), (9, REASON_SWITCH));
        assert_eq!(
            arm(Some(REFILL + 1), 0, u64::MAX, 1),
            (REFILL, REASON_REFILL)
        );
        assert_eq!(arm(None, 0, u64::MAX, 1), (REFILL, REASON_REFILL));
        assert_eq!(arm(Some(REFILL), 0, u64::MAX, 1), (REFILL, REASON_SWITCH));
    }

    #[test]
    fn a_chain_arms_up_to_the_first_point_that_switches() {
        let key = |k: u64| key(5, 1, 10 + k);
        // Not known: one gap, as `arm`.
        for mean in [0u64, 1, 64, 1 << 30] {
            let g = gap(9, mean, key(0));
            let (armed, reason) = arm(g, 100, 100 + 5000, 1);
            assert_eq!(
                chain(9, mean, key, 0, 100, 100 + 5000, 1),
                Chain {
                    armed,
                    reason,
                    draw: g.unwrap_or(0),
                    gaps: 1,
                    stays: 0
                }
            );
        }
        // Alone, or switches off: the deadline or the longest run.
        assert_eq!(chain(9, 64, key, 1, 0, 700, 1).armed, 700);
        assert_eq!(chain(9, 64, key, 1, 0, 700, 1).reason, REASON_DEADLINE);
        assert_eq!(chain(9, 0, key, 3, 0, u64::MAX, 1).reason, REASON_REFILL);
        // Several runnable: the sum of the gaps up to the first switch, whose decision is
        // `stays`; every point before it stayed.
        let mut seen = [0u64; 2];
        for seed in 0..400u64 {
            for n in [2u64, 3, 7] {
                let c = chain(seed, 64, key, n, 0, u64::MAX, 1);
                let g = |k| gap(seed, 64, key(k)).unwrap();
                assert_eq!(c.reason, REASON_SWITCH);
                assert_eq!(c.armed, (0..c.gaps).map(g).sum::<u64>());
                assert_eq!(c.draw, g(c.gaps - 1));
                assert_eq!(c.stays, c.gaps - 1);
                assert!((0..c.gaps - 1).all(|k| stays(seed, key(k), n)));
                assert!(!stays(seed, key(c.gaps - 1), n));
                seen[(c.stays > 0) as usize] += 1;
            }
        }
        // About one point in `n` stays.
        assert!(seen[1] > 200 && seen[0] > 400, "{seen:?}");
        // A deadline inside the chain cuts it there, a tie included.
        for seed in 0..200u64 {
            let c = chain(seed, 64, key, 2, 0, u64::MAX, 1);
            let cut = chain(seed, 64, key, 2, 0, c.armed, 1);
            assert_eq!((cut.armed, cut.reason), (c.armed, REASON_DEADLINE));
            let past = chain(seed, 64, key, 2, 0, c.armed + 1, 1);
            assert_eq!((past.armed, past.reason), (c.armed, REASON_SWITCH));
        }
        // Gaps past the longest run: `REFILL`.
        let big = chain(9, 1 << 40, key, 2, 0, u64::MAX, 1);
        assert_eq!((big.armed, big.reason), (REFILL, REASON_REFILL));
    }

    #[test]
    fn past_the_allowance_the_mean_gap_is_raised() {
        assert_eq!(budget(64, 0, 0), 64);
        assert_eq!(budget(64, ALLOWANCE - 1, 0), 64);
        assert_eq!(budget(64, ALLOWANCE, 0), EVENTS_PER_SWITCH);
        assert_eq!(budget(64, ALLOWANCE, EVENTS_PER_SWITCH), 64);
        assert_eq!(budget(1 << 20, ALLOWANCE, 0), 1 << 20);
        assert_eq!(budget(0, u64::MAX, 0), 0);
    }

    #[test]
    fn the_mean_is_drawn_in_its_range() {
        let mut seen = [false; 2];
        for d in 0..2000u64 {
            let g = mean_gap(crate::draw::mix64(d), 64, 65_536);
            assert!((64..=65_536).contains(&g), "{g}");
            seen[(g < 1024) as usize] = true;
        }
        assert!(seen[0] && seen[1]);
        assert_eq!(mean_gap(123, 8, 8), 8);
    }
}
