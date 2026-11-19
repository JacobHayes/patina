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

/// The cell's value with counter preemption on: nothing is counted, no point is wanted.
pub const NO_LIMIT: i64 = i64::MAX;
/// The longest run the cell is armed for, whatever the gap and the deadlines: when it runs out
/// the thread yields (`REASON_REFILL`). So an instrumented spin-wait hands over by itself in
/// every gap setting (a spin probe cannot find one: its cell changes every pass), and what one
/// runtime entry charges stays bounded however the program writes its cell. About 4 ms of
/// virtual time, and a few ms of CPU time: well before the stall watchdog's first probe.
pub const REFILL: u64 = 1 << 22;

/// `Rec::nr` of a compute point's `Preempt` record (1 is a counter preemption, 2 a spin
/// point): args [rip, the value the cell was armed with, reason, events of this process so
/// far, the segment's drawn gap (0: switches off), the instructions a load-time switch walked
/// past its site]; `out_hash` hashes the general registers where it was taken.
pub const PREEMPT_NR: u32 = 3;
/// Reasons in a compute point's record: the drawn gap ran out (a switch), a deadline or the
/// time limit fell due, or the longest run (`REFILL`) ran out.
pub const REASON_SWITCH: u64 = 1;
pub const REASON_DEADLINE: u64 = 2;
pub const REASON_REFILL: u64 = 3;

/// Virtual time one event costs: a model of a machine, the same for every build and host.
pub const CHARGE_NS: u64 = 1;

/// The mean gap's range when the run gives none (`--fault compute-gap`).
pub const GAP_DEFAULT: (u64, u64) = (64, 65_536);
/// The largest mean gap a run may ask for (so `2G - 1` and every count stay far from overflow).
pub const GAP_MAX: u64 = 1 << 40;

/// The run's mean gap from the plan's draw `d`: `lo` when `lo == hi`, else log-uniform in
/// `[lo, hi]` (`lo >= 1`).
pub fn mean_gap(d: u64, lo: u64, hi: u64) -> u64 {
    if lo >= hi {
        lo
    } else {
        crate::pmu::log_uniform(d, lo, hi)
    }
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

/// The longest walk's range when the run gives none (`--fault compute-walk`).
pub const WALK_DEFAULT: (u64, u64) = (4, 512);
/// The longest walk a run may ask for.
pub const WALK_MAX: u64 = 1 << 16;

/// The instructions a switch walks on before it is taken (`--preempt points`), for the
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

#[cfg(test)]
mod tests {
    use super::*;

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
