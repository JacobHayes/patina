//! Compute points: what the runtime and the launcher agree on for code rebuilt with the
//! compilers' coverage hooks (`sdk/c/patina_compute.c`, ARCHITECTURE.md "Scheduling points").
//!
//! Each hook call (an *event*) decrements one guest word, the cell
//! (`layout::COMPUTE_CELL`), and enters the runtime (`sdk::OP_COMPUTE_POINT`) when it reaches
//! 0. On every return to program code the runtime writes the next segment's gap there; at
//! every runtime entry it reads back how many events ran and charges them to virtual time.
//! A run has one mean gap G (`Config::compute_gap`, drawn per seed); each segment's gap is
//! uniform in `1..=2G-1`.

use crate::draw::{draw, mix64, Stream};

/// The cell's value with counter preemption on: nothing is counted, no point is wanted.
pub const NO_LIMIT: i64 = i64::MAX;
/// The cell's value with switches off (`compute_gap` 0): when it runs out the runtime refills it
/// without consulting the supervisor. Bounded, so that what one runtime entry charges stays
/// bounded however the program writes its cell.
pub const REFILL: i64 = GAP_MAX as i64;

/// `Rec::nr` of a compute point's `Preempt` record (1 is a counter preemption, 2 a spin
/// point): args [rip, the gap that ran out, reason, events of this process so far, 0, 0].
pub const PREEMPT_NR: u32 = 3;
/// Reasons in a compute point's record.
pub const REASON_SWITCH: u64 = 1;
pub const REASON_DEADLINE: u64 = 2;

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
