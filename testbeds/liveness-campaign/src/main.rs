//! Planted-bug guest for the Patina wave-13 liveness watchdog + `cargo patina
//! campaign` end-to-end coverage.
//!
//! The bug is a classic *liveness* bug — "never converges" — gated by a buggify
//! site so it fires on only some generations of a campaign:
//!
//!   * The setup + workload phase does a small, seed-deterministic amount of pure
//!     compute (no virtual-time advance), so a HEALTHY run advances the virtual
//!     clock by zero and completes promptly.
//!   * When `buggify!("liveness-wedge")` fires, the node fails to make any further
//!     progress and spins on retry timers forever: an unbounded loop of virtual-
//!     time sleeps with no genuine effect. The liveness watchdog observes virtual
//!     time marching on with no progress and reports a deterministic
//!     `PATINA_LIVENESS` violation instead of the run advancing virtual time to a
//!     silent budget. The loop is capped at a huge iteration count purely as a
//!     test safety net; the watchdog fires long before it is reached.
//!
//! Because every decision is a pure function of the run seed and the buggify
//! configuration, a campaign re-run reproduces the exact per-generation outcomes,
//! and the wedge produces one deduplicated `LIVENESS` signature across every
//! generation that fires it.
//!
//! A plain `cargo build` of this source (no `cfg(patina)`/`cfg(patina_shim)`)
//! leaves every SDK macro a no-op, so the guest compiles and runs normally outside
//! Patina — `buggify!` returns `false`, the wedge never triggers, and it converges.

use std::time::Duration;

fn main() {
    // Setup boundary. With `--buggify-after-setup` the runtime keeps buggify inert
    // until this call; without it, this is just a coverage marker.
    patina::lifecycle::setup_complete();

    // Workload phase: pure, seed-deterministic compute. No virtual-time advance, so
    // a healthy run never approaches the watchdog's no-progress budget.
    let iterations = patina::buggify_knob!("work-iterations", 4, 2, 8);
    let mut digest: u64 = 0xcbf2_9ce4_8422_2325;
    for i in 0..iterations {
        digest = digest
            .wrapping_mul(0x0000_0100_0000_01b3)
            .wrapping_add(patina::rng());
        patina::sometimes!(digest % 2 == 0, "digest-even");
        patina::reachable!("workload-step");
        println!("GUEST_STEP i={i} digest={digest:016x}");
    }

    // The planted liveness bug. When buggify activates and fires this site, the
    // guest can no longer make progress and spins on retry timers indefinitely.
    if patina::buggify!("liveness-wedge") {
        eprintln!("GUEST_WEDGE planted liveness bug: node never converges (retry-timer churn)");
        for _ in 0..1_000_000u64 {
            // Each sleep advances virtual time with no genuine effect — the exact
            // shape the liveness watchdog is designed to catch.
            std::thread::sleep(Duration::from_secs(3600));
        }
    }

    // Healthy path: the guest converged.
    println!("GUEST_CONVERGED digest={digest:016x}");
}
