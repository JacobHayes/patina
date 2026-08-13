//! A buggify-instrumented wasip1 dogfood guest for Patina Wave 11 Milestone C.
//!
//! It exercises every cooperative-SUT site kind the `patina_sdk` wasm import
//! surface carries — `buggify!`, `buggify_with_prob!`, `buggify_delay!`,
//! `buggify_knob!`, `sometimes!`, `reachable!`, `always!`, `rng()`, and the
//! lifecycle markers — so a `cargo patina run --buggify` proves the WASI path has
//! full parity with native. The workload is a pure function of the run seed and
//! the buggify decisions, so record/replay reproduces the printed digest
//! byte-for-byte and distinct seeds diverge it.
//!
//! Modes (first `--arg`):
//!   (none)      normal run; the `always!` invariant holds.
//!   `violate`   plants an `always!` violation so the host reports a
//!               `violation` verdict and traps — the WASI mirror of the native
//!               abort, proving the invariant oracle bites on wasip1.

use std::io::Write;

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();

    // Setup phase: fault-free. With `--buggify-after-setup` the runtime keeps
    // buggify inert until `setup_complete()`, so any site above this line stays
    // unarmed. `reachable!` records that we got here at all.
    patina_dst::reachable!("wasi-fixture-startup");
    patina_dst::lifecycle::setup_complete();
    patina_dst::lifecycle::event!("workload-begin");

    // Workload phase: several site kinds, all seed-deterministic.
    let iterations = patina_dst::buggify_knob!("iteration-count", 8, 4, 16);
    let mut digest: u64 = 0xcbf2_9ce4_8422_2325; // FNV-1a offset basis
    let mut fired_early = 0u64;
    let mut fired_high = 0u64;
    let mut delayed = 0u64;

    for _ in 0..iterations {
        if patina_dst::buggify!("inject-early-return") {
            fired_early += 1;
            digest = mix(digest, 0x11);
        }
        if patina_dst::buggify_with_prob!("inject-high-prob", 0.9) {
            fired_high += 1;
            digest = mix(digest, 0x22);
        }
        if patina_dst::buggify_delay!("delay-commit") {
            delayed += 1;
            digest = mix(digest, 0x33);
        }
        let draw = patina_dst::rng();
        patina_dst::sometimes!(draw % 2 == 0, "rng-draw-even");
        patina_dst::sometimes!(draw % 5 == 0, "rng-draw-mult-five");
        digest = mix(digest, draw);
    }

    // A fatal invariant that normally holds. `violate` mode makes it false to
    // prove ALWAYS_VIOLATION detection fires under wasip1.
    let ok = mode != "violate";
    patina_dst::always!(ok, "workload-completed");

    let mut out = std::io::stdout();
    let _ = writeln!(
        out,
        "WASI_BUGGIFY_DIGEST iterations={iterations} early={fired_early} high={fired_high} \
delayed={delayed} digest={digest:016x}"
    );
}

/// Inline FNV-1a-style mixing so the digest is a pure function of the buggify
/// decisions and the rng stream, with no external dependency.
fn mix(state: u64, value: u64) -> u64 {
    let mut h = state ^ value;
    h = h.wrapping_mul(0x0000_0100_0000_01b3);
    h ^ (h >> 29)
}
