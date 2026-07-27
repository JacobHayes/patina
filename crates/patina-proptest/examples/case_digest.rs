//! Runs a proptest property under Patina and prints a digest of every generated
//! case. Under `cargo patina native-run` the digest is a pure function of the run
//! `--seed`: the same seed prints the same digest, a different seed prints a
//! different one, and a recorded run replays to the same digest. Under a plain
//! `cargo run --example case_digest` it still runs (OS-entropy fallback).

use std::cell::Cell;

use patina_proptest::prelude::*;

// A passing property: with no failure proptest never shrinks, so the closure is
// invoked exactly `cases` times with freshly generated inputs. Folding those
// inputs yields a digest that depends only on the runner's seed.
fn case_digest() -> u64 {
    let mut runner = patina_proptest::runner();
    let digest = Cell::new(0xcbf2_9ce4_8422_2325_u64);
    let cases = Cell::new(0u64);
    runner
        .run(&(any::<u64>(), 0i64..1_000_000i64), |(a, b)| {
            let mixed = a ^ (b as u64).rotate_left(21);
            digest.set(
                (digest.get() ^ mixed)
                    .wrapping_mul(0x0000_0100_0000_01b3)
                    .rotate_left(13),
            );
            cases.set(cases.get() + 1);
            Ok(())
        })
        .expect("the property holds for every generated case");
    // Fold the case count in too, so a run that generated a different number of
    // cases can never collide with this digest.
    digest.get() ^ cases.get().rotate_left(7)
}

fn main() {
    println!("PROPTEST_DIGEST digest={:016x}", case_digest());
}
