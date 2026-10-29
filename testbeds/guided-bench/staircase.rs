// A planted nested-condition bug for the guided-campaign benchmark
// (scripts/guided-bench.py).
//
// Three gates, nested, each on a different campaign fault knob: the fs error
// rate, the fs short-write rate, and the sleep jitter ceiling. The bug sits
// behind all three. Under a uniform sweep each gate opens in a minority of
// generations, so the bug needs a rare draw of all three at once. Coverage
// gives a guided campaign a path up: each gate reached runs a stage function
// no other path runs (new edges), and the per-fault handlers run once per
// injected fault, so a higher rate reaches a higher hit-count bucket on an
// already covered edge (a new feature) before the gate itself opens.
use std::io::Write;

// Gate thresholds on rates the guest observes, in permille.
const ERROR_GATE: u32 = 75;
const SHORT_GATE: u32 = 155;
// Gate on the largest observed oversleep of a 1 ms sleep, in nanoseconds.
const JITTER_GATE: u128 = 2_050_000;

fn main() {
    let (error_rate, short_rate) = fs_pressure();
    let jitter = max_oversleep();
    println!("GATES error_rate={error_rate} short_rate={short_rate} jitter={jitter}");
    if error_rate >= ERROR_GATE {
        stage_one();
        if short_rate >= SHORT_GATE {
            stage_two();
            if jitter >= JITTER_GATE {
                stage_three();
            }
        }
    }
}

#[inline(never)]
fn on_error() {
    std::hint::black_box(());
}

#[inline(never)]
fn on_short() {
    std::hint::black_box(());
}

/// The observed fs error rate over every operation, and the short-write rate
/// over successful writes (a rate rather than a count, so errors consuming
/// writes do not make the two gates anti-correlated).
fn fs_pressure() -> (u32, u32) {
    let (mut ops, mut errors, mut writes, mut shorts) = (0u32, 0u32, 0u32, 0u32);
    for index in 0..256u32 {
        ops += 1;
        match std::fs::File::create(format!("/probe-{index}")) {
            Err(_) => {
                errors += 1;
                on_error();
            }
            Ok(mut file) => {
                ops += 1;
                match file.write(&[b'x'; 64]) {
                    Err(_) => {
                        errors += 1;
                        on_error();
                    }
                    Ok(written) => {
                        writes += 1;
                        if written < 64 {
                            shorts += 1;
                            on_short();
                        }
                    }
                }
            }
        }
    }
    let short_rate = if writes == 0 { 0 } else { shorts * 1000 / writes };
    (errors * 1000 / ops, short_rate)
}

fn max_oversleep() -> u128 {
    let mut worst = 0;
    for _ in 0..16 {
        let before = std::time::Instant::now();
        std::thread::sleep(std::time::Duration::from_millis(1));
        worst = worst.max(before.elapsed().as_nanos().saturating_sub(1_000_000));
    }
    worst
}

#[inline(never)]
fn stage_one() {
    let _ = std::fs::create_dir("/stage-one");
    println!("STAGE_ONE");
}

#[inline(never)]
fn stage_two() {
    if let Ok(mut file) = std::fs::File::create("/stage-two") {
        let _ = file.write(b"stage-two");
    }
    println!("STAGE_TWO");
}

#[inline(never)]
fn stage_three() {
    println!("STAGE_THREE");
    panic!("planted bug: all three gates open");
}
