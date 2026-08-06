// Efficacy fixture for coverage-guided campaign scheduling.
//
// Three gates, each keyed to a DIFFERENT byte of the generation-derivation hash
// (fs-error permille, fs-short permille, sleep-jitter ceiling), arranged as a
// staircase: each stage a guided campaign reaches opens a hostcall kind it has
// never seen, which is exactly the novelty signal `--guided` steers by. Partial
// progress is therefore inheritable — a child that keeps its ancestor's
// fs-error byte and re-rolls the rest starts one step up the stair — which is
// the property mutation-based search exploits and uniform sampling cannot.
use std::io::{Seek, SeekFrom, Write};

const ERROR_GATE: u32 = 40;
// Gate 2 is a RATE over successful writes, not a count: an injected error
// consumes a write that could otherwise have been short, so a raw count would
// make gates 1 and 2 anti-correlated and the staircase unclimbable.
const SHORT_RATE_GATE: u32 = 150;
const JITTER_GATE: u128 = 2_900_000;

fn main() {
    let (errors, short_rate) = fault_pressure();
    let jitter = max_sleep_jitter();
    println!("GATES errors={errors} short_rate={short_rate} jitter={jitter}");

    if errors >= ERROR_GATE {
        stage_one();
        if short_rate >= SHORT_RATE_GATE {
            stage_two();
            if jitter >= JITTER_GATE {
                stage_three();
            }
        }
    }
}

fn fault_pressure() -> (u32, u32) {
    let mut errors = 0;
    let mut shorts = 0;
    let mut writes = 0;
    for index in 0..256u32 {
        match std::fs::File::create(format!("/probe-{index}")) {
            Err(_) => errors += 1,
            Ok(mut file) => match file.write(&[b'x'; 64]) {
                Err(_) => errors += 1,
                Ok(written) => {
                    writes += 1;
                    if written < 64 {
                        shorts += 1;
                    }
                }
            },
        }
    }
    let short_rate = if writes == 0 { 0 } else { shorts * 1000 / writes };
    (errors, short_rate)
}

fn max_sleep_jitter() -> u128 {
    let mut worst = 0;
    for _ in 0..16 {
        let before = now_nanos();
        std::thread::sleep(std::time::Duration::from_millis(1));
        worst = worst.max(now_nanos().saturating_sub(before));
    }
    worst
}

// Each stage reaches for a hostcall kind no other path uses, so reaching it is a
// depth-novelty event the campaign records in its novelty log.
fn stage_one() {
    let _ = std::fs::create_dir("/stage-one");
    println!("STAGE_ONE");
}

fn stage_two() {
    if let Ok(mut file) = std::fs::File::create("/stage-two") {
        let _ = file.write(b"stage-two");
        let _ = file.seek(SeekFrom::Start(2));
    }
    println!("STAGE_TWO");
}

fn stage_three() {
    if let Ok(entries) = std::fs::read_dir("/") {
        println!("STAGE_THREE entries={}", entries.count());
    } else {
        println!("STAGE_THREE entries=0");
    }
}

fn now_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}
