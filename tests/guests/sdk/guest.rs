//! The SDK test guest in Rust: the script of guest.c (modes script [two], fail, unreach, coin,
//! loop).
use std::io::Read;

fn script(two: bool, argc: usize) {
    patina_dst::reachable!("script-start");
    if argc > 1000 {
        patina_dst::sometimes!(true, "unreached");
    }
    for i in 0..1000 {
        patina_dst::always!(i < 1000, "bounded", "out of range");
        patina_dst::sometimes!(i == 500, "half-way");
        patina_dst::sometimes!(i > 5000, "never-holds");
    }
    let mut bits = String::new();
    for _ in 0..20 {
        bits.push(if patina_dst::buggify!("point-a") { '1' } else { '0' });
        if two {
            let _ = patina_dst::buggify!("point-b");
        }
    }
    let knob = patina_dst::buggify_knob!("knob-a", 7, 1, 100);
    let slept = patina_dst::buggify_delay!("delay-a", std::time::Duration::from_millis(1));
    println!("a={bits} knob={knob} delay={}", slept as u8);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str).unwrap_or("script") {
        "script" => script(args.get(2).is_some_and(|a| a == "two"), args.len()),
        "fail" => {
            patina_dst::reachable!("before-fail");
            let balance = -1;
            patina_dst::always!(balance >= 0, "must-hold", "balance {balance}");
            patina_dst::reachable!("after-fail");
        }
        "unreach" => patina_dst::unreachable!("never-here", "reached"),
        "coin" => {
            let mut b = [0u8; 1];
            std::fs::File::open("/dev/urandom").unwrap().read_exact(&mut b).unwrap();
            patina_dst::sometimes!(b[0] % 2 == 0, "coin");
        }
        "loop" => {
            let n: u64 = args.get(2).and_then(|a| a.parse().ok()).unwrap_or(10_000_000);
            let sdk = args.get(3).is_some_and(|a| a == "sdk");
            let mut acc = 0u64;
            for i in 0..n {
                acc = std::hint::black_box(acc.wrapping_mul(31).wrapping_add(i));
                if sdk {
                    patina_dst::always!(acc != u64::MAX, "loop-bounded", "saturated");
                }
            }
            println!("{acc}");
        }
        m => {
            eprintln!("unknown mode {m}");
            std::process::exit(2);
        }
    }
}
