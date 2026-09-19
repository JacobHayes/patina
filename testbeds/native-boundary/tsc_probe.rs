use std::arch::x86_64::{__rdtscp, _rdtsc};

fn main() {
    let mut aux: u32 = 0xdead_beef;
    for step in 0..3 {
        // SAFETY: unprivileged counter reads; under patina both trap into the
        // deterministic runtime rather than reading the host counter.
        let plain = unsafe { _rdtsc() };
        let with_aux = unsafe { __rdtscp(&mut aux) };
        println!("TSC step={step} rdtsc={plain} rdtscp={with_aux} aux={aux}");
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    println!("TSC total_ticks={}", unsafe { _rdtsc() });
}
