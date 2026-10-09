use std::arch::x86_64::{__rdtscp, _rdtsc};

unsafe extern "C" {
    fn clock_gettime(clock: i32, time: *mut [i64; 2]) -> i32;
}

/// The monotonic clock, read through libc: the counter reads lie between
/// the readings around them.
fn monotonic() -> u64 {
    let mut time = [0i64; 2];
    // SAFETY: `time` is local storage.
    assert_eq!(unsafe { clock_gettime(1, &mut time) }, 0);
    time[0] as u64 * 1_000_000_000 + time[1] as u64
}

fn main() {
    let mut start = 0;
    let mut aux: u32 = 0xdead_beef;
    for step in 0..3 {
        let before = monotonic();
        // SAFETY: unprivileged counter reads; under patina both trap into the
        // deterministic runtime rather than reading the host counter.
        let plain = unsafe { _rdtsc() };
        if step == 0 { start = plain; }
        let with_aux = unsafe { __rdtscp(&mut aux) };
        let after = monotonic();
        println!(
            "TSC step={step} before={before} rdtsc={plain} rdtscp={with_aux} after={after} \
aux={aux}"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    println!("TSC total_ticks={}", unsafe { _rdtsc() } - start);
}
