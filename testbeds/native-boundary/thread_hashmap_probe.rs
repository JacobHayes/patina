// A new thread's first `HashMap` seeds its `RandomState` from the platform's
// entropy API: `CCRandomGenerateBytes` on Darwin, `getrandom(GRND_INSECURE)` on
// Linux. Neither can fail, so the program runs under any entropy fault rate.
use std::collections::HashMap;

fn main() {
    let len = std::thread::spawn(|| {
        let mut map = HashMap::new();
        map.insert(1u32, 2u32);
        map.len()
    })
    .join()
    .unwrap();
    println!("NATIVE_THREAD_HASHMAP len={len}");
}
