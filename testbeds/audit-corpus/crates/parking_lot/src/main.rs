
use parking_lot::{Mutex, Condvar};
fn main() {
    let m = Mutex::new(0u32);
    let cv = Condvar::new();
    { let mut g = m.lock(); *g += 1; cv.notify_one(); std::hint::black_box(&*g); }
    println!("{}", *m.lock());
}
