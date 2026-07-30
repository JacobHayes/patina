
use dashmap::DashMap;
fn main() {
    let m = DashMap::new();
    for i in 0..100u32 { m.insert(i, i * 2); }
    println!("{}", *m.get(&50).unwrap());
}
