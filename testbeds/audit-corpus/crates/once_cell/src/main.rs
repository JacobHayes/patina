use once_cell::sync::Lazy;
static V: Lazy<Vec<u32>> = Lazy::new(|| (0..10u32).collect());
fn main() {
    let s: u32 = V.iter().sum();
    // keep symbols live
    std::hint::black_box(s);
    println!("{}", s);
}
