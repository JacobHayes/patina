
use mimalloc::MiMalloc;
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;
fn main() {
    let mut v: Vec<Box<u64>> = Vec::new();
    for i in 0..1000u64 { v.push(Box::new(i)); }
    let s: u64 = v.iter().map(|b| **b).sum();
    std::hint::black_box(&v);
    println!("{}", s);
}
