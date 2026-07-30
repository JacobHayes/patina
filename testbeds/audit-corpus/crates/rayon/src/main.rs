
use rayon::prelude::*;
fn main() {
    let s: u64 = (0..100_000u64).into_par_iter().map(|x| x % 7).sum();
    println!("{}", s);
}
