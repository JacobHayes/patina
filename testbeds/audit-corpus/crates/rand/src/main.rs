
use rand::Rng;
fn main() { let x: u64 = rand::thread_rng().gen(); println!("{}", x % 100); }
