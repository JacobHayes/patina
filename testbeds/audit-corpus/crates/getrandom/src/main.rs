
fn main() { let mut b = [0u8; 16]; getrandom::getrandom(&mut b).unwrap(); println!("{}", b[0]); }
