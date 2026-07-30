
use sha2::{Sha256, Digest};
fn main() {
    let mut h = Sha256::new();
    h.update(b"hello patina");
    let out = h.finalize();
    println!("{:x}", out[0]);
}
