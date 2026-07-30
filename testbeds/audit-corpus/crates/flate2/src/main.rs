
use flate2::{write::GzEncoder, Compression};
use std::io::Write;
fn main() {
    let mut e = GzEncoder::new(Vec::new(), Compression::default());
    e.write_all(b"hello patina hello patina hello patina").unwrap();
    let out = e.finish().unwrap();
    println!("{}", out.len());
}
