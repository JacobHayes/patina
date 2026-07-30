
fn main() {
    let data = b"hello patina hello patina hello patina";
    let c = zstd::encode_all(&data[..], 3).unwrap();
    let d = zstd::decode_all(&c[..]).unwrap();
    println!("{} {}", c.len(), d.len());
}
