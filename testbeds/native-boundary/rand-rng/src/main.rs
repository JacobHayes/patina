use rand::RngCore;

fn main() {
    let mut rng = rand::rng();
    let first = rng.next_u64();
    let mut bytes = [0u8; 24];
    rng.fill_bytes(&mut bytes);
    print!("NATIVE_RAND_RNG first={first:016x} bytes=");
    for byte in bytes {
        print!("{byte:02x}");
    }
    println!();
}
