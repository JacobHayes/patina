use std::fs::File;
use std::io::Read;

fn main() {
    let mut file = File::open("/dev/urandom").expect("open deterministic urandom");
    let mut bytes = [0u8; 24];
    file.read_exact(&mut bytes)
        .expect("read deterministic urandom");
    print!("NATIVE_URANDOM bytes=");
    for byte in bytes {
        print!("{byte:02x}");
    }
    println!();
}
