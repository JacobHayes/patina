use std::arch::x86_64::_rdrand64_step;

fn main() {
    let mut value: u64 = 0;
    // SAFETY: an unprivileged hardware entropy read.
    println!("RDRAND ok={} value={value}", unsafe {
        _rdrand64_step(&mut value)
    });
}
