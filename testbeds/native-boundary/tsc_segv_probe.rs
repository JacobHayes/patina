use std::arch::x86_64::_rdtsc;

fn main() {
    // SAFETY: a counter read, proving the trap is armed in this very process.
    println!("SEGV probe armed_read={}", unsafe { _rdtsc() });
    // Aligned (so std's write_volatile precondition passes) but in the unmapped
    // zero page, so this is a real hardware fault.
    let wild: *mut u64 = 0x1000 as *mut u64;
    // SAFETY: deliberately unsound — the fault is the thing under test.
    unsafe { wild.write_volatile(1) };
    println!("SEGV probe SURVIVED THE FAULT");
}
