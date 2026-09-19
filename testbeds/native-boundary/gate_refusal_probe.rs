// A genuinely-uninterposed escape: `shm_open` (shared-memory-ipc class) is a
// truly cross-process primitive the shim never interposes, so the pre-run gate
// must REFUSE to run this binary — keeping the refusal path covered now that
// os_unfair_lock is interposed and accepted. The call must be unconditional (a
// dead branch is stripped and would drop the import), so it uses harmless args:
// O_RDONLY on a nonexistent name returns ENOENT with no host effect, so even the
// --allow-unsupported-symbols hatch run stays clean.
use std::ffi::c_char;
unsafe extern "C" {
    fn shm_open(name: *const c_char, oflag: i32, mode: u32) -> i32;
}
fn main() {
    let name = c"/patina-nonexistent-probe";
    let r = unsafe { shm_open(name.as_ptr(), 0, 0) };
    std::hint::black_box(r);
    println!("GATE_REFUSAL_RAN");
}
