// The allocator (`allocator.rs`) with no raw system-call instruction: its
// calls are libc doors only, so it runs on every Linux kernel.
#[path = "../allocator.rs"]
mod allocator;

/// No raw `getcpu`: the binary has no direct-syscall site.
fn raw_cpu() -> Option<i64> {
    None
}

fn main() {
    allocator::main();
}
