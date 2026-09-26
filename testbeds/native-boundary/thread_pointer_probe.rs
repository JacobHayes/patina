//! A guest that carries its own thread-pointer writes. The pre-run audit must
//! refuse it before it runs: the shim linked into it resolves its own
//! thread-locals through that pointer.

fn main() {
    // Never taken (and never reached: the audit refuses the binary first), but
    // the compiler cannot prove it, so the writes stay in the image.
    if std::env::args_os().count() > 64 {
        // SAFETY: not executed.
        unsafe { move_thread_pointer() };
    }
    println!("THREAD_POINTER_PROBE_RAN");
}

/// `wrfsbase rax` and `mov fs, eax`, as bytes so no target feature is needed.
#[cfg(target_arch = "x86_64")]
unsafe fn move_thread_pointer() {
    unsafe {
        std::arch::asm!(
            ".byte 0xf3, 0x48, 0x0f, 0xae, 0xd0",
            ".byte 0x8e, 0xe0",
            in("rax") 0u64,
        );
    }
}

/// `msr tpidr_el0, x0`, as a raw word so any assembler accepts it.
#[cfg(target_arch = "aarch64")]
unsafe fn move_thread_pointer() {
    unsafe { std::arch::asm!(".inst 0xd51bd040", in("x0") 0u64) };
}
