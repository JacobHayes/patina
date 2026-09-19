fn main() {
    unsafe extern "C" {
        fn getauxval(kind: core::ffi::c_ulong) -> core::ffi::c_ulong;
    }
    const AT_RANDOM: core::ffi::c_ulong = 25;
    let p = unsafe { getauxval(AT_RANDOM) } as *const u8;
    assert!(!p.is_null(), "AT_RANDOM pointer is null");
    // SAFETY: the kernel places 16 random bytes at the AT_RANDOM pointer.
    let bytes = unsafe { core::slice::from_raw_parts(p, 16) };
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    println!("AT_RANDOM={hex}");
}
