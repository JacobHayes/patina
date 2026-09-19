fn main() {
    unsafe extern "C" {
        fn getauxval(kind: core::ffi::c_ulong) -> core::ffi::c_ulong;
    }
    const AT_SYSINFO_EHDR: core::ffi::c_ulong = 33;
    println!("AUXV_SYSINFO_EHDR={}", unsafe {
        getauxval(AT_SYSINFO_EHDR)
    });
}
