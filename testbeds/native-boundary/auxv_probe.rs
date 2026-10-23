// What the kernel hands a process at exec, and a reserved signal's action,
// as the guest sees them: the vDSO's address (AT_SYSINFO_EHDR, scrubbed to 0
// where syscall-user-dispatch traps the guest's raw syscalls), the 16 bytes
// at AT_RANDOM (seeded), and a SIGSYS action the guest installs and reads
// back (virtual on every kernel; class pairing:
// reserved_signals_are_stripped_from_every_host_mask).
unsafe extern "C" {
    fn getauxval(kind: core::ffi::c_ulong) -> core::ffi::c_ulong;
    fn signal(sig: i32, handler: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
}
const AT_RANDOM: core::ffi::c_ulong = 25;
const AT_SYSINFO_EHDR: core::ffi::c_ulong = 33;

extern "C" fn ignore(_: i32) {}

fn main() {
    println!("AUXV_SYSINFO_EHDR={}", unsafe {
        getauxval(AT_SYSINFO_EHDR)
    });
    let p = unsafe { getauxval(AT_RANDOM) } as *const u8;
    assert!(!p.is_null(), "AT_RANDOM pointer is null");
    // SAFETY: the kernel places 16 random bytes at the AT_RANDOM pointer.
    let bytes = unsafe { core::slice::from_raw_parts(p, 16) };
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    println!("AT_RANDOM={hex}");
    unsafe {
        let handler = ignore as *mut core::ffi::c_void;
        assert_eq!(signal(31, handler), core::ptr::null_mut());
        assert_eq!(signal(31, core::ptr::null_mut()), handler);
        assert_eq!(
            signal(31, 1usize as *mut core::ffi::c_void),
            core::ptr::null_mut()
        );
        assert_eq!(signal(31, handler), 1usize as *mut core::ffi::c_void);
    }
    println!("SIGSYS guest action roundtrip");
}
