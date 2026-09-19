use std::arch::asm;
unsafe fn prctl(option: i64, a2: i64, a3: i64, a4: i64, a5: i64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", inlateout("rax") 157i64 => r, in("rdi") option,
        in("rsi") a2, in("rdx") a3, in("r10") a4, in("r8") a5,
        out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
fn main() {
    const PR_GET_AUXV: i64 = 0x4155_5856;
    const AT_NULL: u64 = 0;
    const AT_RANDOM: u64 = 25;
    const AT_SYSINFO_EHDR: u64 = 33;
    unsafe extern "C" {
        fn getauxval(kind: core::ffi::c_ulong) -> core::ffi::c_ulong;
    }
    let mut buf = [0u8; 4096];
    let ret = unsafe { prctl(PR_GET_AUXV, buf.as_mut_ptr() as i64, buf.len() as i64, 0, 0) };
    assert!(ret > 0, "PR_GET_AUXV returned {ret}");
    let full = ret as usize;
    assert!(full <= buf.len(), "auxv ({full}) larger than probe buffer");
    // Walk the returned copy: 16-byte (a_type: u64, a_val: u64) entries to AT_NULL.
    let mut at_random_ptr: u64 = 0;
    let mut saw_sysinfo = false;
    let mut terminated = false;
    let mut i = 0usize;
    while i + 16 <= full {
        let t = u64::from_ne_bytes(buf[i..i + 8].try_into().unwrap());
        let v = u64::from_ne_bytes(buf[i + 8..i + 16].try_into().unwrap());
        if t == AT_NULL {
            terminated = true;
            break;
        }
        if t == AT_RANDOM {
            at_random_ptr = v;
        }
        if t == AT_SYSINFO_EHDR {
            saw_sysinfo = true;
        }
        i += 16;
    }
    assert!(terminated, "PR_GET_AUXV buffer had no AT_NULL terminator");
    assert!(
        !saw_sysinfo,
        "AT_SYSINFO_EHDR must be scrubbed from the served auxv"
    );
    assert!(at_random_ptr != 0, "AT_RANDOM missing from the served auxv");
    // The AT_RANDOM entry must point at the SAME scrubbed 16 bytes getauxval reads.
    let ga = unsafe { getauxval(AT_RANDOM as core::ffi::c_ulong) } as u64;
    assert!(ga != 0, "getauxval(AT_RANDOM) null");
    // SAFETY: both pointers address the 16 seed-derived AT_RANDOM bytes.
    let via_prctl = unsafe { core::slice::from_raw_parts(at_random_ptr as *const u8, 16) };
    let via_getaux = unsafe { core::slice::from_raw_parts(ga as *const u8, 16) };
    assert_eq!(
        via_prctl, via_getaux,
        "PR_GET_AUXV AT_RANDOM != getauxval(AT_RANDOM)"
    );
    let hex: String = via_prctl.iter().map(|b| format!("{b:02x}")).collect();
    println!("PR_GET_AUXV len={full} random={hex}");
}
