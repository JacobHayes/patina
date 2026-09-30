//! Metadata inside a declared function extent (not an inter-function gap).
//! Natively this returns 42. The instruction audit deliberately refuses the
//! unreachable metadata inside the sized range; it has no reachability proof.

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
std::arch::global_asm!(
    ".pushsection .text.metadata_probe,\"ax\",@progbits",
    ".global metadata_probe",
    ".type metadata_probe,@function",
    "metadata_probe:",
    "mov eax, 42",
    "ret",
    // Keep the bytes inside .size: inter-function metadata now passes, but
    // undecodable bytes inside a declared range must remain a refusal.
    ".byte 0x41,0x42,0x43,0x44,0x45,0",
    ".size metadata_probe, .-metadata_probe",
    ".popsection",
);

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn probe() {
    unsafe extern "C" {
        fn metadata_probe() -> u32;
    }
    assert_eq!(unsafe { metadata_probe() }, 42);
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn executable_metadata_is_not_executed() {
    probe();
}
