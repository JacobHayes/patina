//! Executable-section metadata, as emitted by native crypto assembly.
//! Natively this returns 42. The linear instruction audit deliberately refuses
//! the unreachable metadata; it has no code/data reachability proof.

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
std::arch::global_asm!(
    ".pushsection .text.metadata_probe,\"ax\",@progbits",
    ".global metadata_probe",
    ".type metadata_probe,@function",
    "metadata_probe:",
    "mov eax, 42",
    "ret",
    ".size metadata_probe, .-metadata_probe",
    // Neutral metadata outside the function but inside the executable section:
    // consecutive REX-prefix bytes make the linear length decoder refuse.
    ".byte 0x41,0x42,0x43,0x44,0x45,0",
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
