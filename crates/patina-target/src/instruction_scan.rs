//! Native instruction-class scanning and architecture coverage.

use crate::import_policy::NativeFormat;
use crate::provenance::NativeProvenanceIndex;
use crate::{NativeEscape, TargetError, code_ranges, x86_scan};
use object::{Architecture, Object, ObjectSection, SectionKind};
use std::collections::BTreeSet;

/// The escape category of a *host-identity* instruction finding: an inline read
/// of the host CPU's own identity (x86-64 `cpuid`), or of its protection-key
/// rights register (`rdpkru`/`wrpkru`), which contradicts the virtual CPU's
/// declared lack of keys on a host that has them.
///
/// It is the one instruction category that INFORMS rather than refuses. Every
/// other category the scan emits is a containment failure; this one is a
/// portability caveat. The distinction is load-bearing in two places — the audit
/// keeps these findings out of the denied set ([`NativeAudit::audit`]), and the
/// report prints them under their own heading ([`render_host_identity_note`]) —
/// so both read this constant rather than matching the string.
///
/// Why visible and not refused: `cpuid` is near-universal in real binaries (libc
/// ifunc resolvers pick a `memcpy` from feature bits, `std`'s
/// `is_x86_feature_detected!` compiles to it, fast-clock crates select a TSC path
/// from the invariant-TSC bit), so refusing it would refuse essentially every
/// x86-64 guest. Trapping it is possible but narrow — Linux
/// `arch_prctl(ARCH_SET_CPUID, 0)` faults CPUID only on capable Intel parts — and
/// is a deferred slice. Until then the honest position is neither "refused" nor
/// "silent" but "reported": the run stays deterministic on a given host, and the
/// note says plainly what is not guaranteed across hosts.
pub const HOST_IDENTITY_CATEGORY: &str = "host-identity";

/// Whether a native finding is a host-identity read ([`HOST_IDENTITY_CATEGORY`])
/// — informational, never part of the refusal set.
pub fn native_escape_is_host_identity(escape: &NativeEscape) -> bool {
    escape.category == HOST_IDENTITY_CATEGORY
}

/// The host-identity instruction sites in a native binary: every inline `cpuid`
/// the scan decodes at a real instruction boundary, with provenance.
///
/// This is a standalone scan (like [`native_deny_trap_armed`]) rather than a
/// field on [`NativeAudit`] because the sites must be reported on EVERY audit
/// outcome — clean, trap-managed, and refused — and a refusing audit returns an
/// error, not an audit. One entry point keeps the three report paths from
/// drifting.
///
/// Fails closed on a parse error, an unsupported format, or an architecture the
/// instruction scan cannot decode: a binary that cannot be scanned must never be
/// reported as carrying no host-identity reads.
pub fn native_host_identity_sites(bytes: &[u8]) -> Result<Vec<NativeEscape>, TargetError> {
    let file = object::File::parse(bytes).map_err(TargetError::NativeParse)?;
    NativeFormat::from_binary(file.format())?;
    let provenance = NativeProvenanceIndex::new(&file);
    Ok(scan_instruction_classes(&file, &provenance)?
        .into_iter()
        .filter(native_escape_is_host_identity)
        .collect())
}

/// The escape category of a *thread-pointer* instruction finding: an inline write
/// of the register TLS resolves through (x86-64 `wrfsbase`, or an FS selector
/// load by `mov fs`/`pop fs`/`lfs`; aarch64 `msr tpidr_el0`).
///
/// The thread pointer is not guest-only state. The shim is linked into the guest
/// and resolves its own thread-locals (the current task, the frame flags, the
/// panic scope) through it, and so does glibc's TCB. A guest that moves it makes
/// the shim read another block as its task state: it schedules the wrong task or
/// corrupts its own state. The syscall door is already closed
/// (`arch_prctl(ARCH_SET_FS)` is refused); these instructions do the same thing
/// with no syscall, so the audit refuses them, and no trap exists that could
/// manage them instead.
///
/// glibc 2.39 never puts one in a dynamically linked guest: ld.so installs the
/// main thread's pointer (outside the scanned image) and new threads get theirs
/// from `clone3(CLONE_SETTLS)`. Static glibc's `__libc_setup_tls` carries one on
/// aarch64, and it is refused like any other site; such images are refused for
/// their inline `svc` anyway.
pub const THREAD_POINTER_CATEGORY: &str = "thread-pointer";

/// The escape category of a *far-transfer* instruction finding: an x86-64 far
/// call, jump or return (`lcall`/`ljmp` through memory, `lret`, `iret`), each of
/// which loads CS from a selector the guest chooses.
///
/// Loading a 32-bit code selector (Linux's `__USER32_CS`) switches the CPU to
/// compatibility mode. From then on the instructions run as 32-bit code, which
/// the audit's 64-bit decoder does not describe: a thread-pointer write or an
/// entropy read there can sit where the 64-bit walk sees something else. The
/// transfer is refused where discovered to defend the decoder's 64-bit-mode
/// assumption. Unscanned transfers or signal-context CS rewrites remain outside
/// that static guarantee (see `ESCAPE-CLASSES.md`). Compilers do not emit these instructions for
/// user-space 64-bit code; the direct far forms (`9a`/`ea`) are invalid in 64-bit mode and already
/// fail closed as undecodable.
pub const FAR_TRANSFER_CATEGORY: &str = "far-transfer";

/// Every instruction finding in a binary's text sections.
///
/// NOT all of them are refusals. All but one category are — a raw `syscall`, a
/// counter/entropy read, a `vsyscall` immediate, an undecodable byte run — but
/// [`HOST_IDENTITY_CATEGORY`] findings are informational and MUST be filtered out
/// before the result reaches a denial set, or `cpuid` (which nearly every x86-64
/// binary contains) starts refusing every guest. [`NativeAudit::audit`] does that
/// filtering; [`native_host_identity_sites`] takes the other half.
pub(super) fn scan_instruction_classes(
    file: &object::File<'_>,
    provenance: &NativeProvenanceIndex,
) -> Result<Vec<NativeEscape>, TargetError> {
    let code_ranges = code_ranges::CodeRanges::new(file)?;
    scan_instruction_ranges(file, provenance, &code_ranges)
}

pub(super) fn scan_instruction_ranges(
    file: &object::File<'_>,
    provenance: &NativeProvenanceIndex,
    code_ranges: &code_ranges::CodeRanges,
) -> Result<Vec<NativeEscape>, TargetError> {
    // Fail closed on any architecture whose ISA this containment scan cannot
    // decode. A `_ => {}` default arm on the per-section match below silently
    // PASSED unsupported-arch binaries — every instruction unexamined — which is
    // exactly the vacuous-gate failure mode the default-deny doctrine forbids: a
    // forbidden `syscall`/`rdtsc`/`mrs` in a riscv64/s390x/... guest would sail
    // through with zero scanning. Refuse the whole scan up front (before touching
    // sections, so even a text-less binary of an undecodable arch is refused),
    // and keep the section-level match exhaustive so adding a new supported arch
    // forces an explicit decoder here rather than defaulting to a silent pass.
    let architecture = file.architecture();
    match architecture {
        Architecture::Aarch64 | Architecture::X86_64 => {}
        _ => return Err(TargetError::UnsupportedNativeArchitecture(architecture)),
    }
    let mut escapes = Vec::new();
    for section in file.sections() {
        if section.kind() != SectionKind::Text {
            continue;
        }
        let data = section.data().map_err(TargetError::NativeParse)?;
        let name = section.name().unwrap_or("<text>");
        match architecture {
            Architecture::Aarch64 => {
                for (index, instruction) in data.as_chunks::<4>().0.iter().enumerate() {
                    let instruction = u32::from_le_bytes(*instruction);
                    if let Some((category, mnemonic)) = aarch64_instruction_category(instruction) {
                        let offset = index * 4;
                        escapes.push(
                            NativeEscape::new(
                                format!("instruction@{name}+0x{offset:x}"),
                                category,
                                vec![
                                    provenance
                                        .for_address(section.address() + offset as u64, Some(name)),
                                ],
                            )
                            .with_mnemonic(mnemonic),
                        );
                    }
                }
            }
            Architecture::X86_64 => {
                let whole_section = 0..data.len();
                let ranges = code_ranges
                    .get(section.index())
                    .unwrap_or(std::slice::from_ref(&whole_section));
                for range in ranges {
                    x86_scan::scan(
                        data,
                        range.clone(),
                        name,
                        section.address(),
                        provenance,
                        &mut escapes,
                    );
                }
                // This deliberately remains a byte-pattern check over the full
                // section, including gaps: vsyscall has no SUD/TSC backstop.
                scan_vsyscall_references(data, name, section.address(), provenance, &mut escapes);
            }
            // Unreachable: the guard above refuses every other architecture. Kept
            // explicit (never a silent `_ => {}`) so a newly-supported arch must be
            // wired into both the guard and a real decoder here.
            _ => unreachable!("unsupported architectures are refused before the section scan"),
        }
    }
    // Overlapping symbol/FDE ranges are scanned independently. Report a site
    // once even when multiple ranges name it, retaining section/walk order.
    let mut seen = BTreeSet::new();
    escapes.retain(|e| seen.insert((e.symbol.clone(), e.category, e.mnemonic)));
    Ok(escapes)
}

/// Refuse a binary whose text materializes an address inside the x86-64 legacy
/// vsyscall page (`0xffffffffff600000..+0x1000`) as a 64-bit immediate. That
/// page's three entries (`gettimeofday`/`time`/`getcpu`) are KERNEL-EMULATED at
/// a fixed address with NO `syscall` instruction — invisible to both the
/// instruction scan and syscall-user-dispatch — so a caller that reads the wall
/// clock or a real CPU id through it escapes determinism entirely. Unlike an
/// auxv key (a bare integer, undetectable), the full 64-bit page address is a
/// reliable immediate signal: the fixed 6 high bytes `60 ff ff ff ff ff` (LE)
/// plus the top nibble of the low-12-bit page offset being zero is a ~2^-52
/// per-offset false-positive, effectively never a coincidence. A `vsyscall`
/// finding is NOT `direct-syscall`, so it is never SUD-downgradable — it always
/// refuses (see [`native_escape_is_sud_manageable`]). SUD-DESIGN.md §6.3.
fn scan_vsyscall_references(
    data: &[u8],
    name: &str,
    section_address: u64,
    provenance: &NativeProvenanceIndex,
    escapes: &mut Vec<NativeEscape>,
) {
    // Little-endian encoding of any address in [0xffffffffff600000, +0x1000):
    //   b[7..2] == [0xff,0xff,0xff,0xff,0xff,0x60]  (bytes 2..8)
    //   b[1] high nibble == 0                       (page offset < 0x1000)
    // b[0] is unconstrained (the low byte of the offset).
    if data.len() < 8 {
        return;
    }
    for offset in 0..=data.len() - 8 {
        let w = &data[offset..offset + 8];
        if w[2] == 0x60
            && w[3] == 0xff
            && w[4] == 0xff
            && w[5] == 0xff
            && w[6] == 0xff
            && w[7] == 0xff
            && (w[1] & 0xf0) == 0
        {
            escapes.push(NativeEscape::new(
                format!("immediate@{name}+0x{offset:x}"),
                "vsyscall",
                vec![provenance.for_address(section_address + offset as u64, Some(name))],
            ));
        }
    }
}

/// The forbidden aarch64 opcodes as `(category, mnemonic)`: `svc #0` (a raw
/// supervisor call) and `mrs Xt, CNTVCT_EL0` (the virtual system counter — the
/// arm64 analogue of `rdtsc`, and unlike `rdtsc` NOT trappable, so it carries a
/// mnemonic only for the message, never for a downgrade; see
/// [`native_escape_is_tsc_manageable`]), `mrs Xt, CNTVCTSS_EL0` (its FEAT_ECV
/// self-synchronising twin, `0xd53be0c0 | Rt`, readable at EL0 under the same
/// kernel control and just as untrappable), `mrs Xt, RNDR` / `mrs Xt, RNDRRS`
/// (FEAT_RNG hardware entropy, the arm64 analogue of `rdrand`/`rdseed` and just
/// as untrappable), and `msr TPIDR_EL0, Xt` (a write of the thread pointer; see
/// [`THREAD_POINTER_CATEGORY`]).
///
/// The physical counter reads (`CNTPCT_EL0`, `CNTPCTSS_EL0`) are not findings:
/// Linux leaves them disabled at EL0, so a read raises SIGILL and returns no
/// time.
///
/// The entropy rows are exactly `mrs Xt, S3_3_C2_C4_0` (`0xd53b2400 | Rt`) and
/// `mrs Xt, S3_3_C2_C4_1` (`0xd53b2420 | Rt`). Every other system-register access
/// stays unclassified, including the same two registers with `L = 0` (an `msr`
/// to a read-only register is UNDEFINED) and the unallocated `op2` values beside
/// them.
///
/// The thread-pointer row is exactly `msr S3_3_C13_C0_2, Xt` (`0xd51bd040 | Rt`).
/// Its neighbours are deliberately not findings:
/// - `mrs Xt, TPIDR_EL0` (`0xd53bd040 | Rt`) reads the pointer, which every TLS
///   access in glibc, std and the shim does.
/// - `msr TPIDRRO_EL0, Xt` (`op2 = 3`) is UNDEFINED at EL0: it raises SIGILL and
///   moves nothing.
/// - `msr TPIDR2_EL0, Xt` (`op2 = 5`) is the SME ABI's lazy-ZA-save block
///   pointer, not a TLS base; glibc 2.39's own `__libc_arm_za_disable` zeroes it.
pub(super) fn aarch64_instruction_category(
    instruction: u32,
) -> Option<(&'static str, &'static str)> {
    if instruction & 0xffe0_001f == 0xd400_0001 {
        Some(("direct-syscall", "svc"))
    } else if instruction & !0x1f == 0xd53b_e040 {
        Some(("cpu-nondeterminism", "cntvct"))
    } else if instruction & !0x1f == 0xd53b_e0c0 {
        Some(("cpu-nondeterminism", "cntvctss"))
    } else if instruction & !0x1f == 0xd53b_2400 {
        Some(("cpu-nondeterminism", "rndr"))
    } else if instruction & !0x1f == 0xd53b_2420 {
        Some(("cpu-nondeterminism", "rndrrs"))
    } else if instruction & !0x1f == 0xd51b_d040 {
        Some((THREAD_POINTER_CATEGORY, "msr tpidr_el0"))
    } else {
        None
    }
}

#[cfg(test)]
mod tests;
