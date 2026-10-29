//! Native instruction-class scanning and architecture coverage.

use crate::import_policy::NativeFormat;
use crate::provenance::NativeProvenanceIndex;
use crate::{NativeEscape, TargetError, code_ranges, x86_scan};
use object::{
    Architecture, Object, ObjectSection, ObjectSymbol, SectionFlags, SectionKind, SymbolKind,
};
use std::collections::{BTreeMap, BTreeSet};

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

/// The category of a *Go build marker*: one of Go's
/// `crypto/internal/boring/sig` functions (`StandardCrypto`, `BoringCrypto`,
/// `FIPSOnly`), each a `jmp` over 29 fixed bytes of data that
/// `rsc.io/goversion` searches for, then the `ret` it lands on. Every Go
/// binary that links `crypto/sha1` or `crypto/tls` carries `StandardCrypto`.
///
/// Its data is not code: decoded as instructions it reads as `lret` (a far
/// transfer, refused) or an undecodable byte. The scan matches a marker by
/// every one of its 32 bytes and steps over the data as its `jmp` does,
/// reporting the site instead of a refusal. Informational, like
/// [`HOST_IDENTITY_CATEGORY`]: the audit keeps it out of the denied set and
/// the report prints it under its own heading
/// ([`crate::render_go_build_marker_note`]).
pub const GO_BUILD_MARKER_CATEGORY: &str = "go-build-marker";

/// Whether a native finding is a Go build marker ([`GO_BUILD_MARKER_CATEGORY`])
/// — informational, never part of the refusal set.
pub fn native_escape_is_go_build_marker(escape: &NativeEscape) -> bool {
    escape.category == GO_BUILD_MARKER_CATEGORY
}

/// The Go build-marker sites in a native binary, with provenance; see
/// [`native_host_identity_sites`], whose contract this shares.
pub fn native_go_build_marker_sites(bytes: &[u8]) -> Result<Vec<NativeEscape>, TargetError> {
    let file = object::File::parse(bytes).map_err(TargetError::Parse)?;
    NativeFormat::from_binary(file.format())?;
    let provenance = NativeProvenanceIndex::new(&file);
    Ok(scan_instruction_classes(&file, &provenance)?
        .into_iter()
        .filter(native_escape_is_go_build_marker)
        .collect())
}

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
    let file = object::File::parse(bytes).map_err(TargetError::Parse)?;
    NativeFormat::from_binary(file.format())?;
    let provenance = NativeProvenanceIndex::new(&file);
    Ok(scan_instruction_classes(&file, &provenance)?
        .into_iter()
        .filter(native_escape_is_host_identity)
        .collect())
}

/// The raw system calls and counter or entropy reads in a relocatable object's
/// code, and every byte run the decoder cannot measure: the seal gate's
/// opcode check over the sealed shim engine, which must reach the kernel only
/// through libc, the region syscall-user-dispatch allows.
///
/// Stricter than the binary scan, as a gate over code Patina compiled itself
/// can be. Code is every section marked as holding instructions (ELF
/// `SHF_EXECINSTR`, Mach-O's instruction attributes), whatever its name.
/// Decoding restarts at every symbol in it, so leading data or a stray byte
/// cannot carry the walk past a function's entry, and an undecodable byte or
/// an instruction running over the next symbol is itself a finding. Fails
/// closed on a parse error or an architecture the scan cannot decode.
pub fn relocatable_raw_opcode_sites(bytes: &[u8]) -> Result<Vec<NativeEscape>, TargetError> {
    let file = object::File::parse(bytes).map_err(TargetError::Parse)?;
    let architecture = file.architecture();
    if !matches!(architecture, Architecture::Aarch64 | Architecture::X86_64) {
        return Err(TargetError::UnsupportedArchitecture(architecture));
    }
    let provenance = NativeProvenanceIndex::new(&file);
    let mut entries: BTreeMap<usize, BTreeSet<u64>> = BTreeMap::new();
    for symbol in file.symbols() {
        if let Some(section) = symbol.section_index()
            && !matches!(symbol.kind(), SymbolKind::Section | SymbolKind::File)
        {
            entries
                .entry(section.0)
                .or_default()
                .insert(symbol.address());
        }
    }
    let mut escapes = Vec::new();
    for section in file.sections().filter(holds_instructions) {
        let data = section.data().map_err(TargetError::Parse)?;
        let name = section.name().unwrap_or("<text>");
        let address = section.address();
        let mut starts = BTreeSet::from([0]);
        starts.extend(
            entries
                .get(&section.index().0)
                .into_iter()
                .flatten()
                .filter_map(|entry| usize::try_from(entry.checked_sub(address)?).ok())
                .filter(|offset| *offset < data.len()),
        );
        let ends = starts.iter().skip(1).copied().chain([data.len()]);
        for range in starts
            .iter()
            .copied()
            .zip(ends)
            .map(|(start, end)| start..end)
        {
            if architecture == Architecture::X86_64 {
                x86_scan::scan(data, range, name, address, &provenance, &mut escapes);
                continue;
            }
            if range.start % 4 != 0 || range.len() % 4 != 0 {
                escapes.push(NativeEscape::new(
                    format!("instruction@{name}+0x{:x}", range.start),
                    UNDECODABLE_CATEGORY,
                    vec![provenance.for_address(address + range.start as u64, Some(name))],
                ));
            }
            scan_aarch64(data, range, name, address, &provenance, &mut escapes);
        }
    }
    let mut seen = BTreeSet::new();
    escapes.retain(|escape| {
        matches!(
            escape.category,
            "direct-syscall" | "cpu-nondeterminism" | UNDECODABLE_CATEGORY
        ) && seen.insert((escape.symbol.clone(), escape.category))
    });
    Ok(escapes)
}

/// The category of a byte run the decoder cannot measure as an instruction.
const UNDECODABLE_CATEGORY: &str = "undecodable-instruction";

/// Whether `section` is marked as holding instructions.
fn holds_instructions(section: &object::Section<'_, '_>) -> bool {
    match section.flags() {
        SectionFlags::Elf { sh_flags } => sh_flags & u64::from(object::elf::SHF_EXECINSTR) != 0,
        SectionFlags::MachO { flags } => {
            flags
                & (object::macho::S_ATTR_PURE_INSTRUCTIONS
                    | object::macho::S_ATTR_SOME_INSTRUCTIONS)
                != 0
        }
        _ => section.kind() == SectionKind::Text,
    }
}

/// Classify each aligned word of `data[range]` as an aarch64 instruction.
fn scan_aarch64(
    data: &[u8],
    range: std::ops::Range<usize>,
    name: &str,
    address: u64,
    provenance: &NativeProvenanceIndex,
    escapes: &mut Vec<NativeEscape>,
) {
    for (index, instruction) in data[range.clone()].as_chunks::<4>().0.iter().enumerate() {
        let instruction = u32::from_le_bytes(*instruction);
        if let Some((category, mnemonic)) = aarch64_instruction_category(instruction) {
            let offset = range.start + index * 4;
            escapes.push(
                NativeEscape::new(
                    format!("instruction@{name}+0x{offset:x}"),
                    category,
                    vec![provenance.for_address(address + offset as u64, Some(name))],
                )
                .with_mnemonic(mnemonic),
            );
        }
    }
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
        _ => return Err(TargetError::UnsupportedArchitecture(architecture)),
    }
    let mut escapes = Vec::new();
    for section in file.sections() {
        if section.kind() != SectionKind::Text {
            continue;
        }
        let data = section.data().map_err(TargetError::Parse)?;
        let name = section.name().unwrap_or("<text>");
        match architecture {
            Architecture::Aarch64 => {
                scan_aarch64(
                    data,
                    0..data.len(),
                    name,
                    section.address(),
                    provenance,
                    &mut escapes,
                );
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
