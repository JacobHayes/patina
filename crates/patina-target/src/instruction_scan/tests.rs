//! Native instruction-class scanning and architecture coverage tests.

use super::*;
use crate::TargetError;
use crate::native_audit::NativeAudit;
use crate::provenance::NativeProvenanceIndex;
use crate::report::{
    render_cpu_nondeterminism_note, render_host_identity_note, render_thread_pointer_note,
};
use crate::shim::{native_escape_is_sud_manageable, native_escape_is_tsc_manageable};
use std::collections::BTreeSet;

#[test]
fn vsyscall_reference_scan_detects_the_page_and_refuses_it() {
    // A `movabs rax, 0xffffffffff600000` (48 b8 <imm64>) — materializing the
    // vsyscall gettimeofday entry — is caught by the immediate signal.
    let mut text = vec![0x48u8, 0xb8];
    text.extend_from_slice(&0xffffffffff600000u64.to_le_bytes());
    let provenance = NativeProvenanceIndex::from_sorted(Vec::new());
    let mut escapes = Vec::new();
    scan_vsyscall_references(&text, ".text", 0, &provenance, &mut escapes);
    assert_eq!(
        escapes.len(),
        1,
        "vsyscall immediate must be found: {escapes:?}"
    );
    assert_eq!(escapes[0].category, "vsyscall");
    // A `vsyscall` finding is never SUD-downgradable (kernel-emulated, no
    // syscall instruction), so it always refuses.
    assert!(!native_escape_is_sud_manageable(&escapes[0]));

    // The `time` entry at +0x400 is also on the page and caught.
    let mut text2 = vec![0x48u8, 0xb8];
    text2.extend_from_slice(&0xffffffffff600400u64.to_le_bytes());
    let mut escapes2 = Vec::new();
    scan_vsyscall_references(&text2, ".text", 0, &provenance, &mut escapes2);
    assert_eq!(escapes2.len(), 1, "vsyscall time entry must be found");

    // RED control: ordinary text (including a nearby-but-not-on-page address)
    // yields no finding — the detector is not a blanket 0xff... matcher.
    let mut clean = vec![0x48u8, 0xb8];
    clean.extend_from_slice(&0xffffffffff700000u64.to_le_bytes()); // wrong page
    clean.extend_from_slice(&[0x90; 16]); // nops
    let mut none = Vec::new();
    scan_vsyscall_references(&clean, ".text", 0, &provenance, &mut none);
    assert!(none.is_empty(), "off-page address must not match: {none:?}");
}

/// Build a minimal but well-formed little-endian ELF64 for `e_machine`, with
/// a single `ALLOC|EXECINSTR` PROGBITS `.text` section carrying `text` plus a
/// `.shstrtab`. Just enough for `object::File::parse` to report the
/// architecture and a real `SectionKind::Text` section — the `.text` bytes
/// are the executable code a silent-pass scanner would skip.
fn minimal_executable_elf64(e_machine: u16, text: &[u8]) -> Vec<u8> {
    // ".text" name at byte 1, ".shstrtab" name at byte 7.
    let shstr: &[u8] = b"\0.text\0.shstrtab\0";
    let text_off = 64u64;
    let shstr_off = text_off + text.len() as u64;
    let shoff = {
        let end = shstr_off + shstr.len() as u64;
        (end + 7) & !7 // section header table is 8-aligned
    };

    let mut elf = Vec::new();
    // e_ident: magic, ELFCLASS64, ELFDATA2LSB, EV_CURRENT, SysV ABI, padding.
    elf.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
    elf.extend_from_slice(&[0u8; 8]);
    elf.extend_from_slice(&2u16.to_le_bytes()); // e_type = ET_EXEC
    elf.extend_from_slice(&e_machine.to_le_bytes()); // e_machine
    elf.extend_from_slice(&1u32.to_le_bytes()); // e_version
    elf.extend_from_slice(&0u64.to_le_bytes()); // e_entry
    elf.extend_from_slice(&0u64.to_le_bytes()); // e_phoff
    elf.extend_from_slice(&shoff.to_le_bytes()); // e_shoff
    elf.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    elf.extend_from_slice(&64u16.to_le_bytes()); // e_ehsize
    elf.extend_from_slice(&0u16.to_le_bytes()); // e_phentsize
    elf.extend_from_slice(&0u16.to_le_bytes()); // e_phnum
    elf.extend_from_slice(&64u16.to_le_bytes()); // e_shentsize
    elf.extend_from_slice(&3u16.to_le_bytes()); // e_shnum
    elf.extend_from_slice(&2u16.to_le_bytes()); // e_shstrndx -> .shstrtab
    assert_eq!(elf.len(), 64, "ELF64 header is 64 bytes");

    elf.extend_from_slice(text); // .text data at offset 64
    elf.extend_from_slice(shstr); // .shstrtab data at offset 72
    while (elf.len() as u64) < shoff {
        elf.push(0);
    }

    let mut push_shdr =
        |name: u32, typ: u32, flags: u64, offset: u64, size: u64, addralign: u64| {
            elf.extend_from_slice(&name.to_le_bytes());
            elf.extend_from_slice(&typ.to_le_bytes());
            elf.extend_from_slice(&flags.to_le_bytes());
            elf.extend_from_slice(&0u64.to_le_bytes()); // sh_addr
            elf.extend_from_slice(&offset.to_le_bytes());
            elf.extend_from_slice(&size.to_le_bytes());
            elf.extend_from_slice(&0u32.to_le_bytes()); // sh_link
            elf.extend_from_slice(&0u32.to_le_bytes()); // sh_info
            elf.extend_from_slice(&addralign.to_le_bytes());
            elf.extend_from_slice(&0u64.to_le_bytes()); // sh_entsize
        };
    push_shdr(0, 0, 0, 0, 0, 0); // 0: SHN_UNDEF
    // 1: .text — SHT_PROGBITS(1), SHF_ALLOC|SHF_EXECINSTR (0x2|0x4).
    push_shdr(1, 1, 0x2 | 0x4, text_off, text.len() as u64, 4);
    // 2: .shstrtab — SHT_STRTAB(3).
    push_shdr(7, 3, 0, shstr_off, shstr.len() as u64, 1);

    elf
}

// Default-deny for architectures the containment scan cannot decode.
// `scan_instruction_classes` once had a `_ => {}` arm that SILENTLY passed
// any binary whose ISA it could not decode: a riscv64/s390x guest — including
// one carrying a forbidden `ecall`/`svc` in `.text` — sailed through with zero
// instructions examined, exactly the vacuous-gate failure mode the default-deny
// doctrine forbids. Feed the scanner a hand-built minimal ELF of such an
// architecture, WITH a real executable `.text` section, and assert both the
// private scanner and the public `NativeAudit::audit` gate fail closed with a
// loud, structured error that names the architecture and the supported set.
// Red-before/green-after: with the old `_ => {}` arm the scan returns
// `Ok(vec![])` and the audit `Ok(_)`, so both assertions below fail.
#[test]
fn refuses_binaries_of_undecodable_architectures() {
    use object::{Architecture, Object, ObjectSection, SectionKind};

    const EM_S390: u16 = 22;
    const EM_RISCV: u16 = 243;
    for (machine, label) in [(EM_RISCV, "riscv"), (EM_S390, "s390")] {
        let elf = minimal_executable_elf64(machine, &[0u8; 8]);

        // The scenario is the live one: object reports a non-decodable arch and
        // a genuine executable text section (the bytes the old arm skipped).
        let parsed = object::File::parse(&*elf).expect("hand-built ELF must parse");
        assert!(
            !matches!(
                parsed.architecture(),
                Architecture::Aarch64 | Architecture::X86_64
            ),
            "{label}: test arch must be one the scanner cannot decode, got {:?}",
            parsed.architecture()
        );
        assert!(
            parsed.sections().any(|s| s.kind() == SectionKind::Text),
            "{label}: the synthetic ELF must carry an executable .text section"
        );

        // Private scanner refuses.
        let provenance = NativeProvenanceIndex::new(&parsed);
        let scan = scan_instruction_classes(&parsed, &provenance);
        assert!(
            matches!(scan, Err(TargetError::UnsupportedNativeArchitecture(_))),
            "{label}: scan must refuse an undecodable arch, got {scan:?}"
        );

        // Public gate refuses end to end.
        let err = NativeAudit::audit(&elf, &BTreeSet::new())
            .expect_err("audit must fail closed on an undecodable arch");
        assert!(
            matches!(err, TargetError::UnsupportedNativeArchitecture(_)),
            "{label}: audit error must be UnsupportedNativeArchitecture, got {err:?}"
        );
        let message = err.to_string();
        assert!(
            message.contains("cannot decode architecture")
                && message.contains("Aarch64")
                && message.contains("X86_64")
                && message.contains("fails closed"),
            "{label}: error must name the arch, the supported set, and fail closed: {message}"
        );
    }
}

// Supported architectures still scan (not swept up by the arch guard): a
// native binary built for the host — Aarch64 on macOS, X86_64 on Linux —
// decodes cleanly. The existing per-class and objdump-corpus tests cover the
// decoders themselves; this asserts the guard itself does not reject a
// supported arch. `scans_supported_arch_binary` builds nothing (no toolchain
// dependence): it hand-builds a supported-arch ELF the same way and asserts
// the scan does NOT return the arch error.
#[test]
fn scans_supported_arch_binary_without_arch_refusal() {
    const EM_X86_64: u16 = 62;
    const EM_AARCH64: u16 = 183;
    for (machine, label) in [(EM_X86_64, "x86_64"), (EM_AARCH64, "aarch64")] {
        let elf = minimal_executable_elf64(machine, &[0u8; 8]);
        let parsed = object::File::parse(&*elf).expect("hand-built ELF must parse");
        let provenance = NativeProvenanceIndex::new(&parsed);
        let scan = scan_instruction_classes(&parsed, &provenance);
        assert!(
            !matches!(scan, Err(TargetError::UnsupportedNativeArchitecture(_))),
            "{label}: a supported arch must not be refused by the arch guard, got {scan:?}"
        );
        // The .text here is all-zero, which decodes to no forbidden opcode on
        // either supported ISA, so the scan succeeds with no findings.
        assert_eq!(
            scan.expect("supported arch scans").len(),
            0,
            "{label}: zeroed .text yields no forbidden-instruction findings"
        );
    }
}

// A `cpuid` site is REPORTED, never refused. CPUID is near-universal in real
// binaries (libc ifunc resolvers, std feature detection), so a refusal would
// break every guest; the finding is informational, and its whole value is
// that it stops being silent. Two properties are pinned together because
// either alone is the wrong outcome: the sites are enumerated
// (`native_host_identity_sites`), AND they never enter the denied set that
// makes `audit` fail closed. The neighbouring instruction classes in the same
// `.text` are unchanged — an `rdtsc` next door still refuses.
// RED before the `0f a2` decode row: the site count is 0 and the note is
// `None`, exactly the silence the fastant probe measured.
#[test]
fn cpuid_sites_are_reported_without_refusing_the_binary() {
    const EM_X86_64: u16 = 62;
    // cpuid; ret; cpuid; ret; nop; nop
    let elf =
        minimal_executable_elf64(EM_X86_64, &[0x0f, 0xa2, 0xc3, 0x0f, 0xa2, 0xc3, 0x90, 0x90]);
    let audit = NativeAudit::audit(&elf, &BTreeSet::new())
        .expect("a host-identity read must not refuse the binary");
    assert!(
        audit.imports.is_empty(),
        "the synthetic fixture imports nothing"
    );

    let sites = native_host_identity_sites(&elf).expect("the fixture scans");
    assert_eq!(sites.len(), 2, "both cpuid sites are enumerated: {sites:?}");
    for site in &sites {
        assert_eq!(site.category, HOST_IDENTITY_CATEGORY);
        assert_eq!(site.mnemonic, Some("cpuid"));
        assert!(
            site.symbol.starts_with("instruction@"),
            "an instruction finding names a .text offset, not a symbol: {}",
            site.symbol
        );
    }

    let note = render_host_identity_note(&sites).expect("a non-empty list renders");
    assert!(
        note.contains("host-identity reads (cpuid, 2 sites)")
            && note.contains("unmanaged")
            && note.contains("cross-host"),
        "the note must name the class, the count, and the portability limit: {note}"
    );
    assert_eq!(
        render_host_identity_note(&[]),
        None,
        "no sites renders no note"
    );

    // Same text plus an rdtsc: the counter read still refuses, and the cpuid
    // site is still reported rather than folded into the refusal.
    let with_rdtsc =
        minimal_executable_elf64(EM_X86_64, &[0x0f, 0xa2, 0x0f, 0x31, 0xc3, 0x90, 0x90, 0x90]);
    let error = NativeAudit::audit(&with_rdtsc, &BTreeSet::new())
        .expect_err("an rdtsc site still fails closed");
    let TargetError::UnsupportedNativeImports(denied) = error else {
        panic!("expected an unsupported-imports refusal, got {error:?}");
    };
    assert_eq!(
        denied
            .iter()
            .map(|escape| (escape.category, escape.mnemonic))
            .collect::<Vec<_>>(),
        vec![("cpu-nondeterminism", Some("rdtsc"))],
        "only the counter read is denied; the cpuid site is not a refusal"
    );
    assert_eq!(
        native_host_identity_sites(&with_rdtsc)
            .expect("the fixture scans")
            .len(),
        1,
        "the host-identity site survives a refusing audit, so a refusal can \
             report it too"
    );
}

const AARCH64_NOP: u32 = 0xd503_201f;

fn aarch64_text(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

// The forbidden aarch64 system-register accesses, for every Xt: the
// thread-pointer write (`msr TPIDR_EL0`), the self-synchronising virtual
// counter (`mrs CNTVCTSS_EL0`) and the FEAT_RNG entropy reads (`mrs
// RNDR`/`RNDRRS`). Their neighbours are not findings: the thread pointer's
// read, the EL0-UNDEFINED `msr TPIDRRO_EL0` and the SME `TPIDR2_EL0` pair;
// the physical counters Linux disables at EL0 (`CNTPCT`/`CNTPCTSS`), the
// UNDEFINED `msr` forms, the unallocated `op2` beside them, and the next
// `CRm`/`op1` over. RED: drop a
// row from `aarch64_instruction_category` and its accesses classify as
// `None`.
#[test]
fn classifies_aarch64_system_register_accesses() {
    for rt in 0..32u32 {
        for (word, expected) in [
            (0xd51b_d040, (THREAD_POINTER_CATEGORY, "msr tpidr_el0")),
            (0xd53b_e0c0, ("cpu-nondeterminism", "cntvctss")),
            (0xd53b_2400, ("cpu-nondeterminism", "rndr")),
            (0xd53b_2420, ("cpu-nondeterminism", "rndrrs")),
        ] {
            assert_eq!(
                aarch64_instruction_category(word | rt),
                Some(expected),
                "{} x{rt}",
                expected.1
            );
        }
        for (neighbour, label) in [
            (0xd53b_d040 | rt, "mrs tpidr_el0"),
            (0xd51b_d060 | rt, "msr tpidrro_el0"),
            (0xd53b_d060 | rt, "mrs tpidrro_el0"),
            (0xd51b_d0a0 | rt, "msr tpidr2_el0"),
            (0xd53b_d0a0 | rt, "mrs tpidr2_el0"),
            (0xd51b_2400 | rt, "msr s3_3_c2_c4_0 (rndr, write)"),
            (0xd51b_2420 | rt, "msr s3_3_c2_c4_1 (rndrrs, write)"),
            (0xd53b_2440 | rt, "mrs s3_3_c2_c4_2"),
            (0xd53b_2300 | rt, "mrs s3_3_c2_c3_0"),
            (0xd53b_2500 | rt, "mrs s3_3_c2_c5_0"),
            (0xd538_2400 | rt, "mrs s3_0_c2_c4_0"),
            (0xd53b_e020 | rt, "mrs cntpct_el0"),
            (0xd53b_e0a0 | rt, "mrs cntpctss_el0"),
            (0xd51b_e0c0 | rt, "msr s3_3_c14_c0_6 (cntvctss, write)"),
            (0xd53b_e0e0 | rt, "mrs s3_3_c14_c0_7"),
        ] {
            assert_eq!(
                aarch64_instruction_category(neighbour),
                None,
                "{label} x{rt}"
            );
        }
    }
}

// The scanner on bytes, end to end through the public gate. glibc 2.39's own
// words are used: `msr tpidr_el0, x20` (ld.so's TLS_INIT_TP) and `msr
// tpidr2_el0, xzr` (libc's `__libc_arm_za_disable`). An image with no
// symbols gives the write no containing function, so no allowance applies:
// the audit refuses it by category and mnemonic, and the note names it.
#[test]
fn aarch64_thread_pointer_write_is_refused_by_name() {
    const EM_AARCH64: u16 = 183;
    let text = aarch64_text(&[
        AARCH64_NOP,
        0xd51b_d054, // msr tpidr_el0, x20
        0xd53b_d040, // mrs x0, tpidr_el0
        0xd51b_d0bf, // msr tpidr2_el0, xzr
    ]);
    let elf = minimal_executable_elf64(EM_AARCH64, &text);
    let Err(TargetError::UnsupportedNativeImports(denied)) =
        NativeAudit::audit(&elf, &BTreeSet::new())
    else {
        panic!("a thread-pointer write must refuse the binary");
    };
    let found: Vec<_> = denied
        .iter()
        .map(|escape| (escape.symbol.as_str(), escape.category, escape.mnemonic))
        .collect();
    assert_eq!(
        found,
        vec![(
            "instruction@.text+0x4",
            THREAD_POINTER_CATEGORY,
            Some("msr tpidr_el0")
        )]
    );
    // No downgrade exists for it, and it is not an informational class.
    assert!(!native_escape_is_sud_manageable(&denied[0]));
    assert!(!native_escape_is_tsc_manageable(&denied[0]));
    assert!(!native_escape_is_host_identity(&denied[0]));
    let note = render_thread_pointer_note(&denied).expect("a thread-pointer note");
    assert!(note.contains("msr tpidr_el0"), "{note}");
    assert_eq!(render_thread_pointer_note(&[]), None);
    assert_eq!(render_cpu_nondeterminism_note(&denied), None);
}
