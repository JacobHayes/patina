//! Boundary-aware x86-64 instruction decoding and forbidden-opcode scanning tests.

use super::*;
/// Decode one instruction, panicking if the decoder fails closed. Returns
/// `(length, forbidden_category)`, dropping the mnemonic (the mnemonic is
/// asserted directly by the tests that care).
fn decode(b: &[u8]) -> (usize, Option<&'static str>) {
    (decode_full(b).0, decode_full(b).1.map(|(cat, _)| cat))
}

/// As [`decode`], keeping the `(category, mnemonic)` pair intact.
fn decode_full(b: &[u8]) -> (usize, Option<Forbidden>) {
    match decode_one(b) {
        Step::Insn { len, cat } => (len, cat),
        Step::Undecodable => panic!("decoder failed closed on {b:02x?}"),
    }
}

fn scan_test(data: &[u8], escapes: &mut Vec<super::super::NativeEscape>) {
    let provenance = super::super::NativeProvenanceIndex::from_sorted(Vec::new());
    scan(data, 0..data.len(), ".text", 0, &provenance, escapes);
}

#[test]
fn measures_representative_instruction_lengths() {
    // (bytes, expected length) across the length-determining features.
    let cases: &[(&[u8], usize)] = &[
        (&[0x90], 1),                                // nop
        (&[0xc3], 1),                                // ret
        (&[0x0f, 0x05], 2),                          // syscall
        (&[0x0f, 0x31], 2),                          // rdtsc
        (&[0x48, 0x89, 0xe5], 3),                    // mov rbp, rsp (REX.W + ModRM reg)
        (&[0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0], 8),  // mov rax,[disp32] (SIB, no base)
        (&[0x48, 0x8d, 0x3d, 0, 0, 0, 0], 7),        // lea rdi,[rip+disp32]
        (&[0xe8, 0, 0, 0, 0], 5),                    // call rel32
        (&[0xeb, 0x00], 2),                          // jmp rel8
        (&[0x0f, 0x84, 0, 0, 0, 0], 6),              // je rel32
        (&[0x48, 0xb8, 1, 2, 3, 4, 5, 6, 7, 8], 10), // mov rax, imm64 (REX.W imm)
        (&[0xb8, 1, 2, 3, 4], 5),                    // mov eax, imm32
        (&[0x66, 0xb8, 1, 2], 4),                    // mov ax, imm16 (0x66 shrinks imm)
        (&[0x68, 1, 2, 3, 4], 5),                    // push imm32
        (&[0x83, 0xc0, 0x01], 3),                    // add eax, imm8 (grp1 Ib)
        (&[0x81, 0xc0, 1, 2, 3, 4], 6),              // add eax, imm32 (grp1 Iz)
        (&[0xf6, 0xc0, 0x01], 3),                    // test al, imm8 (grp3 reg 0 → imm8)
        (&[0xf6, 0xd8], 2),                          // neg al (grp3 reg 3 → no imm)
        (&[0xf7, 0xc0, 1, 2, 3, 4], 6),              // test eax, imm32 (grp3 reg 0)
        (&[0xf7, 0xd8], 2),                          // neg eax (grp3 reg 3 → no imm)
        (&[0x0f, 0xc7, 0xf0], 3),                    // rdrand eax (grp9 reg 6)
        (&[0x48, 0x0f, 0xc7, 0x08], 4),              // cmpxchg8b [rax] (grp9 reg 1)
        (&[0xc8, 1, 2, 3], 4),                       // enter iw, ib
        (&[0x0f, 0x1f, 0x44, 0x00, 0x00], 5),        // 5-byte nop (ModRM+SIB+disp8)
    ];
    for (bytes, expected) in cases {
        let (len, _) = decode(bytes);
        assert_eq!(len, *expected, "length for {bytes:02x?}");
    }
}

/// `(bytes, length, classification)`, lengths and mnemonics as objdump
/// decodes them. Besides the 64-bit syscall and the counter/entropy
/// reads, the i386 syscall entries (`int 0x80`, `sysenter`) are direct
/// syscalls, and the far transfers that load CS (`lcall`/`ljmp` through
/// memory, `lret`, `iret`) are `far-transfer`. Their neighbours are not
/// findings: other `int` vectors, the privileged `sysexit`/`sysret`, the
/// near forms of group 5, and near `ret`. RED: drop a decoder arm and its
/// row decodes as `None`.
#[test]
fn flags_real_forbidden_opcodes_at_a_boundary() {
    let far = super::super::FAR_TRANSFER_CATEGORY;
    let cases: &[(&[u8], usize, Option<Forbidden>)] = &[
        (&[0x0f, 0x05], 2, Some(("direct-syscall", "syscall"))),
        (&[0x0f, 0x31], 2, Some(("cpu-nondeterminism", "rdtsc"))),
        (
            &[0x0f, 0xc7, 0xf0],
            3,
            Some(("cpu-nondeterminism", "rdrand")),
        ),
        (&[0xcd, 0x80], 2, Some(("direct-syscall", "int 0x80"))),
        (&[0x0f, 0x34], 2, Some(("direct-syscall", "sysenter"))),
        (&[0xff, 0x18], 2, Some((far, "lcall"))), // lcall *(%rax)
        (&[0x48, 0xff, 0x18], 3, Some((far, "lcall"))), // m16:64
        (&[0xff, 0x2c, 0x24], 3, Some((far, "ljmp"))), // ljmp *(%rsp)
        (&[0xff, 0x2d, 0, 0, 0, 0], 6, Some((far, "ljmp"))), // ljmp *0(%rip)
        (&[0xcb], 1, Some((far, "lret"))),
        (&[0x48, 0xcb], 2, Some((far, "lret"))), // lretq
        (&[0xca, 0x08, 0x00], 3, Some((far, "lret"))), // lret $8
        (&[0xcf], 1, Some((far, "iret"))),
        (&[0x48, 0xcf], 2, Some((far, "iret"))), // iretq
        (&[0x48, 0x0f, 0xc7, 0x08], 4, None),    // cmpxchg8b (group 9 reg 1)
        (&[0xcd, 0x03], 2, None),                // int $3
        (&[0xcd, 0x81], 2, None),                // int $0x81
        (&[0xcc], 1, None),                      // int3
        (&[0x0f, 0x35], 2, None),                // sysexit (privileged)
        (&[0x0f, 0x07], 2, None),                // sysret (privileged)
        (&[0xff, 0x10], 2, None),                // call *(%rax)
        (&[0xff, 0x20], 2, None),                // jmp *(%rax)
        (&[0xff, 0xd0], 2, None),                // call *%rax
        (&[0xff, 0xe0], 2, None),                // jmp *%rax
        (&[0xff, 0x30], 2, None),                // push (%rax)
        (&[0xc2, 0x08, 0x00], 3, None),          // ret $8
    ];
    for (bytes, len, expected) in cases {
        assert_eq!(decode_full(bytes), (*len, *expected), "{bytes:02x?}");
    }
}

/// The two counter/entropy reads the opcode table did not classify.
/// `rdtscp` (`0f 01 f9`) was measured as an ordinary group-7 instruction
/// and scanned straight past — a guest reading the timestamp counter
/// through it audited CLEAN, which is the false-negative direction this
/// containment gate must never take. `rdseed` (`0f c7 /7`) was the same
/// blind spot one ModRM.reg over from `rdrand`. RED: drop either arm from
/// the decoder and this test fails with `None`.
#[test]
fn classifies_rdtscp_and_rdseed() {
    // rdtscp: mod=3, reg=7, rm=1. Length is unchanged at 3 bytes.
    assert_eq!(
        decode_full(&[0x0f, 0x01, 0xf9]).1,
        Some(("cpu-nondeterminism", "rdtscp"))
    );
    assert_eq!(decode(&[0x0f, 0x01, 0xf9]).0, 3);
    // rdseed eax: `0f c7 /7`, ModRM f8.
    assert_eq!(
        decode_full(&[0x0f, 0xc7, 0xf8]).1,
        Some(("cpu-nondeterminism", "rdseed"))
    );
    // Neighbours in the same groups stay unforbidden: `swapgs`
    // (`0f 01 f8`, reg 7 / rm 0) and the memory forms of group 7
    // (`sgdt [rax]`, reg 0) are not counter reads.
    assert_eq!(decode(&[0x0f, 0x01, 0xf8]).1, None);
    assert_eq!(decode(&[0x0f, 0x01, 0x00]).1, None);
    // And the mnemonic rides onto the finding, since the audit's
    // manageability split reads it rather than the shared category.
    let mut escapes = Vec::new();
    scan_test(
        &[0x0f, 0x31, 0x0f, 0x01, 0xf9, 0x0f, 0xc7, 0xf8],
        &mut escapes,
    );
    let found: Vec<_> = escapes
        .iter()
        .map(|escape| (escape.category, escape.mnemonic))
        .collect();
    assert_eq!(
        found,
        vec![
            ("cpu-nondeterminism", Some("rdtsc")),
            ("cpu-nondeterminism", Some("rdtscp")),
            ("cpu-nondeterminism", Some("rdseed")),
        ]
    );
}

/// `cpuid` (`0f a2`) is decoded and classified `host-identity` — the
/// informational class, not a refusal. It sat in the "no ModRM, no
/// immediate" length row with no category, so a guest branching on host
/// CPU feature bits (libc ifunc resolvers, std feature detection, a
/// fast-clock crate choosing its TSC path) was measured correctly and
/// reported NOTHING: the fastant probe found 11 cpuid sites by objdump in
/// a binary whose 2 rdtsc sites the audit did report. RED: drop the `0xA2`
/// arm and the category is `None` again.
/// `rdpkru`/`wrpkru` (`0f 01 ee`/`ef`, group 7's `mod=3, reg=5,
/// rm=6/7`) are host-identity: visible, not refused. RED: without
/// the group-7 arm they classify as nothing.
#[test]
fn classifies_protection_key_access_as_host_identity() {
    for (bytes, mnemonic) in [
        ([0x0f, 0x01, 0xee], "rdpkru"),
        ([0x0f, 0x01, 0xef], "wrpkru"),
    ] {
        assert_eq!(decode_full(&bytes).1, Some(("host-identity", mnemonic)));
        assert_eq!(decode(&bytes).0, 3);
    }
    // The group's other register forms keep their classes.
    assert_eq!(decode(&[0x0f, 0x01, 0xf9]).1, Some("cpu-nondeterminism"));
    assert_eq!(decode(&[0x0f, 0x01, 0xd0]).1, None, "xgetbv");
}

#[test]
fn classifies_cpuid_as_host_identity() {
    assert_eq!(
        decode_full(&[0x0f, 0xa2]).1,
        Some(("host-identity", "cpuid"))
    );
    // Classification only: the length was already right and stays 2.
    assert_eq!(decode(&[0x0f, 0xa2]).0, 2);
    // Neighbours in the same length row are untouched: `bswap eax`
    // (`0f c8`), `cpuid`'s table row-mates `wbinvd` (`0f 09`) and `ud2`
    // (`0f 0b`) classify as nothing.
    for bytes in [&[0x0f, 0xc8][..], &[0x0f, 0x09][..], &[0x0f, 0x0b][..]] {
        assert_eq!(decode(bytes).1, None, "{bytes:02x?} is not host-identity");
    }
    // And the counter/entropy neighbours keep their own category.
    assert_eq!(decode(&[0x0f, 0x31]).1, Some("cpu-nondeterminism"));
    assert_eq!(decode(&[0x0f, 0xc7, 0xf0]).1, Some("cpu-nondeterminism"));
    // A scan of mixed text attributes each site to its own class, in
    // order: cpuid, rdtsc, cpuid.
    let mut escapes = Vec::new();
    scan_test(&[0x0f, 0xa2, 0x0f, 0x31, 0x0f, 0xa2], &mut escapes);
    let found: Vec<_> = escapes
        .iter()
        .map(|escape| (escape.symbol.as_str(), escape.category, escape.mnemonic))
        .collect();
    assert_eq!(
        found,
        vec![
            ("instruction@.text+0x0", "host-identity", Some("cpuid")),
            ("instruction@.text+0x2", "cpu-nondeterminism", Some("rdtsc")),
            ("instruction@.text+0x4", "host-identity", Some("cpuid")),
        ]
    );
}

#[test]
fn walks_past_forbidden_bytes_embedded_in_operands() {
    // `mov rax, 0x0f31000f05` — the immediate contains both the `0f 05`
    // (syscall) and `0f 31` (rdtsc) byte pairs, but they are operand data,
    // not instruction boundaries. A boundary-aware scan flags neither; the
    // old byte-slide flagged both.
    let mut escapes = Vec::new();
    let text = [0x48, 0xb8, 0x05, 0x0f, 0x00, 0x31, 0x0f, 0x00, 0x00, 0x00];
    scan_test(&text, &mut escapes);
    assert!(
        escapes.is_empty(),
        "operand-embedded opcode bytes must not be flagged: {escapes:?}"
    );
    // The same forbidden bytes at a real boundary (a `syscall` after a nop)
    // must still be caught.
    let mut escapes = Vec::new();
    scan_test(&[0x90, 0x0f, 0x05], &mut escapes);
    assert_eq!(escapes.len(), 1);
    assert_eq!(escapes[0].category, "direct-syscall");
    assert_eq!(escapes[0].symbol, "instruction@.text+0x1");
}

#[test]
fn fails_closed_on_undecodable_bytes() {
    // A reserved EVEX map and a reserved 0F opcode are both declined;
    // the scan reports the offset rather than skipping a length guess.
    for bytes in [&[0x62, 0xf0, 0x7c, 0x48, 0x58, 0xc0][..], &[0x0f, 0x04][..]] {
        let mut escapes = Vec::new();
        scan_test(bytes, &mut escapes);
        assert_eq!(escapes.len(), 1, "should fail closed on {bytes:02x?}");
        assert_eq!(escapes[0].category, "undecodable-instruction");
        assert_eq!(escapes[0].symbol, "instruction@.text+0x0");
    }
}

#[test]
fn measures_vex_avx_instruction_lengths() {
    // VEX (AVX/AVX2) is the encoding the corpus check surfaced; default
    // codegen emits it, so it must be length-decoded rather than declined.
    let cases: &[(&[u8], usize)] = &[
        (&[0xc5, 0xf8, 0x77], 3), // vzeroupper (2-byte VEX, no ModRM)
        (&[0xc5, 0xfd, 0x6f, 0x44, 0x24, 0x20], 6), // vmovdqa ymm0,[rsp+0x20] (SIB+disp8)
        (&[0xc5, 0xfd, 0xd7, 0xc0], 4), // vpmovmskb eax,ymm0 (reg ModRM)
        (&[0xc5, 0xfc, 0x57, 0xc0], 4), // vxorps ymm0,ymm0,ymm0
        (&[0xc5, 0xf1, 0xc4, 0xc0, 0x05], 5), // vpinsrw xmm0,xmm1,eax,imm8
        (&[0xc5, 0xf9, 0xc5, 0xc1, 0x05], 5), // vpextrw eax,xmm1,imm8
        (&[0xc4, 0xe2, 0x7d, 0x00, 0xc1], 5), // 3-byte VEX, 0f38 map, no imm
        (&[0xc4, 0xe3, 0x7d, 0x46, 0xc1, 0x20], 6), // vperm2i128 (0f3a map, imm8)
    ];
    for (bytes, expected) in cases {
        let (len, cat) = decode(bytes);
        assert_eq!(len, *expected, "length for {bytes:02x?}");
        assert_eq!(cat, None, "VEX opcodes are never forbidden: {bytes:02x?}");
    }
}

/// The class pairing is the independent objdump corpus below. These rows
/// check truncation and sentinel placement for its length determinants,
/// including rounding's L'L=3 and compressed disp8.
#[test]
fn measures_evex_lengths_and_reaches_following_forbidden_opcodes() {
    let cases: &[&[u8]] = &[
        &[0x62, 0xf1, 0x74, 0x48, 0x58, 0xc2], // vaddps zmm (register)
        &[0x62, 0xf1, 0x74, 0x09, 0x58, 0xc2], // vaddps xmm {k1}
        &[0x62, 0xf1, 0x74, 0x29, 0x58, 0xc2], // vaddps ymm {k1}
        &[0x62, 0xf1, 0x74, 0xc9, 0x58, 0xc2], // vaddps {k1}{z}
        &[0x62, 0xf1, 0x74, 0x78, 0x58, 0xc2], // vaddps {rz-sae}
        &[0x62, 0xf1, 0x74, 0x58, 0x58, 0x00], // broadcast, no displacement
        &[0x62, 0xf1, 0xfe, 0x48, 0x6f, 0x44, 0x24, 0x01], // SIB + disp8*N
        &[0x62, 0xf1, 0xfe, 0x48, 0x6f, 0x84, 0x88, 0x0f, 0x05, 0, 0], // SIB + disp32
        &[0x62, 0xf1, 0xfe, 0x48, 0x6f, 0x80, 0x0f, 0x05, 0, 0], // mod=2 disp32, no SIB
        &[0x62, 0xf1, 0xfe, 0x48, 0x6f, 0x04, 0x8d, 0x0f, 0x05, 0, 0], // SIB without base
        &[0x62, 0xf1, 0xfe, 0x48, 0x6f, 0x05, 0x0f, 0x05, 0, 0], // RIP-relative disp32
        &[0x64, 0x67, 0x62, 0xf1, 0xfe, 0x48, 0x6f, 0x40, 0x01], // fs + address size
        &[0x62, 0xf1, 0x7d, 0x48, 0x70, 0xc1, 0x05], // vpshufd imm8
        &[0x62, 0xf1, 0x7d, 0x48, 0x71, 0xd1, 0x05], // vpsrlw imm8
        &[0x62, 0xf1, 0x7d, 0x48, 0x72, 0xd1, 0x05], // vpsrld imm8
        &[0x62, 0xf1, 0xfd, 0x48, 0x73, 0xd1, 0x05], // vpsrlq imm8
        &[0x62, 0xf1, 0x74, 0x48, 0xc2, 0xca, 0x05], // vcmpps imm8
        &[0x62, 0xf1, 0x74, 0x48, 0xc6, 0xc2, 0x05], // vshufps imm8
        &[0x62, 0xf2, 0x75, 0x48, 0x8d, 0xc2], // vpermb (map 2)
        &[0x62, 0xf3, 0x75, 0x48, 0x0f, 0x44, 0x24, 0x01, 0x05], // vpalignr (map 3)
    ];
    for &bytes in cases {
        assert_eq!(decode_full(bytes), (bytes.len(), None), "{bytes:02x?}");
        for end in 0..bytes.len() {
            assert!(
                matches!(decode_one(&bytes[..end]), Step::Undecodable),
                "accepted truncated EVEX: {:02x?}",
                &bytes[..end]
            );
        }
        // Several displacements contain 0f 05. Only the appended real
        // syscall and rdtsc must be flagged, at their exact boundaries.
        let mut text = bytes.to_vec();
        text.extend([0x0f, 0x05, 0x0f, 0x31]);
        let mut escapes = Vec::new();
        scan_test(&text, &mut escapes);
        let found: Vec<_> = escapes
            .iter()
            .map(|e| (e.symbol.clone(), e.category, e.mnemonic))
            .collect();
        assert_eq!(
            found,
            vec![
                (
                    format!("instruction@.text+0x{:x}", bytes.len()),
                    "direct-syscall",
                    Some("syscall")
                ),
                (
                    format!("instruction@.text+0x{:x}", bytes.len() + 2),
                    "cpu-nondeterminism",
                    Some("rdtsc")
                ),
            ],
            "{bytes:02x?}"
        );
    }
}

/// Class pairing for the reserved legacy-immediate opcode refusals:
/// every legacy map-1 imm8 opcode is either refused in EVEX or measured
/// with its immediate, never silently shortened to a no-immediate body.
#[test]
fn evex_does_not_drop_legacy_map1_immediates() {
    for opcode in 0..=255 {
        let Some(attr) = two_byte(opcode) else {
            continue;
        };
        if !matches!(attr.imm, Imm::Fixed(1)) {
            continue;
        }
        let bytes = [0x62, 0xf1, 0x7d, 0x48, opcode, 0xc0, 0x05];
        match decode_one(&bytes) {
            Step::Undecodable => {}
            Step::Insn { len, cat } => {
                assert_eq!(len, bytes.len(), "map-1 opcode {opcode:02x}");
                assert_eq!(cat, None);
            }
        }
    }
    for opcode in [0x0f, 0xa4, 0xac, 0xba] {
        assert!(matches!(
            decode_one(&[0x62, 0xf1, 0x7d, 0x48, opcode, 0xc0, 0x05]),
            Step::Undecodable
        ));
    }
}

#[test]
fn evex_rejects_unsupported_maps_and_invalid_prefix_fields() {
    let valid = [0x62, 0xf1, 0x74, 0x48, 0x58, 0xc2]; // vaddps
    for map in (0..=15).filter(|map| !matches!(map, 1..=3)) {
        let mut bytes = valid;
        bytes[1] = 0xf0 | map;
        assert!(matches!(decode_one(&bytes), Step::Undecodable));
    }
    for (index, value) in [
        (1, 0xf9), // P0 bit 3 reserved
        (2, 0x70), // P1 bit 2 must be one
        (3, 0xc8), // z=1 with aaa=0
        (3, 0x68), // L'L=3 without embedded rounding
        (4, 0x77), // VEX-only vzero*: no EVEX form
    ] {
        let mut bytes = valid;
        bytes[index] = value;
        assert!(
            matches!(decode_one(&bytes), Step::Undecodable),
            "{bytes:02x?}"
        );
    }
    // With a memory operand, b means broadcast, not embedded rounding;
    // it cannot rescue the reserved vector length L'L=3.
    assert!(matches!(
        decode_one(&[0x62, 0xf1, 0x74, 0x78, 0x58, 0x00]),
        Step::Undecodable
    ));
    for prefix in [0x66, 0xf0, 0xf2, 0xf3, 0x40, 0x48, 0x4f] {
        let mut bytes = vec![prefix];
        bytes.extend(valid);
        assert!(
            matches!(decode_one(&bytes), Step::Undecodable),
            "{bytes:02x?}"
        );
    }
    // Legal segment prefixes cannot make an instruction exceed 15 bytes.
    let mut bytes = vec![0x64; 9];
    bytes.extend(valid);
    assert_eq!(decode_full(&bytes), (15, None));
    bytes.insert(0, 0x64);
    assert!(matches!(decode_one(&bytes), Step::Undecodable));
}

#[test]
fn decodes_legacy_three_byte_maps() {
    // The exact bytes the `sha2` x86 backend carries (used by guests for
    // an applied-sequence digest). Before the 0f 38/0f 3a
    // maps were length-decoded these all failed closed, refusing the binary
    // at the first `palignr` (`.text+0x42929`). Lengths are objdump-verified.
    let cases: &[(&[u8], usize)] = &[
        (&[0x66, 0x45, 0x0f, 0x3a, 0x0f, 0xec, 0x08], 7), // palignr (0f 3a 0f, imm8)
        (&[0x66, 0x44, 0x0f, 0x3a, 0x0e, 0xe0, 0xf0], 7), // pblendw (0f 3a 0e, imm8)
        (&[0x66, 0x0f, 0x3a, 0x22, 0xe1, 0x00], 6),       // pinsrd  (0f 3a 22, imm8)
        (&[0x66, 0x0f, 0x38, 0x00, 0xfd], 5),             // pshufb  (0f 38 00, no imm)
        (&[0x41, 0x0f, 0x38, 0xcb, 0xdd], 5),             // sha256rnds2 (0f 38 cb)
        (&[0x41, 0x0f, 0x38, 0xcc, 0xfe], 5),             // sha256msg1  (0f 38 cc)
        (&[0x41, 0x0f, 0x38, 0xcd, 0xf0], 5),             // sha256msg2  (0f 38 cd)
    ];
    for (bytes, expected) in cases {
        let (len, cat) = decode(bytes);
        assert_eq!(len, *expected, "length for {bytes:02x?}");
        assert_eq!(
            cat, None,
            "three-byte-map opcodes are never forbidden: {bytes:02x?}"
        );
    }
}

#[test]
fn forbidden_opcode_after_three_byte_map_is_still_caught() {
    // Decoding the 0f 38/0f 3a maps must not blunt the forbidden scan: a
    // `syscall` at the real boundary immediately after a `palignr` (the
    // encoding that used to halt the walk) must still be flagged, and the
    // walk must land on it at exactly the right offset (7 = palignr's len).
    let mut escapes = Vec::new();
    let text = [
        0x66, 0x45, 0x0f, 0x3a, 0x0f, 0xec, 0x08, // palignr (7 bytes)
        0x0f, 0x05, // syscall at offset 7
    ];
    scan_test(&text, &mut escapes);
    assert_eq!(escapes.len(), 1, "{escapes:?}");
    assert_eq!(escapes[0].category, "direct-syscall");
    assert_eq!(escapes[0].symbol, "instruction@.text+0x7");
}

/// Every x86-64 way to move the FS base without a syscall is a
/// thread-pointer finding: `wrfsbase` (32- and 64-bit, any REX.B), and the
/// FS selector loads `mov fs`, `pop fs` and `lfs`. The reads and the GS
/// writes beside them are not, and neither are the rest of group 15
/// (fences, state saves). RED: drop the group 15 resolution or the
/// selector rows and the writes decode as `None`.
#[test]
fn classifies_thread_pointer_writes() {
    let thread_pointer = super::super::THREAD_POINTER_CATEGORY;
    let writes: &[(&[u8], usize, &str)] = &[
        (&[0xf3, 0x48, 0x0f, 0xae, 0xd0], 5, "wrfsbase"), // wrfsbase rax
        (&[0xf3, 0x0f, 0xae, 0xd0], 4, "wrfsbase"),       // wrfsbase eax
        (&[0xf3, 0x49, 0x0f, 0xae, 0xd7], 5, "wrfsbase"), // wrfsbase r15
        (&[0x66, 0xf3, 0x48, 0x0f, 0xae, 0xd0], 6, "wrfsbase"), // extra prefix
        (&[0x8e, 0xe0], 2, "mov fs"),                     // mov fs, eax
        (&[0x8e, 0x20], 2, "mov fs"),                     // mov fs, [rax]
        (&[0x0f, 0xa1], 2, "pop fs"),                     // pop fs
        (&[0x0f, 0xb4, 0x00], 3, "lfs"),                  // lfs eax, [rax]
    ];
    for (bytes, len, mnemonic) in writes {
        assert_eq!(
            decode_full(bytes),
            (*len, Some((thread_pointer, *mnemonic))),
            "{bytes:02x?}"
        );
    }
    let neighbours: &[(&[u8], usize)] = &[
        (&[0xf3, 0x48, 0x0f, 0xae, 0xc0], 5), // rdfsbase rax
        (&[0xf3, 0x48, 0x0f, 0xae, 0xc8], 5), // rdgsbase rax
        (&[0xf3, 0x48, 0x0f, 0xae, 0xd8], 5), // wrgsbase rax
        (&[0x0f, 0xae, 0xe8], 3),             // lfence
        (&[0x0f, 0xae, 0xf0], 3),             // mfence
        (&[0x0f, 0xae, 0x10], 3),             // ldmxcsr [rax] (reg 2, memory)
        (&[0xf3, 0x0f, 0xae, 0x10], 4),       // repz ldmxcsr [rax] (f3, but memory)
        (&[0x0f, 0xae, 0x00], 3),             // fxsave [rax]
        (&[0x8e, 0xe8], 2),                   // mov gs, eax
        (&[0x8e, 0xd8], 2),                   // mov ds, eax
        (&[0x8c, 0xe0], 2),                   // mov eax, fs (a read)
        (&[0x0f, 0xa0], 2),                   // push fs
        (&[0x0f, 0xa9], 2),                   // pop gs
        (&[0x0f, 0xb5, 0x00], 3),             // lgs eax, [rax]
        (&[0x0f, 0xb6, 0xc0], 3),             // movzx eax, al
    ];
    for (bytes, len) in neighbours {
        assert_eq!(decode_full(bytes), (*len, None), "{bytes:02x?}");
    }
}

/// Identify EVEX in corpus bytes, not operand-embedded 62 bytes. This
/// helper counts encodings; decode_one separately validates their lengths.
fn corpus_evex_map(bytes: &[u8]) -> Option<u8> {
    let prefix_len = bytes
        .iter()
        .take_while(|b| {
            matches!(
                b,
                0x66 | 0x67 | 0xf0 | 0xf2 | 0xf3 | 0x2e | 0x36 | 0x3e | 0x26 | 0x64 | 0x65 | 0x40
                    ..=0x4f
            )
        })
        .count();
    bytes[prefix_len..]
        .strip_prefix(&[0x62])?
        .first()
        .map(|p0| p0 & 0x0f)
}

#[test]
fn corpus_evex_counter_handles_prefixes_but_not_operand_bytes() {
    let instruction = [0x62, 0xf1, 0x74, 0x48, 0x58, 0xc2];
    for prefixes in [
        &[][..],
        &[0x67],
        &[0x64],
        &[0x64, 0x67],
        &[0x2e, 0x67],
        &[0x64; 9],
    ] {
        let bytes = [prefixes, &instruction].concat();
        assert_eq!(corpus_evex_map(&bytes), Some(1), "{bytes:02x?}");
    }
    // A mov immediate containing an EVEX-looking prefix is not EVEX.
    assert_eq!(corpus_evex_map(&[0xb8, 0x62, 0xf1, 0x74, 0x48]), None);
    for bytes in [&[][..], &[0x67], &[0x67, 0x62]] {
        assert_eq!(corpus_evex_map(bytes), None);
    }
}

/// Checked-in bytes and boundaries assembled from Patina's own EVEX
/// source (regeneration in tests/fixtures/README.md). This class detector
/// pairs with the EVEX length/truncation/sentinel tests: the oracle is
/// objdump, not a second copy of our length rules. No x86 host, AVX-512
/// CPU, assembler, or external binary is needed to run it.
#[test]
fn x86_decoder_matches_objdump_corpus() {
    let corpus = include_str!("../tests/fixtures/x86-avx512.objdump");
    let mut data = Vec::new();
    let mut boundaries = Vec::new();
    let mut base = None;
    let mut evex_count = 0;
    let mut maps = std::collections::BTreeSet::new();
    for line in corpus.lines() {
        let Some((address, rest)) = line.trim_start().split_once(":\t") else {
            continue; // headings and labels, not instruction rows
        };
        let address = u64::from_str_radix(address, 16).expect("instruction address");
        let (hex, _) = rest.split_once('\t').expect("unwrapped objdump row");
        let bytes: Vec<_> = hex
            .split_whitespace()
            .map(|byte| u8::from_str_radix(byte, 16).expect("instruction byte"))
            .collect();
        assert!(!bytes.is_empty());
        assert_eq!(address, *base.get_or_insert(address) + data.len() as u64);
        boundaries.push((data.len(), bytes.len()));
        if let Some(map) = corpus_evex_map(&bytes) {
            evex_count += 1;
            maps.insert(map);
        }
        data.extend(bytes);
    }
    assert!(evex_count > 0, "corpus must exercise EVEX decoding");
    assert_eq!(maps, [1, 2, 3].into_iter().collect());
    let mut offset = 0;
    for &(start, length) in &boundaries {
        assert_eq!(offset, start);
        assert_eq!(decode_full(&data[offset..]), (length, None));
        offset += length;
    }
    assert_eq!(offset, data.len());
    // Exercise the whole scanner too: the real opcode after the corpus
    // must be reached, with no phantom findings from operand bytes.
    data.extend([0x0f, 0x05]);
    let mut escapes = Vec::new();
    scan_test(&data, &mut escapes);
    assert_eq!(escapes.len(), 1, "{escapes:?}");
    assert_eq!(escapes[0].category, "direct-syscall");
    assert_eq!(escapes[0].symbol, format!("instruction@.text+0x{offset:x}"));
    eprintln!(
        "x86 decoder matched objdump on {} instruction boundaries ({evex_count} EVEX)",
        boundaries.len()
    );
}

// Ground-truth corpus check: the length decoder must reproduce objdump's
// instruction boundaries exactly over a real `.text`, or it could desync
// (a wrong length silently steps over a real instruction — the same
// false-negative failure the byte-slide had). Ignored by default because
// it needs an x86-64 ELF and its `objdump -d -z -j .text` output; run in the
// amd64 container over the real std/glibc probe binaries:
//   PATINA_X86_CORPUS_ELF=/path/guest \
//   PATINA_X86_CORPUS_OBJDUMP=/path/guest.objdump \
//   cargo test -p patina-dst-target -- --ignored x86_decoder_matches_objdump
#[test]
#[ignore = "requires an x86-64 ELF + objdump corpus; run in the amd64 container"]
fn x86_decoder_matches_objdump_external_corpus() {
    use object::{Object, ObjectSection};
    use std::collections::BTreeSet;

    let elf_path =
        std::env::var("PATINA_X86_CORPUS_ELF").expect("set PATINA_X86_CORPUS_ELF to an x86-64 ELF");
    let objdump_path = std::env::var("PATINA_X86_CORPUS_OBJDUMP")
        .expect("set PATINA_X86_CORPUS_OBJDUMP to its `objdump -d -z -j .text` output");
    let bytes = std::fs::read(&elf_path).expect("read ELF");
    let file = object::File::parse(&*bytes).expect("parse ELF");
    let text = file
        .sections()
        .find(|s| s.name() == Ok(".text"))
        .expect(".text section");
    let base = text.address();
    let data = text.data().expect(".text data");

    // Golden boundaries: the address at the start of every objdump
    // instruction line (`  <hexaddr>:\t<bytes>\t<mnemonic>`), restricted to
    // this `.text`. Lines like `<addr> <name>:` (labels) and `\t...`
    // (elided zero runs) are not instruction starts and are skipped.
    //
    // GNU objdump wraps an instruction longer than 7 bytes onto a
    // continuation line — `  <hexaddr>:\t<more bytes>` with NO trailing
    // mnemonic — whose address is an interior byte, not a real boundary
    // (e.g. an 8-byte `cmpq [rip+d32],imm8` prints 7 bytes on its address
    // line and the 8th on a `+7:` continuation). Those must be skipped or
    // they inflate the golden set with phantom boundaries the decoder (which
    // treats the whole thing as one instruction) correctly lacks. A real
    // instruction line always has a second tab before the mnemonic; a
    // continuation line has only bytes, so require `rest` to contain a tab.
    let objdump = std::fs::read_to_string(&objdump_path).expect("read objdump");
    let mut golden = BTreeSet::new();
    let mut syscalls = BTreeSet::new();
    let mut evex_count = 0;
    for line in objdump.lines() {
        let trimmed = line.trim_start();
        if let Some((addr_hex, rest)) = trimmed.split_once(":\t") {
            let is_instruction_line = rest.contains('\t');
            if addr_hex.bytes().all(|c| c.is_ascii_hexdigit()) && is_instruction_line {
                if let Ok(addr) = u64::from_str_radix(addr_hex, 16) {
                    if addr >= base && addr < base + data.len() as u64 {
                        golden.insert(addr);
                        // Read the full instruction from the ELF, so
                        // prefixes wrapping onto objdump continuation
                        // rows cannot hide its EVEX prefix.
                        if corpus_evex_map(&data[(addr - base) as usize..]).is_some() {
                            evex_count += 1;
                        }
                        let (_, mnemonic) = rest.split_once('\t').unwrap();
                        if mnemonic.split_whitespace().next() == Some("syscall") {
                            syscalls.insert(format!("instruction@.text+0x{:x}", addr - base));
                        }
                    }
                }
            }
        }
    }
    assert!(
        golden.len() > 100,
        "objdump corpus looks too small ({} boundaries) — wrong file? \
                 (a real std `.text` has ~10^6; even a tiny probe has hundreds)",
        golden.len()
    );
    let first = *golden.iter().next().unwrap();
    let last = *golden.iter().next_back().unwrap();

    // Walk the decoder and collect its boundaries as absolute addresses.
    let mut decoded = BTreeSet::new();
    let mut offset = 0usize;
    while offset < data.len() {
        let addr = base + offset as u64;
        match decode_one(&data[offset..]) {
            Step::Insn { len, .. } => {
                if addr >= first && addr <= last {
                    decoded.insert(addr);
                }
                assert!(len > 0);
                offset += len;
            }
            Step::Undecodable => panic!(
                "decoder failed closed at {addr:#x} (offset {offset:#x}); \
                         the corpus should be fully decodable — bytes {:02x?}",
                &data[offset..(offset + 8).min(data.len())]
            ),
        }
    }

    // Over objdump's covered range the two boundary sets must be identical.
    // A decoder boundary objdump lacks means we split one instruction in
    // two; a missing one means we merged/overran two — either is a desync.
    let extra: Vec<_> = decoded.difference(&golden).take(5).collect();
    let missing: Vec<_> = golden.difference(&decoded).take(5).collect();
    assert!(
        extra.is_empty() && missing.is_empty(),
        "boundary mismatch vs objdump: {} extra {:#x?}, {} missing {:#x?}",
        decoded.difference(&golden).count(),
        extra,
        golden.difference(&decoded).count(),
        missing,
    );
    let mut escapes = Vec::new();
    scan_test(data, &mut escapes);
    assert!(
        escapes
            .iter()
            .all(|e| e.category != "undecodable-instruction")
    );
    let scanned_syscalls: BTreeSet<_> = escapes
        .iter()
        .filter(|e| e.mnemonic == Some("syscall"))
        .map(|e| e.symbol.clone())
        .collect();
    assert_eq!(scanned_syscalls, syscalls);
    eprintln!(
        "x86 decoder matched objdump on {} instruction boundaries ({evex_count} EVEX, {} syscalls) [{:#x}..={:#x}]",
        golden.len(),
        syscalls.len(),
        first,
        last
    );
}
