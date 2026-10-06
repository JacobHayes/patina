//! ELF and Mach-O import targets and instruction-reference attribution tests.

use super::*;
use crate::provenance::NativeProvenanceIndex;
use crate::tests::elf_with_symbol_runs;
use object::{Architecture, BinaryFormat, Object};
use std::collections::BTreeMap;

// Each stub is mapped by the slot it jumps through, not by its position in
// the table. The two here jump through slots in the opposite order to their
// position, so a positional mapping and a decoded one cannot agree — which is
// the failure that had every `call foo@plt` site in a real binary attributed
// to an unrelated import, and imports reported as referenced from functions
// (`fputs`, `puts`) that never touched them.
#[test]
fn plt_entries_map_by_the_slot_they_jump_through_not_by_position() {
    use object::write::{Object as WriteObject, StandardSegment};
    use object::{Endianness, SectionKind};

    // Entry 0 is a reserved header that is not a stub at all; entry 1 jumps
    // through the higher slot and entry 2 through the lower one.
    let mut plt = vec![0xcc; 16];
    plt.extend_from_slice(&[0xff, 0x25]);
    plt.extend_from_slice(&0x3ff2_i32.to_le_bytes());
    plt.extend_from_slice(&[0xcc; 10]);
    plt.extend_from_slice(&[0xff, 0x25]);
    plt.extend_from_slice(&0x3fda_i32.to_le_bytes());
    plt.extend_from_slice(&[0xcc; 10]);

    let mut object = WriteObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    let section = object.add_section(
        object.segment_name(StandardSegment::Text).to_vec(),
        b".plt".to_vec(),
        SectionKind::Text,
    );
    object.append_section_data(section, &plt, 16);
    let bytes = object.write().expect("synthesized ELF is writable");
    let file = object::File::parse(&*bytes).expect("synthesized ELF parses");
    let base = file
        .sections()
        .find(|section| section.name() == Ok(".plt"))
        .expect("the .plt section survives the round trip")
        .address();

    let higher = base + 0x16 + 0x3ff2;
    let lower = base + 0x26 + 0x3fda;
    assert!(
        higher > lower,
        "the fixture only discriminates if slot order is the reverse of entry order"
    );
    let got_slots = BTreeMap::from([
        (lower, "lower_slot".to_owned()),
        (higher, "higher_slot".to_owned()),
    ]);

    let mut targets = BTreeMap::new();
    collect_elf_plt_targets(&file, &got_slots, &mut targets);
    assert_eq!(
        targets,
        BTreeMap::from([
            (base + 0x10, "higher_slot".to_owned()),
            (base + 0x20, "lower_slot".to_owned()),
        ]),
        "counting entries off against slot order would swap these two"
    );
}

// PLT stubs are decoded through their own GOT slot rather than counted off
// positionally, so an entry that carries no symbol relocation (a reserved
// header word, an ifunc's IRELATIVE) cannot shift the rest of the table onto
// the wrong imports.
#[test]
fn plt_stubs_resolve_through_the_got_slot_they_jump_through() {
    // `jmp *0x2fda(%rip)` at 0x1020: RIP after the 6-byte instruction is
    // 0x1026, so the slot is 0x4000.
    let mut lazy = vec![0xff, 0x25];
    lazy.extend_from_slice(&0x2fda_i32.to_le_bytes());
    assert_eq!(
        decode_plt_stub_slot(Architecture::X86_64, &lazy, 0x1020),
        Some(0x4000)
    );

    // A `.plt.sec` entry: `endbr64` then `bnd jmp *0x2fd1(%rip)`. The jump
    // starts at offset 5, so RIP is 0x1020 + 5 + 6 = 0x102b.
    let mut endbr = vec![0xf3, 0x0f, 0x1e, 0xfa, 0xf2, 0xff, 0x25];
    endbr.extend_from_slice(&0x2fd5_i32.to_le_bytes());
    assert_eq!(
        decode_plt_stub_slot(Architecture::X86_64, &endbr, 0x1020),
        Some(0x4000)
    );

    // aarch64: `adrp x16, 0x4000` then `ldr x17, [x16, #0x18]`.
    let aarch64: Vec<u8> = [0xf000_0010_u32, 0xf940_0e11]
        .iter()
        .flat_map(|instruction| instruction.to_le_bytes())
        .collect();
    assert_eq!(
        decode_plt_stub_slot(Architecture::Aarch64, &aarch64, 0x1000),
        Some(0x4018)
    );

    // Padding is not a stub.
    assert_eq!(
        decode_plt_stub_slot(Architecture::X86_64, &[0xcc; 16], 0x1020),
        None
    );
}

// Import references are read at instruction boundaries, so displacement bytes
// sitting inside another instruction's operand are never mistaken for one.
// The planted `movabs` below carries the exact encoding of a RIP-relative
// load of `phantom_import` in its 8-byte immediate: a scan that matched the
// pattern at every byte offset reported that import as referenced from
// whatever function contained these bytes.
#[test]
fn import_xrefs_ignore_reference_bytes_embedded_in_an_operand() {
    const SECTION: u64 = 0x1000;
    let mut data = vec![0x48, 0xb8];
    // imm64 = `mov rax, [rip+0xff8]` as data — resolving, if decoded at
    // offset 2, to 0x1008 + 0xff8 = 0x2000.
    data.extend_from_slice(&[0x8b, 0x05, 0xf8, 0x0f, 0x00, 0x00, 0x00, 0x00]);
    // A genuine `mov rax, [rip+0x1fef]` at a real boundary (offset 0xa):
    // 0x1011 + 0x1fef = 0x3000.
    data.extend_from_slice(&[0x48, 0x8b, 0x05, 0xef, 0x1f, 0x00, 0x00]);

    let targets = BTreeMap::from([
        (0x2000_u64, "phantom_import".to_owned()),
        (0x3000_u64, "real_import".to_owned()),
    ]);
    let file = elf_with_symbol_runs(&[("caller.c", "caller", SECTION, 0x40)], &[]);
    let file = object::File::parse(&*file).expect("synthesized ELF parses");
    let index = NativeProvenanceIndex::new(&file);

    let mut origins = BTreeMap::new();
    scan_x86_64_import_xrefs(
        &data,
        SECTION,
        Some(".text"),
        &targets,
        &index,
        &mut origins,
    );
    assert_eq!(
        origins.keys().collect::<Vec<_>>(),
        vec!["real_import"],
        "only the reference at a real instruction boundary counts"
    );
}
