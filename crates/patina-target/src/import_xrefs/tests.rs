//! ELF and Mach-O import targets and instruction-reference attribution tests.

use super::*;
use crate::provenance::NativeProvenanceIndex;
use crate::tests::elf_with_symbol_runs;
use object::Architecture;
use std::collections::BTreeMap;

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
