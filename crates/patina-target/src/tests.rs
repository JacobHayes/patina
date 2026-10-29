//! Shared test fixtures.

use crate::NativeEscape;
use crate::provenance::NativeProvenance;
use object::{Architecture, BinaryFormat, SectionKind, SymbolKind};

/// Build an instruction finding with a decoded mnemonic, as the scan does.
pub(super) fn instruction_finding(category: &'static str, mnemonic: &'static str) -> NativeEscape {
    NativeEscape::new(
        "instruction@.text+0x42".into(),
        category,
        vec![NativeProvenance::unknown()],
    )
    .with_mnemonic(mnemonic)
}

/// Build an ELF image whose symbol table has the shape a linker produces: a
/// run of local symbols, each introduced by the STT_FILE marker naming its
/// input object, and then the global symbols — which follow the whole local
/// run and therefore sit under no marker at all.
///
/// `locals` is `(file, symbol, address, size)`; `globals` is
/// `(symbol, address, size)`.
pub(super) fn elf_with_symbol_runs(
    locals: &[(&str, &str, u64, u64)],
    globals: &[(&str, u64, u64)],
) -> Vec<u8> {
    use object::write::{Object as WriteObject, Symbol as WriteSymbol, SymbolSection};
    use object::{Endianness, SymbolFlags, SymbolScope};

    let mut object = WriteObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    let text = object.add_section(Vec::new(), b".text".to_vec(), SectionKind::Text);
    object.append_section_data(text, &[0x90; 0x200], 16);

    let mut current_file = None;
    for (file, symbol, address, size) in locals {
        if current_file != Some(*file) {
            current_file = Some(*file);
            object.add_symbol(WriteSymbol {
                name: file.as_bytes().to_vec(),
                value: 0,
                size: 0,
                kind: SymbolKind::File,
                scope: SymbolScope::Compilation,
                weak: false,
                section: SymbolSection::None,
                flags: SymbolFlags::None,
            });
        }
        object.add_symbol(WriteSymbol {
            name: symbol.as_bytes().to_vec(),
            value: *address,
            size: *size,
            kind: SymbolKind::Text,
            scope: SymbolScope::Compilation,
            weak: false,
            section: SymbolSection::Section(text),
            flags: SymbolFlags::None,
        });
    }
    for (symbol, address, size) in globals {
        object.add_symbol(WriteSymbol {
            name: symbol.as_bytes().to_vec(),
            value: *address,
            size: *size,
            kind: SymbolKind::Text,
            scope: SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(text),
            flags: SymbolFlags::None,
        });
    }
    object.write().expect("synthesized ELF is writable")
}

/// Build a dynamically-linked-shaped ELF64 x86_64 executable carrying a
/// `.dynsym` (what `imports()` reads) and a `.symtab` (the rest of the audited
/// closure). Each entry is `(name, weak, defined)`.
pub(super) fn elf_with_symbol_bindings(
    dynamic: &[(&str, bool, bool)],
    statics: &[(&str, bool, bool)],
) -> Vec<u8> {
    // (symbols, strings) for one ELF64 symbol table, index 0 being the
    // mandatory null entry.
    fn table(symbols: &[(&str, bool, bool)]) -> (Vec<u8>, Vec<u8>) {
        let mut strings = vec![0u8];
        let mut entries = vec![0u8; 24];
        for (name, weak, defined) in symbols {
            let st_name = strings.len() as u32;
            strings.extend_from_slice(name.as_bytes());
            strings.push(0);
            // st_info = (bind << 4) | type; STB_WEAK(2)/STB_GLOBAL(1), STT_FUNC(2).
            let st_info = (if *weak { 2u8 } else { 1u8 } << 4) | 2;
            // A definition lives in .text (section 1); a reference is SHN_UNDEF.
            let (st_shndx, st_size): (u16, u64) = if *defined { (1, 4) } else { (0, 0) };
            entries.extend_from_slice(&st_name.to_le_bytes());
            entries.push(st_info);
            entries.push(0); // st_other
            entries.extend_from_slice(&st_shndx.to_le_bytes());
            entries.extend_from_slice(&0u64.to_le_bytes()); // st_value
            entries.extend_from_slice(&st_size.to_le_bytes());
        }
        (entries, strings)
    }

    let text = [0x90u8; 16]; // nops: nothing the instruction scan forbids
    let shstr: &[u8] = b"\0.text\0.dynsym\0.dynstr\0.symtab\0.strtab\0.shstrtab\0";
    let (dynsym, dynstr) = table(dynamic);
    let (symtab, strtab) = table(statics);
    let align8 = |value: u64| (value + 7) & !7;

    let text_off = 64u64;
    let dynsym_off = text_off + text.len() as u64;
    let dynstr_off = dynsym_off + dynsym.len() as u64;
    let symtab_off = align8(dynstr_off + dynstr.len() as u64);
    let strtab_off = symtab_off + symtab.len() as u64;
    let shstr_off = strtab_off + strtab.len() as u64;
    let shoff = align8(shstr_off + shstr.len() as u64);

    let mut elf = Vec::new();
    elf.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
    elf.extend_from_slice(&[0u8; 8]);
    elf.extend_from_slice(&2u16.to_le_bytes()); // e_type = ET_EXEC
    elf.extend_from_slice(&62u16.to_le_bytes()); // e_machine = EM_X86_64
    elf.extend_from_slice(&1u32.to_le_bytes()); // e_version
    elf.extend_from_slice(&0u64.to_le_bytes()); // e_entry
    elf.extend_from_slice(&0u64.to_le_bytes()); // e_phoff
    elf.extend_from_slice(&shoff.to_le_bytes()); // e_shoff
    elf.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    elf.extend_from_slice(&64u16.to_le_bytes()); // e_ehsize
    elf.extend_from_slice(&0u16.to_le_bytes()); // e_phentsize
    elf.extend_from_slice(&0u16.to_le_bytes()); // e_phnum
    elf.extend_from_slice(&64u16.to_le_bytes()); // e_shentsize
    elf.extend_from_slice(&7u16.to_le_bytes()); // e_shnum
    elf.extend_from_slice(&6u16.to_le_bytes()); // e_shstrndx -> .shstrtab
    assert_eq!(elf.len(), 64, "ELF64 header is 64 bytes");

    elf.extend_from_slice(&text);
    elf.extend_from_slice(&dynsym);
    elf.extend_from_slice(&dynstr);
    while (elf.len() as u64) < symtab_off {
        elf.push(0);
    }
    elf.extend_from_slice(&symtab);
    elf.extend_from_slice(&strtab);
    elf.extend_from_slice(shstr);
    while (elf.len() as u64) < shoff {
        elf.push(0);
    }

    #[allow(clippy::too_many_arguments)]
    let mut push_shdr = |name: u32,
                         typ: u32,
                         flags: u64,
                         offset: u64,
                         size: u64,
                         link: u32,
                         info: u32,
                         addralign: u64,
                         entsize: u64| {
        elf.extend_from_slice(&name.to_le_bytes());
        elf.extend_from_slice(&typ.to_le_bytes());
        elf.extend_from_slice(&flags.to_le_bytes());
        elf.extend_from_slice(&0u64.to_le_bytes()); // sh_addr
        elf.extend_from_slice(&offset.to_le_bytes());
        elf.extend_from_slice(&size.to_le_bytes());
        elf.extend_from_slice(&link.to_le_bytes());
        elf.extend_from_slice(&info.to_le_bytes());
        elf.extend_from_slice(&addralign.to_le_bytes());
        elf.extend_from_slice(&entsize.to_le_bytes());
    };
    push_shdr(0, 0, 0, 0, 0, 0, 0, 0, 0); // 0: SHN_UNDEF
    // 1: .text — SHT_PROGBITS(1), SHF_ALLOC|SHF_EXECINSTR.
    push_shdr(1, 1, 0x2 | 0x4, text_off, text.len() as u64, 0, 0, 4, 0);
    // 2: .dynsym — SHT_DYNSYM(11), linked to .dynstr, one local (the null entry).
    push_shdr(7, 11, 0x2, dynsym_off, dynsym.len() as u64, 3, 1, 8, 24);
    // 3: .dynstr — SHT_STRTAB(3).
    push_shdr(15, 3, 0x2, dynstr_off, dynstr.len() as u64, 0, 0, 1, 0);
    // 4: .symtab — SHT_SYMTAB(2), linked to .strtab.
    push_shdr(23, 2, 0, symtab_off, symtab.len() as u64, 5, 1, 8, 24);
    // 5: .strtab — SHT_STRTAB(3).
    push_shdr(31, 3, 0, strtab_off, strtab.len() as u64, 0, 0, 1, 0);
    // 6: .shstrtab — SHT_STRTAB(3).
    push_shdr(39, 3, 0, shstr_off, shstr.len() as u64, 0, 0, 1, 0);

    elf
}

/// Audit `bytes` as a program whose libc (a host image) defines every name it
/// leaves undefined, unversioned: the load set a unit test means when it is
/// about the executable alone.
pub(super) fn audit_with_libc(
    bytes: &[u8],
    allow: &std::collections::BTreeSet<String>,
) -> Result<crate::NativeAudit, crate::TargetError> {
    use object::{Object, ObjectSymbol};
    let Ok(file @ object::File::Elf64(_)) = object::File::parse(bytes) else {
        return crate::NativeAudit::audit(&crate::LoadSet::executable_only("guest", bytes), allow);
    };
    let names: Vec<String> = file
        .dynamic_symbols()
        .filter(|symbol| symbol.is_undefined())
        .filter_map(|symbol| symbol.name().ok().map(str::to_owned))
        .collect();
    let exports: Vec<(&str, bool, bool)> = names
        .iter()
        .map(|name| (name.as_str(), false, true))
        .collect();
    let libc = elf_with_symbol_bindings(&exports, &[]);
    crate::NativeAudit::audit(
        &load_set(bytes, vec![("libc.so.6", libc, crate::ImageRole::Host)]),
        allow,
    )
}

/// A load set of the executable `bytes` and `images` after it, in order.
pub(super) fn load_set<'a>(
    bytes: &'a [u8],
    images: Vec<(&str, Vec<u8>, crate::ImageRole)>,
) -> crate::LoadSet<'a> {
    let mut set = vec![crate::LoadedImage {
        name: "guest".into(),
        bytes: std::borrow::Cow::Borrowed(bytes),
        role: crate::ImageRole::Executable,
    }];
    set.extend(
        images
            .into_iter()
            .map(|(name, bytes, role)| crate::LoadedImage {
                name: name.into(),
                bytes: std::borrow::Cow::Owned(bytes),
                role,
            }),
    );
    crate::LoadSet::new(set).expect("an executable first")
}
