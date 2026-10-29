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
    let mut set = vec![crate::LoadedImage::new(
        "guest",
        std::borrow::Cow::Borrowed(bytes),
        crate::ImageRole::Executable,
    )];
    set.extend(images.into_iter().map(|(name, bytes, role)| {
        crate::LoadedImage::new(name, std::borrow::Cow::Owned(bytes), role)
    }));
    crate::LoadSet::new(set).expect("an executable first")
}

/// One dylib load command of a synthetic Mach-O image.
pub(super) struct MachODylibSpec<'a> {
    pub install_name: &'a str,
    pub weak: bool,
    pub reexport: bool,
}

/// One undefined symbol of a synthetic Mach-O image: its linker name, library
/// ordinal and whether it is a weak reference.
pub(super) struct MachOUndefined<'a> {
    pub name: &'a str,
    pub ordinal: u8,
    pub weak: bool,
}

/// A minimal linked arm64 Mach-O image, as ld64 lays one out: a `__TEXT`
/// segment whose `__text` section is one `ret`, an optional `LC_ID_DYLIB`,
/// the dylib load commands, and a symbol table with its defined externals
/// first and its undefined ones after (`LC_DYSYMTAB`). Two-level namespace.
pub(super) fn macho_image(
    install_name: Option<&str>,
    dylibs: &[MachODylibSpec<'_>],
    defined: &[&str],
    undefined: &[MachOUndefined<'_>],
) -> Vec<u8> {
    macho_image_with(
        install_name,
        dylibs,
        defined,
        undefined,
        MachOImports::Symbols,
    )
}

/// How a synthetic Mach-O image records what dyld binds.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum MachOImports {
    /// Undefined symbols in the symbol table, as before chained fixups.
    Symbols,
    /// A chained-fixups import table (`DYLD_CHAINED_IMPORT`), where an
    /// ordinal of `0xfd` is a weak-definition coalescing lookup; the symbol
    /// table carries no undefined symbols.
    Chained,
    /// Dyld-info bind records beside a symbol table stripped of its
    /// undefined symbols.
    StrippedWithBinds,
    /// Dyld-info weak (coalescing) bind records alone, as an image whose
    /// pointers address its own weak definitions has, with no undefined
    /// symbols.
    WeakBindsOnly,
}

/// [`macho_image`], recording its imports as `imports` says.
pub(super) fn macho_image_with(
    install_name: Option<&str>,
    dylibs: &[MachODylibSpec<'_>],
    defined: &[&str],
    undefined: &[MachOUndefined<'_>],
    imports: MachOImports,
) -> Vec<u8> {
    const LC_DYLD_CHAINED_FIXUPS: u32 = 0x8000_0034;
    const LC_DYLD_INFO_ONLY: u32 = 0x8000_0022;
    const LC_SEGMENT_64: u32 = 0x19;
    const LC_SYMTAB: u32 = 0x2;
    const LC_DYSYMTAB: u32 = 0xb;
    const LC_ID_DYLIB: u32 = 0xd;
    const LC_LOAD_DYLIB: u32 = 0xc;
    const LC_LOAD_WEAK_DYLIB: u32 = 0x8000_0018;
    const LC_REEXPORT_DYLIB: u32 = 0x8000_001f;
    let u32le = |out: &mut Vec<u8>, value: u32| out.extend_from_slice(&value.to_le_bytes());
    let u64le = |out: &mut Vec<u8>, value: u64| out.extend_from_slice(&value.to_le_bytes());
    let name16 = |name: &str| {
        let mut field = [0u8; 16];
        field[..name.len()].copy_from_slice(name.as_bytes());
        field
    };
    let dylib_command = |cmd: u32, name: &str| {
        let size = (24 + name.len() + 1).next_multiple_of(8);
        let mut out = Vec::new();
        u32le(&mut out, cmd);
        u32le(&mut out, size as u32);
        u32le(&mut out, 24);
        u32le(&mut out, 2);
        u32le(&mut out, 0x1_0000);
        u32le(&mut out, 0x1_0000);
        out.extend_from_slice(name.as_bytes());
        out.resize(size, 0);
        out
    };
    let mut commands: Vec<Vec<u8>> = Vec::new();
    // Offsets are patched once the command sizes are known.
    let segment_size = 72 + 80;
    commands.push(vec![0; segment_size]);
    if let Some(name) = install_name {
        commands.push(dylib_command(LC_ID_DYLIB, name));
    }
    for dylib in dylibs {
        let cmd = if dylib.reexport {
            LC_REEXPORT_DYLIB
        } else if dylib.weak {
            LC_LOAD_WEAK_DYLIB
        } else {
            LC_LOAD_DYLIB
        };
        commands.push(dylib_command(cmd, dylib.install_name));
    }
    let extra = match imports {
        MachOImports::Symbols => None,
        MachOImports::Chained => Some(commands.len()),
        MachOImports::StrippedWithBinds | MachOImports::WeakBindsOnly => Some(commands.len()),
    };
    match imports {
        MachOImports::Symbols => {}
        MachOImports::Chained => commands.push(vec![0; 16]),
        MachOImports::StrippedWithBinds | MachOImports::WeakBindsOnly => commands.push(vec![0; 48]),
    }
    let symbol_undefined: &[MachOUndefined<'_>] = if imports == MachOImports::Symbols {
        undefined
    } else {
        &[]
    };
    commands.push(vec![0; 24]);
    commands.push(vec![0; 80]);
    let sizeofcmds: usize = commands.iter().map(Vec::len).sum();
    let text_offset = (32 + sizeofcmds).next_multiple_of(16);
    let text_address = 0x1_0000_0000u64 + text_offset as u64;
    let symbols_offset = text_offset + 16;
    let mut strings = vec![b' ', 0];
    let mut symbols = Vec::new();
    let mut symbol = |name: &str, n_type: u8, n_sect: u8, n_desc: u16, value: u64| {
        let strx = strings.len() as u32;
        strings.extend_from_slice(name.as_bytes());
        strings.push(0);
        u32le(&mut symbols, strx);
        symbols.push(n_type);
        symbols.push(n_sect);
        symbols.extend_from_slice(&n_desc.to_le_bytes());
        u64le(&mut symbols, value);
    };
    for name in defined {
        symbol(name, 0x0f, 1, 0, text_address);
    }
    for reference in symbol_undefined {
        let desc = (u16::from(reference.ordinal) << 8) | if reference.weak { 0x40 } else { 0 };
        symbol(reference.name, 0x01, 0, desc, 0);
    }
    let nsyms = defined.len() + symbol_undefined.len();
    let strings_offset = symbols_offset + symbols.len();
    let blob_offset = (strings_offset + strings.len()).next_multiple_of(8);
    let mut blob = Vec::new();
    match imports {
        MachOImports::Symbols => {}
        MachOImports::Chained => {
            let count = undefined.len() as u32;
            let imports_offset = 28u32;
            let symbols_at = imports_offset + 4 * count;
            for value in [0, 0, imports_offset, symbols_at, count, 1, 0] {
                u32le(&mut blob, value);
            }
            let mut names = Vec::new();
            for reference in undefined {
                let entry = u32::from(reference.ordinal)
                    | (u32::from(reference.weak) << 8)
                    | ((names.len() as u32) << 9);
                u32le(&mut blob, entry);
                names.extend_from_slice(reference.name.as_bytes());
                names.push(0);
            }
            blob.extend_from_slice(&names);
        }
        MachOImports::StrippedWithBinds | MachOImports::WeakBindsOnly => {
            blob.extend_from_slice(&[0x40, 0x00])
        }
    }
    let file_size = blob_offset + blob.len();

    let mut segment = Vec::new();
    u32le(&mut segment, LC_SEGMENT_64);
    u32le(&mut segment, segment_size as u32);
    segment.extend_from_slice(&name16("__TEXT"));
    u64le(&mut segment, 0x1_0000_0000);
    u64le(&mut segment, file_size as u64);
    u64le(&mut segment, 0);
    u64le(&mut segment, file_size as u64);
    u32le(&mut segment, 5);
    u32le(&mut segment, 5);
    u32le(&mut segment, 1);
    u32le(&mut segment, 0);
    segment.extend_from_slice(&name16("__text"));
    segment.extend_from_slice(&name16("__TEXT"));
    u64le(&mut segment, text_address);
    u64le(&mut segment, 4);
    u32le(&mut segment, text_offset as u32);
    u32le(&mut segment, 2);
    u32le(&mut segment, 0);
    u32le(&mut segment, 0);
    u32le(&mut segment, 0x8000_0400);
    u32le(&mut segment, 0);
    u32le(&mut segment, 0);
    u32le(&mut segment, 0);
    commands[0] = segment;
    if let Some(index) = extra {
        let mut command = Vec::new();
        match imports {
            MachOImports::Chained => {
                u32le(&mut command, LC_DYLD_CHAINED_FIXUPS);
                u32le(&mut command, 16);
                u32le(&mut command, blob_offset as u32);
                u32le(&mut command, blob.len() as u32);
            }
            _ => {
                u32le(&mut command, LC_DYLD_INFO_ONLY);
                u32le(&mut command, 48);
                let (offset, size) = (blob_offset as u32, blob.len() as u32);
                // rebase, bind, then weak-bind offset/size.
                let fields = if imports == MachOImports::WeakBindsOnly {
                    [0, 0, 0, 0, offset, size]
                } else {
                    [0, 0, offset, size, 0, 0]
                };
                for value in fields {
                    u32le(&mut command, value);
                }
                command.resize(48, 0);
            }
        }
        commands[index] = command;
    }
    let count = commands.len();
    let mut symtab = Vec::new();
    u32le(&mut symtab, LC_SYMTAB);
    u32le(&mut symtab, 24);
    u32le(&mut symtab, symbols_offset as u32);
    u32le(&mut symtab, nsyms as u32);
    u32le(&mut symtab, strings_offset as u32);
    u32le(&mut symtab, strings.len() as u32);
    commands[count - 2] = symtab;
    let mut dysymtab = Vec::new();
    u32le(&mut dysymtab, LC_DYSYMTAB);
    u32le(&mut dysymtab, 80);
    for value in [
        0,
        0,
        0,
        defined.len() as u32,
        defined.len() as u32,
        symbol_undefined.len() as u32,
    ] {
        u32le(&mut dysymtab, value);
    }
    dysymtab.resize(80, 0);
    commands[count - 1] = dysymtab;

    let mut out = Vec::new();
    u32le(&mut out, 0xfeed_facf);
    u32le(&mut out, 0x0100_000c);
    u32le(&mut out, 0);
    u32le(&mut out, if install_name.is_some() { 6 } else { 2 });
    u32le(&mut out, count as u32);
    u32le(&mut out, sizeofcmds as u32);
    // MH_NOUNDEFS is not set; MH_DYLDLINK | MH_TWOLEVEL | MH_PIE.
    u32le(&mut out, 0x4 | 0x80 | 0x20_0000);
    u32le(&mut out, 0);
    for command in &commands {
        out.extend_from_slice(command);
    }
    out.resize(text_offset, 0);
    out.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
    out.resize(symbols_offset, 0);
    out.extend_from_slice(&symbols);
    out.extend_from_slice(&strings);
    out.resize(blob_offset, 0);
    out.extend_from_slice(&blob);
    out
}
