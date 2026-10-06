//! Shared native and WASI test fixtures.

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

pub(super) fn module_importing(module: &str, name: &str) -> Vec<u8> {
    let mut bytes = b"\0asm\x01\0\0\0".to_vec();
    // One () -> () function type.
    bytes.extend([1, 4, 1, 0x60, 0, 0]);
    let mut import = vec![1, module.len() as u8];
    import.extend(module.as_bytes());
    import.push(name.len() as u8);
    import.extend(name.as_bytes());
    import.extend([0, 0]); // function import, type index 0
    bytes.push(2);
    bytes.push(import.len() as u8);
    bytes.extend(import);
    bytes
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
