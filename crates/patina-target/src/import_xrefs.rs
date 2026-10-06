//! ELF and Mach-O import targets and instruction-reference attribution.

use crate::provenance::{
    NativeProvenance, NativeProvenanceIndex, bytes_to_string, normalize_provenance,
};
use crate::{code_ranges, x86_scan};
use object::{
    Architecture, BinaryFormat, Object, ObjectSection, ObjectSymbol, RelocationTarget, SectionKind,
    SymbolIndex,
};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn collect_import_provenance(
    file: &object::File<'_>,
    bytes: &[u8],
    provenance: &NativeProvenanceIndex,
    code_ranges: &code_ranges::CodeRanges,
) -> BTreeMap<String, Vec<NativeProvenance>> {
    let mut origins: BTreeMap<String, BTreeSet<NativeProvenance>> = BTreeMap::new();
    collect_section_relocation_provenance(file, provenance, &mut origins);

    let targets = collect_import_targets(file, bytes);
    if !targets.is_empty() {
        collect_import_xref_provenance(file, provenance, code_ranges, &targets, &mut origins);
    }

    origins
        .into_iter()
        .map(|(symbol, set)| (symbol, normalize_provenance(set.into_iter().collect())))
        .collect()
}

fn collect_section_relocation_provenance(
    file: &object::File<'_>,
    provenance: &NativeProvenanceIndex,
    origins: &mut BTreeMap<String, BTreeSet<NativeProvenance>>,
) {
    for section in file.sections() {
        let section_name = section.name().ok();
        for (offset, relocation) in section.relocations() {
            let RelocationTarget::Symbol(index) = relocation.target() else {
                continue;
            };
            let Some(symbol) = file
                .symbol_by_index(index)
                .ok()
                .and_then(|symbol| symbol.name().ok().map(str::to_owned))
            else {
                continue;
            };
            let address = section.address().saturating_add(offset);
            insert_origin(
                origins,
                &symbol,
                provenance.for_address(address, section_name),
            );
        }
    }
}

fn collect_import_targets(file: &object::File<'_>, bytes: &[u8]) -> BTreeMap<u64, String> {
    let mut targets = BTreeMap::new();
    collect_elf_import_targets(file, &mut targets);
    collect_macho_import_targets(file, bytes, &mut targets);
    targets
}

fn collect_elf_import_targets(file: &object::File<'_>, targets: &mut BTreeMap<u64, String>) {
    if !matches!(file.format(), BinaryFormat::Elf) {
        return;
    }

    let dyn_symbols = file
        .dynamic_symbols()
        .filter_map(|symbol| {
            symbol
                .name()
                .ok()
                .map(|name| (symbol.index().0, name.to_owned()))
        })
        .collect::<BTreeMap<usize, String>>();

    // A dynamic relocation only names an import at the address it patches, and
    // for a code reference that address is a GOT slot. Relocations landing
    // elsewhere (`.data.rel.ro` function-pointer tables and the like) are data
    // that happens to hold the address, not a call site, so treating them as
    // reference targets attributed unrelated code to the symbol.
    let got_ranges = file
        .sections()
        .filter_map(|section| {
            matches!(section.name().ok()?, ".got" | ".got.plt" | ".plt.got").then(|| {
                (
                    section.address(),
                    section.address().saturating_add(section.size()),
                )
            })
        })
        .collect::<Vec<_>>();
    let mut got_slots: BTreeMap<u64, String> = BTreeMap::new();
    if let Some(relocations) = file.dynamic_relocations() {
        for (address, relocation) in relocations {
            let RelocationTarget::Symbol(index) = relocation.target() else {
                continue;
            };
            let Some(symbol) = dyn_symbols.get(&index.0).cloned() else {
                continue;
            };
            if !got_ranges
                .iter()
                .any(|(start, end)| address >= *start && address < *end)
            {
                continue;
            }
            got_slots.insert(address, symbol);
        }
    }

    targets.extend(
        got_slots
            .iter()
            .map(|(address, symbol)| (*address, symbol.clone())),
    );
    collect_elf_plt_targets(file, &got_slots, targets);
}

/// Map each PLT stub address to the import it forwards to, so a `call foo@plt`
/// attributes to `foo`.
///
/// The stub is decoded, not counted: every entry indirects through its own GOT
/// slot, and that slot's dynamic relocation already names the symbol. Deriving
/// the mapping positionally instead — Nth stub gets the Nth jump slot — holds
/// only if the relocation list and the stub table correspond one to one, and they
/// routinely do not: `.got` GLOB_DAT entries for address-taken imports have no
/// stub at all, and glibc's ifuncs add IRELATIVE relocations that carry no
/// symbol. Each such entry shifts the rest of the table, so a single one
/// misattributes every call after it to the wrong import.
fn collect_elf_plt_targets(
    file: &object::File<'_>,
    got_slots: &BTreeMap<u64, String>,
    targets: &mut BTreeMap<u64, String>,
) {
    // Both architectures use 16-byte stubs. The section's leading header entry
    // (and the aarch64 header's second half) indirects through a reserved
    // `.got.plt` word that carries no symbol relocation, so it finds no match and
    // needs no special case.
    const ENTRY_SIZE: usize = 16;
    if got_slots.is_empty() {
        return;
    }
    for section in file.sections() {
        let Ok(name) = section.name() else {
            continue;
        };
        if !matches!(name, ".plt" | ".plt.sec" | ".plt.got" | ".iplt") {
            continue;
        }
        let Ok(data) = section.data() else {
            continue;
        };
        for (index, entry) in data.chunks(ENTRY_SIZE).enumerate() {
            let address = section.address() + (index * ENTRY_SIZE) as u64;
            let Some(slot) = decode_plt_stub_slot(file.architecture(), entry, address) else {
                continue;
            };
            let Some(symbol) = got_slots.get(&slot) else {
                continue;
            };
            targets.insert(address, symbol.clone());
        }
    }
}

/// The GOT slot a single PLT stub jumps through, or `None` when the entry is not
/// a recognizable stub for this architecture.
fn decode_plt_stub_slot(
    architecture: Architecture,
    entry: &[u8],
    entry_address: u64,
) -> Option<u64> {
    match architecture {
        // `jmp *disp32(%rip)`, at whatever offset the endbr64/bnd prefixes of the
        // entry's flavor leave it.
        Architecture::X86_64 => (0..entry.len().saturating_sub(5)).find_map(|offset| {
            (entry[offset] == 0xff && entry[offset + 1] == 0x25).then(|| {
                let displacement =
                    i32::from_le_bytes(entry[offset + 2..offset + 6].try_into().expect("4 bytes"));
                (entry_address + offset as u64 + 6).wrapping_add_signed(i64::from(displacement))
            })
        }),
        // `adrp x16, <page>` followed by `ldr x17, [x16, #<offset>]`.
        Architecture::Aarch64 => {
            let instructions = entry
                .chunks_exact(4)
                .map(|bytes| u32::from_le_bytes(bytes.try_into().expect("chunk has four bytes")))
                .collect::<Vec<_>>();
            instructions
                .windows(2)
                .enumerate()
                .find_map(|(index, pair)| {
                    let (register, page) =
                        aarch64_adrp_target(pair[0], entry_address + (index * 4) as u64)?;
                    aarch64_ldr_unsigned_target(pair[1], register, page)
                })
        }
        _ => None,
    }
}

fn collect_macho_import_targets(
    file: &object::File<'_>,
    bytes: &[u8],
    targets: &mut BTreeMap<u64, String>,
) {
    match file {
        object::File::MachO32(_) => collect_macho_import_targets_for::<
            object::macho::MachHeader32<object::Endianness>,
        >(bytes, 4, targets),
        object::File::MachO64(_) => collect_macho_import_targets_for::<
            object::macho::MachHeader64<object::Endianness>,
        >(bytes, 8, targets),
        _ => {}
    }
}

fn collect_macho_import_targets_for<Mach>(
    bytes: &[u8],
    pointer_size: u64,
    targets: &mut BTreeMap<u64, String>,
) where
    Mach: object::read::macho::MachHeader,
{
    use object::endian::U32;
    use object::read::ReadRef;
    use object::read::macho::{Nlist, Section, Segment};

    let Ok(header) = Mach::parse(bytes, 0) else {
        return;
    };
    let Ok(endian) = header.endian() else {
        return;
    };
    let Ok(mut commands) = header.load_commands(endian, bytes, 0) else {
        return;
    };

    let mut symtab = None;
    let mut dysymtab = None;
    let mut sections = Vec::new();
    while let Ok(Some(command)) = commands.next() {
        if let Ok(Some(command)) = command.symtab() {
            symtab = Some(command);
        }
        if let Ok(Some(command)) = command.dysymtab() {
            dysymtab = Some(command);
        }
        if let Ok(Some((segment, section_data))) = Mach::Segment::from_command(command) {
            if let Ok(segment_sections) = segment.sections(endian, section_data) {
                for section in segment_sections {
                    let section_type = section.section_type(endian);
                    if matches!(
                        section_type,
                        object::macho::S_NON_LAZY_SYMBOL_POINTERS
                            | object::macho::S_LAZY_SYMBOL_POINTERS
                            | object::macho::S_SYMBOL_STUBS
                    ) {
                        let entry_size = if section_type == object::macho::S_SYMBOL_STUBS {
                            u64::from(section.reserved2(endian)).max(1)
                        } else {
                            pointer_size
                        };
                        sections.push((
                            section.addr(endian).into(),
                            section.size(endian).into(),
                            section.reserved1(endian),
                            entry_size,
                        ));
                    }
                }
            }
        }
    }

    let (Some(symtab), Some(dysymtab)) = (symtab, dysymtab) else {
        return;
    };
    let Ok(symbols) = symtab.symbols::<Mach, _>(endian, bytes) else {
        return;
    };
    let indirect_offset = u64::from(dysymtab.indirectsymoff.get(endian));
    let indirect_count = dysymtab.nindirectsyms.get(endian) as usize;
    let Ok(indirect) = bytes.read_slice_at::<U32<Mach::Endian>>(indirect_offset, indirect_count)
    else {
        return;
    };

    for (address, size, first_indirect, entry_size) in sections {
        if entry_size == 0 {
            continue;
        }
        let count = size / entry_size;
        for index in 0..count {
            let indirect_index = first_indirect as usize + index as usize;
            let Some(symbol_index) = indirect.get(indirect_index) else {
                continue;
            };
            let symbol_index = symbol_index.get(endian);
            if symbol_index & object::macho::INDIRECT_SYMBOL_LOCAL != 0
                || symbol_index & object::macho::INDIRECT_SYMBOL_ABS != 0
            {
                continue;
            }
            let Ok(symbol) = symbols.symbol(SymbolIndex(symbol_index as usize)) else {
                continue;
            };
            let Ok(name) = symbol.name(endian, symbols.strings()) else {
                continue;
            };
            targets.insert(address + index * entry_size, bytes_to_string(name));
        }
    }
}

pub(super) fn collect_import_xref_provenance(
    file: &object::File<'_>,
    provenance: &NativeProvenanceIndex,
    code_ranges: &code_ranges::CodeRanges,
    targets: &BTreeMap<u64, String>,
    origins: &mut BTreeMap<String, BTreeSet<NativeProvenance>>,
) {
    for section in file.sections() {
        if section.kind() != SectionKind::Text {
            continue;
        }
        let Ok(data) = section.data() else {
            continue;
        };
        let section_name = section.name().ok();
        match file.architecture() {
            Architecture::Aarch64 => scan_aarch64_import_xrefs(
                data,
                section.address(),
                section_name,
                targets,
                provenance,
                origins,
            ),
            Architecture::X86_64 => {
                let whole_section = 0..data.len();
                for range in code_ranges
                    .get(section.index())
                    .unwrap_or(std::slice::from_ref(&whole_section))
                {
                    scan_x86_64_import_xrefs(
                        &data[range.clone()],
                        section.address() + range.start as u64,
                        section_name,
                        targets,
                        provenance,
                        origins,
                    );
                }
            }
            _ => {}
        }
    }
}

fn scan_aarch64_import_xrefs(
    data: &[u8],
    section_address: u64,
    section_name: Option<&str>,
    targets: &BTreeMap<u64, String>,
    provenance: &NativeProvenanceIndex,
    origins: &mut BTreeMap<String, BTreeSet<NativeProvenance>>,
) {
    let instructions = data
        .chunks_exact(4)
        .map(|bytes| u32::from_le_bytes(bytes.try_into().expect("chunk has four bytes")))
        .collect::<Vec<_>>();
    for (index, instruction) in instructions.iter().copied().enumerate() {
        let pc = section_address + index as u64 * 4;
        if let Some(target) = aarch64_branch_target(instruction, pc) {
            if let Some(symbol) = targets.get(&target) {
                insert_origin(origins, symbol, provenance.for_address(pc, section_name));
            }
        }
        let Some((register, page)) = aarch64_adrp_target(instruction, pc) else {
            continue;
        };
        let Some(next) = instructions.get(index + 1).copied() else {
            continue;
        };
        if let Some(target) = aarch64_ldr_unsigned_target(next, register, page) {
            if let Some(symbol) = targets.get(&target) {
                insert_origin(origins, symbol, provenance.for_address(pc, section_name));
            }
        }
    }
}

fn aarch64_branch_target(instruction: u32, pc: u64) -> Option<u64> {
    if instruction & 0x7c00_0000 != 0x1400_0000 {
        return None;
    }
    let offset = sign_extend((instruction & 0x03ff_ffff) as u64, 26) << 2;
    Some(pc.wrapping_add_signed(offset))
}

fn aarch64_adrp_target(instruction: u32, pc: u64) -> Option<(u32, u64)> {
    if instruction & 0x9f00_0000 != 0x9000_0000 {
        return None;
    }
    let immlo = ((instruction >> 29) & 0x3) as u64;
    let immhi = ((instruction >> 5) & 0x7ffff) as u64;
    let imm = sign_extend((immhi << 2) | immlo, 21) << 12;
    let page = (pc & !0xfff).wrapping_add_signed(imm);
    Some((instruction & 0x1f, page))
}

fn aarch64_ldr_unsigned_target(instruction: u32, base_register: u32, page: u64) -> Option<u64> {
    if instruction & 0xffc0_0000 != 0xf940_0000 {
        return None;
    }
    let rn = (instruction >> 5) & 0x1f;
    if rn != base_register {
        return None;
    }
    let imm = u64::from((instruction >> 10) & 0x0fff) * 8;
    Some(page + imm)
}

fn scan_x86_64_import_xrefs(
    data: &[u8],
    section_address: u64,
    section_name: Option<&str>,
    targets: &BTreeMap<u64, String>,
    provenance: &NativeProvenanceIndex,
    origins: &mut BTreeMap<String, BTreeSet<NativeProvenance>>,
) {
    let mut offset = 0usize;
    while offset < data.len() {
        // Undecodable bytes end this range's walk, costing attribution for its
        // tail. The containment scan independently refuses the same declared
        // range; both walks restart at each metadata entry point, not in data.
        let Some((len, reference)) = x86_scan::decode_reference(&data[offset..]) else {
            break;
        };
        if let Some(displacement) = reference {
            let target = (section_address + (offset + len) as u64)
                .wrapping_add_signed(i64::from(displacement));
            if let Some(symbol) = targets.get(&target) {
                insert_origin(
                    origins,
                    symbol,
                    provenance.for_address(section_address + offset as u64, section_name),
                );
            }
        }
        offset += len;
    }
}

fn insert_origin(
    origins: &mut BTreeMap<String, BTreeSet<NativeProvenance>>,
    symbol: &str,
    provenance: NativeProvenance,
) {
    origins
        .entry(symbol.to_string())
        .or_default()
        .insert(provenance);
}

fn sign_extend(value: u64, bits: u8) -> i64 {
    let shift = 64 - bits;
    ((value << shift) as i64) >> shift
}

#[cfg(test)]
mod tests;
