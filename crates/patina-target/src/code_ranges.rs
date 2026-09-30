//! Declared x86-64 ELF code extents, not a control-flow/reachability proof.
//!
//! Each symbol/FDE retains its own start and end: unioning overlapping ranges
//! into one linear walk could discard a real entry point, while intersecting
//! them could hide bytes one source declares to be code. Exact duplicates alone
//! are removed. Missing metadata uses the original whole-section scan; malformed
//! metadata is an error, never a reason to silently use a narrower source.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use gimli::{BaseAddresses, CieOrFde, EhFrame, RunTimeEndian, UnwindSection};
use object::{
    Architecture, BinaryFormat, Object, ObjectSection, ObjectSymbol, SectionKind, SymbolKind,
};

use super::TargetError;

#[derive(Default)]
pub(super) struct CodeRanges {
    sections: BTreeMap<usize, Vec<Range<usize>>>,
}

struct TextSection {
    index: usize,
    address: u64,
    end: u64,
}

impl CodeRanges {
    pub(super) fn new(file: &object::File<'_>) -> Result<Self, TargetError> {
        let mut result = Self::default();
        if file.format() != BinaryFormat::Elf || file.architecture() != Architecture::X86_64 {
            return Ok(result);
        }
        let mut sections = Vec::new();
        for section in file.sections().filter(|s| s.kind() == SectionKind::Text) {
            let size = section.data().map_err(TargetError::NativeParse)?.len() as u64;
            let end = section
                .address()
                .checked_add(size)
                .ok_or_else(|| invalid("text section address overflow"))?;
            sections.push(TextSection {
                index: section.index().0,
                address: section.address(),
                end,
            });
        }
        let mut unsized_starts = BTreeSet::new();
        for symbol in file.symbols().chain(file.dynamic_symbols()) {
            if symbol.kind() != SymbolKind::Text || !symbol.is_definition() {
                continue;
            }
            // A missing/invalid ordinary or extended section index is not a
            // non-text function. Validate it before selecting text coverage.
            let index = symbol
                .section_index()
                .ok_or_else(|| invalid("defined function has no resolved section index"))?;
            let declared_section = file
                .section_by_index(index)
                .map_err(TargetError::NativeParse)?;
            if declared_section.kind() != SectionKind::Text {
                continue;
            }
            let section = sections
                .iter()
                .find(|s| s.index == index.0)
                .expect("all text sections were indexed");
            let start = symbol.address();
            let end = start
                .checked_add(symbol.size())
                .ok_or_else(|| invalid("function symbol address overflow"))?;
            if start < section.address || end > section.end {
                return Err(invalid("function symbol extends outside its text section"));
            }
            if symbol.size() == 0 {
                if start < section.end {
                    unsized_starts.insert((section.index, (start - section.address) as usize));
                }
            } else {
                result.insert(section, start, end);
            }
        }
        if let Some(section) = file.section_by_name(".eh_frame") {
            validate_frame_relocations(file, section.index(), section.address(), section.size())?;
            let data = section.data().map_err(TargetError::NativeParse)?;
            let endian = if file.is_little_endian() {
                RunTimeEndian::Little
            } else {
                RunTimeEndian::Big
            };
            let mut frame = EhFrame::new(data, endian);
            frame.set_address_size(8);
            let mut bases = BaseAddresses::default().set_eh_frame(section.address());
            if let Some(text) = file.section_by_name(".text") {
                bases = bases.set_text(text.address());
            }
            if let Some(got) = file.section_by_name(".got") {
                bases = bases.set_got(got.address());
            }
            let mut entries = frame.entries(&bases);
            while let Some(entry) = entries.next().map_err(TargetError::NativeUnwind)? {
                let CieOrFde::Fde(partial) = entry else {
                    continue;
                };
                let fde = partial
                    .parse(EhFrame::cie_from_offset)
                    .map_err(TargetError::NativeUnwind)?;
                // Gimli returns the encoded slot address without dereferencing
                // DW_EH_PE_indirect. Scanning that slot would omit the real code.
                if fde
                    .cie()
                    .fde_address_encoding()
                    .is_some_and(|encoding| encoding.is_indirect())
                {
                    return Err(invalid("indirect FDE code addresses are unsupported"));
                }
                if fde.len() == 0 {
                    continue; // an empty FDE declares no executable bytes
                }
                let start = fde.initial_address();
                let end = start
                    .checked_add(fde.len())
                    .ok_or_else(|| invalid("FDE address overflow"))?;
                let section = sections
                    .iter()
                    .find(|s| start >= s.address && start < s.end)
                    .ok_or_else(|| invalid("FDE starts outside a text section"))?;
                if end > section.end {
                    return Err(invalid("FDE extends outside its text section"));
                }
                result.insert(section, start, end);
            }
        }
        // A zero-sized STT_FUNC still establishes an entry point. If a sized
        // symbol/FDE shares it, use that extent. Otherwise conservatively scan
        // through the next entry point (or section end), not just zero bytes.
        for section in &sections {
            let ranges = result.sections.entry(section.index).or_default();
            let starts: BTreeSet<_> = ranges
                .iter()
                .map(|r| r.start)
                .chain(
                    unsized_starts
                        .iter()
                        .filter(|(index, _)| *index == section.index)
                        .map(|(_, start)| *start),
                )
                .collect();
            for &(_, start) in unsized_starts
                .iter()
                .filter(|(index, _)| *index == section.index)
            {
                if ranges.iter().any(|r| r.start == start) {
                    continue;
                }
                let end = starts
                    .range((start + 1)..)
                    .next()
                    .copied()
                    .unwrap_or((section.end - section.address) as usize);
                ranges.push(start..end);
            }
            ranges.sort_unstable_by_key(|r| (r.start, r.end));
            ranges.dedup();
        }
        Ok(result)
    }

    fn insert(&mut self, section: &TextSection, start: u64, end: u64) {
        self.sections
            .entry(section.index)
            .or_default()
            .push((start - section.address) as usize..(end - section.address) as usize);
    }

    /// None means no boundaries for this section: scan the entire section, not
    /// zero bytes. Empty sections naturally have an empty whole-section range.
    pub(super) fn get(&self, index: object::SectionIndex) -> Option<&[Range<usize>]> {
        self.sections
            .get(&index.0)
            .filter(|ranges| !ranges.is_empty())
            .map(Vec::as_slice)
    }
}

/// The generic object relocation iterators are best-effort: they omit dynamic
/// tables and can turn unreadable payloads into empty iterators. Use the fallible
/// ELF readers instead. We do not apply relocations or follow runtime pointers.
fn validate_frame_relocations(
    file: &object::File<'_>,
    frame_index: object::SectionIndex,
    frame_address: u64,
    frame_size: u64,
) -> Result<(), TargetError> {
    use object::read::elf::{Rel, Rela, SectionHeader};
    let object::File::Elf64(elf) = file else {
        return Err(invalid("code ranges require ELF64"));
    };
    let endian = elf.endian();
    let frame_end = frame_address
        .checked_add(frame_size)
        .ok_or_else(|| invalid("unwind section address overflow"))?;
    for header in elf.elf_section_table().iter() {
        let kind = header.sh_type(endian);
        let entry_size = match kind {
            object::elf::SHT_REL => 16,
            object::elf::SHT_RELA => 24,
            object::elf::SHT_RELR
            | object::elf::SHT_CREL
            | object::elf::SHT_ANDROID_REL
            | object::elf::SHT_ANDROID_RELA
            | object::elf::SHT_ANDROID_RELR => {
                return Err(invalid(
                    "packed relocation tables are unsupported for unwind ranges",
                ));
            }
            _ => continue,
        };
        if header.sh_entsize(endian) != entry_size || header.sh_size(endian) % entry_size != 0 {
            return Err(invalid("invalid relocation table entry size"));
        }
        let associated = header.sh_info(endian) as usize == frame_index.0;
        let dynamic = header.sh_info(endian) == 0
            || header.sh_flags(endian) & u64::from(object::elf::SHF_ALLOC) != 0;
        let affects_frame =
            |offset| associated || (dynamic && offset >= frame_address && offset < frame_end);
        let affects = if kind == object::elf::SHT_REL {
            let (entries, _) = header
                .rel(endian, elf.data())
                .map_err(TargetError::NativeParse)?
                .expect("SHT_REL reader");
            entries.iter().any(|r| affects_frame(r.r_offset(endian)))
        } else {
            let (entries, _) = header
                .rela(endian, elf.data())
                .map_err(TargetError::NativeParse)?
                .expect("SHT_RELA reader");
            entries.iter().any(|r| affects_frame(r.r_offset(endian)))
        };
        if affects {
            return Err(invalid(
                "relocation targets .eh_frame; code addresses are unresolved",
            ));
        }
    }
    Ok(())
}

fn invalid(reason: &str) -> TargetError {
    TargetError::InvalidNativeCodeRanges(reason.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use object::write::{Object as WriteObject, Symbol, SymbolSection};
    use object::{Endianness, SymbolFlags, SymbolScope};

    // An anonymous compiler-output shape: a function, non-code attribution
    // bytes, then a second function. The marker is deliberately not decoded.
    const RETURN_42: &[u8] = &[0xb8, 42, 0, 0, 0, 0xc3];
    const DATA: &[u8] = b"OGAMS\0";

    fn text_with_tail(tail: &[u8]) -> Vec<u8> {
        [RETURN_42, DATA, tail].concat()
    }

    // Minimal DWARF32 .eh_frame, version-1 CIE with absolute 64-bit pointers.
    // These are our own records, not copied from a compiler's runtime.
    fn eh_frame(ranges: &[(u64, u64)]) -> Vec<u8> {
        let mut data = vec![12, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0x78, 16, 0, 0, 0];
        for &(start, size) in ranges {
            let cie_pointer = data.len() as u32 + 4;
            data.extend(20u32.to_le_bytes());
            data.extend(cie_pointer.to_le_bytes());
            data.extend(start.to_le_bytes());
            data.extend(size.to_le_bytes());
        }
        data.extend(0u32.to_le_bytes());
        data
    }

    fn elf(
        architecture: Architecture,
        text: &[u8],
        symbols: &[(u64, u64)],
        unwind: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut object = WriteObject::new(BinaryFormat::Elf, architecture, Endianness::Little);
        let section = object.add_section(Vec::new(), b".text".to_vec(), SectionKind::Text);
        object.append_section_data(section, text, 4);
        for (i, &(start, size)) in symbols.iter().enumerate() {
            object.add_symbol(Symbol {
                name: format!("function_{i}").into_bytes(),
                value: start,
                size,
                kind: SymbolKind::Text,
                scope: SymbolScope::Linkage,
                weak: false,
                section: SymbolSection::Section(section),
                flags: SymbolFlags::None,
            });
        }
        if let Some(unwind) = unwind {
            let section =
                object.add_section(Vec::new(), b".eh_frame".to_vec(), SectionKind::ReadOnlyData);
            object.append_section_data(section, unwind, 8);
        }
        object.write().unwrap()
    }

    fn scan(bytes: &[u8]) -> Result<Vec<crate::NativeEscape>, TargetError> {
        let file = object::File::parse(bytes).unwrap();
        let provenance = crate::NativeProvenanceIndex::new(&file);
        crate::scan_instruction_classes(&file, &provenance)
    }

    #[test]
    fn inter_function_data_does_not_desynchronize_declared_code() {
        let text = text_with_tail(RETURN_42);
        let ranges = [(0, 6), (12, 6)];
        let unwind = eh_frame(&ranges);
        for (symbols, fdes) in [
            (&ranges[..], None),
            (&[][..], Some(&unwind[..])),
            (&ranges[..], Some(&unwind[..])),
        ] {
            let bytes = elf(Architecture::X86_64, &text, symbols, fdes);
            assert!(scan(&bytes).unwrap().is_empty());
            assert!(crate::NativeAudit::audit(&bytes, &BTreeSet::new()).is_ok());
        }
    }

    // Class-level pairing: vary the forbidden class and the metadata source;
    // none may hide a forbidden instruction in a real function after data.
    #[test]
    fn functions_after_data_keep_every_forbidden_class() {
        let cases: &[(&[u8], &str)] = &[
            (&[0x0f, 0x05], "direct-syscall"),
            (&[0x0f, 0x31], "cpu-nondeterminism"),
            (&[0x0f, 0xc7, 0xf0], "cpu-nondeterminism"),
            (&[0x0f, 0xc7, 0xf8], "cpu-nondeterminism"),
            (&[0xf3, 0x0f, 0xae, 0xd0], "thread-pointer"),
            (&[0xcb], "far-transfer"),
        ];
        for &(opcode, category) in cases {
            let text = text_with_tail(opcode);
            let ranges = [(0, 6), (12, opcode.len() as u64)];
            let unwind = eh_frame(&ranges);
            for (symbols, fdes) in [(&ranges[..], None), (&[][..], Some(&unwind[..]))] {
                let bytes = elf(Architecture::X86_64, &text, symbols, fdes);
                let found = scan(&bytes).unwrap();
                assert_eq!(found.len(), 1, "{found:?}");
                assert_eq!(found[0].category, category);
                assert_eq!(found[0].symbol, "instruction@.text+0xc");
                assert!(matches!(
                    crate::NativeAudit::audit(&bytes, &BTreeSet::new()),
                    Err(TargetError::UnsupportedNativeImports(_))
                ));
            }
        }
    }

    #[test]
    fn data_inside_a_declared_function_is_a_refusal_not_a_resync() {
        let text = text_with_tail(&[0x0f, 0xc7, 0xf0]);
        let short = [(0, 6), (12, 3)];
        let enclosing = [(0, text.len() as u64)];
        let bytes = elf(Architecture::X86_64, &text, &enclosing, None);
        let found = scan(&bytes).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].category, "undecodable-instruction");
        assert!(matches!(
            crate::NativeAudit::audit(&bytes, &BTreeSet::new()),
            Err(TargetError::UnsupportedNativeImports(_))
        ));
        // Neither symbol nor FDE may shrink the other's declared code extent.
        for (symbols, fdes) in [(&enclosing[..], &short[..]), (&short[..], &enclosing[..])] {
            let bytes = elf(Architecture::X86_64, &text, symbols, Some(&eh_frame(fdes)));
            let found = scan(&bytes).unwrap();
            assert!(
                found
                    .iter()
                    .any(|e| e.category == "undecodable-instruction")
            );
            assert!(found.iter().any(|e| e.mnemonic == Some("rdrand")));
            assert!(matches!(
                crate::NativeAudit::audit(&bytes, &BTreeSet::new()),
                Err(TargetError::UnsupportedNativeImports(_))
            ));
        }
    }

    #[test]
    fn missing_metadata_keeps_the_whole_section_fail_closed() {
        let bytes = elf(Architecture::X86_64, &text_with_tail(RETURN_42), &[], None);
        assert!(
            scan(&bytes)
                .unwrap()
                .iter()
                .any(|e| e.category == "undecodable-instruction")
        );
        let bytes = elf(Architecture::X86_64, &[0x0f, 0xc7, 0xf0], &[], None);
        assert_eq!(scan(&bytes).unwrap()[0].mnemonic, Some("rdrand"));
    }

    #[test]
    fn gap_bytes_are_outside_the_declared_code_contract() {
        // Explicit residual, not a reachability claim: even a forbidden opcode
        // in an uncovered gap is not scanned when function metadata exists.
        let text = [RETURN_42, &[0x0f, 0xc7, 0xf0], RETURN_42].concat();
        let bytes = elf(Architecture::X86_64, &text, &[(0, 6), (9, 6)], None);
        assert!(scan(&bytes).unwrap().is_empty());
    }

    #[test]
    fn aarch64_still_scans_data_words_in_executable_sections() {
        let mut text = 0xd65f03c0u32.to_le_bytes().to_vec(); // ret
        text.extend(0xd53b2400u32.to_le_bytes()); // RNDR-shaped data outside function
        let bytes = elf(Architecture::Aarch64, &text, &[(0, 4)], None);
        assert_eq!(scan(&bytes).unwrap()[0].mnemonic, Some("rndr"));
    }

    #[test]
    fn invalid_metadata_is_not_downgraded_to_missing_metadata() {
        for ranges in [[(0, 7)], [(7, 1)], [(u64::MAX, 2)]] {
            let bytes = elf(Architecture::X86_64, RETURN_42, &ranges, None);
            let file = object::File::parse(&*bytes).unwrap();
            assert!(matches!(
                CodeRanges::new(&file),
                Err(TargetError::InvalidNativeCodeRanges(_))
            ));
            let bytes = elf(
                Architecture::X86_64,
                RETURN_42,
                &[(0, 6)],
                Some(&eh_frame(&ranges)),
            );
            let file = object::File::parse(&*bytes).unwrap();
            assert!(CodeRanges::new(&file).is_err());
        }
        let bytes = elf(
            Architecture::X86_64,
            RETURN_42,
            &[(0, 6)],
            Some(&[0xff, 0xff, 0xff]),
        );
        let file = object::File::parse(&*bytes).unwrap();
        assert!(matches!(
            CodeRanges::new(&file),
            Err(TargetError::NativeUnwind(_))
        ));
        assert!(matches!(scan(&bytes), Err(TargetError::NativeUnwind(_))));
        assert!(matches!(
            crate::NativeAudit::audit(&bytes, &BTreeSet::new()),
            Err(TargetError::NativeUnwind(_))
        ));
    }

    #[test]
    fn overlapping_entries_are_scanned_from_each_start_and_findings_are_unique() {
        // A mov immediate contains an independent declared entry. Merging the
        // ranges into a single walk would hide the inner rdrand instruction.
        let text = [0x48, 0xb8, 0x0f, 0xc7, 0xf0, 0, 0, 0, 0, 0];
        let bytes = elf(
            Architecture::X86_64,
            &text,
            &[(0, 10), (2, 3)],
            Some(&eh_frame(&[(2, 3)])),
        );
        let found = scan(&bytes).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].mnemonic, Some("rdrand"));
        assert_eq!(found[0].symbol, "instruction@.text+0x2");
    }

    #[test]
    fn an_instruction_cannot_borrow_operand_bytes_from_a_gap() {
        let text = [0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0];
        let bytes = elf(Architecture::X86_64, &text, &[(0, 2)], None);
        assert_eq!(scan(&bytes).unwrap()[0].category, "undecodable-instruction");
    }

    #[test]
    fn import_attribution_restarts_at_the_same_function_boundaries() {
        // The second function calls address 0x100 (relative to next IP 17).
        let text = text_with_tail(&[0xe8, 0xef, 0, 0, 0, 0xc3]);
        let bytes = elf(Architecture::X86_64, &text, &[(0, 6), (12, 6)], None);
        let file = object::File::parse(&*bytes).unwrap();
        let provenance = crate::NativeProvenanceIndex::new(&file);
        let ranges = CodeRanges::new(&file).unwrap();
        let targets = BTreeMap::from([(0x100, "some_import".to_owned())]);
        let mut origins = BTreeMap::new();
        crate::collect_import_xref_provenance(&file, &provenance, &ranges, &targets, &mut origins);
        let sites: Vec<_> = origins["some_import"].iter().collect();
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].containing_symbol.as_deref(), Some("function_1"));
    }

    // These encoding/reference regressions pair with the range-boundary class
    // detector invalid_metadata_is_not_downgraded_to_missing_metadata: malformed
    // or unresolved metadata must fail, not remove a declaration from coverage.
    #[test]
    fn indirect_fde_addresses_are_not_treated_as_instruction_addresses() {
        // CIE zR with DW_EH_PE_indirect | DW_EH_PE_absptr. Gimli preserves the
        // encoding but initial_address() is the slot, NOT its dereferenced value.
        let mut unwind = vec![
            16, 0, 0, 0, 0, 0, 0, 0, 1, b'z', b'R', 0, 1, 0x78, 16, 1, 0x80, 0, 0, 0,
        ];
        unwind.extend(24u32.to_le_bytes());
        unwind.extend(24u32.to_le_bytes()); // CIE pointer
        unwind.extend(0u64.to_le_bytes()); // address of pointer slot
        unwind.extend(4u64.to_le_bytes()); // real function length
        unwind.extend([0, 0, 0, 0]); // FDE augmentation length + padding
        unwind.extend(0u32.to_le_bytes());
        let mut text = vec![0x90; 20];
        text[..8].copy_from_slice(&16u64.to_le_bytes());
        text[16..].copy_from_slice(&[0x0f, 0xc7, 0xf0, 0xc3]); // real rdrand entry
        let bytes = elf(Architecture::X86_64, &text, &[], Some(&unwind));
        assert!(matches!(
            scan(&bytes),
            Err(TargetError::InvalidNativeCodeRanges(_))
        ));
    }

    #[test]
    fn invalid_symbol_section_indices_cannot_remove_declared_functions() {
        let text = [0xc3, 0x0f, 0xc7, 0xf0];
        for index in [100u16, object::elf::SHN_XINDEX] {
            let mut bytes = elf(Architecture::X86_64, &text, &[(0, 1), (1, 3)], None);
            let file = object::File::parse(&*bytes).unwrap();
            let symbol = file
                .symbols()
                .find(|s| s.name() == Ok("function_1"))
                .unwrap();
            let symtab = file.section_by_name(".symtab").unwrap();
            let at = symtab.file_range().unwrap().0 as usize + symbol.index().0 * 24 + 6;
            // ELF64 st_shndx: an out-of-range ordinary index, or SHN_XINDEX
            // without its required extended-index table. Keep one valid function
            // so dropping this entry would select a dangerously narrowed scan.
            bytes[at..at + 2].copy_from_slice(&index.to_le_bytes());
            assert!(
                scan(&bytes).is_err(),
                "accepted function section index {index}"
            );
            assert!(crate::NativeAudit::audit(&bytes, &BTreeSet::new()).is_err());
        }
    }

    fn elf_with_unwind_relocation() -> Vec<u8> {
        let mut object =
            WriteObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
        let text = object.add_section(Vec::new(), b".text".to_vec(), SectionKind::Text);
        object.append_section_data(text, RETURN_42, 1);
        let symbol = object.section_symbol(text);
        let unwind =
            object.add_section(Vec::new(), b".eh_frame".to_vec(), SectionKind::ReadOnlyData);
        object.append_section_data(unwind, &eh_frame(&[(0, 6)]), 8);
        object
            .add_relocation(
                unwind,
                object::write::Relocation {
                    offset: 24,
                    symbol,
                    addend: 0,
                    flags: object::RelocationFlags::Generic {
                        kind: object::RelocationKind::Absolute,
                        encoding: object::RelocationEncoding::Generic,
                        size: 64,
                    },
                },
            )
            .unwrap();
        object.write().unwrap()
    }

    fn relocation_header(bytes: &[u8]) -> usize {
        let file = object::File::parse(bytes).unwrap();
        let index = file.section_by_name(".rela.eh_frame").unwrap().index().0;
        let shoff = u64::from_le_bytes(bytes[40..48].try_into().unwrap()) as usize;
        shoff + index * 64 // ELF64 section header
    }

    #[test]
    fn unrelocated_fde_addresses_cannot_select_code_ranges() {
        assert!(matches!(
            scan(&elf_with_unwind_relocation()),
            Err(TargetError::InvalidNativeCodeRanges(_))
        ));
    }

    #[test]
    fn unreadable_relocations_are_not_an_empty_relocation_table() {
        let mut bytes = elf_with_unwind_relocation();
        let header = relocation_header(&bytes);
        bytes[header + 24..header + 32].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(scan(&bytes).is_err());
    }

    #[test]
    fn dynamic_relocations_cannot_rewrite_declared_code_addresses() {
        let mut bytes = elf_with_unwind_relocation();
        let header = relocation_header(&bytes);
        // Dynamic relocations have virtual-address offsets and no associated
        // target section (sh_info=0). The frame has VMA 0 in this synthetic ELF,
        // so offset 24 targets its FDE initial-address field in either form.
        bytes[header + 44..header + 48].copy_from_slice(&0u32.to_le_bytes());
        bytes[header + 8..header + 16]
            .copy_from_slice(&u64::from(object::elf::SHF_ALLOC).to_le_bytes());
        assert!(matches!(
            scan(&bytes),
            Err(TargetError::InvalidNativeCodeRanges(_))
        ));

        // A dynamic relocation elsewhere must not disable FDE coverage or
        // refuse an otherwise scanable file: only unwind storage is protected.
        let file = object::File::parse(&*bytes).unwrap();
        let at = file
            .section_by_name(".rela.eh_frame")
            .unwrap()
            .file_range()
            .unwrap()
            .0 as usize;
        bytes[at..at + 8].copy_from_slice(&0x1000u64.to_le_bytes());
        assert!(scan(&bytes).unwrap().is_empty());
    }

    #[test]
    fn unmeasured_relocation_table_formats_fail_closed() {
        let mut bytes = elf_with_unwind_relocation();
        let header = relocation_header(&bytes);
        bytes[header + 56..header + 64].copy_from_slice(&1u64.to_le_bytes()); // sh_entsize
        assert!(scan(&bytes).is_err());
        let mut bytes = elf_with_unwind_relocation();
        bytes[header + 4..header + 8].copy_from_slice(&object::elf::SHT_RELR.to_le_bytes());
        assert!(scan(&bytes).is_err());
    }

    #[test]
    fn zero_sized_entries_are_not_zero_byte_scans() {
        let bytes = elf(
            Architecture::X86_64,
            &[0x0f, 0xc7, 0xf0, 0xc3],
            &[(0, 0), (3, 1)],
            None,
        );
        assert_eq!(scan(&bytes).unwrap()[0].mnemonic, Some("rdrand"));
    }
}
