//! Declared x86-64 ELF code extents, not a control-flow/reachability proof.
//! Relocatable ELF (ET_REL) is refused on every architecture: object files are
//! not runnable guests, even when they have no unresolved unwind relocations.
//!
//! Each symbol/FDE retains its own start and end: unioning overlapping ranges
//! into one linear walk could discard a real entry point, while intersecting
//! them could hide bytes one source declares to be code. Exact duplicates alone
//! are removed. Only a sized STT_FUNC in a section's ordinary .symtab licenses
//! omitting gaps. Otherwise the whole-section scan is added, even with FDEs or
//! dynamic exports. NOTYPE labels and unsized functions add entry walks bounded
//! by every containing declaration, or the next entry/section end in a gap.
//! Malformed metadata is an error, never a reason to use a narrower source.
//!
//! Residuals: lying/short sizes, undeclared entries into gaps or operands, and
//! runtime-generated code can evade static discovery. Active Linux x86 SUD/TSC
//! traps backstop syscall/counter reads, not pre-trap startup. Entropy reads,
//! TLS writes and far transfers have no equivalent runtime trap; CPUID/PKRU
//! remain unmanaged. The full-section vsyscall pattern check cannot cover
//! computed addresses or generated code. See ESCAPE-CLASSES.md per class.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use gimli::{BaseAddresses, CieOrFde, EhFrame, RunTimeEndian, UnwindSection};
use object::{
    Architecture, BinaryFormat, Object, ObjectSection, ObjectSymbol, SectionKind, SymbolFlags,
    SymbolSection,
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
        // Reject object files before any architecture-specific range policy:
        // even no-CFI objects without .rela.eh_frame are not runnable guests.
        if file.format() == BinaryFormat::Elf && file.kind() == object::ObjectKind::Relocatable {
            return Err(TargetError::RelocatableElf);
        }
        let mut result = Self::default();
        if file.format() != BinaryFormat::Elf || file.architecture() != Architecture::X86_64 {
            return Ok(result);
        }
        let mut sections = Vec::new();
        for section in file.sections().filter(|s| s.kind() == SectionKind::Text) {
            let size = section.data().map_err(TargetError::Parse)?.len() as u64;
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
        let mut sized_symtab_sections = BTreeSet::new();
        for (symbol, symtab) in file
            .symbols()
            .map(|s| (s, true))
            .chain(file.dynamic_symbols().map(|s| (s, false)))
        {
            let SymbolFlags::Elf { st_info, .. } = symbol.flags() else {
                continue;
            };
            let kind = st_info & 0x0f;
            if !matches!(
                kind,
                object::elf::STT_FUNC | object::elf::STT_GNU_IFUNC | object::elf::STT_NOTYPE
            ) || matches!(
                symbol.section(),
                SymbolSection::Undefined | SymbolSection::Absolute | SymbolSection::Common
            ) {
                continue;
            }
            // Do not use ObjectSymbol::is_definition: it also excludes local
            // NOTYPE names beginning with '$', which can be real x86 entries.
            // A missing/invalid ordinary or extended section index is not a
            // non-text function. Validate it before selecting text coverage.
            let index = symbol
                .section_index()
                .ok_or_else(|| invalid("defined code entry has no resolved section index"))?;
            let declared_section = file.section_by_index(index).map_err(TargetError::Parse)?;
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
            if symbol.size() == 0 || kind == object::elf::STT_NOTYPE {
                if start < section.end {
                    unsized_starts.insert((section.index, (start - section.address) as usize));
                }
            } else {
                result.insert(section, start, end);
                if symtab && kind == object::elf::STT_FUNC {
                    sized_symtab_sections.insert(section.index);
                }
            }
        }
        if let Some(section) = file.section_by_name(".eh_frame") {
            validate_frame_relocations(file, section.index(), section.address(), section.size())?;
            let data = section.data().map_err(TargetError::Parse)?;
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
            while let Some(entry) = entries.next().map_err(TargetError::Unwind)? {
                let CieOrFde::Fde(partial) = entry else {
                    continue;
                };
                let fde = partial
                    .parse(EhFrame::cie_from_offset)
                    .map_err(TargetError::Unwind)?;
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
        // Untyped labels and zero-sized functions establish independent entries.
        // Preserve every containing declaration's endpoint, even when a shorter
        // declaration shares the start. In gaps, stop at the next known entry.
        // Only original declarations bound these suffixes, never inferred ranges
        // or the whole-section fallback added below.
        for section in &sections {
            let ranges = result.sections.entry(section.index).or_default();
            ranges.sort_unstable_by_key(|r| (r.start, r.end));
            ranges.dedup();
            let declared = ranges.clone();
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
                let ends: BTreeSet<_> = declared
                    .iter()
                    .filter(|r| r.contains(&start))
                    .map(|r| r.end)
                    .collect();
                if ends.is_empty() {
                    let end = starts
                        .range((start + 1)..)
                        .next()
                        .copied()
                        .unwrap_or((section.end - section.address) as usize);
                    ranges.push(start..end);
                } else {
                    ranges.extend(ends.into_iter().map(|end| start..end));
                }
            }
            // FDEs, dynsym functions and labels alone cannot justify omitting
            // gaps: ordinary toolchains leave real functions without unwind
            // records. Keep independent entry walks alongside the full scan.
            if !sized_symtab_sections.contains(&section.index) {
                ranges.push(0..(section.end - section.address) as usize);
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

    /// None means no range policy for this section (e.g. Mach-O): scan it whole.
    /// ELF sections lacking sized .symtab functions explicitly include that
    /// whole-section range alongside independent entry walks.
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
                .map_err(TargetError::Parse)?
                .expect("SHT_REL reader");
            entries.iter().any(|r| affects_frame(r.r_offset(endian)))
        } else {
            let (entries, _) = header
                .rela(endian, elf.data())
                .map_err(TargetError::Parse)?
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
    TargetError::InvalidCodeRanges(reason.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use object::write::{Object as WriteObject, Symbol, SymbolSection};
    use object::{Endianness, SymbolFlags, SymbolKind, SymbolScope};

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
        let symbols: Vec<_> = symbols
            .iter()
            .map(|&(start, size)| (start, size, SymbolKind::Text))
            .collect();
        elf_with_symbols(architecture, text, &symbols, unwind)
    }

    fn elf_with_symbols(
        architecture: Architecture,
        text: &[u8],
        symbols: &[(u64, u64, SymbolKind)],
        unwind: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut object = WriteObject::new(BinaryFormat::Elf, architecture, Endianness::Little);
        let section = object.add_section(Vec::new(), b".text".to_vec(), SectionKind::Text);
        object.append_section_data(section, text, 4);
        for (i, &(start, size, kind)) in symbols.iter().enumerate() {
            object.add_symbol(Symbol {
                name: format!("function_{i}").into_bytes(),
                value: start,
                size,
                kind,
                scope: SymbolScope::Linkage,
                weak: false,
                section: SymbolSection::Section(section),
                flags: if kind == SymbolKind::Unknown {
                    SymbolFlags::Elf {
                        st_info: object::elf::STB_GLOBAL << 4 | object::elf::STT_NOTYPE,
                        st_other: 0,
                    }
                } else {
                    SymbolFlags::None
                },
            });
        }
        if let Some(unwind) = unwind {
            let section =
                object.add_section(Vec::new(), b".eh_frame".to_vec(), SectionKind::ReadOnlyData);
            object.append_section_data(section, unwind, 8);
        }
        linked_elf(object)
    }

    // The writer emits ET_REL. These fixtures model linked address ranges, not
    // runnable programs; mark ET_EXEC so range tests exercise metadata policy
    // rather than the independent object-file refusal.
    fn linked_elf(object: WriteObject<'_>) -> Vec<u8> {
        let mut bytes = object.write().unwrap();
        bytes[16..18].copy_from_slice(&object::elf::ET_EXEC.to_le_bytes());
        bytes
    }

    fn scan(bytes: &[u8]) -> Result<Vec<crate::NativeEscape>, TargetError> {
        let file = object::File::parse(bytes).unwrap();
        let provenance = crate::NativeProvenanceIndex::new(&file);
        crate::scan_instruction_classes(&file, &provenance)
    }

    // Object files are not runnable guests, independently of whether they have
    // unwind records/relocations (handwritten no-CFI assembly often has neither).
    #[test]
    fn relocatable_elf_is_refused_with_or_without_unwind_metadata() {
        for architecture in [Architecture::X86_64, Architecture::Aarch64] {
            for unwind in [None, Some(&[0xff, 0xff, 0xff][..])] {
                let mut bytes = elf(architecture, RETURN_42, &[(0, 6)], unwind);
                bytes[16..18].copy_from_slice(&object::elf::ET_REL.to_le_bytes());
                let parsed = object::File::parse(&*bytes).unwrap();
                assert_eq!(parsed.kind(), object::ObjectKind::Relocatable);
                let error = crate::tests::audit_with_libc(&bytes, &BTreeSet::new())
                    .expect_err("a relocatable object is not a runnable guest");
                assert!(matches!(error, TargetError::RelocatableElf), "{error}");
                assert!(error.to_string().contains("ET_REL"), "{error}");
                assert!(scan(&bytes).unwrap_err().to_string().contains("ET_REL"));
            }
        }
    }

    #[test]
    fn inter_function_data_does_not_desynchronize_declared_code() {
        let text = text_with_tail(RETURN_42);
        let ranges = [(0, 6), (12, 6)];
        let unwind = eh_frame(&ranges);
        for (symbols, fdes) in [(&ranges[..], None), (&ranges[..], Some(&unwind[..]))] {
            let bytes = elf(Architecture::X86_64, &text, symbols, fdes);
            assert!(scan(&bytes).unwrap().is_empty());
            assert!(crate::tests::audit_with_libc(&bytes, &BTreeSet::new()).is_ok());
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
                assert!(
                    found
                        .iter()
                        .any(|e| e.category == category && e.symbol == "instruction@.text+0xc"),
                    "{found:?}"
                );
                assert_eq!(
                    found
                        .iter()
                        .any(|e| e.category == "undecodable-instruction"),
                    symbols.is_empty()
                );
                assert!(matches!(
                    crate::tests::audit_with_libc(&bytes, &BTreeSet::new()),
                    Err(TargetError::UnsupportedImports(_))
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
            crate::tests::audit_with_libc(&bytes, &BTreeSet::new()),
            Err(TargetError::UnsupportedImports(_))
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
                crate::tests::audit_with_libc(&bytes, &BTreeSet::new()),
                Err(TargetError::UnsupportedImports(_))
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

    // Class detector: declarations lacking sized .symtab functions must never
    // narrow the section walk, but still preserve independently declared starts.
    #[test]
    fn fde_only_and_unsized_only_sections_cannot_hide_code_in_gaps() {
        let text = [RETURN_42, &[0x0f, 0xc7, 0xf0, 0xc3]].concat();
        for symbols in [
            vec![],
            vec![(0, 0, SymbolKind::Text)],
            vec![(0, 0, SymbolKind::Unknown)],
        ] {
            let bytes = elf_with_symbols(
                Architecture::X86_64,
                &text,
                &symbols,
                Some(&eh_frame(&[(0, 6)])),
            );
            let found = scan(&bytes).unwrap();
            assert!(
                found.iter().any(|e| e.mnemonic == Some("rdrand")),
                "{found:?}"
            );
            assert!(crate::tests::audit_with_libc(&bytes, &BTreeSet::new()).is_err());
        }
    }

    #[test]
    fn sized_symbol_coverage_is_per_section_not_per_file() {
        let mut object =
            WriteObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
        for (name, text, value, size) in [
            (".text", &[0xc3][..], 0, 1),
            (".text.more", &[0x0f, 0xc7, 0xf0, 0xc3, 0xc3][..], 4, 0),
        ] {
            let section =
                object.add_section(Vec::new(), name.as_bytes().to_vec(), SectionKind::Text);
            object.append_section_data(section, text, 1);
            object.add_symbol(Symbol {
                name: name.as_bytes().to_vec(),
                value,
                size,
                kind: SymbolKind::Text,
                scope: SymbolScope::Linkage,
                weak: false,
                section: SymbolSection::Section(section),
                flags: SymbolFlags::None,
            });
        }
        assert!(
            scan(&linked_elf(object))
                .unwrap()
                .iter()
                .any(|e| e.mnemonic == Some("rdrand"))
        );
    }

    #[test]
    fn whole_section_fallback_preserves_alternate_entries() {
        let text = [
            0x48, 0xb8, 0x0f, 0xc7, 0xf0, 0x90, 0x90, 0x90, 0x90, 0x90, 0xc3,
        ];
        for kind in [SymbolKind::Text, SymbolKind::Unknown] {
            let bytes = elf_with_symbols(
                Architecture::X86_64,
                &text,
                &[(2, 0, kind)],
                Some(&eh_frame(&[(2, 3)])),
            );
            assert!(
                scan(&bytes)
                    .unwrap()
                    .iter()
                    .any(|e| e.mnemonic == Some("rdrand"))
            );
        }
    }

    // The NOTYPE gap/interior pins pair with this class-level variation over
    // instruction classes and declaration positions, not just one byte string.
    #[test]
    fn untyped_entries_in_gaps_and_operands_are_scanned() {
        for opcode in [
            &[0x0f, 0xc7, 0xf0][..],
            &[0x0f, 0x05],
            &[0xf3, 0x0f, 0xae, 0xd0],
            &[0xcb],
        ] {
            let mut operand = vec![0x48, 0xb8]; // movabs, with an alternate entry in its immediate
            operand.extend(opcode);
            operand.resize(10, 0x90);
            operand.push(0xc3);
            for (text, start, size) in [([RETURN_42, opcode].concat(), 6, 6), (operand, 2, 11)] {
                let bytes = elf_with_symbols(
                    Architecture::X86_64,
                    &text,
                    &[(0, size, SymbolKind::Text), (start, 0, SymbolKind::Unknown)],
                    None,
                );
                let found = scan(&bytes).unwrap();
                assert!(
                    found
                        .iter()
                        .any(|e| e.symbol == format!("instruction@.text+0x{start:x}")
                            && e.category != "undecodable-instruction"),
                    "{found:?}"
                );
                assert!(crate::tests::audit_with_libc(&bytes, &BTreeSet::new()).is_err());
            }
        }
    }

    #[test]
    fn untyped_entry_inside_a_sized_function_does_not_extend_into_data() {
        // Entry is the ret inside a function, followed by undecodable data.
        let bytes = elf_with_symbols(
            Architecture::X86_64,
            &text_with_tail(RETURN_42),
            &[
                (0, 6, SymbolKind::Text),
                (5, 0, SymbolKind::Unknown),
                (12, 6, SymbolKind::Text),
            ],
            None,
        );
        assert!(scan(&bytes).unwrap().is_empty());
        assert!(crate::tests::audit_with_libc(&bytes, &BTreeSet::new()).is_ok());
        let file = object::File::parse(&*bytes).unwrap();
        let ranges = CodeRanges::new(&file).unwrap();
        assert!(
            ranges
                .get(file.section_by_name(".text").unwrap().index())
                .unwrap()
                .contains(&(5..6))
        );
        // Even a shorter FDE sharing the label cannot truncate its enclosing
        // function suffix. Both endpoints remain independent scan limits.
        let text = [0x48, 0xb8, 0x90, 0x0f, 0xc7, 0xf0, 0x90, 0x90, 0x90, 0x90];
        let bytes = elf_with_symbols(
            Architecture::X86_64,
            &text,
            &[(0, 10, SymbolKind::Text), (2, 0, SymbolKind::Unknown)],
            Some(&eh_frame(&[(2, 1)])),
        );
        assert!(
            scan(&bytes)
                .unwrap()
                .iter()
                .any(|e| e.mnemonic == Some("rdrand"))
        );
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
                Err(TargetError::InvalidCodeRanges(_))
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
            Err(TargetError::Unwind(_))
        ));
        assert!(matches!(scan(&bytes), Err(TargetError::Unwind(_))));
        assert!(matches!(
            crate::tests::audit_with_libc(&bytes, &BTreeSet::new()),
            Err(TargetError::Unwind(_))
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
        linked_elf(object)
    }

    #[test]
    fn unrelocated_fde_addresses_cannot_select_code_ranges() {
        assert!(matches!(
            scan(&elf_with_unwind_relocation()),
            Err(TargetError::InvalidCodeRanges(_))
        ));
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
