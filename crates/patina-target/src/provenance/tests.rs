//! Native address attribution and object, crate, and symbol provenance tests.

use super::*;
use crate::tests::elf_with_symbol_runs;

// The ELF root cause. A STT_FILE marker names the input object of the LOCAL
// symbols that follow it, and ELF puts every local before the first global,
// so no marker reaches a global symbol. Carrying the last one forward anyway
// stamped every global in the image with whichever object happened to be last
// in the local run — the `object=crtstuff.c` / `object=ucmpti2.c` findings, up
// to and including groups that contradicted themselves
// (`crate=leaker_a object=crtstuff.c`). Locals keep their real object;
// globals report no object rather than a borrowed one.
#[test]
fn elf_file_symbols_never_reach_past_their_own_local_run() {
    let bytes = elf_with_symbol_runs(
        &[
            ("shim.c", "shim_helper", 0x10, 0x10),
            ("ucmpti2.c", "builtin_helper", 0x30, 0x10),
        ],
        &[("_RNvCslpz1a3WbgXx_8leaker_a4addr", 0x80, 0x10)],
    );
    let file = object::File::parse(&*bytes).expect("synthesized ELF parses");
    let index = NativeProvenanceIndex::new(&file);

    let local = index.for_address(0x18, Some(".text"));
    assert_eq!(local.object, "shim.c");
    assert_eq!(local.containing_symbol.as_deref(), Some("shim_helper"));

    let last_local = index.for_address(0x38, Some(".text"));
    assert_eq!(last_local.object, "ucmpti2.c");

    // The regression pin: this global follows `ucmpti2.c` in the table but
    // belongs to neither file symbol.
    let global = index.for_address(0x88, Some(".text"));
    assert_eq!(
        global.object, UNKNOWN_OBJECT,
        "a global symbol must not inherit the last file symbol in the table"
    );
    assert_eq!(global.crate_name.as_deref(), Some("leaker_a"));
    assert_eq!(
        global.containing_symbol.as_deref(),
        Some("_RNvCslpz1a3WbgXx_8leaker_a4addr")
    );
    assert_eq!(
        global.label(),
        "provenance=crate=leaker_a",
        "an unrecorded object is omitted, never rendered as a borrowed one"
    );
}

// The linker demotes a hidden global to a local and lists it inside its own
// file's run or after the last one, so it can follow a marker that is not its
// object's (`crtstuff.c` in a real guest, ahead of aws-lc's functions). Its
// visibility drops the marker for that symbol alone; the run goes on.
#[test]
fn a_demoted_hidden_symbol_does_not_inherit_the_last_file_marker() {
    use object::write::{Object as WriteObject, Symbol, SymbolSection};
    use object::{Architecture, BinaryFormat, Endianness, SectionKind, SymbolScope};

    let mut object = WriteObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    let text = object.add_section(Vec::new(), b".text".to_vec(), SectionKind::Text);
    object.append_section_data(text, &[0x90; 0x100], 16);
    for (name, kind, address, st_other) in [
        ("crtstuff.c", SymbolKind::File, 0, object::elf::STV_DEFAULT),
        (
            "frame_dummy",
            SymbolKind::Text,
            0x10,
            object::elf::STV_DEFAULT,
        ),
        (
            "demoted_helper",
            SymbolKind::Text,
            0x40,
            object::elf::STV_HIDDEN,
        ),
        (
            "later_local",
            SymbolKind::Text,
            0x60,
            object::elf::STV_DEFAULT,
        ),
    ] {
        let st_type = if kind == SymbolKind::File {
            object::elf::STT_FILE
        } else {
            object::elf::STT_FUNC
        };
        object.add_symbol(Symbol {
            name: name.as_bytes().to_vec(),
            value: address,
            size: if kind == SymbolKind::File { 0 } else { 0x10 },
            kind,
            scope: SymbolScope::Compilation,
            weak: false,
            section: if kind == SymbolKind::File {
                SymbolSection::None
            } else {
                SymbolSection::Section(text)
            },
            flags: SymbolFlags::Elf {
                st_info: object::elf::STB_LOCAL << 4 | st_type,
                st_other,
            },
        });
    }
    let bytes = object.write().expect("synthesized ELF is writable");
    let file = object::File::parse(&*bytes).expect("synthesized ELF parses");
    let index = NativeProvenanceIndex::new(&file);
    assert_eq!(index.for_address(0x18, Some(".text")).object, "crtstuff.c");
    let demoted = index.for_address(0x48, Some(".text"));
    assert_eq!(demoted.object, UNKNOWN_OBJECT);
    assert_eq!(demoted.containing_symbol.as_deref(), Some("demoted_helper"));
    assert_eq!(index.for_address(0x68, Some(".text")).object, "crtstuff.c");
}

// The bounded lookup must answer exactly what a scan of every entry answers:
// it only skips entries whose running reach proves they end before the
// address. The planted tables have a huge early container (whose reach keeps
// every later lookup's lower bound at 0), nested sized symbols, zero-size
// labels on and off sized entries, and equal-precision twins that differ only
// in object provenance, so the first-best tie-break and the sized-beats-label
// rule are both exercised at every address.
#[test]
fn bounded_provenance_lookup_matches_a_full_scan() {
    let entry = |address: u64, size: u64, object: Option<&str>, symbol: &str| AddressProvenance {
        address,
        size,
        object_path: object.map(str::to_owned),
        archive_member: None,
        symbol: Some(symbol.to_owned()),
    };
    let tables = [
        vec![
            entry(0x10, 0x20, Some("a.o"), "small_first"),
            entry(0x40, 0, None, "label_alone"),
            entry(0x40, 0x10, None, "sized_at_label"),
            entry(0x48, 0x04, None, "nested"),
            entry(0x48, 0x04, Some("b.o"), "nested_twin_with_object"),
            entry(0x60, 0, Some("c.o"), "label_with_object"),
            entry(0x60, 0, None, "label_twin"),
            entry(0x70, 0x08, None, "after_gap"),
        ],
        vec![
            entry(0x08, 0x1000, Some("big.o"), "huge_early_container"),
            entry(0x20, 0x10, None, "inside_huge"),
            entry(0x20, 0x10, Some("d.o"), "inside_huge_twin"),
            entry(0x90, 0, None, "label_in_huge"),
            entry(0x2000, 0x10, None, "past_huge"),
        ],
    ];
    for mut entries in tables {
        entries.sort_by_key(|entry| (entry.address, entry.size));
        let reference = |address: u64| {
            let mut best: Option<&AddressProvenance> = None;
            for entry in entries
                .iter()
                .filter(|entry| address_in_entry(address, entry))
            {
                if best.is_none_or(|current| entry_better(entry, current)) {
                    best = Some(entry);
                }
            }
            best.and_then(|entry| entry.symbol.clone())
        };
        let expected: Vec<_> = (0..0x2020).map(reference).collect();
        let index = NativeProvenanceIndex::from_sorted(entries);
        for (address, expected) in (0..0x2020u64).zip(expected) {
            assert_eq!(
                index.for_address(address, Some(".text")).containing_symbol,
                expected,
                "address {address:#x}"
            );
        }
    }
}

// Impl methods dominate a real symbol table, and their demangled form starts
// with the impl header rather than the crate. Reading only the first `::`
// segment left `crate=` empty for most of a binary — every `std` finding in
// the reproduction came through as `provenance=` with an object alone.
#[test]
fn crate_name_recovers_from_impl_method_and_generic_symbols() {
    assert_eq!(
        crate_name_from_symbol("_RNvCslpz1a3WbgXx_8leaker_a4addr").as_deref(),
        Some("leaker_a")
    );
    assert_eq!(
            crate_name_from_symbol(
                "_RNvXs1_NtNtNtCs2AWtUsOyxgP_3std2os4unix7processNtNtBb_7process5ChildNtB5_8ChildExt18kill_process_group"
            )
            .as_deref(),
            Some("std")
        );

    // Direct path cases, including the ones that must NOT yield a crate: a
    // generic parameter and a primitive are not crates.
    assert_eq!(
        crate_name_from_demangled_path("<alloc::vec::Vec<T> as core::ops::Drop>::drop").as_deref(),
        Some("alloc")
    );
    assert_eq!(
        crate_name_from_demangled_path("<T as core::fmt::Debug>::fmt"),
        None
    );
    // A codegen unit's file symbol names its crate unless it is hash-only.
    assert_eq!(
        crate_name_from_codegen_unit("std.1e3c4ec04c5261a9-cgu.0").as_deref(),
        Some("std")
    );
    assert_eq!(
        crate_name_from_codegen_unit("9hzrs7df61h1scw4v1u1kzqy5"),
        None
    );
}
