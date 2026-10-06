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

// Nested symbols: the tightest container names the site. This is the shape a
// linked ELF really produces — a global function laid out inside the span of
// a local region symbol, which is the one that carries an object — and
// ranking object provenance ahead of precision made the enclosing region win,
// naming a symbol that merely surrounds the site instead of the function
// holding it.
#[test]
fn elf_containing_symbol_is_the_tightest_enclosing_symbol() {
    let bytes = elf_with_symbol_runs(
        &[("shim.c", "outer_region", 0x10, 0x80)],
        &[("_RNvCslpz1a3WbgXx_8leaker_a4addr", 0x40, 0x10)],
    );
    let file = object::File::parse(&*bytes).expect("synthesized ELF parses");
    let index = NativeProvenanceIndex::new(&file);
    assert_eq!(
        index
            .for_address(0x44, Some(".text"))
            .containing_symbol
            .as_deref(),
        Some("_RNvCslpz1a3WbgXx_8leaker_a4addr")
    );
    assert_eq!(
        index
            .for_address(0x20, Some(".text"))
            .containing_symbol
            .as_deref(),
        Some("outer_region")
    );
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
        crate_name_from_demangled_path("std::io::Write::write_all").as_deref(),
        Some("std")
    );
    assert_eq!(
        crate_name_from_demangled_path("<alloc::vec::Vec<T> as core::ops::Drop>::drop").as_deref(),
        Some("alloc")
    );
    assert_eq!(
        crate_name_from_demangled_path("*const std::ffi::c_void::method").as_deref(),
        Some("std")
    );
    assert_eq!(
        crate_name_from_demangled_path("<T as core::fmt::Debug>::fmt"),
        None
    );
    assert_eq!(
        crate_name_from_demangled_path("<u32 as core::fmt::Display>::fmt"),
        None
    );
    assert_eq!(crate_name_from_demangled_path("{{closure}}"), None);
}

// An object with no name is not attribution. An ELF file symbol may carry an
// empty name, and rendering that produced a bare `object=` with nothing after
// it — the arm64 flavor of the same wrong answer x86_64 gave by borrowing the
// last marker in the table. Both the marker and the label collapse to
// `unknown` instead.
#[test]
fn an_empty_object_name_is_reported_as_unknown_not_as_an_empty_label() {
    assert_eq!(compact_object_label("", None), UNKNOWN_OBJECT);
    assert_eq!(compact_object_label("", Some("")), UNKNOWN_OBJECT);
    assert_eq!(compact_object_label("libfoo.rlib", Some("")), "libfoo.rlib");

    let bytes = elf_with_symbol_runs(
        &[("", "unnamed_file_local", 0x10, 0x10)],
        &[("_RNvCslpz1a3WbgXx_8leaker_a4addr", 0x80, 0x10)],
    );
    let file = object::File::parse(&*bytes).expect("synthesized ELF parses");
    let index = NativeProvenanceIndex::new(&file);
    for address in [0x18, 0x88] {
        let provenance = index.for_address(address, Some(".text"));
        assert_eq!(
            provenance.object, UNKNOWN_OBJECT,
            "an empty file symbol names no object at {address:#x}"
        );
        assert!(
            !provenance.label().contains("object="),
            "an unnamed object must not be rendered at all: {}",
            provenance.label()
        );
    }
}

// rustc names each codegen unit `<crate>.<hash>-cgu.<n>`, and that name is
// what the linker copies into the ELF file symbol — the readable half of
// ELF's object identity. Local-crate units are named by hash alone and must
// not be mined for a crate name.
#[test]
fn codegen_unit_names_yield_a_crate_only_when_they_carry_one() {
    assert_eq!(
        crate_name_from_codegen_unit("std.1e3c4ec04c5261a9-cgu.0").as_deref(),
        Some("std")
    );
    assert_eq!(
        crate_name_from_codegen_unit("compiler_builtins.fb155c23557db162-cgu.000").as_deref(),
        Some("compiler_builtins")
    );
    assert_eq!(
        crate_name_from_codegen_unit("9hzrs7df61h1scw4v1u1kzqy5"),
        None
    );
    assert_eq!(crate_name_from_codegen_unit("crtstuff.c"), None);
    assert_eq!(crate_name_from_codegen_unit("patina_posix.c"), None);
}

// A section name is the one field every site can fill in, so counting it as
// attribution kept each unattributable reference as its own
// `provenance=unknown` group instead of collapsing into one — and kept those
// groups alive alongside the real ones.
#[test]
fn section_only_provenance_collapses_and_yields_to_real_attribution() {
    let site = |section: &str| NativeProvenance {
        object: UNKNOWN_OBJECT.into(),
        crate_name: None,
        containing_symbol: None,
        section: Some(section.into()),
    };
    assert_eq!(
        normalize_provenance(vec![site(".text"), site(".data")]),
        vec![NativeProvenance::unknown()]
    );

    let attributed = NativeProvenance {
        object: "libfoo-1234abcd.rlib(foo.o)".into(),
        crate_name: Some("foo".into()),
        containing_symbol: Some("foo::bar".into()),
        section: Some(".text".into()),
    };
    assert_eq!(
        normalize_provenance(vec![site(".text"), attributed.clone()]),
        vec![attributed]
    );
}
