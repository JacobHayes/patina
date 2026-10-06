//! Native import auditing and inert undefined-weak bindings tests.

use super::*;
use crate::TargetError;
use crate::report::render_inert_weak_imports;
use std::collections::BTreeSet;

/// Build a dynamically-linked-shaped ELF64 x86_64 executable carrying a
/// `.dynsym` (what `imports()` reads) and a `.symtab` (the rest of the audited
/// closure). Each entry is `(name, weak, defined)`.
fn elf_with_symbol_bindings(
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

// The fixture itself must present the shape the rule reasons about, or every
// assertion below would be vacuous: the undefined entries have to reach
// `imports()`, and the weak/defined bits have to survive the round trip.
#[test]
fn symbol_binding_fixture_presents_real_weak_and_defined_bindings() {
    let bytes = elf_with_symbol_bindings(
        &[("weak_undef", true, false), ("strong_undef", false, false)],
        &[("weak_def", true, true)],
    );
    let file = object::File::parse(&*bytes).expect("synthesized ELF parses");
    let imports: Vec<String> = file
        .imports()
        .expect("imports parse")
        .into_iter()
        .map(|import| String::from_utf8_lossy(import.name()).into_owned())
        .collect();
    assert_eq!(imports, vec!["weak_undef", "strong_undef"]);
    let weak: Vec<(String, bool, bool)> = file
        .dynamic_symbols()
        .chain(file.symbols())
        .filter_map(|symbol| symbol.name().ok().filter(|name| !name.is_empty()))
        .zip(
            file.dynamic_symbols()
                .chain(file.symbols())
                .filter(|symbol| symbol.name().is_ok_and(|name| !name.is_empty()))
                .map(|symbol| (symbol.is_weak(), symbol.is_definition())),
        )
        .map(|(name, (weak, defined))| (name.to_owned(), weak, defined))
        .collect();
    assert_eq!(
        weak,
        vec![
            ("weak_undef".to_owned(), true, false),
            ("strong_undef".to_owned(), false, false),
            ("weak_def".to_owned(), true, true),
        ]
    );
}

// Undefined weak imports are inert. aws-lc references its allocator-override
// hooks (`OPENSSL_memory_alloc`/`_free`/`_get_size`/`_realloc`) and `sdallocx`
// weakly: nothing in the link defines them, so each resolves to NULL and the
// referencing code takes its guarded default path. A NULL that cannot be
// called is not a door to the host, so refusing them is a false positive —
// they are reported under their own heading instead, keeping the surface
// visible without demanding an `--allow` that would ALSO clear a real
// definition of the same name if one ever appeared.
#[test]
fn undefined_weak_imports_are_inert_not_refused() {
    let hooks = [
        "OPENSSL_memory_alloc",
        "OPENSSL_memory_free",
        "OPENSSL_memory_get_size",
        "OPENSSL_memory_realloc",
        "sdallocx",
    ];
    let dynamic: Vec<(&str, bool, bool)> = hooks.iter().map(|name| (*name, true, false)).collect();
    let bytes = elf_with_symbol_bindings(&dynamic, &[]);
    let audit = NativeAudit::audit(&bytes, &BTreeSet::new())
        .expect("undefined weak imports must not refuse the audit");
    assert_eq!(
        audit.inert_weak_imports, hooks,
        "each rescued import must be reported under the inert-weak heading"
    );
    for hook in hooks {
        assert!(
            audit.imports.iter().any(|import| import == hook),
            "{hook} must stay listed among the imports"
        );
    }
    let rendered =
        render_inert_weak_imports(&audit.inert_weak_imports).expect("a non-empty list renders");
    assert!(
        rendered.starts_with("inert weak imports"),
        "the heading must name the class: {rendered}"
    );
    assert!(
        rendered.contains("sdallocx") && rendered.contains("resolve to NULL"),
        "the note must list the symbols and say why they are inert: {rendered}"
    );
    assert_eq!(
        render_inert_weak_imports(&[]),
        None,
        "an empty list emits no heading"
    );
}

// Fail-closed guard 1 (planted): the rule keys on "nothing in the audited
// closure defines it". Plant a definition of the same name elsewhere in the
// closure and the weak reference is live again — it now binds to real code —
// so it must fall back to the full classification path and refuse. Without the
// definition check, this fixture audits clean: that is the leak.
#[test]
fn a_defined_weak_symbol_keeps_the_full_classification_path() {
    let bytes = elf_with_symbol_bindings(
        &[("host_side_door", true, false)],
        &[("host_side_door", true, true)],
    );
    let error = NativeAudit::audit(&bytes, &BTreeSet::new())
        .expect_err("a weak symbol the closure DEFINES must not be treated as inert");
    let TargetError::UnsupportedNativeImports(denied) = error else {
        panic!("expected an unsupported-import refusal, got {error:?}");
    };
    assert_eq!(denied.len(), 1);
    assert_eq!(denied[0].symbol, "host_side_door");
    assert_eq!(denied[0].category, "unknown-import");
}

// Fail-closed guard 2: the rule is about weak bindings only. A STRONG
// undefined import is exactly today's escape — the dynamic linker must bind it
// to a real definition or the process will not start — so it is untouched.
#[test]
fn a_strong_undefined_import_is_untouched_by_the_weak_rule() {
    let bytes = elf_with_symbol_bindings(&[("host_side_door", false, false)], &[]);
    let error = NativeAudit::audit(&bytes, &BTreeSet::new())
        .expect_err("a strong undefined import must still refuse");
    let TargetError::UnsupportedNativeImports(denied) = error else {
        panic!("expected an unsupported-import refusal, got {error:?}");
    };
    assert_eq!(denied[0].symbol, "host_side_door");
}

// Fail-closed guard 3: the rule is narrowed to symbols with no known escape
// class, and that narrowing is load-bearing rather than cosmetic. An undefined
// weak reference is NULL only while nothing defines it — and the dynamic
// linker searches the loaded libraries too, so a weak undefined `open` binds
// to libc's `open` at load and runs. Exactly the classified names are the ones
// a loaded library defines, so a weak binding never rescues one.
#[test]
fn a_weak_undefined_import_of_a_classified_escape_still_refuses() {
    for (symbol, category) in [("open", "filesystem"), ("socket", "network")] {
        let bytes = elf_with_symbol_bindings(&[(symbol, true, false)], &[]);
        let error = NativeAudit::audit(&bytes, &BTreeSet::new()).expect_err(
            "a weak reference to a symbol the loaded libraries define must still refuse",
        );
        let TargetError::UnsupportedNativeImports(denied) = error else {
            panic!("expected an unsupported-import refusal, got {error:?}");
        };
        assert_eq!(denied[0].symbol, symbol);
        assert_eq!(denied[0].category, category);
    }
}

// The acceptance shape the three rules above were built for: the exact
// seven-symbol residual a glibc `slatedb-dst --features aws` build carries
// (aws-lc-sys), auditing clean with an EMPTY allow set. The bindings are the
// ones aws-lc's own source produces — `crypto/mem.c` declares the five hooks
// through `WEAK_SYMBOL_FUNC`, which on ELF is `__attribute__((weak))` with no
// definition in the closure — and the two glibc entry points are ordinary
// strong references.
#[test]
fn the_aws_lc_import_residual_audits_clean_with_no_allowance() {
    let weak_hooks = [
        "OPENSSL_memory_alloc",
        "OPENSSL_memory_free",
        "OPENSSL_memory_get_size",
        "OPENSSL_memory_realloc",
        "sdallocx",
    ];
    let mut dynamic: Vec<(&str, bool, bool)> =
        weak_hooks.iter().map(|name| (*name, true, false)).collect();
    // aws-lc's `__assert_fail` binds to the shim's definition in a linked
    // guest, so it is no longer part of the import residual.
    dynamic.push(("__isoc23_sscanf", false, false));

    let bytes = elf_with_symbol_bindings(&dynamic, &[]);
    let audit = NativeAudit::audit(&bytes, &BTreeSet::new())
        .expect("the aws-lc residual must audit clean with zero --allow");
    assert_eq!(
        audit.inert_weak_imports, weak_hooks,
        "the five weak hooks are inert; the glibc symbol is known-safe, not inert"
    );
}
