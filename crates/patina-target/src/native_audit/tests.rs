//! Native import auditing and inert undefined-weak bindings tests.

use super::*;
use crate::TargetError;
use crate::import_policy::SHIM_DLSYM_VERSION;
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
    let mut dynamic: Vec<(&str, bool, bool)> =
        hooks.iter().map(|name| (*name, true, false)).collect();
    // A known-safe strong import beside them audits clean but is not inert.
    dynamic.push(("__isoc23_sscanf", false, false));
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

    // The rule is about weak bindings only: a STRONG undefined import must be
    // bound by the dynamic linker, so it refuses as before.
    let bytes = elf_with_symbol_bindings(&[("host_side_door", false, false)], &[]);
    let error = NativeAudit::audit(&bytes, &BTreeSet::new())
        .expect_err("a strong undefined import must still refuse");
    let TargetError::UnsupportedNativeImports(denied) = error else {
        panic!("expected an unsupported-import refusal, got {error:?}");
    };
    assert_eq!(denied[0].symbol, "host_side_door");
}

// Fail-closed guard 2: the rule is narrowed to symbols with no known escape
// class, and that narrowing is load-bearing rather than cosmetic. An undefined
// weak reference is NULL only while nothing defines it — and the dynamic
// linker searches the loaded libraries too, so a weak undefined `open` binds
// to libc's `open` at load and runs. Exactly the classified names are the ones
// a loaded library defines, so a weak binding never rescues one.
#[test]
fn a_weak_undefined_import_of_a_classified_escape_still_refuses() {
    // Named timer classification keeps a future libc timer with no shim door
    // out of the inert class too.
    for (symbol, category) in [
        ("open", "filesystem"),
        ("socket", "network"),
        ("timer_gettime", "signals-timers"),
        ("timerfd_create", "signals-timers"),
        ("___timer_settime64", "signals-timers"),
        ("timer_future", "signals-timers"),
    ] {
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

/// Build a dynamically-linked-shaped ELF64 x86_64 executable whose undefined
/// dynamic symbols carry GNU symbol-version requirements, so the version-aware
/// import parsing has real `.gnu.version`/`.gnu.version_r` sections to read.
/// Each dynamic entry is `(name, weak, Some(version) | None)`; a `Some` entry
/// becomes an undefined reference needing that version from `libc.so.6`, a
/// `None` entry an ordinary unversioned undefined reference. `defined` names a
/// strong definition the executable exports, in `.symtab` and in `.dynsym` at
/// the global version index, as a link exports the shim's interposers (and
/// used to plant the shim marker).
fn elf_with_versioned_imports(dynamic: &[(&str, bool, Option<&str>)], defined: &[&str]) -> Vec<u8> {
    // Distinct version names, each assigned a version index starting at 2
    // (0 = local, 1 = global/base are reserved).
    let mut versions: Vec<&str> = Vec::new();
    for (_, _, version) in dynamic {
        if let Some(version) = version
            && !versions.contains(version)
        {
            versions.push(version);
        }
    }
    let version_index = |name: &str| 2 + versions.iter().position(|v| *v == name).unwrap() as u16;

    // .dynstr: names, version strings, and the needed-file name.
    let mut dynstr = vec![0u8];
    let dynstr_off = |strings: &mut Vec<u8>, text: &str| {
        let at = strings.len() as u32;
        strings.extend_from_slice(text.as_bytes());
        strings.push(0);
        at
    };
    // .dynsym (index 0 is the mandatory null entry).
    let mut dynsym = vec![0u8; 24];
    let mut versym: Vec<u16> = vec![0]; // null entry is local
    for (name, weak, version) in dynamic {
        let st_name = dynstr_off(&mut dynstr, name);
        let st_info = (if *weak { 2u8 } else { 1u8 } << 4) | 2; // STB * 16 | STT_FUNC
        dynsym.extend_from_slice(&st_name.to_le_bytes());
        dynsym.push(st_info);
        dynsym.push(0); // st_other
        dynsym.extend_from_slice(&0u16.to_le_bytes()); // SHN_UNDEF
        dynsym.extend_from_slice(&0u64.to_le_bytes()); // st_value
        dynsym.extend_from_slice(&0u64.to_le_bytes()); // st_size
        versym.push(match version {
            Some(version) => version_index(version),
            None => 1, // global: object reports no version
        });
    }
    for name in defined {
        let st_name = dynstr_off(&mut dynstr, name);
        dynsym.extend_from_slice(&st_name.to_le_bytes());
        dynsym.push((1u8 << 4) | 2); // STB_GLOBAL | STT_FUNC
        dynsym.push(0);
        dynsym.extend_from_slice(&1u16.to_le_bytes()); // .text (defined)
        dynsym.extend_from_slice(&0u64.to_le_bytes());
        dynsym.extend_from_slice(&4u64.to_le_bytes());
        versym.push(1); // global: the executable's own definition
    }
    let file_name_off = dynstr_off(&mut dynstr, "libc.so.6");
    let version_name_offs: Vec<u32> = versions
        .iter()
        .map(|version| dynstr_off(&mut dynstr, version))
        .collect();

    // .symtab: index 0 null, then one strong definition per `defined` name.
    let mut strtab = vec![0u8];
    let mut symtab = vec![0u8; 24];
    for name in defined {
        let st_name = strtab.len() as u32;
        strtab.extend_from_slice(name.as_bytes());
        strtab.push(0);
        symtab.extend_from_slice(&st_name.to_le_bytes());
        symtab.push((1u8 << 4) | 2); // STB_GLOBAL | STT_FUNC
        symtab.push(0);
        symtab.extend_from_slice(&1u16.to_le_bytes()); // .text (defined)
        symtab.extend_from_slice(&0u64.to_le_bytes());
        symtab.extend_from_slice(&4u64.to_le_bytes());
    }

    // .gnu.version: one u16 per .dynsym entry.
    let mut gnu_version = Vec::new();
    for value in &versym {
        gnu_version.extend_from_slice(&value.to_le_bytes());
    }

    // .gnu.version_r: one Verneed for libc.so.6 with a Vernaux per version.
    let mut verneed = Vec::new();
    verneed.extend_from_slice(&1u16.to_le_bytes()); // vn_version
    verneed.extend_from_slice(&(versions.len() as u16).to_le_bytes()); // vn_cnt
    verneed.extend_from_slice(&file_name_off.to_le_bytes()); // vn_file
    verneed.extend_from_slice(&16u32.to_le_bytes()); // vn_aux (Verneed is 16 bytes)
    verneed.extend_from_slice(&0u32.to_le_bytes()); // vn_next (only one Verneed)
    for (i, name_off) in version_name_offs.iter().enumerate() {
        let index = 2 + i as u16;
        verneed.extend_from_slice(&0u32.to_le_bytes()); // vna_hash
        verneed.extend_from_slice(&0u16.to_le_bytes()); // vna_flags
        verneed.extend_from_slice(&index.to_le_bytes()); // vna_other = version index
        verneed.extend_from_slice(&name_off.to_le_bytes()); // vna_name
        let vna_next = if i + 1 < version_name_offs.len() {
            16u32
        } else {
            0
        };
        verneed.extend_from_slice(&vna_next.to_le_bytes()); // vna_next (Vernaux is 16 bytes)
    }

    let text = [0x90u8; 16];
    let shstr: &[u8] = b"\0.text\0.dynsym\0.dynstr\0.gnu.version\0.gnu.version_r\0.symtab\0.strtab\0.shstrtab\0.dynamic\0";
    // .dynamic: `DT_VERSYM` names the version table, as a real link's does,
    // then `DT_NULL`.
    let mut dynamic_table = Vec::new();
    for (tag, value) in [(object::elf::DT_VERSYM, 0u64), (object::elf::DT_NULL, 0)] {
        dynamic_table.extend_from_slice(&tag.to_le_bytes());
        dynamic_table.extend_from_slice(&value.to_le_bytes());
    }
    let align8 = |value: u64| (value + 7) & !7;

    let text_off = 64u64;
    let dynsym_off = text_off + text.len() as u64;
    let dynstr_off_sec = dynsym_off + dynsym.len() as u64;
    let gnu_version_off = align8(dynstr_off_sec + dynstr.len() as u64);
    let gnu_version_r_off = align8(gnu_version_off + gnu_version.len() as u64);
    let symtab_off = align8(gnu_version_r_off + verneed.len() as u64);
    let strtab_off = symtab_off + symtab.len() as u64;
    let shstr_off = strtab_off + strtab.len() as u64;
    let dynamic_off = align8(shstr_off + shstr.len() as u64);
    let shoff = align8(dynamic_off + dynamic_table.len() as u64);

    let mut elf = Vec::new();
    elf.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
    elf.extend_from_slice(&[0u8; 8]);
    elf.extend_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    elf.extend_from_slice(&62u16.to_le_bytes()); // EM_X86_64
    elf.extend_from_slice(&1u32.to_le_bytes());
    elf.extend_from_slice(&0u64.to_le_bytes()); // e_entry
    elf.extend_from_slice(&0u64.to_le_bytes()); // e_phoff
    elf.extend_from_slice(&shoff.to_le_bytes());
    elf.extend_from_slice(&0u32.to_le_bytes());
    elf.extend_from_slice(&64u16.to_le_bytes()); // e_ehsize
    elf.extend_from_slice(&0u16.to_le_bytes()); // e_phentsize
    elf.extend_from_slice(&0u16.to_le_bytes()); // e_phnum
    elf.extend_from_slice(&64u16.to_le_bytes()); // e_shentsize
    elf.extend_from_slice(&10u16.to_le_bytes()); // e_shnum
    elf.extend_from_slice(&8u16.to_le_bytes()); // e_shstrndx -> .shstrtab
    assert_eq!(elf.len(), 64);

    elf.extend_from_slice(&text);
    elf.extend_from_slice(&dynsym);
    elf.extend_from_slice(&dynstr);
    while (elf.len() as u64) < gnu_version_off {
        elf.push(0);
    }
    elf.extend_from_slice(&gnu_version);
    while (elf.len() as u64) < gnu_version_r_off {
        elf.push(0);
    }
    elf.extend_from_slice(&verneed);
    while (elf.len() as u64) < symtab_off {
        elf.push(0);
    }
    elf.extend_from_slice(&symtab);
    elf.extend_from_slice(&strtab);
    elf.extend_from_slice(shstr);
    while (elf.len() as u64) < dynamic_off {
        elf.push(0);
    }
    elf.extend_from_slice(&dynamic_table);
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
    // Section-header name offsets into `shstr`.
    const SHT_SYMTAB: u32 = 2;
    const SHT_STRTAB: u32 = 3;
    const SHT_DYNSYM: u32 = 11;
    const SHT_GNU_VERSYM: u32 = 0x6fff_ffff;
    const SHT_GNU_VERNEED: u32 = 0x6fff_fffe;
    push_shdr(0, 0, 0, 0, 0, 0, 0, 0, 0); // 0 null
    push_shdr(1, 1, 0x2 | 0x4, text_off, text.len() as u64, 0, 0, 4, 0); // 1 .text
    push_shdr(
        7,
        SHT_DYNSYM,
        0x2,
        dynsym_off,
        dynsym.len() as u64,
        3,
        1,
        8,
        24,
    ); // 2 .dynsym -> .dynstr
    push_shdr(
        15,
        SHT_STRTAB,
        0x2,
        dynstr_off_sec,
        dynstr.len() as u64,
        0,
        0,
        1,
        0,
    ); // 3 .dynstr
    push_shdr(
        23,
        SHT_GNU_VERSYM,
        0x2,
        gnu_version_off,
        gnu_version.len() as u64,
        2,
        0,
        2,
        2,
    ); // 4 .gnu.version -> .dynsym
    push_shdr(
        36,
        SHT_GNU_VERNEED,
        0x2,
        gnu_version_r_off,
        verneed.len() as u64,
        3,
        1,
        4,
        0,
    ); // 5 .gnu.version_r -> .dynstr, info=verneed count
    push_shdr(
        51,
        SHT_SYMTAB,
        0,
        symtab_off,
        symtab.len() as u64,
        7,
        1,
        8,
        24,
    ); // 6 .symtab -> .strtab
    push_shdr(
        59,
        SHT_STRTAB,
        0,
        strtab_off,
        strtab.len() as u64,
        0,
        0,
        1,
        0,
    ); // 7 .strtab
    push_shdr(67, SHT_STRTAB, 0, shstr_off, shstr.len() as u64, 0, 0, 1, 0); // 8 .shstrtab
    const SHT_DYNAMIC: u32 = 6;
    push_shdr(
        77,
        SHT_DYNAMIC,
        0x2 | 0x1,
        dynamic_off,
        dynamic_table.len() as u64,
        3,
        0,
        8,
        16,
    ); // 9 .dynamic -> .dynstr

    elf
}

/// Retype section `index` of an ELF64 little-endian image to `sh_type`.
fn retype_section(elf: &mut [u8], index: usize, sh_type: u32) {
    let shoff = u64::from_le_bytes(elf[0x28..0x30].try_into().unwrap()) as usize;
    let at = shoff + index * 64 + 4;
    elf[at..at + 4].copy_from_slice(&sh_type.to_le_bytes());
}

// The whole point: a versioned `dlsym` import reached around
// `-Wl,--wrap=dlsym`, and a versioned `mmap` import the executable does not
// define itself goes to glibc's. Both are refused by their versioned name,
// whether the reference is strong or weak: weakness is not the shim's mark,
// since compatibility code probes optional symbols weakly too. Only the shim's
// own host-alias vehicle — a weak `dlsym` at exactly `SHIM_DLSYM_VERSION` — is
// admitted; a strong `dlsym` at that version is a guest pin and refused. A
// versioned import of a name the shim does not interpose (`malloc`) is an
// ordinary libc allocator call.
#[test]
fn versioned_bypass_admits_only_the_shim_vehicle() {
    let bytes = elf_with_versioned_imports(
        &[
            ("dlsym", true, Some(SHIM_DLSYM_VERSION)), // the shim's vehicle
            ("dlsym", false, Some(SHIM_DLSYM_VERSION)), // a strong pin
            ("dlsym", false, Some("GLIBC_2.2.5")),     // strong compat pin
            ("dlsym", true, Some("GLIBC_2.17")),       // weak compat pin
            ("dlvsym", true, Some(SHIM_DLSYM_VERSION)), // never wrapped
            ("mmap", false, Some("GLIBC_2.2.5")),      // interposer bypass
            ("malloc", false, Some("GLIBC_2.2.5")),    // ordinary allocator call
        ],
        &[],
    );
    let file = object::File::parse(&*bytes).expect("parses");
    let mut refused: Vec<String> =
        versioned_bypass_escapes(&file, &BTreeSet::new(), &|_| Vec::new())
            .into_iter()
            .map(|escape| {
                assert_eq!(escape.category, VERSIONED_BYPASS_CATEGORY);
                escape.symbol
            })
            .collect();
    refused.sort();
    let mut expected = vec![
        format!("dlsym@{SHIM_DLSYM_VERSION}"),
        "dlsym@GLIBC_2.17".to_owned(),
        "dlsym@GLIBC_2.2.5".to_owned(),
        format!("dlvsym@{SHIM_DLSYM_VERSION}"),
        "mmap@GLIBC_2.2.5".to_owned(),
    ];
    expected.sort();
    assert_eq!(refused, expected);
}

// A versioned import of an interposed name binds to the executable's own
// exported definition, the shim's: the loader searches the executable first,
// and a definition at the global version index satisfies a reference of any
// version (what lld leaves for a `.symver`-pinned `mmap@GLIBC_2.2.5`). So it is
// not a bypass and the audit admits it; the same import with no exported
// definition is refused.
#[test]
fn a_versioned_import_the_executable_exports_binds_to_its_definition() {
    let exported = elf_with_versioned_imports(
        &[("mmap", false, Some("GLIBC_2.2.5"))],
        &["patina_init_from_env", "mmap"],
    );
    let file = object::File::parse(&*exported).expect("parses");
    assert!(dynamic_versions(&file).exported.contains("mmap"));
    NativeAudit::audit(&exported, &BTreeSet::new())
        .expect("a versioned import of an exported interposer binds to the shim");
    let not_exported = elf_with_versioned_imports(
        &[("mmap", false, Some("GLIBC_2.2.5"))],
        &["patina_init_from_env"],
    );
    let error = NativeAudit::audit(&not_exported, &BTreeSet::new())
        .expect_err("with no definition of its own the import reaches glibc");
    let TargetError::UnsupportedNativeImports(denied) = error else {
        panic!("{error:?}");
    };
    assert!(
        denied
            .iter()
            .any(|escape| escape.symbol == "mmap@GLIBC_2.2.5"),
        "{denied:?}"
    );
}

// A dynamic table that names a symbol-version table (`DT_VERSYM`) the section
// headers no longer carry as `SHT_GNU_versym` would leave the versioned-bypass
// check nothing to read; the audit refuses the binary as unauditable instead
// of skipping the check.
#[test]
fn a_dynamic_version_table_without_its_section_is_unauditable() {
    let mut bytes = elf_with_versioned_imports(
        &[("dlsym", false, Some("GLIBC_2.2.5"))],
        &["patina_init_from_env"],
    );
    const SHT_PROGBITS: u32 = 1;
    retype_section(&mut bytes, 4, SHT_PROGBITS);
    let error = NativeAudit::audit(&bytes, &BTreeSet::new())
        .expect_err("a version table hidden from the audit must refuse");
    assert!(
        matches!(error, TargetError::UnauditableNativeElf),
        "{error:?}"
    );
}

// An exact `--allow name@version` clears one specific finding, leaving the
// others refused: the escape surface stays visible and default-deny holds.
#[test]
fn an_exact_versioned_allowance_clears_only_that_finding() {
    let bytes = elf_with_versioned_imports(
        &[
            ("dlsym", false, Some("GLIBC_2.2.5")),
            ("mmap", false, Some("GLIBC_2.2.5")),
        ],
        &[],
    );
    let file = object::File::parse(&*bytes).expect("parses");
    let allow = BTreeSet::from(["dlsym@GLIBC_2.2.5".to_owned()]);
    let refused: Vec<String> = versioned_bypass_escapes(&file, &allow, &|_| Vec::new())
        .into_iter()
        .map(|escape| escape.symbol)
        .collect();
    assert_eq!(refused, vec!["mmap@GLIBC_2.2.5".to_owned()]);
}

// A binary that is NOT shim-linked does not get the versioned-bypass pass:
// without the shim there is no interposer to bypass, so its ordinary libc calls
// (versioned, as every glibc reference is) are governed by the allowlist alone.
// A versioned `mmap` import — which the allowlist admits as process-local memory
// — therefore audits clean here, where a shim-linked binary would see it refused
// as a bypass. Without the marker the audit must not invent one.
#[test]
fn a_non_shim_linked_binary_skips_the_versioned_bypass_pass() {
    let versioned = elf_with_versioned_imports(&[("mmap", false, Some("GLIBC_2.2.5"))], &[]);
    NativeAudit::audit(&versioned, &BTreeSet::new())
        .expect("a non-shim-linked binary is not subjected to the versioned-bypass pass");
    // The same import in a shim-linked binary is the bypass.
    let shim_linked = elf_with_versioned_imports(
        &[("mmap", false, Some("GLIBC_2.2.5"))],
        &["patina_init_from_env"],
    );
    NativeAudit::audit(&shim_linked, &BTreeSet::new())
        .expect_err("a shim-linked versioned mmap bypass must refuse");
}
