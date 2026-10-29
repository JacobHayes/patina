//! Load-set binding audit tests.

use super::*;
use crate::TargetError;
use crate::import_policy::SHIM_DLSYM_VERSION;
use crate::report::render_inert_weak_imports;
use crate::tests::{audit_with_libc, elf_with_symbol_bindings, load_set};
use std::collections::BTreeSet;

/// A host libc defining each of `names`.
fn libc(names: &[&str]) -> (&'static str, Vec<u8>, ImageRole) {
    let exports: Vec<(&str, bool, bool)> = names.iter().map(|name| (*name, false, true)).collect();
    (
        "libc.so.6",
        elf_with_symbol_bindings(&exports, &[]),
        ImageRole::Host,
    )
}

/// The findings of a refused audit.
fn refused(result: Result<NativeAudit, TargetError>) -> Vec<NativeEscape> {
    match result {
        Err(TargetError::UnsupportedImports(denied)) => denied,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

// A weak reference no image in the load set defines is NULL at load: aws-lc's
// allocator-override hooks (`OPENSSL_memory_*`) and `sdallocx` take their
// guarded fallback. They are inert because nothing defines them, whatever
// their names; they are listed under their own heading, not refused.
#[test]
fn a_weak_reference_no_image_defines_is_inert() {
    let hooks = [
        "OPENSSL_memory_alloc",
        "OPENSSL_memory_free",
        "OPENSSL_memory_get_size",
        "OPENSSL_memory_realloc",
        "sdallocx",
        // A classified name is no different: nothing defines it, so nothing runs.
        "open",
    ];
    let mut dynamic: Vec<(&str, bool, bool)> =
        hooks.iter().map(|name| (*name, true, false)).collect();
    dynamic.push(("__isoc23_sscanf", false, false));
    let bytes = elf_with_symbol_bindings(&dynamic, &[]);
    let audit = NativeAudit::audit(
        &load_set(&bytes, vec![libc(&["__isoc23_sscanf"])]),
        &BTreeSet::new(),
    )
    .expect("weak references nothing defines must not refuse the audit");
    let mut expected: Vec<String> = hooks.iter().map(|hook| (*hook).to_owned()).collect();
    expected.sort();
    assert_eq!(audit.inert_weak_imports, expected);
    assert!(render_inert_weak_imports(&audit.inert_weak_imports).is_some());
    assert_eq!(render_inert_weak_imports(&[]), None);
}

// The planted gap: a weak reference to a name a loaded library defines binds to
// that definition at load and runs it. `getloadavg` is in no escape class, so
// a name-based rule cleared it; the binding refuses it, naming the provider.
#[test]
fn a_weak_reference_a_host_image_defines_binds_there_and_is_refused() {
    let bytes = elf_with_symbol_bindings(&[("getloadavg", true, false)], &[]);
    let denied = refused(NativeAudit::audit(
        &load_set(&bytes, vec![libc(&["getloadavg"])]),
        &BTreeSet::new(),
    ));
    assert_eq!(denied.len(), 1, "{denied:?}");
    assert_eq!(denied[0].symbol, "getloadavg");
    assert_eq!(denied[0].category, "unknown-import");
    let binding = denied[0]
        .binding
        .as_ref()
        .expect("a host binding names its provider");
    assert_eq!(binding.provider, "libc.so.6");
    // The same reference is inert where no image defines it.
    NativeAudit::audit(&load_set(&bytes, vec![libc(&[])]), &BTreeSet::new())
        .expect("absent from the load set, the reference is NULL");
}

// A reference the executable itself defines binds there: the executable is
// first in the search order, so its own code (the shim's door) runs, weak or
// strong. A strong reference nothing defines does not resolve at all.
#[test]
fn references_bind_to_the_first_definition_in_search_order() {
    let bytes = elf_with_symbol_bindings(
        &[
            ("hook", true, false),
            ("hook", false, true),
            ("missing", false, false),
        ],
        &[],
    );
    let denied = refused(NativeAudit::audit(
        &load_set(&bytes, vec![libc(&["hook"])]),
        &BTreeSet::new(),
    ));
    let found: Vec<(&str, &str)> = denied
        .iter()
        .map(|escape| (escape.symbol.as_str(), escape.category))
        .collect();
    assert_eq!(found, [("missing", UNRESOLVED_CATEGORY)]);
}

// A library's references are judged as the executable's are, with its name on
// each finding; one that binds to another audited library is contained. Its
// weak `dlsym` is a guest resolver, not the shim's vehicle, so it binds to libc
// and refuses as dynamic loading.
#[test]
fn a_librarys_references_are_judged_by_where_they_bind() {
    let bytes = elf_with_symbol_bindings(&[("a_call", false, false)], &[]);
    let lib_a = elf_with_symbol_bindings(&[("a_call", false, true), ("b_call", false, false)], &[]);
    let lib_b = elf_with_symbol_bindings(
        &[
            ("b_call", false, true),
            ("getloadavg", false, false),
            ("dlsym", true, false),
        ],
        &[],
    );
    let mut denied = refused(NativeAudit::audit(
        &load_set(
            &bytes,
            vec![
                ("liba.so", lib_a, ImageRole::Library),
                ("libb.so", lib_b, ImageRole::Library),
                libc(&["getloadavg", "dlsym"]),
            ],
        ),
        &BTreeSet::new(),
    ));
    denied.sort_by(|left, right| left.symbol.cmp(&right.symbol));
    let found: Vec<(Option<&str>, &str, &str)> = denied
        .iter()
        .map(|escape| {
            (
                escape.image.as_deref(),
                escape.symbol.as_str(),
                escape.category,
            )
        })
        .collect();
    assert_eq!(
        found,
        [
            (Some("libb.so"), "dlsym", "dynamic-loading"),
            (Some("libb.so"), "getloadavg", "unknown-import"),
        ]
    );
}

// A library reference to a name the executable defines but does not export
// (a version script hid the shim's `open`) binds past it to libc's: refused,
// and marked as going around the executable's own definition.
#[test]
fn a_library_reference_past_an_unexported_definition_is_refused() {
    let bytes = elf_with_symbol_bindings(&[], &[("open", false, true)]);
    let lib = elf_with_symbol_bindings(&[("open", false, false)], &[]);
    let denied = refused(NativeAudit::audit(
        &load_set(
            &bytes,
            vec![("libb.so", lib, ImageRole::Library), libc(&["open"])],
        ),
        &BTreeSet::new(),
    ));
    assert_eq!(denied.len(), 1, "{denied:?}");
    assert_eq!(denied[0].category, "filesystem");
    assert!(
        denied[0]
            .binding
            .as_ref()
            .is_some_and(|binding| binding.around_executable)
    );
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

// A dynamic table that names a symbol-version table (`DT_VERSYM`) the section
// headers no longer carry as `SHT_GNU_versym` would leave the binding audit no
// versions to bind by; the audit refuses the binary as unauditable instead of
// binding its references as unversioned.
#[test]
fn a_dynamic_version_table_without_its_section_is_unauditable() {
    let mut bytes = elf_with_versioned_imports(
        &[("dlsym", false, Some("GLIBC_2.2.5"))],
        &["patina_init_from_env"],
    );
    const SHT_PROGBITS: u32 = 1;
    retype_section(&mut bytes, 4, SHT_PROGBITS);
    let error = audit_with_libc(&bytes, &BTreeSet::new())
        .expect_err("a version table hidden from the audit must refuse");
    assert!(matches!(error, TargetError::UnauditableElf), "{error:?}");
}

// The shim's own host-alias resolver is the executable's weak `dlsym` at
// glibc's default version, and only it binds to libc unrefused: a strong pin,
// another version, or `dlvsym` is a guest resolver, refused as dynamic
// loading. A versioned `mmap` the executable exports binds to the executable
// (a definition at the global index satisfies any version); one it does not
// export binds to libc's, around the shim's door.
#[test]
fn a_versioned_reference_binds_by_its_version_and_the_shim_vehicle_alone_passes() {
    let bytes = elf_with_versioned_imports(
        &[
            ("dlsym", true, Some(SHIM_DLSYM_VERSION)),
            ("dlsym", false, Some(SHIM_DLSYM_VERSION)),
            ("dlsym", true, Some("GLIBC_2.2.5")),
            ("dlvsym", true, Some(SHIM_DLSYM_VERSION)),
            ("mmap", false, Some("GLIBC_2.2.5")),
            ("malloc", false, Some("GLIBC_2.2.5")),
        ],
        &["patina_init_from_env", "mmap"],
    );
    let denied = refused(NativeAudit::audit(
        &load_set(&bytes, vec![libc(&["dlsym", "dlvsym", "mmap", "malloc"])]),
        &BTreeSet::new(),
    ));
    let mut found: Vec<String> = denied
        .iter()
        .map(|escape| {
            assert_eq!(escape.category, "dynamic-loading", "{escape:?}");
            let version = escape
                .binding
                .as_ref()
                .and_then(|binding| binding.version.clone());
            format!("{}@{}", escape.symbol, version.unwrap_or_default())
        })
        .collect();
    found.sort();
    found.dedup();
    let mut expected = vec![
        format!("dlsym@{SHIM_DLSYM_VERSION}"),
        "dlsym@GLIBC_2.2.5".to_owned(),
        format!("dlvsym@{SHIM_DLSYM_VERSION}"),
    ];
    expected.sort();
    assert_eq!(found, expected);

    let not_exported = elf_with_versioned_imports(
        &[("mmap", false, Some("GLIBC_2.2.5"))],
        &["patina_init_from_env"],
    );
    let denied = refused(NativeAudit::audit(
        &load_set(&not_exported, vec![libc(&["mmap"])]),
        &BTreeSet::new(),
    ));
    assert_eq!(denied[0].symbol, "mmap");
    let binding = denied[0].binding.as_ref().expect("binds to libc");
    assert_eq!(binding.version.as_deref(), Some("GLIBC_2.2.5"));
}

// An exact `--allow name@version` clears one specific binding, leaving the
// others refused.
#[test]
fn an_exact_versioned_allowance_clears_only_that_finding() {
    let bytes = elf_with_versioned_imports(
        &[
            ("dlsym", false, Some("GLIBC_2.2.5")),
            ("mmap", false, Some("GLIBC_2.2.5")),
        ],
        &[],
    );
    let allow = BTreeSet::from(["dlsym@GLIBC_2.2.5".to_owned()]);
    let denied = refused(NativeAudit::audit(
        &load_set(&bytes, vec![libc(&["dlsym", "mmap"])]),
        &allow,
    ));
    let refused: Vec<&str> = denied.iter().map(|escape| escape.symbol.as_str()).collect();
    assert_eq!(refused, ["mmap"]);
}
