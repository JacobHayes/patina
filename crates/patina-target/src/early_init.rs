//! The executable's own pre-constructor code: its preinit array.
//!
//! glibc's `_dl_init` runs the main executable's preinit array
//! (`DT_PREINIT_ARRAY`/`DT_PREINIT_ARRAYSZ`) before every shared library's
//! constructor and before the executable's `.init_array`. The shim arms its
//! containment (syscall-user-dispatch, the counter trap, the rseq takeover,
//! the fault front) from one entry there, `patina_preinit`
//! (`patina-native-shim`'s `c/posix/init.c`). Entries run in link order and a
//! guest's objects precede the shim's archive, so any other entry would run
//! before containment is armed.
//!
//! The array is found as the loader finds it, through the dynamic table, and
//! as glibc's static startup finds it, through the linker's bounds of the
//! `SHT_PREINIT_ARRAY` section, found by its type, never its name: a renamed
//! section hides nothing. Each entry is
//! attributed by its relocation (a relative one's addend, or the symbol it
//! names) or, where none applies, by its stored address. An entry that is not
//! the shim's is an `early-init` finding, or a `sanitizer-runtime` one when it
//! is a sanitizer runtime's initializer; an entry that cannot be attributed is
//! a finding too. The shim's entry is known by its symbol or, in an image
//! whose symbol table was stripped, by the marker the shim keeps beside it
//! (`.patina.preinit`, holding the same address). That attribution reads what
//! the binary says about itself, so it is the pre-run refusal of an honest
//! mistake, not a proof against a crafted image: the shim proves the property
//! at run time from its own loaded code (`c/posix/init.c`), stopping a run
//! whose array its entry is not alone in, or whose loader never ran it.
//!
//! A shared library's own `DT_PREINIT_ARRAY` is not audited: glibc ignores it,
//! natively as under Patina, so it is never run.

use crate::NativeEscape;
use crate::provenance::{NativeProvenance, NativeProvenanceIndex};
use object::read::elf::{Dyn, ProgramHeader, SectionHeader};
use object::{Object, ObjectSection, ObjectSegment, ObjectSymbol, ObjectSymbolTable, SymbolIndex};
use std::collections::BTreeMap;

/// The refusal class of a pre-constructor entry the shim does not own.
pub(crate) const EARLY_INIT_CATEGORY: &str = "early-init";
/// The refusal class of a sanitizer runtime's preinit initializer.
pub(crate) const SANITIZER_RUNTIME_CATEGORY: &str = "sanitizer-runtime";

/// The shim's preinit function, looked up by name in the symbol table.
const SHIM_PREINIT_ENTRY: &str = "patina_preinit";
/// The section holding that function's address again, for a stripped image.
const SHIM_PREINIT_MARKER: &str = ".patina.preinit";

/// The initializers the sanitizer runtimes register in the executable's
/// preinit array (compiler-rt's `*_preinit.cpp`). A sanitizer runtime
/// interposes the allocator, threads and signals the shim models and issues
/// its own raw syscalls, so a sanitizer build is refused by name.
const SANITIZER_INITS: [&str; 6] = [
    "__asan_init",
    "__hwasan_init",
    "__tsan_init",
    "__msan_init",
    "__lsan_init",
    "_ZN7__ubsan16InitAsStandaloneEv",
];

/// `R_X86_64_RELATIVE` and `R_AARCH64_RELATIVE` (base + addend).
const RELATIVE_RELOCATIONS: [u32; 2] = [
    object::elf::R_X86_64_RELATIVE,
    object::elf::R_AARCH64_RELATIVE,
];

/// What an entry calls, as far as the image says.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Target {
    /// A function in the executable, at this link-time address.
    Address(u64),
    /// A function another image defines, named by the entry's relocation.
    Symbol(String),
    /// Neither: the entry cannot be attributed.
    Unknown,
}

/// One finding per preinit entry other than the shim's.
pub(crate) fn early_init_escapes(
    file: &object::File<'_>,
    provenance: &NativeProvenanceIndex,
) -> Vec<NativeEscape> {
    // The audited architectures are 64-bit; other formats have no preinit array.
    let object::File::Elf64(elf) = file else {
        return Vec::new();
    };
    let Ok(dynamic) = dynamic_table(elf) else {
        return vec![finding(file, provenance, 0, &Target::Unknown)];
    };
    let targets = preinit_targets(file, elf, dynamic).unwrap_or_else(|()| vec![Target::Unknown]);
    let shim = shim_entry(file, elf.endian(), dynamic);
    foreign_entries(&targets, shim)
        .into_iter()
        .map(|index| finding(file, provenance, index, &targets[index]))
        .collect()
}

type DynamicTable<'data> = &'data [object::elf::Dyn64<object::Endianness>];

/// The `PT_DYNAMIC` entries, if the image has a dynamic table.
fn dynamic_table<'data>(
    elf: &object::read::elf::ElfFile64<'data>,
) -> Result<Option<DynamicTable<'data>>, ()> {
    let endian = elf.endian();
    elf.elf_program_headers()
        .iter()
        .find_map(|header| header.dynamic(endian, elf.data()).transpose())
        .transpose()
        .map_err(|_| ())
}

fn tag(dynamic: DynamicTable<'_>, endian: object::Endianness, wanted: i64) -> Option<u64> {
    dynamic
        .iter()
        .find(|entry| entry.d_tag(endian) == wanted)
        .map(|entry| entry.d_val(endian))
}

/// The preinit array's entries: the array the dynamic table names, and every
/// section of type `SHT_PREINIT_ARRAY` (the bounds glibc's static startup
/// walks) that is not that same array. `Err` when the table names an array
/// or relocations the loaded image does not hold.
fn preinit_targets(
    file: &object::File<'_>,
    elf: &object::read::elf::ElfFile64<'_>,
    dynamic: Option<DynamicTable<'_>>,
) -> Result<Vec<Target>, ()> {
    let endian = elf.endian();
    let mut arrays: Vec<(u64, &[u8])> = Vec::new();
    if let Some(table) = dynamic
        && let (Some(array), Some(size)) = (
            tag(table, endian, object::elf::DT_PREINIT_ARRAY),
            tag(table, endian, object::elf::DT_PREINIT_ARRAYSZ),
        )
    {
        arrays.push((array, virtual_range(file, array, size)?));
    }
    for section in elf.sections() {
        let header = section.elf_section_header();
        if header.sh_type(endian) != object::elf::SHT_PREINIT_ARRAY
            || arrays
                .iter()
                .any(|(address, _)| *address == section.address())
        {
            continue;
        }
        arrays.push((section.address(), section.data().map_err(|_| ())?));
    }
    let mut targets = Vec::new();
    for (address, data) in arrays {
        targets.extend(slot_targets(file, endian, dynamic, address, data)?);
    }
    Ok(targets)
}

/// The address of the shim's preinit function: its symbol, or, where the
/// symbol table was stripped, the marker the shim keeps beside the entry
/// (`.patina.preinit`, an allocated section `strip` leaves in place).
fn shim_entry(
    file: &object::File<'_>,
    endian: object::Endianness,
    dynamic: Option<DynamicTable<'_>>,
) -> Option<u64> {
    if let Some(symbol) = file
        .symbols()
        .find(|symbol| symbol.is_definition() && symbol.name() == Ok(SHIM_PREINIT_ENTRY))
    {
        return Some(symbol.address());
    }
    let marker = file.section_by_name(SHIM_PREINIT_MARKER)?;
    let data = marker.data().ok()?;
    match slot_targets(file, endian, dynamic, marker.address(), data).ok()?[..] {
        [Target::Address(address)] => Some(address),
        _ => None,
    }
}

/// What each 8-byte slot at `address` holds once loaded: its relocation's
/// target (from the dynamic table's `DT_RELA`) or, where none applies, the
/// stored address.
fn slot_targets(
    file: &object::File<'_>,
    endian: object::Endianness,
    dynamic: Option<DynamicTable<'_>>,
    address: u64,
    data: &[u8],
) -> Result<Vec<Target>, ()> {
    let slots = address..address + data.len() as u64;
    let relocations = match dynamic.map(|table| {
        (
            tag(table, endian, object::elf::DT_RELA),
            tag(table, endian, object::elf::DT_RELASZ),
        )
    }) {
        Some((Some(rela), Some(size))) => {
            relocations(file, virtual_range(file, rela, size)?, slots, endian)
        }
        _ => BTreeMap::new(),
    };
    Ok(words(data, endian)
        .enumerate()
        .map(|(index, value)| {
            relocations
                .get(&(address + 8 * index as u64))
                .cloned()
                .unwrap_or(Target::Address(value))
        })
        .collect())
}

/// The bytes the loaded image holds at `[address, address + size)`.
fn virtual_range<'data>(
    file: &object::File<'data>,
    address: u64,
    size: u64,
) -> Result<&'data [u8], ()> {
    file.segments()
        .find_map(|segment| segment.data_range(address, size).ok().flatten())
        .ok_or(())
}

/// The 8-byte words of an array.
fn words(data: &[u8], endian: object::Endianness) -> impl Iterator<Item = u64> + '_ {
    data.as_chunks::<8>()
        .0
        .iter()
        .map(move |bytes| match endian {
            object::Endianness::Little => u64::from_le_bytes(*bytes),
            object::Endianness::Big => u64::from_be_bytes(*bytes),
        })
}

/// The `Elf64_Rela` entries that relocate a slot in `slots`: a relative one
/// by its addend, one naming a symbol by that symbol's name, any other as
/// unattributable.
fn relocations(
    file: &object::File<'_>,
    table: &[u8],
    slots: std::ops::Range<u64>,
    endian: object::Endianness,
) -> BTreeMap<u64, Target> {
    let symbols = file.dynamic_symbol_table();
    let fields: Vec<u64> = words(table, endian).collect();
    let mut targets = BTreeMap::new();
    for &[offset, info, addend] in fields.as_chunks::<3>().0 {
        if !slots.contains(&offset) {
            continue;
        }
        let (kind, symbol) = (info as u32, (info >> 32) as usize);
        let target = if RELATIVE_RELOCATIONS.contains(&kind) {
            Target::Address(addend)
        } else if symbol != 0 && addend == 0 {
            symbols
                .as_ref()
                .and_then(|table| table.symbol_by_index(SymbolIndex(symbol)).ok())
                .and_then(|symbol| symbol.name().ok().map(str::to_owned))
                .map_or(Target::Unknown, Target::Symbol)
        } else {
            Target::Unknown
        };
        targets.insert(offset, target);
    }
    targets
}

/// The entries that are not the shim's: every entry when its address is
/// unknown, and every entry that calls something else or cannot be told.
fn foreign_entries(targets: &[Target], shim: Option<u64>) -> Vec<usize> {
    targets
        .iter()
        .enumerate()
        .filter(|(_, target)| shim.is_none_or(|shim| **target != Target::Address(shim)))
        .map(|(index, _)| index)
        .collect()
}

/// A finding's class: a sanitizer runtime's initializer, or any other entry.
fn category(name: Option<&str>) -> &'static str {
    match name {
        Some(name) if SANITIZER_INITS.contains(&name) => SANITIZER_RUNTIME_CATEGORY,
        _ => EARLY_INIT_CATEGORY,
    }
}

fn finding(
    file: &object::File<'_>,
    provenance: &NativeProvenanceIndex,
    index: usize,
    target: &Target,
) -> NativeEscape {
    let (name, site) = match target {
        Target::Address(address) => (
            file.symbols()
                .find(|symbol| symbol.is_definition() && symbol.address() == *address)
                .and_then(|symbol| symbol.name().ok().map(str::to_owned)),
            provenance.for_address(*address, None),
        ),
        Target::Symbol(name) => (Some(name.clone()), unknown_site()),
        Target::Unknown => (None, unknown_site()),
    };
    let symbol = match &name {
        Some(name) => format!("preinit_array[{index}]={name}"),
        None => format!("preinit_array[{index}]"),
    };
    NativeEscape::new(symbol, category(name.as_deref()), vec![site])
}

fn unknown_site() -> NativeProvenance {
    let mut site = NativeProvenance::unknown();
    site.section = Some(".preinit_array".to_owned());
    site
}

#[cfg(test)]
mod tests;
