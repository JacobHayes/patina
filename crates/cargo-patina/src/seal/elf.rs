//! Renaming and localising the symbols of a relocatable ELF object in place:
//! the part of `objcopy --redefine-syms --keep-global-symbols --weaken-symbol`
//! the seal needs, at a fraction of its cost. Only the symbol table, the
//! symbol references of relocation and group sections, and the string table
//! change; every other byte of the object stays where the linker wrote it.
//!
//! ELF orders a symbol table's local symbols before its global ones, so the
//! symbols this localises move down into the local part, and every reference
//! to a global symbol's index is renumbered. A COMDAT group whose signature
//! ends up local stops being COMDAT.
//!
//! The rewrite also binds references: a relocation in a loaded section other
//! than the unwind table that names a symbol the plan binds names its binding
//! instead, unless it lies in a door's own definition, which refuses the
//! rewrite.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::Path;

const SHT_SYMTAB: u32 = 2;
const SHT_RELA: u32 = 4;
const SHT_REL: u32 = 9;
const SHT_GROUP: u32 = 17;
const SHT_SYMTAB_SHNDX: u32 = 18;
const SHN_UNDEF: u16 = 0;
const SHN_COMMON: u16 = 0xfff2;
const SHN_XINDEX: u16 = 0xffff;
const SHF_ALLOC: u64 = 0x2;
const STB_LOCAL: u8 = 0;
const GRP_COMDAT: u32 = 1;
const STB_WEAK: u8 = 2;
const SYMBOL: usize = 24;
const HEADER: usize = 64;

/// What the rewrite does to each global symbol, by name.
pub(super) struct Plan<'a> {
    /// Old name to new name; applies to definitions and references alike.
    pub(super) renames: &'a BTreeMap<String, String>,
    /// The (new) names whose definitions stay global; every other global
    /// definition becomes local.
    pub(super) keep: &'a BTreeSet<String>,
    /// Kept definitions made weak.
    pub(super) weaken: &'a BTreeSet<String>,
    /// The (old) names whose definitions become references to their new name.
    pub(super) undefine: &'a BTreeSet<String>,
    /// Old name to the (old) name of the definition every reference to it
    /// from loaded code or data binds to instead.
    pub(super) bind: &'a BTreeMap<String, String>,
    /// The (old) names of the doors, whose own definitions may name no
    /// symbol the plan binds.
    pub(super) doors: &'a BTreeSet<String>,
}

#[derive(Clone)]
struct Section {
    header: [u8; HEADER],
}

impl Section {
    fn u32(&self, at: usize) -> u32 {
        u32::from_le_bytes(self.header[at..at + 4].try_into().expect("four bytes"))
    }
    fn u64(&self, at: usize) -> u64 {
        u64::from_le_bytes(self.header[at..at + 8].try_into().expect("eight bytes"))
    }
    fn name(&self) -> u32 {
        self.u32(0)
    }
    fn kind(&self) -> u32 {
        self.u32(4)
    }
    fn flags(&self) -> u64 {
        self.u64(8)
    }
    fn offset(&self) -> u64 {
        self.u64(24)
    }
    fn size(&self) -> u64 {
        self.u64(32)
    }
    fn link(&self) -> u32 {
        self.u32(40)
    }
    fn info(&self) -> u32 {
        self.u32(44)
    }
    fn set_u32(&mut self, at: usize, value: u32) {
        self.header[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn set_u64(&mut self, at: usize, value: u64) {
        self.header[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
}

/// Rewrite the symbols of the little-endian ELF64 relocatable object at
/// `path` per `plan`, in place.
pub(super) fn rewrite(path: &Path, plan: &Plan<'_>) -> Result<(), String> {
    let file = File::options()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|error| error.to_string())?;
    let read = |offset: u64, length: u64| -> Result<Vec<u8>, String> {
        let mut bytes = vec![0; usize::try_from(length).map_err(|error| error.to_string())?];
        file.read_exact_at(&mut bytes, offset)
            .map_err(|error| error.to_string())?;
        Ok(bytes)
    };
    let ident = read(0, HEADER as u64)?;
    if ident[..4] != *b"\x7fELF" || ident[4] != 2 || ident[5] != 1 || ident[16..18] != [1, 0] {
        return Err("not a little-endian ELF64 relocatable object".into());
    }
    let shoff = u64::from_le_bytes(ident[0x28..0x30].try_into().expect("eight bytes"));
    let shentsize = u16::from_le_bytes([ident[0x3a], ident[0x3b]]);
    if usize::from(shentsize) != HEADER {
        return Err(format!("unexpected section header size {shentsize}"));
    }
    let mut count = u64::from(u16::from_le_bytes([ident[0x3c], ident[0x3d]]));
    if count == 0 {
        // Extended numbering: the count is the null section's size.
        count = u64::from_le_bytes(read(shoff + 32, 8)?.try_into().expect("eight bytes"));
    }
    let table = read(shoff, count * HEADER as u64)?;
    let mut sections: Vec<Section> = table
        .as_chunks::<HEADER>()
        .0
        .iter()
        .map(|header| Section { header: *header })
        .collect();
    let mut symtabs = sections
        .iter()
        .enumerate()
        .filter(|(_, section)| section.kind() == SHT_SYMTAB);
    let (symtab, None) = (symtabs.next(), symtabs.next()) else {
        return Err("more than one symbol table".into());
    };
    let (symtab_index, symtab) = symtab.ok_or("no symbol table")?;
    let symtab = symtab.clone();
    let strtab_index = symtab.link() as usize;
    let strtab = sections.get(strtab_index).ok_or("no string table")?.clone();
    let mut symbols = read(symtab.offset(), symtab.size())?;
    let mut strings = read(strtab.offset(), strtab.size())?;
    let total = symbols.len() / SYMBOL;
    let first_global = symtab.info() as usize;
    if first_global > total {
        return Err("symbol table's local count exceeds its size".into());
    }

    let name = |strings: &[u8], symbol: &[u8]| -> Result<String, String> {
        let at = u32::from_le_bytes(symbol[..4].try_into().expect("four bytes")) as usize;
        let rest = strings.get(at..).ok_or("symbol name out of range")?;
        let end = rest
            .iter()
            .position(|byte| *byte == 0)
            .ok_or("unterminated name")?;
        String::from_utf8(rest[..end].to_vec()).map_err(|error| error.to_string())
    };
    // What binding needs, read before the rewrite changes any symbol: each
    // bound symbol's binding, the extent of each door's definition, and the
    // sections whose references bind (loaded, other than the unwind table).
    let shndx_table = match sections.iter().find(|section| {
        section.kind() == SHT_SYMTAB_SHNDX && section.link() as usize == symtab_index
    }) {
        Some(section) => Some(read(section.offset(), section.size())?),
        None => None,
    };
    let section_of = |index: usize, symbol: &[u8]| -> Result<usize, String> {
        let shndx = u16::from_le_bytes([symbol[6], symbol[7]]);
        if shndx != SHN_XINDEX {
            return Ok(usize::from(shndx));
        }
        let table = shndx_table
            .as_ref()
            .ok_or("an extended section index without its table")?;
        let entry = table
            .get(index * 4..index * 4 + 4)
            .ok_or("an extended section index out of range")?;
        Ok(u32::from_le_bytes(entry.try_into().expect("four bytes")) as usize)
    };
    let mut globals: BTreeMap<String, u32> = BTreeMap::new();
    let mut bodies: BTreeMap<usize, Vec<(u64, u64, String)>> = BTreeMap::new();
    for index in first_global..total {
        let symbol = &symbols[index * SYMBOL..(index + 1) * SYMBOL];
        let old = name(&strings, symbol)?;
        let shndx = u16::from_le_bytes([symbol[6], symbol[7]]);
        if plan.doors.contains(&old) && shndx != SHN_UNDEF {
            let value = u64::from_le_bytes(symbol[8..16].try_into().expect("eight bytes"));
            let size = u64::from_le_bytes(symbol[16..24].try_into().expect("eight bytes"));
            bodies.entry(section_of(index, symbol)?).or_default().push((
                value,
                value + size,
                old.clone(),
            ));
        }
        globals.insert(
            old,
            u32::try_from(index).map_err(|error| error.to_string())?,
        );
    }
    let mut bindings: BTreeMap<u32, (u32, &str)> = BTreeMap::new();
    for (bound, binding) in plan.bind {
        let Some(&index) = globals.get(bound) else {
            continue;
        };
        let target = *globals
            .get(binding)
            .ok_or_else(|| format!("no binding {binding} for {bound}"))?;
        let door = bound.strip_prefix("__wrap_").unwrap_or(bound);
        bindings.insert(index, (target, door));
    }
    let section_names = {
        let index = match u16::from_le_bytes([ident[0x3e], ident[0x3f]]) {
            SHN_XINDEX => sections[0].link() as usize,
            index => usize::from(index),
        };
        let table = sections.get(index).ok_or("no section name table")?;
        read(table.offset(), table.size())?
    };
    let binding_sections: Vec<bool> = sections
        .iter()
        .map(|section| {
            let name = section_names
                .get(section.name() as usize..)
                .and_then(|rest| rest.split(|byte| *byte == 0).next())
                .unwrap_or_default();
            section.flags() & SHF_ALLOC != 0 && name != b".eh_frame"
        })
        .collect();
    let mut refused: BTreeSet<(String, &str)> = BTreeSet::new();

    // The globals in their new order: those localised, then those kept.
    let mut localised = Vec::new();
    let mut kept = Vec::new();
    for index in first_global..total {
        let symbol = &mut symbols[index * SYMBOL..(index + 1) * SYMBOL];
        let old = name(&strings, symbol)?;
        if plan.undefine.contains(&old) {
            // Global, untyped, default visibility, no section, value or size.
            symbol[4] = 1 << 4;
            symbol[5] = 0;
            symbol[6..].fill(0);
        }
        let renamed = plan.renames.get(&old);
        let new = renamed.cloned().unwrap_or(old);
        let shndx = u16::from_le_bytes([symbol[6], symbol[7]]);
        if shndx == SHN_COMMON {
            return Err(format!("common symbol {new}: no section to localise it in"));
        }
        if renamed.is_some() {
            let at = u32::try_from(strings.len()).map_err(|error| error.to_string())?;
            strings.extend_from_slice(new.as_bytes());
            strings.push(0);
            symbol[..4].copy_from_slice(&at.to_le_bytes());
        }
        let kind = symbol[4] & 0xf;
        if shndx != SHN_UNDEF && !plan.keep.contains(&new) {
            symbol[4] = (STB_LOCAL << 4) | kind;
            localised.push(index);
        } else {
            if shndx != SHN_UNDEF && plan.weaken.contains(&new) {
                symbol[4] = (STB_WEAK << 4) | kind;
            }
            kept.push(index);
        }
    }
    let mut renumber: Vec<u32> = (0..total as u32).collect();
    for (position, old) in localised.iter().chain(&kept).enumerate() {
        renumber[*old] =
            u32::try_from(first_global + position).map_err(|error| error.to_string())?;
    }
    let mut reordered = symbols[..first_global * SYMBOL].to_vec();
    for old in localised.iter().chain(&kept) {
        reordered.extend_from_slice(&symbols[old * SYMBOL..(old + 1) * SYMBOL]);
    }
    let remap = |index: u32| -> Result<u32, String> {
        renumber
            .get(index as usize)
            .copied()
            .ok_or_else(|| format!("symbol index {index} out of range"))
    };

    let locals =
        u32::try_from(first_global + localised.len()).map_err(|error| error.to_string())?;
    for section in &mut sections {
        if section.link() as usize != symtab_index {
            continue;
        }
        match section.kind() {
            SHT_RELA | SHT_REL => {
                let entry = if section.kind() == SHT_RELA { 24 } else { 16 };
                let target = section.info() as usize;
                let binds = binding_sections.get(target).copied().unwrap_or(false);
                let mut relocations = read(section.offset(), section.size())?;
                let mut changed = false;
                for relocation in relocations.chunks_exact_mut(entry) {
                    let info =
                        u64::from_le_bytes(relocation[8..16].try_into().expect("eight bytes"));
                    let mut symbol = (info >> 32) as u32;
                    if binds && let Some(&(binding, door)) = bindings.get(&symbol) {
                        let offset =
                            u64::from_le_bytes(relocation[..8].try_into().expect("eight bytes"));
                        if let Some((_, _, caller)) = bodies.get(&target).and_then(|bodies| {
                            bodies
                                .iter()
                                .find(|(start, end, _)| (*start..*end).contains(&offset))
                        }) {
                            refused.insert((caller.clone(), door));
                        }
                        symbol = binding;
                    }
                    if (symbol as usize) < first_global {
                        continue;
                    }
                    let info = (u64::from(remap(symbol)?) << 32) | (info & 0xffff_ffff);
                    relocation[8..16].copy_from_slice(&info.to_le_bytes());
                    changed = true;
                }
                if changed {
                    file.write_all_at(&relocations, section.offset())
                        .map_err(|error| error.to_string())?;
                }
            }
            SHT_GROUP => {
                let signature = remap(section.info())?;
                section.set_u32(44, signature);
                // The final link keeps one COMDAT group per signature name,
                // whatever its binding: a guest's group of a name the engine
                // made local would discard the engine's, leaving its local
                // definitions in a discarded section. A plain group is never
                // discarded, and the engine, one object, holds no duplicate.
                if signature < locals {
                    let flags = read(section.offset(), 4)?;
                    let flags = u32::from_le_bytes(flags.try_into().expect("four bytes"));
                    file.write_all_at(&(flags & !GRP_COMDAT).to_le_bytes(), section.offset())
                        .map_err(|error| error.to_string())?;
                }
            }
            SHT_SYMTAB_SHNDX => {
                let entries = read(section.offset(), section.size())?;
                let mut moved = entries[..first_global * 4].to_vec();
                for old in localised.iter().chain(&kept) {
                    moved.extend_from_slice(&entries[old * 4..(old + 1) * 4]);
                }
                file.write_all_at(&moved, section.offset())
                    .map_err(|error| error.to_string())?;
            }
            _ => {}
        }
    }
    if !refused.is_empty() {
        let pairs: Vec<String> = refused
            .iter()
            .map(|(caller, door)| format!("{caller} -> {door}"))
            .collect();
        return Err(format!(
            "doors whose own code names another door, which binds to the host's: {pairs:?}"
        ));
    }

    file.write_all_at(&reordered, symtab.offset())
        .map_err(|error| error.to_string())?;
    // The grown string table moves to the end of the file.
    let end = file.metadata().map_err(|error| error.to_string())?.len();
    file.write_all_at(&strings, end)
        .map_err(|error| error.to_string())?;
    sections[strtab_index].set_u64(24, end);
    sections[strtab_index].set_u64(32, strings.len() as u64);
    sections[symtab_index].set_u32(44, locals);
    let table: Vec<u8> = sections.iter().flat_map(|section| section.header).collect();
    file.write_all_at(&table, shoff)
        .map_err(|error| error.to_string())
}
