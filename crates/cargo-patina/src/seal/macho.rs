//! Renaming and localising the symbols of a relocatable 64-bit Mach-O object
//! in place: the Mach-O half of the seal's rewrite (`elf.rs` is the ELF one).
//! The symbol table, the relocation entries' symbol numbers, the indirect
//! symbol table and the string table change; every section's bytes stay where
//! the linker wrote them.
//!
//! Apple's relocatable link has no `--wrap`, and resolves every member's
//! reference to a door to the door's definition, so the split happens here:
//! the definition takes the implementation's name, and every relocation that
//! named it, outside the unwind and debug tables that describe the definition
//! itself, names the door's host binding instead. One inside a door's own
//! definition refuses the rewrite. Darwin has no route aliases, so no engine
//! reference names the door itself.
//!
//! A Mach-O symbol table orders local symbols, then defined externals, then
//! undefined ones, so every symbol this localises or adds moves and every
//! reference to a symbol's index is renumbered. A weak definition made local
//! stops being weak: it is no longer coalesced with a guest's of the same name.
//! A global's debug note (`N_GSYM`) names it, and the final link finds only a
//! global by that name, so a localised global's note becomes a static's
//! (`N_STSYM`), which carries its address instead; a note naming no global
//! (the toolchain's own `compiler_builtins` has a few) is dropped.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const MH_MAGIC_64: u32 = 0xfeed_facf;
const MH_OBJECT: u32 = 1;
const MH_SUBSECTIONS_VIA_SYMBOLS: u32 = 0x2000;
const HEADER: usize = 32;
const LC_SYMTAB: u32 = 0x2;
const LC_DYSYMTAB: u32 = 0xb;
const LC_SEGMENT_64: u32 = 0x19;
const LC_VERSION_MIN_MACOSX: u32 = 0x24;
const LC_FUNCTION_STARTS: u32 = 0x26;
const LC_DATA_IN_CODE: u32 = 0x29;
const LC_LINKER_OPTION: u32 = 0x2d;
const LC_LINKER_OPTIMIZATION_HINT: u32 = 0x2e;
const LC_BUILD_VERSION: u32 = 0x32;
const SECTION: usize = 80;
const SYMBOL: usize = 16;
const RELOCATION: usize = 8;
const N_STAB: u8 = 0xe0;
const N_GSYM: u8 = 0x20;
const N_STSYM: u8 = 0x26;
const N_PEXT: u8 = 0x10;
const N_TYPE: u8 = 0x0e;
const N_EXT: u8 = 0x01;
const N_UNDF: u8 = 0x0;
const N_WEAK_DEF: u16 = 0x0080;
const R_SCATTERED: u32 = 0x8000_0000;
const INDIRECT_SYMBOL_LOCAL: u32 = 0x8000_0000;
const INDIRECT_SYMBOL_ABS: u32 = 0x4000_0000;
const SECTION_TYPE: u32 = 0xff;
const S_ATTR_DEBUG: u32 = 0x0200_0000;
const S_ZEROFILL: u32 = 0x1;
const S_GB_ZEROFILL: u32 = 0xc;
const S_THREAD_LOCAL_ZEROFILL: u32 = 0x12;

/// What the rewrite does to each global symbol, by its symbol name (with
/// Mach-O's leading underscore).
pub(super) struct Plan<'a> {
    /// A door's name to its implementation's: the definition takes the new
    /// name.
    pub(super) doors: &'a BTreeMap<String, String>,
    /// A door's name to its host binding's, the definition every reference
    /// to the door names instead.
    pub(super) bind: &'a BTreeMap<String, String>,
    /// The (new) names whose definitions stay global; every other global
    /// definition becomes local.
    pub(super) keep: &'a BTreeSet<String>,
    /// Mark the object as splittable at its symbols, as every member it was
    /// linked from is (`subsections_via_symbols`).
    pub(super) subsections: bool,
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().expect("two bytes"))
}
fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("four bytes"))
}
fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("eight bytes"))
}
fn set_u32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

/// A section's place in the file and its relocations.
struct Section {
    /// `segname,sectname`, for the unwind-table test.
    name: (Vec<u8>, Vec<u8>),
    addr: u64,
    size: u64,
    debug: bool,
    reloff: usize,
    nreloc: usize,
}

fn trimmed(field: &[u8]) -> Vec<u8> {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    field[..end].to_vec()
}

/// Whether `section` describes its definitions rather than referring to them:
/// its references to a door's definition stay on the implementation.
fn describes_definitions(section: &Section) -> bool {
    section.debug
        || matches!(
            (section.name.0.as_slice(), section.name.1.as_slice()),
            (b"__TEXT", b"__eh_frame") | (b"__LD", b"__compact_unwind")
        )
}

/// Whether the member `bytes`, a relocatable Mach-O object, splits at its
/// symbols exactly as at its sections, so a merged object may be marked
/// `subsections_via_symbols` though it is not: each section holds no
/// non-temporary symbol but at its start.
pub(super) fn splits_at_symbols(bytes: &[u8]) -> Result<bool, String> {
    let object = Object::parse(bytes)?;
    if object.flags & MH_SUBSECTIONS_VIA_SYMBOLS != 0 {
        return Ok(true);
    }
    let symbols = object.symbols(bytes)?;
    let strings = object.strings(bytes)?;
    for symbol in symbols.as_chunks::<SYMBOL>().0 {
        let kind = symbol[4];
        if kind & N_STAB != 0 || kind & N_TYPE != 0xe {
            continue;
        }
        let name = name(strings, symbol)?;
        if name.starts_with('l') || name.starts_with('L') {
            continue;
        }
        let section = usize::from(symbol[5]);
        let start = object
            .section_addresses
            .get(section.wrapping_sub(1))
            .ok_or_else(|| format!("{name}: section {section} out of range"))?;
        if u64_at(symbol, 8) != *start {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The header fields and tables a rewrite reads.
struct Object {
    flags: u32,
    sections: Vec<Section>,
    section_addresses: Vec<u64>,
    /// Offset of the `symtab_command`.
    symtab: usize,
    dysymtab: Option<usize>,
    /// The end of every byte range in the file other than the symbol and
    /// string tables.
    data_end: usize,
}

impl Object {
    fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < HEADER || u32_at(bytes, 0) != MH_MAGIC_64 || u32_at(bytes, 12) != MH_OBJECT
        {
            return Err("not a little-endian 64-bit Mach-O relocatable object".into());
        }
        let ncmds = u32_at(bytes, 16) as usize;
        let sizeofcmds = u32_at(bytes, 20) as usize;
        let mut data_end = HEADER + sizeofcmds;
        let mut extend = |offset: usize, size: usize| -> Result<(), String> {
            let end = offset
                .checked_add(size)
                .filter(|end| *end <= bytes.len())
                .ok_or("a load command's data lies outside the file")?;
            if size > 0 {
                data_end = data_end.max(end);
            }
            Ok(())
        };
        let mut sections = Vec::new();
        let mut section_addresses = Vec::new();
        let (mut symtab, mut dysymtab) = (None, None);
        let mut at = HEADER;
        for _ in 0..ncmds {
            if at + 8 > HEADER + sizeofcmds {
                return Err("load commands overrun their size".into());
            }
            let (cmd, cmdsize) = (u32_at(bytes, at), u32_at(bytes, at + 4) as usize);
            match cmd {
                LC_SEGMENT_64 => {
                    for index in 0..u32_at(bytes, at + 64) as usize {
                        let header = &bytes[at + 72 + index * SECTION..][..SECTION];
                        let flags = u32_at(header, 64);
                        if !matches!(
                            flags & SECTION_TYPE,
                            S_ZEROFILL | S_GB_ZEROFILL | S_THREAD_LOCAL_ZEROFILL
                        ) {
                            extend(u32_at(header, 48) as usize, u64_at(header, 40) as usize)?;
                        }
                        let (reloff, nreloc) =
                            (u32_at(header, 56) as usize, u32_at(header, 60) as usize);
                        extend(reloff, nreloc * RELOCATION)?;
                        section_addresses.push(u64_at(header, 32));
                        sections.push(Section {
                            name: (trimmed(&header[16..32]), trimmed(&header[..16])),
                            addr: u64_at(header, 32),
                            size: u64_at(header, 40),
                            debug: flags & S_ATTR_DEBUG != 0,
                            reloff,
                            nreloc,
                        });
                    }
                }
                LC_SYMTAB => symtab = Some(at),
                LC_DYSYMTAB => {
                    // Only the indirect symbol table belongs in an object.
                    for field in [36, 44, 52, 68, 76] {
                        if u32_at(bytes, at + field) != 0 {
                            return Err("an object with a dynamic library's tables".into());
                        }
                    }
                    extend(
                        u32_at(bytes, at + 56) as usize,
                        u32_at(bytes, at + 60) as usize * 4,
                    )?;
                    dysymtab = Some(at);
                }
                LC_FUNCTION_STARTS | LC_DATA_IN_CODE | LC_LINKER_OPTIMIZATION_HINT => {
                    extend(
                        u32_at(bytes, at + 8) as usize,
                        u32_at(bytes, at + 12) as usize,
                    )?;
                }
                LC_BUILD_VERSION | LC_VERSION_MIN_MACOSX | LC_LINKER_OPTION => {}
                other => return Err(format!("unexpected load command {other:#x}")),
            }
            at += cmdsize;
        }
        Ok(Self {
            flags: u32_at(bytes, 24),
            sections,
            section_addresses,
            symtab: symtab.ok_or("no symbol table")?,
            dysymtab,
            data_end,
        })
    }

    fn symbols<'a>(&self, bytes: &'a [u8]) -> Result<&'a [u8], String> {
        let (offset, count) = (
            u32_at(bytes, self.symtab + 8) as usize,
            u32_at(bytes, self.symtab + 12) as usize,
        );
        bytes
            .get(offset..offset + count * SYMBOL)
            .ok_or_else(|| "the symbol table lies outside the file".into())
    }

    fn strings<'a>(&self, bytes: &'a [u8]) -> Result<&'a [u8], String> {
        let (offset, size) = (
            u32_at(bytes, self.symtab + 16) as usize,
            u32_at(bytes, self.symtab + 20) as usize,
        );
        bytes
            .get(offset..offset + size)
            .ok_or_else(|| "the string table lies outside the file".into())
    }
}

fn name(strings: &[u8], symbol: &[u8]) -> Result<String, String> {
    let rest = strings
        .get(u32_at(symbol, 0) as usize..)
        .ok_or("symbol name out of range")?;
    let end = rest
        .iter()
        .position(|byte| *byte == 0)
        .ok_or("unterminated name")?;
    String::from_utf8(rest[..end].to_vec()).map_err(|error| error.to_string())
}

/// Rewrite the symbols of the relocatable Mach-O object at `path` per `plan`.
pub(super) fn rewrite(path: &Path, plan: &Plan<'_>) -> Result<(), String> {
    let mut bytes = std::fs::read(path).map_err(|error| error.to_string())?;
    let object = Object::parse(&bytes)?;
    let old = object.symbols(&bytes)?.to_vec();
    let mut strings = object.strings(&bytes)?.to_vec();
    let total = old.len() / SYMBOL;

    // The symbols in their new order: locals as they were, then those
    // localised, the kept definitions and the undefined ones.
    let mut symbols: Vec<[u8; SYMBOL]> = Vec::with_capacity(total);
    let (mut locals, mut localised, mut kept, mut undefined) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    // Door definitions by old index, to the door's name.
    let mut split: BTreeMap<usize, &str> = BTreeMap::new();
    // Global definitions by (old) name, to their index.
    let mut definitions: BTreeMap<String, usize> = BTreeMap::new();
    // Undefined references to a door the C seams define.
    let mut seam_references: Vec<(usize, String)> = Vec::new();
    for (index, symbol) in old.as_chunks::<SYMBOL>().0.iter().enumerate() {
        let mut symbol = *symbol;
        let kind = symbol[4];
        if kind & N_STAB != 0 || kind & N_EXT == 0 {
            locals.push(index);
            symbols.push(symbol);
            continue;
        }
        let name = name(&strings, &symbol)?;
        if kind & N_TYPE == N_UNDF {
            if u64_at(&symbol, 8) != 0 {
                return Err(format!(
                    "common symbol {name}: no section to localise it in"
                ));
            }
            if plan.bind.contains_key(&name) {
                seam_references.push((index, name.clone()));
            }
            undefined.push((name, index));
            symbols.push(symbol);
            continue;
        }
        definitions.insert(name.clone(), index);
        let new = match plan.doors.get_key_value(&name) {
            Some((door, implementation)) => {
                split.insert(index, door.as_str());
                let at = u32::try_from(strings.len()).map_err(|error| error.to_string())?;
                strings.extend_from_slice(implementation.as_bytes());
                strings.push(0);
                symbol[..4].copy_from_slice(&at.to_le_bytes());
                implementation.clone()
            }
            None => name,
        };
        if plan.keep.contains(&new) {
            kept.push((new, index));
        } else {
            symbol[4] = kind & !(N_EXT | N_PEXT);
            let desc = u16_at(&symbol, 6) & !N_WEAK_DEF;
            symbol[6..8].copy_from_slice(&desc.to_le_bytes());
            localised.push(index);
        }
        symbols.push(symbol);
    }
    // Each door's binding, and the extent of its definition: to the next
    // symbol in its section, or the section's end.
    let mut starts: BTreeMap<u8, BTreeSet<u64>> = BTreeMap::new();
    for symbol in &symbols {
        if symbol[4] & N_STAB == 0 && symbol[4] & N_TYPE == 0xe {
            starts
                .entry(symbol[5])
                .or_default()
                .insert(u64_at(symbol, 8));
        }
    }
    let mut bindings: BTreeMap<usize, usize> = BTreeMap::new();
    let mut bodies: BTreeMap<u8, Vec<(u64, u64, &str)>> = BTreeMap::new();
    for (&index, door) in &split {
        let binding = plan
            .bind
            .get(*door)
            .and_then(|binding| definitions.get(binding))
            .ok_or_else(|| format!("no host binding for {door}"))?;
        bindings.insert(index, *binding);
        let symbol = &symbols[index];
        let (section, start) = (symbol[5], u64_at(symbol, 8));
        let end = starts
            .get(&section)
            .and_then(|starts| starts.range(start + 1..).next().copied())
            .or_else(|| {
                let header = object.sections.get(usize::from(section).wrapping_sub(1))?;
                Some(header.addr + header.size)
            })
            .unwrap_or(start);
        bodies.entry(section).or_default().push((start, end, door));
    }
    for (index, door) in &seam_references {
        let binding = definitions
            .get(&plan.bind[door])
            .ok_or_else(|| format!("no host binding for {door}"))?;
        bindings.insert(*index, *binding);
    }
    // Every door a reference may name, by its symbol's index.
    let named_doors: BTreeMap<usize, &str> = split
        .iter()
        .map(|(index, door)| (*index, *door))
        .chain(
            seam_references
                .iter()
                .map(|(index, door)| (*index, door.as_str())),
        )
        .collect();
    // Each global debug note follows its symbol: kept, made a static's, or
    // dropped with nothing to describe.
    let mut addresses: BTreeMap<String, (u8, u64)> = BTreeMap::new();
    for index in &localised {
        let symbol = &symbols[*index];
        addresses
            .entry(name(&strings, symbol)?)
            .or_insert((symbol[5], u64_at(symbol, 8)));
    }
    let globals: BTreeSet<&str> = kept.iter().map(|(name, _)| name.as_str()).collect();
    let mut notes = Vec::with_capacity(locals.len());
    for index in locals {
        let symbol = &mut symbols[index];
        if symbol[4] != N_GSYM {
            notes.push(index);
            continue;
        }
        let noted = name(&strings, symbol)?;
        if globals.contains(noted.as_str()) {
            notes.push(index);
        } else if let Some((section, address)) = addresses.get(&noted) {
            symbol[4] = N_STSYM;
            symbol[5] = *section;
            symbol[8..16].copy_from_slice(&address.to_le_bytes());
            notes.push(index);
        }
    }
    let locals = notes;
    kept.sort();
    undefined.sort();
    let order: Vec<usize> = locals
        .iter()
        .chain(&localised)
        .copied()
        .chain(kept.iter().map(|(_, index)| *index))
        .chain(undefined.iter().map(|(_, index)| *index))
        .collect();
    let mut renumber = vec![0u32; symbols.len()];
    for (position, index) in order.iter().enumerate() {
        renumber[*index] = u32::try_from(position).map_err(|error| error.to_string())?;
    }
    let remap = |index: usize, describing: bool| -> Result<u32, String> {
        let target = match bindings.get(&index) {
            Some(binding) if !describing => *binding,
            _ => index,
        };
        renumber
            .get(target)
            .copied()
            .ok_or_else(|| format!("symbol index {index} out of range"))
    };

    let mut refused: BTreeSet<(&str, &str)> = BTreeSet::new();
    for (number, section) in object.sections.iter().enumerate() {
        let describing = describes_definitions(section);
        for entry in 0..section.nreloc {
            let at = section.reloff + entry * RELOCATION;
            if u32_at(&bytes, at) & R_SCATTERED != 0 {
                return Err("a scattered relocation".into());
            }
            let info = u32_at(&bytes, at + 4);
            // r_symbolnum:24, r_pcrel:1, r_length:2, r_extern:1, r_type:4.
            if info & (1 << 27) == 0 {
                continue;
            }
            let named = (info & 0x00ff_ffff) as usize;
            if let Some(door) = named_doors.get(&named).filter(|_| !describing) {
                let site = section.addr + u64::from(u32_at(&bytes, at));
                let section = u8::try_from(number + 1).unwrap_or(0);
                if let Some((_, _, caller)) = bodies.get(&section).and_then(|bodies| {
                    bodies
                        .iter()
                        .find(|(start, end, _)| (*start..*end).contains(&site))
                }) {
                    refused.insert((caller, door));
                }
            }
            let symbol = remap(named, describing)?;
            if symbol > 0x00ff_ffff {
                return Err("more symbols than a relocation can name".into());
            }
            set_u32(&mut bytes, at + 4, (info & 0xff00_0000) | symbol);
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
    if let Some(dysymtab) = object.dysymtab {
        let (offset, count) = (
            u32_at(&bytes, dysymtab + 56) as usize,
            u32_at(&bytes, dysymtab + 60) as usize,
        );
        for at in (offset..offset + count * 4).step_by(4) {
            let entry = u32_at(&bytes, at);
            if entry & (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS) == 0 {
                set_u32(&mut bytes, at, remap(entry as usize, false)?);
            }
        }
        let count = |group: usize| u32::try_from(group).expect("a symbol count fits");
        let locals = count(locals.len() + localised.len());
        set_u32(&mut bytes, dysymtab + 8, 0);
        set_u32(&mut bytes, dysymtab + 12, locals);
        set_u32(&mut bytes, dysymtab + 16, locals);
        set_u32(&mut bytes, dysymtab + 20, count(kept.len()));
        set_u32(&mut bytes, dysymtab + 24, locals + count(kept.len()));
        set_u32(&mut bytes, dysymtab + 28, count(undefined.len()));
    }

    // The new tables replace the old ones at the end of the file, or follow
    // the file where something else lies after them.
    let tables = object.symtab;
    let old_start = (u32_at(&bytes, tables + 8) as usize).min(u32_at(&bytes, tables + 16) as usize);
    let start = if object.data_end <= old_start {
        old_start
    } else {
        bytes.len()
    };
    bytes.truncate(start);
    bytes.resize(start.next_multiple_of(8), 0);
    let symoff = bytes.len();
    for index in &order {
        bytes.extend_from_slice(&symbols[*index]);
    }
    let stroff = bytes.len();
    bytes.extend_from_slice(&strings);
    bytes.resize(bytes.len().next_multiple_of(8), 0);
    let fits = |value: usize| u32::try_from(value).map_err(|error| error.to_string());
    let strsize = fits(bytes.len() - stroff)?;
    set_u32(&mut bytes, tables + 8, fits(symoff)?);
    set_u32(&mut bytes, tables + 12, fits(order.len())?);
    set_u32(&mut bytes, tables + 16, fits(stroff)?);
    set_u32(&mut bytes, tables + 20, strsize);
    if plan.subsections {
        let flags = object.flags | MH_SUBSECTIONS_VIA_SYMBOLS;
        set_u32(&mut bytes, 24, flags);
    }
    std::fs::write(path, bytes).map_err(|error| error.to_string())
}
