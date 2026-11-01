//! The fixed footprint of the objects an ELF seal emits (ARCHITECTURE.md,
//! "The sealed shim"). The guest's own code and data follow the shim's in
//! the final link, and a guest observes its own addresses: Go hashes
//! pointers, so a type descriptor that moves reshapes a map, and with it the
//! comparisons the compute meter charges. So no change inside the shim may
//! move the guest. Each object the seal emits takes a footprint its content
//! decides only through a size class:
//!
//! - each loaded kind of section (code; read-only data with the exception
//!   tables; relocated read-only data; data; zeroed data; and the two thread
//!   locals) is one section of a class size at a fixed alignment, matching
//!   the default scripts' patterns for its kind;
//! - the unwind table's live FDEs are a class count and a class size, padded
//!   with FDEs over pad code (glibc's forced unwind crosses shim frames, so
//!   the table stays a standard one);
//! - the absolute pointers, each a dynamic relocation in a
//!   position-independent guest, are a class count;
//! - the object's references to its own definitions reach no GOT entry: each
//!   loads from a private slot (`elf::privatise_got`).
//!
//! A class is the least of 2^k and 3·2^(k-1) at or above a bound the content
//! decides, so the guest moves only when the shim crosses one. What stays
//! variable is the shim's interface: the symbols the guest links (dynamic
//! symbols, the host imports' PLT and GOT entries and copy relocations),
//! shared COMDAT groups, init and fini arrays, notes and the static-sites
//! table, and the set of distinct CIEs the final link merges. The FDE bytes
//! are as GNU `ld`, the seal's linker, leaves them, trailing `DW_CFA_nop`s
//! stripped; an LLVM relocatable link keeps them, which a GNU final link
//! then drops.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use object::LittleEndian as LE;
use object::elf;
use object::read::elf::{ElfFile64, FileHeader, Rela as _, SectionHeader, SectionTable, Sym as _};

type Header = elf::FileHeader64<LE>;
/// A loaded section: its index, header and name.
type Loaded<'data> = (usize, &'data elf::SectionHeader64<LE>, &'data str);

/// The section the private GOT slots fill, and their symbols' prefix: slot
/// `i` is `patina_got_<i>`, at `8 * i`.
pub(super) const SLOTS: &str = ".data.rel.ro.patina_got";
pub(super) const SLOT: &str = "patina_got_";

/// Every merged section's alignment.
const ALIGN: u64 = 64;

/// One merged section: its name, the input sections it takes (a trailing
/// `*` matches any rest), and its least class.
struct Blob {
    name: &'static str,
    inputs: &'static [&'static str],
    floor: u64,
}

/// In placement order: the first whose inputs match takes a section, as the
/// linker script's statements do.
const BLOBS: [Blob; 7] = [
    Blob {
        name: ".text.patina",
        inputs: &[".text", ".text.*"],
        floor: 4096,
    },
    Blob {
        name: ".rodata.patina",
        inputs: &[
            ".rodata",
            ".rodata.*",
            ".gcc_except_table",
            ".gcc_except_table.*",
        ],
        floor: 4096,
    },
    Blob {
        name: ".data.rel.ro.patina",
        inputs: &[".data.rel.ro", ".data.rel.ro.*"],
        floor: 4096,
    },
    Blob {
        name: ".data.patina",
        inputs: &[".data", ".data.*"],
        floor: 4096,
    },
    Blob {
        name: ".bss.patina",
        inputs: &[".bss", ".bss.*"],
        floor: 4096,
    },
    Blob {
        name: ".tdata.patina",
        inputs: &[".tdata", ".tdata.*"],
        floor: 256,
    },
    Blob {
        name: ".tbss.patina",
        inputs: &[".tbss", ".tbss.*"],
        floor: 256,
    },
];

/// Loaded sections the footprint leaves as they are: the shim's interface
/// (constructors, the static-sites table, the preinit hook) and notes.
fn interface(name: &str) -> bool {
    [".init_array", ".fini_array", ".preinit_array", ".note"]
        .iter()
        .any(|prefix| name.starts_with(prefix))
        || name == "patina_sites"
        || name == ".patina.preinit"
}

/// The alignment the pad's unwind table takes, and so the one the table
/// before it grows to.
const TABLE_ALIGN: u64 = 8;

/// The size of one pad FDE: the linkers keep an FDE's instructions but drop
/// its trailing `DW_CFA_nop`s, padding it to a word.
const FDE: u64 = 20;

/// The architecture's relocation and code facts the footprint relies on.
#[derive(Clone, Copy)]
pub(super) struct Arch {
    aarch64: bool,
}

impl Arch {
    fn of(machine: u16) -> Result<Self, String> {
        match machine {
            elf::EM_X86_64 => Ok(Self { aarch64: false }),
            elf::EM_AARCH64 => Ok(Self { aarch64: true }),
            other => Err(format!("no footprint for ELF machine {other}")),
        }
    }

    /// For a relocation that reaches its symbol through a GOT entry: the
    /// type that reaches a slot holding the symbol's address in the same
    /// way, if one does.
    pub(super) fn got(self, kind: u32) -> Option<Option<u32>> {
        let retarget = if self.aarch64 {
            match kind {
                elf::R_AARCH64_ADR_GOT_PAGE => Some(elf::R_AARCH64_ADR_PREL_PG_HI21),
                elf::R_AARCH64_LD64_GOT_LO12_NC => Some(elf::R_AARCH64_LDST64_ABS_LO12_NC),
                elf::R_AARCH64_GOT_LD_PREL19 => Some(elf::R_AARCH64_LD_PREL_LO19),
                elf::R_AARCH64_LD64_GOTPAGE_LO15 | elf::R_AARCH64_LD64_GOTOFF_LO15 => None,
                _ => return None,
            }
        } else {
            match kind {
                elf::R_X86_64_GOTPCREL | elf::R_X86_64_GOTPCRELX | elf::R_X86_64_REX_GOTPCRELX => {
                    Some(elf::R_X86_64_PC32)
                }
                elf::R_X86_64_GOT32
                | elf::R_X86_64_GOT64
                | elf::R_X86_64_GOTPCREL64
                | elf::R_X86_64_GOTPLT64 => None,
                _ => return None,
            }
        };
        Some(retarget)
    }

    /// Whether a GOT reference must carry no addend to load from a slot:
    /// aarch64's name the entry of symbol plus addend; x86_64's addend is
    /// the instruction's.
    pub(super) fn got_addend_free(self) -> bool {
        self.aarch64
    }

    /// The absolute pointer, the slot's relocation.
    pub(super) fn abs64(self) -> u32 {
        if self.aarch64 {
            elf::R_AARCH64_ABS64
        } else {
            elf::R_X86_64_64
        }
    }

    fn is_none(self, kind: u32) -> bool {
        // aarch64 also spells none 256 (`R_AARCH64_NULL`).
        kind == 0 || (self.aarch64 && kind == 256)
    }
}

/// The ELF machine of a relocatable object.
pub(super) fn arch(bytes: &[u8]) -> Result<Arch, String> {
    let file = ElfFile64::<LE>::parse(bytes).map_err(|error| error.to_string())?;
    Arch::of(file.elf_header().e_machine(LE))
}

/// One relocation as the footprint reads it.
struct Relocation {
    offset: u64,
    kind: u32,
    /// The symbol, and whether it is defined.
    symbol: u32,
    defined: bool,
}

/// What a footprint reads of a relocatable object.
struct Read<'data> {
    arch: Arch,
    sections: SectionTable<'data, Header, &'data [u8]>,
    data: &'data [u8],
    file: ElfFile64<'data, LE>,
    /// The relocation sections against each section.
    relas: BTreeMap<usize, Vec<usize>>,
}

impl<'data> Read<'data> {
    fn parse(data: &'data [u8]) -> Result<Self, String> {
        let file = ElfFile64::<LE>::parse(data).map_err(|error| error.to_string())?;
        let header = file.elf_header();
        if header.e_type(LE) != elf::ET_REL {
            return Err("not a relocatable object".into());
        }
        let arch = Arch::of(header.e_machine(LE))?;
        let sections = header
            .sections(LE, data)
            .map_err(|error| error.to_string())?;
        let mut relas: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for (index, header) in sections.iter().enumerate() {
            if header.sh_type(LE) == elf::SHT_RELA {
                relas
                    .entry(header.sh_info(LE) as usize)
                    .or_default()
                    .push(index);
            }
        }
        Ok(Self {
            arch,
            sections,
            data,
            file,
            relas,
        })
    }

    fn name(&self, header: &elf::SectionHeader64<LE>) -> Result<&'data str, String> {
        let name = self
            .sections
            .section_name(LE, header)
            .map_err(|error| error.to_string())?;
        std::str::from_utf8(name).map_err(|error| error.to_string())
    }

    /// The loaded sections, by index, with their names.
    fn loaded(&self) -> Result<Vec<Loaded<'data>>, String> {
        let mut loaded = Vec::new();
        for (index, header) in self.sections.iter().enumerate() {
            if header.sh_flags(LE) & u64::from(elf::SHF_ALLOC) != 0 {
                loaded.push((index, header, self.name(header)?));
            }
        }
        Ok(loaded)
    }

    /// The relocations against section `target`.
    fn relocations(&self, target: usize) -> Result<Vec<Relocation>, String> {
        let symbols = self.file.elf_symbol_table();
        let mut relocations = Vec::new();
        for &index in self.relas.get(&target).into_iter().flatten() {
            let header = self
                .sections
                .section(object::SectionIndex(index))
                .map_err(|error| error.to_string())?;
            let entries: &[elf::Rela64<LE>] = header
                .data_as_array(LE, self.data)
                .map_err(|error| error.to_string())?;
            for entry in entries {
                let symbol = entry.r_sym(LE, false);
                // Symbol 0, of no definition, is a relocation of none.
                let defined = symbol != 0
                    && symbols
                        .symbol(object::SymbolIndex(symbol as usize))
                        .map_err(|error| error.to_string())?
                        .st_shndx(LE)
                        != elf::SHN_UNDEF;
                relocations.push(Relocation {
                    offset: entry.r_offset(LE),
                    kind: entry.r_type(LE, false),
                    symbol,
                    defined,
                });
            }
        }
        Ok(relocations)
    }

    /// The sections COMDAT groups hold.
    fn comdat_members(&self) -> Result<BTreeSet<usize>, String> {
        let mut members = BTreeSet::new();
        for header in self.sections.iter() {
            if header.sh_type(LE) != elf::SHT_GROUP {
                continue;
            }
            let words: &[object::U32<LE>] = header
                .data_as_array(LE, self.data)
                .map_err(|error| error.to_string())?;
            if let Some((flags, rest)) = words.split_first()
                && flags.get(LE) & elf::GRP_COMDAT != 0
            {
                members.extend(rest.iter().map(|word| word.get(LE) as usize));
            }
        }
        Ok(members)
    }

    fn symbol_name(&self, index: u32) -> Result<&'data str, String> {
        let symbols = self.file.elf_symbol_table();
        let symbol = symbols
            .symbol(object::SymbolIndex(index as usize))
            .map_err(|error| error.to_string())?;
        let name = symbols
            .symbol_name(LE, symbol)
            .map_err(|error| error.to_string())?;
        std::str::from_utf8(name).map_err(|error| error.to_string())
    }

    fn is_global(&self, index: u32) -> Result<bool, String> {
        let symbol = self
            .file
            .elf_symbol_table()
            .symbol(object::SymbolIndex(index as usize))
            .map_err(|error| error.to_string())?;
        Ok(symbol.st_bind() != elf::STB_LOCAL)
    }
}

/// The names of the global definitions the object's loaded code reaches
/// through a GOT entry, each to get a private slot. A reference `bind` will
/// rebind names its binding; the names in `skip` become references, which
/// stay the interface's.
pub(super) fn got_targets(
    bytes: &[u8],
    bind: &BTreeMap<String, String>,
    skip: &BTreeSet<String>,
) -> Result<BTreeSet<String>, String> {
    let read = Read::parse(bytes)?;
    let mut targets = BTreeSet::new();
    for (index, _, name) in read.loaded()? {
        if name == ".eh_frame" {
            continue;
        }
        for relocation in read.relocations(index)? {
            if read.arch.got(relocation.kind).is_none() {
                continue;
            }
            let symbol = read.symbol_name(relocation.symbol)?;
            if skip.contains(symbol) {
                continue;
            }
            if let Some(binding) = bind.get(symbol) {
                targets.insert(binding.clone());
            } else if relocation.defined && read.is_global(relocation.symbol)? {
                targets.insert(symbol.to_owned());
            }
        }
    }
    Ok(targets)
}

/// The assembly of the private slots for `targets`, in their order.
pub(super) fn slots(targets: &BTreeSet<String>) -> String {
    let mut text = format!("\t.section {SLOTS},\"aw\",%progbits\n\t.p2align 3\n");
    for (index, target) in targets.iter().enumerate() {
        writeln!(text, "{SLOT}{index}:\n\t.quad \"{target}\"").expect("writing to a string");
    }
    text
}

/// The least class at or above `bound`, from `floor`, a power of two.
fn class(bound: u64, floor: u64) -> u64 {
    let mut size = floor;
    loop {
        if bound <= size {
            return size;
        }
        if bound <= size + size / 2 {
            return size + size / 2;
        }
        size *= 2;
    }
}

/// The unwind table's live FDEs: their count and bytes. An FDE whose start
/// carries no relocation (its code was collected) leaves the final link. A
/// table that does not end on its alignment (at least `TABLE_ALIGN`) has its last record grown to it
/// by the next link, which counts here.
fn fdes(read: &Read<'_>) -> Result<(u64, u64), String> {
    let (mut count, mut bytes) = (0, 0);
    for (index, header, name) in read.loaded()? {
        if name != ".eh_frame" {
            continue;
        }
        let live: BTreeSet<u64> = read
            .relocations(index)?
            .into_iter()
            .filter(|relocation| !read.arch.is_none(relocation.kind))
            .map(|relocation| relocation.offset)
            .collect();
        let data = header
            .data(LE, read.data)
            .map_err(|error| error.to_string())?;
        let align = header.sh_addralign(LE).max(TABLE_ALIGN);
        let mut last_live = false;
        let mut at = 0;
        while at + 4 <= data.len() {
            let length = u32::from_le_bytes(data[at..at + 4].try_into().expect("four bytes"));
            if length == 0 {
                if data[at..].iter().any(|byte| *byte != 0) {
                    return Err("an unwind table terminator before its end".into());
                }
                break;
            }
            if length == u32::MAX || length % 4 != 0 {
                return Err(format!("an unwind record of length {length:#x}"));
            }
            let end = at + 4 + length as usize;
            if end > data.len() || length < 8 {
                return Err("a truncated unwind record".into());
            }
            let id = u32::from_le_bytes(data[at + 4..at + 8].try_into().expect("four bytes"));
            last_live = id != 0 && live.contains(&(at as u64 + 8));
            if last_live {
                count += 1;
                bytes += 4 + u64::from(length);
            }
            at = end;
        }
        if last_live && at == data.len() {
            bytes += (align - at as u64 % align) % align;
        }
    }
    Ok((count, bytes))
}

/// The absolute pointers in loaded sections to definitions: a relative
/// relocation each in a position-independent guest.
fn pointers(read: &Read<'_>) -> Result<u64, String> {
    let mut count = 0;
    for (index, _, _) in read.loaded()? {
        count += read
            .relocations(index)?
            .iter()
            .filter(|relocation| relocation.kind == read.arch.abs64() && relocation.defined)
            .count() as u64;
    }
    Ok(count)
}

/// The footprint an object takes: the linker script that merges and pads
/// its sections, the pad object's assembly, and what the result must be.
pub(super) struct Footprint {
    pub(super) script: String,
    pub(super) pad: String,
    /// Each merged section's class, by name.
    sizes: BTreeMap<&'static str, u64>,
    /// The pass-through group members.
    groups: BTreeSet<String>,
    fdes: (u64, u64),
    pointers: u64,
}

/// Plan the footprint of the object `bytes`. Refuses a loaded section of no
/// known kind, one aligned past the fixed alignment, and a group member whose
/// name the script cannot spell.
pub(super) fn plan(bytes: &[u8]) -> Result<Footprint, String> {
    let read = Read::parse(bytes)?;
    let arch = read.arch;
    let mut bounds = [0u64; BLOBS.len()];
    let mut groups = BTreeSet::new();
    let mut unknown = BTreeSet::new();
    let shared = read.comdat_members()?;
    for (index, header, name) in read.loaded()? {
        let align = header.sh_addralign(LE).max(1);
        if align > ALIGN {
            return Err(format!(
                "section {name} is aligned to {align}, past the footprint's {ALIGN}"
            ));
        }
        let blob = BLOBS
            .iter()
            .position(|blob| blob.inputs.iter().any(|input| matches(input, name)));
        // A COMDAT group member, shared with the guest's by name, stays its
        // group's own section, outside the merge. The rewrite dissolves the
        // engine's private groups, so another group's member is unplanned.
        if header.sh_flags(LE) & u64::from(elf::SHF_GROUP) != 0 {
            if !shared.contains(&index) {
                return Err(format!("{name} is a member of a group of no shared name"));
            }
            if !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
            {
                return Err(format!("group member {name:?} cannot be named in a script"));
            }
            groups.insert(name.to_owned());
            continue;
        }
        match blob {
            Some(blob) => bounds[blob] += header.sh_size(LE) + align - 1,
            None if name == ".eh_frame" || interface(name) => {}
            None => {
                unknown.insert(name);
            }
        }
    }
    if !unknown.is_empty() {
        return Err(format!("loaded sections of no footprint kind: {unknown:?}"));
    }

    // At least one pad FDE, so the class size is always reachable.
    let (count, size) = fdes(&read)?;
    if size % 4 != 0 {
        return Err(format!("unwind FDEs of {size} bytes, not whole words"));
    }
    let fde_count = class(count + 1, 64);
    let pad_fdes = fde_count - count;
    let fde_bytes = class(size + FDE * pad_fdes, 4096);
    let extra = fde_bytes - size - FDE * pad_fdes;
    // The table, the pad's appended, ends on its alignment, so no later link
    // grows its last FDE: the pad's CIE (24 bytes, 20 on aarch64, whose
    // initial rules are shorter) takes a word more if not.
    let table: u64 = read
        .loaded()?
        .iter()
        .filter(|(_, _, name)| *name == ".eh_frame")
        .map(|(_, header, _)| {
            header
                .sh_size(LE)
                .next_multiple_of(header.sh_addralign(LE).max(TABLE_ALIGN))
        })
        .sum();
    let cie = if arch.aarch64 { 20 } else { 24 };
    let longer_cie = !(table + cie + FDE * pad_fdes + extra).is_multiple_of(8);
    let pointers = pointers(&read)?;
    let pointer_count = class(pointers, 64);
    let pad_pointers = pointer_count - pointers;

    let code = if arch.aarch64 { 4 } else { 1 };
    let (text, relro) = (0, 2);
    bounds[text] += pad_fdes * code;
    bounds[relro] += pad_pointers * 8;
    let mut sizes = BTreeMap::new();
    for (blob, bound) in BLOBS.iter().zip(bounds) {
        sizes.insert(blob.name, class(bound + ALIGN - 1, blob.floor));
    }

    let mut script = String::from("SECTIONS\n{\n");
    for group in &groups {
        writeln!(script, "  {group} 0 : {{ *({group}) }}").expect("writing to a string");
    }
    // A trap, `brk #0` or `int3`, in the script's big-endian spelling.
    let fill = if arch.aarch64 {
        "0x000020d4"
    } else {
        "0xcccccccc"
    };
    for (index, blob) in BLOBS.iter().enumerate() {
        writeln!(
            script,
            "  {} 0 : {{ *({}) . = {:#x}; }}{}",
            blob.name,
            blob.inputs.join(" "),
            sizes[blob.name],
            if index == text {
                format!(" ={fill}")
            } else {
                String::new()
            }
        )
        .expect("writing to a string");
    }
    script.push_str("}\n");

    Ok(Footprint {
        script,
        pad: pad(arch, pad_fdes, extra, pad_pointers, longer_cie),
        sizes,
        groups,
        fdes: (fde_count, fde_bytes),
        pointers: pointer_count,
    })
}

/// The pad object: each merged kind's alignment, `fdes` pad FDEs (the last
/// `extra` bytes longer) over pad code under their own CIE (a word longer if
/// `longer_cie`), and `pointers` pad pointers.
fn pad(arch: Arch, fdes: u64, extra: u64, pointers: u64, longer_cie: bool) -> String {
    let mut text = String::new();
    for blob in &BLOBS {
        let kind = match blob.name {
            ".bss.patina" => "\"aw\",%nobits",
            ".tbss.patina" => "\"awT\",%nobits",
            ".tdata.patina" => "\"awT\",%progbits",
            ".text.patina" => "\"ax\",%progbits",
            ".rodata.patina" => "\"a\",%progbits",
            _ => "\"aw\",%progbits",
        };
        writeln!(
            text,
            "\t.section {}_footprint,{kind}\n\t.p2align {}",
            blob.name,
            ALIGN.trailing_zeros()
        )
        .expect("writing to a string");
        if blob.name == ".text.patina" {
            let trap = if arch.aarch64 { "brk #0" } else { "int3" };
            for index in 0..fdes {
                writeln!(text, ".Lpatina_pad{index}:\n\t{trap}").expect("writing to a string");
            }
        }
        if blob.name == ".data.rel.ro.patina" {
            text.push_str(".Lpatina_pointer:\n");
            for _ in 0..pointers {
                text.push_str("\t.quad .Lpatina_pointer\n");
            }
        }
    }
    // Aligned as an eight-byte table is (an assembler may align it so
    // anyway), so the table before it grows to that alignment, as counted.
    // A CIE of no augmentation data but the FDE encoding (PC-relative,
    // signed four bytes), whose initial rule is the call's: CFA at the stack
    // pointer past the return address, which it holds.
    let (kind, alignment, return_column, rules) = if arch.aarch64 {
        ("%progbits", 4, 30, "0x0c, 31, 0")
    } else {
        ("@unwind", 1, 16, "0x0c, 7, 8, 0x90, 1")
    };
    let range = if arch.aarch64 { 4 } else { 1 };
    // The CFA rule the CIE states, restated: the filler of the last FDE.
    let restate = if arch.aarch64 { "0x0e, 0" } else { "0x0e, 8" };
    let longer = if longer_cie {
        format!("\t.byte {restate}, {restate}\n")
    } else {
        String::new()
    };
    write!(
        text,
        "\t.section .eh_frame,\"a\",{kind}\n\t.p2align 3\n\
         .Lpatina_cie:\n\t.long .Lpatina_cie_end - .Lpatina_cie_id\n\
         .Lpatina_cie_id:\n\t.long 0\n\t.byte 1\n\t.asciz \"zR\"\n\
         \t.uleb128 {alignment}\n\t.sleb128 -8\n\t.uleb128 {return_column}\n\
         \t.uleb128 1\n\t.byte 0x1b\n\t.byte {rules}\n{longer}\t.p2align 2, 0\n\
         .Lpatina_cie_end:\n"
    )
    .expect("writing to a string");
    for index in 0..fdes {
        // Length, CIE pointer, start, range and an empty augmentation: 17
        // bytes, a word with the padding; the last restates the CFA rule
        // (two bytes a time) `extra` bytes' worth.
        let restated = if index + 1 == fdes { extra / 2 } else { 0 };
        write!(
            text,
            ".Lpatina_fde{index}:\n\t.long .Lpatina_fde{index}_end - .Lpatina_fde{index}_id\n\
             .Lpatina_fde{index}_id:\n\t.long .Lpatina_fde{index}_id - .Lpatina_cie\n\
             \t.long .Lpatina_pad{index} - .\n\t.long {range}\n\t.uleb128 0\n\
             \t.rept {restated}\n\t.byte {restate}\n\t.endr\n\
             \t.fill {}, 1, 0\n.Lpatina_fde{index}_end:\n",
            FDE - 17
        )
        .expect("writing to a string");
    }
    text
}

/// Mark the merged sections of the object at `path` retained, in place, so
/// no collecting link drops one that a reference would otherwise keep: the
/// relocatable link keeps the flag only where every input carries it.
pub(super) fn retain(path: &std::path::Path) -> Result<(), String> {
    use std::os::unix::fs::FileExt;

    let bytes = std::fs::read(path).map_err(|error| error.to_string())?;
    let read = Read::parse(&bytes)?;
    let table = read.file.elf_header().e_shoff(LE);
    let mut patches = Vec::new();
    for (index, header, name) in read.loaded()? {
        if BLOBS.iter().any(|blob| blob.name == name) {
            let flags = header.sh_flags(LE) | u64::from(elf::SHF_GNU_RETAIN);
            patches.push((table + index as u64 * 64 + 8, flags));
        }
    }
    let file = std::fs::File::options()
        .write(true)
        .open(path)
        .map_err(|error| error.to_string())?;
    for (offset, flags) in patches {
        file.write_all_at(&flags.to_le_bytes(), offset)
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

/// Whether the script's input pattern `pattern` takes section `name`.
fn matches(pattern: &str, name: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => name == pattern,
    }
}

/// Check the object `bytes` took `footprint`: each merged section at its
/// class and the fixed alignment, no other loaded section but the unwind
/// table, the group members and the interface's, the unwind table and the
/// pointers at their classes, and no GOT reference to a definition.
pub(super) fn check(bytes: &[u8], footprint: &Footprint) -> Result<(), String> {
    let read = Read::parse(bytes)?;
    let mut problems = Vec::new();
    let mut seen = BTreeMap::new();
    for (index, header, name) in read.loaded()? {
        if let Some(&size) = footprint.sizes.get(name) {
            let (actual, align) = (header.sh_size(LE), header.sh_addralign(LE));
            if header.sh_flags(LE) & u64::from(elf::SHF_GNU_RETAIN) == 0 {
                problems.push(format!("{name} is not retained"));
            }
            if (actual, align) != (size, ALIGN) {
                problems.push(format!(
                    "{name} is {actual:#x} bytes aligned to {align}, not {size:#x} aligned to {ALIGN}"
                ));
            }
            *seen.entry(name).or_insert(0) += 1;
        } else if name != ".eh_frame" && !interface(name) && !footprint.groups.contains(name) {
            problems.push(format!("{name} is loaded outside the footprint"));
        }
        if name == ".eh_frame" {
            continue;
        }
        for relocation in read.relocations(index)? {
            if relocation.defined && read.arch.got(relocation.kind).is_some() {
                problems.push(format!(
                    "{name} reaches {} through a GOT entry",
                    read.symbol_name(relocation.symbol)?
                ));
            }
        }
    }
    for blob in &BLOBS {
        if seen.get(blob.name) != Some(&1) {
            problems.push(format!("not one {} section", blob.name));
        }
    }
    let fdes = fdes(&read)?;
    if fdes != footprint.fdes {
        problems.push(format!(
            "{} live FDEs of {} bytes, not {} of {}",
            fdes.0, fdes.1, footprint.fdes.0, footprint.fdes.1
        ));
    }
    let pointers = pointers(&read)?;
    if pointers != footprint.pointers {
        problems.push(format!(
            "{pointers} absolute pointers, not {}",
            footprint.pointers
        ));
    }
    if problems.is_empty() {
        Ok(())
    } else {
        problems.dedup();
        Err(format!(
            "the footprint did not hold: {}",
            problems.join("; ")
        ))
    }
}
