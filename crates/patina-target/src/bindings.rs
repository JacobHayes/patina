//! Where each dynamic reference in an ELF load set binds, as glibc's loader
//! binds it.
//!
//! A reference is a dynamic relocation naming a symbol, or an undefined dynamic
//! symbol. The loader resolves it against the load set's images in search
//! order (the executable, then its dependencies breadth-first), taking the
//! first image whose dynamic symbol table defines the name at an acceptable
//! version. That provider decides the reference's disposition: an audited
//! image contains it, a host image runs host code, and a weak reference no
//! image defines stays NULL.
//!
//! The version rules implemented are the documented subset ordinary toolchain
//! output needs, after glibc's `check_match`:
//!
//! * a provider without a symbol-version table satisfies any reference;
//! * a reference that requires a version is satisfied by a definition of that
//!   version, or by one at the global index (an unversioned definition, as an
//!   executable carries);
//! * a reference without a version is satisfied by a definition at the global
//!   index, or by the one definition of that name not marked hidden (its
//!   default version).
//!
//! A provider that defines the name but satisfies none of these, and a
//! version requirement the loader treats as hidden, are refused by name
//! instead of being resolved by a guess.

use crate::TargetError;
use crate::load_set::{ImageRole, LoadSet};
use object::elf;
use object::read::elf::{ElfFile64, FileHeader, SectionHeader, Sym, SymbolTable, VersionTable};
use object::{Endianness, SymbolIndex};
use std::collections::{BTreeSet, HashMap};

type Header = elf::FileHeader64<Endianness>;

/// One image's dynamic symbols, indexed by name for lookup.
pub(crate) struct ElfImage<'data> {
    endian: Endianness,
    symbols: SymbolTable<'data, Header>,
    versions: Option<VersionTable<'data, Header>>,
    /// `DT_SYMBOLIC`/`DF_SYMBOLIC`: the image's own definitions satisfy its
    /// own references first.
    symbolic: bool,
    /// A version requirement marked hidden (`vna_other` bit 15), which changes
    /// glibc's matching in ways this subset does not model.
    hidden_requirement: bool,
    /// Dynamic relocations, `(symbol index, relocation type)`, symbol 0
    /// included for the types that name none.
    relocations: Vec<(usize, u32)>,
    machine: u16,
    exports: HashMap<&'data [u8], Vec<Export<'data>>>,
}

/// One definition an image's dynamic symbol table offers the loader.
struct Export<'data> {
    /// The version it is defined at; `None` at the global index.
    version: Option<&'data [u8]>,
    global: bool,
    hidden: bool,
}

/// One reference the loader resolves.
pub(crate) struct Reference<'data> {
    pub(crate) name: &'data [u8],
    /// The version it requires (or, for a definition the image binds to
    /// itself, the version it is defined at).
    pub(crate) version: Option<&'data [u8]>,
    pub(crate) weak: bool,
    copy: bool,
    /// The image itself binds it: a local, protected, or `DT_SYMBOLIC`
    /// definition of its own.
    own: bool,
}

/// Where a reference binds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Binding {
    /// The image at this index in the load set provides it.
    Image(usize),
    /// A weak reference no image defines: NULL at load.
    Absent,
    /// A strong reference no image defines: the program does not start, or
    /// fails at the call.
    Unresolved,
    /// A provider defines the name, but outside the version subset modeled.
    Undecidable,
}

impl<'data> ElfImage<'data> {
    pub(crate) fn parse(bytes: &'data [u8]) -> Result<Self, TargetError> {
        let file = ElfFile64::<Endianness>::parse(bytes).map_err(TargetError::Parse)?;
        let endian = file.endian();
        let sections = file.elf_section_table();
        let symbols = sections
            .symbols(endian, bytes, elf::SHT_DYNSYM)
            .map_err(TargetError::Parse)?;
        let versions = sections
            .versions(endian, bytes)
            .map_err(TargetError::Parse)?;
        let mut symbolic = false;
        for entry in &file.elf_dynamic_table().map_err(TargetError::Parse)? {
            symbolic |= entry.tag == elf::DT_SYMBOLIC
                || (entry.tag == elf::DT_FLAGS && entry.val & u64::from(elf::DF_SYMBOLIC) != 0);
        }
        let mut hidden_requirement = false;
        if let Some((mut needs, _)) = sections
            .gnu_verneed(endian, bytes)
            .map_err(TargetError::Parse)?
        {
            while let Some((_, mut auxiliaries)) = needs.next().map_err(TargetError::Parse)? {
                while let Some(auxiliary) = auxiliaries.next().map_err(TargetError::Parse)? {
                    hidden_requirement |= auxiliary.vna_other.get(endian) & elf::VERSYM_HIDDEN != 0;
                }
            }
        }
        let dynsym = symbols.section();
        let mut relocations = Vec::new();
        for section in sections.iter() {
            let linked = section.sh_link(endian) as usize == dynsym.0;
            match section.sh_type(endian) {
                elf::SHT_RELA if linked => {
                    for rela in section
                        .data_as_array::<elf::Rela64<Endianness>, _>(endian, bytes)
                        .map_err(TargetError::Parse)?
                    {
                        relocations.push((
                            rela.r_sym(endian, false) as usize,
                            rela.r_type(endian, false),
                        ));
                    }
                }
                elf::SHT_REL if linked => {
                    for rel in section
                        .data_as_array::<elf::Rel64<Endianness>, _>(endian, bytes)
                        .map_err(TargetError::Parse)?
                    {
                        relocations.push((rel.r_sym(endian) as usize, rel.r_type(endian)));
                    }
                }
                elf::SHT_CREL => {
                    return Err(TargetError::UnreadableLoadSet(
                        "a CREL relocation section, which this audit does not read".into(),
                    ));
                }
                _ => {}
            }
        }
        let mut image = Self {
            endian,
            symbols,
            versions,
            symbolic,
            hidden_requirement,
            relocations,
            machine: file.elf_header().e_machine(endian),
            exports: HashMap::new(),
        };
        image.exports = image.index_exports()?;
        Ok(image)
    }

    fn index_exports(&self) -> Result<HashMap<&'data [u8], Vec<Export<'data>>>, TargetError> {
        let mut exports: HashMap<&'data [u8], Vec<Export<'data>>> = HashMap::new();
        for (index, symbol) in self.symbols.enumerate() {
            if !exported(symbol, self.endian) {
                continue;
            }
            let name = self
                .symbols
                .symbol_name(self.endian, symbol)
                .map_err(TargetError::Parse)?;
            let (version, global, hidden) = self.version_of(index)?;
            exports.entry(name).or_default().push(Export {
                version,
                global,
                hidden,
            });
        }
        Ok(exports)
    }

    /// The version a dynamic symbol carries: its name (`None` at the local and
    /// global indices), whether it is at the global index, and its hidden bit.
    fn version_of(
        &self,
        index: SymbolIndex,
    ) -> Result<(Option<&'data [u8]>, bool, bool), TargetError> {
        let Some(versions) = &self.versions else {
            return Ok((None, true, false));
        };
        let version_index = versions.version_index(self.endian, index);
        let version = versions
            .version(version_index)
            .map_err(TargetError::Parse)?
            .map(|version| version.name());
        Ok((
            version,
            version_index.index() <= elf::VER_NDX_GLOBAL,
            version_index.is_hidden(),
        ))
    }

    /// Whether the image carries a relocation that runs a resolver function at
    /// load (`IRELATIVE`), or exports one (`STT_GNU_IFUNC`): code that runs
    /// during relocation, before the executable's preinit array.
    pub(crate) fn runs_resolvers(&self) -> bool {
        let irelative = match self.machine {
            elf::EM_X86_64 => elf::R_X86_64_IRELATIVE,
            elf::EM_AARCH64 => elf::R_AARCH64_IRELATIVE,
            _ => return true,
        };
        self.relocations.iter().any(|(_, kind)| *kind == irelative)
            || self.symbols.iter().any(|symbol| {
                symbol.st_type() == elf::STT_GNU_IFUNC && !symbol.is_undefined(self.endian)
            })
    }

    /// Whether a version requirement is marked hidden.
    pub(crate) fn has_hidden_requirement(&self) -> bool {
        self.hidden_requirement
    }

    /// Every reference the loader resolves for this image: each dynamic
    /// relocation that names a symbol, and each undefined dynamic symbol no
    /// relocation names.
    pub(crate) fn references(&self) -> Result<Vec<Reference<'data>>, TargetError> {
        let copy = match self.machine {
            elf::EM_X86_64 => elf::R_X86_64_COPY,
            elf::EM_AARCH64 => elf::R_AARCH64_COPY,
            _ => {
                return Err(TargetError::UnreadableLoadSet(format!(
                    "relocations of ELF machine {} are not modeled",
                    self.machine
                )));
            }
        };
        let mut seen = BTreeSet::new();
        let mut references = Vec::new();
        let mut push = |index: usize, is_copy: bool| -> Result<(), TargetError> {
            if index == 0 || !seen.insert((index, is_copy)) {
                return Ok(());
            }
            let symbol = self
                .symbols
                .symbol(SymbolIndex(index))
                .map_err(TargetError::Parse)?;
            let name = self
                .symbols
                .symbol_name(self.endian, symbol)
                .map_err(TargetError::Parse)?;
            let (version, _, _) = self.version_of(SymbolIndex(index))?;
            let defined = !symbol.is_undefined(self.endian);
            let own = defined
                && (symbol.st_bind() == elf::STB_LOCAL
                    || symbol.st_visibility() == elf::STV_PROTECTED
                    || self.symbolic);
            references.push(Reference {
                name,
                version,
                weak: symbol.st_bind() == elf::STB_WEAK,
                copy: is_copy,
                own: own && !is_copy,
            });
            Ok(())
        };
        for (index, kind) in &self.relocations {
            push(*index, *kind == copy)?;
        }
        for (index, symbol) in self.symbols.enumerate() {
            if symbol.is_undefined(self.endian) {
                push(index.0, false)?;
            }
        }
        Ok(references)
    }

    /// Whether this image satisfies `reference`: `Some(true)` when one of its
    /// definitions matches, `Some(false)` when it defines the name only
    /// outside the modeled subset, `None` when it does not define it.
    fn satisfies(&self, reference: &Reference<'_>) -> Option<bool> {
        let exports = self.exports.get(reference.name)?;
        if self.versions.is_none() {
            return Some(true);
        }
        let matched = match reference.version {
            Some(required) => exports.iter().any(|export| {
                export.version == Some(required) || (export.global && !export.hidden)
            }),
            None => {
                exports.iter().any(|export| export.global && !export.hidden)
                    || exports.iter().filter(|export| !export.hidden).count() == 1
            }
        };
        Some(matched)
    }
}

/// Whether a dynamic symbol is a definition the loader may bind another
/// image's reference to (glibc's `do_lookup_x` filter).
fn exported(symbol: &elf::Sym64<Endianness>, endian: Endianness) -> bool {
    !symbol.is_undefined(endian)
        && matches!(
            symbol.st_bind(),
            elf::STB_GLOBAL | elf::STB_WEAK | elf::STB_GNU_UNIQUE
        )
        && !matches!(symbol.st_visibility(), elf::STV_HIDDEN | elf::STV_INTERNAL)
        && matches!(
            symbol.st_type(),
            elf::STT_NOTYPE
                | elf::STT_OBJECT
                | elf::STT_FUNC
                | elf::STT_COMMON
                | elf::STT_TLS
                | elf::STT_GNU_IFUNC
        )
}

/// Where the reference `reference`, made by the image at index `from`, binds.
pub(crate) fn bind(images: &[ElfImage<'_>], from: usize, reference: &Reference<'_>) -> Binding {
    if reference.own {
        return Binding::Image(from);
    }
    for (index, image) in images.iter().enumerate() {
        // A copy relocation fills the executable's storage from the next
        // definition: its own is the destination, not the source.
        if reference.copy && index == from {
            continue;
        }
        match image.satisfies(reference) {
            Some(true) => return Binding::Image(index),
            Some(false) => return Binding::Undecidable,
            None => {}
        }
    }
    if reference.weak {
        Binding::Absent
    } else {
        Binding::Unresolved
    }
}

/// Parse every image of an ELF load set, in its search order.
pub(crate) fn parse_images<'set>(
    load_set: &'set LoadSet<'_>,
) -> Result<Vec<ElfImage<'set>>, TargetError> {
    load_set
        .images()
        .iter()
        .map(|image| {
            ElfImage::parse(&image.bytes).map_err(|error| match error {
                TargetError::UnreadableLoadSet(reason) => {
                    TargetError::UnreadableLoadSet(format!("{}: {reason}", image.name))
                }
                other => other,
            })
        })
        .collect()
}

/// Whether the image at `index` is the platform's.
pub(crate) fn is_host(load_set: &LoadSet<'_>, index: usize) -> bool {
    load_set.images()[index].role == ImageRole::Host
}
