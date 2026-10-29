//! Where each reference in a Mach-O load set binds, as dyld binds it.
//!
//! A reference is an import dyld binds: an entry of the image's chained-fixup
//! import table (`LC_DYLD_CHAINED_FIXUPS`), or, in an image without one, an
//! undefined external symbol. Its library ordinal names where dyld looks:
//!
//! * the image itself or the main executable;
//! * one of the image's own dylib load commands (two-level namespace): that
//!   dylib provides the name if it exports it, or a dylib it re-exports does;
//! * every loaded image: a flat lookup (`-undefined dynamic_lookup`, or an
//!   image without `MH_TWOLEVEL`) or a weak-definition coalescing lookup
//!   (C++ inline and template definitions). The audit does not model dyld's
//!   order here: the reference is bound into the host, or into a shared-cache
//!   image, if any of those exports the name, and into an audited image only
//!   otherwise.
//!
//! Exports are the export trie's (`LC_DYLD_EXPORTS_TRIE`, or the dyld-info
//! trie) together with the symbol table's external definitions.
//!
//! Host images (`libSystem` and the libraries it re-exports) and shared-cache
//! application images have no file to read; whether one exports a name is
//! asked of the platform's loader through the load set's
//! [`ExportOracle`](crate::ExportOracle). A shared-cache image's code and own
//! bindings are never looked through: a reference bound to one is judged by
//! the caller.

use crate::TargetError;
use crate::bindings::Binding;
use crate::load_set::{ImageRole, LoadSet};
use object::macho;
use object::read::macho::{ExportData, MachHeader, MachOFile64, Nlist};
use object::{Endianness, U32};
use std::collections::BTreeSet;

/// One image's references and exported names.
pub(crate) struct MachOImage<'data> {
    references: Vec<MachOReference<'data>>,
    exports: BTreeSet<Vec<u8>>,
    /// Names the export trie forwards to another dylib by name.
    forwarded: BTreeSet<Vec<u8>>,
    /// External weak definitions, which dyld may coalesce with another
    /// image's definition of the same name. Only read for an image without
    /// chained fixups, whose coalescing binds are not among its references.
    weak_definitions: Vec<Vec<u8>>,
    /// The export trie names a stub-and-resolver export: dyld runs the
    /// resolver when it binds a reference to it, before the shim's entry.
    pub(crate) runs_resolvers: bool,
    /// The ordinals of its `LC_REEXPORT_DYLIB` (or re-export flagged) dylibs.
    reexports: Vec<usize>,
}

/// One import of an image.
#[derive(Clone, Copy, Debug)]
pub(crate) struct MachOReference<'data> {
    /// The symbol's linker name (`_getloadavg`).
    pub name: &'data [u8],
    ordinal: Ordinal,
    /// A weak import: dyld binds it to NULL when no image provides it.
    pub weak: bool,
}

/// Where dyld looks for an import.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ordinal {
    SelfImage,
    MainExecutable,
    /// Every loaded image, in load order.
    Flat,
    /// Weak-definition coalescing across every loaded image.
    WeakLookup,
    /// The image's dylib load command of this (1-based) ordinal.
    Dylib(usize),
}

/// What a lookup of a name in one image found.
enum Lookup {
    /// The image at this load set index provides it.
    Found(usize),
    Missing,
    /// The answer depends on an image the audit cannot read.
    Unknown,
}

/// Re-export chains deeper than this are not followed.
const REEXPORT_DEPTH: usize = 8;

fn unreadable(what: &str) -> TargetError {
    TargetError::UnreadableLoadSet(format!("its {what} cannot be read"))
}

impl<'data> MachOImage<'data> {
    pub(crate) fn parse(bytes: &'data [u8]) -> Result<Self, TargetError> {
        let file = MachOFile64::<Endianness>::parse(bytes).map_err(TargetError::Parse)?;
        let endian = file.endian();
        let twolevel = file.macho_header().flags(endian) & macho::MH_TWOLEVEL != 0;
        let symbols = file.macho_symbol_table();
        let mut undefined = Vec::new();
        let mut exports = BTreeSet::new();
        let mut weak_definitions = Vec::new();
        for symbol in symbols.iter() {
            let n_type = symbol.n_type();
            if n_type & macho::N_STAB != 0 || n_type & macho::N_EXT == 0 {
                continue;
            }
            let name = symbol
                .name(endian, symbols.strings())
                .map_err(TargetError::Parse)?;
            match n_type & macho::N_TYPE {
                // An undefined symbol with a value is a common definition.
                macho::N_UNDF if symbol.n_value(endian) == 0 => {
                    let ordinal = symbol.library_ordinal(endian);
                    undefined.push(MachOReference {
                        name,
                        ordinal: if !twolevel {
                            Ordinal::Flat
                        } else {
                            match ordinal {
                                macho::SELF_LIBRARY_ORDINAL => Ordinal::SelfImage,
                                macho::DYNAMIC_LOOKUP_ORDINAL => Ordinal::Flat,
                                macho::EXECUTABLE_ORDINAL => Ordinal::MainExecutable,
                                ordinal => Ordinal::Dylib(usize::from(ordinal)),
                            }
                        },
                        weak: symbol.n_desc(endian) & macho::N_WEAK_REF != 0,
                    });
                }
                macho::N_UNDF => {}
                // A private external is linked away, never exported.
                _ if n_type & macho::N_PEXT == 0 => {
                    exports.insert(name.to_vec());
                    if symbol.n_desc(endian) & macho::N_WEAK_DEF != 0 {
                        weak_definitions.push(name.to_vec());
                    }
                }
                _ => {}
            }
        }
        let mut chained = None;
        let mut trie = None;
        let mut binds = false;
        let mut commands = file
            .macho_header()
            .load_commands(endian, bytes, 0)
            .map_err(TargetError::Parse)?;
        while let Some(command) = commands.next().map_err(TargetError::Parse)? {
            match command.cmd() {
                macho::LC_DYLD_CHAINED_FIXUPS => {
                    let data: &macho::LinkeditDataCommand<Endianness> =
                        command.data().map_err(TargetError::Parse)?;
                    chained = Some(linkedit(bytes, endian, data)?);
                }
                macho::LC_DYLD_EXPORTS_TRIE => {
                    let data: &macho::LinkeditDataCommand<Endianness> =
                        command.data().map_err(TargetError::Parse)?;
                    trie = Some(*data);
                }
                macho::LC_DYLD_INFO | macho::LC_DYLD_INFO_ONLY => {
                    let info: &macho::DyldInfoCommand<Endianness> =
                        command.data().map_err(TargetError::Parse)?;
                    // Weak binds are the coalescing table, naming the
                    // image's own weak definitions too: an image whose
                    // pointers address its own weak function has them with
                    // no undefined symbol. Its definitions are judged as
                    // coalescing lookups.
                    binds |=
                        info.bind_size.get(endian) != 0 || info.lazy_bind_size.get(endian) != 0;
                    if trie.is_none() && info.export_size.get(endian) != 0 {
                        trie = Some(macho::LinkeditDataCommand {
                            cmd: U32::new(endian, macho::LC_DYLD_EXPORTS_TRIE),
                            cmdsize: U32::new(endian, 16),
                            dataoff: info.export_off,
                            datasize: info.export_size,
                        });
                    }
                }
                _ => {}
            }
        }
        let mut forwarded = BTreeSet::new();
        let mut runs_resolvers = false;
        if let Some(trie) = trie {
            let mut entries = trie
                .exports_trie(endian, bytes)
                .map_err(|_| unreadable("export trie"))?;
            while let Some(entry) = entries.next().map_err(|_| unreadable("export trie"))? {
                let name = entry.name().to_vec();
                if entry.flags() & macho::EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION != 0 {
                    weak_definitions.push(name.clone());
                }
                match entry.data() {
                    ExportData::Reexport { .. } => {
                        forwarded.insert(name);
                    }
                    ExportData::StubAndResolver { .. } => {
                        runs_resolvers = true;
                        exports.insert(name);
                    }
                    ExportData::Regular { .. } => {
                        exports.insert(name);
                    }
                }
            }
        }
        let references = match chained {
            Some(fixups) => {
                // The coalescing binds are among the chained imports.
                weak_definitions.clear();
                chained_imports(fixups)?
            }
            // A symbol table stripped of its undefined symbols, beside bind
            // records dyld still applies, hides what the image imports.
            None if undefined.is_empty() && binds => {
                return Err(unreadable("imports (its symbol table was stripped)"));
            }
            None => undefined,
        };
        weak_definitions.sort();
        weak_definitions.dedup();
        let request = crate::load_set::macho_load_request(bytes)?.unwrap_or_default();
        let reexports = request
            .dylibs
            .iter()
            .enumerate()
            .filter(|(_, dylib)| dylib.reexport)
            .map(|(index, _)| index + 1)
            .collect();
        Ok(Self {
            references,
            exports,
            forwarded,
            weak_definitions,
            runs_resolvers,
            reexports,
        })
    }

    pub(crate) fn references(&self) -> &[MachOReference<'data>] {
        &self.references
    }

    /// The image's external weak definitions dyld may coalesce, as references
    /// a coalescing lookup binds.
    pub(crate) fn coalesced_definitions(&self) -> impl Iterator<Item = MachOReference<'_>> {
        self.weak_definitions.iter().map(|name| MachOReference {
            name: name.as_slice(),
            ordinal: Ordinal::WeakLookup,
            weak: false,
        })
    }
}

/// The bytes a `__LINKEDIT` data command names.
fn linkedit<'data>(
    bytes: &'data [u8],
    endian: Endianness,
    command: &macho::LinkeditDataCommand<Endianness>,
) -> Result<&'data [u8], TargetError> {
    let start = command.dataoff.get(endian) as usize;
    let size = command.datasize.get(endian) as usize;
    bytes
        .get(start..start.saturating_add(size))
        .ok_or_else(|| unreadable("chained fixups"))
}

/// The import table of a chained-fixups blob (`dyld_chained_fixups_header`).
fn chained_imports(fixups: &[u8]) -> Result<Vec<MachOReference<'_>>, TargetError> {
    let word = |at: usize| -> Result<u32, TargetError> {
        fixups
            .get(at..at + 4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().expect("four bytes")))
            .ok_or_else(|| unreadable("chained fixups"))
    };
    let imports_offset = word(8)? as usize;
    let symbols_offset = word(12)? as usize;
    let count = word(16)? as usize;
    let format = word(20)?;
    if word(24)? != 0 {
        return Err(unreadable("chained fixups (compressed symbol names)"));
    }
    let name = |offset: usize| -> Result<&[u8], TargetError> {
        let start = symbols_offset.saturating_add(offset);
        let rest = fixups
            .get(start..)
            .ok_or_else(|| unreadable("chained fixups"))?;
        let end = rest
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| unreadable("chained fixups"))?;
        Ok(&rest[..end])
    };
    let mut imports = Vec::with_capacity(count);
    for index in 0..count {
        let (ordinal, weak, offset) = match format {
            // DYLD_CHAINED_IMPORT and DYLD_CHAINED_IMPORT_ADDEND: one word of
            // lib_ordinal:8, weak_import:1, name_offset:23 (and an addend).
            1 | 2 => {
                let stride = if format == 1 { 4 } else { 8 };
                let raw = word(imports_offset + index * stride)?;
                (
                    match raw & 0xff {
                        0xff => Ordinal::MainExecutable,
                        0xfe => Ordinal::Flat,
                        0xfd => Ordinal::WeakLookup,
                        0 => Ordinal::SelfImage,
                        ordinal => Ordinal::Dylib(ordinal as usize),
                    },
                    raw & 0x100 != 0,
                    (raw >> 9) as usize,
                )
            }
            // DYLD_CHAINED_IMPORT_ADDEND64: lib_ordinal:16, weak_import:1,
            // reserved:15, name_offset:32, then a 64-bit addend.
            3 => {
                let at = imports_offset + index * 16;
                let low = word(at)?;
                (
                    match low & 0xffff {
                        0xffff => Ordinal::MainExecutable,
                        0xfffe => Ordinal::Flat,
                        0xfffd => Ordinal::WeakLookup,
                        0 => Ordinal::SelfImage,
                        ordinal => Ordinal::Dylib(ordinal as usize),
                    },
                    low & 0x1_0000 != 0,
                    word(at + 4)? as usize,
                )
            }
            _ => return Err(unreadable("chained fixups (an unknown import format)")),
        };
        imports.push(MachOReference {
            name: name(offset)?,
            ordinal,
            weak,
        });
    }
    Ok(imports)
}

/// Parse every image whose own references the audit judges (the executable
/// and the on-disk application libraries); `None` for the others.
pub(crate) fn parse_macho_images<'set>(
    load_set: &'set LoadSet<'_>,
) -> Result<Vec<Option<MachOImage<'set>>>, TargetError> {
    load_set
        .images()
        .iter()
        .map(|image| match image.role {
            ImageRole::Executable | ImageRole::Library => {
                MachOImage::parse(&image.bytes).map(Some).map_err(|error| {
                    TargetError::UnreadableLoadSet(format!("{}: {error}", image.name))
                })
            }
            ImageRole::Host | ImageRole::SharedCache => Ok(None),
        })
        .collect()
}

/// Where `reference`, made by the image at index `from`, binds.
pub(crate) fn bind_macho(
    load_set: &LoadSet<'_>,
    images: &[Option<MachOImage<'_>>],
    from: usize,
    reference: &MachOReference<'_>,
) -> Binding {
    let unbound = || {
        if reference.weak {
            Binding::Absent
        } else {
            Binding::Unresolved
        }
    };
    let to = match reference.ordinal {
        Ordinal::SelfImage => return Binding::Image(from),
        Ordinal::MainExecutable => return Binding::Image(0),
        Ordinal::Flat | Ordinal::WeakLookup => {
            return global(load_set, images, reference).unwrap_or_else(unbound);
        }
        Ordinal::Dylib(ordinal) => match load_set.images()[from].dependencies.get(ordinal - 1) {
            None => return Binding::Undecidable,
            // A weak dylib dyld did not find.
            Some(None) => return unbound(),
            Some(Some(to)) => *to,
        },
    };
    match lookup(load_set, images, to, reference.name, 0) {
        Lookup::Found(provider) => Binding::Image(provider),
        Lookup::Missing => unbound(),
        // A strong reference to a host or shared-cache image dyld launched
        // against binds there; only a weak one needs the export answered.
        Lookup::Unknown
            if !reference.weak
                && matches!(
                    load_set.images()[to].role,
                    ImageRole::Host | ImageRole::SharedCache
                ) =>
        {
            Binding::Image(to)
        }
        Lookup::Unknown => Binding::Undecidable,
    }
}

/// A lookup across every loaded image: bound into the first host or
/// shared-cache image exporting the name, whatever an audited image defines;
/// else into the first audited image defining it. `None` when nothing
/// provides it.
fn global(
    load_set: &LoadSet<'_>,
    images: &[Option<MachOImage<'_>>],
    reference: &MachOReference<'_>,
) -> Option<Binding> {
    let mut unknown = false;
    for (index, image) in load_set.images().iter().enumerate() {
        if matches!(image.role, ImageRole::Host | ImageRole::SharedCache) {
            match platform_exports(load_set, index, reference.name) {
                Some(true) => return Some(Binding::Image(index)),
                Some(false) => {}
                None => unknown = true,
            }
        }
    }
    if unknown {
        return Some(Binding::Undecidable);
    }
    images
        .iter()
        .position(|image| {
            image
                .as_ref()
                .is_some_and(|image| image.exports.contains(reference.name))
        })
        .map(Binding::Image)
}

/// Whether the image at `index`, or one it re-exports, provides `name`.
fn lookup(
    load_set: &LoadSet<'_>,
    images: &[Option<MachOImage<'_>>],
    index: usize,
    name: &[u8],
    depth: usize,
) -> Lookup {
    if matches!(
        load_set.images()[index].role,
        ImageRole::Host | ImageRole::SharedCache
    ) {
        return match platform_exports(load_set, index, name) {
            Some(true) => Lookup::Found(index),
            Some(false) => Lookup::Missing,
            None => Lookup::Unknown,
        };
    }
    let Some(image) = &images[index] else {
        return Lookup::Unknown;
    };
    if image.forwarded.contains(name) {
        return Lookup::Unknown;
    }
    if image.exports.contains(name) {
        return Lookup::Found(index);
    }
    if depth >= REEXPORT_DEPTH {
        return Lookup::Unknown;
    }
    let mut unknown = false;
    for ordinal in &image.reexports {
        match load_set.images()[index].dependencies.get(ordinal - 1) {
            Some(Some(next)) => match lookup(load_set, images, *next, name, depth + 1) {
                Lookup::Found(provider) => return Lookup::Found(provider),
                Lookup::Missing => {}
                Lookup::Unknown => unknown = true,
            },
            Some(None) => {}
            None => unknown = true,
        }
    }
    if unknown {
        Lookup::Unknown
    } else {
        Lookup::Missing
    }
}

/// The oracle's answer for an image with no file: the C name is the linker
/// name less its leading underscore.
fn platform_exports(load_set: &LoadSet<'_>, index: usize, name: &[u8]) -> Option<bool> {
    let name = std::str::from_utf8(name).ok()?;
    let c_name = name.strip_prefix('_')?;
    load_set
        .oracle()?
        .exports(&load_set.images()[index].name, c_name)
}
