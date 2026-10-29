//! Native import auditing over a program's load set.

use crate::bindings::{Binding, ElfImage, bind, is_host, parse_images};
use crate::early_init::{EARLY_INIT_CATEGORY, early_init_escapes};
use crate::import_policy::{
    NativeFormat, NativeImportDecision, SHIM_DLSYM_VERSION, native_import_decision,
};
use crate::import_xrefs::collect_import_provenance;
use crate::instruction_scan::{
    native_escape_is_go_build_marker, native_escape_is_host_identity, scan_instruction_ranges,
};
use crate::load_set::{ImageRole, LoadSet, LoadedImage, elf_load_request};
use crate::provenance::{NativeProvenance, NativeProvenanceIndex};
use crate::shim::native_binary_is_shim_linked;
use crate::{HostBinding, NativeEscape, TargetError, code_ranges};
use object::{Object, ObjectSymbol};
use std::cell::OnceCell;
use std::collections::BTreeSet;

/// The category of a strong reference no image in the load set defines.
pub(super) const UNRESOLVED_CATEGORY: &str = "unresolved-import";

/// The category of a reference whose provider defines the name outside the
/// symbol-version subset the audit models (see [`crate::bindings`]).
pub(super) const UNDECIDABLE_CATEGORY: &str = "undecidable-binding";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeAudit {
    /// The executable's undefined dynamic symbols.
    pub imports: Vec<String>,
    /// Weak references no image in the load set defines: NULL at load, see
    /// [`render_inert_weak_imports`](crate::render_inert_weak_imports). A
    /// library's are prefixed with its name.
    pub inert_weak_imports: Vec<String>,
}

impl NativeAudit {
    /// Audit a program over the images its loader maps.
    ///
    /// Each reference is judged by where it binds at load: one that binds to
    /// an audited image (the executable, the shim's doors in it, or an
    /// application library) is contained; a weak one nothing defines is
    /// inert; one that binds into a host image (the loader, glibc, the vDSO)
    /// runs host code and is admitted only by the effect policy, by name;
    /// anything else is refused by name. Every audited image's code is
    /// scanned, and the early-execution hazards the loader runs before the
    /// shim's preinit entry are refused.
    pub fn audit(load_set: &LoadSet<'_>, allow: &BTreeSet<String>) -> Result<Self, TargetError> {
        let bytes: &[u8] = &load_set.executable().bytes;
        let file = object::File::parse(bytes).map_err(TargetError::Parse)?;
        let format = NativeFormat::from_binary(file.format())?;
        if unauditable_elf(&file) {
            return Err(TargetError::UnauditableElf);
        }
        let mut imports = file
            .imports()
            .map_err(TargetError::Parse)?
            .into_iter()
            .map(|import| String::from_utf8_lossy(import.name()).into_owned())
            .collect::<Vec<_>>();
        imports.sort();
        imports.dedup();
        let provenance = NativeProvenanceIndex::new(&file);
        let code_ranges = code_ranges::CodeRanges::new(&file)?;
        // Attribution walks the whole binary (relocations, code
        // cross-references), and only a denied import consults it, so it is
        // computed on first use: a clean binary, the common case before every
        // run, never pays for it.
        let import_provenance = OnceCell::new();
        let provenance_of = |symbol: &str| {
            import_provenance
                .get_or_init(|| collect_import_provenance(&file, bytes, &provenance, &code_ranges))
                .get(symbol)
                .cloned()
                .unwrap_or_else(|| vec![NativeProvenance::unknown()])
        };
        // Host-identity reads and Go build markers are informational, so they
        // are dropped here rather than joining the refusal set
        // (`render_host_identity_note` over `native_host_identity_sites`, and
        // its Go-marker twin, are what report them, on every outcome).
        // The scan still classifies them in one place; only the disposition
        // differs.
        let mut inert_weak_imports = Vec::new();
        // The scan runs first: it refuses an architecture it cannot decode,
        // whose relocations the binding pass could not read either.
        let mut denied: Vec<NativeEscape> = Vec::new();
        denied.extend(
            scan_instruction_ranges(&file, &provenance, &code_ranges)?
                .into_iter()
                .filter(informative_only),
        );
        match format {
            NativeFormat::Elf => judge_elf_bindings(
                load_set,
                &file,
                allow,
                &provenance_of,
                &mut denied,
                &mut inert_weak_imports,
            )?,
            // Mach-O libraries are not resolved yet: every import binds into
            // a dylib and is judged by name.
            NativeFormat::MachO => {
                for symbol in &imports {
                    if let NativeImportDecision::Denied(category) =
                        native_import_decision(symbol, format, allow)
                    {
                        denied.push(NativeEscape::new(
                            symbol.clone(),
                            category,
                            provenance_of(symbol),
                        ));
                    }
                }
            }
        }
        denied.extend(early_init_escapes(&file, &provenance));
        for image in load_set.images() {
            if image.role == ImageRole::Library {
                denied.extend(library_code_escapes(image)?);
            }
        }
        denied.dedup();
        if !denied.is_empty() {
            return Err(TargetError::UnsupportedImports(denied));
        }
        inert_weak_imports.sort();
        inert_weak_imports.dedup();
        Ok(Self {
            imports,
            inert_weak_imports,
        })
    }
}

/// Whether a scan finding refuses: host-identity reads and Go build markers
/// are reported, never refused.
fn informative_only(escape: &NativeEscape) -> bool {
    !native_escape_is_host_identity(escape) && !native_escape_is_go_build_marker(escape)
}

/// Judge every reference of every audited ELF image by where it binds.
fn judge_elf_bindings(
    load_set: &LoadSet<'_>,
    executable: &object::File<'_>,
    allow: &BTreeSet<String>,
    provenance_of: &dyn Fn(&str) -> Vec<NativeProvenance>,
    denied: &mut Vec<NativeEscape>,
    inert: &mut Vec<String>,
) -> Result<(), TargetError> {
    let images = parse_images(load_set)?;
    let shim_linked = native_binary_is_shim_linked(&load_set.executable().bytes).unwrap_or(false);
    // What the executable defines in any symbol table: a reference that binds
    // past one of these to a host image went around the executable's own
    // definition, which for a shim-linked guest is the shim's door.
    let executable_defines: BTreeSet<&str> = executable
        .symbols()
        .chain(executable.dynamic_symbols())
        .filter(|symbol| symbol.is_definition())
        .filter_map(|symbol| symbol.name().ok())
        .collect();
    for (index, image) in load_set.images().iter().enumerate() {
        let request = elf_load_request(&image.bytes)?.unwrap_or_default();
        if request.audit_modules || request.filters {
            return Err(TargetError::UnreadableLoadSet(format!(
                "{} names loader audit modules or filter objects, which run or redirect before \
                 the audit could judge them",
                image.name
            )));
        }
        if index == 0 {
            for (present, name) in [
                (request.init_first, "DF_1_INITFIRST"),
                (images[0].runs_resolvers(), "ifunc-resolver"),
            ] {
                if present {
                    denied.push(NativeEscape::new(
                        name.into(),
                        EARLY_INIT_CATEGORY,
                        vec![NativeProvenance::unknown()],
                    ));
                }
            }
        }
    }
    for (from, image) in images.iter().enumerate() {
        if is_host(load_set, from) {
            continue;
        }
        let site = Site::new(load_set, from, provenance_of);
        if image.has_hidden_requirement() {
            denied.push(site.escape("version requirement".into(), UNDECIDABLE_CATEGORY));
            continue;
        }
        for reference in image.references()? {
            let name = String::from_utf8_lossy(reference.name).into_owned();
            let version = reference
                .version
                .map(|version| String::from_utf8_lossy(version).into_owned());
            match bind(&images, from, &reference) {
                Binding::Image(to) if !is_host(load_set, to) => {}
                Binding::Absent => inert.push(site.label(&name)),
                Binding::Unresolved | Binding::Undecidable
                    if allow.contains(&name) || allow.contains(&site.label(&name)) => {}
                Binding::Unresolved => denied.push(site.escape(name, UNRESOLVED_CATEGORY)),
                Binding::Undecidable => {
                    let mut escape = site.escape(name, UNDECIDABLE_CATEGORY);
                    escape.binding = version.map(|version| HostBinding {
                        version: Some(version),
                        provider: "a definition at another version".into(),
                        around_executable: false,
                    });
                    denied.push(escape);
                }
                Binding::Image(to) => {
                    // The shim's own host-alias resolver: the executable's weak
                    // `dlsym` at glibc's default version (see
                    // `SHIM_DLSYM_VERSION`). Only the executable's: a library's
                    // `dlsym` is a guest resolver like any other.
                    if from == 0
                        && shim_linked
                        && reference.weak
                        && name == "dlsym"
                        && version.as_deref() == Some(SHIM_DLSYM_VERSION)
                    {
                        continue;
                    }
                    if let Some(version) = &version
                        && allow.contains(&format!("{name}@{version}"))
                    {
                        continue;
                    }
                    let NativeImportDecision::Denied(category) =
                        native_import_decision(&name, NativeFormat::Elf, allow)
                    else {
                        continue;
                    };
                    let around_executable = executable_defines.contains(name.as_str());
                    let mut escape = site.escape(name, category);
                    escape.binding = Some(HostBinding {
                        version,
                        provider: load_set.images()[to].name.clone(),
                        around_executable,
                    });
                    denied.push(escape);
                }
            }
        }
    }
    Ok(())
}

/// Where a reference is made: the executable, attributed by its own
/// provenance, or a library, named.
struct Site<'a> {
    library: Option<&'a str>,
    provenance_of: &'a dyn Fn(&str) -> Vec<NativeProvenance>,
}

impl<'a> Site<'a> {
    fn new(
        load_set: &'a LoadSet<'_>,
        index: usize,
        provenance_of: &'a dyn Fn(&str) -> Vec<NativeProvenance>,
    ) -> Self {
        let image = &load_set.images()[index];
        Self {
            library: (image.role == ImageRole::Library).then_some(image.name.as_str()),
            provenance_of,
        }
    }

    /// The name a finding at this site is listed under: a library's carries
    /// the library's name.
    fn label(&self, name: &str) -> String {
        match self.library {
            Some(library) => format!("{library}: {name}"),
            None => name.to_owned(),
        }
    }

    fn escape(&self, name: String, category: &'static str) -> NativeEscape {
        match self.library {
            Some(library) => library_escape(name, category, library),
            None => {
                let provenance = (self.provenance_of)(&name);
                NativeEscape::new(name, category, provenance)
            }
        }
    }
}

/// A finding in a library, attributed to the library.
fn library_escape(name: String, category: &'static str, library: &str) -> NativeEscape {
    let mut escape = NativeEscape::new(name, category, vec![library_provenance(library)]);
    escape.image = Some(library.to_owned());
    escape
}

fn library_provenance(library: &str) -> NativeProvenance {
    NativeProvenance {
        object: library.to_owned(),
        ..NativeProvenance::unknown()
    }
}

/// What an application library's own code and loader metadata refuse: its
/// forbidden instructions, and anything the loader runs before the
/// executable's preinit array (an `INITFIRST` initializer, an IFUNC resolver).
/// A library's own preinit array is ignored by glibc, so it is not read.
fn library_code_escapes(image: &LoadedImage<'_>) -> Result<Vec<NativeEscape>, TargetError> {
    let in_library = |error: TargetError| match error {
        TargetError::UnauditableElf => TargetError::UnreadableLoadSet(format!(
            "{} has no section headers or dynamic symbol table to audit",
            image.name
        )),
        other => other,
    };
    let file = object::File::parse(&*image.bytes).map_err(TargetError::Parse)?;
    if unauditable_elf(&file) {
        return Err(in_library(TargetError::UnauditableElf));
    }
    let provenance = NativeProvenanceIndex::new(&file);
    let code_ranges = code_ranges::CodeRanges::new(&file)?;
    let mut escapes: Vec<NativeEscape> = scan_instruction_ranges(&file, &provenance, &code_ranges)?
        .into_iter()
        .filter(informative_only)
        .map(|mut escape| {
            for origin in &mut escape.provenance {
                if origin.is_unknown() {
                    origin.object = image.name.clone();
                }
            }
            escape.image = Some(image.name.clone());
            escape
        })
        .collect();
    let request = elf_load_request(&image.bytes)?.unwrap_or_default();
    if request.init_first {
        escapes.push(library_escape(
            "DF_1_INITFIRST".into(),
            EARLY_INIT_CATEGORY,
            &image.name,
        ));
    }
    if ElfImage::parse(&image.bytes)?.runs_resolvers() {
        escapes.push(library_escape(
            "ifunc-resolver".into(),
            EARLY_INIT_CATEGORY,
            &image.name,
        ));
    }
    Ok(escapes)
}

/// Whether an ELF lacks what the audit reads: imports come from the dynamic
/// symbol table, their version requirements from the `SHT_GNU_versym`
/// section, and code ranges from the section headers, while the loader needs
/// none of them. A binary whose section headers were removed would otherwise
/// pass with no imports and no scanned code, and one whose dynamic table names
/// a version table (`DT_VERSYM`) the sections do not carry would have its
/// versioned references bound with no versions read. An `ET_REL` object is refused
/// later, by name, and a Mach-O is never judged here.
pub(crate) fn unauditable_elf(file: &object::File<'_>) -> bool {
    use object::read::elf::ProgramHeader;
    let object::File::Elf64(elf) = file else {
        return false;
    };
    let endian = elf.endian();
    let dynamic = elf
        .elf_program_headers()
        .iter()
        .any(|header| header.p_type(endian) == object::elf::PT_DYNAMIC);
    let names_versions = elf.elf_dynamic_table().is_ok_and(|table| {
        table
            .iter()
            .any(|entry| entry.tag == object::elf::DT_VERSYM)
    });
    let versions_readable = matches!(
        elf.elf_section_table().versions(endian, elf.data()),
        Ok(Some(_))
    );
    file.kind() != object::ObjectKind::Relocatable
        && (file.sections().next().is_none()
            || dynamic && file.dynamic_symbol_table().is_none()
            || names_versions && !versions_readable)
}

#[cfg(test)]
mod tests;
