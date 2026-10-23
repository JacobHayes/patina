//! Native import auditing and inert undefined-weak bindings.

use crate::early_init::early_init_escapes;
use crate::import_policy::{
    NativeFormat, NativeImportDecision, UNKNOWN_IMPORT_CATEGORY, elf_interposed_import,
    elf_shim_dlsym_vehicle, elf_wrapped_resolver, native_import_decision, normalize_native_symbol,
};
use crate::import_xrefs::collect_import_provenance;
use crate::instruction_scan::{
    native_escape_is_go_build_marker, native_escape_is_host_identity, scan_instruction_ranges,
};
use crate::provenance::{NativeProvenance, NativeProvenanceIndex};
use crate::shim::native_binary_is_shim_linked;
use crate::{NativeEscape, TargetError, code_ranges};
use object::read::elf::Sym as _;
use object::{Object, ObjectSymbol};
use std::cell::OnceCell;
use std::collections::BTreeSet;

/// The category of a versioned undefined ELF import that reached around a shim
/// interposer or the `-Wl,--wrap=dlsym` wrap (see [`versioned_bypass_escapes`]).
pub(super) const VERSIONED_BYPASS_CATEGORY: &str = "versioned-bypass";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeAudit {
    pub imports: Vec<String>,
    /// Imports the undefined-weak rule cleared: see [`render_inert_weak_imports`].
    pub inert_weak_imports: Vec<String>,
}

impl NativeAudit {
    /// Audit native imports and reject every symbol that is not explicitly
    /// caller-allowed or classified as safe for the binary's native format.
    pub fn audit(bytes: &[u8], allow: &BTreeSet<String>) -> Result<Self, TargetError> {
        let file = object::File::parse(bytes).map_err(TargetError::NativeParse)?;
        let format = NativeFormat::from_binary(file.format())?;
        if unauditable_elf(&file) {
            return Err(TargetError::UnauditableNativeElf);
        }
        let mut imports = file
            .imports()
            .map_err(TargetError::NativeParse)?
            .into_iter()
            .map(|import| String::from_utf8_lossy(import.name()).into_owned())
            .collect::<Vec<_>>();
        imports.sort();
        imports.dedup();
        let provenance = NativeProvenanceIndex::new(&file);
        let code_ranges = code_ranges::CodeRanges::new(&file)?;
        // Attribution and the undefined-weak rule each walk the whole binary
        // (relocations, code cross-references, every symbol), and only a
        // denied import consults them, so each is computed on first use: a
        // clean binary, the common case before every run, never pays for them.
        let import_provenance = OnceCell::new();
        let provenance_of = |symbol: &str| {
            import_provenance
                .get_or_init(|| collect_import_provenance(&file, bytes, &provenance, &code_ranges))
                .get(symbol)
                .cloned()
                .unwrap_or_else(|| vec![NativeProvenance::unknown()])
        };
        let inert_weak = OnceCell::new();
        let mut inert_weak_imports = Vec::new();
        let mut denied = Vec::new();
        for symbol in &imports {
            let NativeImportDecision::Denied(category) =
                native_import_decision(symbol, format, allow)
            else {
                continue;
            };
            if category == UNKNOWN_IMPORT_CATEGORY
                && inert_weak
                    .get_or_init(|| inert_weak_symbols(&file))
                    .contains(normalize_native_symbol(symbol))
            {
                inert_weak_imports.push(symbol.clone());
                continue;
            }
            denied.push(NativeEscape::new(
                symbol.clone(),
                category,
                provenance_of(symbol),
            ));
        }
        // Host-identity reads and Go build markers are informational, so they
        // are dropped here rather than joining the refusal set
        // (`render_host_identity_note` over `native_host_identity_sites`, and
        // its Go-marker twin, are what report them, on every outcome).
        // The scan still classifies them in one place; only the disposition
        // differs.
        denied.extend(
            scan_instruction_ranges(&file, &provenance, &code_ranges)?
                .into_iter()
                .filter(|escape| {
                    !native_escape_is_host_identity(escape)
                        && !native_escape_is_go_build_marker(escape)
                }),
        );
        denied.extend(early_init_escapes(&file, &provenance));
        // A versioned reference pins a glibc symbol version that the shim's own
        // unversioned definition/wrap cannot satisfy, so the link leaves it an
        // undefined import the loader binds to libc — around the interposer.
        // This only means anything for a shim-linked binary: without the shim,
        // the allowlist already governs an ordinary libc call, versioned or not.
        if native_binary_is_shim_linked(bytes).unwrap_or(false) {
            denied.extend(versioned_bypass_escapes(&file, allow, &provenance_of));
        }
        if !denied.is_empty() {
            return Err(TargetError::UnsupportedNativeImports(denied));
        }
        Ok(Self {
            imports,
            inert_weak_imports,
        })
    }
}

/// One undefined ELF dynamic symbol that carries a symbol-version requirement.
struct VersionedImport {
    /// The symbol name as spelled in `.dynsym` (version suffix excluded; the
    /// version is carried separately through `.gnu.version`).
    name: String,
    /// The version requirement name from `.gnu.version_r` (e.g. `GLIBC_2.2.5`).
    version: String,
    /// A weak binding: the shim's host-alias `dlsym` vehicle is weak by its own
    /// `.weak __real_dlsym` directive (see `elf_shim_dlsym_vehicle`).
    weak: bool,
}

/// The executable's dynamic symbols as the loader resolves versioned imports
/// against them: every undefined symbol that carries a symbol-version
/// requirement, and every name the executable itself exports a definition of.
#[derive(Default)]
struct DynamicVersions {
    imports: Vec<VersionedImport>,
    /// Names defined in `.dynsym` at the global version index. The executable
    /// is first in the loader's lookup scope, and glibc's `check_match` lets a
    /// definition at the global index satisfy a reference of any version, so a
    /// versioned import of one of these names binds to the executable's own
    /// definition, never to libc's. Both GNU ld and lld export an executable
    /// definition of every name a linked library also defines, so the shim's
    /// interposers are here.
    exported: BTreeSet<String>,
}

/// Read [`DynamicVersions`] from `.dynsym`, `.gnu.version` and
/// `.gnu.version_r`. Empty for a non-ELF binary (Mach-O has no symbol
/// versioning) or an ELF with no version sections.
fn dynamic_versions(file: &object::File<'_>) -> DynamicVersions {
    let object::File::Elf64(elf) = file else {
        return DynamicVersions::default();
    };
    let endian = elf.endian();
    let data = elf.data();
    let Ok(Some(versions)) = elf.elf_section_table().versions(endian, data) else {
        return DynamicVersions::default();
    };
    let symbols = elf.elf_dynamic_symbol_table();
    let strings = symbols.strings();
    let mut out = DynamicVersions::default();
    for (index, symbol) in symbols.enumerate() {
        let Ok(name) = symbol.name(endian, strings) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        let name = String::from_utf8_lossy(name).into_owned();
        let version_index = versions.version_index(endian, index);
        if !symbol.is_undefined(endian) {
            if version_index.is_global() {
                out.exported.insert(name);
            }
            continue;
        }
        // `version` is `Ok(None)` for the local and global (unversioned) indices,
        // so only a real version requirement reaches the push.
        let Ok(Some(version)) = versions.version(version_index) else {
            continue;
        };
        out.imports.push(VersionedImport {
            name,
            version: String::from_utf8_lossy(version.name()).into_owned(),
            weak: symbol.st_bind() == object::elf::STB_WEAK,
        });
    }
    out
}

/// Refuse every undefined versioned import that reaches glibc's own text for a
/// name the shim relies on catching: an interposed name, or the
/// `dlsym`/`dlvsym` resolver behind `-Wl,--wrap=dlsym`.
///
/// `--wrap` rewrites only *unversioned* references, so a `.symver`-pinned
/// `dlsym@GLIBC_2.2.5` stays an undefined import, and since the executable
/// defines `__wrap_dlsym` rather than `dlsym`, the loader binds it to libc's
/// real resolver, past the restricted one. A versioned reference to an
/// interposed name (`mmap@GLIBC_2.2.5`) is different: the linker either binds
/// it to the shim's definition outright (GNU ld) or leaves an import the loader
/// binds to the executable's exported definition (lld), the shim's either way.
/// So the signal is a versioned import of such a name that the executable does
/// not itself export ([`DynamicVersions::exported`]): only that one reaches
/// libc.
///
/// The one legitimate versioned import is the shim's host-alias `dlsym` vehicle
/// (`__real_dlsym`: weak, at glibc's default `dlsym` version); it is admitted,
/// and only it. A caller may still clear a specific finding with an exact
/// `--allow name@version`.
fn versioned_bypass_escapes(
    file: &object::File<'_>,
    allow: &BTreeSet<String>,
    provenance_of: &dyn Fn(&str) -> Vec<NativeProvenance>,
) -> Vec<NativeEscape> {
    let dynamic = dynamic_versions(file);
    let mut escapes = Vec::new();
    for import in dynamic.imports {
        if !import.version.starts_with("GLIBC_") || dynamic.exported.contains(&import.name) {
            continue;
        }
        let bypass = if elf_wrapped_resolver(&import.name) {
            !elf_shim_dlsym_vehicle(&import.name, &import.version, import.weak)
        } else {
            elf_interposed_import(&import.name)
        };
        if !bypass {
            continue;
        }
        let versioned = format!("{}@{}", import.name, import.version);
        if allow.contains(&versioned) {
            continue;
        }
        escapes.push(NativeEscape::new(
            versioned,
            VERSIONED_BYPASS_CATEGORY,
            provenance_of(&import.name),
        ));
    }
    escapes
}

/// Whether an ELF lacks what the audit reads: imports come from the dynamic
/// symbol table, their version requirements from the `SHT_GNU_versym`
/// section, and code ranges from the section headers, while the loader needs
/// none of them. A binary whose section headers were removed would otherwise
/// pass with no imports and no scanned code, and one whose dynamic table names
/// a version table (`DT_VERSYM`) the sections do not carry would pass the
/// versioned-bypass check with no versions read. An `ET_REL` object is refused
/// later, by name, and a Mach-O is never judged here.
fn unauditable_elf(file: &object::File<'_>) -> bool {
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

/// The normalized names this binary references *only* through undefined weak
/// bindings — the references an undefined-weak import can be judged inert on.
///
/// An undefined weak reference is the C way of asking "is this hook present?":
/// if nothing supplies a definition it resolves to NULL and the referencing code
/// takes its guarded fallback path (aws-lc's `OPENSSL_memory_alloc`/`_free`/
/// `_get_size`/`_realloc` allocator-override hooks and `sdallocx`). A NULL that
/// is never called is not a door to the host, so refusing one is a false
/// positive.
///
/// The rule is only as sound as its disqualifiers, and both are computed over the
/// WHOLE audited closure — every static and dynamic symbol, definitions included:
///
/// * a name the closure **defines** anywhere is removed. The weak reference then
///   binds to that real code, which is exactly the classification path's job.
/// * a name with any **strong** undefined reference is removed. A strong
///   reference must be bound for the process to start, so the weak sibling rides
///   along to whatever definition satisfies it.
///
/// Callers apply this only to imports that match no named escape class (see
/// [`UNKNOWN_IMPORT_CATEGORY`]); that narrowing is load-bearing, not cosmetic.
/// "Undefined" means undefined *in this image*, and the dynamic linker still
/// searches the loaded libraries — so a weak undefined `open` binds to libc's
/// `open` at load time and runs. The classified names are precisely the ones a
/// loaded library defines, so a weak binding may never rescue one.
fn inert_weak_symbols(file: &object::File<'_>) -> BTreeSet<String> {
    let mut weak_undefined: BTreeSet<String> = BTreeSet::new();
    let mut disqualified: BTreeSet<String> = BTreeSet::new();
    for symbol in file.symbols().chain(file.dynamic_symbols()) {
        let Ok(name) = symbol.name() else { continue };
        if name.is_empty() {
            continue;
        }
        let normalized = normalize_native_symbol(name).to_owned();
        // Anything that is not an undefined *weak* reference disqualifies the
        // name: a definition binds it, and a strong reference forces a binding.
        // Judged on the negative so an exotic binding (common, absolute, a format
        // the reader classifies as neither) also disqualifies — fail closed.
        if symbol.is_undefined() && symbol.is_weak() {
            weak_undefined.insert(normalized);
        } else {
            disqualified.insert(normalized);
        }
    }
    weak_undefined
        .difference(&disqualified)
        .cloned()
        .collect::<BTreeSet<_>>()
}

#[cfg(test)]
mod tests;
