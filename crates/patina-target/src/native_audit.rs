//! Native import auditing and inert undefined-weak bindings.

use crate::early_init::early_init_escapes;
use crate::import_policy::{
    NativeFormat, NativeImportDecision, UNKNOWN_IMPORT_CATEGORY, native_import_decision,
    normalize_native_symbol,
};
use crate::import_xrefs::collect_import_provenance;
use crate::instruction_scan::{native_escape_is_host_identity, scan_instruction_ranges};
use crate::provenance::{NativeProvenance, NativeProvenanceIndex};
use crate::{NativeEscape, TargetError, code_ranges};
use object::{Object, ObjectSymbol};
use std::collections::BTreeSet;

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
        let import_provenance = collect_import_provenance(&file, bytes, &provenance, &code_ranges);
        let inert_weak = inert_weak_symbols(&file);
        let mut inert_weak_imports = Vec::new();
        let mut denied = Vec::new();
        for symbol in &imports {
            let NativeImportDecision::Denied(category) =
                native_import_decision(symbol, format, allow)
            else {
                continue;
            };
            if category == UNKNOWN_IMPORT_CATEGORY
                && inert_weak.contains(normalize_native_symbol(symbol))
            {
                inert_weak_imports.push(symbol.clone());
                continue;
            }
            denied.push(NativeEscape::new(
                symbol.clone(),
                category,
                import_provenance
                    .get(symbol)
                    .cloned()
                    .unwrap_or_else(|| vec![NativeProvenance::unknown()]),
            ));
        }
        // Host-identity reads are informational, so they are dropped here rather
        // than joining the refusal set (`render_host_identity_note` over
        // `native_host_identity_sites` is what reports them, on every outcome).
        // The scan still classifies them in one place; only the disposition
        // differs.
        denied.extend(
            scan_instruction_ranges(&file, &provenance, &code_ranges)?
                .into_iter()
                .filter(|escape| !native_escape_is_host_identity(escape)),
        );
        denied.extend(early_init_escapes(&file, &provenance));
        if !denied.is_empty() {
            return Err(TargetError::UnsupportedNativeImports(denied));
        }
        Ok(Self {
            imports,
            inert_weak_imports,
        })
    }
}

/// Whether an ELF lacks what the audit reads: imports come from the dynamic
/// symbol table and code ranges from the section headers, while the loader
/// needs neither. A binary whose section headers were removed would otherwise
/// pass with no imports and no scanned code. An `ET_REL` object is refused
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
    file.kind() != object::ObjectKind::Relocatable
        && (file.sections().next().is_none() || dynamic && file.dynamic_symbol_table().is_none())
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
