//! Native address attribution and object, crate, and symbol provenance.

use object::{Object, ObjectSymbol, SymbolKind};
use std::path::Path;

/// The `object` value for a site whose defining object the linked image does not
/// record. Mach-O keeps a per-address object/archive-member map, so this is rare
/// there; ELF only records object identity for an input file's *local* symbols,
/// so every global symbol legitimately lands here (see [`NativeProvenanceIndex`]).
const UNKNOWN_OBJECT: &str = "unknown";

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct NativeProvenance {
    /// Compact object/archive-member label (`libfoo-<hash>.rlib(member.o)` on
    /// Mach-O, the codegen-unit object name on ELF), or [`UNKNOWN_OBJECT`] when
    /// the linked image no longer carries enough information.
    pub object: String,
    /// Rust crate name recovered from an rlib/member name or a Rust symbol.
    pub crate_name: Option<String>,
    /// Function/data symbol containing the reference or instruction site.
    pub containing_symbol: Option<String>,
    /// Native section containing the reference or instruction site.
    pub section: Option<String>,
}

impl NativeProvenance {
    pub fn unknown() -> Self {
        Self {
            object: UNKNOWN_OBJECT.into(),
            crate_name: None,
            containing_symbol: None,
            section: None,
        }
    }

    /// Whether this names nothing actionable: no object, no crate, no containing
    /// symbol. The section is deliberately not part of the judgement — it is the
    /// one field every site can fill in, so counting it as attribution turned
    /// each unattributable reference into its own `provenance=unknown` group
    /// instead of collapsing them into one.
    pub fn is_unknown(&self) -> bool {
        self.object == UNKNOWN_OBJECT
            && self.crate_name.is_none()
            && self.containing_symbol.is_none()
    }

    pub fn label(&self) -> String {
        let mut parts = Vec::new();
        if let Some(crate_name) = &self.crate_name {
            parts.push(format!("crate={crate_name}"));
        }
        if self.object != UNKNOWN_OBJECT {
            parts.push(format!("object={}", self.object));
        }
        if parts.is_empty() {
            return "provenance=unknown".into();
        }
        format!("provenance={}", parts.join(" "))
    }

    pub fn site_label(&self) -> Option<String> {
        let mut parts = Vec::new();
        if let Some(symbol) = &self.containing_symbol {
            parts.push(format!("symbol={symbol}"));
        }
        if let Some(section) = &self.section {
            parts.push(format!("section={section}"));
        }
        if parts.is_empty() {
            None
        } else {
            Some(parts.join(" "))
        }
    }
}

pub(super) fn normalize_provenance(mut provenance: Vec<NativeProvenance>) -> Vec<NativeProvenance> {
    if provenance.is_empty() {
        return vec![NativeProvenance::unknown()];
    }
    // Collapse every unattributable site to the one canonical `unknown`, so a
    // set of them dedups to a single entry and is then dropped outright when any
    // attributed site exists for the same symbol.
    for entry in &mut provenance {
        if entry.is_unknown() {
            *entry = NativeProvenance::unknown();
        }
    }
    provenance.sort();
    provenance.dedup();
    if provenance.len() > 1 {
        provenance.retain(|entry| !entry.is_unknown());
    }
    if provenance.is_empty() {
        vec![NativeProvenance::unknown()]
    } else {
        provenance
    }
}

#[derive(Clone, Debug)]
pub(super) struct AddressProvenance {
    address: u64,
    size: u64,
    object_path: Option<String>,
    archive_member: Option<String>,
    symbol: Option<String>,
}

pub(super) struct NativeProvenanceIndex {
    /// Sorted by `(address, size)`.
    entries: Vec<AddressProvenance>,
    /// `reach[i]` is the largest end address among `entries[..=i]` (a zero-size
    /// label ends one past its address), so it never decreases. Every entry
    /// before the first `reach` past an address ends at or before it and cannot
    /// contain it, which bounds a lookup's scan from below.
    reach: Vec<u64>,
}

impl NativeProvenanceIndex {
    pub(super) fn new(file: &object::File<'_>) -> Self {
        let mut entries = Vec::new();

        // Mach-O keeps STAB-derived object/archive-member provenance. The object
        // crate exposes it as an address map, so preserve it before falling back
        // to the generic symbol table below.
        let object_map = file.object_map();
        for entry in object_map.symbols() {
            let object = entry.object(&object_map);
            entries.push(AddressProvenance {
                address: entry.address(),
                size: entry.size(),
                object_path: Some(bytes_to_string(object.path())),
                archive_member: object.member().map(bytes_to_string),
                symbol: Some(bytes_to_string(entry.name())),
            });
        }

        // The generic symbol table: the only source of a containing symbol on
        // ELF, and the fallback for a Mach-O image whose object map was stripped.
        //
        // ELF also carries STT_FILE markers naming each input object, but their
        // reach is narrow and easy to overstate. A file symbol is itself local,
        // and ELF requires every local symbol to precede the first global, so a
        // marker only names the input object of the LOCAL symbols that follow it
        // — the run ends at the first global, after which no marker applies to
        // anything. Carrying the marker forward regardless attributed every
        // global symbol in the image to whichever file symbol happened to come
        // last (`crtstuff.c`, `ucmpti2.c`, ...), which is wrong for essentially
        // every Rust symbol, and produced groups as self-contradictory as
        // `crate=leaker_a object=crtstuff.c`. So the association stops at the
        // local run; a global's object is genuinely not recorded in a linked ELF
        // and degrades to `unknown`, with `crate=` still recovered from the
        // symbol's own mangling.
        let mut current_file = None;
        for symbol in file.symbols() {
            if symbol.kind() == SymbolKind::File {
                current_file = symbol
                    .name()
                    .ok()
                    .filter(|name| !name.is_empty())
                    .map(str::to_owned);
                continue;
            }
            if !symbol.is_local() {
                current_file = None;
            }
            if !symbol.is_definition() || symbol.address() == 0 {
                continue;
            }
            if !matches!(
                symbol.kind(),
                SymbolKind::Text | SymbolKind::Label | SymbolKind::Data | SymbolKind::Unknown
            ) {
                continue;
            }
            entries.push(AddressProvenance {
                address: symbol.address(),
                size: symbol.size(),
                object_path: current_file.clone(),
                archive_member: None,
                symbol: symbol.name().ok().map(str::to_owned),
            });
        }

        entries.sort_by_key(|entry| (entry.address, entry.size));
        Self::from_sorted(entries)
    }

    pub(super) fn from_sorted(entries: Vec<AddressProvenance>) -> Self {
        let reach = entries
            .iter()
            .scan(0u64, |reach, entry| {
                *reach = (*reach).max(entry_end(entry));
                Some(*reach)
            })
            .collect();
        Self { entries, reach }
    }

    pub(super) fn for_address(&self, address: u64, section: Option<&str>) -> NativeProvenance {
        // The candidates are exactly the entries starting at or before `address`
        // whose running reach extends past it; visiting them in index order keeps
        // the first-best tie-breaking of a full scan. A binary's call sites hit
        // this once per import reference, so a scan from index 0 was quadratic.
        let first = self.reach.partition_point(|reach| *reach <= address);
        let last = self
            .entries
            .partition_point(|entry| entry.address <= address);
        let mut best = None;
        for entry in self.entries.get(first..last).unwrap_or_default() {
            if address_in_entry(address, entry) {
                best = match best {
                    None => Some(entry),
                    Some(prev) if entry_better(entry, prev) => Some(entry),
                    Some(prev) => Some(prev),
                };
            }
        }

        let Some(entry) = best else {
            let mut unknown = NativeProvenance::unknown();
            unknown.section = section.map(str::to_owned);
            return unknown;
        };

        let object = entry
            .object_path
            .as_deref()
            .map(|path| compact_object_label(path, entry.archive_member.as_deref()))
            .unwrap_or_else(|| "unknown".into());
        let crate_name = entry
            .object_path
            .as_deref()
            .and_then(|path| crate_name_from_object(path, entry.archive_member.as_deref()))
            .or_else(|| {
                entry
                    .archive_member
                    .as_deref()
                    .and_then(crate_name_from_object_member)
            })
            .or_else(|| entry.symbol.as_deref().and_then(crate_name_from_symbol));

        NativeProvenance {
            object,
            crate_name,
            containing_symbol: entry.symbol.clone(),
            section: section.map(str::to_owned),
        }
    }
}

/// One past the last address `entry` contains (see [`address_in_entry`]).
fn entry_end(entry: &AddressProvenance) -> u64 {
    entry.address.saturating_add(entry.size.max(1))
}

fn address_in_entry(address: u64, entry: &AddressProvenance) -> bool {
    if entry.size == 0 {
        address == entry.address
    } else {
        address >= entry.address && address < entry.address.saturating_add(entry.size)
    }
}

/// Which of two entries containing the same address describes it more precisely.
/// The tightest container wins: a smaller sized symbol is nested inside a larger
/// one, and a sized symbol beats a zero-size label (which matched only because it
/// sits exactly on the address). Object provenance breaks ties between equally
/// precise entries only — ranking it first let a bare label outrank the function
/// that actually contains the site.
fn entry_better(candidate: &AddressProvenance, current: &AddressProvenance) -> bool {
    match (candidate.size, current.size) {
        (0, 0) => candidate.object_path.is_some() && current.object_path.is_none(),
        (0, _) => false,
        (_, 0) => true,
        (candidate_size, current_size) if candidate_size != current_size => {
            candidate_size < current_size
        }
        _ => candidate.object_path.is_some() && current.object_path.is_none(),
    }
}

pub(super) fn bytes_to_string(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// The compact label for a defining object, or [`UNKNOWN_OBJECT`] when the
/// sources produce no name at all.
///
/// The empty case is a real one, not defensive padding: an ELF STT_FILE marker
/// can carry an empty name, and a marker whose name is empty was rendered as a
/// bare `object=` with nothing after it — an "attribution" naming nothing, which
/// is the arm64 flavor of the same wrong answer x86_64 gave by borrowing a
/// neighbor's marker. Nothing downstream should have to distinguish an empty
/// object from an absent one, so an empty label never leaves this function.
fn compact_object_label(path: &str, member: Option<&str>) -> String {
    let file = Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(path);
    let label = match member {
        Some(member) if !member.is_empty() => format!("{file}({member})"),
        _ => file.to_string(),
    };
    if label.is_empty() {
        UNKNOWN_OBJECT.to_string()
    } else {
        label
    }
}

fn crate_name_from_object(path: &str, member: Option<&str>) -> Option<String> {
    let file = Path::new(path).file_name()?.to_str()?;
    crate_name_from_archive(file)
        .or_else(|| member.and_then(crate_name_from_object_member))
        .or_else(|| crate_name_from_codegen_unit(file))
        .or_else(|| crate_name_from_source_path(path))
}

/// The crate behind an ELF STT_FILE marker. rustc names each codegen unit
/// `<crate>.<hash>-cgu.<n>` (`std.1e3c4ec04c5261a9-cgu.0`), and that name is what
/// the linker copies into the file symbol, so it is the ELF counterpart of a
/// Mach-O archive member. Local-crate codegen units are named by hash alone and
/// carry no crate, which this rejects rather than inventing one.
fn crate_name_from_codegen_unit(file: &str) -> Option<String> {
    let (crate_name, rest) = file.split_once('.')?;
    let (hash, index) = rest.rsplit_once("-cgu.")?;
    let valid = !crate_name.is_empty()
        && crate_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        && !crate_name.starts_with(|byte: char| byte.is_ascii_digit())
        && !hash.is_empty()
        && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
        && !index.is_empty()
        && index.bytes().all(|byte| byte.is_ascii_digit());
    valid.then(|| crate_name.to_owned())
}

fn crate_name_from_archive(file: &str) -> Option<String> {
    let stem = file.strip_suffix(".rlib")?;
    let stem = stem.strip_prefix("lib").unwrap_or(stem);
    strip_hash_suffix(stem).map(str::to_owned)
}

fn crate_name_from_object_member(member: &str) -> Option<String> {
    let file = Path::new(member)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(member);
    let stem = file.strip_suffix(".o").unwrap_or(file);
    strip_hash_suffix(stem).map(str::to_owned)
}

fn crate_name_from_source_path(path: &str) -> Option<String> {
    let mut prev = None;
    for component in Path::new(path).components() {
        let text = component.as_os_str().to_str()?;
        if text == "src" {
            return prev.map(str::to_owned);
        }
        prev = Some(text);
    }
    None
}

fn strip_hash_suffix(stem: &str) -> Option<&str> {
    let (prefix, suffix) = stem.rsplit_once('-').unwrap_or((stem, ""));
    if suffix.len() >= 8 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Some(prefix)
    } else if !stem.is_empty() {
        Some(stem)
    } else {
        None
    }
}

fn crate_name_from_symbol(symbol: &str) -> Option<String> {
    let stripped = symbol.trim_start_matches('_');
    let demangled = rustc_demangle::try_demangle(stripped)
        .or_else(|_| rustc_demangle::try_demangle(symbol))
        .ok()?;
    crate_name_from_demangled_path(&format!("{demangled:#}"))
}

/// The defining crate at the head of a demangled Rust path. A free path starts
/// with the crate outright (`std::io::copy`), but an inherent- or trait-impl
/// method starts with the impl header instead
/// (`<std::os::unix::process::Child as ChildExt>::kill_process_group`), and impl
/// methods dominate a real binary's symbol table — refusing to look past the
/// header left `crate=` unrecoverable for most of it. The leading type
/// punctuation is peeled, then the head identifier is accepted only when a `::`
/// follows it, so a generic parameter or primitive (`<T as ...>`, `<u32 as ...>`)
/// is rejected instead of being reported as a crate.
fn crate_name_from_demangled_path(path: &str) -> Option<String> {
    let mut rest = path.trim_start();
    loop {
        let peeled = ['<', '&', '*', '(', '[']
            .iter()
            .find_map(|prefix| rest.strip_prefix(*prefix))
            .or_else(|| {
                ["mut ", "const ", "dyn ", "impl "]
                    .iter()
                    .find_map(|prefix| rest.strip_prefix(*prefix))
            });
        match peeled {
            Some(peeled) => rest = peeled.trim_start(),
            None => break,
        }
    }

    let end =
        rest.find(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))?;
    let (name, tail) = rest.split_at(end);
    if !tail.starts_with("::") || name.is_empty() || name.starts_with(|c: char| c.is_ascii_digit())
    {
        return None;
    }
    Some(name.to_owned())
}

#[cfg(test)]
mod tests;
