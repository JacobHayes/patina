//! Coverage symbol lookup and attribution.

use super::*;

#[derive(Clone, Debug)]
struct FunctionSymbol {
    address: u64,
    end: u64,
    symbol: String,
    demangled: String,
}

#[derive(Clone, Debug)]
struct SymbolTable {
    anchor: u64,
    functions: Vec<FunctionSymbol>,
    /// A Go guest's 8-bit counters, in section order, each with the package
    /// that owns it.
    go_counters: Vec<Option<String>>,
}

/// The section Go's linker gathers its libFuzzer 8-bit counters into, which the
/// runtime registers whole at start-up.
const GO_COUNTER_SECTION: &str = ".go.fuzzcntrs";

/// The packages that own a Go binary's 8-bit counters, by offset into
/// [`GO_COUNTER_SECTION`]. Go writes no pc table, but each counter is a
/// compiler static named `<package>..stmp_<N>`, so a counter names its package
/// (not its function). Empty when the binary has no such section.
fn go_counter_packages(file: &object::File<'_>) -> Vec<Option<String>> {
    use object::ObjectSection;
    let Some(section) = file.section_by_name(GO_COUNTER_SECTION) else {
        return Vec::new();
    };
    let (start, len) = (section.address(), section.size());
    let Ok(slots) = usize::try_from(len) else {
        return Vec::new();
    };
    let mut packages = vec![None; slots];
    for symbol in file.symbols() {
        let Some(offset) = symbol.address().checked_sub(start).filter(|&at| at < len) else {
            continue;
        };
        let Some((package, _)) = symbol
            .name()
            .ok()
            .and_then(|name| name.rsplit_once("..stmp_"))
        else {
            continue;
        };
        packages[offset as usize] = Some(go_import_path(package));
    }
    packages
}

/// The import path a Go linker symbol prefix names. The linker escapes a few
/// bytes of the path as `%xx` (a `.` in its last element, `%`, `"`, spaces and
/// control bytes; `cmd/internal/objabi.PathToPrefix`), so `dot.pkg` links as
/// `dot%2epkg`. A malformed escape stays as written.
fn go_import_path(prefix: &str) -> String {
    let bytes = prefix.as_bytes();
    let mut path = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        let escaped = (bytes[at] == b'%')
            .then(|| bytes.get(at + 1..at + 3))
            .flatten()
            .and_then(|hex| u8::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok());
        match escaped {
            Some(byte) => {
                path.push(byte);
                at += 3;
            }
            None => {
                path.push(bytes[at]);
                at += 1;
            }
        }
    }
    String::from_utf8_lossy(&path).into_owned()
}

fn read_symbol_table(binary: &Path) -> Result<SymbolTable, CliError> {
    let bytes = fs::read(binary).map_err(|error| {
        CliError(format!(
            "failed to read binary {} for coverage symbolization: {error}",
            binary.display()
        ))
    })?;
    let file = object::File::parse(&*bytes).map_err(|error| {
        CliError(format!(
            "failed to parse binary {} for coverage symbolization: {error}",
            binary.display()
        ))
    })?;
    let go_counters = go_counter_packages(&file);
    let mut anchor = None;
    let mut functions = BTreeMap::<u64, FunctionSymbol>::new();
    for symbol in file.symbols().chain(file.dynamic_symbols()) {
        let Ok(name) = symbol.name() else {
            continue;
        };
        let normalized = name.trim_start_matches('_');
        if normalized == "patina_yield_point" {
            anchor = Some(symbol.address());
        }
        if symbol.is_undefined() || symbol.kind() != SymbolKind::Text || symbol.address() == 0 {
            continue;
        }
        let demangled = demangle_symbol(name);
        let size = symbol.size();
        let address = symbol.address();
        let end = if size == 0 {
            address
        } else {
            address.saturating_add(size)
        };
        functions.entry(address).or_insert(FunctionSymbol {
            address,
            end,
            symbol: name.to_string(),
            demangled,
        });
    }
    let anchor = anchor.ok_or_else(|| {
        CliError(format!(
            "coverage symbolization could not find nm anchor symbol patina_yield_point in {}; is this a native --instrument binary?",
            binary.display()
        ))
    })?;
    let mut functions: Vec<_> = functions.into_values().collect();
    functions.sort_by_key(|function| function.address);
    let addresses: Vec<u64> = functions.iter().map(|function| function.address).collect();
    for (index, function) in functions.iter_mut().enumerate() {
        if function.end <= function.address {
            if let Some(next) = addresses.get(index + 1).copied() {
                function.end = next;
            } else {
                function.end = u64::MAX;
            }
        }
    }
    Ok(SymbolTable {
        anchor,
        functions,
        go_counters,
    })
}

fn demangle_symbol(name: &str) -> String {
    if let Ok(demangled) = rustc_demangle::try_demangle(name) {
        return format!("{demangled:#}");
    }
    if let Some(stripped) = name.strip_prefix('_')
        && let Ok(demangled) = rustc_demangle::try_demangle(stripped)
    {
        return format!("{demangled:#}");
    }
    name.trim_start_matches('_').to_string()
}

impl SymbolTable {
    fn function_for_pc(&self, pc: u64) -> Option<&FunctionSymbol> {
        let index = self
            .functions
            .partition_point(|function| function.address <= pc);
        let function = self.functions.get(index.checked_sub(1)?)?;
        (pc < function.end).then_some(function)
    }
}

#[derive(Clone, Debug)]
struct EdgeAttribution {
    crate_name: String,
    module: String,
    covered: bool,
}

impl RollupLeaf for EdgeAttribution {
    fn crate_name(&self) -> &str {
        &self.crate_name
    }

    fn module(&self) -> &str {
        &self.module
    }

    fn bucket(&self) -> &str {
        if self.covered { "covered" } else { "uncovered" }
    }

    fn is_gap(&self) -> bool {
        !self.covered
    }
}

#[derive(Clone, Debug, Default)]
pub(super) struct CoverageStats {
    pub(super) edges_total: u64,
    pub(super) edges_covered: u64,
    pub(super) hits_total: u64,
}

impl CoverageStats {
    fn add(&mut self, covered: bool, hits: u64) {
        self.edges_total += 1;
        if covered {
            self.edges_covered += 1;
        }
        self.hits_total = self.hits_total.saturating_add(hits);
    }

    pub(super) fn covered_permille(&self) -> u64 {
        permille(self.edges_covered, self.edges_total)
    }
}

#[derive(Clone, Debug)]
pub(super) struct CoverageReportTree {
    pub(super) rollup: Rollup,
    pub(super) crates: BTreeMap<String, CoverageStats>,
    pub(super) modules: BTreeMap<(String, String), CoverageStats>,
    pub(super) functions: BTreeMap<String, CoverageStats>,
}

/// The static pc edge `index`'s anchor-relative `delta` names. The zero delta
/// names none: the shim writes it for a pc-table sentinel, a guard whose block
/// LLVM deleted or folded away. Whether the edge was hit plays no part — a hit
/// sentinel is real coverage at an unknown site, never an edge at the anchor.
fn edge_static_pc(index: usize, anchor: u64, delta: i64) -> Result<Option<u64>, CliError> {
    if delta == 0 {
        return Ok(None);
    }
    u64::try_from(i128::from(anchor) + i128::from(delta))
        .map(Some)
        .map_err(|_| {
            CliError(format!(
                "coverage edge {index} static pc is out of range: anchor={anchor} delta={delta}"
            ))
        })
}

pub(super) fn symbolize_coverage(
    binary: &Path,
    data: &CoverageData,
) -> Result<CoverageReportTree, CliError> {
    if data.hits.len() != data.deltas.len() {
        return Err(CliError(format!(
            "coverage input has {} hit counters but {} site deltas",
            data.hits.len(),
            data.deltas.len()
        )));
    }
    let symbols = read_symbol_table(binary)?;
    let go_packages = go_edge_packages(&symbols.go_counters, &data.deltas);
    let mut edges = Vec::with_capacity(data.hits.len());
    let mut crates = BTreeMap::<String, CoverageStats>::new();
    let mut modules = BTreeMap::<(String, String), CoverageStats>::new();
    let mut functions = BTreeMap::<String, CoverageStats>::new();
    for (index, (&hits, &delta)) in data.hits.iter().zip(&data.deltas).enumerate() {
        let covered = hits != 0;
        let static_pc = edge_static_pc(index, symbols.anchor, delta)?;
        let function = static_pc.and_then(|pc| symbols.function_for_pc(pc));
        let (crate_name, module, function_path, symbol_name) = function.map_or_else(
            || {
                // A Go counter's package is its crate and module both; its
                // function is unknown.
                let package = go_packages(index).unwrap_or("<unknown>");
                (
                    package.to_string(),
                    package.to_string(),
                    "<unknown>".to_string(),
                    "<unknown>".to_string(),
                )
            },
            |function| {
                let parsed = parse_symbol_path(&function.demangled);
                (
                    parsed.crate_name,
                    parsed.module,
                    parsed.function_path,
                    function.symbol.clone(),
                )
            },
        );
        crates
            .entry(crate_name.clone())
            .or_default()
            .add(covered, hits);
        modules
            .entry((crate_name.clone(), module.clone()))
            .or_default()
            .add(covered, hits);
        functions
            .entry(function_path.clone())
            .or_default()
            .add(covered, hits);
        let _ = (symbol_name, static_pc);
        edges.push(EdgeAttribution {
            crate_name,
            module,
            covered,
        });
    }
    let rollup = build_rollup(&edges, COVERED_BUCKETS);
    Ok(CoverageReportTree {
        rollup,
        crates,
        modules,
        functions,
    })
}

/// The package owning edge `index`, for the edges that are a Go binary's 8-bit
/// counters. The shim writes those last, after any guard words, in section
/// order and each with the zero (unknown) site, so the trailing
/// `packages.len()` edges are the section's counters when every one of them
/// has the zero site. Any other shape names no package.
fn go_edge_packages<'a>(
    packages: &'a [Option<String>],
    deltas: &[i64],
) -> impl Fn(usize) -> Option<&'a str> {
    let first = deltas
        .len()
        .checked_sub(packages.len())
        .filter(|&first| !packages.is_empty() && deltas[first..].iter().all(|&delta| delta == 0));
    move |index| {
        let offset = index.checked_sub(first?)?;
        packages.get(offset)?.as_deref()
    }
}

struct ParsedSymbolPath {
    crate_name: String,
    module: String,
    function_path: String,
}

fn parse_symbol_path(demangled: &str) -> ParsedSymbolPath {
    let cleaned = demangled
        .split("::h")
        .next()
        .unwrap_or(demangled)
        .trim()
        .to_string();
    let grouping_path = grouping_path_for_symbol(&cleaned);
    let parts: Vec<&str> = grouping_path
        .split("::")
        .map(|part| part.trim_matches(|c| c == '<' || c == '>' || c == '&' || c == '[' || c == ']'))
        .filter(|part| !part.is_empty())
        .collect();
    if parts.is_empty() {
        return ParsedSymbolPath {
            crate_name: "<unknown>".to_string(),
            module: "<unknown>".to_string(),
            function_path: cleaned,
        };
    }
    let crate_name = if parts.len() == 1 && primitive_type(parts[0]) {
        "core".to_string()
    } else {
        parts[0].to_string()
    };
    let module = if parts.len() <= 1 {
        crate_name.clone()
    } else {
        parts[..parts.len() - 1].join("::")
    };
    ParsedSymbolPath {
        crate_name,
        module,
        function_path: cleaned,
    }
}

fn primitive_type(part: &str) -> bool {
    matches!(
        part,
        "bool"
            | "char"
            | "str"
            | "u8"
            | "u16"
            | "u32"
            | "u64"
            | "u128"
            | "usize"
            | "i8"
            | "i16"
            | "i32"
            | "i64"
            | "i128"
            | "isize"
    )
}

fn grouping_path_for_symbol(symbol: &str) -> &str {
    let symbol = symbol
        .trim_start_matches("&mut ")
        .trim_start_matches("mut ")
        .trim_start_matches("const ");
    if symbol.starts_with('[') || symbol.starts_with('*') {
        return "core";
    }
    let Some(inner) = symbol
        .strip_prefix('<')
        .and_then(|rest| rest.split('>').next())
    else {
        return symbol;
    };
    let inner = inner.trim();
    if let Some((left, right)) = inner.split_once(" as ") {
        let left = left.trim();
        if left.contains("::") && !left.starts_with('*') && left != "()" {
            return normalize_grouping_path(left);
        }
        return normalize_grouping_path(right.trim());
    }
    normalize_grouping_path(inner)
}

fn normalize_grouping_path(path: &str) -> &str {
    let path = path
        .trim_start_matches("&mut ")
        .trim_start_matches("mut ")
        .trim_start_matches("const ")
        .trim_start_matches('<')
        .trim_start();
    if path.starts_with('*') {
        return "core";
    }
    if let Some(stripped) = path.strip_prefix('[') {
        let stripped = stripped.trim_start_matches('&');
        if stripped.contains("::") {
            return stripped;
        }
        return "core";
    }
    path
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_zero_delta_names_no_site_and_others_offset_the_anchor() {
        let anchor = 0x1000;
        assert_eq!(edge_static_pc(0, anchor, 0).unwrap(), None);
        assert_eq!(edge_static_pc(1, anchor, 0x10).unwrap(), Some(0x1010));
        assert_eq!(edge_static_pc(2, anchor, -0x10).unwrap(), Some(0xff0));
        assert!(edge_static_pc(3, anchor, -0x2000).is_err());
    }

    #[test]
    fn a_go_symbol_prefix_unescapes_to_its_import_path() {
        assert_eq!(
            go_import_path("example.com/a/dot%2epkg"),
            "example.com/a/dot.pkg"
        );
        assert_eq!(
            go_import_path("crypto/internal/entropy/v1%2e0%2e0"),
            "crypto/internal/entropy/v1.0.0"
        );
        assert_eq!(go_import_path("fmt"), "fmt");
        assert_eq!(go_import_path("odd%zz%2"), "odd%zz%2");
    }

    #[test]
    fn go_counters_name_the_trailing_zero_site_edges_only() {
        let packages = vec![Some("fmt".to_string()), None, Some("main".to_string())];
        // One guard edge with a real site, then the three Go counters.
        let owner = go_edge_packages(&packages, &[8, 0, 0, 0]);
        assert_eq!(
            (0..4).map(&owner).collect::<Vec<_>>(),
            [None, Some("fmt"), None, Some("main")]
        );
        // A map whose trailing edges are not all unknown sites, or that is
        // shorter than the section, is not this binary's Go counters.
        let owner = go_edge_packages(&packages, &[0, 0, 8]);
        assert!((0..3).all(|index| owner(index).is_none()));
        let owner = go_edge_packages(&packages, &[0, 0]);
        assert!((0..2).all(|index| owner(index).is_none()));
    }
}
